# beacon_chain
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# This module is started when a chain stall is detected, i.e.,
# a long period without any chain progress, while at the same time being
# connected to a healthy number of different peers.
#
# In such a scenario, the network may partition into multiple groups of peers
# that build on separate branches. It is vital to specifically target peers
# from different partitions and download branches which are not necessarily
# popularly served. Branches may be unpopular because they are expensive to
# apply, and may have a difficult time propagating despite a large weight in
# attestations backing them. This only exacerbates the longer the split view
# scenario is ongoing.
#
# While sync manager can sync popular chains well, it cannot reliably sync
# minority chains only served by a limited number of peers. This module
# augments sync manager in the split view scenario.
# Note that request manager is not running while sync manager is running.
#
# Note that the canonical chain may not be on the highest slot number,
# as some partitions of the network may have built on top of branches
# with lower validator support while the canonical chain was not visible.
#
# Despite its simplicity and brute-force approach, this module has been highly
# effective in the final month of Goerli. It managed to sync the entire Nimbus
# testnet fleet to the same branch, while also tracking >25 alternate branches.
# Likewise, the Nimbus testnet fleet could discover the canonical Holesky branch
# when an invalid block got justified due to bugs in all majority EL clients.
# Further improvements should be applied:
#
# 1. Progress is currently relatively slow as this module downloads in backward
#    order before the results get applied in forward order.
#
#    This could be addressed by probing the peer about the branch that it's on.
#    We could send a by-root request for all our known heads to identify which
#    ones they are aware of, followed by a binary search back to finalized slot
#    to determine how far along the peer's progress is. From there on, by range
#    requests allow forward sync and remembering partial progress along the way.
#    We also wouldn't have to be as careful to avoid rate limit disconnections.
#    Empty epoch progress also needs to be remembered across syncing sessions,
#    because in a split view scenario often there are hundreds of empty epochs,
#    and by-range syncing is highly ineffective.
#
# 2. The peer pool currently provides the best available peer on acquisition.
#    Its filtering should be extended to have a better targeting for interesting
#    peers, i.e., those that claim to know about head roots that we are unaware
#    of and also have a head slot in the past, indicating that sync manager will
#    not target those peers and will not manage to pull their branches quickly.
#
# 3. When monitoring gossip, peers that inform about blocks with unknown parent
#    roots or aggregates referring to unknown beacon roots should be transferred
#    into branch discovery as well. Gossip only propagates through peers that
#    have validated the data themselves, so they must have the parent data.
#
# 4. Testing. Beyond Goerli, there is no regular long-lasting low participation
#    network that reflects a realistic scenario. The network needs to be huge,
#    geographically distributed with a variety of clients and lots of activity.
#    Blocks need to take a while to apply to test the slow propagation when
#    there are lots of empty epochs between blocks. There must be reorgs of
#    hundreds of blocks to reflect EL suddenly going back to optimistic mode.
#    A smaller simulation to run in CI may be achieveable by intentionally
#    setting the `SECONDS_PER_SLOT` to a low value. Furthermore, synthetic
#    scenarios can be tested in unit tests by mocking peers and blocks and
#    making timers and rate limits configurable.

import
  std/[algorithm, deques, hashes, sets],
  chronos, chronicles, metrics, results,
  ../spec/[forks, network],
  ../consensus_object_pools/block_pools_types,
  ../networking/[eth2_network, peer_pool],
  ./sync_protocol

logScope:
  topics = "branchdiscovery"

declareGauge beacon_sync_branchdiscovery_state,
  "Branch discovery module operating state"

declareGauge beacon_sync_branchdiscovery_pending,
  "Number of beacon blocks discovered that are not yet connected to local DAG"

declareCounter beacon_sync_branchdiscovery_discovered_blocks,
  "Number of beacon blocks discovered by the branch discovery module"

type
  BlockMeta = ref object
    bid: BlockId
    parent: BlockMeta
    isKnown: bool
    isUnviable: bool

  KeyedBlockMeta = object
    data: BlockMeta

func hash(key: KeyedBlockMeta): Hash =
  hash(key.data.bid.root)

func `==`(a, b: KeyedBlockMeta): bool =
  a.data.bid.root == b.data.bid.root

func get(blockMetas: var HashSet[KeyedBlockMeta], bid: BlockId): BlockMeta =
  let key = KeyedBlockMeta(data: BlockMeta(bid: bid))
  if key in blockMetas:
    try:
      blockMetas[key].data
    except KeyError:
      raiseAssert "contains"
  else:
    key.data

proc incl(blockMetas: var HashSet[KeyedBlockMeta], meta: BlockMeta) =
  let key = KeyedBlockMeta(data: meta)
  blockMetas.incl key
  beacon_sync_branchdiscovery_pending.set(blockMetas.len.int64)

type
  BranchDiscoveryState* {.pure.} = enum
    Stopped,
    Suspended,
    Active

  GetSlotCallback* =
    proc(): Slot {.gcsafe, raises: [].}

  IsBlockKnownCallback* =
    proc(blockRoot: Eth2Digest): bool {.gcsafe, raises: [].}

  BlockVerifierError* {.pure.} = enum
    InvalidProposerSignature
      ## The proposer signature does not validate, but there could be a copy of
      ## the block on the network with the same beacon block root and correct
      ## signature so this does not mean that the block root itself is bad

    Invalid
      ## Proposer signature validates and the beacon block doesn't apply.
      ## All blocks building on this beacon block are implicitly invalid

    UnviableBranch
      ## Value does not descend from finalized head block.
      ## All blocks building on this beacon block are implicitly unviable

    Duplicate
      ## The block is already known and does not add new information

  BlockVerifierCallback* = proc(
      signedBlock: ForkedSignedBeaconBlock,
      blobs: Opt[BlobSidecars]
  ): Future[Result[void, BlockVerifierError]] {.
      async: (raises: [CancelledError]).}

  BranchDiscovery*[A, B] = object
    pool: PeerPool[A, B]
    getWallSlot: GetSlotCallback
    getFinalizedSlot: GetSlotCallback
    isBlockKnown: IsBlockKnownCallback
    blockVerifier: BlockVerifierCallback
    isActive: AsyncEvent
    loopFuture: Future[void].Raising([])
    peerQueue: Deque[A]
    blockMetas: HashSet[KeyedBlockMeta]

proc new*[A, B](
    T: type BranchDiscovery[A, B],
    pool: PeerPool[A, B],
    getWallSlot: GetSlotCallback,
    getFinalizedSlot: GetSlotCallback,
    isBlockKnown: IsBlockKnownCallback,
    blockVerifier: BlockVerifierCallback): ref BranchDiscovery[A, B] =
  let self = (ref BranchDiscovery[A, B])(
    pool: pool,
    getWallSlot: getWallSlot,
    getFinalizedSlot: getFinalizedSlot,
    isBlockKnown: isBlockKnown,
    blockVerifier: blockVerifier,
    isActive: newAsyncEvent())
  self[].isActive.fire()
  self

proc getKnownBlock[A](
    peer: A,
    blockRoot: Eth2Digest
): Future[Opt[ref ForkedSignedBeaconBlock]] {.
    async: (raises: [CancelledError]).} =
  let rsp = await peer.beaconBlocksByRoot_v2(
    BlockRootsList @[blockRoot], maxResponseItems = 1)
  if rsp.isErr:
    # `eth2_network` already descored according to the specific error
    debug "Failed to receive block", err = rsp.error,
      peer, peer_score = peer.getScore()
    return err()
  template blocks: untyped = rsp.unsafeGet

  if blocks.len == 0:
    # The peer was advertising to know this block root, expecting avaialbility
    peer.updateScore(PeerScoreNoValues)
    debug "Received no blocks", numBlocks = blocks.len,
      peer, peer_score = peer.getScore()
    return err()
  template blck: untyped = blocks[0]
  if blck[].root != blockRoot:
    peer.updateScore(PeerScoreBadResponse)
    debug "Received incorrect block", receivedRoot = blck[].root,
      peer, peer_score = peer.getScore()
    return err()

  ok blocks[0]

proc getBlobSidecarsForKnownBlock[A](
    peer: A,
    blockRoot: Eth2Digest,
    numBlobs: int
): Future[Opt[Opt[BlobSidecars]]] {.async: (raises: [CancelledError]).} =
  var blobs: Opt[BlobSidecars]
  if numBlobs > 0:
    var blobIds: seq[BlobIdentifier]
    for i in 0 ..< numBlobs:
      blobIds.add BlobIdentifier(
        block_root: blockRoot,
        index: i.BlobIndex)

    let rsp = await peer.blobSidecarsByRoot(
      BlobIdentifierList blobIds, maxResponseItems = blobIds.len)
    if rsp.isErr:
      # `eth2_network` already descored according to the specific error
      debug "Failed to receive blobs", err = rsp.error,
        peer, peer_score = peer.getScore()
      return err()
    template blobSidecars: untyped = rsp.unsafeGet

    if blobSidecars.len < blobIds.len:
      peer.updateScore(PeerScoreMissingValues)
      debug "Received not all blobs",
        numBlobs = blobSidecars.len, expectedNumBlobs = blobIds.len,
        peer, peer_score = peer.getScore()
      return err()
    for i, blobSidecar in blobSidecars:
      let root = hash_tree_root(blobSidecar[].signed_block_header.message)
      if root != blockRoot:
        peer.updateScore(PeerScoreBadResponse)
        debug "Received unexpected blob",
          peer, peer_score = peer.getScore()
        return err()
      blobSidecar[].verify_blob_sidecar_inclusion_proof().isOkOr:
        peer.updateScore(PeerScoreBadResponse)
        debug "Received invalid blob",
          peer, peer_score = peer.getScore()
        return err()
    blobs = Opt.some distinctBase(blobSidecars).sortedByIt(it.index)
    for i, blobSidecar in blobs.get:
      if blobSidecar[].index != i.BlobIndex:
        peer.updateScore(PeerScoreBadResponse)
        debug "Received duplicate blobs while others are missing",
          peer, peer_score = peer.getScore()
        return err()
  ok blobs

proc discoverBranch[A, B](
    self: ref BranchDiscovery[A, B],
    peer: A) {.async: (raises: [CancelledError]).} =
  let oldPeerHeadSlot = peer.getHeadSlot()
  if Moment.now() - peer.getStatusLastTime() >= StatusExpirationTime:
    if not(await peer.updateStatus()):
      peer.updateScore(PeerScoreNoStatus)
      debug "Failed to update status",
        peer, peer_score = peer.getScore()
      return
  let peerHeadSlot = peer.getHeadSlot()
  if peerHeadSlot != oldPeerHeadSlot:
    peer.updateScore(PeerScoreGoodStatus)
    debug "Peer has synced to a new head", oldPeerHeadSlot, peerHeadSlot,
      peer, peer_score = peer.getScore()

  let finalizedSlot = self.getFinalizedSlot()
  if peerHeadSlot <= finalizedSlot:
    # This peer can sync from different peers, it is useless to us at this time
    peer.updateScore(PeerScoreUseless)
    debug "Peer's head slot is already finalized", peerHeadSlot, finalizedSlot,
      peer, peer_score = peer.getScore()
    return

  let peerBlockRoot = peer.getHeadRoot()
  if self.isBlockKnown(peerBlockRoot):
    # This peer may be actively syncing from us, only descore if no disconnect
    if peer.getScore() >= PeerScoreLowLimit - PeerScoreUseless:
      peer.updateScore(PeerScoreUseless)
    debug "Peer's head block root is already known", peerBlockRoot,
      peer, peer_score = peer.getScore()
    return

  # Obtain metadata for all blocks connecting to the DAG
  var
    meta = self.blockMetas.get BlockId(
      slot: peerHeadSlot,
      root: peerBlockRoot)
    peerChain: Deque[BlockMeta]
  while meta != nil and not meta.isUnviable:
    # Exit once branch can be connected
    if meta.bid.slot <= self.getFinalizedSlot() or
        self.isBlockKnown(meta.bid.root):
      debug "Branch metadata discovery complete",
        bid = meta.bid, numBranchBlocks = peerChain.len,
        peer, peer_score = peer.getScore()
      meta = nil
      break

    if not meta.isKnown:
      if peer.getScore() < PeerScoreLowLimit:
        debug "Failed to discover new branch from peer",
          bid = meta.bid, numBranchBlocks = peerChain.len,
          peer, peer_score = peer.getScore()
        break
      info "Discovering new branch from peer",
        bid = meta.bid, numBranchBlocks = peerChain.len,
        peer, peer_score = peer.getScore()
      let blck = (await peer.getKnownBlock(meta.bid.root)).valueOr:
        continue
      if meta.bid.slot <= self.getFinalizedSlot() or
          self.isBlockKnown(meta.bid.root):
        # Block became known / finality advanced during `await`
        continue
      meta = self.blockMetas.get(meta.bid)
      if not meta.isKnown:
        meta.bid.slot = blck[].getForkedBlockField(slot)
        let wallSlot = self.getWallSlot()
        if meta.bid.slot > wallSlot:
          peer.updateScore(PeerScoreBadResponse)
          debug "Received block is from future",
            wallSlot, receivedSlot = meta.bid.slot,
            bid = meta.bid, numBranchBlocks = peerChain.len,
            peer, peer_score = peer.getScore()
          break

        if meta.parent == nil and meta.bid.slot > self.getFinalizedSlot():
          let metaParent = self.blockMetas.get BlockId(
            slot: meta.bid.slot - 1,  # Upper bound
            root: blck[].getForkedBlockField(parent_root))
          if meta.bid.slot <= metaParent.bid.slot:
            debug "Received block is more recent than its known parent",
              receivedSlot = meta.bid.slot, parentSlot = metaParent.bid.slot,
              bid = meta.bid, numBranchBlocks = peerChain.len,
              peer, peer_score = peer.getScore()
            meta.isUnviable = true
            break
          else:
            if metaParent.bid.slot > self.getFinalizedSlot():
              meta.parent = metaParent
              if not meta.parent.isKnown:
                self.blockMetas.incl meta.parent
        meta.isKnown = true
        self.blockMetas.incl meta
        peer.updateScore(PeerScoreGoodBatchValue)

    if meta.parent != nil:
      if meta.parent.isUnviable:
        debug "Received block builds on unviable parent",
          receivedSlot = meta.bid.slot, parentSlot = meta.parent.bid.slot,
          bid = meta.bid, numBranchBlocks = peerChain.len,
          peer, peer_score = peer.getScore()
        meta.isUnviable = true
        break
      if meta.bid.slot <= meta.parent.bid.slot:
        # Slot check has to be re-done as parent slot may have been lowered
        debug "Received block is more recent than its parent",
          receivedSlot = meta.bid.slot, parentSlot = meta.parent.bid.slot,
          bid = meta.bid, numBranchBlocks = peerChain.len,
          peer, peer_score = peer.getScore()
        meta.isUnviable = true
        break

    peerChain.addFirst meta
    meta = meta.parent

  if meta != nil:  # Early exit
    if meta.isUnviable:
      peer.updateScore(PeerScoreUnviableFork)
      debug "Received block is unviable",
        bid = meta.bid, numBranchBlocks = peerChain.len,
        peer, peer_score = peer.getScore()
      while peerChain.len > 0:
        meta = peerChain.popFirst()
        meta.isUnviable = true
    return

  if peerChain.len == 0:
    peer.updateScore(PeerScoreUseless)
    debug "Peer has no blocks of interest",
      peer, peer_score = peer.getScore()
    return

  # Metadata is available, fetch blocks and apply them in order
  while peerChain.len > 0:
    meta = peerChain.popFirst()

    while true:
      if self.isBlockKnown(meta.bid.root):
        debug "Branch from peer no longer unknown",
          bid = meta.bid, numBranchBlocks = peerChain.len,
          peer, peer_score = peer.getScore()
        break
      if peer.getScore() < PeerScoreLowLimit:
        debug "Failed to fetch branch from peer",
          bid = meta.bid, numBranchBlocks = peerChain.len,
          peer, peer_score = peer.getScore()
        return
      let
        blck = (await peer.getKnownBlock(meta.bid.root)).valueOr:
          continue
        numBlobs = withBlck(blck[]):
          when consensusFork >= ConsensusFork.Deneb:
            forkyBlck.message.body.blob_kzg_commitments.len
          else:
            0
        blobs = (await peer.getBlobSidecarsForKnownBlock(
            meta.bid.root, numBlobs)).valueOr:
          continue
      if self.isBlockKnown(meta.bid.root):
        debug "Branch from peer asynchronously became known",
          bid = meta.bid, numBranchBlocks = peerChain.len,
          peer, peer_score = peer.getScore()
        break
      let err = (await self.blockVerifier(blck[], blobs)).errorOr:
        peer.updateScore(PeerScoreGoodValues)
        beacon_sync_branchdiscovery_discovered_blocks.inc()
        info "Discovered new branch from peer",
          bid = meta.bid, numBranchBlocks = peerChain.len,
          peer, peer_score = peer.getScore()
        break
      case err
      of BlockVerifierError.InvalidProposerSignature:
        peer.updateScore(PeerScoreBadResponse)
        debug "Received block with invalid proposer signature",
          bid = meta.bid, numBranchBlocks = peerChain.len,
          peer, peer_score = peer.getScore()
      of BlockVerifierError.Invalid, BlockVerifierError.UnviableBranch:
        if err == BlockVerifierError.Invalid:
          peer.updateScore(PeerScoreBadResponse)
          debug "Received invalid block",
            bid = meta.bid, numBranchBlocks = peerChain.len,
            peer, peer_score = peer.getScore()
        else:
          peer.updateScore(PeerScoreUnviableFork)
          debug "Received unviable block",
            bid = meta.bid, numBranchBlocks = peerChain.len,
            peer, peer_score = peer.getScore()
        meta.isUnviable = true
        while peerChain.len > 0:
          meta = peerChain.popFirst()
          meta.isUnviable = true
        return
      of BlockVerifierError.Duplicate:
        debug "Received duplicate block",
          bid = meta.bid, numBranchBlocks = peerChain.len,
          peer, peer_score = peer.getScore()
        break

proc prune(self: var BranchDiscovery) =
  let finalizedSlot = self.getFinalizedSlot()
  var toDelete: seq[KeyedBlockMeta]
  for key in self.blockMetas:
    if key.data.parent != nil and key.data.parent.bid.slot <= finalizedSlot:
      key.data.parent = nil
    if key.data.bid.slot <= finalizedSlot:
      toDelete.add key
  for key in toDelete:
    self.blockMetas.excl key
  if toDelete.len > 0:
    debug "Pruned pending branches",
      numDeleted = toDelete.len, numMetas = self.blockMetas.len
  beacon_sync_branchdiscovery_pending.set(self.blockMetas.len.int64)

proc loop(self: ref BranchDiscovery) {.async: (raises: []).} =
  try:
    while true:
      await self[].isActive.wait()

      const pollInterval = chronos.seconds(2)
      await sleepAsync(pollInterval)

      let peer =
        if self[].peerQueue.len > 0:
          self[].peerQueue.popFirst()
        else:
          try:
            self[].pool.acquireNoWait()
          except PeerPoolError as exc:
            debug "Failed to acquire peer", exc = exc.msg
            continue
      defer: self[].pool.release(peer)

      await self.discoverBranch(peer)

      self[].prune()
  except CancelledError:
    self[].blockMetas.reset()

func state*(self: ref BranchDiscovery): BranchDiscoveryState =
  if self[].loopFuture == nil:
    BranchDiscoveryState.Stopped
  elif not self[].isActive.isSet:
    BranchDiscoveryState.Suspended
  else:
    BranchDiscoveryState.Active

proc clearPeerQueue(self: ref BranchDiscovery) =
  while self[].peerQueue.len > 0:
    let peer = self[].peerQueue.popLast()
    self[].pool.release(peer)

proc start*(self: ref BranchDiscovery) =
  doAssert self[].loopFuture == nil
  info "Starting discovery of new branches"
  self[].loopFuture = self.loop()
  beacon_sync_branchdiscovery_state.set(self.state.ord().int64)

proc stop*(self: ref BranchDiscovery) {.async: (raises: []).} =
  if self[].loopFuture != nil:
    info "Stopping discovery of new branches"
    await self[].loopFuture.cancelAndWait()
    self[].loopFuture = nil
    beacon_sync_branchdiscovery_state.set(self.state.ord().int64)
    self.clearPeerQueue()

proc suspend*(self: ref BranchDiscovery) =
  self[].isActive.clear()
  beacon_sync_branchdiscovery_state.set(self.state.ord().int64)
  self.clearPeerQueue()

proc resume*(self: ref BranchDiscovery) =
  self[].isActive.fire()
  beacon_sync_branchdiscovery_state.set(self.state.ord().int64)

proc transferOwnership*[A, B](self: ref BranchDiscovery[A, B], peer: A) =
  const maxPeersInQueue = 10
  if self.state != BranchDiscoveryState.Active or
      self[].peerQueue.len >= maxPeersInQueue or
      peer.getHeadSlot() <= self[].getFinalizedSlot() or
      self[].isBlockKnown(peer.getHeadRoot()):
    self[].pool.release(peer)
    return

  debug "Peer transferred to branch discovery",
    peer, peer_score = peer.getScore()
  self[].peerQueue.addLast(peer)
