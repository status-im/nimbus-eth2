# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
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
# Further improvements should be applied:
#
# 1. Progress is currently limited by the size of `block_quarantine` per cycle,
#    as this module downloads in backward order into the quarantine before the
#    results get applied in forward order. This further limits the concurrency
#    to a single peer at a time, because there is only a single quarantine that
#    can hold a pending branch history.
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
  std/[algorithm, deques],
  chronos, chronicles, metrics, results,
  ../spec/[forks, network],
  ../consensus_object_pools/block_pools_types,
  ../networking/[eth2_network, peer_pool],
  ./sync_protocol

logScope:
  topics = "branchdiscovery"

declareGauge beacon_sync_branchdiscovery_state,
  "Branch discovery module operating state"

declareCounter beacon_sync_branchdiscovery_discovered_blocks,
  "Number of beacon blocks discovered by the branch discovery module"

type
  BranchDiscoveryState* {.pure.} = enum
    Stopped,
    Suspended,
    Active

  GetSlotCallback* =
    proc(): Slot {.gcsafe, raises: [].}

  IsBlockKnownCallback* =
    proc(blockRoot: Eth2Digest): bool {.gcsafe, raises: [].}

  BlockVerifierCallback* = proc(
      signedBlock: ForkedSignedBeaconBlock,
      blobs: Opt[BlobSidecars]
  ): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).}

  BranchDiscovery*[A, B] = object
    pool: PeerPool[A, B]
    getFinalizedSlot: GetSlotCallback
    isBlockKnown: IsBlockKnownCallback
    blockVerifier: BlockVerifierCallback
    isActive: AsyncEvent
    loopFuture: Future[void].Raising([])
    peerQueue: Deque[A]

proc new*[A, B](
    T: type BranchDiscovery[A, B],
    pool: PeerPool[A, B],
    getFinalizedSlot: GetSlotCallback,
    isBlockKnown: IsBlockKnownCallback,
    blockVerifier: BlockVerifierCallback): ref BranchDiscovery[A, B] =
  let self = (ref BranchDiscovery[A, B])(
    pool: pool,
    getFinalizedSlot: getFinalizedSlot,
    isBlockKnown: isBlockKnown,
    blockVerifier: blockVerifier,
    isActive: newAsyncEvent())
  self[].isActive.fire()
  self

proc discoverBranch[A, B](
    self: BranchDiscovery[A, B],
    peer: A) {.async: (raises: [CancelledError]).} =
  logScope:
    peer
    peer_score = peer.getScore()

  let oldPeerHeadSlot = peer.getHeadSlot()
  if Moment.now() - peer.getStatusLastTime() >= StatusExpirationTime:
    if not(await peer.updateStatus()):
      peer.updateScore(PeerScoreNoStatus)
      debug "Failed to update status"
      return
  let peerHeadSlot = peer.getHeadSlot()
  if peerHeadSlot != oldPeerHeadSlot:
    peer.updateScore(PeerScoreGoodStatus)
    debug "Peer has synced to a new head", oldPeerHeadSlot, peerHeadSlot

  let finalizedSlot = self.getFinalizedSlot()
  if peerHeadSlot <= finalizedSlot:
    # This peer can sync from different peers, it is useless to us at this time
    peer.updateScore(PeerScoreUseless)
    debug "Peer's head slot is already finalized", peerHeadSlot, finalizedSlot
    return

  var blockRoot = peer.getHeadRoot()
  logScope: blockRoot
  if self.isBlockKnown(blockRoot):
    # This peer may be actively syncing from us, only descore if no disconnect
    if peer.getScore() >= PeerScoreLowLimit - PeerScoreUseless:
      peer.updateScore(PeerScoreUseless)
    debug "Peer's head block root is already known"
    return

  # Many peers disconnect on rate limit, we have to avoid getting hit by it
  # to have a chance in picking up branches that don't have good propagation
  const
    maxRequestsPerBurst = 15
    burstDuration = chronos.seconds(30)
  let bucket = TokenBucket.new(maxRequestsPerBurst, burstDuration)
  template consumeTokens(numTokens: int) =
    try:
      await bucket.consume(numTokens)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      raiseAssert "TokenBucket.consume should not fail: " & $exc.msg

  var parentSlot = peerHeadSlot + 1
  logScope: parentSlot
  while true:
    if self.isBlockKnown(blockRoot):
      debug "Branch from peer no longer unknown"
      return
    if peer.getScore() < PeerScoreLowLimit:
      debug "Failed to discover new branch from peer"
      return

    debug "Discovering new branch from peer"
    consumeTokens(1)
    let rsp = await peer.beaconBlocksByRoot_v2(BlockRootsList @[blockRoot])
    if rsp.isErr:
      # `eth2_network` already descored according to the specific error
      debug "Failed to receive block", err = rsp.error
      consumeTokens(5)
      continue
    template blocks: untyped = rsp.get

    # The peer was the one providing us with this block root, it should exist
    if blocks.len == 0:
      peer.updateScore(PeerScoreNoValues)
      debug "Received no blocks", numBlocks = blocks.len
      consumeTokens(5)
      continue
    if blocks.len > 1:
      peer.updateScore(PeerScoreBadResponse)
      debug "Received too many blocks", numBlocks = blocks.len
      return
    template blck: untyped = blocks[0][]
    if blck.slot >= parentSlot:
      peer.updateScore(PeerScoreBadResponse)
      debug "Received block older than parent", receivedSlot = blck.slot
      return
    if blck.root != blockRoot:
      peer.updateScore(PeerScoreBadResponse)
      debug "Received incorrect block", receivedRoot = blck.root
      return

    var blobIds: seq[BlobIdentifier]
    withBlck(blck):
      when consensusFork >= ConsensusFork.Deneb:
        for i in 0 ..< forkyBlck.message.body.blob_kzg_commitments.len:
          blobIds.add BlobIdentifier(block_root: blockRoot, index: i.BlobIndex)
    var blobs: Opt[BlobSidecars]
    if blobIds.len > 0:
      while true:
        if self.isBlockKnown(blockRoot):
          debug "Branch from peer no longer unknown"
          return
        if peer.getScore() < PeerScoreLowLimit:
          debug "Failed to discover new branch from peer"
          return

        consumeTokens(1)
        let r = await peer.blobSidecarsByRoot(BlobIdentifierList blobIds)
        if r.isErr:
          # `eth2_network` already descored according to the specific error
          debug "Failed to receive blobs", err = r.error
          consumeTokens(5)
          continue
        template blobSidecars: untyped = r.unsafeGet

        if blobSidecars.len < blobIds.len:
          peer.updateScore(PeerScoreMissingValues)
          debug "Received not all blobs",
            numBlobs = blobSidecars.len, expectedNumBlobs = blobIds.len
          consumeTokens(5)
          continue
        if blobSidecars.len > blobIds.len:
          peer.updateScore(PeerScoreBadResponse)
          debug "Received too many blobs",
            numBlobs = blobSidecars.len, expectedNumBlobs = blobIds.len
          return
        for i, blobSidecar in blobSidecars:
          let root = hash_tree_root(blobSidecar[].signed_block_header.message)
          if root != blockRoot:
            peer.updateScore(PeerScoreBadResponse)
            debug "Received unexpected blob"
            return
          blobSidecar[].verify_blob_sidecar_inclusion_proof().isOkOr:
            peer.updateScore(PeerScoreBadResponse)
            debug "Received invalid blob"
            return
        blobs = Opt.some distinctBase(blobSidecars).sortedByIt(it.index)
        for i, blobSidecar in blobs.get:
          if blobSidecar[].index != i.BlobIndex:
            peer.updateScore(PeerScoreBadResponse)
            debug "Received duplicate blobs while others are missing"
            return
        break

    let err = (await self.blockVerifier(blck, blobs)).errorOr:
      peer.updateScore(PeerScoreGoodBatchValue + PeerScoreGoodValues)
      beacon_sync_branchdiscovery_discovered_blocks.inc()
      info "Discovered new branch from peer"
      break
    case err
    of VerifierError.Invalid:
      peer.updateScore(PeerScoreBadResponse)
      debug "Received invalid block"
      return
    of VerifierError.UnviableFork:
      peer.updateScore(PeerScoreUnviableFork)
      debug "Received unviable block"
      return
    of VerifierError.Duplicate:
      peer.updateScore(PeerScoreGoodValues)
      debug "Connected new branch from peer"
      break
    of VerifierError.MissingParent:
      peer.updateScore(PeerScoreGoodBatchValue)
      parentSlot = blck.slot
      blockRoot = blck.getForkedBlockField(parent_root)
      continue

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

      await self[].discoverBranch(peer)
  except CancelledError:
    return

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
