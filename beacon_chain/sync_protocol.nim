import
  options, tables, sequtils, algorithm, sets, macros,
  chronicles, chronos, metrics, stew/ranges/bitranges,
  spec/[datatypes, crypto, digest, helpers], eth/rlp,
  beacon_node_types, eth2_network, beacon_chain_db, block_pool, time, ssz

when networkBackend == rlpxBackend:
  import eth/rlp/options as rlpOptions
  template libp2pProtocol*(name: string, version: int) {.pragma.}

declareGauge libp2p_peers, "Number of libp2p peers"

type
  ValidatorSetDeltaFlags {.pure.} = enum
    Activation = 0
    Exit = 1

  ValidatorChangeLogEntry* = object
    case kind*: ValidatorSetDeltaFlags
    of Activation:
      pubkey: ValidatorPubKey
    else:
      index: uint32

  ValidatorSet = seq[Validator]

  BeaconSyncState* = ref object
    node*: BeaconNode
    db*: BeaconChainDB

  BlockRootSlot* = object
    blockRoot: Eth2Digest
    slot: Slot

const
  MaxRootsToRequest = 512'u64
  MaxHeadersToRequest = MaxRootsToRequest
  MaxAncestorBlocksResponse = 256

func toHeader(b: BeaconBlock): BeaconBlockHeader =
  BeaconBlockHeader(
    slot: b.slot,
    parent_root: b.parent_root,
    state_root: b.state_root,
    body_root: hash_tree_root(b.body),
    signature: b.signature
  )

proc fromHeaderAndBody(b: var BeaconBlock, h: BeaconBlockHeader, body: BeaconBlockBody) =
  doAssert(hash_tree_root(body) == h.body_root)
  b.slot = h.slot
  b.parent_root = h.parent_root
  b.state_root = h.state_root
  b.body = body
  b.signature = h.signature

proc importBlocks(node: BeaconNode,
                  blocks: openarray[BeaconBlock]) =
  for blk in blocks:
    node.onBeaconBlock(node, blk)
  info "Forward sync imported blocks", len = blocks.len

proc mergeBlockHeadersAndBodies(headers: openarray[BeaconBlockHeader], bodies: openarray[BeaconBlockBody]): Option[seq[BeaconBlock]] =
  if bodies.len != headers.len:
    info "Cannot merge bodies and headers. Length mismatch.", bodies = bodies.len, headers = headers.len
    return

  var res: seq[BeaconBlock]
  for i in 0 ..< headers.len:
    if hash_tree_root(bodies[i]) != headers[i].body_root:
      info "Block body is wrong for header"
      return

    res.setLen(res.len + 1)
    res[^1].fromHeaderAndBody(headers[i], bodies[i])
  some(res)

proc getBeaconBlocks*(peer: Peer,
                      blockRoot: Eth2Digest,
                      slot: Slot,
                      maxBlocks, skipSlots: uint64,
                      backward: bool): Future[Option[seq[BeaconBlock]]] {.gcsafe, async.}

proc getBeaconBlocksSpec*(peer: Peer, blockRoot: Eth2Digest,
                          slot: Slot, maxBlocks, skipSlots: uint64,
             backward: bool): Future[Option[seq[BeaconBlock]]] {.gcsafe, async.}

p2pProtocol BeaconSync(version = 1,
                       rlpxName = "bcs",
                       networkState = BeaconSyncState):

  onPeerConnected do (peer: Peer):
    let
      protocolVersion = 1 # TODO: Spec doesn't specify this yet
      node = peer.networkState.node
      blockPool = node.blockPool
      finalizedHead = blockPool.finalizedHead
      headBlock = blockPool.head.blck
      bestRoot = headBlock.root
      bestSlot = headBlock.slot
      latestFinalizedEpoch = finalizedHead.slot.compute_epoch_of_slot()

    let handshakeFut = peer.hello(node.forkVersion,
                                  finalizedHead.blck.root, latestFinalizedEpoch,
                                  bestRoot, bestSlot, timeout = 10.seconds)
    let m = await handshakeFut

    if m.forkVersion != node.forkVersion:
      await peer.disconnect(IrrelevantNetwork)
      return

    # TODO: onPeerConnected runs unconditionally for every connected peer, but we
    # don't need to sync with everybody. The beacon node should detect a situation
    # where it needs to sync and it should execute the sync algorithm with a certain
    # number of randomly selected peers. The algorithm itself must be extracted in a proc.
    try:
      libp2p_peers.set peer.network.peers.len.int64
      debug "Peer connected. Initiating sync", peer, bestSlot, remoteBestSlot = m.bestSlot

      let bestDiff = cmp((latestFinalizedEpoch, bestSlot), (m.latestFinalizedEpoch, m.bestSlot))
      if bestDiff >= 0:
        # Nothing to do?
        debug "Nothing to sync", peer
      else:
        # TODO: Check for WEAK_SUBJECTIVITY_PERIOD difference and terminate the
        # connection if it's too big.

        var s = bestSlot + 1
        while s <= m.bestSlot:
          debug "Waiting for block headers", fromPeer = peer, remoteBestSlot = m.bestSlot, peer
          let headersLeft = uint64(m.bestSlot - s)
          let blocks = await peer.getBeaconBlocksSpec(bestRoot, s, min(headersLeft, MaxHeadersToRequest), 0, false)
          if blocks.isSome:
            if blocks.get.len == 0:
              info "Got 0 blocks while syncing", peer
              break
            node.importBlocks(blocks.get)
            let lastSlot = blocks.get[^1].slot
            if lastSlot <= s:
              info "Slot did not advance during sync", peer
              break

            s = lastSlot + 1
          else:
            break

    except CatchableError:
      warn "Failed to sync with peer", peer, err = getCurrentExceptionMsg()

  onPeerDisconnected do (peer: Peer):
    libp2p_peers.set peer.network.peers.len.int64

  handshake:
    proc hello(
            peer: Peer,
            fork_version: array[4, byte],
            latestFinalizedRoot: Eth2Digest,
            latestFinalizedEpoch: Epoch,
            bestRoot: Eth2Digest,
            bestSlot: Slot) {.
            libp2pProtocol("/eth2/beacon_chain/req/hello", 1).}

  proc goodbye(
            peer: Peer,
            reason: DisconnectionReason) {.
            libp2pProtocol("/eth2/beacon_chain/req/goodbye", 1).}

  requestResponse:
    proc getBeaconBlocksReq(
            peer: Peer,
            headBlockRoot: Eth2Digest,
            start_slot: uint64,
            count: uint64,
            step: uint64) {.
            libp2pProtocol("/eth2/beacon_chain/req/beacon_blocks", 1).} =
      ## TODO: procedure was renamed from `getBeaconBlocks()` to
      ## `getBeaconBlocksReq()`, because `getBeaconBlocks()` already exists.
      var blocks: seq[BeaconBlock]
      # `step == 0` has no sense, so we will return empty array of blocks.
      # `count == 0` means that empty array of blocks requested.
      #
      # Current version of network specification do not cover case when
      # `start_slot` is empty, in such case we will return next available slot
      # which is follows `start_slot + step` sequence. For example for, if
      # `start_slot` is 2 and `step` is 2 and slots 2, 4, 6 are not available,
      # then [8, 10, ...] will be returned.
      if step > 0'u64 and count > 0'u64:
        let pool = peer.networkState.node.blockPool
        var blck = pool.getRef(headBlockRoot)
        var slot = start_slot
        while not(isNil(blck)):
          if blck.slot == slot:
            blocks.add(pool.get(blck).data)
            slot = slot + step
          elif blck.slot > slot:
            if (blck.slot - slot) mod step == 0:
              blocks.add(pool.get(blck).data)
            slot = slot + ((blck.slot - slot) div step + 1) * step
          if uint64(len(blocks)) == count:
            break
          blck = blck.parent

      await response.send(blocks)

    proc getRecentBeaconBlocks(
            peer: Peer,
            blockRoots: openarray[Eth2Digest]) {.
            libp2pProtocol("/eth2/beacon_chain/req/recent_beacon_blocks", 1).} =
      let pool = peer.networkState.node.blockPool
      var blocks = newSeq[BeaconBlock](len(blockRoots))

      var index = 0
      for root in blockRoots:
        let blockRef = pool.getRef(root)
        if not(isNil(blockRef)):
          blocks[index] = pool.get(blockRef).data
        inc(index)

      await response.send(blocks)

    proc beaconBlocks(
            peer: Peer,
            blocks: openarray[BeaconBlock])

  requestResponse:
    proc getBeaconBlockRoots(
            peer: Peer,
            fromSlot: Slot,
            maxRoots: uint64) {.
            libp2pProtocol("/eth2/beacon_chain/req/beacon_block_roots", 1).} =
      let maxRoots = min(MaxRootsToRequest, maxRoots)
      var s = fromSlot
      var roots = newSeqOfCap[BlockRootSlot](maxRoots)
      let blockPool = peer.networkState.node.blockPool
      let maxSlot = blockPool.head.blck.slot
      while s <= maxSlot:
        for r in blockPool.blockRootsForSlot(s):
          roots.add BlockRootSlot(blockRoot: r, slot: s)
          if roots.len == maxRoots.int: break
        s += 1
      await response.send(roots)

    proc beaconBlockRoots(
            peer: Peer,
            roots: openarray[BlockRootSlot])

  requestResponse:
    proc getBeaconBlockHeaders(
            peer: Peer,
            blockRoot: Eth2Digest,
            slot: Slot,
            maxHeaders: uint64,
            skipSlots: uint64,
            backward: bool) {.
            libp2pProtocol("/eth2/beacon_chain/req/beacon_block_headers", 1).} =
      let maxHeaders = min(MaxHeadersToRequest, maxHeaders)
      var headers: seq[BeaconBlockHeader]
      let db = peer.networkState.db

      if backward:
        # TODO: implement skipSlots

        var blockRoot = blockRoot
        if slot != GENESIS_SLOT:
          # TODO: Get block from the best chain by slot
          # blockRoot = ...
          discard

        let blockPool = peer.networkState.node.blockPool
        var br = blockPool.getRef(blockRoot)
        var blockRefs = newSeqOfCap[BlockRef](maxHeaders)

        while not br.isNil:
          blockRefs.add(br)
          if blockRefs.len == maxHeaders.int:
            break
          br = br.parent

        headers = newSeqOfCap[BeaconBlockHeader](blockRefs.len)
        for i in blockRefs.high .. 0:
          headers.add(blockPool.get(blockRefs[i]).data.toHeader)
      else:
        # TODO: This branch has to be revisited and possibly somehow merged with the
        # branch above once we can traverse the best chain forward
        # TODO: implement skipSlots
        headers = newSeqOfCap[BeaconBlockHeader](maxHeaders)
        var s = slot
        let blockPool = peer.networkState.node.blockPool
        let maxSlot = blockPool.head.blck.slot
        while s <= maxSlot:
          for r in blockPool.blockRootsForSlot(s):
            headers.add(db.getBlock(r).get().toHeader)
            if headers.len == maxHeaders.int: break
          s += 1

      await response.send(headers)

    proc beaconBlockHeaders(
            peer: Peer,
            blockHeaders: openarray[BeaconBlockHeader])

  # TODO move this at the bottom, because it's not in the spec yet, but it will
  # consume a `method_id`
  requestResponse:
    proc getAncestorBlocks(
            peer: Peer,
            needed: openarray[FetchRecord]) {.
            libp2pProtocol("/eth2/beacon_chain/req/ancestor_blocks", 1).} =
      var resp = newSeqOfCap[BeaconBlock](needed.len)
      let db = peer.networkState.db
      var neededRoots = initSet[Eth2Digest]()
      for rec in needed: neededRoots.incl(rec.root)

      for rec in needed:
        if (var blck = db.getBlock(rec.root); blck.isSome()):
          # TODO validate historySlots
          let firstSlot = blck.get().slot - rec.historySlots

          for i in 0..<rec.historySlots.int:
            resp.add(blck.get())
            if resp.len >= MaxAncestorBlocksResponse:
              break

            if blck.get().parent_root in neededRoots:
              # Don't send duplicate blocks, if neededRoots has roots that are
              # in the same chain
              break

            if (blck = db.getBlock(blck.get().parent_root);
                blck.isNone() or blck.get().slot < firstSlot):
              break

          if resp.len >= MaxAncestorBlocksResponse:
            break

      await response.send(resp)

    proc ancestorBlocks(
            peer: Peer,
            blocks: openarray[BeaconBlock])

  requestResponse:
    proc getBeaconBlockBodies(
            peer: Peer,
            blockRoots: openarray[Eth2Digest]) {.
            libp2pProtocol("/eth2/beacon_chain/req/beacon_block_bodies", 1).} =
      # TODO: Validate blockRoots.len
      var bodies = newSeqOfCap[BeaconBlockBody](blockRoots.len)
      let db = peer.networkState.db
      for r in blockRoots:
        if (let blk = db.getBlock(r); blk.isSome):
          bodies.add(blk.get().body)
        else:
          bodies.setLen(bodies.len + 1) # According to wire spec. Pad with zero body.
      await response.send(bodies)

    proc beaconBlockBodies(
            peer: Peer,
            blockBodies: openarray[BeaconBlockBody])

proc getBeaconBlocks*(peer: Peer,
                      blockRoot: Eth2Digest,
                      slot: Slot,
                      maxBlocks, skipSlots: uint64,
                      backward: bool): Future[Option[seq[BeaconBlock]]] {.async.} =
  ## Retrieve block headers and block bodies from the remote peer,
  ## merge them into blocks.
  assert(maxBlocks <= MaxHeadersToRequest)
  let headersResp = await peer.getBeaconBlockHeaders(blockRoot, slot, maxBlocks, skipSlots, backward)
  if headersResp.isNone: return

  let headers = headersResp.get.blockHeaders
  if headers.len == 0:
    info "Peer has no headers", peer
    var res: seq[BeaconBlock]
    return some(res)

  let bodiesRequest = headers.mapIt(signing_root(it))

  debug "Block headers received. Requesting block bodies", peer
  let bodiesResp = await peer.getBeaconBlockBodies(bodiesRequest)
  if bodiesResp.isNone:
    info "Did not receive bodies", peer
    return

  result = mergeBlockHeadersAndBodies(headers, bodiesResp.get.blockBodies)
  # If result.isNone: disconnect with BreachOfProtocol?

proc getBeaconBlocksSpec*(peer: Peer, blockRoot: Eth2Digest, slot: Slot,
                          maxBlocks, skipSlots: uint64,
                   backward: bool): Future[Option[seq[BeaconBlock]]] {.async.} =
  ## Retrieve blocks from the remote peer, according to new network
  ## specification.
  doAssert(maxBlocks <= MaxHeadersToRequest)
  var startSlot = uint64(slot) + skipSlots
  var blocksResp = await peer.getBeaconBlocksReq(blockRoot, startSlot,
                                                 maxBlocks, 1'u64)
  let blocks = blocksResp.get.blocks
  info "Peer returned blocks", peer, count = len(blocks)
  result = some(blocks)
