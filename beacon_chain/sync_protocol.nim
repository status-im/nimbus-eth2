import
  options, tables, sequtils, algorithm, sets, macros,
  chronicles, chronos, stew/ranges/bitranges,
  spec/[datatypes, crypto, digest, helpers], eth/rlp,
  beacon_node_types, eth2_network, beacon_chain_db, block_pool, time, ssz

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
    networkId*: uint8
    chainId*: uint64
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

p2pProtocol BeaconSync(version = 1,
                       shortName = "bcs",
                       networkState = BeaconSyncState):

  onPeerConnected do (peer: Peer):
    let
      protocolVersion = 1 # TODO: Spec doesn't specify this yet
      node = peer.networkState.node
      networkId = peer.networkState.networkId
      chainId = peer.networkState.networkId
      blockPool = node.blockPool
      finalizedHead = blockPool.finalizedHead
      headBlock = blockPool.head.blck
      bestRoot = headBlock.root
      bestSlot = headBlock.slot
      latestFinalizedEpoch = finalizedHead.slot.compute_epoch_of_slot()

    let m = await peer.hello(networkId, chainId, finalizedHead.blck.root,
                             latestFinalizedEpoch, bestRoot, bestSlot,
                             timeout = 10.seconds)

    if m.networkId != networkId:
      await peer.disconnect(IrrelevantNetwork)
      return

    # TODO: onPeerConnected runs unconditionally for every connected peer, but we
    # don't need to sync with everybody. The beacon node should detect a situation
    # where it needs to sync and it should execute the sync algorithm with a certain
    # number of randomly selected peers. The algorithm itself must be extracted in a proc.
    try:
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
          let blocks = await peer.getBeaconBlocks(bestRoot, s, min(headersLeft, MaxHeadersToRequest), 0, false)
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

  handshake:
    proc hello(
            peer: Peer,
            networkId: uint8,
            chainId: uint64,
            latestFinalizedRoot: Eth2Digest,
            latestFinalizedEpoch: Epoch,
            bestRoot: Eth2Digest,
            bestSlot: Slot)

  proc goodbye(peer: Peer, reason: DisconnectionReason)

  nextId 10

  requestResponse:
    proc getBeaconBlockRoots(
            peer: Peer,
            fromSlot: Slot,
            maxRoots: uint64) =
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

    proc beaconBlockRoots(peer: Peer, roots: openarray[BlockRootSlot])

  requestResponse:
    proc getBeaconBlockHeaders(
            peer: Peer,
            blockRoot: Eth2Digest,
            slot: Slot,
            maxHeaders: uint64,
            skipSlots: uint64,
            backward: bool) =
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

    proc beaconBlockHeaders(peer: Peer, blockHeaders: openarray[BeaconBlockHeader])

  requestResponse:
    proc getBeaconBlockBodies(
            peer: Peer,
            blockRoots: openarray[Eth2Digest]) =
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
  ## Retrieve block headers and block bodies from the remote peer, merge them into blocks.
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
