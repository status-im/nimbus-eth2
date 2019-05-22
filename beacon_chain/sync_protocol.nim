import
  options, tables, sequtils, algorithm,
  chronicles, chronos, ranges/bitranges,
  spec/[datatypes, crypto, digest, helpers], eth/rlp,
  beacon_node_types, eth2_network, beacon_chain_db, block_pool, time, ssz

from beacon_node import onBeaconBlock
  # Careful handling of beacon_node <-> sync_protocol
  # to avoid recursive dependencies

type
  ValidatorChangeLogEntry* = object
    case kind*: ValidatorSetDeltaFlags
    of Activation:
      pubkey: ValidatorPubKey
    else:
      index: uint32

  ValidatorSet = seq[Validator]

  BeaconSyncState* = ref object
    networkId*: uint64
    node*: BeaconNode
    db*: BeaconChainDB

const
  MaxRootsToRequest = 512
  MaxHeadersToRequest = MaxRootsToRequest
  MaxAncestorBlocksResponse = 256

func toHeader(b: BeaconBlock): BeaconBlockHeaderRLP =
  BeaconBlockHeaderRLP(
    slot: b.slot.uint64,
    parent_root: b.previous_block_root,
    state_root: b.state_root,
    randao_reveal: b.body.randao_reveal,
    eth1_data : b.body.eth1_data,
    signature: b.signature,
    body: hash_tree_root(b.body)
  )

proc fromHeaderAndBody(b: var BeaconBlock, h: BeaconBlockHeaderRLP, body: BeaconBlockBody) =
  doAssert(hash_tree_root(body) == h.body)
  b.slot = h.slot.Slot
  b.previous_block_root = h.parent_root
  b.state_root = h.state_root
  b.body.randao_reveal = h.randao_reveal
  b.body.eth1_data = h.eth1_data
  b.signature = h.signature
  b.body = body

proc importBlocks(node: BeaconNode,
                  blocks: openarray[BeaconBlock]) =
  for blk in blocks:
    node.onBeaconBlock(blk)
  info "Forward sync imported blocks", len = blocks.len

proc mergeBlockHeadersAndBodies(headers: openarray[BeaconBlockHeaderRLP], bodies: openarray[BeaconBlockBody]): Option[seq[BeaconBlock]] =
  if bodies.len != headers.len:
    info "Cannot merge bodies and headers. Length mismatch.", bodies = bodies.len, headers = headers.len
    return

  var res: seq[BeaconBlock]
  for i in 0 ..< headers.len:
    if hash_tree_root(bodies[i]) != headers[i].body:
      info "Block body is wrong for header"
      return

    res.setLen(res.len + 1)
    res[^1].fromHeaderAndBody(headers[i], bodies[i])
  some(res)

proc getBeaconBlocks*(peer: Peer, blockRoot: Eth2Digest, slot: Slot, maxBlocks, skipSlots: int, backward: uint8): Future[Option[seq[BeaconBlock]]] {.gcsafe, async.}


p2pProtocol BeaconSync(version = 1,
                       shortName = "bcs",
                       networkState = BeaconSyncState):

  onPeerConnected do(peer: Peer):
    let
      protocolVersion = 1 # TODO: Spec doesn't specify this yet
      node = peer.networkState.node
      networkId = peer.networkState.networkId
      blockPool = node.blockPool
      finalizedHead = blockPool.finalizedHead
      headBlock = blockPool.head.blck
      bestRoot = headBlock.root
      bestSlot = headBlock.slot
      latestFinalizedEpoch = finalizedHead.slot.slot_to_epoch()

    let m = await handshake(peer, timeout = 10.seconds,
                            status(networkId, finalizedHead.blck.root,
                                   latestFinalizedEpoch, bestRoot, bestSlot))

    if m.networkId != networkId:
      await peer.disconnect(UselessPeer)
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
        trace "Nothing to sync", peer = peer.remote
      else:
        # TODO: Check for WEAK_SUBJECTIVITY_PERIOD difference and terminate the
        # connection if it's too big.

        var s = bestSlot + 1
        while s <= m.bestSlot:
          debug "Waiting for block headers", fromPeer = peer, remoteBestSlot = m.bestSlot, peer
          let headersLeft = int(m.bestSlot - s)
          let blocks = await peer.getBeaconBlocks(bestRoot, s, min(headersLeft, MaxHeadersToRequest), 0, 0)
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

  proc status(
            peer: Peer,
            networkId: uint64,
            latestFinalizedRoot: Eth2Digest,
            latestFinalizedEpoch: Epoch,
            bestRoot: Eth2Digest,
            bestSlot: Slot) {.libp2pProtocol("hello", "1.0.0").}

  requestResponse:
    proc getBeaconBlockRoots(peer: Peer, fromSlot: Slot, maxRoots: int) =
      let maxRoots = min(MaxRootsToRequest, maxRoots)
      var s = fromSlot
      var roots = newSeqOfCap[(Eth2Digest, Slot)](maxRoots)
      let blockPool = peer.networkState.node.blockPool
      let maxSlot = blockPool.head.blck.slot
      while s <= maxSlot:
        for r in blockPool.blockRootsForSlot(s):
          roots.add((r, s))
          if roots.len == maxRoots: break
        s += 1
      await response.send(roots)

    proc beaconBlockRoots(peer: Peer, roots: openarray[(Eth2Digest, Slot)])

  requestResponse:
    proc getBeaconBlockHeaders(
            peer: Peer,
            blockRoot: Eth2Digest,
            slot: Slot,
            maxHeaders: int,
            skipSlots: int,
            backward: uint8) {.libp2pProtocol("rpc/beacon_block_headers", "1.0.0").} =
      let maxHeaders = min(MaxHeadersToRequest, maxHeaders)
      var headers = newSeqOfCap[BeaconBlockHeaderRLP](maxHeaders)
      let db = peer.networkState.db

      if backward != 0:
        # TODO: implement skipSlots

        var blockRoot = blockRoot
        if slot != GENESIS_SLOT:
          # TODO: Get block from the best chain by slot
          # blockRoot = ...
          discard

        while true:
          if (let b = db.getBlock(blockRoot); b.isSome):
            headers.add(b.get().toHeader)
            blockRoot = headers[^1].parent_root
            if headers.len == maxHeaders:
              break
          else:
            break
        headers.reverse()
      else:
        # TODO: This branch has to be revisited and possibly somehow merged with the
        # branch above once we can traverse the best chain forward
        # TODO: implement skipSlots
        var s = slot
        let blockPool = peer.networkState.node.blockPool
        let maxSlot = blockPool.head.blck.slot
        while s <= maxSlot:
          for r in blockPool.blockRootsForSlot(s):
            headers.add(db.getBlock(r).get().toHeader)
            if headers.len == maxHeaders: break
          s += 1

      await response.send(headers)

    proc beaconBlockHeaders(peer: Peer, blockHeaders: openarray[BeaconBlockHeaderRLP])

  requestResponse:
    proc getAncestorBlocks(
            peer: Peer,
            needed: openarray[FetchRecord]) =
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

            if blck.get().previous_block_root in neededRoots:
              # Don't send duplicate blocks, if neededRoots has roots that are
              # in the same chain
              break

            if (blck = db.getBlock(blck.get().previous_block_root);
                blck.isNone() or blck.get().slot < firstSlot):
              break

          if resp.len >= MaxAncestorBlocksResponse:
            break

      await response.send(resp)

    proc ancestorBlocks(peer: Peer, blocks: openarray[BeaconBlock])

  requestResponse:
    proc getBeaconBlockBodies(
            peer: Peer,
            blockRoots: openarray[Eth2Digest]) {.libp2pProtocol("rpc/beacon_block_bodies", "1.0.0").} =
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

proc getBeaconBlocks*(peer: Peer, blockRoot: Eth2Digest, slot: Slot, maxBlocks, skipSlots: int, backward: uint8): Future[Option[seq[BeaconBlock]]] {.async.} =
  ## Retrieve block headers and block bodies from the remote peer, merge them into blocks.
  assert(maxBlocks <= MaxHeadersToRequest)
  let headersResp = await peer.getBeaconBlockHeaders(blockRoot, slot, maxBlocks, skipSlots, backward)
  if headersResp.isNone: return

  let headers = headersResp.get.blockHeaders
  if headers.len == 0:
    info "Peer has no headers", peer
    var res: seq[BeaconBlock]
    return some(res)

  let bodiesRequest = headers.mapIt(hash_tree_root(it))

  debug "Block headers received. Requesting block bodies", peer
  let bodiesResp = await peer.getBeaconBlockBodies(bodiesRequest)
  if bodiesResp.isNone:
    info "Did not receive bodies", peer
    return

  result = mergeBlockHeadersAndBodies(headers, bodiesResp.get.blockBodies)
  # If result.isNone: disconnect with BreachOfProtocol?
