import
  options, tables,
  chronicles, chronos, ranges/bitranges,
  spec/[datatypes, crypto, digest], eth/rlp,
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
                  roots: openarray[(Eth2Digest, Slot)],
                  headers: openarray[BeaconBlockHeaderRLP],
                  bodies: openarray[BeaconBlockBody]) =
  var bodyMap = initTable[Eth2Digest, int]()

  for i, b in bodies:
    bodyMap[hash_tree_root(b)] = i

  var goodBlocks, badBlocks = 0
  for h in headers:
    let iBody = bodyMap.getOrDefault(h.body, -1)
    if iBody >= 0:
      var blk: BeaconBlock
      blk.fromHeaderAndBody(h, bodies[iBody])
      node.onBeaconBlock(blk)
      inc goodBlocks
    else:
      inc badBlocks

  info "Forward sync imported blocks", goodBlocks, badBlocks, headers = headers.len, bodies = bodies.len, roots = roots.len

p2pProtocol BeaconSync(version = 1,
                       shortName = "bcs",
                       networkState = BeaconSyncState):

  onPeerConnected do(peer: Peer):
    let
      protocolVersion = 1 # TODO: Spec doesn't specify this yet
      node = peer.networkState.node
      networkId = peer.networkState.networkId
      blockPool = node.blockPool
      latestState = blockPool.latestState()
      headBlock = blockPool.head

    var
      latestFinalizedRoot: Eth2Digest # TODO
      latestFinalizedEpoch = latestState.finalized_epoch
      bestRoot: Eth2Digest # TODO
      bestSlot = headBlock.slot

    let m = await handshake(peer, timeout = 10.seconds,
                            status(networkId, latestFinalizedRoot,
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
          debug "Waiting for block roots", fromPeer = peer, remoteBestSlot = m.bestSlot, peer
          let r = await peer.getBeaconBlockRoots(s, MaxRootsToRequest)
          if not r.isSome:
            debug "Block roots not received", peer
            break
          let roots = r.get.roots
          debug "Received block roots", len = roots.len, peer
          if roots.len != 0:
            if roots.len > MaxRootsToRequest:
              # Attack?
              await peer.disconnect(BreachOfProtocol, true)
              break

            let headers = await peer.getBeaconBlockHeaders(bestRoot, s, roots.len, 0)
            var bodiesRequest = newSeqOfCap[Eth2Digest](roots.len)
            for r in roots:
              bodiesRequest.add(r[0])

            debug "Block headers received. Requesting block bodies", peer
            let bodies = await peer.getBeaconBlockBodies(bodiesRequest)
            node.importBlocks(roots, headers.get.blockHeaders, bodies.get.blockBodies)

            let lastSlot = roots[^1][1]
            if roots.len == MaxRootsToRequest:
              # Next batch of roots starts with the last slot of the current one
              # to make sure we did not miss any roots with this slot that did
              # not fit into the response.

              if s == lastSlot:
                info "Too many roots for a single slot while syncing"
                break
              s = lastSlot
            else:
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
      let maxSlot = blockPool.head.slot
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
            skipSlots: int) {.libp2pProtocol("rpc/beacon_block_headers", "1.0.0").} =
      # TODO: validate implement slipSlots
      let maxHeaders = min(MaxHeadersToRequest, maxHeaders)
      var s = slot
      var headers = newSeqOfCap[BeaconBlockHeaderRLP](maxHeaders)
      let db = peer.networkState.db
      let blockPool = peer.networkState.node.blockPool
      let maxSlot = blockPool.head.slot
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
      await response.send(bodies)

    proc beaconBlockBodies(
            peer: Peer,
            blockBodies: openarray[BeaconBlockBody])

