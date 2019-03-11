import
  options, tables,
  chronicles, chronos, ranges/bitranges,
  spec/[datatypes, crypto, digest],
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
    node*: BeaconNode
    db*: BeaconChainDB

func toHeader(b: BeaconBlock): BeaconBlockHeader =
  BeaconBlockHeader(
    slot: b.slot,
    parent_root: b.parent_root,
    state_root: b.state_root,
    randao_reveal: b.randao_reveal,
    eth1_data : b.eth1_data,
    signature: b.signature,
    body: hash_tree_root_final(b.body)
  )

proc fromHeaderAndBody(b: var BeaconBlock, h: BeaconBlockHeader, body: BeaconBlockBody) =
  assert(hash_tree_root_final(body) == h.body)
  b.slot = h.slot
  b.parent_root = h.parent_root
  b.state_root = h.state_root
  b.randao_reveal = h.randao_reveal
  b.eth1_data = h.eth1_data
  b.signature = h.signature
  b.body = body

proc importBlocks(node: BeaconNode, roots: openarray[(Eth2Digest, uint64)], headers: openarray[BeaconBlockHeader], bodies: openarray[BeaconBlockBody]) =
  var bodyMap = initTable[Eth2Digest, int]()

  for i, b in bodies:
    bodyMap[hash_tree_root_final(b)] = i

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
    const
      protocolVersion = 1 # TODO: Spec doesn't specify this yet
      networkId = 1
    let node = peer.networkState.node

    var
      latestFinalizedRoot: Eth2Digest # TODO
      latestFinalizedEpoch: uint64 = node.state.data.finalized_epoch
      bestRoot: Eth2Digest # TODO
      bestSlot: uint64 = node.state.data.slot

    let m = await handshake(peer, timeout = 500,
                            status(networkId, latestFinalizedRoot,
                                   latestFinalizedEpoch, bestRoot, bestSlot))
    let bestDiff = cmp((latestFinalizedEpoch, bestSlot), (m.latestFinalizedEpoch, m.bestSlot))
    if bestDiff == 0:
      # Nothing to do?
      trace "Nothing to sync", peer = peer.remote
    else:
      # TODO: Check for WEAK_SUBJECTIVITY_PERIOD difference and terminate the
      # connection if it's too big.
      let blockPool = peer.networkState.node.blockPool

      if bestDiff > 0:
        # Send roots
        # TODO: Currently we send all block roots in one "packet". Maybe
        # they should be split to multiple packets.
        type Root = (Eth2Digest, uint64)
        var roots = newSeqOfCap[Root](128)
        for i in m.bestSlot .. bestSlot:
          for r in blockPool.blockRootsForSlot(i):
            roots.add((r, i))

        await peer.beaconBlockRoots(roots)
      else:
        # Receive roots
        let roots = await peer.nextMsg(BeaconSync.beaconBlockRoots)
        let headers = await peer.getBeaconBlockHeaders(bestRoot, bestSlot, roots.roots.len, 0)
        var bodiesRequest = newSeqOfCap[Eth2Digest](roots.roots.len)
        for r in roots.roots:
          bodiesRequest.add(r[0])
        let bodies = await peer.getBeaconBlockBodies(bodiesRequest)
        node.importBlocks(roots.roots, headers.get.blockHeaders, bodies.get.blockBodies)

  proc status(
            peer: Peer,
            networkId: int,
            latestFinalizedRoot: Eth2Digest,
            latestFinalizedEpoch: uint64,
            bestRoot: Eth2Digest,
            bestSlot: uint64) {.libp2pProtocol("hello", "1.0.0").}

  proc beaconBlockRoots(
            peer: Peer,
            roots: openarray[(Eth2Digest, uint64)]) {.libp2pProtocol("rpc/beacon_block_roots", "1.0.0").}

  requestResponse:
    proc getBeaconBlockHeaders(
            peer: Peer,
            blockRoot: Eth2Digest,
            slot: uint64,
            maxHeaders: int,
            skipSlots: int) {.libp2pProtocol("rpc/beacon_block_headers", "1.0.0").} =
      # TODO: validate maxHeaders and implement slipSlots
      var s = slot
      var headers = newSeqOfCap[BeaconBlockHeader](maxHeaders)
      let db = peer.networkState.db
      let blockPool = peer.networkState.node.blockPool
      while headers.len < maxHeaders:
        for r in blockPool.blockRootsForSlot(s):
          headers.add(db.getBlock(r).get().toHeader)
          if headers.len == maxHeaders: break
        inc s
      await response.send(headers)

    proc beaconBlockHeaders(
            peer: Peer,
            blockHeaders: openarray[BeaconBlockHeader])

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

