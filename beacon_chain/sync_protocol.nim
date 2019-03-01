import
  options, tables,
  chronicles, eth/[rlp, p2p], chronos, ranges/bitranges, eth/p2p/rlpx,
  spec/[datatypes, crypto, digest],
  beacon_node, beacon_chain_db, time, ssz

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

proc fromHeader(b: var BeaconBlock, h: BeaconBlockHeader) =
  b.slot = h.slot
  b.parent_root = h.parent_root
  b.state_root = h.state_root
  b.randao_reveal = h.randao_reveal
  b.eth1_data = h.eth1_data
  b.signature = h.signature

proc importBlocks(node: BeaconNode, roots: openarray[(Eth2Digest, uint64)], headers: openarray[BeaconBlockHeader], bodies: openarray[BeaconBlockBody]) =
  var bodyMap = initTable[Eth2Digest, int]()

  for i, b in bodies:
    bodyMap[hash_tree_root_final(b)] = i

  var goodBlocks, badBlocks = 0
  for h in headers:
    let iBody = bodyMap.getOrDefault(h.body, -1)
    if iBody >= 0:
      var blk: BeaconBlock
      blk.fromHeader(h)
      blk.body = bodies[iBody]
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

    await peer.status(protocolVersion, networkId, latestFinalizedRoot, latestFinalizedEpoch,
        bestRoot, bestSlot)

    let m = await peer.nextMsg(BeaconSync.status)
    let bestDiff = cmp((latestFinalizedEpoch, bestSlot), (m.latestFinalizedEpoch, m.bestSlot))
    if bestDiff == 0:
      # Nothing to do?
      trace "Nothing to sync", peer = peer.node
    else:
      # TODO: Check for WEAK_SUBJECTIVITY_PERIOD difference and terminate the
      # connection if it's too big.
      let db = peer.networkState.db

      if bestDiff > 0:
        # Send roots
        # TODO: Currently we send all block roots in one "packet". Maybe
        # they should be split to multiple packets.
        type Root = (Eth2Digest, uint64)
        var roots = newSeqOfCap[Root](128)
        for i in m.bestSlot .. bestSlot:
          for r in db.getBlockRootsForSlot(i):
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

  proc status(peer: Peer, protocolVersion, networkId: int, latestFinalizedRoot: Eth2Digest,
        latestFinalizedEpoch: uint64, bestRoot: Eth2Digest, bestSlot: uint64)

  proc beaconBlockRoots(peer: Peer, roots: openarray[(Eth2Digest, uint64)])

  requestResponse:
    proc getBeaconBlockHeaders(peer: Peer, blockRoot: Eth2Digest, slot: uint64, maxHeaders: int, skipSlots: int) =
      # TODO: validate maxHeaders
      var s = slot
      var headers = newSeqOfCap[BeaconBlockHeader](maxHeaders)
      let db = peer.networkState.db
      while headers.len < maxHeaders:
        let blkRoots = db.getBlockRootsForSlot(s)
        for r in blkRoots:
          headers.add(db.getBlock(r).get().toHeader)
          if headers.len == maxHeaders: break
        inc s
      await peer.beaconBlockHeaders(reqId, headers)

    proc beaconBlockHeaders(peer: Peer, blockHeaders: openarray[BeaconBlockHeader])

  requestResponse:
    proc getBeaconBlockBodies(peer: Peer, blockRoots: openarray[Eth2Digest]) =
      # TODO: Validate blockRoots.len
      var bodies = newSeqOfCap[BeaconBlockBody](blockRoots.len)
      let db = peer.networkState.db
      for r in blockRoots:
        if (let blk = db.getBlock(r); blk.isSome):
          bodies.add(blk.get().body)
      await peer.beaconBlockBodies(reqId, bodies)

    proc beaconBlockBodies(peer: Peer, blockBodies: openarray[BeaconBlockBody])


  requestResponse:
    proc getValidatorChangeLog(peer: Peer, changeLogHead: Eth2Digest) =
      var bb: BeaconBlock
      var bs: BeaconState
      # TODO: get the changelog from the DB.
      await peer.validatorChangeLog(reqId, bb, bs, [], [], @[])

    proc validatorChangeLog(peer: Peer,
                            signedBlock: BeaconBlock,
                            beaconState: BeaconState,
                            added: openarray[ValidatorPubKey],
                            removed: openarray[uint32],
                            order: seq[byte])

type
  # A bit shorter names for convenience
  ChangeLog = BeaconSync.validatorChangeLog
  ChangeLogEntry = ValidatorChangeLogEntry

func validate*(log: ChangeLog): bool =
  # TODO:
  # Assert that the number of raised bits in log.order (a.k.a population count)
  # matches the number of elements in log.added
  # https://en.wikichip.org/wiki/population_count
  return true

iterator changes*(log: ChangeLog): ChangeLogEntry =
  var
    bits = log.added.len + log.removed.len
    addedIdx = 0
    removedIdx = 0

  template nextItem(collection): auto =
    let idx = `collection Idx`
    inc `collection Idx`
    log.collection[idx]

  for i in 0 ..< bits:
    yield if log.order.getBit(i):
      ChangeLogEntry(kind: Activation, pubkey: nextItem(added))
    else:
      ChangeLogEntry(kind: ValidatorSetDeltaFlags.Exit, index: nextItem(removed))

proc getValidatorChangeLog*(node: EthereumNode, changeLogHead: Eth2Digest):
                            Future[(Peer, ChangeLog)] {.async.} =
  while true:
    let peer = node.randomPeerWith(BeaconSync)
    if peer == nil: return

    let res = await peer.getValidatorChangeLog(changeLogHead, timeout = 1)
    if res.isSome:
      return (peer, res.get)

proc applyValidatorChangeLog*(log: ChangeLog,
                              outBeaconState: var BeaconState): bool =
  # TODO:
  #
  # 1. Validate that the signedBlock state root hash matches the
  #    provided beaconState
  #
  # 2. Validate that the applied changelog produces the correct
  #    new change log head
  #
  # 3. Check that enough signatures from the known validator set
  #    are present
  #
  # 4. Apply all changes to the validator set
  #

  outBeaconState.finalized_epoch =
    log.signedBlock.slot div SLOTS_PER_EPOCH

  outBeaconState.validator_registry_delta_chain_tip =
    log.beaconState.validator_registry_delta_chain_tip

