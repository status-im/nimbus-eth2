import
  options, tables, sequtils, algorithm, sets, macros,
  chronicles, chronos, stew/ranges/bitranges,
  spec/[datatypes, crypto, digest, helpers], eth/rlp,
  beacon_node_types, eth2_network, beacon_chain_db, block_pool, time, ssz

when networkBackend == rlpxBackend:
  import eth/rlp/options as rlpOptions
  template libp2pProtocol*(name: string, version: int) {.pragma.}

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
          let blocksResp = await peer.getBeaconBlocks(bestRoot, s, min(headersLeft, MaxHeadersToRequest), 0'u64)
          if blocksResp.isSome:
            if blocksResp.get.blocks.len == 0:
              info "Got 0 blocks while syncing", peer
              break
            node.importBlocks(blocksResp.get.blocks)
            let lastSlot = blocksResp.get.blocks[^1].slot
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
    proc getBeaconBlocks(
            peer: Peer,
            headBlockRoot: Eth2Digest,
            start_slot: Slot,
            count: uint64,
            step: uint64) {.
            libp2pProtocol("/eth2/beacon_chain/req/beacon_blocks", 1).} =
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
            if uint64(len(blocks)) == count:
              break
          blck = blck.parent

      await response.send(blocks)

    proc getRecentBeaconBlocks(
            peer: Peer,
            blockRoots: openarray[Eth2Digest]) {.
            libp2pProtocol("/eth2/beacon_chain/req/recent_beacon_blocks", 1).} =
      var blocks: seq[BeaconBlock]
      # `len(blockRoots) == 0` has no sense, so we will return empty array of
      # blocks.
      if len(blockRoots) > 0:
        let pool = peer.networkState.node.blockPool
        blocks = newSeq[BeaconBlock](len(blockRoots))

        var index = 0
        for root in blockRoots:
          let blockRef = pool.getRef(root)
          if not isNil(blockRef):
            blocks[index] = pool.get(blockRef).data
          inc index

      await response.send(blocks)

    proc beaconBlocks(
            peer: Peer,
            blocks: openarray[BeaconBlock])

