import
  options, tables, sets, macros,
  chronicles, chronos, metrics, stew/ranges/bitranges,
  spec/[datatypes, crypto, digest, helpers],
  beacon_node_types, eth2_network, block_pool, ssz

when networkBackend == libp2p:
  import libp2p/switch

declarePublicGauge libp2p_peers, "Number of libp2p peers"

logScope:
  topics = "sync"

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

  BeaconBlockCallback* = proc(blck: SignedBeaconBlock) {.gcsafe.}
  BeaconSyncNetworkState* = ref object
    blockPool*: BlockPool
    forkVersion*: array[4, byte]
    onBeaconBlock*: BeaconBlockCallback

  BeaconSyncPeerState* = ref object
    initialStatusReceived: bool

  BlockRootSlot* = object
    blockRoot: Eth2Digest
    slot: Slot

const
  MAX_REQUESTED_BLOCKS = 20'u64

func init*(
    v: BeaconSyncNetworkState, blockPool: BlockPool,
    forkVersion: array[4, byte], onBeaconBlock: BeaconBlockCallback) =
  v.blockPool = blockPool
  v.forkVersion = forkVersion
  v.onBeaconBlock = onBeaconBlock

proc importBlocks(state: BeaconSyncNetworkState,
                  blocks: openarray[SignedBeaconBlock]) {.gcsafe.} =
  for blk in blocks:
    state.onBeaconBlock(blk)
  info "Forward sync imported blocks", len = blocks.len

type
  StatusMsg = object
    forkVersion*: array[4, byte]
    finalizedRoot*: Eth2Digest
    finalizedEpoch*: Epoch
    headRoot*: Eth2Digest
    headSlot*: Slot

proc getCurrentStatus(state: BeaconSyncNetworkState): StatusMsg {.gcsafe.} =
  let
    blockPool = state.blockPool
    finalizedHead = blockPool.finalizedHead
    headBlock = blockPool.head.blck
    headRoot = headBlock.root
    headSlot = headBlock.slot
    finalizedEpoch = finalizedHead.slot.compute_epoch_at_slot()

  StatusMsg(
    fork_version: state.forkVersion,
    finalizedRoot: finalizedHead.blck.root,
    finalizedEpoch: finalizedEpoch,
    headRoot: headRoot,
    headSlot: headSlot)

proc handleInitialStatus(peer: Peer,
                         state: BeaconSyncNetworkState,
                         ourStatus: StatusMsg,
                         theirStatus: StatusMsg) {.async, gcsafe.}

p2pProtocol BeaconSync(version = 1,
                       rlpxName = "bcs",
                       networkState = BeaconSyncNetworkState,
                       peerState = BeaconSyncPeerState):

  onPeerConnected do (peer: Peer):
    if peer.wasDialed:
      let
        ourStatus = peer.networkState.getCurrentStatus()
        # TODO: The timeout here is so high only because we fail to
        # respond in time due to high CPU load in our single thread.
        theirStatus = await peer.status(ourStatus, timeout = 60.seconds)

      if theirStatus.isSome:
        await peer.handleInitialStatus(peer.networkState, ourStatus, theirStatus.get)
      else:
        warn "Status response not received in time"

  onPeerDisconnected do (peer: Peer):
    libp2p_peers.set peer.network.peers.len.int64

  requestResponse:
    proc status(peer: Peer, theirStatus: StatusMsg) {.libp2pProtocol("status", 1).} =
      let
        ourStatus = peer.networkState.getCurrentStatus()

      trace "Sending status msg", ourStatus
      await response.send(ourStatus)

      if not peer.state.initialStatusReceived:
        peer.state.initialStatusReceived = true
        await peer.handleInitialStatus(peer.networkState, ourStatus, theirStatus)

    proc statusResp(peer: Peer, msg: StatusMsg)

  proc goodbye(peer: Peer, reason: DisconnectionReason) {.libp2pProtocol("goodbye", 1).}

  requestResponse:
    proc beaconBlocksByRange(
            peer: Peer,
            headBlockRoot: Eth2Digest,
            startSlot: Slot,
            count: uint64,
            step: uint64) {.
            libp2pProtocol("beacon_blocks_by_range", 1).} =
      trace "got range request", peer, count, startSlot, headBlockRoot, step

      if count > 0'u64:
        let count = if step != 0: min(count, MAX_REQUESTED_BLOCKS.uint64) else: 1
        let pool = peer.networkState.blockPool
        var results: array[MAX_REQUESTED_BLOCKS, BlockRef]
        let
          lastPos = min(count.int, results.len) - 1
          firstPos = pool.getBlockRange(headBlockRoot, startSlot, step,
                                        results.toOpenArray(0, lastPos))
        for i in firstPos.int .. lastPos.int:
          trace "wrote response block", slot = results[i].slot
          await response.write(pool.get(results[i]).data)

    proc beaconBlocksByRoot(
            peer: Peer,
            blockRoots: openarray[Eth2Digest]) {.
            libp2pProtocol("beacon_blocks_by_root", 1).} =
      let
        pool = peer.networkState.blockPool

      for root in blockRoots:
        let blockRef = pool.getRef(root)
        if not isNil(blockRef):
          await response.write(pool.get(blockRef).data)

    proc beaconBlocks(
            peer: Peer,
            blocks: openarray[SignedBeaconBlock])

proc handleInitialStatus(peer: Peer,
                         state: BeaconSyncNetworkState,
                         ourStatus: StatusMsg,
                         theirStatus: StatusMsg) {.async, gcsafe.} =
  when networkBackend == libp2p:
    # TODO: This doesn't seem like an appropraite place for this call,
    # but it's hard to pick a better place at the moment.
    # nim-libp2p plans to add a general `onPeerConnected` callback which
    # will allow us to implement the subscription earlier.
    # The root of the problem is that both sides must call `subscribeToPeer`
    # before any GossipSub traffic will flow between them.
    await peer.network.switch.subscribeToPeer(peer.info)

  if theirStatus.forkVersion != state.forkVersion:
    notice "Irrelevant peer",
      peer, theirFork = theirStatus.forkVersion, ourFork = state.forkVersion
    await peer.disconnect(IrrelevantNetwork)
    return

  # TODO: onPeerConnected runs unconditionally for every connected peer, but we
  # don't need to sync with everybody. The beacon node should detect a situation
  # where it needs to sync and it should execute the sync algorithm with a certain
  # number of randomly selected peers. The algorithm itself must be extracted in a proc.
  try:
    libp2p_peers.set peer.network.peers.len.int64

    debug "Peer connected. Initiating sync", peer,
          localHeadSlot = ourStatus.headSlot,
          remoteHeadSlot = theirStatus.headSlot,
          remoteHeadRoot = theirStatus.headRoot

    let bestDiff = cmp((ourStatus.finalizedEpoch, ourStatus.headSlot),
                       (theirStatus.finalizedEpoch, theirStatus.headSlot))
    if bestDiff >= 0:
      # Nothing to do?
      debug "Nothing to sync", peer
    else:
      # TODO: Check for WEAK_SUBJECTIVITY_PERIOD difference and terminate the
      # connection if it's too big.
      var s = ourStatus.headSlot + 1
      var theirStatus = theirStatus
      while s <= theirStatus.headSlot:
        let numBlocksToRequest = min(uint64(theirStatus.headSlot - s) + 1,
                                     MAX_REQUESTED_BLOCKS)

        debug "Requesting blocks", peer, remoteHeadSlot = theirStatus.headSlot,
                                         ourHeadSlot = s,
                                         numBlocksToRequest

        # TODO: The timeout here is so high only because we fail to
        # respond in time due to high CPU load in our single thread.
        let blocks = await peer.beaconBlocksByRange(theirStatus.headRoot, s,
                                                    numBlocksToRequest, 1'u64,
                                                    timeout = 60.seconds)
        if blocks.isSome:
          info "got blocks", total = blocks.get.len
          if blocks.get.len == 0:
            info "Got 0 blocks while syncing", peer
            break

          state.importBlocks(blocks.get)
          let lastSlot = blocks.get[^1].message.slot
          if lastSlot <= s:
            info "Slot did not advance during sync", peer
            break

          s = lastSlot + 1

          # TODO: Maybe this shouldn't happen so often.
          # The alternative could be watching up a timer here.

          let statusResp = await peer.status(state.getCurrentStatus())
          if statusResp.isSome:
            theirStatus = statusResp.get
          else:
            # We'll ignore this error and we'll try to request
            # another range optimistically. If that fails, the
            # syncing will be interrupted.
            discard
        else:
          error "Did not get any blocks from peer. Aborting sync."
          break

  except CatchableError as e:
    warn "Failed to sync with peer", peer, err = e.msg

