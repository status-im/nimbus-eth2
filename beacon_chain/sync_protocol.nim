import
  options, tables, sets, macros,
  chronicles, chronos, stew/ranges/bitranges, libp2p/switch,
  spec/[datatypes, crypto, digest, helpers],
  beacon_node_types, eth2_network, block_pool, ssz

logScope:
  topics = "sync"

type
  StatusMsg* = object
    forkVersion*: array[4, byte]
    finalizedRoot*: Eth2Digest
    finalizedEpoch*: Epoch
    headRoot*: Eth2Digest
    headSlot*: Slot

  ValidatorSetDeltaFlags {.pure.} = enum
    Activation = 0
    Exit = 1

  ValidatorChangeLogEntry* = object
    case kind*: ValidatorSetDeltaFlags
    of Activation:
      pubkey: ValidatorPubKey
    else:
      index: uint32

  BeaconBlockCallback* = proc(signedBlock: SignedBeaconBlock) {.gcsafe.}
  BeaconSyncNetworkState* = ref object
    blockPool*: BlockPool
    forkVersion*: array[4, byte]
    onBeaconBlock*: BeaconBlockCallback

  BeaconSyncPeerState* = ref object
    initialStatusReceived*: bool
    statusMsg*: StatusMsg

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
                         theirStatus: StatusMsg): Future[bool] {.async, gcsafe.}

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
        let tstatus = theirStatus.get()
        let res = await peer.handleInitialStatus(peer.networkState,
                                                 ourStatus, tstatus)
        if res:
          peer.state(BeaconSync).statusMsg = tstatus
      else:
        warn "Status response not received in time"

  requestResponse:
    proc status(peer: Peer, theirStatus: StatusMsg) {.libp2pProtocol("status", 1).} =
      let
        ourStatus = peer.networkState.getCurrentStatus()

      trace "Sending status msg", ourStatus
      await response.send(ourStatus)

      if not peer.state.initialStatusReceived:
        peer.state.initialStatusReceived = true
        let res = await peer.handleInitialStatus(peer.networkState,
                                                 ourStatus, theirStatus)
        if res:
          peer.state(BeaconSync).statusMsg = theirStatus

    proc statusResp(peer: Peer, msg: StatusMsg)

  proc goodbye(peer: Peer, reason: DisconnectionReason) {.libp2pProtocol("goodbye", 1).}

  requestResponse:
    proc beaconBlocksByRange(
            peer: Peer,
            startSlot: Slot,
            count: uint64,
            step: uint64) {.
            libp2pProtocol("beacon_blocks_by_range", 1).} =
      trace "got range request", peer, count, startSlot, step

      if count > 0'u64:
        let count = if step != 0: min(count, MAX_REQUESTED_BLOCKS.uint64) else: 1
        let pool = peer.networkState.blockPool
        var results: array[MAX_REQUESTED_BLOCKS, BlockRef]
        let
          lastPos = min(count.int, results.len) - 1
          firstPos = pool.getBlockRange(pool.head.blck.root, startSlot, step,
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
                       theirStatus: StatusMsg): Future[bool] {.async, gcsafe.} =
  if theirStatus.forkVersion != state.forkVersion:
    notice "Irrelevant peer",
      peer, theirFork = theirStatus.forkVersion, ourFork = state.forkVersion
    await peer.disconnect(IrrelevantNetwork)
    return false
  debug "Peer connected", peer,
                          localHeadSlot = ourStatus.headSlot,
                          remoteHeadSlot = theirStatus.headSlot,
                          remoteHeadRoot = theirStatus.headRoot
  return true
