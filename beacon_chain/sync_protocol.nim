import
  options, tables, sets, macros,
  chronicles, chronos, stew/ranges/bitranges, libp2p/switch,
  spec/[datatypes, crypto, digest, helpers],
  beacon_node_types, eth2_network, block_pool, ssz

logScope:
  topics = "sync"

type
  StatusMsg* = object
    forkDigest*: ForkDigest
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
    forkDigest*: ForkDigest
    onBeaconBlock*: BeaconBlockCallback

  BeaconSyncPeerState* = ref object
    initialStatusReceived*: bool
    statusMsg*: StatusMsg

  BlockRootSlot* = object
    blockRoot: Eth2Digest
    slot: Slot

const
  MAX_REQUESTED_BLOCKS = 20'u64

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
    forkDigest: state.forkDigest,
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
    proc ping(peer: Peer, value: uint64) {.libp2pProtocol("ping", 1).} =
      await response.write(peer.network.metadata.seq_number)

    proc pingResp(peer: Peer, value: uint64)

  requestResponse:
    proc getMetadata(peer: Peer) {.libp2pProtocol("metadata", 1).} =
      await response.write(peer.network.metadata)

    proc metadataReps(peer: Peer, metadata: Eth2Metadata)

  requestResponse:
    proc beaconBlocksByRange(
            peer: Peer,
            startSlot: Slot,
            count: uint64,
            step: uint64) {.
            libp2pProtocol("beacon_blocks_by_range", 1).} =
      trace "got range request", peer, startSlot, count, step

      if count > 0'u64:
        var blocks: array[MAX_REQUESTED_BLOCKS, BlockRef]
        let
          pool = peer.networkState.blockPool
          # Limit number of blocks in response
          count = min(count.Natural, blocks.len)

        let startIndex =
          pool.getBlockRange(startSlot, step, blocks.toOpenArray(0, count - 1))

        for b in blocks[startIndex..^1]:
          doAssert not b.isNil, "getBlockRange should return non-nil blocks only"
          trace "wrote response block", slot = b.slot, roor = shortLog(b.root)
          await response.write(pool.get(b).data)

        debug "Block range request done",
          peer, startSlot, count, step, found = count - startIndex

    proc beaconBlocksByRoot(
            peer: Peer,
            blockRoots: openarray[Eth2Digest]) {.
            libp2pProtocol("beacon_blocks_by_root", 1).} =
      let
        pool = peer.networkState.blockPool

      var found = 0
      for root in blockRoots:
        let blockRef = pool.getRef(root)
        if not isNil(blockRef):
          await response.write(pool.get(blockRef).data)
          inc found

      debug "Block root request done",
        peer, roots = blockRoots.len, found

    proc beaconBlocks(
            peer: Peer,
            blocks: openarray[SignedBeaconBlock])

proc handleInitialStatus(peer: Peer,
                         state: BeaconSyncNetworkState,
                         ourStatus: StatusMsg,
                       theirStatus: StatusMsg): Future[bool] {.async, gcsafe.} =
  if theirStatus.forkDigest != state.forkDigest:
    notice "Irrelevant peer",
      peer, theirFork = theirStatus.forkDigest, ourFork = state.forkDigest
    await peer.disconnect(IrrelevantNetwork)
    return false
  debug "Peer connected", peer,
                          localHeadSlot = ourStatus.headSlot,
                          remoteHeadSlot = theirStatus.headSlot,
                          remoteHeadRoot = theirStatus.headRoot
  return true

proc initBeaconSync*(network: Eth2Node,
                     blockPool: BlockPool,
                     forkDigest: ForkDigest,
                     onBeaconBlock: BeaconBlockCallback) =
  var networkState = network.protocolState(BeaconSync)
  networkState.blockPool = blockPool
  networkState.forkDigest = forkDigest
  networkState.onBeaconBlock = onBeaconBlock
