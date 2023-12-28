# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[tables, sets, macros],
  chronicles, chronos, snappy, snappy/codec,
  libp2p/switch,
  ../spec/datatypes/[phase0, altair, bellatrix, capella, deneb],
  ../spec/[helpers, forks, network],
  ".."/[beacon_clock],
  ../networking/eth2_network,
  ../consensus_object_pools/blockchain_dag,
  ../rpc/rest_constants

logScope:
  topics = "sync"

const
  blockResponseCost = allowedOpsPerSecondCost(64) # Allow syncing ~64 blocks/sec (minus request costs)

  lightClientBootstrapResponseCost = allowedOpsPerSecondCost(1)
    ## Only one bootstrap per peer should ever be needed - no need to allow more
  lightClientUpdateResponseCost = allowedOpsPerSecondCost(1000)
    ## Updates are tiny - we can allow lots of them
  lightClientFinalityUpdateResponseCost = allowedOpsPerSecondCost(100)
  lightClientOptimisticUpdateResponseCost = allowedOpsPerSecondCost(100)

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

  BeaconSyncNetworkState = ref object
    dag: ChainDAGRef
    cfg: RuntimeConfig
    forkDigests: ref ForkDigests
    genesisBlockRoot: Eth2Digest
    getBeaconTime: GetBeaconTimeFn

  BeaconSyncPeerState* = ref object
    statusLastTime*: chronos.Moment
    statusMsg*: StatusMsg

  BlockRootSlot* = object
    blockRoot: Eth2Digest
    slot: Slot

  BlockRootsList* = List[Eth2Digest, Limit MAX_REQUEST_BLOCKS]
  BlobIdentifierList* = List[BlobIdentifier, Limit (MAX_REQUEST_BLOB_SIDECARS)]

template readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type ForkySignedBeaconBlock):
    Future[NetRes[MsgType]] =
  readChunkPayload(conn, peer, MsgType)

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type (ref ForkedSignedBeaconBlock)):
    Future[NetRes[MsgType]] {.async.} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF

  if contextBytes == peer.network.forkDigests.phase0:
    let res = await readChunkPayload(conn, peer, phase0.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  elif contextBytes == peer.network.forkDigests.altair:
    let res = await readChunkPayload(conn, peer, altair.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  elif contextBytes == peer.network.forkDigests.bellatrix:
    let res = await readChunkPayload(conn, peer, bellatrix.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  elif contextBytes == peer.network.forkDigests.capella:
    let res = await readChunkPayload(conn, peer, capella.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  elif contextBytes == peer.network.forkDigests.deneb:
    let res = await readChunkPayload(conn, peer, deneb.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  else:
    return neterr InvalidContextBytes

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type (ref BlobSidecar)):
    Future[NetRes[MsgType]] {.async.} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF

  if contextBytes == peer.network.forkDigests.deneb:
    let res = await readChunkPayload(conn, peer, BlobSidecar)
    if res.isOk:
      return ok newClone(res.get)
    else:
      return err(res.error)
  else:
    return neterr InvalidContextBytes

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type SomeForkedLightClientObject):
    Future[NetRes[MsgType]] {.async.} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF
  let contextFork =
    peer.network.forkDigests[].consensusForkForDigest(contextBytes).valueOr:
      return neterr InvalidContextBytes

  withLcDataFork(lcDataForkAtConsensusFork(contextFork)):
    when lcDataFork > LightClientDataFork.None:
      let res = await eth2_network.readChunkPayload(
        conn, peer, MsgType.Forky(lcDataFork))
      if res.isOk:
        if contextFork !=
            peer.network.cfg.consensusForkAtEpoch(res.get.contextEpoch):
          return neterr InvalidContextBytes
        return ok MsgType.init(res.get)
      else:
        return err(res.error)
    else:
      return neterr InvalidContextBytes

func shortLog*(s: StatusMsg): auto =
  (
    forkDigest: s.forkDigest,
    finalizedRoot: shortLog(s.finalizedRoot),
    finalizedEpoch: shortLog(s.finalizedEpoch),
    headRoot: shortLog(s.headRoot),
    headSlot: shortLog(s.headSlot)
  )
chronicles.formatIt(StatusMsg): shortLog(it)

func disconnectReasonName(reason: uint64): string =
  # haha, nim doesn't support uint64 in `case`!
  if reason == uint64(ClientShutDown): "Client shutdown"
  elif reason == uint64(IrrelevantNetwork): "Irrelevant network"
  elif reason == uint64(FaultOrError): "Fault or error"
  else: "Disconnected (" & $reason & ")"

func forkDigestAtEpoch(state: BeaconSyncNetworkState,
                       epoch: Epoch): ForkDigest =
  state.forkDigests[].atEpoch(epoch, state.cfg)

proc getCurrentStatus(state: BeaconSyncNetworkState): StatusMsg =
  let
    dag = state.dag
    wallSlot = state.getBeaconTime().slotOrZero

  if dag != nil:
    StatusMsg(
      forkDigest: state.forkDigestAtEpoch(wallSlot.epoch),
      finalizedRoot: dag.finalizedHead.blck.root,
      finalizedEpoch: dag.finalizedHead.slot.epoch,
      headRoot: dag.head.root,
      headSlot: dag.head.slot)
  else:
    StatusMsg(
      forkDigest: state.forkDigestAtEpoch(wallSlot.epoch),
      finalizedRoot: state.genesisBlockRoot,
      finalizedEpoch: GENESIS_EPOCH,
      headRoot: state.genesisBlockRoot,
      headSlot: GENESIS_SLOT)

proc checkStatusMsg(state: BeaconSyncNetworkState, status: StatusMsg):
    Result[void, cstring] =
  let
    dag = state.dag
    wallSlot = (state.getBeaconTime() + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero

  if status.finalizedEpoch > status.headSlot.epoch:
    # Can be equal during genesis or checkpoint start
    return err("finalized epoch newer than head")

  if status.headSlot > wallSlot:
    return err("head more recent than wall clock")

  if state.forkDigestAtEpoch(wallSlot.epoch) != status.forkDigest:
    return err("fork digests differ")

  if dag != nil:
    if status.finalizedEpoch <= dag.finalizedHead.slot.epoch:
      let blockId = dag.getBlockIdAtSlot(status.finalizedEpoch.start_slot())
      if blockId.isSome and
          (not status.finalizedRoot.isZero) and
          status.finalizedRoot != blockId.get().bid.root:
        return err("peer following different finality")
  else:
    if status.finalizedEpoch == GENESIS_EPOCH:
      if status.finalizedRoot != state.genesisBlockRoot:
        return err("peer following different finality")

  ok()

proc handleStatus(peer: Peer,
                  state: BeaconSyncNetworkState,
                  theirStatus: StatusMsg): Future[bool] {.gcsafe.}

proc setStatusMsg(peer: Peer, statusMsg: StatusMsg) {.gcsafe.}

{.pop.} # TODO fix p2p macro for raises

p2pProtocol BeaconSync(version = 1,
                       networkState = BeaconSyncNetworkState,
                       peerState = BeaconSyncPeerState):

  onPeerConnected do (peer: Peer, incoming: bool) {.async.}:
    debug "Peer connected",
      peer, peerId = shortLog(peer.peerId), incoming
    # Per the eth2 protocol, whoever dials must send a status message when
    # connected for the first time, but because of how libp2p works, there may
    # be a race between incoming and outgoing connections and disconnects that
    # makes the incoming flag unreliable / obsolete by the time we get to
    # this point - instead of making assumptions, we'll just send a status
    # message redundantly.
    # TODO(zah)
    #      the spec does not prohibit sending the extra status message on
    #      incoming connections, but it should not be necessary - this would
    #      need a dedicated flow in libp2p that resolves the race conditions -
    #      this needs more thinking around the ordering of events and the
    #      given incoming flag
    let
      ourStatus = peer.networkState.getCurrentStatus()
      theirStatus = await peer.status(ourStatus, timeout = RESP_TIMEOUT_DUR)

    if theirStatus.isOk:
      discard await peer.handleStatus(peer.networkState, theirStatus.get())
    else:
      debug "Status response not received in time",
            peer, errorKind = theirStatus.error.kind
      await peer.disconnect(FaultOrError)

  proc status(peer: Peer,
              theirStatus: StatusMsg,
              response: SingleChunkResponse[StatusMsg])
    {.async, libp2pProtocol("status", 1, isRequired = true).} =
    let ourStatus = peer.networkState.getCurrentStatus()
    trace "Sending status message", peer = peer, status = ourStatus
    await response.send(ourStatus)
    discard await peer.handleStatus(peer.networkState, theirStatus)

  proc ping(peer: Peer, value: uint64): uint64
    {.libp2pProtocol("ping", 1, isRequired = true).} =
    return peer.network.metadata.seq_number

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/p2p-interface.md#transitioning-from-v1-to-v2
  proc getMetaData(peer: Peer): uint64
    {.libp2pProtocol("metadata", 1, isRequired = true).} =
    raise newException(InvalidInputsError, "GetMetaData v1 unsupported")

  proc getMetadata_v2(peer: Peer): altair.MetaData
    {.libp2pProtocol("metadata", 2, isRequired = true).} =
    return peer.network.metadata

  proc beaconBlocksByRange_v2(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      reqStep: uint64,
      response: MultipleChunksResponse[
        ref ForkedSignedBeaconBlock, Limit MAX_REQUEST_BLOCKS])
      {.async, libp2pProtocol("beacon_blocks_by_range", 2).} =
    # TODO Semantically, this request should return a non-ref, but doing so
    #      runs into extreme inefficiency due to the compiler introducing
    #      hidden copies - in future nim versions with move support, this should
    #      be revisited
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref ForkedSignedBeaconBlock]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation
    # TODO reqStep is deprecated - future versions can remove support for
    #      values != 1: https://github.com/ethereum/consensus-specs/pull/2856

    trace "got range request", peer, startSlot,
                               count = reqCount, step = reqStep
    if reqCount == 0 or reqStep == 0:
      raise newException(InvalidInputsError, "Empty range requested")

    var blocks: array[MAX_REQUEST_BLOCKS.int, BlockId]
    let
      dag = peer.networkState.dag
      # Limit number of blocks in response
      count = int min(reqCount, blocks.lenu64)
      endIndex = count - 1
      startIndex =
        dag.getBlockRange(startSlot, reqStep,
                          blocks.toOpenArray(0, endIndex))

    var
      found = 0
      bytes: seq[byte]

    for i in startIndex..endIndex:
      if dag.getBlockSZ(blocks[i], bytes):
        # In general, there is not much intermediate time between post-merge
        # blocks all being optimistic and none of them being optimistic. The
        # EL catches up, tells the CL the head is verified, and that's it.
        if  blocks[i].slot.epoch >= dag.cfg.BELLATRIX_FORK_EPOCH and
            not dag.head.executionValid:
          continue

        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read block size, database corrupt?",
            bytes = bytes.len(), blck = shortLog(blocks[i])
          continue

        # TODO extract from libp2pProtocol
        peer.awaitQuota(blockResponseCost, "beacon_blocks_by_range/2")
        peer.network.awaitQuota(blockResponseCost, "beacon_blocks_by_range/2")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.networkState.forkDigestAtEpoch(blocks[i].slot.epoch).data)

        inc found

    debug "Block range request done",
      peer, startSlot, count, reqStep

  proc beaconBlocksByRoot_v2(
      peer: Peer,
      # Please note that the SSZ list here ensures that the
      # spec constant MAX_REQUEST_BLOCKS is enforced:
      blockRoots: BlockRootsList,
      response: MultipleChunksResponse[
        ref ForkedSignedBeaconBlock, Limit MAX_REQUEST_BLOCKS])
      {.async, libp2pProtocol("beacon_blocks_by_root", 2).} =
    # TODO Semantically, this request should return a non-ref, but doing so
    #      runs into extreme inefficiency due to the compiler introducing
    #      hidden copies - in future nim versions with move support, this should
    #      be revisited
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref ForkedSignedBeaconBlock]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation
    if blockRoots.len == 0:
      raise newException(InvalidInputsError, "No blocks requested")

    let
      dag = peer.networkState.dag
      count = blockRoots.len

    var
      found = 0
      bytes: seq[byte]

    for i in 0..<count:
      let
        blockRef = dag.getBlockRef(blockRoots[i]).valueOr:
          continue

      if dag.getBlockSZ(blockRef.bid, bytes):
        # In general, there is not much intermediate time between post-merge
        # blocks all being optimistic and none of them being optimistic. The
        # EL catches up, tells the CL the head is verified, and that's it.
        if  blockRef.slot.epoch >= dag.cfg.BELLATRIX_FORK_EPOCH and
            not dag.head.executionValid:
          continue

        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read block size, database corrupt?",
            bytes = bytes.len(), blck = shortLog(blockRef)
          continue

        # TODO extract from libp2pProtocol
        peer.awaitQuota(blockResponseCost, "beacon_blocks_by_root/2")
        peer.network.awaitQuota(blockResponseCost, "beacon_blocks_by_root/2")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.networkState.forkDigestAtEpoch(blockRef.slot.epoch).data)

        inc found

    debug "Block root request done",
      peer, roots = blockRoots.len, count, found


  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/p2p-interface.md#blobsidecarsbyroot-v1
  proc blobSidecarsByRoot(
      peer: Peer,
      blobIds: BlobIdentifierList,
      response: MultipleChunksResponse[
        ref BlobSidecar, Limit(MAX_REQUEST_BLOB_SIDECARS)])
      {.async, libp2pProtocol("blob_sidecars_by_root", 1).} =
    # TODO Semantically, this request should return a non-ref, but doing so
    #      runs into extreme inefficiency due to the compiler introducing
    #      hidden copies - in future nim versions with move support, this should
    #      be revisited
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref BlobSidecar]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation
    trace "got blobs range request", peer, len = blobIds.len
    if blobIds.len == 0:
      raise newException(InvalidInputsError, "No blobs requested")

    let
      dag = peer.networkState.dag
      count = blobIds.len

    var
      found = 0
      bytes: seq[byte]

    for i in 0..<count:
      let blockRef = dag.getBlockRef(blobIds[i].block_root).valueOr:
        continue
      let index = blobIds[i].index
      if dag.db.getBlobSidecarSZ(blockRef.bid.root, index, bytes):
        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read blob size, database corrupt?",
            bytes = bytes.len(), blck = shortLog(blockRef), blobindex = index
          continue

        peer.awaitQuota(blockResponseCost, "blob_sidecars_by_root/1")
        peer.network.awaitQuota(blockResponseCost, "blob_sidecars_by_root/1")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.networkState.forkDigestAtEpoch(blockRef.slot.epoch).data)
        inc found

    debug "Blob root request done",
      peer, roots = blobIds.len, count, found

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/p2p-interface.md#blobsidecarsbyrange-v1
  proc blobSidecarsByRange(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      response: MultipleChunksResponse[
        ref BlobSidecar, Limit(MAX_REQUEST_BLOB_SIDECARS)])
      {.async, libp2pProtocol("blob_sidecars_by_range", 1).} =
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref BlobSidecar]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation

    trace "got blobs range request", peer, startSlot, count = reqCount
    if reqCount == 0:
      raise newException(InvalidInputsError, "Empty range requested")

    let
      dag = peer.networkState.dag
      epochBoundary =
        if dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS >= dag.head.slot.epoch:
          GENESIS_EPOCH
        else:
          dag.head.slot.epoch - dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS

    if startSlot.epoch < epochBoundary:
      raise newException(ResourceUnavailableError, BlobsOutOfRange)

    var blockIds: array[int(MAX_REQUEST_BLOB_SIDECARS), BlockId]
    let
      count = int min(reqCount, blockIds.lenu64)
      endIndex = count - 1
      startIndex =
        dag.getBlockRange(startSlot, 1, blockIds.toOpenArray(0, endIndex))

    var
      found = 0
      bytes: seq[byte]

    for i in startIndex..endIndex:
      for j in 0..<MAX_BLOBS_PER_BLOCK:
        if dag.db.getBlobSidecarSZ(blockIds[i].root, BlobIndex(j), bytes):
          # In general, there is not much intermediate time between post-merge
          # blocks all being optimistic and none of them being optimistic. The
          # EL catches up, tells the CL the head is verified, and that's it.
          if  blockIds[i].slot.epoch >= dag.cfg.BELLATRIX_FORK_EPOCH and
              not dag.head.executionValid:
            continue

          let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
            warn "Cannot read blobs sidecar size, database corrupt?",
              bytes = bytes.len(), blck = shortLog(blockIds[i])
            continue

          # TODO extract from libp2pProtocol
          peer.awaitQuota(blockResponseCost, "blobs_sidecars_by_range/1")
          peer.network.awaitQuota(blockResponseCost, "blobs_sidecars_by_range/1")

          await response.writeBytesSZ(
            uncompressedLen, bytes,
            peer.networkState.forkDigestAtEpoch(blockIds[i].slot.epoch).data)
          inc found
        else:
          break

    debug "BlobSidecar range request done",
      peer, startSlot, count = reqCount, found

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientbootstrap
  proc lightClientBootstrap(
      peer: Peer,
      blockRoot: Eth2Digest,
      response: SingleChunkResponse[ForkedLightClientBootstrap])
      {.async, libp2pProtocol("light_client_bootstrap", 1,
                              isLightClientRequest = true).} =
    trace "Received LC bootstrap request", peer, blockRoot
    let dag = peer.networkState.dag
    doAssert dag.lcDataStore.serve

    let bootstrap = dag.getLightClientBootstrap(blockRoot)
    withForkyBootstrap(bootstrap):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyBootstrap.contextEpoch
          contextBytes = peer.networkState.forkDigestAtEpoch(contextEpoch).data

        # TODO extract from libp2pProtocol
        peer.awaitQuota(
          lightClientBootstrapResponseCost,
          "light_client_bootstrap/1")
        await response.sendSSZ(forkyBootstrap, contextBytes)
      else:
        raise newException(ResourceUnavailableError, LCBootstrapUnavailable)

    debug "LC bootstrap request done", peer, blockRoot

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#lightclientupdatesbyrange
  proc lightClientUpdatesByRange(
      peer: Peer,
      startPeriod: SyncCommitteePeriod,
      reqCount: uint64,
      response: MultipleChunksResponse[
        ForkedLightClientUpdate, MAX_REQUEST_LIGHT_CLIENT_UPDATES])
      {.async, libp2pProtocol("light_client_updates_by_range", 1,
                              isLightClientRequest = true).} =
    trace "Received LC updates by range request", peer, startPeriod, reqCount
    let dag = peer.networkState.dag
    doAssert dag.lcDataStore.serve

    let
      headPeriod = dag.head.slot.sync_committee_period
      # Limit number of updates in response
      maxSupportedCount =
        if startPeriod > headPeriod:
          0'u64
        else:
          min(headPeriod + 1 - startPeriod, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
      count = min(reqCount, maxSupportedCount)
      onePastPeriod = startPeriod + count

    var found = 0
    for period in startPeriod..<onePastPeriod:
      let update = dag.getLightClientUpdateForPeriod(period)
      withForkyUpdate(update):
        when lcDataFork > LightClientDataFork.None:
          let
            contextEpoch = forkyUpdate.contextEpoch
            contextBytes =
              peer.networkState.forkDigestAtEpoch(contextEpoch).data

          # TODO extract from libp2pProtocol
          peer.awaitQuota(
            lightClientUpdateResponseCost,
            "light_client_updates_by_range/1")
          await response.writeSSZ(forkyUpdate, contextBytes)
          inc found
        else:
          discard

    debug "LC updates by range request done", peer, startPeriod, count, found

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientfinalityupdate
  proc lightClientFinalityUpdate(
      peer: Peer,
      response: SingleChunkResponse[ForkedLightClientFinalityUpdate])
      {.async, libp2pProtocol("light_client_finality_update", 1,
                              isLightClientRequest = true).} =
    trace "Received LC finality update request", peer
    let dag = peer.networkState.dag
    doAssert dag.lcDataStore.serve

    let finality_update = dag.getLightClientFinalityUpdate()
    withForkyFinalityUpdate(finality_update):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyFinalityUpdate.contextEpoch
          contextBytes = peer.networkState.forkDigestAtEpoch(contextEpoch).data

        # TODO extract from libp2pProtocol
        peer.awaitQuota(
          lightClientFinalityUpdateResponseCost,
          "light_client_finality_update/1")
        await response.sendSSZ(forkyFinalityUpdate, contextBytes)
      else:
        raise newException(ResourceUnavailableError, LCFinUpdateUnavailable)

    debug "LC finality update request done", peer

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientoptimisticupdate
  proc lightClientOptimisticUpdate(
      peer: Peer,
      response: SingleChunkResponse[ForkedLightClientOptimisticUpdate])
      {.async, libp2pProtocol("light_client_optimistic_update", 1,
                              isLightClientRequest = true).} =
    trace "Received LC optimistic update request", peer
    let dag = peer.networkState.dag
    doAssert dag.lcDataStore.serve

    let optimistic_update = dag.getLightClientOptimisticUpdate()
    withForkyOptimisticUpdate(optimistic_update):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyOptimisticUpdate.contextEpoch
          contextBytes = peer.networkState.forkDigestAtEpoch(contextEpoch).data

        # TODO extract from libp2pProtocol
        peer.awaitQuota(
          lightClientOptimisticUpdateResponseCost,
          "light_client_optimistic_update/1")
        await response.sendSSZ(forkyOptimisticUpdate, contextBytes)
      else:
        raise newException(ResourceUnavailableError, LCOptUpdateUnavailable)

    debug "LC optimistic update request done", peer

  proc goodbye(peer: Peer,
               reason: uint64)
    {.async, libp2pProtocol("goodbye", 1, isRequired = true).} =
    debug "Received Goodbye message", reason = disconnectReasonName(reason), peer

proc setStatusMsg(peer: Peer, statusMsg: StatusMsg) =
  debug "Peer status", peer, statusMsg
  peer.state(BeaconSync).statusMsg = statusMsg
  peer.state(BeaconSync).statusLastTime = Moment.now()

proc handleStatus(peer: Peer,
                  state: BeaconSyncNetworkState,
                  theirStatus: StatusMsg): Future[bool] {.async, gcsafe.} =
  let
    res = checkStatusMsg(state, theirStatus)

  return if res.isErr():
    debug "Irrelevant peer", peer, theirStatus, err = res.error()
    await peer.disconnect(IrrelevantNetwork)
    false
  else:
    peer.setStatusMsg(theirStatus)

    if peer.connectionState == Connecting:
      # As soon as we get here it means that we passed handshake succesfully. So
      # we can add this peer to PeerPool.
      await peer.handlePeer()
    true

proc updateStatus*(peer: Peer): Future[bool] {.async.} =
  ## Request `status` of remote peer ``peer``.
  let
    nstate = peer.networkState(BeaconSync)
    ourStatus = getCurrentStatus(nstate)

  let theirFut = awaitne peer.status(ourStatus, timeout = RESP_TIMEOUT_DUR)
  if theirFut.failed():
    return false
  else:
    let theirStatus = theirFut.read()
    if theirStatus.isOk:
      return await peer.handleStatus(nstate, theirStatus.get())
    else:
      return false

proc getHeadSlot*(peer: Peer): Slot =
  ## Returns head slot for specific peer ``peer``.
  peer.state(BeaconSync).statusMsg.headSlot

proc getFinalizedEpoch*(peer: Peer): Epoch =
  ## Returns head slot for specific peer ``peer``.
  peer.state(BeaconSync).statusMsg.finalizedEpoch

proc initBeaconSync*(network: Eth2Node, dag: ChainDAGRef,
                     getBeaconTime: GetBeaconTimeFn) =
  var networkState = network.protocolState(BeaconSync)
  networkState.dag = dag
  networkState.cfg = dag.cfg
  networkState.forkDigests = dag.forkDigests
  networkState.genesisBlockRoot = dag.genesisBlockRoot
  networkState.getBeaconTime = getBeaconTime

proc initBeaconSync*(network: Eth2Node,
                     cfg: RuntimeConfig,
                     forkDigests: ref ForkDigests,
                     genesisBlockRoot: Eth2Digest,
                     getBeaconTime: GetBeaconTimeFn) =
  var networkState = network.protocolState(BeaconSync)
  networkState.dag = nil
  networkState.cfg = cfg
  networkState.forkDigests = forkDigests
  networkState.genesisBlockRoot = genesisBlockRoot
  networkState.getBeaconTime = getBeaconTime
