
## Generated at line 87
type
  BeaconSync* = object
template State*(PROTO: type BeaconSync): type =
  ref[BeaconSyncPeerState:ObjectType]

template NetworkState*(PROTO: type BeaconSync): type =
  ref[BeaconSyncNetworkState:ObjectType]

type
  statusObj* = distinct StatusMsg
template status*(PROTO: type BeaconSync): type =
  StatusMsg

template msgProtocol*(MSG: type statusObj): type =
  BeaconSync

template RecType*(MSG: type statusObj): untyped =
  StatusMsg

type
  pingObj* = distinct uint64
template ping*(PROTO: type BeaconSync): type =
  uint64

template msgProtocol*(MSG: type pingObj): type =
  BeaconSync

template RecType*(MSG: type pingObj): untyped =
  uint64

type
  getMetadataObj* = object
  
template getMetadata*(PROTO: type BeaconSync): type =
  getMetadataObj

template msgProtocol*(MSG: type getMetadataObj): type =
  BeaconSync

template RecType*(MSG: type getMetadataObj): untyped =
  getMetadataObj

type
  beaconBlocksByRangeObj* = object
    startSlot*: Slot
    count*: uint64
    step*: uint64

template beaconBlocksByRange*(PROTO: type BeaconSync): type =
  beaconBlocksByRangeObj

template msgProtocol*(MSG: type beaconBlocksByRangeObj): type =
  BeaconSync

template RecType*(MSG: type beaconBlocksByRangeObj): untyped =
  beaconBlocksByRangeObj

type
  beaconBlocksByRootObj* = distinct BlockRootsList
template beaconBlocksByRoot*(PROTO: type BeaconSync): type =
  BlockRootsList

template msgProtocol*(MSG: type beaconBlocksByRootObj): type =
  BeaconSync

template RecType*(MSG: type beaconBlocksByRootObj): untyped =
  BlockRootsList

type
  goodbyeObj* = distinct uint64
template goodbye*(PROTO: type BeaconSync): type =
  uint64

template msgProtocol*(MSG: type goodbyeObj): type =
  BeaconSync

template RecType*(MSG: type goodbyeObj): untyped =
  uint64

var BeaconSyncProtocolObj = initProtocol("BeaconSync", createPeerState[Peer,
    ref[BeaconSyncPeerState:ObjectType]], createNetworkState[Eth2Node,
    ref[BeaconSyncNetworkState:ObjectType]])
var BeaconSyncProtocol = addr BeaconSyncProtocolObj
template protocolInfo*(PROTO: type BeaconSync): auto =
  BeaconSyncProtocol

proc status*(peer: Peer; theirStatus: StatusMsg;
            timeout: Duration = milliseconds(10000'i64)): Future[NetRes[StatusMsg]] {.
    gcsafe, libp2pProtocol("status", 1).} =
  var outputStream = memoryOutput()
  var writer = init(WriterType(SSZ), outputStream)
  writeValue(writer, theirStatus)
  let msgBytes = getOutput(outputStream)
  makeEth2Request(peer, "/eth2/beacon_chain/req/status/1/", msgBytes, StatusMsg,
                  timeout)

proc ping*(peer: Peer; value: uint64; timeout: Duration = milliseconds(10000'i64)): Future[
    NetRes[uint64]] {.gcsafe, libp2pProtocol("ping", 1).} =
  var outputStream = memoryOutput()
  var writer = init(WriterType(SSZ), outputStream)
  writeValue(writer, value)
  let msgBytes = getOutput(outputStream)
  makeEth2Request(peer, "/eth2/beacon_chain/req/ping/1/", msgBytes, uint64, timeout)

proc getMetadata*(peer: Peer; timeout: Duration = milliseconds(10000'i64)): Future[
    NetRes[Eth2Metadata]] {.gcsafe, libp2pProtocol("metadata", 1).} =
  var msgBytes: seq[byte]
  makeEth2Request(peer, "/eth2/beacon_chain/req/metadata/1/", msgBytes,
                  Eth2Metadata, timeout)

proc beaconBlocksByRange*(peer: Peer; startSlot: Slot; count: uint64; step: uint64;
                         timeout: Duration = milliseconds(10000'i64)): Future[
    NetRes[seq[SignedBeaconBlock]]] {.gcsafe, libp2pProtocol(
    "beacon_blocks_by_range", 1).} =
  var outputStream = memoryOutput()
  var writer = init(WriterType(SSZ), outputStream)
  var recordWriterCtx = beginRecord(writer, beaconBlocksByRangeObj)
  writeField(writer, recordWriterCtx, "startSlot", startSlot)
  writeField(writer, recordWriterCtx, "count", count)
  writeField(writer, recordWriterCtx, "step", step)
  endRecord(writer, recordWriterCtx)
  let msgBytes = getOutput(outputStream)
  makeEth2Request(peer, "/eth2/beacon_chain/req/beacon_blocks_by_range/1/",
                  msgBytes, seq[SignedBeaconBlock], timeout)

proc beaconBlocksByRoot*(peer: Peer; blockRoots: BlockRootsList;
                        timeout: Duration = milliseconds(10000'i64)): Future[
    NetRes[seq[SignedBeaconBlock]]] {.gcsafe,
                                     libp2pProtocol("beacon_blocks_by_root", 1).} =
  var outputStream = memoryOutput()
  var writer = init(WriterType(SSZ), outputStream)
  writeValue(writer, blockRoots)
  let msgBytes = getOutput(outputStream)
  makeEth2Request(peer, "/eth2/beacon_chain/req/beacon_blocks_by_root/1/",
                  msgBytes, seq[SignedBeaconBlock], timeout)

proc goodbye*(peer: Peer; reason: uint64): Future[void] {.gcsafe,
    libp2pProtocol("goodbye", 1).} =
  var outputStream = memoryOutput()
  var writer = init(WriterType(SSZ), outputStream)
  writeValue(writer, reason)
  let msgBytes = getOutput(outputStream)
  sendNotificationMsg(peer, "/eth2/beacon_chain/req/goodbye/1/", msgBytes)

proc statusUserHandler(peer: Peer; theirStatus: StatusMsg;
                      response: SingleChunkResponse[StatusMsg]) {.async,
    libp2pProtocol("status", 1), gcsafe.} =
  type
    CurrentProtocol = BeaconSync
  template state(peer: Peer): ref[BeaconSyncPeerState:ObjectType] =
    cast[ref[BeaconSyncPeerState:ObjectType]](getState(peer, BeaconSyncProtocol))

  template networkState(peer: Peer): ref[BeaconSyncNetworkState:ObjectType] =
    cast[ref[BeaconSyncNetworkState:ObjectType]](getNetworkState(peer.network,
        BeaconSyncProtocol))

  let ourStatus = peer.networkState.getCurrentStatus()
  trace "Sending status message", peer = peer, status = ourStatus
  await response.send(ourStatus)
  await peer.handleStatus(peer.networkState, ourStatus, theirStatus)

proc pingUserHandler(peer: Peer; value: uint64): uint64 {.libp2pProtocol("ping", 1),
    gcsafe.} =
  type
    CurrentProtocol = BeaconSync
  template state(peer: Peer): ref[BeaconSyncPeerState:ObjectType] =
    cast[ref[BeaconSyncPeerState:ObjectType]](getState(peer, BeaconSyncProtocol))

  template networkState(peer: Peer): ref[BeaconSyncNetworkState:ObjectType] =
    cast[ref[BeaconSyncNetworkState:ObjectType]](getNetworkState(peer.network,
        BeaconSyncProtocol))

  return peer.network.metadata.seq_number

proc getMetadataUserHandler(peer: Peer): Eth2Metadata {.
    libp2pProtocol("metadata", 1), gcsafe.} =
  type
    CurrentProtocol = BeaconSync
  template state(peer: Peer): ref[BeaconSyncPeerState:ObjectType] =
    cast[ref[BeaconSyncPeerState:ObjectType]](getState(peer, BeaconSyncProtocol))

  template networkState(peer: Peer): ref[BeaconSyncNetworkState:ObjectType] =
    cast[ref[BeaconSyncNetworkState:ObjectType]](getNetworkState(peer.network,
        BeaconSyncProtocol))

  return peer.network.metadata

proc beaconBlocksByRangeUserHandler(peer: Peer; startSlot: Slot; count: uint64;
                                   step: uint64; response: MultipleChunksResponse[
    SignedBeaconBlock]) {.async, libp2pProtocol("beacon_blocks_by_range", 1), gcsafe.} =
  type
    CurrentProtocol = BeaconSync
  template state(peer: Peer): ref[BeaconSyncPeerState:ObjectType] =
    cast[ref[BeaconSyncPeerState:ObjectType]](getState(peer, BeaconSyncProtocol))

  template networkState(peer: Peer): ref[BeaconSyncNetworkState:ObjectType] =
    cast[ref[BeaconSyncNetworkState:ObjectType]](getNetworkState(peer.network,
        BeaconSyncProtocol))

  trace "got range request", peer, startSlot, count, step
  if count > 0'u64:
    var blocks: array[MAX_REQUESTED_BLOCKS, BlockRef]
    let
      chainDag = peer.networkState.chainDag
      count = min(count.Natural, blocks.len)
    let
      endIndex = count - 1
      startIndex = chainDag.getBlockRange(startSlot, step,
                                        blocks.toOpenArray(0, endIndex))
    for b in blocks[startIndex .. endIndex]:
      doAssert not b.isNil, "getBlockRange should return non-nil blocks only"
      trace "wrote response block", slot = b.slot, roor = shortLog(b.root)
      await response.write(chainDag.get(b).data)
    debug "Block range request done", peer, startSlot, count, step,
         found = count - startIndex

proc beaconBlocksByRootUserHandler(peer: Peer; blockRoots: BlockRootsList; response: MultipleChunksResponse[
    SignedBeaconBlock]) {.async, libp2pProtocol("beacon_blocks_by_root", 1), gcsafe.} =
  type
    CurrentProtocol = BeaconSync
  template state(peer: Peer): ref[BeaconSyncPeerState:ObjectType] =
    cast[ref[BeaconSyncPeerState:ObjectType]](getState(peer, BeaconSyncProtocol))

  template networkState(peer: Peer): ref[BeaconSyncNetworkState:ObjectType] =
    cast[ref[BeaconSyncNetworkState:ObjectType]](getNetworkState(peer.network,
        BeaconSyncProtocol))

  let
    chainDag = peer.networkState.chainDag
    count = blockRoots.len
  var found = 0
  for root in blockRoots[0 ..< count]:
    let blockRef = chainDag.getRef(root)
    if not isNil(blockRef):
      await response.write(chainDag.get(blockRef).data)
      inc found
  debug "Block root request done", peer, roots = blockRoots.len, count, found

proc goodbyeUserHandler(peer: Peer; reason: uint64) {.async,
    libp2pProtocol("goodbye", 1), gcsafe.} =
  type
    CurrentProtocol = BeaconSync
  template state(peer: Peer): ref[BeaconSyncPeerState:ObjectType] =
    cast[ref[BeaconSyncPeerState:ObjectType]](getState(peer, BeaconSyncProtocol))

  template networkState(peer: Peer): ref[BeaconSyncNetworkState:ObjectType] =
    cast[ref[BeaconSyncNetworkState:ObjectType]](getNetworkState(peer.network,
        BeaconSyncProtocol))

  debug "Received Goodbye message", reason = disconnectReasonName(reason), peer

template callUserHandler(MSG: type statusObj; peer: Peer; stream: Connection;
                        msg: StatusMsg): untyped =
  var response = init(SingleChunkResponse[StatusMsg], peer, stream)
  statusUserHandler(peer, msg, response)

proc statusMounter(network: Eth2Node) =
  proc snappyThunk(stream: Connection; protocol: string): Future[void] {.gcsafe.} =
    return handleIncomingStream(network, stream, statusObj)

  mount network.switch, LPProtocol(codec: "/eth2/beacon_chain/req/status/1/" &
      "ssz_snappy", handler: snappyThunk)

template callUserHandler(MSG: type pingObj; peer: Peer; stream: Connection; msg: uint64): untyped =
  sendUserHandlerResultAsChunkImpl(stream, pingUserHandler(peer, msg))

proc pingMounter(network: Eth2Node) =
  proc snappyThunk(stream: Connection; protocol: string): Future[void] {.gcsafe.} =
    return handleIncomingStream(network, stream, pingObj)

  mount network.switch, LPProtocol(codec: "/eth2/beacon_chain/req/ping/1/" &
      "ssz_snappy", handler: snappyThunk)

template callUserHandler(MSG: type getMetadataObj; peer: Peer; stream: Connection;
                        msg: getMetadataObj): untyped =
  sendUserHandlerResultAsChunkImpl(stream, getMetadataUserHandler(peer))

proc getMetadataMounter(network: Eth2Node) =
  proc snappyThunk(stream: Connection; protocol: string): Future[void] {.gcsafe.} =
    return handleIncomingStream(network, stream, getMetadataObj)

  mount network.switch, LPProtocol(codec: "/eth2/beacon_chain/req/metadata/1/" &
      "ssz_snappy", handler: snappyThunk)

template callUserHandler(MSG: type beaconBlocksByRangeObj; peer: Peer;
                        stream: Connection; msg: beaconBlocksByRangeObj): untyped =
  var response = init(MultipleChunksResponse[SignedBeaconBlock], peer, stream)
  beaconBlocksByRangeUserHandler(peer, msg.startSlot, msg.count, msg.step, response)

proc beaconBlocksByRangeMounter(network: Eth2Node) =
  proc snappyThunk(stream: Connection; protocol: string): Future[void] {.gcsafe.} =
    return handleIncomingStream(network, stream, beaconBlocksByRangeObj)

  mount network.switch, LPProtocol(codec: "/eth2/beacon_chain/req/beacon_blocks_by_range/1/" &
      "ssz_snappy", handler: snappyThunk)

template callUserHandler(MSG: type beaconBlocksByRootObj; peer: Peer;
                        stream: Connection; msg: BlockRootsList): untyped =
  var response = init(MultipleChunksResponse[SignedBeaconBlock], peer, stream)
  beaconBlocksByRootUserHandler(peer, msg, response)

proc beaconBlocksByRootMounter(network: Eth2Node) =
  proc snappyThunk(stream: Connection; protocol: string): Future[void] {.gcsafe.} =
    return handleIncomingStream(network, stream, beaconBlocksByRootObj)

  mount network.switch, LPProtocol(codec: "/eth2/beacon_chain/req/beacon_blocks_by_root/1/" &
      "ssz_snappy", handler: snappyThunk)

template callUserHandler(MSG: type goodbyeObj; peer: Peer; stream: Connection;
                        msg: uint64): untyped =
  goodbyeUserHandler(peer, msg)

proc goodbyeMounter(network: Eth2Node) =
  proc snappyThunk(stream: Connection; protocol: string): Future[void] {.gcsafe.} =
    return handleIncomingStream(network, stream, goodbyeObj)

  mount network.switch, LPProtocol(codec: "/eth2/beacon_chain/req/goodbye/1/" &
      "ssz_snappy", handler: snappyThunk)

registerMsg(BeaconSyncProtocol, "status", statusMounter,
            "/eth2/beacon_chain/req/status/1/")
registerMsg(BeaconSyncProtocol, "ping", pingMounter,
            "/eth2/beacon_chain/req/ping/1/")
registerMsg(BeaconSyncProtocol, "getMetadata", getMetadataMounter,
            "/eth2/beacon_chain/req/metadata/1/")
registerMsg(BeaconSyncProtocol, "beaconBlocksByRange", beaconBlocksByRangeMounter,
            "/eth2/beacon_chain/req/beacon_blocks_by_range/1/")
registerMsg(BeaconSyncProtocol, "beaconBlocksByRoot", beaconBlocksByRootMounter,
            "/eth2/beacon_chain/req/beacon_blocks_by_root/1/")
registerMsg(BeaconSyncProtocol, "goodbye", goodbyeMounter,
            "/eth2/beacon_chain/req/goodbye/1/")
proc BeaconSyncPeerConnected(peer: Peer; incoming: bool) {.async, gcsafe.} =
  type
    CurrentProtocol = BeaconSync
  template state(peer: Peer): ref[BeaconSyncPeerState:ObjectType] =
    cast[ref[BeaconSyncPeerState:ObjectType]](getState(peer, BeaconSyncProtocol))

  template networkState(peer: Peer): ref[BeaconSyncNetworkState:ObjectType] =
    cast[ref[BeaconSyncNetworkState:ObjectType]](getNetworkState(peer.network,
        BeaconSyncProtocol))

  debug "Peer connected", peer, peerInfo = shortLog(peer.info), incoming
  let
    ourStatus = peer.networkState.getCurrentStatus()
    theirStatus = await peer.status(ourStatus, timeout = 60.seconds)
  if theirStatus.isOk:
    await peer.handleStatus(peer.networkState, ourStatus, theirStatus.get())
  else:
    warn "Status response not received in time", peer, error = theirStatus.error

setEventHandlers(BeaconSyncProtocol, BeaconSyncPeerConnected, nil)
registerProtocol(BeaconSyncProtocol)