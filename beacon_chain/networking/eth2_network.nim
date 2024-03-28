{.push raises: [].}

import
  results,
  chronos,
  libp2p/switch,
  ../spec/[eth2_ssz_serialization, network]

type
  ErrorMsg = List[byte, 256]
  Eth2Node = ref object of RootObj
    switch: Switch
    protocols: seq[ProtocolInfo]

  Peer = ref object
    network: Eth2Node
    peerId: PeerId
    connectionState: ConnectionState
    protocolStates: seq[RootRef]

  ConnectionState = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  UntypedResponse = ref object
    peer: Peer
    stream: Connection
    writtenChunks: int

  SingleChunkResponse[MsgType] = distinct UntypedResponse

  MultipleChunksResponse[MsgType; maxLen: static Limit] = distinct UntypedResponse

  MessageInfo = object
    name: string

    libp2pCodecName: string
    protocolMounter: MounterProc

  ProtocolInfoObj = object
    name: string
    messages: seq[MessageInfo]
    index: int # the position of the protocol in the
                # ordered list of supported protocols

    peerStateInitializer: PeerStateInitializer
    networkStateInitializer: NetworkStateInitializer
    onPeerConnected: OnPeerConnectedHandler
    onPeerDisconnected: OnPeerDisconnectedHandler

  ProtocolInfo = ptr ProtocolInfoObj

  ResponseCode = enum
    Success
    InvalidRequest
    ServerError
    ResourceUnavailable

  PeerStateInitializer = proc(peer: Peer): RootRef {.gcsafe, raises: [].}
  NetworkStateInitializer = proc(network: Eth2Node): RootRef {.gcsafe, raises: [].}
  OnPeerConnectedHandler = proc(peer: Peer, incoming: bool): Future[void] {.async: (raises: [CancelledError]).}
  OnPeerDisconnectedHandler = proc(peer: Peer): Future[void] {.async: (raises: [CancelledError]).}
  MounterProc = proc(network: Eth2Node) {.gcsafe, raises: [].}

  Eth2NetworkingErrorKind = enum
    BrokenConnection
    ReceivedErrorResponse
    UnexpectedEOF
    PotentiallyExpectedEOF
    StreamOpenTimeout
    ReadResponseTimeout

    InvalidResponseCode
    InvalidSnappyBytes
    InvalidSszBytes
    InvalidSizePrefix
    ZeroSizePrefix
    SizePrefixOverflow
    InvalidContextBytes
    ResponseChunkOverflow

    UnknownError

  Eth2NetworkingError = object
    case kind: Eth2NetworkingErrorKind
    of ReceivedErrorResponse:
      responseCode: ResponseCode
      errorMsg: string
    else:
      discard

  InvalidInputsError = object of CatchableError

  ResourceUnavailableError = object of CatchableError

  NetRes[T] = Result[T, Eth2NetworkingError]

template neterr(kindParam: Eth2NetworkingErrorKind): auto =
  err(type(result), Eth2NetworkingError(kind: kindParam))

const
  libp2p_pki_schemes {.strdefine.} = ""

when libp2p_pki_schemes != "secp256k1":
  {.fatal: "Incorrect building process, please use -d:\"libp2p_pki_schemes=secp256k1\"".}

template libp2pProtocol(name: string, version: int) {.pragma.}

func shortProtocolId(protocolId: string): string = discard
proc init(T: type Peer, network: Eth2Node, peerId: PeerId): Peer {.gcsafe.}

proc getPeer(node: Eth2Node, peerId: PeerId): Peer = discard
proc peerFromStream(network: Eth2Node, conn: Connection): Peer =
  result = network.getPeer(conn.peerId)
  result.peerId = conn.peerId

func `<`(a, b: Peer): bool = false
const
  maxRequestQuota = 1000000
  fullReplenishTime = 5.seconds

template awaitQuota(peerParam: Peer, costParam: float, protocolIdParam: string) = discard

template awaitQuota(
    networkParam: Eth2Node, costParam: float, protocolIdParam: string) =
  let
    network = networkParam
    cost = int(costParam)

  if not network.quota.tryConsume(cost.int):
    let protocolId = protocolIdParam
    nbc_reqresp_messages_throttled.inc(1, [protocolId])
    await network.quota.consume(cost.int)

func allowedOpsPerSecondCost(n: int): float =
  const replenishRate = (maxRequestQuota / fullReplenishTime.nanoseconds.float)
  (replenishRate * 1000000000'f / n.float)

const
  libp2pRequestCost = allowedOpsPerSecondCost(8)

proc releasePeer(peer: Peer) = discard
proc sendErrorResponse(peer: Peer,
                       conn: Connection,
                       responseCode: ResponseCode,
                       errMsg: ErrorMsg): Future[void] = discard
proc uncompressFramedStream(conn: Connection,
                            expectedSize: int): Future[Result[seq[byte], string]]
                            {.async: (raises: [CancelledError]).} = discard
func chunkMaxSize[T](): uint32 =
  when isFixedSize(T):
    uint32 fixedPortionSize(T)
  else:
    static: doAssert MAX_CHUNK_SIZE < high(uint32).uint64
    MAX_CHUNK_SIZE.uint32

proc readVarint2(conn: Connection): Future[NetRes[uint64]] {.
    async: (raises: [CancelledError]).} =
  try:
    ok await conn.readVarint()
  except LPStreamEOFError: #, LPStreamIncompleteError, InvalidVarintError
    neterr UnexpectedEOF
  except LPStreamIncompleteError:
    neterr UnexpectedEOF
  except InvalidVarintError:
    neterr InvalidSizePrefix
  except CancelledError as exc:
    raise exc
  except CatchableError:
    neterr UnknownError

proc readChunkPayload(conn: Connection, peer: Peer,
                       MsgType: type): Future[NetRes[MsgType]]
                       {.async: (raises: [CancelledError]).} =
  let
    sm = now(chronos.Moment)
    size = ? await readVarint2(conn)

  const maxSize = chunkMaxSize[MsgType]()
  if size > maxSize:
    return neterr SizePrefixOverflow
  if size == 0:
    return neterr ZeroSizePrefix

  let
    dataRes = await conn.uncompressFramedStream(size.int)
    data = dataRes.valueOr:
      return neterr InvalidSnappyBytes

  try:
    ok SSZ.decode(data, MsgType)
  except SerializationError:
    neterr InvalidSszBytes

proc init(T: type MultipleChunksResponse, peer: Peer, conn: Connection): T =
  T(UntypedResponse(peer: peer, stream: conn))

proc init[MsgType](T: type SingleChunkResponse[MsgType],
                    peer: Peer, conn: Connection): T =
  T(UntypedResponse(peer: peer, stream: conn))

proc initProtocol(name: string,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer,
                  index: int): ProtocolInfoObj =
  ProtocolInfoObj(
    name: name,
    messages: @[],
    index: index,
    peerStateInitializer: peerInit,
    networkStateInitializer: networkInit)

proc setEventHandlers(p: ProtocolInfo,
                      onPeerConnected: OnPeerConnectedHandler,
                      onPeerDisconnected: OnPeerDisconnectedHandler) =
  p.onPeerConnected = onPeerConnected
  p.onPeerDisconnected = onPeerDisconnected

proc handleIncomingStream(network: Eth2Node,
                          conn: Connection,
                          protocolId: string,
                          MsgType: type) {.async: (raises: [CancelledError]).} =
  mixin callUserHandler, RecType

  type MsgRec = RecType(MsgType)
  const msgName {.used.} = typetraits.name(MsgType)


  let peer = peerFromStream(network, conn)
  try:
    case peer.connectionState
    of Disconnecting, Disconnected, None:
      return
    of Connecting:
      discard
    of Connected:
      discard

    template returnInvalidRequest(msg: ErrorMsg) =
      await sendErrorResponse(peer, conn, InvalidRequest, msg)
      return

    template returnInvalidRequest(msg: string) =
      returnInvalidRequest(default(ErrorMsg))

    template returnResourceUnavailable(msg: ErrorMsg) =
      await sendErrorResponse(peer, conn, ResourceUnavailable, msg)
      return

    template returnResourceUnavailable(msg: string) =
      returnResourceUnavailable(default(ErrorMsg))

    const isEmptyMsg = when MsgRec is object:
      when totalSerializedFields(MsgRec) == 0: true
      else: false
    else:
      false

    let msg =
      try:
        when isEmptyMsg:
          NetRes[MsgRec].ok default(MsgRec)
        else:
          # TODO(zah) The TTFB timeout is not implemented in LibP2P streams
          # back-end
          let deadline = sleepAsync RESP_TIMEOUT_DUR

          await(readChunkPayload(conn, peer, MsgRec))

      finally:




        awaitQuota(peer, libp2pRequestCost, shortProtocolId(protocolId))

    try:
      await callUserHandler(MsgType, peer, conn, msg.get)
    except InvalidInputsError as exc:
      returnInvalidRequest exc.msg
    except ResourceUnavailableError as exc:
      returnResourceUnavailable exc.msg
    except CatchableError:
      await sendErrorResponse(peer, conn, ServerError, default(ErrorMsg))

  except CatchableError:
    discard

  finally:
    try:
      await noCancel conn.closeWithEOF()
    except CatchableError:
      discard
    releasePeer(peer)

proc init(T: type Peer, network: Eth2Node, peerId: PeerId): Peer =
  let res = Peer(
    peerId: peerId,
    network: network,
    connectionState: ConnectionState.None,
    lastReqTime: now(chronos.Moment),
    lastMetadataTime: now(chronos.Moment),
  )
  res.protocolStates.setLen(network.protocolStates.len())
  for proto in network.protocols:
    if not(isNil(proto.peerStateInitializer)):
      res.protocolStates[proto.index] = proto.peerStateInitializer(res)
  res

proc registerMsg(protocol: ProtocolInfo,
                 name: string,
                 mounter: MounterProc,
                 libp2pCodecName: string) =
  protocol.messages.add MessageInfo(name: name,
                                    protocolMounter: mounter,
                                    libp2pCodecName: libp2pCodecName)

type
  BeaconSync = object
type
  beaconBlocksByRange_v2Obj = object
    reqCount: uint64
    reqStep: uint64

template RecType(MSG: type beaconBlocksByRange_v2Obj): untyped =
  beaconBlocksByRange_v2Obj

var BeaconSyncProtocolObj = initProtocol("BeaconSync", nil, nil, 0)
let BeaconSyncProtocol = addr BeaconSyncProtocolObj
proc beaconBlocksByRange_v2UserHandler(peer: Peer; reqCount: uint64;
                                       reqStep: uint64; response: MultipleChunksResponse[
    ref uint64, Limit MAX_REQUEST_BLOCKS]) {.async,
    libp2pProtocol("beacon_blocks_by_range", 2), gcsafe.} =
  type
    CurrentProtocol {.used.} = BeaconSync

  discard

template callUserHandler(MSG: type beaconBlocksByRange_v2Obj; peer: Peer;
                         stream: Connection; msg: beaconBlocksByRange_v2Obj): untyped =
  var response = init(MultipleChunksResponse[ref uint64,
      Limit MAX_REQUEST_BLOCKS], peer, stream)
  beaconBlocksByRange_v2UserHandler(peer, msg.reqCount, msg.reqStep, response)

proc beaconBlocksByRange_v2Mounter(network: Eth2Node) {.raises: [].} =
  proc snappyThunk(stream: Connection; protocol: string): Future[void] {.gcsafe.} =
    return handleIncomingStream(network, stream, protocol,
                                beaconBlocksByRange_v2Obj)

  try:
    mount network.switch, LPProtocol.new(codecs = @[
        "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"],
        handler = snappyThunk)
  except LPError:
    raiseAssert "foo"

registerMsg(BeaconSyncProtocol, "beaconBlocksByRange_v2",
            beaconBlocksByRange_v2Mounter,
            "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy")
setEventHandlers(BeaconSyncProtocol, nil, nil)
