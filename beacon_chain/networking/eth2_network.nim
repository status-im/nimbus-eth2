{.push raises: [].}

import
  std/[typetraits, os, strutils, tables, macrocache],
  results,
  stew/[leb128, byteutils, io2],
  stew/shims/macros,
  json_serialization, json_serialization/std/[net, sets, options],
  chronos, chronos/ratelimit, chronicles,
  libp2p/[switch, peerinfo, multiaddress, multicodec, crypto/crypto,
    crypto/secp, builders],
  libp2p/protocols/pubsub/[
      pubsub, gossipsub, rpc/message, rpc/messages, peertable, pubsubpeer],
  libp2p/stream/connection,
  eth/[keys, async_utils],
  ../spec/[eth2_ssz_serialization, network, helpers, forks],
  "."/[eth2_discovery, eth2_protocol_dsl, libp2p_json_serialization, peer_pool, peer_scores]

type
  PublicKey = crypto.PublicKey
  ErrorMsg = List[byte, 256]
  DirectPeers = Table[PeerId, seq[MultiAddress]]

  SeenItem = object
    peerId: PeerId
    stamp: chronos.Moment

  Eth2Node = ref object of RootObj
    switch: Switch
    pubsub: GossipSub
    discovery: Eth2DiscoveryProtocol
    discoveryEnabled: bool
    wantedPeers: int
    hardMaxPeers: int
    peerPool: PeerPool[Peer, PeerId]
    protocols: seq[ProtocolInfo]
    protocolStates: seq[RootRef]
    metadata: altair.MetaData
    connectTimeout: chronos.Duration
    seenThreshold: chronos.Duration
    connQueue: AsyncQueue[PeerAddr]
    seenTable: Table[PeerId, SeenItem]
    connWorkers: seq[Future[void].Raising([CancelledError])]
    connTable: HashSet[PeerId]
    forkId: ENRForkID
    discoveryForkId: ENRForkID
    forkDigests: ref ForkDigests
    rng: ref HmacDrbgContext
    peers: Table[PeerId, Peer]
    directPeers: DirectPeers
    validTopics: HashSet[string]
    peerPingerHeartbeatFut: Future[void].Raising([CancelledError])
    peerTrimmerHeartbeatFut: Future[void].Raising([CancelledError])
    cfg: RuntimeConfig

    quota: TokenBucket ## Global quota mainly for high-bandwidth stuff

  AverageThroughput = object
    count: uint64
    average: float

  Peer = ref object
    network: Eth2Node
    peerId: PeerId
    discoveryId: Eth2DiscoveryId
    connectionState: ConnectionState
    protocolStates: seq[RootRef]
    netThroughput: AverageThroughput
    score: int
    quota: TokenBucket
    lastReqTime: Moment
    connections: int
    enr: Opt[enr.Record]
    metadata: Opt[altair.MetaData]
    failedMetadataRequests: int
    lastMetadataTime: Moment
    direction: PeerType
    disconnectedFut: Future[void]
    statistics: SyncResponseStats

  PeerAddr = object
    peerId: PeerId
    addrs: seq[MultiAddress]

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

  DisconnectionReason = enum
    ClientShutDown = 1
    IrrelevantNetwork = 2
    FaultOrError = 3
    PeerScoreLow = 237 # 79  3

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

const
  requestPrefix = "/eth2/beacon_chain/req/"
  requestSuffix = "/ssz_snappy"

  SeenTableTimeIrrelevantNetwork = 24.hours
  SeenTableTimeClientShutDown = 10.minutes
  SeenTableTimeFaultOrError = 10.minutes
  SeenTablePenaltyError = 60.minutes
  ProtocolViolations = {InvalidResponseCode..Eth2NetworkingErrorKind.high()}

template neterr(kindParam: Eth2NetworkingErrorKind): auto =
  err(type(result), Eth2NetworkingError(kind: kindParam))

const
  libp2p_pki_schemes {.strdefine.} = ""

when libp2p_pki_schemes != "secp256k1":
  {.fatal: "Incorrect building process, please use -d:\"libp2p_pki_schemes=secp256k1\"".}

template libp2pProtocol(name: string, version: int) {.pragma.}

func shortLog(peer: Peer): string = shortLog(peer.peerId)
func shortProtocolId(protocolId: string): string =
  let
    start = if protocolId.startsWith(requestPrefix): requestPrefix.len else: 0
    ends = if protocolId.endsWith(requestSuffix):
      protocolId.high - requestSuffix.len
    else:
      protocolId.high
  protocolId[start..ends]

proc init(T: type Peer, network: Eth2Node, peerId: PeerId): Peer {.gcsafe.}

proc getNetworkState(node: Eth2Node, proto: ProtocolInfo): RootRef =
  doAssert node.protocolStates[proto.index] != nil, $proto.index
  node.protocolStates[proto.index]

proc getPeer(node: Eth2Node, peerId: PeerId): Peer =
  node.peers.withValue(peerId, peer) do:
    return peer[]
  do:
    let peer = Peer.init(node, peerId)
    return node.peers.mgetOrPut(peerId, peer)

proc peerFromStream(network: Eth2Node, conn: Connection): Peer =
  result = network.getPeer(conn.peerId)
  result.peerId = conn.peerId

func updateScore(peer: Peer, score: int) {.inline.} =
  peer.score = peer.score + score
  if peer.score > PeerScoreHighLimit:
    peer.score = PeerScoreHighLimit

func calcThroughput(dur: Duration, value: uint64): float =
  let secs = float(chronos.seconds(1).nanoseconds)
  if isZero(dur):
    0.0
  else:
    float(value) * (secs / float(dur.nanoseconds))

func updateNetThroughput(peer: Peer, dur: Duration,
                         bytesCount: uint64) {.inline.} =
  let bytesPerSecond = calcThroughput(dur, bytesCount)
  let a = peer.netThroughput.average
  let n = peer.netThroughput.count
  peer.netThroughput.average = a + (bytesPerSecond - a) / float(n + 1)
  inc(peer.netThroughput.count)

func `<`(a, b: Peer): bool =
  if a.score < b.score:
    true
  elif a.score == b.score:
    (a.netThroughput.average < b.netThroughput.average)
  else:
    false

const
  maxRequestQuota = 1000000
  fullReplenishTime = 5.seconds

template awaitQuota(peerParam: Peer, costParam: float, protocolIdParam: string) =
  let
    peer = peerParam
    cost = int(costParam)

  if not peer.quota.tryConsume(cost.int):
    let protocolId = protocolIdParam
    await peer.quota.consume(cost.int)

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

proc addSeen(network: Eth2Node, peerId: PeerId,
              period: chronos.Duration) =
  let item = SeenItem(peerId: peerId, stamp: now(chronos.Moment) + period)
  withValue(network.seenTable, peerId, entry) do:
    if entry.stamp < item.stamp:
      entry.stamp = item.stamp
  do:
    network.seenTable[peerId] = item

proc disconnect(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async: (raises: [CancelledError]).} =
  try:
    if peer.connectionState notin {Disconnecting, Disconnected}:
      peer.connectionState = Disconnecting
      let seenTime = case reason
        of ClientShutDown:
          SeenTableTimeClientShutDown
        of IrrelevantNetwork:
          SeenTableTimeIrrelevantNetwork
        of FaultOrError:
          SeenTableTimeFaultOrError
        of PeerScoreLow:
          SeenTablePenaltyError
      peer.network.addSeen(peer.peerId, seenTime)
      await peer.network.switch.disconnect(peer.peerId)
  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    warn "Unexpected error while disconnecting peer",
      peer = peer.peerId,
      reason = reason,
      exc = exc.msg

proc releasePeer(peer: Peer) =
  if peer.connectionState notin {ConnectionState.Disconnecting,
                                 ConnectionState.Disconnected}:
    if peer.score < PeerScoreLowLimit:
      asyncSpawn(peer.disconnect(PeerScoreLow))

proc getRequestProtoName(fn: NimNode): NimNode =

  let pragmas = fn.pragma
  if pragmas.kind == nnkPragma and pragmas.len > 0:
    for pragma in pragmas:
      try:
        if pragma.len > 0 and $pragma[0] == "libp2pProtocol":
          let protoName = $(pragma[1])
          let protoVer = $(pragma[2].intVal)
          return newLit(requestPrefix & protoName & "/" & protoVer & requestSuffix)
      except Exception as exc: raiseAssert exc.msg # TODO https://github.com/nim-lang/Nim/issues/17454

  return newLit("")

template errorMsgLit(x: static string): ErrorMsg =
  const val = ErrorMsg toBytes(x)
  val

proc sendErrorResponse(peer: Peer,
                       conn: Connection,
                       responseCode: ResponseCode,
                       errMsg: ErrorMsg): Future[void] = discard
proc sendNotificationMsg(peer: Peer, protocolId: string, requestBytes: seq[byte])
    {.async: (raises: [CancelledError]).} =  discard
proc sendResponseChunkBytes(
    response: UntypedResponse, payload: openArray[byte],
    contextBytes: openArray[byte] = []): Future[void] = discard
proc uncompressFramedStream(conn: Connection,
                            expectedSize: int): Future[Result[seq[byte], string]]
                            {.async: (raises: [CancelledError]).} = discard
func chunkMaxSize[T](): uint32 =
  when isFixedSize(T):
    uint32 fixedPortionSize(T)
  else:
    static: doAssert MAX_CHUNK_SIZE < high(uint32).uint64
    MAX_CHUNK_SIZE.uint32

from ../spec/datatypes/capella import SignedBeaconBlock
from ../spec/datatypes/deneb import SignedBeaconBlock

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
  except CatchableError as exc:
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

  peer.updateNetThroughput(now(chronos.Moment) - sm,
                            uint64(10 + size))
  try:
    ok SSZ.decode(data, MsgType)
  except SerializationError:
    neterr InvalidSszBytes

proc makeEth2Request(peer: Peer, protocolId: string, requestBytes: seq[byte],
                     ResponseMsg: type,
                     timeout: Duration): Future[NetRes[ResponseMsg]]
                    {.async: (raises: [CancelledError]).} = discard

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

proc implementSendProcBody(sendProc: SendProc) =
  let
    msg = sendProc.msg
    UntypedResponse = bindSym "UntypedResponse"

  proc sendCallGenerator(peer, bytes: NimNode): NimNode =
    if msg.kind != msgResponse:
      let msgProto = getRequestProtoName(msg.procDef)
      case msg.kind
      of msgRequest:
        let ResponseRecord = msg.response.recName
        quote:
          makeEth2Request(`peer`, `msgProto`, `bytes`,
                          `ResponseRecord`, `timeoutVar`)
      else:
        quote: sendNotificationMsg(`peer`, `msgProto`, `bytes`)
    else:
      quote: sendResponseChunkBytes(`UntypedResponse`(`peer`), `bytes`)

  sendProc.useStandardBody(nil, nil, sendCallGenerator)

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
      peer.updateScore(PeerScoreInvalidRequest)
      await sendErrorResponse(peer, conn, InvalidRequest, msg)
      return

    template returnInvalidRequest(msg: string) =
      returnInvalidRequest(ErrorMsg msg.toBytes)

    template returnResourceUnavailable(msg: ErrorMsg) =
      await sendErrorResponse(peer, conn, ResourceUnavailable, msg)
      return

    template returnResourceUnavailable(msg: string) =
      returnResourceUnavailable(ErrorMsg msg.toBytes)

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

          awaitWithTimeout(
            readChunkPayload(conn, peer, MsgRec), deadline):
              # Timeout, e.g., cancellation due to fulfillment by different peer.
              # Treat this similarly to `UnexpectedEOF`, `PotentiallyExpectedEOF`.
              await sendErrorResponse(
                peer, conn, InvalidRequest,
                errorMsgLit "Request full data not sent in time")
              return

      finally:




        awaitQuota(peer, libp2pRequestCost, shortProtocolId(protocolId))

    if msg.isErr:
      if msg.error.kind in ProtocolViolations:
        peer.updateScore(PeerScoreInvalidRequest)
      else:
        peer.updateScore(PeerScorePoorRequest)

      let (responseCode, errMsg) = case msg.error.kind
        of UnexpectedEOF, PotentiallyExpectedEOF:
          (InvalidRequest, errorMsgLit "Incomplete request")

        of InvalidContextBytes:
          (ServerError, errorMsgLit "Unrecognized context bytes")

        of InvalidSnappyBytes:
          (InvalidRequest, errorMsgLit "Failed to decompress snappy payload")

        of InvalidSszBytes:
          (InvalidRequest, errorMsgLit "Failed to decode SSZ payload")

        of InvalidSizePrefix:
          (InvalidRequest, errorMsgLit "Invalid chunk size prefix")

        of ZeroSizePrefix:
          (InvalidRequest, errorMsgLit "The request chunk cannot have a size of zero")

        of SizePrefixOverflow:
          (InvalidRequest, errorMsgLit "The chunk size exceed the maximum allowed")

        of InvalidResponseCode, ReceivedErrorResponse,
           StreamOpenTimeout, ReadResponseTimeout:
          # These shouldn't be possible in a request, because
          # there are no response codes being read, no stream
          # openings and no reading of responses:
          (ServerError, errorMsgLit "Internal server error")

        of BrokenConnection:
          return

        of ResponseChunkOverflow:
          (InvalidRequest, errorMsgLit "Too many chunks in response")

        of UnknownError:
          (InvalidRequest, errorMsgLit "Unknown error while processing request")

      await sendErrorResponse(peer, conn, responseCode, errMsg)
      return

    try:
      await callUserHandler(MsgType, peer, conn, msg.get)
    except InvalidInputsError as exc:
      returnInvalidRequest exc.msg
    except ResourceUnavailableError as exc:
      returnResourceUnavailable exc.msg
    except CatchableError as exc:
      await sendErrorResponse(peer, conn, ServerError, ErrorMsg exc.msg.toBytes)

  except CatchableError as exc:
    discard

  finally:
    try:
      await noCancel conn.closeWithEOF()
    except CatchableError as exc:
      discard
    releasePeer(peer)

proc init(T: type Peer, network: Eth2Node, peerId: PeerId): Peer =
  let res = Peer(
    peerId: peerId,
    network: network,
    connectionState: ConnectionState.None,
    lastReqTime: now(chronos.Moment),
    lastMetadataTime: now(chronos.Moment),
    quota: TokenBucket.new(maxRequestQuota.int, fullReplenishTime)
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

proc p2pProtocolBackendImpl(p: P2PProtocol): Backend =
  var
    Format = ident "SSZ"
    Connection = bindSym "Connection"
    Peer = bindSym "Peer"
    Eth2Node = bindSym "Eth2Node"
    registerMsg = bindSym "registerMsg"
    initProtocol = bindSym "initProtocol"
    msgVar = ident "msg"
    networkVar = ident "network"
    callUserHandler = ident "callUserHandler"
    MSG = ident "MSG"

  new result

  result.PeerType = Peer
  result.NetworkType = Eth2Node
  result.setEventHandlers = bindSym "setEventHandlers"
  result.SerializationFormat = Format
  result.RequestResultsWrapper = ident "NetRes"

  result.implementMsg = proc (msg: eth2_protocol_dsl.Message) =
    if msg.kind == msgResponse:
      return

    let
      protocol = msg.protocol
      msgName = $msg.ident
      msgNameLit = newLit msgName
      MsgRecName = msg.recName
      MsgStrongRecName = msg.strongRecName
      codecNameLit = getRequestProtoName(msg.procDef)
      protocolMounterName = ident(msgName & "Mounter")

    var userHandlerCall = newTree(nnkDiscardStmt)

    if msg.userHandler != nil:
      var OutputParamType = if msg.kind == msgRequest: msg.outputParamType
                            else: nil

      if OutputParamType == nil:
        userHandlerCall = msg.genUserHandlerCall(msgVar, [peerVar])
        if msg.kind == msgRequest:
          userHandlerCall = newCall(ident"sendUserHandlerResultAsChunkImpl",
                                    streamVar,
                                    userHandlerCall)
      else:
        if OutputParamType.kind == nnkVarTy:
          OutputParamType = OutputParamType[0]

        let isChunkStream = eqIdent(OutputParamType[0], "MultipleChunksResponse")
        msg.response.recName = if isChunkStream:
          newTree(nnkBracketExpr, ident"List", OutputParamType[1], OutputParamType[2])
        else:
          OutputParamType[1]

        let responseVar = ident("response")
        userHandlerCall = newStmtList(
          newVarStmt(responseVar,
                     newCall(ident"init", OutputParamType,
                                          peerVar, streamVar)),
          msg.genUserHandlerCall(msgVar, [peerVar], outputParam = responseVar))

    protocol.outRecvProcs.add quote do:
      template `callUserHandler`(`MSG`: type `MsgStrongRecName`,
                                 `peerVar`: `Peer`,
                                 `streamVar`: `Connection`,
                                 `msgVar`: `MsgRecName`): untyped =
        `userHandlerCall`

      proc `protocolMounterName`(`networkVar`: `Eth2Node`) {.raises: [].} =
        proc snappyThunk(`streamVar`: `Connection`,
                         `protocolVar`: string): Future[void] {.gcsafe.} =
          return handleIncomingStream(`networkVar`, `streamVar`, `protocolVar`,
                                      `MsgStrongRecName`)

        try:
          mount `networkVar`.switch,
                LPProtocol.new(
                  codecs = @[`codecNameLit`], handler = snappyThunk)
        except LPError as exc:
          # Failure here indicates that the mounting was done incorrectly which
          # would be a programming error
          raiseAssert exc.msg
    if msg.kind == msgHandshake:
      macros.error "Handshake messages are not supported in LibP2P protocols"
    else:
      var sendProc = msg.createSendProc()
      implementSendProcBody sendProc

    protocol.outProcRegistrations.add(
      newCall(registerMsg,
              protocol.protocolInfoVar,
              msgNameLit,
              protocolMounterName,
              codecNameLit))

  result.implementProtocolInit = proc (p: P2PProtocol): NimNode =
    let
      id = CacheCounter"eth2_network_protocol_id"
      tmp = id.value
    id.inc(1)

    newCall(initProtocol, newLit(p.name), p.peerInit, p.netInit, newLit(tmp))

type
  BeaconSyncNetworkState {.final.} = ref object of RootObj
    cfg: RuntimeConfig

p2pProtocol BeaconSync(version = 1,
                       networkState = BeaconSyncNetworkState):
  proc beaconBlocksByRange_v2(
      peer: Peer,
      reqCount: uint64,
      reqStep: uint64,
      response: MultipleChunksResponse[
        ref uint64, Limit MAX_REQUEST_BLOCKS])
      {.async, libp2pProtocol("beacon_blocks_by_range", 2).} = discard
