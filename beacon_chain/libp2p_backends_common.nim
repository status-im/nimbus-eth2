import
  metrics

type
  ResponseCode* = enum
    Success
    InvalidRequest
    ServerError

  Bytes = seq[byte]

const
  defaultIncomingReqTimeout = 5000
  HandshakeTimeout = FaultOrError

  # Spec constants
  # https://github.com/ethereum/eth2.0-specs/blob/dev/specs/networking/p2p-interface.md#eth-20-network-interaction-domains
  REQ_RESP_MAX_SIZE* = 1 * 1024 * 1024 # bytes
  GOSSIP_MAX_SIZE* = 1 * 1024 * 1024 # bytes
  TTFB_TIMEOUT* = 5.seconds
  RESP_TIMEOUT* = 10.seconds

  readTimeoutErrorMsg = "Exceeded read timeout for a request"

logScope:
  topics = "libp2p"

declarePublicGauge libp2p_peers, "Number of libp2p peers"

template libp2pProtocol*(name: string, version: int) {.pragma.}

proc getRequestProtoName(fn: NimNode): NimNode =
  # `getCustomPragmaVal` doesn't work yet on regular nnkProcDef nodes
  # (TODO: file as an issue)

  let pragmas = fn.pragma
  if pragmas.kind == nnkPragma and pragmas.len > 0:
    for pragma in pragmas:
      if pragma.len > 0 and $pragma[0] == "libp2pProtocol":
        let protoName = $(pragma[1])
        let protoVer = $(pragma[2].intVal)
        return newLit("/eth2/beacon_chain/req/" & protoName & "/" & protoVer & "/ssz")

  return newLit("")

template raisePeerDisconnected(msg: string, r: DisconnectionReason) =
  var e = newException(PeerDisconnected, msg)
  e.reason = r
  raise e

proc disconnectAndRaise(peer: Peer,
                        reason: DisconnectionReason,
                        msg: string) {.async.} =
  let r = reason
  await peer.disconnect(r)
  raisePeerDisconnected(msg, r)

proc readChunk(stream: P2PStream,
               MsgType: type,
               withResponseCode: bool,
               deadline: Future[void]): Future[Option[MsgType]] {.gcsafe.}

proc readSizePrefix(stream: P2PStream,
                    deadline: Future[void]): Future[int] {.async.} =
  trace "about to read msg size prefix"
  var parser: VarintParser[uint64, ProtoBuf]
  while true:
    var nextByte: byte
    var readNextByte = stream.readExactly(addr nextByte, 1)
    await readNextByte or deadline
    if not readNextByte.finished:
      trace "size prefix byte not received in time"
      return -1
    case parser.feedByte(nextByte)
    of Done:
      let res = parser.getResult
      if res > uint64(REQ_RESP_MAX_SIZE):
        trace "size prefix outside of range", res
        return -1
      else:
        trace "got size prefix", res
        return int(res)
    of Overflow:
      trace "size prefix overflow"
      return -1
    of Incomplete:
      continue

proc readMsgBytes(stream: P2PStream,
                  withResponseCode: bool,
                  deadline: Future[void]): Future[Bytes] {.async.} =
  trace "about to read message bytes", withResponseCode

  try:
    if withResponseCode:
      var responseCode: byte
      trace "about to read response code"
      var readResponseCode = stream.readExactly(addr responseCode, 1)
      await readResponseCode or deadline

      if not readResponseCode.finished:
        trace "response code not received in time"
        return

      if responseCode > ResponseCode.high.byte:
        trace "invalid response code", responseCode
        return

      logScope: responseCode = ResponseCode(responseCode)
      trace "got response code"

      case ResponseCode(responseCode)
      of InvalidRequest, ServerError:
        let responseErrMsg = await readChunk(stream, string, false, deadline)
        debug "P2P request resulted in error", responseErrMsg
        return

      of Success:
        # The response is OK, the execution continues below
        discard

    var sizePrefix = await readSizePrefix(stream, deadline)
    trace "got msg size prefix", sizePrefix

    if sizePrefix == -1:
      debug "Failed to read an incoming message size prefix", peer = stream.peer
      return

    if sizePrefix == 0:
      debug "Received SSZ with zero size", peer = stream.peer
      return

    trace "about to read msg bytes"
    var msgBytes = newSeq[byte](sizePrefix)
    var readBody = stream.readExactly(addr msgBytes[0], sizePrefix)
    await readBody or deadline
    if not readBody.finished:
      trace "msg bytes not received in time"
      return

    trace "got message bytes", msgBytes
    return msgBytes

  except TransportIncompleteError:
    return @[]

proc readChunk(stream: P2PStream,
               MsgType: type,
               withResponseCode: bool,
               deadline: Future[void]): Future[Option[MsgType]] {.gcsafe, async.} =
  var msgBytes = await stream.readMsgBytes(withResponseCode, deadline)
  try:
    if msgBytes.len > 0:
      return some SSZ.decode(msgBytes, MsgType)
  except SerializationError as err:
    debug "Failed to decode a network message",
          msgBytes, errMsg = err.formatMsg("<msg>")
    return

proc readResponse(
       stream: P2PStream,
       MsgType: type,
       deadline: Future[void]): Future[Option[MsgType]] {.gcsafe, async.} =

  when MsgType is seq:
    type E = ElemType(MsgType)
    var results: MsgType
    while true:
      let nextRes = await readChunk(stream, E, true, deadline)
      if nextRes.isNone: break
      results.add nextRes.get
    if results.len > 0:
      return some(results)
  else:
    return await readChunk(stream, MsgType, true, deadline)

proc encodeErrorMsg(responseCode: ResponseCode, errMsg: string): Bytes =
  var s = init OutputStream
  s.append byte(responseCode)
  s.appendVarint errMsg.len
  s.appendValue SSZ, errMsg
  s.getOutput

proc sendErrorResponse(peer: Peer,
                       stream: P2PStream,
                       err: ref SerializationError,
                       msgName: string,
                       msgBytes: Bytes) {.async.} =
  debug "Received an invalid request",
        peer, msgName, msgBytes, errMsg = err.formatMsg("<msg>")

  let responseBytes = encodeErrorMsg(InvalidRequest, err.formatMsg("msg"))
  await stream.writeAllBytes(responseBytes)
  await stream.close()

proc sendErrorResponse(peer: Peer,
                       stream: P2PStream,
                       responseCode: ResponseCode,
                       errMsg: string) {.async.} =
  debug "Error processing request", peer, responseCode, errMsg

  let responseBytes = encodeErrorMsg(ServerError, errMsg)
  await stream.writeAllBytes(responseBytes)
  await stream.close()

proc sendNotificationMsg(peer: Peer, protocolId: string, requestBytes: Bytes) {.async} =
  var deadline = sleepAsync RESP_TIMEOUT
  var streamFut = peer.network.openStream(peer, protocolId)
  await streamFut or deadline
  if not streamFut.finished:
    # TODO: we are returning here because the deadline passed, but
    # the stream can still be opened eventually a bit later. Who is
    # going to close it then?
    raise newException(TransmissionError, "Failed to open LibP2P stream")

  let stream = streamFut.read
  defer:
    await safeClose(stream)

  var s = init OutputStream
  s.appendVarint requestBytes.len.uint64
  s.append requestBytes
  let bytes = s.getOutput
  await stream.writeAllBytes(bytes)

# TODO There is too much duplication in the responder functions, but
# I hope to reduce this when I increse the reliance on output streams.
proc sendResponseChunkBytes(responder: UntypedResponder, payload: Bytes) {.async.} =
  var s = init OutputStream
  s.append byte(Success)
  s.appendVarint payload.len.uint64
  s.append payload
  let bytes = s.getOutput
  await responder.stream.writeAllBytes(bytes)

proc sendResponseChunkObj(responder: UntypedResponder, val: auto) {.async.} =
  var s = init OutputStream
  s.append byte(Success)
  s.appendValue SSZ, sizePrefixed(val)
  let bytes = s.getOutput
  await responder.stream.writeAllBytes(bytes)

proc sendResponseChunks[T](responder: UntypedResponder, chunks: seq[T]) {.async.} =
  var s = init OutputStream
  for chunk in chunks:
    s.append byte(Success)
    s.appendValue SSZ, sizePrefixed(chunk)

  let bytes = s.getOutput
  await responder.stream.writeAllBytes(bytes)

proc makeEth2Request(peer: Peer, protocolId: string, requestBytes: Bytes,
                     ResponseMsg: type,
                     timeout: Duration): Future[Option[ResponseMsg]] {.gcsafe, async.} =
  var deadline = sleepAsync timeout

  # Open a new LibP2P stream
  var streamFut = peer.network.openStream(peer, protocolId)
  await streamFut or deadline
  if not streamFut.finished:
    # TODO: we are returning here because the deadline passed, but
    # the stream can still be opened eventually a bit later. Who is
    # going to close it then?
    return none(ResponseMsg)

  let stream = streamFut.read
  defer:
    await safeClose(stream)

  # Send the request
  var s = init OutputStream
  s.appendVarint requestBytes.len.uint64
  s.append requestBytes
  let bytes = s.getOutput
  await stream.writeAllBytes(bytes)

  # Read the response
  return await stream.readResponse(ResponseMsg, deadline)

proc init*[MsgType](T: type Responder[MsgType],
                    peer: Peer, stream: P2PStream): T =
  T(UntypedResponder(peer: peer, stream: stream))

template write*[M](r: var Responder[M], val: auto): auto =
  mixin send
  type Msg = M
  type MsgRec = RecType(Msg)
  when MsgRec is seq|openarray:
    type E = ElemType(MsgRec)
    when val is E:
      sendResponseChunkObj(UntypedResponder(r), val)
    elif val is MsgRec:
      sendResponseChunks(UntypedResponder(r), val)
    else:
      {.fatal: "Unepected message type".}
  else:
    send(r, val)

proc performProtocolHandshakes*(peer: Peer) {.async.} =
  var subProtocolsHandshakes = newSeqOfCap[Future[void]](allProtocols.len)
  for protocol in allProtocols:
    if protocol.handshake != nil:
      subProtocolsHandshakes.add((protocol.handshake)(peer, nil))

  await all(subProtocolsHandshakes)

template initializeConnection*(peer: Peer): auto =
  performProtocolHandshakes(peer)

proc initProtocol(name: string,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer): ProtocolInfoObj =
  result.name = name
  result.messages = @[]
  result.peerStateInitializer = peerInit
  result.networkStateInitializer = networkInit

proc registerProtocol(protocol: ProtocolInfo) =
  # TODO: This can be done at compile-time in the future
  let pos = lowerBound(gProtocols, protocol)
  gProtocols.insert(protocol, pos)
  for i in 0 ..< gProtocols.len:
    gProtocols[i].index = i

proc setEventHandlers(p: ProtocolInfo,
                      handshake: HandshakeStep,
                      disconnectHandler: DisconnectionHandler) =
  p.handshake = handshake
  p.disconnectHandler = disconnectHandler

proc implementSendProcBody(sendProc: SendProc) =
  let
    msg = sendProc.msg
    UntypedResponder = bindSym "UntypedResponder"
    await = ident "await"

  proc sendCallGenerator(peer, bytes: NimNode): NimNode =
    if msg.kind != msgResponse:
      let msgProto = getRequestProtoName(msg.procDef)
      case msg.kind
      of msgRequest:
        let
          timeout = msg.timeoutParam[0]
          ResponseRecord = msg.response.recName
        quote:
          makeEth2Request(`peer`, `msgProto`, `bytes`,
                          `ResponseRecord`, `timeout`)
      else:
        quote: sendNotificationMsg(`peer`, `msgProto`, `bytes`)
    else:
      quote: sendResponseChunkBytes(`UntypedResponder`(`peer`), `bytes`)

  sendProc.useStandardBody(nil, nil, sendCallGenerator)

proc handleIncomingStream(network: Eth2Node, stream: P2PStream,
                          MsgType, Format: distinct type) {.async, gcsafe.} =
  mixin callUserHandler
  const msgName = typetraits.name(MsgType)

  ## Uncomment this to enable tracing on all incoming requests
  ## You can include `msgNameLit` in the condition to select
  ## more specific requests:
  # when chronicles.runtimeFilteringEnabled:
  #   setLogLevel(LogLevel.TRACE)
  #   defer: setLogLevel(LogLevel.DEBUG)
  #   trace "incoming " & `msgNameLit` & " stream"

  defer:
    await safeClose(stream)

  let
    deadline = sleepAsync RESP_TIMEOUT
    msgBytes = await readMsgBytes(stream, false, deadline)
    peer = peerFromStream(network, stream)

  if msgBytes.len == 0:
    await sendErrorResponse(peer, stream, ServerError, readTimeoutErrorMsg)
    return

  var msg: MsgType
  try:
    msg = decode(Format, msgBytes, MsgType)
  except SerializationError as err:
    await sendErrorResponse(peer, stream, err, msgName, msgBytes)
    return
  except Exception as err:
    # TODO. This is temporary code that should be removed after interop.
    # It can be enabled only in certain diagnostic builds where it should
    # re-raise the exception.
    debug "Crash during serialization", inputBytes = toHex(msgBytes), msgName
    await sendErrorResponse(peer, stream, ServerError, err.msg)
    raise err

  try:
    logReceivedMsg(peer, msg)
    await callUserHandler(peer, stream, msg)
  except CatchableError as err:
    await sendErrorResponse(peer, stream, ServerError, err.msg)

