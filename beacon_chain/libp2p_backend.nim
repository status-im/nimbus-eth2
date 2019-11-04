import
  algorithm,
  stew/varints, stew/shims/[macros, tables], chronos, chronicles,
  libp2p/daemon/daemonapi, faststreams/output_stream, serialization,
  json_serialization/std/options, eth/p2p/p2p_protocol_dsl,
  libp2p_json_serialization, ssz

export
  daemonapi, p2pProtocol, libp2p_json_serialization, ssz

type
  Eth2Node* = ref object of RootObj
    daemon*: DaemonAPI
    peers*: Table[PeerID, Peer]
    protocolStates*: seq[RootRef]

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

  Peer* = ref object
    network*: Eth2Node
    id*: PeerID
    wasDialed*: bool
    connectionState*: ConnectionState
    protocolStates*: seq[RootRef]
    maxInactivityAllowed*: Duration

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  DisconnectionReason* = enum
    ClientShutDown
    IrrelevantNetwork
    FaultOrError

  UntypedResponder = object
    peer*: Peer
    stream*: P2PStream

  Responder*[MsgType] = distinct UntypedResponder

  MessageInfo* = object
    name*: string

    # Private fields:
    thunk*: ThunkProc
    libp2pProtocol: string
    printer*: MessageContentPrinter
    nextMsgResolver*: NextMsgResolver

  ProtocolInfoObj* = object
    name*: string
    messages*: seq[MessageInfo]
    index*: int # the position of the protocol in the
                # ordered list of supported protocols

    # Private fields:
    peerStateInitializer*: PeerStateInitializer
    networkStateInitializer*: NetworkStateInitializer
    handshake*: HandshakeStep
    disconnectHandler*: DisconnectionHandler

  ProtocolInfo* = ptr ProtocolInfoObj

  CompressedMsgId = tuple
    protocolIdx, methodId: int

  ResponseCode* = enum
    Success
    InvalidRequest
    ServerError

  PeerStateInitializer* = proc(peer: Peer): RootRef {.gcsafe.}
  NetworkStateInitializer* = proc(network: EthereumNode): RootRef {.gcsafe.}
  HandshakeStep* = proc(peer: Peer, stream: P2PStream): Future[void] {.gcsafe.}
  DisconnectionHandler* = proc(peer: Peer): Future[void] {.gcsafe.}
  ThunkProc* = proc(daemon: DaemonAPI, stream: P2PStream): Future[void] {.gcsafe.}
  MessageContentPrinter* = proc(msg: pointer): string {.gcsafe.}
  NextMsgResolver* = proc(msgData: SszReader, future: FutureBase) {.gcsafe.}

  Bytes = seq[byte]

  PeerDisconnected* = object of CatchableError
    reason*: DisconnectionReason

  TransmissionError* = object of CatchableError

  ResponseSizeLimitReached* = object of CatchableError

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
  topic = "libp2p"

template `$`*(peer: Peer): string = $peer.id
chronicles.formatIt(Peer): $it

template libp2pProtocol*(name: string, version: int) {.pragma.}

include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing

proc init*(T: type Peer, network: Eth2Node, id: PeerID): Peer {.gcsafe.}

proc getPeer*(node: Eth2Node, peerId: PeerID): Peer {.gcsafe.} =
  result = node.peers.getOrDefault(peerId)
  if result == nil:
    result = Peer.init(node, peerId)
    node.peers[peerId] = result

proc peerFromStream(daemon: DaemonAPI, stream: P2PStream): Peer {.gcsafe.} =
  Eth2Node(daemon.userData).getPeer(stream.peer)

proc safeClose(stream: P2PStream) {.async.} =
  if P2PStreamFlags.Closed notin stream.flags:
    await close(stream)

proc disconnect*(peer: Peer, reason: DisconnectionReason, notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    await peer.network.daemon.disconnect(peer.id)
    peer.connectionState = Disconnected
    peer.network.peers.del(peer.id)

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

template reraiseAsPeerDisconnected(peer: Peer, errMsgExpr: static string,
                                   reason = FaultOrError): auto =
  const errMsg = errMsgExpr
  debug errMsg, err = getCurrentExceptionMsg()
  disconnectAndRaise(peer, reason, errMsg)

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

proc init*(T: type Eth2Node, daemon: DaemonAPI): Future[T] {.async.} =
  new result
  result.daemon = daemon
  result.daemon.userData = result
  result.peers = initTable[PeerID, Peer]()

  newSeq result.protocolStates, allProtocols.len
  for proto in allProtocols:
    if proto.networkStateInitializer != nil:
      result.protocolStates[proto.index] = proto.networkStateInitializer(result)

    for msg in proto.messages:
      if msg.libp2pProtocol.len > 0:
        await daemon.addHandler(@[msg.libp2pProtocol], msg.thunk)

proc readChunk(stream: P2PStream,
               MsgType: type,
               withResponseCode: bool,
               deadline: Future[void]): Future[Option[MsgType]] {.gcsafe.}

proc readSizePrefix(transp: StreamTransport,
                    deadline: Future[void]): Future[int] {.async.} =
  var parser: VarintParser[uint64, ProtoBuf]
  while true:
    var nextByte: byte
    var readNextByte = transp.readExactly(addr nextByte, 1)
    await readNextByte or deadline
    if not readNextByte.finished:
      return -1
    case parser.feedByte(nextByte)
    of Done:
      let res = parser.getResult
      if res > uint64(REQ_RESP_MAX_SIZE):
        return -1
      else:
        return int(res)
    of Overflow:
      return -1
    of Incomplete:
      continue

proc readMsgBytes(stream: P2PStream,
                  withResponseCode: bool,
                  deadline: Future[void]): Future[Bytes] {.async.} =
  try:
    if withResponseCode:
      var responseCode: byte
      var readResponseCode = stream.transp.readExactly(addr responseCode, 1)
      await readResponseCode or deadline
      if not readResponseCode.finished:
        return
      if responseCode > ResponseCode.high.byte: return

      logScope: responseCode = ResponseCode(responseCode)
      case ResponseCode(responseCode)
      of InvalidRequest, ServerError:
        let responseErrMsg = await readChunk(stream, string, false, deadline)
        debug "P2P request resulted in error", responseErrMsg
        return
      of Success:
        # The response is OK, the execution continues below
        discard

    var sizePrefix = await readSizePrefix(stream.transp, deadline)
    if sizePrefix == -1:
      debug "Failed to read an incoming message size prefix", peer = stream.peer
      return

    if sizePrefix == 0:
      debug "Received SSZ with zero size", peer = stream.peer
      return

    var msgBytes = newSeq[byte](sizePrefix)
    var readBody = stream.transp.readExactly(addr msgBytes[0], sizePrefix)
    await readBody or deadline
    if not readBody.finished: return

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
  discard await stream.transp.write(responseBytes)
  await stream.close()

proc sendErrorResponse(peer: Peer,
                       stream: P2PStream,
                       responseCode: ResponseCode,
                       errMsg: string) {.async.} =
  debug "Error processing request", peer, responseCode, errMsg

  let responseBytes = encodeErrorMsg(ServerError, errMsg)
  discard await stream.transp.write(responseBytes)
  await stream.close()

proc writeSizePrefix(transp: StreamTransport, size: uint64) {.async.} =
  var
    varintBuf: array[10, byte]
    varintSize = vsizeof(size)
    cursor = createWriteCursor(varintBuf)
  cursor.appendVarint size
  var sent = await transp.write(varintBuf[0 ..< varintSize])
  if sent != varintSize:
    raise newException(TransmissionError, "Failed to deliver size prefix")

proc sendNotificationMsg(peer: Peer, protocolId: string, requestBytes: Bytes) {.async} =
  var deadline = sleepAsync RESP_TIMEOUT
  var streamFut = peer.network.daemon.openStream(peer.id, @[protocolId])
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
  let sent = await stream.transp.write(bytes)
  if sent != bytes.len:
    raise newException(TransmissionError, "Failed to deliver msg bytes")

template raiseMaxRespSizeError =
  raise newException(ResponseSizeLimitReached, "Response size limit reached")

# TODO There is too much duplication in the responder functions, but
# I hope to reduce this when I increse the reliance on output streams.
proc sendResponseChunkBytes(responder: UntypedResponder, payload: Bytes) {.async.} =
  var s = init OutputStream
  s.append byte(Success)
  s.appendVarint payload.len.uint64
  s.append payload
  let bytes = s.getOutput

  let sent = await responder.stream.transp.write(bytes)
  if sent != bytes.len:
    raise newException(TransmissionError, "Failed to deliver all bytes")

proc sendResponseChunkObj(responder: UntypedResponder, val: auto) {.async.} =
  var s = init OutputStream
  s.append byte(Success)
  s.appendValue SSZ, sizePrefixed(val)
  let bytes = s.getOutput

  let sent = await responder.stream.transp.write(bytes)
  if sent != bytes.len:
    raise newException(TransmissionError, "Failed to deliver all bytes")

proc sendResponseChunks[T](responder: UntypedResponder, chunks: seq[T]) {.async.} =
  var s = init OutputStream
  for chunk in chunks:
    s.append byte(Success)
    s.appendValue SSZ, sizePrefixed(chunk)

  let bytes = s.getOutput
  let sent = await responder.stream.transp.write(bytes)
  if sent != bytes.len:
    raise newException(TransmissionError, "Failed to deliver all bytes")

proc makeEth2Request(peer: Peer, protocolId: string, requestBytes: Bytes,
                     ResponseMsg: type,
                     timeout: Duration): Future[Option[ResponseMsg]] {.gcsafe, async.} =
  var deadline = sleepAsync timeout

  # Open a new LibP2P stream
  var streamFut = peer.network.daemon.openStream(peer.id, @[protocolId])
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
  let sent = await stream.transp.write(bytes)
  if sent != bytes.len:
    await disconnectAndRaise(peer, FaultOrError, "Incomplete send")

  # Read the response
  return await stream.readResponse(ResponseMsg, deadline)

proc p2pStreamName(MsgType: type): string =
  mixin msgProtocol, protocolInfo, msgId
  MsgType.msgProtocol.protocolInfo.messages[MsgType.msgId].libp2pProtocol

proc init*(T: type Peer, network: Eth2Node, id: PeerID): Peer =
  new result
  result.id = id
  result.network = network
  result.connectionState = Connected
  result.maxInactivityAllowed = 15.minutes # TODO: Read this from the config
  newSeq result.protocolStates, allProtocols.len
  for i in 0 ..< allProtocols.len:
    let proto = allProtocols[i]
    if proto.peerStateInitializer != nil:
      result.protocolStates[i] = proto.peerStateInitializer(result)

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

proc registerMsg(protocol: ProtocolInfo,
                 name: string,
                 thunk: ThunkProc,
                 libp2pProtocol: string,
                 printer: MessageContentPrinter) =
  protocol.messages.add MessageInfo(name: name,
                                    thunk: thunk,
                                    libp2pProtocol: libp2pProtocol,
                                    printer: printer)

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

proc init*[MsgType](T: type Responder[MsgType],
                    peer: Peer, stream: P2PStream): T =
  T(UntypedResponder(peer: peer, stream: stream))

proc backendLoop*(node: Eth2Node) {.async.} =
  discard

import
  typetraits

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
      static: echo "BAD TYPE ", name(E), " vs ", name(type(val))
      {.fatal: "bad".}
  else:
    send(r, val)

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

proc p2pProtocolBackendImpl*(p: P2PProtocol): Backend =
  var
    Format = ident "SSZ"
    Responder = bindSym "Responder"
    DaemonAPI = bindSym "DaemonAPI"
    P2PStream = ident "P2PStream"
    OutputStream = bindSym "OutputStream"
    Peer = bindSym "Peer"
    Eth2Node = bindSym "Eth2Node"
    messagePrinter = bindSym "messagePrinter"
    milliseconds = bindSym "milliseconds"
    registerMsg = bindSym "registerMsg"
    initProtocol = bindSym "initProtocol"
    bindSymOp = bindSym "bindSym"
    errVar = ident "err"
    msgVar = ident "msg"
    msgBytesVar = ident "msgBytes"
    daemonVar = ident "daemon"
    await = ident "await"

  p.useRequestIds = false
  p.useSingleRecordInlining = true

  new result

  result.PeerType = Peer
  result.NetworkType = Eth2Node
  result.registerProtocol = bindSym "registerProtocol"
  result.setEventHandlers = bindSym "setEventHandlers"
  result.SerializationFormat = Format
  result.ResponderType = Responder

  result.afterProtocolInit = proc (p: P2PProtocol) =
    p.onPeerConnected.params.add newIdentDefs(streamVar, P2PStream)

  result.implementMsg = proc (msg: Message) =
    let
      protocol = msg.protocol
      msgName = $msg.ident
      msgNameLit = newLit msgName
      msgRecName = msg.recName

    if msg.procDef.body.kind != nnkEmpty and msg.kind == msgRequest:
      # Request procs need an extra param - the stream where the response
      # should be written:
      msg.userHandler.params.insert(2, newIdentDefs(streamVar, P2PStream))
      msg.initResponderCall.add streamVar

    ##
    ## Implemenmt Thunk
    ##
    var thunkName = ident(msgName & "_thunk")
    let awaitUserHandler = msg.genAwaitUserHandler(msgVar, [peerVar, streamVar])

    let tracing = when tracingEnabled:
      quote: logReceivedMsg(`streamVar`.peer, `msgVar`.get)
    else:
      newStmtList()

    msg.defineThunk quote do:
      proc `thunkName`(`daemonVar`: `DaemonAPI`,
                       `streamVar`: `P2PStream`) {.async, gcsafe.} =
        defer:
          `await` safeClose(`streamVar`)

        let
          `deadlineVar` = sleepAsync RESP_TIMEOUT
          `msgBytesVar` = `await` readMsgBytes(`streamVar`, false, `deadlineVar`)
          `peerVar` = peerFromStream(`daemonVar`, `streamVar`)

        if `msgBytesVar`.len == 0:
          `await` sendErrorResponse(`peerVar`, `streamVar`,
                                    ServerError, readTimeoutErrorMsg)
          return

        var `msgVar`: `msgRecName`
        try:
          `msgVar` = decode(`Format`, `msgBytesVar`, `msgRecName`)
        except SerializationError as `errVar`:
          `await` sendErrorResponse(`peerVar`, `streamVar`, `errVar`,
                                    `msgNameLit`, `msgBytesVar`)
          return
        except Exception as err:
          # TODO. This is temporary code that should be removed after interop.
          # It can be enabled only in certain diagnostic builds where it should
          # re-raise the exception.
          debug "Crash during serialization", inputBytes = toHex(`msgBytesVar`),
                                              msgName = `msgNameLit`,
                                              deserializedType = astToStr(`msgRecName`)
          `await` sendErrorResponse(`peerVar`, `streamVar`, ServerError, err.msg)

        try:
          `tracing`
          `awaitUserHandler`
        except ResponseSizeLimitReached:
          # The response size limit is currently handled with an exception in
          # order to make it easier to switch to an alternative policy when it
          # will be signalled with an error response code (and to avoid making
          # the `response` API in the high-level protocols more complicated for now).
          chronicles.debug "response size limit reached", peer, reqName = `msgNameLit`
        except CatchableError as `errVar`:
          `await` sendErrorResponse(`peerVar`, `streamVar`, ServerError, `errVar`.msg)

    ##
    ## Implement Senders and Handshake
    ##
    if msg.kind == msgHandshake:
      macros.error "Handshake messages are not supported in LibP2P protocols"
    else:
      var sendProc = msg.createSendProc()
      implementSendProcBody sendProc

    protocol.outProcRegistrations.add(
      newCall(registerMsg,
              protocol.protocolInfoVar,
              msgNameLit,
              thunkName,
              getRequestProtoName(msg.procDef),
              newTree(nnkBracketExpr, messagePrinter, msgRecName)))

  result.implementProtocolInit = proc (p: P2PProtocol): NimNode =
    return newCall(initProtocol, newLit(p.name), p.peerInit, p.netInit)

