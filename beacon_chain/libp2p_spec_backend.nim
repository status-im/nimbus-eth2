import
  tables, deques, options, algorithm, stew/shims/[macros, tables],
  stew/ranges/ptr_arith, chronos, chronicles, serialization, faststreams/input_stream,
  eth/async_utils, eth/p2p/p2p_protocol_dsl, libp2p/daemon/daemonapi,
  libp2p_json_serialization, ssz

export
  daemonapi, p2pProtocol, serialization, ssz, libp2p_json_serialization

const
  # Compression nibble
  NoCompression* = byte 0

  # Encoding nibble
  SszEncoding* = byte 1

  beaconChainProtocol = "/eth/serenity/beacon/rpc/1"

type
  Eth2Node* = ref object of RootObj
    daemon*: DaemonAPI
    peers*: Table[PeerID, Peer]
    protocolStates*: seq[RootRef]

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

  Peer* = ref object
    network*: Eth2Node
    id*: PeerID
    lastReqId*: uint64
    rpcStream*: P2PStream
    connectionState*: ConnectionState
    awaitedMessages: Table[CompressedMsgId, FutureBase]
    outstandingRequests*: Table[uint64, OutstandingRequest]
    protocolStates*: seq[RootRef]
    maxInactivityAllowed*: Duration

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  DisconnectionReason* = enum
    ClientShutdown = 1
    IrrelevantNetwork
    FaultOrError

  CompressedMsgId = tuple
    protocolIdx, methodId: int

  ResponderWithId*[MsgType] = object
    peer*: Peer
    reqId*: uint64

  Response*[MsgType] = distinct Peer

  # -----------------------------------------

  ResponseCode* = enum
    NoError
    ParseError = 10
    InvalidRequest = 20
    MethodNotFound = 30
    ServerError = 40

  OutstandingRequest* = object
    id*: uint64
    future*: FutureBase
    timeoutAt*: Moment
    responseThunk*: ThunkProc

  ProtocolConnection* = object
    stream*: P2PStream
    protocolInfo*: ProtocolInfo

  MessageInfo* = object
    id*: int
    name*: string

    # Private fields:
    thunk*: ThunkProc
    printer*: MessageContentPrinter
    nextMsgResolver*: NextMsgResolver
    requestResolver*: RequestResolver

  ProtocolInfoObj* = object
    name*: string
    version*: int
    messages*: seq[MessageInfo]
    index*: int # the position of the protocol in the
                # ordered list of supported protocols

    # Private fields:
    peerStateInitializer*: PeerStateInitializer
    networkStateInitializer*: NetworkStateInitializer
    handshake*: HandshakeStep
    disconnectHandler*: DisconnectionHandler

  ProtocolInfo* = ptr ProtocolInfoObj

  SpecOuterMsgHeader {.packed.} = object
    compression {.bitsize: 4.}: uint
    encoding {.bitsize: 4.}: uint
    msgLen: uint64

  SpecInnerMsgHeader {.packed.} = object
    reqId: uint64
    methodId: uint16

  ErrorResponse {.packed.} = object
    outerHeader: SpecOuterMsgHeader
    innerHeader: SpecInnerMsgHeader

  PeerStateInitializer* = proc(peer: Peer): RootRef {.gcsafe.}
  NetworkStateInitializer* = proc(network: Eth2Node): RootRef {.gcsafe.}

  HandshakeStep* = proc(peer: Peer, handshakeStream: P2PStream): Future[void] {.gcsafe.}
  DisconnectionHandler* = proc(peer: Peer): Future[void] {.gcsafe.}

  ThunkProc* = proc(peer: Peer,
                    stream: P2PStream,
                    reqId: uint64,
                    reqFuture: FutureBase,
                    msgData: ByteStreamVar): Future[void] {.gcsafe.}

  MessageContentPrinter* = proc(msg: pointer): string {.gcsafe.}
  NextMsgResolver* = proc(msg: pointer, future: FutureBase) {.gcsafe.}
  RequestResolver* = proc(msg: pointer, future: FutureBase) {.gcsafe.}

  Bytes = seq[byte]

  InvalidMsgIdError = object of InvalidMsgError

  PeerDisconnected* = object of P2PBackendError
    reason*: DisconnectionReason

  PeerLoopExitReason = enum
    Success
    UnsupportedCompression
    UnsupportedEncoding
    ProtocolViolation
    InactivePeer
    InternalError

const
  HandshakeTimeout = FaultOrError
  BreachOfProtocol* = FaultOrError
    # TODO: We should lobby for more disconnection reasons.

template isOdd(val: SomeInteger): bool =
  type T = type(val)
  (val and T(1)) != 0

proc init(T: type SpecOuterMsgHeader,
          compression, encoding: byte, msgLen: uint64): T =
  T(compression: compression, encoding: encoding, msgLen: msgLen)

proc readPackedObject(stream: P2PStream, T: type): Future[T] {.async.} =
  await stream.transp.readExactly(addr result, sizeof result)

proc appendPackedObject(stream: OutputStreamVar, value: auto) =
  let valueAsBytes = cast[ptr byte](unsafeAddr(value))
  stream.append makeOpenArray(valueAsBytes, sizeof(value))

proc getThunk(protocol: ProtocolInfo, methodId: uint16): ThunkProc =
  if methodId.int >= protocol.messages.len: return nil
  protocol.messages[methodId.int].thunk

include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing
include libp2p_backends_common

proc handleConnectingBeaconChainPeer(daemon: DaemonAPI, stream: P2PStream) {.async, gcsafe.}

proc init*(T: type Eth2Node, daemon: DaemonAPI): Future[Eth2Node] {.async.} =
  new result
  result.daemon = daemon
  result.daemon.userData = result
  result.peers = initTable[PeerID, Peer]()

  newSeq result.protocolStates, allProtocols.len
  for proto in allProtocols:
    if proto.networkStateInitializer != nil:
      result.protocolStates[proto.index] = proto.networkStateInitializer(result)

  await daemon.addHandler(@[beaconChainProtocol], handleConnectingBeaconChainPeer)

proc init*(T: type Peer, network: Eth2Node, id: PeerID): Peer =
  new result
  result.id = id
  result.network = network
  result.awaitedMessages = initTable[CompressedMsgId, FutureBase]()
  result.maxInactivityAllowed = 15.minutes # TODO: read this from the config
  result.connectionState = None
  newSeq result.protocolStates, allProtocols.len
  for i in 0 ..< allProtocols.len:
    let proto = allProtocols[i]
    if proto.peerStateInitializer != nil:
      result.protocolStates[i] = proto.peerStateInitializer(result)

proc init*[MsgName](T: type ResponderWithId[MsgName],
                    peer: Peer, reqId: uint64): T =
  T(peer: peer, reqId: reqId)

proc sendMsg*(peer: Peer, data: Bytes) {.gcsafe, async.} =
  try:
    var unsentBytes = data.len
    while true:
      # TODO: this looks wrong.
      # We are always trying to write the same data.
      # Find all other places where such code is used.
      unsentBytes -= await peer.rpcStream.transp.write(data)
      if unsentBytes <= 0: return
  except CatchableError:
    await peer.disconnect(FaultOrError)
    # this is usually a "(32) Broken pipe":
    # FIXME: this exception should be caught somewhere in addMsgHandler() and
    # sending should be retried a few times
    raise

proc sendMsg*[T](responder: ResponderWithId[T], data: Bytes): Future[void] =
  return sendMsg(responder.peer, data)

proc sendErrorResponse(peer: Peer, reqId: uint64,
                       responseCode: ResponseCode): Future[void] =
  var resp = ErrorResponse(
    outerHeader: SpecOuterMsgHeader.init(
      compression = NoCompression,
      encoding = SszEncoding,
      msgLen = uint64 sizeof(SpecInnerMsgHeader)),
    innerHeader: SpecInnerMsgHeader(
      reqId: reqId,
      methodId: uint16(responseCode)))

  # TODO: don't allocate the Bytes sequence here
  return peer.sendMsg @(makeOpenArray(cast[ptr byte](addr resp), sizeof resp))

proc recvAndDispatchMsg*(peer: Peer): Future[PeerLoopExitReason] {.async.} =
  template fail(reason) =
    return reason

  # For now, we won't try to handle the presence of multiple sub-protocols
  # since the spec is not defining how they will be mapped to P2P streams.
  doAssert allProtocols.len == 1

  var
    stream = peer.rpcStream
    protocol = allProtocols[0]

  var outerHeader = await stream.readPackedObject(SpecOuterMsgHeader)

  if outerHeader.compression != NoCompression:
    fail UnsupportedCompression

  if outerHeader.encoding != SszEncoding:
    fail UnsupportedEncoding

  if outerHeader.msgLen <= SpecInnerMsgHeader.sizeof.uint64:
    fail ProtocolViolation

  let
    innerHeader = await stream.readPackedObject(SpecInnerMsgHeader)
    reqId = innerHeader.reqId

  var msgContent = newSeq[byte](outerHeader.msgLen - SpecInnerMsgHeader.sizeof.uint64)
  await stream.transp.readExactly(addr msgContent[0], msgContent.len)

  var msgContentStream = memoryStream(msgContent)

  if reqId.isOdd:
    peer.outstandingRequests.withValue(reqId, req):
      let thunk = req.responseThunk
      let reqFuture = req.future
      peer.outstandingRequests.del(reqId)

      try:
        await thunk(peer, stream, reqId, reqFuture, msgContentStream)
      except SerializationError:
        debug "Error during deserialization", err = getCurrentExceptionMsg()
        fail ProtocolViolation
      except CatchableError:
        # TODO
        warn ""
    do:
      debug "Ignoring late or invalid response ID", peer, id = reqId
      # TODO: skip the message
  else:
    let thunk = protocol.getThunk(innerHeader.methodId)
    if thunk != nil:
      try:
        await thunk(peer, stream, reqId, nil, msgContentStream)
      except SerializationError:
        debug "Error during deserialization", err = getCurrentExceptionMsg()
        fail ProtocolViolation
      except CatchableError:
        # TODO
        warn ""
    else:
      debug "P2P request method not found", methodId = innerHeader.methodId
      await peer.sendErrorResponse(reqId, MethodNotFound)

proc dispatchMessages*(peer: Peer): Future[PeerLoopExitReason] {.async.} =
  while true:
    let dispatchedMsgFut = recvAndDispatchMsg(peer)
    doAssert peer.maxInactivityAllowed.milliseconds > 0
    yield dispatchedMsgFut or sleepAsync(peer.maxInactivityAllowed)
    if not dispatchedMsgFut.finished:
      return InactivePeer
    elif dispatchedMsgFut.failed:
      error "Error in peer loop"
      return InternalError
    else:
      let status = dispatchedMsgFut.read
      if status == Success: continue
      return status

proc performProtocolHandshakes*(peer: Peer) {.async.} =
  peer.initProtocolStates allProtocols

  # Please note that the ordering of operations here is important!
  #
  # We must first start all handshake procedures and give them a
  # chance to send any initial packages they might require over
  # the network and to yield on their `nextMsg` waits.
  #
  var subProtocolsHandshakes = newSeqOfCap[Future[void]](allProtocols.len)
  for protocol in allProtocols:
    if protocol.handshake != nil:
      subProtocolsHandshakes.add((protocol.handshake)(peer, peer.rpcStream))

  # The `dispatchMesssages` loop must be started after this.
  # Otherwise, we risk that some of the handshake packets sent by
  # the other peer may arrrive too early and be processed before
  # the handshake code got a change to wait for them.
  #
  var messageProcessingLoop = peer.dispatchMessages()
  messageProcessingLoop.callback = proc(p: pointer) {.gcsafe.} =
    if messageProcessingLoop.failed:
      debug "Ending dispatchMessages loop", peer,
            err = messageProcessingLoop.error.msg
    else:
      debug "Ending dispatchMessages", peer,
            exitCode = messageProcessingLoop.read
    traceAsyncErrors peer.disconnect(ClientShutdown)

  # The handshake may involve multiple async steps, so we wait
  # here for all of them to finish.
  #
  await all(subProtocolsHandshakes)

  peer.connectionState = Connected
  debug "Peer connection initialized", peer

proc initializeConnection*(peer: Peer) {.async.} =
  let daemon = peer.network.daemon
  try:
    peer.connectionState = Connecting
    peer.rpcStream = await daemon.openStream(peer.id, @[beaconChainProtocol])
    await performProtocolHandshakes(peer)
  except CatchableError:
    await reraiseAsPeerDisconnected(peer, "Failed to perform handshake")

proc handleConnectingBeaconChainPeer(daemon: DaemonAPI, stream: P2PStream) {.async, gcsafe.} =
  let peer = daemon.peerFromStream(stream)
  peer.rpcStream = stream
  peer.connectionState = Connecting
  await performProtocolHandshakes(peer)

proc resolvePendingFutures(peer: Peer, protocol: ProtocolInfo,
                           methodId: int, msg: pointer, reqFuture: FutureBase) =

  let msgId = (protocolIdx: protocol.index, methodId: methodId)

  if peer.awaitedMessages[msgId] != nil:
    let msgInfo = protocol.messages[methodId]
    msgInfo.nextMsgResolver(msg, peer.awaitedMessages[msgId])
    peer.awaitedMessages[msgId] = nil

  if reqFuture != nil and not reqFuture.finished:
    protocol.messages[methodId].requestResolver(msg, reqFuture)

proc initProtocol(name: string, version: int,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer): ProtocolInfoObj =
  result.name = name
  result.version = version
  result.messages = @[]
  result.peerStateInitializer = peerInit
  result.networkStateInitializer = networkInit

proc registerMsg(protocol: ProtocolInfo,
                 id: int, name: string,
                 thunk: ThunkProc,
                 printer: MessageContentPrinter,
                 requestResolver: RequestResolver,
                 nextMsgResolver: NextMsgResolver) =
  if protocol.messages.len <= id:
    protocol.messages.setLen(id + 1)
  protocol.messages[id] = MessageInfo(id: id,
                                      name: name,
                                      thunk: thunk,
                                      printer: printer,
                                      requestResolver: requestResolver,
                                      nextMsgResolver: nextMsgResolver)

template applyDecorator(p: NimNode, decorator: NimNode) =
  if decorator.kind != nnkNilLit: p.addPragma decorator

proc prepareRequest(peer: Peer,
                    protocol: ProtocolInfo,
                    requestMethodId, responseMethodId: uint16,
                    stream: OutputStreamVar,
                    timeout: Duration,
                    responseFuture: FutureBase): DelayedWriteCursor =
  assert peer != nil and
         protocol != nil and
         responseFuture != nil and
         responseMethodId.int < protocol.messages.len

  doAssert timeout.milliseconds > 0

  result = stream.delayFixedSizeWrite sizeof(SpecOuterMsgHeader)

  inc peer.lastReqId, 2
  let reqId = peer.lastReqId

  stream.appendPackedObject SpecInnerMsgHeader(
    reqId: reqId, methodId: requestMethodId)

  template responseMsgInfo: auto =
    protocol.messages[responseMethodId.int]

  let
    requestResolver = responseMsgInfo.requestResolver
    timeoutAt = Moment.fromNow(timeout)

  peer.outstandingRequests[reqId + 1] = OutstandingRequest(
    id: reqId,
    future: responseFuture,
    timeoutAt: timeoutAt,
    responseThunk: responseMsgInfo.thunk)

  proc timeoutExpired(udata: pointer) =
    requestResolver(nil, responseFuture)
    peer.outstandingRequests.del(reqId + 1)

  addTimer(timeoutAt, timeoutExpired, nil)

proc prepareResponse(responder: ResponderWithId,
                     stream: OutputStreamVar): DelayedWriteCursor =
  result = stream.delayFixedSizeWrite sizeof(SpecOuterMsgHeader)

  stream.appendPackedObject SpecInnerMsgHeader(
    reqId: responder.reqId + 1,
    methodId: uint16(Success))

proc prepareMsg(peer: Peer, methodId: uint16,
                stream: OutputStreamVar): DelayedWriteCursor =
  result = stream.delayFixedSizeWrite sizeof(SpecOuterMsgHeader)

  inc peer.lastReqId, 2
  stream.appendPackedObject SpecInnerMsgHeader(
    reqId: peer.lastReqId, methodId: methodId)

proc finishOuterHeader(headerCursor: DelayedWriteCursor) =
  var outerHeader = SpecOuterMsgHeader.init(
    compression = NoCompression,
    encoding = SszEncoding,
    msgLen = uint64(headerCursor.totalBytesWrittenAfterCursor))

  headerCursor.endWrite makeOpenArray(cast[ptr byte](addr outerHeader),
                                      sizeof outerHeader)

proc implementSendProcBody(sendProc: SendProc) =
  let
    msg = sendProc.msg
    delayedWriteCursor = ident "delayedWriteCursor"
    peer = sendProc.peerParam

  proc preSerializationStep(stream: NimNode): NimNode =
    case msg.kind
    of msgRequest:
      let
        requestMethodId = newLit(msg.id)
        responseMethodId = newLit(msg.response.id)
        protocol = sendProc.msg.protocol.protocolInfoVar
        timeout = sendProc.timeoutParam

      quote do:
        var `delayedWriteCursor` = prepareRequest(
          `peer`, `protocol`, `requestMethodId`, `responseMethodId`,
          `stream`, `timeout`, `resultIdent`)

    of msgResponse:
      quote do:
        var `delayedWriteCursor` = prepareResponse(`peer`, `stream`)

    of msgHandshake, msgNotification:
      let methodId = newLit(msg.id)
      quote do:
        var `delayedWriteCursor` = prepareMsg(`peer`, `methodId`, `stream`)

  proc postSerializationStep(stream: NimNode): NimNode =
    newCall(bindSym "finishOuterHeader", delayedWriteCursor)

  proc sendCallGenerator(peer, bytes: NimNode): NimNode =
    let
      linkSendFailureToReqFuture = bindSym "linkSendFailureToReqFuture"
      sendMsg = bindSym "sendMsg"
      sendCall = newCall(sendMsg, peer, bytes)

    if msg.kind == msgRequest:
      # In RLPx requests, the returned future was allocated here and passed
      # to `prepareRequest`. It's already assigned to the result variable
      # of the proc, so we just wait for the sending operation to complete
      # and we return in a normal way. (the waiting is done, so we can catch
      # any possible errors).
      quote: `linkSendFailureToReqFuture`(`sendCall`, `resultIdent`)
    else:
      # In normal RLPx messages, we are returning the future returned by the
      # `sendMsg` call.
      quote: return `sendCall`

  sendProc.useStandardBody(
    preSerializationStep,
    postSerializationStep,
    sendCallGenerator)

proc p2pProtocolBackendImpl*(p: P2PProtocol): Backend =
  let
    Option = bindSym "Option"
    Peer = bindSym "Peer"
    EthereumNode = bindSym "EthereumNode"

    Format = ident "SSZ"
    Response = bindSym "Response"
    ResponderWithId = bindSym "ResponderWithId"
    perProtocolMsgId = ident "perProtocolMsgId"

    mount = bindSym "mount"

    messagePrinter = bindSym "messagePrinter"
    resolveFuture = bindSym "resolveFuture"
    requestResolver = bindSym "requestResolver"
    resolvePendingFutures = bindSym "resolvePendingFutures"
    nextMsg = bindSym "nextMsg"
    initProtocol = bindSym "initProtocol"
    registerMsg = bindSym "registerMsg"
    handshakeImpl = bindSym "handshakeImpl"

    stream = ident "stream"
    protocol = ident "protocol"
    response = ident "response"
    reqFutureVar = ident "reqFuture"
    msgContents = ident "msgContents"
    receivedMsg = ident "receivedMsg"

    ProtocolInfo = bindSym "ProtocolInfo"
    P2PStream = bindSym "P2PStream"
    ByteStreamVar = bindSym "ByteStreamVar"

  new result

  result.registerProtocol = bindSym "registerProtocol"
  result.setEventHandlers = bindSym "setEventHandlers"
  result.PeerType = Peer
  result.NetworkType = EthereumNode
  result.SerializationFormat = Format

  p.useRequestIds = true
  result.ReqIdType = ident "uint64"
  result.ResponderType = ResponderWithId

  result.afterProtocolInit = proc (p: P2PProtocol) =
    p.onPeerConnected.params.add newIdentDefs(ident"handshakeStream", P2PStream)

  result.implementMsg = proc (msg: Message) =
    var
      msgIdLit = newLit(msg.id)
      msgRecName = msg.recIdent
      msgIdent = msg.ident
      msgName = $msgIdent
      protocol = msg.protocol

    ##
    ## Implemenmt Thunk
    ##
    let traceMsg = when tracingEnabled:
      newCall(bindSym"logReceivedMsg", peer, receivedMsg)
    else:
      newStmtList()

    let callResolvePendingFutures = newCall(
      resolvePendingFutures, peerVar,
                             protocol.protocolInfoVar,
                             msgIdLit,
                             newCall("addr", receivedMsg),
                             reqFutureVar)

    var userHandlerParams = @[peerVar]
    if msg.kind == msgRequest:
      userHandlerParams.add reqIdVar

    let
      thunkName = ident(msgName & "_thunk")
      awaitUserHandler = msg.genAwaitUserHandler(receivedMsg, userHandlerParams)

    msg.defineThunk quote do:
      proc `thunkName`(`peerVar`: `Peer`,
                       `stream`: `P2PStream`,
                       `reqIdVar`: uint64,
                       `reqFutureVar`: FutureBase,
                       `msgContents`: `ByteStreamVar`) {.async, gcsafe.} =
        var `receivedMsg` = `mount`(`Format`, `msgContents`, `msgRecName`)
        `traceMsg`
        `awaitUserHandler`
        `callResolvePendingFutures`

    ##
    ## Implement Senders and Handshake
    ##
    var sendProc = msg.createSendProc(isRawSender = (msg.kind == msgHandshake))
    implementSendProcBody sendProc

    if msg.kind == msgHandshake:
      discard msg.createHandshakeTemplate(sendProc.def.name, handshakeImpl, nextMsg)

    protocol.outProcRegistrations.add(
      newCall(registerMsg,
              protocol.protocolInfoVar,
              msgIdLit,
              newLit(msgName),
              thunkName,
              newTree(nnkBracketExpr, messagePrinter, msgRecName),
              newTree(nnkBracketExpr, requestResolver, msgRecName),
              newTree(nnkBracketExpr, resolveFuture, msgRecName)))

  result.implementProtocolInit = proc (protocol: P2PProtocol): NimNode =
    return newCall(initProtocol,
                   newLit(protocol.shortName),
                   newLit(protocol.version),
                   protocol.peerInit, protocol.netInit)

