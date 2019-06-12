import
  tables, deques, options, algorithm, std_shims/[macros_shim, tables_shims],
  ranges/ptr_arith, chronos, chronicles, serialization, faststreams/input_stream,
  eth/p2p/p2p_protocol_dsl, libp2p/daemon/daemonapi,
  ssz

export
  daemonapi, p2pProtocol, serialization, ssz

const
  # Compression nibble
  NoCompression* = uint 0

  # Encoding nibble
  SszEncoding* = uint 1

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
    lastSentMsgId*: uint64
    rpcStream*: P2PStream
    connectionState*: ConnectionState
    awaitedMessages: Table[CompressedMsgId, FutureBase]
    outstandingRequests*: seq[Deque[OutstandingRequest]]
    protocolStates*: seq[RootRef]
    maxInactivityAllowed: Duration

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
    dispatcher: Dispatcher

  ProtocolInfo* = ptr ProtocolInfoObj

  Dispatcher* = object
    messages*: seq[MessageInfo]

  SpecOuterMsgHeader {.packed.} = object
    compression {.bitsize: 4.}: uint
    encoding {.bitsize: 4.}: uint
    msgLen: uint64

  SpecInnerMsgHeader {.packed.} = object
    reqId: uint64
    methodId: uint16

  PeerStateInitializer* = proc(peer: Peer): RootRef {.gcsafe.}
  NetworkStateInitializer* = proc(network: Eth2Node): RootRef {.gcsafe.}

  HandshakeStep* = proc(peer: Peer, handshakeStream: P2PStream): Future[void] {.gcsafe.}
  DisconnectionHandler* = proc(peer: Peer): Future[void] {.gcsafe.}

  ThunkProc* = proc(peer: Peer,
                    stream: P2PStream,
                    reqId: uint64,
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

proc readPackedObject(stream: P2PStream, T: type): Future[T] {.async.} =
  await stream.transp.readExactly(addr result, sizeof result)

proc appendPackedObject(stream: OutputStreamVar, value: auto) =
  let valueAsBytes = cast[ptr byte](unsafeAddr(value))
  stream.append makeOpenArray(valueAsBytes, sizeof(value))

include libp2p_backends_common
include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing

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
  result.connectionState = Connected
  newSeq result.protocolStates, allProtocols.len
  for i in 0 ..< allProtocols.len:
    let proto = allProtocols[i]
    if proto.peerStateInitializer != nil:
      result.protocolStates[i] = proto.peerStateInitializer(result)

proc init*[MsgName](T: type ResponderWithId[MsgName],
                    peer: Peer, reqId: uint64): T =
  T(peer: peer, reqId: reqId)

proc performProtocolHandshakes*(peer: Peer) {.async.} =
  var subProtocolsHandshakes = newSeqOfCap[Future[void]](allProtocols.len)
  for protocol in allProtocols:
    if protocol.handshake != nil:
      subProtocolsHandshakes.add((protocol.handshake)(peer, peer.rpcStream))

  await all(subProtocolsHandshakes)
  debug "All protocols initialized", peer

proc initializeConnection*(peer: Peer) {.async.} =
  let daemon = peer.network.daemon
  try:
    peer.rpcStream = await daemon.openStream(peer.id, @[beaconChainProtocol])
    await performProtocolHandshakes(peer)
  except CatchableError:
    await reraiseAsPeerDisconnected(peer, "Failed to perform handshake")

proc handleConnectingBeaconChainPeer(daemon: DaemonAPI, stream: P2PStream) {.async, gcsafe.} =
  let peer = daemon.peerFromStream(stream)
  peer.rpcStream = stream
  await performProtocolHandshakes(peer)

proc accepts(d: Dispatcher, methodId: uint16): bool =
  methodId.int < d.messages.len

proc invokeThunk(peer: Peer,
                 protocol: ProtocolInfo,
                 stream: P2PStream,
                 methodId: int,
                 reqId: uint64,
                 msgContents: ByteStreamVar): Future[void] =
  template raiseInvalidMsgId =
    raise newException(InvalidMsgIdError,
      "ETH2 message with an invalid id " & $methodId)

  if methodId >= protocol.dispatcher.messages.len: raiseInvalidMsgId()
  var thunk = protocol.dispatcher.messages[methodId].thunk
  if thunk == nil: raiseInvalidMsgId()

  return thunk(peer, stream, reqId, msgContents)

proc recvAndDispatchMsg*(peer: Peer, protocol: ProtocolInfo, stream: P2PStream):
                         Future[PeerLoopExitReason] {.async.} =
  template fail(reason) =
    return reason

  var outerHeader = await stream.readPackedObject(SpecOuterMsgHeader)

  if outerHeader.compression != NoCompression:
    fail UnsupportedCompression

  if outerHeader.encoding != SszEncoding:
    fail UnsupportedEncoding

  if outerHeader.msgLen <= SpecInnerMsgHeader.sizeof.uint64:
    fail ProtocolViolation

  var innerHeader = await stream.readPackedObject(SpecInnerMsgHeader)

  var msgContent = newSeq[byte](outerHeader.msgLen - SpecInnerMsgHeader.sizeof.uint64)
  await stream.transp.readExactly(addr msgContent[0], msgContent.len)

  var msgContentStream = memoryStream(msgContent)

  if protocol.dispatcher.accepts(innerHeader.methodId):
    try:
      await invokeThunk(peer, protocol, stream,
                        innerHeader.methodId.int,
                        innerHeader.reqId,
                        msgContentStream)
    except SerializationError:
      fail ProtocolViolation
    except CatchableError:
      warn ""

proc sendMsg*(peer: Peer, data: Bytes) {.gcsafe, async.} =
  try:
    var unsentBytes = data.len
    while true:
      unsentBytes -= await peer.rpcStream.transp.write(data)
      if unsentBytes <= 0: return
  except:
    await peer.disconnect(FaultOrError)
    # this is usually a "(32) Broken pipe":
    # FIXME: this exception should be caught somewhere in addMsgHandler() and
    # sending should be retried a few times
    raise

proc sendMsg*[T](responder: ResponderWithId[T], data: Bytes): Future[void] =
  return sendMsg(responder.peer, data)

proc dispatchMessages*(peer: Peer, protocol: ProtocolInfo, stream: P2PStream):
                       Future[PeerLoopExitReason] {.async.} =
  while true:
    let dispatchedMsgFut = recvAndDispatchMsg(peer, protocol, stream)
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

proc registerRequest(peer: Peer,
                     protocol: ProtocolInfo,
                     timeout: Duration,
                     responseFuture: FutureBase,
                     responseMethodId: uint16): uint64 =
  inc peer.lastSentMsgId
  result = peer.lastSentMsgId

  let timeoutAt = Moment.fromNow(timeout)
  let req = OutstandingRequest(id: result,
                               future: responseFuture,
                               timeoutAt: timeoutAt)
  peer.outstandingRequests[responseMethodId.int].addLast req

  let requestResolver = protocol.dispatcher.messages[responseMethodId.int].requestResolver
  proc timeoutExpired(udata: pointer) = requestResolver(nil, responseFuture)

  addTimer(timeoutAt, timeoutExpired, nil)

proc resolvePendingFutures(peer: Peer, protocol: ProtocolInfo,
                           methodId: int, msg: pointer, reqId: uint64) =
  logScope:
    msg = protocol.dispatcher.messages[methodId].name
    msgContents = protocol.dispatcher.messages[methodId].printer(msg)
    receivedReqId = reqId
    remotePeer = peer.id

  template resolve(future) =
    (protocol.dispatcher.messages[methodId].requestResolver)(msg, future)

  template outstandingReqs: auto =
    peer.outstandingRequests[methodId]

  let msgId = (protocolIdx: protocol.index, methodId: methodId)
  if peer.awaitedMessages[msgId] != nil:
    let msgInfo = protocol.dispatcher.messages[methodId]
    msgInfo.nextMsgResolver(msg, peer.awaitedMessages[msgId])
    peer.awaitedMessages[msgId] = nil

  # TODO: This is not completely sound because we are still using a global
  # `reqId` sequence (the problem is that we might get a response ID that
  # matches a request ID for a different type of request). To make the code
  # correct, we can use a separate sequence per response type, but we have
  # to first verify that the other Ethereum clients are supporting this
  # correctly (because then, we'll be reusing the same reqIds for different
  # types of requests). Alternatively, we can assign a separate interval in
  # the `reqId` space for each type of response.
  if reqId > peer.lastSentMsgId:
    warn "RLPx response without a matching request"
    return

  var idx = 0
  while idx < outstandingReqs.len:
    template req: auto = outstandingReqs()[idx]

    if req.future.finished:
      doAssert req.timeoutAt <= Moment.now()
      # Here we'll remove the expired request by swapping
      # it with the last one in the deque (if necessary):
      if idx != outstandingReqs.len - 1:
        req = outstandingReqs.popLast
        continue
      else:
        outstandingReqs.shrink(fromLast = 1)
        # This was the last item, so we don't have any
        # more work to do:
        return

    if req.id == reqId:
      resolve req.future
      # Here we'll remove the found request by swapping
      # it with the last one in the deque (if necessary):
      if idx != outstandingReqs.len - 1:
        req = outstandingReqs.popLast
      else:
        outstandingReqs.shrink(fromLast = 1)
      return

    inc idx

  debug "late or duplicate reply for a network request"

proc initProtocol(name: string, version: int,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer): ProtocolInfoObj =
  result.name = name
  result.version = version
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

  let reqId = registerRequest(peer, protocol, timeout,
                              responseFuture, responseMethodId)

  result = stream.delayFixedSizeWrite sizeof(SpecOuterMsgHeader)

  stream.appendPackedObject SpecInnerMsgHeader(
    reqId: reqId,
    methodId: requestMethodId)

proc prepareResponse(responder: ResponderWithId,
                     stream: OutputStreamVar): DelayedWriteCursor =
  result = stream.delayFixedSizeWrite sizeof(SpecOuterMsgHeader)

proc implementSendProcBody(sendProc: SendProc) =
  let
    msg = sendProc.msg
    delayedWriteCursor = ident "delayedWriteCursor"
    peer = sendProc.peerParam

  proc preludeGenerator(stream: NimNode): NimNode =
    result = newStmtList()
    case msg.kind
    of msgRequest:
      let
        requestMethodId = newLit(msg.id)
        responseMethodId = newLit(msg.response.id)
        protocol = sendProc.msg.protocol.protocolInfoVar
        timeout = sendProc.timeoutParam

      result.add quote do:
        let `delayedWriteCursor` = `prepareRequest`(
          `peer`, `protocol`, `requestMethodId`, `responseMethodId`,
          `stream`, `timeout`, `resultIdent`)
    of msgResponse:
      result.add quote do:
        let `delayedWriteCursor` = `prepareResponse`(`peer`, `stream`)
    else:
      discard

  proc sendCallGenerator(peer, bytes: NimNode): NimNode =
    let
      linkSendFailureToReqFuture = bindSym "linkSendFailureToReqFuture"
      sendMsg = bindSym "sendMsg"
      sendCall = newCall(sendMsg, peer, bytes)

    if msg.kind == msgRequest:
      # In RLPx requests, the returned future was allocated here and passed
      # to `registerRequest`. It's already assigned to the result variable
      # of the proc, so we just wait for the sending operation to complete
      # and we return in a normal way. (the waiting is done, so we can catch
      # any possible errors).
      quote: `linkSendFailureToReqFuture`(`sendCall`, `resultIdent`)
    else:
      # In normal RLPx messages, we are returning the future returned by the
      # `sendMsg` call.
      quote: return `sendCall`

  sendProc.useStandardBody(preludeGenerator, sendCallGenerator)

proc p2pProtocolBackendImpl*(p: P2PProtocol): Backend =
  let
    Option = bindSym "Option"
    Peer = bindSym "Peer"
    EthereumNode = bindSym "EthereumNode"

    Format = ident "SSZ"
    Response = bindSym "Response"
    ResponderWithId = bindSym "ResponderWithId"
    perProtocolMsgId = ident"perProtocolMsgId"

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

    let callResolvePendingFutures = if msg.kind == msgResponse:
      newCall(resolvePendingFutures,
              peerVar, protocol.protocolInfoVar,
              msgIdLit, newCall("addr", receivedMsg), reqIdVar)
    else:
      newStmtList()

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

