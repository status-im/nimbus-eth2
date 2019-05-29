import
  tables, deques, options, algorithm, std_shims/macros_shim,
  chronos, chronicles, serialization, faststreams/input_stream,
  eth/p2p/p2p_protocol_dsl, libp2p/daemon/daemonapi,
  ssz

const
  # Compression nibble
  NoCompression* = uint 0
  
  # Encoding nibble
  SszEncoding* = uint 1

type
  Eth2Node* = ref object of RootObj
    daemon*: DaemonAPI
    peers*: Table[PeerID, Peer]
    protocolStates*: seq[RootRef]

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

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
    protocolIndex, msgId: int

  ResponseWithId*[MsgType] = object
    peer*: Peer
    id*: int

  Response*[MsgType] = distinct Peer

  # -----------------------------------------

  ResponseCode* = enum
    NoError
    ParseError = 10
    InvalidRequest = 20
    MethodNotFound = 30
    ServerError = 40

  OutstandingRequest* = object
    id*: int
    future*: FutureBase
    timeoutAt*: Moment

  ProtocolConnection* = object
    stream*: P2PStream
    protocolInfo*: ProtocolInfo

  Peer* = ref object
    network*: Eth2Node
    id*: PeerID
    lastSentMsgId*: int
    rpcStream*: P2PStream
    connectionState*: ConnectionState
    protocolStates*: seq[RootRef]
    maxInactivityAllowed: Duration
    awaitedMessages: Table[CompressedMsgId, FutureBase]
    outstandingRequests*: seq[Deque[OutstandingRequest]]

  MessageInfo* = object
    id*: int
    name*: string

    # Private fields:
    thunk*: ThunkProc
    libp2pProtocol: string
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
  NextMsgResolver* = proc(msgData: SszReader, future: FutureBase) {.gcsafe.}
  RequestResolver* = proc(msg: pointer, future: FutureBase) {.gcsafe.}

  Bytes = seq[byte]

  InvalidMsgIdError = object of InvalidMsgError

var
  gProtocols: seq[ProtocolInfo]

include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing

proc `$`*(peer: Peer): string = $peer.id

proc readFixedSizeStruct(stream: P2PStream, T: type): Future[T] {.async.} =
  await stream.transp.readExactly(addr result, sizeof result)

type
  PeerLoopExitReason = enum
    Success
    UnsupportedCompression
    UnsupportedEncoding
    ProtocolViolation
    InactivePeer
    InternalError

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

proc disconnect*(peer: Peer, reason: DisconnectionReason, notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    await peer.network.daemon.disconnect(peer.id)
    peer.connectionState = Disconnected
    peer.network.peers.del(peer.id)

proc recvAndDispatchMsg*(peer: Peer, protocol: ProtocolInfo, stream: P2PStream):
                         Future[PeerLoopExitReason] {.async.} =
  template fail(reason) =
    return reason

  var outerHeader = await stream.readFixedSizeStruct(SpecOuterMsgHeader)

  if outerHeader.compression != NoCompression:
    fail UnsupportedCompression
  
  if outerHeader.encoding != SszEncoding:
    fail UnsupportedEncoding

  if outerHeader.msgLen <= SpecInnerMsgHeader.sizeof.uint64:
    fail ProtocolViolation

  var innerHeader = await stream.readFixedSizeStruct(SpecInnerMsgHeader)

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

proc nextMsg*(peer: Peer, MsgType: type): Future[MsgType] =
  ## This procs awaits a specific RLPx message.
  ## Any messages received while waiting will be dispatched to their
  ## respective handlers. The designated message handler will also run
  ## to completion before the future returned by `nextMsg` is resolved.
  let wantedId = peer.perPeerMsgId(MsgType)
  let f = peer.awaitedMessages[wantedId]
  if not f.isNil:
    return Future[MsgType](f)

  initFuture result
  peer.awaitedMessages[wantedId] = result

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

proc nextMsgResolver[MsgType](msgData: ByteStreamVar, future: FutureBase) {.gcsafe.} =
  var reader = msgData
  Future[MsgType](future).complete reader.readRecordType(MsgType, MsgType.rlpFieldsCount > 1)

proc registerRequest(peer: Peer,
                     protocol: ProtocolInfo,
                     timeout: Duration,
                     responseFuture: FutureBase,
                     responseMsgId: int): int =
  inc peer.lastSentMsgId
  result = peer.lastSentMsgId

  let timeoutAt = Moment.fromNow(timeout)
  let req = OutstandingRequest(id: result,
                               future: responseFuture,
                               timeoutAt: timeoutAt)
  peer.outstandingRequests[responseMsgId].addLast req

  let requestResolver = protocol.dispatcher.messages[responseMsgId].requestResolver
  proc timeoutExpired(udata: pointer) = requestResolver(nil, responseFuture)
  
  addTimer(timeoutAt, timeoutExpired, nil)

proc resolveResponseFuture(peer: Peer, protocol: ProtocolInfo, msgId: int, msg: pointer, reqId: int) =
  when false:
    logScope:
      msg = peer.dispatcher.messages[msgId].name
      msgContents = peer.dispatcher.messages[msgId].printer(msg)
      receivedReqId = reqId
      remotePeer = peer.remote

  template resolve(future) =
    (protocol.dispatcher.messages[msgId].requestResolver)(msg, future)

  template outstandingReqs: auto =
    peer.outstandingRequests[msgId]

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

  debug "late or duplicate reply for a RLPx request"

proc initProtocol(name: string, version: int,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer): ProtocolInfoObj =
  result.name = name
  result.version = version
  result.messages = @[]
  result.peerStateInitializer = peerInit
  result.networkStateInitializer = networkInit

proc setEventHandlers(p: ProtocolInfo,
                      handshake: HandshakeStep,
                      disconnectHandler: DisconnectionHandler) =
  p.handshake = handshake
  p.disconnectHandler = disconnectHandler

proc registerProtocol(protocol: ProtocolInfo) =
  # TODO: This can be done at compile-time in the future
  let pos = lowerBound(gProtocols, protocol)
  gProtocols.insert(protocol, pos)
  for i in 0 ..< gProtocols.len:
    gProtocols[i].index = i

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

proc implementSendProcBody(msg: Message): NimNode =
  proc preludeGenerator(stream: NimNode): NimNode =
    result = newStmtList()
    if mgs.kind == msgRequest:
      var reqId = ident "reqId"
      let reqToResponseOffset = responseMsgId - msgId
      let responseMsgId = quote do: `perPeerMsgIdVar` + `reqToResponseOffset`

      # Each request is registered so we can resolve it when the response
      # arrives. There are two types of protocols: LES-like protocols use
      # explicit `reqId` sent over the wire, while the ETH wire protocol
      # assumes there is one outstanding request at a time (if there are
      # multiple requests we'll resolve them in FIFO order).
      let registerRequestCall = newCall(registerRequest, msgRecipient,
                                                         msg.timeoutParam[0],
                                                         resultIdent,
                                                         responseMsgId)

      result.add quote do:
        let `reqId` = `registerRequestCall`
        #`stream`.write(uint64(`reqId`))
        #`stream`.write(uint16(`methodId`))

  proc sendCallGenerator(peer, bytes: NimNode): NimNode =
    let
      linkSendFailureToReqFuture = bindSym "linkSendFailureToReqFuture"
      sendMsg = bindSym "sendMsg"
      resultIdent = ident "result"
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

  msg.createSendProcBody(preludeGenerator, sendCallGenerator)

proc p2pProtocolBackendImpl*(p: P2PProtocol): Backend =
  let
    resultIdent = ident "result"
    Option = bindSym "Option"
    
    # XXX: Binding the int type causes instantiation failure for some reason
    # Int = bindSym "int"
    Int = ident "int"
    Peer = bindSym "Peer"
    EthereumNode = bindSym "EthereumNode"
    Format = bindSym "SSZ"
    Response = bindSym "Response"
    ResponseWithId = bindSym "ResponseWithId"
    perProtocolMsgId = ident"perProtocolMsgId"

    mount = bindSym "mount"

    messagePrinter = bindSym "messagePrinter"
    nextMsgResolver = bindSym "nextMsgResolver"
    registerRequest = bindSym "registerRequest"
    requestResolver = bindSym "requestResolver"
    resolveResponseFuture = bindSym "resolveResponseFuture"
    nextMsg = bindSym "nextMsg"
    initProtocol = bindSym "initProtocol"
    registerMsg = bindSym "registerMsg"
    
    peer = ident "peer"
    reqId = ident "reqId"
    stream = ident "stream"
    protocol = ident "protocol"
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

  result.implementMsg = proc (p: P2PProtocol, msg: Message, resp: Message = nil) =
    var
      msgId = msg.id
      msgIdLit = newLit(msgId)
      msgRecName = msg.recIdent
      msgKind = msg.kind
      n = msg.procDef
      responseMsgId = if resp != nil: resp.id else: -1
      responseRecord = if resp != nil: resp.recIdent else: nil
      msgIdent = n.name
      msgName = $msgIdent
      hasReqIds = msgKind in {msgRequest, msgResponse}
      userPragmas = n.pragma

      # variables used in the sending procs
      msgRecipient = ident"msgRecipient"
      sendTo = ident"sendTo"
      rlpWriter = ident"writer"
      paramsToWrite = newSeq[NimNode](0)
      perPeerMsgIdVar  = ident"perPeerMsgId"

      # nodes to store the user-supplied message handling proc if present
      userHandlerCall: NimNode = nil
      awaitUserHandler = newStmtList()

    case msgKind
    of msgRequest:
      discard
      
    of msgResponse:
      if hasReqIds:
        paramsToWrite.add newDotExpr(sendTo, ident"id")

    of msgHandshake, msgNotification: discard

    if msg.userHandler != nil:
      var extraDefs: NimNode
      if msgKind == msgRequest:
        let peerParam = msg.userHandler.params[1][0]
        let response = ident"response"
        if hasReqIds:
          extraDefs = quote do:
            let `response` = `ResponseWithId`[`responseRecord`](peer: `peerParam`, id: `reqId`)
        else:
          extraDefs = quote do:
            let `response` = `Response`[`responseRecord`](`peerParam`)

        msg.userHandler.addPreludeDefs extraDefs

      # This is the call to the user supplied handled. Here we add only the
      # initial peer param, while the rest of the params will be added later.
      userHandlerCall = newCall(msg.userHandler.name, peer)

      if hasReqIds:
        msg.userHandler.params.insert(2, newIdentDefs(reqId, ident"int"))
        userHandlerCall.add reqId

      # When there is a user handler, it must be awaited in the thunk proc.
      # Above, by default `awaitUserHandler` is set to a no-op statement list.
      awaitUserHandler = newCall("await", userHandlerCall)

      p.outRecvProcs.add(msg.userHandler)

    for param, paramType in n.typedParams(skip = 1):
      # This is a fragment of the sending proc that
      # serializes each of the passed parameters:
      paramsToWrite.add param

      # If there is user message handler, we'll place a call to it by
      # unpacking the fields of the received message:
      if userHandlerCall != nil:
        userHandlerCall.add newDotExpr(receivedMsg, param)

    let traceMsg = when tracingEnabled:
      newCall(bindSym"logReceivedMsg", peer, receivedMsg)
    else:
      newStmtList()
  
    # variables used in the receiving procs
    let callResolvedResponseFuture = if msgKind == msgResponse:
      newCall(resolveResponseFuture, peer, msgIdLit, newCall("addr", receivedMsg), reqId)
    else:
      newStmtList()

    let thunkName = ident(msgName & "_thunk")
    var thunkProc = quote do:
      proc `thunkName`(`peer`: `Peer`,
                       `stream`: `P2PStream`,
                       `reqId`: uint64,
                       `msgContents`: `ByteStreamVar`) {.async, gcsafe.} =
        var `receivedMsg` = `mount`(`SSZ`, `msgContents`, `msgRecName`)
        `traceMsg`
        `awaitUserHandler`
        `callResolvedResponseFuture`

    for p in userPragmas: thunkProc.addPragma p

    case msgKind
    of msgRequest:  thunkProc.applyDecorator p.incomingRequestThunkDecorator
    of msgResponse: thunkProc.applyDecorator p.incomingResponseThunkDecorator
    else: discard
    
    p.outRecvProcs.add thunkProc

    var msgSendProc = n
    let msgSendProcName = n.name
    p.outSendProcs.add msgSendProc

    # TODO: check that the first param has the correct type
    msgSendProc.params[1][0] = sendTo
    msgSendProc.addPragma ident"gcsafe"

    case msgKind
    of msgRequest:
      # Add a timeout parameter for all request procs
      msgSendProc.params.add msg.timeoutParam
    of msgResponse:
      # A response proc must be called with a response object that originates
      # from a certain request. Here we change the Peer parameter at position
      # 1 to the correct strongly-typed ResponseType. The incoming procs still
      # gets the normal Peer paramter.
      # let rsp = bindSym "Response"
      # let rspId = bindSym "ResponseWithId"
      let
        ResponseType = newTree(nnkBracketExpr, ResponseWithId, msgRecName)

      msgSendProc.params[1][1] = ResponseType

      p.outSendProcs.add quote do:
        template send*(r: `ResponseType`, args: varargs[untyped]): auto =
          `msgSendProcName`(r, args)
    else: discard

    # We change the return type of the sending proc to a Future.
    # If this is a request proc, the future will return the response record.
    let rt = if msgKind != msgRequest: ident"void"
             else: newTree(nnkBracketExpr, Option, responseRecord)
    msgSendProc.params[0] = newTree(nnkBracketExpr, ident("Future"), rt)

    let msgBytes = ident"msgBytes"

    let finalizeRequest = quote do:
      let `msgBytes` = `finish`(`rlpWriter`)

    if msgKind == msgHandshake:
      var
        rawSendProc = genSym(nskProc, msgName & "RawSend")
        handshakeExchanger = newProc(name = msg.identWithExportMarker,
                                     procType = nnkTemplateDef)

      handshakeExchanger.params = msgSendProc.params.copyNimTree
      handshakeExchanger.params.add msg.timeoutParam
      handshakeExchanger.params[0] = newTree(nnkBracketExpr, ident("Future"), msgRecName)

      var
        forwardCall = newCall(rawSendProc).appendAllParams(handshakeExchanger)
        peerValue = forwardCall[1]
        timeoutValue = msg.timeoutParam[0]
        handshakeImpl = ident"handshakeImpl"

      forwardCall[1] = peer
      forwardCall.del(forwardCall.len - 1)

      handshakeExchanger.body = quote do:
        let `peer` = `peerValue`
        let sendingFuture = `forwardCall`
        `handshakeImpl`(`peer`,
                        sendingFuture,
                        `nextMsg`(`peer`, `msgRecName`),
                        `timeoutValue`)

      msgSendProc.name = rawSendProc
      p.outSendProcs.add handshakeExchanger
    else:
      # Make the send proc public
      msgSendProc.name = msg.identWithExportMarker

    let initWriter = quote do:
      var `rlpWriter` = `initRlpWriter`()
      const `perProtocolMsgId` = `msgId`
      let `perPeerMsgIdVar` = `msgIdLit`
      `append`(`rlpWriter`, `perPeerMsgIdVar`)

    msgSendProc.body = implementSendProcBody(msg)

    if msgKind == msgRequest:
      msgSendProc.applyDecorator p.outgoingRequestDecorator

    p.outProcRegistrations.add(
      newCall(registerMsg,
              p.protocolInfoVar,
              newIntLitNode(msgId),
              newStrLitNode($n.name),
              thunkName,
              newTree(nnkBracketExpr, messagePrinter, msgRecName),
              newTree(nnkBracketExpr, requestResolver, msgRecName),
              newTree(nnkBracketExpr, nextMsgResolver, msgRecName)))

  result.implementProtocolInit = proc (p: P2PProtocol): NimNode =
    return newCall(initProtocol,
                   newLit(p.shortName),
                   newLit(p.version),
                   p.peerInit, p.netInit)

