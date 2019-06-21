import
  options, macros, algorithm, tables,
  std_shims/[macros_shim, tables_shims], chronos, chronicles,
  libp2p/daemon/daemonapi, faststreams/output_stream, serialization,
  eth/p2p/p2p_protocol_dsl,
  ssz

export
  daemonapi, p2pProtocol

type
  Eth2Node* = ref object of RootObj
    daemon*: DaemonAPI
    peers*: Table[PeerID, Peer]
    protocolStates*: seq[RootRef]

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

  Peer* = ref object
    network*: Eth2Node
    id*: PeerID
    connectionState*: ConnectionState
    awaitedMessages: Table[CompressedMsgId, FutureBase]
    protocolStates*: seq[RootRef]
    maxInactivityAllowed*: Duration

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  DisconnectionReason* = enum
    UselessPeer
    BreachOfProtocol
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

const
  defaultIncomingReqTimeout = 5000
  defaultOutgoingReqTimeout = 10000
  HandshakeTimeout = BreachOfProtocol

  IrrelevantNetwork* = UselessPeer

include libp2p_backends_common
include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing

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

proc readMsg(stream: P2PStream, MsgType: type,
             deadline: Future[void]): Future[Option[MsgType]] {.async.} =
  var sizePrefix: uint32
  var readSizePrefix = stream.transp.readExactly(addr sizePrefix, sizeof(sizePrefix))
  await readSizePrefix or deadline
  if not readSizePrefix.finished: return

  var msgBytes = newSeq[byte](sizePrefix.int + sizeof(sizePrefix))
  copyMem(addr msgBytes[0], addr sizePrefix, sizeof(sizePrefix))
  var readBody = stream.transp.readExactly(addr msgBytes[sizeof(sizePrefix)], sizePrefix.int)
  await readBody or deadline
  if not readBody.finished: return

  let decoded = SSZ.decode(msgBytes, MsgType)
  try:
    return some(decoded)
  except SerializationError:
    return

proc sendMsg(peer: Peer, protocolId: string, requestBytes: Bytes) {.async} =
  var stream = await peer.network.daemon.openStream(peer.id, @[protocolId])
  # TODO how does openStream fail? Set a timeout here and handle it
  let sent = await stream.transp.write(requestBytes)
  # TODO: Should I check that `sent` is equal to the desired number of bytes

proc sendBytes(stream: P2PStream, bytes: Bytes) {.async.} =
  let sent = await stream.transp.write(bytes)
  # TODO: Should I check that `sent` is equal to the desired number of bytes

proc makeEth2Request(peer: Peer, protocolId: string, requestBytes: Bytes,
                     ResponseMsg: type,
                     timeout = 10.seconds): Future[Option[ResponseMsg]] {.async.} =
  var deadline = sleepAsync timeout

  # Open a new LibP2P stream
  var streamFut = peer.network.daemon.openStream(peer.id, @[protocolId])
  await streamFut or deadline
  if not streamFut.finished:
    return none(ResponseMsg)

  # Send the request
  let stream = streamFut.read
  let sent = await stream.transp.write(requestBytes)
  if sent != requestBytes.len:
    await disconnectAndRaise(peer, FaultOrError, "Incomplete send")

  # Read the response
  return await stream.readMsg(ResponseMsg, deadline)

proc p2pStreamName(MsgType: type): string =
  mixin msgProtocol, protocolInfo, msgId
  MsgType.msgProtocol.protocolInfo.messages[MsgType.msgId].libp2pProtocol

template handshakeImpl(HandshakeTypeExpr: untyped,
                         # TODO: we cannot use a type parameter above
                         # because of the following Nim issue:
                         #
                       peerExpr: Peer,
                       streamExpr: P2PStream,
                       lazySendCall: Future[void],
                       timeoutExpr: Duration): auto =
  # We make sure the inputs are evaluated only once.
  let
    stream = streamExpr
    peer = peerExpr
    timeout = timeoutExpr

  # TODO: This is a work-around for a Nim issue. Please note that it's
  # semantically wrong, so if you get a compilation failure, try to
  # remove it (perhaps Nim got fixed)
  type HandshakeType = type(HandshakeTypeExpr)

  proc asyncStep(stream: P2PStream): Future[HandshakeType] {.async.} =
    let deadline = sleepAsync timeout
    var stream = stream
    if stream == nil:
      try: stream = await openStream(peer.network.daemon, peer.id,
                                     @[p2pStreamName(HandshakeType)],
                                     # TODO openStream should accept Duration
                                     int milliseconds(timeout))
      except CatchableError:
        const errMsg = "Failed to open LIBP2P stream"
        debug errMsg,
              stream = p2pStreamName(HandshakeType),
              err = getCurrentExceptionMsg()
        await disconnectAndRaise(peer, FaultOrError, errMsg)

    try:
      # Please pay attention that `lazySendCall` is evaluated lazily here.
      # For this reason `handshakeImpl` must remain a template.
      await lazySendCall
      let response = await readMsg(stream, HandshakeType, deadline)
      if response.isSome:
        return response.get
      else:
        await disconnectAndRaise(peer, BreachOfProtocol, "Handshake not completed in time")
    except CatchableError:
      await reraiseAsPeerDisconnected(peer, "Failure during handshake")

  asyncStep(stream)

proc resolveNextMsgFutures(peer: Peer, msg: auto) =
  type MsgType = type(msg)
  let msgId = getCompressedMsgId(MsgType)
  let future = peer.awaitedMessages.getOrDefault(msgId)
  if future != nil:
    Future[MsgType](future).complete msg

proc init*(T: type Peer, network: Eth2Node, id: PeerID): Peer =
  new result
  result.id = id
  result.network = network
  result.awaitedMessages = initTable[CompressedMsgId, FutureBase]()
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

template getRecipient(peer: Peer): Peer =
  peer

# TODO: this should be removed eventually
template getRecipient(stream: P2PStream): P2PStream =
  stream

template getRecipient(response: Responder): Peer =
  UntypedResponder(response).peer

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
  when true:
    return newLit("rpc/" & $fn.name)
  else:
    # `getCustomPragmaVal` doesn't work yet on regular nnkProcDef nodes
    # (TODO: file as an issue)
    let pragmas = fn.pragma
    if pragmas.kind == nnkPragma and pragmas.len > 0:
      for pragma in pragmas:
        if pragma.len > 0 and $pragma[0] == "libp2pProtocol":
          return pragma[1]

    error "All stream opening procs must have the 'libp2pProtocol' pragma specified.", fn

proc init*[MsgType](T: type Responder[MsgType],
                    peer: Peer, stream: P2PStream): T =
  T(UntypedResponder(peer: peer, stream: stream))

proc implementSendProcBody(sendProc: SendProc) =
  let
    msg = sendProc.msg
    peer = sendProc.peerParam
    timeout = sendProc.timeoutParam
    ResponseRecord = if msg.response != nil: msg.response.recIdent else: nil
    UntypedResponder = bindSym "UntypedResponder"
    sendMsg = bindSym "sendMsg"
    sendBytes = bindSym "sendBytes"
    makeEth2Request = bindSym "makeEth2Request"

  proc sendCallGenerator(peer, bytes: NimNode): NimNode =
    if msg.kind != msgResponse:
      let msgProto = getRequestProtoName(msg.procDef)
      case msg.kind
      of msgRequest:
        let timeout = msg.timeoutParam[0]
        quote: `makeEth2Request`(`peer`, `msgProto`, `bytes`,
                                 `ResponseRecord`, `timeout`)
      of msgHandshake:
        quote: `sendBytes`(`peer`, `bytes`)
      else:
        quote: `sendMsg`(`peer`, `msgProto`, `bytes`)
    else:
      quote: `sendBytes`(`UntypedResponder`(`peer`).stream, `bytes`)

  sendProc.useStandardBody(nil, nil, sendCallGenerator)

proc p2pProtocolBackendImpl*(p: P2PProtocol): Backend =
  var
    Format = ident "SSZ"
    Responder = bindSym "Responder"
    DaemonAPI = bindSym "DaemonAPI"
    P2PStream = ident "P2PStream"
    Peer = bindSym "Peer"
    Eth2Node = bindSym "Eth2Node"
    messagePrinter = bindSym "messagePrinter"
    peerFromStream = bindSym "peerFromStream"
    handshakeImpl = bindSym "handshakeImpl"
    resolveNextMsgFutures = bindSym "resolveNextMsgFutures"
    milliseconds = bindSym "milliseconds"
    registerMsg = bindSym "registerMsg"
    initProtocol = bindSym "initProtocol"
    bindSymOp = bindSym "bindSym"
    receivedMsg = ident "msg"
    daemonVar = ident "daemon"
    streamVar = ident "stream"
    deadlineVar = ident "deadline"
    await = ident "await"

  p.useRequestIds = false

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
      msgRecName = msg.recIdent

    if msg.procDef.body.kind != nnkEmpty and msg.kind == msgRequest:
      # Request procs need an extra param - the stream where the response
      # should be written:
      msg.userHandler.params.insert(2, newIdentDefs(streamVar, P2PStream))
      msg.initResponderCall.add streamVar

    ##
    ## Implemenmt Thunk
    ##
    let awaitUserHandler = msg.genAwaitUserHandler(
      newCall("get", receivedMsg), [peerVar, streamVar])

    let tracing = when tracingEnabled:
      quote do: logReceivedMsg(`streamVar`.peer, `receivedMsg`.get)
    else:
      newStmtList()

    let
      requestDataTimeout = newCall(milliseconds, newLit(defaultIncomingReqTimeout))
      thunkName = ident(msgName & "_thunk")

    msg.defineThunk if msg.kind == msgHandshake:
      # In LibP2P protocols, the `onPeerConnected` handler is executed when the
      # other peer opens a stream. Contrary to other thunk procs, the message is
      # not immediately deserialized. Instead, the handshake "sender proc" acts
      # as an exchanger that sends our handshake message while deserializing the
      # contents of the other peer's handshake.
      # Thus, the very first communication act of the `onPeerConnected` handler
      # must be the execution of the handshake exchanger.
      let handshake = msg.protocol.onPeerConnected
      if handshake.isNil:
        macros.error "A LibP2P protocol with a handshake must also include an " &
                     "`onPeerConnected` handler.", msg.procDef

      # We must generate a forward declaration for the `onPeerConnected` handler,
      # so we can call it from the thunk proc:
      let handshakeProcName = handshake.name
      msg.protocol.outRecvProcs.add quote do:
        proc `handshakeProcName`(`peerVar`: `Peer`,
                                 `streamVar`: `P2PStream`) {.async, gcsafe.}

      quote:
        proc `thunkName`(`daemonVar`: `DaemonAPI`,
                         `streamVar`: `P2PStream`): Future[void] {.gcsafe.} =
          let `peerVar` = `peerFromStream`(`daemonVar`, `streamVar`)
          return `handshakeProcName`(`peerVar`, `streamVar`)
    else:
      quote:
        proc `thunkName`(`daemonVar`: `DaemonAPI`,
                         `streamVar`: `P2PStream`) {.async, gcsafe.} =
          var `deadlineVar` = sleepAsync `requestDataTimeout`
          var `receivedMsg` = `await` readMsg(`streamVar`,
                                              `msgRecName`,
                                              `deadlineVar`)
          if `receivedMsg`.isNone:
            # TODO: This peer is misbehaving, perhaps we should penalize him somehow
            return
          let `peerVar` = `peerFromStream`(`daemonVar`, `streamVar`)
          `tracing`
          `awaitUserHandler`
          `resolveNextMsgFutures`(`peerVar`, get(`receivedMsg`))

    ##
    ## Implement Senders and Handshake
    ##
    var sendProc = msg.createSendProc(isRawSender = (msg.kind == msgHandshake))
    implementSendProcBody sendProc

    if msg.kind == msgHandshake:
      var
        rawSendProc = newLit($sendProc.def.name)
        handshakeExchanger = msg.createSendProc(nnkMacroDef)
        paramsArray = newTree(nnkBracket).appendAllParams(handshakeExchanger.def)
        bindSym = ident "bindSym"
        getAst = ident "getAst"

      handshakeExchanger.setBody quote do:
        let
          stream = ident "stream"
          rawSendProc = `bindSymOp` `rawSendProc`
          params = `paramsArray`
          lazySendCall = newCall(rawSendProc, params)
          peer = params[0]
          timeout = params[^1]

        lazySendCall[1] = stream
        lazySendCall.del(lazySendCall.len - 1)

        return `getAst`(`handshakeImpl`(`msgRecName`, peer, stream, lazySendCall, timeout))

      sendProc.def.params[1][1] = P2PStream

    protocol.outProcRegistrations.add(
      newCall(registerMsg,
              protocol.protocolInfoVar,
              newLit(msgName),
              thunkName,
              getRequestProtoName(msg.procDef),
              newTree(nnkBracketExpr, messagePrinter, msgRecName)))

  result.implementProtocolInit = proc (p: P2PProtocol): NimNode =
    return newCall(initProtocol, newLit(p.name), p.peerInit, p.netInit)

