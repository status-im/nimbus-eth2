import
  macros, algorithm, tables,
  std_shims/[macros_shim, tables_shims], chronos, chronicles,
  libp2p/daemon/daemonapi, faststreams/output_stream, serialization,
  json_serialization/std/options, eth/p2p/p2p_protocol_dsl,
  libp2p_json_serialization, ssz

export
  daemonapi, p2pProtocol, libp2p_json_serialization

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

  ResponseCode* = enum
    Success
    EncodingError
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

const
  defaultIncomingReqTimeout = 5000
  defaultOutgoingReqTimeout = 10000
  HandshakeTimeout = BreachOfProtocol

  IrrelevantNetwork* = UselessPeer

include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing
include libp2p_backends_common

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

proc readMsg(stream: P2PStream,
             MsgType: type,
             withResponseCode: bool,
             deadline: Future[void]): Future[Option[MsgType]] {.gcsafe.}

proc readMsgBytes(stream: P2PStream,
                  withResponseCode: bool,
                  deadline: Future[void]): Future[Bytes] {.async.} =
  if withResponseCode:
    var responseCode: byte
    var readResponseCode = stream.transp.readExactly(addr responseCode, 1)
    await readResponseCode or deadline
    if not readResponseCode.finished: return
    if responseCode > ResponseCode.high.byte: return

    logScope: responseCode = ResponseCode(responseCode)
    case ResponseCode(responseCode)
    of InvalidRequest:
      debug "P2P request was classified as invalid"
      return
    of EncodingError, ServerError:
      let responseErrMsg = await readMsg(stream, string, false, deadline)
      debug "P2P request resulted in error", responseErrMsg
      return
    of Success:
      # The response is OK, the execution continues below
      discard

  var sizePrefix: uint32
  var readSizePrefix = stream.transp.readExactly(addr sizePrefix, sizeof(sizePrefix))
  await readSizePrefix or deadline
  if not readSizePrefix.finished: return

  if sizePrefix == 0:
    debug "Received SSZ with zero size", peer = stream.peer
    return

  var msgBytes = newSeq[byte](sizePrefix.int + sizeof(sizePrefix))
  copyMem(addr msgBytes[0], addr sizePrefix, sizeof(sizePrefix))
  var readBody = stream.transp.readExactly(addr msgBytes[sizeof(sizePrefix)], sizePrefix.int)
  await readBody or deadline
  if not readBody.finished: return

  return msgBytes

proc readMsgBytesOrClose(stream: P2PStream,
                         withResponseCode: bool,
                         deadline: Future[void]): Future[Bytes] {.async.} =
  result = await stream.readMsgBytes(withResponseCode, deadline)
  if result.len == 0: await stream.close()

proc readMsg(stream: P2PStream,
             MsgType: type,
             withResponseCode: bool,
             deadline: Future[void]): Future[Option[MsgType]] {.gcsafe, async.} =
  var msgBytes = await stream.readMsgBytesOrClose(withResponseCode, deadline)
  try:
    if msgBytes.len > 0: return some SSZ.decode(msgBytes, MsgType)
  except SerializationError as err:
    debug "Failed to decode a network message",
          msgBytes, errMsg = err.formatMsg("<msg>")
    return

proc sendErrorResponse(peer: Peer,
                       stream: P2PStream,
                       err: ref SerializationError,
                       msgName: string,
                       msgBytes: Bytes) {.async.} =
  debug "Received an invalid request",
        peer, msgName, msgBytes, errMsg = err.formatMsg("<msg>")

  var responseCode = byte(EncodingError)
  discard await stream.transp.write(addr responseCode, 1)
  await stream.close()

proc sendErrorResponse(peer: Peer,
                       stream: P2PStream,
                       responseCode: ResponseCode,
                       errMsg: string) {.async.} =
  debug "Error processing request",
        peer, responseCode, errMsg

  var outputStream = init OutputStream
  outputStream.append byte(responseCode)
  outputStream.appendValue SSZ, errMsg

  discard await stream.transp.write(outputStream.getOutput)
  await stream.close()

proc sendMsg(peer: Peer, protocolId: string, requestBytes: Bytes) {.async} =
  var stream = await peer.network.daemon.openStream(peer.id, @[protocolId])
  # TODO how does openStream fail? Set a timeout here and handle it
  let sent = await stream.transp.write(requestBytes)
  if sent != requestBytes.len:
    raise newException(TransmissionError, "Failed to deliver all bytes")

proc sendBytes(stream: P2PStream, bytes: Bytes) {.async.} =
  let sent = await stream.transp.write(bytes)
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
    return none(ResponseMsg)

  # Send the request
  let stream = streamFut.read
  let sent = await stream.transp.write(requestBytes)
  if sent != requestBytes.len:
    await disconnectAndRaise(peer, FaultOrError, "Incomplete send")

  # Read the response
  return await stream.readMsg(ResponseMsg, true, deadline)

proc exchangeHandshake(peer: Peer, protocolId: string, requestBytes: Bytes,
                       ResponseMsg: type,
                       timeout: Duration): Future[ResponseMsg] {.gcsafe, async.} =
  var response = await makeEth2Request(peer, protocolId, requestBytes,
                                       ResponseMsg, timeout)
  if not response.isSome:
    await peer.disconnectAndRaise(BreachOfProtocol, "Failed to complete a handshake")

  return response.get

proc p2pStreamName(MsgType: type): string =
  mixin msgProtocol, protocolInfo, msgId
  MsgType.msgProtocol.protocolInfo.messages[MsgType.msgId].libp2pProtocol

template handshakeImpl(outputStreamVar, handshakeSerializationCall: untyped,
                       lowLevelThunk: untyped,
                       HandshakeType: untyped,
                         # TODO: we cannot use a type parameter above
                         # because of the following Nim issue:
                         #
                       peer: Peer,
                       stream: P2PStream,
                       timeout: Duration): auto =
  if stream == nil:
    var outputStreamVar = init OutputStream
    handshakeSerializationCall
    exchangeHandshake(peer, p2pStreamName(HandshakeType),
                      getOutput(outputStreamVar), HandshakeType, timeout)
  else:
    proc asyncStep: Future[HandshakeType] {.async.} =
      let deadline = sleepAsync timeout
      var responseFut = nextMsg(peer, HandshakeType)
      await lowLevelThunk(peer.network.daemon, stream) or deadline
      if not responseFut.finished:
        await disconnectAndRaise(peer, BreachOfProtocol, "Failed to complete a handshake")

      var outputStreamVar = init OutputStream
      append(outputStreamVar, byte(Success))
      handshakeSerializationCall
      await sendBytes(stream, getOutput(outputStreamVar))

      return responseFut.read

    asyncStep()

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
  return newLit("/ETH/BeaconChain/" & $fn.name & "/1/SSZ")

proc init*[MsgType](T: type Responder[MsgType],
                    peer: Peer, stream: P2PStream): T =
  T(UntypedResponder(peer: peer, stream: stream))

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
          ResponseRecord = msg.response.recIdent
        quote:
          makeEth2Request(`peer`, `msgProto`, `bytes`,
                          `ResponseRecord`, `timeout`)
      of msgHandshake:
        let
          timeout = msg.timeoutParam[0]
          HandshakeRecord = msg.recIdent
        quote:
          exchangeHandshake(`peer`, `msgProto`, `bytes`,
                            `HandshakeRecord`, `timeout`)
      else:
        quote: sendMsg(`peer`, `msgProto`, `bytes`)
    else:
      quote: sendBytes(`UntypedResponder`(`peer`).stream, `bytes`)

  proc prependResponseCode(stream: NimNode): NimNode =
    quote: append(`stream`, byte(Success))

  let preSerializationStep = if msg.kind == msgResponse:
    prependResponseCode
  else:
    nil

  sendProc.useStandardBody(preSerializationStep, nil, sendCallGenerator)

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
      msgRecName = msg.recIdent

    if msg.procDef.body.kind != nnkEmpty and msg.kind == msgRequest:
      # Request procs need an extra param - the stream where the response
      # should be written:
      msg.userHandler.params.insert(2, newIdentDefs(streamVar, P2PStream))
      msg.initResponderCall.add streamVar

    ##
    ## Implemenmt Thunk
    ##
    var thunkName = ident(msgName & "_thunk")
    let
      requestDataTimeout = newCall(milliseconds, newLit(defaultIncomingReqTimeout))
      awaitUserHandler = msg.genAwaitUserHandler(msgVar, [peerVar, streamVar])

    let tracing = when tracingEnabled:
      quote: logReceivedMsg(`streamVar`.peer, `msgVar`.get)
    else:
      newStmtList()

    msg.defineThunk quote do:
      proc `thunkName`(`daemonVar`: `DaemonAPI`,
                       `streamVar`: `P2PStream`) {.async, gcsafe.} =
        let
          `deadlineVar` = sleepAsync `requestDataTimeout`
          `msgBytesVar` = `await` readMsgBytes(`streamVar`, false, `deadlineVar`)
          `peerVar` = peerFromStream(`daemonVar`, `streamVar`)

        if `msgBytesVar`.len == 0:
          `await` sendErrorResponse(`peerVar`, `streamVar`, ServerError,
                                    "Exceeded read timeout for a request")
          return

        var `msgVar`: `msgRecName`
        try:
          `msgVar` = decode(`Format`, `msgBytesVar`, `msgRecName`)
        except SerializationError as `errVar`:
          `await` sendErrorResponse(`peerVar`, `streamVar`, `errVar`,
                                    `msgNameLit`, `msgBytesVar`)
          return

        try:
          `tracing`
          `awaitUserHandler`
          resolveNextMsgFutures(`peerVar`, `msgVar`)
        except CatchableError as `errVar`:
          `await` sendErrorResponse(`peerVar`, `streamVar`, ServerError, `errVar`.msg)

    ##
    ## Implement Senders and Handshake
    ##
    if msg.kind == msgHandshake:
      # In LibP2P protocols, the handshake thunk is special. Instead of directly
      # deserializing the incoming message and calling the user-supplied handler,
      # we execute the `onPeerConnected` handler instead.
      #
      # The `onPeerConnected` handler is executed symmetrically for both peers
      # and it's expected that one of its very first steps would be to send the
      # handshake and then await the same from the other side. We call this step
      # "handshakeExchanger".
      #
      # For the initiating peer, the handshakeExchanger opens a stream and sends
      # a regular request through it, but on the receiving side, it just setups
      # a future and call the lower-level thunk that will complete it.
      #
      let
        handshake = msg.protocol.onPeerConnected
        lowLevelThunkName = $thunkName

      if handshake.isNil:
        macros.error "A LibP2P protocol with a handshake must also include an " &
                     "`onPeerConnected` handler.", msg.procDef

      # We must generate a forward declaration for the `onPeerConnected` handler,
      # so we can call it from the thunk proc:
      let handshakeProcName = handshake.name
      msg.protocol.outRecvProcs.add quote do:
        proc `handshakeProcName`(`peerVar`: `Peer`,
                                 `streamVar`: `P2PStream`) {.async, gcsafe.}

      # Here we replace the 'thunkProc' that will be registered as a handler
      # for incoming messages:
      thunkName = ident(msgName & "_handleConnection")

      msg.protocol.outRecvProcs.add quote do:
        proc `thunkName`(`daemonVar`: `DaemonAPI`,
                         `streamVar`: `P2PStream`) {.async, gcsafe.} =
          let `peerVar` = peerFromStream(`daemonVar`, `streamVar`)
          try:
            debug "INCOMING CONNECTION", `peerVar`
            `await` `handshakeProcName`(`peerVar`, `streamVar`)
            debug "HANDSHAKE COMPLETED", `peerVar`
          except SerializationError as err:
            debug "Failed to decode message",
                  err = err.formatMsg("<msg>"),
                  msg = `msgNameLit`,
                  peer = $(`streamVar`.peer)
            `await` disconnect(`peerVar`, FaultOrError)
          except CatchableError as err:
            debug "Failed to complete handshake", err = err.msg
            `await` disconnect(`peerVar`, FaultOrError)

      var
        handshakeSerializer = msg.createSerializer()
        handshakeSerializerName = newLit($handshakeSerializer.name)
        handshakeExchanger = msg.createSendProc(nnkMacroDef)
        paramsArray = newTree(nnkBracket).appendAllParams(handshakeExchanger.def)
        handshakeTypeName = newLit($msg.recIdent)
        getAst = ident "getAst"
        res = ident "result"

      handshakeExchanger.setBody quote do:
        let
          stream = ident "stream"
          outputStreamVar = ident "outputStream"
          lowLevelThunk = ident `lowLevelThunkName`
          HandshakeType = ident `handshakeTypeName`
          params = `paramsArray`
          peer = params[0]
          timeout = params[^1]
          handshakeSerializationCall = newCall(`bindSymOp` `handshakeSerializerName`, params)

        handshakeSerializationCall[1] = outputStreamVar
        handshakeSerializationCall.del(handshakeSerializationCall.len - 1)

        `res` = `getAst`(handshakeImpl(outputStreamVar, handshakeSerializationCall,
                                       lowLevelThunk, HandshakeType,
                                       peer, stream, timeout))

        when defined(debugMacros) or defined(debugHandshake):
          echo "---- Handshake implementation ----"
          echo repr(`res`)
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

