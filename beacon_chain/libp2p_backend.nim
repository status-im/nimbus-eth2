import
  algorithm, typetraits,
  stew/varints, stew/shims/[macros, tables], chronos, chronicles,
  faststreams/output_stream, serialization,
  json_serialization/std/options, eth/p2p/p2p_protocol_dsl,
  # TODO: create simpler to use libp2p modules that use re-exports
  libp2p/[switch, multistream, connection,
          base58, multiaddress, peerinfo, peer,
          crypto/crypto, protocols/identify, protocols/protocol],
  libp2p/muxers/mplex/[mplex, types],
  libp2p/protocols/secure/[secure, secio],
  libp2p/protocols/pubsub/[pubsub, floodsub],
  libp2p/transports/[transport, tcptransport],
  libp2p_json_serialization, ssz

export
  p2pProtocol, libp2p_json_serialization, ssz

type
  # TODO Is this really needed?
  Eth2Node* = ref object of RootObj
    switch*: Switch
    peers*: Table[PeerID, Peer]
    protocolStates*: seq[RootRef]
    libp2pTransportLoops*: seq[Future[void]]

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

  Peer* = ref object
    network*: Eth2Node
    info*: PeerInfo
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
    stream*: Connection

  Responder*[MsgType] = distinct UntypedResponder

  MessageInfo* = object
    name*: string

    # Private fields:
    libp2pCodecName: string
    protocolMounter*: MounterProc
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

  PeerStateInitializer* = proc(peer: Peer): RootRef {.gcsafe.}
  NetworkStateInitializer* = proc(network: EthereumNode): RootRef {.gcsafe.}
  HandshakeStep* = proc(peer: Peer, stream: Connection): Future[void] {.gcsafe.}
  DisconnectionHandler* = proc(peer: Peer): Future[void] {.gcsafe.}
  ThunkProc* = LPProtoHandler
  MounterProc* = proc(network: Eth2Node) {.gcsafe.}
  MessageContentPrinter* = proc(msg: pointer): string {.gcsafe.}
  NextMsgResolver* = proc(msgData: SszReader, future: FutureBase) {.gcsafe.}

  Bytes = seq[byte]

  PeerDisconnected* = object of CatchableError
    reason*: DisconnectionReason

  TransmissionError* = object of CatchableError

template `$`*(peer: Peer): string = id(peer.info)
chronicles.formatIt(Peer): $it

include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing
include libp2p_backends_common

proc init*(T: type Peer, network: Eth2Node, info: PeerInfo): Peer {.gcsafe.}

proc peer(stream: Connection): PeerID =
  # TODO: Can this be `none`?
  stream.peerInfo.get.peerId

proc getPeer*(node: Eth2Node, peerInfo: PeerInfo): Peer {.gcsafe.} =
  let peerId = peerInfo.peerId
  result = node.peers.getOrDefault(peerId)
  if result == nil:
    result = Peer.init(node, peerInfo)
    node.peers[peerId] = result

proc peerFromStream(network: Eth2Node, connection: Connection): Peer {.gcsafe.} =
  # TODO: Can this be `none`?
  return network.getPeer(connection.peerInfo.get)

proc safeClose(connection: Connection) {.async.} =
  if not connection.closed:
    await close(connection)

proc disconnect*(peer: Peer, reason: DisconnectionReason, notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    await peer.network.switch.disconnect(peer.info)
    peer.connectionState = Disconnected
    peer.network.peers.del(peer.info.peerId)

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
  debug errMsg
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

proc init*(T: type Eth2Node, switch: Switch): T =
  new result
  result.switch = switch
  result.peers = initTable[PeerID, Peer]()

  newSeq result.protocolStates, allProtocols.len
  for proto in allProtocols:
    if proto.networkStateInitializer != nil:
      result.protocolStates[proto.index] = proto.networkStateInitializer(result)

    for msg in proto.messages:
      if msg.protocolMounter != nil:
        msg.protocolMounter result

proc start*(node: Eth2Node) {.async.} =
  node.libp2pTransportLoops = await node.switch.start()

proc readChunk(stream: Connection,
               MsgType: type,
               withResponseCode: bool,
               deadline: Future[void]): Future[Option[MsgType]] {.gcsafe.}

proc readSizePrefix(stream: Connection,
                    deadline: Future[void]): Future[int] {.async.} =
  var parser: VarintParser[uint64, ProtoBuf]
  while true:
    var nextByte: byte
    var readNextByte = stream.readExactly(addr nextByte, 1)
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

proc readMsgBytes(stream: Connection,
                  withResponseCode: bool,
                  deadline: Future[void]): Future[Bytes] {.async.} =
  try:
    if withResponseCode:
      var responseCode: byte
      var readResponseCode = stream.readExactly(addr responseCode, 1)
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

    var sizePrefix = await readSizePrefix(stream, deadline)
    if sizePrefix == -1:
      debug "Failed to read an incoming message size prefix", peer = stream.peer
      return

    if sizePrefix == 0:
      debug "Received SSZ with zero size", peer = stream.peer
      return

    var msgBytes = newSeq[byte](sizePrefix)
    var readBody = stream.readExactly(addr msgBytes[0], sizePrefix)
    await readBody or deadline
    if not readBody.finished: return

    return msgBytes
  except TransportIncompleteError:
    return @[]

proc readChunk(stream: Connection,
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
       stream: Connection,
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

template writeAllBytes(stream: Connection, bytes: seq[byte]): untyped =
  # TODO: This exists only as a compatibility layer between the daemon
  # APIs and the native LibP2P ones. It won't be necessary once the
  # daemon is removed.
  stream.write(bytes)

proc sendErrorResponse(peer: Peer,
                       stream: Connection,
                       err: ref SerializationError,
                       msgName: string,
                       msgBytes: Bytes) {.async.} =
  debug "Received an invalid request",
        peer, msgName, msgBytes, errMsg = err.formatMsg("<msg>")

  let responseBytes = encodeErrorMsg(InvalidRequest, err.formatMsg("msg"))
  await stream.writeAllBytes(responseBytes)
  await stream.close()

proc sendErrorResponse(peer: Peer,
                       stream: Connection,
                       responseCode: ResponseCode,
                       errMsg: string) {.async.} =
  debug "Error processing request", peer, responseCode, errMsg

  let responseBytes = encodeErrorMsg(ServerError, errMsg)
  await stream.writeAllBytes(responseBytes)
  await stream.close()

proc sendNotificationMsg(peer: Peer, protocolId: string, requestBytes: Bytes) {.async} =
  var deadline = sleepAsync RESP_TIMEOUT
  var streamFut = peer.network.switch.dial(peer.info, protocolId)
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
  var streamFut = peer.network.switch.dial(peer.info, protocolId)
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

proc p2pStreamName(MsgType: type): string =
  mixin msgProtocol, protocolInfo, msgId
  MsgType.msgProtocol.protocolInfo.messages[MsgType.msgId].libp2pCodecName

proc init*(T: type Peer, network: Eth2Node, info: PeerInfo): Peer =
  new result
  result.info = info
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
                 mounter: MounterProc,
                 libp2pCodecName: string,
                 printer: MessageContentPrinter) =
  protocol.messages.add MessageInfo(name: name,
                                    protocolMounter: mounter,
                                    libp2pCodecName: libp2pCodecName,
                                    printer: printer)

proc init*[MsgType](T: type Responder[MsgType],
                    peer: Peer, stream: Connection): T =
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

proc handleIncomingStream(network: Eth2Node, stream: Connection,
                          MsgType, Format: distinct type) {.async, gcsafe.} =
  mixin callUserHandler
  const msgName = typetraits.name(MsgType)

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

proc p2pProtocolBackendImpl*(p: P2PProtocol): Backend =
  var
    Format = ident "SSZ"
    Responder = bindSym "Responder"
    Connection = bindSym "Connection"
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
    networkVar = ident "network"
    await = ident "await"
    callUserHandler = ident "callUserHandler"

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
    p.onPeerConnected.params.add newIdentDefs(streamVar, Connection)

  result.implementMsg = proc (msg: Message) =
    let
      protocol = msg.protocol
      msgName = $msg.ident
      msgNameLit = newLit msgName
      MsgRecName = msg.recName
      codecNameLit = getRequestProtoName(msg.procDef)

    if msg.procDef.body.kind != nnkEmpty and msg.kind == msgRequest:
      # Request procs need an extra param - the stream where the response
      # should be written:
      msg.userHandler.params.insert(2, newIdentDefs(streamVar, Connection))
      msg.initResponderCall.add streamVar

    ##
    ## Implement the Thunk:
    ##
    ## The protocol handlers in nim-libp2p receive only a `Connection`
    ## parameter and there is no way to access the wider context (such
    ## as the current `Switch`). In our handlers, we may need to list all
    ## peers in the current network, so we must keep a reference to the
    ## network object in the closure environment of the installed handlers.
    ##
    ## For this reason, we define a `protocol mounter` proc that will
    ## initialize the network object by creating handlers bound to the
    ## specific network.
    ##
    let
      protocolMounterName = ident(msgName & "_mounter")
      userHandlerCall = msg.genUserHandlerCall(msgVar, [peerVar, streamVar])

    let tracing = when tracingEnabled:
      quote: logReceivedMsg(`streamVar`.peer, `msgVar`.get)
    else:
      newStmtList()

    var mounter: NimNode
    if msg.userHandler != nil:
      protocol.outRecvProcs.add quote do:
        template `callUserHandler`(`peerVar`: `Peer`,
                                   `streamVar`: `Connection`,
                                   `msgVar`: `MsgRecName`): untyped =
          `userHandlerCall`

        proc `protocolMounterName`(`networkVar`: `Eth2Node`) =
          proc thunk(`streamVar`: `Connection`,
                      proto: string): Future[void] {.gcsafe.} =
            return handleIncomingStream(`networkVar`, `streamVar`,
                                        `MsgRecName`, `Format`)

          mount `networkVar`.switch,
                LPProtocol(codec: `codecNameLit`, handler: thunk)

      mounter = protocolMounterName
    else:
      mounter = newNilLit()

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
              mounter,
              codecNameLit,
              newTree(nnkBracketExpr, messagePrinter, MsgRecName)))

  result.implementProtocolInit = proc (p: P2PProtocol): NimNode =
    return newCall(initProtocol, newLit(p.name), p.peerInit, p.netInit)

