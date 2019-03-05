import
  options, macros, algorithm,
  std_shims/[macros_shim, tables_shims], chronos, chronicles,
  libp2p/daemon/daemonapi, faststreams/output_stream, serialization,
  ssz

export
  daemonapi

type
  Eth2Node* = ref object of RootObj
    daemon*: DaemonAPI
    peers*: Table[PeerID, Peer]
    protocolStates*: seq[RootRef]

  Peer* = ref object
    network: Eth2Node
    id: PeerID
    connectionState: ConnectionState
    awaitedMessages: Table[CompressedMsgId, FutureBase]
    protocolStates*: seq[RootRef]

  EthereumNode = Eth2Node # This alias is needed for state_helpers below

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

  MessageInfo* = object
    name*: string

    # Private fields:
    thunk*: MessageHandler
    libp2pProtocol: string
    printer*: MessageContentPrinter
    nextMsgResolver*: NextMsgResolver

  CompressedMsgId = tuple
    protocolIndex, msgId: int

  MessageKind* = enum
    msgNotification,
    msgRequest,
    msgResponse

  PeerStateInitializer* = proc(peer: Peer): RootRef {.gcsafe.}
  NetworkStateInitializer* = proc(network: EthereumNode): RootRef {.gcsafe.}
  HandshakeStep* = proc(peer: Peer, handshakeStream: P2PStream): Future[void] {.gcsafe.}
  DisconnectionHandler* = proc(peer: Peer): Future[void] {.gcsafe.}
  MessageHandler* = proc(daemon: DaemonAPI, stream: P2PStream): Future[void] {.gcsafe.}
  MessageContentPrinter* = proc(msg: pointer): string {.gcsafe.}
  NextMsgResolver* = proc(msgData: SszReader, future: FutureBase) {.gcsafe.}

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  UntypedResponse = object
    peer*: Peer
    stream*: P2PStream

  Response*[MsgType] = distinct UntypedResponse

  Bytes = seq[byte]

  DisconnectionReason* = enum
    BreachOfProtocol

  PeerDisconnected* = object of CatchableError
    reason*: DisconnectionReason

const
  defaultIncomingReqTimeout = 5000
  defaultOutgoingReqTimeout = 10000

var
  gProtocols: seq[ProtocolInfo]

# The variables above are immutable RTTI information. We need to tell
# Nim to not consider them GcSafe violations:
template allProtocols: auto = {.gcsafe.}: gProtocols

proc disconnect*(peer: Peer) {.async.} =
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
  await peer.disconnect()
  raisePeerDisconnected(msg, reason)

proc init*(node: Eth2Node) {.async.} =
  node.daemon = await newDaemonApi({PSGossipSub})
  node.daemon.userData = node
  init node.peers

  newSeq node.protocolStates, allProtocols.len
  for proto in allProtocols:
    if proto.networkStateInitializer != nil:
      node.protocolStates[proto.index] = proto.networkStateInitializer(node)

    for msg in proto.messages:
      if msg.libp2pProtocol.len > 0:
        await node.daemon.addHandler(@[msg.libp2pProtocol], msg.thunk)

include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing

import typetraits

proc readMsg(stream: P2PStream, MsgType: type,
             timeout = 10000): Future[Option[MsgType]] {.async.} =
  var timeout = sleepAsync timeout
  var sizePrefix: uint32
  var readSizePrefix = stream.transp.readExactly(addr sizePrefix, sizeof(sizePrefix))
  await readSizePrefix or timeout
  if not readSizePrefix.finished: return

  debug "EXPECTING MSG", msg = MsgType.name, size = sizePrefix.int

  var msgBytes = newSeq[byte](sizePrefix.int + sizeof(sizePrefix))
  copyMem(addr msgBytes[0], addr sizePrefix, sizeof(sizePrefix))
  var readBody = stream.transp.readExactly(addr msgBytes[sizeof(sizePrefix)], sizePrefix.int)
  await readBody or timeout
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
                     timeout = 10000): Future[Option[ResponseMsg]] {.async.} =
  var stream = await peer.network.daemon.openStream(peer.id, @[protocolId])
  # TODO how does openStream fail? Set a timeout here and handle it
  let sent = await stream.transp.write(requestBytes)
  # TODO: Should I check that `sent` is equal to the desired number of bytes
  return await stream.readMsg(ResponseMsg, timeout)

proc handshakeImpl(peer: Peer,
                   handshakeSendFut: Future[void],
                   handshakeStream: P2PStream,
                   timeout: int,
                   HandshakeType: type): Future[HandshakeType] {.async.} =
  await handshakeSendFut
  let response = await handshakeStream.readMsg(HandshakeType, timeout)
  if response.isSome:
    return response.get
  else:
    await peer.disconnectAndRaise(BreachOfProtocol, "Handshake not completed in time")

proc p2pStreamName(MsgType: type): string =
  mixin msgProtocol, protocolInfo, msgId
  MsgType.msgProtocol.protocolInfo.messages[MsgType.msgId].libp2pProtocol

macro handshake*(peer: Peer, timeout = 10000, sendCall: untyped): untyped =
  let
    msgName = $sendCall[0]
    msgType = newDotExpr(ident"CurrentProtocol", ident(msgName))
    handshakeStream = ident "handshakeStream"
    handshakeImpl = bindSym "handshakeImpl"
    await = ident "await"

  sendCall.insert(1, handshakeStream)

  result = quote do:
    proc payload(peer: Peer, `handshakeStream`: P2PStream): Future[`msgType`] {.async.} =
      var `handshakeStream` = `handshakeStream`
      if `handshakeStream` == nil:
        `handshakeStream` = `await` openStream(peer.network.daemon,
                                               peer.id,
                                               @[p2pStreamName(`msgType`)],
                                               `timeout`)
      return `await` `handshakeImpl`(peer, `sendCall`, `handshakeStream`, `timeout`, `msgType`)

    payload(`peer`, `handshakeStream`)

proc getCompressedMsgId(MsgType: type): CompressedMsgId =
  mixin msgProtocol, protocolInfo, msgId
  (protocolIndex: MsgType.msgProtocol.protocolInfo.index, msgId: MsgType.msgId)

proc nextMsg*(peer: Peer, MsgType: type): Future[MsgType] =
  ## This procs awaits a specific P2P message.
  ## Any messages received while waiting will be dispatched to their
  ## respective handlers. The designated message handler will also run
  ## to completion before the future returned by `nextMsg` is resolved.
  mixin msgProtocol, protocolInfo, msgId
  let awaitedMsgId = getCompressedMsgId(MsgType)
  let f = getOrDefault(peer.awaitedMessages, awaitedMsgId)
  if not f.isNil:
    return Future[MsgType](f)

  newFuture result
  peer.awaitedMessages[awaitedMsgId] = result

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

proc getPeer*(node: Eth2Node, peerId: PeerID): Peer =
  result = node.peers.getOrDefault(peerId)
  if result == nil:
    result = Peer.init(node, peerId)
    node.peers[peerId] = result

proc peerFromStream(daemon: DaemonAPI, stream: P2PStream): Peer =
  Eth2Node(daemon.userData).getPeer(stream.peer)

template getRecipient(peer: Peer): Peer =
  peer

# TODO: this should be removed eventually
template getRecipient(stream: P2PStream): P2PStream =
  stream

template getRecipient(response: Response): Peer =
  UntypedResponse(response).peer

proc messagePrinter[MsgType](msg: pointer): string {.gcsafe.} =
  result = ""
  # TODO: uncommenting the line below increases the compile-time
  # tremendously (for reasons not yet known)
  # result = $(cast[ptr MsgType](msg)[])

proc initProtocol(name: string,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer): ProtocolInfoObj =
  result.name = name
  result.messages = @[]
  result.peerStateInitializer = peerInit
  result.networkStateInitializer = networkInit

proc setEventHandlers(p: ProtocolInfo,
                      handshake: HandshakeStep,
                      disconnectHandler: DisconnectionHandler) =
  p.handshake = handshake
  p.disconnectHandler = disconnectHandler

proc registerMsg(protocol: ProtocolInfo,
                 name: string,
                 thunk: MessageHandler,
                 libp2pProtocol: string,
                 printer: MessageContentPrinter) =
  protocol.messages.add MessageInfo(name: name,
                                    thunk: thunk,
                                    libp2pProtocol: libp2pProtocol,
                                    printer: printer)

proc registerProtocol(protocol: ProtocolInfo) =
  # TODO: This can be done at compile-time in the future
  let pos = lowerBound(gProtocols, protocol)
  gProtocols.insert(protocol, pos)
  for i in 0 ..< gProtocols.len:
    gProtocols[i].index = i

template libp2pProtocol*(name, version: string) {.pragma.}

proc getRequestProtoName(fn: NimNode): NimNode =
  # `getCustomPragmaVal` doesn't work yet on regular nnkProcDef nodes
  # (TODO: file as an issue)

  let pragmas = fn.pragma
  if pragmas.kind == nnkPragma and pragmas.len > 0:
    for pragma in pragmas:
      if pragma.len > 0 and $pragma[0] == "libp2pProtocol":
        return pragma[1]

  error "All stream opening procs must have the 'libp2pProtocol' pragma specified.", fn

macro p2pProtocolImpl(name: static[string],
                      version: static[uint],
                      body: untyped,
                      timeout: static[int] = defaultOutgoingReqTimeout,
                      shortName: static[string] = "",
                      peerState = type(nil),
                      networkState = type(nil)): untyped =
  ## The macro used to defined P2P sub-protocols. See README.
  var
    # XXX: deal with a Nim bug causing the macro params to be
    # zero when they are captured by a closure:
    defaultTimeout = timeout
    protoName = name
    nextId = -1
    protoNameIdent = ident(protoName)
    outTypes = newNimNode(nnkStmtList)
    outSendProcs = newNimNode(nnkStmtList)
    outRecvProcs = newNimNode(nnkStmtList)
    outProcRegistrations = newNimNode(nnkStmtList)
    response = ident"response"
    name_openStream = newTree(nnkPostfix, ident("*"), ident"openStream")
    outputStream = ident"outputStream"
    currentProtocolSym = ident"CurrentProtocol"
    protocol = ident(protoName & "Protocol")
    peerState = verifyStateType peerState.getType
    networkState = verifyStateType networkState.getType
    handshake = newNilLit()
    disconnectHandler = newNilLit()
    Format = ident"SSZ"
    Option = bindSym "Option"
    UntypedResponse = bindSym "UntypedResponse"
    Response = bindSym "Response"
    DaemonAPI = bindSym "DaemonAPI"
    P2PStream = ident "P2PStream"
    # XXX: Binding the int type causes instantiation failure for some reason
    # Int = bindSym "int"
    Int = ident "int"
    Void = ident "void"
    Peer = bindSym "Peer"
    writeField = bindSym "writeField"
    createNetworkState = bindSym "createNetworkState"
    createPeerState = bindSym "createPeerState"
    getOutput = bindSym "getOutput"
    messagePrinter = bindSym "messagePrinter"
    initProtocol = bindSym "initProtocol"
    getRecipient = bindSym "getRecipient"
    peerFromStream = bindSym "peerFromStream"
    makeEth2Request = bindSym "makeEth2Request"
    sendMsg = bindSym "sendMsg"
    sendBytes = bindSym "sendBytes"
    getState = bindSym "getState"
    getNetworkState = bindSym "getNetworkState"
    resolveNextMsgFutures = bindSym "resolveNextMsgFutures"

  proc augmentUserHandler(userHandlerProc: NimNode,
                          msgKind = msgNotification,
                          extraDefinitions: NimNode = nil) =
    ## Turns a regular proc definition into an async proc and adds
    ## the helpers for accessing the peer and network protocol states.

    userHandlerProc.addPragma ident"gcsafe"
    userHandlerProc.addPragma ident"async"

    # We allow the user handler to use `openarray` params, but we turn
    # those into sequences to make the `async` pragma happy.
    for i in 1 ..< userHandlerProc.params.len:
      var param = userHandlerProc.params[i]
      param[^2] = chooseFieldType(param[^2])

    var userHandlerDefinitions = newStmtList()

    userHandlerDefinitions.add quote do:
      type `currentProtocolSym` = `protoNameIdent`

    if extraDefinitions != nil:
      userHandlerDefinitions.add extraDefinitions

    # Define local accessors for the peer and the network protocol states
    # inside each user message handler proc (e.g. peer.state.foo = bar)
    if peerState != nil:
      userHandlerDefinitions.add quote do:
        template state(p: `Peer`): `peerState` =
          cast[`peerState`](`getState`(p, `protocol`))

    if networkState != nil:
      userHandlerDefinitions.add quote do:
        template networkState(p: `Peer`): `networkState` =
          cast[`networkState`](`getNetworkState`(p.network, `protocol`))

    userHandlerProc.body.insert 0, userHandlerDefinitions

  proc liftEventHandler(doBlock: NimNode, handlerName: string): NimNode =
    ## Turns a "named" do block to a regular async proc
    ## (e.g. onPeerConnected do ...)
    result = newTree(nnkProcDef)
    doBlock.copyChildrenTo(result)
    result.name = genSym(nskProc, protoName & handlerName)
    augmentUserHandler result
    outRecvProcs.add result

  proc addMsgHandler(n: NimNode, msgKind = msgNotification,
                     responseRecord: NimNode = nil): NimNode =
    if n[0].kind == nnkPostfix:
      macros.error("p2pProcotol procs are public by default. " &
                   "Please remove the postfix `*`.", n)

    inc nextId

    let
      msgIdent = n.name
      msgName = $n.name

    var
      userPragmas = n.pragma

      # variables used in the sending procs
      msgRecipient = ident"msgRecipient"
      sendTo = ident"sendTo"
      writer = ident"writer"
      recordStartMemo = ident"recordStartMemo"
      reqTimeout: NimNode
      appendParams = newNimNode(nnkStmtList)
      paramsToWrite = newSeq[NimNode](0)
      msgId = newLit(nextId)

      # variables used in the receiving procs
      receivedMsg = ident"msg"
      daemon = ident "daemon"
      stream = ident "stream"
      await = ident "await"
      peerIdent = ident "peer"
      tracing = newNimNode(nnkStmtList)

      # nodes to store the user-supplied message handling proc if present
      userHandlerProc: NimNode = nil
      userHandlerCall: NimNode = nil
      awaitUserHandler = newStmtList()

      # a record type associated with the message
      msgRecord = newIdentNode(msgName & "Obj")
      msgRecordFields = newTree(nnkRecList)
      msgRecordBody = newTree(nnkObjectTy,
                              newEmptyNode(),
                              newEmptyNode(),
                              msgRecordFields)

    result = msgRecord

    if msgKind == msgRequest:
      # If the request proc has a default timeout specified, remove it from
      # the signature for now so we can generate the `thunk` proc without it.
      # The parameter will be added back later only for to the sender proc.
      # When the timeout is not specified, we use a default one.
      reqTimeout = popTimeoutParam(n)
      if reqTimeout == nil:
        reqTimeout = newTree(nnkIdentDefs,
                             ident"timeout",
                             Int, newLit(defaultTimeout))

    if n.body.kind != nnkEmpty:
      # Implement the receiving thunk proc that deserialzed the
      # message parameters and calls the user proc:
      userHandlerProc = n.copyNimTree
      userHandlerProc.name = genSym(nskProc, msgName)

      # This is the call to the user supplied handler.
      # Here we add only the initial params, the rest will be added later.
      userHandlerCall = newCall(userHandlerProc.name)
      # When there is a user handler, it must be awaited in the thunk proc.
      # Above, by default `awaitUserHandler` is set to a no-op statement list.
      awaitUserHandler = newCall(await, userHandlerCall)

      var extraDefs: NimNode
      if msgKind == msgRequest:
        # Request procs need an extra param - the stream where the response
        # should be written:
        userHandlerProc.params.insert(1, newIdentDefs(stream, P2PStream))
        userHandlerCall.add stream
        let peer = userHandlerProc.params[2][0]
        extraDefs = quote do:
          # Jump through some hoops to work aroung
          # https://github.com/nim-lang/Nim/issues/6248
          let `response` = `Response`[`responseRecord`](
            `UntypedResponse`(peer: `peer`, stream: `stream`))

      # Resolve the Eth2Peer from the LibP2P data received in the thunk
      userHandlerCall.add peerIdent

      augmentUserHandler userHandlerProc, msgKind, extraDefs
      outRecvProcs.add userHandlerProc

    elif msgName == "status":
      awaitUserHandler = quote do:
        `await` `handshake`(`peerIdent`, `stream`)

    for param, paramType in n.typedParams(skip = 1):
      paramsToWrite.add param

      # Each message has a corresponding record type.
      # Here, we create its fields one by one:
      msgRecordFields.add newTree(nnkIdentDefs,
        newTree(nnkPostfix, ident("*"), param), # The fields are public
        chooseFieldType(paramType),             # some types such as openarray
                                                # are automatically remapped
        newEmptyNode())

      # If there is user message handler, we'll place a call to it by
      # unpacking the fields of the received message:
      if userHandlerCall != nil:
        userHandlerCall.add quote do: get(`receivedMsg`).`param` # newDotExpr(newCall("get", receivedMsg), param)

    when tracingEnabled:
      tracing = quote do:
        logReceivedMsg(`stream`.peer, `receivedMsg`.get)

    let requestDataTimeout = newLit(defaultIncomingReqTimeout)

    let thunkName = ident(msgName & "_thunk")
    var thunkProc = quote do:
      proc `thunkName`(`daemon`: `DaemonAPI`, `stream`: `P2PStream`) {.async, gcsafe.} =
        var `receivedMsg` = `await` readMsg(`stream`, `msgRecord`, `requestDataTimeout`)
        if `receivedMsg`.isNone:
          # TODO: This peer is misbehaving, perhaps we should penalize him somehow
          return
        let `peerIdent` = `peerFromStream`(`daemon`, `stream`)
        `tracing`
        `awaitUserHandler`
        `resolveNextMsgFutures`(`peerIdent`, get(`receivedMsg`))

    for p in userPragmas:
      thunkProc.addPragma p

    outRecvProcs.add thunkProc

    outTypes.add quote do:
      # This is a type featuring a single field for each message param:
      type `msgRecord`* = `msgRecordBody`

      # Add a helper template for accessing the message type:
      # e.g. p2p.hello:
      template `msgIdent`*(T: type `protoNameIdent`): type = `msgRecord`
      template msgId*(T: type `msgRecord`): int = `msgId`
      template msgProtocol*(T: type `msgRecord`): type = `protoNameIdent`

    var msgSendProc = n
    let msgSendProcName = n.name
    outSendProcs.add msgSendProc

    # TODO: check that the first param has the correct type
    msgSendProc.params[1][0] = sendTo
    if nextId == 0: msgSendProc.params[1][1] = P2PStream
    msgSendProc.addPragma ident"gcsafe"

    # Add a timeout parameter for all request procs
    case msgKind
    of msgRequest:
      msgSendProc.params.add reqTimeout
    of msgResponse:
      # A response proc must be called with a response object that originates
      # from a certain request. Here we change the Peer parameter at position
      # 1 to the correct strongly-typed ResponseType. The incoming procs still
      # gets the normal Peer paramter.
      let ResponseType = newTree(nnkBracketExpr, Response, msgRecord)
      msgSendProc.params[1][1] = ResponseType
      outSendProcs.add quote do:
        template send*(r: `ResponseType`, args: varargs[untyped]): auto =
          `msgSendProcName`(r, args)
    else: discard

    # We change the return type of the sending proc to a Future.
    # If this is a request proc, the future will return the response record.
    let rt = case msgKind
             of msgRequest: newTree(nnkBracketExpr, Option, responseRecord)
             of msgResponse, msgNotification: Void
    msgSendProc.params[0] = newTree(nnkBracketExpr, ident("Future"), rt)

    let msgBytes = ident"msgBytes"

    # Make the send proc public
    msgSendProc.name = newTree(nnkPostfix, ident("*"), msgSendProc.name)

    let initWriter = quote do:
      var `outputStream` = init OutputStream
      var `writer` = init(WriterType(`Format`), `outputStream`)
      var `recordStartMemo` = beginRecord(`writer`, `msgRecord`)

    for param in paramsToWrite:
      appendParams.add newCall(writeField, writer, newLit($param), param)

    when tracingEnabled:
      appendParams.add logSentMsgFields(msgRecipient, protocol, msgName, paramsToWrite)

    let finalizeRequest = quote do:
      endRecord(`writer`, `recordStartMemo`)
      let `msgBytes` = `getOutput`(`outputStream`)

    var msgProto = newLit("")
    let sendCall =
      if msgKind != msgResponse:
        msgProto = getRequestProtoName(n)

        when false:
          var openStreamProc = n.copyNimTree
          var openStreamProc.name = name_openStream
          openStreamProc.params.insert 1, newIdentDefs(ident"T", msgRecord)

        if msgKind == msgRequest:
          let timeout = reqTimeout[0]
          quote: `makeEth2Request`(`msgRecipient`, `msgProto`, `msgBytes`,
                                   `responseRecord`, `timeout`)
        elif nextId == 0:
          quote: `sendBytes`(`sendTo`, `msgBytes`)
        else:
          quote: `sendMsg`(`msgRecipient`, `msgProto`, `msgBytes`)
      else:
        quote: `sendBytes`(`UntypedResponse`(`sendTo`).stream, `msgBytes`)

    msgSendProc.body = quote do:
      let `msgRecipient` = `getRecipient`(`sendTo`)
      `initWriter`
      `appendParams`
      `finalizeRequest`
      return `sendCall`

    outProcRegistrations.add(
      newCall(bindSym("registerMsg"),
              protocol,
              newLit(msgName),
              thunkName,
              msgProto,
              newTree(nnkBracketExpr, messagePrinter, msgRecord)))

  outTypes.add quote do:
    # Create a type acting as a pseudo-object representing the protocol
    # (e.g. p2p)
    type `protoNameIdent`* = object

  if peerState != nil:
    outTypes.add quote do:
      template State*(P: type `protoNameIdent`): type = `peerState`

  if networkState != nil:
    outTypes.add quote do:
      template NetworkState*(P: type `protoNameIdent`): type = `networkState`

  for n in body:
    case n.kind
    of {nnkCall, nnkCommand}:
      if eqIdent(n[0], "nextID"):
        discard
      elif eqIdent(n[0], "requestResponse"):
        # `requestResponse` can be given a block of 2 or more procs.
        # The last one is considered to be a response message, while
        # all preceeding ones are requests triggering the response.
        # The system makes sure to automatically insert a hidden `reqId`
        # parameter used to discriminate the individual messages.
        block processReqResp:
          if n.len == 2 and n[1].kind == nnkStmtList:
            var procs = newSeq[NimNode](0)
            for def in n[1]:
              if def.kind == nnkProcDef:
                procs.add(def)
            if procs.len > 1:
              let responseRecord = addMsgHandler(procs[^1],
                                                 msgKind = msgResponse)
              for i in 0 .. procs.len - 2:
                discard addMsgHandler(procs[i],
                                      msgKind = msgRequest,
                                      responseRecord = responseRecord)

              # we got all the way to here, so everything is fine.
              # break the block so it doesn't reach the error call below
              break processReqResp
          macros.error("requestResponse expects a block with at least two proc definitions")
      elif eqIdent(n[0], "onPeerConnected"):
        var handshakeProc = liftEventHandler(n[1], "Handshake")
        handshakeProc.params.add newIdentDefs(ident"handshakeStream", P2PStream)
        handshake = handshakeProc.name
      elif eqIdent(n[0], "onPeerDisconnected"):
        disconnectHandler = liftEventHandler(n[1], "PeerDisconnect").name
      else:
        macros.error(repr(n) & " is not a recognized call in P2P protocol definitions", n)
    of nnkProcDef:
      discard addMsgHandler(n)

    of nnkCommentStmt:
      discard

    else:
      macros.error("illegal syntax in a P2P protocol definition", n)

  let peerInit = if peerState == nil: newNilLit()
                 else: newTree(nnkBracketExpr, createPeerState, peerState)

  let netInit  = if networkState == nil: newNilLit()
                 else: newTree(nnkBracketExpr, createNetworkState, networkState)

  result = newNimNode(nnkStmtList)
  result.add outTypes
  result.add quote do:
    # One global variable per protocol holds the protocol run-time data
    var p = `initProtocol`(`protoName`, `peerInit`, `netInit`)
    var `protocol` = addr p

    # The protocol run-time data is available as a pseudo-field
    # (e.g. `p2p.protocolInfo`)
    template protocolInfo*(P: type `protoNameIdent`): ProtocolInfo = `protocol`

  result.add outSendProcs, outRecvProcs, outProcRegistrations
  result.add quote do:
    setEventHandlers(`protocol`, `handshake`, `disconnectHandler`)

  result.add newCall(bindSym("registerProtocol"), protocol)

  when defined(debugP2pProtocol) or defined(debugMacros):
    echo repr(result)

macro p2pProtocol*(protocolOptions: untyped, body: untyped): untyped =
  let protoName = $(protocolOptions[0])
  result = protocolOptions
  result[0] = bindSym"p2pProtocolImpl"
  result.add(newTree(nnkExprEqExpr,
                     ident("name"),
                     newLit(protoName)))
  result.add(newTree(nnkExprEqExpr,
                     ident("body"),
                     body))

proc makeMessageHandler[MsgType](msgHandler: proc(msg: MsgType)): P2PPubSubCallback =
  result = proc(api: DaemonAPI, ticket: PubsubTicket, msg: PubSubMessage): Future[bool] {.async.} =
    msgHandler SSZ.decode(msg.data, MsgType)
    return true

proc subscribe*[MsgType](node: EthereumNode,
                         topic: string,
                         msgHandler: proc(msg: MsgType)) {.async.} =
  discard await node.daemon.pubsubSubscribe(topic, makeMessageHandler(msgHandler))

proc broadcast*(node: Eth2Node, topic: string, msg: auto) {.async.} =
  await node.daemon.pubsubPublish(topic, SSZ.encode(msg))

