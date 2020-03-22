import
  # Std lib
  typetraits, strutils, os, random, algorithm,
  options as stdOptions, net as stdNet,

  # Status libs
  stew/[io, varints, base58], stew/shims/[macros, tables], stint,
  faststreams/output_stream,
  json_serialization, json_serialization/std/[net, options],
  chronos, chronicles, metrics,
  # TODO: create simpler to use libp2p modules that use re-exports
  libp2p/[switch, standard_setup, peerinfo, peer, connection,
          multiaddress, multicodec, crypto/crypto,
          protocols/identify, protocols/protocol],
  libp2p/protocols/secure/[secure, secio],
  libp2p/protocols/pubsub/[pubsub, floodsub],
  libp2p/transports/[transport, tcptransport],
  eth/[keys, async_utils], eth/p2p/[enode, p2p_protocol_dsl],
  eth/net/nat, eth/p2p/discoveryv5/[enr, node],

  # Beacon node modules
  version, conf, eth2_discovery, libp2p_json_serialization, conf, ssz,
  peer_pool

import
  eth/p2p/discoveryv5/protocol as discv5_protocol

export
  version, multiaddress, peer_pool, peerinfo, p2pProtocol,
  libp2p_json_serialization, ssz

logScope:
  topics = "networking"

type
  KeyPair* = crypto.KeyPair
  PublicKey* = crypto.PublicKey
  PrivateKey* = crypto.PrivateKey

  Bytes = seq[byte]
  P2PStream = Connection

  # TODO Is this really needed?
  Eth2Node* = ref object of RootObj
    switch*: Switch
    discovery*: Eth2DiscoveryProtocol
    wantedPeers*: int
    peerPool*: PeerPool[Peer, PeerID]
    protocolStates*: seq[RootRef]
    libp2pTransportLoops*: seq[Future[void]]

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

  Peer* = ref object
    network*: Eth2Node
    info*: PeerInfo
    wasDialed*: bool
    discoveryId*: Eth2DiscoveryId
    connectionState*: ConnectionState
    protocolStates*: seq[RootRef]
    maxInactivityAllowed*: Duration
    score*: int

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  UntypedResponder = object
    peer*: Peer
    stream*: P2PStream

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

  ResponseCode* = enum
    Success
    InvalidRequest
    ServerError

  PeerStateInitializer* = proc(peer: Peer): RootRef {.gcsafe.}
  NetworkStateInitializer* = proc(network: EthereumNode): RootRef {.gcsafe.}
  HandshakeStep* = proc(peer: Peer, stream: P2PStream): Future[void] {.gcsafe.}
  DisconnectionHandler* = proc(peer: Peer): Future[void] {.gcsafe.}
  ThunkProc* = LPProtoHandler
  MounterProc* = proc(network: Eth2Node) {.gcsafe.}
  MessageContentPrinter* = proc(msg: pointer): string {.gcsafe.}
  NextMsgResolver* = proc(msgData: SszReader, future: FutureBase) {.gcsafe.}

  DisconnectionReason* = enum
    ClientShutDown
    IrrelevantNetwork
    FaultOrError

  PeerDisconnected* = object of CatchableError
    reason*: DisconnectionReason

  TransmissionError* = object of CatchableError

const
  clientId* = "Nimbus beacon node v" & fullVersionStr
  networkKeyFilename = "privkey.protobuf"

  TCP = net.Protocol.IPPROTO_TCP
  HandshakeTimeout = FaultOrError

  # Spec constants
  # https://github.com/ethereum/eth2.0-specs/blob/dev/specs/networking/p2p-interface.md#eth-20-network-interaction-domains
  REQ_RESP_MAX_SIZE* = 1 * 1024 * 1024 # bytes
  GOSSIP_MAX_SIZE* = 1 * 1024 * 1024 # bytes
  TTFB_TIMEOUT* = 5.seconds
  RESP_TIMEOUT* = 10.seconds

  readTimeoutErrorMsg = "Exceeded read timeout for a request"

let
  globalListeningAddr = parseIpAddress("0.0.0.0")

# Metrics for tracking attestation and beacon block loss
declareCounter gossip_messages_sent,
  "Number of gossip messages sent by this peer"

declareCounter gossip_messages_received,
  "Number of gossip messages received by this peer"

declarePublicGauge libp2p_successful_dials,
                   "Number of successfully dialed peers"

declarePublicGauge libp2p_peers,
                   "Number of active libp2p peers"

template libp2pProtocol*(name: string, version: int) {.pragma.}

template `$`*(peer: Peer): string = id(peer.info)
chronicles.formatIt(Peer): $it

template remote*(peer: Peer): untyped =
  peer.info.peerId

# TODO: This exists only as a compatibility layer between the daemon
# APIs and the native LibP2P ones. It won't be necessary once the
# daemon is removed.
#
template writeAllBytes(stream: P2PStream, bytes: seq[byte]): untyped =
  write(stream, bytes)

template openStream(node: Eth2Node, peer: Peer, protocolId: string): untyped =
  dial(node.switch, peer.info, protocolId)

proc peer(stream: P2PStream): PeerID =
  # TODO: Can this be `nil`?
  stream.peerInfo.peerId
#
# End of compatibility layer

proc init*(T: type Peer, network: Eth2Node, info: PeerInfo): Peer {.gcsafe.}

proc getPeer*(node: Eth2Node, peerInfo: PeerInfo): Peer {.gcsafe.} =
  let peerId = peerInfo.peerId
  result = node.peerPool.getOrDefault(peerId)
  if result == nil:
    result = Peer.init(node, peerInfo)

proc peerFromStream(network: Eth2Node, stream: P2PStream): Peer {.gcsafe.} =
  # TODO: Can this be `nil`?
  return network.getPeer(stream.peerInfo)

proc getKey*(peer: Peer): PeerID {.inline.} =
  result = peer.info.peerId

proc getFuture*(peer: Peer): Future[void] {.inline.} =
  result = peer.info.lifeFuture()

proc `<`*(a, b: Peer): bool =
  result = `<`(a.score, b.score)

proc disconnect*(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    await peer.network.switch.disconnect(peer.info)
    peer.connectionState = Disconnected
    peer.network.peerPool.release(peer)
    peer.info.close()

proc safeClose(stream: P2PStream) {.async.} =
  if not stream.closed:
    await close(stream)

proc handleIncomingPeer*(peer: Peer)

include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing

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

    trace "about to read msg bytes", len = sizePrefix
    var msgBytes = newSeq[byte](sizePrefix)
    var readBody = stream.readExactly(addr msgBytes[0], sizePrefix)
    await readBody or deadline
    if not readBody.finished:
      trace "msg bytes not received in time"
      return

    trace "got message bytes", len = sizePrefix
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
  mixin callUserHandler, RecType
  const msgName = typetraits.name(MsgType)

  ## Uncomment this to enable tracing on all incoming requests
  ## You can include `msgNameLit` in the condition to select
  ## more specific requests:
  # when chronicles.runtimeFilteringEnabled:
  #   setLogLevel(LogLevel.TRACE)
  #   defer: setLogLevel(LogLevel.DEBUG)
  #   trace "incoming " & `msgNameLit` & " stream"

  let peer = peerFromStream(network, stream)

  handleIncomingPeer(peer)

  defer:
    await safeClose(stream)

  let
    deadline = sleepAsync RESP_TIMEOUT
    msgBytes = await readMsgBytes(stream, false, deadline)

  if msgBytes.len == 0:
    await sendErrorResponse(peer, stream, ServerError, readTimeoutErrorMsg)
    return

  type MsgRec = RecType(MsgType)
  var msg: MsgRec
  try:
    msg = decode(Format, msgBytes, MsgRec)
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
    logReceivedMsg(peer, MsgType(msg))
    await callUserHandler(peer, stream, msg)
  except CatchableError as err:
    await sendErrorResponse(peer, stream, ServerError, err.msg)

proc handleOutgoingPeer*(peer: Peer): Future[void] {.async.} =
  let network = peer.network

  proc onPeerClosed(udata: pointer) {.gcsafe.} =
    debug "Peer (outgoing) lost", peer = $peer.info
    libp2p_peers.set int64(len(network.peerPool))

  let res = await network.peerPool.addOutgoingPeer(peer)
  if res:
    debug "Peer (outgoing) has been added to PeerPool", peer = $peer.info
    peer.getFuture().addCallback(onPeerClosed)
  libp2p_peers.set int64(len(network.peerPool))

proc handleIncomingPeer*(peer: Peer) =
  let network = peer.network

  proc onPeerClosed(udata: pointer) {.gcsafe.} =
    debug "Peer (incoming) lost", peer = $peer.info
    libp2p_peers.set int64(len(network.peerPool))

  let res = network.peerPool.addIncomingPeerNoWait(peer)
  if res:
    debug "Peer (incoming) has been added to PeerPool", peer = $peer.info
    peer.getFuture().addCallback(onPeerClosed)
  libp2p_peers.set int64(len(network.peerPool))

proc toPeerInfo*(r: enr.TypedRecord): PeerInfo =
  if r.secp256k1.isSome:
    var pubKey: keys.PublicKey
    if recoverPublicKey(r.secp256k1.get, pubKey) != EthKeysStatus.Success:
      return # TODO

    let peerId = PeerID.init crypto.PublicKey(scheme: Secp256k1, skkey: pubKey)
    var addresses = newSeq[MultiAddress]()

    if r.ip.isSome and r.tcp.isSome:
      let ip = IpAddress(family: IpAddressFamily.IPv4,
                         address_v4: r.ip.get)
      addresses.add MultiAddress.init(ip, TCP, Port r.tcp.get)

    if r.ip6.isSome:
      let ip = IpAddress(family: IpAddressFamily.IPv6,
                         address_v6: r.ip6.get)
      if r.tcp6.isSome:
        addresses.add MultiAddress.init(ip, TCP, Port r.tcp6.get)
      elif r.tcp.isSome:
        addresses.add MultiAddress.init(ip, TCP, Port r.tcp.get)
      else:
        discard

    if addresses.len > 0:
      return PeerInfo.init(peerId, addresses)

proc toPeerInfo(r: Option[enr.TypedRecord]): PeerInfo =
  if r.isSome:
    return r.get.toPeerInfo

proc dialPeer*(node: Eth2Node, peerInfo: PeerInfo) {.async.} =
  logScope: peer = $peerInfo

  debug "Connecting to peer"
  await node.switch.connect(peerInfo)
  var peer = node.getPeer(peerInfo)
  peer.wasDialed = true

  debug "Initializing connection"
  await initializeConnection(peer)

  inc libp2p_successful_dials
  debug "Network handshakes completed"

  await handleOutgoingPeer(peer)

proc runDiscoveryLoop*(node: Eth2Node) {.async.} =
  debug "Starting discovery loop"

  while true:
    let currentPeerCount = node.peerPool.len
    if currentPeerCount < node.wantedPeers:
      try:
        let discoveredPeers =
          node.discovery.randomNodes(node.wantedPeers - currentPeerCount)
        debug "Discovered peers", peer = $discoveredPeers
        for peer in discoveredPeers:
          try:
            let peerInfo = peer.record.toTypedRecord.toPeerInfo
            if peerInfo != nil and peerInfo.id notin node.switch.connections:
              # TODO do this in parallel
              await node.dialPeer(peerInfo)
          except CatchableError as err:
            debug "Failed to connect to peer", peer = $peer, err = err.msg
      except CatchableError as err:
        debug "Failure in discovery", err = err.msg

    await sleepAsync seconds(1)

proc init*(T: type Eth2Node, conf: BeaconNodeConf,
           switch: Switch, ip: IpAddress, privKey: keys.PrivateKey): T =
  new result
  result.switch = switch
  result.discovery = Eth2DiscoveryProtocol.new(conf, ip, privKey.data)
  result.wantedPeers = conf.maxPeers
  result.peerPool = newPeerPool[Peer, PeerID](maxPeers = conf.maxPeers)

  newSeq result.protocolStates, allProtocols.len
  for proto in allProtocols:
    if proto.networkStateInitializer != nil:
      result.protocolStates[proto.index] = proto.networkStateInitializer(result)

    for msg in proto.messages:
      if msg.protocolMounter != nil:
        msg.protocolMounter result

template publicKey*(node: Eth2Node): keys.PublicKey =
  node.discovery.privKey.getPublicKey

template addKnownPeer*(node: Eth2Node, peer: ENode|enr.Record) =
  node.discovery.addNode peer

proc start*(node: Eth2Node) {.async.} =
  node.discovery.open()
  node.libp2pTransportLoops = await node.switch.start()
  traceAsyncErrors node.runDiscoveryLoop()

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

proc registerMsg(protocol: ProtocolInfo,
                 name: string,
                 mounter: MounterProc,
                 libp2pCodecName: string,
                 printer: MessageContentPrinter) =
  protocol.messages.add MessageInfo(name: name,
                                    protocolMounter: mounter,
                                    libp2pCodecName: libp2pCodecName,
                                    printer: printer)

proc p2pProtocolBackendImpl*(p: P2PProtocol): Backend =
  var
    Format = ident "SSZ"
    Responder = bindSym "Responder"
    P2PStream = bindSym "P2PStream"
    Peer = bindSym "Peer"
    Eth2Node = bindSym "Eth2Node"
    messagePrinter = bindSym "messagePrinter"
    registerMsg = bindSym "registerMsg"
    initProtocol = bindSym "initProtocol"
    msgVar = ident "msg"
    networkVar = ident "network"
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
    p.onPeerConnected.params.add newIdentDefs(streamVar, P2PStream)

  result.implementMsg = proc (msg: Message) =
    let
      protocol = msg.protocol
      msgName = $msg.ident
      msgNameLit = newLit msgName
      MsgRecName = msg.recName
      MsgStrongRecName = msg.strongRecName
      codecNameLit = getRequestProtoName(msg.procDef)

    if msg.procDef.body.kind != nnkEmpty and msg.kind == msgRequest:
      # Request procs need an extra param - the stream where the response
      # should be written:
      msg.userHandler.params.insert(2, newIdentDefs(streamVar, P2PStream))
      msg.initResponderCall.add streamVar

    ##
    ## Implement the Thunk:
    ##
    ## The protocol handlers in nim-libp2p receive only a `P2PStream`
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

    var mounter: NimNode
    if msg.userHandler != nil:
      protocol.outRecvProcs.add quote do:
        template `callUserHandler`(`peerVar`: `Peer`,
                                   `streamVar`: `P2PStream`,
                                   `msgVar`: `MsgRecName`): untyped =
          `userHandlerCall`

        proc `protocolMounterName`(`networkVar`: `Eth2Node`) =
          proc thunk(`streamVar`: `P2PStream`,
                      proto: string): Future[void] {.gcsafe.} =
            return handleIncomingStream(`networkVar`, `streamVar`,
                                        `MsgStrongRecName`, `Format`)

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

proc setupNat(conf: BeaconNodeConf): tuple[ip: IpAddress,
                                           tcpPort: Port,
                                           udpPort: Port] =
  # defaults
  result.ip = globalListeningAddr
  result.tcpPort = conf.tcpPort
  result.udpPort = conf.udpPort

  var nat: NatStrategy
  case conf.nat.toLowerAscii:
    of "any":
      nat = NatAny
    of "none":
      nat = NatNone
    of "upnp":
      nat = NatUpnp
    of "pmp":
      nat = NatPmp
    else:
      if conf.nat.startsWith("extip:") and isIpAddress(conf.nat[6..^1]):
        # any required port redirection is assumed to be done by hand
        result.ip = parseIpAddress(conf.nat[6..^1])
        nat = NatNone
      else:
        error "not a valid NAT mechanism, nor a valid IP address", value = conf.nat
        quit(QuitFailure)

  if nat != NatNone:
    let extIP = getExternalIP(nat)
    if extIP.isSome:
      result.ip = extIP.get()
      let extPorts = redirectPorts(tcpPort = result.tcpPort,
                                   udpPort = result.udpPort,
                                   description = clientId)
      if extPorts.isSome:
        (result.tcpPort, result.udpPort) = extPorts.get()

func asLibp2pKey*(key: keys.PublicKey): PublicKey =
  PublicKey(scheme: Secp256k1, skkey: key)

func asEthKey*(key: PrivateKey): keys.PrivateKey =
  keys.PrivateKey(data: key.skkey.data)

proc initAddress*(T: type MultiAddress, str: string): T =
  let address = MultiAddress.init(str)
  if IPFS.match(address) and matchPartial(multiaddress.TCP, address):
    result = address
  else:
    raise newException(MultiAddressError,
                       "Invalid bootstrap node multi-address")

template tcpEndPoint(address, port): auto =
  MultiAddress.init(address, Protocol.IPPROTO_TCP, port)

proc getPersistentNetKeys*(conf: BeaconNodeConf): KeyPair =
  let privKeyPath = conf.dataDir / networkKeyFilename
  var privKey: PrivateKey
  if not fileExists(privKeyPath):
    createDir conf.dataDir.string
    privKey = PrivateKey.random(Secp256k1)
    writeFile(privKeyPath, privKey.getBytes())
  else:
    let keyBytes = readFile(privKeyPath)
    privKey = PrivateKey.init(keyBytes.toOpenArrayByte(0, keyBytes.high))

  KeyPair(seckey: privKey, pubkey: privKey.getKey())

proc createEth2Node*(conf: BeaconNodeConf,
                     bootstrapNodes: seq[ENode]): Future[Eth2Node] {.async.} =
  var
    (extIp, extTcpPort, _) = setupNat(conf)
    hostAddress = tcpEndPoint(conf.libp2pAddress, conf.tcpPort)
    announcedAddresses = if extIp == globalListeningAddr: @[]
                         else: @[tcpEndPoint(extIp, extTcpPort)]

  info "Initializing networking", hostAddress,
                                  announcedAddresses,
                                  bootstrapNodes

  let keys = conf.getPersistentNetKeys
  # TODO nim-libp2p still doesn't have support for announcing addresses
  # that are different from the host address (this is relevant when we
  # are running behind a NAT).
  var switch = newStandardSwitch(some keys.seckey, hostAddress,
                                 triggerSelf = true, gossip = false)
  result = Eth2Node.init(conf, switch, extIp, keys.seckey.asEthKey)

proc getPersistenBootstrapAddr*(conf: BeaconNodeConf,
                                ip: IpAddress, port: Port): ENode =
  let pair = getPersistentNetKeys(conf)
  initENode(pair.pubkey.skkey, Address(ip: ip, udpPort: port))

proc shortForm*(id: KeyPair): string =
  $PeerID.init(id.pubkey)

proc toPeerInfo(enode: ENode): PeerInfo =
  let
    peerId = PeerID.init enode.pubkey.asLibp2pKey
    addresses = @[MultiAddress.init enode.toMultiAddressStr]
  return PeerInfo.init(peerId, addresses)

proc connectToNetwork*(node: Eth2Node,
                       bootstrapNodes: seq[ENode],
                       bootstrapEnrs: seq[enr.Record]) {.async.} =
  for bootstrapNode in bootstrapEnrs:
    debug "Adding known peer", peer = bootstrapNode
    node.addKnownPeer bootstrapNode

  await node.start()

  proc checkIfConnectedToBootstrapNode {.async.} =
    await sleepAsync(30.seconds)
    if bootstrapEnrs.len > 0 and libp2p_successful_dials.value == 0:
      fatal "Failed to connect to any bootstrap node. Quitting", bootstrapEnrs
      quit 1

  traceAsyncErrors checkIfConnectedToBootstrapNode()

proc saveConnectionAddressFile*(node: Eth2Node, filename: string) =
  writeFile(filename, $node.switch.peerInfo.addrs[0] & "/p2p/" &
                      node.switch.peerInfo.id)

func peersCount*(node: Eth2Node): int =
  len(node.peerPool)

proc subscribe*[MsgType](node: Eth2Node,
                         topic: string,
                         msgHandler: proc(msg: MsgType) {.gcsafe.} ) {.async, gcsafe.} =
  template execMsgHandler(peerExpr, gossipBytes, gossipTopic) =
    inc gossip_messages_received
    trace "Incoming pubsub message received",
      peer = peerExpr, len = gossipBytes.len, topic = gossipTopic,
      message_id = `$`(sha256.digest(gossipBytes))
    msgHandler SSZ.decode(gossipBytes, MsgType)

  let incomingMsgHandler = proc(topic: string,
                                data: seq[byte]) {.async, gcsafe.} =
    execMsgHandler "unknown", data, topic

  await node.switch.subscribe(topic, incomingMsgHandler)

proc traceMessage(fut: FutureBase, digest: MDigest[256]) =
  fut.addCallback do (arg: pointer):
    if not(fut.failed):
      trace "Outgoing pubsub message has been sent", message_id = `$`(digest)

proc broadcast*(node: Eth2Node, topic: string, msg: auto) =
  inc gossip_messages_sent
  let broadcastBytes = SSZ.encode(msg)
  var fut = node.switch.publish(topic, broadcastBytes)
  traceMessage(fut, sha256.digest(broadcastBytes))
  traceAsyncErrors(fut)

# TODO:
# At the moment, this is just a compatiblity shim for the existing RLPx functionality.
# The filtering is not implemented properly yet.
iterator randomPeers*(node: Eth2Node, maxPeers: int, Protocol: type): Peer =
  var peers = newSeq[Peer]()
  for _, peer in pairs(node.peers): peers.add peer
  shuffle peers
  if peers.len > maxPeers: peers.setLen(maxPeers)
  for p in peers: yield p

