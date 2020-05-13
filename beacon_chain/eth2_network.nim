import
  # Std lib
  typetraits, strutils, os, random, algorithm,
  options as stdOptions, net as stdNet,

  # Status libs
  stew/[varints, base58, bitseqs], stew/shims/[macros, tables], stint,
  faststreams/output_stream, snappy, snappy/framing,
  json_serialization, json_serialization/std/[net, options],
  chronos, chronicles, metrics,
  # TODO: create simpler to use libp2p modules that use re-exports
  libp2p/[switch, standard_setup, peerinfo, peer, connection, errors,
          multiaddress, multicodec, crypto/crypto, crypto/secp,
          protocols/identify, protocols/protocol],
  libp2p/protocols/secure/[secure, secio],
  libp2p/protocols/pubsub/[pubsub, floodsub, rpc/messages],
  libp2p/transports/[transport, tcptransport],
  libp2p/stream/lpstream,
  eth/[keys, async_utils], eth/p2p/[enode, p2p_protocol_dsl],
  eth/net/nat, eth/p2p/discoveryv5/[enr, node],
  # Beacon node modules
  version, conf, eth2_discovery, libp2p_json_serialization, conf, ssz,
  peer_pool, spec/[datatypes, network]

import
  eth/p2p/discoveryv5/protocol as discv5_protocol

export
  version, multiaddress, peer_pool, peerinfo, p2pProtocol,
  libp2p_json_serialization, ssz, peer

logScope:
  topics = "networking"

type
  KeyPair* = crypto.KeyPair
  PublicKey* = crypto.PublicKey
  PrivateKey* = crypto.PrivateKey

  Bytes = seq[byte]

  # TODO: This is here only to eradicate a compiler
  # warning about unused import (rpc/messages).
  GossipMsg = messages.Message

  # TODO Is this really needed?
  Eth2Node* = ref object of RootObj
    switch*: Switch
    discovery*: Eth2DiscoveryProtocol
    wantedPeers*: int
    peerPool*: PeerPool[Peer, PeerID]
    protocolStates*: seq[RootRef]
    libp2pTransportLoops*: seq[Future[void]]
    discoveryLoop: Future[void]
    metadata*: Eth2Metadata

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

  Eth2MetaData* = object
    seq_number*: uint64
    attnets*: BitArray[ATTESTATION_SUBNET_COUNT]

  ENRForkID* = object
    fork_digest*: ForkDigest
    next_fork_version*: Version
    next_fork_epoch*: Epoch

  Peer* = ref object
    network*: Eth2Node
    info*: PeerInfo
    wasDialed*: bool
    discoveryId*: Eth2DiscoveryId
    connectionState*: ConnectionState
    protocolStates*: seq[RootRef]
    maxInactivityAllowed*: Duration
    score*: int
    supportsSnappy: bool

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  UntypedResponder = object
    peer*: Peer
    stream*: Connection

  Responder*[MsgType] = distinct UntypedResponder

  MessageInfo* = object
    name*: string

    # Private fields:
    libp2pCodecName: string
    protocolMounter*: MounterProc

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
  HandshakeStep* = proc(peer: Peer, conn: Connection): Future[void] {.gcsafe.}
  DisconnectionHandler* = proc(peer: Peer): Future[void] {.gcsafe.}
  ThunkProc* = LPProtoHandler
  MounterProc* = proc(network: Eth2Node) {.gcsafe.}
  MessageContentPrinter* = proc(msg: pointer): string {.gcsafe.}

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
  nodeMetadataFilename = "node-metadata.json"

  TCP = net.Protocol.IPPROTO_TCP
  HandshakeTimeout = FaultOrError

  # Spec constants
  # https://github.com/ethereum/eth2.0-specs/blob/dev/specs/networking/p2p-interface.md#eth-20-network-interaction-domains
  MAX_CHUNK_SIZE* = 1 * 1024 * 1024 # bytes
  GOSSIP_MAX_SIZE* = 1 * 1024 * 1024 # bytes
  TTFB_TIMEOUT* = 5.seconds
  RESP_TIMEOUT* = 10.seconds

  readTimeoutErrorMsg = "Exceeded read timeout for a request"

  NewPeerScore* = 200
    ## Score which will be assigned to new connected Peer
  PeerScoreLimit* = 0
    ## Score after which peer will be kicked

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

template openStream(node: Eth2Node, peer: Peer, protocolId: string): untyped =
  dial(node.switch, peer.info, protocolId)

func peerId(conn: Connection): PeerID =
  # TODO: Can this be `nil`?
  conn.peerInfo.peerId

proc init*(T: type Peer, network: Eth2Node, info: PeerInfo): Peer {.gcsafe.}

proc getPeer*(node: Eth2Node, peerInfo: PeerInfo): Peer {.gcsafe.} =
  let peerId = peerInfo.peerId
  result = node.peerPool.getOrDefault(peerId)
  if result == nil:
    # TODO: We should register this peer in the pool!
    result = Peer.init(node, peerInfo)

proc peerFromStream(network: Eth2Node, conn: Connection): Peer {.gcsafe.} =
  # TODO: Can this be `nil`?
  return network.getPeer(conn.peerInfo)

proc getKey*(peer: Peer): PeerID {.inline.} =
  result = peer.info.peerId

proc getFuture*(peer: Peer): Future[void] {.inline.} =
  result = peer.info.lifeFuture()

proc `<`*(a, b: Peer): bool =
  result = `<`(a.score, b.score)

proc getScore*(a: Peer): int =
  result = a.score

proc updateScore*(peer: Peer, score: int) =
  ## Update peer's ``peer`` score with value ``score``.
  peer.score = peer.score + score

proc disconnect*(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    await peer.network.switch.disconnect(peer.info)
    peer.connectionState = Disconnected
    peer.network.peerPool.release(peer)
    peer.info.close()

proc safeClose(conn: Connection) {.async.} =
  if not conn.closed:
    await close(conn)

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
        return newLit("/eth2/beacon_chain/req/" & protoName & "/" & protoVer & "/")

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

proc readChunk(conn: Connection,
               MsgType: type,
               withResponseCode: bool,
               deadline: Future[void]): Future[Option[MsgType]] {.gcsafe.}

proc readSizePrefix(conn: Connection,
                    deadline: Future[void]): Future[int] {.async.} =
  trace "about to read msg size prefix"
  var parser: VarintParser[uint64, ProtoBuf]
  while true:
    var nextByte: byte
    var readNextByte = conn.readExactly(addr nextByte, 1)
    await readNextByte or deadline
    if not readNextByte.finished:
      trace "size prefix byte not received in time"
      return -1
    case parser.feedByte(nextByte)
    of Done:
      let res = parser.getResult
      if res > uint64(MAX_CHUNK_SIZE):
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

proc readMsgBytes(conn: Connection,
                  withResponseCode: bool,
                  deadline: Future[void]): Future[Bytes] {.async.} =
  trace "about to read message bytes", withResponseCode

  try:
    if withResponseCode:
      var responseCode: byte
      trace "about to read response code"
      var readResponseCode = conn.readExactly(addr responseCode, 1)
      try:
        await readResponseCode or deadline
      except LPStreamEOFError:
        trace "end of stream received"
        return

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
        let responseErrMsg = await conn.readChunk(string, false, deadline)
        debug "P2P request resulted in error", responseErrMsg
        return

      of Success:
        # The response is OK, the execution continues below
        discard

    var sizePrefix = await conn.readSizePrefix(deadline)
    trace "got msg size prefix", sizePrefix

    if sizePrefix == -1:
      debug "Failed to read an incoming message size prefix", peer = conn.peerId
      return

    if sizePrefix == 0:
      debug "Received SSZ with zero size", peer = conn.peerId
      return

    trace "about to read msg bytes", len = sizePrefix
    var msgBytes = newSeq[byte](sizePrefix)
    var readBody = conn.readExactly(addr msgBytes[0], sizePrefix)
    await readBody or deadline
    if not readBody.finished:
      trace "msg bytes not received in time"
      return

    trace "got message bytes", len = sizePrefix
    return msgBytes

  except TransportIncompleteError:
    return @[]

proc readChunk(conn: Connection,
               MsgType: type,
               withResponseCode: bool,
               deadline: Future[void]): Future[Option[MsgType]] {.gcsafe, async.} =
  var msgBytes = await conn.readMsgBytes(withResponseCode, deadline)
  try:
    if msgBytes.len > 0:
      return some SSZ.decode(msgBytes, MsgType)
  except SerializationError as err:
    debug "Failed to decode a network message",
          msgBytes, errMsg = err.formatMsg("<msg>")
    return

proc readResponse(
       conn: Connection,
       MsgType: type,
       deadline: Future[void]): Future[Option[MsgType]] {.gcsafe, async.} =

  when MsgType is seq:
    type E = ElemType(MsgType)
    var results: MsgType
    while true:
      let nextRes = await conn.readChunk(E, true, deadline)
      if nextRes.isNone: break
      results.add nextRes.get
    if results.len > 0:
      return some(results)
  else:
    return await conn.readChunk(MsgType, true, deadline)

proc encodeErrorMsg(responseCode: ResponseCode, errMsg: string): Bytes =
  var s = memoryOutput()
  s.append byte(responseCode)
  s.appendVarint errMsg.len
  s.appendValue SSZ, errMsg
  s.getOutput

proc sendErrorResponse(peer: Peer,
                       conn: Connection,
                       err: ref SerializationError,
                       msgName: string,
                       msgBytes: Bytes) {.async.} =
  debug "Received an invalid request",
        peer, msgName, msgBytes, errMsg = err.formatMsg("<msg>")

  let responseBytes = encodeErrorMsg(InvalidRequest, err.formatMsg("msg"))
  await conn.write(responseBytes)
  await conn.close()

proc sendErrorResponse(peer: Peer,
                       conn: Connection,
                       responseCode: ResponseCode,
                       errMsg: string) {.async.} =
  debug "Error processing request", peer, responseCode, errMsg

  let responseBytes = encodeErrorMsg(ServerError, errMsg)
  await conn.write(responseBytes)
  await conn.close()

proc sendNotificationMsg(peer: Peer, protocolId: string, requestBytes: Bytes) {.async} =
  var
    deadline = sleepAsync RESP_TIMEOUT
    protocolId = protocolId & (if peer.supportsSnappy: "ssz_snappy" else: "ssz")
    streamFut = peer.network.openStream(peer, protocolId)

  await streamFut or deadline

  if not streamFut.finished:
    streamFut.cancel()
    raise newException(TransmissionError, "Failed to open LibP2P stream")

  let stream = streamFut.read
  try:
    var s = memoryOutput()
    s.appendVarint requestBytes.len.uint64
    if peer.supportsSnappy:
      framing_format_compress(s, requestBytes)
    else:
      s.append requestBytes
    let bytes = s.getOutput
    await stream.write(bytes)
  finally:
    await safeClose(stream)

# TODO There is too much duplication in the responder functions, but
# I hope to reduce this when I increse the reliance on output streams.
proc sendResponseChunkBytes(responder: UntypedResponder, payload: Bytes) {.async.} =
  var s = memoryOutput()
  s.append byte(Success)
  s.appendVarint payload.len.uint64
  s.append payload
  let bytes = s.getOutput
  await responder.stream.write(bytes)

proc sendResponseChunkObj(responder: UntypedResponder, val: auto) {.async.} =
  var s = memoryOutput()
  s.append byte(Success)
  s.appendValue SSZ, sizePrefixed(val)
  let bytes = s.getOutput
  await responder.stream.write(bytes)

proc sendResponseChunks[T](responder: UntypedResponder, chunks: seq[T]) {.async.} =
  var s = memoryOutput()
  for chunk in chunks:
    s.append byte(Success)
    s.appendValue SSZ, sizePrefixed(chunk)

  let bytes = s.getOutput
  await responder.stream.write(bytes)

proc makeEth2Request(peer: Peer, protocolId: string, requestBytes: Bytes,
                     ResponseMsg: type,
                     timeout: Duration): Future[Option[ResponseMsg]] {.gcsafe, async.} =
  var
    deadline = sleepAsync timeout
    protocolId = protocolId & (if peer.supportsSnappy: "ssz_snappy" else: "ssz")
    streamFut = peer.network.openStream(peer, protocolId)

  await streamFut or deadline

  if not streamFut.finished:
    streamFut.cancel()
    return none(ResponseMsg)

  let stream = streamFut.read
  try:
    # Send the request
    var s = memoryOutput()
    s.appendVarint requestBytes.len.uint64
    if peer.supportsSnappy:
      framing_format_compress(s, requestBytes)
    else:
      s.append requestBytes
    let bytes = s.getOutput
    await stream.write(bytes)

    # Read the response
    return await stream.readResponse(ResponseMsg, deadline)
  finally:
    await safeClose(stream)

proc init*[MsgType](T: type Responder[MsgType],
                    peer: Peer, conn: Connection): T =
  T(UntypedResponder(peer: peer, stream: conn))

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

  await allFuturesThrowing(subProtocolsHandshakes)

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

proc handleIncomingStream(network: Eth2Node, conn: Connection, useSnappy: bool,
                          MsgType, Format: distinct type) {.async, gcsafe.} =
  mixin callUserHandler, RecType
  const msgName = typetraits.name(MsgType)

  ## Uncomment this to enable tracing on all incoming requests
  ## You can include `msgNameLit` in the condition to select
  ## more specific requests:
  # when chronicles.runtimeFilteringEnabled:
  #   setLogLevel(LogLevel.TRACE)
  #   defer: setLogLevel(LogLevel.DEBUG)
  #   trace "incoming " & `msgNameLit` & " conn"

  let peer = peerFromStream(network, conn)

  try:
    let deadline = sleepAsync RESP_TIMEOUT
    var msgBytes = await readMsgBytes(conn, false, deadline)

    if msgBytes.len == 0:
      await sendErrorResponse(peer, conn, ServerError, readTimeoutErrorMsg)
      return

    if useSnappy:
      msgBytes = framingFormatUncompress(msgBytes)

    type MsgRec = RecType(MsgType)
    var msg: MsgRec
    try:
      msg = decode(Format, msgBytes, MsgRec)
    except SerializationError as err:
      await sendErrorResponse(peer, conn, err, msgName, msgBytes)
      return
    except Exception as err:
      # TODO. This is temporary code that should be removed after interop.
      # It can be enabled only in certain diagnostic builds where it should
      # re-raise the exception.
      debug "Crash during serialization", inputBytes = toHex(msgBytes), msgName
      await sendErrorResponse(peer, conn, ServerError, err.msg)
      raise err

    try:
      logReceivedMsg(peer, MsgType(msg))
      await callUserHandler(peer, conn, msg)
    except CatchableError as err:
      await sendErrorResponse(peer, conn, ServerError, err.msg)
  finally:
    await safeClose(conn)

proc handleOutgoingPeer*(peer: Peer): Future[bool] {.async.} =
  let network = peer.network

  proc onPeerClosed(udata: pointer) {.gcsafe.} =
    debug "Peer (outgoing) lost", peer = $peer.info
    libp2p_peers.set int64(len(network.peerPool))

  let res = await network.peerPool.addOutgoingPeer(peer)
  if res:
    peer.updateScore(NewPeerScore)
    debug "Peer (outgoing) has been added to PeerPool", peer = $peer.info
    peer.getFuture().addCallback(onPeerClosed)
    result = true

  libp2p_peers.set int64(len(network.peerPool))

proc handleIncomingPeer*(peer: Peer): Future[bool] {.async.} =
  let network = peer.network

  proc onPeerClosed(udata: pointer) {.gcsafe.} =
    debug "Peer (incoming) lost", peer = $peer.info
    libp2p_peers.set int64(len(network.peerPool))

  let res = await network.peerPool.addIncomingPeer(peer)
  if res:
    peer.updateScore(NewPeerScore)
    debug "Peer (incoming) has been added to PeerPool", peer = $peer.info
    peer.getFuture().addCallback(onPeerClosed)
    result = true

  libp2p_peers.set int64(len(network.peerPool))

proc toPeerInfo*(r: enr.TypedRecord): PeerInfo =
  if r.secp256k1.isSome:
    var pubKey = keys.PublicKey.fromRaw(r.secp256k1.get)
    if pubkey.isErr:
      return # TODO

    let peerId = PeerID.init crypto.PublicKey(
      scheme: Secp256k1, skkey: secp.SkPublicKey(pubKey[]))
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

  #let msDial = newMultistream()
  #let conn = node.switch.connections.getOrDefault(peerInfo.id)
  #let ls = await msDial.list(conn)
  #debug "Supported protocols", ls

  debug "Initializing connection"
  await initializeConnection(peer)

  inc libp2p_successful_dials
  debug "Network handshakes completed"

proc runDiscoveryLoop*(node: Eth2Node) {.async.} =
  debug "Starting discovery loop"

  while true:
    let currentPeerCount = node.peerPool.len
    if currentPeerCount < node.wantedPeers:
      try:
        let discoveredPeers =
          node.discovery.randomNodes(node.wantedPeers - currentPeerCount)
        for peer in discoveredPeers:
          try:
            let peerInfo = peer.record.toTypedRecord.toPeerInfo
            if peerInfo != nil:
              if peerInfo.id notin node.switch.connections:
                debug "Discovered new peer", peer = $peer
                # TODO do this in parallel
                await node.dialPeer(peerInfo)
              else:
                peerInfo.close()
          except CatchableError as err:
            debug "Failed to connect to peer", peer = $peer, err = err.msg
      except CatchableError as err:
        debug "Failure in discovery", err = err.msg

    await sleepAsync seconds(1)

proc getPersistentNetMetadata*(conf: BeaconNodeConf): Eth2Metadata =
  let metadataPath = conf.dataDir / nodeMetadataFilename
  if not fileExists(metadataPath):
    result = Eth2Metadata()
    for i in 0 ..< ATTESTATION_SUBNET_COUNT:
      # TODO: For now, we indicate that we participate in all subnets
      result.attnets[i] = true
    Json.saveFile(metadataPath, result)
  else:
    result = Json.loadFile(metadataPath, Eth2Metadata)

proc init*(T: type Eth2Node, conf: BeaconNodeConf, enrForkId: ENRForkID,
           switch: Switch, ip: Option[IpAddress], tcpPort, udpPort: Port,
           privKey: keys.PrivateKey): T =
  new result
  result.switch = switch
  result.wantedPeers = conf.maxPeers
  result.peerPool = newPeerPool[Peer, PeerID](maxPeers = conf.maxPeers)
  result.metadata = getPersistentNetMetadata(conf)
  result.discovery = Eth2DiscoveryProtocol.new(
    conf, ip, tcpPort, udpPort, privKey.toRaw,
    {"eth2": SSZ.encode(enrForkId), "attnets": SSZ.encode(result.metadata.attnets)})

  newSeq result.protocolStates, allProtocols.len
  for proto in allProtocols:
    if proto.networkStateInitializer != nil:
      result.protocolStates[proto.index] = proto.networkStateInitializer(result)

    for msg in proto.messages:
      if msg.protocolMounter != nil:
        msg.protocolMounter result

template publicKey*(node: Eth2Node): keys.PublicKey =
  node.discovery.privKey.toPublicKey.tryGet()

template addKnownPeer*(node: Eth2Node, peer: ENode|enr.Record) =
  node.discovery.addNode peer

proc start*(node: Eth2Node) {.async.} =
  node.discovery.open()
  node.discovery.start()
  node.libp2pTransportLoops = await node.switch.start()
  node.discoveryLoop = node.runDiscoveryLoop()
  traceAsyncErrors node.discoveryLoop

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
                 libp2pCodecName: string) =
  protocol.messages.add MessageInfo(name: name,
                                    protocolMounter: mounter,
                                    libp2pCodecName: libp2pCodecName)

proc p2pProtocolBackendImpl*(p: P2PProtocol): Backend =
  var
    Format = ident "SSZ"
    Responder = bindSym "Responder"
    Connection = bindSym "Connection"
    Peer = bindSym "Peer"
    Eth2Node = bindSym "Eth2Node"
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
    p.onPeerConnected.params.add newIdentDefs(streamVar, Connection)

  result.implementMsg = proc (msg: p2p_protocol_dsl.Message) =
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

    var mounter: NimNode
    if msg.userHandler != nil:
      protocol.outRecvProcs.add quote do:
        template `callUserHandler`(`peerVar`: `Peer`,
                                   `streamVar`: `Connection`,
                                   `msgVar`: `MsgRecName`): untyped =
          `userHandlerCall`

        proc `protocolMounterName`(`networkVar`: `Eth2Node`) =
          proc sszThunk(`streamVar`: `Connection`,
                      proto: string): Future[void] {.gcsafe.} =
            return handleIncomingStream(`networkVar`, `streamVar`, false,
                                        `MsgStrongRecName`, `Format`)

          mount `networkVar`.switch,
                LPProtocol(codec: `codecNameLit` & "ssz",
                           handler: sszThunk)

          proc snappyThunk(`streamVar`: `Connection`,
                      proto: string): Future[void] {.gcsafe.} =
            return handleIncomingStream(`networkVar`, `streamVar`, true,
                                        `MsgStrongRecName`, `Format`)

          mount `networkVar`.switch,
                LPProtocol(codec: `codecNameLit` & "ssz_snappy",
                           handler: snappyThunk)

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
              codecNameLit))

  result.implementProtocolInit = proc (p: P2PProtocol): NimNode =
    return newCall(initProtocol, newLit(p.name), p.peerInit, p.netInit)

proc setupNat(conf: BeaconNodeConf): tuple[ip: Option[IpAddress],
                                           tcpPort: Port,
                                           udpPort: Port] {.gcsafe.} =
  # defaults
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
        result.ip = some(parseIpAddress(conf.nat[6..^1]))
        nat = NatNone
      else:
        error "not a valid NAT mechanism, nor a valid IP address", value = conf.nat
        quit(QuitFailure)

  if nat != NatNone:
    result.ip = getExternalIP(nat)
    if result.ip.isSome:
      # TODO redirectPorts in considered a gcsafety violation
      # because it obtains the address of a non-gcsafe proc?
      let extPorts = ({.gcsafe.}:
        redirectPorts(tcpPort = result.tcpPort,
                      udpPort = result.udpPort,
                      description = clientId))
      if extPorts.isSome:
        (result.tcpPort, result.udpPort) = extPorts.get()

func asLibp2pKey*(key: keys.PublicKey): PublicKey =
  PublicKey(scheme: Secp256k1, skkey: secp.SkPublicKey(key))

func asEthKey*(key: PrivateKey): keys.PrivateKey =
  keys.PrivateKey(key.skkey)

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

proc createEth2Node*(conf: BeaconNodeConf, enrForkId: ENRForkID): Future[Eth2Node] {.async, gcsafe.} =
  var
    (extIp, extTcpPort, extUdpPort) = setupNat(conf)
    hostAddress = tcpEndPoint(conf.libp2pAddress, conf.tcpPort)
    announcedAddresses = if extIp.isNone(): @[]
                         else: @[tcpEndPoint(extIp.get(), extTcpPort)]

  info "Initializing networking", hostAddress,
                                  announcedAddresses

  let keys = conf.getPersistentNetKeys
  # TODO nim-libp2p still doesn't have support for announcing addresses
  # that are different from the host address (this is relevant when we
  # are running behind a NAT).
  var switch = newStandardSwitch(some keys.seckey, hostAddress,
                                 triggerSelf = true, gossip = true,
                                 sign = false, verifySignature = false, transportFlags = {TransportFlag.ReuseAddr})
  result = Eth2Node.init(conf, enrForkId, switch,
                         extIp, extTcpPort, extUdpPort,
                         keys.seckey.asEthKey)

proc getPersistenBootstrapAddr*(conf: BeaconNodeConf,
                                ip: IpAddress, port: Port): EnrResult[enr.Record] =
  let pair = getPersistentNetKeys(conf)
  return enr.Record.init(1'u64, # sequence number
                         pair.seckey.asEthKey,
                         some(ip), port, port, @[])

proc announcedENR*(node: Eth2Node): enr.Record =
  doAssert node.discovery != nil, "The Eth2Node must be initialized"
  node.discovery.localNode.record

proc shortForm*(id: KeyPair): string =
  $PeerID.init(id.pubkey)

proc toPeerInfo(enode: ENode): PeerInfo =
  let
    peerId = PeerID.init enode.pubkey.asLibp2pKey
    addresses = @[MultiAddress.init enode.toMultiAddressStr]
  return PeerInfo.init(peerId, addresses)

proc connectToNetwork*(node: Eth2Node) {.async.} =
  await node.start()

  proc checkIfConnectedToBootstrapNode {.async.} =
    await sleepAsync(30.seconds)
    if node.discovery.bootstrapRecords.len > 0 and libp2p_successful_dials.value == 0:
      fatal "Failed to connect to any bootstrap node. Quitting",
        bootstrapEnrs = node.discovery.bootstrapRecords
      quit 1

  # TODO: The initial sync forces this to time out.
  #       Revisit when the new Sync manager is integrated.
  # traceAsyncErrors checkIfConnectedToBootstrapNode()

func peersCount*(node: Eth2Node): int =
  len(node.peerPool)

proc subscribe*[MsgType](node: Eth2Node,
                         topic: string,
                         msgHandler: proc(msg: MsgType) {.gcsafe.},
                         msgValidator: proc(msg: MsgType): bool {.gcsafe.} ) {.async, gcsafe.} =
  template execMsgHandler(peerExpr, gossipBytes, gossipTopic, useSnappy) =
    inc gossip_messages_received
    trace "Incoming pubsub message received",
      peer = peerExpr, len = gossipBytes.len, topic = gossipTopic,
      message_id = `$`(sha256.digest(gossipBytes))
    when useSnappy:
      msgHandler SSZ.decode(snappy.decode(gossipBytes), MsgType)
    else:
      msgHandler SSZ.decode(gossipBytes, MsgType)

  # All message types which are subscribed to should be validated; putting
  # this in subscribe(...) ensures that the default approach is correct.
  template execMsgValidator(gossipBytes, gossipTopic, useSnappy): bool =
    trace "Incoming pubsub message received for validation",
      len = gossipBytes.len, topic = gossipTopic,
      message_id = `$`(sha256.digest(gossipBytes))
    when useSnappy:
      msgValidator SSZ.decode(snappy.decode(gossipBytes), MsgType)
    else:
      msgValidator SSZ.decode(gossipBytes, MsgType)

  # Validate messages as soon as subscribed
  let incomingMsgValidator = proc(topic: string,
                                  message: GossipMsg): Future[bool]
                                 {.async, gcsafe.} =
    return execMsgValidator(message.data, topic, false)
  let incomingMsgValidatorSnappy = proc(topic: string,
                                        message: GossipMsg): Future[bool]
                                       {.async, gcsafe.} =
    return execMsgValidator(message.data, topic, true)

  node.switch.addValidator(topic, incomingMsgValidator)
  node.switch.addValidator(topic & "_snappy", incomingMsgValidatorSnappy)

  let incomingMsgHandler = proc(topic: string,
                                data: seq[byte]) {.async, gcsafe.} =
    execMsgHandler "unknown", data, topic, false
  let incomingMsgHandlerSnappy = proc(topic: string,
                                      data: seq[byte]) {.async, gcsafe.} =
    execMsgHandler "unknown", data, topic, true

  var switchSubscriptions: seq[Future[void]] = @[]
  switchSubscriptions.add(node.switch.subscribe(topic, incomingMsgHandler))
  switchSubscriptions.add(node.switch.subscribe(topic & "_snappy", incomingMsgHandlerSnappy))

  await allFutures(switchSubscriptions)

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
  # also publish to the snappy-compressed topics
  let snappyEncoded = snappy.encode(broadcastBytes)
  var futSnappy = node.switch.publish(topic & "_snappy", snappyEncoded)
  traceMessage(futSnappy, sha256.digest(snappyEncoded))
  traceAsyncErrors(futSnappy)

# TODO:
# At the moment, this is just a compatiblity shim for the existing RLPx functionality.
# The filtering is not implemented properly yet.
iterator randomPeers*(node: Eth2Node, maxPeers: int, Protocol: type): Peer =
  var peers = newSeq[Peer]()
  for _, peer in pairs(node.peers): peers.add peer
  shuffle peers
  if peers.len > maxPeers: peers.setLen(maxPeers)
  for p in peers: yield p
