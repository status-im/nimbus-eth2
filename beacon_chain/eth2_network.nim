import
  # Std lib
  typetraits, strutils, os, random, algorithm, sequtils,
  options as stdOptions,

  # Status libs
  stew/[varints, base58, endians2, results, byteutils],
  stew/shims/net as stewNet,
  stew/shims/[macros, tables],
  faststreams/[inputs, outputs, buffers], snappy, snappy/framing,
  json_serialization, json_serialization/std/[net, options],
  chronos, chronicles, metrics,
  # TODO: create simpler to use libp2p modules that use re-exports
  libp2p/[switch, standard_setup, peerinfo, peer, connection, errors,
          multiaddress, multicodec, crypto/crypto, crypto/secp,
          protocols/identify, protocols/protocol],
  libp2p/protocols/secure/[secure, secio],
  libp2p/protocols/pubsub/[pubsub, floodsub, rpc/messages],
  libp2p/transports/tcptransport,
  libp2p/stream/lpstream,
  eth/[keys, async_utils], eth/p2p/p2p_protocol_dsl,
  eth/net/nat, eth/p2p/discoveryv5/[enr, node],
  # Beacon node modules
  version, conf, eth2_discovery, libp2p_json_serialization, conf,
  ssz/ssz_serialization,
  peer_pool, spec/[datatypes, network]

export
  version, multiaddress, peer_pool, peerinfo, p2pProtocol,
  libp2p_json_serialization, ssz_serialization, peer, results

logScope:
  topics = "networking"

type
  KeyPair* = crypto.KeyPair
  PublicKey* = crypto.PublicKey
  PrivateKey* = crypto.PrivateKey

  Bytes = seq[byte]
  ErrorMsg = List[byte, 256]

  # TODO: This is here only to eradicate a compiler
  # warning about unused import (rpc/messages).
  GossipMsg = messages.Message

  SeenItem* = object
    pinfo*: PeerInfo
    stamp*: chronos.Moment

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
    connectTimeout*: chronos.Duration
    seenThreshold*: chronos.Duration
    connQueue: AsyncQueue[PeerInfo]
    seenTable: Table[PeerID, SeenItem]
    connWorkers: seq[Future[void]]

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
    lacksSnappy: bool

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  UntypedResponse = ref object
    peer*: Peer
    stream*: Connection
    noSnappy*: bool
    writtenChunks*: int

  SingleChunkResponse*[MsgType] = distinct UntypedResponse
    ## Protocol requests using this type will produce request-making
    ## client-side procs that return `NetRes[MsgType]`

  MultipleChunksResponse*[MsgType] = distinct UntypedResponse
    ## Protocol requests using this type will produce request-making
    ## client-side procs that return `NetRes[seq[MsgType]]`.
    ## In the future, such procs will return an `InputStream[NetRes[MsgType]]`.

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

  Eth2NetworkingErrorKind* = enum
    BrokenConnection
    ReceivedErrorResponse
    UnexpectedEOF
    PotentiallyExpectedEOF
    InvalidResponseCode
    InvalidSnappyBytes
    InvalidSszBytes
    StreamOpenTimeout
    ReadResponseTimeout
    ZeroSizePrefix
    SizePrefixOverflow

  Eth2NetworkingError = object
    case kind*: Eth2NetworkingErrorKind
    of ReceivedErrorResponse:
      responseCode: ResponseCode
      errorMsg: ErrorMsg
    else:
      discard

  NetRes*[T] = Result[T, Eth2NetworkingError]
    ## This is type returned from all network requests

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
  PeerScoreLowLimit* = 0
    ## Score after which peer will be kicked
  PeerScoreHighLimit* = 1000
    ## Max value of peer's score

  ConcurrentConnections* = 10
    ## Maximum number of active concurrent connection requests.

template neterr(kindParam: Eth2NetworkingErrorKind): auto =
  err(type(result), Eth2NetworkingError(kind: kindParam))

# Metrics for tracking attestation and beacon block loss
declareCounter gossip_messages_sent,
  "Number of gossip messages sent by this peer"

declareCounter gossip_messages_received,
  "Number of gossip messages received by this peer"

declarePublicGauge libp2p_successful_dials,
  "Number of successfully dialed peers"

declarePublicGauge libp2p_failed_dials,
  "Number of dialing attempts that failed"

declarePublicGauge libp2p_timeout_dials,
  "Number of dialing attempts that exceeded timeout"

declarePublicGauge libp2p_peers,
  "Number of active libp2p peers"

proc safeClose(conn: Connection) {.async.} =
  if not conn.closed:
    await close(conn)

const
  snappy_implementation {.strdefine.} = "libp2p"

const useNativeSnappy = when snappy_implementation == "native": true
                        elif snappy_implementation == "libp2p": false
                        else: {.fatal: "Please set snappy_implementation to either 'libp2p' or 'native'".}

template libp2pProtocol*(name: string, version: int) {.pragma.}

template `$`*(peer: Peer): string = id(peer.info)
chronicles.formatIt(Peer): $it

template remote*(peer: Peer): untyped =
  peer.info.peerId

proc openStream(node: Eth2Node,
                peer: Peer,
                protocolId: string): Future[Connection] {.async.} =
  let protocolId = protocolId & (if peer.lacksSnappy: "ssz" else: "ssz_snappy")
  try:
    result = await dial(node.switch, peer.info, protocolId)
  except CancelledError:
    raise
  except CatchableError:
    # TODO: LibP2P should raise a more specific exception here
    if peer.lacksSnappy == false:
      peer.lacksSnappy = true
      trace "Snappy connection failed. Trying without Snappy",
            peer, protocolId
      return await openStream(node, peer, protocolId)
    else:
      raise

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

proc updateScore*(peer: Peer, score: int) {.inline.} =
  ## Update peer's ``peer`` score with value ``score``.
  peer.score = peer.score + score
  if peer.score > PeerScoreHighLimit:
    peer.score = PeerScoreHighLimit

proc disconnect*(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    await peer.network.switch.disconnect(peer.info)
    peer.connectionState = Disconnected
    peer.network.peerPool.release(peer)
    peer.info.close()

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

proc writeChunk*(conn: Connection,
                 responseCode: Option[ResponseCode],
                 payload: Bytes,
                 noSnappy: bool) {.async.} =
  var output = memoryOutput()

  if responseCode.isSome:
    output.write byte(responseCode.get)

  output.write varintBytes(payload.len.uint64)

  if noSnappy:
    output.write(payload)
  else:
    output.write(framingFormatCompress payload)

  await conn.write(output.getOutput)

template errorMsgLit(x: static string): ErrorMsg =
  const val = ErrorMsg toBytes(x)
  val

proc formatErrorMsg(msg: ErrorMSg): string =
  let candidate = string.fromBytes(asSeq(msg))
  for c in candidate:
    # TODO UTF-8 - but let's start with ASCII
    if ord(c) < 32 or ord(c) > 127:
      return byteutils.toHex(asSeq(msg))

  return candidate

proc sendErrorResponse(peer: Peer,
                       conn: Connection,
                       noSnappy: bool,
                       responseCode: ResponseCode,
                       errMsg: ErrorMsg) {.async.} =
  debug "Error processing request",
    peer, responseCode, errMsg = formatErrorMsg(errMsg)
  await conn.writeChunk(some responseCode, SSZ.encode(errMsg), noSnappy)

proc sendNotificationMsg(peer: Peer, protocolId: string, requestBytes: Bytes) {.async} =
  var
    deadline = sleepAsync RESP_TIMEOUT
    streamFut = peer.network.openStream(peer, protocolId)

  await streamFut or deadline

  if not streamFut.finished:
    streamFut.cancel()
    raise newException(TransmissionError, "Failed to open LibP2P stream")

  let stream = streamFut.read
  try:
    await stream.writeChunk(none ResponseCode, requestBytes, peer.lacksSnappy)
  finally:
    await safeClose(stream)

proc sendResponseChunkBytes(response: UntypedResponse, payload: Bytes) {.async.} =
  inc response.writtenChunks
  await response.stream.writeChunk(some Success, payload, response.noSnappy)

proc sendResponseChunkObj(response: UntypedResponse, val: auto) {.async.} =
  inc response.writtenChunks
  await response.stream.writeChunk(some Success, SSZ.encode(val), response.noSnappy)

template sendUserHandlerResultAsChunkImpl*(stream: Connection,
                                           noSnappy: bool,
                                           handlerResultFut: Future): untyped =
  let handlerRes = await handlerResultFut
  writeChunk(stream, some Success, SSZ.encode(handlerRes), noSnappy)

template sendUserHandlerResultAsChunkImpl*(stream: Connection,
                                           noSnappy: bool,
                                           handlerResult: auto): untyped =
  writeChunk(stream, some Success, SSZ.encode(handlerResult), noSnappy)

when useNativeSnappy:
  include faststreams_backend
else:
  include libp2p_streams_backend

template awaitWithTimeout[T](operation: Future[T],
                             deadline: Future[void],
                             onTimeout: untyped): T =
  let f = operation
  await f or deadline
  if not f.finished:
    cancel f
    onTimeout
  else:
    f.read

proc makeEth2Request(peer: Peer, protocolId: string, requestBytes: Bytes,
                     ResponseMsg: type,
                     timeout: Duration): Future[NetRes[ResponseMsg]]
                    {.gcsafe, async.} =
  var deadline = sleepAsync timeout

  let stream = awaitWithTimeout(peer.network.openStream(peer, protocolId),
                                deadline): return neterr StreamOpenTimeout
  try:
    # Send the request
    await stream.writeChunk(none ResponseCode, requestBytes, peer.lacksSnappy)

    # Read the response
    return awaitWithTimeout(
      readResponse(when useNativeSnappy: libp2pInput(stream)
                   else: stream,
                   peer.lacksSnappy,
                   ResponseMsg),
      deadline, neterr(ReadResponseTimeout))
  finally:
    await safeClose(stream)

proc init*[MsgType](T: type MultipleChunksResponse[MsgType],
                    peer: Peer, conn: Connection, noSnappy: bool): T =
  T(UntypedResponse(peer: peer, stream: conn, noSnappy: noSnappy))

proc init*[MsgType](T: type SingleChunkResponse[MsgType],
                    peer: Peer, conn: Connection, noSnappy: bool): T =
  T(UntypedResponse(peer: peer, stream: conn, noSnappy: noSnappy))

template write*[M](r: MultipleChunksResponse[M], val: M): untyped =
  sendResponseChunkObj(UntypedResponse(r), val)

template send*[M](r: SingleChunkResponse[M], val: auto): untyped =
  doAssert UntypedResponse(r).writtenChunks == 0
  sendResponseChunkObj(UntypedResponse(r), val)

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
    UntypedResponse = bindSym "UntypedResponse"

  proc sendCallGenerator(peer, bytes: NimNode): NimNode =
    if msg.kind != msgResponse:
      let msgProto = getRequestProtoName(msg.procDef)
      case msg.kind
      of msgRequest:
        let ResponseRecord = msg.response.recName
        quote:
          makeEth2Request(`peer`, `msgProto`, `bytes`,
                          `ResponseRecord`, `timeoutVar`)
      else:
        quote: sendNotificationMsg(`peer`, `msgProto`, `bytes`)
    else:
      quote: sendResponseChunkBytes(`UntypedResponse`(`peer`), `bytes`)

  sendProc.useStandardBody(nil, nil, sendCallGenerator)

proc handleIncomingStream(network: Eth2Node,
                          conn: Connection,
                          noSnappy: bool,
                          MsgType: type) {.async, gcsafe.} =
  mixin callUserHandler, RecType

  type MsgRec = RecType(MsgType)
  const msgName {.used.} = typetraits.name(MsgType)

  ## Uncomment this to enable tracing on all incoming requests
  ## You can include `msgNameLit` in the condition to select
  ## more specific requests:
  # when chronicles.runtimeFilteringEnabled:
  #   setLogLevel(LogLevel.TRACE)
  #   defer: setLogLevel(LogLevel.DEBUG)
  #   trace "incoming " & `msgNameLit` & " conn"

  try:
    let peer = peerFromStream(network, conn)

    template returnInvalidRequest(msg: ErrorMsg) =
      await sendErrorResponse(peer, conn, noSnappy, InvalidRequest, msg)
      return

    template returnInvalidRequest(msg: string) =
      returnInvalidRequest(ErrorMsg msg.toBytes)

    let s = when useNativeSnappy:
      let fs = libp2pInput(conn)

      if fs.timeoutToNextByte(TTFB_TIMEOUT):
        returnInvalidRequest(errorMsgLit "Request first byte not sent in time")

      fs
    else:
      # TODO The TTFB timeout is not implemented in LibP2P streams back-end
      conn

    let deadline = sleepAsync RESP_TIMEOUT

    let msg = if sizeof(MsgRec) > 0:
      try:
        awaitWithTimeout(readChunkPayload(s, noSnappy, MsgRec), deadline):
          returnInvalidRequest(errorMsgLit "Request full data not sent in time")

      except SerializationError as err:
        returnInvalidRequest err.formatMsg("msg")

      except SnappyError as err:
        returnInvalidRequest err.msg
    else:
      NetRes[MsgRec].ok default(MsgRec)

    if msg.isErr:
      let (responseCode, errMsg) = case msg.error.kind
        of UnexpectedEOF, PotentiallyExpectedEOF:
          (InvalidRequest, errorMsgLit "Incomplete request")

        of InvalidSnappyBytes:
          (InvalidRequest, errorMsgLit "Failed to decompress snappy payload")

        of InvalidSszBytes:
          (InvalidRequest, errorMsgLit "Failed to decode SSZ payload")

        of ZeroSizePrefix:
          (InvalidRequest, errorMsgLit "The request chunk cannot have a size of zero")

        of SizePrefixOverflow:
          (InvalidRequest, errorMsgLit "The chunk size exceed the maximum allowed")

        of InvalidResponseCode, ReceivedErrorResponse,
           StreamOpenTimeout, ReadResponseTimeout:
          # These shouldn't be possible in a request, because
          # there are no response codes being read, no stream
          # openings and no reading of responses:
          (ServerError, errorMsgLit "Internal server error")

        of BrokenConnection:
          return

      await sendErrorResponse(peer, conn, noSnappy, responseCode, errMsg)
      return

    try:
      logReceivedMsg(peer, MsgType(msg.get))
      await callUserHandler(MsgType, peer, conn, noSnappy, msg.get)
    except CatchableError as err:
      await sendErrorResponse(peer, conn, noSnappy, ServerError,
                              ErrorMsg err.msg.toBytes)

  except CatchableError as err:
    debug "Error processing an incoming request", err = err.msg, msgName

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
      let ip = ipv4(r.ip.get)
      addresses.add MultiAddress.init(ip, tcpProtocol, Port r.tcp.get)

    if r.ip6.isSome:
      let ip = ipv6(r.ip6.get)
      if r.tcp6.isSome:
        addresses.add MultiAddress.init(ip, tcpProtocol, Port r.tcp6.get)
      elif r.tcp.isSome:
        addresses.add MultiAddress.init(ip, tcpProtocol, Port r.tcp.get)
      else:
        discard

    if addresses.len > 0:
      return PeerInfo.init(peerId, addresses)

proc toPeerInfo(r: Option[enr.TypedRecord]): PeerInfo =
  if r.isSome:
    return r.get.toPeerInfo

proc isSeen*(network: ETh2Node, pinfo: PeerInfo): bool =
  let currentTime = now(chronos.Moment)
  let item = network.seenTable.getOrDefault(pinfo.peerId)
  if isNil(item.pinfo):
    # Peer is not in SeenTable.
    return false
  if currentTime - item.stamp >= network.seenThreshold:
    network.seenTable.del(pinfo.peerId)
    return false
  return true

proc addSeen*(network: ETh2Node, pinfo: PeerInfo) =
  let item = SeenItem(pinfo: pinfo, stamp: now(chronos.Moment))
  network.seenTable[pinfo.peerId] = item

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

proc connectWorker(network: Eth2Node) {.async.} =
  debug "Connection worker started"
  while true:
    let pi = await network.connQueue.popFirst()
    let r1 = network.peerPool.hasPeer(pi.peerId)
    let r2 = network.isSeen(pi)

    if not(r1) and not(r2):
      # We trying to connect to peers which are not present in our PeerPool and
      # not present in our SeenTable.
      var fut = network.dialPeer(pi)
      # We discarding here just because we going to check future state, to avoid
      # condition where connection happens and timeout reached.
      let res = await withTimeout(fut, network.connectTimeout)
      # We handling only timeout and errors, because successfull connections
      # will be stored in PeerPool.
      if fut.finished():
        if fut.failed() and not(fut.cancelled()):
          debug "Unable to establish connection with peer", peer = $pi,
                errMsg = fut.readError().msg
          inc libp2p_failed_dials
          network.addSeen(pi)
        continue
      debug "Connection to remote peer timed out", peer = $pi
      inc libp2p_timeout_dials
      network.addSeen(pi)
    else:
      debug "Peer is already connected or already seen", peer = $pi,
            peer_pool_has_peer = $r1, seen_table_has_peer = $r2,
            seen_table_size = len(network.seenTable)

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
            let peerRecord = peer.record.toTypedRecord
            if peerRecord.isOk:
              let peerInfo = peerRecord.value.toPeerInfo
              if peerInfo != nil:
                if peerInfo.id notin node.switch.connections:
                  debug "Discovered new peer", peer = $peer
                  await node.connQueue.addLast(peerInfo)
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
           switch: Switch, ip: Option[ValidIpAddress], tcpPort, udpPort: Port,
           privKey: keys.PrivateKey): T =
  new result
  result.switch = switch
  result.wantedPeers = conf.maxPeers
  result.peerPool = newPeerPool[Peer, PeerID](maxPeers = conf.maxPeers)
  result.connectTimeout = 10.seconds
  result.seenThreshold = 10.minutes
  result.seenTable = initTable[PeerID, SeenItem]()
  result.connQueue = newAsyncQueue[PeerInfo](ConcurrentConnections)
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

  for i in 0 ..< ConcurrentConnections:
    result.connWorkers.add(connectWorker(result))

template publicKey*(node: Eth2Node): keys.PublicKey =
  node.discovery.privKey.toPublicKey.tryGet()

template addKnownPeer*(node: Eth2Node, peer: enr.Record) =
  node.discovery.addNode peer

proc start*(node: Eth2Node) {.async.} =
  node.discovery.open()
  node.discovery.start()
  node.libp2pTransportLoops = await node.switch.start()
  node.discoveryLoop = node.runDiscoveryLoop()
  traceAsyncErrors node.discoveryLoop

proc stop*(node: Eth2Node) {.async.} =
  # Ignore errors in futures, since we're shutting down (but log them on the
  # TRACE level, if a timeout is reached).
  let
    waitedFutures = @[
      node.discovery.closeWait(),
      node.switch.stop(),
    ]
    timeout = 5.seconds
    completed = await withTimeout(allFutures(waitedFutures), timeout)
  if not completed:
    trace "Eth2Node.stop(): timeout reached", timeout, futureErrors = waitedFutures.filterIt(it.error != nil).mapIt(it.error.msg)

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
    Bool = bindSym "bool"
    Connection = bindSym "Connection"
    Peer = bindSym "Peer"
    Eth2Node = bindSym "Eth2Node"
    registerMsg = bindSym "registerMsg"
    initProtocol = bindSym "initProtocol"
    msgVar = ident "msg"
    networkVar = ident "network"
    callUserHandler = ident "callUserHandler"
    noSnappyVar = ident "noSnappy"
    MSG = ident "MSG"

  p.useRequestIds = false
  p.useSingleRecordInlining = true

  new result

  result.PeerType = Peer
  result.NetworkType = Eth2Node
  result.registerProtocol = bindSym "registerProtocol"
  result.setEventHandlers = bindSym "setEventHandlers"
  result.SerializationFormat = Format
  result.RequestResultsWrapper = ident "NetRes"

  result.afterProtocolInit = proc (p: P2PProtocol) =
    p.onPeerConnected.params.add newIdentDefs(streamVar, Connection)

  result.implementMsg = proc (msg: p2p_protocol_dsl.Message) =
    if msg.kind == msgResponse:
      return

    let
      protocol = msg.protocol
      msgName = $msg.ident
      msgNameLit = newLit msgName
      MsgRecName = msg.recName
      MsgStrongRecName = msg.strongRecName
      codecNameLit = getRequestProtoName(msg.procDef)
      protocolMounterName = ident(msgName & "Mounter")

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
    var userHandlerCall = newTree(nnkDiscardStmt)

    if msg.userHandler != nil:
      var OutputParamType = if msg.kind == msgRequest: msg.outputParamType
                            else: nil

      if OutputParamType == nil:
        userHandlerCall = msg.genUserHandlerCall(msgVar, [peerVar])
        if msg.kind == msgRequest:
          userHandlerCall = newCall(ident"sendUserHandlerResultAsChunkImpl",
                                    streamVar,
                                    noSnappyVar,
                                    userHandlerCall)
      else:
        if OutputParamType.kind == nnkVarTy:
          OutputParamType = OutputParamType[0]

        let isChunkStream = eqIdent(OutputParamType[0], "MultipleChunksResponse")
        msg.response.recName = if isChunkStream:
          newTree(nnkBracketExpr, ident"seq", OutputParamType[1])
        else:
          OutputParamType[1]

        let responseVar = ident("response")
        userHandlerCall = newStmtList(
          newVarStmt(responseVar,
                     newCall(ident"init", OutputParamType,
                                          peerVar, streamVar, noSnappyVar)),
          msg.genUserHandlerCall(msgVar, [peerVar], outputParam = responseVar))

    protocol.outRecvProcs.add quote do:
      template `callUserHandler`(`MSG`: type `MsgStrongRecName`,
                                 `peerVar`: `Peer`,
                                 `streamVar`: `Connection`,
                                 `noSnappyVar`: bool,
                                 `msgVar`: `MsgRecName`): untyped =
        `userHandlerCall`

      proc `protocolMounterName`(`networkVar`: `Eth2Node`) =
        proc sszThunk(`streamVar`: `Connection`,
                      `protocolVar`: string): Future[void] {.gcsafe.} =
          return handleIncomingStream(`networkVar`, `streamVar`, true,
                                      `MsgStrongRecName`)

        mount `networkVar`.switch,
              LPProtocol(codec: `codecNameLit` & "ssz",
                         handler: sszThunk)

        proc snappyThunk(`streamVar`: `Connection`,
                         `protocolVar`: string): Future[void] {.gcsafe.} =
          return handleIncomingStream(`networkVar`, `streamVar`, false,
                                      `MsgStrongRecName`)

        mount `networkVar`.switch,
              LPProtocol(codec: `codecNameLit` & "ssz_snappy",
                         handler: snappyThunk)

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
              protocolMounterName,
              codecNameLit))

  result.implementProtocolInit = proc (p: P2PProtocol): NimNode =
    return newCall(initProtocol, newLit(p.name), p.peerInit, p.netInit)

proc setupNat(conf: BeaconNodeConf): tuple[ip: Option[ValidIpAddress],
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
      if conf.nat.startsWith("extip:"):
        try:
          # any required port redirection is assumed to be done by hand
          result.ip = some(ValidIpAddress.init(conf.nat[6..^1]))
          nat = NatNone
        except ValueError:
          error "nor a valid IP address", address = conf.nat[6..^1]
          quit QuitFailure
      else:
        error "not a valid NAT mechanism", value = conf.nat
        quit QuitFailure

  if nat != NatNone:
    let extIp = getExternalIP(nat)
    if extIP.isSome:
      result.ip = some(ValidIpAddress.init extIp.get)
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
  MultiAddress.init(address, tcpProtocol, port)

proc getPersistentNetKeys*(conf: BeaconNodeConf): KeyPair =
  let
    privKeyPath = conf.dataDir / networkKeyFilename
    privKey =
      if not fileExists(privKeyPath):
        createDir conf.dataDir.string
        let key = PrivateKey.random(Secp256k1).tryGet()
        writeFile(privKeyPath, key.getBytes().tryGet())
        key
      else:
        let keyBytes = readFile(privKeyPath)
        PrivateKey.init(keyBytes.toOpenArrayByte(0, keyBytes.high)).tryGet()

  KeyPair(seckey: privKey, pubkey: privKey.getKey().tryGet())

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
                                 sign = false, verifySignature = false,
                                 transportFlags = {ServerFlags.ReuseAddr})
  result = Eth2Node.init(conf, enrForkId, switch,
                         extIp, extTcpPort, extUdpPort,
                         keys.seckey.asEthKey)

proc getPersistenBootstrapAddr*(conf: BeaconNodeConf,
                                ip: ValidIpAddress, port: Port): EnrResult[enr.Record] =
  let pair = getPersistentNetKeys(conf)
  return enr.Record.init(1'u64, # sequence number
                         pair.seckey.asEthKey,
                         some(ip), port, port, @[])

proc announcedENR*(node: Eth2Node): enr.Record =
  doAssert node.discovery != nil, "The Eth2Node must be initialized"
  node.discovery.localNode.record

proc shortForm*(id: KeyPair): string =
  $PeerID.init(id.pubkey)

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
      trace "Outgoing pubsub message sent", message_id = `$`(digest)

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
