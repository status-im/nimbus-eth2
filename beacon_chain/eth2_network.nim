import
  # Std lib
  std/[typetraits, strutils, os, algorithm, sequtils, math, sets],
  std/options as stdOptions,

  # Status libs
  stew/[varints, base58, base64, endians2, results, byteutils], bearssl,
  stew/shims/net as stewNet,
  stew/shims/[macros, tables],
  faststreams/[inputs, outputs, buffers], snappy, snappy/framing,
  json_serialization, json_serialization/std/[net, options],
  chronos, chronicles, metrics,
  # TODO: create simpler to use libp2p modules that use re-exports
  libp2p/[switch, standard_setup, peerinfo,
          multiaddress, multicodec, crypto/crypto, crypto/secp,
          protocols/identify, protocols/protocol],
  libp2p/protocols/secure/[secure, secio],
  libp2p/protocols/pubsub/[pubsub, floodsub, rpc/message, rpc/messages],
  libp2p/transports/tcptransport,
  libp2p/stream/lpstream,
  eth/[keys, async_utils], eth/p2p/p2p_protocol_dsl,
  eth/net/nat, eth/p2p/discoveryv5/[enr, node],
  # Beacon node modules
  version, conf, eth2_discovery, libp2p_json_serialization, conf,
  ssz/ssz_serialization,
  peer_pool, spec/[datatypes, network], ./time

export
  version, multiaddress, peer_pool, peerinfo, p2pProtocol,
  libp2p_json_serialization, ssz_serialization, results

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
    peerId*: PeerID
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
    connQueue: AsyncQueue[PeerAddr]
    seenTable: Table[PeerID, SeenItem]
    connWorkers: seq[Future[void]]
    connTable: HashSet[PeerID]
    forkId: ENRForkID
    rng*: ref BrHmacDrbgContext
    peers: Table[PeerID, Peer]

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

  Eth2MetaData* = object
    seq_number*: uint64
    attnets*: BitArray[ATTESTATION_SUBNET_COUNT]

  ENRForkID* = object
    fork_digest*: ForkDigest
    next_fork_version*: Version
    next_fork_epoch*: Epoch

  AverageThroughput* = object
    count*: uint64
    average*: float

  Peer* = ref object
    network*: Eth2Node
    info*: PeerInfo
    discoveryId*: Eth2DiscoveryId
    connectionState*: ConnectionState
    protocolStates*: seq[RootRef]
    maxInactivityAllowed*: Duration
    netThroughput: AverageThroughput
    score*: int
    connections*: int
    disconnectedFut: Future[void]

  PeerAddr* = object
    peerId*: PeerID
    addrs*: seq[MultiAddress]

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  UntypedResponse = ref object
    peer*: Peer
    stream*: Connection
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
    onPeerConnected*: OnPeerConnectedHandler
    onPeerDisconnected*: OnPeerDisconnectedHandler

  ProtocolInfo* = ptr ProtocolInfoObj

  ResponseCode* = enum
    Success
    InvalidRequest
    ServerError

  PeerStateInitializer* = proc(peer: Peer): RootRef {.gcsafe.}
  NetworkStateInitializer* = proc(network: EthereumNode): RootRef {.gcsafe.}
  OnPeerConnectedHandler* = proc(peer: Peer, incoming: bool): Future[void] {.gcsafe.}
  OnPeerDisconnectedHandler* = proc(peer: Peer): Future[void] {.gcsafe.}
  ThunkProc* = LPProtoHandler
  MounterProc* = proc(network: Eth2Node) {.gcsafe.}
  MessageContentPrinter* = proc(msg: pointer): string {.gcsafe.}

  DisconnectionReason* = enum
    # might see other values on the wire!
    ClientShutDown = 1
    IrrelevantNetwork = 2
    FaultOrError = 3

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
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#eth2-network-interaction-domains
  MAX_CHUNK_SIZE* = 1 * 1024 * 1024 # bytes
  GOSSIP_MAX_SIZE* = 1 * 1024 * 1024 # bytes
  TTFB_TIMEOUT* = 5.seconds
  RESP_TIMEOUT* = 10.seconds

  NewPeerScore* = 200
    ## Score which will be assigned to new connected Peer
  PeerScoreLowLimit* = 0
    ## Score after which peer will be kicked
  PeerScoreHighLimit* = 1000
    ## Max value of peer's score

  ConcurrentConnections* = 4
    ## Maximum number of active concurrent connection requests.

  SeenTableTimeTimeout* =
    when not defined(local_testnet): 5.minutes else: 10.seconds

    ## Seen period of time for timeout connections
  SeenTableTimeDeadPeer* =
    when not defined(local_testnet): 5.minutes else: 10.seconds

    ## Period of time for dead peers.
  SeenTableTimeIrrelevantNetwork* = 24.hours
    ## Period of time for `IrrelevantNetwork` error reason.
  SeenTableTimeClientShutDown* = 10.minutes
    ## Period of time for `ClientShutDown` error reason.
  SeemTableTimeFaultOrError* = 10.minutes
    ## Period of time for `FaultOnError` error reason.

var successfullyDialledAPeer = false # used to show a warning

template neterr(kindParam: Eth2NetworkingErrorKind): auto =
  err(type(result), Eth2NetworkingError(kind: kindParam))

# Metrics for tracking attestation and beacon block loss
declareCounter nbc_gossip_messages_sent,
  "Number of gossip messages sent by this peer"

declareCounter nbc_gossip_messages_received,
  "Number of gossip messages received by this peer"

declarePublicCounter nbc_successful_dials,
  "Number of successfully dialed peers"

declarePublicCounter nbc_failed_dials,
  "Number of dialing attempts that failed"

declarePublicCounter nbc_timeout_dials,
  "Number of dialing attempts that exceeded timeout"

declarePublicGauge nbc_peers,
  "Number of active libp2p peers"

proc safeClose(conn: Connection) {.async.} =
  if not conn.closed:
    await close(conn)

const
  snappy_implementation {.strdefine.} = "libp2p"

const useNativeSnappy = when snappy_implementation == "native": true
                        elif snappy_implementation == "libp2p": false
                        else: {.fatal: "Please set snappy_implementation to either 'libp2p' or 'native'".}

const
  libp2p_pki_schemes {.strdefine.} = ""

when libp2p_pki_schemes != "secp256k1":
  {.fatal: "Incorrect building process, please use -d:\"libp2p_pki_schemes=secp256k1\"".}

template libp2pProtocol*(name: string, version: int) {.pragma.}

template `$`*(peer: Peer): string = id(peer.info)
chronicles.formatIt(Peer): $it

template remote*(peer: Peer): untyped =
  peer.info.peerId

proc openStream(node: Eth2Node,
                peer: Peer,
                protocolId: string): Future[Connection] {.async.} =
  let
    protocolId = protocolId & "ssz_snappy"
    conn = await dial(
      node.switch, peer.info.peerId, peer.info.addrs, protocolId)

  # libp2p may replace peerinfo ref sometimes, so make sure we have a recent
  # one
  if conn.peerInfo != nil:
    peer.info = conn.peerInfo

  return conn

proc init*(T: type Peer, network: Eth2Node, info: PeerInfo): Peer {.gcsafe.}

proc getPeer*(node: Eth2Node, peerId: PeerID): Peer {.gcsafe.} =
  node.peers.withValue(peerId, peer) do:
    return peer[]
  do:
    let peer = Peer.init(node, PeerInfo.init(peerId))
    return node.peers.mGetOrPut(peerId, peer)

proc peerFromStream(network: Eth2Node, conn: Connection): Peer =
  # TODO: Can this be `nil`?
  return network.getPeer(conn.peerInfo.peerId)

proc getKey*(peer: Peer): PeerID {.inline.} =
  result = peer.info.peerId

proc getFuture*(peer: Peer): Future[void] {.inline.} =
  if peer.disconnectedFut.isNil:
    peer.disconnectedFut = newFuture[void]()
  result = peer.disconnectedFut

proc getScore*(a: Peer): int =
  ## Returns current score value for peer ``peer``.
  result = a.score

proc updateScore*(peer: Peer, score: int) {.inline.} =
  ## Update peer's ``peer`` score with value ``score``.
  peer.score = peer.score + score
  if peer.score > PeerScoreHighLimit:
    peer.score = PeerScoreHighLimit

proc calcThroughput(dur: Duration, value: uint64): float {.inline.} =
  let secs = float(chronos.seconds(1).nanoseconds)
  if isZero(dur):
    0.0
  else:
    float(value) * (secs / float(dur.nanoseconds))

proc updateNetThroughput*(peer: Peer, dur: Duration,
                          bytesCount: uint64) {.inline.} =
  ## Update peer's ``peer`` network throughput.
  let bytesPerSecond = calcThroughput(dur, bytesCount)
  let a = peer.netThroughput.average
  let n = peer.netThroughput.count
  peer.netThroughput.average = a + (bytesPerSecond - a) / float(n + 1)
  inc(peer.netThroughput.count)

proc netBps*(peer: Peer): float {.inline.} =
  ## Returns current network throughput average value in Bps for peer ``peer``.
  round((peer.netThroughput.average * 10_000) / 10_000)

proc netKbps*(peer: Peer): float {.inline.} =
  ## Returns current network throughput average value in Kbps for peer ``peer``.
  round(((peer.netThroughput.average / 1024) * 10_000) / 10_000)

proc netMbps*(peer: Peer): float {.inline.} =
  ## Returns current network throughput average value in Mbps for peer ``peer``.
  round(((peer.netThroughput.average / (1024 * 1024)) * 10_000) / 10_000)

proc `<`*(a, b: Peer): bool =
  ## Comparison function, which first checks peer's scores, and if the peers'
  ## score is equal it compares peers' network throughput.
  if a.score < b.score:
    true
  elif a.score == b.score:
    (a.netThroughput.average < b.netThroughput.average)
  else:
    false

proc isSeen*(network: ETh2Node, peerId: PeerID): bool =
  let currentTime = now(chronos.Moment)
  if peerId notin network.seenTable:
    return false
  let item = network.seenTable[peerId]
  if currentTime >= item.stamp:
    # Peer is in SeenTable, but the time period has expired.
    network.seenTable.del(peerId)
    return false
  return true

proc addSeen*(network: ETh2Node, peerId: PeerID,
              period: chronos.Duration) =
  let item = SeenItem(peerId: peerId, stamp: now(chronos.Moment) + period)
  network.seenTable[peerId] = item

proc disconnect*(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    await peer.network.switch.disconnect(peer.info.peerId)
    peer.connectionState = Disconnected
    peer.network.peerPool.release(peer)
    let seenTime = case reason
      of ClientShutDown:
        SeenTableTimeClientShutDown
      of IrrelevantNetwork:
        SeenTableTimeIrrelevantNetwork
      of FaultOrError:
        SeemTableTimeFaultOrError
    peer.network.addSeen(peer.info.peerId, seenTime)

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
                 payload: Bytes) {.async.} =
  var output = memoryOutput()

  if responseCode.isSome:
    output.write byte(responseCode.get)

  output.write varintBytes(payload.lenu64)
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
                       responseCode: ResponseCode,
                       errMsg: ErrorMsg) {.async.} =
  debug "Error processing request",
    peer, responseCode, errMsg = formatErrorMsg(errMsg)
  await conn.writeChunk(some responseCode, SSZ.encode(errMsg))

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
    await stream.writeChunk(none ResponseCode, requestBytes)
  finally:
    await safeClose(stream)

proc sendResponseChunkBytes(response: UntypedResponse, payload: Bytes) {.async.} =
  inc response.writtenChunks
  await response.stream.writeChunk(some Success, payload)

proc sendResponseChunkObj(response: UntypedResponse, val: auto) {.async.} =
  inc response.writtenChunks
  await response.stream.writeChunk(some Success, SSZ.encode(val))

template sendUserHandlerResultAsChunkImpl*(stream: Connection,
                                           handlerResultFut: Future): untyped =
  let handlerRes = await handlerResultFut
  writeChunk(stream, some Success, SSZ.encode(handlerRes))

template sendUserHandlerResultAsChunkImpl*(stream: Connection,
                                           handlerResult: auto): untyped =
  writeChunk(stream, some Success, SSZ.encode(handlerResult))

when useNativeSnappy:
  include faststreams_backend
else:
  include libp2p_streams_backend

proc makeEth2Request(peer: Peer, protocolId: string, requestBytes: Bytes,
                     ResponseMsg: type,
                     timeout: Duration): Future[NetRes[ResponseMsg]]
                    {.gcsafe, async.} =
  var deadline = sleepAsync timeout

  let stream = awaitWithTimeout(peer.network.openStream(peer, protocolId),
                                deadline): return neterr StreamOpenTimeout
  try:
    # Send the request
    await stream.writeChunk(none ResponseCode, requestBytes)

    # Read the response
    return awaitWithTimeout(
      readResponse(when useNativeSnappy: libp2pInput(stream) else: stream,
                   peer, ResponseMsg),
      deadline, neterr(ReadResponseTimeout))
  finally:
    await safeClose(stream)

proc init*[MsgType](T: type MultipleChunksResponse[MsgType],
                    peer: Peer, conn: Connection): T =
  T(UntypedResponse(peer: peer, stream: conn))

proc init*[MsgType](T: type SingleChunkResponse[MsgType],
                    peer: Peer, conn: Connection): T =
  T(UntypedResponse(peer: peer, stream: conn))

template write*[M](r: MultipleChunksResponse[M], val: auto): untyped =
  sendResponseChunkObj(UntypedResponse(r), val)

template send*[M](r: SingleChunkResponse[M], val: auto): untyped =
  doAssert UntypedResponse(r).writtenChunks == 0
  sendResponseChunkObj(UntypedResponse(r), val)

proc performProtocolHandshakes*(peer: Peer, incoming: bool) {.async.} =
  # Loop down serially because it's easier to reason about the connection state
  # when there are fewer async races, specially during setup
  for protocol in allProtocols:
    if protocol.onPeerConnected != nil:
      await protocol.onPeerConnected(peer, incoming)

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
                      onPeerConnected: OnPeerConnectedHandler,
                      onPeerDisconnected: OnPeerDisconnectedHandler) =
  p.onPeerConnected = onPeerConnected
  p.onPeerDisconnected = onPeerDisconnected

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

    # TODO peer connection setup is broken, update info in some better place
    #      whenever race is fix:
    #      https://github.com/status-im/nim-beacon-chain/issues/1157
    peer.info = conn.peerInfo

    template returnInvalidRequest(msg: ErrorMsg) =
      await sendErrorResponse(peer, conn, InvalidRequest, msg)
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
        awaitWithTimeout(readChunkPayload(s, peer, MsgRec), deadline):
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

      await sendErrorResponse(peer, conn, responseCode, errMsg)
      return

    try:
      logReceivedMsg(peer, MsgType(msg.get))
      await callUserHandler(MsgType, peer, conn, msg.get)
    except CatchableError as err:
      await sendErrorResponse(peer, conn, ServerError,
                              ErrorMsg err.msg.toBytes)

  except CatchableError as err:
    debug "Error processing an incoming request", err = err.msg, msgName

  finally:
    await safeClose(conn)

proc handleOutgoingPeer(peer: Peer): Future[bool] {.async.} =
  let network = peer.network

  proc onPeerClosed(udata: pointer) {.gcsafe.} =
    debug "Peer (outgoing) lost", peer
    nbc_peers.set int64(len(network.peerPool))

  let res = await network.peerPool.addOutgoingPeer(peer)
  if res:
    peer.updateScore(NewPeerScore)
    debug "Peer (outgoing) has been added to PeerPool", peer
    peer.getFuture().addCallback(onPeerClosed)
    result = true

  nbc_peers.set int64(len(network.peerPool))

proc handleIncomingPeer(peer: Peer): Future[bool] {.async.} =
  let network = peer.network

  proc onPeerClosed(udata: pointer) {.gcsafe.} =
    debug "Peer (incoming) lost", peer
    nbc_peers.set int64(len(network.peerPool))

  let res = await network.peerPool.addIncomingPeer(peer)
  if res:
    peer.updateScore(NewPeerScore)
    debug "Peer (incoming) has been added to PeerPool", peer
    peer.getFuture().addCallback(onPeerClosed)
    result = true

  nbc_peers.set int64(len(network.peerPool))

proc toPeerAddr*(r: enr.TypedRecord):
    Result[PeerAddr, cstring] {.raises: [Defect].} =
  if not r.secp256k1.isSome:
    return err("enr: no secp256k1 key in record")

  let
    pubKey = ? keys.PublicKey.fromRaw(r.secp256k1.get)
    peerId = ? PeerID.init(crypto.PublicKey(
      scheme: Secp256k1, skkey: secp.SkPublicKey(pubKey)))

  var addrs = newSeq[MultiAddress]()

  if r.ip.isSome and r.tcp.isSome:
    let ip = ipv4(r.ip.get)
    addrs.add MultiAddress.init(ip, tcpProtocol, Port r.tcp.get)

  if r.ip6.isSome:
    let ip = ipv6(r.ip6.get)
    if r.tcp6.isSome:
      addrs.add MultiAddress.init(ip, tcpProtocol, Port r.tcp6.get)
    elif r.tcp.isSome:
      addrs.add MultiAddress.init(ip, tcpProtocol, Port r.tcp.get)
    else:
      discard

  if addrs.len == 0:
    return err("enr: no addresses in record")

  ok(PeerAddr(peerId: peerId, addrs: addrs))

proc dialPeer*(node: Eth2Node, peerAddr: PeerAddr) {.async.} =
  logScope: peer = peerAddr.peerId

  debug "Connecting to discovered peer"

  # TODO connect is called here, but there's no guarantee that the connection
  #      we get when using dialPeer later on is the one we just connected
  let peer = node.getPeer(peerAddr.peerId)

  await node.switch.connect(peerAddr.peerId, peerAddr.addrs)

  #let msDial = newMultistream()
  #let conn = node.switch.connections.getOrDefault(peerInfo.id)
  #let ls = await msDial.list(conn)
  #debug "Supported protocols", ls

  inc nbc_successful_dials
  successfullyDialledAPeer = true
  debug "Network handshakes completed"

proc connectWorker(network: Eth2Node) {.async.} =
  debug "Connection worker started"

  while true:
    let
      remotePeerAddr = await network.connQueue.popFirst()
      peerPoolHasRemotePeer = network.peerPool.hasPeer(remotePeerAddr.peerId)
      seenTableHasRemotePeer = network.isSeen(remotePeerAddr.peerId)
      remotePeerAlreadyConnected = remotePeerAddr.peerId in network.connTable

    if not(peerPoolHasRemotePeer) and not(seenTableHasRemotePeer) and not(remotePeerAlreadyConnected):
      network.connTable.incl(remotePeerAddr.peerId)
      try:
        # We trying to connect to peers which are not in PeerPool, SeenTable and
        # ConnTable.
        var fut = network.dialPeer(remotePeerAddr)
        # We discarding here just because we going to check future state, to avoid
        # condition where connection happens and timeout reached.
        discard await withTimeout(fut, network.connectTimeout)
        # We handling only timeout and errors, because successfull connections
        # will be stored in PeerPool.
        if fut.finished():
          if fut.failed() and not(fut.cancelled()):
            debug "Unable to establish connection with peer", peer = remotePeerAddr.peerId,
                  errMsg = fut.readError().msg
            inc nbc_failed_dials
            network.addSeen(remotePeerAddr.peerId, SeenTableTimeDeadPeer)
          continue
        debug "Connection to remote peer timed out", peer = remotePeerAddr.peerId
        inc nbc_timeout_dials
        network.addSeen(remotePeerAddr.peerId, SeenTableTimeTimeout)
      finally:
        network.connTable.excl(remotePeerAddr.peerId)
    else:
      trace "Peer is already connected, connecting or already seen",
            peer = remotePeerAddr.peerId, peer_pool_has_peer = $peerPoolHasRemotePeer, seen_table_has_peer = $seenTableHasRemotePeer,
            connecting_peer = $remotePeerAlreadyConnected, seen_table_size = len(network.seenTable)

    # Prevent (a purely theoretical) high CPU usage when losing connectivity.
    await sleepAsync(1.seconds)

proc runDiscoveryLoop*(node: Eth2Node) {.async.} =
  debug "Starting discovery loop"

  let enrField = ("eth2", SSZ.encode(node.forkId))
  while true:
    let currentPeerCount = node.peerPool.len
    if currentPeerCount < node.wantedPeers:
      try:
        let discoveredPeers =
          node.discovery.randomNodes(node.wantedPeers - currentPeerCount,
            enrField)
        for peer in discoveredPeers:
          try:
            let peerRecord = peer.record.toTypedRecord
            if peerRecord.isOk:
              let peerAddr = peerRecord.value.toPeerAddr
              if peerAddr.isOk:
                if not node.switch.isConnected(peerAddr.get().peerId):
                  await node.connQueue.addLast(peerAddr.get())
                else:
                  discard # peerInfo.close()
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

proc onConnEvent(node: Eth2Node, peerId: PeerID, event: ConnEvent) {.async.} =
  let peer = node.getPeer(peerId)
  case event.kind
  of ConnEventKind.Connected:
    inc peer.connections
    debug "Peer upgraded", peer = peerId, connections = peer.connections

    if peer.connections == 1:
      # Libp2p may connect multiple times to the same peer - using different
      # transports or both incoming and outgoing. For now, we'll count our
      # "fist" encounter with the peer as the true connection, leaving the
      # other connections be - libp2p limits the number of concurrent
      # connections to the same peer, and only one of these connections will be
      # active. Nonetheless, this quirk will cause a number of odd behaviours:
      # * For peer limits, we might miscount the incoming vs outgoing quota
      # * Protocol handshakes are wonky: we'll not necessarily use the newly
      #   connected transport - instead we'll just pick a random one!
      await performProtocolHandshakes(peer, event.incoming)

      # While performing the handshake, the peer might have been disconnected -
      # there's still a slim chance of a race condition here if a reconnect
      # happens quickly
      if peer.connections == 1:

        # TODO when the pool is full, adding it will block - this means peers
        #      will be left in limbo until some other peer makes room for it
        let added = if event.incoming:
          await handleIncomingPeer(peer)
        else:
          await handleOutgoingPeer(peer)

        if not added:
          # We must have hit a limit!
          await peer.disconnect(FaultOrError)

  of ConnEventKind.Disconnected:
    dec peer.connections
    debug "Peer disconnected", peer = peerId, connections = peer.connections
    if peer.connections == 0:
      let fut = peer.disconnectedFut
      if fut != nil:
        peer.disconnectedFut = nil
        fut.complete()

proc init*(T: type Eth2Node, conf: BeaconNodeConf, enrForkId: ENRForkID,
           switch: Switch, ip: Option[ValidIpAddress], tcpPort, udpPort: Port,
           privKey: keys.PrivateKey, rng: ref BrHmacDrbgContext): T =
  new result
  result.switch = switch
  result.wantedPeers = conf.maxPeers
  result.peerPool = newPeerPool[Peer, PeerID](maxPeers = conf.maxPeers)
  when not defined(local_testnet):
    result.connectTimeout = 1.minutes
    result.seenThreshold = 5.minutes
  else:
    result.connectTimeout = 10.seconds
    result.seenThreshold = 10.seconds
  result.seenTable = initTable[PeerID, SeenItem]()
  result.connTable = initHashSet[PeerID]()
  result.connQueue = newAsyncQueue[PeerAddr](ConcurrentConnections)
  result.metadata = getPersistentNetMetadata(conf)
  result.forkId = enrForkId
  result.discovery = Eth2DiscoveryProtocol.new(
    conf, ip, tcpPort, udpPort, privKey,
    {"eth2": SSZ.encode(result.forkId), "attnets": SSZ.encode(result.metadata.attnets)},
    rng)

  newSeq result.protocolStates, allProtocols.len
  for proto in allProtocols:
    if proto.networkStateInitializer != nil:
      result.protocolStates[proto.index] = proto.networkStateInitializer(result)

    for msg in proto.messages:
      if msg.protocolMounter != nil:
        msg.protocolMounter result

  let node = result
  proc peerHook(peerId: PeerID, event: ConnEvent): Future[void] {.gcsafe.} =
    onConnEvent(node, peerId, event)

  switch.addConnEventHandler(peerHook, ConnEventKind.Connected)
  switch.addConnEventHandler(peerHook, ConnEventKind.Disconnected)

template publicKey*(node: Eth2Node): keys.PublicKey =
  node.discovery.privKey.toPublicKey

proc startListening*(node: Eth2Node) {.async.} =
  node.discovery.open()
  node.libp2pTransportLoops = await node.switch.start()

proc start*(node: Eth2Node) {.async.} =
  for i in 0 ..< ConcurrentConnections:
    node.connWorkers.add connectWorker(node)

  node.discovery.start()
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
                                          peerVar, streamVar)),
          msg.genUserHandlerCall(msgVar, [peerVar], outputParam = responseVar))

    protocol.outRecvProcs.add quote do:
      template `callUserHandler`(`MSG`: type `MsgStrongRecName`,
                                 `peerVar`: `Peer`,
                                 `streamVar`: `Connection`,
                                 `msgVar`: `MsgRecName`): untyped =
        `userHandlerCall`

      proc `protocolMounterName`(`networkVar`: `Eth2Node`) =
        proc snappyThunk(`streamVar`: `Connection`,
                         `protocolVar`: string): Future[void] {.gcsafe.} =
          return handleIncomingStream(`networkVar`, `streamVar`,
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

proc getPersistentNetKeys*(
    rng: var BrHmacDrbgContext, conf: BeaconNodeConf): KeyPair =
  let
    privKeyPath = conf.dataDir / networkKeyFilename
    privKey =
      if not fileExists(privKeyPath):
        createDir conf.dataDir.string
        let key = PrivateKey.random(Secp256k1, rng).tryGet()
        writeFile(privKeyPath, key.getBytes().tryGet())
        key
      else:
        let keyBytes = readFile(privKeyPath)
        PrivateKey.init(keyBytes.toOpenArrayByte(0, keyBytes.high)).tryGet()

  KeyPair(seckey: privKey, pubkey: privKey.getKey().tryGet())

func gossipId(data: openArray[byte]): string =
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#topics-and-messages
  base64.encode(Base64Url, sha256.digest(data).data)

func msgIdProvider(m: messages.Message): string =
  gossipId(m.data)

proc createEth2Node*(rng: ref BrHmacDrbgContext, conf: BeaconNodeConf, enrForkId: ENRForkID): Eth2Node {.gcsafe.} =
  var
    (extIp, extTcpPort, extUdpPort) = setupNat(conf)
    hostAddress = tcpEndPoint(conf.libp2pAddress, conf.tcpPort)
    announcedAddresses = if extIp.isNone(): @[]
                         else: @[tcpEndPoint(extIp.get(), extTcpPort)]

  info "Initializing networking", hostAddress,
                                  announcedAddresses

  let keys = getPersistentNetKeys(rng[], conf)
  # TODO nim-libp2p still doesn't have support for announcing addresses
  # that are different from the host address (this is relevant when we
  # are running behind a NAT).
  var switch = newStandardSwitch(some keys.seckey, hostAddress,
                                 triggerSelf = true, gossip = true,
                                 sign = false, verifySignature = false,
                                 transportFlags = {ServerFlags.ReuseAddr},
                                 msgIdProvider = msgIdProvider,
                                 secureManagers = [
                                   SecureProtocol.Noise, # Only noise in ETH2!
                                 ],
                                 rng = rng)
  result = Eth2Node.init(conf, enrForkId, switch,
                         extIp, extTcpPort, extUdpPort,
                         keys.seckey.asEthKey, rng = rng)

proc getPersistenBootstrapAddr*(rng: var BrHmacDrbgContext, conf: BeaconNodeConf,
                                ip: ValidIpAddress, port: Port): EnrResult[enr.Record] =
  let pair = getPersistentNetKeys(rng, conf)
  return enr.Record.init(1'u64, # sequence number
                         pair.seckey.asEthKey,
                         some(ip), port, port, @[])

proc announcedENR*(node: Eth2Node): enr.Record =
  doAssert node.discovery != nil, "The Eth2Node must be initialized"
  node.discovery.localNode.record

proc shortForm*(id: KeyPair): string =
  $PeerID.init(id.pubkey)

let BOOTSTRAP_NODE_CHECK_INTERVAL = 30.seconds
proc checkIfConnectedToBootstrapNode(p: pointer) {.gcsafe.} =
  # Keep showing warnings until we connect to at least one bootstrap node
  # successfully, in order to allow detection of an invalid configuration.
  let node = cast[Eth2Node](p)
  if node.discovery.bootstrapRecords.len > 0 and not successfullyDialledAPeer:
    warn "Failed to connect to any bootstrap node",
      bootstrapEnrs = node.discovery.bootstrapRecords
    addTimer(BOOTSTRAP_NODE_CHECK_INTERVAL, checkIfConnectedToBootstrapNode, p)

proc startLookingForPeers*(node: Eth2Node) {.async.} =
  await node.start()
  addTimer(BOOTSTRAP_NODE_CHECK_INTERVAL, checkIfConnectedToBootstrapNode, node[].addr)

func peersCount*(node: Eth2Node): int =
  len(node.peerPool)

proc subscribe*[MsgType](node: Eth2Node,
                         topic: string,
                         msgHandler: proc(msg: MsgType) {.gcsafe.} ) {.async, gcsafe.} =
  proc execMsgHandler(topic: string, data: seq[byte]) {.async, gcsafe.} =
    inc nbc_gossip_messages_received
    trace "Incoming pubsub message received",
      len = data.len, topic, msgId = gossipId(data)
    try:
      msgHandler SSZ.decode(snappy.decode(data), MsgType)
    except CatchableError as err:
      debug "Gossip msg handler error",
        msg = err.msg, len = data.len, topic, msgId = gossipId(data)

  await node.switch.subscribe(topic & "_snappy", execMsgHandler)

proc addValidator*[MsgType](node: Eth2Node,
                            topic: string,
                            msgValidator: proc(msg: MsgType): bool {.gcsafe.} ) =
  # Validate messages as soon as subscribed
  proc execValidator(
      topic: string, message: GossipMsg): Future[bool] {.async, gcsafe.} =
    trace "Validating incoming gossip message",
      len = message.data.len, topic, msgId = gossipId(message.data)
    try:
      return msgValidator SSZ.decode(snappy.decode(message.data), MsgType)
    except CatchableError as err:
      debug "Gossip validation error",
        msg = err.msg, msgId = gossipId(message.data)
      return false

  node.switch.addValidator(topic & "_snappy", execValidator)

proc subscribe*[MsgType](node: Eth2Node,
                         topic: string,
                         msgHandler: proc(msg: MsgType) {.gcsafe.},
                         msgValidator: proc(msg: MsgType): bool {.gcsafe.} ) {.async, gcsafe.} =
  node.addValidator(topic, msgValidator)
  await node.subscribe(topic, msgHandler)

proc unsubscribe*(node: Eth2Node, topic: string): Future[void] =
  node.switch.unsubscribeAll(topic)

proc traceMessage(fut: FutureBase, msgId: string) =
  fut.addCallback do (arg: pointer):
    if not(fut.failed):
      trace "Outgoing pubsub message sent", msgId
    elif fut.error != nil:
      debug "Gossip message not sent", msgId, err = fut.error.msg
    else:
      debug "Unexpected future state for gossip", msgId, state = fut.state

proc broadcast*(node: Eth2Node, topic: string, msg: auto) =
  inc nbc_gossip_messages_sent
  let
    data = snappy.encode(SSZ.encode(msg))
  var futSnappy = node.switch.publish(topic & "_snappy", data, 1.minutes)
  traceMessage(futSnappy, gossipId(data))
