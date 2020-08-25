import
  # Std lib
  std/[typetraits, strutils, os, algorithm, math, sets],
  std/options as stdOptions,

  # Status libs
  stew/[varints, base58, base64, endians2, results, byteutils, io2], bearssl,
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
  libp2p/protocols/pubsub/[pubsub, rpc/message, rpc/messages],
  libp2p/transports/tcptransport,
  libp2p/stream/connection,
  eth/[keys, async_utils], eth/p2p/p2p_protocol_dsl,
  eth/net/nat, eth/p2p/discoveryv5/[enr, node],
  # Beacon node modules
  version, conf, eth2_discovery, libp2p_json_serialization, conf,
  ssz/ssz_serialization,
  peer_pool, spec/[datatypes, network], ./time,
  keystore_management

when defined(nbc_gossipsub_11):
  import libp2p/protocols/pubsub/gossipsub
else:
  import libp2p/protocols/pubsub/gossipsub10

when chronicles.enabledLogLevel == LogLevel.TRACE:
  import std/sequtils

export
  version, multiaddress, peer_pool, peerinfo, p2pProtocol, connection,
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
    pubsub*: PubSub
    discovery*: Eth2DiscoveryProtocol
    discoveryEnabled*: bool
    wantedPeers*: int
    peerPool*: PeerPool[Peer, PeerID]
    protocolStates*: seq[RootRef]
    libp2pTransportLoops*: seq[Future[void]]
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

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.3/specs/phase0/p2p-interface.md#goodbye
  DisconnectionReason* = enum
    # might see other values on the wire!
    ClientShutDown = 1
    IrrelevantNetwork = 2
    FaultOrError = 3
    # Clients MAY use reason codes above 128 to indicate alternative,
    # erroneous request-specific responses.
    PeerScoreLow = 237 # 79 * 3

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
  nodeMetadataFilename = "node-metadata.json"

  TCP = net.Protocol.IPPROTO_TCP
  HandshakeTimeout = FaultOrError

  NewPeerScore* = 200
    ## Score which will be assigned to new connected Peer
  PeerScoreLowLimit* = 0
    ## Score after which peer will be kicked
  PeerScoreHighLimit* = 1000
    ## Max value of peer's score

  ConcurrentConnections* = 10
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
  SeenTableTimeFaultOrError* = 10.minutes
    ## Period of time for `FaultOnError` error reason.
  SeenTablePenaltyError* = 60.minutes
    ## Period of time for peers which score below or equal to zero.

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

const
  snappy_implementation {.strdefine.} = "libp2p"

const useNativeSnappy = when snappy_implementation == "native": true
                        elif snappy_implementation == "libp2p": false
                        else: {.fatal: "Please set snappy_implementation to either 'libp2p' or 'native'".}

const
  libp2p_pki_schemes {.strdefine.} = ""

when libp2p_pki_schemes != "secp256k1":
  {.fatal: "Incorrect building process, please use -d:\"libp2p_pki_schemes=secp256k1\"".}

const
  NetworkInsecureKeyPassword = "INSECUREPASSWORD"

template libp2pProtocol*(name: string, version: int) {.pragma.}

func shortLog*(peer: Peer): string = shortLog(peer.info.peerId)
chronicles.formatIt(Peer): shortLog(it)

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

proc getPeer*(node: Eth2Node, peerId: PeerID): Peer =
  node.peers.withValue(peerId, peer) do:
    return peer[]
  do:
    let peer = Peer.init(node, PeerInfo.init(peerId))
    return node.peers.mGetOrPut(peerId, peer)

proc peerFromStream(network: Eth2Node, conn: Connection): Peer =
  # TODO: Can this be `nil`?
  return network.getPeer(conn.peerInfo.peerId)

proc getKey*(peer: Peer): PeerID {.inline.} =
  peer.info.peerId

proc getFuture*(peer: Peer): Future[void] {.inline.} =
  if peer.disconnectedFut.isNil:
    peer.disconnectedFut = newFuture[void]()
  peer.disconnectedFut

proc getScore*(a: Peer): int =
  ## Returns current score value for peer ``peer``.
  a.score

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
  ## Returns ``true`` if ``peerId`` present in SeenTable and time period is not
  ## yet expired.
  let currentTime = now(chronos.Moment)
  if peerId notin network.seenTable:
    false
  else:
    let item = network.seenTable[peerId]
    if currentTime >= item.stamp:
      # Peer is in SeenTable, but the time period has expired.
      network.seenTable.del(peerId)
      false
    else:
      true

proc addSeen*(network: ETh2Node, peerId: PeerID,
              period: chronos.Duration) =
  ## Adds peer with PeerID ``peerId`` to SeenTable and timeout ``period``.
  let item = SeenItem(peerId: peerId, stamp: now(chronos.Moment) + period)
  network.seenTable[peerId] = item

proc disconnect*(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  try:
    if peer.connectionState notin {Disconnecting, Disconnected}:
      peer.connectionState = Disconnecting
      # We adding peer in SeenTable before actual disconnect to avoid races.
      let seenTime = case reason
        of ClientShutDown:
          SeenTableTimeClientShutDown
        of IrrelevantNetwork:
          SeenTableTimeIrrelevantNetwork
        of FaultOrError:
          SeenTableTimeFaultOrError
        of PeerScoreLow:
          SeenTablePenaltyError
      peer.network.addSeen(peer.info.peerId, seenTime)
      await peer.network.switch.disconnect(peer.info.peerId)
      peer.connectionState = Disconnected
  except CatchableError as exc:
    # We do not care about exceptions in disconnection procedure.
    trace "Exception while disconnecting peer", peer = peer.info.peerId,
                                                reason = reason

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
                 payload: Bytes): Future[void] =
  var output = memoryOutput()

  if responseCode.isSome:
    output.write byte(responseCode.get)

  output.write varintBytes(payload.lenu64)
  output.write(framingFormatCompress payload)

  conn.write(output.getOutput)

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
                       errMsg: ErrorMsg): Future[void] =
  debug "Error processing request",
    peer, responseCode, errMsg = formatErrorMsg(errMsg)
  conn.writeChunk(some responseCode, SSZ.encode(errMsg))

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
    await stream.close()

proc sendResponseChunkBytes(response: UntypedResponse, payload: Bytes): Future[void] =
  inc response.writtenChunks
  response.stream.writeChunk(some Success, payload)

proc sendResponseChunkObj(response: UntypedResponse, val: auto): Future[void] =
  inc response.writtenChunks
  response.stream.writeChunk(some Success, SSZ.encode(val))

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
                    {.async.} =
  var deadline = sleepAsync timeout

  let stream = awaitWithTimeout(peer.network.openStream(peer, protocolId),
                                deadline): return neterr StreamOpenTimeout
  try:
    # Send the request
    await stream.writeChunk(none ResponseCode, requestBytes)
    # Half-close the stream to mark the end of the request - if this is not
    # done, the other peer might never send us the response.
    await stream.close()

    # Read the response
    return
      await readResponse(when useNativeSnappy: libp2pInput(stream) else: stream,
                         peer, ResponseMsg, timeout)
  finally:
    await stream.closeWithEOF()

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
                          MsgType: type) {.async.} =
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
    await conn.closeWithEOF()

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

proc checkPeer(node: Eth2Node, peerAddr: PeerAddr): bool =
  logScope: peer = peerAddr.peerId
  let peerId = peerAddr.peerId
  if node.peerPool.hasPeer(peerId):
    trace "Already connected"
    false
  else:
    if node.isSeen(peerId):
      trace "Recently connected"
      false
    else:
      true

proc dialPeer*(node: Eth2Node, peerAddr: PeerAddr, index = 0) {.async.} =
  ## Establish connection with remote peer identified by address ``peerAddr``.
  logScope:
    peer = peerAddr.peerId
    index = index

  if not(node.checkPeer(peerAddr)):
    return

  debug "Connecting to discovered peer"
  var deadline = sleepAsync(node.connectTimeout)
  var workfut = node.switch.connect(peerAddr.peerId, peerAddr.addrs)

  try:
    # `or` operation will only raise exception of `workfut`, because `deadline`
    # could not raise exception.
    await workfut or deadline
    if workfut.finished():
      if not deadline.finished():
        deadline.cancel()
      inc nbc_successful_dials
    else:
      # TODO: As soon as `nim-libp2p` will be able to handle cancellation
      # properly and will have cancellation tests, we need add here cancellation
      # of `workfut`.
      # workfut.cancel()
      debug "Connection to remote peer timed out"
      inc nbc_timeout_dials
      node.addSeen(peerAddr.peerId, SeenTableTimeTimeout)
  except CatchableError as exc:
    debug "Connection to remote peer failed", msg = exc.msg
    inc nbc_failed_dials
    node.addSeen(peerAddr.peerId, SeenTableTimeDeadPeer)

proc connectWorker(node: Eth2Node, index: int) {.async.} =
  debug "Connection worker started", index = index
  while true:
    # This loop will never produce HIGH CPU usage because it will wait
    # and block until it not obtains new peer from the queue ``connQueue``.
    let remotePeerAddr = await node.connQueue.popFirst()
    await node.dialPeer(remotePeerAddr, index)
    # Peer was added to `connTable` before adding it to `connQueue`, so we
    # excluding peer here after processing.
    node.connTable.excl(remotePeerAddr.peerId)

proc toPeerAddr(node: Node): Result[PeerAddr, cstring] {.raises: [Defect].} =
  let nodeRecord = ? node.record.toTypedRecord()
  let peerAddr = ? nodeRecord.toPeerAddr()
  ok(peerAddr)

proc runDiscoveryLoop*(node: Eth2Node) {.async.} =
  debug "Starting discovery loop"
  let enrField = ("eth2", SSZ.encode(node.forkId))

  while true:
    # We always request constant number of peers to avoid problem with
    # low amount of returned peers.
    let discoveredNodes = node.discovery.randomNodes(node.wantedPeers, enrField)

    var newPeers = 0
    for discNode in discoveredNodes:
      let res = discNode.toPeerAddr()
      if res.isOk():
        let peerAddr = res.get()
        # Waiting for an empty space in PeerPool.
        while true:
          if node.peerPool.lenSpace({PeerType.Outgoing}) == 0:
            await node.peerPool.waitForEmptySpace(PeerType.Outgoing)
          else:
            break
        # Check if peer present in SeenTable or PeerPool.
        if node.checkPeer(peerAddr):
          if peerAddr.peerId notin node.connTable:
            # We adding to pending connections table here, but going
            # to remove it only in `connectWorker`.
            node.connTable.incl(peerAddr.peerId)
            await node.connQueue.addLast(peerAddr)
            inc(newPeers)
      else:
        debug "Failed to decode discovery's node address",
              node = $discnode, errMsg = res.error

    trace "Discovery tick", wanted_peers = node.wantedPeers,
          space = node.peerPool.shortLogSpace(),
          acquired = node.peerPool.shortLogAcquired(),
          available = node.peerPool.shortLogAvailable(),
          current = node.peerPool.shortLogCurrent(),
          length = len(node.peerPool),
          discovered_nodes = len(discoveredNodes),
          new_peers = newPeers

    if newPeers == 0:
      if node.peerPool.lenCurrent() <= node.wantedPeers shr 2:
        warn "Less than 25% wanted peers and could not discover new nodes",
              discovered = len(discoveredNodes), new_peers = newPeers,
              wanted_peers = node.wantedPeers
      await sleepAsync(5.seconds)
    else:
      await sleepAsync(1.seconds)

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
    debug "Peer upgraded", peer = $peerId, connections = peer.connections

    if peer.connections == 1:
      # Libp2p may connect multiple times to the same peer - using different
      # transports for both incoming and outgoing. For now, we'll count our
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
        let res =
          if event.incoming:
            node.peerPool.addPeerNoWait(peer, PeerType.Incoming)
          else:
            node.peerPool.addPeerNoWait(peer, PeerType.Outgoing)

        case res:
        of PeerStatus.LowScoreError, PeerStatus.NoSpaceError:
          # Peer has low score or we do not have enough space in PeerPool,
          # we are going to disconnect it gracefully.
          await peer.disconnect(FaultOrError)
        of PeerStatus.DeadPeerError:
          # Peer's lifetime future is finished, so its already dead,
          # we do not need to perform gracefull disconect.
          discard
        of PeerStatus.DuplicateError:
          # Peer is already present in PeerPool, we can't perform disconnect,
          # because in such case we could kill both connections (connection
          # which is present in PeerPool and new one).
          discard
        of PeerStatus.Success:
          # Peer was added to PeerPool.
          discard

  of ConnEventKind.Disconnected:
    dec peer.connections
    debug "Peer disconnected", peer = $peerId, connections = peer.connections
    if peer.connections == 0:
      let fut = peer.disconnectedFut
      if fut != nil:
        peer.disconnectedFut = nil
        fut.complete()

proc init*(T: type Eth2Node, conf: BeaconNodeConf, enrForkId: ENRForkID,
           switch: Switch, pubsub: PubSub, ip: Option[ValidIpAddress],
           tcpPort, udpPort: Port, privKey: keys.PrivateKey, discovery: bool,
           rng: ref BrHmacDrbgContext): T =
  new result
  result.switch = switch
  result.pubsub = pubsub
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
  # Its important here to create AsyncQueue with limited size, otherwise
  # it could produce HIGH cpu usage.
  result.connQueue = newAsyncQueue[PeerAddr](ConcurrentConnections)
  result.metadata = getPersistentNetMetadata(conf)
  result.forkId = enrForkId
  result.discovery = Eth2DiscoveryProtocol.new(
    conf, ip, tcpPort, udpPort, privKey,
    {"eth2": SSZ.encode(result.forkId), "attnets": SSZ.encode(result.metadata.attnets)},
    rng)
  result.discoveryEnabled = discovery

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
  if node.discoveryEnabled:
    node.discovery.open()
  node.libp2pTransportLoops = await node.switch.start()
  await node.pubsub.start()

proc start*(node: Eth2Node) {.async.} =

  proc onPeerCountChanged() =
    trace "Number of peers has been changed",
          space = node.peerPool.shortLogSpace(),
          acquired = node.peerPool.shortLogAcquired(),
          available = node.peerPool.shortLogAvailable(),
          current = node.peerPool.shortLogCurrent(),
          length = len(node.peerPool)
    nbc_peers.set int64(len(node.peerPool))

  node.peerPool.setPeerCounter(onPeerCountChanged)

  for i in 0 ..< ConcurrentConnections:
    node.connWorkers.add connectWorker(node, i)

  if node.discoveryEnabled:
    node.discovery.start()
    traceAsyncErrors node.runDiscoveryLoop()
  else:
    notice "Discovery disabled; trying bootstrap nodes",
      nodes = node.discovery.bootstrapRecords.len
    for enr in node.discovery.bootstrapRecords:
      let tr = enr.toTypedRecord()
      if tr.isOk():
        let pa = tr.get().toPeerAddr()
        if pa.isOk():
          await node.connQueue.addLast(pa.get())

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
    trace "Eth2Node.stop(): timeout reached", timeout,
      futureErrors = waitedFutures.filterIt(it.error != nil).mapIt(it.error.msg)

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
              LPProtocol(codecs: @[`codecNameLit` & "ssz_snappy"],
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
                                           udpPort: Port] =
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

proc getPersistentNetKeys*(rng: var BrHmacDrbgContext,
                           conf: BeaconNodeConf): KeyPair =
  case conf.cmd
  of noCommand:
    if conf.netKeyFile == "random":
      let res = PrivateKey.random(Secp256k1, rng)
      if res.isErr():
        fatal "Could not generate random network key file"
        quit QuitFailure
      let privKey = res.get()
      let pubKey = privKey.getKey().tryGet()
      info "Using random network key",
           network_public_key = byteutils.toHex(pubKey.getBytes().tryGet())
      return KeyPair(seckey: privKey, pubkey: privKey.getKey().tryGet())
    else:
      let keyPath =
        if isAbsolute(conf.netKeyFile):
          conf.netKeyFile
        else:
          conf.dataDir / conf.netKeyFile

      if fileAccessible(keyPath, {AccessFlags.Find}):
        info "Network key storage is present, unlocking", key_path = keyPath

        # Insecure password used only for automated testing.
        let insecurePassword =
          if conf.netKeyInsecurePassword:
            some(NetworkInsecureKeyPassword)
          else:
            none[string]()

        let res = loadNetKeystore(keyPath, insecurePassword)
        if res.isNone():
          fatal "Could not load network key file"
          quit QuitFailure
        let privKey = res.get()
        let pubKey = privKey.getKey().tryGet()
        info "Network key storage was successfully unlocked",
             key_path = keyPath,
             network_public_key = byteutils.toHex(pubKey.getBytes().tryGet())
        return KeyPair(seckey: privKey, pubkey: pubKey)
      else:
        info "Network key storage is missing, creating a new one",
             key_path = keyPath
        let rres = PrivateKey.random(Secp256k1, rng)
        if rres.isErr():
          fatal "Could not generate random network key file"
          quit QuitFailure

        let privKey = rres.get()
        let pubKey = privKey.getKey().tryGet()

        # Insecure password used only for automated testing.
        let insecurePassword =
          if conf.netKeyInsecurePassword:
            some(NetworkInsecureKeyPassword)
          else:
            none[string]()

        let sres = saveNetKeystore(rng, keyPath, privKey, insecurePassword)
        if sres.isErr():
          fatal "Could not create network key file", key_path = keyPath
          quit QuitFailure

        info "New network key storage was created", key_path = keyPath,
             network_public_key = byteutils.toHex(pubKey.getBytes().tryGet())
        return KeyPair(seckey: privKey, pubkey: pubKey)

  of createTestnet:
    if conf.netKeyFile == "random":
      fatal "Could not create testnet using `random` network key"
      quit QuitFailure

    let keyPath =
      if isAbsolute(conf.netKeyFile):
        conf.netKeyFile
      else:
        conf.dataDir / conf.netKeyFile

    let rres = PrivateKey.random(Secp256k1, rng)
    if rres.isErr():
      fatal "Could not generate random network key file"
      quit QuitFailure

    let privKey = rres.get()
    let pubKey = privKey.getKey().tryGet()

    # Insecure password used only for automated testing.
    let insecurePassword =
      if conf.netKeyInsecurePassword:
        some(NetworkInsecureKeyPassword)
      else:
        none[string]()

    let sres = saveNetKeystore(rng, keyPath, privKey, insecurePassword)
    if sres.isErr():
      fatal "Could not create network key file", key_path = keyPath
      quit QuitFailure

    info "New network key storage was created", key_path = keyPath,
         network_public_key = byteutils.toHex(pubKey.getBytes().tryGet())

    return KeyPair(seckey: privKey, pubkey: privkey.getKey().tryGet())
  else:
    let res = PrivateKey.random(Secp256k1, rng)
    if res.isErr():
      fatal "Could not generate random network key file"
      quit QuitFailure

    let privKey = res.get()
    return KeyPair(seckey: privKey, pubkey: privkey.getKey().tryGet())

func gossipId(data: openArray[byte]): string =
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.3/specs/phase0/p2p-interface.md#topics-and-messages
  base64.encode(Base64Url, sha256.digest(data).data)

func msgIdProvider(m: messages.Message): string =
  gossipId(m.data)

proc createEth2Node*(rng: ref BrHmacDrbgContext,
                     conf: BeaconNodeConf,
                     netKeys: KeyPair,
                     enrForkId: ENRForkID): Eth2Node =
  var
    (extIp, extTcpPort, extUdpPort) = setupNat(conf)
    hostAddress = tcpEndPoint(conf.listenAddress, conf.tcpPort)
    announcedAddresses = if extIp.isNone(): @[]
                         else: @[tcpEndPoint(extIp.get(), extTcpPort)]
  let networkPublicKey = byteutils.toHex(netKeys.pubkey.getBytes().tryGet())
  notice "Initializing networking", hostAddress,
                                  networkPublicKey,
                                  announcedAddresses


  # TODO nim-libp2p still doesn't have support for announcing addresses
  # that are different from the host address (this is relevant when we
  # are running behind a NAT).
  var switch = newStandardSwitch(some netKeys.seckey, hostAddress,
                                 transportFlags = {ServerFlags.ReuseAddr},
                                 secureManagers = [
                                   SecureProtocol.Noise, # Only noise in ETH2!
                                 ],
                                 rng = rng)

  let pubsub = GossipSub.init(
    switch = switch,
    msgIdProvider = msgIdProvider,
    triggerSelf = true, sign = false,
    verifySignature = false, anonymize = true).PubSub

  switch.mount(pubsub)

  result = Eth2Node.init(conf, enrForkId, switch, pubsub,
                         extIp, extTcpPort, extUdpPort,
                         netKeys.seckey.asEthKey,
                         discovery = conf.discv5Enabled,
                         rng = rng)

proc announcedENR*(node: Eth2Node): enr.Record =
  doAssert node.discovery != nil, "The Eth2Node must be initialized"
  node.discovery.localNode.record

proc shortForm*(id: KeyPair): string =
  $PeerID.init(id.pubkey)

proc subscribe*[MsgType](node: Eth2Node,
                         topic: string,
                         msgHandler: proc(msg: MsgType) {.gcsafe.} ) {.async.} =
  proc execMsgHandler(topic: string, data: seq[byte]) {.async.} =
    inc nbc_gossip_messages_received
    trace "Incoming pubsub message received",
      len = data.len, topic, msgId = gossipId(data)
    try:
      let decompressed = snappy.decode(data, GOSSIP_MAX_SIZE)
      if decompressed.len > 0:
        msgHandler SSZ.decode(decompressed, MsgType)
      else:
        # TODO penalize peer?
        debug "Failed to decompress gossip payload"
    except CatchableError as err:
      debug "Gossip msg handler error",
        msg = err.msg, len = data.len, topic, msgId = gossipId(data)

  await node.pubsub.subscribe(topic & "_snappy", execMsgHandler)

proc subscribe*(node: Eth2Node, topic: string) {.async.} =
  proc dummyMsgHandler(topic: string, data: seq[byte]) {.async.} =
    discard

  await node.pubsub.subscribe(topic & "_snappy", dummyMsgHandler)

proc addValidator*[MsgType](node: Eth2Node,
                            topic: string,
                            msgValidator: proc(msg: MsgType):
                            ValidationResult {.gcsafe.} ) =
  # Validate messages as soon as subscribed
  proc execValidator(
      topic: string, message: GossipMsg): Future[bool] {.async.} =
    trace "Validating incoming gossip message",
      len = message.data.len, topic, msgId = gossipId(message.data)
    try:
      let decompressed = snappy.decode(message.data, GOSSIP_MAX_SIZE)
      if decompressed.len > 0:
        return msgValidator(SSZ.decode(decompressed, MsgType)) == EVRESULT_ACCEPT
      else:
        # TODO penalize peer?
        debug "Failed to decompress gossip payload"
    except CatchableError as err:
      debug "Gossip validation error",
        msg = err.msg, msgId = gossipId(message.data)
      return false

  node.pubsub.addValidator(topic & "_snappy", execValidator)

proc unsubscribe*(node: Eth2Node, topic: string): Future[void] =
  node.pubsub.unsubscribeAll(topic)

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
  var futSnappy = node.pubsub.publish(topic & "_snappy", data)
  traceMessage(futSnappy, gossipId(data))
