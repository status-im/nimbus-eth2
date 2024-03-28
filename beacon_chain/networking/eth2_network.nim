{.push raises: [].}

import
  std/[typetraits, os, strutils, algorithm, tables, macrocache],
  results,
  stew/[leb128, byteutils, io2],
  stew/shims/macros,
  json_serialization, json_serialization/std/[net, sets, options],
  chronos, chronos/ratelimit, chronicles,
  libp2p/[switch, peerinfo, multiaddress, multicodec, crypto/crypto,
    crypto/secp, builders],
  libp2p/protocols/pubsub/[
      pubsub, gossipsub, rpc/message, rpc/messages, peertable, pubsubpeer],
  libp2p/stream/connection,
  eth/[keys, async_utils],
  ../spec/[eth2_ssz_serialization, network, helpers, forks],
  "."/[eth2_discovery, eth2_protocol_dsl, libp2p_json_serialization, peer_pool, peer_scores]

type
  PublicKey = crypto.PublicKey
  ErrorMsg = List[byte, 256]
  DirectPeers = Table[PeerId, seq[MultiAddress]]

  SeenItem = object
    peerId: PeerId
    stamp: chronos.Moment

  Eth2Node = ref object of RootObj
    switch: Switch
    pubsub: GossipSub
    discovery: Eth2DiscoveryProtocol
    discoveryEnabled: bool
    wantedPeers: int
    hardMaxPeers: int
    peerPool: PeerPool[Peer, PeerId]
    protocols: seq[ProtocolInfo]
      ## Protocols managed by the DSL and mounted on the switch
    protocolStates: seq[RootRef]
    metadata: altair.MetaData
    connectTimeout: chronos.Duration
    seenThreshold: chronos.Duration
    connQueue: AsyncQueue[PeerAddr]
    seenTable: Table[PeerId, SeenItem]
    connWorkers: seq[Future[void].Raising([CancelledError])]
    connTable: HashSet[PeerId]
    forkId: ENRForkID
    discoveryForkId: ENRForkID
    forkDigests: ref ForkDigests
    rng: ref HmacDrbgContext
    peers: Table[PeerId, Peer]
    directPeers: DirectPeers
    validTopics: HashSet[string]
    peerPingerHeartbeatFut: Future[void].Raising([CancelledError])
    peerTrimmerHeartbeatFut: Future[void].Raising([CancelledError])
    cfg: RuntimeConfig

    quota: TokenBucket ## Global quota mainly for high-bandwidth stuff

  AverageThroughput = object
    count: uint64
    average: float

  Peer = ref object
    network: Eth2Node
    peerId: PeerId
    discoveryId: Eth2DiscoveryId
    connectionState: ConnectionState
    protocolStates: seq[RootRef]
    netThroughput: AverageThroughput
    score: int
    quota: TokenBucket
    lastReqTime: Moment
    connections: int
    enr: Opt[enr.Record]
    metadata: Opt[altair.MetaData]
    failedMetadataRequests: int
    lastMetadataTime: Moment
    direction: PeerType
    disconnectedFut: Future[void]
    statistics: SyncResponseStats

  PeerAddr = object
    peerId: PeerId
    addrs: seq[MultiAddress]

  ConnectionState = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  UntypedResponse = ref object
    peer: Peer
    stream: Connection
    writtenChunks: int

  SingleChunkResponse[MsgType] = distinct UntypedResponse
    ## Protocol requests using this type will produce request-making
    ## client-side procs that return `NetRes[MsgType]`

  MultipleChunksResponse[MsgType; maxLen: static Limit] = distinct UntypedResponse
    ## Protocol requests using this type will produce request-making
    ## client-side procs that return `NetRes[List[MsgType, maxLen]]`.
    ## In the future, such procs will return an `InputStream[NetRes[MsgType]]`.

  MessageInfo = object
    name: string

    # Private fields:
    libp2pCodecName: string
    protocolMounter: MounterProc

  ProtocolInfoObj = object
    name: string
    messages: seq[MessageInfo]
    index: int # the position of the protocol in the
                # ordered list of supported protocols

    # Private fields:
    peerStateInitializer: PeerStateInitializer
    networkStateInitializer: NetworkStateInitializer
    onPeerConnected: OnPeerConnectedHandler
    onPeerDisconnected: OnPeerDisconnectedHandler

  ProtocolInfo = ptr ProtocolInfoObj

  ResponseCode = enum
    Success
    InvalidRequest
    ServerError
    ResourceUnavailable

  PeerStateInitializer = proc(peer: Peer): RootRef {.gcsafe, raises: [].}
  NetworkStateInitializer = proc(network: Eth2Node): RootRef {.gcsafe, raises: [].}
  OnPeerConnectedHandler = proc(peer: Peer, incoming: bool): Future[void] {.async: (raises: [CancelledError]).}
  OnPeerDisconnectedHandler = proc(peer: Peer): Future[void] {.async: (raises: [CancelledError]).}
  ThunkProc = LPProtoHandler
  MounterProc = proc(network: Eth2Node) {.gcsafe, raises: [].}
  MessageContentPrinter = proc(msg: pointer): string {.gcsafe, raises: [].}

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#goodbye
  DisconnectionReason = enum
    # might see other values on the wire!
    ClientShutDown = 1
    IrrelevantNetwork = 2
    FaultOrError = 3
    # Clients MAY use reason codes above 128 to indicate alternative,
    # erroneous request-specific responses.
    PeerScoreLow = 237 # 79  3

  TransmissionError = object of CatchableError

  Eth2NetworkingErrorKind = enum
    # Potentially benign errors (network conditions)
    BrokenConnection
    ReceivedErrorResponse
    UnexpectedEOF
    PotentiallyExpectedEOF
    StreamOpenTimeout
    ReadResponseTimeout

    # Errors for which we descore heavily (protocol violations)
    InvalidResponseCode
    InvalidSnappyBytes
    InvalidSszBytes
    InvalidSizePrefix
    ZeroSizePrefix
    SizePrefixOverflow
    InvalidContextBytes
    ResponseChunkOverflow

    UnknownError

  Eth2NetworkingError = object
    case kind: Eth2NetworkingErrorKind
    of ReceivedErrorResponse:
      responseCode: ResponseCode
      errorMsg: string
    else:
      discard

  InvalidInputsError = object of CatchableError

  ResourceUnavailableError = object of CatchableError

  NetRes[T] = Result[T, Eth2NetworkingError]
    ## This is type returned from all network requests

const
  requestPrefix = "/eth2/beacon_chain/req/"
  requestSuffix = "/ssz_snappy"

  ConcurrentConnections = 20
    ## Maximum number of active concurrent connection requests.

  SeenTableTimeIrrelevantNetwork = 24.hours
    ## Period of time for `IrrelevantNetwork` error reason.
  SeenTableTimeClientShutDown = 10.minutes
    ## Period of time for `ClientShutDown` error reason.
  SeenTableTimeFaultOrError = 10.minutes
    ## Period of time for `FaultOnError` error reason.
  SeenTablePenaltyError = 60.minutes
    ## Period of time for peers which score below or equal to zero.
  SeenTableTimeReconnect = 1.minutes
    ## Minimal time between disconnection and reconnection attempt

  ProtocolViolations = {InvalidResponseCode..Eth2NetworkingErrorKind.high()}

template neterr(kindParam: Eth2NetworkingErrorKind): auto =
  err(type(result), Eth2NetworkingError(kind: kindParam))

const
  libp2p_pki_schemes {.strdefine.} = ""

when libp2p_pki_schemes != "secp256k1":
  {.fatal: "Incorrect building process, please use -d:\"libp2p_pki_schemes=secp256k1\"".}

template libp2pProtocol(name: string, version: int) {.pragma.}

func shortLog(peer: Peer): string = shortLog(peer.peerId)
chronicles.formatIt(Peer): shortLog(it)
chronicles.formatIt(PublicKey): byteutils.toHex(it.getBytes().tryGet())

func shortProtocolId(protocolId: string): string =
  let
    start = if protocolId.startsWith(requestPrefix): requestPrefix.len else: 0
    ends = if protocolId.endsWith(requestSuffix):
      protocolId.high - requestSuffix.len
    else:
      protocolId.high
  protocolId[start..ends]

proc init(T: type Peer, network: Eth2Node, peerId: PeerId): Peer {.gcsafe.}

proc getState(peer: Peer, proto: ProtocolInfo): RootRef =
  doAssert peer.protocolStates[proto.index] != nil, $proto.index
  peer.protocolStates[proto.index]

proc getNetworkState(node: Eth2Node, proto: ProtocolInfo): RootRef =
  doAssert node.protocolStates[proto.index] != nil, $proto.index
  node.protocolStates[proto.index]

template protocolState(node: Eth2Node, Protocol: type): untyped =
  mixin NetworkState
  bind getNetworkState
  type S = Protocol.NetworkState
  S(getNetworkState(node, Protocol.protocolInfo))

proc getPeer(node: Eth2Node, peerId: PeerId): Peer =
  node.peers.withValue(peerId, peer) do:
    return peer[]
  do:
    let peer = Peer.init(node, peerId)
    return node.peers.mgetOrPut(peerId, peer)

proc peerFromStream(network: Eth2Node, conn: Connection): Peer =
  result = network.getPeer(conn.peerId)
  result.peerId = conn.peerId

func updateScore(peer: Peer, score: int) {.inline.} =
  ## Update peer's ``peer`` score with value ``score``.
  peer.score = peer.score + score
  if peer.score > PeerScoreHighLimit:
    peer.score = PeerScoreHighLimit

func calcThroughput(dur: Duration, value: uint64): float =
  let secs = float(chronos.seconds(1).nanoseconds)
  if isZero(dur):
    0.0
  else:
    float(value) * (secs / float(dur.nanoseconds))

func updateNetThroughput(peer: Peer, dur: Duration,
                         bytesCount: uint64) {.inline.} =
  ## Update peer's ``peer`` network throughput.
  let bytesPerSecond = calcThroughput(dur, bytesCount)
  let a = peer.netThroughput.average
  let n = peer.netThroughput.count
  peer.netThroughput.average = a + (bytesPerSecond - a) / float(n + 1)
  inc(peer.netThroughput.count)

func `<`(a, b: Peer): bool =
  ## Comparison function, which first checks peer's scores, and if the peers'
  ## score is equal it compares peers' network throughput.
  if a.score < b.score:
    true
  elif a.score == b.score:
    (a.netThroughput.average < b.netThroughput.average)
  else:
    false

const
  maxRequestQuota = 1000000
  maxGlobalQuota = 2 * maxRequestQuota
    ## Roughly, this means we allow 2 peers to sync from us at a time
  fullReplenishTime = 5.seconds

template awaitQuota(peerParam: Peer, costParam: float, protocolIdParam: string) =
  let
    peer = peerParam
    cost = int(costParam)

  if not peer.quota.tryConsume(cost.int):
    let protocolId = protocolIdParam
    debug "Awaiting peer quota", peer, cost = cost, protocolId = protocolId
    await peer.quota.consume(cost.int)

template awaitQuota(
    networkParam: Eth2Node, costParam: float, protocolIdParam: string) =
  let
    network = networkParam
    cost = int(costParam)

  if not network.quota.tryConsume(cost.int):
    let protocolId = protocolIdParam
    debug "Awaiting network quota", peer, cost = cost, protocolId = protocolId
    nbc_reqresp_messages_throttled.inc(1, [protocolId])
    await network.quota.consume(cost.int)

func allowedOpsPerSecondCost(n: int): float =
  const replenishRate = (maxRequestQuota / fullReplenishTime.nanoseconds.float)
  (replenishRate * 1000000000'f / n.float)

const
  libp2pRequestCost = allowedOpsPerSecondCost(8)
    ## Maximum number of libp2p requests per peer per second

proc addSeen(network: Eth2Node, peerId: PeerId,
              period: chronos.Duration) =
  ## Adds peer with PeerId ``peerId`` to SeenTable and timeout ``period``.
  let item = SeenItem(peerId: peerId, stamp: now(chronos.Moment) + period)
  withValue(network.seenTable, peerId, entry) do:
    if entry.stamp < item.stamp:
      entry.stamp = item.stamp
  do:
    network.seenTable[peerId] = item

proc disconnect(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async: (raises: [CancelledError]).} =
  # Per the specification, we MAY send a disconnect reason to the other peer but
  # we currently don't - the fact that we're disconnecting is obvious and the
  # reason already known (wrong network is known from status message) or doesn't
  # greatly matter for the listening side (since it can't be trusted anyway)
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
      peer.network.addSeen(peer.peerId, seenTime)
      await peer.network.switch.disconnect(peer.peerId)
  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    # switch.disconnect shouldn't raise
    warn "Unexpected error while disconnecting peer",
      peer = peer.peerId,
      reason = reason,
      exc = exc.msg

proc releasePeer(peer: Peer) =
  ## Checks for peer's score and disconnects peer if score is less than
  ## `PeerScoreLowLimit`.
  if peer.connectionState notin {ConnectionState.Disconnecting,
                                 ConnectionState.Disconnected}:
    if peer.score < PeerScoreLowLimit:
      debug "Peer was disconnected due to low score", peer = peer,
            peer_score = peer.score, score_low_limit = PeerScoreLowLimit,
            score_high_limit = PeerScoreHighLimit
      asyncSpawn(peer.disconnect(PeerScoreLow))

proc getRequestProtoName(fn: NimNode): NimNode =
  # `getCustomPragmaVal` doesn't work yet on regular nnkProcDef nodes
  # (TODO: file as an issue)

  let pragmas = fn.pragma
  if pragmas.kind == nnkPragma and pragmas.len > 0:
    for pragma in pragmas:
      try:
        if pragma.len > 0 and $pragma[0] == "libp2pProtocol":
          let protoName = $(pragma[1])
          let protoVer = $(pragma[2].intVal)
          return newLit(requestPrefix & protoName & "/" & protoVer & requestSuffix)
      except Exception as exc: raiseAssert exc.msg # TODO https://github.com/nim-lang/Nim/issues/17454

  return newLit("")

template errorMsgLit(x: static string): ErrorMsg =
  const val = ErrorMsg toBytes(x)
  val

proc sendErrorResponse(peer: Peer,
                       conn: Connection,
                       responseCode: ResponseCode,
                       errMsg: ErrorMsg): Future[void] = discard
proc sendNotificationMsg(peer: Peer, protocolId: string, requestBytes: seq[byte])
    {.async: (raises: [CancelledError]).} =  discard
proc sendResponseChunkBytesSZ(
    response: UntypedResponse, uncompressedLen: uint64,
    payloadSZ: openArray[byte],
    contextBytes: openArray[byte] = []): Future[void] = discard

proc sendResponseChunkBytes(
    response: UntypedResponse, payload: openArray[byte],
    contextBytes: openArray[byte] = []): Future[void] = discard
proc uncompressFramedStream(conn: Connection,
                            expectedSize: int): Future[Result[seq[byte], string]]
                            {.async: (raises: [CancelledError]).} = discard
func chunkMaxSize[T](): uint32 =
  # compiler error on (T: type) syntax...
  when isFixedSize(T):
    uint32 fixedPortionSize(T)
  else:
    static: doAssert MAX_CHUNK_SIZE < high(uint32).uint64
    MAX_CHUNK_SIZE.uint32

from ../spec/datatypes/capella import SignedBeaconBlock
from ../spec/datatypes/deneb import SignedBeaconBlock

proc readVarint2(conn: Connection): Future[NetRes[uint64]] {.
    async: (raises: [CancelledError]).} =
  try:
    ok await conn.readVarint()
  except LPStreamEOFError: #, LPStreamIncompleteError, InvalidVarintError
    # TODO compiler error - haha, uncaught exception
    # Error: unhandled exception: closureiters.nim(322, 17) `c[i].kind == nkType`  [AssertionError]
    neterr UnexpectedEOF
  except LPStreamIncompleteError:
    neterr UnexpectedEOF
  except InvalidVarintError:
    neterr InvalidSizePrefix
  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    debug "Unexpected error", exc = exc.msg
    neterr UnknownError

proc readChunkPayload(conn: Connection, peer: Peer,
                       MsgType: type): Future[NetRes[MsgType]]
                       {.async: (raises: [CancelledError]).} =
  let
    sm = now(chronos.Moment)
    size = ? await readVarint2(conn)

  const maxSize = chunkMaxSize[MsgType]()
  if size > maxSize:
    return neterr SizePrefixOverflow
  if size == 0:
    return neterr ZeroSizePrefix

  # The `size.int` conversion is safe because `size` is bounded to `MAX_CHUNK_SIZE`
  let
    dataRes = await conn.uncompressFramedStream(size.int)
    data = dataRes.valueOr:
      debug "Snappy decompression/read failed", msg = $dataRes.error, conn
      return neterr InvalidSnappyBytes

  # `10` is the maximum size of variable integer on wire, so error could
  # not be significant.
  peer.updateNetThroughput(now(chronos.Moment) - sm,
                            uint64(10 + size))
  try:
    ok SSZ.decode(data, MsgType)
  except SerializationError:
    neterr InvalidSszBytes

proc makeEth2Request(peer: Peer, protocolId: string, requestBytes: seq[byte],
                     ResponseMsg: type,
                     timeout: Duration): Future[NetRes[ResponseMsg]]
                    {.async: (raises: [CancelledError]).} = discard

proc init(T: type MultipleChunksResponse, peer: Peer, conn: Connection): T =
  T(UntypedResponse(peer: peer, stream: conn))

proc init[MsgType](T: type SingleChunkResponse[MsgType],
                    peer: Peer, conn: Connection): T =
  T(UntypedResponse(peer: peer, stream: conn))

proc performProtocolHandshakes(peer: Peer, incoming: bool) {.async: (raises: [CancelledError]).} =
  # Loop down serially because it's easier to reason about the connection state
  # when there are fewer async races, specially during setup
  for protocol in peer.network.protocols:
    if protocol.onPeerConnected != nil:
      await protocol.onPeerConnected(peer, incoming)

proc initProtocol(name: string,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer,
                  index: int): ProtocolInfoObj =
  ProtocolInfoObj(
    name: name,
    messages: @[],
    index: index,
    peerStateInitializer: peerInit,
    networkStateInitializer: networkInit)

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
                          protocolId: string,
                          MsgType: type) {.async: (raises: [CancelledError]).} =
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

  let peer = peerFromStream(network, conn)
  try:
    case peer.connectionState
    of Disconnecting, Disconnected, None:
      # We got incoming stream request while disconnected or disconnecting.
      debug "Got incoming request from disconnected peer", peer = peer,
           message = msgName
      return
    of Connecting:
      # We got incoming stream request while handshake is not yet finished,
      # TODO: We could check it here.
      debug "Got incoming request from peer while in handshake", peer = peer,
            msgName
    of Connected:
      # We got incoming stream from peer with proper connection state.
      debug "Got incoming request from peer", peer = peer, msgName

    template returnInvalidRequest(msg: ErrorMsg) =
      peer.updateScore(PeerScoreInvalidRequest)
      await sendErrorResponse(peer, conn, InvalidRequest, msg)
      return

    template returnInvalidRequest(msg: string) =
      returnInvalidRequest(ErrorMsg msg.toBytes)

    template returnResourceUnavailable(msg: ErrorMsg) =
      await sendErrorResponse(peer, conn, ResourceUnavailable, msg)
      return

    template returnResourceUnavailable(msg: string) =
      returnResourceUnavailable(ErrorMsg msg.toBytes)

    const isEmptyMsg = when MsgRec is object:
      # We need nested `when` statements here, because Nim doesn't properly
      # apply boolean short-circuit logic at compile time and this causes
      # `totalSerializedFields` to be applied to non-object types that it
      # doesn't know how to support.
      when totalSerializedFields(MsgRec) == 0: true
      else: false
    else:
      false

    let msg =
      try:
        when isEmptyMsg:
          NetRes[MsgRec].ok default(MsgRec)
        else:
          # TODO(zah) The TTFB timeout is not implemented in LibP2P streams
          # back-end
          let deadline = sleepAsync RESP_TIMEOUT_DUR

          awaitWithTimeout(
            readChunkPayload(conn, peer, MsgRec), deadline):
              # Timeout, e.g., cancellation due to fulfillment by different peer.
              # Treat this similarly to `UnexpectedEOF`, `PotentiallyExpectedEOF`.
              await sendErrorResponse(
                peer, conn, InvalidRequest,
                errorMsgLit "Request full data not sent in time")
              return

      finally:
        # The request quota is shared between all requests - it represents the
        # cost to perform a service on behalf of a client and is incurred
        # regardless if the request succeeds or fails - we don't count waiting
        # for this quota against timeouts so as not to prematurely disconnect
        # clients that are on the edge - nonetheless, the client will count it.

        # When a client exceeds their quota, they will be slowed down without
        # notification - as long as they don't make parallel requests (which is
        # limited by libp2p), this will naturally adapt them to the available
        # quota.

        # Note that the `msg` will be stored in memory while we wait for the
        # quota to be available. The amount of such messages in memory is
        # bounded by the libp2p limit of parallel streams

        # This quota also applies to invalid requests thanks to the use of
        # `finally`.

        awaitQuota(peer, libp2pRequestCost, shortProtocolId(protocolId))

    if msg.isErr:
      if msg.error.kind in ProtocolViolations:
        peer.updateScore(PeerScoreInvalidRequest)
      else:
        peer.updateScore(PeerScorePoorRequest)

      let (responseCode, errMsg) = case msg.error.kind
        of UnexpectedEOF, PotentiallyExpectedEOF:
          (InvalidRequest, errorMsgLit "Incomplete request")

        of InvalidContextBytes:
          (ServerError, errorMsgLit "Unrecognized context bytes")

        of InvalidSnappyBytes:
          (InvalidRequest, errorMsgLit "Failed to decompress snappy payload")

        of InvalidSszBytes:
          (InvalidRequest, errorMsgLit "Failed to decode SSZ payload")

        of InvalidSizePrefix:
          (InvalidRequest, errorMsgLit "Invalid chunk size prefix")

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

        of ResponseChunkOverflow:
          (InvalidRequest, errorMsgLit "Too many chunks in response")

        of UnknownError:
          (InvalidRequest, errorMsgLit "Unknown error while processing request")

      await sendErrorResponse(peer, conn, responseCode, errMsg)
      return

    try:
      # logReceivedMsg(peer, MsgType(msg.get))
      await callUserHandler(MsgType, peer, conn, msg.get)
    except InvalidInputsError as exc:
      returnInvalidRequest exc.msg
    except ResourceUnavailableError as exc:
      returnResourceUnavailable exc.msg
    except CatchableError as exc:
      await sendErrorResponse(peer, conn, ServerError, ErrorMsg exc.msg.toBytes)

  except CatchableError as exc:
    debug "Error processing an incoming request", exc = exc.msg, msgName

  finally:
    try:
      await noCancel conn.closeWithEOF()
    except CatchableError as exc:
      debug "Unexpected error while closing incoming connection", exc = exc.msg
    releasePeer(peer)

proc onConnEvent(
    node: Eth2Node, peerId: PeerId, event: ConnEvent) {.
    async: (raises: [CancelledError]).} =
  let peer = node.getPeer(peerId)
  case event.kind
  of ConnEventKind.Connected:
    inc peer.connections
    debug "Peer connection upgraded", peer = $peerId,
                                      connections = peer.connections
    if peer.connections == 1:
      # Libp2p may connect multiple times to the same peer - using different
      # transports for both incoming and outgoing. For now, we'll count our
      # "fist" encounter with the peer as the true connection, leaving the
      # other connections be - libp2p limits the number of concurrent
      # connections to the same peer, and only one of these connections will be
      # active. Nonetheless, this quirk will cause a number of odd behaviours:
      #   connected transport - instead we'll just pick a random one!
      case peer.connectionState
      of Disconnecting:
        # We got connection with peer which we currently disconnecting.
        # Normally this does not happen, but if a peer is being disconnected
        # while a concurrent (incoming for example) connection attempt happens,
        # we might end up here
        debug "Got connection attempt from peer that we are disconnecting",
             peer = peerId
        try:
          await node.switch.disconnect(peerId)
        except CancelledError as exc:
          raise exc
        except CatchableError as exc:
          debug "Unexpected error while disconnecting peer", exc = exc.msg
        return
      of None:
        # We have established a connection with the new peer.
        peer.connectionState = Connecting
      of Disconnected:
        # We have established a connection with the peer that we have seen
        # before - reusing the existing peer object is fine
        peer.connectionState = Connecting
        peer.score = 0 # Will be set to NewPeerScore after handshake
      of Connecting, Connected:
        # This means that we got notification event from peer which we already
        # connected or connecting right now. If this situation will happened,
        # it means bug on `nim-libp2p` side.
        warn "Got connection attempt from peer which we already connected",
             peer = peerId
        await peer.disconnect(FaultOrError)
        return

      # Store connection direction inside Peer object.
      if event.incoming:
        peer.direction = PeerType.Incoming
      else:
        peer.direction = PeerType.Outgoing

      await performProtocolHandshakes(peer, event.incoming)

  of ConnEventKind.Disconnected:
    dec peer.connections
    debug "Lost connection to peer", peer = peerId,
                                     connections = peer.connections

    if peer.connections == 0:
      debug "Peer disconnected", peer = $peerId, connections = peer.connections

      # Whatever caused disconnection, avoid connection spamming
      node.addSeen(peerId, SeenTableTimeReconnect)

      let fut = peer.disconnectedFut
      if not(isNil(fut)):
        fut.complete()
        peer.disconnectedFut = nil
      else:
        # TODO (cheatfate): This could be removed when bug will be fixed inside
        # `nim-libp2p`.
        debug "Got new event while peer is already disconnected",
              peer = peerId, peer_state = peer.connectionState
      peer.connectionState = Disconnected

proc new(T: type Eth2Node,
         runtimeCfg: RuntimeConfig,
         enrForkId: ENRForkID, discoveryForkId: ENRForkID,
         forkDigests: ref ForkDigests,
         switch: Switch, pubsub: GossipSub,
         ip: Option[IpAddress], tcpPort, udpPort: Option[Port],
         privKey: keys.PrivateKey, discovery: bool,
         directPeers: DirectPeers,
         rng: ref HmacDrbgContext): T {.raises: [CatchableError].} =
  when not defined(local_testnet):
    let
      connectTimeout = chronos.minutes(1)
      seenThreshold = chronos.minutes(5)
  else:
    let
      connectTimeout = chronos.seconds(10)
      seenThreshold = chronos.seconds(10)
  type MetaData = altair.MetaData # Weird bug without this..

  # Versions up to v22.3.0 would write an empty `MetaData` to
  #`data-dir/node-metadata.json` which would then be reloaded on startup - don't
  # write a file with this name or downgrades will break!
  const metadata = MetaData()

  let node = T(
    switch: switch,
    pubsub: pubsub,
    wantedPeers: config.maxPeers,
    hardMaxPeers: config.hardMaxPeers.get(config.maxPeers * 3 div 2), #1.5
    cfg: runtimeCfg,
    peerPool: newPeerPool[Peer, PeerId](),
    # Its important here to create AsyncQueue with limited size, otherwise
    # it could produce HIGH cpu usage.
    connQueue: newAsyncQueue[PeerAddr](ConcurrentConnections),
    metadata: metadata,
    forkId: enrForkId,
    discoveryForkId: discoveryForkId,
    forkDigests: forkDigests,
    discovery: Eth2DiscoveryProtocol.new(
      config, ip, tcpPort, udpPort, privKey,
      {
        enrForkIdField: SSZ.encode(enrForkId),
        enrAttestationSubnetsField: SSZ.encode(metadata.attnets)
      },
    rng),
    discoveryEnabled: discovery,
    rng: rng,
    connectTimeout: connectTimeout,
    seenThreshold: seenThreshold,
    directPeers: directPeers,
    quota: TokenBucket.new(maxGlobalQuota, fullReplenishTime)
  )

  proc peerHook(peerId: PeerId, event: ConnEvent): Future[void] {.gcsafe.} =
    onConnEvent(node, peerId, event)

  switch.addConnEventHandler(peerHook, ConnEventKind.Connected)
  switch.addConnEventHandler(peerHook, ConnEventKind.Disconnected)

  proc scoreCheck(peer: Peer): bool =
    peer.score >= PeerScoreLowLimit

  proc onDeletePeer(peer: Peer) =
    peer.releasePeer()

  node.peerPool.setScoreCheck(scoreCheck)
  node.peerPool.setOnDeletePeer(onDeletePeer)

  node

proc init(T: type Peer, network: Eth2Node, peerId: PeerId): Peer =
  let res = Peer(
    peerId: peerId,
    network: network,
    connectionState: ConnectionState.None,
    lastReqTime: now(chronos.Moment),
    lastMetadataTime: now(chronos.Moment),
    quota: TokenBucket.new(maxRequestQuota.int, fullReplenishTime)
  )
  res.protocolStates.setLen(network.protocolStates.len())
  for proto in network.protocols:
    if not(isNil(proto.peerStateInitializer)):
      res.protocolStates[proto.index] = proto.peerStateInitializer(res)
  res

proc registerMsg(protocol: ProtocolInfo,
                 name: string,
                 mounter: MounterProc,
                 libp2pCodecName: string) =
  protocol.messages.add MessageInfo(name: name,
                                    protocolMounter: mounter,
                                    libp2pCodecName: libp2pCodecName)

proc p2pProtocolBackendImpl(p: P2PProtocol): Backend =
  var
    Format = ident "SSZ"
    Connection = bindSym "Connection"
    Peer = bindSym "Peer"
    Eth2Node = bindSym "Eth2Node"
    registerMsg = bindSym "registerMsg"
    initProtocol = bindSym "initProtocol"
    msgVar = ident "msg"
    networkVar = ident "network"
    callUserHandler = ident "callUserHandler"
    MSG = ident "MSG"

  new result

  result.PeerType = Peer
  result.NetworkType = Eth2Node
  result.setEventHandlers = bindSym "setEventHandlers"
  result.SerializationFormat = Format
  result.RequestResultsWrapper = ident "NetRes"

  result.implementMsg = proc (msg: eth2_protocol_dsl.Message) =
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
          newTree(nnkBracketExpr, ident"List", OutputParamType[1], OutputParamType[2])
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

      proc `protocolMounterName`(`networkVar`: `Eth2Node`) {.raises: [].} =
        proc snappyThunk(`streamVar`: `Connection`,
                         `protocolVar`: string): Future[void] {.gcsafe.} =
          return handleIncomingStream(`networkVar`, `streamVar`, `protocolVar`,
                                      `MsgStrongRecName`)

        try:
          mount `networkVar`.switch,
                LPProtocol.new(
                  codecs = @[`codecNameLit`], handler = snappyThunk)
        except LPError as exc:
          # Failure here indicates that the mounting was done incorrectly which
          # would be a programming error
          raiseAssert exc.msg
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
    # This `macrocache` counter gives each protocol its own integer index which
    # is later used to index per-protocol, per-instace data kept in the peer and
    # network - the counter is global across all modules / protocols of the
    # application
    let
      id = CacheCounter"eth2_network_protocol_id"
      tmp = id.value
    id.inc(1)

    newCall(initProtocol, newLit(p.name), p.peerInit, p.netInit, newLit(tmp))

type
  BeaconSyncNetworkState {.final.} = ref object of RootObj
    cfg: RuntimeConfig

p2pProtocol BeaconSync(version = 1,
                       networkState = BeaconSyncNetworkState):
  proc beaconBlocksByRange_v2(
      peer: Peer,
      reqCount: uint64,
      reqStep: uint64,
      response: MultipleChunksResponse[
        ref uint64, Limit MAX_REQUEST_BLOCKS])
      {.async, libp2pProtocol("beacon_blocks_by_range", 2).} = discard
