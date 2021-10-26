# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Std lib
  std/[typetraits, os, sequtils, strutils, algorithm, math, tables],

  # Status libs
  stew/[leb128, endians2, results, byteutils, io2, bitops2], bearssl,
  stew/shims/net as stewNet,
  stew/shims/[macros],
  faststreams/[inputs, outputs, buffers], snappy, snappy/framing,
  json_serialization, json_serialization/std/[net, sets, options],
  chronos, chronicles, metrics,
  libp2p/[switch, peerinfo, multiaddress, multicodec, crypto/crypto,
    crypto/secp, builders],
  libp2p/protocols/pubsub/[
      pubsub, gossipsub, rpc/message, rpc/messages, peertable, pubsubpeer],
  libp2p/stream/connection,
  libp2p/utils/semaphore,
  eth/[keys, async_utils], eth/p2p/p2p_protocol_dsl,
  eth/net/nat, eth/p2p/discoveryv5/[enr, node, random2],
  ".."/[version, conf, beacon_clock],
  ../spec/datatypes/[phase0, altair, merge],
  ../spec/[eth2_ssz_serialization, network, helpers, forks],
  ../validators/keystore_management,
  ./eth2_discovery, ./peer_pool, ./libp2p_json_serialization

when chronicles.enabledLogLevel == LogLevel.TRACE:
  import std/sequtils

export
  tables, version, multiaddress, peer_pool, peerinfo, p2pProtocol, connection,
  libp2p_json_serialization, eth2_ssz_serialization, results, eth2_discovery

logScope:
  topics = "networking"

type
  NetKeyPair* = crypto.KeyPair
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

  Eth2Node* = ref object of RootObj
    switch*: Switch
    pubsub*: GossipSub
    discovery*: Eth2DiscoveryProtocol
    discoveryEnabled*: bool
    wantedPeers*: int
    peerPool*: PeerPool[Peer, PeerID]
    protocolStates*: seq[RootRef]
    libp2pTransportLoops*: seq[Future[void]]
    metadata*: altair.MetaData
    connectTimeout*: chronos.Duration
    seenThreshold*: chronos.Duration
    connQueue: AsyncQueue[PeerAddr]
    seenTable: Table[PeerID, SeenItem]
    connWorkers: seq[Future[void]]
    connTable: HashSet[PeerID]
    forkId*: ENRForkID
    discoveryForkId*: ENRForkID
    forkDigests*: ForkDigestsRef
    rng*: ref BrHmacDrbgContext
    peers*: Table[PeerID, Peer]
    validTopics: HashSet[string]
    peerPingerHeartbeatFut: Future[void]
    cfg: RuntimeConfig
    getBeaconTime: GetBeaconTimeFn

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

  AverageThroughput* = object
    count*: uint64
    average*: float

  Peer* = ref object
    network*: Eth2Node
    peerId*: PeerId
    discoveryId*: Eth2DiscoveryId
    connectionState*: ConnectionState
    protocolStates*: seq[RootRef]
    netThroughput: AverageThroughput
    score*: int
    requestQuota*: float
    lastReqTime*: Moment
    connections*: int
    enr*: Option[enr.Record]
    metadata*: Option[phase0.MetaData]
    lastMetadataTime*: Moment
    direction*: PeerType
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

  UntypedResponse* = ref object
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

  PeerStateInitializer* = proc(peer: Peer): RootRef {.gcsafe, raises: [Defect].}
  NetworkStateInitializer* = proc(network: EthereumNode): RootRef {.gcsafe, raises: [Defect].}
  OnPeerConnectedHandler* = proc(peer: Peer, incoming: bool): Future[void] {.gcsafe.}
  OnPeerDisconnectedHandler* = proc(peer: Peer): Future[void] {.gcsafe, raises: [Defect].}
  ThunkProc* = LPProtoHandler
  MounterProc* = proc(network: Eth2Node) {.gcsafe, raises: [Defect, CatchableError].}
  MessageContentPrinter* = proc(msg: pointer): string {.gcsafe, raises: [Defect].}

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/p2p-interface.md#goodbye
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
    InvalidContextBytes

  Eth2NetworkingError = object
    case kind*: Eth2NetworkingErrorKind
    of ReceivedErrorResponse:
      responseCode: ResponseCode
      errorMsg: string
    else:
      discard

  InvalidInputsError* = object of CatchableError

  NetRes*[T] = Result[T, Eth2NetworkingError]
    ## This is type returned from all network requests

func phase0metadata*(node: Eth2Node): phase0.MetaData =
  phase0.MetaData(
    seq_number: node.metadata.seq_number,
    attnets: node.metadata.attnets)

const
  clientId* = "Nimbus beacon node " & fullVersionStr
  nodeMetadataFilename = "node-metadata.json"

  NewPeerScore* = 200
    ## Score which will be assigned to new connected Peer
  PeerScoreLowLimit* = 0
    ## Score after which peer will be kicked
  PeerScoreHighLimit* = 1000
    ## Max value of peer's score
  PeerScoreInvalidRequest* = -500
    ## This peer is sending malformed or nonsensical data

  ConcurrentConnections = 20
    ## Maximum number of active concurrent connection requests.

  SeenTableTimeTimeout =
    when not defined(local_testnet): 5.minutes else: 10.seconds

    ## Seen period of time for timeout connections
  SeenTableTimeDeadPeer =
    when not defined(local_testnet): 5.minutes else: 10.seconds

    ## Period of time for dead peers.
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

template neterr*(kindParam: Eth2NetworkingErrorKind): auto =
  err(type(result), Eth2NetworkingError(kind: kindParam))

# Metrics for tracking attestation and beacon block loss
declareCounter nbc_gossip_messages_sent,
  "Number of gossip messages sent by this peer"

declareCounter nbc_gossip_messages_received,
  "Number of gossip messages received by this peer"

declareCounter nbc_gossip_failed_snappy,
  "Number of gossip messages that failed snappy decompression"

declareCounter nbc_gossip_failed_ssz,
  "Number of gossip messages that failed SSZ parsing"

declareCounter nbc_successful_dials,
  "Number of successfully dialed peers"

declareCounter nbc_failed_dials,
  "Number of dialing attempts that failed"

declareCounter nbc_timeout_dials,
  "Number of dialing attempts that exceeded timeout"

declareGauge nbc_peers,
  "Number of active libp2p peers"

declareCounter nbc_successful_discoveries,
  "Number of successful discoveries"

declareCounter nbc_failed_discoveries,
  "Number of failed discoveries"

declareCounter nbc_cycling_kicked_peers,
  "Number of peers kicked for peer cycling"

const delayBuckets = [1.0, 5.0, 10.0, 20.0, 40.0, 60.0]

declareHistogram nbc_resolve_time,
  "Time(s) used while resolving peer information",
   buckets = delayBuckets

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

func shortLog*(peer: Peer): string = shortLog(peer.peerId)
chronicles.formatIt(Peer): shortLog(it)
chronicles.formatIt(PublicKey): byteutils.toHex(it.getBytes().tryGet())

template remote*(peer: Peer): untyped =
  peer.peerId

proc openStream(node: Eth2Node,
                peer: Peer,
                protocolId: string): Future[Connection] {.async.} =
  # When dialling here, we do not provide addresses - all new connection
  # attempts are handled via `connect` which also takes into account
  # reconnection timeouts
  let
    protocolId = protocolId & "ssz_snappy"
    conn = await dial(
      node.switch, peer.peerId, protocolId)

  return conn

proc init*(T: type Peer, network: Eth2Node, peerId: PeerId): Peer {.gcsafe.}

func peerId*(node: Eth2Node): PeerID =
  node.switch.peerInfo.peerId

func enrRecord*(node: Eth2Node): Record =
  node.discovery.localNode.record

proc getPeer*(node: Eth2Node, peerId: PeerID): Peer =
  node.peers.withValue(peerId, peer) do:
    return peer[]
  do:
    let peer = Peer.init(node, peerId)
    return node.peers.mgetOrPut(peerId, peer)

proc peerFromStream(network: Eth2Node, conn: Connection): Peer =
  result = network.getPeer(conn.peerId)
  result.peerId = conn.peerId

proc getKey*(peer: Peer): PeerID {.inline.} =
  peer.peerId

proc getFuture*(peer: Peer): Future[void] {.inline.} =
  if isNil(peer.disconnectedFut):
    peer.disconnectedFut = newFuture[void]("Peer.disconnectedFut")
  peer.disconnectedFut

proc getScore*(a: Peer): int =
  ## Returns current score value for peer ``peer``.
  a.score

proc updateScore*(peer: Peer, score: int) {.inline.} =
  ## Update peer's ``peer`` score with value ``score``.
  peer.score = peer.score + score
  if peer.score > PeerScoreHighLimit:
    peer.score = PeerScoreHighLimit

proc calcThroughput(dur: Duration, value: uint64): float =
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

const
  maxRequestQuota = 1000000.0
  fullReplenishTime = 5.seconds
  replenishRate = (maxRequestQuota / fullReplenishTime.nanoseconds.float)

proc updateRequestQuota*(peer: Peer, reqCost: float) =
  let
    currentTime = now(chronos.Moment)
    nanosSinceLastReq = nanoseconds(currentTime - peer.lastReqTime)
    replenishedQuota = peer.requestQuota + nanosSinceLastReq.float * replenishRate

  peer.lastReqTime = currentTime
  peer.requestQuota = min(replenishedQuota, maxRequestQuota) - reqCost

template awaitNonNegativeRequestQuota*(peer: Peer) =
  let quota = peer.requestQuota
  if quota < 0:
    await sleepAsync(nanoseconds(int((-quota) / replenishRate)))

func allowedOpsPerSecondCost*(n: int): float =
  (replenishRate * 1000000000'f / n.float)

proc isSeen*(network: ETh2Node, peerId: PeerID): bool =
  ## Returns ``true`` if ``peerId`` present in SeenTable and time period is not
  ## yet expired.
  let currentTime = now(chronos.Moment)
  if peerId notin network.seenTable:
    false
  else:
    let item = try: network.seenTable[peerId]
    except KeyError: raiseAssert "checked with notin"
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
  withValue(network.seenTable, peerId, entry) do:
    if entry.stamp < item.stamp:
      entry.stamp = item.stamp
  do:
    network.seenTable[peerId] = item

proc disconnect*(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async.} =
  # TODO(zah): How should we notify the other peer?
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
  except CatchableError:
    # We do not care about exceptions in disconnection procedure.
    trace "Exception while disconnecting peer", peer = peer.peerId,
                                                reason = reason

include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing

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
          return newLit("/eth2/beacon_chain/req/" & protoName & "/" & protoVer & "/")
      except Exception as exc: raiseAssert exc.msg # TODO https://github.com/nim-lang/Nim/issues/17454

  return newLit("")

proc writeChunk*(conn: Connection,
                 responseCode: Option[ResponseCode],
                 payload: Bytes,
                 contextBytes: openarray[byte] = []): Future[void] =
  var output = memoryOutput()

  try:
    if responseCode.isSome:
      output.write byte(responseCode.get)

    if contextBytes.len > 0:
      output.write contextBytes

    output.write toBytes(payload.lenu64, Leb128).toOpenArray()

    framingFormatCompress(output, payload)
  except IOError as exc:
    raiseAssert exc.msg # memoryOutput shouldn't raise
  conn.write(output.getOutput)

template errorMsgLit(x: static string): ErrorMsg =
  const val = ErrorMsg toBytes(x)
  val

func formatErrorMsg(msg: ErrorMsg): string =
  # ErrorMsg "usually" contains a human-readable string - we'll try to parse it
  # as ASCII and return hex if that fails
  for c in msg:
    if c < 32 or c > 127:
      return byteutils.toHex(asSeq(msg))

  string.fromBytes(asSeq(msg))

proc sendErrorResponse(peer: Peer,
                       conn: Connection,
                       responseCode: ResponseCode,
                       errMsg: ErrorMsg): Future[void] =
  debug "Error processing request",
    peer, responseCode, errMsg = formatErrorMsg(errMsg)
  conn.writeChunk(some responseCode, SSZ.encode(errMsg))

proc sendNotificationMsg(peer: Peer, protocolId: string, requestBytes: Bytes) {.async.} =
  var
    deadline = sleepAsync RESP_TIMEOUT
    streamFut = peer.network.openStream(peer, protocolId)

  await streamFut or deadline

  if not streamFut.finished:
    await streamFut.cancelAndWait()
    raise newException(TransmissionError, "Failed to open LibP2P stream")

  let stream = streamFut.read
  try:
    await stream.writeChunk(none ResponseCode, requestBytes)
  finally:
    await stream.close()

proc sendResponseChunkBytes(response: UntypedResponse, payload: Bytes): Future[void] =
  inc response.writtenChunks
  response.stream.writeChunk(some Success, payload)

proc sendResponseChunk*(response: UntypedResponse, val: auto): Future[void] =
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
    # Some clients don't want a length sent for empty requests
    # So don't send anything on empty requests
    if requestBytes.len > 0:
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

template write*[M](r: MultipleChunksResponse[M], val: M): untyped =
  mixin sendResponseChunk
  sendResponseChunk(UntypedResponse(r), val)

template send*[M](r: SingleChunkResponse[M], val: M): untyped =
  mixin sendResponseChunk
  doAssert UntypedResponse(r).writtenChunks == 0
  sendResponseChunk(UntypedResponse(r), val)

proc performProtocolHandshakes*(peer: Peer, incoming: bool) {.async.} =
  # Loop down serially because it's easier to reason about the connection state
  # when there are fewer async races, specially during setup
  for protocol in allProtocols:
    if protocol.onPeerConnected != nil:
      await protocol.onPeerConnected(peer, incoming)

proc initProtocol(name: string,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer): ProtocolInfoObj =
  ProtocolInfoObj(
    name: name,
    messages: @[],
    peerStateInitializer: peerInit,
    networkStateInitializer: networkInit)

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

  let peer = peerFromStream(network, conn)
  try:
    case peer.connectionState
    of Disconnecting, Disconnected, None:
      # We got incoming stream request while disconnected or disconnecting.
      debug "Got incoming request from disconnected peer", peer = peer,
           message = msgName
      await conn.closeWithEOF()
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

    let s = when useNativeSnappy:
      let fs = libp2pInput(conn)

      if fs.timeoutToNextByte(TTFB_TIMEOUT):
        returnInvalidRequest(errorMsgLit "Request first byte not sent in time")

      fs
    else:
      # TODO(zah) The TTFB timeout is not implemented in LibP2P streams back-end
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

        of InvalidContextBytes:
          (ServerError, errorMsgLit "Unrecognized context bytes")

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
    except InvalidInputsError as err:
      returnInvalidRequest err.msg
      await sendErrorResponse(peer, conn, ServerError,
                              ErrorMsg err.msg.toBytes)
    except CatchableError as err:
      await sendErrorResponse(peer, conn, ServerError,
                              ErrorMsg err.msg.toBytes)

  except CatchableError as err:
    debug "Error processing an incoming request", err = err.msg, msgName

  finally:
    await conn.closeWithEOF()
    discard network.peerPool.checkPeerScore(peer)

proc toPeerAddr*(r: enr.TypedRecord,
                 proto: IpTransportProtocol): Result[PeerAddr, cstring] =
  if not r.secp256k1.isSome:
    return err("enr: no secp256k1 key in record")

  let
    pubKey = ? keys.PublicKey.fromRaw(r.secp256k1.get)
    peerId = ? PeerID.init(crypto.PublicKey(
      scheme: Secp256k1, skkey: secp.SkPublicKey(pubKey)))

  var addrs = newSeq[MultiAddress]()

  case proto
  of tcpProtocol:
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

  of udpProtocol:
    if r.ip.isSome and r.udp.isSome:
      let ip = ipv4(r.ip.get)
      addrs.add MultiAddress.init(ip, udpProtocol, Port r.udp.get)

    if r.ip6.isSome:
      let ip = ipv6(r.ip6.get)
      if r.udp6.isSome:
        addrs.add MultiAddress.init(ip, udpProtocol, Port r.udp6.get)
      elif r.udp.isSome:
        addrs.add MultiAddress.init(ip, udpProtocol, Port r.udp.get)
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
      debug "Connection to remote peer timed out"
      inc nbc_timeout_dials
      node.addSeen(peerAddr.peerId, SeenTableTimeTimeout)
      await cancelAndWait(workfut)
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
    # Previous worker dial might have hit the maximum peers.
    # TODO: could clear the whole connTable and connQueue here also, best
    # would be to have this event based coming from peer pool or libp2p.
    if node.switch.connManager.outSema.count > 0:
      await node.dialPeer(remotePeerAddr, index)
    # Peer was added to `connTable` before adding it to `connQueue`, so we
    # excluding peer here after processing.
    node.connTable.excl(remotePeerAddr.peerId)

proc toPeerAddr(node: Node): Result[PeerAddr, cstring] =
  let nodeRecord = ? node.record.toTypedRecord()
  let peerAddr = ? nodeRecord.toPeerAddr(tcpProtocol)
  ok(peerAddr)

proc isCompatibleForkId*(discoveryForkId: ENRForkID, peerForkId: ENRForkID): bool =
  if discoveryForkId.fork_digest == peerForkId.fork_digest:
    if discoveryForkId.next_fork_version < peerForkId.next_fork_version:
      # Peer knows about a fork and we don't
      true
    elif discoveryForkId.next_fork_version == peerForkId.next_fork_version:
      # We should have the same next_fork_epoch
      discoveryForkId.next_fork_epoch == peerForkId.next_fork_epoch

    else:
      # Our next fork version is bigger than the peer's one
      false
  else:
    # Wrong fork digest
    false

proc queryRandom*(
    d: Eth2DiscoveryProtocol,
    forkId: ENRForkID,
    wantedAttnets: AttnetBits,
    wantedSyncnets: SyncnetBits): Future[seq[Node]] {.async.} =
  ## Perform a discovery query for a random target
  ## (forkId) and matching at least one of the attestation subnets.

  let nodes = await d.queryRandom()

  var filtered: seq[(int, Node)]
  for n in nodes:
    var score: int = 0

    let eth2FieldBytes = n.record.tryGet(enrForkIdField, seq[byte])
    if eth2FieldBytes.isNone():
      continue
    let peerForkId =
      try:
        SSZ.decode(eth2FieldBytes.get(), ENRForkID)
      except SszError as e:
        debug "Could not decode the eth2 field of peer",
          peer = n.record.toURI(), exception = e.name, msg = e.msg
        continue

    if not forkId.isCompatibleForkId(peerForkId):
      continue

    let attnetsBytes = n.record.tryGet(enrAttestationSubnetsField, seq[byte])
    if attnetsBytes.isSome():
      let attnetsNode =
        try:
          SSZ.decode(attnetsBytes.get(), AttnetBits)
        except SszError as e:
          debug "Could not decode the attnets ERN bitfield of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

      for i in 0..<ATTESTATION_SUBNET_COUNT:
        if wantedAttnets[i] and attnetsNode[i]:
          score += 1

    let syncnetsBytes = n.record.tryGet(enrSyncSubnetsField, seq[byte])
    if syncnetsBytes.isSome():
      let syncnetsNode =
        try:
          SSZ.decode(syncnetsBytes.get(), SyncnetBits)
        except SszError as e:
          debug "Could not decode the syncnets ENR bitfield of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

      for i in allSyncSubcommittees():
        if wantedSyncnets[i] and syncnetsNode[i]:
          score += 10 # connecting to the right syncnet is urgent

    if score > 0:
      filtered.add((score, n))

  d.rng[].shuffle(filtered)
  return filtered.sortedByIt(-it[0]).mapIt(it[1])

proc trimConnections(node: Eth2Node, count: int) {.async.} =
  # Kill `count` peers, scoring them to remove the least useful ones

  var scores = initOrderedTable[PeerID, int]()

  # Take into account the stabilitySubnets
  # During sync, only this will be used to score peers
  #
  # A peer subscribed to all stabilitySubnets will
  # have 640 points
  for peer in node.peers.values:
    if peer.connectionState != Connected: continue
    if peer.metadata.isNone: continue

    let
      stabilitySubnets = peer.metadata.get().attnets
      stabilitySubnetsCount = stabilitySubnets.countOnes()
      thisPeersScore = 10 * stabilitySubnetsCount

    scores[peer.peerId] = thisPeersScore

  # Split a 1000 points for each topic's peers
  # This gives priority to peers in topics with few peers
  # For instance, a topic with `dHigh` peers will give 80 points to each peer
  # Whereas a topic with `dLow` peers will give 250 points to each peer
  for topic, _ in node.pubsub.topics:
    let
      peerCount = node.pubsub.mesh.peers(topic)
      scorePerPeer = 1_000 div max(peerCount, 1)

    if peerCount == 0: continue

    for peer in node.pubsub.mesh[topic]:
      if peer.peerId notin scores: continue

      # Divide by the number of connections
      # A peer using multiple connections is wasteful
      let
        connCount = node.switch.connmanager.connCount(peer.peerId)
        thisPeersScore = scorePerPeer div max(1, connCount)

      scores[peer.peerId] = scores[peer.peerId] + thisPeersScore

  proc sortPerScore(a, b: (PeerID, int)): int =
    system.cmp(a[1], b[1])

  scores.sort(sortPerScore)

  var toKick = count

  for peerId in scores.keys:
    #TODO kill a single connection instead of the whole peer
    # Not possible with the current libp2p's conn management
    debug "kicking peer", peerId, score=scores[peerId]
    await node.switch.disconnect(peerId)
    dec toKick
    inc(nbc_cycling_kicked_peers)
    if toKick <= 0: return

proc getLowSubnets(node: Eth2Node, epoch: Epoch): (AttnetBits, SyncnetBits) =
  # Returns the subnets required to have a healthy mesh
  # The subnets are computed, to, in order:
  # - Have 0 subscribed subnet below `dLow`
  # - Have 0 subnet with < `d` peers from topic subscription
  # - Have 0 subscribed subnet below `dOut` outgoing peers

  template findLowSubnets(topicNameGenerator: untyped,
                          SubnetIdType: type,
                          totalSubnets: static int): auto =
    var
      lowOutgoingSubnets: BitArray[totalSubnets]
      belowDLowSubnets: BitArray[totalSubnets]
      belowDOutSubnets: BitArray[totalSubnets]

    for subNetId in 0 ..< totalSubnets:
      let topic =
        topicNameGenerator(node.forkId.forkDigest, SubnetIdType(subNetId))

      if node.pubsub.gossipsub.peers(topic) < node.pubsub.parameters.d:
        lowOutgoingSubnets.setBit(subNetId)

      # Not subscribed
      if topic notin node.pubsub.mesh: continue

      if node.pubsub.mesh.peers(topic) < node.pubsub.parameters.dLow:
        belowDlowSubnets.setBit(subNetId)

      let outPeers = node.pubsub.mesh.getOrDefault(topic).countIt(it.outbound)
      if outPeers < node.pubsub.parameters.dOut:
        belowDOutSubnets.setBit(subNetId)

    if belowDLowSubnets.countOnes() > 0:
      belowDLowSubnets
    elif lowOutgoingSubnets.countOnes() > 0:
      lowOutgoingSubnets
    else:
      belowDOutSubnets

  return (
    findLowSubnets(getAttestationTopic, SubnetId, ATTESTATION_SUBNET_COUNT),
    # We start looking one epoch before the transition in order to allow
    # some time for the gossip meshes to get healthy:
    if epoch + 1 >= node.cfg.ALTAIR_FORK_EPOCH:
      findLowSubnets(getSyncCommitteeTopic, SyncSubcommitteeIndex, SYNC_COMMITTEE_SUBNET_COUNT)
    else:
      default(SyncnetBits)
  )

proc runDiscoveryLoop*(node: Eth2Node) {.async.} =
  debug "Starting discovery loop"

  while true:
    let
      currentEpoch = node.getBeaconTime().slotOrZero.epoch
      (wantedAttnets, wantedSyncnets) = node.getLowSubnets(currentEpoch)
      wantedAttnetsCount = wantedAttnets.countOnes()
      wantedSyncnetsCount = wantedSyncnets.countOnes()

    if wantedAttnetsCount > 0 or wantedSyncnetsCount > 0:
      let discoveredNodes = await node.discovery.queryRandom(
        node.discoveryForkId, wantedAttnets, wantedSyncnets)

      let newPeers = block:
        var np = newSeq[PeerAddr]()
        for discNode in discoveredNodes:
          let res = discNode.toPeerAddr()
          if res.isErr():
            debug "Failed to decode discovery's node address",
                  node = discnode, errMsg = res.error
            continue

          let peerAddr = res.get()
          if node.checkPeer(peerAddr) and
            peerAddr.peerId notin node.connTable:
            np.add(peerAddr)
        np

      # We have to be careful to kick enough peers to make room for new ones
      # (If we are here, we have an unhealthy mesh, so if we're full, we have bad peers)
      # But no kick too many peers because with low max-peers, that can cause disruption
      # Also keep in mind that a lot of dial fails, and that we can have incoming peers waiting
      let
        roomRequired = 1 + newPeers.len()
        roomCurrent = node.peerPool.lenSpace({PeerType.Outgoing})
        roomDelta = roomRequired - roomCurrent

        maxPeersToKick = len(node.peerPool) div 5
        peersToKick = min(roomDelta, maxPeersToKick)

      if peersToKick > 0 and newPeers.len() > 0:
        await node.trimConnections(peersToKick)

      for peerAddr in newPeers:
          # We adding to pending connections table here, but going
          # to remove it only in `connectWorker`.
          node.connTable.incl(peerAddr.peerId)
          await node.connQueue.addLast(peerAddr)

      debug "Discovery tick", wanted_peers = node.wantedPeers,
            space = node.peerPool.shortLogSpace(),
            acquired = node.peerPool.shortLogAcquired(),
            available = node.peerPool.shortLogAvailable(),
            current = node.peerPool.shortLogCurrent(),
            length = len(node.peerPool),
            discovered_nodes = len(discoveredNodes),
            kicked_peers = max(0, peersToKick),
            new_peers = len(newPeers)

      if len(newPeers) == 0:
        let currentPeers = node.peerPool.lenCurrent()
        if currentPeers <= node.wantedPeers shr 2: #  25%
          warn "Peer count low, no new peers discovered",
            discovered_nodes = len(discoveredNodes), new_peers = newPeers,
            current_peers = currentPeers, wanted_peers = node.wantedPeers

    # Discovery `queryRandom` can have a synchronous fast path for example
    # when no peers are in the routing table. Don't run it in continuous loop.
    #
    # Also, give some time to dial the discovered nodes and update stats etc
    await sleepAsync(5.seconds)

proc getPersistentNetMetadata*(config: BeaconNodeConf): altair.MetaData
                              {.raises: [Defect, IOError, SerializationError].} =
  let metadataPath = config.dataDir / nodeMetadataFilename
  if not fileExists(metadataPath):
    var res: altair.MetaData
    for i in 0 ..< ATTESTATION_SUBNET_COUNT:
      # TODO:
      # Persistent (stability) subnets should be stored with their expiration
      # epochs. For now, indicate that we participate in no persistent subnets.
      res.attnets[i] = false
    Json.saveFile(metadataPath, res)
    res
  else:
    Json.loadFile(metadataPath, altair.MetaData)

proc resolvePeer(peer: Peer) =
  # Resolve task which performs searching of peer's public key and recovery of
  # ENR using discovery5. We only resolve ENR for peers we know about to avoid
  # querying the network - as of now, the ENR is not needed, except for
  # debuggging
  logScope: peer = peer.peerId
  let startTime = now(chronos.Moment)
  let nodeId =
    block:
      var key: PublicKey
      # `secp256k1` keys are always stored inside PeerID.
      discard peer.peerId.extractPublicKey(key)
      keys.PublicKey.fromRaw(key.skkey.getBytes()).get().toNodeId()

  debug "Peer's ENR recovery task started", node_id = $nodeId

  # This is "fast-path" for peers which was dialed. In this case discovery
  # already has most recent ENR information about this peer.
  let gnode = peer.network.discovery.getNode(nodeId)
  if gnode.isSome():
    peer.enr = some(gnode.get().record)
    inc(nbc_successful_discoveries)
    let delay = now(chronos.Moment) - startTime
    nbc_resolve_time.observe(delay.toFloatSeconds())
    debug "Peer's ENR recovered", delay

proc handlePeer*(peer: Peer) {.async.} =
  let res = peer.network.peerPool.addPeerNoWait(peer, peer.direction)
  case res:
  of PeerStatus.LowScoreError, PeerStatus.NoSpaceError:
    # Peer has low score or we do not have enough space in PeerPool,
    # we are going to disconnect it gracefully.
    # Peer' state will be updated in connection event.
    debug "Peer has low score or there no space in PeerPool",
          peer = peer, reason = res
    await peer.disconnect(FaultOrError)
  of PeerStatus.DeadPeerError:
    # Peer's lifetime future is finished, so its already dead,
    # we do not need to perform gracefull disconect.
    # Peer's state will be updated in connection event.
    discard
  of PeerStatus.DuplicateError:
    # Peer is already present in PeerPool, we can't perform disconnect,
    # because in such case we could kill both connections (connection
    # which is present in PeerPool and new one).
    # This is possible bug, because we could enter here only if number
    # of `peer.connections == 1`, it means that Peer's lifetime is not
    # tracked properly and we still not received `Disconnected` event.
    debug "Peer is already present in PeerPool", peer = peer
  of PeerStatus.Success:
    # Peer was added to PeerPool.
    peer.score = NewPeerScore
    peer.connectionState = Connected
    # We spawn task which will obtain ENR for this peer.
    resolvePeer(peer)
    debug "Peer successfully connected", peer = peer,
                                         connections = peer.connections

proc onConnEvent(node: Eth2Node, peerId: PeerID, event: ConnEvent) {.async.} =
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
      # * For peer limits, we might miscount the incoming vs outgoing quota
      # * Protocol handshakes are wonky: we'll not necessarily use the newly
      #   connected transport - instead we'll just pick a random one!
      case peer.connectionState
      of Disconnecting:
        # We got connection with peer which we currently disconnecting.
        # Normally this does not happen, but if a peer is being disconnected
        # while a concurrent (incoming for example) connection attempt happens,
        # we might end up here
        debug "Got connection attempt from peer that we are disconnecting",
             peer = peerId
        await node.switch.disconnect(peerId)
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

proc new*(T: type Eth2Node, config: BeaconNodeConf, runtimeCfg: RuntimeConfig,
          enrForkId: ENRForkID, discoveryForkId: ENRForkId, forkDigests: ForkDigestsRef,
          getBeaconTime: GetBeaconTimeFn, switch: Switch,
          pubsub: GossipSub, ip: Option[ValidIpAddress], tcpPort,
          udpPort: Option[Port], privKey: keys.PrivateKey, discovery: bool,
          rng: ref BrHmacDrbgContext): T {.raises: [Defect, CatchableError].} =
  let
    metadata = getPersistentNetMetadata(config)
  when not defined(local_testnet):
    let
      connectTimeout = 1.minutes
      seenThreshold = 5.minutes
  else:
    let
      connectTimeout = 10.seconds
      seenThreshold = 10.seconds

  let node = T(
    switch: switch,
    pubsub: pubsub,
    wantedPeers: config.maxPeers,
    cfg: runtimeCfg,
    peerPool: newPeerPool[Peer, PeerID](maxPeers = config.maxPeers),
    # Its important here to create AsyncQueue with limited size, otherwise
    # it could produce HIGH cpu usage.
    connQueue: newAsyncQueue[PeerAddr](ConcurrentConnections),
    # TODO: The persistent net metadata should only be used in the case of reusing
    # the previous netkey.
    metadata: metadata,
    forkId: enrForkId,
    discoveryForkId: discoveryForkId,
    forkDigests: forkDigests,
    getBeaconTime: getBeaconTime,
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
    seenThreshold: seenThreshold
  )

  newSeq node.protocolStates, allProtocols.len
  for proto in allProtocols:
    if proto.networkStateInitializer != nil:
      node.protocolStates[proto.index] = proto.networkStateInitializer(node)

    for msg in proto.messages:
      if msg.protocolMounter != nil:
        msg.protocolMounter node


  proc peerHook(peerId: PeerId, event: ConnEvent): Future[void] {.gcsafe.} =
    onConnEvent(node, peerId, event)

  switch.addConnEventHandler(peerHook, ConnEventKind.Connected)
  switch.addConnEventHandler(peerHook, ConnEventKind.Disconnected)

  node

template publicKey*(node: Eth2Node): keys.PublicKey =
  node.discovery.privKey.toPublicKey

proc startListening*(node: Eth2Node) {.async.} =
  if node.discoveryEnabled:
    try:
       node.discovery.open()
    except CatchableError:
      fatal "Failed to start discovery service. UDP port may be already in use"
      quit 1

  try:
    node.libp2pTransportLoops = await node.switch.start()
  except CatchableError:
    fatal "Failed to start LibP2P transport. TCP port may be already in use"
    quit 1

  await node.pubsub.start()

proc peerPingerHeartbeat(node: Eth2Node): Future[void] {.gcsafe.}

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
        let pa = tr.get().toPeerAddr(tcpProtocol)
        if pa.isOk():
          await node.connQueue.addLast(pa.get())
  node.peerPingerHeartbeatFut = node.peerPingerHeartbeat()

proc stop*(node: Eth2Node) {.async.} =
  # Ignore errors in futures, since we're shutting down (but log them on the
  # TRACE level, if a timeout is reached).
  let
    waitedFutures = if node.discoveryEnabled:
                      @[node.discovery.closeWait(), node.switch.stop()]
                    else:
                      @[node.switch.stop()]
    timeout = 5.seconds
    completed = await withTimeout(allFutures(waitedFutures), timeout)
  if not completed:
    trace "Eth2Node.stop(): timeout reached", timeout,
      futureErrors = waitedFutures.filterIt(it.error != nil).mapIt(it.error.msg)

proc init*(T: type Peer, network: Eth2Node, peerId: PeerId): Peer =
  let res = Peer(
    peerId: peerId,
    network: network,
    connectionState: ConnectionState.None,
    lastReqTime: now(chronos.Moment),
    lastMetadataTime: now(chronos.Moment),
    protocolStates: newSeq[RootRef](len(allProtocols))
  )
  for i in 0 ..< len(allProtocols):
    let proto = allProtocols[i]
    if not(isNil(proto.peerStateInitializer)):
      res.protocolStates[i] = proto.peerStateInitializer(res)
  res

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

#Must import here because of cyclicity
import ../sync/sync_protocol

proc updatePeerMetadata(node: Eth2Node, peerId: PeerID) {.async.} =
  trace "updating peer metadata", peerId

  var peer = node.getPeer(peerId)

  #getMetaData can fail with an exception
  let newMetadata =
    try:
      tryGet(await peer.getMetaData())
    except CatchableError:
      let metadataV2 =
        try: tryGet(await peer.getMetadata_v2())
        except CatchableError as exc:
          debug "Failed to retrieve metadata from peer!", peerId, msg=exc.msg
          return

      phase0.MetaData(seq_number: metadataV2.seq_number,
                      attnets: metadataV2.attnets)

  peer.metadata = some(newMetadata)
  peer.lastMetadataTime = Moment.now()

const
  # For Phase0, metadata change every +27 hours
  MetadataRequestFrequency = 30.minutes

  # Metadata request has 10 seconds timeout, and the loop sleeps for 5 seconds
  # 50 seconds = 3 attempts
  MetadataRequestMaxFailureTime = 50.seconds

proc peerPingerHeartbeat(node: Eth2Node) {.async.} =
  while true:
    let heartbeatStart_m = Moment.now()
    var updateFutures: seq[Future[void]]

    for peer in node.peers.values:
      if peer.connectionState != Connected: continue

      if peer.metadata.isNone or
        heartbeatStart_m - peer.lastMetadataTime > MetadataRequestFrequency:
        updateFutures.add(node.updatePeerMetadata(peer.peerId))

    discard await allFinished(updateFutures)

    for peer in node.peers.values:
      if peer.connectionState != Connected: continue
      let lastMetadata =
        if peer.metadata.isNone:
          peer.lastMetadataTime
        else:
          peer.lastMetadataTime + MetadataRequestFrequency

      if heartbeatStart_m - lastMetadata > MetadataRequestMaxFailureTime:
        debug "no metadata from peer, kicking it", peer
        asyncSpawn peer.disconnect(PeerScoreLow)

    await sleepAsync(5.seconds)

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
                           config: BeaconNodeConf): NetKeyPair =
  case config.cmd
  of noCommand, record:
    if config.netKeyFile == "random":
      let res = PrivateKey.random(Secp256k1, rng)
      if res.isErr():
        fatal "Could not generate random network key file"
        quit QuitFailure
      let
        privKey = res.get()
        pubKey = privKey.getPublicKey().expect("working public key from random")
        pres = PeerID.init(pubKey)
      if pres.isErr():
        fatal "Could not obtain PeerID from network key"
        quit QuitFailure
      info "Generating new networking key", network_public_key = pubKey,
                                            network_peer_id = $pres.get()
      NetKeyPair(seckey: privKey, pubkey: pubKey)
    else:
      let keyPath =
        if isAbsolute(config.netKeyFile):
          config.netKeyFile
        else:
          config.dataDir / config.netKeyFile

      if fileAccessible(keyPath, {AccessFlags.Find}):
        info "Network key storage is present, unlocking", key_path = keyPath

        # Insecure password used only for automated testing.
        let insecurePassword =
          if config.netKeyInsecurePassword:
            some(NetworkInsecureKeyPassword)
          else:
            none[string]()

        let res = loadNetKeystore(keyPath, insecurePassword)
        if res.isNone():
          fatal "Could not load network key file"
          quit QuitFailure
        let
          privKey = res.get()
          pubKey = privKey.getPublicKey().expect("working public key from file")
        info "Network key storage was successfully unlocked",
             key_path = keyPath, network_public_key = pubKey
        NetKeyPair(seckey: privKey, pubkey: pubKey)
      else:
        info "Network key storage is missing, creating a new one",
             key_path = keyPath
        let rres = PrivateKey.random(Secp256k1, rng)
        if rres.isErr():
          fatal "Could not generate random network key file"
          quit QuitFailure

        let
          privKey = rres.get()
          pubKey = privKey.getPublicKey().expect("working public key from random")

        # Insecure password used only for automated testing.
        let insecurePassword =
          if config.netKeyInsecurePassword:
            some(NetworkInsecureKeyPassword)
          else:
            none[string]()

        let sres = saveNetKeystore(rng, keyPath, privKey, insecurePassword)
        if sres.isErr():
          fatal "Could not create network key file", key_path = keyPath
          quit QuitFailure

        info "New network key storage was created", key_path = keyPath,
             network_public_key = pubKey
        NetKeyPair(seckey: privKey, pubkey: pubKey)

  of createTestnet:
    if config.netKeyFile == "random":
      fatal "Could not create testnet using `random` network key"
      quit QuitFailure

    let keyPath =
      if isAbsolute(config.netKeyFile):
        config.netKeyFile
      else:
        config.dataDir / config.netKeyFile

    let rres = PrivateKey.random(Secp256k1, rng)
    if rres.isErr():
      fatal "Could not generate random network key file"
      quit QuitFailure

    let
      privKey = rres.get()
      pubKey = privKey.getPublicKey().expect("working public key from random")

    # Insecure password used only for automated testing.
    let insecurePassword =
      if config.netKeyInsecurePassword:
        some(NetworkInsecureKeyPassword)
      else:
        none[string]()

    let sres = saveNetKeystore(rng, keyPath, privKey, insecurePassword)
    if sres.isErr():
      fatal "Could not create network key file", key_path = keyPath
      quit QuitFailure

    info "New network key storage was created", key_path = keyPath,
         network_public_key = pubKey

    NetKeyPair(seckey: privKey, pubkey: pubKey)
  else:
    let res = PrivateKey.random(Secp256k1, rng)
    if res.isErr():
      fatal "Could not generate random network key file"
      quit QuitFailure

    let
      privKey = res.get()
      pubKey = privKey.getPublicKey().expect("working public key from random")
    NetKeyPair(seckey: privKey, pubkey: pubKey)

func gossipId(
    data: openArray[byte], altairPrefix, topic: string, valid: bool): seq[byte] =
  # https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#topics-and-messages
  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/p2p-interface.md#topics-and-messages
  const
    MESSAGE_DOMAIN_INVALID_SNAPPY = [0x00'u8, 0x00, 0x00, 0x00]
    MESSAGE_DOMAIN_VALID_SNAPPY = [0x01'u8, 0x00, 0x00, 0x00]
  let messageDigest = withEth2Hash:
    h.update(
      if valid: MESSAGE_DOMAIN_VALID_SNAPPY else: MESSAGE_DOMAIN_INVALID_SNAPPY)

    if topic.startsWith(altairPrefix):
      h.update topic.len.uint64.toBytesLE
      h.update topic

    h.update data

  messageDigest.data[0..19]

proc newBeaconSwitch*(config: BeaconNodeConf, seckey: PrivateKey,
                      address: MultiAddress,
                      rng: ref BrHmacDrbgContext): Switch {.raises: [Defect, CatchableError].} =
  SwitchBuilder
    .new()
    .withPrivateKey(seckey)
    .withAddress(address)
    .withRng(rng)
    .withNoise()
    .withMplex(5.minutes, 5.minutes)
    .withMaxConnections(config.maxPeers)
    .withAgentVersion(config.agentString)
    .withTcpTransport({ServerFlags.ReuseAddr})
    .build()

proc createEth2Node*(rng: ref BrHmacDrbgContext,
                     config: BeaconNodeConf,
                     netKeys: NetKeyPair,
                     cfg: RuntimeConfig,
                     forkDigests: ForkDigestsRef,
                     getBeaconTime: GetBeaconTimeFn,
                     genesisValidatorsRoot: Eth2Digest): Eth2Node
                    {.raises: [Defect, CatchableError].} =
  let
    enrForkId = getENRForkID(
      cfg, getBeaconTime().slotOrZero.epoch, genesisValidatorsRoot)

    discoveryForkId = getDiscoveryForkID(
      cfg, getBeaconTime().slotOrZero.epoch, genesisValidatorsRoot)

    (extIp, extTcpPort, extUdpPort) = try: setupAddress(
      config.nat, config.listenAddress, config.tcpPort, config.udpPort, clientId)
    except CatchableError as exc: raise exc
    except Exception as exc: raiseAssert exc.msg

    hostAddress = tcpEndPoint(config.listenAddress, config.tcpPort)
    announcedAddresses = if extIp.isNone() or extTcpPort.isNone(): @[]
                         else: @[tcpEndPoint(extIp.get(), extTcpPort.get())]

  debug "Initializing networking", hostAddress,
                                   network_public_key = netKeys.pubkey,
                                   announcedAddresses

  # TODO nim-libp2p still doesn't have support for announcing addresses
  # that are different from the host address (this is relevant when we
  # are running behind a NAT).
  var switch = newBeaconSwitch(config, netKeys.seckey, hostAddress, rng)

  let altairPrefix = "/eth2/" & $forkDigests.altair

  func msgIdProvider(m: messages.Message): seq[byte] =
    template topic: untyped =
      if m.topicIDs.len > 0: m.topicIDs[0] else: ""

    try:
      let decoded = snappy.decode(m.data, GOSSIP_MAX_SIZE)
      gossipId(decoded, altairPrefix, topic, true)
    except CatchableError:
      gossipId(m.data, altairPrefix, topic, false)

  let
    params = GossipSubParams(
      explicit: true,
      pruneBackoff: 1.minutes,
      floodPublish: true,
      gossipFactor: 0.05,
      d: 8,
      dLow: 6,
      dHigh: 12,
      dScore: 6,
      dOut: 6 div 2, # less than dlow and no more than dlow/2
      dLazy: 6,
      heartbeatInterval: 700.milliseconds,
      historyLength: 6,
      historyGossip: 3,
      fanoutTTL: 60.seconds,
      seenTTL: 385.seconds,
      gossipThreshold: -40,
      publishThreshold: -80,
      graylistThreshold: -160, # also disconnect threshold
      opportunisticGraftThreshold: 1,
      decayInterval: 12.seconds, #TODO this is not used in libp2p
      decayToZero: 0.01,
      retainScore: 385.seconds,
      appSpecificWeight: 0.0,
      ipColocationFactorWeight: -5,
      ipColocationFactorThreshold: 3.0,
      behaviourPenaltyWeight: -5,
      behaviourPenaltyDecay: 0.986,
      disconnectBadPeers: true,
      directPeers:
        block:
          var res = initTable[PeerId, seq[MultiAddress]]()
          if config.directPeers.len > 0:
            for s in config.directPeers:
              let
                maddress = MultiAddress.init(s).tryGet()
                mpeerId = maddress[multiCodec("p2p")].tryGet()
                peerId = PeerID.init(mpeerId.protoAddress().tryGet()).tryGet()
              res.mgetOrPut(peerId, @[]).add(maddress)
              info "Adding priviledged direct peer", peerId, address = maddress
          res
    )
    pubsub = GossipSub.init(
      switch = switch,
      msgIdProvider = msgIdProvider,
      triggerSelf = true,
      sign = false,
      verifySignature = false,
      anonymize = true,
      parameters = params)

  switch.mount(pubsub)

  let node = Eth2Node.new(
    config, cfg, enrForkId, discoveryForkId, forkDigests, getBeaconTime, switch, pubsub, extIp,
    extTcpPort, extUdpPort, netKeys.seckey.asEthKey,
    discovery = config.discv5Enabled, rng = rng)

  node.pubsub.subscriptionValidator =
    proc(topic: string): bool {.gcsafe, raises: [Defect].} =
      topic in node.validTopics

  node

proc announcedENR*(node: Eth2Node): enr.Record =
  doAssert node.discovery != nil, "The Eth2Node must be initialized"
  node.discovery.localNode.record

proc shortForm*(id: NetKeyPair): string =
  $PeerID.init(id.pubkey)


# Gossipsub scoring explained:
# A score of a peer in a topic is the sum of 5 different scores:
#
# `timeInMesh`: for each `Quantum` spent in a mesh,
# the peer will win `Weight` points, up to `(Cap * Weight)`
#
# Every following score decays: score is multiplied by `Decay` in every heartbeat
# until they reach `decayToZero` (0.1 by default)
#
# `firstMessageDelivery`: for each message delivered first,
# the peer will win `Weight` points, up to `(Cap * Weight)`
#
# `meshMessageDeliveries`: The most convoluted way possible to punish
# peers not sending enough traffic in a topic.
#
# For each message (duplicate or first) received in a topic, the score is incremented, up to `Cap`.
# If the score of the topic gets below `Threshold`, the peer
# since at least `Activation` time will have: `score += (Threshold - Score)² * Weight`
# (`Weight` should be negative to punish them)
#
# `meshFailurePenalty`: same as meshMessageDeliveries, but only happens on prune
# to avoid peers constantly unsubbing-resubbing
#
# `invalidMessageDeliveries`: for each message not passing validation received, a peer
# score is incremented. Final score = `Score * Score * Weight`
#
#
# Once we have the 5 scores for each peer/topic, we sum them up per peer
# using the topicWeight of each topic.
#
# Nimbus strategy:
# Trying to get a 100 possible points in each topic before weighting
# And then, weight each topic to have 100 points max total
#
# In order of priority:
# - A badly behaving peer (eg, sending bad messages) will be heavily sanctionned
# - A good peer will gain good scores
# - Inactive/slow peers will be mildly sanctionned.
#
# Since a "slow" topic will punish everyone in it, we don't want to punish
# good peers which are unlucky and part of a slow topic. So, we give more points to
# good peers than we remove to slow peers
#
# Global topics are good to check stability of peers, but since we can only
# have ~20 peers in global topics, we need to score on subnets to have data
# about as much peers as possible, even the subnets are less stable
func computeDecay(
  startValue: float,
  endValue: float,
  timeToEndValue: Duration,
  heartbeatTime: Duration
  ): float =
  # startValue will to to endValue in timeToEndValue
  # given the returned decay

  let heartbeatsToZero = timeToEndValue.milliseconds.float / heartbeatTime.milliseconds.float
  pow(endValue / startValue, 1 / heartbeatsToZero)

func computeMessageDeliveriesWeight(
  messagesThreshold: float,
  maxLostPoints: float): float =

  let maxDeficit = messagesThreshold
  -maxLostPoints / (maxDeficit * maxDeficit)

type TopicType* = enum
  BlockTopic,
  AggregateTopic,
  SubnetTopic,
  OtherTopic

proc getTopicParams(
  topicWeight: float,
  heartbeatPeriod: Duration,
  period: Duration,
  averageOverNPeriods: float,
  peersPerTopic: int,
  expectedMessagesPerPeriod: int,
  timeInMeshQuantum: Duration
  ): TopicParams =

  let
    # Statistically, a peer will be first for every `receivedMessage / d`
    shouldBeFirstPerPeriod = expectedMessagesPerPeriod / peersPerTopic
    shouldBeFirstOverNPeriod = shouldBeFirstPerPeriod * averageOverNPeriods

    # A peer being first in 1/d% messages will reach a score of
    # `shouldSendOverNPeriod`
    firstMessageDecay =
      computeDecay(
        startValue = shouldBeFirstOverNPeriod,
        endValue = 0.1,
        timeToEndValue = period * averageOverNPeriods.int * 2,
        heartbeatPeriod)
 
    # Start to remove up to 30 points when peer send less
    # than half message than expected
    shouldSendAtLeastPerPeriod = expectedMessagesPerPeriod / 2
    shouldSendAtLeastOverNPeriod = shouldSendAtLeastPerPeriod * averageOverNPeriods

    messageDeliveryThreshold = shouldSendAtLeastOverNPeriod
    messageDeliveryWeight = computeMessageDeliveriesWeight(messageDeliveryThreshold, 30.0)
    messageDeliveryDecay =
      computeDecay(
        startValue = expectedMessagesPerPeriod.float * averageOverNPeriods,
        endValue = 0,
        timeToEndValue = period * averageOverNPeriods.int,
        heartbeatPeriod)

    # Invalid message should be remembered a long time
    invalidMessageDecay = computeDecay(
                            startValue = 1,
                            endValue = 0.1,
                            timeToEndValue = chronos.minutes(1),
                            heartbeatPeriod)

  let topicParams = TopicParams(
    topicWeight: topicWeight,
    timeInMeshWeight: 0.1,
    timeInMeshQuantum: timeInMeshQuantum,
    timeInMeshCap: 300, # 30 points after timeInMeshQuantum * 300
    firstMessageDeliveriesWeight: 35.0 / shouldBeFirstOverNPeriod,
    firstMessageDeliveriesDecay: firstMessageDecay,
    firstMessageDeliveriesCap: shouldBeFirstOverNPeriod, # Max points: 70
    meshMessageDeliveriesWeight: messageDeliveryWeight,
    meshMessageDeliveriesDecay: messageDeliveryDecay,
    meshMessageDeliveriesThreshold: messageDeliveryThreshold,
    meshMessageDeliveriesCap: expectedMessagesPerPeriod.float * averageOverNPeriods,
    meshMessageDeliveriesActivation: period * averageOverNPeriods.int,
    meshMessageDeliveriesWindow: chronos.milliseconds(10),
    meshFailurePenaltyWeight: messageDeliveryWeight,
    meshFailurePenaltyDecay: messageDeliveryDecay,
    invalidMessageDeliveriesWeight: -1, # 10 invalid messages = -100 points
    invalidMessageDeliveriesDecay: invalidMessageDecay
  )
  topicParams

proc getTopicParams(
  heartbeatPeriod: Duration,
  slotPeriod: Duration,
  peersPerTopic: int,
  topicType: TopicType): TopicParams =
  case topicType:
    of BlockTopic:
      getTopicParams(
        topicWeight = 0.1,
        heartbeatPeriod = heartbeatPeriod,
        period = slotPeriod,
        averageOverNPeriods = 10, # Average over 10 slots, to smooth missing proposals
        peersPerTopic = peersPerTopic,
        expectedMessagesPerPeriod = 1, # One proposal per slot
        timeInMeshQuantum = chronos.seconds(15) # Stable topic
      )
    of AggregateTopic:
      getTopicParams(
        topicWeight = 0.1,
        heartbeatPeriod = heartbeatPeriod,
        period = slotPeriod,
        averageOverNPeriods = 2,
        peersPerTopic = peersPerTopic,
        expectedMessagesPerPeriod = (TARGET_AGGREGATORS_PER_COMMITTEE * ATTESTATION_SUBNET_COUNT).int,
        timeInMeshQuantum = chronos.seconds(15) # Stable topic
      )
    of SubnetTopic:
      getTopicParams(
        topicWeight = 0.8 / ATTESTATION_SUBNET_COUNT,
        heartbeatPeriod = heartbeatPeriod,
        period = slotPeriod,
        averageOverNPeriods = ATTESTATION_SUBNET_COUNT, # Smooth out empty committees
        peersPerTopic = peersPerTopic,
        expectedMessagesPerPeriod = TARGET_COMMITTEE_SIZE.int, #TODO use current number
        timeInMeshQuantum = chronos.seconds(6) # Flaky topic
      )
    of OtherTopic:
      TopicParams.init()

static:
  for topicType in ord(low(TopicType))..ord(high(TopicType)):
    getTopicParams(
        heartbeatPeriod = chronos.milliseconds(700),
        slotPeriod = chronos.seconds(12),
        peersPerTopic = 8,
        TopicType(topicType)
      ).validateParameters().tryGet()


proc getTopicParams(node: Eth2Node, topicType: TopicType): TopicParams =
  let
    heartbeatPeriod = node.pubsub.parameters.heartbeatInterval
    slotPeriod = chronos.seconds(SECONDS_PER_SLOT.int)
    peersPerTopic = node.pubsub.parameters.d

  getTopicParams(heartbeatPeriod, slotPeriod, peersPerTopic, topicType)

proc subscribe*(
    node: Eth2Node, topic: string, topicType: TopicType,
    enableTopicMetrics: bool = false) =
  if enableTopicMetrics:
    node.pubsub.knownTopics.incl(topic)

  node.pubsub.topicParams[topic] = node.getTopicParams(topicType)

  # Passing in `nil` because we do all message processing in the validator
  node.pubsub.subscribe(topic, nil)

proc newValidationResultFuture(v: ValidationResult): Future[ValidationResult] =
  let res = newFuture[ValidationResult]("eth2_network.execValidator")
  res.complete(v)
  res

proc addValidator*[MsgType](node: Eth2Node,
                            topic: string,
                            msgValidator: proc(msg: MsgType):
                            ValidationResult {.gcsafe, raises: [Defect].} ) =
  # Message validators run when subscriptions are enabled - they validate the
  # data and return an indication of whether the message should be broadcast
  # or not - validation is `async` but implemented without the macro because
  # this is a performance hotspot.
  proc execValidator(topic: string, message: GossipMsg):
      Future[ValidationResult] {.raises: [Defect].} =
    inc nbc_gossip_messages_received
    trace "Validating incoming gossip message", len = message.data.len, topic

    var decompressed = snappy.decode(message.data, GOSSIP_MAX_SIZE)
    let res = if decompressed.len > 0:
      try:
        let decoded = SSZ.decode(decompressed, MsgType)
        decompressed = newSeq[byte](0) # release memory before validating
        msgValidator(decoded) # doesn't raise!
      except SszError as e:
        inc nbc_gossip_failed_ssz
        debug "Error decoding gossip",
          topic, len = message.data.len, decompressed = decompressed.len,
          error = e.msg
        ValidationResult.Reject
    else: # snappy returns empty seq on failed decompression
      inc nbc_gossip_failed_snappy
      debug "Error decompressing gossip", topic, len = message.data.len
      ValidationResult.Reject

    newValidationResultFuture(res)

  node.validTopics.incl topic # Only allow subscription to validated topics
  node.pubsub.addValidator(topic, execValidator)

proc addAsyncValidator*[MsgType](node: Eth2Node,
                            topic: string,
                            msgValidator: proc(msg: MsgType):
                            Future[ValidationResult] {.gcsafe, raises: [Defect].} ) =
  proc execValidator(topic: string, message: GossipMsg):
      Future[ValidationResult] {.raises: [Defect].} =
    inc nbc_gossip_messages_received
    trace "Validating incoming gossip message", len = message.data.len, topic

    var decompressed = snappy.decode(message.data, GOSSIP_MAX_SIZE)
    if decompressed.len > 0:
      try:
        let decoded = SSZ.decode(decompressed, MsgType)
        decompressed = newSeq[byte](0) # release memory before validating
        msgValidator(decoded) # doesn't raise!
      except SszError as e:
        inc nbc_gossip_failed_ssz
        debug "Error decoding gossip",
          topic, len = message.data.len, decompressed = decompressed.len,
          error = e.msg
        newValidationResultFuture(ValidationResult.Reject)
    else: # snappy returns empty seq on failed decompression
      inc nbc_gossip_failed_snappy
      debug "Error decompressing gossip", topic, len = message.data.len
      newValidationResultFuture(ValidationResult.Reject)

  node.validTopics.incl topic # Only allow subscription to validated topics

  node.pubsub.addValidator(topic, execValidator)

proc unsubscribe*(node: Eth2Node, topic: string) =
  node.pubsub.unsubscribeAll(topic)

proc traceMessage(fut: FutureBase, topic: string) =
  fut.addCallback do (arg: pointer):
    if not(fut.failed):
      trace "Outgoing pubsub message sent"
    elif fut.error != nil:
      debug "Gossip message not sent",
        topic, err = fut.error.msg
    else:
      debug "Unexpected future state for gossip",
        topic, state = fut.state

proc broadcast*(node: Eth2Node, topic: string, msg: auto) =
  try:
    let
      uncompressed = SSZ.encode(msg)
      compressed = try: snappy.encode(uncompressed)
      except InputTooLarge:
        raiseAssert "More than 4gb? not likely.."

    # This is only for messages we create. A message this large amounts to an
    # internal logic error.
    doAssert uncompressed.len <= GOSSIP_MAX_SIZE
    inc nbc_gossip_messages_sent

    var futSnappy = node.pubsub.publish(topic, compressed)
    traceMessage(futSnappy, topic)
  except IOError as exc:
    raiseAssert exc.msg # TODO in-memory compression shouldn't fail

proc subscribeAttestationSubnets*(
    node: Eth2Node, subnets: AttnetBits, forkDigest: ForkDigest) =
  # https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#attestations-and-aggregation
  # Nimbus won't score attestation subnets for now, we just rely on block and
  # aggregate which are more stable and reliable

  for subnet_id, enabled in subnets:
    if enabled:
      node.subscribe(getAttestationTopic(
        forkDigest, SubnetId(subnet_id)), SubnetTopic) # don't score attestation subnets for now

proc unsubscribeAttestationSubnets*(
    node: Eth2Node, subnets: AttnetBits, forkDigest: ForkDigest) =
  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/p2p-interface.md#attestations-and-aggregation
  # Nimbus won't score attestation subnets for now; we just rely on block and
  # aggregate which are more stable and reliable

  for subnet_id, enabled in subnets:
    if enabled:
      node.unsubscribe(getAttestationTopic(forkDigest, SubnetId(subnet_id)))

proc updateStabilitySubnetMetadata*(node: Eth2Node, attnets: AttnetBits) =
  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/p2p-interface.md#metadata
  if node.metadata.attnets == attnets:
    return

  node.metadata.seq_number += 1
  node.metadata.attnets = attnets

  # https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/validator.md#phase-0-attestation-subnet-stability
  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/p2p-interface.md#attestation-subnet-bitfield
  let res = node.discovery.updateRecord({
    enrAttestationSubnetsField: SSZ.encode(node.metadata.attnets)
  })
  if res.isErr():
    # This should not occur in this scenario as the private key would always
    # be the correct one and the ENR will not increase in size.
    warn "Failed to update the ENR attnets field", error = res.error
  else:
    debug "Stability subnets changed; updated ENR attnets", attnets

proc updateSyncnetsMetadata*(node: Eth2Node, syncnets: SyncnetBits) =
  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/altair/validator.md#sync-committee-subnet-stability
  if node.metadata.syncnets == syncnets:
    return

  node.metadata.seq_number += 1
  node.metadata.syncnets = syncnets

  let res = node.discovery.updateRecord({
    enrSyncSubnetsField: SSZ.encode(node.metadata.syncnets)
  })
  if res.isErr():
    # This should not occur in this scenario as the private key would always
    # be the correct one and the ENR will not increase in size.
    warn "Failed to update the ENR syncnets field", error = res.error
  else:
    debug "Sync committees changed; updated ENR syncnets", syncnets

proc updateForkId(node: Eth2Node, value: ENRForkID) =
  node.forkId = value
  let res = node.discovery.updateRecord({enrForkIdField: SSZ.encode value})
  if res.isErr():
    # This should not occur in this scenario as the private key would always
    # be the correct one and the ENR will not increase in size.
    warn "Failed to update the ENR fork id", value, error = res.error
  else:
    debug "ENR fork id changed", value

proc updateForkId*(node: Eth2Node, epoch: Epoch, genesisValidatorsRoot: Eth2Digest) =
  node.updateForkId(getENRForkId(node.cfg, epoch, genesisValidatorsRoot))
  node.discoveryForkId = getDiscoveryForkID(node.cfg, epoch, genesisValidatorsRoot)

func forkDigestAtEpoch(node: Eth2Node, epoch: Epoch): ForkDigest =
  case node.cfg.stateForkAtEpoch(epoch)
  of BeaconStateFork.Merge:  node.forkDigests.merge
  of BeaconStateFork.Altair: node.forkDigests.altair
  of BeaconStateFork.Phase0: node.forkDigests.phase0

proc getWallEpoch(node: Eth2Node): Epoch =
  node.getBeaconTime().slotOrZero.epoch

proc broadcastAttestation*(node: Eth2Node, subnet_id: SubnetId,
                           attestation: Attestation) =
  # Regardless of the contents of the attestation,
  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/altair/p2p-interface.md#transitioning-the-gossip
  # implies that pre-fork, messages using post-fork digests might be
  # ignored, whilst post-fork, there is effectively a seen_ttl-based
  # timer unsubscription point that means no new pre-fork-forkdigest
  # should be sent.
  let forkPrefix = node.forkDigestAtEpoch(node.getWallEpoch)
  let topic = getAttestationTopic(forkPrefix, subnet_id)
  node.broadcast(topic, attestation)

proc broadcastVoluntaryExit*(node: Eth2Node, exit: SignedVoluntaryExit) =
  let topic = getVoluntaryExitsTopic(
    node.forkDigestAtEpoch(node.getWallEpoch))
  node.broadcast(topic, exit)

proc broadcastAttesterSlashing*(node: Eth2Node, slashing: AttesterSlashing) =
  let topic = getAttesterSlashingsTopic(
    node.forkDigestAtEpoch(node.getWallEpoch))
  node.broadcast(topic, slashing)

proc broadcastProposerSlashing*(node: Eth2Node, slashing: ProposerSlashing) =
  let topic = getProposerSlashingsTopic(
    node.forkDigestAtEpoch(node.getWallEpoch))
  node.broadcast(topic, slashing)

proc broadcastAggregateAndProof*(node: Eth2Node,
                                 proof: SignedAggregateAndProof) =
  let topic = getAggregateAndProofsTopic(
    node.forkDigestAtEpoch(node.getWallEpoch))
  node.broadcast(topic, proof)

proc broadcastBeaconBlock*(node: Eth2Node, blck: phase0.SignedBeaconBlock) =
  let topic = getBeaconBlocksTopic(node.forkDigests.phase0)
  node.broadcast(topic, blck)

proc broadcastBeaconBlock*(node: Eth2Node, blck: altair.SignedBeaconBlock) =
  let topic = getBeaconBlocksTopic(node.forkDigests.altair)
  node.broadcast(topic, blck)

proc broadcastBeaconBlock*(node: Eth2Node, blck: merge.SignedBeaconBlock) =
  let topic = getBeaconBlocksTopic(node.forkDigests.merge)
  node.broadcast(topic, blck)

proc broadcastBeaconBlock*(node: Eth2Node, forked: ForkedSignedBeaconBlock) =
  withBlck(forked): node.broadcastBeaconBlock(blck)

proc broadcastSyncCommitteeMessage*(
    node: Eth2Node, msg: SyncCommitteeMessage, committeeIdx: SyncSubcommitteeIndex) =
  let topic = getSyncCommitteeTopic(node.forkDigests.altair, committeeIdx)
  node.broadcast(topic, msg)

proc broadcastSignedContributionAndProof*(
    node: Eth2Node, msg: SignedContributionAndProof) =
  let topic = getSyncCommitteeContributionAndProofTopic(node.forkDigests.altair)
  node.broadcast(topic, msg)
