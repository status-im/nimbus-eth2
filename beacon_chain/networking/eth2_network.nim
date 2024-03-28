{.push raises: [].}

import
  std/[typetraits, os, strutils, tables, macrocache],
  results,
  json_serialization, json_serialization/std/[net, sets, options],
  chronos,
  libp2p/[switch, peerinfo, crypto/crypto,
    crypto/secp],
  libp2p/protocols/pubsub/[
      pubsub, gossipsub, rpc/message, rpc/messages, pubsubpeer],
  eth/[async_utils],
  ../spec/[eth2_ssz_serialization, network]

type
  ErrorMsg = List[byte, 256]
  DirectPeers = Table[PeerId, seq[MultiAddress]]

  SeenItem = object
    peerId: PeerId
    stamp: chronos.Moment

  Eth2Node = ref object of RootObj
    switch: Switch
    pubsub: GossipSub
    discoveryEnabled: bool
    wantedPeers: int
    hardMaxPeers: int
    protocols: seq[ProtocolInfo]
    protocolStates: seq[RootRef]
    connQueue: AsyncQueue[PeerAddr]
    seenTable: Table[PeerId, SeenItem]
    connWorkers: seq[Future[void].Raising([CancelledError])]
    connTable: HashSet[PeerId]
    forkId: ENRForkID
    discoveryForkId: ENRForkID
    rng: ref HmacDrbgContext
    peers: Table[PeerId, Peer]
    directPeers: DirectPeers
    validTopics: HashSet[string]
    peerPingerHeartbeatFut: Future[void].Raising([CancelledError])
    peerTrimmerHeartbeatFut: Future[void].Raising([CancelledError])
    cfg: RuntimeConfig

  AverageThroughput = object
    count: uint64
    average: float

  Peer = ref object
    network: Eth2Node
    peerId: PeerId
    connectionState: ConnectionState
    protocolStates: seq[RootRef]
    netThroughput: AverageThroughput
    score: int
    lastReqTime: Moment
    connections: int
    metadata: Opt[altair.MetaData]
    failedMetadataRequests: int
    lastMetadataTime: Moment
    disconnectedFut: Future[void]

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

  MultipleChunksResponse[MsgType; maxLen: static Limit] = distinct UntypedResponse

  MessageInfo = object
    name: string

    libp2pCodecName: string
    protocolMounter: MounterProc

  ProtocolInfoObj = object
    name: string
    messages: seq[MessageInfo]
    index: int # the position of the protocol in the
                # ordered list of supported protocols

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
  MounterProc = proc(network: Eth2Node) {.gcsafe, raises: [].}

  DisconnectionReason = enum
    ClientShutDown = 1
    IrrelevantNetwork = 2
    FaultOrError = 3
    PeerScoreLow = 237 # 79  3

  Eth2NetworkingErrorKind = enum
    BrokenConnection
    ReceivedErrorResponse
    UnexpectedEOF
    PotentiallyExpectedEOF
    StreamOpenTimeout
    ReadResponseTimeout

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

const
  requestPrefix = "/eth2/beacon_chain/req/"
  requestSuffix = "/ssz_snappy"

  SeenTableTimeIrrelevantNetwork = 24.hours
  SeenTableTimeClientShutDown = 10.minutes
  SeenTableTimeFaultOrError = 10.minutes
  SeenTablePenaltyError = 60.minutes
  ProtocolViolations = {InvalidResponseCode..Eth2NetworkingErrorKind.high()}

template neterr(kindParam: Eth2NetworkingErrorKind): auto =
  err(type(result), Eth2NetworkingError(kind: kindParam))

const
  libp2p_pki_schemes {.strdefine.} = ""

when libp2p_pki_schemes != "secp256k1":
  {.fatal: "Incorrect building process, please use -d:\"libp2p_pki_schemes=secp256k1\"".}

template libp2pProtocol(name: string, version: int) {.pragma.}

func shortProtocolId(protocolId: string): string =
  let
    start = if protocolId.startsWith(requestPrefix): requestPrefix.len else: 0
    ends = if protocolId.endsWith(requestSuffix):
      protocolId.high - requestSuffix.len
    else:
      protocolId.high
  protocolId[start..ends]

proc init(T: type Peer, network: Eth2Node, peerId: PeerId): Peer {.gcsafe.}

proc getPeer(node: Eth2Node, peerId: PeerId): Peer =
  node.peers.withValue(peerId, peer) do:
    return peer[]
  do:
    let peer = Peer.init(node, peerId)
    return node.peers.mgetOrPut(peerId, peer)

proc peerFromStream(network: Eth2Node, conn: Connection): Peer =
  result = network.getPeer(conn.peerId)
  result.peerId = conn.peerId

func updateScore(peer: Peer, score: int) = discard
func calcThroughput(dur: Duration, value: uint64): float =
  let secs = float(chronos.seconds(1).nanoseconds)
  if isZero(dur):
    0.0
  else:
    float(value) * (secs / float(dur.nanoseconds))

func updateNetThroughput(peer: Peer, dur: Duration,
                         bytesCount: uint64) {.inline.} =
  let bytesPerSecond = calcThroughput(dur, bytesCount)
  let a = peer.netThroughput.average
  let n = peer.netThroughput.count
  peer.netThroughput.average = a + (bytesPerSecond - a) / float(n + 1)
  inc(peer.netThroughput.count)

func `<`(a, b: Peer): bool =
  if a.score < b.score:
    true
  elif a.score == b.score:
    (a.netThroughput.average < b.netThroughput.average)
  else:
    false

const
  maxRequestQuota = 1000000
  fullReplenishTime = 5.seconds

template awaitQuota(peerParam: Peer, costParam: float, protocolIdParam: string) = discard

template awaitQuota(
    networkParam: Eth2Node, costParam: float, protocolIdParam: string) =
  let
    network = networkParam
    cost = int(costParam)

  if not network.quota.tryConsume(cost.int):
    let protocolId = protocolIdParam
    nbc_reqresp_messages_throttled.inc(1, [protocolId])
    await network.quota.consume(cost.int)

func allowedOpsPerSecondCost(n: int): float =
  const replenishRate = (maxRequestQuota / fullReplenishTime.nanoseconds.float)
  (replenishRate * 1000000000'f / n.float)

const
  libp2pRequestCost = allowedOpsPerSecondCost(8)

proc addSeen(network: Eth2Node, peerId: PeerId,
              period: chronos.Duration) =
  let item = SeenItem(peerId: peerId, stamp: now(chronos.Moment) + period)
  withValue(network.seenTable, peerId, entry) do:
    if entry.stamp < item.stamp:
      entry.stamp = item.stamp
  do:
    network.seenTable[peerId] = item

proc disconnect(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async: (raises: [CancelledError]).} =
  try:
    if peer.connectionState notin {Disconnecting, Disconnected}:
      peer.connectionState = Disconnecting
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
  except CatchableError:
    discard

proc releasePeer(peer: Peer) = discard
template errorMsgLit(x: static string): ErrorMsg = default(ErrorMsg)
proc sendErrorResponse(peer: Peer,
                       conn: Connection,
                       responseCode: ResponseCode,
                       errMsg: ErrorMsg): Future[void] = discard
proc uncompressFramedStream(conn: Connection,
                            expectedSize: int): Future[Result[seq[byte], string]]
                            {.async: (raises: [CancelledError]).} = discard
func chunkMaxSize[T](): uint32 =
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
    neterr UnexpectedEOF
  except LPStreamIncompleteError:
    neterr UnexpectedEOF
  except InvalidVarintError:
    neterr InvalidSizePrefix
  except CancelledError as exc:
    raise exc
  except CatchableError:
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

  let
    dataRes = await conn.uncompressFramedStream(size.int)
    data = dataRes.valueOr:
      return neterr InvalidSnappyBytes

  peer.updateNetThroughput(now(chronos.Moment) - sm,
                            uint64(10 + size))
  try:
    ok SSZ.decode(data, MsgType)
  except SerializationError:
    neterr InvalidSszBytes

proc init(T: type MultipleChunksResponse, peer: Peer, conn: Connection): T =
  T(UntypedResponse(peer: peer, stream: conn))

proc init[MsgType](T: type SingleChunkResponse[MsgType],
                    peer: Peer, conn: Connection): T =
  T(UntypedResponse(peer: peer, stream: conn))

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

proc handleIncomingStream(network: Eth2Node,
                          conn: Connection,
                          protocolId: string,
                          MsgType: type) {.async: (raises: [CancelledError]).} =
  mixin callUserHandler, RecType

  type MsgRec = RecType(MsgType)
  const msgName {.used.} = typetraits.name(MsgType)


  let peer = peerFromStream(network, conn)
  try:
    case peer.connectionState
    of Disconnecting, Disconnected, None:
      return
    of Connecting:
      discard
    of Connected:
      discard

    template returnInvalidRequest(msg: ErrorMsg) =
      await sendErrorResponse(peer, conn, InvalidRequest, msg)
      return

    template returnInvalidRequest(msg: string) =
      returnInvalidRequest(default(ErrorMsg))

    template returnResourceUnavailable(msg: ErrorMsg) =
      await sendErrorResponse(peer, conn, ResourceUnavailable, msg)
      return

    template returnResourceUnavailable(msg: string) =
      returnResourceUnavailable(default(ErrorMsg))

    const isEmptyMsg = when MsgRec is object:
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




        awaitQuota(peer, libp2pRequestCost, shortProtocolId(protocolId))

    try:
      await callUserHandler(MsgType, peer, conn, msg.get)
    except InvalidInputsError as exc:
      returnInvalidRequest exc.msg
    except ResourceUnavailableError as exc:
      returnResourceUnavailable exc.msg
    except CatchableError as exc:
      await sendErrorResponse(peer, conn, ServerError, default(ErrorMsg))

  except CatchableError:
    discard

  finally:
    try:
      await noCancel conn.closeWithEOF()
    except CatchableError:
      discard
    releasePeer(peer)

proc init(T: type Peer, network: Eth2Node, peerId: PeerId): Peer =
  let res = Peer(
    peerId: peerId,
    network: network,
    connectionState: ConnectionState.None,
    lastReqTime: now(chronos.Moment),
    lastMetadataTime: now(chronos.Moment),
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

type
  BeaconSync = object
type
  beaconBlocksByRange_v2Obj = object
    reqCount: uint64
    reqStep: uint64

template RecType(MSG: type beaconBlocksByRange_v2Obj): untyped =
  beaconBlocksByRange_v2Obj

var BeaconSyncProtocolObj = initProtocol("BeaconSync", nil, nil, 0)
let BeaconSyncProtocol = addr BeaconSyncProtocolObj
proc beaconBlocksByRange_v2UserHandler(peer: Peer; reqCount: uint64;
                                       reqStep: uint64; response: MultipleChunksResponse[
    ref uint64, Limit MAX_REQUEST_BLOCKS]) {.async,
    libp2pProtocol("beacon_blocks_by_range", 2), gcsafe.} =
  type
    CurrentProtocol {.used.} = BeaconSync

  discard

template callUserHandler(MSG: type beaconBlocksByRange_v2Obj; peer: Peer;
                         stream: Connection; msg: beaconBlocksByRange_v2Obj): untyped =
  var response = init(MultipleChunksResponse[ref uint64,
      Limit MAX_REQUEST_BLOCKS], peer, stream)
  beaconBlocksByRange_v2UserHandler(peer, msg.reqCount, msg.reqStep, response)

proc beaconBlocksByRange_v2Mounter(network: Eth2Node) {.raises: [].} =
  proc snappyThunk(stream: Connection; protocol: string): Future[void] {.gcsafe.} =
    return handleIncomingStream(network, stream, protocol,
                                beaconBlocksByRange_v2Obj)

  try:
    mount network.switch, LPProtocol.new(codecs = @[
        "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"],
        handler = snappyThunk)
  except LPError:
    raiseAssert "foo"

registerMsg(BeaconSyncProtocol, "beaconBlocksByRange_v2",
            beaconBlocksByRange_v2Mounter,
            "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy")
setEventHandlers(BeaconSyncProtocol, nil, nil)
