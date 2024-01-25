# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[sequtils],
  stew/[results, base10],
  chronicles,
  chronos/apps/http/httpdebug,
  libp2p/[multiaddress, multicodec, peerstore],
  libp2p/protocols/pubsub/pubsubpeer,
  ./rest_utils,
  ../el/el_manager,
  ../validators/beacon_validators,
  ../spec/[forks, beacon_time],
  ../beacon_node, ../nimbus_binary_common

export rest_utils

when defined(chronosFutureTracking):
  import stew/base10

logScope: topics = "rest_nimbusapi"

type
  RestPeerInfo* = object
    peerId*: string
    addrs*: seq[string]
    protocols*: seq[string]
    protoVersion*: string
    agentVersion*: string

  RestPeerInfoTuple* = tuple
    peerId: string
    addrs: seq[string]
    protocols: seq[string]
    protoVersion: string
    agentVersion: string

  RestSimplePeer* = object
    info*: RestPeerInfo
    connectionState*: string
    score*: int

  RestFutureInfo* = object
    id*: string
    child_id*: string
    procname*: string
    filename*: string
    line*: int
    state*: string

  RestChronosMetricsInfo* = object
    tcp_transports*: uint64
    udp_transports*: uint64
    tcp_servers*: uint64
    stream_readers*: uint64
    stream_writers*: uint64
    http_client_connections*: uint64
    http_client_requests*: uint64
    http_client_responses*: uint64
    http_server_secure_connections*: uint64
    http_server_unsecure_connections*: uint64
    http_server_requests*: uint64
    http_server_responses*: uint64
    http_body_readers*: uint64
    http_body_writers*: uint64

  RestConnectionInfo* = object
    handle*: string
    query*: string
    connection_type*: string
    connection_state*: string
    remote_address*: string
    local_address*: string
    since_accept*: string
    since_create*: string

  RestPubSubPeer* = object
    peerId*: PeerId
    score*: float64
    iHaveBudget*: int
    outbound*: bool
    appScore*: float64
    behaviourPenalty*: float64
    sendConnAvail*: bool
    closed*: bool
    atEof*: bool
    address*: string
    backoff*: string
    agent*: string

  RestPeerStats* = object
    peerId*: PeerId
    null*: bool
    connected*: bool
    expire*: string
    score*: float64

  RestPeerStatus* = object
    peerId*: PeerId
    connected*: bool

RestJson.useDefaultSerializationFor(
  BlockProposalEth1Data,
  Eth1BlockObj,
  RestChronosMetricsInfo,
  RestConnectionInfo,
  RestFutureInfo,
  RestPeerInfo,
  RestPeerInfoTuple,
  RestPeerStats,
  RestPeerStatus,
  RestPubSubPeer,
  RestSimplePeer,
)

proc toInfo(node: BeaconNode, peerId: PeerId): RestPeerInfo =
  RestPeerInfo(
    peerId: $peerId,
    addrs: node.network.switch.peerStore[AddressBook][peerId].mapIt($it),
    protocols: node.network.switch.peerStore[ProtoBook][peerId],
    protoVersion: node.network.switch.peerStore[ProtoVersionBook][peerId],
    agentVersion: node.network.switch.peerStore[AgentBook][peerId]
  )

proc toNode(v: PubSubPeer, backoff: Moment): RestPubSubPeer =
  RestPubSubPeer(
    peerId: v.peerId,
    score: v.score,
    iHaveBudget: v.iHaveBudget,
    outbound: v.outbound,
    appScore: v.appScore,
    behaviourPenalty: v.behaviourPenalty,
    sendConnAvail: v.sendConn != nil,
    closed: v.sendConn != nil and v.sendConn.closed,
    atEof: v.sendConn != nil and v.sendConn.atEof,
    address:
      if v.address.isSome():
        $v.address.get()
      else:
        "<no address>",
    backoff: $(backoff - Moment.now()),
    agent:
      when defined(libp2p_agents_metrics):
        v.shortAgent
      else:
        "unknown"
  )

proc installNimbusApiHandlers*(router: var RestRouter, node: BeaconNode) =
  router.api(MethodGet, "/nimbus/v1/beacon/head") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(node.dag.head.slot)

  router.api(MethodGet, "/nimbus/v1/chain/head") do() -> RestApiResponse:
    let
      head = node.dag.head
      finalized = getStateField(node.dag.headState, finalized_checkpoint)
      justified =
        getStateField(node.dag.headState, current_justified_checkpoint)
    return RestApiResponse.jsonResponse(
      (
        head_slot: head.slot,
        head_block_root: head.root.data.toHex(),
        finalized_slot: finalized.epoch * SLOTS_PER_EPOCH,
        finalized_block_root: finalized.root.data.toHex(),
        justified_slot: justified.epoch * SLOTS_PER_EPOCH,
        justified_block_root: justified.root.data.toHex()
      )
    )

  router.api(MethodGet, "/nimbus/v1/syncmanager/status") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse(node.syncManager.inProgress)

  router.api(MethodGet, "/nimbus/v1/node/peerid") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse((peerid: $node.network.peerId()))

  router.api(MethodGet, "/nimbus/v1/node/version") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse((version: "Nimbus/" & fullVersionStr))

  router.api(MethodGet, "/nimbus/v1/network/ids") do (
    ) -> RestApiResponse:
    var res: seq[PeerId]
    for peerId, peer in node.network.peerPool:
      res.add(peerId)
    return RestApiResponse.jsonResponse((peerids: res))

  router.api(MethodGet, "/nimbus/v1/network/peers") do (
    ) -> RestApiResponse:
    var res: seq[RestSimplePeer]
    for id, peer in node.network.peerPool:
      res.add(
        RestSimplePeer(
          info: toInfo(node, id),
          connectionState: $peer.connectionState,
          score: peer.score
        )
      )
    return RestApiResponse.jsonResponse((peers: res))

  router.api(MethodPost, "/nimbus/v1/graffiti") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    if contentBody.isNone:
      return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)

    template setGraffitiAux(node: BeaconNode,
                            graffitiStr: string): RestApiResponse =
      node.graffitiBytes = try:
        GraffitiBytes.init(graffitiStr)
      except CatchableError as err:
        return RestApiResponse.jsonError(Http400, InvalidGraffitiBytesValue,
                                         err.msg)
      RestApiResponse.jsonResponse((result: true))

    let body = contentBody.get()
    if body.contentType == ApplicationJsonMediaType:
      let graffitiBytes = decodeBody(GraffitiBytes, body)
      if graffitiBytes.isErr():
        return RestApiResponse.jsonError(Http400, InvalidGraffitiBytesValue,
                                         $graffitiBytes.error())
      node.graffitiBytes = graffitiBytes.get()
      return RestApiResponse.jsonResponse((result: true))
    elif body.contentType == TextPlainMediaType:
      return node.setGraffitiAux body.strData()
    elif body.contentType == UrlEncodedMediaType:
      return node.setGraffitiAux decodeUrl(body.strData())
    else:
      return RestApiResponse.jsonError(Http400, "Unsupported content type: " &
                                                $body.contentType)

  router.api(MethodGet, "/nimbus/v1/graffiti") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse(node.graffitiBytes)

  router.api(MethodPost, "/nimbus/v1/chronicles/settings") do (
    log_level: Option[string]) -> RestApiResponse:
    if log_level.isSome():
      let level =
        block:
          let res = log_level.get()
          if res.isErr():
            return RestApiResponse.jsonError(Http400, InvalidLogLevelValueError,
                                             $res.error())
          res.get()
      {.gcsafe.}:
        updateLogLevel(level)
    return RestApiResponse.jsonResponse((result: true))

  router.api(MethodGet, "/nimbus/v1/eth1/chain") do (
    ) -> RestApiResponse:
    let res = mapIt(node.elManager.eth1ChainBlocks, it)
    return RestApiResponse.jsonResponse(res)

  router.api(MethodGet, "/nimbus/v1/eth1/proposal_data") do (
    ) -> RestApiResponse:
    let wallSlot = node.beaconClock.now.slotOrZero
    let head =
      block:
        let res = node.getSyncedHead(wallSlot)
        if res.isErr():
          return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError,
                                           $res.error())
        let tres = res.get()
        if not tres.executionValid:
          return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
        tres
    let proposalState = assignClone(node.dag.headState)
    node.dag.withUpdatedState(
        proposalState[],
        head.atSlot(wallSlot).toBlockSlotId().expect("not nil")):
      return RestApiResponse.jsonResponse(
        node.getBlockProposalEth1Data(updatedState))
    do:
      return RestApiResponse.jsonError(Http400, PrunedStateError)

  router.api(MethodGet, "/nimbus/v1/debug/chronos/futures") do (
    ) -> RestApiResponse:
    when defined(chronosFutureTracking):
      var res: seq[RestFutureInfo]
      for item in pendingFutures():
        let loc = item.location[LocCreateIndex][]
        let futureId = Base10.toString(item.id)
        let childId =
          if isNil(item.child): ""
          else: Base10.toString(item.child.id)
        res.add(
          RestFutureInfo(
            id: futureId,
            child_id: childId,
            procname: $loc.procedure,
            filename: $loc.file,
            line: loc.line,
            state: $item.state
          )
        )
      return RestApiResponse.jsonResponse(res)
    else:
      return RestApiResponse.jsonError(Http503,
        "Compile with '-d:chronosFutureTracking' to get this request working")

  router.api(MethodGet, "/nimbus/v1/debug/chronos/metrics") do (
    ) -> RestApiResponse:

    template getCount(name: string): uint64 =
      let res = getTrackerCounter(name)
      uint64(res.opened - res.closed)

    let res = RestChronosMetricsInfo(
      tcp_transports: getCount(StreamTransportTrackerName),
      udp_transports: getCount(DgramTransportTrackerName),
      tcp_servers: getCount(StreamServerTrackerName),
      stream_readers: getCount(AsyncStreamReaderTrackerName),
      stream_writers: getCount(AsyncStreamWriterTrackerName),
      http_client_connections: getCount(HttpClientConnectionTrackerName),
      http_client_requests: getCount(HttpClientRequestTrackerName),
      http_client_responses: getCount(HttpClientResponseTrackerName),
      http_server_secure_connections:
        getCount(HttpServerSecureConnectionTrackerName),
      http_server_unsecure_connections:
        getCount(HttpServerUnsecureConnectionTrackerName),
      http_server_requests: getCount(HttpServerRequestTrackerName),
      http_server_responses: getCount(HttpServerResponseTrackerName),
      http_body_readers: getCount(HttpBodyReaderTrackerName),
      http_body_writers: getCount(HttpBodyWriterTrackerName)
    )
    return RestApiResponse.jsonResponse(res)

  router.api(MethodGet, "/nimbus/v1/debug/chronos/restserver/connections") do (
    ) -> RestApiResponse:
    var res: seq[RestConnectionInfo]
    for connection in node.restServer.server.getConnections():
      let
        connectionState =
          case connection.connectionState
          of httpdebug.ConnectionState.Accepted: "accepted"
          of httpdebug.ConnectionState.Alive: "alive"
          of httpdebug.ConnectionState.Closing: "closing"
          of httpdebug.ConnectionState.Closed: "closed"
        connectionType =
          case connection.connectionType
          of ConnectionType.Secure: "secure"
          of ConnectionType.NonSecure: "non-secure"
        localAddress =
          if connection.localAddress.isNone():
            "not available"
          else:
            $connection.localAddress.get()
        remoteAddress =
          if connection.remoteAddress.isNone():
            "not available"
          else:
            $connection.remoteAddress.get()
        query = connection.query.get("not available")
        handle = Base10.toString(uint64(connection.handle))
        moment = Moment.now()
        sinceAccept = $(moment - connection.acceptMoment)
        sinceCreate =
          if connection.createMoment.isSome():
            $(moment - connection.createMoment.get())
          else:
            "not available"

      res.add(
        RestConnectionInfo(
          handle: handle,
          query: query,
          connection_state: connectionState,
          connection_type: connectionType,
          local_address: localAddress,
          remote_address: remoteAddress,
          since_accept: sinceAccept,
          since_create: sinceCreate
        )
      )
    return RestApiResponse.jsonResponse(res)

  router.api(MethodPost, "/nimbus/v1/validator/activity/{epoch}") do (
    epoch: Epoch, contentBody: Option[ContentBody]) -> RestApiResponse:
    let indexList =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[RestValidatorIndex], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidValidatorIndexValueError,
                                           $dres.error())
        var
          res: seq[ValidatorIndex]
          dupset: HashSet[ValidatorIndex]

        let items = dres.get()
        for item in items:
          let vres = item.toValidatorIndex()
          if vres.isErr():
            case vres.error()
            of ValidatorIndexError.TooHighValue:
              return RestApiResponse.jsonError(Http400,
                                               TooHighValidatorIndexValueError)
            of ValidatorIndexError.UnsupportedValue:
              return RestApiResponse.jsonError(Http500,
                                            UnsupportedValidatorIndexValueError)
          let index = vres.get()
          if index in dupset:
            return RestApiResponse.jsonError(Http400,
                                             DuplicateValidatorIndexArrayError)
          dupset.incl(index)
          res.add(index)
        if len(res) == 0:
          return RestApiResponse.jsonError(Http400,
                                           EmptyValidatorIndexArrayError)
        res
    let qepoch =
      block:
        if epoch.isErr():
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                           $epoch.error())
        let
          res = epoch.get()
          wallEpoch = node.currentSlot().epoch()
          nextEpoch =
            if wallEpoch == FAR_FUTURE_EPOCH:
              wallEpoch
            else:
              wallEpoch + 1
          prevEpoch = get_previous_epoch(wallEpoch)
        if (res < prevEpoch) or (res > nextEpoch):
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                    "Requested epoch is more than one epoch from current epoch")
        res
    let response = indexList.mapIt(
      RestActivityItem(
        index: it,
        epoch: qepoch,
        active: node.attestationPool[].validatorSeenAtEpoch(qepoch, it)
      )
    )
    return RestApiResponse.jsonResponse(response)

  router.api(MethodGet, "/nimbus/v1/debug/gossip/peers") do (
    ) -> RestApiResponse:

    let gossipPeers =
      block:
        var res: seq[tuple[topic: string, peers: seq[RestPubSubPeer]]]
        for topic, v in node.network.pubsub.gossipsub:
          var peers: seq[RestPubSubPeer]
          let backoff = node.network.pubsub.backingOff.getOrDefault(topic)
          for peer in v:
            peers.add(peer.toNode(backoff.getOrDefault(peer.peerId)))
          res.add((topic: topic, peers: peers))
        res
    let meshPeers =
      block:
        var res: seq[tuple[topic: string, peers: seq[RestPubSubPeer]]]
        for topic, v in node.network.pubsub.mesh:
          var peers: seq[RestPubSubPeer]
          let backoff = node.network.pubsub.backingOff.getOrDefault(topic)
          for peer in v:
            peers.add(peer.toNode(backoff.getOrDefault(peer.peerId)))
          res.add((topic: topic, peers: peers))
        res
    let colocationPeers =
      block:
        var res: seq[tuple[address: string, peerids: seq[PeerId]]]
        for k, v in node.network.pubsub.peersInIP:
          var peerids: seq[PeerId]
          for id in v:
            peerids.add(id)
          res.add(($k, peerids))
        res
    let peerStats =
      block:
        var stats: seq[RestPeerStats]
        for peerId, pstats in node.network.pubsub.peerStats:
          let peer = node.network.pubsub.peers.getOrDefault(peerId)
          stats.add(
            RestPeerStats(
              peerId: peerId,
              null: isNil(peer),
              connected: if isNil(peer): false else: peer.connected(),
              expire: $(pstats.expire - Moment.now()),
              score: pstats.score
            )
          )
        stats
    let allPeers =
      block:
        var peers: seq[RestPeerStatus]
        for peerId, peer in node.network.pubsub.peers:
          peers.add(RestPeerStatus(peerId: peerId, connected: peer.connected))
        peers
    return RestApiResponse.jsonResponse(
      (
        gossip_peers: gossipPeers,
        mesh_peers: meshPeers,
        colocation_peers: colocationPeers,
        peer_stats: peerStats,
        all_peers: allPeers
      )
    )

  router.api(MethodPost, "/nimbus/v1/timesync") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let
      timestamp2 = getTimestamp()
      timestamp1 =
        block:
          if contentBody.isNone():
            return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
          let dres = decodeBody(RestNimbusTimestamp1, contentBody.get())
          if dres.isErr():
            return RestApiResponse.jsonError(Http400,
                                             InvalidTimestampValue,
                                             $dres.error())
          dres.get().timestamp1
    let
      delay = node.processingDelay.valueOr: ZeroDuration
      response = RestNimbusTimestamp2(
        timestamp1: timestamp1,
        timestamp2: timestamp2,
        timestamp3: getTimestamp(),
        delay: uint64(delay.nanoseconds)
      )
    return RestApiResponse.jsonResponsePlain(response)
