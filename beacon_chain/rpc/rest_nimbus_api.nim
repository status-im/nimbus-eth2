# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[strutils, sequtils],
  stew/base10,
  results,
  chronicles,
  chronos/apps/http/httpdebug,
  libp2p/[multiaddress, multicodec, peerstore],
  libp2p/protocols/pubsub/pubsubpeer,
  ./rest_utils,
  ../el/el_manager,
  ../spec/[forks, beacon_time, peerdas_helpers, column_map],
  ../sync/validator_custody,
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
  router.api2(MethodGet, "/nimbus/v1/beacon/head") do () -> RestApiResponse:
    RestApiResponse.jsonResponse(node.dag.head.slot)

  router.api2(MethodGet, "/nimbus/v1/chain/head") do() -> RestApiResponse:
    let
      head = node.dag.head
      finalized = node.dag.headState.finalized_checkpoint
      justified = node.dag.headState.current_justified_checkpoint
    RestApiResponse.jsonResponse(
      (
        head_slot: head.slot,
        head_block_root: head.root.data.toHex(),
        finalized_slot: finalized.epoch * SLOTS_PER_EPOCH,
        finalized_block_root: finalized.root.data.toHex(),
        justified_slot: justified.epoch * SLOTS_PER_EPOCH,
        justified_block_root: justified.root.data.toHex()
      )
    )

  router.api2(MethodGet, "/nimbus/v1/syncmanager/status") do (
    ) -> RestApiResponse:
    RestApiResponse.jsonResponse(node.syncManager.inProgress)

  router.api2(MethodGet, "/nimbus/v1/node/peerid") do (
    ) -> RestApiResponse:
    RestApiResponse.jsonResponse((peerid: $node.network.peerId()))

  router.api2(MethodGet, "/nimbus/v1/node/version") do (
    ) -> RestApiResponse:
    RestApiResponse.jsonResponse((version: "Nimbus/" & fullVersionStr))

  router.api2(MethodGet, "/nimbus/v1/network/ids") do (
    ) -> RestApiResponse:
    var res: seq[PeerId]
    for peerId, peer in node.network.peerPool:
      res.add(peerId)
    RestApiResponse.jsonResponse((peerids: res))

  router.api2(MethodGet, "/nimbus/v1/network/peers") do (
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
    RestApiResponse.jsonResponse((peers: res))

  router.api2(MethodPost, "/nimbus/v1/graffiti") do (
      contentBody: Option[ContentBody]) -> RestApiResponse:
    RestApiResponse.jsonError(Http410, DeprecatedRemovalNimbusGraffiti)

  router.api2(MethodGet, "/nimbus/v1/graffiti") do () -> RestApiResponse:
    RestApiResponse.jsonError(Http410, DeprecatedRemovalNimbusGraffiti)

  router.api2(MethodPost, "/nimbus/v1/chronicles/settings") do (
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
        try:
          updateLogLevel(level)
        except ValueError:
          return RestApiResponse.jsonResponse((result: false))
    RestApiResponse.jsonResponse((result: true))

  router.api2(MethodGet, "/nimbus/v1/debug/chronos/futures") do (
    ) -> RestApiResponse:
    when defined(chronosFutureTracking):
      var res: seq[RestFutureInfo]
      for item in pendingFutures():
        let loc = item.location[LocCreateIndex][]
        let futureId = Base10.toString(item.internalId)
        let childId =
          if isNil(item.internalChild): ""
          else: Base10.toString(item.internalChild.internalId)
        res.add(
          RestFutureInfo(
            id: futureId,
            child_id: childId,
            procname: $loc.procedure,
            filename: $loc.file,
            line: loc.line,
            state: $item.internalState
          )
        )
      RestApiResponse.jsonResponse(res)
    else:
      RestApiResponse.jsonError(Http503,
        "Compile with '-d:chronosFutureTracking' to get this request working")

  router.api2(MethodGet, "/nimbus/v1/debug/chronos/metrics") do (
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
    RestApiResponse.jsonResponse(res)

  router.api2(MethodGet, "/nimbus/v1/debug/chronos/restserver/connections") do (
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
    RestApiResponse.jsonResponse(res)

  router.api2(MethodPost, "/nimbus/v1/validator/activity/{epoch}") do (
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
    RestApiResponse.jsonResponse(response)

  router.api2(MethodGet, "/nimbus/v1/debug/gossip/peers") do (
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
    RestApiResponse.jsonResponse(
      (
        gossip_peers: gossipPeers,
        mesh_peers: meshPeers,
        colocation_peers: colocationPeers,
        peer_stats: peerStats,
        all_peers: allPeers
      )
    )

  router.api2(MethodPost, "/nimbus/v1/timesync") do (
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
    RestApiResponse.jsonResponsePlain(response)

  router.metricsApi2(
    MethodGet,
    "/nimbus/v1/debug/beacon/states/{state_id}/historical_summaries",
    {RestServerMetricsType.Status, Response},
  ) do(state_id: StateIdent) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError, $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        return RestApiResponse.jsonError(Http404, StateNotFoundError, $error)
      contentType = preferredContentType(jsonMediaType, sszMediaType).valueOr:
        return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)

    node.withStateForBlockSlotId(bslot):
      return withState(state):
        when consensusFork >= ConsensusFork.Capella:
          const historicalSummariesFork =
            historicalSummariesForkAtConsensusFork(consensusFork)
              .expect("HistoricalSummariesFork for Capella onwards")

          let response = getHistoricalSummariesResponse(historicalSummariesFork)(
            historical_summaries: forkyState.data.historical_summaries,
            proof: forkyState.data
              .build_proof(historicalSummariesFork.historical_summaries_gindex)
              .expect("Valid gindex"),
            slot: bslot.slot,
          )

          if contentType == jsonMediaType:
            RestApiResponse.jsonResponseFinalizedWVersion(
              response,
              node.getStateOptimistic(state),
              node.dag.isFinalized(bslot.bid),
              consensusFork, node.hasRestAllowedOrigin)
          elif contentType == sszMediaType:
            RestApiResponse.sszResponse(
              response, consensusFork, node.hasRestAllowedOrigin)
          else:
            RestApiResponse.jsonError(Http500, InvalidAcceptError)
        else:
          RestApiResponse.jsonError(Http404, HistoricalSummariesUnavailable)

    RestApiResponse.jsonError(Http404, StateNotFoundError)

  router.api2(MethodGet, "/nimbus/v1/debug/sync/peers") do (
    ) -> RestApiResponse:

    proc getMetadataCgc(peer: Peer): Result[uint8, cstring] =
      let metadata = peer.metadata
      if metadata.isNone():
        return err("metadata is not available")
      if metadata.get.custody_group_count > NUMBER_OF_COLUMNS:
        return err("metadata cgc out of range")
      ok(uint8(metadata.get.custody_group_count))

    proc getEnrCgc(peer: Peer): Result[uint8, cstring] =
      if peer.enr.isNone():
        return err("enr is not available")
      let
        enr = peer.enr.get()
        field = enr.get(enrCustodyGroupCountField, seq[byte]).valueOr:
          return err("enr cgc field is not available")
        cgc =
          try:
            SSZ.decode(field, uint8)
          except SszError, SerializationError:
            return err("unable to decode enr cgc field")
      if cgc > NUMBER_OF_COLUMNS:
        return err("enr cgc value is out of range")
      ok(cgc)

    let localMap = node.validatorCustody.getMap()

    var
      usefulPeers = 0
      uselessPeers = 0
      supernodePeers = 0
      totalPeers = 0
      incomingPeers = 0
      outgoingPeers = 0
      indices: array[NUMBER_OF_COLUMNS, int]
      distribution: array[NUMBER_OF_COLUMNS, int]
      counts: seq[int]
      res: seq[RestSyncPeer]
      columns = 0

    for peer in node.network.peers.values():
      if peer.connectionState == Connected:
        let
          nodeId = peer.fetchNodeIdFromPeerId().get()
          enrcgc = peer.getEnrCgc()
          metcgc = peer.getMetadataCgc()
          cgc =
            if enrcgc.isOk():
              enrcgc.get()
            else:
              if metcgc.isOk():
                metcgc.get()
              else:
                0'u8
          enrField = if enrcgc.isOk(): $enrcgc.get() else: $enrcgc.error
          metField = if metcgc.isOk(): $metcgc.get() else: $metcgc.error

          columnMap =
            node.network.cfg.resolve_column_map_from_custody_groups(
              nodeId, CustodyIndex(cgc))
          intersectMap = localMap and columnMap

        for index in columnMap.items():
          inc(distribution[int(index)])

        for index in intersectMap.items():
          inc(indices[int(index)])

        if len(columnMap) == NUMBER_OF_COLUMNS:
          inc(supernodePeers)
        if len(intersectMap) == 0:
          inc(uselessPeers)
        else:
          inc(usefulPeers)

        if peer.direction == PeerType.Incoming:
          inc(incomingPeers)
        else:
          inc(outgoingPeers)

        inc(totalPeers)

        let peer = RestSyncPeer(
          peer_id: $peer.peerId,
          node_id: $nodeId,
          direction: toLowerAscii($peer.direction),
          enr_cgc: enrField,
          meta_cgc: metField,
          cgc: int(cgc),
          columns: columnMap.mapIt(int(it)).toSeq(),
          intersection: intersectMap.mapIt(int(it)).toSeq(),
          agent: $peer.getRemoteAgent(),
          agent_full:
            node.network.switch.peerStore[AgentBook][peer.peerId],
          proto_full:
            node.network.switch.peerStore[ProtoVersionBook][peer.peerId]
        )
        res.add(peer)

    for index in localMap:
      let count = indices[int(index)]
      if count != 0:
        inc(columns)
      counts.add(count)

    let fillRate = (float(columns) * 100.0) / float(len(localMap))

    RestApiResponse.jsonResponseWMeta(
      res,
      (
        total_peers_count: RestNumeric(totalPeers),
        useless_peers_count: RestNumeric(uselessPeers),
        useful_peers_count: RestNumeric(usefulPeers),
        supernode_peers_count: RestNumeric(supernodePeers),
        incoming_peers_count: RestNumeric(incomingPeers),
        outgoing_peers_count: RestNumeric(outgoingPeers),
        custody_map: localMap.mapIt(int(it)).toSeq(),
        columns_count: RestNumeric(len(localMap)),
        counts: counts,
        fill_rate: fillRate,
        distribution: distribution
      ))

  router.api2(MethodGet, "/nimbus/v1/debug/custody") do (
    ) -> RestApiResponse:
    let
      slot = node.currentSlot()
      res =
        "{\"data\":" & node.validatorCustody.debugCustodyJsonDump(slot) & "}\n"
    RestApiResponse.response(res, Http200, "application/json")
