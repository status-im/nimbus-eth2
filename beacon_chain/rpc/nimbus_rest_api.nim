# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[deques, sequtils],
  stew/results,
  chronicles,
  presto,
  libp2p/[multiaddress, multicodec],
  libp2p/protocols/pubsub/pubsubpeer,
  ./eth2_json_rest_serialization, ./rest_utils,
  ../eth1/eth1_monitor,
  ../validators/validator_duties,
  ../beacon_node_common, ../nimbus_binary_common

logScope: topics = "rest_nimbusapi"

type
  PeerInfoTuple* = tuple
    peerId: string
    addrs: seq[string]
    protocols: seq[string]
    protoVersion: string
    agentVersion: string

  SimplePeerTuple* = tuple
    info: PeerInfoTuple
    connectionState: string
    score: int

  FutureInfoTuple* = tuple
    id: int
    procname: string
    filename: string
    line: int
    state: string

  PubSubPeerTuple* = tuple
    peerId: PeerID
    score: float64
    iWantBudget: int
    iHaveBudget: int
    outbound: bool
    appScore: float64
    behaviourPenalty: float64
    sendConnAvail: bool
    closed: bool
    atEof: bool
    address: string
    backoff: string
    agent: string

  PeerStatsTuple* = tuple
    peerId: PeerID
    null: bool
    connected: bool
    expire: string
    score: float64

  PeerStatusTuple* = tuple
    peerId: PeerID
    connected: bool

proc toNode(v: PubSubPeer, backoff: Moment): PubSubPeerTuple =
  (
    peerId: v.peerId,
    score: v.score,
    iWantBudget: v.iWantBudget,
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
  router.api(MethodGet, "/api/nimbus/v1/beacon/head") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(node.chainDag.head.slot)

  router.api(MethodGet, "/api/nimbus/v1/chain/head") do() -> RestApiResponse:
    let
      head = node.chainDag.head
      finalized = node.chainDag.headState.data.data.finalized_checkpoint
      justified = node.chainDag.headState.data.data.current_justified_checkpoint
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

  router.api(MethodGet, "/api/nimbus/v1/syncmanager/status") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse(node.syncManager.inProgress)

  router.api(MethodGet, "/api/nimbus/v1/node/peerid") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse((peerid: $node.network.peerId()))

  router.api(MethodGet, "/api/nimbus/v1/node/version") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse((version: "Nimbus/" & fullVersionStr))

  router.api(MethodGet, "/api/nimbus/v1/network/ids") do (
    ) -> RestApiResponse:
    var res: seq[PeerID]
    for peerId, peer in node.network.peerPool:
      res.add(peerId)
    return RestApiResponse.jsonResponse((peerids: res))

  router.api(MethodGet, "/api/nimbus/v1/network/peers") do (
    ) -> RestApiResponse:
    var res: seq[SimplePeerTuple]
    for id, peer in node.network.peerPool:
      res.add((
        info: shortLog(peer.info),
        connectionState: $peer.connectionState,
        score: peer.score,
      ))
    return RestApiResponse.jsonResponse((peers: res))

  router.api(MethodPost, "/api/nimbus/v1/chronicles/settings") do (
    log_level: Option[string]) -> RestApiResponse:
    if log_level.isSome():
      let level =
        block:
          let res = log_level.get()
          if res.isErr():
            return RestApiResponse.jsonError(Http400, "Invalid log_level value",
                                             $res.error())
          res.get()
      {.gcsafe.}:
        updateLogLevel(level)
    return RestApiResponse.jsonResponse((result: true))

  router.api(MethodGet, "/api/nimbus/v1/eth1/chain") do (
    ) -> RestApiResponse:
    let res =
      if not(isNil(node.eth1Monitor)):
        mapIt(node.eth1Monitor.blocks, it)
      else:
        @[]
    return RestApiResponse.jsonResponse(res)

  router.api(MethodGet, "/api/nimbus/v1/eth1/proposal_data") do (
    ) -> RestApiResponse:
    let wallSlot = node.beaconClock.now.slotOrZero
    let head =
      block:
        let res = node.getCurrentHead(wallSlot)
        if res.isErr():
          return RestApiResponse.jsonError(Http503, "Node is not synced yet")
        res.get()
    let proposalState = assignClone(node.chainDag.headState)
    node.chainDag.withState(proposalState[], head.atSlot(wallSlot)):
      return RestApiResponse.jsonResponse(node.getBlockProposalEth1Data(state))

  router.api(MethodGet, "/api/nimbus/v1/debug/chronos/futures") do (
    ) -> RestApiResponse:
    when defined(chronosFutureTracking):
      var res: seq[FutureInfoTuple]
      for item in pendingFutures():
        let loc = item.location[LocCreateIndex][]
        res.add(
          (
            id: item.id,
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

  router.api(MethodGet, "/api/nimbus/v1/debug/gossip/peers") do (
    ) -> RestApiResponse:

    let gossipPeers =
      block:
        var res: seq[tuple[topic: string, peers: seq[PubSubPeerTuple]]]
        for topic, v in node.network.pubsub.gossipsub:
          var peers: seq[PubSubPeerTuple]
          let backoff = node.network.pubsub.backingOff.getOrDefault(topic)
          for peer in v:
            peers.add(peer.toNode(backOff.getOrDefault(peer.peerId)))
          res.add((topic: topic, peers: peers))
        res
    let meshPeers =
      block:
        var res: seq[tuple[topic: string, peers: seq[PubSubPeerTuple]]]
        for topic, v in node.network.pubsub.mesh:
          var peers: seq[PubSubPeerTuple]
          let backoff = node.network.pubsub.backingOff.getOrDefault(topic)
          for peer in v:
            peers.add(peer.toNode(backOff.getOrDefault(peer.peerId)))
          res.add((topic: topic, peers: peers))
        res
    let colocationPeers =
      block:
        var res: seq[tuple[address: string, peerids: seq[PeerID]]]
        for k, v in node.network.pubsub.peersInIP:
          var peerids: seq[PeerID]
          for id in v:
            peerids.add(id)
          res.add(($k, peerids))
        res
    let peerStats =
      block:
        var stats: seq[PeerStatsTuple]
        for peerId, pstats in node.network.pubsub.peerStats:
          let peer = node.network.pubsub.peers.getOrDefault(peerId)
          stats.add(
            (
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
        var peers: seq[PeerStatusTuple]
        for peerId, peer in node.network.pubsub.peers:
          peers.add((peerId: peerId, connected: peer.connected))
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
