# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[deques, sequtils, sets],
  chronos,
  stew/byteutils,
  json_rpc/servers/httpserver,
  libp2p/protocols/pubsub/pubsubpeer,

  ".."/[
    beacon_node, nimbus_binary_common, networking/eth2_network,
    eth1/eth1_monitor, validators/validator_duties],
  ../spec/datatypes/base,
  ../spec/[forks],
  ./rpc_utils

when defined(chronosFutureTracking):
  import stew/base10

logScope: topics = "nimbusapi"

type
  RpcServer = RpcHttpServer

  FutureInfo* = object
    id*: string
    child_id*: string
    procname*: string
    filename*: string
    line*: int
    state*: string

proc installNimbusApiHandlers*(rpcServer: RpcServer, node: BeaconNode) {.
    raises: [Defect, CatchableError].} =
  ## Install non-standard api handlers - some of these are used by 3rd-parties
  ## such as eth2stats, pending a full REST api
  rpcServer.rpc("getBeaconHead") do () -> Slot:
    return node.dag.head.slot

  rpcServer.rpc("getChainHead") do () -> JsonNode:
    let
      head = node.dag.head
      finalized = getStateField(node.dag.headState.data, finalized_checkpoint)
      justified =
        getStateField(node.dag.headState.data, current_justified_checkpoint)
    return %* {
      "head_slot": head.slot,
      "head_block_root": head.root.data.toHex(),
      "finalized_slot": finalized.epoch * SLOTS_PER_EPOCH,
      "finalized_block_root": finalized.root.data.toHex(),
      "justified_slot": justified.epoch * SLOTS_PER_EPOCH,
      "justified_block_root": justified.root.data.toHex(),
    }

  rpcServer.rpc("getSyncing") do () -> bool:
    return node.syncManager.inProgress

  rpcServer.rpc("getNetworkPeerId") do () -> string:
    return $node.network.peerId()

  rpcServer.rpc("getNetworkPeers") do () -> seq[string]:
    for peerId, peer in node.network.peerPool:
      result.add $peerId

  rpcServer.rpc("getNodeVersion") do () -> string:
    return "Nimbus/" & fullVersionStr

  rpcServer.rpc("peers") do () -> JsonNode:
    var res = newJObject()
    var peers = newJArray()
    for id, peer in node.network.peerPool:
      peers.add(
        %(
          id: shortLog(peer.peerId),
          connectionState: $peer.connectionState,
          score: peer.score,
        )
      )
    res.add("peers", peers)

    return res

  rpcServer.rpc("setLogLevel") do (level: string) -> bool:
    {.gcsafe.}: # It's probably not, actually. Hopefully we don't log from threads...
      updateLogLevel(level)
    return true

  rpcServer.rpc("setGraffiti") do (graffiti: string) -> bool:
    node.graffitiBytes = GraffitiBytes.init(graffiti)
    return true

  rpcServer.rpc("getEth1Chain") do () -> seq[Eth1Block]:
    result = if node.eth1Monitor != nil:
      mapIt(node.eth1Monitor.depositChainBlocks, it)
    else:
      @[]

  rpcServer.rpc("getEth1ProposalData") do () -> BlockProposalEth1Data:
    let
      wallSlot = node.beaconClock.now.slotOrZero
      head = node.doChecksAndGetCurrentHead(wallSlot)

    let proposalState = assignClone(node.dag.headState)
    node.dag.withState(proposalState[], head.atSlot(wallSlot)):
      return node.getBlockProposalEth1Data(stateData.data)

  rpcServer.rpc("debug_getChronosFutures") do () -> seq[FutureInfo]:
    when defined(chronosFutureTracking):
      var res: seq[FutureInfo]

      for item in pendingFutures():
        let loc = item.location[LocCreateIndex][]
        let futureId = Base10.toString(item.id)
        let childId =
          if isNil(item.child): ""
          else: Base10.toString(item.child.id)
        res.add FutureInfo(
          id: futureId,
          child_id: childId,
          procname: $loc.procedure,
          filename: $loc.file,
          line: loc.line,
          state: $item.state
        )

      return res
    else:
      raise (ref CatchableError)(
        msg: "Compile with '-d:chronosFutureTracking' to enable this request")

  rpcServer.rpc("debug_getGossipSubPeers") do () -> JsonNode:
    var res = newJObject()
    var gossipsub = newJObject()

    proc toNode(v: PubSubPeer, backoff: Moment): JsonNode =
      %(
        peerId: $v.peerId,
        score: v.score,
        iWantBudget: v.iWantBudget,
        iHaveBudget: v.iHaveBudget,
        outbound: v.outbound,
        appScore: v.appScore,
        behaviourPenalty: v.behaviourPenalty,
        sendConnAvail: v.sendConn != nil,
        closed: v.sendConn != nil and v.sendConn.closed,
        atEof: v.sendConn != nil and v.sendConn.atEof,
        address: if v.address.isSome():
            $v.address.get()
          else:
            "<no address>",
        backoff: $(backoff - Moment.now()),
        agent: when defined(libp2p_agents_metrics):
            v.shortAgent
          else:
            "unknown",
      )

    for topic, v in node.network.pubsub.gossipsub:
      var peers = newJArray()
      let backoff = node.network.pubsub.backingOff.getOrDefault(topic)
      for peer in v:
        peers.add(peer.toNode(backOff.getOrDefault(peer.peerId)))

      gossipsub.add(topic, peers)

    res.add("gossipsub", gossipsub)

    var mesh = newJObject()
    for topic, v in node.network.pubsub.mesh:
      var peers = newJArray()
      let backoff = node.network.pubsub.backingOff.getOrDefault(topic)
      for peer in v:
        peers.add(peer.toNode(backOff.getOrDefault(peer.peerId)))

      mesh.add(topic, peers)

    res.add("mesh", mesh)

    var coloc = newJArray()
    for k, v in node.network.pubsub.peersInIP:
      var a = newJObject()
      var peers = newJArray()
      for p in v:
        peers.add(%($p))
      a.add($k, peers)
      coloc.add(a)

    res.add("colocationPeers", coloc)

    var stats = newJArray()
    for peerId, pstats in node.network.pubsub.peerStats:
      let
        peer = node.network.pubsub.peers.getOrDefault(peerId)
        null = isNil(peer)
        connected = if null:
            false
          else :
            peer.connected()

      stats.add(%(
        peerId: $peerId,
        null: null,
        connected: connected,
        expire: $(pstats.expire - Moment.now()),
        score: pstats.score
      ))

    res.add("peerStats", stats)

    var peers = newJArray()
    for peerId, peer in node.network.pubsub.peers:
      peers.add(%(
        connected: peer.connected,
        peerId: $peerId
      ))

    res.add("allPeers", peers)

    return res
