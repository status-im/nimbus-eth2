# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[deques, sequtils, sets],
  chronos,
  stew/shims/macros,
  stew/byteutils,
  json_rpc/[rpcserver, jsonmarshal],

  rpc_utils,
  ../beacon_node_common, ../nimbus_binary_common,
  ../networking/eth2_network,
  ../eth1/eth1_monitor,
  ../validators/validator_duties,
  ../spec/[digest, datatypes, presets],

  libp2p/protocols/pubsub/pubsubpeer


logScope: topics = "nimbusapi"

type
  RpcServer = RpcHttpServer

  FutureInfo* = object
    id*: int
    procname*: string
    filename*: string
    line*: int
    state*: string

proc installNimbusApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =
  ## Install non-standard api handlers - some of these are used by 3rd-parties
  ## such as eth2stats, pending a full REST api
  rpcServer.rpc("getBeaconHead") do () -> Slot:
    return node.chainDag.head.slot

  rpcServer.rpc("getChainHead") do () -> JsonNode:
    let
      head = node.chainDag.head
      finalized = node.chainDag.headState.data.data.finalized_checkpoint
      justified = node.chainDag.headState.data.data.current_justified_checkpoint
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
          info: shortLog(peer.info),
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

  rpcServer.rpc("getEth1Chain") do () -> seq[Eth1Block]:
    result = if node.eth1Monitor != nil:
      mapIt(node.eth1Monitor.blocks, it)
    else:
      @[]

  rpcServer.rpc("getEth1ProposalData") do () -> BlockProposalEth1Data:
    let
      wallSlot = node.beaconClock.now.slotOrZero
      head = node.doChecksAndGetCurrentHead(wallSlot)

    let proposalState = assignClone(node.chainDag.headState)
    node.chainDag.withState(proposalState[], head.atSlot(wallSlot)):
      return node.getBlockProposalEth1Data(state)

  rpcServer.rpc("getChronosFutures") do () -> seq[FutureInfo]:
    when defined(chronosFutureTracking):
      var res: seq[FutureInfo]

      for item in pendingFutures():
        let loc = item.location[LocCreateIndex][]
        res.add FutureInfo(
          id: item.id,
          procname: $loc.procedure,
          filename: $loc.file,
          line: loc.line,
          state: $item.state
        )

      return res
    else:
      raise (ref CatchableError)(
        msg: "Compile with '-d:chronosFutureTracking' to enable this request")

  rpcServer.rpc("getGossipSubPeers") do () -> JsonNode:
    var res = newJObject()
    var gossipsub = newJObject()

    proc toNode(v: PubSubPeer): JsonNode =
      %(
        peerId: $v.peerId,
        score: v.score,
        iWantBudget: v.iWantBudget,
        iHaveBudget: v.iHaveBudget,
        outbound: v.outbound,
        appScore: v.appScore,
        behaviourPenalty: v.behaviourPenalty
      )

    for topic, v in node.network.pubsub.gossipsub:
      var peers = newJArray()
      for peer in v:
        peers.add(peer.toNode())

      gossipsub.add(topic, peers)

    res.add("gossipsub", gossipsub)

    var mesh = newJObject()
    for topic, v in node.network.pubsub.mesh:
      var peers = newJArray()
      for peer in v:
        peers.add(peer.toNode())

      mesh.add(topic, peers)

    res.add("mesh", mesh)

    return res
