import
  std/[sequtils, deques],
  json_rpc/[rpcserver, jsonmarshal],
  chronicles,
  ../version, ../beacon_node_common, ../eth2_json_rpc_serialization,
  ../eth1_monitor, ../validator_duties, ../eth2_network, ../peer_pool,
  ../spec/[datatypes, digest, presets],
  ./rpc_utils

logScope: topics = "debugapi"

type
  RpcServer = RpcHttpServer
  Eth1Block = eth1_monitor.Eth1Block

proc installDebugApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.rpc("get_v1_debug_beacon_states_stateId") do (
      stateId: string) -> BeaconState:
    withStateForStateId(stateId):
      return state

  rpcServer.rpc("get_v1_debug_beacon_heads") do (
      stateId: string) -> seq[tuple[root: Eth2Digest, slot: Slot]]:
    return node.chainDag.heads.mapIt((it.root, it.slot))

  rpcServer.rpc("get_v1_debug_eth1_chain") do () -> seq[Eth1Block]:
    return mapIt(node.eth1Monitor.blocks, it)

  rpcServer.rpc("get_v1_debug_eth1_proposal_data") do () -> BlockProposalEth1Data:
    let
      wallSlot = node.beaconClock.now.slotOrZero
      head = node.doChecksAndGetCurrentHead(wallSlot)

    node.chainDag.withState(node.chainDag.tmpState, head.atSlot(wallSlot)):
      return node.getBlockProposalEth1Data(state)

