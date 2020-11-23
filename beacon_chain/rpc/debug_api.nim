import
  std/sequtils,
  json_rpc/[rpcserver, jsonmarshal],
  chronicles,
  ../version, ../beacon_node_common, ../eth2_json_rpc_serialization,
  ../eth2_network, ../peer_pool,
  ../spec/[datatypes, digest, presets],
  ./rpc_utils

logScope: topics = "debugapi"

type
  RpcServer = RpcHttpServer

proc installDebugApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.rpc("get_v1_debug_beacon_states_stateId") do (
      stateId: string) -> BeaconState:
    withStateForStateId(stateId):
      return state

  rpcServer.rpc("get_v1_debug_beacon_heads") do (
      stateId: string) -> seq[tuple[root: Eth2Digest, slot: Slot]]:
    return node.chainDag.heads.mapIt((it.root, it.slot))

