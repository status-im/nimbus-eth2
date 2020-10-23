import
  chronicles,
  json_rpc/[rpcserver, jsonmarshal],

  ../beacon_node_common, ../eth2_network,
  ../peer_pool, ../version,
  ../spec/[datatypes, digest, presets],
  ../spec/eth2_apis/callsigs_types

logScope: topics = "nodeapi"

type
  RpcServer = RpcHttpServer

template unimplemented() =
  raise (ref CatchableError)(msg: "Unimplemented")

proc installNodeApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.rpc("get_v1_node_identity") do () -> NodeIdentityTuple:
    # TODO rest of fields
    return (
      peer_id: node.network.peerId(),
      enr: node.network.enrRecord(),
      p2p_addresses: newSeq[MultiAddress](0),
      discovery_addresses: newSeq[MultiAddress](0),
      metadata: (0'u64, "")
    )

  rpcServer.rpc("get_v1_node_peers") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("get_v1_node_peers_peerId") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("get_v1_node_version") do () -> JsonNode:
    return %{
      "version": "Nimbus/" & fullVersionStr
    }

  rpcServer.rpc("get_v1_node_syncing") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("get_v1_node_health") do () -> JsonNode:
    unimplemented()
