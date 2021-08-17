import
  options,
  rpc_types

proc get_v1_node_identity(): RpcNodeIdentity
proc get_v1_node_version(): JsonNode
proc get_v1_node_syncing(): RpcSyncInfo
proc get_v1_node_health(): JsonNode

proc get_v1_node_peers(state: Option[seq[string]],
                       direction: Option[seq[string]]): seq[RpcNodePeer]
