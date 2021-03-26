import
  options,
  callsigs_types

proc get_v1_node_identity(): NodeIdentityTuple
proc get_v1_node_version(): JsonNode
proc get_v1_node_syncing(): SyncInfo
proc get_v1_node_health(): JsonNode

proc get_v1_node_peers(state: Option[seq[string]],
                       direction: Option[seq[string]]): seq[NodePeerTuple]
