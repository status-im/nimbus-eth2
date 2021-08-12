import
  std/os,
  json_rpc/rpcclient,
  "."/[rpc_types, eth2_json_rpc_serialization],
  ../datatypes/[phase0, altair]

export
  rpcclient,
  rpc_types,
  eth2_json_rpc_serialization

createRpcSigs(RpcClient, currentSourcePath.parentDir / "rpc_beacon_calls.nim")
createRpcSigs(RpcClient, currentSourcePath.parentDir / "rpc_debug_calls.nim")
createRpcSigs(RpcClient, currentSourcePath.parentDir / "rpc_nimbus_calls.nim")
createRpcSigs(RpcClient, currentSourcePath.parentDir / "rpc_node_calls.nim")
createRpcSigs(RpcClient, currentSourcePath.parentDir / "rpc_validator_calls.nim")
