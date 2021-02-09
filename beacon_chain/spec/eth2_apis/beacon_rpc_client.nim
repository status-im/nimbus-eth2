import
  std/[os, json],
  json_rpc/[rpcclient, jsonmarshal],
  ../../eth2_json_rpc_serialization,
  ../crypto, ../digest, ../datatypes,
  callsigs_types

export
  rpcclient,
  crypto, digest, datatypes,
  callsigs_types,
  eth2_json_rpc_serialization

createRpcSigs(RpcClient, currentSourcePath.parentDir / "beacon_callsigs.nim")
createRpcSigs(RpcClient, currentSourcePath.parentDir / "debug_callsigs.nim")
createRpcSigs(RpcClient, currentSourcePath.parentDir / "nimbus_callsigs.nim")
createRpcSigs(RpcClient, currentSourcePath.parentDir / "node_callsigs.nim")
createRpcSigs(RpcClient, currentSourcePath.parentDir / "validator_callsigs.nim")
