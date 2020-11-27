import
  os, json,
  json_rpc/[rpcclient, jsonmarshal],
  ../../eth2_json_rpc_serialization,
  ../digest, ../datatypes,
  callsigs_types

createRpcSigs(RpcClient, currentSourcePath.parentDir / "beacon_callsigs.nim")

