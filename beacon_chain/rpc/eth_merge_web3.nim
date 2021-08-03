import
  strutils,
  json_serialization/std/[sets, net], serialization/errors,
  ../spec/datatypes/base,
  ../spec/[crypto, digest, eth2_apis/rpc_beacon_client],
  json_rpc/[client, jsonmarshal]

from os import DirSep, AltSep
template sourceDir: string = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0]
createRpcSigs(RpcClient, sourceDir & "/eth_merge_sigs.nim")
