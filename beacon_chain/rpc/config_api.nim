# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  json_rpc/[rpcserver, jsonmarshal],
  chronicles,
  ../beacon_node_common,

  ../spec/datatypes

logScope: topics = "configapi"

type
  RpcServer = RpcHttpServer

template unimplemented() =
  raise (ref CatchableError)(msg: "Unimplemented")

proc installConfigApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.rpc("get_v1_config_fork_schedule") do () -> seq[Fork]:
    return @[node.chainDag.headState.data.data.fork]

  rpcServer.rpc("get_v1_config_spec") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("get_v1_config_deposit_contract") do () -> JsonNode:
    unimplemented()
