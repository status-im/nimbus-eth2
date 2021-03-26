# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  json_rpc/servers/httpserver,
  chronicles,
  ../beacon_node_common

logScope: topics = "eventapi"

type
  RpcServer = RpcHttpServer

template unimplemented() =
  raise (ref CatchableError)(msg: "Unimplemented")

proc installEventApiHandlers*(rpcServer: RpcServer, node: BeaconNode) {.
    raises: [Exception].} = # TODO fix json-rpc
  rpcServer.rpc("get_v1_events") do () -> JsonNode:
    unimplemented()
