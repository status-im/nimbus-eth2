# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## The `rpc_api`  module is a server implementation of a JSON-RPC-based API
## for Nimbus - it is based on the common REST API for Ethereum 2 found at
## https://ethereum.github.io/eth2.0-APIs/# but uses JSON-RPC as transport
## instead. There are also minor historical differences in encoding and data -
## these differences will likely remain so as to not break old tooling.
##
## The JSON-RPC is used by community utilities and tools and is kept for
## backwards compatibility mainly.
## A corresponding client can be found in the
## `spec/eth2_apis/rpc_beacon_client` module.
import
  "."/[
    rpc_beacon_api, rpc_config_api, rpc_debug_api, rpc_event_api,
    rpc_nimbus_api, rpc_node_api, rpc_validator_api]

export
  rpc_beacon_api, rpc_config_api, rpc_debug_api, rpc_event_api,
  rpc_nimbus_api, rpc_node_api, rpc_validator_api
