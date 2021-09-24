# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos, presto/client,
  "."/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc getState*(state_id: StateIdent): RestResponse[GetStateResponse] {.
     rest, endpoint: "/eth/v1/debug/beacon/states/{state_id}",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getState

# TODO altair
# proc getStateV2*(state_id: StateIdent): RestResponse[GetStateV2Response] {.
#      rest, endpoint: "/eth/v2/debug/beacon/states/{state_id}",
#      meth: MethodGet.}
#   ## https://ethereum.github.io/beacon-APIs/#/Beacon/getState

proc getDebugChainHeads*(): RestResponse[GetDebugChainHeadsResponse] {.
     rest, endpoint: "/eth/v1/debug/beacon/heads",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getDebugChainHeads

proc getStateV2*(state_id: StateIdent): RestResponse[GetStateV2Response] {.
     rest, endpoint: "/eth/v2/debug/beacon/states/{state_id}",
     accept: "application/json", meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2

proc getSszPhase0StateV2*(state_id: StateIdent): RestResponse[GetPhase0StateSszResponse] {.
     rest, endpoint: "/eth/v2/debug/beacon/states/{state_id}",
     accept: "application/octet-stream", meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2

proc getSszAltairStateV2*(state_id: StateIdent): RestResponse[GetAltairStateSszResponse] {.
     rest, endpoint: "/eth/v2/debug/beacon/states/{state_id}",
     accept: "application/octet-stream", meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2
