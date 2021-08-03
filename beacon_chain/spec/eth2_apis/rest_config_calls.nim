# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  presto/client,
  "."/[rest_types, eth2_rest_serialization]

export client, rest_types, eth2_rest_serialization

proc getForkSchedule*(): RestResponse[GetForkScheduleResponse] {.
     rest, endpoint: "/eth/v1/config/fork_schedule", meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Config/getForkSchedule

proc getSpec*(): RestResponse[GetSpecResponse] {.
     rest, endpoint: "/eth/v1/config/spec", meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Config/getSpec

proc getDepositContract*(): RestResponse[GetDepositContractResponse] {.
     rest, endpoint: "/eth/v1/config/deposit_contract", meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Config/getDepositContract
