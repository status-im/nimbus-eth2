# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  presto/client, chronicles,
  ".."/[helpers, forks, eth2_ssz_serialization],
  "."/[rest_types, rest_common, eth2_rest_serialization]

export client, rest_types, eth2_rest_serialization

proc getNextWithdrawals*(state_id: StateIdent
             ): RestResponse[GetNextWithdrawalsResponse] {.
     rest, endpoint: "/eth/v1/builder/states/{state_id}/expected_withdrawals",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.0#/Builder/getNextWithdrawals
