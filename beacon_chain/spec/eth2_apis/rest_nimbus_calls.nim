# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos, presto/client,
  "."/[rest_types, eth2_rest_serialization]

proc getValidatorsActivity*(epoch: Epoch,
                            body: seq[ValidatorIndex]
                           ): RestPlainResponse {.
     rest, endpoint: "/nimbus/v1/validator/activity/{epoch}",
     meth: MethodPost.}
