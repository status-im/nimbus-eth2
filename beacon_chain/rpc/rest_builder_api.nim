# beacon_chain
# Copyright (c) 2023-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import ./rest_utils

export rest_utils

logScope: topics = "rest_builderapi"

proc installBuilderApiHandlers*(router: var RestRouter) =
  router.api2(MethodGet,
              "/eth/v1/builder/states/{state_id}/expected_withdrawals") do (
    state_id: StateIdent) -> RestApiResponse:
    RestApiResponse.jsonError(Http410, DeprecatedRemovalElectra)
