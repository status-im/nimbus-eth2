# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ./rest_utils,
  ./state_ttl_cache,
  ../beacon_node

export rest_utils

logScope: topics = "rest_builderapi"

proc installBuilderApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.0#/Builder/getNextWithdrawals
  # https://github.com/ethereum/beacon-APIs/blob/v2.4.0/apis/builder/states/expected_withdrawals.yaml
  router.api2(MethodGet,
              "/eth/v1/builder/states/{state_id}/expected_withdrawals") do (
    state_id: StateIdent) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                         $error)

    node.withStateForBlockSlotId(bslot):
      withState(state):
        when consensusFork >= ConsensusFork.Capella:
          return RestApiResponse.jsonResponseWOpt(
            get_expected_withdrawals(forkyState.data),
            node.getStateOptimistic(state))
        else:
          return RestApiResponse.jsonError(
            Http400, "The specified state is not a capella state")

    RestApiResponse.jsonError(Http404, StateNotFoundError)
