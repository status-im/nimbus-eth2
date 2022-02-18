# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/sequtils
import chronicles
import ".."/[version, beacon_node],
       ".."/spec/forks,
       "."/[rest_utils, state_ttl_cache]

export rest_utils

logScope: topics = "rest_debug"

proc installDebugApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/#/Debug/getState
  router.api(MethodGet,
             "/eth/v1/debug/beacon/states/{state_id}") do (
    state_id: StateIdent) -> RestApiResponse:
    if node.kind != BeaconNodeKind.Full:
      return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)

    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                           $state_id.error())
        let bres = node.getBlockSlot(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                           $bres.error())
        bres.get()
    let contentType =
      block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()
    node.withStateForBlockSlot(bslot):
      return
        case stateData.data.kind
        of BeaconStateFork.Phase0:
          if contentType == sszMediaType:
            RestApiResponse.sszResponse(stateData.data.phase0Data.data)
          elif contentType == jsonMediaType:
            RestApiResponse.jsonResponse(stateData.data.phase0Data.data)
          else:
            RestApiResponse.jsonError(Http500, InvalidAcceptError)
        of BeaconStateFork.Altair, BeaconStateFork.Bellatrix:
          RestApiResponse.jsonError(Http404, StateNotFoundError)
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2
  router.api(MethodGet,
             "/eth/v2/debug/beacon/states/{state_id}") do (
    state_id: StateIdent) -> RestApiResponse:
    if node.kind != BeaconNodeKind.Full:
      return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)

    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                           $state_id.error())
        let bres = node.getBlockSlot(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                           $bres.error())
        bres.get()
    let contentType =
      block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()
    node.withStateForBlockSlot(bslot):
      return
        if contentType == jsonMediaType:
          RestApiResponse.jsonResponsePlain(stateData.data)
        elif contentType == sszMediaType:
          withState(stateData.data):
            RestApiResponse.sszResponse(state.data)
        else:
          RestApiResponse.jsonError(Http500, InvalidAcceptError)
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getDebugChainHeads
  router.api(MethodGet,
             "/eth/v1/debug/beacon/heads") do () -> RestApiResponse:
    if node.kind != BeaconNodeKind.Full:
      return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)

    return RestApiResponse.jsonResponse(
      node.dag.heads.mapIt((root: it.root, slot: it.slot))
    )

  # Legacy URLS - Nimbus <= 1.5.5 used to expose the REST API with an additional
  # `/api` path component
  router.redirect(
    MethodGet,
    "/api/eth/v1/debug/beacon/states/{state_id}",
    "/eth/v1/debug/beacon/states/{state_id}"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v2/debug/beacon/states/{state_id}",
    "/eth/v2/debug/beacon/states/{state_id}"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/debug/beacon/heads",
    "/eth/v1/debug/beacon/heads"
  )
