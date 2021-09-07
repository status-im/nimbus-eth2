import std/sequtils
import chronicles
import ".."/[version, beacon_node_common],
       ".."/spec/forks,
       "."/rest_utils

logScope: topics = "rest_debug"

proc installDebugApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/#/Debug/getState
  router.api(MethodGet,
             "/api/eth/v1/debug/beacon/states/{state_id}") do (
    state_id: StateIdent) -> RestApiResponse:
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
        let res = preferredContentType("application/octet-stream",
                                       "application/json")
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()
    node.withStateForBlockSlot(bslot):
      return
        case stateData.data.beaconStateFork
        of BeaconStateFork.forkPhase0:
          case contentType
            of "application/octet-stream":
              RestApiResponse.sszResponse(stateData.data.hbsPhase0.data)
            of "application/json":
              RestApiResponse.jsonResponsePlain(stateData.data.hbsPhase0.data)
            else:
              RestApiResponse.jsonError(Http500, InvalidAcceptError)
        of BeaconStateFork.forkAltair:
          RestApiResponse.jsonError(Http404, StateNotFoundError)
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2
  router.api(MethodGet,
             "/api/eth/v2/debug/beacon/states/{state_id}") do (
    state_id: StateIdent) -> RestApiResponse:
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
        let res = preferredContentType("application/octet-stream",
                                       "application/json")
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()
    node.withStateForBlockSlot(bslot):
      return
        case stateData.data.beaconStateFork
        of BeaconStateFork.forkPhase0:
          case contentType
          of "application/json":
            RestApiResponse.jsonResponse(
              (
                version: BeaconBlockFork.Phase0,
                data: stateData.data.hbsPhase0.data
              )
            )
          of "application/octet-stream":
            RestApiResponse.sszResponse(
              (
                version: BeaconBlockFork.Phase0,
                data: stateData.data.hbsPhase0.data
              )
            )
          else:
            RestApiResponse.jsonError(Http500, InvalidAcceptError)
        of BeaconStateFork.forkAltair:
          case contentType
          of "application/json":
            RestApiResponse.jsonResponse(
              (
                version: BeaconBlockFork.Altair,
                data: stateData.data.hbsAltair.data
              )
            )
          of "application/octet-stream":
            RestApiResponse.sszResponse(
              (
                version: BeaconBlockFork.Altair,
                data: stateData.data.hbsAltair.data
              )
            )
          else:
            RestApiResponse.jsonError(Http500, InvalidAcceptError)
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getDebugChainHeads
  router.api(MethodGet,
             "/api/eth/v1/debug/beacon/heads") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      node.dag.heads.mapIt((root: it.root, slot: it.slot))
    )

  router.redirect(
    MethodGet,
    "/eth/v1/debug/beacon/states/{state_id}",
    "/api/eth/v1/debug/beacon/states/{state_id}"
  )
  router.redirect(
    MethodGet,
    "/eth/v1/debug/beacon/heads",
    "/api/eth/v1/debug/beacon/heads"
  )
  router.redirect(
    MethodGet,
    "/eth/v2/debug/beacon/heads",
    "/api/eth/v2/debug/beacon/heads"
  )
