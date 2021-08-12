import
  std/sequtils,
  presto,
  chronicles,
  ../version, ../beacon_node_common,
  ./rest_utils

logScope: topics = "rest_debug"

proc installDebugApiHandlers*(router: var RestRouter, node: BeaconNode) =
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
    node.withStateForBlockSlot(bslot):
      return RestApiResponse.jsonResponse(stateData.data.hbsPhase0.data)
    return RestApiResponse.jsonError(Http500, InternalServerError)

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

proc getDebugChainHeads*(): RestResponse[GetDebugChainHeadsResponse] {.
     rest, endpoint: "/eth/v1/debug/beacon/heads",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getDebugChainHeads
