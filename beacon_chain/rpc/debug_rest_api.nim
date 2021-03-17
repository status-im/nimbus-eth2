import
  std/sequtils,
  presto,
  chronicles,
  ../version, ../beacon_node_common,
  ../eth2_network, ../peer_pool,
  ../spec/[datatypes, digest, presets],
  ./rest_utils

logScope: topics = "rest_debug"

proc installDebugApiHandlers*(router: var RestRouter, node: BeaconNode) =
  router.api(MethodGet,
             "/api/eth/v1/debug/beacon/states/{state_id}") do (
    state_id: StateIdent) -> RestApiResponse:
    # TODO: This is very expensive call
    if state_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                       $state_id.error())
    let bres = node.getBlockSlot(state_id.get())
    if bres.isErr():
      return RestApiResponse.jsonError(Http404, "State not found",
                                       $bres.error())
    node.withStateForStateIdent(bres.get()):
      return RestApiResponse.jsonResponse(%state())

    return RestApiResponse.jsonError(Http500, "Internal server error")

  router.api(MethodGet,
             "/api/eth/v1/debug/beacon/heads") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      %node.chainDag.heads.mapIt((root: it.root, slot: it.slot))
    )
