# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import chronicles
import ../beacon_node,
       ./rest_utils

logScope: topics = "rest_light_client"

proc installLightClientApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://github.com/ethereum/beacon-APIs/pull/181
  router.api(MethodGet,
             "/eth/v0/beacon/light_client/bootstrap/{block_root}") do (
    block_root: Eth2Digest) -> RestApiResponse:
    doAssert node.dag.lcDataStore.serve
    let vroot = block:
      if block_root.isErr():
        return RestApiResponse.jsonError(Http400, InvalidBlockRootValueError,
                                         $block_root.error())
      block_root.get()

    let bootstrap = node.dag.getLightClientBootstrap(vroot)
    if bootstrap.isOk:
      return RestApiResponse.jsonResponse(bootstrap)
    else:
      return RestApiResponse.jsonError(Http404, LCBootstrapUnavailable)

  # https://github.com/ethereum/beacon-APIs/pull/181
  router.api(MethodGet,
             "/eth/v0/beacon/light_client/updates") do (
    start_period: Option[SyncCommitteePeriod], count: Option[uint64]
    ) -> RestApiResponse:
    doAssert node.dag.lcDataStore.serve
    let vstart = block:
      if start_period.isNone():
        return RestApiResponse.jsonError(Http400, MissingStartPeriodValueError)
      let rstart = start_period.get()
      if rstart.isErr():
        return RestApiResponse.jsonError(Http400, InvalidSyncPeriodError,
                                         $rstart.error())
      rstart.get()
    let vcount = block:
      if count.isNone():
        return RestApiResponse.jsonError(Http400, MissingCountValueError)
      let rcount = count.get()
      if rcount.isErr():
        return RestApiResponse.jsonError(Http400, InvalidCountError,
                                         $rcount.error())
      rcount.get()
    let
      headPeriod = node.dag.head.slot.sync_committee_period
       # Limit number of updates in response
      maxSupportedCount =
        if vstart > headPeriod:
          0'u64
        else:
          min(headPeriod + 1 - vstart, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
      numPeriods = min(vcount, maxSupportedCount)
      onePastPeriod = vstart + numPeriods

    var updates = newSeqOfCap[LightClientUpdate](numPeriods)
    for period in vstart..<onePastPeriod:
      let update = node.dag.getLightClientUpdateForPeriod(period)
      if update.isSome:
        updates.add update.get
    return RestApiResponse.jsonResponse(updates)

  # https://github.com/ethereum/beacon-APIs/pull/181
  router.api(MethodGet,
             "/eth/v0/beacon/light_client/finality_update") do (
    ) -> RestApiResponse:
    doAssert node.dag.lcDataStore.serve
    let finality_update = node.dag.getLightClientFinalityUpdate()
    if finality_update.isSome:
      return RestApiResponse.jsonResponse(finality_update)
    else:
      return RestApiResponse.jsonError(Http404, LCFinUpdateUnavailable)

  # https://github.com/ethereum/beacon-APIs/pull/181
  router.api(MethodGet,
             "/eth/v0/beacon/light_client/optimistic_update") do (
    ) -> RestApiResponse:
    doAssert node.dag.lcDataStore.serve
    let optimistic_update = node.dag.getLightClientOptimisticUpdate()
    if optimistic_update.isSome:
      return RestApiResponse.jsonResponse(optimistic_update)
    else:
      return RestApiResponse.jsonError(Http404, LCOptUpdateUnavailable)
