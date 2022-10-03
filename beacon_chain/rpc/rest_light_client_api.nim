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
    let contentType =
      block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()

    let vroot = block:
      if block_root.isErr():
        return RestApiResponse.jsonError(Http400, InvalidBlockRootValueError,
                                         $block_root.error())
      block_root.get()

    let bootstrap = node.dag.getLightClientBootstrap(vroot)
    if bootstrap.isNone:
      return RestApiResponse.jsonError(Http404, LCBootstrapUnavailable)

    let
      contextEpoch = bootstrap.get.contextEpoch
      contextFork = node.dag.cfg.stateForkAtEpoch(contextEpoch)
    return
      if contentType == sszMediaType:
        let headers = [("eth-consensus-version", contextFork.toString())]
        RestApiResponse.sszResponse(bootstrap.get, headers)
      elif contentType == jsonMediaType:
        RestApiResponse.jsonResponseWVersion(bootstrap.get, contextFork)
      else:
        RestApiResponse.jsonError(Http500, InvalidAcceptError)

  # https://github.com/ethereum/beacon-APIs/pull/181
  router.api(MethodGet,
             "/eth/v0/beacon/light_client/updates") do (
    start_period: Option[SyncCommitteePeriod], count: Option[uint64]
    ) -> RestApiResponse:
    doAssert node.dag.lcDataStore.serve
    let contentType =
      block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()

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

    var updates = newSeqOfCap[RestVersioned[LightClientUpdate]](numPeriods)
    for period in vstart..<onePastPeriod:
      let update = node.dag.getLightClientUpdateForPeriod(period)
      if update.isSome:
        let
          contextEpoch = update.get.contextEpoch
          contextFork = node.dag.cfg.stateForkAtEpoch(contextEpoch)
        updates.add RestVersioned[LightClientUpdate](
          data: update.get,
          jsonVersion: contextFork,
          sszContext: node.dag.forkDigests[].atStateFork(contextFork))

    return
      if contentType == sszMediaType:
        RestApiResponse.sszResponseVersionedList(updates)
      elif contentType == jsonMediaType:
        RestApiResponse.jsonResponseVersionedList(updates)
      else:
        RestApiResponse.jsonError(Http500, InvalidAcceptError)

  # https://github.com/ethereum/beacon-APIs/pull/181
  router.api(MethodGet,
             "/eth/v0/beacon/light_client/finality_update") do (
    ) -> RestApiResponse:
    doAssert node.dag.lcDataStore.serve
    let contentType =
      block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()

    let finality_update = node.dag.getLightClientFinalityUpdate()
    if finality_update.isNone:
      return RestApiResponse.jsonError(Http404, LCFinUpdateUnavailable)

    let
      contextEpoch = finality_update.get.contextEpoch
      contextFork = node.dag.cfg.stateForkAtEpoch(contextEpoch)
    return
      if contentType == sszMediaType:
        let headers = [("eth-consensus-version", contextFork.toString())]
        RestApiResponse.sszResponse(finality_update.get, headers)
      elif contentType == jsonMediaType:
        RestApiResponse.jsonResponseWVersion(finality_update.get, contextFork)
      else:
        RestApiResponse.jsonError(Http500, InvalidAcceptError)

  # https://github.com/ethereum/beacon-APIs/pull/181
  router.api(MethodGet,
             "/eth/v0/beacon/light_client/optimistic_update") do (
    ) -> RestApiResponse:
    doAssert node.dag.lcDataStore.serve
    let contentType =
      block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()

    let optimistic_update = node.dag.getLightClientOptimisticUpdate()
    if optimistic_update.isNone:
      return RestApiResponse.jsonError(Http404, LCOptUpdateUnavailable)

    let
      contextEpoch = optimistic_update.get.contextEpoch
      contextFork = node.dag.cfg.stateForkAtEpoch(contextEpoch)
    return
      if contentType == sszMediaType:
        let headers = [("eth-consensus-version", contextFork.toString())]
        RestApiResponse.sszResponse(optimistic_update.get, headers)
      elif contentType == jsonMediaType:
        RestApiResponse.jsonResponseWVersion(optimistic_update.get, contextFork)
      else:
        RestApiResponse.jsonError(Http500, InvalidAcceptError)
