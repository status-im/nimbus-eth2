# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronicles
import ../beacon_node,
       ./rest_utils

logScope: topics = "rest_light_client"

proc installLightClientApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Beacon/getLightClientBootstrap
  router.api(MethodGet,
             "/eth/v1/beacon/light_client/bootstrap/{block_root}") do (
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
    withForkyBootstrap(bootstrap):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyBootstrap.contextEpoch
          contextFork = node.dag.cfg.consensusForkAtEpoch(contextEpoch)
        return
          if contentType == sszMediaType:
            let headers = [("eth-consensus-version", contextFork.toString())]
            RestApiResponse.sszResponse(forkyBootstrap, headers)
          elif contentType == jsonMediaType:
            RestApiResponse.jsonResponseWVersion(forkyBootstrap, contextFork)
          else:
            RestApiResponse.jsonError(Http500, InvalidAcceptError)
      else:
        return RestApiResponse.jsonError(Http404, LCBootstrapUnavailable)

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Beacon/getLightClientUpdatesByRange
  router.api(MethodGet,
             "/eth/v1/beacon/light_client/updates") do (
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

    var updates =
      newSeqOfCap[RestVersioned[ForkedLightClientUpdate]](numPeriods)
    for period in vstart..<onePastPeriod:
      let
        update = node.dag.getLightClientUpdateForPeriod(period)
        contextEpoch = withForkyUpdate(update):
          when lcDataFork > LightClientDataFork.None:
            forkyUpdate.contextEpoch
          else:
            continue
        contextFork = node.dag.cfg.consensusForkAtEpoch(contextEpoch)
      updates.add RestVersioned[ForkedLightClientUpdate](
        data: update,
        jsonVersion: contextFork,
        sszContext: node.dag.forkDigests[].atConsensusFork(contextFork))

    return
      if contentType == sszMediaType:
        RestApiResponse.sszResponseVersioned(updates)
      elif contentType == jsonMediaType:
        RestApiResponse.jsonResponseVersioned(updates)
      else:
        RestApiResponse.jsonError(Http500, InvalidAcceptError)

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Beacon/getLightClientFinalityUpdate
  router.api(MethodGet,
             "/eth/v1/beacon/light_client/finality_update") do (
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
    withForkyFinalityUpdate(finality_update):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyFinalityUpdate.contextEpoch
          contextFork = node.dag.cfg.consensusForkAtEpoch(contextEpoch)
        return
          if contentType == sszMediaType:
            let headers = [("eth-consensus-version", contextFork.toString())]
            RestApiResponse.sszResponse(forkyFinalityUpdate, headers)
          elif contentType == jsonMediaType:
            RestApiResponse.jsonResponseWVersion(
              forkyFinalityUpdate, contextFork)
          else:
            RestApiResponse.jsonError(Http500, InvalidAcceptError)
      else:
        return RestApiResponse.jsonError(Http404, LCFinUpdateUnavailable)

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Beacon/getLightClientOptimisticUpdate
  router.api(MethodGet,
             "/eth/v1/beacon/light_client/optimistic_update") do (
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
    withForkyOptimisticUpdate(optimistic_update):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyOptimisticUpdate.contextEpoch
          contextFork = node.dag.cfg.consensusForkAtEpoch(contextEpoch)
        return
          if contentType == sszMediaType:
            let headers = [("eth-consensus-version", contextFork.toString())]
            RestApiResponse.sszResponse(forkyOptimisticUpdate, headers)
          elif contentType == jsonMediaType:
            RestApiResponse.jsonResponseWVersion(
              forkyOptimisticUpdate, contextFork)
          else:
            RestApiResponse.jsonError(Http500, InvalidAcceptError)
      else:
        return RestApiResponse.jsonError(Http404, LCOptUpdateUnavailable)
