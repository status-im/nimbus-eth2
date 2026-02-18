# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/sequtils
import chronicles, metrics
import ".."/beacon_node,
       ".."/spec/forks,
       "."/[rest_beacon_api, rest_utils, state_ttl_cache]

from ../fork_choice/proto_array import ProtoArrayItem, items

export rest_utils

logScope: topics = "rest_debug"

proc installDebugApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Debug/getDebugDataColumnSidecars
  # https://github.com/ethereum/beacon-APIs/blob/v4.0.0-alpha.0/apis/debug/data_column_sidecars.yaml
  router.api2(
      MethodGet, "/eth/v1/debug/beacon/data_column_sidecars/{block_id}") do (
      block_id: BlockIdent, indices: seq[uint64]) -> RestApiResponse:
    handleDataSidecarRequest[
      InvalidDataColumnSidecarIndexValueError,
      List[fulu.DataColumnSidecar, NUMBER_OF_COLUMNS],
    ](
      node, preferredContentType(jsonMediaType, sszMediaType),
      block_id, indices)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getState
  router.api2(MethodGet, "/eth/v1/debug/beacon/states/{state_id}") do (
    state_id: StateIdent) -> RestApiResponse:
    RestApiResponse.jsonError(
      Http410, DeprecatedRemovalBeaconBlocksDebugStateV1)

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=v3.1.0#/Debug/getStateV2
  # https://github.com/ethereum/beacon-APIs/blob/v4.0.0-alpha.0/apis/debug/state.v2.yaml
  router.metricsApi2(
    MethodGet, "/eth/v2/debug/beacon/states/{state_id}",
    {RestServerMetricsType.Status, Response}) do (
    state_id: StateIdent) -> RestApiResponse:
    let
      bslot = block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                           $state_id.error())
        let bres = node.getBlockSlotId(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                           $bres.error())
        bres.get()
      contentType = block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()

    node.withStateForBlockSlotId(bslot):
      return
        if contentType == jsonMediaType:
          RestApiResponse.jsonResponseState(
            state, node.getStateOptimistic(state),
            node.dag.isFinalized(bslot.bid),
            node.hasRestAllowedOrigin)
        elif contentType == sszMediaType:
          withState(state):
            RestApiResponse.sszResponse(
              forkyState.data, state.kind, node.hasRestAllowedOrigin)
        else:
          RestApiResponse.jsonError(Http500, InvalidAcceptError)

    RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getDebugChainHeads
  router.api2(MethodGet,
              "/eth/v1/debug/beacon/heads") do () -> RestApiResponse:
    RestApiResponse.jsonError(
      Http410, DeprecatedRemovalGetDebugChainHeadsV1)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getDebugChainHeadsV2
  router.api2(MethodGet,
              "/eth/v2/debug/beacon/heads") do () -> RestApiResponse:
    RestApiResponse.jsonResponse(
      node.dag.heads.mapIt(
        RestChainHeadV2(
          root: it.root,
          slot: it.slot,
          execution_optimistic: not it.executionValid
        )
      )
    )

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Debug/getDebugForkChoice
  router.api2(MethodGet, "/eth/v1/debug/fork_choice") do () -> RestApiResponse:
    template forkChoice: auto = node.attestationPool[].forkChoice

    var response = GetForkChoiceResponse(
      justified_checkpoint: forkChoice.checkpoints.justified.checkpoint,
      finalized_checkpoint: forkChoice.checkpoints.finalized,
      extra_data: RestExtraData(
        confirmed_root: forkChoice.get_safe_beacon_block_root,
        current_epoch_observed_justified_checkpoint:
          forkChoice.backend.current_epoch_observed_justified.checkpoint,
        previous_slot_head: forkChoice.backend.previous_slot_head,
        current_slot_head: forkChoice.backend.current_slot_head))

    for item in forkChoice.backend.proto_array:
      let
        unrealized = item.unrealized.get(item.checkpoints)
        u_justified_checkpoint =
          if unrealized.justified != item.checkpoints.justified:
            Opt.some unrealized.justified
          else:
            Opt.none(Checkpoint)
        u_finalized_checkpoint =
          if unrealized.finalized != item.checkpoints.finalized:
            Opt.some unrealized.finalized
          else:
            Opt.none(Checkpoint)

      response.fork_choice_nodes.add RestNode(
        slot: item.bid.slot,
        block_root: item.bid.root,
        parent_root: item.parent,
        justified_epoch: item.checkpoints.justified.epoch,
        finalized_epoch: item.checkpoints.finalized.epoch,
        weight: item.weight,
        validity:
          if item.invalid:
            RestNodeValidity.invalid
          else:
            # Fork choice doesn't necessarily prune finalized blocks in a
            # synchronized way to the chaindag, so can't assume that when
            # item.bid.slot is before finalizedHead, it has shared status
            # regarding optimistic/validity as finalizedHead, so fallback
            # to optimistic is more appropriate for this REST endpoint.
            let blck = node.dag.getBlockRef(item.bid.root)
            if blck.isNone() or not blck.get.executionValid:
              RestNodeValidity.optimistic
            else:
              RestNodeValidity.valid,
        execution_block_hash:
          node.dag.loadExecutionBlockHash(item.bid).get(ZERO_HASH),
        extra_data: Opt.some RestNodeExtraData(
          justified_root: item.checkpoints.justified.root,
          finalized_root: item.checkpoints.finalized.root,
          u_justified_checkpoint: u_justified_checkpoint,
          u_finalized_checkpoint: u_finalized_checkpoint,
          best_child: item.bestChild,
          best_descendant: item.bestDescendant))

    RestApiResponse.jsonResponsePlain(response)
