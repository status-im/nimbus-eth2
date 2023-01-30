# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/sequtils
import chronicles
import ".."/beacon_node,
       ".."/spec/forks,
       "."/[rest_utils, state_ttl_cache]

from ../fork_choice/proto_array import ProtoArrayItem, items

export rest_utils

logScope: topics = "rest_debug"

proc installDebugApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/#/Debug/getState
  router.api(MethodGet,
             "/eth/v1/debug/beacon/states/{state_id}") do (
    state_id: StateIdent) -> RestApiResponse:
    return RestApiResponse.jsonError(
      Http410, DeprecatedRemovalBeaconBlocksDebugStateV1)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2
  router.api(MethodGet,
             "/eth/v2/debug/beacon/states/{state_id}") do (
    state_id: StateIdent) -> RestApiResponse:
    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                           $state_id.error())
        let bres = node.getBlockSlotId(state_id.get())
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
    node.withStateForBlockSlotId(bslot):
      return
        if contentType == jsonMediaType:
          RestApiResponse.jsonResponseState(
            state,
            node.getStateOptimistic(state)
          )
        elif contentType == sszMediaType:
          let headers = [("eth-consensus-version", state.kind.toString())]
          withState(state):
            RestApiResponse.sszResponse(forkyState.data, headers)
        else:
          RestApiResponse.jsonError(Http500, InvalidAcceptError)
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getDebugChainHeads
  router.api(MethodGet,
             "/eth/v1/debug/beacon/heads") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      node.dag.heads.mapIt((root: it.root, slot: it.slot))
    )

  # https://ethereum.github.io/beacon-APIs/#/Debug/getDebugChainHeadsV2
  router.api(MethodGet,
             "/eth/v2/debug/beacon/heads") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      node.dag.heads.mapIt(
        (
          root: it.root,
          slot: it.slot,
          execution_optimistic: node.getBlockRefOptimistic(it)
        )
      )
    )

  # https://github.com/ethereum/beacon-APIs/pull/232
  if node.config.debugForkChoice or experimental in node.dag.updateFlags:
    router.api(MethodGet,
               "/eth/v1/debug/fork_choice") do () -> RestApiResponse:
      type
        ForkChoiceResponseExtraData = object
          justified_root: Eth2Digest
          finalized_root: Eth2Digest
          u_justified_checkpoint: Option[Checkpoint]
          u_finalized_checkpoint: Option[Checkpoint]
          best_child: Eth2Digest
          best_descendant: Eth2Digest
          invalid: bool

        ForkChoiceResponse = object
          slot: Slot
          block_root: Eth2Digest
          parent_root: Eth2Digest
          justified_epoch: Epoch
          finalized_epoch: Epoch
          weight: uint64
          execution_optimistic: bool
          execution_payload_root: Eth2Digest
          extra_data: Option[ForkChoiceResponseExtraData]

      var responses: seq[ForkChoiceResponse]
      for item in node.attestationPool[].forkChoice.backend.proto_array:
        let
          unrealized = item.unrealized.get(item.checkpoints)
          u_justified_checkpoint =
            if unrealized.justified != item.checkpoints.justified:
              some unrealized.justified
            else:
              none(Checkpoint)
          u_finalized_checkpoint =
            if unrealized.finalized != item.checkpoints.finalized:
              some unrealized.finalized
            else:
              none(Checkpoint)

        responses.add ForkChoiceResponse(
          slot: item.bid.slot,
          block_root: item.bid.root,
          parent_root: item.parent,
          justified_epoch: item.checkpoints.justified.epoch,
          finalized_epoch: item.checkpoints.finalized.epoch,
          weight: cast[uint64](item.weight),
          execution_optimistic: node.dag.is_optimistic(item.bid.root),
          execution_payload_root: node.dag.loadExecutionBlockRoot(item.bid),
          extra_data: some ForkChoiceResponseExtraData(
            justified_root: item.checkpoints.justified.root,
            finalized_root: item.checkpoints.finalized.root,
            u_justified_checkpoint: u_justified_checkpoint,
            u_finalized_checkpoint: u_finalized_checkpoint,
            best_child: item.bestChild,
            bestDescendant: item.bestDescendant,
            invalid: item.invalid))
      return RestApiResponse.jsonResponse(responses)
