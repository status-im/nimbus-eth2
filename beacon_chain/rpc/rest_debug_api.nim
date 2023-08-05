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
    return RestApiResponse.jsonError(
      Http410, DeprecatedRemovalGetDebugChainHeadsV1)

  # https://ethereum.github.io/beacon-APIs/#/Debug/getDebugChainHeadsV2
  router.api(MethodGet,
             "/eth/v2/debug/beacon/heads") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      node.dag.heads.mapIt(
        (
          root: it.root,
          slot: it.slot,
          execution_optimistic: not it.executionValid
        )
      )
    )

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Debug/getDebugForkChoice
  router.api(MethodGet,
             "/eth/v1/debug/fork_choice") do () -> RestApiResponse:
    template forkChoice: auto = node.attestationPool[].forkChoice

    var response = GetForkChoiceResponse(
      justified_checkpoint: forkChoice.checkpoints.justified.checkpoint,
      finalized_checkpoint: forkChoice.checkpoints.finalized)

    for item in forkChoice.backend.proto_array:
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

      response.fork_choice_nodes.add RestNode(
        slot: item.bid.slot,
        block_root: item.bid.root,
        parent_root: item.parent,
        justified_epoch: item.checkpoints.justified.epoch,
        finalized_epoch: item.checkpoints.finalized.epoch,
        weight: cast[uint64](item.weight),
        validity:
          if item.invalid:
            RestNodeValidity.invalid
          elif node.dag.is_optimistic(item.bid):
            RestNodeValidity.optimistic
          else:
            RestNodeValidity.valid,
        execution_block_hash: node.dag.loadExecutionBlockHash(item.bid),
        extra_data: some RestNodeExtraData(
          justified_root: item.checkpoints.justified.root,
          finalized_root: item.checkpoints.finalized.root,
          u_justified_checkpoint: u_justified_checkpoint,
          u_finalized_checkpoint: u_finalized_checkpoint,
          best_child: item.bestChild,
          bestDescendant: item.bestDescendant))

    return RestApiResponse.jsonResponsePlain(response)
