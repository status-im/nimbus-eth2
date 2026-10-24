# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import chronicles, metrics
import ../beacon_node,
       ../spec/forks,
       ./[rest_beacon_api, rest_utils, state_ttl_cache]

from std/sequtils import mapIt
from ../fork_choice/proto_array import ProtoArrayItem, items
from ../fork_choice/fork_choice_epbs import getPtcTally

export rest_utils

logScope: topics = "rest_debug"

proc installDebugApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Debug/getDebugDataColumnSidecars
  # https://github.com/ethereum/beacon-APIs/blob/v4.0.0-alpha.0/apis/debug/data_column_sidecars.yaml
  router.api2(
      MethodGet, "/eth/v1/debug/beacon/data_column_sidecars/{block_id}") do (
      block_id: BlockIdent, indices: seq[uint64]) -> RestApiResponse:
    let
      blockIdent = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)
      bid = node.getBlockId(blockIdent).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)
    if bid.slot.epoch >= node.dag.cfg.GLOAS_FORK_EPOCH:
      handleDataSidecarRequest[
        InvalidDataColumnSidecarIndexValueError,
        List[gloas.DataColumnSidecar, NUMBER_OF_COLUMNS],
      ](
        node, preferredContentType(jsonMediaType, sszMediaType),
        block_id, indices)
    else:
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
        confirmed_root: forkChoice.retrieve_fast_confirmed_root(),
        current_epoch_observed_justified_checkpoint:
          forkChoice.backend.current_epoch_observed_justified.checkpoint,
        previous_epoch_greatest_unrealized_checkpoint:
          forkChoice.backend.previous_epoch_greatest_unrealized_checkpoint,
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

  # https://github.com/ethereum/beacon-APIs/blob/v5.0.0-beta.0/apis/debug/fork_choice.v2.yaml
  router.api2(MethodGet, "/eth/v2/debug/fork_choice") do () -> RestApiResponse:
    template forkChoice: auto = node.attestationPool[].forkChoice

    var response = GetForkChoiceResponseV2(
      justified_checkpoint: forkChoice.checkpoints.justified.checkpoint,
      finalized_checkpoint: forkChoice.checkpoints.finalized,
      extra_data: RestExtraData(
        confirmed_root: forkChoice.retrieve_fast_confirmed_root(),
        current_epoch_observed_justified_checkpoint:
          forkChoice.backend.current_epoch_observed_justified.checkpoint,
        previous_epoch_greatest_unrealized_checkpoint:
          forkChoice.backend.previous_epoch_greatest_unrealized_checkpoint,
        previous_slot_head: forkChoice.backend.previous_slot_head,
        current_slot_head: forkChoice.backend.current_slot_head))

    # `proto_array` keeps one base node per block (which is the EMPTY variant
    # for post-Gloas blocks, which also accumulates same-slot PENDING votes) and
    # adds a separate FULL node once the payload is verified. The spec tree has
    # three nodes per block, so each node is expanded below into PENDING, EMPTY
    # and (if present) FULL.
    var
      slots: Table[Eth2Digest, Slot]
      fullItems: Table[Eth2Digest, ProtoArrayItem]

    for item in forkChoice.backend.proto_array:
      if item.isFull:
        fullItems[item.bid.root] = item
      else:
        slots[item.bid.root] = item.bid.slot

    template isGloas(slot: Slot): bool =
      node.dag.cfg.consensusForkAtEpoch(slot.epoch) >= ConsensusFork.Gloas

    # `RestNodeV2.parent_payload_status` is required but nullable
    let
      nullStatus = JsonString("null")
      pendingStatus = JsonString(RestJson.encode(RestPayloadStatus.pending))
      emptyStatus = JsonString(RestJson.encode(RestPayloadStatus.empty))
      fullStatus = JsonString(RestJson.encode(RestPayloadStatus.full))

    template nodeExtraData(src: ProtoArrayItem): RestNodeExtraData =
      block:
        let unrealized = src.unrealized.get(src.checkpoints)
        RestNodeExtraData(
          justified_root: src.checkpoints.justified.root,
          finalized_root: src.checkpoints.finalized.root,
          u_justified_checkpoint:
            if unrealized.justified != src.checkpoints.justified:
              Opt.some unrealized.justified
            else:
              Opt.none(Checkpoint),
          u_finalized_checkpoint:
            if unrealized.finalized != src.checkpoints.finalized:
              Opt.some unrealized.finalized
            else:
              Opt.none(Checkpoint),
          best_child: src.bestChild,
          best_descendant: src.bestDescendant)

    for item in forkChoice.backend.proto_array:
      if item.isFull:
        continue # Emitted together with its base node below

      let
        root = item.bid.root
        blck = node.dag.getBlockRef(root)
        (blockHash, parentHash) =
          if blck.isSome():
            node.dag.loadExecutionAndParentBlockHash(blck.get())
          else:
            node.dag.loadExecutionAndParentBlockHash(item.bid)
        executionValid = blck.isSome() and blck.get().executionValid
        parentSlot = slots.getOrDefault(item.parent, FAR_FUTURE_SLOT)
        parentStatus =
          if parentSlot == FAR_FUTURE_SLOT:
            nullStatus
          elif not isGloas(parentSlot) or item.parentIsFull:
            fullStatus
          else:
            emptyStatus

      template nodeValidity(isInvalid: bool): RestNodeValidity =
        if isInvalid:
          RestNodeValidity.invalid
        elif executionValid:
          RestNodeValidity.valid
        else:
          RestNodeValidity.optimistic

      if not isGloas(item.bid.slot):
        response.fork_choice_nodes.add RestNodeV2(
          slot: item.bid.slot,
          block_root: root,
          payload_status: RestPayloadStatus.full,
          parent_root: item.parent,
          parent_payload_status: parentStatus,
          justified_checkpoint: item.checkpoints.justified,
          finalized_checkpoint: item.checkpoints.finalized,
          weight: item.weight,
          validity: nodeValidity(item.invalid),
          execution_block_hash: blockHash.get(ZERO_HASH),
          extra_data: nodeExtraData(item))
        continue

      let
        hasFull = root in fullItems
        fullItem = fullItems.getOrDefault(root)
        tally = forkChoice.backend.getPtcTally(root)

      var attesterCount, availability, dataAvailability: uint64
      for i in 0 ..< tally.voted.len:
        if tally.voted[i]:
          inc attesterCount
          if tally.present[i]:
            inc availability
          if tally.available[i]:
            inc dataAvailability

      template addGloasNode(
          status: RestPayloadStatus,
          pRoot: Eth2Digest,
          parentStatus: JsonString,
          nodeWeight: uint64,
          isInvalid: bool,
          execHash: Opt[Eth2Digest],
          src: ProtoArrayItem) =
        response.fork_choice_nodes.add RestNodeV2(
          slot: item.bid.slot,
          block_root: root,
          payload_status: status,
          parent_root: pRoot,
          parent_payload_status: parentStatus,
          justified_checkpoint: src.checkpoints.justified,
          finalized_checkpoint: src.checkpoints.finalized,
          weight: nodeWeight,
          validity: nodeValidity(isInvalid),
          execution_block_hash: execHash.get(ZERO_HASH),
          payload_attester_count: attesterCount,
          payload_availability_yes_count: availability,
          payload_data_availability_yes_count: dataAvailability,
          extra_data: nodeExtraData(src))

      let
        fullWeight = if hasFull: fullItem.weight else: 0'u64
        boost =
          if root == forkChoice.backend.proto_array.previousProposerBoostRoot:
            uint64(forkChoice.backend.proto_array.previousProposerBoostScore)
          else:
            0'u64
        emptyWeight =
          item.weight - min(item.weight, item.pendingWeight + boost)

      addGloasNode(
        RestPayloadStatus.pending, item.parent, parentStatus,
        item.weight + fullWeight, item.invalid, parentHash, item)

      addGloasNode(
        RestPayloadStatus.empty, root, pendingStatus,
        emptyWeight, item.invalid, parentHash, item)

      if hasFull:
        addGloasNode(
          RestPayloadStatus.full, root, pendingStatus,
          fullItem.weight, fullItem.invalid, blockHash, fullItem)

    RestApiResponse.jsonResponse(response)
