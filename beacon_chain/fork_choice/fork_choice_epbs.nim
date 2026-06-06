# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/enumerate,
  ../consensus_object_pools/[blockchain_dag, spec_cache],
  ./[fork_choice_types, proto_array]

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#modified-is_head_weak
proc is_head_weak(
    self: var ForkChoice, head_root: Eth2Digest, dag: ChainDAGRef): bool =
  let
    total = self.checkpoints.justified.total_active_balance
    reorg_threshold =
      (total div SLOTS_PER_EPOCH) * dag.cfg.REORG_HEAD_WEIGHT_THRESHOLD div 100

  let proto_node = self.backend.proto_array.node(head_root).valueOr:
    return true

  var head_weight = proto_node.weight.Gwei

  # Also count effective balance of equivocating validators (vote disabled via
  # `vote.slot == FAR_FUTURE_SLOT`) in the head slot's committees, so the weight
  # is monotonic in observed attestations.
  dag.getBlockRef(head_root).isErrOr:
    dag.getShufflingRef(value, proto_node.bid.slot.epoch, true).isErrOr:
      template balances: untyped = self.checkpoints.justified.balances
      for committee_index in get_committee_indices(value):
        for _, val in value.get_beacon_committee(
            proto_node.bid.slot, committee_index):
          if val < self.backend.votes.lenu64 and
              self.backend.votes[val].slot == FAR_FUTURE_SLOT and
              val < balances.lenu64:
            head_weight += balances[val].effective_balance

  head_weight < reorg_threshold

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#new-should_apply_proposer_boost
proc should_apply_proposer_boost*(
    self: var ForkChoice, dag: ChainDAGRef): bool =
  template proposer_root: untyped = self.checkpoints.proposer_boost_root
  if proposer_root.isZero:
    return false

  let block_node = self.backend.proto_array.node(proposer_root).valueOr:
    return false
  if block_node.parent.isNone: return true
  let parent_node = self.backend.proto_array.node(block_node.parent.get()).valueOr:
    return true

  let slot = block_node.bid.slot

  # Apply proposer boost if `parent` is not from the previous slot
  if parent_node.bid.slot + 1 < slot:
    return true

  # Apply proposer boost if `parent` is not weak
  if not self.is_head_weak(parent_node.bid.root, dag):
    return true

  # If `parent` is weak and from the previous slot, apply proposer boost if
  # there are no early equivocations
  let parentBlck = dag.getBlockRef(parent_node.bid.root).valueOr:
    return true
  let parentProposer = dag.getProposer(
      parentBlck, parent_node.bid.slot).valueOr:
    return true

  for root, timeliness in self.backend.block_timeliness:
    if not timeliness[PTC_TIMELINESS_INDEX]: continue
    if root == parent_node.bid.root: continue
    let candBlck = dag.getBlockRef(root).valueOr: continue
    if candBlck.slot != parent_node.bid.slot: continue
    let candProposer = dag.getProposer(candBlck, candBlck.slot).valueOr: continue
    if candProposer == parentProposer:
      return false

  true

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#new-on_payload_attestation_message
proc on_payload_attestation_message*(
    self: var ForkChoice,
    dag: ChainDAGRef,
    validator_index: uint64,
    data: PayloadAttestationData,
    is_from_block: bool = false): FcResult[void] =
  ## Run ``on_payload_attestation_message`` upon receiving a new ``ptc_message`` from
  ## either within a block or directly on the wire.
  template beacon_block_root: untyped = data.beacon_block_root
  let
    slot = data.slot
    valIdx = ValidatorIndex(validator_index)

  if slot.epoch < dag.cfg.GLOAS_FORK_EPOCH:
    return ok()

  # PTC attestation must be for a known block. If block is unknown, delay
  # consideration until the block is found
  if beacon_block_root notin self.backend.proto_array.indices:
    return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

  # PTC votes can only change the vote for their assigned beacon block, return
  # early otherwise
  let blockSlot = self.backend.proto_array.slot(beacon_block_root).valueOr:
    return err ForkChoiceError(kind: fcInvalidPayloadAttestation)
  if slot != blockSlot:
    return ok()

  # The spec uses the state at `beacon_block_root`; the payload timeliness
  # committee only needs that block's shuffling, which is cheaper to obtain.
  debugGloasComment "revisit get_ptc perf: getShufflingRef recompute vs cached/ptc_window"
  let
    blockRef = dag.getBlockRef(beacon_block_root).valueOr:
      return err ForkChoiceError(kind: fcInvalidPayloadAttestation)
    shufflingRef = dag.getShufflingRef(blockRef, slot.epoch, true).valueOr:
      return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      # Check that it's for the current slot if it is coming from the wire
      if not is_from_block and
          slot != self.checkpoints.time.slotOrZero(dag.timeParams):
        return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

      # Get all positions of the attester in the PTC
      var ptc_indices: seq[int]
      for ptc_index, vidx in enumerate(
          get_ptc(forkyState.data, shufflingRef, slot)):
        if vidx == valIdx:
          ptc_indices.add ptc_index

      # Check that the attester is from the PTC
      if ptc_indices.len == 0:
        return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

      trace "Validated PTC vote",
        validator_index,
        ptc_positions = ptc_indices.len,
        payload_present = data.payload_present,
        blob_data_available = data.blob_data_available

      # Update the votes for the block
      let tally = addr self.backend.ptcVotes.mgetOrPut(
        beacon_block_root, PtcVoteTally())
      for ptc_index in ptc_indices:
        tally.present[ptc_index] = data.payload_present
        tally.available[ptc_index] = data.blob_data_available

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#new-on_execution_payload_envelope
func on_execution_payload*(
    self: var ForkChoice, cfg: RuntimeConfig, timeParams: TimeParams,
    signedEnvelope: SignedExecutionPayloadEnvelope): FcResult[void] =
  ## Run ``on_execution_payload_envelope`` upon receiving a new execution
  ## payload envelope.
  template envelope: untyped = signedEnvelope.message
  template beacon_block_root: untyped = envelope.beacon_block_root
  let current_slot = self.checkpoints.time.slotOrZero(timeParams)

  if current_slot.epoch < cfg.GLOAS_FORK_EPOCH:
    return ok()

  # The corresponding beacon block root needs to be known
  if beacon_block_root notin self.backend.proto_array.indices:
    return err ForkChoiceError(kind: fcFinalizedNodeUnknown,
                                blockRoot: beacon_block_root)

  # Add execution payload envelope to the store
  ? self.backend.proto_array.onPayloadVerified(beacon_block_root)
  ok()
