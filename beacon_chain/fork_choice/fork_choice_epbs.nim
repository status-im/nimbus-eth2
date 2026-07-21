# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[enumerate, sets],
  ../consensus_object_pools/[blockchain_dag, spec_cache],
  ./[fork_choice_types, proto_array]

from ../spec/beaconstate import get_ptc
from ../spec/datatypes/gloas import
  PAYLOAD_TIMELY_THRESHOLD, DATA_AVAILABILITY_TIMELY_THRESHOLD

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/fork-choice.md#payload_timeliness
func payload_timeliness*(
    self: var ForkChoiceBackend, root: Eth2Digest, timely: bool): bool =
  # Return whether the execution payload for the beacon block with root ``root``
  # is considered ``timely`` (or not, when ``timely`` is ``False``), taking into
  # consideration local availability and PTC votes.

  # If the payload is not locally available, the payload
  # is not considered available regardless of the PTC vote
  if root notin self.proto_array.fullBlockIndices:
    return not timely
  var count = 0'u64
  self.ptc_votes.withValue(root, tally):
    for i in 0 ..< tally[].voted.len:
      if tally[].voted[i] and tally[].present[i] == timely:
        inc count
  count > PAYLOAD_TIMELY_THRESHOLD

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/fork-choice.md#payload_data_availability
func payload_data_availability*(
    self: var ForkChoiceBackend, root: Eth2Digest, available: bool): bool =
  # Return whether the blob data for the beacon block with root ``root`` is
  # considered ``available`` (or not, when ``available`` is ``False``), taking into
  # consideration local availability and PTC votes.

  # If the payload is not locally available, the blob data
  # is not considered available regardless of the PTC vote
  if root notin self.proto_array.fullBlockIndices:
    return not available
  var count = 0'u64
  self.ptc_votes.withValue(root, tally):
    for i in 0 ..< tally[].voted.len:
      if tally[].voted[i] and tally[].available[i] == available:
        inc count
  count > DATA_AVAILABILITY_TIMELY_THRESHOLD

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/fork-choice.md#should_extend_payload
func should_extend_payload*(
    self: var ForkChoiceBackend, root: Eth2Digest): bool =
  if root notin self.proto_array.fullBlockIndices:
    return false
  self.payload_timeliness(root, timely = true) and
    self.payload_data_availability(root, available = true)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/fork-choice.md#should_build_on_full
func should_build_on_full*(
    self: var ForkChoiceBackend, root: Eth2Digest, full: bool,
    current_slot: Slot): bool =
  let slot = self.proto_array.slot(root).valueOr:
    return false
  if slot + 1 != current_slot:
    return full
  if not full:
    return false
  if self.payload_timeliness(root, timely = false):
    return false
  if self.payload_data_availability(root, available = false):
    return false
  true

proc should_build_on_full*(
    self: var ForkChoice, dag: ChainDAGRef, head: BlockRef, full: bool,
    wallSlot: Slot): bool =
  if head.slot == GENESIS_SLOT or head.slot.epoch < dag.cfg.GLOAS_FORK_EPOCH:
    return true
  self.backend.should_build_on_full(head.root, full, wallSlot)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#modified-is_head_weak
proc is_head_weak(
    self: var ForkChoice, head_root: Eth2Digest, dag: ChainDAGRef): bool =
  # Calculate weight threshold for weak head
  let
    total = self.checkpoints.justified.total_active_balance
    reorg_threshold =
      (total div SLOTS_PER_EPOCH) * dag.cfg.REORG_HEAD_WEIGHT_THRESHOLD div 100

  let proto_node = self.backend.proto_array.node(head_root).valueOr:
    return true

  var head_weight = proto_node.weight.Gwei

  if head_root == self.backend.proto_array.previousProposerBoostRoot:
    head_weight -= self.backend.proto_array.previousProposerBoostScore

  # Compute head weight including equivocations
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

  for root in self.backend.timely_proposer_blocks:
    if root == parent_node.bid.root: continue
    let candBlck = dag.getBlockRef(root).valueOr: continue
    if candBlck.slot != parent_node.bid.slot: continue
    let candProposer = dag.getProposer(candBlck, candBlck.slot).valueOr: continue
    if candProposer == parentProposer:
      return false

  true

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/fork-choice.md#new-on_payload_attestation_message
proc on_payload_attestation_message*(
    self: var ForkChoice,
    dag: ChainDAGRef,
    validator_index: uint64,
    data: PayloadAttestationData): FcResult[void] =
  ## Run ``on_payload_attestation_message`` upon receiving a new ``ptc_message``
  ## from either within a block or directly on the wire.
  template beacon_block_root: untyped = data.beacon_block_root
  let slot = data.slot
  let valIdx = ValidatorIndex.init(validator_index).valueOr:
    return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

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

  # Check that the attestation is for the current slot. The signature is verified
  # upstream in `validatePayloadAttestationMessage` (gossip).
  if slot != self.checkpoints.time.slotOrZero(dag.timeParams):
    return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      # Update the votes for the block
      var tally: ptr PtcVoteTally
      for ptc_index, vidx in enumerate(get_ptc(forkyState.data, slot)):
        if vidx == valIdx:
          if tally.isNil:
            tally = addr self.backend.ptc_votes.mgetOrPut(
              beacon_block_root, PtcVoteTally())
          tally.voted[ptc_index] = true
          tally.present[ptc_index] = data.payload_present
          tally.available[ptc_index] = data.blob_data_available

      # Check that the attester is from the PTC
      if tally.isNil:
        return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

      trace "Recorded PTC vote",
        validator_index,
        payload_present = data.payload_present,
        blob_data_available = data.blob_data_available
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
