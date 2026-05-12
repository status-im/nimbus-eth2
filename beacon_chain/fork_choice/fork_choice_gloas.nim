# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Standard library
  std/[tables, sets],
  # Status libraries
  results, chronicles,
  # Internal
  ../spec/[beaconstate, helpers, state_transition_block],
  ../spec/datatypes/[phase0, altair, bellatrix],
  # Fork choice
  ../consensus_object_pools/blockchain_dag,
  "."/[fork_choice_types, proto_array]

func isGloasEnabled*(dag: ChainDAGRef, slot: Slot): bool =
  slot.epoch >= dag.cfg.GLOAS_FORK_EPOCH

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#new-on_payload_attestation_message
proc on_payload_attestation_message*(
   self: var ForkChoice,
   dag: ChainDAGRef,
   validator_index: ValidatorIndex,
   beacon_block_root: Eth2Digest,
   slot: Slot,
   payload_present: bool,
   blob_data_available: bool,
   is_from_block: bool = false): FcResult[void] =
  ## Run ``on_payload_attestation_message`` upon receiving
  ## a new ``ptc_message`` directly on the wire.

  if not dag.isGloasEnabled(slot):
    return ok()

  # The beacon block root must be known
  if beacon_block_root notin self.backend.proto_array.indices:
    return ok()

  # PTC attestation must be for a known block.
  # If block is unknown, delay consideration until the block is found
  discard self.backend.ptc_vote.mgetOrPut(
    beacon_block_root, default(PtcVotes))

  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      # check that its for the current slot if it is coming from the wire
      if not is_from_block:
        if slot != self.checkpoints.time.slotOrZero(dag.timeParams):
          return ok()

      var
        ptc_index = -1
        i = 0

      for vidx in get_ptc(forkyState.data, slot):
        if vidx == validator_index:
          ptc_index = i
          break
        inc i

      # Check that the attester is from the PTC
      if ptc_index >= 0:
        var votes =
          self.backend.ptc_vote.mgetOrPut(
            beacon_block_root, default(PtcVotes))
        votes.voted.setBit(ptc_index)
        if payload_present:
          votes.value.setBit(ptc_index)
        else:
          votes.value.clearBit(ptc_index)
        self.backend.ptc_vote[beacon_block_root] = votes

        var da_votes =
          self.backend.ptc_data_availability_vote.mgetOrPut(
            beacon_block_root, default(PtcVotes))
        da_votes.voted.setBit(ptc_index)
        if blob_data_available:
          da_votes.value.setBit(ptc_index)
        else:
          da_votes.value.clearBit(ptc_index)
        self.backend.ptc_data_availability_vote[beacon_block_root] = da_votes

        trace "Recorded PTC vote",
          validator_index, payload_present, blob_data_available
  ok()

# Block timeliness and proposer boost
# ----------------------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#modified-record_block_timeliness
proc record_block_timeliness*(
    self: var ForkChoice, dag: ChainDAGRef,
    blck_slot: Slot, root: Eth2Digest,
    consensusFork: ConsensusFork) =
  let
    current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)
    is_current_slot = current_slot == blck_slot

  self.backend.block_timeliness[root] = [
    is_current_slot and self.checkpoints.time <
      current_slot.attestation_deadline(dag.timeParams, consensusFork),
    is_current_slot and self.checkpoints.time <
      current_slot.payload_attestation_deadline(dag.timeParams)]

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/phase0/fork-choice.md#update_proposer_boost_root
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#modified-update_proposer_boost_root
proc update_proposer_boost_root*(
    self: var ForkChoice, dag: ChainDAGRef,
    blckRef: BlockRef, blck: ForkyTrustedBeaconBlock, current_slot: Slot) =

  template is_first_block: bool =
    self.checkpoints.proposer_boost_root == ZERO_HASH

  let is_timely = self.backend.block_timeliness.getOrDefault(
    blckRef.root, [false, false])[ATTESTATION_TIMELINESS_INDEX]

  # Add proposer score boost if the block is the first timely block
  # for this slot, with the same proposer as the canonical chain.
  if is_timely and is_first_block:
    # Only apply boost if the block's proposer matches the expected proposer
    # on the canonical chain (head advanced to current slot).
    let expectedProposer = dag.getProposer(dag.head, current_slot)
    if expectedProposer.isSome and
        blck.proposer_index == expectedProposer.get().uint64:
      self.checkpoints.proposer_boost_root = blckRef.root

template getPhysicalNode*(
    self: var ForkChoice, logicalIdx: int): ptr ProtoNode =
  let physicalIdx = logicalIdx - self.backend.proto_array.nodes.offset
  if physicalIdx >= 0 and
      physicalIdx < self.backend.proto_array.nodes.buf.len:
    addr self.backend.proto_array.nodes.buf[physicalIdx]
  else: nil

template getNode*(
    self: var ForkChoice, root: Eth2Digest): ptr ProtoNode =
  let idx = self.backend.proto_array.indices.getOrDefault(root, -1)
  if idx < 0: nil
  else:
    self.getPhysicalNode(idx)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#modified-is_head_weak
func is_head_weak(
    self: var ForkChoice, head_root: Eth2Digest,
    dag: ChainDAGRef): bool =
  let
    total = self.checkpoints.justified.total_active_balance
    reorg_threshold =
      (total div SLOTS_PER_EPOCH) * dag.cfg.REORG_HEAD_WEIGHT_THRESHOLD div 100

  let proto_node = self.getNode(head_root)
  if proto_node == nil:
    return true

  proto_node.weight.Gwei < reorg_threshold

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#new-should_apply_proposer_boost
proc should_apply_proposer_boost*(
    self: var ForkChoice, dag: ChainDAGRef): bool =
  let proposer_root = self.checkpoints.proposer_boost_root
  if proposer_root.isZero:
    return false

  let idx = self.backend.proto_array.indices.getOrDefault(proposer_root, -1)
  if idx < 0: return false
  let block_node = self.getPhysicalNode(idx)
  if block_node == nil: return false

  if block_node.parent.isNone: return true
  let parent_node = self.getPhysicalNode(block_node.parent.get())
  if parent_node == nil: return true

  let slot = block_node.bid.slot

  if parent_node.bid.slot + 1 < slot:
    return true

  if not self.is_head_weak(parent_node.bid.root, dag):
    return true

  # If parent is weak and from the previous slot, apply
  # proposer boost if there are no early equivocations
  for i in 0 ..< self.backend.proto_array.nodes.buf.len:
    let blk = addr self.backend.proto_array.nodes.buf[i]
    if blk.bid.root != parent_node.bid.root and
        blk.bid.slot + 1 == slot and
        blk.proposerIndex == parent_node.proposerIndex and
        self.backend.block_timeliness.getOrDefault(
          blk.bid.root, [false, false])[PTC_TIMELINESS_INDEX]:
      return false

  true

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/fork-choice.md#new-on_execution_payload_envelope
proc on_execution_payload*(
    self: var ForkChoice, dag: ChainDAGRef,
    signedEnvelope: SignedExecutionPayloadEnvelope): FcResult[void] =
  template envelope: auto = signedEnvelope.message
  let
    beacon_block_root = envelope.beacon_block_root
    current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)

  if not dag.isGloasEnabled(current_slot):
    return ok()

  if beacon_block_root notin self.backend.proto_array.indices:
    return err ForkChoiceError(kind: fcFinalizedNodeUnknown,
                                blockRoot: beacon_block_root)

  # Verify the execution payload envelope
  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      let verifyResult = dag.timeParams.verify_execution_payload_envelope(
          dag.forkAtEpoch(envelope.payload.slot_number.epoch),
          forkyState, signedEnvelope,
          dag.genesis_validators_root)
      if verifyResult.isErr:
        debug "Execution payload envelope verification failed",
          error = verifyResult.error,
          beacon_block_root = shortLog(beacon_block_root),
          headSlot = forkyState.data.slot
        return err ForkChoiceError(kind: fcFinalizedNodeUnknown,
                                    blockRoot: beacon_block_root)

  self.backend.execution_payload_states.incl(beacon_block_root)
  ? self.backend.proto_array.onPayloadVerified(beacon_block_root)
  ok()
