# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Standard library
  std/tables,
  # Status libraries
  results, chronicles,
  # Internal
  ../spec/[beaconstate, helpers, state_transition_block],
  ../spec/datatypes/[phase0, altair, bellatrix],
  # Fork choice
  ../consensus_object_pools/[blockchain_dag, spec_cache],
  "."/[fork_choice_types, proto_array]

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#new-should_apply_proposer_boost
proc should_apply_proposer_boost*(
    self: var ForkChoice, dag: ChainDAGRef): bool =
  let proposer_root = self.checkpoints.proposer_boost_root
  if proposer_root.isZero:
    return false

  let block_node = self.backend.proto_array.getNode(proposer_root)
  if block_node == nil: return false
  if block_node.parent.isNone: return true
  let parent_node =
    self.backend.proto_array.getPhysicalNode(block_node.parent.get())
  if parent_node == nil: return true

  let slot = block_node.bid.slot

  # Apply boost if the parent is not from the previous slot
  if parent_node.bid.slot + 1 < slot:
    return true

  # Apply boost if the parent is not weak
  if not self.is_head_weak(parent_node.bid.root, dag):
    return true

  # Parent is weak and from the previous slot: withhold boost if its proposer
  # has a PTC-timely equivocating sibling at the parent's slot. (Same slot does
  # not imply same proposer across forks, so the proposer is checked.)
  let parentBlck = dag.getBlockRef(parent_node.bid.root)
  if parentBlck.isNone:
    return true
  let parentProposer = dag.getProposer(
      parentBlck.get, parent_node.bid.slot).valueOr:
    return true

  for root, timeliness in self.backend.block_timeliness:
    if not timeliness[PTC_TIMELINESS_INDEX]: continue
    if root == parent_node.bid.root: continue
    let candBlck = dag.getBlockRef(root).valueOr: continue
    if candBlck.slot != parent_node.bid.slot: continue
    let candProposer = dag.getProposer(candBlck, candBlck.slot).valueOr: continue
    if candProposer.uint64 == parentProposer.uint64:
      return false

  true

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#new-on_payload_attestation_message
proc on_payload_attestation_message*(
    self: var ForkChoice,
    dag: ChainDAGRef,
    ptc_message: PayloadAttestationMessage,
    is_from_block: bool = false): FcResult[void] =
  let
    beacon_block_root = ptc_message.data.beacon_block_root
    slot = ptc_message.data.slot
    validator_index = ValidatorIndex(ptc_message.validator_index)

  if slot.epoch < dag.cfg.GLOAS_FORK_EPOCH:
    return ok()

  if beacon_block_root notin self.backend.proto_array.indices:
    return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

  let blockSlot = self.backend.proto_array.slot(beacon_block_root).valueOr:
    return err ForkChoiceError(kind: fcInvalidPayloadAttestation)
  if slot != blockSlot:
    return ok()

  var ptcIndices: seq[int]
  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      if not is_from_block:
        if slot != self.checkpoints.time.slotOrZero(dag.timeParams):
          return err ForkChoiceError(kind: fcInvalidPayloadAttestation)
        if not is_valid_indexed_payload_attestation(
            forkyState.data,
            IndexedPayloadAttestation(
              attesting_indices:
                List[uint64, Limit PTC_SIZE].init(
                  @[ptc_message.validator_index]),
              data: ptc_message.data,
              signature: ptc_message.signature)):
          return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

      var ptcIndex = 0
      for vidx in get_ptc(forkyState.data, slot):
        if vidx == validator_index:
          ptcIndices.add ptcIndex
        inc ptcIndex

      if ptcIndices.len == 0:
        return err ForkChoiceError(kind: fcInvalidPayloadAttestation)

      trace "Validated PTC vote",
        validator_index,
        ptc_positions = ptcIndices.len,
        payload_present = ptc_message.data.payload_present,
        blob_data_available = ptc_message.data.blob_data_available

  for ptcIndex in ptcIndices:
    self.backend.ptcVotes.mgetOrPut(
      beacon_block_root, PtcVoteTally()).present[ptcIndex] =
        ptc_message.data.payload_present
    self.backend.ptcVotes.mgetOrPut(
      beacon_block_root, PtcVoteTally()).available[ptcIndex] =
        ptc_message.data.blob_data_available

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#new-on_execution_payload_envelope
# The spec's `is_data_available` precondition is enforced by the caller
# (`block_processor.storePayload` via `verifySidecars`) before this is invoked.
proc on_execution_payload*(
    self: var ForkChoice, dag: ChainDAGRef,
    signedEnvelope: SignedExecutionPayloadEnvelope): FcResult[void] =
  template envelope: auto = signedEnvelope.message
  let
    beacon_block_root = envelope.beacon_block_root
    current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)

  if current_slot.epoch < dag.cfg.GLOAS_FORK_EPOCH:
    return ok()

  if beacon_block_root notin self.backend.proto_array.indices:
    return err ForkChoiceError(kind: fcFinalizedNodeUnknown,
                                blockRoot: beacon_block_root)

  # Verify the execution payload envelope using the state after the block,
  # not dag.headState which may still be at the parent.
  let blck = dag.getBlockRef(beacon_block_root).valueOr:
    return err ForkChoiceError(kind: fcFinalizedNodeUnknown,
                                blockRoot: beacon_block_root)
  let bsi = blck.bid.atSlot()
  dag.withUpdatedState(dag.epochRefState, bsi):
    withState(updatedState):
      when consensusFork >= ConsensusFork.Gloas:
        let verifyResult = dag.timeParams.verify_execution_payload_envelope(
            dag.forkAtEpoch(envelope.payload.slot_number.epoch),
            forkyState, signedEnvelope,
            dag.genesis_validators_root)
        if verifyResult.isErr:
          debug "Execution payload envelope verification failed",
            error = verifyResult.error,
            beacon_block_root = shortLog(beacon_block_root),
            stateSlot = forkyState.data.slot
          return err ForkChoiceError(kind: fcFinalizedNodeUnknown,
                                      blockRoot: beacon_block_root)
  do:
    debug "Unable to load state for envelope verification",
      beacon_block_root = shortLog(beacon_block_root)
    return err ForkChoiceError(kind: fcFinalizedNodeUnknown,
                                blockRoot: beacon_block_root)

  ? self.backend.proto_array.onPayloadVerified(beacon_block_root)
  ok()
