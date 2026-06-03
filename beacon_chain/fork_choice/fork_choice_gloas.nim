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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/fork-choice.md#new-on_payload_attestation_message
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
    return err ForkChoiceError(kind: fcPtcBlockUnknown)

  let blockSlot = self.backend.proto_array.slot(beacon_block_root).valueOr:
    return err ForkChoiceError(kind: fcPtcBlockUnknown)
  if slot != blockSlot:
    return ok()

  var ptcIndices: seq[int]
  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      if not is_from_block:
        if slot != self.checkpoints.time.slotOrZero(dag.timeParams):
          return err ForkChoiceError(kind: fcPtcInvalidSlot)
        if not is_valid_indexed_payload_attestation(
            forkyState.data,
            IndexedPayloadAttestation(
              attesting_indices:
                List[uint64, Limit PTC_SIZE].init(
                  @[ptc_message.validator_index]),
              data: ptc_message.data,
              signature: ptc_message.signature)):
          return err ForkChoiceError(kind: fcPtcInvalidSignature)

      var ptcIndex = 0
      for vidx in get_ptc(forkyState.data, slot):
        if vidx == validator_index:
          ptcIndices.add ptcIndex
        inc ptcIndex

      if ptcIndices.len == 0:
        return err ForkChoiceError(kind: fcPtcNotMember)

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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/fork-choice.md#modified-record_block_timeliness
proc record_block_timeliness*(
    self: var ForkChoice, dag: ChainDAGRef,
    blck_slot: Slot, root: Eth2Digest,
    consensusFork: ConsensusFork,
    proposerIndex: uint64): bool =
  let
    current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)
    is_current_slot = current_slot == blck_slot
    is_timely = is_current_slot and self.checkpoints.time <
      current_slot.attestation_deadline(dag.timeParams, consensusFork)
    ptc_timely = is_current_slot and self.checkpoints.time <
      current_slot.payload_attestation_deadline(dag.timeParams)

  if ptc_timely:
    self.backend.timely_proposer_blocks.mgetOrPut(
      blck_slot, @[]).add((proposerIndex, root))

  is_timely

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/gloas/fork-choice.md#modified-get_dependent_root
func get_dependent_root(
    dag: ChainDAGRef, root: Eth2Digest, current_slot: Slot): Eth2Digest =
  let epoch = current_slot.epoch
  if epoch <= MIN_SEED_LOOKAHEAD:
    # Genesis block parent
    return ZERO_HASH
  let blckRef = dag.getBlockRef(root).valueOr:
    return ZERO_HASH
  let dependent_slot =
    start_slot(Epoch(epoch.uint64 - MIN_SEED_LOOKAHEAD)) - 1
  let ancestor = blckRef.get_ancestor(dependent_slot)
  if ancestor.isNil:
    return ZERO_HASH
  ancestor.root

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fork-choice.md#update_proposer_boost_root
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/gloas/fork-choice.md#modified-update_proposer_boost_root
proc update_proposer_boost_root*(
    self: var ForkChoice, dag: ChainDAGRef,
    blckRef: BlockRef, head_root: Eth2Digest,
    current_slot: Slot, is_timely: bool) =

  template is_first_block: bool =
    self.checkpoints.proposer_boost_root == ZERO_HASH

  # Add proposer score boost if the block is timely, not conflicting with an
  # existing block, with the same dependent root as the canonical chain head.
  let is_same_dependent_root =
    get_dependent_root(dag, blckRef.root, current_slot) ==
    get_dependent_root(dag, head_root, current_slot)
  if is_timely and is_first_block and is_same_dependent_root:
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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/fork-choice.md#modified-is_head_weak
proc is_head_weak(
    self: var ForkChoice, head_root: Eth2Digest,
    dag: ChainDAGRef): bool =
  let
    total = self.checkpoints.justified.total_active_balance
    reorg_threshold =
      (total div SLOTS_PER_EPOCH) * dag.cfg.REORG_HEAD_WEIGHT_THRESHOLD div 100

  let proto_node = self.getNode(head_root)
  if proto_node == nil:
    return true

  var head_weight = proto_node.weight.Gwei

  # Also count the effective balance of equivocating validators (vote disabled
  # via `vote.slot == FAR_FUTURE_SLOT`) in the head slot's committees, so the
  # weight is monotonic in observed attestations.
  let headBlck = dag.getBlockRef(head_root)
  if headBlck.isSome:
    let shuffling =
      dag.getShufflingRef(headBlck.get, proto_node.bid.slot.epoch, true)
    if shuffling.isSome:
      let shufflingRef = shuffling.get
      template balances: untyped = self.checkpoints.justified.balances
      for committee_index in get_committee_indices(shufflingRef):
        for _, val in shufflingRef.get_beacon_committee(
            proto_node.bid.slot, committee_index):
          if val < self.backend.votes.lenu64 and
              self.backend.votes[val].slot == FAR_FUTURE_SLOT and
              val < balances.lenu64:
            head_weight += balances[val].effective_balance

  head_weight < reorg_threshold

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/fork-choice.md#new-should_apply_proposer_boost
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

  # `parent.proposer_index` is the deterministic proposer for its slot.
  let parentBlck = dag.getBlockRef(parent_node.bid.root)
  if parentBlck.isNone:
    return true
  let parentProposer = dag.getProposer(
      parentBlck.get, parent_node.bid.slot).valueOr:
    return true

  let entries = self.backend.timely_proposer_blocks.getOrDefault(
    parent_node.bid.slot)
  for (proposer, root) in entries:
    if proposer == parentProposer.uint64 and root != parent_node.bid.root:
      return false

  true

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/fork-choice.md#new-on_execution_payload_envelope
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
