# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Standard library
  std/[sets, tables],
  # Status libraries
  results, chronicles,
  # Internal
  ../spec/[beaconstate, helpers, state_transition_block],
  ../spec/datatypes/[phase0, altair, bellatrix],
  # Fork choice
  ../consensus_object_pools/[spec_cache, blockchain_dag],
  ./[fork_choice_types, proto_array, fast_confirmation, fork_choice_epbs]

from std/sequtils import keepItIf
export results, fork_choice_types, fork_choice_epbs
export proto_array.len

# This is a port of https://github.com/sigp/lighthouse/pull/804
# which is a port of "Proto-Array": https://github.com/protolambda/lmd-ghost
# See also:
# - Protolambda port of Lighthouse: https://github.com/protolambda/eth2-py-hacks/blob/ae286567/proto_array.py
# - Prysmatic writeup: https://hackmd.io/bABJiht3Q9SyV3Ga4FT9lQ#High-level-concept
# - Gasper Whitepaper: https://arxiv.org/abs/2003.03052

# Forward declarations
# ----------------------------------------------------------------------

type Index = fork_choice_types.Index

func compute_deltas(
    deltas: var openArray[Delta],
    indices: Table[Eth2Digest, Index],
    fullBlockIndices: Table[Eth2Digest, Index],
    indices_offset: Index,
    votes: var openArray[VoteTracker],
    old_balances: openArray[ForkChoiceBalance],
    new_balances: openArray[ForkChoiceBalance]): FcResult[void]

func find_head(
    self: var ForkChoiceBackend,
    current_slot: Slot,
    checkpoints: Checkpoints,
    proposerBoostRoot: Eth2Digest): FcResult[Eth2Digest]

# Fork choice routines
# ----------------------------------------------------------------------

logScope: topics = "fork_choice"

func init*(
    T: type ForkChoiceBackend, confirmation_byzantine_threshold: uint64,
    finalized: BalanceCheckpoint, finalizedSlot, currentSlot: Slot): T =
  T(confirmation_byzantine_threshold: confirmation_byzantine_threshold,
    proto_array: ProtoArray.init(
      finalized.checkpoint, finalizedSlot, currentSlot),
    confirmed: BlockId(
      slot: finalizedSlot,
      root: finalized.checkpoint.root),
    current_epoch_observed_justified: finalized.balance_source,
    previous_epoch_greatest_unrealized_checkpoint: finalized.checkpoint,
    previous_slot_head: finalized.checkpoint.root,
    current_slot_head: finalized.checkpoint.root)

proc init*(
    T: type ForkChoice, confirmation_byzantine_threshold: uint64,
    epochRef: EpochRef, blck: BlockRef, currentSlot = GENESIS_SLOT,
    wallTime = default(BeaconTime)): T =
  ## Initialize a fork choice context for a finalized state - in the finalized
  ## state, the justified and finalized checkpoints are the same, so only one
  ## is used here
  debug "Initializing fork choice",
    epoch = epochRef.epoch, blck = shortLog(blck)

  let
    finalized = to_balance_checkpoint(epochRef, blck)
    finalizedSlot = blck.slot
  ForkChoice(
    backend: ForkChoiceBackend.init(
      confirmation_byzantine_threshold, finalized, finalizedSlot, currentSlot),
    checkpoints: Checkpoints(
      time: wallTime,
      justified: finalized,
      finalized: finalized.checkpoint))

func process_attestation(
    self: var ForkChoiceBackend,
    validator_index: ValidatorIndex, block_root: Eth2Digest, slot: Slot,
    payload_present: bool, cfg: RuntimeConfig) =
  ## Add an attestation to the fork choice context
  self.votes.extend(validator_index.int + 1)

  template vote: untyped = self.votes[validator_index]

  if slot.epoch >= cfg.GLOAS_FORK_EPOCH:
    # slot based tracking with payload preference
    if slot > vote.slot or vote.next_root.isZero:
      vote.next_root = block_root
      vote.slot = slot
      vote.next_payload_present = payload_present

      trace "Integrating Gloas vote in fork choice",
        validator_index = validator_index,
        slot = slot,
        payload_present = payload_present,
        new_vote = shortLog(vote)
  else:
    if vote.slot != FAR_FUTURE_SLOT:
      if slot.epoch > vote.slot.epoch or vote.next_root.isZero:
        vote.next_root = block_root
        vote.slot = slot

      trace "Integrating vote in fork choice",
        validator_index = validator_index,
        new_vote = shortLog(vote)

proc process_attestation_queue(
    self: var ForkChoice, slot: Slot, cfg: RuntimeConfig) =
  # Spec:
  # Attestations can only affect the fork choice of subsequent slots.
  # Delay consideration in the fork choice until their slot is in the past.
  let startTick = Moment.now()
  self.queuedAttestations.keepItIf:
    if it.slot < slot:
      for validator_index in it.attesting_indices:
        self.backend.process_attestation(
          validator_index, it.block_root, it.slot,
          it.committee_index == CommitteeIndex(1), cfg)
      false
    else:
      true
  let endTick = Moment.now()
  debug "Processed attestation queue", processDur = endTick - startTick

proc update_justified(
    self: var Checkpoints, dag: ChainDAGRef,
    epoch: Epoch, blck: BlockRef) =
  let epochRef = dag.getEpochRef(blck, epoch, preFinalized = false).valueOr:
    # Shouldn't happen for justified data unless out of sync with ChainDAG
    warn "Skipping justified checkpoint update, no EpochRef - report bug",
      blck, epoch, error
    return

  trace "Updating justified",
    store = self.justified.checkpoint,
    state = Checkpoint(root: blck.root, epoch: epochRef.epoch)
  self.justified = to_balance_checkpoint(epochRef, blck)

proc update_justified(
    self: var ForkChoice, dag: ChainDAGRef,
    justified: Checkpoint, current_slot: Slot): FcResult[void] =
  if justified == self.backend.current_epoch_observed_justified.checkpoint:
    trace "Updating justified (cache hit)",
      store = self.checkpoints.justified.checkpoint,
      state = self.backend.current_epoch_observed_justified.checkpoint
    self.checkpoints.justified =
      self.backend.current_epoch_observed_justified.info
    return ok()

  let blck = dag.getBlockRef(justified.root).valueOr:
    return err ForkChoiceError(
      kind: fcJustifiedNodeUnknown,
      blockRoot: justified.root)
  self.checkpoints.update_justified(dag, justified.epoch, blck)
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/phase0/fork-choice.md#update_checkpoints
proc update_checkpoints(
    self: var ForkChoice, dag: ChainDAGRef,
    checkpoints: FinalityCheckpoints, current_slot: Slot): FcResult[void] =
  ## Update checkpoints in store if necessary
  # Update justified checkpoint
  if checkpoints.justified.epoch > self.checkpoints.justified.checkpoint.epoch:
    ? self.update_justified(dag, checkpoints.justified, current_slot)

  # Update finalized checkpoint
  if checkpoints.finalized.epoch > self.checkpoints.finalized.epoch:
    trace "Updating finalized",
      store = self.checkpoints.finalized, state = checkpoints.finalized
    self.checkpoints.finalized = checkpoints.finalized

    template previous_epoch_justified: Checkpoint =
      self.backend.previous_epoch_greatest_unrealized_checkpoint
    if self.checkpoints.finalized.epoch >= previous_epoch_justified.epoch:
      trace "Pruned previous_epoch_greatest_unrealized_checkpoint",
        store = previous_epoch_justified, state = self.checkpoints.finalized
      previous_epoch_justified = self.checkpoints.finalized

  ok()

proc update_confirmed(
    self: var ForkChoiceBackend, dag: ChainDAGRef, confirmed: BlockId,
    current_slot: Slot, reason = "", diag = default(FcrDiagnostics)) =
  template prev: BlockId = self.confirmed
  template curr: BlockId = confirmed
  if curr != prev:
    if reason != "" and (prev.slot > curr.slot or not dag.isCanonical(prev)):
      incSafeReorgs()
      if diag.chain_len > 0:
        notice "Previous 'safe' block no longer safe",
          previousSafe = prev, currentSafe = curr, reason, diag
      else:
        notice "Previous 'safe' block no longer safe",
          previousSafe = prev, currentSafe = curr, reason
    else:
      trace "Updating 'safe' block",
        previousSafe = prev, currentSafe = curr
  if dag.onFastConfirmation != nil:
    if curr != prev or current_slot != self.latest_fcr_event_slot:
      self.latest_fcr_event_slot = current_slot
      dag.onFastConfirmation FastConfirmationInfoObject.init(curr, current_slot)
  prev = curr

proc to_block_id(self: ForkChoiceBackend, checkpoint: Checkpoint): BlockId =
  result.slot = self.proto_array.slot(checkpoint.root).valueOr:
    warn "Checkpoint not in proto array", checkpoint
    checkpoint.epoch.start_slot
  result.root = checkpoint.root

func observed_justified_block_id(self: ForkChoiceBackend): BlockId =
  BlockId(
    slot: self.current_epoch_observed_justified.info.block_slot,
    root: self.current_epoch_observed_justified.checkpoint.root)

proc update_unrealized_justified(self: var ForkChoice, dag: ChainDAGRef) =
  let unrealized = self.backend.previous_epoch_greatest_unrealized_checkpoint
  if unrealized == self.backend.current_epoch_observed_justified.checkpoint:
    return

  let
    blck = dag.getBlockRef(unrealized.root).valueOr:
      warn "Skipping unrealized justified checkpoint update - no BlockRef",
        unrealized
      return
    epochRef = dag.getEpochRef(blck, unrealized.epoch, false).valueOr:
      warn "Skipping unrealized justified checkpoint update - no EpochRef",
        unrealized, blck, error
      return
    old_source = move(self.backend.current_epoch_observed_justified)
  self.backend.current_epoch_observed_justified.info =
    epochRef.to_balance_checkpoint(blck)
  self.backend.current_epoch_observed_justified.assign_shufflings(old_source)

proc reconfirm_fcr(
    self: var ForkChoice, dag: ChainDAGRef,
    confirmed: var BlockId, current_slot: Slot,
    reason: var string, diag: var FcrDiagnostics): FcResult[void] =
  template fcr: ForkChoiceBackend = self.backend

  # Reconfirm with previous balance source after attestations
  # from past slots have been applied
  self.process_attestation_queue(current_slot, dag.cfg)
  if ? fcr.should_revert_confirmed_on_new_epoch(
      dag, confirmed, current_slot, diag):
    reason = "epoch"
    confirmed = fcr.to_block_id(self.checkpoints.finalized)
    incSafeEpochReverts()

  # Update observed justified checkpoints at the start of an epoch
  self.update_unrealized_justified(dag)

  # Restart confirmation chain if necessary
  fcr.current_slot_head = ? fcr.find_head(current_slot, self.checkpoints,
                                          self.checkpoints.proposer_boost_root)
  if ? fcr.should_restart_confirmation_chain(confirmed, current_slot):
    reason = "restart/e"
    confirmed = fcr.observed_justified_block_id
    incSafeRestarts()
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/phase0/fork-choice.md#on_tick_per_slot
proc on_tick(
    self: var ForkChoice, dag: ChainDAGRef, time: BeaconTime): FcResult[void] =
  ## Must be called at least once per slot.
  let previous_time = self.checkpoints.time

  # Update store time
  if time < previous_time:
    return err ForkChoiceError(kind: fcInconsistentTick)
  self.checkpoints.time = time

  let
    current_slot = time.slotOrZero(dag.timeParams)
    previous_slot = previous_time.slotOrZero(dag.timeParams)

  if current_slot > previous_slot:
    # Reset store.proposer_boost_root
    self.checkpoints.proposer_boost_root = ZERO_HASH

    # Update prev and curr slot head
    self.backend.previous_slot_head = self.backend.current_slot_head
    self.backend.current_slot_head = dag.head.root

    if (current_slot + 1).is_epoch:
      # Update greatest unrealized justified checkpoint
      # at the last slot of an epoch
      template justified: Checkpoint = self.checkpoints.justified.checkpoint
      self.backend.previous_epoch_greatest_unrealized_checkpoint =
        self.backend.proto_array.unrealized_justified(justified)

    elif current_slot.is_epoch:
      # Pull-up unrealized justified / finalized checkpoints from previous epoch
      let realized = self.backend.proto_array.realizePendingCheckpoints(
        FinalityCheckpoints(
          justified: self.checkpoints.justified.checkpoint,
          finalized: self.checkpoints.finalized))
      ? self.update_checkpoints(dag, realized, current_slot)

      var
        confirmed = self.backend.confirmed
        reason: string
        diag: FcrDiagnostics
      self.reconfirm_fcr(dag, confirmed, current_slot, reason, diag).isOkOr:
        warn "Failed to reconfirm 'safe' block - report bug",
          current_slot, reason = error
        reason = "reconfirm"
        confirmed = self.backend.to_block_id(self.checkpoints.finalized)
        incSafeErrors()
      self.backend.update_confirmed(dag, confirmed, current_slot, reason, diag)

    else:
      discard
  ok()

func contains*(self: ForkChoiceBackend, block_root: Eth2Digest): bool =
  ## Returns `true` if a block is known to the fork choice
  ## and `false` otherwise.
  ##
  ## In particular, before adding a block, its parent
  ## must be known to the fork choice
  self.proto_array.indices.contains(block_root)

proc update_time*(
    self: var ForkChoice, dag: ChainDAGRef, time: BeaconTime): FcResult[void] =
  # `time` is the wall time, meaning it changes on every call typically
  let step_size = dag.timeParams.SLOT_DURATION
  if time > self.checkpoints.time:
    let
      preSlot = self.checkpoints.time.slotOrZero(dag.timeParams)
      postSlot = time.slotOrZero(dag.timeParams)
    # Call on_tick at least once per slot.
    while time >= self.checkpoints.time + step_size:
      ? self.on_tick(dag, self.checkpoints.time + step_size)

    if time > self.checkpoints.time:
      # Might create two ticks for the last slot.
      ? self.on_tick(dag, time)

    if preSlot != postSlot:
      self.process_attestation_queue(postSlot, dag.cfg)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/phase0/fork-choice.md#on_attestation
proc on_attestation*(
    self: var ForkChoice,
    dag: ChainDAGRef,
    attestation_slot: Slot,
    beacon_block_root: Eth2Digest,
    attesting_indices: openArray[ValidatorIndex],
    attestation_committee_index: CommitteeIndex,
    wallTime: BeaconTime): FcResult[void] =
  ? self.update_time(dag,
    max(wallTime, attestation_slot.start_beacon_time(dag.timeParams)))

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#modified-validate_on_attestation
  if attestation_slot.epoch >= dag.cfg.GLOAS_FORK_EPOCH:
    let index = attestation_committee_index.uint64
    if index notin [0'u64, 1'u64]:
      return err ForkChoiceError(kind: fcInvalidAttestation)
    let block_slot = self.backend.proto_array.slot(beacon_block_root)
    if block_slot.isSome and block_slot.get == attestation_slot and index != 0:
      return err ForkChoiceError(kind: fcInvalidAttestation)
    # If attesting for a full node, the payload must be known
    debugGloasComment "temporarily disabled"
    # if index == 1 and
    #     beacon_block_root notin self.backend.proto_array.fullBlockIndices:
    #   return err ForkChoiceError(kind: fcInvalidAttestation)

  if attestation_slot < self.checkpoints.time.slotOrZero(dag.timeParams):
    for validator_index in attesting_indices:
      # attestation_slot and target epoch must match, per attestation rules
      self.backend.process_attestation(
        validator_index, beacon_block_root, attestation_slot,
        attestation_committee_index == CommitteeIndex(1), dag.cfg)
  else:
    # Spec:
    # Attestations can only affect the fork choice of subsequent slots.
    # Delay consideration in the fork choice until their slot is in the past.
    self.queuedAttestations.add QueuedAttestation(
      attesting_indices: @attesting_indices,
      block_root: beacon_block_root,
      committee_index: attestation_committee_index,
      slot: attestation_slot)
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/phase0/fork-choice.md#on_attester_slashing
func process_equivocation*(
    self: var ForkChoice, validator_index: ValidatorIndex) =
  self.backend.votes.extend(validator_index.int + 1)

  # Disallow future votes
  template vote: untyped = self.backend.votes[validator_index]
  if vote.slot != FAR_FUTURE_SLOT or not vote.next_root.isZero:
    vote.slot = FAR_FUTURE_SLOT
    vote.next_root.reset()

    trace "Integrating equivocation in fork choice", validator_index

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/phase0/fork-choice.md#on_block
func process_block*(
    self: var ForkChoiceBackend,
    bid: BlockId,
    parent_root: Eth2Digest,
    checkpoints: FinalityCheckpoints,
    unrealized = Opt.none(FinalityCheckpoints),
    parent_payload_status = PAYLOAD_STATUS_PENDING): FcResult[void] =
  self.proto_array.onBlock(
    bid, parent_root, checkpoints, unrealized, parent_payload_status)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#modified-record_block_timeliness
func record_block_timeliness(
    self: var ForkChoice, timeParams: TimeParams,
    blckRef: BlockRef, blck: ForkyTrustedBeaconBlock,
    current_slot: Slot): bool =
  ## Record whether the block is PTC-timely (read by `should_apply_proposer_boost`)
  ## and return whether it is attestation-timely (used by `update_proposer_boost_root`).
  const consensusFork = typeof(blck).kind
  let isCurrentSlot = current_slot == blck.slot

  when consensusFork >= ConsensusFork.Gloas:
    if isCurrentSlot and self.checkpoints.time <
        blck.slot.payload_attestation_deadline(timeParams):
      self.backend.timely_proposer_blocks.incl blckRef.root

  isCurrentSlot and self.checkpoints.time <
    blck.slot.attestation_deadline(timeParams, consensusFork)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/fork-choice.md#modified-update_proposer_boost_root
func update_proposer_boost_root(
    self: var ForkChoice, dag: ChainDAGRef,
    blckRef: BlockRef, current_slot: Slot, is_timely: bool) =
  template is_first_block: bool =
    self.checkpoints.proposer_boost_root == ZERO_HASH

  template is_same_dependent_root: bool =
    get_dependent_root(dag, blckRef.bid, current_slot) ==
      get_dependent_root(dag, dag.head.bid, current_slot)

  # Add proposer score boost if the block is timely, not conflicting with an
  # existing boosted block, and shares the dependent root of the canonical head.
  if is_timely and is_first_block and is_same_dependent_root:
    self.checkpoints.proposer_boost_root = blckRef.root

proc process_block*(
    self: var ForkChoice,
    dag: ChainDAGRef,
    epochRef: EpochRef,
    blckRef: BlockRef,
    unrealized: FinalityCheckpoints,
    blck: ForkyTrustedBeaconBlock,
    wallTime: BeaconTime): FcResult[void] =
  ? self.update_time(dag,
    max(wallTime, blckRef.slot.start_beacon_time(dag.timeParams)))

  for attester_slashing in blck.body.attester_slashings:
    for idx in getValidatorIndices(attester_slashing):
      let i = ValidatorIndex.init(idx).valueOr:
        continue
      self.process_equivocation(i)

  for attestation in blck.body.attestations:
    if attestation.data.beacon_block_root in self.backend:
      when typeof(blck).kind >= ConsensusFork.Gloas:
        let payloadPresent = attestation.data.index == 1
        for vidx in dag.get_attesting_indices(attestation):
          self.backend.process_attestation(
            vidx, attestation.data.beacon_block_root, attestation.data.slot,
            payloadPresent, dag.cfg)
      else:
        for vidx in dag.get_attesting_indices(attestation):
          self.backend.process_attestation(
            vidx, attestation.data.beacon_block_root, attestation.data.slot,
            false, dag.cfg)

  when typeof(blck).kind >= ConsensusFork.Gloas:
    for pa in blck.body.payload_attestations:
      let tally = addr self.backend.ptc_votes.mgetOrPut(
        pa.data.beacon_block_root, PtcVoteTally())
      for i in 0 ..< pa.aggregation_bits.len:
        if pa.aggregation_bits[i]:
          tally.present[i] = pa.data.payload_present
          tally.available[i] = pa.data.blob_data_available

  trace "Integrating block in fork choice",
    block_root = shortLog(blckRef)

  # Add proposer score boost if the block is timely
  let slot = self.checkpoints.time.slotOrZero(dag.timeParams)
  let isTimely = self.record_block_timeliness(dag.timeParams, blckRef, blck, slot)
  self.update_proposer_boost_root(dag, blckRef, slot, isTimely)

  # Update checkpoints in store if necessary
  ? self.update_checkpoints(dag, epochRef.checkpoints, slot)

  # If block is from a prior epoch, pull up the post-state to next epoch to
  # realize new finality info
  let unrealized_is_better =
    unrealized.justified.epoch > epochRef.checkpoints.justified.epoch or
    unrealized.finalized.epoch > epochRef.checkpoints.finalized.epoch
  if unrealized_is_better:
    if epochRef.epoch < slot.epoch:
      trace "Pulling up chain tip",
        blck = shortLog(blckRef), checkpoints = epochRef.checkpoints, unrealized
      ? self.update_checkpoints(dag, unrealized, slot)
      ? process_block(
        self.backend, blckRef.bid, blck.parent_root, unrealized)
    else:
      ? process_block(
        self.backend, blckRef.bid, blck.parent_root,
        epochRef.checkpoints, Opt.some unrealized)  # Realized in `on_tick`
  else:
    ? process_block(
      self.backend, blckRef.bid, blck.parent_root, epochRef.checkpoints)

  ok()

func find_head(
    self: var ForkChoiceBackend,
    current_slot: Slot,
    checkpoints: Checkpoints,
    proposerBoostRoot: Eth2Digest): FcResult[Eth2Digest] =
  ## Returns the new blockchain head

  # Apply score changes
  var deltas = newSeq[Delta](self.proto_array.nodes.len)
  ? deltas.compute_deltas(
    indices = self.proto_array.indices,
    fullBlockIndices = self.proto_array.fullBlockIndices,
    indices_offset = self.proto_array.nodes.offset,
    votes = self.votes,
    old_balances = self.balances,
    new_balances = checkpoints.justified.balances)
  ? self.proto_array.applyScoreChanges(
    deltas, current_slot,
    FinalityCheckpoints(
      justified: checkpoints.justified.checkpoint,
      finalized: checkpoints.finalized),
    checkpoints.justified.total_active_balance,
    proposerBoostRoot)
  self.balances = checkpoints.justified.balances

  # Find the best block
  var new_head{.noinit.}: Eth2Digest
  ? self.proto_array.findHead(new_head)

  trace "Fork choice requested",
    current_slot, checkpoints = FinalityCheckpoints(
      justified: checkpoints.justified.checkpoint,
      finalized: checkpoints.finalized),
    fork_choice_head = shortLog(new_head)
  ok(new_head)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/phase0/fork-choice.md#get_head
proc get_head*(
    self: var ForkChoice, dag: ChainDAGRef,
    wallTime: BeaconTime): FcResult[Eth2Digest] =
  ? self.update_time(dag, wallTime)
  self.backend.find_head(
    self.checkpoints.time.slotOrZero(dag.timeParams),
    self.checkpoints, self.checkpoints.proposer_boost_root)

proc advance_fcr(
    self: var ForkChoice, dag: ChainDAGRef, blckRef: BlockRef,
    confirmed: var BlockId, current_slot: Slot,
    reason: var string): FcResult[void] =
  template fcr: ForkChoiceBackend = self.backend

  if ? fcr.should_revert_confirmed_on_new_head(
      blckRef, confirmed, current_slot):
    reason = "head"
    confirmed = fcr.to_block_id(self.checkpoints.finalized)
    incSafeHeadReverts()

  if ? fcr.should_restart_confirmation_chain(confirmed, current_slot):
    reason = "restart/h"
    confirmed = fcr.observed_justified_block_id
    incSafeRestarts()

  # Attempt to further advance the latest confirmed block.
  if confirmed.slot.epoch + 1 >= current_slot.epoch:
    template justified: Checkpoint = self.checkpoints.justified.checkpoint
    let unrealized = fcr.proto_array.unrealized_justified(justified)
    confirmed = ? fcr.find_latest_confirmed_descendant(
      dag, blckRef, unrealized, confirmed, current_slot)
  ok()

proc will_select_head*(
    self: var ForkChoice, dag: ChainDAGRef,
    blckRef: BlockRef, wallTime: BeaconTime): FcResult[void] =
  ? self.update_time(dag, wallTime)
  let
    current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)
    consensusFork = dag.cfg.consensusForkAtEpoch(current_slot.epoch)
    threshold = current_slot.attestation_deadline(dag.timeParams, consensusFork)
  if self.checkpoints.time < threshold:
    self.backend.current_slot_head = blckRef.root

  var
    confirmed = self.backend.confirmed
    reason: string
  self.advance_fcr(dag, blckRef, confirmed, current_slot, reason).isOkOr:
    warn "Failed to advance 'safe' block - report bug",
      blckRef, current_slot, reason = error
    reason = "advance"
    confirmed = self.backend.to_block_id(self.checkpoints.finalized)
    incSafeErrors()
  self.backend.update_confirmed(dag, confirmed, current_slot, reason)
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/fork_choice/safe-block.md#get_safe_execution_block_hash
func retrieve_fast_confirmed_bid*(self: ForkChoice): lent BlockId =
  self.backend.confirmed

func retrieve_fast_confirmed_root*(self: ForkChoice): lent Eth2Digest =
  self.retrieve_fast_confirmed_bid.root

proc prune(
    self: var ForkChoiceBackend, dag: ChainDAGRef,
    checkpoints: FinalityCheckpoints, current_slot: Slot): FcResult[void] =
  ## Prune blocks preceding the finalized root as they are now unneeded.
  ? self.proto_array.prune(checkpoints)
  if self.previous_slot_head notin self.proto_array:
    self.previous_slot_head = checkpoints.finalized.root
  if self.current_slot_head notin self.proto_array:
    self.current_slot_head = checkpoints.finalized.root
  if self.confirmed.root notin self.proto_array:
    template confirmed: BlockId = self.to_block_id(checkpoints.finalized)
    self.update_confirmed(dag, confirmed, current_slot, "prune")

  # Drop per-block fork-choice state for blocks no longer in the proto-array.
  var staleRoots: seq[Eth2Digest]
  for root in self.ptc_votes.keys:
    if root notin self.proto_array.indices:
      staleRoots.add root
  for root in staleRoots:
    self.ptc_votes.del root

  staleRoots.setLen(0)
  for root in self.timely_proposer_blocks:
    if root notin self.proto_array.indices:
      staleRoots.add root
  for root in staleRoots:
    self.timely_proposer_blocks.excl root

  ok()

proc prune*(self: var ForkChoice, dag: ChainDAGRef): FcResult[void] =
  let current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)
  self.backend.prune(dag, FinalityCheckpoints(
    justified: self.checkpoints.justified.checkpoint,
    finalized: self.checkpoints.finalized), current_slot)

func mark_root_invalid*(self: var ForkChoice, root: Eth2Digest) =
  try:
    let nodePhysicalIdx =
      self.backend.proto_array.indices[root] -
        self.backend.proto_array.nodes.offset
    if nodePhysicalIdx < self.backend.proto_array.nodes.buf.len:
      self.backend.proto_array.nodes.buf[nodePhysicalIdx].invalid = true
    self.backend.proto_array.propagateInvalidity(nodePhysicalIdx)
  # Best-effort; attempts to mark unknown roots invalid harmlessly ignored
  except KeyError:
    discard

func compute_deltas(
    deltas: var openArray[Delta],
    indices: Table[Eth2Digest, Index],
    fullBlockIndices: Table[Eth2Digest, Index],
    indices_offset: Index,
    votes: var openArray[VoteTracker],
    old_balances: openArray[ForkChoiceBalance],
    new_balances: openArray[ForkChoiceBalance]): FcResult[void] =
  ## Update `deltas`
  ##   between old and new balances
  ##   between votes
  ##
  ## `deltas.len` must match `indices.len` (length match)
  ##
  ## Error:
  ## - If a value in indices is greater than `indices.len`
  ## - If a `Eth2Digest` in `votes` does not exist in `indices`
  ##   except for the `ZERO_HASH`

  for val_index, vote in votes.mpairs():
    # No need to create a score change if the validator has never voted
    # or if votes are for the zero hash (alias to the genesis block)
    if vote.current_root.isZero and vote.next_root.isZero:
      continue

    # If the validator was not included in `old_balances` (i.e. did not exist)
    # its balance is zero
    let old_balance =
      if val_index < old_balances.len:
        old_balances[val_index].unslashed_balance
      else:
        0.Gwei

    # If the validator is not known in the `new_balances` then
    # use balance of zero
    #
    # It is possible that there is a vote for an unknown validator if we change
    # our justified state to a new state with a higher epoch on a different fork
    # as that fork may have on-boarded less validators than the previous fork.
    #
    # Note that attesters are the same as they are activated only under finality
    let new_balance =
      if val_index < new_balances.len:
        new_balances[val_index].unslashed_balance
      else:
        0.Gwei

    if  vote.current_root != vote.next_root or old_balance != new_balance or
        vote.payload_present != vote.next_payload_present:
      template resolveIndex(root: Eth2Digest, payloadPresent: bool): int =
        if payloadPresent and root in fullBlockIndices:
          fullBlockIndices.unsafeGet(root) - indices_offset
        else:
          indices.unsafeGet(root) - indices_offset
      # Ignore the current or next vote if it is not known in `indices`.
      # We assume that it is outside of our tree (i.e., pre-finalization)
      # and therefore not interesting.
      if vote.current_root in indices:
        let index = resolveIndex(vote.current_root, vote.payload_present)
        if index >= deltas.len:
          return err ForkChoiceError(
            kind: fcInvalidNodeDelta,
            index: index)
        deltas[index] -= Delta old_balance
          # Note that delta can be negative
          # TODO: is int64 big enough?

      if vote.slot != FAR_FUTURE_SLOT and not vote.next_root.isZero:
        if vote.next_root in indices:
          let index = resolveIndex(vote.next_root, vote.next_payload_present)
          if index >= deltas.len:
            return err ForkChoiceError(
              kind: fcInvalidNodeDelta,
              index: index)
          deltas[index] += Delta new_balance
            # Note that delta can be negative
            # TODO: is int64 big enough?

      vote.current_root = vote.next_root
      vote.payload_present = vote.next_payload_present
  return ok()

# Sanity checks
# ----------------------------------------------------------------------
# Sanity checks on internal private procedures

when isMainModule:
  import stew/endians2

  func fakeHash(index: SomeInteger): Eth2Digest =
    ## Create fake hashes
    ## Those are just the value serialized in big-endian
    ## We add 16x16 to avoid having a zero hash are those are special cased
    ## We store them in the first 8 bytes
    ## as those are the one used in hash tables Table[Eth2Digest, T]
    result.data[0 ..< 8] = (16*16+index).uint64.toBytesBE()

  proc tZeroHash() =
    echo "    fork_choice compute_deltas - test zero votes"

    const validator_count = 16
    var
      deltas = newSeqUninit[Delta](validator_count)

      indices: Table[Eth2Digest, Index]
      fullBlockIndices: Table[Eth2Digest, Index]
      votes: seq[VoteTracker]
      old_balances: seq[ForkChoiceBalance]
      new_balances: seq[ForkChoiceBalance]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add default(VoteTracker)
      old_balances.add 0.ForkChoiceBalance
      new_balances.add 0.ForkChoiceBalance

    let err = deltas.compute_deltas(
      indices, fullBlockIndices, indices_offset = 0,
      votes, old_balances, new_balances)

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas == newSeq[Delta](validator_count), "deltas should be zeros"

    for vote in votes:
      doAssert vote.current_root == vote.next_root,
        "The vote should have been updated"

  proc tAll_voted_the_same() =
    echo "    fork_choice compute_deltas - test all same votes"

    const
      Balance = ForkChoiceBalance(42)
      validator_count = 16
    var
      deltas = newSeqUninit[Delta](validator_count)

      indices: Table[Eth2Digest, Index]
      fullBlockIndices: Table[Eth2Digest, Index]
      votes: seq[VoteTracker]
      old_balances: seq[ForkChoiceBalance]
      new_balances: seq[ForkChoiceBalance]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add VoteTracker(
        current_root: ZERO_HASH,
        next_root: fakeHash(0), # Get a non-zero hash
        slot: Slot(0))
      old_balances.add Balance
      new_balances.add Balance

    let err = deltas.compute_deltas(
      indices, fullBlockIndices, indices_offset = 0,
      votes, old_balances, new_balances)

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      if i == 0:
        doAssert delta == Delta(Balance.unslashed_balance * validator_count),
          "The 0th root should have a delta"
      else:
        doAssert delta == 0,
          "The non-0 indexes should have a zero delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root,
        "The vote should have been updated"

  proc tDifferent_votes() =
    echo "    fork_choice compute_deltas - test all different votes"

    const
      Balance = ForkChoiceBalance(42)
      validator_count = 16
    var
      deltas = newSeqUninit[Delta](validator_count)

      indices: Table[Eth2Digest, Index]
      fullBlockIndices: Table[Eth2Digest, Index]
      votes: seq[VoteTracker]
      old_balances: seq[ForkChoiceBalance]
      new_balances: seq[ForkChoiceBalance]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add VoteTracker(
        current_root: ZERO_HASH,
        next_root: fakeHash(i), # Each vote for a different root
        slot: Slot(0))
      old_balances.add Balance
      new_balances.add Balance

    let err = deltas.compute_deltas(
      indices, fullBlockIndices, indices_offset = 0,
      votes, old_balances, new_balances)

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      doAssert delta == Delta(Balance.unslashed_balance),
        "Each root should have a delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root,
        "The vote should have been updated"

  proc tMoving_votes() =
    echo "    fork_choice compute_deltas - test moving votes"

    const
      Balance = ForkChoiceBalance(42)
      validator_count = 16
      TotalDeltas = Delta(Balance.unslashed_balance * validator_count)
    var
      deltas = newSeqUninit[Delta](validator_count)

      indices: Table[Eth2Digest, Index]
      fullBlockIndices: Table[Eth2Digest, Index]
      votes: seq[VoteTracker]
      old_balances: seq[ForkChoiceBalance]
      new_balances: seq[ForkChoiceBalance]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add VoteTracker(
        # Move vote from root 0 to root 1
        current_root: fakeHash(0),
        next_root: fakeHash(1),
        slot: Slot(0))
      old_balances.add Balance
      new_balances.add Balance

    let err = deltas.compute_deltas(
      indices, fullBlockIndices, indices_offset = 0,
      votes, old_balances, new_balances)

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      if i == 0:
        doAssert delta == -TotalDeltas, "0th root should have a negative delta"
      elif i == 1:
        doAssert delta == TotalDeltas, "1st root should have a positive delta"
      else:
        doAssert delta == 0,
          "The non-0 and non-1 indexes should have a zero delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root,
        "The vote should have been updated"

  proc tMove_out_of_tree() =
    echo "    fork_choice compute_deltas - test votes for unknown subtree"

    const Balance = ForkChoiceBalance(42)

    var
      indices: Table[Eth2Digest, Index]
      fullBlockIndices: Table[Eth2Digest, Index]
      votes: seq[VoteTracker]

    # Add a block
    indices[fakeHash(1)] = 0

    # 2 validators
    var deltas = newSeqUninit[Delta](2)
    let
      old_balances = @[Balance, Balance]
      new_balances = @[Balance, Balance]

    # One validator moves their vote from the block to the zero hash
    votes.add VoteTracker(
      current_root: fakeHash(1),
      next_root: ZERO_HASH,
      slot: Slot(0))

    # One validator moves their vote from the block to
    # something outside of the tree
    votes.add VoteTracker(
      current_root: fakeHash(1),
      next_root: fakeHash(1337),
      slot: Slot(0))

    let err = deltas.compute_deltas(
      indices, fullBlockIndices, indices_offset = 0,
      votes, old_balances, new_balances)

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance.unslashed_balance) * 2,
      "The 0th block should have lost both balances."

    for vote in votes:
      doAssert vote.current_root == vote.next_root,
        "The vote should have been updated"

  proc tChanging_balances() =
    echo "    fork_choice compute_deltas - test changing balances"

    const
      OldBalance = ForkChoiceBalance(42)
      NewBalance = ForkChoiceBalance(OldBalance.unslashed_balance * 2)
      validator_count = 16
      TotalOldDeltas = Delta(OldBalance.unslashed_balance * validator_count)
      TotalNewDeltas = Delta(NewBalance.unslashed_balance * validator_count)
    var
      deltas = newSeqUninit[Delta](validator_count)

      indices: Table[Eth2Digest, Index]
      fullBlockIndices: Table[Eth2Digest, Index]
      votes: seq[VoteTracker]
      old_balances: seq[ForkChoiceBalance]
      new_balances: seq[ForkChoiceBalance]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add VoteTracker(
        # Move vote from root 0 to root 1
        current_root: fakeHash(0),
        next_root: fakeHash(1),
        slot: Slot(0))
      old_balances.add OldBalance
      new_balances.add NewBalance

    let err = deltas.compute_deltas(
      indices, fullBlockIndices, indices_offset = 0,
      votes, old_balances, new_balances)

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      if i == 0:
        doAssert delta == -TotalOldDeltas,
          "0th root should have a negative delta"
      elif i == 1:
        doAssert delta == TotalNewDeltas,
          "1st root should have a positive delta"
      else:
        doAssert delta == 0,
          "The non-0 and non-1 indexes should have a zero delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root,
        "The vote should have been updated"

  proc tValidator_appears() =
    echo "    fork_choice compute_deltas - test validator appears"

    const Balance = ForkChoiceBalance(42)

    var
      indices: Table[Eth2Digest, Index]
      fullBlockIndices: Table[Eth2Digest, Index]
      votes: seq[VoteTracker]

    # Add 2 blocks
    indices[fakeHash(1)] = 0
    indices[fakeHash(2)] = 1

    # 1 validator at the start, 2 at the end
    var deltas = newSeqUninit[Delta](2)
    let
      old_balances = @[Balance]
      new_balances = @[Balance, Balance]

    # Both moves vote from Block 1 to 2
    for _ in 0 ..< 2:
      votes.add VoteTracker(
        current_root: fakeHash(1),
        next_root: fakeHash(2),
        slot: Slot(0))

    let err = deltas.compute_deltas(
      indices, fullBlockIndices, indices_offset = 0,
      votes, old_balances, new_balances)

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance.unslashed_balance),
      "Block 1 should have lost only 1 balance"
    doAssert deltas[1] == Delta(Balance.unslashed_balance) * 2,
      "Block 2 should have gained 2 balances"

    for vote in votes:
      doAssert vote.current_root == vote.next_root,
        "The vote should have been updated"

  proc tValidator_disappears() =
    echo "    fork_choice compute_deltas - test validator disappears"

    const Balance = ForkChoiceBalance(42)

    var
      indices: Table[Eth2Digest, Index]
      fullBlockIndices: Table[Eth2Digest, Index]
      votes: seq[VoteTracker]

    # Add 2 blocks
    indices[fakeHash(1)] = 0
    indices[fakeHash(2)] = 1

    # 2 validator at the start, 1 at the end
    var deltas = newSeqUninit[Delta](2)
    let
      old_balances = @[Balance, Balance]
      new_balances = @[Balance]

    # Both moves vote from Block 1 to 2
    for _ in 0 ..< 2:
      votes.add VoteTracker(
        current_root: fakeHash(1),
        next_root: fakeHash(2),
        slot: Slot(0))

    let err = deltas.compute_deltas(
      indices, fullBlockIndices, indices_offset = 0,
      votes, old_balances, new_balances)

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance.unslashed_balance) * 2,
      "Block 1 should have lost 2 balances"
    doAssert deltas[1] == Delta(Balance.unslashed_balance),
      "Block 2 should have gained 1 balance"

    for vote in votes:
      doAssert vote.current_root == vote.next_root,
        "The vote should have been updated"

  # ----------------------------------------------------------------------

  echo "fork_choice internal tests for compute_deltas"
  tZeroHash()
  tAll_voted_the_same()
  tDifferent_votes()
  tMoving_votes()
  tChanging_balances()
  tValidator_appears()
  tValidator_disappears()
