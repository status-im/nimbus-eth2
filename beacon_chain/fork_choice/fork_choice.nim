# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Standard library
  std/[sequtils, tables],
  # Status libraries
  stew/[results], chronicles,
  # Internal
  ../spec/[beaconstate, helpers, state_transition_block],
  ../spec/datatypes/[phase0, altair, bellatrix],
  # Fork choice
  ./fork_choice_types, ./proto_array,
  ../consensus_object_pools/[spec_cache, blockchain_dag]

export results, fork_choice_types
export proto_array.len

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md
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
       indices_offset: Index,
       votes: var openArray[VoteTracker],
       old_balances: openArray[Gwei],
       new_balances: openArray[Gwei]
     ): FcResult[void]
# Fork choice routines
# ----------------------------------------------------------------------

logScope: topics = "fork_choice"

func init*(
    T: type ForkChoiceBackend, checkpoints: FinalityCheckpoints,
    version: ForkChoiceVersion): T =
  T(proto_array: ProtoArray.init(checkpoints, version))

proc init*(
    T: type ForkChoice, epochRef: EpochRef, blck: BlockRef,
    version: ForkChoiceVersion): T =
  ## Initialize a fork choice context for a finalized state - in the finalized
  ## state, the justified and finalized checkpoints are the same, so only one
  ## is used here
  debug "Initializing fork choice",
    epoch = epochRef.epoch, blck = shortLog(blck)

  let checkpoint = Checkpoint(root: blck.root, epoch: epochRef.epoch)
  ForkChoice(
    backend: ForkChoiceBackend.init(
      FinalityCheckpoints(
        justified: checkpoint,
        finalized: checkpoint),
      version),
    checkpoints: Checkpoints(
      version: version,
      justified: BalanceCheckpoint(
        checkpoint: checkpoint,
        total_active_balance: epochRef.total_active_balance,
        balances: epochRef.effective_balances),
      finalized: checkpoint,
      best_justified: checkpoint))

func extend[T](s: var seq[T], minLen: int) =
  ## Extend a sequence so that it can contains at least `minLen` elements.
  ## If it's already bigger, the sequence is unmodified.
  ## The extension is zero-initialized
  if s.len < minLen:
    s.setLen(minLen)

proc update_justified(
    self: var Checkpoints, dag: ChainDAGRef, blck: BlockRef, epoch: Epoch) =
  let
    epochRef = dag.getEpochRef(blck, epoch, false).valueOr:
      # Shouldn't happen for justified data unless out of sync with ChainDAG
      warn "Skipping justified checkpoint update, no EpochRef - report bug",
        blck, epoch, error
      return
    justified = Checkpoint(root: blck.root, epoch: epochRef.epoch)

  trace "Updating justified",
    store = self.justified.checkpoint, state = justified
  self.justified = BalanceCheckpoint(
    checkpoint: Checkpoint(root: blck.root, epoch: epochRef.epoch),
    total_active_balance: epochRef.total_active_balance,
    balances: epochRef.effective_balances)

proc update_justified(
    self: var Checkpoints, dag: ChainDAGRef,
    justified: Checkpoint): FcResult[void] =
  let blck = dag.getBlockRef(justified.root).valueOr:
    return err ForkChoiceError(
      kind: fcJustifiedNodeUnknown,
      blockRoot: justified.root)

  self.update_justified(dag, blck, justified.epoch)
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/fork-choice.md#update_checkpoints
proc update_checkpoints(
    self: var Checkpoints, dag: ChainDAGRef,
    checkpoints: FinalityCheckpoints): FcResult[void] =
  ## Update checkpoints in store if necessary
  # Update justified checkpoint
  if checkpoints.justified.epoch > self.justified.checkpoint.epoch:
    ? self.update_justified(dag, checkpoints.justified)

  # Update finalized checkpoint
  if checkpoints.finalized.epoch > self.finalized.epoch:
    trace "Updating finalized",
      store = self.finalized, state = checkpoints.finalized
    self.finalized = checkpoints.finalized

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/phase0/fork-choice.md#on_tick_per_slot
proc on_tick(
    self: var ForkChoice, dag: ChainDAGRef, time: BeaconTime): FcResult[void] =
  ## Must be called at least once per slot.
  let previous_time = self.checkpoints.time

  # Update store time
  if time < previous_time:
    return err ForkChoiceError(kind: fcInconsistentTick)
  self.checkpoints.time = time

  let
    current_slot = time.slotOrZero
    previous_slot = previous_time.slotOrZero

  # If this is a new slot, reset store.proposer_boost_root
  if current_slot > previous_slot:
    self.checkpoints.proposer_boost_root = ZERO_HASH

  # If a new epoch, pull-up justification and finalization from previous epoch
  if current_slot > previous_slot and current_slot.is_epoch:
    for realized in self.backend.proto_array.realizePendingCheckpoints():
      ? self.checkpoints.update_checkpoints(dag, realized)

  ok()

func process_attestation(
       self: var ForkChoiceBackend,
       validator_index: ValidatorIndex,
       block_root: Eth2Digest,
       target_epoch: Epoch
     ) =
  ## Add an attestation to the fork choice context
  self.votes.extend(validator_index.int + 1)

  template vote: untyped = self.votes[validator_index]
  if target_epoch > vote.next_epoch or vote.next_root.isZero:
    vote.next_root = block_root
    vote.next_epoch = target_epoch

    trace "Integrating vote in fork choice",
      validator_index = validator_index,
      new_vote = shortLog(vote)

proc process_attestation_queue(self: var ForkChoice, slot: Slot) =
  # Spec:
  # Attestations can only affect the fork choice of subsequent slots.
  # Delay consideration in the fork choice until their slot is in the past.
  let startTick = Moment.now()
  self.queuedAttestations.keepItIf:
    if it.slot < slot:
      for validator_index in it.attesting_indices:
        self.backend.process_attestation(
          validator_index, it.block_root, it.slot.epoch())
      false
    else:
      true
  let endTick = Moment.now()
  debug "Processed attestation queue", processDur = endTick - startTick

func contains*(self: ForkChoiceBackend, block_root: Eth2Digest): bool =
  ## Returns `true` if a block is known to the fork choice
  ## and `false` otherwise.
  ##
  ## In particular, before adding a block, its parent must be known to the fork choice
  self.proto_array.indices.contains(block_root)

proc update_time*(self: var ForkChoice, dag: ChainDAGRef, time: BeaconTime):
    FcResult[void] =
  # `time` is the wall time, meaning it changes on every call typically
  const step_size = seconds(SECONDS_PER_SLOT.int)
  if time > self.checkpoints.time:
    let
      preSlot = self.checkpoints.time.slotOrZero()
      postSlot = time.slotOrZero()
    # Call on_tick at least once per slot.
    while time >= self.checkpoints.time + step_size:
      ? self.on_tick(dag, self.checkpoints.time + step_size)

    if time > self.checkpoints.time:
      # Might create two ticks for the last slot.
      ? self.on_tick(dag, time)

    if preSlot != postSlot:
      self.process_attestation_queue(postSlot)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/fork-choice.md#on_attestation
proc on_attestation*(
       self: var ForkChoice,
       dag: ChainDAGRef,
       attestation_slot: Slot,
       beacon_block_root: Eth2Digest,
       attesting_indices: openArray[ValidatorIndex],
       wallTime: BeaconTime
     ): FcResult[void] =
  ? self.update_time(dag, max(wallTime, attestation_slot.start_beacon_time))

  if attestation_slot < self.checkpoints.time.slotOrZero:
    for validator_index in attesting_indices:
      # attestation_slot and target epoch must match, per attestation rules
      self.backend.process_attestation(
        validator_index, beacon_block_root, attestation_slot.epoch)
  else:
    # Spec:
    # Attestations can only affect the fork choice of subsequent slots.
    # Delay consideration in the fork choice until their slot is in the past.
    self.queuedAttestations.add(QueuedAttestation(
      slot: attestation_slot,
      attesting_indices: @attesting_indices,
      block_root: beacon_block_root))
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/phase0/fork-choice.md#on_attester_slashing
func process_equivocation*(
       self: var ForkChoice,
       validator_index: ValidatorIndex
     ) =
  self.backend.votes.extend(validator_index.int + 1)

  # Disallow future votes
  template vote: untyped = self.backend.votes[validator_index]
  if vote.next_epoch != FAR_FUTURE_EPOCH or not vote.next_root.isZero:
    vote.next_epoch = FAR_FUTURE_EPOCH
    vote.next_root.reset()

    trace "Integrating equivocation in fork choice",
      validator_index

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#on_block
func process_block*(self: var ForkChoiceBackend,
                    bid: BlockId,
                    parent_root: Eth2Digest,
                    checkpoints: FinalityCheckpoints,
                    unrealized = none(FinalityCheckpoints)): FcResult[void] =
  self.proto_array.onBlock(bid, parent_root, checkpoints, unrealized)

proc process_block*(self: var ForkChoice,
                    dag: ChainDAGRef,
                    epochRef: EpochRef,
                    blckRef: BlockRef,
                    unrealized: FinalityCheckpoints,
                    blck: ForkyTrustedBeaconBlock,
                    wallTime: BeaconTime): FcResult[void] =
  ? update_time(self, dag, max(wallTime, blckRef.slot.start_beacon_time))

  for attester_slashing in blck.body.attester_slashings:
    for idx in getValidatorIndices(attester_slashing):
      let i = ValidatorIndex.init(idx).valueOr:
        continue
      self.process_equivocation(i)

  for attestation in blck.body.attestations:
    if attestation.data.beacon_block_root in self.backend:
      for validator_index in dag.get_attesting_indices(attestation):
        self.backend.process_attestation(
          validator_index,
          attestation.data.beacon_block_root,
          attestation.data.target.epoch)

  trace "Integrating block in fork choice",
    block_root = shortLog(blckRef)

  # Add proposer score boost if the block is timely
  let slot = self.checkpoints.time.slotOrZero
  if slot == blck.slot and
      self.checkpoints.time < slot.attestation_deadline and
      self.checkpoints.proposer_boost_root == ZERO_HASH:
    self.checkpoints.proposer_boost_root = blckRef.root

  # Update checkpoints in store if necessary
  ? update_checkpoints(self.checkpoints, dag, epochRef.checkpoints)

  # If block is from a prior epoch, pull up the post-state to next epoch to
  # realize new finality info
  let unrealized_is_better =
    unrealized.justified.epoch > epochRef.checkpoints.justified.epoch or
    unrealized.finalized.epoch > epochRef.checkpoints.finalized.epoch
  if unrealized_is_better:
    if epochRef.epoch < slot.epoch:
      trace "Pulling up chain tip",
        blck = shortLog(blckRef), checkpoints = epochRef.checkpoints, unrealized
      ? update_checkpoints(self.checkpoints, dag, unrealized)
      ? process_block(
        self.backend, blckRef.bid, blck.parent_root, unrealized)
    else:
      ? process_block(
        self.backend, blckRef.bid, blck.parent_root,
        epochRef.checkpoints, some unrealized)  # Realized in `on_tick`
  else:
    ? process_block(
      self.backend, blckRef.bid, blck.parent_root, epochRef.checkpoints)

  ok()

func find_head(
       self: var ForkChoiceBackend,
       current_epoch: Epoch,
       checkpoints: FinalityCheckpoints,
       justified_total_active_balance: Gwei,
       justified_state_balances: seq[Gwei],
       proposer_boost_root: Eth2Digest
     ): FcResult[Eth2Digest] =
  ## Returns the new blockchain head

  # Compute deltas with previous call
  #   we might want to reuse the `deltas` buffer across calls
  var deltas = newSeq[Delta](self.proto_array.indices.len)
  ? deltas.compute_deltas(
    indices = self.proto_array.indices,
    indices_offset = self.proto_array.nodes.offset,
    votes = self.votes,
    old_balances = self.balances,
    new_balances = justified_state_balances)

  # Apply score changes
  ? self.proto_array.applyScoreChanges(
    deltas, current_epoch, checkpoints,
    justified_total_active_balance, proposer_boost_root)

  self.balances = justified_state_balances

  # Find the best block
  var new_head{.noinit.}: Eth2Digest
  ? self.proto_array.findHead(new_head, checkpoints.justified.root)

  trace "Fork choice requested",
    checkpoints, fork_choice_head = shortLog(new_head)

  return ok(new_head)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/phase0/fork-choice.md#get_head
proc get_head*(self: var ForkChoice,
               dag: ChainDAGRef,
               wallTime: BeaconTime): FcResult[Eth2Digest] =
  ? self.update_time(dag, wallTime)

  self.backend.find_head(
    self.checkpoints.time.slotOrZero.epoch,
    FinalityCheckpoints(
      justified: self.checkpoints.justified.checkpoint,
      finalized: self.checkpoints.finalized),
    self.checkpoints.justified.total_active_balance,
    self.checkpoints.justified.balances,
    self.checkpoints.proposer_boost_root)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/fork_choice/safe-block.md#get_safe_beacon_block_root
func get_safe_beacon_block_root*(self: ForkChoice): Eth2Digest =
  # Use most recent justified block as a stopgap
  self.checkpoints.justified.checkpoint.root

func prune*(
       self: var ForkChoiceBackend, checkpoints: FinalityCheckpoints
     ): FcResult[void] =
  ## Prune blocks preceding the finalized root as they are now unneeded.
  self.proto_array.prune(checkpoints)

func prune*(self: var ForkChoice): FcResult[void] =
  self.backend.prune(
    FinalityCheckpoints(
      justified: self.checkpoints.justified.checkpoint,
      finalized: self.checkpoints.finalized))

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
       indices_offset: Index,
       votes: var openArray[VoteTracker],
       old_balances: openArray[Gwei],
       new_balances: openArray[Gwei]
     ): FcResult[void] =
  ## Update `deltas`
  ##   between old and new balances
  ##   between votes
  ##
  ## `deltas.len` must match `indices.len` (length match)
  ##
  ## Error:
  ## - If a value in indices is greater than `indices.len`
  ## - If a `Eth2Digest` in `votes` does not exist in `indices`
  ##   except for the `default(Eth2Digest)` (i.e. zero hash)

  for val_index, vote in votes.mpairs():
    # No need to create a score change if the validator has never voted
    # or if votes are for the zero hash (alias to the genesis block)
    if vote.current_root.isZero and vote.next_root.isZero:
      continue

    # If the validator was not included in `old_balances` (i.e. did not exist)
    # its balance is zero
    let old_balance = if val_index < old_balances.len: old_balances[val_index]
                      else: 0

    # If the validator is not known in the `new_balances` then use balance of zero
    #
    # It is possible that there is a vote for an unknown validator if we change our
    # justified state to a new state with a higher epoch on a different fork
    # because that fork may have on-boarded less validators than the previous fork.
    #
    # Note that attesters are not different as they are activated only under finality
    let new_balance = if val_index < new_balances.len: new_balances[val_index]
                      else: 0

    if vote.current_root != vote.next_root or old_balance != new_balance:
      # Ignore the current or next vote if it is not known in `indices`.
      # We assume that it is outside of our tree (i.e., pre-finalization) and therefore not interesting.
      if vote.current_root in indices:
        let index = indices.unsafeGet(vote.current_root) - indices_offset
        if index >= deltas.len:
          return err ForkChoiceError(
            kind: fcInvalidNodeDelta,
            index: index)
        deltas[index] -= Delta old_balance
          # Note that delta can be negative
          # TODO: is int64 big enough?

      if vote.next_epoch != FAR_FUTURE_EPOCH or not vote.next_root.isZero:
        if vote.next_root in indices:
          let index = indices.unsafeGet(vote.next_root) - indices_offset
          if index >= deltas.len:
            return err ForkChoiceError(
              kind: fcInvalidNodeDelta,
              index: index)
          deltas[index] += Delta new_balance
            # Note that delta can be negative
            # TODO: is int64 big enough?

      vote.current_root = vote.next_root
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
    var deltas = newSeqUninitialized[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices.add fakeHash(i), i
      votes.add default(VoteTracker)
      old_balances.add 0
      new_balances.add 0

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas == newSeq[Delta](validator_count), "deltas should be zeros"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tAll_voted_the_same() =
    echo "    fork_choice compute_deltas - test all same votes"

    const
      Balance = Gwei(42)
      validator_count = 16
    var deltas = newSeqUninitialized[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices.add fakeHash(i), i
      votes.add VoteTracker(
        current_root: default(Eth2Digest),
        next_root: fakeHash(0), # Get a non-zero hash
        next_epoch: Epoch(0)
      )
      old_balances.add Balance
      new_balances.add Balance

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      if i == 0:
        doAssert delta == Delta(Balance * validator_count), "The 0th root should have a delta"
      else:
        doAssert delta == 0, "The non-0 indexes should have a zero delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tDifferent_votes() =
    echo "    fork_choice compute_deltas - test all different votes"

    const
      Balance = Gwei(42)
      validator_count = 16
    var deltas = newSeqUninitialized[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices.add fakeHash(i), i
      votes.add VoteTracker(
        current_root: default(Eth2Digest),
        next_root: fakeHash(i), # Each vote for a different root
        next_epoch: Epoch(0)
      )
      old_balances.add Balance
      new_balances.add Balance

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      doAssert delta == Delta(Balance), "Each root should have a delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tMoving_votes() =
    echo "    fork_choice compute_deltas - test moving votes"

    const
      Balance = Gwei(42)
      validator_count = 16
      TotalDeltas = Delta(Balance * validator_count)
    var deltas = newSeqUninitialized[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices.add fakeHash(i), i
      votes.add VoteTracker(
        # Move vote from root 0 to root 1
        current_root: fakeHash(0),
        next_root: fakeHash(1),
        next_epoch: Epoch(0)
      )
      old_balances.add Balance
      new_balances.add Balance

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      if i == 0:
        doAssert delta == -TotalDeltas, "0th root should have a negative delta"
      elif i == 1:
        doAssert delta == TotalDeltas, "1st root should have a positive delta"
      else:
        doAssert delta == 0, "The non-0 and non-1 indexes should have a zero delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tMove_out_of_tree() =
    echo "    fork_choice compute_deltas - test votes for unknown subtree"

    const Balance = Gwei(42)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]

    # Add a block
    indices.add fakeHash(1), 0

    # 2 validators
    var deltas = newSeqUninitialized[Delta](2)
    let old_balances = @[Balance, Balance]
    let new_balances = @[Balance, Balance]

    # One validator moves their vote from the block to the zero hash
    votes.add VoteTracker(
      current_root: fakeHash(1),
      next_root: default(Eth2Digest),
      next_epoch: Epoch(0)
    )

    # One validator moves their vote from the block to something outside of the tree
    votes.add VoteTracker(
      current_root: fakeHash(1),
      next_root: fakeHash(1337),
      next_epoch: Epoch(0)
    )

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance)*2, "The 0th block should have lost both balances."

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tChanging_balances() =
    echo "    fork_choice compute_deltas - test changing balances"

    const
      OldBalance = Gwei(42)
      NewBalance = OldBalance * 2
      validator_count = 16
      TotalOldDeltas = Delta(OldBalance * validator_count)
      TotalNewDeltas = Delta(NewBalance * validator_count)
    var deltas = newSeqUninitialized[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices.add fakeHash(i), i
      votes.add VoteTracker(
        # Move vote from root 0 to root 1
        current_root: fakeHash(0),
        next_root: fakeHash(1),
        next_epoch: Epoch(0)
      )
      old_balances.add OldBalance
      new_balances.add NewBalance

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      if i == 0:
        doAssert delta == -TotalOldDeltas, "0th root should have a negative delta"
      elif i == 1:
        doAssert delta == TotalNewDeltas, "1st root should have a positive delta"
      else:
        doAssert delta == 0, "The non-0 and non-1 indexes should have a zero delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tValidator_appears() =
    echo "    fork_choice compute_deltas - test validator appears"

    const Balance = Gwei(42)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]

    # Add 2 blocks
    indices.add fakeHash(1), 0
    indices.add fakeHash(2), 1

    # 1 validator at the start, 2 at the end
    var deltas = newSeqUninitialized[Delta](2)
    let old_balances = @[Balance]
    let new_balances = @[Balance, Balance]

    # Both moves vote from Block 1 to 2
    for _ in 0 ..< 2:
      votes.add VoteTracker(
        current_root: fakeHash(1),
        next_root: fakeHash(2),
        next_epoch: Epoch(0)
      )


    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance), "Block 1 should have lost only 1 balance"
    doAssert deltas[1] == Delta(Balance)*2, "Block 2 should have gained 2 balances"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tValidator_disappears() =
    echo "    fork_choice compute_deltas - test validator disappears"

    const Balance = Gwei(42)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]

    # Add 2 blocks
    indices.add fakeHash(1), 0
    indices.add fakeHash(2), 1

    # 1 validator at the start, 2 at the end
    var deltas = newSeqUninitialized[Delta](2)
    let old_balances = @[Balance, Balance]
    let new_balances = @[Balance]

    # Both moves vote from Block 1 to 2
    for _ in 0 ..< 2:
      votes.add VoteTracker(
        current_root: fakeHash(1),
        next_root: fakeHash(2),
        next_epoch: Epoch(0)
      )


    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance)*2, "Block 1 should have lost 2 balances"
    doAssert deltas[1] == Delta(Balance), "Block 2 should have gained 1 balance"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  # ----------------------------------------------------------------------

  echo "fork_choice internal tests for compute_deltas"
  tZeroHash()
  tAll_voted_the_same()
  tDifferent_votes()
  tMoving_votes()
  tChanging_balances()
  tValidator_appears()
  tValidator_disappears()
