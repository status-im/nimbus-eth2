# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/[sequtils, sets, tables, typetraits],
  # Status libraries
  stew/results, chronicles,
  # Internal
  ../spec/[beaconstate, datatypes, digest, helpers],
  # Fork choice
  ./fork_choice_types, ./proto_array,
  ../block_pools/[spec_cache, chain_dag]

export sets, results, fork_choice_types
export proto_array.len

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md
# This is a port of https://github.com/sigp/lighthouse/pull/804
# which is a port of "Proto-Array": https://github.com/protolambda/lmd-ghost
# See also:
# - Protolambda port of Lighthouse: https://github.com/protolambda/eth2-py-hacks/blob/ae286567/proto_array.py
# - Prysmatic writeup: https://hackmd.io/bABJiht3Q9SyV3Ga4FT9lQ#High-level-concept
# - Gasper Whitepaper: https://arxiv.org/abs/2003.03052

# Forward declarations
# ----------------------------------------------------------------------

func compute_deltas(
       deltas: var openarray[Delta],
       indices: Table[Eth2Digest, Index],
       indices_offset: Index,
       votes: var openArray[VoteTracker],
       old_balances: openarray[Gwei],
       new_balances: openarray[Gwei]
     ): FcResult[void]
# TODO: raises [Defect] - once https://github.com/nim-lang/Nim/issues/12862 is fixed
#       https://github.com/status-im/nim-beacon-chain/pull/865#pullrequestreview-389117232

# Fork choice routines
# ----------------------------------------------------------------------

logScope:
  topics = "fork_choice"

proc init*(T: type ForkChoiceBackend,
           justified_epoch: Epoch,
           finalized_root: Eth2Digest,
           finalized_epoch: Epoch): T =
  T(
    proto_array: ProtoArray.init(
      justified_epoch,
      finalized_root,
      finalized_epoch
    )
  )

proc init*(T: type ForkChoice,
           epochRef: EpochRef,
           blck: BlockRef): T =
  ## Initialize a fork choice context for a genesis state - in the genesis
  ## state, the justified and finalized checkpoints are the same, so only one
  ## is used here
  debug "Initializing fork choice",
    epoch = epochRef.epoch, blck = shortLog(blck)

  let
    justified = BalanceCheckpoint(blck: blck, epochRef: epochRef)
    finalized = Checkpoint(root: blck.root, epoch: epochRef.epoch)
    best_justified = Checkpoint(
      root: justified.blck.root, epoch: justified.epochRef.epoch)

  ForkChoice(
    backend: ForkChoiceBackend.init(
      epochRef.epoch, blck.root, epochRef.epoch),
    checkpoints: Checkpoints(
      justified: justified,
      finalized: finalized,
      best_justified: best_justified)
  )

func extend[T](s: var seq[T], minLen: int) =
  ## Extend a sequence so that it can contains at least `minLen` elements.
  ## If it's already bigger, the sequence is unmodified.
  ## The extension is zero-initialized
  if s.len < minLen:
    s.setLen(minLen)

proc compute_slots_since_epoch_start(slot: Slot): uint64 =
    slot - slot.epoch().compute_start_slot_at_epoch()


proc on_tick(self: var Checkpoints, dag: ChainDAGRef, time: Slot): FcResult[void] =
  if self.time > time:
    return err(ForkChoiceError(kind: fcInconsistentTick))

  let newEpoch = self.time.epoch() != time.epoch()
  self.time = time

  if newEpoch and
      self.best_justified.epoch > self.justified.epochRef.epoch:
    let blck = dag.getRef(self.best_justified.root)
    if blck.isNil:
      return err(ForkChoiceError(
        kind: fcJustifiedNodeUnknown, block_root: self.best_justified.root))

    self.justified = BalanceCheckpoint(
      blck: blck,
      epochRef: dag.getEpochRef(blck, self.best_justified.epoch))
  ok()

proc process_attestation_queue(self: var ForkChoice) {.gcsafe.}
proc update_time(self: var ForkChoice, dag: ChainDAGRef, time: Slot): FcResult[void] =
  while time > self.checkpoints.time:
    ? on_tick(self.checkpoints, dag, self.checkpoints.time + 1)

  self.process_attestation_queue()

  ok()

func process_attestation*(
       self: var ForkChoiceBackend,
       validator_index: ValidatorIndex,
       block_root: Eth2Digest,
       target_epoch: Epoch
     ) =
  if block_root == Eth2Digest():
    return

  ## Add an attestation to the fork choice context
  self.votes.extend(validator_index.int + 1)

  template vote: untyped = self.votes[validator_index.int]
    # alias

  if target_epoch > vote.next_epoch or vote == default(VoteTracker):
    # TODO: the "default" condition is probably unneeded
    vote.next_root = block_root
    vote.next_epoch = target_epoch

    {.noSideEffect.}:
      trace "Integrating vote in fork choice",
        validator_index = validator_index,
        new_vote = shortLog(vote)

proc process_attestation_queue(self: var ForkChoice) =
  var
    keep: seq[QueuedAttestation]
  for attestation in self.queuedAttestations:
    if attestation.slot < self.checkpoints.time:
      for validator_index in attestation.attesting_indices:
        self.backend.process_attestation(
          validator_index, attestation.block_root,
          attestation.slot.epoch())
    else:
      keep.add attestation

  self.queuedAttestations = keep

func contains*(self: ForkChoiceBackend, block_root: Eth2Digest): bool =
  ## Returns `true` if a block is known to the fork choice
  ## and `false` otherwise.
  ##
  ## In particular, before adding a block, its parent must be known to the fork choice
  self.proto_array.indices.contains(block_root)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#on_attestation
proc on_attestation*(
       self: var ForkChoice,
       dag: ChainDAGRef,
       attestation_slot: Slot,
       beacon_block_root: Eth2Digest,
       attesting_indices: HashSet[ValidatorIndex],
       wallSlot: Slot
     ): FcResult[void] =
  ? self.update_time(dag, wallSlot)

  if beacon_block_root == Eth2Digest():
    return ok()

  if attestation_slot < self.checkpoints.time:
    for validator_index in attesting_indices:
      # attestation_slot and target epoch must match, per attestation rules
      self.backend.process_attestation(
        validator_index, beacon_block_root, attestation_slot.epoch)
  else:
    self.queuedAttestations.add(QueuedAttestation(
      slot: attestation_slot,
      attesting_indices: toSeq(attesting_indices),
      block_root: beacon_block_root))
  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#should_update_justified_checkpoint
proc should_update_justified_checkpoint(
        self: var Checkpoints,
        dag: ChainDAGRef,
        epochRef: EpochRef): FcResult[bool] =
  if compute_slots_since_epoch_start(self.time) < SAFE_SLOTS_TO_UPDATE_JUSTIFIED:
      return ok(true)

  let
    justified_slot = compute_start_slot_at_epoch(self.justified.epochRef.epoch)

  let new_justified_checkpoint = epochRef.current_justified_checkpoint;

  let justified_blck = dag.getRef(new_justified_checkpoint.root)

  if justified_blck.isNil:
    return err(ForkChoiceError(
      kind: fcJustifiedNodeUnknown, block_root: new_justified_checkpoint.root))

  let justified_ancestor =
    justified_blck.atSlot(justified_slot)

  if justified_ancestor.blck.root != self.justified.blck.root:
    return ok(false)

  ok(true)

proc process_state(self: var Checkpoints,
                   dag: ChainDAGRef,
                   epochRef: EpochRef,
                   blck: BlockRef): FcResult[void] =
  let
    state_justified_epoch = epochRef.current_justified_checkpoint.epoch
    state_finalized_epoch = epochRef.finalized_checkpoint.epoch

  trace "Processing epoch",
    epoch = epochRef.epoch,
    state_justified_epoch = state_justified_epoch,
    current_justified = self.justified.epochRef.epoch,
    state_finalized_epoch = state_finalized_epoch,
    current_finalized = self.finalized.epoch

  if state_justified_epoch > self.justified.epochRef.epoch:
    if state_justified_epoch > self.best_justified.epoch:
      self.best_justified = epochRef.current_justified_checkpoint

    if ? should_update_justified_checkpoint(self, dag, epochRef):
      let justifiedBlck = blck.atEpochStart(state_justified_epoch)

      self.justified =
        BalanceCheckpoint(
          blck: justifiedBlck.blck,
          epochRef: dag.getEpochRef(justifiedBlck.blck, state_justified_epoch))

  if state_finalized_epoch > self.finalized.epoch:
    self.finalized = epochRef.finalized_checkpoint

    if self.justified.epochRef.epoch != state_justified_epoch or
      self.justified.blck.root != epochRef.current_justified_checkpoint.root:

      if (state_justified_epoch > self.justified.epochRef.epoch) or
          (self.justified.blck.atEpochStart(self.finalized.epoch).blck.root !=
            self.finalized.root):

        let justifiedBlck = blck.atEpochStart(state_justified_epoch)

        self.justified =
          BalanceCheckpoint(
            blck: justifiedBlck.blck,
            epochRef: dag.getEpochRef(justifiedBlck.blck, state_justified_epoch))
  ok()

proc process_block*(self: var ForkChoiceBackend,
                    block_root: Eth2Digest,
                    parent_root: Eth2Digest,
                    justified_epoch: Epoch,
                    finalized_epoch: Epoch): FcResult[void] =
  self.proto_array.on_block(
    block_root, parent_root, justified_epoch, finalized_epoch)

proc process_block*(self: var ForkChoice,
                    dag: ChainDAGRef,
                    epochRef: EpochRef,
                    blckRef: BlockRef,
                    blck: SomeBeaconBlock,
                    wallSlot: Slot): FcResult[void] =
  ? update_time(self, dag, wallSlot)
  ? process_state(self.checkpoints, dag, epochRef, blckRef)

  for attestation in blck.body.attestations:
    let targetBlck = dag.getRef(attestation.data.target.root)
    if targetBlck.isNil:
      continue
    if attestation.data.beacon_block_root in self.backend:
      let
        participants = get_attesting_indices(
          epochRef, attestation.data, attestation.aggregation_bits)

      for validator in participants:
        self.backend.process_attestation(
          validator,
          attestation.data.beacon_block_root,
          attestation.data.target.epoch)

  ? process_block(
      self.backend, blckRef.root, blck.parent_root,
      epochRef.current_justified_checkpoint.epoch,
      epochRef.finalized_checkpoint.epoch
    )

  trace "Integrating block in fork choice",
    block_root = shortLog(blckRef)

  ok()

proc find_head*(
       self: var ForkChoiceBackend,
       justified_epoch: Epoch,
       justified_root: Eth2Digest,
       finalized_epoch: Epoch,
       justified_state_balances: seq[Gwei]
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
    new_balances = justified_state_balances
  )

  # Apply score changes
  ? self.proto_array.apply_score_changes(
    deltas, justified_epoch, finalized_epoch
  )

  self.balances = justified_state_balances

  # Find the best block
  var new_head{.noInit.}: Eth2Digest
  ? self.proto_array.find_head(new_head, justified_root)

  {.noSideEffect.}:
    debug "Fork choice requested",
      justified_epoch = justified_epoch,
      justified_root = shortLog(justified_root),
      finalized_epoch = finalized_epoch,
      fork_choice_head = shortLog(new_head)

  return ok(new_head)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#get_head
proc get_head*(self: var ForkChoice,
               dag: ChainDAGRef,
               wallSlot: Slot): FcResult[Eth2Digest] =
  ? self.update_time(dag, wallSlot)

  self.backend.find_head(
    self.checkpoints.justified.epochRef.epoch,
    self.checkpoints.justified.blck.root,
    self.checkpoints.finalized.epoch,
    self.checkpoints.justified.epochRef.effective_balances,
  )

func prune*(
       self: var ForkChoiceBackend, finalized_root: Eth2Digest
     ): FcResult[void] =
  ## Prune blocks preceding the finalized root as they are now unneeded.
  self.proto_array.prune(finalized_root)

func prune*(self: var ForkChoice): FcResult[void] =
  self.backend.prune(self.checkpoints.finalized.root)

func compute_deltas(
       deltas: var openarray[Delta],
       indices: Table[Eth2Digest, Index],
       indices_offset: Index,
       votes: var openArray[VoteTracker],
       old_balances: openarray[Gwei],
       new_balances: openarray[Gwei]
     ): FcResult[void] =
  ## Update `deltas`
  ##   between old and new balances
  ##   between votes
  ##
  ## `deltas.len` must match `indices.len` (lenght match)
  ##
  ## Error:
  ## - If a value in indices is greater than `indices.len`
  ## - If a `Eth2Digest` in `votes` does not exist in `indices`
  ##   except for the `default(Eth2Digest)` (i.e. zero hash)

  for val_index, vote in votes.mpairs():
    # No need to create a score change if the validator has never voted
    # or if votes are for the zero hash (alias to the genesis block)
    if vote.current_root == default(Eth2Digest) and vote.next_root == default(Eth2Digest):
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
            index: index
          )
        deltas[index] -= Delta old_balance
          # Note that delta can be negative
          # TODO: is int64 big enough?

      if vote.next_root in indices:
        let index = indices.unsafeGet(vote.next_root) - indices_offset
        if index >= deltas.len:
          return err ForkChoiceError(
            kind: fcInvalidNodeDelta,
            index: index
          )
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

    for i, delta in deltas.pairs:
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

    for i, delta in deltas.pairs:
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

    for i, delta in deltas.pairs:
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

    for i, delta in deltas.pairs:
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
