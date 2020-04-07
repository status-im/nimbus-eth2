# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/tables, std/options, std/typetraits,
  # Status libraries
  stew/result,
  # Internal
  ../spec/[datatypes, digest],
  # Fork choice
  ./fork_choice_types, ./proto_array

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/fork-choice.md
# This is a port of https://github.com/sigp/lighthouse/pull/804
# which is a port of "Proto-Array": https://github.com/protolambda/lmd-ghost
# See also:
# - Protolambda port of Lighthouse: https://github.com/protolambda/eth2-py-hacks/blob/ae286567/proto_array.py
# - Prysmatic writeup: https://hackmd.io/bABJiht3Q9SyV3Ga4FT9lQ#High-level-concept
# - Gasper Whitepaper: https://arxiv.org/abs/2003.03052

const DefaultPruneThreshold = 256

# Forward declarations
# ----------------------------------------------------------------------

func compute_deltas(
       deltas: var openarray[Delta],
       indices: Table[Eth2Digest, Index],
       votes: var openArray[VoteTracker],
       old_balances: openarray[Gwei],
       new_balances: openarray[Gwei]
     ): ForkChoiceError {.raises: [].}

# Fork choice routines
# ----------------------------------------------------------------------

func initForkChoice*(
       finalized_block_slot: Slot,
       finalized_block_state_root: Eth2Digest,
       justified_epoch: Epoch,
       finalized_epoch: Epoch,
       finalized_root: Eth2Digest
     ): Result[ForkChoice, string] {.raises: [].} =
  ## Initialize a fork choice context
  var proto_array = ProtoArray(
    prune_threshold: DefaultPruneThreshold,
    justified_epoch: justified_epoch,
    finalized_epoch: finalized_epoch
  )

  let err = proto_array.on_block(
    finalized_block_slot,
    finalized_root,
    none(Eth2Digest),
    finalized_block_state_root,
    justified_epoch,
    finalized_epoch
  )
  if err.kind != fcSuccess:
    result.err("Failed to add finalized block to proto_array: " & $err)
    return
  result.ok(ForkChoice(proto_array: proto_array))


func extend[T](s: var seq[T], minLen: int) {.raises: [].} =
  ## Extend a sequence so that it can contains at least `minLen` elements.
  ## If it's already bigger, the sequence is unmodified.
  ## The extension is zero-initialized
  let curLen = s.len
  let diff = minLen - curLen
  if diff > 0:
    # Note: seq has a length and a capacity.
    #       If the new length is less than the original capacity
    #         => setLen will not zeroMem
    #       If the capacity was too small
    #         => reallocation occurs
    #         => the fresh buffer is zeroMem-ed
    #       In the second case our own zeroMem is redundant
    #       but this should happen rarely as we reuse the buffer
    #       most of the time
    s.setLen(minLen)
    zeroMem(s[curLen].addr, diff * sizeof(T))


func process_attestation*(
       self: var ForkChoice,
       validator_index: ValidatorIndex,
       block_root: Eth2Digest,
       target_epoch: Epoch
     ): Result[void, string] {.raises: [].} =
  ## Add an attestation to the fork choice context
  self.votes.extend(validator_index.int + 1)

  template vote: untyped {.dirty.} = self.votes[validator_index.int]
    # alias

  if target_epoch > vote.next_epoch or vote == default(VoteTracker):
    # TODO: the "default" condition is probably unneeded
    vote.next_root = block_root
    vote.next_epoch = target_epoch

  result.ok()


func process_block*(
       self: var ForkChoice,
       slot: Slot,
       block_root: Eth2Digest,
       parent_root: Eth2Digest,
       state_root: Eth2Digest,
       justified_epoch: Epoch,
       finalized_epoch: Epoch
     ): Result[void, string] {.raises: [].} =
  ## Add a block to the fork choice context
  let err = self.proto_array.on_block(
    slot, block_root, some(parent_root), state_root, justified_epoch, finalized_epoch
  )
  if err.kind != fcSuccess:
    result.err("process_block_error: " & $err)
    return
  result.ok()


func find_head*(
       self: var ForkChoice,
       justified_epoch: Epoch,
       justified_root: Eth2Digest,
       finalized_epoch: Epoch,
       justified_state_balances: seq[Gwei]
     ): Result[Eth2Digest, string] {.raises: [].} =
  ## Returns the new blockchain head

  # Compute deltas with previous call
  #   we might want to reuse the `deltas` buffer across calls
  var deltas = newSeq[Delta](self.proto_array.indices.len)
  let delta_err = deltas.compute_deltas(
    indices = self.proto_array.indices,
    votes = self.votes,
    old_balances = self.balances,
    new_balances = justified_state_balances
  )
  if delta_err.kind != fcSuccess:
    result.err("find_head compute_deltas failed: " & $delta_err)
    return

  # Apply score changes
  let score_err = self.proto_array.apply_score_changes(
    deltas, justified_epoch, finalized_epoch
  )
  if score_err.kind != fcSuccess:
    result.err("find_head apply_score_changes failed: " & $score_err)

  self.balances = justified_state_balances

  # Find the best block
  var new_head{.noInit.}: Eth2Digest
  let ghost_err = self.proto_array.find_head(new_head, justified_root)
  if ghost_err.kind != fcSuccess:
    result.err("find_head failed: " & $ghost_err)
    return

  result.ok(new_head)


func maybe_prune*(
       self: var ForkChoice, finalized_root: Eth2Digest
     ): Result[void, string] {.raises: [].} =
  ## Prune blocks preceding the finalized root as they are now unneeded.
  let err = self.proto_array.maybe_prune(finalized_root)
  if err.kind != fcSuccess:
    result.err("find_head maybe_pruned failed: " & $err)
  result.ok()


func compute_deltas(
       deltas: var openarray[Delta],
       indices: Table[Eth2Digest, Index],
       votes: var openArray[VoteTracker],
       old_balances: openarray[Gwei],
       new_balances: openarray[Gwei]
     ): ForkChoiceError {.raises: [].} =
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
        let index = indices.unsafeGet(vote.current_root)
        if index >= deltas.len:
          return ForkChoiceError(
            kind: fcErrInvalidNodeDelta,
            index: index
          )
        deltas[index] -= Delta old_balance
          # Note that delta can be negative
          # TODO: is int64 big enough?

      if vote.next_root in indices:
        let index = indices.unsafeGet(vote.next_root)
        if index >= deltas.len:
          return ForkChoiceError(
            kind: fcErrInvalidNodeDelta,
            index: index
          )
        deltas[index] += Delta new_balance
          # Note that delta can be negative
          # TODO: is int64 big enough?

      vote.current_root = vote.next_root
  return ForkChoiceSuccess

# Sanity checks
# ----------------------------------------------------------------------
# Sanity checks on internal private procedures

when isMainModule:
  import stew/endians2

  func fakeHash*(index: SomeInteger): Eth2Digest =
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
      indices, votes, old_balances, new_balances
    )

    doAssert err.kind == fcSuccess, "compute_deltas finished with error: " & $err

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
      indices, votes, old_balances, new_balances
    )

    doAssert err.kind == fcSuccess, "compute_deltas finished with error: " & $err

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
      indices, votes, old_balances, new_balances
    )

    doAssert err.kind == fcSuccess, "compute_deltas finished with error: " & $err

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
      indices, votes, old_balances, new_balances
    )

    doAssert err.kind == fcSuccess, "compute_deltas finished with error: " & $err

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
      indices, votes, old_balances, new_balances
    )

    doAssert err.kind == fcSuccess, "compute_deltas finished with error: " & $err

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
      indices, votes, old_balances, new_balances
    )

    doAssert err.kind == fcSuccess, "compute_deltas finished with error: " & $err

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
      indices, votes, old_balances, new_balances
    )

    doAssert err.kind == fcSuccess, "compute_deltas finished with error: " & $err

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
      indices, votes, old_balances, new_balances
    )

    doAssert err.kind == fcSuccess, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance)*2, "Block 1 should have lost 2 balances"
    doAssert deltas[1] == Delta(Balance), "Block 2 should have gained 1 balance"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  # ----------------------------------------------------------------------

  echo "fork_choice internal tests for compute_deltas"
  # tZeroHash()
  tAll_voted_the_same()
  tDifferent_votes()
  tMoving_votes()
  tChanging_balances()
  # tValidator_appears()
  # tValidator_disappears()
