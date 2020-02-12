# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition, as described in
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
#
# The purpose of this code right is primarily educational, to help piece
# together the mechanics of the beacon state and to discover potential problem
# areas. The entry point is `updateState` which is at the bottom of the file!
#
# General notes about the code (TODO):
# * It's inefficient - we quadratically copy, allocate and iterate when there
#   are faster options
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * We mix procedural and functional styles for no good reason, except that the
#   spec does so also.
# * There are likely lots of bugs.
# * For indices, we get a mix of uint64, ValidatorIndex and int - this is currently
#   swept under the rug with casts
# * The spec uses uint64 for data types, but functions in the spec often assume
#   signed bigint semantics - under- and overflows ensue
# * Sane error handling is missing in most cases (yay, we'll get the chance to
#   debate exceptions again!)
# When updating the code, add TODO sections to mark where there are clear
# improvements to be made - other than that, keep things similar to spec for
# now.

import
  collections/sets, chronicles, sets,
  ./extras, ./ssz, metrics,
  ./spec/[datatypes, digest, helpers, validator],
  ./spec/[state_transition_block, state_transition_epoch],
  ../nbench/bench_lab

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#additional-metrics
declareGauge beacon_current_validators, """Number of status="pending|active|exited|withdrawable" validators in current epoch""" # On epoch transition
declareGauge beacon_previous_validators, """Number of status="pending|active|exited|withdrawable" validators in previous epoch""" # On epoch transition

# Canonical state transition functions
# ---------------------------------------------------------------

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
func process_slot*(state: var BeaconState) {.nbench.}=
  # Cache state root
  let previous_state_root = hash_tree_root(state)
  state.state_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    previous_state_root

  # Cache latest block header state root
  if state.latest_block_header.state_root == ZERO_HASH:
    state.latest_block_header.state_root = previous_state_root

  # Cache block root
  state.block_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    hash_tree_root(state.latest_block_header)

func get_epoch_validator_count(state: BeaconState): int64 =
  # https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#additional-metrics
  #
  # This O(n) loop doesn't add to the algorithmic complexity of the epoch
  # transition -- registry update already does this. It is not great, but
  # isn't new, either. If profiling shows issues some of this can be loop
  # fusion'ed.
  for index, validator in state.validators:
    # These work primarily for the `beacon_current_validators` metric defined
    # as 'Number of status="pending|active|exited|withdrawable" validators in
    # current epoch'. This is, in principle, equivalent to checking whether a
    # validator's either at less than MAX_EFFECTIVE_BALANCE, or has withdrawn
    # already because withdrawable_epoch has passed, which more precisely has
    # intuitive meaning of all-the-current-relevant-validators. So, check for
    # not-(either (not-even-pending) or withdrawn). That is validators change
    # from not-even-pending to pending to active to exited to withdrawable to
    # withdrawn, and this avoids bugs on potential edge cases and off-by-1's.
    if (validator.activation_epoch != FAR_FUTURE_EPOCH or
          validator.effective_balance > MAX_EFFECTIVE_BALANCE) and
       validator.withdrawable_epoch > get_current_epoch(state):
      result += 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc process_slots*(state: var BeaconState, slot: Slot) {.nbench.}=
  if not (state.slot <= slot):
    warn("Trying to apply old block",
      state_slot = state.slot,
      slot = slot)
    return

  # Catch up to the target slot
  while state.slot < slot:
    process_slot(state)
    let is_epoch_transition = (state.slot + 1) mod SLOTS_PER_EPOCH == 0
    if is_epoch_transition:
      # Note: Genesis epoch = 0, no need to test if before Genesis
      beacon_previous_validators.set(get_epoch_validator_count(state))
      process_epoch(state)
    state.slot += 1
    if is_epoch_transition:
      beacon_current_validators.set(get_epoch_validator_count(state))

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
proc verifyStateRoot(state: BeaconState, blck: BeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  let state_root = hash_tree_root(state)
  if state_root != blck.state_root:
    notice "Block: root verification failed",
      block_state_root = blck.state_root, state_root
    false
  else:
    true

proc state_transition*(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool {.nbench.}=
  ## Time in the beacon chain moves by slots. Every time (haha.) that happens,
  ## we will update the beacon state. Normally, the state updates will be driven
  ## by the contents of a new block, but it may happen that the block goes
  ## missing - the state updates happen regardless.
  ##
  ## Each call to this function will advance the state by one slot - new_block,
  ## must match that slot. If the update fails, the state will remain unchanged.
  ##
  ## The flags are used to specify that certain validations should be skipped
  ## for the new block. This is done during block proposal, to create a state
  ## whose hash can be included in the new block.
  #
  # TODO this function can be written with a loop inside to handle all empty
  #      slots up to the slot of the new_block - but then again, why not eagerly
  #      update the state as time passes? Something to ponder...
  #      One reason to keep it this way is that you need to look ahead if you're
  #      the block proposer, though in reality we only need a partial update for
  #      that ===> Implemented as process_slots
  # TODO There's a discussion about what this function should do, and when:
  #      https://github.com/ethereum/eth2.0-specs/issues/284

  # TODO check to which extent this copy can be avoided (considering forks etc),
  #      for now, it serves as a reminder that we need to handle invalid blocks
  #      somewhere..
  #      many functions will mutate `state` partially without rolling back
  #      the changes in case of failure (look out for `var BeaconState` and
  #      bool return values...)

  ## TODO, of cacheState/processEpoch/processSlot/processBloc, only the last
  ## might fail, so should this bother capturing here, or?
  var old_state = state

  # These should never fail.
  process_slots(state, blck.slot)

  # Block updates - these happen when there's a new block being suggested
  # by the block proposer. Every actor in the network will update its state
  # according to the contents of this block - but first they will validate
  # that the block is sane.
  # TODO what should happen if block processing fails?
  #      https://github.com/ethereum/eth2.0-specs/issues/293
  var per_epoch_cache = get_empty_per_epoch_cache()

  if processBlock(state, blck, flags, per_epoch_cache):
    # This is a bit awkward - at the end of processing we verify that the
    # state we arrive at is what the block producer thought it would be -
    # meaning that potentially, it could fail verification
    if skipValidation in flags or verifyStateRoot(state, blck):
      # TODO: allow skipping just verifyStateRoot for mocking
      #       instead of both processBlock and verifyStateRoot
      #       https://github.com/status-im/nim-beacon-chain/issues/407
      # State root is what it should be - we're done!
      return true

  # Block processing failed, roll back changes
  state = old_state
  false

# Hashed-state transition functions
# ---------------------------------------------------------------

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
func process_slot(state: var HashedBeaconState) =
  # Cache state root
  let previous_slot_state_root = state.root
  state.data.state_roots[state.data.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    previous_slot_state_root

  # Cache latest block header state root
  if state.data.latest_block_header.state_root == ZERO_HASH:
    state.data.latest_block_header.state_root = previous_slot_state_root

  # Cache block root
  state.data.block_roots[state.data.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    hash_tree_root(state.data.latest_block_header)

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc process_slots*(state: var HashedBeaconState, slot: Slot) =
  # TODO: Eth specs strongly assert that state.data.slot <= slot
  #       This prevents receiving attestation in any order
  #       (see tests/test_attestation_pool)
  #       but it maybe an artifact of the test case
  #       as this was not triggered in the testnet1
  #       after a hour
  if state.data.slot > slot:
    notice(
      "Unusual request for a slot in the past",
      state_root = shortLog(state.root),
      current_slot = state.data.slot,
      target_slot = slot
    )

  # Catch up to the target slot
  while state.data.slot < slot:
    process_slot(state)
    let is_epoch_transition = (state.data.slot + 1) mod SLOTS_PER_EPOCH == 0
    if is_epoch_transition:
      # Note: Genesis epoch = 0, no need to test if before Genesis
      beacon_previous_validators.set(get_epoch_validator_count(state.data))
      process_epoch(state.data)
    state.data.slot += 1
    if is_epoch_transition:
      beacon_current_validators.set(get_epoch_validator_count(state.data))
    state.root = hash_tree_root(state.data)

proc state_transition*(
    state: var HashedBeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  # Save for rollback
  var old_state = state

  process_slots(state, blck.slot)
  var per_epoch_cache = get_empty_per_epoch_cache()

  if processBlock(state.data, blck, flags, per_epoch_cache):
    if skipValidation in flags or verifyStateRoot(state.data, blck):
      # State root is what it should be - we're done!

      # TODO when creating a new block, state_root is not yet set.. comparing
      #      with zero hash here is a bit fragile however, but this whole thing
      #      should go away with proper hash caching
      state.root =
        if blck.state_root == Eth2Digest(): hash_tree_root(state.data)
        else: blck.state_root

      return true

  # Block processing failed, roll back changes
  state = old_state
  false
