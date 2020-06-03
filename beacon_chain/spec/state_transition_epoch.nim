# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition - epoch processing, as described in
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
#
# The purpose of this code right is primarily educational, to help piece
# together the mechanics of the beacon state and to discover potential problem
# areas.
#
# The entry point is `process_epoch` which is at the bottom of this file.
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

{.push raises: [Defect].}

import
  math, sequtils, tables,
  stew/[bitops2], chronicles, json_serialization/std/sets,
  metrics, ../extras, ../ssz/merkleization,
  beaconstate, crypto, datatypes, digest, helpers, validator,
  state_transition_helpers,
  ../../nbench/bench_lab

# Logging utilities
# --------------------------------------------------------

logScope: topics = "consens"

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#interop-metrics
declareGauge beacon_finalized_epoch, "Current finalized epoch" # On epoch transition
declareGauge beacon_finalized_root, "Current finalized root" # On epoch transition
declareGauge beacon_current_justified_epoch, "Current justified epoch" # On epoch transition
declareGauge beacon_current_justified_root, "Current justified root" # On epoch transition
declareGauge beacon_previous_justified_epoch, "Current previously justified epoch" # On epoch transition
declareGauge beacon_previous_justified_root, "Current previously justified root" # On epoch transition

# Non-spec
declareGauge epoch_transition_justification_and_finalization, "Epoch transition justification and finalization time"
declareGauge epoch_transition_times_rewards_and_penalties, "Epoch transition reward and penalty time"
declareGauge epoch_transition_registry_updates, "Epoch transition registry updates time"
declareGauge epoch_transition_slashings, "Epoch transition slashings time"
declareGauge epoch_transition_final_updates, "Epoch transition final updates time"
declareGauge beacon_current_epoch, "Current epoch"

# Spec
# --------------------------------------------------------

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_total_active_balance
func get_total_active_balance*(state: BeaconState, cache: var StateCache): Gwei =
  # Return the combined effective balance of the active validators.
  # Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei
  # minimum to avoid divisions by zero.

  # TODO refactor get_epoch_per_epoch_cache() not to be, well, empty, so can
  # avoid this ever refilling, and raiseAssert, and get rid of var
  let
    epoch = state.slot.compute_epoch_at_slot
  try:
    if epoch notin cache.shuffled_active_validator_indices:
      cache.shuffled_active_validator_indices[epoch] =
        get_shuffled_active_validator_indices(state, epoch)

    get_total_balance(state, cache.shuffled_active_validator_indices[epoch])
  except KeyError:
    raiseAssert("get_total_active_balance(): cache always filled before usage")

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#helper-functions-1
func get_matching_source_attestations(state: BeaconState,
                                      epoch: Epoch): seq[PendingAttestation] =
  doAssert epoch in [get_current_epoch(state), get_previous_epoch(state)]
  if epoch == get_current_epoch(state):
    state.current_epoch_attestations.asSeq
  else:
    state.previous_epoch_attestations.asSeq

func get_matching_target_attestations(state: BeaconState, epoch: Epoch):
    seq[PendingAttestation] =
  filterIt(
    get_matching_source_attestations(state, epoch),
    it.data.target.root == get_block_root(state, epoch)
  )

func get_matching_head_attestations(state: BeaconState, epoch: Epoch):
    seq[PendingAttestation] =
  filterIt(
     get_matching_target_attestations(state, epoch),
     it.data.beacon_block_root ==
       get_block_root_at_slot(state, it.data.slot)
  )

func get_attesting_balance(
    state: BeaconState, attestations: seq[PendingAttestation],
    stateCache: var StateCache): Gwei =
  # Return the combined effective balance of the set of unslashed validators
  # participating in ``attestations``.
  # Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei
  # minimum to avoid divisions by zero.
  get_total_balance(state, get_unslashed_attesting_indices(
    state, attestations, stateCache))

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/core/0_beacon-chain.md#justification-and-finalization
proc process_justification_and_finalization*(state: var BeaconState,
    stateCache: var StateCache, updateFlags: UpdateFlags = {}) {.nbench.} =

  logScope: pcs = "process_justification_and_finalization"

  if get_current_epoch(state) <= GENESIS_EPOCH + 1:
    return

  let
    previous_epoch = get_previous_epoch(state)
    current_epoch = get_current_epoch(state)
    old_previous_justified_checkpoint = state.previous_justified_checkpoint
    old_current_justified_checkpoint = state.current_justified_checkpoint

  # Process justifications
  state.previous_justified_checkpoint = state.current_justified_checkpoint

  ## Spec:
  ## state.justification_bits[1:] = state.justification_bits[:-1]
  ## state.justification_bits[0] = 0b0
  # TODO JUSTIFICATION_BITS_LENGTH is a constant in spec, move there or fix
  # BitVector serialization in SSZ layer
  const JUSTIFICATION_BITS_LENGTH = 4
  state.justification_bits = (state.justification_bits shl 1) and
    cast[uint8]((2^JUSTIFICATION_BITS_LENGTH) - 1)

  # This is a somewhat expensive approach
  let active_validator_indices {.used.} =
    toHashSet(mapIt(
      get_active_validator_indices(state, get_current_epoch(state)), it.int))

  let matching_target_attestations_previous =
    get_matching_target_attestations(state, previous_epoch)  # Previous epoch

  ## This epoch processing is the last time these previous attestations can
  ## matter -- in the next epoch, they'll be 2 epochs old, when BeaconState
  ## tracks current_epoch_attestations and previous_epoch_attestations only
  ## per
  ## https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#attestations
  ## and `get_matching_source_attestations(...)` via
  ## https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#helper-functions-1
  ## and
  ## https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#final-updates
  ## after which the state.previous_epoch_attestations is replaced.
  let total_active_balance = get_total_active_balance(state, stateCache)
  trace "Non-attesting indices in previous epoch",
    missing_all_validators=
      difference(active_validator_indices,
        toHashSet(mapIt(get_attesting_indices(state,
          matching_target_attestations_previous, stateCache), it.int))),
    missing_unslashed_validators=
      difference(active_validator_indices,
        toHashSet(mapIt(get_unslashed_attesting_indices(state,
          matching_target_attestations_previous, stateCache), it.int))),
    prev_attestations_len=len(state.previous_epoch_attestations),
    cur_attestations_len=len(state.current_epoch_attestations),
    num_active_validators=len(active_validator_indices),
    required_balance = total_active_balance * 2,
    attesting_balance_prev = get_attesting_balance(state, matching_target_attestations_previous, stateCache)
  if get_attesting_balance(state, matching_target_attestations_previous,
      stateCache) * 3 >= total_active_balance * 2:
    state.current_justified_checkpoint =
      Checkpoint(epoch: previous_epoch,
                 root: get_block_root(state, previous_epoch))
    state.justification_bits.setBit 1

    trace "Justified with previous epoch",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.current_justified_checkpoint),
      cat = "justification"

  let matching_target_attestations_current =
    get_matching_target_attestations(state, current_epoch)  # Current epoch
  if get_attesting_balance(state, matching_target_attestations_current,
      stateCache) * 3 >= total_active_balance * 2:
    state.current_justified_checkpoint =
      Checkpoint(epoch: current_epoch,
                 root: get_block_root(state, current_epoch))
    state.justification_bits.setBit 0

    trace "Justified with current epoch",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.current_justified_checkpoint),
      cat = "justification"

  # Process finalizations
  let bitfield = state.justification_bits

  ## The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th
  ## as source
  if (bitfield and 0b1110) == 0b1110 and
     old_previous_justified_checkpoint.epoch + 3 == current_epoch:
    state.finalized_checkpoint = old_previous_justified_checkpoint

    trace "Finalized with rule 234",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.finalized_checkpoint),
      cat = "finalization"

  ## The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as
  ## source
  if (bitfield and 0b110) == 0b110 and
     old_previous_justified_checkpoint.epoch + 2 == current_epoch:
    state.finalized_checkpoint = old_previous_justified_checkpoint

    trace "Finalized with rule 23",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.finalized_checkpoint),
      cat = "finalization"

  ## The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as
  ## source
  if (bitfield and 0b111) == 0b111 and
     old_current_justified_checkpoint.epoch + 2 == current_epoch:
    state.finalized_checkpoint = old_current_justified_checkpoint

    trace "Finalized with rule 123",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.finalized_checkpoint),
      cat = "finalization"

  ## The 1st/2nd most recent epochs are justified, the 1st using the 2nd as
  ## source
  if (bitfield and 0b11) == 0b11 and
     old_current_justified_checkpoint.epoch + 1 == current_epoch:
    state.finalized_checkpoint = old_current_justified_checkpoint

    trace "Finalized with rule 12",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.finalized_checkpoint),
      cat = "finalization"

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#rewards-and-penalties-1
func get_base_reward(state: BeaconState, index: ValidatorIndex,
    total_balance: auto): Gwei =
  # Spec function recalculates total_balance every time, which creates an
  # O(n^2) situation.
  let effective_balance = state.validators[index].effective_balance
  effective_balance * BASE_REWARD_FACTOR div
    integer_squareroot(total_balance) div BASE_REWARDS_PER_EPOCH

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#rewards-and-penalties-1
func get_attestation_deltas(state: BeaconState, stateCache: var StateCache):
    tuple[a: seq[Gwei], b: seq[Gwei]] {.nbench.}=
  let
    previous_epoch = get_previous_epoch(state)
    total_balance = get_total_active_balance(state, stateCache)
  var
    rewards = repeat(0'u64, len(state.validators))
    penalties = repeat(0'u64, len(state.validators))
    eligible_validator_indices : seq[ValidatorIndex] = @[]

  for index, v in state.validators:
    if is_active_validator(v, previous_epoch) or
        (v.slashed and previous_epoch + 1 < v.withdrawable_epoch):
      eligible_validator_indices.add index.ValidatorIndex

  # Micro-incentives for matching FFG source, FFG target, and head
  let
    matching_source_attestations =
      get_matching_source_attestations(state, previous_epoch)
    matching_target_attestations =
      get_matching_target_attestations(state, previous_epoch)
    matching_head_attestations =
      get_matching_head_attestations(state, previous_epoch)

  for attestations in
      [matching_source_attestations, matching_target_attestations,
       matching_head_attestations]:
    let
      unslashed_attesting_indices =
        get_unslashed_attesting_indices(state, attestations, stateCache)
      attesting_balance = get_total_balance(state, unslashed_attesting_indices)
    for index in eligible_validator_indices:
      if index in unslashed_attesting_indices:
        # Factored out from balance totals to avoid uint64 overflow
        const increment = EFFECTIVE_BALANCE_INCREMENT
        let reward_numerator = get_base_reward(state, index, total_balance) *
          (attesting_balance div increment)
        rewards[index] += reward_numerator div (total_balance div increment)
      else:
        penalties[index] += get_base_reward(state, index, total_balance)

  # Proposer and inclusion delay micro-rewards
  ## This depends on matching_source_attestations being an indexable seq, not a
  ## set, hash table, etc.
  let source_attestation_attesting_indices =
    mapIt(
      matching_source_attestations,
      get_attesting_indices(state, it.data, it.aggregation_bits, stateCache))

  for index in get_unslashed_attesting_indices(
      state, matching_source_attestations, stateCache):
    # Translation of attestation = min([...])
    doAssert matching_source_attestations.len > 0

    # Start by filtering the right attestations
    var filtered_matching_source_attestations: seq[PendingAttestation]

    for source_attestation_index, a in matching_source_attestations:
      if index notin
          source_attestation_attesting_indices[source_attestation_index]:
        continue
      filtered_matching_source_attestations.add a

    # The first filtered attestation serves as min until we find something
    # better
    var attestation = filtered_matching_source_attestations[0]
    for source_attestation_index, a in filtered_matching_source_attestations:
      if a.inclusion_delay < attestation.inclusion_delay:
        attestation = a

    let
      base_reward = get_base_reward(state, index, total_balance)
      proposer_reward = (base_reward div PROPOSER_REWARD_QUOTIENT).Gwei

    rewards[attestation.proposer_index.int] += proposer_reward
    let max_attester_reward = base_reward - proposer_reward

    rewards[index] += max_attester_reward div attestation.inclusion_delay

  # Inactivity penalty
  let finality_delay = previous_epoch - state.finalized_checkpoint.epoch
  if finality_delay > MIN_EPOCHS_TO_INACTIVITY_PENALTY:
    let matching_target_attesting_indices =
      get_unslashed_attesting_indices(
        state, matching_target_attestations, stateCache)
    for index in eligible_validator_indices:
      penalties[index] +=
        BASE_REWARDS_PER_EPOCH.uint64 * get_base_reward(state, index, total_balance)
      if index notin matching_target_attesting_indices:
        penalties[index] +=
          state.validators[index].effective_balance *
            finality_delay div INACTIVITY_PENALTY_QUOTIENT

  (rewards, penalties)

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#rewards-and-penalties-1
func process_rewards_and_penalties(
    state: var BeaconState, cache: var StateCache) {.nbench.}=
  if get_current_epoch(state) == GENESIS_EPOCH:
    return

  let (rewards, penalties) = get_attestation_deltas(state, cache)

  for i in 0 ..< len(state.validators):
    increase_balance(state, i.ValidatorIndex, rewards[i])
    decrease_balance(state, i.ValidatorIndex, penalties[i])

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/core/0_beacon-chain.md#slashings
func process_slashings*(state: var BeaconState, cache: var StateCache) {.nbench.}=
  let
    epoch = get_current_epoch(state)
    total_balance = get_total_active_balance(state, cache)

  for index, validator in state.validators:
    if validator.slashed and epoch + EPOCHS_PER_SLASHINGS_VECTOR div 2 ==
        validator.withdrawable_epoch:
      let increment = EFFECTIVE_BALANCE_INCREMENT # Factored out from penalty
                                                  # numerator to avoid uint64 overflow
      let penalty_numerator =
        validator.effective_balance div increment *
          min(sum(state.slashings) * 3, total_balance)
      let penalty = penalty_numerator div total_balance * increment
      decrease_balance(state, index.ValidatorIndex, penalty)

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#final-updates
func process_final_updates*(state: var BeaconState) {.nbench.}=
  let
    current_epoch = get_current_epoch(state)
    next_epoch = current_epoch + 1

  # Reset eth1 data votes
  if next_epoch mod EPOCHS_PER_ETH1_VOTING_PERIOD == 0:
    state.eth1_data_votes = default(type state.eth1_data_votes)

  # Update effective balances with hysteresis
  for index, validator in state.validators:
    let balance = state.balances[index]
    const
      HYSTERESIS_INCREMENT =
        EFFECTIVE_BALANCE_INCREMENT div HYSTERESIS_QUOTIENT
      DOWNWARD_THRESHOLD =
        HYSTERESIS_INCREMENT * HYSTERESIS_DOWNWARD_MULTIPLIER
      UPWARD_THRESHOLD = HYSTERESIS_INCREMENT * HYSTERESIS_UPWARD_MULTIPLIER
    if balance + DOWNWARD_THRESHOLD < validator.effective_balance or
        validator.effective_balance + UPWARD_THRESHOLD < balance:
      state.validators[index].effective_balance =
        min(
          balance - balance mod EFFECTIVE_BALANCE_INCREMENT,
          MAX_EFFECTIVE_BALANCE)

  # Reset slashings
  state.slashings[next_epoch mod EPOCHS_PER_SLASHINGS_VECTOR] = 0.Gwei

  # Set randao mix
  state.randao_mixes[next_epoch mod EPOCHS_PER_HISTORICAL_VECTOR] =
    get_randao_mix(state, current_epoch)

  # Set historical root accumulator
  if next_epoch mod (SLOTS_PER_HISTORICAL_ROOT div SLOTS_PER_EPOCH).uint64 == 0:
    # Equivalent to hash_tree_root(foo: HistoricalBatch), but without using
    # significant additional stack or heap.
    # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#historicalbatch
    # In response to https://github.com/status-im/nim-beacon-chain/issues/921
    state.historical_roots.add hash_tree_root(
      [hash_tree_root(state.block_roots), hash_tree_root(state.state_roots)])

  # Rotate current/previous epoch attestations
  state.previous_epoch_attestations = state.current_epoch_attestations
  state.current_epoch_attestations = default(type state.current_epoch_attestations)

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#epoch-processing
proc process_epoch*(state: var BeaconState, updateFlags: UpdateFlags,
    per_epoch_cache: var StateCache) {.nbench.} =
  let currentEpoch = get_current_epoch(state)
  trace "process_epoch",
    current_epoch = currentEpoch

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#justification-and-finalization
  process_justification_and_finalization(state, per_epoch_cache, updateFlags)

  # state.slot hasn't been incremented yet.
  if verifyFinalization in updateFlags and currentEpoch >= 3:
    # Rule 2/3/4 finalization results in the most pessimal case. The other
    # three finalization rules finalize more quickly as long as the any of
    # the finalization rules triggered.
    doAssert state.finalized_checkpoint.epoch + 3 >= currentEpoch

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#rewards-and-penalties-1
  process_rewards_and_penalties(state, per_epoch_cache)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#registry-updates
  process_registry_updates(state, per_epoch_cache)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#slashings
  process_slashings(state, per_epoch_cache)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#final-updates
  process_final_updates(state)

  # Once per epoch metrics
  beacon_current_epoch.set(currentEpoch.int64)
  beacon_finalized_epoch.set(state.finalized_checkpoint.epoch.int64)
  beacon_finalized_root.set(state.finalized_checkpoint.root.toGaugeValue)
  beacon_current_justified_epoch.set(
    state.current_justified_checkpoint.epoch.int64)
  beacon_current_justified_root.set(
    state.current_justified_checkpoint.root.toGaugeValue)
  beacon_previous_justified_epoch.set(
    state.previous_justified_checkpoint.epoch.int64)
  beacon_previous_justified_root.set(
    state.previous_justified_checkpoint.root.toGaugeValue)
