# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition - epoch processing, as described in
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
#
# The entry point is `process_epoch`, which is at the bottom of this file.
#
# General notes about the code (TODO):
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * For indices, we get a mix of uint64, ValidatorIndex and int - this is currently
#   swept under the rug with casts
# When updating the code, add TODO sections to mark where there are clear
# improvements to be made - other than that, keep things similar to spec for
# now.

{.push raises: [Defect].}

import
  math, sequtils, tables, algorithm,
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_total_active_balance
func get_total_active_balance*(state: BeaconStateView, cache: var StateCache): Gwei =
  # Return the combined effective balance of the active validators.
  # Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei
  # minimum to avoid divisions by zero.

  let
    epoch = state.get_current_epoch()

  get_total_balance(
    state, cache.get_shuffled_active_validator_indices(state, epoch))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#helper-functions-1
template get_matching_source_attestations(state: BeaconStateView,
                                          epoch: Epoch): seq[PendingAttestation] =
  doAssert epoch in [get_current_epoch(state), get_previous_epoch(state)]
  if epoch == get_current_epoch(state):
    state.current_epoch_attestations.asSeq
  else:
    state.previous_epoch_attestations.asSeq

func get_matching_target_attestations(state: BeaconStateView, epoch: Epoch):
    seq[PendingAttestation] =
  filterIt(
    get_matching_source_attestations(state, epoch),
    it.data.target.root == get_block_root(state, epoch)
  )

func get_matching_head_attestations(state: BeaconStateView, epoch: Epoch):
    seq[PendingAttestation] =
  filterIt(
     get_matching_target_attestations(state, epoch),
     it.data.beacon_block_root ==
       get_block_root_at_slot(state, it.data.slot)
  )

func get_attesting_balance(
    state: BeaconStateView, attestations: seq[PendingAttestation],
    stateCache: var StateCache): Gwei =
  # Return the combined effective balance of the set of unslashed validators
  # participating in ``attestations``.
  # Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei
  # minimum to avoid divisions by zero.
  get_total_balance(state, get_unslashed_attesting_indices(
    state, attestations, stateCache))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#justification-and-finalization
proc process_justification_and_finalization*(state: var BeaconState,
    cache: var StateCache, updateFlags: UpdateFlags = {}) {.nbench.} =

  logScope: pcs = "process_justification_and_finalization"

  if get_current_epoch(state.unsafeView()) <= GENESIS_EPOCH + 1:
    return

  let
    previous_epoch = get_previous_epoch(state.unsafeView())
    current_epoch = get_current_epoch(state.unsafeView())
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

  let matching_target_attestations_previous =
    get_matching_target_attestations(state.unsafeView(), previous_epoch)  # Previous epoch

  if verifyFinalization in updateFlags:
    let active_validator_indices =
      toHashSet(cache.get_shuffled_active_validator_indices(
          state.unsafeView(), get_current_epoch(state.unsafeView())))

    # Non-attesting indices in previous epoch
    let missing_all_validators =
      difference(active_validator_indices,
        get_attesting_indices(
          state.unsafeView(), matching_target_attestations_previous, cache))

    # testnet0 and testnet1 have 8 non-attesting validators each, by default
    if missing_all_validators.len > 15:
      info "Missing too many attesters from previous epoch in verifyFinalization mode",
        missing_all_validators,
        epoch = get_current_epoch(state.unsafeView())

  # This epoch processing is the last time these previous attestations can
  # matter -- in the next epoch, they'll be 2 epochs old, when BeaconState
  # tracks current_epoch_attestations and previous_epoch_attestations only
  # per
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#attestations
  # and `get_matching_source_attestations(...)` via
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#helper-functions-1
  # and
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#final-updates
  # after which the state.previous_epoch_attestations is replaced.
  let total_active_balance = get_total_active_balance(state.unsafeView(), cache)
  when chronicles.enabledLogLevel == LogLevel.TRACE:
    let active_validator_indices =
      toHashSet(cache.get_shuffled_active_validator_indices(
          state.unsafeView(), get_current_epoch(state.unsafeView())))

    trace "Non-attesting indices in previous epoch",
      missing_all_validators =
        difference(active_validator_indices, get_attesting_indices(
          state.unsafeView(), matching_target_attestations_previous, cache)),
      missing_unslashed_validators =
        difference(active_validator_indices,
          get_unslashed_attesting_indices(
            state.unsafeView(), matching_target_attestations_previous, cache)),
      prev_attestations_len = len(state.previous_epoch_attestations),
      cur_attestations_len = len(state.current_epoch_attestations),
      num_active_validators = len(active_validator_indices),
      total_active_balance,
      attesting_balance_prev = get_attesting_balance(
        state.unsafeView(), matching_target_attestations_previous, cache)

  if get_attesting_balance(state.unsafeView(), matching_target_attestations_previous,
      cache) * 3 >= total_active_balance * 2:
    state.current_justified_checkpoint =
      Checkpoint(epoch: previous_epoch,
                 root: get_block_root(state.unsafeView(), previous_epoch))
    state.justification_bits.setBit 1

    trace "Justified with previous epoch",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.current_justified_checkpoint)

  let matching_target_attestations_current =
    get_matching_target_attestations(state.unsafeView(), current_epoch)  # Current epoch
  if get_attesting_balance(state.unsafeView(), matching_target_attestations_current,
      cache) * 3 >= total_active_balance * 2:
    state.current_justified_checkpoint =
      Checkpoint(epoch: current_epoch,
                 root: get_block_root(state.unsafeView(), current_epoch))
    state.justification_bits.setBit 0

    trace "Justified with current epoch",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.current_justified_checkpoint)

  # Process finalizations
  let bitfield = state.justification_bits

  ## The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th
  ## as source
  if (bitfield and 0b1110) == 0b1110 and
     old_previous_justified_checkpoint.epoch + 3 == current_epoch:
    state.finalized_checkpoint = old_previous_justified_checkpoint

    trace "Finalized with rule 234",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.finalized_checkpoint)

  ## The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as
  ## source
  if (bitfield and 0b110) == 0b110 and
     old_previous_justified_checkpoint.epoch + 2 == current_epoch:
    state.finalized_checkpoint = old_previous_justified_checkpoint

    trace "Finalized with rule 23",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.finalized_checkpoint)

  ## The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as
  ## source
  if (bitfield and 0b111) == 0b111 and
     old_current_justified_checkpoint.epoch + 2 == current_epoch:
    state.finalized_checkpoint = old_current_justified_checkpoint

    trace "Finalized with rule 123",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.finalized_checkpoint)

  ## The 1st/2nd most recent epochs are justified, the 1st using the 2nd as
  ## source
  if (bitfield and 0b11) == 0b11 and
     old_current_justified_checkpoint.epoch + 1 == current_epoch:
    state.finalized_checkpoint = old_current_justified_checkpoint

    trace "Finalized with rule 12",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.finalized_checkpoint)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#helpers
func get_base_reward(state: BeaconStateView, index: ValidatorIndex,
    total_balance: auto): Gwei =
  # Spec function recalculates total_balance every time, which creates an
  # O(n^2) situation.
  let effective_balance = state.validators[index].effective_balance
  effective_balance * BASE_REWARD_FACTOR div
    integer_squareroot(total_balance) div BASE_REWARDS_PER_EPOCH

func get_proposer_reward(state: BeaconStateView, attesting_index: ValidatorIndex,
    total_balance: Gwei): Gwei =
  # Spec version recalculates get_total_active_balance(state) quadratically
  get_base_reward(state, attesting_index, total_balance) div PROPOSER_REWARD_QUOTIENT

func get_finality_delay(state: BeaconStateView): uint64 =
  get_previous_epoch(state) - state.finalized_checkpoint.epoch

func is_in_inactivity_leak(state: BeaconStateView): bool =
  get_finality_delay(state) > MIN_EPOCHS_TO_INACTIVITY_PENALTY

iterator get_eligible_validator_indices(state: BeaconStateView): ValidatorIndex =
  # TODO probably iterates multiple times over epoch transitions
  let previous_epoch = get_previous_epoch(state)
  for idx, v in state.validators:
    if is_active_validator(v, previous_epoch) or
        (v.slashed and previous_epoch + 1 < v.withdrawable_epoch):
      yield idx.ValidatorIndex

func get_attestation_component_deltas(state: BeaconStateView,
                                      attestations: seq[PendingAttestation],
                                      total_balance: Gwei,
                                      cache: var StateCache,
                                      ): tuple[a: seq[Gwei], b: seq[Gwei]] =
  # Helper with shared logic for use by get source, target, and head deltas
  # functions
  var
    rewards = repeat(0'u64, len(state.validators))
    penalties = repeat(0'u64, len(state.validators))
  let
    unslashed_attesting_indices =
      get_unslashed_attesting_indices(state, attestations, cache)
    attesting_balance = get_total_balance(state, unslashed_attesting_indices)

  for index in get_eligible_validator_indices(state):
    if index in unslashed_attesting_indices:
      const increment = EFFECTIVE_BALANCE_INCREMENT  # \
      # Factored out from balance totals to avoid uint64 overflow

      if is_in_inactivity_leak(state):
        # Since full base reward will be canceled out by inactivity penalty deltas,
        # optimal participation receives full base reward compensation here.
        rewards[index] += get_base_reward(state, index, total_balance)
      else:
        let reward_numerator = get_base_reward(state, index, total_balance) * (attesting_balance div increment)
        rewards[index] += reward_numerator div (total_balance div increment)
    else:
       penalties[index] += get_base_reward(state, index, total_balance)
  (rewards, penalties)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#components-of-attestation-deltas
# These is slightly refactored to calculate total_balance once.
func get_source_deltas*(
    state: BeaconStateView, total_balance: Gwei, cache: var StateCache):
    tuple[a: seq[Gwei], b: seq[Gwei]] =
  # Return attester micro-rewards/penalties for source-vote for each validator.

  get_attestation_component_deltas(
    state,
    get_matching_source_attestations(state, get_previous_epoch(state)),
    total_balance, cache)

func get_target_deltas*(
    state: BeaconStateView, total_balance: Gwei, cache: var StateCache):
    tuple[a: seq[Gwei], b: seq[Gwei]] =
  # Return attester micro-rewards/penalties for target-vote for each validator.
  let matching_target_attestations =
    get_matching_target_attestations(state, get_previous_epoch(state))
  get_attestation_component_deltas(
    state, matching_target_attestations, total_balance, cache)

func get_head_deltas*(
    state: BeaconStateView, total_balance: Gwei, cache: var StateCache):
    tuple[a: seq[Gwei], b: seq[Gwei]] =
  # Return attester micro-rewards/penalties for head-vote for each validator.
  let matching_head_attestations =
    get_matching_head_attestations(state, get_previous_epoch(state))
  get_attestation_component_deltas(
    state, matching_head_attestations, total_balance, cache)

func get_inclusion_delay_deltas*(
    state: BeaconStateView, total_balance: Gwei, cache: var StateCache):
    seq[Gwei] =
  # Return proposer and inclusion delay micro-rewards/penalties for each validator.
  var
    rewards = repeat(0'u64, len(state.validators))
    matching_source_attestations =
      get_matching_source_attestations(state, get_previous_epoch(state))

  # Translation of attestation = min([...])
  # The spec (pseudo)code defines this in terms of Python's min(), which per
  # https://docs.python.org/3/library/functions.html#min:
  # If multiple items are minimal, the function returns the first one
  # encountered.
  # Therefore, this approach depends on Nim's default sort being stable, per
  # https://nim-lang.org/docs/algorithm.html#sort,openArray[T],proc(T,T) via
  # "The sorting is guaranteed to be stable and the worst case is guaranteed
  # to be O(n log n)."
  matching_source_attestations.sort do (x, y: PendingAttestation) -> int:
    cmp(x.inclusion_delay, y.inclusion_delay)

  # Order/indices in source_attestation_attesting_indices matches sorted order
  let source_attestation_attesting_indices = mapIt(
    matching_source_attestations,
    get_attesting_indices(state, it.data, it.aggregation_bits, cache))

  for index in get_unslashed_attesting_indices(
      state, matching_source_attestations, cache):
    for source_attestation_index, attestation in matching_source_attestations:
      if index in
          source_attestation_attesting_indices[source_attestation_index]:
        rewards[attestation.proposer_index] +=
          get_proposer_reward(state, index, total_balance)
        let max_attester_reward =
          get_base_reward(state, index, total_balance) -
            get_proposer_reward(state, index, total_balance)
        rewards[index] +=
          Gwei(max_attester_reward div attestation.inclusion_delay)
        break

  # No penalties associated with inclusion delay
  # Spec constructs both and returns both; this doesn't
  rewards

func get_inactivity_penalty_deltas*(
    state: BeaconStateView, total_balance: Gwei, cache: var StateCache):
    seq[Gwei] =
  # Return inactivity reward/penalty deltas for each validator.
  var penalties = repeat(0'u64, len(state.validators))
  if is_in_inactivity_leak(state):
    let
      matching_target_attestations =
        get_matching_target_attestations(state, get_previous_epoch(state))
      matching_target_attesting_indices =
        get_unslashed_attesting_indices(state, matching_target_attestations, cache)
    for index in get_eligible_validator_indices(state):
      # If validator is performing optimally this cancels all rewards for a neutral balance
      let base_reward = get_base_reward(state, index, total_balance)
      penalties[index] +=
        Gwei(BASE_REWARDS_PER_EPOCH * base_reward -
          get_proposer_reward(state, index, total_balance))
      # matching_target_attesting_indices is a HashSet
      if index notin matching_target_attesting_indices:
        let effective_balance = state.validators[index].effective_balance
        penalties[index] +=
          Gwei(effective_balance * get_finality_delay(state) div
            INACTIVITY_PENALTY_QUOTIENT)

  # No rewards associated with inactivity penalties
  # Spec constructs rewards anyway; this doesn't
  penalties

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_attestation_deltas
func get_attestation_deltas(state: BeaconStateView, cache: var StateCache):
    tuple[a: seq[Gwei], b: seq[Gwei]] =
  # Return attestation reward/penalty deltas for each validator.
  let
    total_balance = get_total_active_balance(state, cache)
    (source_rewards, source_penalties) =
      get_source_deltas(state, total_balance, cache)
    (target_rewards, target_penalties) =
      get_target_deltas(state, total_balance, cache)
    (head_rewards, head_penalties) =
      get_head_deltas(state, total_balance, cache)
    inclusion_delay_rewards =
      get_inclusion_delay_deltas(state, total_balance, cache)
    inactivity_penalties =
      get_inactivity_penalty_deltas(state, total_balance, cache)

  let rewards = mapIt(0 ..< len(state.validators),
    source_rewards[it] + target_rewards[it] + head_rewards[it] +
      inclusion_delay_rewards[it])

  let penalties = mapIt(0 ..< len(state.validators),
    source_penalties[it] + target_penalties[it] + head_penalties[it] +
      inactivity_penalties[it])

  (rewards, penalties)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#process_rewards_and_penalties
func process_rewards_and_penalties(
    state: var BeaconState, cache: var StateCache) {.nbench.}=
  if get_current_epoch(state.unsafeView()) == GENESIS_EPOCH:
    return

  let (rewards, penalties) = get_attestation_deltas(state.unsafeView(), cache)

  for i in 0 ..< len(state.validators):
    increase_balance(state, i.ValidatorIndex, rewards[i])
    decrease_balance(state, i.ValidatorIndex, penalties[i])

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#slashings
func process_slashings*(state: var BeaconState, cache: var StateCache) {.nbench.}=
  let
    epoch = get_current_epoch(state.unsafeView())
    total_balance = get_total_active_balance(state.unsafeView(), cache)

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

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#final-updates
func process_final_updates*(state: var BeaconState) {.nbench.}=
  let
    current_epoch = get_current_epoch(state.unsafeView())
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
  state.slashings[int(next_epoch mod EPOCHS_PER_SLASHINGS_VECTOR)] = 0.Gwei

  # Set randao mix
  state.randao_mixes[next_epoch mod EPOCHS_PER_HISTORICAL_VECTOR] =
    get_randao_mix(state.unsafeView(), current_epoch)

  # Set historical root accumulator
  if next_epoch mod (SLOTS_PER_HISTORICAL_ROOT div SLOTS_PER_EPOCH) == 0:
    # Equivalent to hash_tree_root(foo: HistoricalBatch), but without using
    # significant additional stack or heap.
    # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#historicalbatch
    # In response to https://github.com/status-im/nim-beacon-chain/issues/921
    state.historical_roots.add hash_tree_root(
      [hash_tree_root(state.block_roots), hash_tree_root(state.state_roots)])

  # Rotate current/previous epoch attestations
  state.previous_epoch_attestations = state.current_epoch_attestations
  state.current_epoch_attestations = default(type state.current_epoch_attestations)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#epoch-processing
proc process_epoch*(state: var BeaconState, updateFlags: UpdateFlags,
    per_epoch_cache: var StateCache) {.nbench.} =
  let currentEpoch = get_current_epoch(state.unsafeView())
  trace "process_epoch",
    current_epoch = currentEpoch

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#justification-and-finalization
  process_justification_and_finalization(state, per_epoch_cache, updateFlags)

  # state.slot hasn't been incremented yet.
  if verifyFinalization in updateFlags and currentEpoch >= 2:
    doAssert state.current_justified_checkpoint.epoch + 2 >= currentEpoch

  if verifyFinalization in updateFlags and currentEpoch >= 3:
    # Rule 2/3/4 finalization results in the most pessimal case. The other
    # three finalization rules finalize more quickly as long as the any of
    # the finalization rules triggered.
    doAssert state.finalized_checkpoint.epoch + 3 >= currentEpoch

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#rewards-and-penalties-1
  process_rewards_and_penalties(state, per_epoch_cache)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#registry-updates
  process_registry_updates(state, per_epoch_cache)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#slashings
  process_slashings(state, per_epoch_cache)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#final-updates
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
