# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition - epoch processing, as described in
# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#epoch-processing and
# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/beacon-chain.md#epoch-processing
#
# The entry point is `process_epoch`, which is at the bottom of this file.
#
# General notes about the code:
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * When updating the code, add TODO sections to mark where there are clear
#   improvements to be made - other than that, keep things similar to spec unless
#   motivated by security or performance considerations

{.push raises: [Defect].}

import
  std/[algorithm, math],
  stew/bitops2, chronicles,
  ../extras,
  ./datatypes/[phase0, altair, merge],
  "."/[beaconstate, eth2_merkleization, helpers, validator],
  ../../nbench/bench_lab

export extras, phase0, altair

# Logging utilities
# --------------------------------------------------------

logScope: topics = "consens"

# Accessors that implement the max condition in `get_total_balance`:
# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#get_total_balance
template current_epoch*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT, v.current_epoch_raw)
template previous_epoch*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT, v.previous_epoch_raw)
template current_epoch_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT, v.current_epoch_attesters_raw)
template current_epoch_target_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT, v.current_epoch_target_attesters_raw)
template previous_epoch_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT, v.previous_epoch_attesters_raw)
template previous_epoch_target_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT, v.previous_epoch_target_attesters_raw)
template previous_epoch_head_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT, v.previous_epoch_head_attesters_raw)

func init*(info: var phase0.EpochInfo, state: phase0.BeaconState) =
  info.total_balances = TotalBalances()
  info.statuses.setLen(state.validators.len)

  for i in 0..<state.validators.len:
    let v = unsafeAddr state.validators[i]
    var flags: set[RewardFlags]

    if v[].slashed:
      flags.incl(RewardFlags.isSlashed)
    if state.get_current_epoch() >= v[].withdrawable_epoch:
      flags.incl RewardFlags.canWithdrawInCurrentEpoch

    if v[].is_active_validator(state.get_current_epoch()):
      info.total_balances.current_epoch_raw += v[].effective_balance

    if v[].is_active_validator(state.get_previous_epoch()):
      flags.incl RewardFlags.isActiveInPreviousEpoch
      info.total_balances.previous_epoch_raw += v[].effective_balance

    info.statuses[i] = RewardStatus(
      current_epoch_effective_balance: v[].effective_balance,
      flags: flags,
    )

func add(a: var RewardDelta, b: RewardDelta) =
  a.rewards += b.rewards
  a.penalties += b.penalties

func process_attestation(
    info: var phase0.EpochInfo, state: phase0.BeaconState, a: PendingAttestation,
    cache: var StateCache) =
  # Collect information about the attestation
  var
    flags: set[RewardFlags]
    is_previous_epoch_attester: Option[InclusionInfo]

  if a.data.target.epoch == state.get_current_epoch():
    flags.incl RewardFlags.isCurrentEpochAttester

    if a.data.target.root == get_block_root(state, state.get_current_epoch()):
      flags.incl RewardFlags.isCurrentEpochTargetAttester

  elif a.data.target.epoch == state.get_previous_epoch():
    is_previous_epoch_attester = some(InclusionInfo(
      delay: a.inclusion_delay,
      proposer_index: a.proposer_index,
    ))

    if a.data.target.root == get_block_root(state, state.get_previous_epoch()):
      flags.incl RewardFlags.isPreviousEpochTargetAttester

      if a.data.beacon_block_root == get_block_root_at_slot(state, a.data.slot):
        flags.incl RewardFlags.isPreviousEpochHeadAttester

  # Update the cache for all participants
  for validator_index in get_attesting_indices(
      state, a.data, a.aggregation_bits, cache):
    template v(): untyped = info.statuses[validator_index]

    v.flags = v.flags + flags

    if is_previous_epoch_attester.isSome:
      if v.is_previous_epoch_attester.isSome:
        if is_previous_epoch_attester.get().delay <
            v.is_previous_epoch_attester.get().delay:
          v.is_previous_epoch_attester = is_previous_epoch_attester
      else:
        v.is_previous_epoch_attester = is_previous_epoch_attester

func process_attestations*(
    info: var phase0.EpochInfo, state: phase0.BeaconState, cache: var StateCache) =
  # Walk state attestations and update the status information
  for a in state.previous_epoch_attestations:
    process_attestation(info, state, a, cache)
  for a in state.current_epoch_attestations:
    process_attestation(info, state, a, cache)

  for idx, v in info.statuses:
    if v.flags.contains RewardFlags.isSlashed:
      continue

    let validator_balance = state.validators[idx].effective_balance

    if v.flags.contains RewardFlags.isCurrentEpochAttester:
      info.total_balances.current_epoch_attesters_raw += validator_balance

    if v.flags.contains RewardFlags.isCurrentEpochTargetAttester:
      info.total_balances.current_epoch_target_attesters_raw += validator_balance

    if v.is_previous_epoch_attester.isSome():
      info.total_balances.previous_epoch_attesters_raw += validator_balance

    if v.flags.contains RewardFlags.isPreviousEpochTargetAttester:
      info.total_balances.previous_epoch_target_attesters_raw += validator_balance

    if v.flags.contains RewardFlags.isPreviousEpochHeadAttester:
      info.total_balances.previous_epoch_head_attesters_raw += validator_balance

# https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/phase0/beacon-chain.md#helpers
# get_eligible_validator_indices
func is_eligible_validator*(validator: RewardStatus): bool =
  validator.flags.contains(RewardFlags.isActiveInPreviousEpoch) or
    (validator.flags.contains(RewardFlags.isSlashed) and not
      (validator.flags.contains RewardFlags.canWithdrawInCurrentEpoch))

func is_eligible_validator*(validator: Validator, previous_epoch: Epoch): bool =
  is_active_validator(validator, previous_epoch) or
    (validator.slashed and previous_epoch + 1 < validator.withdrawable_epoch)

func is_eligible_validator*(validator: ParticipationInfo): bool =
  validator.flags.contains(ParticipationFlag.eligible)

# Spec
# --------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/beacon-chain.md#get_unslashed_participating_indices
# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#get_total_balance
func get_unslashed_participating_balances*(state: altair.BeaconState | merge.BeaconState):
    UnslashedParticipatingBalances =
  let
    previous_epoch = get_previous_epoch(state)
    current_epoch = get_current_epoch(state)
  var res: UnslashedParticipatingBalances

  for validator_index in 0'u64 ..< state.validators.lenu64:
    let
      is_active_current_epoch = is_active_validator(
        state.validators[validator_index], current_epoch)
      validator_effective_balance =
        state.validators[validator_index].effective_balance

    if is_active_current_epoch:
      # Active balance counted also for slashed validators
      res.current_epoch += validator_effective_balance

    if state.validators[validator_index].slashed:
      continue

    let
      is_active_previous_epoch = is_active_validator(
        state.validators[validator_index], previous_epoch)
      previous_epoch_participation =
        state.previous_epoch_participation[validator_index]

    if is_active_previous_epoch:
      for flag_index in 0 ..< PARTICIPATION_FLAG_WEIGHTS.len:
        if has_flag(previous_epoch_participation, flag_index):
          res.previous_epoch[flag_index] += validator_effective_balance

    # Only TIMELY_TARGET_FLAG_INDEX is used with the current epoch in Altair
    # and Merge
    if is_active_current_epoch and has_flag(
        state.current_epoch_participation[validator_index],
        TIMELY_TARGET_FLAG_INDEX):
      res.current_epoch_TIMELY_TARGET += validator_effective_balance

  for flag_index in 0 ..< PARTICIPATION_FLAG_WEIGHTS.len:
    res.previous_epoch[flag_index] =
      max(EFFECTIVE_BALANCE_INCREMENT, res.previous_epoch[flag_index])

  res.current_epoch_TIMELY_TARGET =
    max(EFFECTIVE_BALANCE_INCREMENT, res.current_epoch_TIMELY_TARGET)

  res.current_epoch = max(EFFECTIVE_BALANCE_INCREMENT, res.current_epoch)

  res

func is_unslashed_participating_index(
    state: altair.BeaconState | merge.BeaconState, flag_index: int, epoch: Epoch,
    validator_index: ValidatorIndex): bool =
  doAssert epoch in [get_previous_epoch(state), get_current_epoch(state)]
  # TODO hoist this conditional
  let epoch_participation =
    if epoch == get_current_epoch(state):
      unsafeAddr state.current_epoch_participation
    else:
      unsafeAddr state.previous_epoch_participation

  is_active_validator(state.validators[validator_index], epoch) and
    has_flag(epoch_participation[].asSeq()[validator_index], flag_index) and
    not state.validators[validator_index].slashed

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#justification-and-finalization
proc process_justification_and_finalization*(state: var phase0.BeaconState,
    total_balances: TotalBalances, flags: UpdateFlags = {}) {.nbench.} =
  # Initial FFG checkpoint values have a `0x00` stub for `root`.
  # Skip FFG updates in the first two epochs to avoid corner cases that might
  # result in modifying this stub.
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

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#misc
  const JUSTIFICATION_BITS_LENGTH = 4

  state.justification_bits = (state.justification_bits shl 1) and
    cast[uint8]((2^JUSTIFICATION_BITS_LENGTH) - 1)

  let total_active_balance = total_balances.current_epoch
  if total_balances.previous_epoch_target_attesters * 3 >=
      total_active_balance * 2:
    state.current_justified_checkpoint =
      Checkpoint(epoch: previous_epoch,
                 root: get_block_root(state, previous_epoch))
    state.justification_bits.setBit 1

    trace "Justified with previous epoch",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.current_justified_checkpoint)
  elif verifyFinalization in flags:
    warn "Low attestation participation in previous epoch",
      total_balances, epoch = get_current_epoch(state)

  if total_balances.current_epoch_target_attesters * 3 >=
      total_active_balance * 2:
    state.current_justified_checkpoint =
      Checkpoint(epoch: current_epoch,
                 root: get_block_root(state, current_epoch))
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

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/beacon-chain.md#justification-and-finalization
# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#justification-and-finalization
# TODO merge these things -- effectively, the phase0 process_justification_and_finalization is mostly a stub in this world
proc weigh_justification_and_finalization(state: var (altair.BeaconState | merge.BeaconState),
                                          total_active_balance: Gwei,
                                          previous_epoch_target_balance: Gwei,
                                          current_epoch_target_balance: Gwei,
                                          flags: UpdateFlags = {}) =
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

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#misc
  const JUSTIFICATION_BITS_LENGTH = 4

  state.justification_bits = (state.justification_bits shl 1) and
    cast[uint8]((2^JUSTIFICATION_BITS_LENGTH) - 1)

  if previous_epoch_target_balance * 3 >= total_active_balance * 2:
    state.current_justified_checkpoint =
      Checkpoint(epoch: previous_epoch,
                 root: get_block_root(state, previous_epoch))
    state.justification_bits.setBit 1

    trace "Justified with previous epoch",
      current_epoch = current_epoch,
      checkpoint = shortLog(state.current_justified_checkpoint)
  elif verifyFinalization in flags:
    warn "Low attestation participation in previous epoch",
      total_active_balance,
      previous_epoch_target_balance,
      current_epoch_target_balance,
      epoch = get_current_epoch(state)

  if current_epoch_target_balance * 3 >= total_active_balance * 2:
    state.current_justified_checkpoint =
      Checkpoint(epoch: current_epoch,
                 root: get_block_root(state, current_epoch))
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

proc process_justification_and_finalization*(state: var (altair.BeaconState | merge.BeaconState),
    balances: UnslashedParticipatingBalances,
    flags: UpdateFlags = {}) {.nbench.} =
  # Initial FFG checkpoint values have a `0x00` stub for `root`.
  # Skip FFG updates in the first two epochs to avoid corner cases that might
  # result in modifying this stub.
  if get_current_epoch(state) <= GENESIS_EPOCH + 1:
    return

  # These ultimately differ from phase0 only in these lines, with the phase 0
  # version effectively embedding weigh_justification_and_finalization(), for
  # historical reasons.
  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.2/specs/phase0/beacon-chain.md#justification-and-finalization
  weigh_justification_and_finalization(
    state, balances.current_epoch,
    balances.previous_epoch[TIMELY_TARGET_FLAG_INDEX],
    balances.current_epoch_TIMELY_TARGET, flags)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#helpers
func get_base_reward_sqrt*(state: phase0.BeaconState, index: ValidatorIndex,
    total_balance_sqrt: auto): Gwei =
  # Spec function recalculates total_balance every time, which creates an
  # O(n^2) situation.
  let effective_balance = state.validators.asSeq()[index].effective_balance
  effective_balance * BASE_REWARD_FACTOR div
    total_balance_sqrt div BASE_REWARDS_PER_EPOCH

func get_proposer_reward(base_reward: Gwei): Gwei =
  # Spec version recalculates get_total_active_balance(state) quadratically
  base_reward div PROPOSER_REWARD_QUOTIENT

func is_in_inactivity_leak(finality_delay: uint64): bool =
  finality_delay > MIN_EPOCHS_TO_INACTIVITY_PENALTY

func get_finality_delay(state: SomeBeaconState): uint64 =
  get_previous_epoch(state) - state.finalized_checkpoint.epoch

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-alpha.8/specs/phase0/beacon-chain.md#rewards-and-penalties-1
func is_in_inactivity_leak(state: altair.BeaconState | merge.BeaconState): bool =
  # TODO remove this, see above
  get_finality_delay(state) > MIN_EPOCHS_TO_INACTIVITY_PENALTY

func get_attestation_component_delta(is_unslashed_attester: bool,
                                     attesting_balance: Gwei,
                                     total_balance: Gwei,
                                     base_reward: uint64,
                                     finality_delay: uint64): RewardDelta =
  # Helper with shared logic for use by get source, target, and head deltas
  # functions
  if is_unslashed_attester:
    if is_in_inactivity_leak(finality_delay):
      # Since full base reward will be canceled out by inactivity penalty deltas,
      # optimal participation receives full base reward compensation here.
      RewardDelta(rewards: base_reward)
    else:
      let reward_numerator =
        base_reward * (attesting_balance div EFFECTIVE_BALANCE_INCREMENT)
      RewardDelta(rewards:
        reward_numerator div (total_balance div EFFECTIVE_BALANCE_INCREMENT))
  else:
    RewardDelta(penalties: base_reward)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/phase0/beacon-chain.md#components-of-attestation-deltas
func get_source_delta*(validator: RewardStatus,
                       base_reward: uint64,
                       total_balances: TotalBalances,
                       finality_delay: uint64): RewardDelta =
  ## Return attester micro-rewards/penalties for source-vote for each validator.
  get_attestation_component_delta(
    validator.is_previous_epoch_attester.isSome() and
      not (validator.flags.contains RewardFlags.isSlashed),
    total_balances.previous_epoch_attesters,
    total_balances.current_epoch,
    base_reward,
    finality_delay)

func get_target_delta*(validator: RewardStatus,
                       base_reward: uint64,
                       total_balances: TotalBalances,
                       finality_delay: uint64): RewardDelta =
  ## Return attester micro-rewards/penalties for target-vote for each validator.
  get_attestation_component_delta(
    validator.flags.contains(RewardFlags.isPreviousEpochTargetAttester) and
      not (validator.flags.contains(RewardFlags.isSlashed)),
    total_balances.previous_epoch_target_attesters,
    total_balances.current_epoch,
    base_reward,
    finality_delay)

func get_head_delta*(validator: RewardStatus,
                     base_reward: uint64,
                     total_balances: TotalBalances,
                     finality_delay: uint64): RewardDelta =
  ## Return attester micro-rewards/penalties for head-vote for each validator.
  get_attestation_component_delta(
    validator.flags.contains(RewardFlags.isPreviousEpochHeadAttester) and
      ((not validator.flags.contains(RewardFlags.isSlashed))),
    total_balances.previous_epoch_head_attesters,
    total_balances.current_epoch,
    base_reward,
    finality_delay)

func get_inclusion_delay_delta*(validator: RewardStatus,
                                base_reward: uint64):
                                  (RewardDelta, Option[(uint64, RewardDelta)]) =
  ## Return proposer and inclusion delay micro-rewards/penalties for each validator.
  if validator.is_previous_epoch_attester.isSome() and ((not validator.flags.contains(RewardFlags.isSlashed))):
    let
      inclusion_info = validator.is_previous_epoch_attester.get()
      proposer_reward = get_proposer_reward(base_reward)
      proposer_delta = RewardDelta(rewards: proposer_reward)

    let
      max_attester_reward = base_reward - proposer_reward
      delta = RewardDelta(rewards: max_attester_reward div inclusion_info.delay)
      proposer_index = inclusion_info.proposer_index;
    return (delta, some((proposer_index, proposer_delta)))

func get_inactivity_penalty_delta*(validator: RewardStatus,
                                   base_reward: Gwei,
                                   finality_delay: uint64): RewardDelta =
  ## Return inactivity reward/penalty deltas for each validator.
  var delta: RewardDelta

  if is_in_inactivity_leak(finality_delay):
    # If validator is performing optimally this cancels all rewards for a neutral balance
    delta.penalties +=
      BASE_REWARDS_PER_EPOCH * base_reward - get_proposer_reward(base_reward)

    # Additionally, all validators whose FFG target didn't match are penalized extra
    # This condition is equivalent to this condition from the spec:
    # `index not in get_unslashed_attesting_indices(state, matching_target_attestations)`
    if (validator.flags.contains(RewardFlags.isSlashed)) or
        ((not validator.flags.contains(RewardFlags.isPreviousEpochTargetAttester))):
      delta.penalties +=
        validator.current_epoch_effective_balance * finality_delay div
          INACTIVITY_PENALTY_QUOTIENT

  delta

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#get_attestation_deltas
func get_attestation_deltas(state: phase0.BeaconState, info: var phase0.EpochInfo) =
  ## Update rewards with attestation reward/penalty deltas for each validator.

  let
    finality_delay = get_finality_delay(state)
    total_balance = info.total_balances.current_epoch
    total_balance_sqrt = integer_squareroot(total_balance)
  # Filter out ineligible validators. All sub-functions of the spec do this
  # except for `get_inclusion_delay_deltas`. It's safe to do so here because
  # any validator that is in the unslashed indices of the matching source
  # attestations is active, and therefore eligible.
  for index, validator in info.statuses.mpairs():
    if not is_eligible_validator(validator):
      continue

    let
      base_reward = get_base_reward_sqrt(
        state, index.ValidatorIndex, total_balance_sqrt)

    let
      source_delta = get_source_delta(
        validator, base_reward, info.total_balances, finality_delay)
      target_delta = get_target_delta(
        validator, base_reward, info.total_balances, finality_delay)
      head_delta = get_head_delta(
        validator, base_reward, info.total_balances, finality_delay)
      (inclusion_delay_delta, proposer_delta) =
        get_inclusion_delay_delta(validator, base_reward)
      inactivity_delta = get_inactivity_penalty_delta(
        validator, base_reward, finality_delay)

    validator.delta.add source_delta
    validator.delta.add target_delta
    validator.delta.add head_delta
    validator.delta.add inclusion_delay_delta
    validator.delta.add inactivity_delta

    if proposer_delta.isSome:
      let proposer_index = proposer_delta.get()[0]
      if proposer_index < info.statuses.lenu64:
        info.statuses[proposer_index].delta.add(
          proposer_delta.get()[1])

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/beacon-chain.md#get_base_reward
func get_base_reward_increment(
    state: altair.BeaconState | merge.BeaconState, index: ValidatorIndex,
    base_reward_per_increment: Gwei): Gwei =
  ## Return the base reward for the validator defined by ``index`` with respect
  ## to the current ``state``.
  let increments =
    state.validators[index].effective_balance div EFFECTIVE_BALANCE_INCREMENT
  increments * base_reward_per_increment

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/beacon-chain.md#get_flag_index_deltas
iterator get_flag_index_deltas(
    state: altair.BeaconState | merge.BeaconState, flag_index: int,
    base_reward_per_increment: Gwei,
    info: altair.EpochInfo):
    (ValidatorIndex, RewardDelta) =
  ## Return the deltas for a given ``flag_index`` by scanning through the
  ## participation flags.
  let
    previous_epoch = get_previous_epoch(state)
    weight = PARTICIPATION_FLAG_WEIGHTS[flag_index].uint64 # safe
    unslashed_participating_balance =
      info.balances.previous_epoch[flag_index]
    unslashed_participating_increments =
      unslashed_participating_balance div EFFECTIVE_BALANCE_INCREMENT
    active_increments =
      info.balances.current_epoch div EFFECTIVE_BALANCE_INCREMENT

  for index in 0 ..< state.validators.len:
    if not is_eligible_validator(info.validators[index]):
      continue

    template vidx: ValidatorIndex = index.ValidatorIndex
    let base_reward = get_base_reward_increment(state, vidx, base_reward_per_increment)
    yield
      if is_unslashed_participating_index(
          state, flag_index, previous_epoch, vidx):
        if not is_in_inactivity_leak(state):
          let reward_numerator =
            base_reward * weight * unslashed_participating_increments
          (vidx, RewardDelta(
            rewards: reward_numerator div (active_increments * WEIGHT_DENOMINATOR),
            penalties: 0.Gwei))
        else:
          (vidx, RewardDelta(rewards: 0.Gwei, penalties: 0.Gwei))
      elif flag_index != TIMELY_HEAD_FLAG_INDEX:
        (vidx, RewardDelta(
          rewards: 0.Gwei,
          penalties: base_reward * weight div WEIGHT_DENOMINATOR))
      else:
        (vidx, RewardDelta(rewards: 0.Gwei, penalties: 0.Gwei))

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/beacon-chain.md#modified-get_inactivity_penalty_deltas
iterator get_inactivity_penalty_deltas(
    cfg: RuntimeConfig, state: altair.BeaconState | merge.BeaconState,
    info: altair.EpochInfo):
    (ValidatorIndex, Gwei) =
  ## Return the inactivity penalty deltas by considering timely target
  ## participation flags and inactivity scores.
  let
    penalty_denominator =
      cfg.INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_ALTAIR
    previous_epoch = get_previous_epoch(state)

  for index in 0 ..< state.validators.len:
    if not is_eligible_validator(info.validators[index]):
      continue

    template vidx: untyped = index.ValidatorIndex
    if not is_unslashed_participating_index(
        state, TIMELY_TARGET_FLAG_INDEX, previous_epoch, vidx):
      let
        penalty_numerator = state.validators[index].effective_balance *
          state.inactivity_scores[index]
      yield (vidx, Gwei(penalty_numerator div penalty_denominator))

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#rewards-and-penalties-1
func process_rewards_and_penalties(
    state: var phase0.BeaconState, info: var phase0.EpochInfo) {.nbench.} =
  # No rewards are applied at the end of `GENESIS_EPOCH` because rewards are
  # for work done in the previous epoch
  doAssert info.statuses.len == state.validators.len

  if get_current_epoch(state) == GENESIS_EPOCH:
    return

  get_attestation_deltas(state, info)

  # Here almost all balances are updated (assuming most validators are active) -
  # clearing the cache becomes a bottleneck if done item by item because of the
  # recursive nature of cache clearing - instead, we clear the whole cache then
  # update the raw list directly
  state.balances.clearCache()
  for idx, v in info.statuses:
    var balance = state.balances.asSeq()[idx]
    increase_balance(balance, v.delta.rewards)
    decrease_balance(balance, v.delta.penalties)
    state.balances.asSeq()[idx] = balance

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/beacon-chain.md#rewards-and-penalties
func process_rewards_and_penalties(
    cfg: RuntimeConfig, state: var (altair.BeaconState | merge.BeaconState),
    info: var altair.EpochInfo)
    {.nbench.} =
  if get_current_epoch(state) == GENESIS_EPOCH:
    return

  let
    total_active_balance = info.balances.current_epoch
    base_reward_per_increment = get_base_reward_per_increment(
      total_active_balance)

  doAssert state.validators.len() == info.validators.len()
  for flag_index in 0 ..< PARTICIPATION_FLAG_WEIGHTS.len:
    for validator_index, delta in get_flag_index_deltas(
        state, flag_index, base_reward_per_increment, info):
      info.validators[validator_index].delta.add(delta)

  for validator_index, penalty in get_inactivity_penalty_deltas(
      cfg, state, info):
    info.validators[validator_index].delta.penalties += penalty

  # Here almost all balances are updated (assuming most validators are active) -
  # clearing the cache becomes a bottleneck if done item by item because of the
  # recursive nature of cache clearing - instead, we clear the whole cache then
  # update the raw list directly
  state.balances.clearCache()
  for index in 0 ..< len(state.validators):
    var balance = state.balances.asSeq()[index]
    increase_balance(balance, info.validators[index].delta.rewards)
    decrease_balance(balance, info.validators[index].delta.penalties)
    state.balances.asSeq()[index] = balance

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#registry-updates
func process_registry_updates*(
    cfg: RuntimeConfig, state: var SomeBeaconState, cache: var StateCache) {.nbench.} =
  ## Process activation eligibility and ejections

  # Make visible, e.g.,
  # https://github.com/status-im/nimbus-eth2/pull/608
  # https://github.com/sigp/lighthouse/pull/657
  let epoch {.used.} = get_current_epoch(state)
  trace "process_registry_updates validator balances",
    balances=state.balances,
    active_validator_indices=get_active_validator_indices(state, epoch),
    epoch=epoch

  # is_active_validator(...) is activation_epoch <= epoch < exit_epoch,
  # and changes here to either activation_epoch or exit_epoch only take
  # effect with a compute_activation_exit_epoch(...) delay of, based on
  # the current epoch, 1 + MAX_SEED_LOOKAHEAD epochs ahead. Thus caches
  # remain valid for this epoch through though this function along with
  # the rest of the epoch transition.
  for index in 0..<state.validators.len():
    if is_eligible_for_activation_queue(state.validators.asSeq()[index]):
      state.validators[index].activation_eligibility_epoch =
        get_current_epoch(state) + 1

    if is_active_validator(state.validators.asSeq()[index], get_current_epoch(state)) and
        state.validators.asSeq()[index].effective_balance <= cfg.EJECTION_BALANCE:
      initiate_validator_exit(cfg, state, index.ValidatorIndex, cache)

  ## Queue validators eligible for activation and not dequeued for activation
  var activation_queue : seq[tuple[a: Epoch, b: int]] = @[]
  for index in 0..<state.validators.len():
    let validator = unsafeAddr state.validators.asSeq()[index]
    if is_eligible_for_activation(state, validator[]):
      activation_queue.add (
        validator[].activation_eligibility_epoch, index)

  activation_queue.sort(system.cmp)

  ## Dequeued validators for activation up to churn limit (without resetting
  ## activation epoch)
  let churn_limit = get_validator_churn_limit(cfg, state, cache)
  for i, epoch_and_index in activation_queue:
    if i.uint64 >= churn_limit:
      break
    let
      (_, index) = epoch_and_index
    state.validators[index].activation_epoch =
      compute_activation_exit_epoch(get_current_epoch(state))

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/altair/beacon-chain.md#slashings
func process_slashings*(state: var SomeBeaconState, total_balance: Gwei) {.nbench.} =
  let
    epoch = get_current_epoch(state)
    multiplier =
      # tradeoff here about interleaving phase0/altair, but for these
      # single-constant changes...
      uint64(when state is phase0.BeaconState:
        PROPORTIONAL_SLASHING_MULTIPLIER
      elif state is altair.BeaconState or state is merge.BeaconState:
        PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR
      else:
        raiseAssert "process_slashings: incorrect BeaconState type")
    adjusted_total_slashing_balance =
      min(sum(state.slashings.data) * multiplier, total_balance)

  for index in 0..<state.validators.len:
    let validator = unsafeAddr state.validators.asSeq()[index]
    if validator[].slashed and epoch + EPOCHS_PER_SLASHINGS_VECTOR div 2 ==
        validator[].withdrawable_epoch:
      const increment = EFFECTIVE_BALANCE_INCREMENT # Factored out from penalty
                                                    # numerator to avoid uint64 overflow
      let penalty_numerator =
        validator[].effective_balance div increment *
        adjusted_total_slashing_balance
      let penalty = penalty_numerator div total_balance * increment
      decrease_balance(state, index.ValidatorIndex, penalty)

# https://github.com/ethereum/consensus-specs/blob/34cea67b91/specs/phase0/beacon-chain.md#eth1-data-votes-updates
func process_eth1_data_reset*(state: var SomeBeaconState) {.nbench.} =
  let next_epoch = get_current_epoch(state) + 1

  # Reset eth1 data votes
  if next_epoch mod EPOCHS_PER_ETH1_VOTING_PERIOD == 0:
    state.eth1_data_votes = default(type state.eth1_data_votes)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#effective-balances-updates
func process_effective_balance_updates*(state: var SomeBeaconState) {.nbench.} =
  # Update effective balances with hysteresis
  for index in 0..<state.validators.len:
    let balance = state.balances.asSeq()[index]
    const
      HYSTERESIS_INCREMENT =
        EFFECTIVE_BALANCE_INCREMENT div HYSTERESIS_QUOTIENT
      DOWNWARD_THRESHOLD =
        HYSTERESIS_INCREMENT * HYSTERESIS_DOWNWARD_MULTIPLIER
      UPWARD_THRESHOLD = HYSTERESIS_INCREMENT * HYSTERESIS_UPWARD_MULTIPLIER
    let effective_balance = state.validators.asSeq()[index].effective_balance
    if balance + DOWNWARD_THRESHOLD < effective_balance or
        effective_balance + UPWARD_THRESHOLD < balance:
      state.validators[index].effective_balance =
        min(
          balance - balance mod EFFECTIVE_BALANCE_INCREMENT,
          MAX_EFFECTIVE_BALANCE)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#slashings-balances-updates
func process_slashings_reset*(state: var SomeBeaconState) {.nbench.} =
  let next_epoch = get_current_epoch(state) + 1

  # Reset slashings
  state.slashings[int(next_epoch mod EPOCHS_PER_SLASHINGS_VECTOR)] = 0.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#randao-mixes-updates
func process_randao_mixes_reset*(state: var SomeBeaconState) {.nbench.} =
  let
    current_epoch = get_current_epoch(state)
    next_epoch = current_epoch + 1

  # Set randao mix
  state.randao_mixes[next_epoch mod EPOCHS_PER_HISTORICAL_VECTOR] =
    get_randao_mix(state, current_epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#historical-roots-updates
func process_historical_roots_update*(state: var SomeBeaconState) {.nbench.} =
  ## Set historical root accumulator
  let next_epoch = get_current_epoch(state) + 1

  if next_epoch mod (SLOTS_PER_HISTORICAL_ROOT div SLOTS_PER_EPOCH) == 0:
    # Equivalent to hash_tree_root(foo: HistoricalBatch), but without using
    # significant additional stack or heap.
    # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#historicalbatch
    # In response to https://github.com/status-im/nimbus-eth2/issues/921
    if not state.historical_roots.add hash_tree_root(
        [hash_tree_root(state.block_roots), hash_tree_root(state.state_roots)]):
      raiseAssert "no more room for historical roots, so long and thanks for the fish!"

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#participation-records-rotation
func process_participation_record_updates*(state: var phase0.BeaconState) {.nbench.} =
  # Rotate current/previous epoch attestations - using swap avoids copying all
  # elements using a slow genericSeqAssign
  state.previous_epoch_attestations.clear()
  swap(state.previous_epoch_attestations, state.current_epoch_attestations)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/altair/beacon-chain.md#participation-flags-updates
func process_participation_flag_updates*(state: var (altair.BeaconState | merge.BeaconState)) =
  state.previous_epoch_participation = state.current_epoch_participation

  const zero = 0.ParticipationFlags
  for i in 0 ..< state.current_epoch_participation.len:
    state.current_epoch_participation.data[i] = zero

  # Shouldn't be wasted zeroing, because state.current_epoch_participation only
  # grows. New elements are automatically initialized to 0, as required.
  doAssert state.current_epoch_participation.data.setLen(state.validators.len)

  state.current_epoch_participation.resetCache()

# https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/altair/beacon-chain.md#sync-committee-updates
proc process_sync_committee_updates*(state: var (altair.BeaconState | merge.BeaconState)) =
  let next_epoch = get_current_epoch(state) + 1
  if next_epoch mod EPOCHS_PER_SYNC_COMMITTEE_PERIOD == 0:
    state.current_sync_committee = state.next_sync_committee
    state.next_sync_committee = get_next_sync_committee(state)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/beacon-chain.md#inactivity-scores
func process_inactivity_updates*(
    cfg: RuntimeConfig, state: var (altair.BeaconState | merge.BeaconState),
    info: altair.EpochInfo) =
  # Score updates based on previous epoch participation, skip genesis epoch
  if get_current_epoch(state) == GENESIS_EPOCH:
    return

  let
    previous_epoch = get_previous_epoch(state)  # get_eligible_validator_indices()
    not_in_inactivity_leak = not is_in_inactivity_leak(state)

  state.inactivity_scores.clearCache()
  for index in 0'u64 ..< state.validators.lenu64:
    if not is_eligible_validator(info.validators[index]):
      continue

    # Increase the inactivity score of inactive validators
    var inactivity_score = state.inactivity_scores.asSeq()[index]
    # TODO activeness already checked; remove redundant checks between
    # is_active_validator and is_unslashed_participating_index
    if is_unslashed_participating_index(
        state, TIMELY_TARGET_FLAG_INDEX, previous_epoch, index.ValidatorIndex):
      inactivity_score -= min(1'u64, inactivity_score)
    else:
      inactivity_score += cfg.INACTIVITY_SCORE_BIAS
    # Decrease the inactivity score of all eligible validators during a
    # leak-free epoch
    if not_in_inactivity_leak:
      inactivity_score -= min(INACTIVITY_SCORE_RECOVERY_RATE.uint64, inactivity_score)
    state.inactivity_scores.asSeq()[index] = inactivity_score

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#epoch-processing
proc process_epoch*(
    cfg: RuntimeConfig, state: var phase0.BeaconState, flags: UpdateFlags,
    cache: var StateCache, info: var phase0.EpochInfo) {.nbench.} =
  let currentEpoch = get_current_epoch(state)
  trace "process_epoch",
    current_epoch = currentEpoch
  init(info, state)
  info.process_attestations(state, cache)

  # https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#justification-and-finalization
  process_justification_and_finalization(state, info.total_balances, flags)

  # state.slot hasn't been incremented yet.
  if verifyFinalization in flags and currentEpoch >= 2:
    doAssert state.current_justified_checkpoint.epoch + 2 >= currentEpoch

  if verifyFinalization in flags and currentEpoch >= 3:
    # Rule 2/3/4 finalization results in the most pessimal case. The other
    # three finalization rules finalize more quickly as long as the any of
    # the finalization rules triggered.
    doAssert state.finalized_checkpoint.epoch + 3 >= currentEpoch

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#rewards-and-penalties-1
  process_rewards_and_penalties(state, info)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#registry-updates
  process_registry_updates(cfg, state, cache)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#slashings
  process_slashings(state, info.total_balances.current_epoch)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#eth1-data-votes-updates
  process_eth1_data_reset(state)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#effective-balances-updates
  process_effective_balance_updates(state)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#slashings-balances-updates
  process_slashings_reset(state)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#randao-mixes-updates
  process_randao_mixes_reset(state)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#historical-roots-updates
  process_historical_roots_update(state)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#participation-records-rotation
  process_participation_record_updates(state)

func init*(
    info: var altair.EpochInfo,
    state: altair.BeaconState | merge.BeaconState) =
  # init participation, overwriting the full structure
  info.balances = get_unslashed_participating_balances(state)
  info.validators.setLen(state.validators.len())

  let previous_epoch = get_previous_epoch(state)
  for index in 0..<state.validators.len():
    var flags: set[ParticipationFlag]
    if is_eligible_validator(state.validators[index], previous_epoch):
      flags.incl ParticipationFlag.eligible

    info.validators[index] = ParticipationInfo(
      flags: flags
    )

func init*(
    T: type altair.EpochInfo, state: altair.BeaconState | merge.BeaconState): T =
  init(result, state)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/beacon-chain.md#epoch-processing
proc process_epoch*(
    cfg: RuntimeConfig, state: var (altair.BeaconState | merge.BeaconState),
    flags: UpdateFlags, cache: var StateCache, info: var altair.EpochInfo)
    {.nbench.} =
  let currentEpoch = get_current_epoch(state)
  trace "process_epoch",
    current_epoch = currentEpoch

  info.init(state)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#justification-and-finalization
  process_justification_and_finalization(state, info.balances, flags)

  # state.slot hasn't been incremented yet.
  if verifyFinalization in flags and currentEpoch >= 2:
    doAssert state.current_justified_checkpoint.epoch + 2 >= currentEpoch

  if verifyFinalization in flags and currentEpoch >= 3:
    # Rule 2/3/4 finalization results in the most pessimal case. The other
    # three finalization rules finalize more quickly as long as the any of
    # the finalization rules triggered.
    doAssert state.finalized_checkpoint.epoch + 3 >= currentEpoch

  process_inactivity_updates(cfg, state, info)  # [New in Altair]

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/phase0/beacon-chain.md#rewards-and-penalties-1
  process_rewards_and_penalties(cfg, state, info)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#registry-updates
  process_registry_updates(cfg, state, cache)

  # https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#slashings
  process_slashings(state, info.balances.current_epoch)

  process_eth1_data_reset(state)

  process_effective_balance_updates(state)

  process_slashings_reset(state)

  process_randao_mixes_reset(state)

  process_historical_roots_update(state)

  process_participation_flag_updates(state)  # [New in Altair]

  process_sync_committee_updates(state)  # [New in Altair]
