# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# State transition - epoch processing, as described in
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#epoch-processing
# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#epoch-processing
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#epoch-processing
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#epoch-processing
#
# The entry point is `process_epoch`, which is at the bottom of this file.
#
# General notes about the code:
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * When updating the code, add TODO sections to mark where there are clear
#   improvements to be made - other than that, keep things similar to spec unless
#   motivated by security or performance considerations

import
  stew/assign2, chronicles,
  ../extras,
  "."/[beaconstate, eth2_merkleization, validator]

from std/math import sum, `^`
from stew/bitops2 import setBit
from ./datatypes/capella import
  BeaconState, HistoricalSummary, Withdrawal, WithdrawalIndex

export extras, phase0, altair

# Logging utilities
# --------------------------------------------------------

logScope: topics = "consens"

# Accessors that implement the max condition in `get_total_balance`:
# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#get_total_balance
template current_epoch*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT.Gwei, v.current_epoch_raw)
template previous_epoch*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT.Gwei, v.previous_epoch_raw)
template current_epoch_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT.Gwei, v.current_epoch_attesters_raw)
template current_epoch_target_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT.Gwei, v.current_epoch_target_attesters_raw)
template previous_epoch_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT.Gwei, v.previous_epoch_attesters_raw)
template previous_epoch_target_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT.Gwei, v.previous_epoch_target_attesters_raw)
template previous_epoch_head_attesters*(v: TotalBalances): Gwei =
  max(EFFECTIVE_BALANCE_INCREMENT.Gwei, v.previous_epoch_head_attesters_raw)

func init*(info: var phase0.EpochInfo, state: phase0.BeaconState) =
  info.balances = TotalBalances()
  info.validators.setLen(state.validators.len)

  for i in 0..<state.validators.len:
    let v = unsafeAddr state.validators[i]
    var flags: set[RewardFlags]

    if v[].slashed:
      flags.incl(RewardFlags.isSlashed)
    if state.get_current_epoch() >= v[].withdrawable_epoch:
      flags.incl RewardFlags.canWithdrawInCurrentEpoch

    if v[].is_active_validator(state.get_current_epoch()):
      info.balances.current_epoch_raw += v[].effective_balance

    if v[].is_active_validator(state.get_previous_epoch()):
      flags.incl RewardFlags.isActiveInPreviousEpoch
      info.balances.previous_epoch_raw += v[].effective_balance

    info.validators[i] = RewardStatus(
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
    is_previous_epoch_attester: Opt[InclusionInfo]

  if a.data.target.epoch == state.get_current_epoch():
    flags.incl RewardFlags.isCurrentEpochAttester

    if a.data.target.root == get_block_root(state, state.get_current_epoch()):
      flags.incl RewardFlags.isCurrentEpochTargetAttester

  elif a.data.target.epoch == state.get_previous_epoch():
    is_previous_epoch_attester = Opt.some(InclusionInfo(
      delay: a.inclusion_delay,
      proposer_index: a.proposer_index,
    ))

    if a.data.target.root == get_block_root(state, state.get_previous_epoch()):
      flags.incl RewardFlags.isPreviousEpochTargetAttester

      if a.data.beacon_block_root == get_block_root_at_slot(state, a.data.slot):
        flags.incl RewardFlags.isPreviousEpochHeadAttester

  # Update the cache for all participants
  for validator_index in get_attesting_indices_iter(
      state, a.data, a.aggregation_bits, cache):
    template v(): untyped = info.validators[validator_index]

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

  for idx, v in info.validators:
    if v.flags.contains RewardFlags.isSlashed:
      continue

    let validator_balance = state.validators[idx].effective_balance

    if v.flags.contains RewardFlags.isCurrentEpochAttester:
      info.balances.current_epoch_attesters_raw += validator_balance

    if v.flags.contains RewardFlags.isCurrentEpochTargetAttester:
      info.balances.current_epoch_target_attesters_raw += validator_balance

    if v.is_previous_epoch_attester.isSome():
      info.balances.previous_epoch_attesters_raw += validator_balance

    if v.flags.contains RewardFlags.isPreviousEpochTargetAttester:
      info.balances.previous_epoch_target_attesters_raw += validator_balance

    if v.flags.contains RewardFlags.isPreviousEpochHeadAttester:
      info.balances.previous_epoch_head_attesters_raw += validator_balance

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#helpers
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

from ./datatypes/deneb import BeaconState

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#get_unslashed_participating_indices
func get_unslashed_participating_balances*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState):
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
      for flag_index in TimelyFlag:
        if has_flag(previous_epoch_participation, flag_index):
          res.previous_epoch[flag_index] += validator_effective_balance

    # Only TIMELY_TARGET_FLAG_INDEX is used with the current epoch in Altair
    # and merge
    if is_active_current_epoch and has_flag(
        state.current_epoch_participation[validator_index],
        TIMELY_TARGET_FLAG_INDEX):
      res.current_epoch_TIMELY_TARGET += validator_effective_balance

  for flag_index in TimelyFlag:
    res.previous_epoch[flag_index] =
      max(EFFECTIVE_BALANCE_INCREMENT.Gwei, res.previous_epoch[flag_index])

  res.current_epoch_TIMELY_TARGET =
    max(EFFECTIVE_BALANCE_INCREMENT.Gwei, res.current_epoch_TIMELY_TARGET)

  res.current_epoch = max(EFFECTIVE_BALANCE_INCREMENT.Gwei, res.current_epoch)

  res

func is_unslashed_participating_index(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState,
    flag_index: TimelyFlag, epoch: Epoch, validator_index: ValidatorIndex): bool =
  doAssert epoch in [get_previous_epoch(state), get_current_epoch(state)]
  # TODO hoist this conditional
  let epoch_participation =
    if epoch == get_current_epoch(state):
      unsafeAddr state.current_epoch_participation
    else:
      unsafeAddr state.previous_epoch_participation

  is_active_validator(state.validators[validator_index], epoch) and
    has_flag(epoch_participation[].item(validator_index), flag_index) and
    not state.validators[validator_index].slashed

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#justification-and-finalization
type FinalityState = object
  slot: Slot
  current_epoch_ancestor_root: Eth2Digest
  previous_epoch_ancestor_root: Eth2Digest
  justification_bits: JustificationBits
  previous_justified_checkpoint: Checkpoint
  current_justified_checkpoint: Checkpoint
  finalized_checkpoint: Checkpoint

func toFinalityState(state: ForkyBeaconState): FinalityState =
  let
    current_epoch = get_current_epoch(state)
    previous_epoch = get_previous_epoch(state)
  FinalityState(
    slot: state.slot,
    current_epoch_ancestor_root:
      if state.slot > current_epoch.start_slot:
        get_block_root(state, current_epoch)
      else:
        ZERO_HASH,
    previous_epoch_ancestor_root:
      if state.slot > previous_epoch.start_slot:
        get_block_root(state, previous_epoch)
      else:
        ZERO_HASH,
    justification_bits:
      state.justification_bits,
    previous_justified_checkpoint:
      state.previous_justified_checkpoint,
    current_justified_checkpoint:
      state.current_justified_checkpoint,
    finalized_checkpoint:
      state.finalized_checkpoint)

func get_current_epoch(state: FinalityState): Epoch =
  state.slot.epoch

func get_previous_epoch(state: FinalityState): Epoch =
  get_previous_epoch(get_current_epoch(state))

func get_block_root(state: FinalityState, epoch: Epoch): Eth2Digest =
  doAssert state.slot > epoch.start_slot
  if epoch == get_current_epoch(state):
    state.current_epoch_ancestor_root
  else:
    doAssert epoch == get_previous_epoch(state)
    state.previous_epoch_ancestor_root

type
  JustificationAndFinalizationInfo = object
    previous_justified_checkpoint: Checkpoint
    current_justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    justification_bits: JustificationBits

proc weigh_justification_and_finalization(
    state: ForkyBeaconState | FinalityState,
    total_active_balance: Gwei,
    previous_epoch_target_balance: Gwei,
    current_epoch_target_balance: Gwei,
    flags: UpdateFlags = {}): JustificationAndFinalizationInfo =
  let
    previous_epoch = get_previous_epoch(state)
    current_epoch = get_current_epoch(state)
    old_previous_justified_checkpoint = state.previous_justified_checkpoint
    old_current_justified_checkpoint = state.current_justified_checkpoint

  var res = JustificationAndFinalizationInfo(
    previous_justified_checkpoint: state.previous_justified_checkpoint,
    current_justified_checkpoint: state.current_justified_checkpoint,
    finalized_checkpoint: state.finalized_checkpoint,
    justification_bits: state.justification_bits)

  # Process justifications
  res.previous_justified_checkpoint = res.current_justified_checkpoint

  ## Spec:
  ## state.justification_bits[1:] = state.justification_bits[:-1]
  ## state.justification_bits[0] = 0b0

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#misc
  const JUSTIFICATION_BITS_LENGTH = 4

  res.justification_bits = JustificationBits(
    (uint8(res.justification_bits) shl 1) and
    uint8((2^JUSTIFICATION_BITS_LENGTH) - 1))

  if previous_epoch_target_balance * 3 >= total_active_balance * 2:
    res.current_justified_checkpoint = Checkpoint(
      epoch: previous_epoch, root: get_block_root(state, previous_epoch))
    uint8(res.justification_bits).setBit 1

    trace "Justified with previous epoch",
      current_epoch = current_epoch,
      checkpoint = shortLog(res.current_justified_checkpoint)
  elif strictVerification in flags:
    fatal "Low attestation participation in previous epoch",
      total_active_balance,
      previous_epoch_target_balance,
      current_epoch_target_balance,
      epoch = get_current_epoch(state)
    quit 1

  if current_epoch_target_balance * 3 >= total_active_balance * 2:
    res.current_justified_checkpoint = Checkpoint(
      epoch: current_epoch, root: get_block_root(state, current_epoch))
    uint8(res.justification_bits).setBit 0

    trace "Justified with current epoch",
      current_epoch = current_epoch,
      checkpoint = shortLog(res.current_justified_checkpoint)

  # Process finalizations
  let bitfield = uint8(res.justification_bits)

  ## The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th
  ## as source
  if (bitfield and 0b1110) == 0b1110 and
     old_previous_justified_checkpoint.epoch + 3 == current_epoch:
    res.finalized_checkpoint = old_previous_justified_checkpoint

    trace "Finalized with rule 234",
      current_epoch = current_epoch,
      checkpoint = shortLog(res.finalized_checkpoint)

  ## The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as
  ## source
  if (bitfield and 0b110) == 0b110 and
     old_previous_justified_checkpoint.epoch + 2 == current_epoch:
    res.finalized_checkpoint = old_previous_justified_checkpoint

    trace "Finalized with rule 23",
      current_epoch = current_epoch,
      checkpoint = shortLog(res.finalized_checkpoint)

  ## The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as
  ## source
  if (bitfield and 0b111) == 0b111 and
     old_current_justified_checkpoint.epoch + 2 == current_epoch:
    res.finalized_checkpoint = old_current_justified_checkpoint

    trace "Finalized with rule 123",
      current_epoch = current_epoch,
      checkpoint = shortLog(res.finalized_checkpoint)

  ## The 1st/2nd most recent epochs are justified, the 1st using the 2nd as
  ## source
  if (bitfield and 0b11) == 0b11 and
     old_current_justified_checkpoint.epoch + 1 == current_epoch:
    res.finalized_checkpoint = old_current_justified_checkpoint

    trace "Finalized with rule 12",
      current_epoch = current_epoch,
      checkpoint = shortLog(res.finalized_checkpoint)

  res

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#justification-and-finalization
proc process_justification_and_finalization*(
    state: var phase0.BeaconState,
    balances: TotalBalances, flags: UpdateFlags = {}) =
  # Initial FFG checkpoint values have a `0x00` stub for `root`.
  # Skip FFG updates in the first two epochs to avoid corner cases that might
  # result in modifying this stub.
  if get_current_epoch(state) <= GENESIS_EPOCH + 1:
    return

  let jfRes = weigh_justification_and_finalization(
    state, balances.current_epoch,
    balances.previous_epoch_target_attesters,
    balances.current_epoch_target_attesters, flags)
  assign(
    state.previous_justified_checkpoint, jfRes.previous_justified_checkpoint)
  assign(
    state.current_justified_checkpoint, jfRes.current_justified_checkpoint)
  assign(state.finalized_checkpoint, jfRes.finalized_checkpoint)
  assign(state.justification_bits, jfRes.justification_bits)

proc compute_unrealized_finality*(
    state: phase0.BeaconState, cache: var StateCache): FinalityCheckpoints =
  if get_current_epoch(state) <= GENESIS_EPOCH + 1:
    return FinalityCheckpoints(
      justified: state.current_justified_checkpoint,
      finalized: state.finalized_checkpoint)

  var info: phase0.EpochInfo
  info.init(state)
  info.process_attestations(state, cache)
  template balances(): auto = info.balances

  var finalityState = state.toFinalityState()
  let jfRes = weigh_justification_and_finalization(
    finalityState, balances.current_epoch,
    balances.previous_epoch_target_attesters,
    balances.current_epoch_target_attesters)
  FinalityCheckpoints(
    justified: jfRes.current_justified_checkpoint,
    finalized: jfRes.finalized_checkpoint)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#justification-and-finalization
proc process_justification_and_finalization*(
    state: var (altair.BeaconState | bellatrix.BeaconState |
                capella.BeaconState | deneb.BeaconState | electra.BeaconState),
    balances: UnslashedParticipatingBalances,
    flags: UpdateFlags = {}) =
  # Initial FFG checkpoint values have a `0x00` stub for `root`.
  # Skip FFG updates in the first two epochs to avoid corner cases that might
  # result in modifying this stub.
  if get_current_epoch(state) <= GENESIS_EPOCH + 1:
    return

  let jfRes = weigh_justification_and_finalization(
    state, balances.current_epoch,
    balances.previous_epoch[TIMELY_TARGET_FLAG_INDEX],
    balances.current_epoch_TIMELY_TARGET, flags)
  assign(
    state.previous_justified_checkpoint, jfRes.previous_justified_checkpoint)
  assign(
    state.current_justified_checkpoint, jfRes.current_justified_checkpoint)
  assign(state.finalized_checkpoint, jfRes.finalized_checkpoint)
  assign(state.justification_bits, jfRes.justification_bits)

proc compute_unrealized_finality*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState): FinalityCheckpoints =
  if get_current_epoch(state) <= GENESIS_EPOCH + 1:
    return FinalityCheckpoints(
      justified: state.current_justified_checkpoint,
      finalized: state.finalized_checkpoint)

  let balances = get_unslashed_participating_balances(state)

  var finalityState = state.toFinalityState()
  let jfRes = weigh_justification_and_finalization(
    finalityState, balances.current_epoch,
    balances.previous_epoch[TIMELY_TARGET_FLAG_INDEX],
    balances.current_epoch_TIMELY_TARGET)
  FinalityCheckpoints(
    justified: jfRes.current_justified_checkpoint,
    finalized: jfRes.finalized_checkpoint)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#helpers
func get_base_reward_sqrt*(state: phase0.BeaconState, index: ValidatorIndex,
    total_balance_sqrt: auto): Gwei =
  # Spec function recalculates total_balance every time, which creates an
  # O(n^2) situation.
  let effective_balance = state.validators[index].effective_balance
  effective_balance * BASE_REWARD_FACTOR div
    total_balance_sqrt div BASE_REWARDS_PER_EPOCH

func get_proposer_reward*(base_reward: Gwei): Gwei =
  # Spec version recalculates get_total_active_balance(state) quadratically
  base_reward div PROPOSER_REWARD_QUOTIENT

func is_in_inactivity_leak(finality_delay: uint64): bool =
  finality_delay > MIN_EPOCHS_TO_INACTIVITY_PENALTY

func get_finality_delay*(state: ForkyBeaconState): uint64 =
  get_previous_epoch(state) - state.finalized_checkpoint.epoch

func get_attestation_component_reward*(
    attesting_balance: Gwei,
    total_balance: Gwei,
    base_reward: Gwei,
    finality_delay: uint64): Gwei =
  if is_in_inactivity_leak(finality_delay):
    # Since full base reward will be canceled out by inactivity penalty deltas,
    # optimal participation receives full base reward compensation here.
    base_reward
  else:
    let reward_numerator =
      base_reward * (attesting_balance div EFFECTIVE_BALANCE_INCREMENT.Gwei)
    reward_numerator div (total_balance div EFFECTIVE_BALANCE_INCREMENT.Gwei)

func get_attestation_component_delta(
    is_unslashed_attester: bool,
    attesting_balance: Gwei,
    total_balance: Gwei,
    base_reward: Gwei,
    finality_delay: uint64): RewardDelta =
  # Helper with shared logic for use by get source, target, and head deltas
  # functions
  if is_unslashed_attester:
    RewardDelta(rewards: get_attestation_component_reward(
      attesting_balance,
      total_balance,
      base_reward,
      finality_delay))
  else:
    RewardDelta(penalties: base_reward)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/phase0/beacon-chain.md#components-of-attestation-deltas
func get_source_delta*(
    validator: RewardStatus,
    base_reward: Gwei,
    balances: TotalBalances,
    finality_delay: uint64): RewardDelta =
  ## Return attester micro-rewards/penalties for source-vote for each validator.
  get_attestation_component_delta(
    validator.is_previous_epoch_attester.isSome() and
      not (validator.flags.contains RewardFlags.isSlashed),
    balances.previous_epoch_attesters,
    balances.current_epoch,
    base_reward,
    finality_delay)

func get_target_delta*(
    validator: RewardStatus,
    base_reward: Gwei,
    balances: TotalBalances,
    finality_delay: uint64): RewardDelta =
  ## Return attester micro-rewards/penalties for target-vote for each validator.
  get_attestation_component_delta(
    validator.flags.contains(RewardFlags.isPreviousEpochTargetAttester) and
      not (validator.flags.contains(RewardFlags.isSlashed)),
    balances.previous_epoch_target_attesters,
    balances.current_epoch,
    base_reward,
    finality_delay)

func get_head_delta*(
    validator: RewardStatus,
    base_reward: Gwei,
    balances: TotalBalances,
    finality_delay: uint64): RewardDelta =
  ## Return attester micro-rewards/penalties for head-vote for each validator.
  get_attestation_component_delta(
    validator.flags.contains(RewardFlags.isPreviousEpochHeadAttester) and
      ((not validator.flags.contains(RewardFlags.isSlashed))),
    balances.previous_epoch_head_attesters,
    balances.current_epoch,
    base_reward,
    finality_delay)

func get_inclusion_delay_delta*(
    validator: RewardStatus,
    base_reward: Gwei): (RewardDelta, Opt[(uint64, RewardDelta)]) =
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
    return (delta, Opt.some((proposer_index, proposer_delta)))

func get_inactivity_penalty_delta*(
    validator: RewardStatus,
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_attestation_deltas
func get_attestation_deltas(
    state: phase0.BeaconState, info: var phase0.EpochInfo) =
  ## Update rewards with attestation reward/penalty deltas for each validator.
  let
    finality_delay = get_finality_delay(state)
    total_balance = info.balances.current_epoch
    total_balance_sqrt = integer_squareroot(distinctBase(total_balance))
  # Filter out ineligible validators. All sub-functions of the spec do this
  # except for `get_inclusion_delay_deltas`. It's safe to do so here because
  # any validator that is in the unslashed indices of the matching source
  # attestations is active, and therefore eligible.
  for index, validator in info.validators.mpairs():
    if not is_eligible_validator(validator):
      continue

    let
      base_reward = get_base_reward_sqrt(
        state, index.ValidatorIndex, total_balance_sqrt)

    let
      source_delta = get_source_delta(
        validator, base_reward, info.balances, finality_delay)
      target_delta = get_target_delta(
        validator, base_reward, info.balances, finality_delay)
      head_delta = get_head_delta(
        validator, base_reward, info.balances, finality_delay)
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
      if proposer_index < info.validators.lenu64:
        info.validators[proposer_index].delta.add(
          proposer_delta.get()[1])

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#get_base_reward
func get_base_reward_increment*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState,
    index: ValidatorIndex, base_reward_per_increment: Gwei): Gwei =
  ## Return the base reward for the validator defined by ``index`` with respect
  ## to the current ``state``.
  let increments =
    state.validators[index].effective_balance div
    EFFECTIVE_BALANCE_INCREMENT.Gwei
  increments * base_reward_per_increment

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#get_flag_index_deltas
func get_flag_index_reward*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState,
    base_reward: Gwei,
    active_increments: uint64,
    unslashed_participating_increments: uint64,
    weight, finality_delay: uint64): Gwei =
  if not is_in_inactivity_leak(finality_delay):
    let reward_numerator =
      base_reward * weight * unslashed_participating_increments
    reward_numerator div (active_increments * WEIGHT_DENOMINATOR)
  else:
    0.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#get_flag_index_deltas
func get_unslashed_participating_increment*(
    info: altair.EpochInfo | bellatrix.BeaconState,
    flag_index: TimelyFlag): uint64 =
  info.balances.previous_epoch[flag_index] div EFFECTIVE_BALANCE_INCREMENT.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#get_flag_index_deltas
func get_active_increments*(
    info: altair.EpochInfo | bellatrix.BeaconState): uint64 =
  info.balances.current_epoch div EFFECTIVE_BALANCE_INCREMENT.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#get_flag_index_deltas
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#modified-get_inactivity_penalty_deltas
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#modified-get_inactivity_penalty_deltas
# Combines get_flag_index_deltas() and get_inactivity_penalty_deltas()
template get_flag_and_inactivity_delta(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState,
    base_reward_per_increment: Gwei, finality_delay: uint64,
    previous_epoch: Epoch, active_increments: uint64,
    penalty_denominator: uint64,
    epoch_participation: ptr EpochParticipationFlags,
    participating_increments: array[3, uint64], info: var altair.EpochInfo,
    vidx: ValidatorIndex, inactivity_score: uint64
): (ValidatorIndex, Gwei, Gwei, Gwei, Gwei, Gwei, Gwei) =
  let
    base_reward = get_base_reward_increment(state, vidx, base_reward_per_increment)
    pflags =
      if  is_active_validator(state.validators[vidx], previous_epoch) and
          not state.validators[vidx].slashed:
        epoch_participation[].item(vidx)
      else:
        0

  if has_flag(pflags, TIMELY_SOURCE_FLAG_INDEX):
    info.validators[vidx].flags.incl ParticipationFlag.timelySourceAttester
  if has_flag(pflags, TIMELY_TARGET_FLAG_INDEX):
    info.validators[vidx].flags.incl ParticipationFlag.timelyTargetAttester
  if has_flag(pflags, TIMELY_HEAD_FLAG_INDEX):
    info.validators[vidx].flags.incl ParticipationFlag.timelyHeadAttester

  template reward(flag: untyped): untyped =
    if has_flag(pflags, flag):
      get_flag_index_reward(
        state, base_reward, active_increments,
        participating_increments[ord(flag)],
        PARTICIPATION_FLAG_WEIGHTS[flag], finality_delay)
    else:
      0.Gwei

  template penalty(flag: untyped): untyped =
    if not has_flag(pflags, flag):
      base_reward * PARTICIPATION_FLAG_WEIGHTS[flag] div WEIGHT_DENOMINATOR
    else:
      0.Gwei

  let inactivity_penalty =
    if has_flag(pflags, TIMELY_TARGET_FLAG_INDEX):
      0.Gwei
    else:
      let penalty_numerator =
        state.validators[vidx].effective_balance * inactivity_score
      penalty_numerator div penalty_denominator

  (vidx, reward(TIMELY_SOURCE_FLAG_INDEX),
   reward(TIMELY_TARGET_FLAG_INDEX), reward(TIMELY_HEAD_FLAG_INDEX),
   penalty(TIMELY_SOURCE_FLAG_INDEX), penalty(TIMELY_TARGET_FLAG_INDEX),
   inactivity_penalty)

iterator get_flag_and_inactivity_deltas*(
    cfg: RuntimeConfig,
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState,
    base_reward_per_increment: Gwei, info: var altair.EpochInfo,
    finality_delay: uint64):
    (ValidatorIndex, Gwei, Gwei, Gwei, Gwei, Gwei, Gwei) =
  ## Return the deltas for a given ``flag_index`` by scanning through the
  ## participation flags.
  #
  # This deviates from spec by processing all flags at once, so does not take a
  # flag_index parameter. Fold get_inactivity_penalty_deltas loop into this one
  # as well.
  const INACTIVITY_PENALTY_QUOTIENT =
    when state is altair.BeaconState:
      INACTIVITY_PENALTY_QUOTIENT_ALTAIR
    else:
      INACTIVITY_PENALTY_QUOTIENT_BELLATRIX

  static: doAssert ord(high(TimelyFlag)) == 2

  let
    previous_epoch = get_previous_epoch(state)
    active_increments = get_active_increments(info)
    penalty_denominator =
      cfg.INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT
    epoch_participation =
      if previous_epoch == get_current_epoch(state):
        unsafeAddr state.current_epoch_participation
      else:
        unsafeAddr state.previous_epoch_participation
    participating_increments = [
      get_unslashed_participating_increment(info, TIMELY_SOURCE_FLAG_INDEX),
      get_unslashed_participating_increment(info, TIMELY_TARGET_FLAG_INDEX),
      get_unslashed_participating_increment(info, TIMELY_HEAD_FLAG_INDEX)]

  for vidx in state.validators.vindices:
    if not is_eligible_validator(info.validators[vidx]):
      continue

    # Yielding these as a structure with identifiable names rather than
    # multiple-return-value style creates spurious nimZeroMem calls.
    yield get_flag_and_inactivity_delta(
      state, base_reward_per_increment, finality_delay, previous_epoch,
      active_increments, penalty_denominator, epoch_participation,
      participating_increments, info, vidx, state.inactivity_scores[vidx])

func get_flag_and_inactivity_delta_for_validator(
    cfg: RuntimeConfig,
    state: deneb.BeaconState | electra.BeaconState,
    base_reward_per_increment: Gwei, info: var altair.EpochInfo,
    finality_delay: uint64, vidx: ValidatorIndex, inactivity_score: Gwei):
    Opt[(ValidatorIndex, Gwei, Gwei, Gwei, Gwei, Gwei, Gwei)] =
  ## Return the deltas for a given ``flag_index`` by scanning through the
  ## participation flags.
  const INACTIVITY_PENALTY_QUOTIENT =
    when state is altair.BeaconState:
      INACTIVITY_PENALTY_QUOTIENT_ALTAIR
    else:
      INACTIVITY_PENALTY_QUOTIENT_BELLATRIX

  static: doAssert ord(high(TimelyFlag)) == 2

  let
    previous_epoch = get_previous_epoch(state)
    active_increments = get_active_increments(info)
    penalty_denominator =
      cfg.INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT
    epoch_participation =
      if previous_epoch == get_current_epoch(state):
        unsafeAddr state.current_epoch_participation
      else:
        unsafeAddr state.previous_epoch_participation
    participating_increments = [
      get_unslashed_participating_increment(info, TIMELY_SOURCE_FLAG_INDEX),
      get_unslashed_participating_increment(info, TIMELY_TARGET_FLAG_INDEX),
      get_unslashed_participating_increment(info, TIMELY_HEAD_FLAG_INDEX)]

  if not is_eligible_validator(info.validators[vidx]):
    return Opt.none((ValidatorIndex, Gwei, Gwei, Gwei, Gwei, Gwei, Gwei))

  Opt.some get_flag_and_inactivity_delta(
    state, base_reward_per_increment, finality_delay, previous_epoch,
    active_increments, penalty_denominator, epoch_participation,
    participating_increments, info, vidx, inactivity_score.uint64)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/phase0/beacon-chain.md#rewards-and-penalties-1
func process_rewards_and_penalties*(
    state: var phase0.BeaconState, info: var phase0.EpochInfo) =
  # No rewards are applied at the end of `GENESIS_EPOCH` because rewards are
  # for work done in the previous epoch
  doAssert info.validators.len == state.validators.len

  if get_current_epoch(state) == GENESIS_EPOCH:
    return

  get_attestation_deltas(state, info)

  # Here almost all balances are updated (assuming most validators are active) -
  # clearing the cache becomes a bottleneck if done item by item because of the
  # recursive nature of cache clearing - instead, we clear the whole cache then
  # update the raw list directly
  state.balances.clearCache()
  for idx, v in info.validators:
    var balance = state.balances.item(idx)
    increase_balance(balance, v.delta.rewards)
    decrease_balance(balance, v.delta.penalties)
    state.balances.asSeq()[idx] = balance

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#rewards-and-penalties
func process_rewards_and_penalties*(
    cfg: RuntimeConfig,
    state: var (altair.BeaconState | bellatrix.BeaconState |
                capella.BeaconState | deneb.BeaconState | electra.BeaconState),
    info: var altair.EpochInfo) =
  if get_current_epoch(state) == GENESIS_EPOCH:
    return

  let
    total_active_balance = info.balances.current_epoch
    base_reward_per_increment = get_base_reward_per_increment(
      total_active_balance)
    finality_delay = get_finality_delay(state)

  doAssert state.validators.len() == info.validators.len()
  for validator_index, reward0, reward1, reward2, penalty0, penalty1, penalty2 in
      get_flag_and_inactivity_deltas(
        cfg, state, base_reward_per_increment, info, finality_delay):
    # templatize this loop? or replicate a couple lines of code?
    info.validators[validator_index].delta.rewards += reward0 + reward1 + reward2
    info.validators[validator_index].delta.penalties += penalty0 + penalty1 + penalty2

  # Here almost all balances are updated (assuming most validators are active) -
  # clearing the cache becomes a bottleneck if done item by item because of the
  # recursive nature of cache clearing - instead, we clear the whole cache then
  # update the raw list directly
  state.balances.clearCache()
  for vidx in state.validators.vindices:
    var balance = state.balances.item(vidx)
    increase_balance(balance, info.validators[vidx].delta.rewards)
    decrease_balance(balance, info.validators[vidx].delta.penalties)
    state.balances.asSeq()[vidx] = balance

from std/heapqueue import HeapQueue, `[]`, len, push, replace

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/phase0/beacon-chain.md#registry-updates
func process_registry_updates*(
    cfg: RuntimeConfig,
    state: var (phase0.BeaconState | altair.BeaconState |
                bellatrix.BeaconState | capella.BeaconState |
                deneb.BeaconState),
    cache: var StateCache): Result[void, cstring] =
  ## Process activation eligibility and ejections

  # is_active_validator(...) is activation_epoch <= epoch < exit_epoch,
  # and changes here to either activation_epoch or exit_epoch only take
  # effect with a compute_activation_exit_epoch(...) delay of, based on
  # the current epoch, 1 + MAX_SEED_LOOKAHEAD epochs ahead. Thus caches
  # remain valid for this epoch through though this function along with
  # the rest of the epoch transition.
  #
  # This implementation fuses the two loops over all validators in the
  # spec code.

  ## Queue validators eligible for activation and not dequeued for activation
  var activation_queue: HeapQueue[(uint64, uint32)]
  let churn_limit =
    when typeof(state).kind >= ConsensusFork.Deneb:
      get_validator_activation_churn_limit(cfg, state, cache)
    else:
      get_validator_churn_limit(cfg, state, cache)

  var maybe_exit_queue_info: Opt[ExitQueueInfo]

  for vidx in state.validators.vindices:
    if is_eligible_for_activation_queue(
        typeof(state).kind, state.validators.item(vidx)):
      state.validators.mitem(vidx).activation_eligibility_epoch =
        get_current_epoch(state) + 1

    if is_active_validator(state.validators.item(vidx), get_current_epoch(state)) and
        state.validators.item(vidx).effective_balance <= cfg.EJECTION_BALANCE.Gwei:
      # Typically, there will be no ejected validators, and even more rarely,
      # more than one. Therefore, only calculate the information required for
      # initiate_validator_exit if there actually is at least one.
      let exit_queue_info = maybe_exit_queue_info.valueOr:
        let initial_exit_queue_info = get_state_exit_queue_info(state)
        maybe_exit_queue_info = Opt.some initial_exit_queue_info
        initial_exit_queue_info

      maybe_exit_queue_info = Opt.some (? initiate_validator_exit(
        cfg, state, vidx, exit_queue_info, cache))

    let validator = unsafeAddr state.validators.item(vidx)
    if is_eligible_for_activation(state, validator[]):
      let val_key =
        (FAR_FUTURE_EPOCH - validator[].activation_eligibility_epoch,
         high(distinctBase(ValidatorIndex)) - distinctBase(vidx))
      if activation_queue.len.uint64 < churn_limit:
        activation_queue.push val_key
      elif val_key > activation_queue[0]:
        discard activation_queue.replace val_key

  ## Dequeued validators for activation up to activation churn limit
  ## (without resetting activation epoch)
  doAssert activation_queue.len.uint64 <= churn_limit
  for i in 0 ..< activation_queue.len:
    let (_, vidx_complement) = activation_queue[i]
    state.validators.mitem(
      high(distinctBase(ValidatorIndex)) - vidx_complement).activation_epoch =
        compute_activation_exit_epoch(get_current_epoch(state))

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/electra/beacon-chain.md#modified-process_registry_updates
func process_registry_updates*(
    cfg: RuntimeConfig, state: var electra.BeaconState, cache: var StateCache):
    Result[void, cstring] =
  # Process activation eligibility and ejections
  for index in 0 ..< state.validators.len:
    let validator = state.validators.item(index)
    if is_eligible_for_activation_queue(typeof(state).kind, validator):
      # Usually not too many at once, so do this individually
      state.validators.mitem(index).activation_eligibility_epoch =
        get_current_epoch(state) + 1

    if  is_active_validator(validator, get_current_epoch(state)) and
        distinctBase(validator.effective_balance) <= cfg.EJECTION_BALANCE:
      discard ? initiate_validator_exit(
        cfg, state, ValidatorIndex(index), static(default(ExitQueueInfo)), cache)

  # Activate all eligible validators
  let activation_epoch =
    compute_activation_exit_epoch(get_current_epoch(state))
  for index in 0 ..< state.validators.len:
    if is_eligible_for_activation(state, state.validators.item(index)):
      state.validators.mitem(index).activation_epoch = activation_epoch

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#slashings
func get_adjusted_total_slashing_balance*(
    state: ForkyBeaconState, total_balance: Gwei): Gwei =
  const multiplier =
    # tradeoff here about interleaving phase0/altair, but for these
    # single-constant changes...
    when state is phase0.BeaconState:
      PROPORTIONAL_SLASHING_MULTIPLIER
    elif state is altair.BeaconState:
      PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR
    elif state is bellatrix.BeaconState or state is capella.BeaconState or
         state is deneb.BeaconState or state is electra.BeaconState:
      PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX
    else:
      {.fatal: "process_slashings: incorrect BeaconState type".}
  min(sum(state.slashings.data) * multiplier, total_balance)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/electra/beacon-chain.md#modified-process_slashings
func slashing_penalty_applies*(validator: Validator, epoch: Epoch): bool =
  validator.slashed and
  epoch + EPOCHS_PER_SLASHINGS_VECTOR div 2 == validator.withdrawable_epoch

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/phase0/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/electra/beacon-chain.md#modified-process_slashings
func get_slashing_penalty*(
    consensusFork: static ConsensusFork, validator: Validator,
    adjusted_total_slashing_balance, total_balance: Gwei): Gwei =
  # Factored out from penalty numerator to avoid uint64 overflow
  const increment = EFFECTIVE_BALANCE_INCREMENT.Gwei

  when consensusFork <= ConsensusFork.Deneb:
    let penalty_numerator = validator.effective_balance div increment *
                            adjusted_total_slashing_balance
    penalty_numerator div total_balance * increment
  elif consensusFork == ConsensusFork.Electra:
    let
      effective_balance_increments = validator.effective_balance div increment
      penalty_per_effective_balance_increment =
        adjusted_total_slashing_balance div (total_balance div increment)

    # [Modified in Electra:EIP7251]
    penalty_per_effective_balance_increment * effective_balance_increments
  else:
    static: doAssert false

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#slashings
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/electra/beacon-chain.md#modified-process_slashings
func get_slashing(
    state: ForkyBeaconState, total_balance: Gwei, vidx: ValidatorIndex): Gwei =
  # For efficiency reasons, it doesn't make sense to have process_slashings use
  # this per-validator index version, but keep them parallel otherwise.
  let
    epoch = get_current_epoch(state)
    adjusted_total_slashing_balance = get_adjusted_total_slashing_balance(
      state, total_balance)

  let validator = unsafeAddr state.validators.item(vidx)
  if slashing_penalty_applies(validator[], epoch):
    get_slashing_penalty(
      typeof(state).kind, validator[], adjusted_total_slashing_balance,
      total_balance)
  else:
    0.Gwei

func process_slashings*(state: var ForkyBeaconState, total_balance: Gwei) =
  let
    epoch = get_current_epoch(state)
    adjusted_total_slashing_balance = get_adjusted_total_slashing_balance(
      state, total_balance)

  for vidx in state.validators.vindices:
    let validator = unsafeAddr state.validators.item(vidx)
    if slashing_penalty_applies(validator[], epoch):
      let penalty = get_slashing_penalty(
        typeof(state).kind, validator[], adjusted_total_slashing_balance,
        total_balance)
      decrease_balance(state, vidx, penalty)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#eth1-data-votes-updates
func process_eth1_data_reset*(state: var ForkyBeaconState) =
  let next_epoch = get_current_epoch(state) + 1

  # Reset eth1 data votes
  if next_epoch mod EPOCHS_PER_ETH1_VOTING_PERIOD == 0:
    state.eth1_data_votes = default(type state.eth1_data_votes)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#effective-balances-updates
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.1/specs/electra/beacon-chain.md#updated-process_effective_balance_updates
func process_effective_balance_updates*(state: var ForkyBeaconState) =
  # Update effective balances with hysteresis
  for vidx in state.validators.vindices:
    let
      balance = state.balances.item(vidx)
      effective_balance = state.validators.item(vidx).effective_balance

    if effective_balance_might_update(balance, effective_balance):
      let new_effective_balance = get_effective_balance_update(
        typeof(state).kind, balance, effective_balance, vidx.distinctBase)
      # Protect against unnecessary cache invalidation
      if new_effective_balance != effective_balance:
        state.validators.mitem(vidx).effective_balance = new_effective_balance

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#slashings-balances-updates
func process_slashings_reset*(state: var ForkyBeaconState) =
  let next_epoch = get_current_epoch(state) + 1

  # Reset slashings
  state.slashings[int(next_epoch mod EPOCHS_PER_SLASHINGS_VECTOR)] = 0.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#randao-mixes-updates
func process_randao_mixes_reset*(state: var ForkyBeaconState) =
  let
    current_epoch = get_current_epoch(state)
    next_epoch = current_epoch + 1

  # Set randao mix
  state.randao_mixes[next_epoch mod EPOCHS_PER_HISTORICAL_VECTOR] =
    get_randao_mix(state, current_epoch)

func compute_historical_root*(state: var ForkyBeaconState): Eth2Digest =
  # Equivalent to hash_tree_root(foo: HistoricalBatch), but without using
  # significant additional stack or heap.
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#historicalbatch
  # In response to https://github.com/status-im/nimbus-eth2/issues/921
  hash_tree_root([
    hash_tree_root(state.block_roots), hash_tree_root(state.state_roots)])

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#historical-roots-updates
func process_historical_roots_update*(state: var ForkyBeaconState) =
  ## Set historical root accumulator
  let next_epoch = get_current_epoch(state) + 1

  if next_epoch mod (SLOTS_PER_HISTORICAL_ROOT div SLOTS_PER_EPOCH) == 0:
    # Equivalent to hash_tree_root(foo: HistoricalBatch), but without using
    # significant additional stack or heap.
    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/phase0/beacon-chain.md#historicalbatch
    # In response to https://github.com/status-im/nimbus-eth2/issues/921
    if not state.historical_roots.add state.compute_historical_root():
      raiseAssert "no more room for historical roots, so long and thanks for the fish!"

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#participation-records-rotation
func process_participation_record_updates*(state: var phase0.BeaconState) =
  # Rotate current/previous epoch attestations - using swap avoids copying all
  # elements using a slow genericSeqAssign
  state.previous_epoch_attestations.clear()
  swap(state.previous_epoch_attestations, state.current_epoch_attestations)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#participation-flags-updates
func process_participation_flag_updates*(
    state: var (altair.BeaconState | bellatrix.BeaconState |
                capella.BeaconState | deneb.BeaconState |
                electra.BeaconState)) =
  state.previous_epoch_participation = state.current_epoch_participation

  const zero = 0.ParticipationFlags
  for i in 0 ..< state.current_epoch_participation.len:
    asList(state.current_epoch_participation)[i] = zero

  # Shouldn't be wasted zeroing, because state.current_epoch_participation only
  # grows. New elements are automatically initialized to 0, as required.
  doAssert state.current_epoch_participation.asList.setLen(state.validators.len)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#sync-committee-updates
func process_sync_committee_updates*(
    state: var (altair.BeaconState | bellatrix.BeaconState |
                capella.BeaconState | deneb.BeaconState |
                electra.BeaconState)) =
  let next_epoch = get_current_epoch(state) + 1
  if next_epoch.is_sync_committee_period():
    state.current_sync_committee = state.next_sync_committee
    state.next_sync_committee = get_next_sync_committee(state)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#inactivity-scores
template compute_inactivity_update(
    cfg: RuntimeConfig,
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState,
    info: altair.EpochInfo,
    pre_inactivity_score: uint64): uint64 =
  let previous_epoch = get_previous_epoch(state)  # get_eligible_validator_indices()

  # Increase the inactivity score of inactive validators
  var inactivity_score = pre_inactivity_score
  # TODO activeness already checked; remove redundant checks between
  # is_active_validator and is_unslashed_participating_index
  if is_unslashed_participating_index(
      state, TIMELY_TARGET_FLAG_INDEX, previous_epoch, index):
    inactivity_score -= min(1'u64, inactivity_score)
  else:
    inactivity_score += cfg.INACTIVITY_SCORE_BIAS
  # Decrease the inactivity score of all eligible validators during a
  # leak-free epoch
  if not_in_inactivity_leak:
    inactivity_score -=
      min(cfg.INACTIVITY_SCORE_RECOVERY_RATE, inactivity_score)
  inactivity_score

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#inactivity-scores
func process_inactivity_updates*(
    cfg: RuntimeConfig,
    state: var (altair.BeaconState | bellatrix.BeaconState |
                capella.BeaconState | deneb.BeaconState | electra.BeaconState),
    info: altair.EpochInfo) =
  # Score updates based on previous epoch participation, skip genesis epoch
  if get_current_epoch(state) == GENESIS_EPOCH:
    return

  let
    finality_delay = get_finality_delay(state)
    not_in_inactivity_leak = not is_in_inactivity_leak(finality_delay)

  for index in 0'u64 ..< state.validators.lenu64:
    if not is_eligible_validator(info.validators[index]):
      continue

    let
      pre_inactivity_score = state.inactivity_scores.asSeq()[index]
      index = index.ValidatorIndex # intentional shadowing
      inactivity_score =
        compute_inactivity_update(cfg, state, info, pre_inactivity_score)

    # Most inactivity scores remain at 0 - avoid invalidating cache
    if pre_inactivity_score != inactivity_score:
      state.inactivity_scores[index] = inactivity_score

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/capella/beacon-chain.md#historical-summaries-updates
func process_historical_summaries_update*(
    state: var (capella.BeaconState | deneb.BeaconState | electra.BeaconState)):
    Result[void, cstring] =
  # Set historical block root accumulator.
  let next_epoch = get_current_epoch(state) + 1
  if next_epoch mod (SLOTS_PER_HISTORICAL_ROOT div SLOTS_PER_EPOCH) == 0:
    let historical_summary = HistoricalSummary(
      block_summary_root: hash_tree_root(state.block_roots),
      state_summary_root: hash_tree_root(state.state_roots),
    )
    if not state.historical_summaries.add(historical_summary):
      return err("process_historical_summaries_update: state.historical_summaries full")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#new-process_pending_balance_deposits
func process_pending_balance_deposits*(
    cfg: RuntimeConfig, state: var electra.BeaconState,
    cache: var StateCache): Result[void, cstring] =
  let
    next_epoch = get_current_epoch(state) + 1
    available_for_processing = state.deposit_balance_to_consume +
      get_activation_exit_churn_limit(cfg, state, cache)
  var
    processed_amount = 0.Gwei
    next_deposit_index = 0
    deposits_to_postpone: seq[PendingBalanceDeposit]

  for deposit in state.pending_balance_deposits:
    let validator = state.validators.item(deposit.index)

    let deposit_validator_index = ValidatorIndex.init(deposit.index).valueOr:
      # TODO this function in spec doesn't really have error returns as such
      return err("process_pending_balance_deposits: deposit index out of range")

    # Validator is exiting, postpone the deposit until after withdrawable epoch
    if validator.exit_epoch < FAR_FUTURE_EPOCH:
      if next_epoch <= validator.withdrawable_epoch:
        deposits_to_postpone.add(deposit)
      # Deposited balance will never become active. Increase balance but do not
      # consume churn
      else:
        increase_balance(state, deposit_validator_index, deposit.amount)
    # Validator is not exiting, attempt to process deposit
    else:
      # Deposit does not fit in the churn, no more deposit processing in this
      # epoch.
      if processed_amount + deposit.amount > available_for_processing:
        break
      # Deposit fits in the churn, process it. Increase balance and consume churn.
      else:
        increase_balance(state, deposit_validator_index, deposit.amount)
        processed_amount += deposit.amount

    # Regardless of how the deposit was handled, we move on in the queue.
    next_deposit_index += 1

  state.pending_balance_deposits =
    HashList[PendingBalanceDeposit, Limit PENDING_BALANCE_DEPOSITS_LIMIT].init(
      state.pending_balance_deposits.asSeq[next_deposit_index..^1])

  if len(state.pending_balance_deposits) == 0:
    state.deposit_balance_to_consume = Gwei(0)
  else:
    state.deposit_balance_to_consume =
      available_for_processing - processed_amount

  if len(deposits_to_postpone) > 0:
    discard state.pending_balance_deposits.add deposits_to_postpone

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#new-process_pending_consolidations
func process_pending_consolidations*(
    cfg: RuntimeConfig, state: var electra.BeaconState):
    Result[void, cstring] =
  let next_epoch = get_current_epoch(state) + 1
  var next_pending_consolidation = 0
  for pending_consolidation in state.pending_consolidations:
    let source_validator =
      state.validators.item(pending_consolidation.source_index)
    if source_validator.slashed:
      next_pending_consolidation += 1
      continue
    if source_validator.withdrawable_epoch > next_epoch:
      break

    let
      source_validator_index = ValidatorIndex.init(
          pending_consolidation.source_index).valueOr:
        return err("process_pending_consolidations: source index out of range")
      target_validator_index = ValidatorIndex.init(
          pending_consolidation.target_index).valueOr:
        return err("process_pending_consolidations: target index out of range")

    # Churn any target excess active balance of target and raise its max
    switch_to_compounding_validator(state, target_validator_index)

    # Move active balance to target. Excess balance is withdrawable.
    let active_balance = get_active_balance(state, source_validator_index)
    decrease_balance(state, source_validator_index, active_balance)
    increase_balance(state, target_validator_index, active_balance)
    inc next_pending_consolidation

  state.pending_consolidations =
    HashList[PendingConsolidation, Limit PENDING_CONSOLIDATIONS_LIMIT].init(
      state.pending_consolidations.asSeq[next_pending_consolidation..^1])

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#epoch-processing
proc process_epoch*(
    cfg: RuntimeConfig, state: var phase0.BeaconState, flags: UpdateFlags,
    cache: var StateCache, info: var phase0.EpochInfo): Result[void, cstring] =
  let epoch = get_current_epoch(state)
  trace "process_epoch", epoch

  info.init(state)
  info.process_attestations(state, cache)

  process_justification_and_finalization(state, info.balances, flags)

  # state.slot hasn't been incremented yet.
  if strictVerification in flags and epoch >= 2:
    doAssert state.current_justified_checkpoint.epoch + 2 >= epoch

  if strictVerification in flags and epoch >= 3:
    # Rule 2/3/4 finalization results in the most pessimal case. The other
    # three finalization rules finalize more quickly as long as the any of
    # the finalization rules triggered.
    doAssert state.finalized_checkpoint.epoch + 3 >= epoch

  process_rewards_and_penalties(state, info)
  ? process_registry_updates(cfg, state, cache)
  process_slashings(state, info.balances.current_epoch)
  process_eth1_data_reset(state)
  process_effective_balance_updates(state)
  process_slashings_reset(state)
  process_randao_mixes_reset(state)
  process_historical_roots_update(state)
  process_participation_record_updates(state)

  ok()

func init*(
    info: var altair.EpochInfo,
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState) =
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
    T: type altair.EpochInfo,
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState): T =
  init(result, state)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#epoch-processing
proc process_epoch*(
    cfg: RuntimeConfig,
    state: var (altair.BeaconState | bellatrix.BeaconState),
    flags: UpdateFlags, cache: var StateCache, info: var altair.EpochInfo):
    Result[void, cstring] =
  let epoch = get_current_epoch(state)
  trace "process_epoch", epoch

  info.init(state)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#justification-and-finalization
  # [Modified in Altair]
  process_justification_and_finalization(state, info.balances, flags)

  # state.slot hasn't been incremented yet.
  if strictVerification in flags and epoch >= 2:
    doAssert state.current_justified_checkpoint.epoch + 2 >= epoch

  if strictVerification in flags and epoch >= 3:
    # Rule 2/3/4 finalization results in the most pessimal case. The other
    # three finalization rules finalize more quickly as long as the any of
    # the finalization rules triggered.
    doAssert state.finalized_checkpoint.epoch + 3 >= epoch

  process_inactivity_updates(cfg, state, info)  # [New in Altair]

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#rewards-and-penalties
  process_rewards_and_penalties(cfg, state, info)  # [Modified in Altair]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#registry-updates
  ? process_registry_updates(cfg, state, cache)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#slashings
  process_slashings(state, info.balances.current_epoch)  # [Modified in Altair]

  process_eth1_data_reset(state)
  process_effective_balance_updates(state)
  process_slashings_reset(state)
  process_randao_mixes_reset(state)
  process_historical_roots_update(state)
  process_participation_flag_updates(state)  # [New in Altair]
  process_sync_committee_updates(state)  # [New in Altair]

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#epoch-processing
proc process_epoch*(
    cfg: RuntimeConfig,
    state: var (capella.BeaconState | deneb.BeaconState),
    flags: UpdateFlags, cache: var StateCache, info: var altair.EpochInfo):
    Result[void, cstring] =
  let epoch = get_current_epoch(state)
  trace "process_epoch", epoch

  info.init(state)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#justification-and-finalization
  process_justification_and_finalization(state, info.balances, flags)

  # state.slot hasn't been incremented yet.
  if strictVerification in flags:
    # Rule 2/3/4 finalization results in the most pessimal case. The other
    # three finalization rules finalize more quickly as long as the any of
    # the finalization rules triggered.
    if (epoch >= 2 and state.current_justified_checkpoint.epoch + 2 < epoch) or
       (epoch >= 3 and state.finalized_checkpoint.epoch + 3 < epoch):
      fatal "The network did not finalize",
             epoch, finalizedEpoch = state.finalized_checkpoint.epoch
      quit 1

  process_inactivity_updates(cfg, state, info)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#rewards-and-penalties
  process_rewards_and_penalties(cfg, state, info)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#registry-updates
  ? process_registry_updates(cfg, state, cache)

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#slashings
  process_slashings(state, info.balances.current_epoch)

  process_eth1_data_reset(state)
  process_effective_balance_updates(state)
  process_slashings_reset(state)
  process_randao_mixes_reset(state)
  ? process_historical_summaries_update(state)  # [Modified in Capella]
  process_participation_flag_updates(state)
  process_sync_committee_updates(state)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.1/specs/electra/beacon-chain.md#epoch-processing
proc process_epoch*(
    cfg: RuntimeConfig, state: var electra.BeaconState,
    flags: UpdateFlags, cache: var StateCache, info: var altair.EpochInfo):
    Result[void, cstring] =
  let epoch = get_current_epoch(state)
  trace "process_epoch", epoch

  info.init(state)

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#justification-and-finalization
  process_justification_and_finalization(state, info.balances, flags)

  # state.slot hasn't been incremented yet.
  if strictVerification in flags:
    # Rule 2/3/4 finalization results in the most pessimal case. The other
    # three finalization rules finalize more quickly as long as the any of
    # the finalization rules triggered.
    if (epoch >= 2 and state.current_justified_checkpoint.epoch + 2 < epoch) or
       (epoch >= 3 and state.finalized_checkpoint.epoch + 3 < epoch):
      fatal "The network did not finalize",
             epoch, finalizedEpoch = state.finalized_checkpoint.epoch
      quit 1

  process_inactivity_updates(cfg, state, info)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#rewards-and-penalties
  process_rewards_and_penalties(cfg, state, info)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#registry-updates
  ? process_registry_updates(cfg, state, cache)  # [Modified in Electra:EIP7251]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#slashings
  process_slashings(state, info.balances.current_epoch)

  process_eth1_data_reset(state)
  ? process_pending_balance_deposits(cfg, state, cache)  # [New in Electra:EIP7251]
  ? process_pending_consolidations(cfg, state)  # [New in Electra:EIP7251]
  process_effective_balance_updates(state)  # [Modified in Electra:EIP7251]
  process_slashings_reset(state)
  process_randao_mixes_reset(state)
  ? process_historical_summaries_update(state)  # [Modified in Capella]
  process_participation_flag_updates(state)
  process_sync_committee_updates(state)

  ok()

proc get_validator_balance_after_epoch*(
    cfg: RuntimeConfig, state: deneb.BeaconState | electra.BeaconState,
    cache: var StateCache, info: var altair.EpochInfo,
    index: ValidatorIndex): Gwei =
  # Run a subset of process_epoch() which affects an individual validator,
  # without modifying state itself
  info.init(state)   # TODO avoid quadratic aspects here

  # Can't use process_justification_and_finalization(), but use its helper
  # function. Used to calculate inactivity_score.
  let jf_info =
    # process_justification_and_finalization() skips first two epochs
    if get_current_epoch(state) <= GENESIS_EPOCH + 1:
      JustificationAndFinalizationInfo(
        previous_justified_checkpoint: state.previous_justified_checkpoint,
        current_justified_checkpoint: state.current_justified_checkpoint,
        finalized_checkpoint: state.finalized_checkpoint,
        justification_bits: state.justification_bits)
    else:
      weigh_justification_and_finalization(
        state, info.balances.current_epoch,
        info.balances.previous_epoch[TIMELY_TARGET_FLAG_INDEX],
        info.balances.current_epoch_TIMELY_TARGET, {})

  # Used as part of process_rewards_and_penalties
  let inactivity_score =
    # process_inactivity_updates skips GENESIS_EPOCH and ineligible validators
    if  get_current_epoch(state) == GENESIS_EPOCH or
        not is_eligible_validator(info.validators[index]):
      0.Gwei
    else:
      let
        finality_delay =
          get_previous_epoch(state) - jf_info.finalized_checkpoint.epoch
        not_in_inactivity_leak = not is_in_inactivity_leak(finality_delay)
        pre_inactivity_score = state.inactivity_scores.asSeq()[index]

      # This is a template which uses not_in_inactivity_leak and index
      compute_inactivity_update(cfg, state, info, pre_inactivity_score).Gwei

  # process_rewards_and_penalties for a single validator
  let reward_and_penalties_balance = block:
    # process_rewards_and_penalties doesn't run at GENESIS_EPOCH
    if get_current_epoch(state) == GENESIS_EPOCH:
      state.balances.item(index)
    else:
      let
        total_active_balance = info.balances.current_epoch
        base_reward_per_increment = get_base_reward_per_increment(
          total_active_balance)
        finality_delay = get_finality_delay(state)

      var balance = state.balances.item(index)
      let maybeDelta = get_flag_and_inactivity_delta_for_validator(
        cfg, state, base_reward_per_increment, info, finality_delay, index,
        inactivity_score)
      if maybeDelta.isOk:
        # Can't use isErrOr in generics
        let (validator_index, reward0, reward1, reward2, penalty0, penalty1, penalty2) =
          maybeDelta.get
        info.validators[validator_index].delta.rewards += reward0 + reward1 + reward2
        info.validators[validator_index].delta.penalties += penalty0 + penalty1 + penalty2
        increase_balance(balance, info.validators[index].delta.rewards)
        decrease_balance(balance, info.validators[index].delta.penalties)
      balance

  # The two directly balance-changing operations, from Altair through Deneb,
  # are these. The rest is necessary to look past a single epoch transition,
  # but that's not the use case here.
  var post_epoch_balance = reward_and_penalties_balance
  decrease_balance(
    post_epoch_balance,
    get_slashing(state, info.balances.current_epoch, index))

  # Electra adds process_pending_balance_deposit to the list of potential
  # balance-changing epoch operations. This should probably be cached, so
  # the 16+ invocations of this function each time, e.g., withdrawals are
  # calculated don't repeat it, if it's empirically too expensive. Limits
  # exist on how large this structure can get though.
  when type(state).kind >= ConsensusFork.Electra:
    let available_for_processing = state.deposit_balance_to_consume +
      get_activation_exit_churn_limit(cfg, state, cache)
    var processed_amount = 0.Gwei

    for deposit in state.pending_balance_deposits:
      let
        validator = state.validators.item(deposit.index)
        deposit_validator_index = ValidatorIndex.init(deposit.index).valueOr:
          break

      # Validator is exiting, postpone the deposit until after withdrawable epoch
      if validator.exit_epoch < FAR_FUTURE_EPOCH:
        if  not(get_current_epoch(state) <= validator.withdrawable_epoch) and
            deposit_validator_index == index:
          increase_balance(post_epoch_balance, deposit.amount)
      # Validator is not exiting, attempt to process deposit
      else:
        if not(processed_amount + deposit.amount > available_for_processing):
          if deposit_validator_index == index:
            increase_balance(post_epoch_balance, deposit.amount)
          processed_amount += deposit.amount

  post_epoch_balance

proc get_next_slot_expected_withdrawals*(
    cfg: RuntimeConfig, state: deneb.BeaconState, cache: var StateCache,
    info: var altair.EpochInfo): seq[Withdrawal] =
  get_expected_withdrawals_aux(state, (state.slot + 1).epoch) do:
    # validator_index is defined by an injected symbol within the template
    get_validator_balance_after_epoch(
      cfg, state, cache, info, validator_index.ValidatorIndex)

proc get_next_slot_expected_withdrawals*(
    cfg: RuntimeConfig, state: electra.BeaconState, cache: var StateCache,
    info: var altair.EpochInfo): seq[Withdrawal] =
  let (res, _) = get_expected_withdrawals_with_partial_count_aux(
      state, (state.slot + 1).epoch) do:
    # validator_index is defined by an injected symbol within the template
    get_validator_balance_after_epoch(
      cfg, state, cache, info, validator_index.ValidatorIndex)
  res
