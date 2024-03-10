{.push raises: [].}

import
  ../extras,
  "."/[beaconstate, eth2_merkleization, validator]

from std/math import sum, `^`
from stew/bitops2 import setBit
from ./datatypes/capella import
  BeaconState, HistoricalSummary, Withdrawal, WithdrawalIndex

export extras, phase0, altair

# Accessors that implement the max condition in `get_total_balance`:
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_total_balance
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/altair/beacon-chain.md#get_unslashed_participating_indices
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
      max(EFFECTIVE_BALANCE_INCREMENT, res.previous_epoch[flag_index])

  res.current_epoch_TIMELY_TARGET =
    max(EFFECTIVE_BALANCE_INCREMENT, res.current_epoch_TIMELY_TARGET)

  res.current_epoch = max(EFFECTIVE_BALANCE_INCREMENT, res.current_epoch)

  res

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

  if current_epoch_target_balance * 3 >= total_active_balance * 2:
    res.current_justified_checkpoint = Checkpoint(
      epoch: current_epoch, root: get_block_root(state, current_epoch))
    uint8(res.justification_bits).setBit 0

  # Process finalizations
  let bitfield = uint8(res.justification_bits)

  ## The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th
  ## as source
  if (bitfield and 0b1110) == 0b1110 and
     old_previous_justified_checkpoint.epoch + 3 == current_epoch:
    res.finalized_checkpoint = old_previous_justified_checkpoint

  ## The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as
  ## source
  if (bitfield and 0b110) == 0b110 and
     old_previous_justified_checkpoint.epoch + 2 == current_epoch:
    res.finalized_checkpoint = old_previous_justified_checkpoint

  ## The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as
  ## source
  if (bitfield and 0b111) == 0b111 and
     old_current_justified_checkpoint.epoch + 2 == current_epoch:
    res.finalized_checkpoint = old_current_justified_checkpoint

  ## The 1st/2nd most recent epochs are justified, the 1st using the 2nd as
  ## source
  if (bitfield and 0b11) == 0b11 and
     old_current_justified_checkpoint.epoch + 1 == current_epoch:
    res.finalized_checkpoint = old_current_justified_checkpoint

  res

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
