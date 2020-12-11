# beacon_chain
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  ssz/types,
  spec/[datatypes, digest, helpers]

func diffModIncrement[T, U](hl: HashArray[U, T], end0, end1: uint64):
    HashList[T, U] =
  doAssert end1 >= end0
  # because RANDAO mixes update within epochs, include overlap with current
  # slot/epoch/time unit.
  for i in end0 ..< end1:
    result.add hl[i mod U.uint64]

func applyModIncrement[T, U](
    ha: var HashArray[U, T], hl: HashList[T, U], slot: uint64) =
  var indexSlot = slot

  for item in hl:
    ha[indexSlot mod U.uint64] = item
    indexSlot += 1

func diffAppend[T, U](hl: HashList[T, U], end0: int): HashList[T, U] =
  doAssert hl.len >= end0
  for i in end0 ..< hl.len:
    result.add hl[i]

func applyAppend[T, U](ha: var HashList[T, U], hl: HashList[T, U]) =
  for item in hl:
    ha.add item

func getImmutableValidatorData(validator: Validator): ImmutableValidatorData =
  ImmutableValidatorData(
    pubkey: validator.pubkey,
    withdrawal_credentials: validator.withdrawal_credentials)

func diffValidatorIdentities(state: BeaconState, skipFirst: int):
    HashList[ImmutableValidatorData, Limit VALIDATOR_REGISTRY_LIMIT] =
  # These are append-only. Ignore the first specified number of identities.
  doAssert skipFirst <= state.validators.len
  for i in skipFirst ..< state.validators.len:
    result.add getImmutableValidatorData(state.validators[i])

func applyValidatorIdentities(
    validators: var HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT],
    hl: HashList[ImmutableValidatorData, Limit VALIDATOR_REGISTRY_LIMIT]) =
  for item in hl:
    validators.add Validator(
      pubkey: item.pubkey,
      withdrawal_credentials: item.withdrawal_credentials)

func getValidatorStatus(validator: Validator): ValidatorStatus =
  ValidatorStatus(
      effective_balance: validator.effective_balance,
      slashed: validator.slashed,
      activation_eligibility_epoch: validator.activation_eligibility_epoch,
      activation_epoch: validator.activation_epoch,
      exit_epoch: validator.exit_epoch,
      withdrawable_epoch: validator.withdrawable_epoch)

func getValidatorStatuses(state: BeaconState):
    HashList[ValidatorStatus, Limit VALIDATOR_REGISTRY_LIMIT] =
  for validator in state.validators:
    result.add getValidatorStatus(validator)

func setValidatorStatuses(
    validators: var HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT],
    hl: HashList[ValidatorStatus, Limit VALIDATOR_REGISTRY_LIMIT]) =
  doAssert validators.len == hl.len

  for i in 0 ..< hl.len:
    validators[i].effective_balance = hl[i].effective_balance
    validators[i].slashed = hl[i].slashed

    validators[i].activation_eligibility_epoch =
      hl[i].activation_eligibility_epoch
    validators[i].activation_epoch = hl[i].activation_epoch
    validators[i].exit_epoch = hl[i].exit_epoch
    validators[i].withdrawable_epoch = hl[i].withdrawable_epoch

func deltaEncodeBalances[T](balances: T): T =
  if balances.len == 0:
    return

  result.add balances[0]

  for i in 1 ..< balances.len:
    result.add balances[i] - balances[i - 1]

func deltaDecodeBalances[T](encodedBalances: T): T =
  var accum = 0'u64
  for i in 0 ..< encodedBalances.len:
    accum += encodedBalances[i]
    result.add accum

func diffStates*(state0, state1: BeaconState): BeaconStateDiff =
  doAssert state1.slot > state0.slot
  doAssert state0.slot + 128 > state1.slot
  # TODO not here, but in chainDag, an isancestorof check

  doAssert state0.genesis_time == state1.genesis_time
  doAssert state0.genesis_validators_root == state1.genesis_validators_root
  doAssert state0.fork == state1.fork

  BeaconStateDiff(
    slot: state1.slot,
    latest_block_header: state1.latest_block_header,

    block_roots: diffModIncrement[Eth2Digest, SLOTS_PER_HISTORICAL_ROOT.int64](
      state1.block_roots, state0.slot.uint64, state1.slot.uint64),
    state_roots: diffModIncrement[Eth2Digest, SLOTS_PER_HISTORICAL_ROOT.int64](
      state1.state_roots, state0.slot.uint64, state1.slot.uint64),
    historical_roots: diffAppend[Eth2Digest, HISTORICAL_ROOTS_LIMIT.int64](
      state1.historical_roots, state0.historical_roots.len),

    eth1_data: state1.eth1_data,
    eth1_data_votes: state1.eth1_data_votes,
    eth1_deposit_index: state1.eth1_deposit_index,

    validatorIdentities: diffValidatorIdentities(state1, state0.validators.len),
    validatorStatuses: getValidatorStatuses(state1),
    balances: deltaEncodeBalances[
      HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]](state1.balances),

    # RANDAO mixes gets updated every block, in place, so ensure there's always
    # >=1 value from it
    randao_mixes: diffModIncrement[Eth2Digest, EPOCHS_PER_HISTORICAL_VECTOR.int64](
      state1.randao_mixes, state0.slot.compute_epoch_at_slot.uint64,
      state1.slot.compute_epoch_at_slot.uint64 + 1),
    slashings: diffModIncrement[uint64, EPOCHS_PER_SLASHINGS_VECTOR.int64](
      state1.slashings, state0.slot.compute_epoch_at_slot.uint64,
      state1.slot.compute_epoch_at_slot.uint64),

    previous_epoch_attestations: state1.previous_epoch_attestations,
    current_epoch_attestations: state1.current_epoch_attestations,

    justification_bits: state1.justification_bits,
    previous_justified_checkpoint: state1.previous_justified_checkpoint,
    current_justified_checkpoint: state1.current_justified_checkpoint,
    finalized_checkpoint: state1.finalized_checkpoint
  )

func applyDiff*(state: var BeaconState, stateDiff: BeaconStateDiff) =
  # Carry over always-unchanged genesis_time, genesis_validators_root, and
  # fork.
  state.latest_block_header = stateDiff.latest_block_header

  applyModIncrement[Eth2Digest, SLOTS_PER_HISTORICAL_ROOT.int64](
    state.block_roots, stateDiff.block_roots, state.slot.uint64)
  applyModIncrement[Eth2Digest, SLOTS_PER_HISTORICAL_ROOT.int64](
    state.state_roots, stateDiff.state_roots, state.slot.uint64)
  applyAppend[Eth2Digest, HISTORICAL_ROOTS_LIMIT.int64](
    state.historical_roots, stateDiff.historical_roots)

  state.eth1_data = stateDiff.eth1_data
  state.eth1_data_votes = stateDiff.eth1_data_votes
  state.eth1_deposit_index = stateDiff.eth1_deposit_index

  applyValidatorIdentities(state.validators, stateDiff.validator_identities)
  setValidatorStatuses(state.validators, stateDiff.validator_statuses)
  state.balances = deltaDecodebalances[
    HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]](stateDiff.balances)

  # RANDAO mixes gets updated every block, in place, so ensure there's always
  # >=1 value from it
  applyModIncrement[Eth2Digest, EPOCHS_PER_HISTORICAL_VECTOR.int64](
    state.randao_mixes, stateDiff.randao_mixes, state.slot.epoch.uint64 + 1)
  applyModIncrement[uint64, EPOCHS_PER_SLASHINGS_VECTOR.int64](
    state.slashings, stateDiff.slashings, state.slot.epoch.uint64)

  state.previous_epoch_attestations = stateDiff.previous_epoch_attestations
  state.current_epoch_attestations = stateDiff.current_epoch_attestations

  state.justification_bits = stateDiff.justification_bits
  state.previous_justified_checkpoint = stateDiff.previous_justified_checkpoint
  state.current_justified_checkpoint = stateDiff.current_justified_checkpoint
  state.finalized_checkpoint = stateDiff.finalized_checkpoint

  # Don't update slot until the end, because various other updates depend on it
  state.slot = stateDiff.slot
