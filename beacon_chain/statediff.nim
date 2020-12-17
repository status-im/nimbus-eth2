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

func diffModIncEpoch[T, U](hl: HashArray[U, T], startSlot: uint64):
    array[SLOTS_PER_EPOCH, T] =
  static: doAssert U.uint64 mod SLOTS_PER_EPOCH == 0
  doAssert startSlot mod SLOTS_PER_EPOCH == 0
  for i in startSlot ..< startSlot + SLOTS_PER_EPOCH:
    result[i mod SLOTS_PER_EPOCH] = hl[i mod U.uint64]

func applyModIncrement[T, U](
    ha: var HashArray[U, T], hl: array[SLOTS_PER_EPOCH, T], slot: uint64) =
  var indexSlot = slot

  for item in hl:
    ha[indexSlot mod U.uint64] = item
    indexSlot += 1

func getImmutableValidatorData*(validator: Validator): ImmutableValidatorData =
  ImmutableValidatorData(
    pubkey: validator.pubkey,
    withdrawal_credentials: validator.withdrawal_credentials)

func applyValidatorIdentities(
    validators: var HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT],
    hl: auto) =
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
    List[ValidatorStatus, Limit VALIDATOR_REGISTRY_LIMIT] =
  for validator in state.validators:
    result.add getValidatorStatus(validator)

func setValidatorStatuses(
    validators: var HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT],
    hl: List[ValidatorStatus, Limit VALIDATOR_REGISTRY_LIMIT]) =
  doAssert validators.len == hl.len

  for i in 0 ..< hl.len:
    validators[i].effective_balance = hl[i].effective_balance
    validators[i].slashed = hl[i].slashed

    validators[i].activation_eligibility_epoch =
      hl[i].activation_eligibility_epoch
    validators[i].activation_epoch = hl[i].activation_epoch
    validators[i].exit_epoch = hl[i].exit_epoch
    validators[i].withdrawable_epoch = hl[i].withdrawable_epoch

func deltaEncodeBalances*[T, U](balances: HashList[T, U]): List[T, U] =
  if balances.len == 0:
    return

  result.add balances[0]

  for i in 1 ..< balances.len:
    result.add balances[i] - balances[i - 1]

  doAssert balances.len == result.len

func deltaDecodeBalances*[T, U](encodedBalances: List[T, U]): HashList[T, U] =
  var accum = 0'u64
  for i in 0 ..< encodedBalances.len:
    accum += encodedBalances[i]
    result.add accum

  doAssert encodedBalances.len == result.len

func diffStates*(state0, state1: BeaconState): BeaconStateDiff =
  doAssert state1.slot > state0.slot
  doAssert state0.slot.isEpoch
  doAssert state1.slot == state0.slot + SLOTS_PER_EPOCH
  # TODO not here, but in chainDag, an isancestorof check

  doAssert state0.genesis_time == state1.genesis_time
  doAssert state0.genesis_validators_root == state1.genesis_validators_root
  doAssert state0.fork == state1.fork
  doAssert state1.historical_roots.len - state0.historical_roots.len in [0, 1]

  let historical_root_added =
    state0.historical_roots.len != state1.historical_roots.len

  BeaconStateDiff(
    slot: state1.slot,
    latest_block_header: state1.latest_block_header,

    block_roots: diffModIncEpoch[Eth2Digest, SLOTS_PER_HISTORICAL_ROOT.int64](
      state1.block_roots, state0.slot.uint64),
    state_roots: diffModIncEpoch[Eth2Digest, SLOTS_PER_HISTORICAL_ROOT.int64](
      state1.state_roots, state0.slot.uint64),
    historical_root_added: historical_root_added,
    historical_root:
      if historical_root_added:
        state1.historical_roots[state0.historical_roots.len]
      else:
        default(Eth2Digest),
    eth1_data: state1.eth1_data,
    eth1_data_votes: state1.eth1_data_votes,
    eth1_deposit_index: state1.eth1_deposit_index,

    validatorStatuses: getValidatorStatuses(state1),
    balances: deltaEncodeBalances[uint64, Limit VALIDATOR_REGISTRY_LIMIT](
      state1.balances),

    # RANDAO mixes gets updated every block, in place
    randao_mix: state1.randao_mixes[state0.slot.compute_epoch_at_slot.uint64 mod
      EPOCHS_PER_HISTORICAL_VECTOR.uint64],
    slashing: state1.slashings[state0.slot.compute_epoch_at_slot.uint64 mod
      EPOCHS_PER_HISTORICAL_VECTOR.uint64],

    previous_epoch_attestations: state1.previous_epoch_attestations,
    current_epoch_attestations: state1.current_epoch_attestations,

    justification_bits: state1.justification_bits,
    previous_justified_checkpoint: state1.previous_justified_checkpoint,
    current_justified_checkpoint: state1.current_justified_checkpoint,
    finalized_checkpoint: state1.finalized_checkpoint
  )

func applyDiff*(
    state: var BeaconState,
    immutableValidators: openArray[ImmutableValidatorData],
    stateDiff: BeaconStateDiff) =
  # Carry over unchanged genesis_time, genesis_validators_root, and fork.
  state.latest_block_header = stateDiff.latest_block_header

  applyModIncrement[Eth2Digest, SLOTS_PER_HISTORICAL_ROOT.int64](
    state.block_roots, stateDiff.block_roots, state.slot.uint64)
  applyModIncrement[Eth2Digest, SLOTS_PER_HISTORICAL_ROOT.int64](
    state.state_roots, stateDiff.state_roots, state.slot.uint64)
  if stateDiff.historical_root_added:
    state.historical_roots.add stateDiff.historical_root

  state.eth1_data = stateDiff.eth1_data
  state.eth1_data_votes = stateDiff.eth1_data_votes
  state.eth1_deposit_index = stateDiff.eth1_deposit_index

  applyValidatorIdentities(state.validators, immutableValidators)
  setValidatorStatuses(state.validators, stateDiff.validator_statuses)
  state.balances = deltaDecodeBalances[uint64, Limit VALIDATOR_REGISTRY_LIMIT](
    stateDiff.balances)

  # RANDAO mixes gets updated every block, in place, so ensure there's always
  # >=1 value from it
  let epochIndex =
    state.slot.epoch.uint64 mod EPOCHS_PER_HISTORICAL_VECTOR.uint64
  state.randao_mixes[epochIndex] = stateDiff.randao_mix
  state.slashings[epochIndex] = stateDiff.slashing

  state.previous_epoch_attestations = stateDiff.previous_epoch_attestations
  state.current_epoch_attestations = stateDiff.current_epoch_attestations

  state.justification_bits = stateDiff.justification_bits
  state.previous_justified_checkpoint = stateDiff.previous_justified_checkpoint
  state.current_justified_checkpoint = stateDiff.current_justified_checkpoint
  state.finalized_checkpoint = stateDiff.finalized_checkpoint

  # Don't update slot until the end, because various other updates depend on it
  state.slot = stateDiff.slot
