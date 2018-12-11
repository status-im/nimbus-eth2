# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

import
  options, nimcrypto, sequtils, math,
  eth_common,
  ../ssz,
  ./crypto, ./datatypes, ./digest, ./helpers

func is_active_validator*(validator: ValidatorRecord): bool =
  validator.status in {ACTIVE, ACTIVE_PENDING_EXIT}

func min_empty_validator_index(validators: seq[ValidatorRecord], current_slot: uint64): Option[int] =
  for i, v in validators:
    if v.balance == 0 and
        v.latest_status_change_slot +
          ZERO_BALANCE_VALIDATOR_TTL.uint64 <= current_slot:
      return some(i)

func get_new_validators*(current_validators: seq[ValidatorRecord],
                         fork_data: ForkData,
                         pubkey: ValidatorPubKey,
                         deposit: uint64,
                         proof_of_possession: ValidatorSig,
                         withdrawal_credentials: Eth2Digest,
                         randao_commitment: Eth2Digest,
                         status: ValidatorStatusCodes,
                         current_slot: uint64
                         ): tuple[validators: seq[ValidatorRecord], index: int] =
  # TODO Spec candidate: inefficient API
  #
  # Check that validator really did register
  # TODO fix tests and enable (nightmare)
  # let msg = hashSSZ((pubkey, withdrawal_credentials, randao_commitment))
  # assert BLSVerify(
  #   pubkey, msg, proof_of_possession,
  #   get_domain(fork_data, current_slot, DOMAIN_DEPOSIT))

  var validators_copy = current_validators

  for index, validator in validators_copy.mpairs():
    if validator.pubkey == pubkey:
      assert validator.withdrawal_credentials == withdrawal_credentials

      validator.balance += deposit
      return (validators_copy, index)

  # new validator
  let
    rec = ValidatorRecord(
      pubkey: pubkey,
      withdrawal_credentials: withdrawal_credentials,
      randao_commitment: randao_commitment,
      randao_skips: 0,
      balance: deposit,
      status: status,
      latest_status_change_slot: current_slot,
      exit_count: 0
    )

  let index = min_empty_validator_index(validators_copy, current_slot)
  if index.isNone:
    validators_copy.add(rec)
    (validators_copy, len(validators_copy) - 1)
  else:
    validators_copy[index.get()] = rec
    (validators_copy, index.get())

func get_active_validator_indices*(validators: openArray[ValidatorRecord]): seq[Uint24] =
  ## Select the active validators
  for idx, val in validators:
    if is_active_validator(val):
      result.add idx.Uint24

func get_new_shuffling*(seed: Eth2Digest,
                        validators: openArray[ValidatorRecord],
                        crosslinking_start_shard: uint64
                        ): array[EPOCH_LENGTH, seq[ShardCommittee]] =
  ## Split up validators into groups at the start of every epoch,
  ## determining at what height they can make attestations and what shard they are making crosslinks for
  ## Implementation should do the following: http://vitalik.ca/files/ShuffleAndAssign.png

  let
    active_validator_indices = get_active_validator_indices(validators)
    committees_per_slot = clamp(
      len(active_validator_indices) div EPOCH_LENGTH div TARGET_COMMITTEE_SIZE,
      1, SHARD_COUNT div EPOCH_LENGTH).uint64
    # Shuffle with seed
    shuffled_active_validator_indices = shuffle(active_validator_indices, seed)
    # Split the shuffled list into cycle_length pieces
    validators_per_slot = split(shuffled_active_validator_indices, EPOCH_LENGTH)

  assert validators_per_slot.len() == EPOCH_LENGTH # what split should do..

  for slot, slot_indices in validators_per_slot:
    let
      shard_indices = split(slot_indices, committees_per_slot)
      shard_id_start =
        crosslinking_start_shard + slot.uint64 * committees_per_slot

    var committees = newSeq[ShardCommittee](shard_indices.len)
    for shard_position, indices in shard_indices:
      committees[shard_position].shard =
        shard_id_start + shard_position.uint64 mod SHARD_COUNT.uint64
      committees[shard_position].committee = indices
      committees[shard_position].total_validator_count =
        len(active_validator_indices).uint64

    result[slot] = committees

func get_new_validator_registry_delta_chain_tip(
    current_validator_registry_delta_chain_tip: Eth2Digest,
    index: Uint24,
    pubkey: ValidatorPubKey,
    flag: ValidatorSetDeltaFlags): Eth2Digest =
  ## Compute the next hash in the validator registry delta hash chain.

  withEth2Hash:
    h.update hashSSZ(current_validator_registry_delta_chain_tip)
    h.update hashSSZ(flag.uint8)
    h.update hashSSZ(index)
    h.update hashSSZ(pubkey)

func get_effective_balance*(validator: ValidatorRecord): uint64 =
    min(validator.balance, MAX_DEPOSIT)

func exit_validator*(index: Uint24,
                     state: var BeaconState,
                     new_status: ValidatorStatusCodes) =
  ## Remove the validator with the given `index` from `state`.
  ## Note that this function mutates `state`.

  state.validator_registry_exit_count += 1

  var
    validator = addr state.validator_registry[index]

  validator.status = new_status
  validator.latest_status_change_slot = state.slot
  validator.exit_count = state.validator_registry_exit_count

  # Remove validator from persistent committees
  for committee in state.persistent_committees.mitems():
    for i, validator_index in committee:
      if validator_index == index:
        committee.delete(i)
        break

  if new_status == EXITED_WITH_PENALTY:
    state.latest_penalized_exit_balances[
      (state.slot div COLLECTIVE_PENALTY_CALCULATION_PERIOD).int] +=
        get_effective_balance(validator[])

    var
      whistleblower = addr state.validator_registry[
        get_beacon_proposer_index(state, state.slot)]
      whistleblower_reward =
        validator.balance div WHISTLEBLOWER_REWARD_QUOTIENT

    whistleblower.balance += whistleblower_reward
    validator.balance -= whistleblower_reward

  state.validator_registry_delta_chain_tip =
    get_new_validator_registry_delta_chain_tip(
      state.validator_registry_delta_chain_tip, index, validator.pubkey,
      ValidatorSetDeltaFlags.EXIT)

func get_updated_validator_registry*(
    validator_registry: seq[ValidatorRecord],
    latest_penalized_exit_balances: seq[uint64],
    validator_registry_delta_chain_tip: Eth2Digest,
    current_slot: uint64):
      tuple[
        validators: seq[ValidatorRecord],
        latest_penalized_exit_balances: seq[uint64],
        validator_registry_delta_chain_tip: Eth2Digest] =
  ## Return changed validator registry and `latest_penalized_exit_balances`,
  ## `validator_registry_delta_chain_tip`.

  # TODO inefficient
  var
    validator_registry = validator_registry
    latest_penalized_exit_balances = latest_penalized_exit_balances

  # The active validators
  let active_validator_indices =
    get_active_validator_indices(validator_registry)
  # The total effective balance of active validators
  let total_balance = sum(mapIt(
    active_validator_indices, get_effective_balance(validator_registry[it])))

  # The maximum balance churn in Gwei (for deposits and exits separately)
  let max_balance_churn = max(
      MAX_DEPOSIT * GWEI_PER_ETH,
      total_balance div (2 * MAX_BALANCE_CHURN_QUOTIENT)
  )

  # Activate validators within the allowable balance churn
  var balance_churn = 0'u64
  var validator_registry_delta_chain_tip = validator_registry_delta_chain_tip
  for i in 0..<len(validator_registry):
    if validator_registry[i].status == PENDING_ACTIVATION and
        validator_registry[i].balance >= MAX_DEPOSIT:
      # Check the balance churn would be within the allowance
      balance_churn += get_effective_balance(validator_registry[i])
      if balance_churn > max_balance_churn:
          break

      # Activate validator
      validator_registry[i].status = ACTIVE
      validator_registry[i].latest_status_change_slot = current_slot
      validator_registry_delta_chain_tip =
        get_new_validator_registry_delta_chain_tip(
          validator_registry_delta_chain_tip,
          i.Uint24,
          validator_registry[i].pubkey,
          ACTIVATION,
        )

  # Exit validators within the allowable balance churn
  balance_churn = 0
  for i in 0..<len(validator_registry):
    if validator_registry[i].status == ACTIVE_PENDING_EXIT:
      # Check the balance churn would be within the allowance
      balance_churn += get_effective_balance(validator_registry[i])
      if balance_churn > max_balance_churn:
        break

      # Exit validator
      validator_registry[i].status = EXITED_WITHOUT_PENALTY
      validator_registry[i].latest_status_change_slot = current_slot
      validator_registry_delta_chain_tip =
        get_new_validator_registry_delta_chain_tip(
          validator_registry_delta_chain_tip,
          i.Uint24,
          validator_registry[i].pubkey,
          ValidatorSetDeltaFlags.EXIT,
        )

  # Calculate the total ETH that has been penalized in the last ~2-3 withdrawal
  # periods
  let period_index =
    (current_slot div COLLECTIVE_PENALTY_CALCULATION_PERIOD).int
  let total_penalties = (
    (latest_penalized_exit_balances[period_index]) +
    (if period_index >= 1:
      latest_penalized_exit_balances[period_index - 1] else: 0) +
    (if period_index >= 2:
      latest_penalized_exit_balances[period_index - 2] else: 0)
  )

  # Calculate penalties for slashed validators
  func to_penalize(v: ValidatorRecord): bool =
    v.status == EXITED_WITH_PENALTY
  for v in validator_registry.mitems():
    if not to_penalize(v): continue
    v.balance -=
      (get_effective_balance(v) * min(total_penalties * 3, total_balance) div
      total_balance)

  (validator_registry, latest_penalized_exit_balances,
    validator_registry_delta_chain_tip)
