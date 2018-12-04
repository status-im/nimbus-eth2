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

func min_empty_validator_index(validators: seq[ValidatorRecord], current_slot: uint64): Option[int] =
  for i, v in validators:
    if v.balance == 0 and
        v.latest_status_change_slot + DELETION_PERIOD.uint64 <= current_slot:
      return some(i)

func get_new_validators*(current_validators: seq[ValidatorRecord],
                         fork_data: ForkData,
                         pubkey: ValidatorPubKey,
                         deposit: uint64,
                         proof_of_possession: seq[byte],
                         withdrawal_credentials: Eth2Digest,
                         randao_commitment: Eth2Digest,
                         status: ValidatorStatusCodes,
                         current_slot: uint64
                         ): tuple[validators: seq[ValidatorRecord], index: int] =
  # TODO Spec candidate: inefficient API
  #
  # Check that validator really did register
  # let signed_message = signed_message = bytes32(pubkey) + withdrawal_credentials + randao_commitment
  # assert BLSVerify(pub=pubkey,
  #                  msg=hash(signed_message),
  #                  sig=proof_of_possession,
  # domain=get_domain(
  #     fork_data,
  #     current_slot,
  #     DOMAIN_DEPOSIT
  # ))

  var new_validators = current_validators

  for index, val in new_validators.mpairs():
    if val.pubkey == pubkey:
      # assert deposit_size >= MIN_TOPUP_SIZE
      # assert val.status != WITHDRAWN
      # assert val.withdrawal_credentials == withdrawal_credentials

      val.balance.inc(deposit.int)
      return (new_validators, index)

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

  let index = min_empty_validator_index(new_validators, current_slot)
  if index.isNone:
    new_validators.add(rec)
    (new_validators, len(new_validators) - 1)
  else:
    new_validators[index.get()] = rec
    (new_validators, index.get())

func get_active_validator_indices*(validators: openArray[ValidatorRecord]): seq[Uint24] =
  ## Select the active validators
  for idx, val in validators:
    if val.status in {ACTIVE, PENDING_EXIT}:
      result.add idx.Uint24

func get_new_shuffling*(seed: Eth2Digest,
                        validators: openArray[ValidatorRecord],
                        crosslinking_start_shard: uint64
                        ): array[EPOCH_LENGTH, seq[ShardAndCommittee]] =
  ## Split up validators into groups at the start of every epoch,
  ## determining at what height they can make attestations and what shard they are making crosslinks for
  ## Implementation should do the following: http://vitalik.ca/files/ShuffleAndAssign.png

  let
    active_validators = get_active_validator_indices(validators)
    committees_per_slot = clamp(
      len(active_validators) div EPOCH_LENGTH div TARGET_COMMITTEE_SIZE,
      1, SHARD_COUNT div EPOCH_LENGTH).uint64
    # Shuffle with seed
    shuffled_active_validator_indices = shuffle(active_validators, seed)
    # Split the shuffled list into cycle_length pieces
    validators_per_slot = split(shuffled_active_validator_indices, EPOCH_LENGTH)

  assert validators_per_slot.len() == EPOCH_LENGTH # what split should do..

  for slot, slot_indices in validators_per_slot:
    let
      shard_indices = split(slot_indices, committees_per_slot)
      shard_id_start =
        crosslinking_start_shard + slot.uint64 * committees_per_slot

    var committees = newSeq[ShardAndCommittee](shard_indices.len)
    for shard_position, indices in shard_indices:
      committees[shard_position].shard =
        uint64(shard_id_start + shard_position.uint64) mod SHARD_COUNT.uint64
      committees[shard_position].committee = indices

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
    # TODO h.update hashSSZ(pubkey)

func get_effective_balance*(validator: ValidatorRecord): uint64 =
    min(validator.balance, MAX_DEPOSIT.uint64)

func exit_validator*(index: Uint24,
                     state: var BeaconState,
                     penalize: bool,
                     current_slot: uint64) =
  ## Remove the validator with the given `index` from `state`.
  ## Note that this function mutates `state`.

  state.validator_registry_exit_count.inc()

  var
    validator = state.validator_registry[index]

  validator.latest_status_change_slot = current_slot
  validator.exit_count = state.validator_registry_exit_count

  # Remove validator from persistent committees
  for committee in state.persistent_committees.mitems():
    for i, validator_index in committee:
      if validator_index == index:
        committee.delete(i)
        break

  if penalize:
    validator.status = EXITED_WITH_PENALTY
    state.latest_penalized_exit_balances[
      (current_slot div COLLECTIVE_PENALTY_CALCULATION_PERIOD.uint64).int].inc(
        get_effective_balance(validator).int)

    var
      whistleblower =
        state.validator_registry[get_beacon_proposer_index(state, current_slot).int]
      whistleblower_reward =
        validator.balance div WHISTLEBLOWER_REWARD_QUOTIENT.uint64
    whistleblower.balance.inc(whistleblower_reward.int)
    validator.balance.dec(whistleblower_reward.int)
  else:
    validator.status = PENDING_EXIT

  state.validator_registry_delta_chain_tip =
    get_new_validator_registry_delta_chain_tip(
      state.validator_registry_delta_chain_tip,
      index,
      validator.pubkey,
      EXIT,
  )

func get_changed_validators*(validators: seq[ValidatorRecord],
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
  var validators = validators

  # The active validators
  let active_validator_indices = get_active_validator_indices(validators)
  # The total balance of active validators
  # TODO strange spec code
  let total_balance = sum(mapIt(active_validator_indices, get_effective_balance(validators[it])))
  # The maximum total Gwei that can be deposited and withdrawn
  let max_allowable_change = max(
      uint64(2 * MAX_DEPOSIT * GWEI_PER_ETH),
      total_balance div MAX_CHURN_QUOTIENT.uint64
  )

  # Go through the list start to end, depositing and withdrawing as many as possible
  var total_changed: uint64 = 0
  var validator_registry_delta_chain_tip = validator_registry_delta_chain_tip
  for i in 0..<validators.len:
    if validators[i].status == PENDING_ACTIVATION:
      validators[i].status = ACTIVE
      total_changed.inc(get_effective_balance(validators[i]).int)
      let validator_registry_delta_chain_tip =
        get_new_validator_registry_delta_chain_tip(
          validator_registry_delta_chain_tip,
          i.Uint24,
          validators[i].pubkey,
          ACTIVATION,
      )
    elif validators[i].status == EXITED_WITHOUT_PENALTY:
      validators[i].latest_status_change_slot = current_slot
      total_changed.inc(get_effective_balance(validators[i]).int)
      validator_registry_delta_chain_tip =
        get_new_validator_registry_delta_chain_tip(
          validator_registry_delta_chain_tip,
          i.Uint24,
          validators[i].pubkey,
          EXIT,
      )
    if total_changed >= max_allowable_change:
        break

  # Calculate the total ETH that has been penalized in the last ~2-3 withdrawal periods
  let period_index =
    (current_slot div COLLECTIVE_PENALTY_CALCULATION_PERIOD.uint64).int
  let total_penalties = (
    (latest_penalized_exit_balances[period_index]) +
    (if period_index >= 1: latest_penalized_exit_balances[period_index - 1] else: 0) +
    (if period_index >= 2: latest_penalized_exit_balances[period_index - 2] else: 0)
  )

  # Calculate penalties for slashed validators
  func to_penalize(v: ValidatorRecord): bool =
      v.status == EXITED_WITH_PENALTY
  var validators_to_penalize = filter(validators, to_penalize)
  for v in validators_to_penalize.mitems():
    v.balance.dec(
      (get_effective_balance(v) * min(total_penalties * 3'u64, total_balance) div
        total_balance).int)

  (validators, latest_penalized_exit_balances, validator_registry_delta_chain_tip)
