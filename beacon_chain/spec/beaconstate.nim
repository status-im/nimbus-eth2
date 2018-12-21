# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles, math, options, sequtils,
  ../extras, ../ssz,
  ./crypto, ./datatypes, ./digest, ./helpers, ./validator

func process_deposit(state: var BeaconState,
                     pubkey: ValidatorPubKey,
                     deposit: uint64,
                     proof_of_possession: ValidatorSig,
                     withdrawal_credentials: Eth2Digest,
                     randao_commitment: Eth2Digest): Uint24 =
  ## Process a deposit from Ethereum 1.0.
  let msg = hash_tree_root_final(
    (pubkey, withdrawal_credentials, randao_commitment))
  assert bls_verify(
    pubkey, msg.data, proof_of_possession,
    get_domain(state.fork_data, state.slot, DOMAIN_DEPOSIT))

  let validator_pubkeys = mapIt(state.validator_registry, it.pubkey)

  if pubkey notin validator_pubkeys:
    # Add new validator
    let validator = ValidatorRecord(
      pubkey: pubkey,
      withdrawal_credentials: withdrawal_credentials,
      randao_commitment: randao_commitment,
      randao_layers: 0,
      balance: deposit,
      status: PENDING_ACTIVATION,
      latest_status_change_slot: state.slot,
      exit_count: 0
    )

    let index = min_empty_validator_index(state.validator_registry, state.slot)
    if index.isNone():
      state.validator_registry.add(validator)
      (len(state.validator_registry) - 1).Uint24
    else:
      state.validator_registry[index.get()] = validator
      index.get().Uint24
  else:
    # Increase balance by deposit
    let index = validator_pubkeys.find(pubkey)
    let validator = addr state.validator_registry[index]
    assert validator.withdrawal_credentials == withdrawal_credentials

    validator.balance += deposit
    index.Uint24

func activate_validator(state: var BeaconState,
                        index: Uint24) =
  ## Activate the validator with the given ``index``.
  let validator = addr state.validator_registry[index]

  if validator.status != PENDING_ACTIVATION:
      return

  validator.status = ACTIVE
  validator.latest_status_change_slot = state.slot
  state.validator_registry_delta_chain_tip =
    get_new_validator_registry_delta_chain_tip(
      state.validator_registry_delta_chain_tip,
      index,
      validator.pubkey,
      ACTIVATION,
    )

func initiate_validator_exit(state: var BeaconState,
                             index: Uint24) =
  ## Initiate exit for the validator with the given ``index``.
  let validator = addr state.validator_registry[index]
  if validator.status != ACTIVE:
    return

  validator.status = ACTIVE_PENDING_EXIT
  validator.latest_status_change_slot = state.slot

func exit_validator(state: var BeaconState,
                     index: Uint24,
                     new_status: ValidatorStatusCodes) =
  ## Exit the validator with the given ``index``.
  ## Note that this function mutates ``state``.

  let
    validator = addr state.validator_registry[index]
    prev_status = validator.status

  if prev_status == EXITED_WITH_PENALTY:
    return

  validator.status = new_status
  validator.latest_status_change_slot = state.slot

  if new_status == EXITED_WITH_PENALTY:
    state.latest_penalized_exit_balances[
      (state.slot div COLLECTIVE_PENALTY_CALCULATION_PERIOD).int] +=
        get_effective_balance(validator[])

    let
      whistleblower = addr state.validator_registry[
        get_beacon_proposer_index(state, state.slot)]
      whistleblower_reward =
        validator.balance div WHISTLEBLOWER_REWARD_QUOTIENT

    whistleblower.balance += whistleblower_reward
    validator.balance -= whistleblower_reward

  if prev_status == EXITED_WITHOUT_PENALTY:
    return

  # The following updates only occur if not previous exited
  state.validator_registry_exit_count += 1
  validator.exit_count = state.validator_registry_exit_count
  state.validator_registry_delta_chain_tip =
    get_new_validator_registry_delta_chain_tip(
      state.validator_registry_delta_chain_tip,
      index,
      validator.pubkey,
      ValidatorSetDeltaFlags.EXIT
    )

  # Remove validator from persistent committees
  for committee in state.persistent_committees.mitems():
    for i, validator_index in committee:
      if validator_index == index:
        committee.delete(i)
        break

func update_validator_status*(state: var BeaconState,
                              index: Uint24,
                              new_status: ValidatorStatusCodes) =
  ##  Update the validator status with the given ``index`` to ``new_status``.
  ## Handle other general accounting related to this status update.
  if new_status == ACTIVE:
      activate_validator(state, index)
  if new_status == ACTIVE_PENDING_EXIT:
      initiate_validator_exit(state, index)
  if new_status in [EXITED_WITH_PENALTY, EXITED_WITHOUT_PENALTY]:
      exit_validator(state, index, new_status)

func get_initial_beacon_state*(
    initial_validator_deposits: openArray[Deposit],
    genesis_time: uint64,
    processed_pow_receipt_root: Eth2Digest): BeaconState =
  ## BeaconState constructor
  ##
  ## Before the beacon chain starts, validators will register in the Eth1 chain
  ## and deposit ETH. When enough many validators have registered, a
  ## `ChainStart` log will be emitted and the beacon chain can start beaconing.
  ##
  ## Because the state root hash is part of the genesis block, the beacon state
  ## must be calculated before creating the genesis block.

  # Induct validators
  # Not in spec: the system doesn't work unless there are at least EPOCH_LENGTH
  # validators - there needs to be at least one member in each committee -
  # good to know for testing, though arguably the system is not that useful at
  # at that point :)
  assert initial_validator_deposits.len >= EPOCH_LENGTH

  var state = BeaconState(
    # Misc
    slot: INITIAL_SLOT_NUMBER,
    genesis_time: genesis_time,
    fork_data: ForkData(
        pre_fork_version: INITIAL_FORK_VERSION,
        post_fork_version: INITIAL_FORK_VERSION,
        fork_slot: INITIAL_SLOT_NUMBER,
    ),

    validator_registry_latest_change_slot: INITIAL_SLOT_NUMBER,
    validator_registry_exit_count: 0,
    validator_registry_delta_chain_tip: ZERO_HASH,

    # Finality
    previous_justified_slot: INITIAL_SLOT_NUMBER,
    justified_slot: INITIAL_SLOT_NUMBER,
    finalized_slot: INITIAL_SLOT_NUMBER,

    # Recent state
    latest_state_recalculation_slot: INITIAL_SLOT_NUMBER,

     # PoW receipt root
    processed_pow_receipt_root: processed_pow_receipt_root,
  )

  # handle initial deposits and activations
  for deposit in initial_validator_deposits:
    let validator_index = process_deposit(
      state,
      deposit.deposit_data.deposit_parameters.pubkey,
      deposit.deposit_data.value,
      deposit.deposit_data.deposit_parameters.proof_of_possession,
      deposit.deposit_data.deposit_parameters.withdrawal_credentials,
      deposit.deposit_data.deposit_parameters.randao_commitment
    )
    if state.validator_registry[validator_index].balance >= MAX_DEPOSIT:
      update_validator_status(state, validator_index, ACTIVE)

  # set initial committee shuffling
  let
    initial_shuffling =
      get_new_shuffling(Eth2Digest(), state.validator_registry, 0)

  # initial_shuffling + initial_shuffling in spec, but more ugly
  for i, n in initial_shuffling:
    state.shard_committees_at_slots[i] = n
    state.shard_committees_at_slots[EPOCH_LENGTH + i] = n

  # set initial persistent shuffling
  let active_validator_indices =
    get_active_validator_indices(state.validator_registry)

  state.persistent_committees = split(shuffle(
    active_validator_indices, ZERO_HASH), SHARD_COUNT)

  state

func get_block_root*(state: BeaconState,
                     slot: uint64): Eth2Digest =
  doAssert state.slot <= slot + LATEST_BLOCK_ROOTS_LENGTH
  doAssert slot < state.slot
  state.latest_block_roots[slot mod LATEST_BLOCK_ROOTS_LENGTH]

func get_attestation_participants*(state: BeaconState,
                                   attestation_data: AttestationData,
                                   participation_bitfield: seq[byte]): seq[Uint24] =
  ## Attestation participants in the attestation data are called out in a
  ## bit field that corresponds to the committee of the shard at the time - this
  ## function converts it to list of indices in to BeaconState.validators
  ## Returns empty list if the shard is not found
  # TODO Linear search through shard list? borderline ok, it's a small list
  # TODO bitfield type needed, once bit order settles down
  # TODO iterator candidate
  let
    sncs_for_slot = get_shard_committees_at_slot(
      state, attestation_data.slot)

  for snc in sncs_for_slot:
    if snc.shard != attestation_data.shard:
      continue

    # TODO investigate functional library / approach to help avoid loop bugs
    assert len(participation_bitfield) == ceil_div8(len(snc.committee))
    for i, vindex in snc.committee:
      if bitIsSet(participation_bitfield, i):
        result.add(vindex)
    return # found the shard, we're done

func process_ejections*(state: var BeaconState) =
  ## Iterate through the validator registry
  ## and eject active validators with balance below ``EJECTION_BALANCE``.

  for i, v in state.validator_registry.mpairs():
    if is_active_validator(v) and v.balance < EJECTION_BALANCE:
      exit_validator(state, i.Uint24, EXITED_WITHOUT_PENALTY)

func update_validator_registry*(state: var BeaconState) =
  # Update validator registry.
  # Note that this function mutates ``state``.

  (state.validator_registry,
    state.latest_penalized_exit_balances,
    state.validator_registry_delta_chain_tip) =
      get_updated_validator_registry(
        state.validator_registry,
        state.latest_penalized_exit_balances,
        state.validator_registry_delta_chain_tip,
        state.slot
      )

proc checkAttestation*(state: BeaconState, attestation: Attestation): bool =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot.
  ##
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#attestations-1

  if attestation.data.slot + MIN_ATTESTATION_INCLUSION_DELAY >= state.slot:
    warn("Attestation too new",
      attestation_slot = attestation.data.slot, state_slot = state.slot)
    return

  if attestation.data.slot + EPOCH_LENGTH <= state.slot:
    warn("Attestation too old",
      attestation_slot = attestation.data.slot, state_slot = state.slot)
    return

  let expected_justified_slot =
    if attestation.data.slot >= state.slot - (state.slot mod EPOCH_LENGTH):
      state.justified_slot
    else:
      state.previous_justified_slot

  if attestation.data.justified_slot != expected_justified_slot:
    warn("Unexpected justified slot",
      attestation_justified_slot = attestation.data.justified_slot,
      expected_justified_slot)
    return

  let expected_justified_block_root =
    get_block_root(state, attestation.data.justified_slot)
  if attestation.data.justified_block_root != expected_justified_block_root:
    warn("Unexpected justified block root",
      attestation_justified_block_root = attestation.data.justified_block_root,
      expected_justified_block_root)
    return

  if state.latest_crosslinks[attestation.data.shard].shard_block_root notin [
      attestation.data.latest_crosslink_root,
      attestation.data.shard_block_root]:
    warn("Unexpected crosslink shard_block_root")
    return

  let
    participants = get_attestation_participants(
      state, attestation.data, attestation.participation_bitfield)
    group_public_key = bls_aggregate_pubkeys(mapIt(
      participants, state.validator_registry[it].pubkey))

  # Verify that aggregate_signature verifies using the group pubkey.
  let msg = hash_tree_root_final(attestation.data)

  if not bls_verify(
        group_public_key, @(msg.data) & @[0'u8], attestation.aggregate_signature,
        get_domain(state.fork_data, attestation.data.slot, DOMAIN_ATTESTATION)
      ):
    warn("Invalid attestation group signature")
    return

  # To be removed in Phase1:
  if attestation.data.shard_block_root != ZERO_HASH:
    warn("Invalid shard block root")
    return

  true
