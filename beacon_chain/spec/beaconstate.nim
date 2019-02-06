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

func get_effective_balance*(state: BeaconState, index: ValidatorIndex): uint64 =
  # Validators collect rewards which increases their balance but not their
  # influence. Validators may also lose balance if they fail to do their duty
  # in which case their influence decreases. Once they drop below a certain
  # balance, they're removed from the validator registry.
  min(state.validator_balances[index], MAX_DEPOSIT_AMOUNT)

func sum_effective_balances*(
    state: BeaconState, validator_indices: openArray[ValidatorIndex]): uint64 =
  # TODO spec - add as helper? Used pretty often
  for index in validator_indices:
    result += get_effective_balance(state, index)

func validate_proof_of_possession(state: BeaconState,
                                  pubkey: ValidatorPubKey,
                                  proof_of_possession: ValidatorSig,
                                  withdrawal_credentials: Eth2Digest,
                                  randao_commitment: Eth2Digest): bool =
  let proof_of_possession_data = DepositInput(
    pubkey: pubkey,
    withdrawal_credentials: withdrawal_credentials,
    randao_commitment: randao_commitment
  )

  bls_verify(
    pubkey,
    hash_tree_root_final(proof_of_possession_data).data,
    proof_of_possession,
    get_domain(
        state.fork,
        state.slot,
        DOMAIN_DEPOSIT,
    )
  )

func process_deposit(state: var BeaconState,
                     pubkey: ValidatorPubKey,
                     amount: uint64,
                     proof_of_possession: ValidatorSig,
                     withdrawal_credentials: Eth2Digest,
                     randao_commitment: Eth2Digest) =
  ## Process a deposit from Ethereum 1.0.

  if false:
    # TODO return error; currently, just fails if ever called
    # but hadn't been set up to run at all
    doAssert validate_proof_of_possession(
      state, pubkey, proof_of_possession, withdrawal_credentials,
      randao_commitment)

  let validator_pubkeys = state.validator_registry.mapIt(it.pubkey)

  if pubkey notin validator_pubkeys:
    # Add new validator
    let validator = Validator(
      pubkey: pubkey,
      withdrawal_credentials: withdrawal_credentials,
      randao_commitment: randao_commitment,
      randao_layers: 0,
      activation_epoch: FAR_FUTURE_EPOCH,
      exit_epoch: FAR_FUTURE_EPOCH,
      withdrawal_epoch: FAR_FUTURE_EPOCH,
      penalized_epoch: FAR_FUTURE_EPOCH,
      exit_count: 0,
      status_flags: 0,
    )

    # Note: In phase 2 registry indices that have been withdrawn for a long time will be recycled.
    state.validator_registry.add(validator)
    state.validator_balances.add(amount)
  else:
    # Increase balance by deposit amount
    let index = validator_pubkeys.find(pubkey)
    let validator = addr state.validator_registry[index]
    assert state.validator_registry[index].withdrawal_credentials ==
      withdrawal_credentials

    state.validator_balances[index] += amount

func get_entry_exit_effect_epoch*(epoch: EpochNumber): EpochNumber =
  ## An entry or exit triggered in the ``epoch`` given by the input takes effect at
  ## the epoch given by the output.
  epoch + 1 + ENTRY_EXIT_DELAY

func activate_validator(state: var BeaconState,
                        index: ValidatorIndex,
                        genesis: bool) =
  ## Activate the validator with the given ``index``.
  let validator = addr state.validator_registry[index]

  validator.activation_epoch = if genesis: GENESIS_EPOCH else: get_entry_exit_effect_epoch(get_current_epoch(state))

func initiate_validator_exit(state: var BeaconState,
                             index: ValidatorIndex) =
  ## Initiate exit for the validator with the given ``index``.
  var validator = state.validator_registry[index]
  validator.status_flags = validator.status_flags or INITIATED_EXIT
  state.validator_registry[index] = validator

func exit_validator*(state: var BeaconState,
                     index: ValidatorIndex) =
  ## Exit the validator with the given ``index``.

  let validator = addr state.validator_registry[index]

  # The following updates only occur if not previous exited
  if validator.exit_epoch <= get_entry_exit_effect_epoch(get_current_epoch(state)):
    return

  validator.exit_epoch = get_entry_exit_effect_epoch(get_current_epoch(state))

  # The following updates only occur if not previous exited
  state.validator_registry_exit_count += 1
  validator.exit_count = state.validator_registry_exit_count

func process_penalties_and_exits(state: var BeaconState) =
  let
    current_epoch = get_current_epoch(state)
    # The active validators
    active_validator_indices = get_active_validator_indices(state.validator_registry, state.slot)
  # The total effective balance of active validators
  var total_balance : uint64 = 0
  for i in active_validator_indices:
    total_balance += get_effective_balance(state, i)

  for index, validator in state.validator_registry:
    if current_epoch == validator.penalized_epoch + LATEST_PENALIZED_EXIT_LENGTH div 2:
      let
        e = (current_epoch mod LATEST_PENALIZED_EXIT_LENGTH).int
        total_at_start = state.latest_penalized_exit_balances[(e + 1) mod LATEST_PENALIZED_EXIT_LENGTH]
        total_at_end = state.latest_penalized_exit_balances[e]
        total_penalties = total_at_end - total_at_start
        penalty = get_effective_balance(state, index.ValidatorIndex) * min(total_penalties * 3, total_balance) div total_balance
      state.validator_balances[index] -= penalty

  ## 'state' is of type <var BeaconState> which cannot be captured as it
  ## would violate memory safety, when using nested function approach in
  ## spec directly. That said, the spec approach evidently is not meant,
  ## based on its abundant and pointless memory copies, for production.
  var eligible_indices : seq[ValidatorIndex] = @[]
  for i in 0 ..< len(state.validator_registry):
    eligible_indices.add i.ValidatorIndex

  ## TODO figure out that memory safety issue, which would come up again when
  ## sorting, and then actually do withdrawals

func get_initial_beacon_state*(
    initial_validator_deposits: openArray[Deposit],
    genesis_time: uint64,
    latest_eth1_data: Eth1Data,
    flags: UpdateFlags = {}): BeaconState =
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
    slot: GENESIS_SLOT,
    genesis_time: genesis_time,
    fork: Fork(
        previous_version: GENESIS_FORK_VERSION,
        current_version: GENESIS_FORK_VERSION,
        epoch: GENESIS_EPOCH,
    ),

    validator_registry_update_epoch: GENESIS_EPOCH,
    validator_registry_exit_count: 0,
    validator_registry_delta_chain_tip: ZERO_HASH,

    # Randomness and committees
    previous_epoch_start_shard: GENESIS_START_SHARD,
    current_epoch_start_shard: GENESIS_START_SHARD,
    previous_calculation_epoch: GENESIS_EPOCH,
    current_calculation_epoch: GENESIS_EPOCH,
    previous_epoch_seed: ZERO_HASH,
    current_epoch_seed: ZERO_HASH,

    # Finality
    previous_justified_epoch: GENESIS_EPOCH,
    justified_epoch: GENESIS_EPOCH,
    justification_bitfield: 0,
    finalized_epoch: GENESIS_EPOCH,

    # Deposit root
    latest_eth1_data: latest_eth1_data,
  )

  # Process initial deposits
  for deposit in initial_validator_deposits:
    process_deposit(
      state,
      deposit.deposit_data.deposit_input.pubkey,
      deposit.deposit_data.amount,
      deposit.deposit_data.deposit_input.proof_of_possession,
      deposit.deposit_data.deposit_input.withdrawal_credentials,
      deposit.deposit_data.deposit_input.randao_commitment,
    )

  # Process initial activations
  for validator_index in 0 ..< state.validator_registry.len:
    let vi = validator_index.ValidatorIndex
    if get_effective_balance(state, vi) >= MAX_DEPOSIT_AMOUNT:
      activate_validator(state, vi, true)

  state

func get_block_root*(state: BeaconState,
                     slot: uint64): Eth2Digest =
  doAssert state.slot <= slot + LATEST_BLOCK_ROOTS_LENGTH
  doAssert slot < state.slot
  state.latest_block_roots[slot mod LATEST_BLOCK_ROOTS_LENGTH]

func get_attestation_participants*(state: BeaconState,
                                   attestation_data: AttestationData,
                                   aggregation_bitfield: seq[byte]): seq[ValidatorIndex] =
  ## Attestation participants in the attestation data are called out in a
  ## bit field that corresponds to the committee of the shard at the time - this
  ## function converts it to list of indices in to BeaconState.validators
  ## Returns empty list if the shard is not found
  # TODO Linear search through shard list? borderline ok, it's a small list
  # TODO bitfield type needed, once bit order settles down
  # TODO iterator candidate

  # Find the committee in the list with the desired shard
  let crosslink_committees = get_crosslink_committees_at_slot(state, attestation_data.slot)

  # TODO investigate functional library / approach to help avoid loop bugs
  assert anyIt(
    crosslink_committees,
    it[1] == attestation_data.shard)
  let crosslink_committee = mapIt(
    filterIt(crosslink_committees, it.shard == attestation_data.shard),
    it.committee)[0]
  assert len(aggregation_bitfield) == (len(crosslink_committee) + 7) div 8

  # Find the participating attesters in the committee
  result = @[]
  for i, validator_index in crosslink_committee:
    let aggregation_bit = (aggregation_bitfield[i div 8] shr (7 - (i mod 8))) mod 2
    if aggregation_bit == 1:
      result.add(validator_index)

func process_ejections*(state: var BeaconState) =
  ## Iterate through the validator registry
  ## and eject active validators with balance below ``EJECTION_BALANCE``.

  for index in get_active_validator_indices(state.validator_registry, state.slot):
    if state.validator_balances[index] < EJECTION_BALANCE:
      exit_validator(state, index)

func update_validator_registry*(state: var BeaconState) =
  let
    current_epoch = get_current_epoch(state)
    next_epoch = current_epoch + 1
    active_validator_indices =
      get_active_validator_indices(state.validator_registry, state.slot)
    # The total effective balance of active validators
    total_balance = sum_effective_balances(state, active_validator_indices)

    # The maximum balance churn in Gwei (for deposits and exits separately)
    max_balance_churn = max(
        MAX_DEPOSIT_AMOUNT,
        total_balance div (2 * MAX_BALANCE_CHURN_QUOTIENT)
    )

  # Activate validators within the allowable balance churn
  var balance_churn = 0'u64
  for index, validator in state.validator_registry:
    if validator.activation_epoch > get_entry_exit_effect_epoch(current_epoch) and
      state.validator_balances[index] >= MAX_DEPOSIT_AMOUNT:
      # Check the balance churn would be within the allowance
      balance_churn += get_effective_balance(state, index.ValidatorIndex)
      if balance_churn > max_balance_churn:
        break

      # Activate validator
      activate_validator(state, index.ValidatorIndex, false)

  # Exit validators within the allowable balance churn
  balance_churn = 0
  for index, validator in state.validator_registry:
    if validator.exit_epoch > get_entry_exit_effect_epoch(current_epoch) and
      ((validator.status_flags and INITIATED_EXIT) == INITIATED_EXIT):
      # Check the balance churn would be within the allowance
      balance_churn += get_effective_balance(state, index.ValidatorIndex)
      if balance_churn > max_balance_churn:
        break

      # Exit validator
      exit_validator(state, index.ValidatorIndex)

  state.validator_registry_update_epoch = current_epoch

  # Perform additional updates
  state.current_calculation_epoch = next_epoch
  state.current_epoch_start_shard = (state.current_epoch_start_shard + get_current_epoch_committee_count(state)) mod SHARD_COUNT
  state.current_epoch_seed = generate_seed(state, state.current_calculation_epoch)

  # TODO "If a validator registry update does not happen do the following: ..."

  process_penalties_and_exits(state)

func get_epoch_start_slot*(epoch: EpochNumber): SlotNumber =
  epoch * EPOCH_LENGTH

proc checkAttestation*(
    state: BeaconState, attestation: Attestation, flags: UpdateFlags): bool =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!
  ##
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#attestations-1

  if not (attestation.data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot):
    warn("Attestation too new",
      attestation_slot = attestation.data.slot, state_slot = state.slot)
    return

  if not (attestation.data.slot + EPOCH_LENGTH >= state.slot):
    warn("Attestation too old",
      attestation_slot = attestation.data.slot, state_slot = state.slot)
    return

  let expected_justified_epoch =
    if attestation.data.slot >= get_epoch_start_slot(get_current_epoch(state)):
      state.justified_epoch
    else:
      state.previous_justified_epoch

  if not (attestation.data.justified_epoch == expected_justified_epoch):
    warn("Unexpected justified epoch",
      attestation_justified_epoch = attestation.data.justified_epoch,
      expected_justified_epoch)
    return

  let expected_justified_block_root =
    get_block_root(state, get_epoch_start_slot(attestation.data.justified_epoch))
  if not (attestation.data.justified_block_root == expected_justified_block_root):
    warn("Unexpected justified block root",
      attestation_justified_block_root = attestation.data.justified_block_root,
      expected_justified_block_root)
    return

  if not (state.latest_crosslinks[attestation.data.shard].shard_block_root in [
      attestation.data.latest_crosslink_root,
      attestation.data.shard_block_root]):
    warn("Unexpected crosslink shard_block_root")
    return

  let
    participants = get_attestation_participants(
      state, attestation.data, attestation.aggregation_bitfield)
    group_public_key = bls_aggregate_pubkeys(
      participants.mapIt(state.validator_registry[it].pubkey))

  if skipValidation notin flags:
    # Verify that aggregate_signature verifies using the group pubkey.
    let msg = hash_tree_root_final(attestation.data)

    if not bls_verify(
          group_public_key, @(msg.data) & @[0'u8], attestation.aggregate_signature,
          0, # TODO: get_domain(state.fork, attestation.data.slot, DOMAIN_ATTESTATION)
        ):
      warn("Invalid attestation group signature")
      return

  # To be removed in Phase1:
  if attestation.data.shard_block_root != ZERO_HASH:
    warn("Invalid shard block root")
    return

  true
