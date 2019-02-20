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

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_effective_balance
func get_effective_balance*(state: BeaconState, index: ValidatorIndex): uint64 =
  ## Return the effective balance (also known as "balance at stake") for a
  ## validator with the given ``index``.
  min(state.validator_balances[index], MAX_DEPOSIT_AMOUNT)

func sum_effective_balances*(
    state: BeaconState, validator_indices: openArray[ValidatorIndex]): uint64 =
  # TODO spec - add as helper? Used pretty often
  for index in validator_indices:
    result += get_effective_balance(state, index)

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#validate_proof_of_possession
func validate_proof_of_possession(state: BeaconState,
                                  pubkey: ValidatorPubKey,
                                  proof_of_possession: ValidatorSig,
                                  withdrawal_credentials: Eth2Digest): bool =
  let proof_of_possession_data = DepositInput(
    pubkey: pubkey,
    withdrawal_credentials: withdrawal_credentials,
    proof_of_possession: ValidatorSig(),
  )

  bls_verify(
    pubkey,
    hash_tree_root_final(proof_of_possession_data).data,
    proof_of_possession,
    get_domain(
        state.fork,
        get_current_epoch(state),
        DOMAIN_DEPOSIT,
    )
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#process_deposit
func process_deposit(state: var BeaconState,
                     pubkey: ValidatorPubKey,
                     amount: Gwei,
                     proof_of_possession: ValidatorSig,
                     withdrawal_credentials: Eth2Digest) =
  ## Process a deposit from Ethereum 1.0.

  if false:
    # TODO return error; currently, just fails if ever called
    # but hadn't been set up to run at all
    doAssert validate_proof_of_possession(
      state, pubkey, proof_of_possession, withdrawal_credentials)

  let validator_pubkeys = state.validator_registry.mapIt(it.pubkey)

  if pubkey notin validator_pubkeys:
    # Add new validator
    let validator = Validator(
      pubkey: pubkey,
      withdrawal_credentials: withdrawal_credentials,
      activation_epoch: FAR_FUTURE_EPOCH,
      exit_epoch: FAR_FUTURE_EPOCH,
      withdrawable_epoch: FAR_FUTURE_EPOCH,
      slashed_epoch: FAR_FUTURE_EPOCH,
      status_flags: 0,
    )

    ## Note: In phase 2 registry indices that have been withdrawn for a long
    ## time will be recycled.
    state.validator_registry.add(validator)
    state.validator_balances.add(amount)
  else:
    # Increase balance by deposit amount
    let index = validator_pubkeys.find(pubkey)
    let validator = addr state.validator_registry[index]
    assert state.validator_registry[index].withdrawal_credentials ==
      withdrawal_credentials

    state.validator_balances[index] += amount

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_entry_exit_effect_epoch
func get_entry_exit_effect_epoch*(epoch: Epoch): Epoch =
  ## An entry or exit triggered in the ``epoch`` given by the input takes effect at
  ## the epoch given by the output.
  epoch + 1 + ACTIVATION_EXIT_DELAY

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#activate_validator
func activate_validator(state: var BeaconState,
                        index: ValidatorIndex,
                        genesis: bool) =
  ## Activate the validator with the given ``index``.
  ## Note that this function mutates ``state``.
  let validator = addr state.validator_registry[index]

  validator.activation_epoch =
    if genesis:
      GENESIS_EPOCH
    else:
      get_entry_exit_effect_epoch(get_current_epoch(state))

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#initiate_validator_exit
func initiate_validator_exit(state: var BeaconState,
                             index: ValidatorIndex) =
  ## Initiate exit for the validator with the given ``index``.
  ## Note that this function mutates ``state``.
  var validator = addr state.validator_registry[index]
  validator.status_flags = validator.status_flags or INITIATED_EXIT

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#exit_validator
func exit_validator*(state: var BeaconState,
                     index: ValidatorIndex) =
  ## Exit the validator with the given ``index``.
  ## Note that this function mutates ``state``.

  let validator = addr state.validator_registry[index]

  # The following updates only occur if not previous exited
  if validator.exit_epoch <= get_entry_exit_effect_epoch(get_current_epoch(state)):
    return

  validator.exit_epoch = get_entry_exit_effect_epoch(get_current_epoch(state))

func process_penalties_and_exits(state: var BeaconState) =
  ## Penalize the validator of the given ``index``.
  ## Note that this function mutates ``state``.
  let
    current_epoch = get_current_epoch(state)
    # The active validators
    active_validator_indices = get_active_validator_indices(state.validator_registry, state.slot)
  # The total effective balance of active validators
  var total_balance : uint64 = 0
  for i in active_validator_indices:
    total_balance += get_effective_balance(state, i)

  for index, validator in state.validator_registry:
    if current_epoch == validator.slashed_epoch + LATEST_SLASHED_EXIT_LENGTH div 2:
      let
        e = (current_epoch mod LATEST_SLASHED_EXIT_LENGTH).int
        total_at_start = state.latest_slashed_balances[(e + 1) mod LATEST_SLASHED_EXIT_LENGTH]
        total_at_end = state.latest_slashed_balances[e]
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
  ## Get the initial ``BeaconState``.
  ##
  ## Before the beacon chain starts, validators will register in the Eth1 chain
  ## and deposit ETH. When enough many validators have registered, a
  ## `ChainStart` log will be emitted and the beacon chain can start beaconing.
  ##
  ## Because the state root hash is part of the genesis block, the beacon state
  ## must be calculated before creating the genesis block.

  # Induct validators
  # Not in spec: the system doesn't work unless there are at least SLOTS_PER_EPOCH
  # validators - there needs to be at least one member in each committee -
  # good to know for testing, though arguably the system is not that useful at
  # at that point :)
  assert initial_validator_deposits.len >= SLOTS_PER_EPOCH

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

    # TODO remove or conditionally compile; not in spec anymore
    validator_registry_delta_chain_tip: ZERO_HASH,

    # Randomness and committees
    previous_shuffling_start_shard: GENESIS_START_SHARD,
    current_shuffling_start_shard: GENESIS_START_SHARD,
    previous_shuffling_epoch: GENESIS_EPOCH,
    current_shuffling_epoch: GENESIS_EPOCH,
    previous_shuffling_seed: ZERO_HASH,
    current_shuffling_seed: ZERO_HASH,

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
    )

  # Process initial activations
  for validator_index in 0 ..< state.validator_registry.len:
    let vi = validator_index.ValidatorIndex
    if get_effective_balance(state, vi) >= MAX_DEPOSIT_AMOUNT:
      activate_validator(state, vi, true)

  state

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_block_root
func get_block_root*(state: BeaconState,
                     slot: Slot): Eth2Digest =
  # Return the block root at a recent ``slot``.

  doAssert state.slot <= slot + LATEST_BLOCK_ROOTS_LENGTH
  doAssert slot < state.slot
  state.latest_block_roots[slot mod LATEST_BLOCK_ROOTS_LENGTH]

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_attestation_participants
func get_attestation_participants*(state: BeaconState,
                                   attestation_data: AttestationData,
                                   bitfield: seq[byte]): seq[ValidatorIndex] =
  ## Return the participant indices at for the ``attestation_data`` and
  ## ``bitfield``.
  ## Attestation participants in the attestation data are called out in a
  ## bit field that corresponds to the committee of the shard at the time;
  ## this function converts it to list of indices in to BeaconState.validators
  ##
  ## Returns empty list if the shard is not found
  ## Return the participant indices at for the ``attestation_data`` and ``bitfield``.
  ##
  # TODO Linear search through shard list? borderline ok, it's a small list
  # TODO bitfield type needed, once bit order settles down
  # TODO iterator candidate

  ## Return the participant indices at for the ``attestation_data`` and
  ## ``bitfield``.
  let crosslink_committees = get_crosslink_committees_at_slot(
    state, attestation_data.slot)

  assert anyIt(
    crosslink_committees,
    it[1] == attestation_data.shard)
  let crosslink_committee = mapIt(
    filterIt(crosslink_committees, it.shard == attestation_data.shard),
    it.committee)[0]

  assert verify_bitfield(bitfield, len(crosslink_committee))

  # Find the participating attesters in the committee
  result = @[]
  for i, validator_index in crosslink_committee:
    let aggregation_bit = get_bitfield_bit(bitfield, i)
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
  state.current_shuffling_epoch = next_epoch
  state.current_shuffling_start_shard = (state.current_shuffling_start_shard + get_current_epoch_committee_count(state)) mod SHARD_COUNT
  state.current_shuffling_seed = generate_seed(state, state.current_shuffling_epoch)

  # TODO "If a validator registry update does not happen do the following: ..."

  process_penalties_and_exits(state)

## https://github.com/ethereum/eth2.0-specs/blob/v0.2.0/specs/core/0_beacon-chain.md#attestations-1
proc checkAttestation*(
    state: BeaconState, attestation: Attestation, flags: UpdateFlags): bool =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!

  # Can't underflow, because GENESIS_SLOT > MIN_ATTESTATION_INCLUSION_DELAY
  if not (attestation.data.slot <= state.slot - MIN_ATTESTATION_INCLUSION_DELAY):
    warn("Attestation too new",
      attestation_slot = attestation.data.slot, state_slot = state.slot)
    return

  if not (state.slot - MIN_ATTESTATION_INCLUSION_DELAY <
      attestation.data.slot + SLOTS_PER_EPOCH):
    warn("Attestation too old",
      attestation_slot = attestation.data.slot, state_slot = state.slot)
    return

  let expected_justified_epoch =
    # https://github.com/ethereum/eth2.0-specs/issues/618
    if attestation.data.slot + 1 >= get_epoch_start_slot(get_current_epoch(state)):
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

  if not (state.latest_crosslinks[attestation.data.shard] in [
      attestation.data.latest_crosslink,
      Crosslink(
        shard_block_root: attestation.data.shard_block_root,
        epoch: slot_to_epoch(attestation.data.slot))]):
    warn("Unexpected crosslink shard")
    return

  assert allIt(attestation.custody_bitfield, it == 0) #TO BE REMOVED IN PHASE 1
  assert anyIt(attestation.aggregation_bitfield, it != 0)

  let crosslink_committee = mapIt(
    filterIt(get_crosslink_committees_at_slot(state, attestation.data.slot),
             it.shard == attestation.data.shard),
    it.committee)[0]

  # Extra checks not in specs
  # https://github.com/status-im/nim-beacon-chain/pull/105#issuecomment-462432544
  assert attestation.aggregation_bitfield.len == (
            crosslink_committee.len + 7) div 8, (
              "Error: got " & $attestation.aggregation_bitfield.len &
              " but expected " & $((crosslink_committee.len + 7) div 8)
            )

  assert attestation.custody_bitfield.len == (
            crosslink_committee.len + 7) div 8, (
              "Error: got " & $attestation.custody_bitfield.len &
              " but expected " & $((crosslink_committee.len + 7) div 8)
            )
  # End extra checks

  assert allIt(0 ..< len(crosslink_committee),
    if get_bitfield_bit(attestation.aggregation_bitfield, it) == 0b0:
      # Should always be true in phase 0, because of above assertion
      get_bitfield_bit(attestation.custody_bitfield, it) == 0b0
    else:
      true)

  let
    participants = get_attestation_participants(
      state, attestation.data, attestation.aggregation_bitfield)

    ## TODO when the custody_bitfield assertion-to-emptiness disappears do this
    ## and fix the custody_bit_0_participants check to depend on it.
    # custody_bit_1_participants = {nothing, always, because assertion above}
    custody_bit_1_participants: seq[ValidatorIndex] = @[]
    custody_bit_0_participants = participants

    group_public_key = bls_aggregate_pubkeys(
      participants.mapIt(state.validator_registry[it].pubkey))

  ## the rest; turns into expensive NOP until then.
  if skipValidation notin flags:
    # Verify that aggregate_signature verifies using the group pubkey.
    assert bls_verify_multiple(
      @[
        bls_aggregate_pubkeys(mapIt(custody_bit_0_participants,
                                    state.validator_registry[it].pubkey)),
        bls_aggregate_pubkeys(mapIt(custody_bit_1_participants,
                                    state.validator_registry[it].pubkey)),
      ],
      @[
        hash_tree_root(AttestationDataAndCustodyBit(
          data: attestation.data, custody_bit: false)),
        hash_tree_root(AttestationDataAndCustodyBit(
          data: attestation.data, custody_bit: true)),
      ],
      attestation.aggregate_signature,
      get_domain(state.fork, slot_to_epoch(attestation.data.slot),
                 DOMAIN_ATTESTATION),
    )

  # To be removed in Phase1:
  if attestation.data.shard_block_root != ZERO_HASH:
    warn("Invalid shard block root")
    return

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_total_balance
func get_total_balance(state: BeaconState, validators: seq[ValidatorIndex]): Gwei =
  # Return the combined effective balance of an array of validators.
  foldl(validators, a + get_effective_balance(state, b), 0'u64)

# https://github.com/ethereum/eth2.0-specs/blob/v0.2.0/specs/core/0_beacon-chain.md#prepare_validator_for_withdrawal
func prepare_validator_for_withdrawal(state: var BeaconState, index: ValidatorIndex) =
  ## Set the validator with the given ``index`` with ``WITHDRAWABLE`` flag.
  ## Note that this function mutates ``state``.
  var validator = addr state.validator_registry[index]
  # TODO rm WITHDRAWABLE, since gone in 0.3.0
  validator.status_flags = validator.status_flags or WITHDRAWABLE
