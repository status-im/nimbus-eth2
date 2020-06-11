# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  tables, algorithm, math, sequtils, options,
  json_serialization/std/sets, chronicles,
  ../extras, ../ssz/merkleization,
  ./crypto, ./datatypes, ./digest, ./helpers, ./validator,
  ../../nbench/bench_lab

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#is_valid_merkle_branch
func is_valid_merkle_branch*(leaf: Eth2Digest, branch: openarray[Eth2Digest], depth: uint64, index: uint64, root: Eth2Digest): bool {.nbench.}=
  ## Check if ``leaf`` at ``index`` verifies against the Merkle ``root`` and
  ## ``branch``.
  var
    value = leaf
    buf: array[64, byte]

  for i in 0 ..< depth.int:
    if (index div (1'u64 shl i)) mod 2 != 0:
      buf[0..31] = branch[i.int].data
      buf[32..63] = value.data
    else:
      buf[0..31] = value.data
      buf[32..63] = branch[i.int].data
    value = eth2hash(buf)
  value == root

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#increase_balance
func increase_balance*(
    state: var BeaconState, index: ValidatorIndex, delta: Gwei) =
  # Increase the validator balance at index ``index`` by ``delta``.
  state.balances[index] += delta

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#decrease_balance
func decrease_balance*(
    state: var BeaconState, index: ValidatorIndex, delta: Gwei) =
  ## Decrease the validator balance at index ``index`` by ``delta``, with
  ## underflow protection.
  state.balances[index] =
    if delta > state.balances[index]:
      0'u64
    else:
      state.balances[index] - delta

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#deposits
proc process_deposit*(
    state: var BeaconState, deposit: Deposit, flags: UpdateFlags = {}): bool {.nbench.}=
  # Process an Eth1 deposit, registering a validator or increasing its balance.

  # Verify the Merkle branch
  if skipMerkleValidation notin flags and not is_valid_merkle_branch(
    hash_tree_root(deposit.data),
    deposit.proof,
    DEPOSIT_CONTRACT_TREE_DEPTH + 1,  # Add 1 for the `List` length mix-in
    state.eth1_deposit_index,
    state.eth1_data.deposit_root,
  ):
    notice "Deposit merkle validation failed",
      proof = deposit.proof, deposit_root = state.eth1_data.deposit_root,
      deposit_index = state.eth1_deposit_index
    return false

  # Deposits must be processed in order
  state.eth1_deposit_index += 1

  let
    pubkey = deposit.data.pubkey
    amount = deposit.data.amount
    validator_pubkeys = mapIt(state.validators, it.pubkey)
    index = validator_pubkeys.find(pubkey)

  if index == -1:
    # Verify the deposit signature (proof of possession) which is not checked
    # by the deposit contract

    # Fork-agnostic domain since deposits are valid across forks
    let domain = compute_domain(DOMAIN_DEPOSIT)

    let signing_root = compute_signing_root(deposit.getDepositMessage, domain)
    if skipBLSValidation notin flags and not bls_verify(
        pubkey, signing_root.data,
        deposit.data.signature):
      # It's ok that deposits fail - they get included in blocks regardless
      # TODO spec test?
      debug "Skipping deposit with invalid signature",
        pubkey, signing_root, signature = deposit.data.signature
      return true

    # Add validator and balance entries
    state.validators.add(Validator(
      pubkey: pubkey,
      withdrawal_credentials: deposit.data.withdrawal_credentials,
      activation_eligibility_epoch: FAR_FUTURE_EPOCH,
      activation_epoch: FAR_FUTURE_EPOCH,
      exit_epoch: FAR_FUTURE_EPOCH,
      withdrawable_epoch: FAR_FUTURE_EPOCH,
      effective_balance: min(amount - amount mod EFFECTIVE_BALANCE_INCREMENT,
        MAX_EFFECTIVE_BALANCE)
    ))
    state.balances.add(amount)
  else:
     # Increase balance by deposit amount
     increase_balance(state, index.ValidatorIndex, amount)

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#compute_activation_exit_epoch
func compute_activation_exit_epoch(epoch: Epoch): Epoch =
  ## Return the epoch during which validator activations and exits initiated in
  ## ``epoch`` take effect.
  epoch + 1 + MAX_SEED_LOOKAHEAD

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_validator_churn_limit
func get_validator_churn_limit(state: BeaconState, cache: var StateCache):
    uint64 =
  # Return the validator churn limit for the current epoch.
  max(MIN_PER_EPOCH_CHURN_LIMIT,
    len(cache.shuffled_active_validator_indices) div
      CHURN_LIMIT_QUOTIENT).uint64

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#initiate_validator_exit
func initiate_validator_exit*(state: var BeaconState,
                              index: ValidatorIndex, cache: var StateCache) =
  # Initiate the exit of the validator with index ``index``.

  # Return if validator already initiated exit
  let validator = addr state.validators[index]
  if validator.exit_epoch != FAR_FUTURE_EPOCH:
    return

  # Compute exit queue epoch
  var exit_epochs = mapIt(
    filterIt(state.validators, it.exit_epoch != FAR_FUTURE_EPOCH),
    it.exit_epoch)
  exit_epochs.add compute_activation_exit_epoch(get_current_epoch(state))
  var exit_queue_epoch = max(exit_epochs)
  let exit_queue_churn = foldl(
    state.validators,
    a + (if b.exit_epoch == exit_queue_epoch: 1'u64 else: 0'u64),
    0'u64)

  if exit_queue_churn >= get_validator_churn_limit(state, cache):
    exit_queue_epoch += 1

  # Set validator exit epoch and withdrawable epoch
  validator.exit_epoch = exit_queue_epoch
  validator.withdrawable_epoch =
    validator.exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#slash_validator
proc slash_validator*(state: var BeaconState, slashed_index: ValidatorIndex,
    cache: var StateCache) =
  # Slash the validator with index ``index``.
  let epoch = get_current_epoch(state)
  initiate_validator_exit(state, slashed_index, cache)
  let validator = addr state.validators[slashed_index]

  debug "slash_validator: ejecting validator via slashing (validator_leaving)",
    index = slashed_index,
    num_validators = state.validators.len,
    current_epoch = get_current_epoch(state),
    validator_slashed = validator.slashed,
    validator_withdrawable_epoch = validator.withdrawable_epoch,
    validator_exit_epoch = validator.exit_epoch,
    validator_effective_balance = validator.effective_balance

  validator.slashed = true
  validator.withdrawable_epoch =
    max(validator.withdrawable_epoch, epoch + EPOCHS_PER_SLASHINGS_VECTOR)
  state.slashings[epoch mod EPOCHS_PER_SLASHINGS_VECTOR] +=
    validator.effective_balance
  decrease_balance(state, slashed_index,
    validator.effective_balance div MIN_SLASHING_PENALTY_QUOTIENT)

  # The rest doesn't make sense without there being any proposer index, so skip
  # Apply proposer and whistleblower rewards
  let proposer_index = get_beacon_proposer_index(state, cache)
  if proposer_index.isNone:
    debug "No beacon proposer index and probably no active validators"
    return

  let
    # Spec has whistleblower_index as optional param, but it's never used.
    whistleblower_index = proposer_index.get
    whistleblowing_reward =
      (validator.effective_balance div WHISTLEBLOWER_REWARD_QUOTIENT).Gwei
    proposer_reward = whistleblowing_reward div PROPOSER_REWARD_QUOTIENT
  increase_balance(state, proposer_index.get, proposer_reward)
  # TODO: evaluate if spec bug / underflow can be triggered
  doAssert(whistleblowing_reward >= proposer_reward, "Spec bug: underflow in slash_validator")
  increase_balance(
    state, whistleblower_index, whistleblowing_reward - proposer_reward)

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#genesis
proc initialize_beacon_state_from_eth1*(
    eth1_block_hash: Eth2Digest,
    eth1_timestamp: uint64,
    deposits: openArray[Deposit],
    flags: UpdateFlags = {}): BeaconStateRef {.nbench.}=
  ## Get the genesis ``BeaconState``.
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
  doAssert deposits.len >= SLOTS_PER_EPOCH

  const SECONDS_PER_DAY = uint64(60*60*24)
  var state = BeaconStateRef(
    fork: Fork(
      previous_version: Version(GENESIS_FORK_VERSION),
      current_version: Version(GENESIS_FORK_VERSION),
      epoch: GENESIS_EPOCH),
    genesis_time:
      eth1_timestamp + 2'u64 * SECONDS_PER_DAY -
        (eth1_timestamp mod SECONDS_PER_DAY),
    eth1_data:
      Eth1Data(block_hash: eth1_block_hash, deposit_count: uint64(len(deposits))),
    latest_block_header:
      BeaconBlockHeader(
        body_root: hash_tree_root(BeaconBlockBody(
          randao_reveal: ValidatorSig(kind: OpaqueBlob)
        ))
      )
  )

  # Seed RANDAO with Eth1 entropy
  state.randao_mixes.fill(eth1_block_hash)

  # Process deposits
  let
    leaves = deposits.mapIt(it.data)
  var i = 0
  for prefix_root in hash_tree_roots_prefix(
      leaves, 2'i64^DEPOSIT_CONTRACT_TREE_DEPTH):
    state.eth1_data.deposit_root = prefix_root
    discard process_deposit(state[], deposits[i], flags)
    i += 1

  # Process activations
  for validator_index in 0 ..< state.validators.len:
    let
      balance = state.balances[validator_index]
      validator = addr state.validators[validator_index]

    validator.effective_balance = min(
      balance - balance mod EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)

    if validator.effective_balance == MAX_EFFECTIVE_BALANCE:
      validator.activation_eligibility_epoch = GENESIS_EPOCH
      validator.activation_epoch = GENESIS_EPOCH

  # Set genesis validators root for domain separation and chain versioning
  state.genesis_validators_root = hash_tree_root(state.validators)

  state

proc initialize_hashed_beacon_state_from_eth1*(
    eth1_block_hash: Eth2Digest,
    eth1_timestamp: uint64,
    deposits: openArray[Deposit],
    flags: UpdateFlags = {}): HashedBeaconState =
  let genesisState = initialize_beacon_state_from_eth1(
    eth1_block_hash, eth1_timestamp, deposits, flags)
  HashedBeaconState(data: genesisState[], root: hash_tree_root(genesisState[]))

func is_valid_genesis_state*(state: BeaconState): bool =
  if state.genesis_time < MIN_GENESIS_TIME:
    return false
  # This is an okay get_active_validator_indices(...) for the time being.
  if len(get_active_validator_indices(state, GENESIS_EPOCH)) < MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
    return false
  return true

# TODO this is now a non-spec helper function, and it's not really accurate
# so only usable/used in research/ and tests/
func get_initial_beacon_block*(state: BeaconState): SignedBeaconBlock =
  SignedBeaconBlock(
    message: BeaconBlock(
      slot: GENESIS_SLOT,
      state_root: hash_tree_root(state),
      body: BeaconBlockBody(
        # TODO: This shouldn't be necessary if OpaqueBlob is the default
        randao_reveal: ValidatorSig(kind: OpaqueBlob))))
      # parent_root, randao_reveal, eth1_data, signature, and body automatically
      # initialized to default values.

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_block_root_at_slot
func get_block_root_at_slot*(state: BeaconState,
                             slot: Slot): Eth2Digest =
  # Return the block root at a recent ``slot``.

  doAssert state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
  doAssert slot < state.slot
  state.block_roots[slot mod SLOTS_PER_HISTORICAL_ROOT]

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_block_root
func get_block_root*(state: BeaconState, epoch: Epoch): Eth2Digest =
  # Return the block root at the start of a recent ``epoch``.
  get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch))

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_total_balance
func get_total_balance*(state: BeaconState, validators: auto): Gwei =
  ## Return the combined effective balance of the ``indices``.
  ## ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
  ## Math safe up to ~10B ETH, afterwhich this overflows uint64.
  max(EFFECTIVE_BALANCE_INCREMENT,
    foldl(validators, a + state.validators[b].effective_balance, 0'u64)
  )

# XXX: Move to state_transition_epoch.nim?

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#is_eligible_for_activation_queue
func is_eligible_for_activation_queue(validator: Validator): bool =
  # Check if ``validator`` is eligible to be placed into the activation queue.
  validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH and
    validator.effective_balance == MAX_EFFECTIVE_BALANCE

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#is_eligible_for_activation
func is_eligible_for_activation(state: BeaconState, validator: Validator):
    bool =
  # Check if ``validator`` is eligible for activation.

  # Placement in queue is finalized
  validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch and
  # Has not yet been activated
    validator.activation_epoch == FAR_FUTURE_EPOCH

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#registry-updates
proc process_registry_updates*(state: var BeaconState,
    cache: var StateCache) {.nbench.}=
  ## Process activation eligibility and ejections
  ## Try to avoid caching here, since this could easily become undefined

  # Make visible, e.g.,
  # https://github.com/status-im/nim-beacon-chain/pull/608
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
  for index, validator in state.validators:
    if is_eligible_for_activation_queue(validator):
      state.validators[index].activation_eligibility_epoch =
        get_current_epoch(state) + 1

    if is_active_validator(validator, get_current_epoch(state)) and
        validator.effective_balance <= EJECTION_BALANCE:
      debug "Registry updating: ejecting validator due to low balance (validator_leaving)",
        index = index,
        num_validators = state.validators.len,
        current_epoch = get_current_epoch(state),
        validator_slashed = validator.slashed,
        validator_withdrawable_epoch = validator.withdrawable_epoch,
        validator_exit_epoch = validator.exit_epoch,
        validator_effective_balance = validator.effective_balance
      initiate_validator_exit(state, index.ValidatorIndex, cache)

  ## Queue validators eligible for activation and not dequeued for activation
  var activation_queue : seq[tuple[a: Epoch, b: int]] = @[]
  for index, validator in state.validators:
    if is_eligible_for_activation(state, validator):
      activation_queue.add (
        state.validators[index].activation_eligibility_epoch, index)

  activation_queue.sort(system.cmp)

  ## Dequeued validators for activation up to churn limit (without resetting
  ## activation epoch)
  let churn_limit = get_validator_churn_limit(state, cache)
  for i, epoch_and_index in activation_queue:
    if i.uint64 >= churn_limit:
      break
    let
      (_, index) = epoch_and_index
      validator = addr state.validators[index]
    validator.activation_epoch =
      compute_activation_exit_epoch(get_current_epoch(state))

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
proc is_valid_indexed_attestation*(
    state: BeaconState, indexed_attestation: IndexedAttestation,
    flags: UpdateFlags): bool =
  # Check if ``indexed_attestation`` has sorted and unique indices and a valid
  # aggregate signature.
  # TODO: this is noSideEffect besides logging
  #       https://github.com/status-im/nim-chronicles/issues/62

  # Verify indices are sorted and unique
  # TODO: A simple loop can verify that the indicates are monotonically
  #       increasing and non-repeating here!
  let indices = indexed_attestation.attesting_indices
  if indices.asSeq != sorted(toHashSet(indices.asSeq).toSeq, system.cmp):
    notice "indexed attestation: indices not sorted"
    return false

  # Verify aggregate signature
  let pubkeys = mapIt(indices, state.validators[it.int].pubkey) # TODO: fuse loops with blsFastAggregateVerify
  let domain = state.get_domain(DOMAIN_BEACON_ATTESTER, indexed_attestation.data.target.epoch)
  let signing_root = compute_signing_root(indexed_attestation.data, domain)
  if skipBLSValidation notin flags and
       not blsFastAggregateVerify(
             pubkeys, signing_root.data, indexed_attestation.signature
       ):
    notice "indexed attestation: signature verification failure"
    return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_attesting_indices
func get_attesting_indices*(state: BeaconState,
                            data: AttestationData,
                            bits: CommitteeValidatorsBits,
                            stateCache: var StateCache):
                            HashSet[ValidatorIndex] =
  # Return the set of attesting indices corresponding to ``data`` and ``bits``.
  result = initHashSet[ValidatorIndex]()
  let committee = get_beacon_committee(
    state, data.slot, data.index.CommitteeIndex, stateCache)

  # This shouldn't happen if one begins with a valid BeaconState and applies
  # valid updates, but one can construct a BeaconState where it does. Do not
  # do anything here since the PendingAttestation wouldn't have made it past
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#attestations
  # which checks len(attestation.aggregation_bits) == len(committee) that in
  # nim-beacon-chain lives in check_attestation(...).
  # Addresses https://github.com/status-im/nim-beacon-chain/issues/922
  if bits.len != committee.len:
    trace "get_attesting_indices: inconsistent aggregation and committee length"
    return

  for i, index in committee:
    if bits[i]:
      result.incl index

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_indexed_attestation
func get_indexed_attestation*(state: BeaconState, attestation: Attestation,
    stateCache: var StateCache): IndexedAttestation =
  # Return the indexed attestation corresponding to ``attestation``.
  let
    attesting_indices =
      get_attesting_indices(
        state, attestation.data, attestation.aggregation_bits, stateCache)

  IndexedAttestation(
    attesting_indices:
      List[uint64, MAX_VALIDATORS_PER_COMMITTEE].init(
        sorted(mapIt(attesting_indices.toSeq, it.uint64), system.cmp)),
    data: attestation.data,
    signature: attestation.signature
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#attestations
proc check_attestation*(
    state: BeaconState, attestation: Attestation, flags: UpdateFlags,
    stateCache: var StateCache): bool =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!

  let
    stateSlot = state.slot
    data = attestation.data

  trace "process_attestation: beginning",
    attestation=attestation

  if not (data.index < get_committee_count_at_slot(state, data.slot)):
    warn("Data index exceeds committee count",
      data_index = data.index,
      committee_count = get_committee_count_at_slot(state, data.slot))
    return

  if not (data.target.epoch == get_previous_epoch(state) or
      data.target.epoch == get_current_epoch(state)):
    warn("Target epoch not current or previous epoch")
    return

  if not (data.target.epoch == compute_epoch_at_slot(data.slot)):
    warn("Target epoch inconsistent with epoch of data slot",
      target_epoch = data.target.epoch,
      data_slot_epoch = compute_epoch_at_slot(data.slot))
    return

  if not (data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= stateSlot):
    warn("Attestation too new",
      attestation_slot = shortLog(data.slot),
      state_slot = shortLog(stateSlot))
    return

  if not (stateSlot <= data.slot + SLOTS_PER_EPOCH):
    warn("Attestation too old",
      attestation_slot = shortLog(data.slot),
      state_slot = shortLog(stateSlot))
    return

  let committee = get_beacon_committee(
    state, data.slot, data.index.CommitteeIndex, stateCache)
  if attestation.aggregation_bits.len != committee.len:
    warn("Inconsistent aggregation and committee length",
      aggregation_bits_len = attestation.aggregation_bits.len,
      committee_len = committee.len
    )
    return

  let ffg_check_data = (data.source.epoch, data.source.root, data.target.epoch)

  if data.target.epoch == get_current_epoch(state):
    if not (ffg_check_data == (state.current_justified_checkpoint.epoch,
        state.current_justified_checkpoint.root, get_current_epoch(state))):
      warn("FFG data not matching current justified epoch")
      return
  else:
    if not (ffg_check_data == (state.previous_justified_checkpoint.epoch,
        state.previous_justified_checkpoint.root, get_previous_epoch(state))):
      warn("FFG data not matching previous justified epoch")
      return

  if not is_valid_indexed_attestation(
      state, get_indexed_attestation(state, attestation, stateCache), flags):
    warn("process_attestation: signature or bitfields incorrect")
    return

  true

proc process_attestation*(
    state: var BeaconState, attestation: Attestation, flags: UpdateFlags,
    stateCache: var StateCache): bool {.nbench.}=
  # In the spec, attestation validation is mixed with state mutation, so here
  # we've split it into two functions so that the validation logic can be
  # reused when looking for suitable blocks to include in attestations.
  # TODO don't log warnings when looking for attestations (return
  #      Result[void, cstring] instead of logging in check_attestation?)

  let proposer_index = get_beacon_proposer_index(state, stateCache)
  if proposer_index.isNone:
    debug "No beacon proposer index and probably no active validators"
    return false

  if check_attestation(state, attestation, flags, stateCache):
    let
      attestation_slot = attestation.data.slot
      pending_attestation = PendingAttestation(
        data: attestation.data,
        aggregation_bits: attestation.aggregation_bits,
        inclusion_delay: state.slot - attestation_slot,
        proposer_index: proposer_index.get.uint64,
      )

    if attestation.data.target.epoch == get_current_epoch(state):
      trace "process_attestation: current_epoch_attestations.add",
        attestation = shortLog(attestation),
        pending_attestation = pending_attestation,
        indices = get_attesting_indices(
          state, attestation.data, attestation.aggregation_bits, stateCache).len
      state.current_epoch_attestations.add(pending_attestation)
    else:
      trace "process_attestation: previous_epoch_attestations.add",
        attestation = shortLog(attestation),
        pending_attestation = pending_attestation,
        indices = get_attesting_indices(
          state, attestation.data, attestation.aggregation_bits, stateCache).len
      state.previous_epoch_attestations.add(pending_attestation)

    true
  else:
    trace "process_attestation: check_attestation failed",
      attestation = shortLog(attestation),
      indices = get_attesting_indices(
        state, attestation.data, attestation.aggregation_bits, stateCache).len
    false

func makeAttestationData*(
    state: BeaconState, slot: Slot, committee_index: uint64,
    beacon_block_root: Eth2Digest): AttestationData =
  ## Create an attestation / vote for the block `beacon_block_root` using the
  ## data in `state` to fill in the rest of the fields.
  ## `state` is the state corresponding to the `beacon_block_root` advanced to
  ## the slot we're attesting to.

  let
    current_epoch = get_current_epoch(state)
    start_slot = compute_start_slot_at_epoch(current_epoch)
    epoch_boundary_block_root =
      if start_slot == state.slot: beacon_block_root
      else: get_block_root_at_slot(state, start_slot)

  doAssert slot.compute_epoch_at_slot == current_epoch

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.2/specs/phase0/validator.md#attestation-data
  AttestationData(
    slot: slot,
    index: committee_index,
    beacon_block_root: beacon_block_root,
    source: state.current_justified_checkpoint,
    target: Checkpoint(
      epoch: current_epoch,
      root: epoch_boundary_block_root
    )
  )
