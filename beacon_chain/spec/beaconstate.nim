# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  tables, algorithm, math, options, sequtils,
  json_serialization/std/sets, chronicles, stew/bitseqs,
  ../extras, ../ssz,
  ./crypto, ./datatypes, ./digest, ./helpers, ./validator

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#is_valid_merkle_branch
func is_valid_merkle_branch(leaf: Eth2Digest, branch: openarray[Eth2Digest], depth: uint64, index: uint64, root: Eth2Digest): bool =
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#increase_balance
func increase_balance*(
    state: var BeaconState, index: ValidatorIndex, delta: Gwei) =
  # Increase the validator balance at index ``index`` by ``delta``.
  state.balances[index] += delta

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#decrease_balance
func decrease_balance*(
    state: var BeaconState, index: ValidatorIndex, delta: Gwei) =
  ## Decrease the validator balance at index ``index`` by ``delta``, with
  ## underflow protection.
  state.balances[index] =
    if delta > state.balances[index]:
      0'u64
    else:
      state.balances[index] - delta

# https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#deposits
func process_deposit*(
    state: var BeaconState, deposit: Deposit, flags: UpdateFlags = {}): bool =
  # Process an Eth1 deposit, registering a validator or increasing its balance.

  # Verify the Merkle branch
  # TODO enable this check, but don't use doAssert
  if not is_valid_merkle_branch(
    hash_tree_root(deposit.data),
     deposit.proof,
     DEPOSIT_CONTRACT_TREE_DEPTH,
     state.eth1_deposit_index,
    state.eth1_data.deposit_root,
  ):
    ## TODO: a notice-like mechanism which works in a func
    ## here and elsewhere, one minimal approach is a check-if-true
    ## and return false iff so.
    ## obviously, better/more principled ones exist, but
    ## generally require broader rearchitecting, and this is what
    ## mostly happens now, just haphazardly.
    discard

  # Deposits must be processed in order
  state.eth1_deposit_index += 1

  let
    pubkey = deposit.data.pubkey
    amount = deposit.data.amount
    validator_pubkeys = mapIt(state.validators, it.pubkey)
    index = validator_pubkeys.find(pubkey)

  if index == -1:
    # Verify the deposit signature (proof of possession)
    if skipValidation notin flags and not bls_verify(
        pubkey, signing_root(deposit.data).data, deposit.data.signature,
        compute_domain(DOMAIN_DEPOSIT)):
      return false

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

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#compute_activation_exit_epoch
func compute_activation_exit_epoch*(epoch: Epoch): Epoch =
  ## Return the epoch during which validator activations and exits initiated in
  ## ``epoch`` take effect.
  epoch + 1 + ACTIVATION_EXIT_DELAY

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#get_validator_churn_limit
func get_validator_churn_limit(state: BeaconState): uint64 =
  # Return the validator churn limit for the current epoch.
  let active_validator_indices =
    get_active_validator_indices(state, get_current_epoch(state))
  max(MIN_PER_EPOCH_CHURN_LIMIT,
    len(active_validator_indices) div CHURN_LIMIT_QUOTIENT).uint64

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#initiate_validator_exit
func initiate_validator_exit*(state: var BeaconState,
                              index: ValidatorIndex) =
  # Initiate the exit of the validator with index ``index``.

  # Return if validator already initiated exit
  let validator = addr state.validators[index]
  if validator.exit_epoch != FAR_FUTURE_EPOCH:
    return

  # Compute exit queue epoch
  # TODO try zero-functional here
  var exit_epochs = mapIt(
    filterIt(state.validators, it.exit_epoch != FAR_FUTURE_EPOCH),
    it.exit_epoch)
  exit_epochs.add compute_activation_exit_epoch(get_current_epoch(state))
  var exit_queue_epoch = max(exit_epochs)
  let exit_queue_churn = foldl(
    state.validators,
    a + (if b.exit_epoch == exit_queue_epoch: 1'u64 else: 0'u64),
    0'u64)

  if exit_queue_churn >= get_validator_churn_limit(state):
    exit_queue_epoch += 1

  # Set validator exit epoch and withdrawable epoch
  validator.exit_epoch = exit_queue_epoch
  validator.withdrawable_epoch =
    validator.exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#slash_validator
func slash_validator*(state: var BeaconState, slashed_index: ValidatorIndex,
    stateCache: var StateCache) =
  # Slash the validator with index ``index``.
  let epoch = get_current_epoch(state)
  initiate_validator_exit(state, slashed_index)
  let validator = addr state.validators[slashed_index]
  validator.slashed = true
  validator.withdrawable_epoch =
    max(validator.withdrawable_epoch, epoch + EPOCHS_PER_SLASHINGS_VECTOR)
  state.slashings[epoch mod EPOCHS_PER_SLASHINGS_VECTOR] +=
    validator.effective_balance
  decrease_balance(state, slashed_index,
    validator.effective_balance div MIN_SLASHING_PENALTY_QUOTIENT)

  let
    proposer_index = get_beacon_proposer_index(state, stateCache)
    # Spec has whistleblower_index as optional param, but it's never used.
    whistleblower_index = proposer_index
    whistleblowing_reward =
      (validator.effective_balance div WHISTLEBLOWER_REWARD_QUOTIENT).Gwei
    proposer_reward = whistleblowing_reward div PROPOSER_REWARD_QUOTIENT
  increase_balance(state, proposer_index, proposer_reward)
  increase_balance(
    state, whistleblower_index, whistleblowing_reward - proposer_reward)

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#get_compact_committees_root
func get_compact_committees_root*(state: BeaconState, epoch: Epoch): Eth2Digest =
  # Return the compact committee root at ``epoch``.

  # TODO if profiling shows this as expensive, plumb through properly
  var cache = get_empty_per_epoch_cache()

  var committees : array[SHARD_COUNT, CompactCommittee]
  let start_shard = get_start_shard(state, epoch)
  for committee_number in 0'u64 ..< get_committee_count(state, epoch):
    let shard = (start_shard + committee_number) mod SHARD_COUNT
    for index in get_crosslink_committee(state, epoch, shard, cache):
      let validator = state.validators[index]
      committees[shard.int].pubkeys.add(validator.pubkey)
      let
        compact_balance =
          validator.effective_balance div EFFECTIVE_BALANCE_INCREMENT

        # `index` (top 6 bytes) + `slashed` (16th bit) + `compact_balance`
        # (bottom 15 bits)
        compact_validator =
          uint64((index.uint64 shl 16) + (validator.slashed.uint64 shl 15) +
            compact_balance)
      committees[shard.int].compact_validators.add(compact_validator)

  hash_tree_root(committees)

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#genesis
func initialize_beacon_state_from_eth1*(
    eth1_block_hash: Eth2Digest,
    eth1_timestamp: uint64,
    deposits: openArray[Deposit],
    flags: UpdateFlags = {}): BeaconState =
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
  var state = BeaconState(
    genesis_time:
      eth1_timestamp + 2'u64 * SECONDS_PER_DAY -
        (eth1_timestamp mod SECONDS_PER_DAY),
    eth1_data:
      Eth1Data(block_hash: eth1_block_hash, deposit_count: uint64(len(deposits))),
    latest_block_header:
      BeaconBlockHeader(
        body_root: hash_tree_root(BeaconBlockBody(
          # TODO: This shouldn't be necessary if OpaqueBlob is the default
          randao_reveal: ValidatorSig(kind: OpaqueBlob))),
        # TODO: This shouldn't be necessary if OpaqueBlob is the default
        signature: BlsValue[Signature](kind: OpaqueBlob)))

  # Process deposits
  let leaves = deposits.mapIt(it.data)
  for i, deposit in deposits:
    let deposit_data_list = leaves[0..i]
    state.eth1_data.deposit_root = hash_tree_root(
      sszList(deposit_data_list, (2'i64^DEPOSIT_CONTRACT_TREE_DEPTH) + 1))

    discard process_deposit(state, deposit, flags)

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

  # Populate active_index_roots and compact_committees_roots
  let active_index_root = hash_tree_root(
    sszList(
      get_active_validator_indices(state, GENESIS_EPOCH),
      VALIDATOR_REGISTRY_LIMIT + 1))

  let committee_root = get_compact_committees_root(state, GENESIS_EPOCH)
  for index in 0 ..< EPOCHS_PER_HISTORICAL_VECTOR:
    state.active_index_roots[index] = active_index_root
    state.compact_committees_roots[index] = committee_root
  state

proc is_valid_genesis_state*(state: BeaconState): bool =
  if state.genesis_time < MIN_GENESIS_TIME:
    return false
  if len(get_active_validator_indices(state, GENESIS_EPOCH)) < MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
    return false
  return true

# TODO candidate for spec?
# https://github.com/ethereum/eth2.0-specs/blob/0.5.1/specs/core/0_beacon-chain.md#on-genesis
func get_initial_beacon_block*(state: BeaconState): BeaconBlock =
  BeaconBlock(
    slot: GENESIS_SLOT,
    state_root: hash_tree_root(state)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#get_attestation_data_slot
func get_attestation_data_slot*(state: BeaconState,
    data: AttestationData, committee_count: uint64): Slot =
  # Return the slot corresponding to the attestation ``data``.
  let
    offset = (data.crosslink.shard + SHARD_COUNT -
      get_start_shard(state, data.target.epoch)) mod SHARD_COUNT

  compute_start_slot_of_epoch(data.target.epoch) + offset div
    (committee_count div SLOTS_PER_EPOCH)

# This is the slower (O(n)), spec-compatible signature.
func get_attestation_data_slot*(state: BeaconState,
    data: AttestationData): Slot =
  get_attestation_data_slot(
    state, data, get_committee_count(state, data.target.epoch))

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#get_block_root_at_slot
func get_block_root_at_slot*(state: BeaconState,
                             slot: Slot): Eth2Digest =
  # Return the block root at a recent ``slot``.

  doAssert state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
  doAssert slot < state.slot
  state.block_roots[slot mod SLOTS_PER_HISTORICAL_ROOT]

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#get_block_root
func get_block_root*(state: BeaconState, epoch: Epoch): Eth2Digest =
  # Return the block root at the start of a recent ``epoch``.
  get_block_root_at_slot(state, compute_start_slot_of_epoch(epoch))

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#get_total_balance
func get_total_balance*(state: BeaconState, validators: auto): Gwei =
  ## Return the combined effective balance of the ``indices``. (1 Gwei minimum
  ## to avoid divisions by zero.)
  max(1'u64,
    foldl(validators, a + state.validators[b].effective_balance, 0'u64)
  )

# XXX: Move to state_transition_epoch.nim?
# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#registry-updates
func process_registry_updates*(state: var BeaconState) =
  ## Process activation eligibility and ejections
  ## Try to avoid caching here, since this could easily become undefined

  for index, validator in state.validators:
    if validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH and
        validator.effective_balance == MAX_EFFECTIVE_BALANCE:
      state.validators[index].activation_eligibility_epoch =
        get_current_epoch(state)

    if is_active_validator(validator, get_current_epoch(state)) and
        validator.effective_balance <= EJECTION_BALANCE:
      initiate_validator_exit(state, index.ValidatorIndex)

  ## Queue validators eligible for activation and not dequeued for activation
  ## prior to finalized epoch
  var activation_queue : seq[tuple[a: Epoch, b: int]] = @[]
  for index, validator in state.validators:
    if validator.activation_eligibility_epoch != FAR_FUTURE_EPOCH and
        validator.activation_epoch >=
          compute_activation_exit_epoch(state.finalized_checkpoint.epoch):
      activation_queue.add (
        state.validators[index].activation_eligibility_epoch, index)

  activation_queue.sort(system.cmp)

  ## Dequeued validators for activation up to churn limit (without resetting
  ## activation epoch)
  let churn_limit = get_validator_churn_limit(state)
  for i, epoch_and_index in activation_queue:
    if i.uint64 >= churn_limit:
      break
    let
      (epoch, index) = epoch_and_index
      validator = addr state.validators[index]
    if validator.activation_epoch == FAR_FUTURE_EPOCH:
      validator.activation_epoch =
        compute_activation_exit_epoch(get_current_epoch(state))

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#is_valid_indexed_attestation
func is_valid_indexed_attestation*(
    state: BeaconState, indexed_attestation: IndexedAttestation): bool =
  # Check if ``indexed_attestation`` has valid indices and signature.

  let
    bit_0_indices = indexed_attestation.custody_bit_0_indices.asSeq
    bit_1_indices = indexed_attestation.custody_bit_1_indices.asSeq

  # Verify no index has custody bit equal to 1 [to be removed in phase 1]
  if len(bit_1_indices) != 0:
    return false

  # Verify max number of indices
  let combined_len = len(bit_0_indices) + len(bit_1_indices)
  if not (combined_len <= MAX_VALIDATORS_PER_COMMITTEE):
    return false

  # Verify index sets are disjoint
  if len(intersection(bit_0_indices.toSet, bit_1_indices.toSet)) != 0:
    return false

  # Verify indices are sorted
  if bit_0_indices != sorted(bit_0_indices, system.cmp):
    return false

  if bit_1_indices != sorted(bit_1_indices, system.cmp):
    return false

  # Verify aggregate signature
  bls_verify_multiple(
    @[
      bls_aggregate_pubkeys(
        mapIt(bit_0_indices, state.validators[it.int].pubkey)),
      bls_aggregate_pubkeys(
        mapIt(bit_1_indices, state.validators[it.int].pubkey)),
    ],
    @[
      hash_tree_root(AttestationDataAndCustodyBit(
        data: indexed_attestation.data, custody_bit: false)),
      hash_tree_root(AttestationDataAndCustodyBit(
        data: indexed_attestation.data, custody_bit: true)),
    ],
    indexed_attestation.signature,
    get_domain(
      state,
      DOMAIN_ATTESTATION,
      indexed_attestation.data.target.epoch
    ),
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#get_attesting_indices
func get_attesting_indices*(state: BeaconState,
                            data: AttestationData,
                            bits: CommitteeValidatorsBits,
                            stateCache: var StateCache):
                            HashSet[ValidatorIndex] =
  # Return the set of attesting indices corresponding to ``data`` and ``bits``.
  result = initSet[ValidatorIndex]()
  let committee =
    get_crosslink_committee(
      state, data.target.epoch, data.crosslink.shard, stateCache)
  for i, index in committee:
    if bits[i]:
      result.incl index

# TODO remove after removing attestation pool legacy usage
func get_attesting_indices_seq*(state: BeaconState,
                                attestation_data: AttestationData,
                                bits: CommitteeValidatorsBits): seq[ValidatorIndex] =
  var cache = get_empty_per_epoch_cache()
  toSeq(items(get_attesting_indices(
    state, attestation_data, bits, cache)))

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#get_indexed_attestation
func get_indexed_attestation*(state: BeaconState, attestation: Attestation,
    stateCache: var StateCache): IndexedAttestation =
  # Return the indexed attestation corresponding to ``attestation``.
  let
    attesting_indices =
      get_attesting_indices(
        state, attestation.data, attestation.aggregation_bits, stateCache)
    custody_bit_1_indices =
      get_attesting_indices(
        state, attestation.data, attestation.custody_bits, stateCache)

  doAssert custody_bit_1_indices <= attesting_indices

  let
    # custody_bit_0_indices = attesting_indices.difference(custody_bit_1_indices)
    custody_bit_0_indices =
      filterIt(toSeq(items(attesting_indices)), it notin custody_bit_1_indices)

  ## TODO No fundamental reason to do so many type conversions
  ## verify_indexed_attestation checks for sortedness but it's
  ## entirely a local artifact, seemingly; networking uses the
  ## Attestation data structure, which can't be unsorted. That
  ## the conversion here otherwise needs sorting is due to the
  ## usage of HashSet -- order only matters in one place (that
  ## 0.6.3 highlights and explicates) except in that the spec,
  ## for no obvious reason, verifies it.
  IndexedAttestation(
    custody_bit_0_indices: CustodyBitIndices sorted(
      mapIt(custody_bit_0_indices, it.uint64), system.cmp),
    # toSeq pointlessly constructs int-indexable copy so mapIt can infer type;
    # see above
    custody_bit_1_indices: CustodyBitIndices sorted(
      mapIt(toSeq(items(custody_bit_1_indices)), it.uint64),
      system.cmp),
    data: attestation.data,
    signature: attestation.signature,
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#attestations
proc check_attestation*(
    state: BeaconState, attestation: Attestation, flags: UpdateFlags,
    stateCache: var StateCache): bool =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!

  let stateSlot =
    if nextSlot in flags: state.slot + 1
    else: state.slot

  let data = attestation.data

  trace "process_attestation: beginning",
    attestation=attestation

  if not (data.crosslink.shard < SHARD_COUNT):
    warn("Attestation shard too high",
      attestation_shard = data.crosslink.shard)
    return

  if not (data.target.epoch == get_previous_epoch(state) or
      data.target.epoch == get_current_epoch(state)):
    warn("Target epoch not current or previous epoch")
    return

  let attestation_slot = get_attestation_data_slot(state, attestation.data)

  if not (attestation_slot + MIN_ATTESTATION_INCLUSION_DELAY <= stateSlot):
    warn("Attestation too new",
      attestation_slot = shortLog(attestation_slot),
      state_slot = shortLog(stateSlot))
    return

  if not (stateSlot <= attestation_slot + SLOTS_PER_EPOCH):
    warn("Attestation too old",
      attestation_slot = shortLog(attestation_slot),
      state_slot = shortLog(stateSlot))
    return

  let committee = get_crosslink_committee(state, data.target.epoch, data.crosslink.shard, stateCache)
  if attestation.aggregation_bits.len != attestation.custody_bits.len:
    warn("Inconsistent aggregation and custody bits",
      aggregation_bits_len = attestation.aggregation_bits.len,
      custody_bits_len = attestation.custody_bits.len
    )
    return
  if attestation.aggregation_bits.len != committee.len:
    warn("Inconsistent aggregation and committee length",
      aggregation_bits_len = attestation.aggregation_bits.len,
      committee_len = committee.len
    )
    return

  # Check FFG data, crosslink data, and signature
  let ffg_check_data = (data.source.epoch, data.source.root, data.target.epoch)

  var cache = get_empty_per_epoch_cache()
  if data.target.epoch == get_current_epoch(state):
    if not (ffg_check_data == (state.current_justified_checkpoint.epoch,
        state.current_justified_checkpoint.root, get_current_epoch(state))):
      warn("FFG data not matching current justified epoch")
      return

    if not (data.crosslink.parent_root ==
        hash_tree_root(state.current_crosslinks[data.crosslink.shard])):
      warn("Crosslink shard's current crosslinks not matching crosslink parent root")
      return
  else:
    if not (ffg_check_data == (state.previous_justified_checkpoint.epoch,
        state.previous_justified_checkpoint.root, get_previous_epoch(state))):
      warn("FFG data not matching current justified epoch")
      return

    if not (data.crosslink.parent_root ==
        hash_tree_root(state.previous_crosslinks[data.crosslink.shard])):
      warn("Crosslink shard's previous crosslinks not matching crosslink parent root")
      return

  let parent_crosslink = if data.target.epoch == get_current_epoch(state):
    state.current_crosslinks[data.crosslink.shard]
  else:
    state.previous_crosslinks[data.crosslink.shard]

  if not (data.crosslink.parent_root == hash_tree_root(parent_crosslink)):
    warn("Crosslink parent root doesn't match parent crosslink's root")
    return

  if not (data.crosslink.start_epoch == parent_crosslink.end_epoch):
    warn("Crosslink start and end epochs not the same")
    return

  if not (data.crosslink.end_epoch == min(
      data.target.epoch,
      parent_crosslink.end_epoch + MAX_EPOCHS_PER_CROSSLINK)):
    warn("Crosslink end epoch incorrect",
      crosslink_end_epoch = data.crosslink.end_epoch,
      parent_crosslink_end_epoch = parent_crosslink.end_epoch,
      target_epoch = data.target.epoch)
    return

  if not (data.crosslink.data_root == ZERO_HASH):  # [to be removed in phase 1]
    warn("Crosslink data root not zero")
    return

  # Check signature and bitfields
  if not is_valid_indexed_attestation(
      state, get_indexed_attestation(state, attestation, stateCache)):
    warn("process_attestation: signature or bitfields incorrect")
    return

  true

proc process_attestation*(
    state: var BeaconState, attestation: Attestation, flags: UpdateFlags,
    stateCache: var StateCache): bool =
  # In the spec, attestation validation is mixed with state mutation, so here
  # we've split it into two functions so that the validation logic can be
  # reused when looking for suitable blocks to include in attestations.
  # TODO don't log warnings when looking for attestations (return
  #      Result[void, cstring] instead of logging in check_attestation?)
  if check_attestation(state, attestation, flags, stateCache):
    let
      attestation_slot = get_attestation_data_slot(state, attestation.data)
      pending_attestation = PendingAttestation(
        data: attestation.data,
        aggregation_bits: attestation.aggregation_bits,
        inclusion_delay: state.slot - attestation_slot,
        proposer_index: get_beacon_proposer_index(state, stateCache),
      )

    if attestation.data.target.epoch == get_current_epoch(state):
      trace "process_attestation: current_epoch_attestations.add",
        pending_attestation = pending_attestation,
        indices = get_attesting_indices(
          state, attestation.data, attestation.aggregation_bits, stateCache).len
      state.current_epoch_attestations.add(pending_attestation)
    else:
      trace "process_attestation: previous_epoch_attestations.add",
        pending_attestation = pending_attestation,
        indices = get_attesting_indices(
          state, attestation.data, attestation.aggregation_bits, stateCache).len
      state.previous_epoch_attestations.add(pending_attestation)

    true
  else:
    false

proc makeAttestationData*(
    state: BeaconState, shard: uint64,
    beacon_block_root: Eth2Digest): AttestationData =
  ## Create an attestation / vote for the block `beacon_block_root` using the
  ## data in `state` to fill in the rest of the fields.
  ## `state` is the state corresponding to the `beacon_block_root` advanced to
  ## the slot we're attesting to.

  ## https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/validator/0_beacon-chain-validator.md#construct-attestation

  let
    current_epoch = get_current_epoch(state)
    start_slot = compute_start_slot_of_epoch(current_epoch)
    epoch_boundary_block_root =
      if start_slot == state.slot: beacon_block_root
      else: get_block_root_at_slot(state, start_slot)
    parent_crosslink_end_epoch = state.current_crosslinks[shard].end_epoch

  AttestationData(
    beacon_block_root: beacon_block_root,
    source: state.current_justified_checkpoint,
    target: Checkpoint(
      epoch: current_epoch,
      root: epoch_boundary_block_root
    ),
    crosslink: Crosslink(
      shard: shard,
      parent_root: hash_tree_root(state.current_crosslinks[shard]),
      start_epoch: parent_crosslink_end_epoch,
      end_epoch: min(
        current_epoch, parent_crosslink_end_epoch + MAX_EPOCHS_PER_CROSSLINK),
    )
  )
