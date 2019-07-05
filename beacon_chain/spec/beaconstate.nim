# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  algorithm, chronicles, collections/sets, math, options, sequtils,
  ../extras, ../ssz, ../beacon_node_types,
  ./bitfield, ./crypto, ./datatypes, ./digest, ./helpers, ./validator,
  tables

# https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#verify_merkle_branch
func verify_merkle_branch(leaf: Eth2Digest, proof: openarray[Eth2Digest], depth: uint64, index: uint64, root: Eth2Digest): bool =
  ## Verify that the given ``leaf`` is on the merkle branch ``proof``
  ## starting with the given ``root``.
  var
    value = leaf
    buf: array[64, byte]

  for i in 0 ..< depth.int:
    if (index div (1'u64 shl i)) mod 2 != 0:
      buf[0..31] = proof[i.int].data
      buf[32..63] = value.data
    else:
      buf[0..31] = value.data
      buf[32..63] = proof[i.int].data
    value = eth2hash(buf)
  value == root

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#increase_balance
func increase_balance*(
    state: var BeaconState, index: ValidatorIndex, delta: Gwei) =
  # Increase the validator balance at index ``index`` by ``delta``.
  state.balances[index] += delta

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#decrease_balance
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
  if not verify_merkle_branch(
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
    # TODO should be get_domain(state, DOMAIN_DEPOSIT)
    if skipValidation notin flags and not bls_verify(
        pubkey, signing_root(deposit.data).data, deposit.data.signature,
        3'u64):
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#compute_activation_exit_epoch
func compute_activation_exit_epoch*(epoch: Epoch): Epoch =
  ## Return the epoch during which validator activations and exits initiated in
  ## ``epoch`` take effect.
  epoch + 1 + ACTIVATION_EXIT_DELAY

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#get_validator_churn_limit
func get_validator_churn_limit(state: BeaconState): uint64 =
  # Return the validator churn limit for the current epoch.
  let active_validator_indices =
    get_active_validator_indices(state, get_current_epoch(state))
  max(MIN_PER_EPOCH_CHURN_LIMIT,
    len(active_validator_indices) div CHURN_LIMIT_QUOTIENT).uint64

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#initiate_validator_exit
func initiate_validator_exit*(state: var BeaconState,
                              index: ValidatorIndex) =
  # Initiate the exit of the validator with index ``index``.

  # Return if validator already initiated exit
  let validator = addr state.validators[index]
  if validator.exit_epoch != FAR_FUTURE_EPOCH:
    return

  # Compute exit queue epoch
  # TODO try zero-functional here
  let exit_epochs = mapIt(
    filterIt(state.validators, it.exit_epoch != FAR_FUTURE_EPOCH),
    it.exit_epoch)
  var exit_queue_epoch =
    max(max(exit_epochs),
      compute_activation_exit_epoch(get_current_epoch(state)))
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#slash_validator
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

func get_temporary_block_header(blck: BeaconBlock): BeaconBlockHeader =
  ## Return the block header corresponding to a block with ``state_root`` set
  ## to ``ZERO_HASH``.
  BeaconBlockHeader(
    slot: blck.slot,
    parent_root: blck.parent_root,
    state_root: ZERO_HASH,
    body_root: hash_tree_root(blck.body),
    # signing_root(block) is used for block id purposes so signature is a stub
    signature: ValidatorSig(),
  )

func get_empty_block*(): BeaconBlock =
  # Nim default values fill this in mostly correctly.
  BeaconBlock(slot: GENESIS_SLOT)

func get_genesis_beacon_state*(
    genesis_validator_deposits: openArray[Deposit],
    genesis_time: uint64,
    genesis_eth1_data: Eth1Data,
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
  doAssert genesis_validator_deposits.len >= SLOTS_PER_EPOCH

  var state = BeaconState(
    # Misc
    genesis_time: genesis_time,
    fork: Fork(
        previous_version: GENESIS_FORK_VERSION,
        current_version: GENESIS_FORK_VERSION,
        epoch: GENESIS_EPOCH,
    ),

    latest_block_header: get_temporary_block_header(get_empty_block()),

    # Ethereum 1.0 chain data
    # eth1_data_votes automatically initialized
    eth1_data: genesis_eth1_data,
  )

  # Process genesis deposits
  for deposit in genesis_validator_deposits:
    discard process_deposit(state, deposit, flags)

  # Process genesis activations
  for validator_index in 0 ..< state.validators.len:
    let validator = addr state.validators[validator_index]
    if validator.effective_balance >= MAX_EFFECTIVE_BALANCE:
      validator.activation_eligibility_epoch = GENESIS_EPOCH
      validator.activation_epoch = GENESIS_EPOCH

  let genesis_active_index_root = hash_tree_root(
    get_active_validator_indices(state, GENESIS_EPOCH))
  for index in 0 ..< EPOCHS_PER_HISTORICAL_VECTOR:
    state.active_index_roots[index] = genesis_active_index_root

  state

func get_initial_beacon_block*(state: BeaconState): BeaconBlock =
  BeaconBlock(
    slot: GENESIS_SLOT,
    state_root: hash_tree_root(state)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#get_attestation_data_slot
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#get_block_root_at_slot
func get_block_root_at_slot*(state: BeaconState,
                             slot: Slot): Eth2Digest =
  # Return the block root at a recent ``slot``.

  doAssert state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
  doAssert slot < state.slot
  state.block_roots[slot mod SLOTS_PER_HISTORICAL_ROOT]

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#get_block_root
func get_block_root*(state: BeaconState, epoch: Epoch): Eth2Digest =
  # Return the block root at the start of a recent ``epoch``.
  get_block_root_at_slot(state, compute_start_slot_of_epoch(epoch))

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#get_total_balance
func get_total_balance*(state: BeaconState, validators: auto): Gwei =
  ## Return the combined effective balance of the ``indices``. (1 Gwei minimum
  ## to avoid divisions by zero.)
  max(1'u64,
    foldl(validators, a + state.validators[b].effective_balance, 0'u64)
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#registry-updates
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#is_valid_indexed_attestation
func is_valid_indexed_attestation*(
    state: BeaconState, indexed_attestation: IndexedAttestation): bool =
  # Verify validity of ``indexed_attestation`` fields.

  let
    bit_0_indices = indexed_attestation.custody_bit_0_indices
    bit_1_indices = indexed_attestation.custody_bit_1_indices

  # Verify no index has custody bit equal to 1 [to be removed in phase 1]
  if len(bit_1_indices) != 0:
    return false

  # Verify max number of indices
  let combined_len = len(bit_0_indices) + len(bit_1_indices)
  if not (combined_len <= MAX_VALIDATORS_PER_COMMITTEE):
    return false

  # Verify index sets are disjoint
  if len(intersection(toSet(bit_0_indices), toSet(bit_1_indices))) != 0:
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#get_attesting_indices
func get_attesting_indices*(state: BeaconState,
                            attestation_data: AttestationData,
                            bitfield: BitField,
                            stateCache: var StateCache):
                            HashSet[ValidatorIndex] =
  ## Return the sorted attesting indices corresponding to ``attestation_data``
  ## and ``bitfield``.
  ## The spec goes through a lot of hoops to sort things, and sometimes
  ## constructs sets from the results here. The basic idea is to always
  ## just keep it in a HashSet, which seems to suffice. If needed, it's
  ## possible to follow the spec more literally.
  result = initSet[ValidatorIndex]()
  let committee =
    get_crosslink_committee(
      state, attestation_data.target.epoch, attestation_data.crosslink.shard,
      stateCache)
  for i, index in committee:
    if get_bitfield_bit(bitfield, i):
      result.incl index

func get_attesting_indices_seq*(
    state: BeaconState, attestation_data: AttestationData, bitfield: BitField):
    seq[ValidatorIndex] =
  var cache = get_empty_per_epoch_cache()
  toSeq(items(get_attesting_indices(
    state, attestation_data, bitfield, cache)))

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#get_indexed_attestation
func get_indexed_attestation(state: BeaconState, attestation: Attestation,
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
    ## TODO quadratic, .items, but first-class iterators, etc
    ## filterIt can't work on HashSets directly because it is
    ## assuming int-indexable thing to extract type, because,
    ## like lots of other things in sequtils, it's a template
    ## which doesn't otherwise care about the type system. It
    ## is a mess. Just write the for-loop, etc, I guess, is a
    ## reasonable reaction because of the special for binding
    ## with (non-closure, etc) iterators no other part of Nim
    ## can access. As such, this function's doing many copies
    ## and allocations it has no fundamental reason to do.
    ## TODO phrased in 0.8 as
    ## custody_bit_0_indices = attesting_indices.difference(custody_bit_1_indices)
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
    custody_bit_0_indices: sorted(
      mapIt(custody_bit_0_indices, it.uint64), system.cmp),
    # toSeq pointlessly constructs int-indexable copy so mapIt can infer type;
    # see above
    custody_bit_1_indices:
      sorted(mapIt(toSeq(items(custody_bit_1_indices)), it.uint64),
        system.cmp),
    data: attestation.data,
    signature: attestation.signature,
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#attestations
proc process_attestation*(
    state: BeaconState, attestation: Attestation, flags: UpdateFlags,
    stateCache: var StateCache): bool =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!

  let stateSlot =
    if nextSlot in flags: state.slot + 1
    else: state.slot

  let data = attestation.data

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
      attestation_slot = humaneSlotNum(attestation_slot),
      state_slot = humaneSlotNum(stateSlot))
    return

  if not (stateSlot <= attestation_slot + SLOTS_PER_EPOCH):
    warn("Attestation too old",
      attestation_slot = humaneSlotNum(attestation_slot),
      state_slot = humaneSlotNum(stateSlot))
    return

  let pending_attestation = PendingAttestation(
    data: data,
    aggregation_bits: attestation.aggregation_bits,
    inclusion_delay: state.slot - attestation_slot,
    proposer_index: get_beacon_proposer_index(state, stateCache),
  )

  # Check FFG data, crosslink data, and signature
  let ffg_check_data = (data.source.epoch, data.source.root, data.target.epoch)

  if data.target.epoch == get_current_epoch(state):
    if not (ffg_check_data == (state.current_justified_epoch,
        state.current_justified_root, get_current_epoch(state))):
      warn("FFG data not matching current justified epoch")
      return

    if not (data.crosslink.parent_root ==
        hash_tree_root(state.current_crosslinks[data.crosslink.shard])):
      warn("Crosslink shard's current crosslinks not matching crosslink parent root")
      return

    #state.current_epoch_attestations.add(pending_attestation)
  else:
    if not (ffg_check_data == (state.previous_justified_epoch,
        state.previous_justified_root, get_previous_epoch(state))):
      warn("FFG data not matching current justified epoch")
      return

    if not (data.crosslink.parent_root ==
        hash_tree_root(state.previous_crosslinks[data.crosslink.shard])):
      warn("Crosslink shard's previous crosslinks not matching crosslink parent root")
      return

    #state.previous_epoch_attestations.add(pending_attestation)

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

proc makeAttestationData*(
    state: BeaconState, shard_offset: uint64,
    beacon_block_root: Eth2Digest): AttestationData =
  ## Fine points:
  ## Head must be the head state during the slot that validator is
  ## part of committee - notably, it can't be a newer or older state (!)

  let
    epoch_start_slot = compute_start_slot_of_epoch(compute_epoch_of_slot(state.slot))
    target_root =
      if epoch_start_slot == state.slot: beacon_block_root
      else: get_block_root_at_slot(state, epoch_start_slot)
    shard = (shard_offset + get_start_shard(state,
      compute_epoch_of_slot(state.slot))) mod SHARD_COUNT
    target_epoch = compute_epoch_of_slot(state.slot)

  AttestationData(
    beacon_block_root: beacon_block_root,
    source: Checkpoint(
      epoch: state.current_justified_epoch,
      root: state.current_justified_root
    ),
    target: Checkpoint(
      root: target_root,
      epoch: target_epoch
    ),
    crosslink: Crosslink(
      shard: shard,
      parent_root: hash_tree_root(state.current_crosslinks[shard]),
      start_epoch: state.current_crosslinks[shard].end_epoch,
      end_epoch: target_epoch,
    )
  )
