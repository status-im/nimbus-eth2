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

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#verify_merkle_branch
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#increase_balance
func increase_balance*(
    state: var BeaconState, index: ValidatorIndex, delta: Gwei) =
  # Increase validator balance by ``delta``.
  state.balances[index] += delta

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#decrease_balance
func decrease_balance*(
    state: var BeaconState, index: ValidatorIndex, delta: Gwei) =
  # Decrease validator balance by ``delta`` with underflow protection.
  state.balances[index] =
    if delta > state.balances[index]:
      0'u64
    else:
      state.balances[index] - delta

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#deposits
func process_deposit*(
    state: var BeaconState, deposit: Deposit, flags: UpdateFlags = {}): bool =
  # Process an Eth1 deposit, registering a validator or increasing its balance.

  # Verify the Merkle branch
  # TODO enable this check, but don't use doAssert
  if not verify_merkle_branch(
    hash_tree_root(deposit.data),
     deposit.proof,
     DEPOSIT_CONTRACT_TREE_DEPTH,
     deposit.index,
    state.latest_eth1_data.deposit_root,
  ):
    ## TODO: a notice-like mechanism which works in a func
    ## here and elsewhere, one minimal approach is a check-if-true
    ## and return false iff so.
    ## obviously, better/more principled ones exist, but
    ## generally require broader rearchitecting, and this is what
    ## mostly happens now, just haphazardly.
    discard

  # Deposits must be processed in order
  if not (deposit.index == state.deposit_index):
    ## TODO see above, re errors
    ## it becomes even more important, as one might might sometimes want
    ## to flag such things as higher/lower priority. chronicles?
    return false

  state.deposit_index += 1

  let
    pubkey = deposit.data.pubkey
    amount = deposit.data.amount
    validator_pubkeys = mapIt(state.validator_registry, it.pubkey)
    index = validator_pubkeys.find(pubkey)

  if index == -1:
    # Verify the deposit signature (proof of possession)
    # TODO should be get_domain(state, DOMAIN_DEPOSIT)
    if skipValidation notin flags and not bls_verify(
        pubkey, signing_root(deposit.data).data, deposit.data.signature,
        3'u64):
      return false

    # Add validator and balance entries
    state.validator_registry.add(Validator(
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#get_delayed_activation_exit_epoch
func get_delayed_activation_exit_epoch*(epoch: Epoch): Epoch =
  ## Return the epoch at which an activation or exit triggered in ``epoch``
  ## takes effect.
  epoch + 1 + ACTIVATION_EXIT_DELAY

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#get_churn_limit
func get_churn_limit(state: BeaconState): uint64 =
  max(
    MIN_PER_EPOCH_CHURN_LIMIT,
    len(get_active_validator_indices(state, get_current_epoch(state))) div
      CHURN_LIMIT_QUOTIENT
  ).uint64

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#initiate_validator_exit
func initiate_validator_exit*(state: var BeaconState,
                              index: ValidatorIndex) =
  # Initiate the validator of the given ``index``.

  # Return if validator already initiated exit
  let validator = addr state.validator_registry[index]
  if validator.exit_epoch != FAR_FUTURE_EPOCH:
    return

  # Compute exit queue epoch
  # TODO try zero-functional here
  let exit_epochs = mapIt(
    filterIt(state.validator_registry, it.exit_epoch != FAR_FUTURE_EPOCH),
    it.exit_epoch)
  var exit_queue_epoch =
    max(max(exit_epochs),
      get_delayed_activation_exit_epoch(get_current_epoch(state)))
  let exit_queue_churn = foldl(
    state.validator_registry,
    a + (if b.exit_epoch == exit_queue_epoch: 1'u64 else: 0'u64),
    0'u64)

  if exit_queue_churn >= get_churn_limit(state):
    exit_queue_epoch += 1

  # Set validator exit epoch and withdrawable epoch
  validator.exit_epoch = exit_queue_epoch
  validator.withdrawable_epoch =
    validator.exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#slash_validator
func slash_validator*(state: var BeaconState, slashed_index: ValidatorIndex) =
  # Slash the validator with index ``index``.
  let current_epoch = get_current_epoch(state)
  initiate_validator_exit(state, slashed_index)
  state.validator_registry[slashed_index].slashed = true
  state.validator_registry[slashed_index].withdrawable_epoch =
    current_epoch + LATEST_SLASHED_EXIT_LENGTH
  let slashed_balance =
    state.validator_registry[slashed_index].effective_balance
  state.latest_slashed_balances[current_epoch mod LATEST_SLASHED_EXIT_LENGTH] +=
    slashed_balance

  let
    proposer_index = get_beacon_proposer_index(state)
    whistleblower_index = proposer_index
    whistleblowing_reward = slashed_balance div WHISTLEBLOWING_REWARD_QUOTIENT
    proposer_reward = whistleblowing_reward div PROPOSER_REWARD_QUOTIENT
  increase_balance(state, proposer_index, proposer_reward)
  increase_balance(
    state, whistleblower_index, whistleblowing_reward - proposer_reward)
  decrease_balance(state, slashed_index, whistleblowing_reward)

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#get_temporary_block_header
func get_temporary_block_header*(blck: BeaconBlock): BeaconBlockHeader =
  ## Return the block header corresponding to a block with ``state_root`` set
  ## to ``ZERO_HASH``.
  BeaconBlockHeader(
    slot: blck.slot,
    previous_block_root: blck.previous_block_root,
    state_root: ZERO_HASH,
    block_body_root: hash_tree_root(blck.body),
    # signing_root(block) is used for block id purposes so signature is a stub
    signature: EMPTY_SIGNATURE,
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#on-genesis
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
    slot: GENESIS_SLOT,
    genesis_time: genesis_time,
    fork: Fork(
        previous_version: GENESIS_FORK_VERSION,
        current_version: GENESIS_FORK_VERSION,
        epoch: GENESIS_EPOCH,
    ),

    # validator_registry and balances automatically initalized

    # Randomness and committees
    # latest_randao_mixes automatically initialized

    # Finality
    # previous_epoch_attestations and current_epoch_attestations automatically
    # initialized
    previous_justified_epoch: GENESIS_EPOCH,
    current_justified_epoch: GENESIS_EPOCH,
    justification_bitfield: 0,
    finalized_epoch: GENESIS_EPOCH,
    finalized_root: ZERO_HASH,

    # Recent state
    # latest_block_roots, latest_state_roots, latest_active_index_roots,
    # latest_slashed_balances, and latest_slashed_balances automatically
    # initialized
    latest_block_header: get_temporary_block_header(get_empty_block()),

    # Ethereum 1.0 chain data
    # eth1_data_votes automatically initialized
    latest_eth1_data: genesis_eth1_data,
    deposit_index: 0,
  )

  for i in 0 ..< SHARD_COUNT:
    state.current_crosslinks[i] = Crosslink(
      epoch: GENESIS_EPOCH, crosslink_data_root: ZERO_HASH)

  # Process genesis deposits
  for deposit in genesis_validator_deposits:
    discard process_deposit(state, deposit, flags)

  # Process genesis activations
  for validator_index in 0 ..< state.validator_registry.len:
    let validator = addr state.validator_registry[validator_index]
    if validator.effective_balance >= MAX_EFFECTIVE_BALANCE:
      validator.activation_eligibility_epoch = GENESIS_EPOCH
      validator.activation_epoch = GENESIS_EPOCH

  let genesis_active_index_root = hash_tree_root(
    get_active_validator_indices(state, GENESIS_EPOCH))
  for index in 0 ..< LATEST_ACTIVE_INDEX_ROOTS_LENGTH:
    state.latest_active_index_roots[index] = genesis_active_index_root

  state

# TODO candidate for spec?
# https://github.com/ethereum/eth2.0-specs/blob/0.5.1/specs/core/0_beacon-chain.md#on-genesis
func get_initial_beacon_block*(state: BeaconState): BeaconBlock =
  BeaconBlock(
    slot: GENESIS_SLOT,
    state_root: hash_tree_root(state)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/core/0_beacon-chain.md#get_attestation_slot
func get_attestation_slot*(state: BeaconState,
    attestation: Attestation|PendingAttestation,
    committee_count: uint64): Slot =
  let
    epoch = attestation.data.target_epoch
    offset = (attestation.data.shard + SHARD_COUNT -
      get_epoch_start_shard(state, epoch)) mod SHARD_COUNT

  # TODO re-instate once double-check correct conditions in attestation pool
  #get_epoch_start_slot(epoch) + offset div (committee_count div SLOTS_PER_EPOCH)
  attestation.data.slot

# This is the slower (O(n)), spec-compatible signature.
func get_attestation_slot*(state: BeaconState,
    attestation: Attestation|PendingAttestation): Slot =
  let epoch = attestation.data.target_epoch
  get_attestation_slot(
    state, attestation, get_epoch_committee_count(state, epoch))

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#get_block_root_at_slot
func get_block_root_at_slot*(state: BeaconState,
                             slot: Slot): Eth2Digest =
  # Return the block root at a recent ``slot``.

  doAssert state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
  doAssert slot < state.slot
  state.latest_block_roots[slot mod SLOTS_PER_HISTORICAL_ROOT]

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#get_block_root
func get_block_root*(state: BeaconState, epoch: Epoch): Eth2Digest =
  # Return the block root at a recent ``epoch``.
  get_block_root_at_slot(state, get_epoch_start_slot(epoch))

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#get_attestation_participants
## TODO this is now a wrapper and not natively in 0.6.3; upstream callers
## should find other approaches
func get_attestation_participants*(state: BeaconState,
                                   attestation_data: AttestationData,
                                   bitfield: BitField): seq[ValidatorIndex] =
  ## Return the participant indices at for the ``attestation_data`` and
  ## ``bitfield``.
  ## Attestation participants in the attestation data are called out in a
  ## bit field that corresponds to the committee of the shard at the time;
  ## this function converts it to list of indices in to BeaconState.validators
  ##
  ## Returns empty list if the shard is not found
  ## Return the participant indices at for the ``attestation_data`` and ``bitfield``.

  # Find the committee in the list with the desired shard
  let crosslink_committee = get_crosslink_committee(
    state, attestation_data.target_epoch, attestation_data.shard)

  # TODO this and other attestation-based fields need validation so we don't
  #      crash on a malicious attestation!
  doAssert verify_bitfield(bitfield, len(crosslink_committee))

  # Find the participating attesters in the committee
  result = @[]
  for i, validator_index in crosslink_committee:
    let aggregation_bit = get_bitfield_bit(bitfield, i)
    if aggregation_bit:
      result.add(validator_index)

# TODO legacy function; either gradually remove callers or incorporate as own
iterator get_attestation_participants_cached*(state: BeaconState,
                                   attestation_data: AttestationData,
                                   bitfield: BitField,
                                   cache: var StateCache): ValidatorIndex =
  for participant in get_attestation_participants(
      state, attestation_data, bitfield):
    yield participant

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#get_total_balance
func get_total_balance*(state: BeaconState, validators: auto): Gwei =
  # Return the combined effective balance of an array of ``validators``.
  foldl(validators, a + state.validator_registry[b].effective_balance, 0'u64)

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#registry-updates
func process_registry_updates*(state: var BeaconState) =
  # Process activation eligibility and ejections
  for index, validator in state.validator_registry:
    if validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH and
        validator.effective_balance >= MAX_EFFECTIVE_BALANCE:
      state.validator_registry[index].activation_eligibility_epoch =
        get_current_epoch(state)

    if is_active_validator(validator, get_current_epoch(state)) and
        validator.effective_balance <= EJECTION_BALANCE:
      initiate_validator_exit(state, index.ValidatorIndex)

  ## Queue validators eligible for activation and not dequeued for activation
  ## prior to finalized epoch
  var activation_queue : seq[tuple[a: Epoch, b: int]] = @[]
  for index, validator in state.validator_registry:
    if validator.activation_eligibility_epoch != FAR_FUTURE_EPOCH and
        validator.activation_epoch >=
          get_delayed_activation_exit_epoch(state.finalized_epoch):
      activation_queue.add (
        state.validator_registry[index].activation_eligibility_epoch, index)

  activation_queue.sort(system.cmp)

  ## Dequeued validators for activation up to churn limit (without resetting
  ## activation epoch)
  let churn_limit = get_churn_limit(state)
  for i, epoch_and_index in activation_queue:
    if i.uint64 >= churn_limit:
      break
    let
      (epoch, index) = epoch_and_index
      validator = addr state.validator_registry[index]
    if validator.activation_epoch == FAR_FUTURE_EPOCH:
      validator.activation_epoch =
        get_delayed_activation_exit_epoch(get_current_epoch(state))

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#verify_indexed_attestation
func verify_indexed_attestation*(
    state: BeaconState, indexed_attestation: IndexedAttestation): bool =
  # Verify validity of ``indexed_attestation`` fields.

  let
    custody_bit_0_indices = indexed_attestation.custody_bit_0_indices
    custody_bit_1_indices = indexed_attestation.custody_bit_1_indices

  # Ensure no duplicate indices across custody bits
  if len(intersection(toSet(custody_bit_0_indices), toSet(custody_bit_1_indices))) != 0:
     return false

  if len(custody_bit_1_indices) > 0:  # [TO BE REMOVED IN PHASE 1]
    return false

  let combined_len = len(custody_bit_0_indices) + len(custody_bit_1_indices)
  if not (1 <= combined_len and combined_len <= MAX_INDICES_PER_ATTESTATION):
    return false

  if custody_bit_0_indices != sorted(custody_bit_0_indices, system.cmp):
    return false

  if custody_bit_1_indices != sorted(custody_bit_1_indices, system.cmp):
    return false

  bls_verify_multiple(
    @[
      bls_aggregate_pubkeys(
        mapIt(custody_bit_0_indices, state.validator_registry[it.int].pubkey)),
      bls_aggregate_pubkeys(
        mapIt(custody_bit_1_indices, state.validator_registry[it.int].pubkey)),
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
      indexed_attestation.data.target_epoch
    ),
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#get_attesting_indices
func get_attesting_indices*(state: BeaconState,
                           attestation_data: AttestationData,
                           bitfield: BitField): HashSet[ValidatorIndex] =
  ## Return the sorted attesting indices corresponding to ``attestation_data``
  ## and ``bitfield``.
  ## The spec goes through a lot of hoops to sort things, and sometimes
  ## constructs sets from the results here. The basic idea is to always
  ## just do the right thing and keep it in a HashSet.
  result = initSet[ValidatorIndex]()
  let committee =
    get_crosslink_committee(state, attestation_data.target_epoch,
      attestation_data.shard)
  doAssert verify_bitfield(bitfield, len(committee))
  for i, index in committee:
    if get_bitfield_bit(bitfield, i):
      result.incl index

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#convert_to_indexed
func convert_to_indexed(state: BeaconState, attestation: Attestation): IndexedAttestation =
  # Convert ``attestation`` to (almost) indexed-verifiable form.
  let
    attesting_indices =
      get_attesting_indices(
        state, attestation.data, attestation.aggregation_bitfield)
    custody_bit_1_indices =
      get_attesting_indices(
        state, attestation.data, attestation.custody_bitfield)

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
    custody_bit_0_indices =
      filterIt(toSeq(items(attesting_indices)), it notin custody_bit_1_indices)

  # TODO No fundamental reason to do so many type conversions
  IndexedAttestation(
    custody_bit_0_indices: mapIt(custody_bit_0_indices, it.uint64),
    # toSeq pointlessly constructs int-indexable copy so mapIt can infer type;
    # see above
    custody_bit_1_indices:
      mapIt(toSeq(items(custody_bit_1_indices)), it.uint64),
    data: attestation.data,
    signature: attestation.signature,
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#attestations
proc checkAttestation*(
    state: BeaconState, attestation: Attestation, flags: UpdateFlags): bool =
  ## Process ``Attestation`` operation.
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!

  let stateSlot =
    if nextSlot in flags: state.slot + 1
    else: state.slot

  let attestation_slot = get_attestation_slot(state, attestation)
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

  # Check target epoch, source epoch, source root, and source crosslink
  let data = attestation.data
  if not (
    (data.target_epoch, data.source_epoch, data.source_root, data.previous_crosslink_root) ==
      (get_current_epoch(state), state.current_justified_epoch,
       state.current_justified_root,
       hash_tree_root(state.current_crosslinks[data.shard])) or
    (data.target_epoch, data.source_epoch, data.source_root, data.previous_crosslink_root) ==
      (get_previous_epoch(state), state.previous_justified_epoch,
       state.previous_justified_root,
       hash_tree_root(state.previous_crosslinks[data.shard]))):
    warn("checkAttestation: target epoch, source epoch, source root, or source crosslink invalid")
    return

  ## Check crosslink data root
  ## [to be removed in phase 1]
  if attestation.data.crosslink_data_root != ZERO_HASH:
    warn("Invalid crosslink data root")
    return

  # Check signature and bitfields
  if not verify_indexed_attestation(
      state, convert_to_indexed(state, attestation)):
    warn("checkAttestation: signature or bitfields incorrect")
    return

  true

proc makeAttestationData*(
    state: BeaconState, shard: uint64,
    beacon_block_root: Eth2Digest): AttestationData =
  ## Fine points:
  ## Head must be the head state during the slot that validator is
  ## part of committee - notably, it can't be a newer or older state (!)

  let
    epoch_start_slot = get_epoch_start_slot(slot_to_epoch(state.slot))
    target_root =
      if epoch_start_slot == state.slot: beacon_block_root
      else: get_block_root_at_slot(state, epoch_start_slot)

  AttestationData(
    slot: state.slot,
    shard: shard,
    beacon_block_root: beacon_block_root,
    target_root: target_root,
    crosslink_data_root: Eth2Digest(), # Stub in phase0
    previous_crosslink_root: hash_tree_root(state.current_crosslinks[shard]),
    source_epoch: state.current_justified_epoch,
    source_root: state.current_justified_root,
    target_epoch: slot_to_epoch(state.slot)
  )
