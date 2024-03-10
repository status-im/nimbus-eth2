{.push raises: [].}

import
  stew/assign2,
  json_serialization/std/sets,
  ../extras,
  ./datatypes/[phase0, altair, bellatrix],
  "."/[eth2_merkleization, forks, validator]

from std/algorithm import fill

export extras, forks, validator

func increase_balance(balance: var Gwei, delta: Gwei) =
  balance += delta

func increase_balance(
    state: var ForkyBeaconState, index: ValidatorIndex, delta: Gwei) =
  if delta != 0: # avoid dirtying the balance cache if not needed
    increase_balance(state.balances.mitem(index), delta)

func decrease_balance(balance: var Gwei, delta: Gwei) =
  balance =
    if delta > balance:
      0'u64
    else:
      balance - delta

func decrease_balance(
    state: var ForkyBeaconState, index: ValidatorIndex, delta: Gwei) =
  if delta != 0: # avoid dirtying the balance cache if not needed
    decrease_balance(state.balances.mitem(index), delta)

func get_validator_from_deposit(deposit: DepositData):
    Validator =
  let
    amount = deposit.amount
    effective_balance = min(
      amount - amount mod EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)

  Validator(
    pubkeyData: HashedValidatorPubKey.init(deposit.pubkey),
    withdrawal_credentials: deposit.withdrawal_credentials,
    activation_eligibility_epoch: FAR_FUTURE_EPOCH,
    activation_epoch: FAR_FUTURE_EPOCH,
    exit_epoch: FAR_FUTURE_EPOCH,
    withdrawable_epoch: FAR_FUTURE_EPOCH,
    effective_balance: effective_balance
  )

func compute_activation_exit_epoch*(epoch: Epoch): Epoch =
  epoch + 1 + MAX_SEED_LOOKAHEAD

func genesis_time_from_eth1_timestamp(
    cfg: RuntimeConfig, eth1_timestamp: uint64): uint64 =
  eth1_timestamp + cfg.GENESIS_DELAY

func get_initial_beacon_block*(state: phase0.HashedBeaconState):
    phase0.TrustedSignedBeaconBlock =
  let message = phase0.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  phase0.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: altair.HashedBeaconState):
    altair.TrustedSignedBeaconBlock =
  let message = altair.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  altair.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: bellatrix.HashedBeaconState):
    bellatrix.TrustedSignedBeaconBlock =
  let message = bellatrix.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  bellatrix.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: capella.HashedBeaconState):
    capella.TrustedSignedBeaconBlock =
  let message = capella.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  capella.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: deneb.HashedBeaconState):
    deneb.TrustedSignedBeaconBlock =
  let message = deneb.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  deneb.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

from ./datatypes/electra import HashedBeaconState, TrustedSignedBeaconBlock

func get_initial_beacon_block*(state: electra.HashedBeaconState):
    electra.TrustedSignedBeaconBlock =
  let message = electra.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  electra.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_block_root_at_slot*(state: ForkyBeaconState, slot: Slot): Eth2Digest =

  doAssert slot + SLOTS_PER_HISTORICAL_ROOT > slot

  doAssert state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
  doAssert slot < state.slot
  state.block_roots[slot mod SLOTS_PER_HISTORICAL_ROOT]

func get_block_root_at_slot(
    state: ForkedHashedBeaconState, slot: Slot): Eth2Digest =
  withState(state):
    get_block_root_at_slot(forkyState.data, slot)

func get_block_root*(state: ForkyBeaconState, epoch: Epoch): Eth2Digest =
  get_block_root_at_slot(state, epoch.start_slot())

template get_total_balance(
    state: ForkyBeaconState, validator_indices: untyped): Gwei =
  var res = 0.Gwei
  for validator_index in validator_indices:
    res += state.validators[validator_index].effective_balance
  max(EFFECTIVE_BALANCE_INCREMENT, res)

iterator get_attesting_indices_iter*(state: ForkyBeaconState,
                                     data: AttestationData,
                                     bits: CommitteeValidatorsBits,
                                     cache: var StateCache): ValidatorIndex =

  let committee_index = CommitteeIndex.init(data.index)
  if committee_index.isErr() or bits.lenu64 != get_beacon_committee_len(
      state, data.slot, committee_index.get(), cache):
    discard
  else:
    for index_in_committee, validator_index in get_beacon_committee(
        state, data.slot, committee_index.get(), cache):
      if bits[index_in_committee]:
        yield validator_index

func check_attestation_slot_target*(data: AttestationData): Result[Slot, cstring] =
  if not (data.target.epoch == epoch(data.slot)):
    return err("Target epoch doesn't match attestation slot")

  ok(data.slot)

func check_attestation_index*(
    index, committees_per_slot: uint64):
    Result[CommitteeIndex, cstring] =
  CommitteeIndex.init(index, committees_per_slot)

func check_attestation_index*(
    data: AttestationData, committees_per_slot: uint64):
    Result[CommitteeIndex, cstring] =
  check_attestation_index(data.index, committees_per_slot)

func get_total_active_balance*(state: ForkyBeaconState, cache: var StateCache): Gwei =

  let epoch = state.get_current_epoch()

  cache.total_active_balance.withValue(epoch, tab) do:
    return tab[]
  do:
    let tab = get_total_balance(
      state, cache.get_shuffled_active_validator_indices(state, epoch))
    cache.total_active_balance[epoch] = tab
    return tab

func get_next_sync_committee_keys(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState):
    array[SYNC_COMMITTEE_SIZE, ValidatorPubKey] =

  let epoch = get_current_epoch(state) + 1

  const MAX_RANDOM_BYTE = 255
  let
    active_validator_indices = get_active_validator_indices(state, epoch)
    active_validator_count = uint64(len(active_validator_indices))
    seed = get_seed(state, epoch, DOMAIN_SYNC_COMMITTEE)
  var
    i = 0'u64
    index = 0
    res: array[SYNC_COMMITTEE_SIZE, ValidatorPubKey]
    hash_buffer: array[40, byte]
  hash_buffer[0..31] = seed.data
  while index < SYNC_COMMITTEE_SIZE:
    hash_buffer[32..39] = uint_to_bytes(uint64(i div 32))
    let
      shuffled_index = compute_shuffled_index(
        uint64(i mod active_validator_count), active_validator_count, seed)
      candidate_index = active_validator_indices[shuffled_index]
      random_byte = eth2digest(hash_buffer).data[i mod 32]
      effective_balance = state.validators[candidate_index].effective_balance
    if effective_balance * MAX_RANDOM_BYTE >= MAX_EFFECTIVE_BALANCE * random_byte:
      res[index] = state.validators[candidate_index].pubkey
      inc index
    i += 1'u64
  res

func has_eth1_withdrawal_credential*(validator: Validator): bool =
  validator.withdrawal_credentials.data[0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX

func is_fully_withdrawable_validator(
    validator: Validator, balance: Gwei, epoch: Epoch): bool =
  has_eth1_withdrawal_credential(validator) and
    validator.withdrawable_epoch <= epoch and balance > 0

func is_partially_withdrawable_validator(
    validator: Validator, balance: Gwei): bool =
  let
    has_max_effective_balance =
      validator.effective_balance == MAX_EFFECTIVE_BALANCE
    has_excess_balance = balance > MAX_EFFECTIVE_BALANCE
  has_eth1_withdrawal_credential(validator) and
    has_max_effective_balance and has_excess_balance

func get_expected_withdrawals*(
    state: capella.BeaconState | deneb.BeaconState | electra.BeaconState):
    seq[Withdrawal] =
  let
    epoch = get_current_epoch(state)
    num_validators = lenu64(state.validators)
  var
    withdrawal_index = state.next_withdrawal_index
    validator_index = state.next_withdrawal_validator_index
    withdrawals: seq[Withdrawal] = @[]
    bound = min(len(state.validators), MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
  for _ in 0 ..< bound:
    let
      validator = state.validators[validator_index]
      balance = state.balances[validator_index]
    if is_fully_withdrawable_validator(validator, balance, epoch):
      var w = Withdrawal(
        index: withdrawal_index,
        validator_index: validator_index,
        amount: balance)
      w.address.data[0..19] = validator.withdrawal_credentials.data[12..^1]
      withdrawals.add w
      withdrawal_index = WithdrawalIndex(withdrawal_index + 1)
    elif is_partially_withdrawable_validator(validator, balance):
      var w = Withdrawal(
        index: withdrawal_index,
        validator_index: validator_index,
        amount: balance - MAX_EFFECTIVE_BALANCE)
      w.address.data[0..19] = validator.withdrawal_credentials.data[12..^1]
      withdrawals.add w
      withdrawal_index = WithdrawalIndex(withdrawal_index + 1)
    if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
      break
    validator_index = (validator_index + 1) mod num_validators
  withdrawals

func compute_deposit_root(deposits: openArray[DepositData]): Eth2Digest =
  var merkleizer = createMerkleizer2(DEPOSIT_CONTRACT_TREE_DEPTH + 1)
  for i, deposit in deposits:
    let htr = hash_tree_root(deposit)
    merkleizer.addChunk(htr.data)

  mixInLength(merkleizer.getFinalHash(), deposits.len)

proc initialize_beacon_state_from_eth1*(
    cfg: RuntimeConfig,
    eth1_block_hash: Eth2Digest,
    eth1_timestamp: uint64,
    deposits: openArray[DepositData],
    execution_payload_header: ForkyExecutionPayloadHeader,
    flags: UpdateFlags = {}): auto =

  doAssert deposits.lenu64 >= SLOTS_PER_EPOCH

  const consensusFork = typeof(execution_payload_header).kind
  let
    forkVersion = cfg.forkVersion(consensusFork)
    fork = Fork(
      previous_version: forkVersion,
      current_version: forkVersion,
      epoch: GENESIS_EPOCH)

  template state(): untyped = result
  result = consensusFork.BeaconState(
    fork: fork,
    genesis_time: genesis_time_from_eth1_timestamp(cfg, eth1_timestamp),
    eth1_data: Eth1Data(
      deposit_count: deposits.lenu64,
      deposit_root: compute_deposit_root(deposits),
      block_hash: eth1_block_hash),
    eth1_deposit_index: deposits.lenu64,
    latest_block_header: BeaconBlockHeader(
      body_root: hash_tree_root(default consensusFork.BeaconBlockBody)))

  state.randao_mixes.data.fill(eth1_block_hash)

  var pubkeyToIndex = initTable[ValidatorPubKey, ValidatorIndex]()
  for idx, deposit in deposits:
    let
      pubkey = deposit.pubkey
      amount = deposit.amount

    pubkeyToIndex.withValue(pubkey, foundIdx) do:
      # Increase balance by deposit amount
      increase_balance(state, foundIdx[], amount)
    do:
      pubkeyToIndex[pubkey] = ValidatorIndex(state.validators.len)
      if not state.validators.add(get_validator_from_deposit(deposit)):
        raiseAssert "too many validators"
      if not state.balances.add(amount):
        raiseAssert "same as validators"

  var
    empty_participation: EpochParticipationFlags
    inactivity_scores = HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]()

  doAssert empty_participation.asList.setLen(state.validators.len)
  doAssert inactivity_scores.data.setLen(state.validators.len)
  inactivity_scores.resetCache()

  state.previous_epoch_participation = empty_participation
  state.current_epoch_participation = empty_participation
  state.inactivity_scores = inactivity_scores

  for vidx in state.validators.vindices:
    let
      balance = state.balances.item(vidx)
      validator = addr state.validators.mitem(vidx)

    validator.effective_balance = min(
      balance - balance mod EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)

    if validator.effective_balance == MAX_EFFECTIVE_BALANCE:
      validator.activation_eligibility_epoch = GENESIS_EPOCH
      validator.activation_epoch = GENESIS_EPOCH

  state.genesis_validators_root = hash_tree_root(state.validators)

  state.latest_execution_payload_header = execution_payload_header


func latest_block_root(state: ForkyBeaconState, state_root: Eth2Digest):
    Eth2Digest =
  if state.slot == state.latest_block_header.slot:
    # process_slot will not yet have updated the header of the "current" block -
    # similar to block creation, we fill it in with the state root
    var tmp = state.latest_block_header
    tmp.state_root = state_root
    hash_tree_root(tmp)
  elif state.slot <=
      (state.latest_block_header.slot + SLOTS_PER_HISTORICAL_ROOT):
    # block_roots is limited to about a day - see assert in
    # `get_block_root_at_slot`
    state.get_block_root_at_slot(state.latest_block_header.slot)
  else:
    # Reallly long periods of empty slots - unlikely but possible
    hash_tree_root(state.latest_block_header)

func latest_block_root*(state: ForkyHashedBeaconState): Eth2Digest =
  latest_block_root(state.data, state.root)

func latest_block_root*(state: ForkedHashedBeaconState): Eth2Digest =
  withState(state): latest_block_root(forkyState)

func dependent_root*(state: ForkyHashedBeaconState, epoch: Epoch): Eth2Digest =
  if epoch > state.data.slot.epoch:
    state.latest_block_root
  elif epoch == Epoch(0):
    if state.data.slot == Slot(0):
      state.latest_block_root
    else:
      state.data.get_block_root_at_slot(Slot(0))
  else:
    let dependent_slot = epoch.start_slot - 1
    if state.data.slot <= dependent_slot + SLOTS_PER_HISTORICAL_ROOT:
      state.data.get_block_root_at_slot(epoch.start_slot - 1)
    else:
      Eth2Digest() # "don't know"

func proposer_dependent_root*(state: ForkyHashedBeaconState): Eth2Digest =
  state.dependent_root(state.data.slot.epoch)

func latest_block_id*(state: ForkyHashedBeaconState): BlockId =
  BlockId(
    root: state.latest_block_root,
    slot: state.data.latest_block_header.slot)

func latest_block_id*(state: ForkedHashedBeaconState): BlockId =
  withState(state): forkyState.latest_block_id()

func matches_block_slot(
    state: ForkyHashedBeaconState, block_root: Eth2Digest, slot: Slot): bool =
  slot == state.data.slot and block_root == state.latest_block_root
func matches_block_slot*(
    state: ForkedHashedBeaconState, block_root: Eth2Digest, slot: Slot): bool =
  withState(state): forkyState.matches_block_slot(block_root, slot)

func can_advance_slots(
    state: ForkyHashedBeaconState, block_root: Eth2Digest, target_slot: Slot): bool =
  target_slot >= state.data.slot and block_root == state.latest_block_root
func can_advance_slots*(
    state: ForkedHashedBeaconState, block_root: Eth2Digest, target_slot: Slot): bool =
  withState(state): forkyState.can_advance_slots(block_root, target_slot)
