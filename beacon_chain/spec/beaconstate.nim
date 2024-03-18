import
  ../extras,
  "."/[eth2_merkleization, forks, validator]

from std/algorithm import fill

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

func genesis_time_from_eth1_timestamp(
    cfg: RuntimeConfig, eth1_timestamp: uint64): uint64 =
  eth1_timestamp + cfg.GENESIS_DELAY

func get_initial_beacon_block*(state: phase0.HashedBeaconState):
    phase0.TrustedSignedBeaconBlock =
  let message = phase0.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
  phase0.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: altair.HashedBeaconState):
    altair.TrustedSignedBeaconBlock =
  let message = altair.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
  altair.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: bellatrix.HashedBeaconState):
    bellatrix.TrustedSignedBeaconBlock =
  let message = bellatrix.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
  bellatrix.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: capella.HashedBeaconState):
    capella.TrustedSignedBeaconBlock =
  let message = capella.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
  capella.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: deneb.HashedBeaconState):
    deneb.TrustedSignedBeaconBlock =
  let message = deneb.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
  deneb.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

from ./datatypes/electra import HashedBeaconState, TrustedSignedBeaconBlock

func get_initial_beacon_block*(state: electra.HashedBeaconState):
    electra.TrustedSignedBeaconBlock =
  let message = electra.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
  electra.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_block_root_at_slot(state: ForkyBeaconState, slot: Slot): Eth2Digest =

  doAssert slot + SLOTS_PER_HISTORICAL_ROOT > slot

  doAssert state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
  doAssert slot < state.slot
  state.block_roots[slot mod SLOTS_PER_HISTORICAL_ROOT]

func get_block_root_at_slot(
    state: ForkedHashedBeaconState, slot: Slot): Eth2Digest =
  withState(state):
    get_block_root_at_slot(forkyState.data, slot)

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
    var tmp = state.latest_block_header
    tmp.state_root = state_root
    hash_tree_root(tmp)
  elif state.slot <=
      (state.latest_block_header.slot + SLOTS_PER_HISTORICAL_ROOT):
    state.get_block_root_at_slot(state.latest_block_header.slot)
  else:
    hash_tree_root(state.latest_block_header)

func latest_block_root*(state: ForkyHashedBeaconState): Eth2Digest =
  latest_block_root(state.data, state.root)
