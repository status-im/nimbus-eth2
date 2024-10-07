# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/assign2,
  json_serialization/std/sets,
  chronicles,
  ./datatypes/[phase0, altair, bellatrix, epbs],
  "."/[eth2_merkleization, forks, signatures, validator]

from std/algorithm import fill, sort
from std/sequtils import anyIt, mapIt, toSeq

export extras, forks, validator, chronicles

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#increase_balance
func increase_balance*(balance: var Gwei, delta: Gwei) =
  balance += delta

func increase_balance*(
    state: var ForkyBeaconState, index: ValidatorIndex, delta: Gwei) =
  ## Increase the validator balance at index ``index`` by ``delta``.
  if delta != 0.Gwei: # avoid dirtying the balance cache if not needed
    increase_balance(state.balances.mitem(index), delta)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#decrease_balance
func decrease_balance*(balance: var Gwei, delta: Gwei) =
  balance =
    if delta > balance:
      0.Gwei
    else:
      balance - delta

func decrease_balance*(
    state: var ForkyBeaconState, index: ValidatorIndex, delta: Gwei) =
  ## Decrease the validator balance at index ``index`` by ``delta``, with
  ## underflow protection.
  if delta != 0.Gwei: # avoid dirtying the balance cache if not needed
    decrease_balance(state.balances.mitem(index), delta)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#new-is_compounding_withdrawal_credential
func is_compounding_withdrawal_credential*(
    withdrawal_credentials: Eth2Digest): bool =
  withdrawal_credentials.data[0] == COMPOUNDING_WITHDRAWAL_PREFIX

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#new-has_compounding_withdrawal_credential
func has_compounding_withdrawal_credential*(validator: Validator): bool =
  ## Check if ``validator`` has an 0x02 prefixed "compounding" withdrawal
  ## credential.
  is_compounding_withdrawal_credential(validator.withdrawal_credentials)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#new-get_max_effective_balance
func get_max_effective_balance*(validator: Validator): Gwei =
  ## Get max effective balance for ``validator``.
  if has_compounding_withdrawal_credential(validator):
    MAX_EFFECTIVE_BALANCE_ELECTRA.Gwei
  else:
    MIN_ACTIVATION_BALANCE.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.3/specs/phase0/beacon-chain.md#deposits
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#modified-apply_deposit
func get_validator_from_deposit*(
    _: phase0.BeaconState | altair.BeaconState | bellatrix.BeaconState |
       capella.BeaconState | deneb.BeaconState,
    pubkey: ValidatorPubKey, withdrawal_credentials: Eth2Digest, amount: Gwei):
    Validator =
  let
    effective_balance = min(
      amount - amount mod EFFECTIVE_BALANCE_INCREMENT.Gwei,
      MAX_EFFECTIVE_BALANCE.Gwei)

  Validator(
    pubkeyData: HashedValidatorPubKey.init(pubkey),
    withdrawal_credentials: withdrawal_credentials,
    activation_eligibility_epoch: FAR_FUTURE_EPOCH,
    activation_epoch: FAR_FUTURE_EPOCH,
    exit_epoch: FAR_FUTURE_EPOCH,
    withdrawable_epoch: FAR_FUTURE_EPOCH,
    effective_balance: effective_balance
  )

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#deposits
func get_validator_from_deposit*(
    _: electra.BeaconState, pubkey: ValidatorPubKey,
    withdrawal_credentials: Eth2Digest, amount: Gwei): Validator =
  var validator = Validator(
    pubkeyData: HashedValidatorPubKey.init(pubkey),
    withdrawal_credentials: withdrawal_credentials,
    activation_eligibility_epoch: FAR_FUTURE_EPOCH,
    activation_epoch: FAR_FUTURE_EPOCH,
    exit_epoch: FAR_FUTURE_EPOCH,
    withdrawable_epoch: FAR_FUTURE_EPOCH,
    effective_balance: 0.Gwei  # [Modified in Electra:EIP7251]
  )

  # [Modified in Electra:EIP7251]
  let max_effective_balance = get_max_effective_balance(validator)
  validator.effective_balance = min(
    amount - amount mod static(Gwei(EFFECTIVE_BALANCE_INCREMENT)),
    max_effective_balance)

  validator

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#modified-add_validator_to_registry
func add_validator_to_registry*(
    state: var ForkyBeaconState, deposit_data: DepositData, amount: Gwei):
    Result[void, cstring] =
  # New validator! Add validator and balance entries
  if not state.validators.add(get_validator_from_deposit(
      state, deposit_data.pubkey, deposit_data.withdrawal_credentials, amount)):
    return err("apply_deposit: too many validators")

  if not state.balances.add(amount):
    static: doAssert state.balances.maxLen == state.validators.maxLen
    raiseAssert "adding validator succeeded, so should balances"

  when typeof(state).kind >= ConsensusFork.Altair:
    if not state.previous_epoch_participation.add(ParticipationFlags(0)):
      return err("apply_deposit: too many validators (previous_epoch_participation)")
    if not state.current_epoch_participation.add(ParticipationFlags(0)):
      return err("apply_deposit: too many validators (current_epoch_participation)")
    if not state.inactivity_scores.add(0'u64):
      return err("apply_deposit: too many validators (inactivity_scores)")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#compute_activation_exit_epoch
func compute_activation_exit_epoch*(epoch: Epoch): Epoch =
  ## Return the epoch during which validator activations and exits initiated in
  ## ``epoch`` take effect.
  epoch + 1 + MAX_SEED_LOOKAHEAD

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#get_validator_churn_limit
func get_validator_churn_limit*(
      cfg: RuntimeConfig, state: ForkyBeaconState, cache: var StateCache):
    uint64 =
  ## Return the validator churn limit for the current epoch.
  max(
    cfg.MIN_PER_EPOCH_CHURN_LIMIT,
    count_active_validators(
      state, state.get_current_epoch(), cache) div cfg.CHURN_LIMIT_QUOTIENT)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/deneb/beacon-chain.md#new-get_validator_activation_churn_limit
func get_validator_activation_churn_limit*(
      cfg: RuntimeConfig, state: deneb.BeaconState | electra.BeaconState,
      cache: var StateCache): uint64 =
  ## Return the validator activation churn limit for the current epoch.
  min(
    cfg.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT,
    get_validator_churn_limit(cfg, state, cache))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#initiate_validator_exit
func get_state_exit_queue_info*(
    state: phase0.BeaconState | altair.BeaconState | bellatrix.BeaconState |
    capella.BeaconState | deneb.BeaconState): ExitQueueInfo =
  var
    exit_queue_epoch = compute_activation_exit_epoch(get_current_epoch(state))
    exit_queue_churn: uint64
  # Compute max exit epoch
  for idx in 0..<state.validators.len:
    let exit_epoch = state.validators.item(idx).exit_epoch
    if exit_epoch != FAR_FUTURE_EPOCH and exit_epoch > exit_queue_epoch:
      exit_queue_epoch = exit_epoch

      # Reset exit queue churn counter as the expected exit_queue_epoch updates
      # via this essentially max()-but-not-FAR_FUTURE_EPOCH loop to restart the
      # counting the second for loop in spec version does. Only the last count,
      # the one corresponding to the ultimately correct exit_queue_epoch, won't
      # be reset.
      exit_queue_churn = 0

    # Second spec loop body, which there is responsible for taking the already
    # known exit_queue_epoch, scanning for all validators with that exit epoch
    # and checking if they'll reach validator_churn_limit(state). Do that here
    # incrementally to fuse the two loops and save an all-validator iteration.
    if exit_epoch == exit_queue_epoch:
      inc exit_queue_churn

  ExitQueueInfo(
    exit_queue_epoch: exit_queue_epoch, exit_queue_churn: exit_queue_churn)

func get_state_exit_queue_info*(
  state: electra.BeaconState | epbs.BeaconState): ExitQueueInfo =
  # Electra initiate_validator_exit doesn't have same quadratic aspect given
  # StateCache balance caching
  default(ExitQueueInfo)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#initiate_validator_exit
func initiate_validator_exit*(
    cfg: RuntimeConfig,
    state: var (phase0.BeaconState | altair.BeaconState |
                bellatrix.BeaconState | capella.BeaconState |
                deneb.BeaconState),
    index: ValidatorIndex, exit_queue_info: ExitQueueInfo,
    cache: var StateCache): Result[ExitQueueInfo, cstring] =
  ## Initiate the exit of the validator with index ``index``.

  if state.validators.item(index).exit_epoch != FAR_FUTURE_EPOCH:
    return ok(exit_queue_info) # Before touching cache

  # Return if validator already initiated exit
  let validator = addr state.validators.mitem(index)

  var
    exit_queue_epoch = exit_queue_info.exit_queue_epoch
    exit_queue_churn = exit_queue_info.exit_queue_churn

  if exit_queue_churn >= get_validator_churn_limit(cfg, state, cache):
    inc exit_queue_epoch

  # Bookkeeping for inter-operation caching; include this exit for next time
    exit_queue_churn = 1
  else:
    inc exit_queue_churn

  # Set validator exit epoch and withdrawable epoch
  validator.exit_epoch = exit_queue_epoch

  if  validator.exit_epoch + cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY <
      validator.exit_epoch:
    return err("initiate_validator_exit: exit_epoch overflowed")

  validator.withdrawable_epoch =
    validator.exit_epoch + cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY

  ok(ExitQueueInfo(
    exit_queue_epoch: exit_queue_epoch, exit_queue_churn: exit_queue_churn))

func get_total_active_balance*(state: ForkyBeaconState, cache: var StateCache): Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#new-get_balance_churn_limit
func get_balance_churn_limit(
    cfg: RuntimeConfig, state: electra.BeaconState,
    cache: var StateCache): Gwei =
  ## Return the churn limit for the current epoch.
  let churn = max(
    cfg.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA.Gwei,
    get_total_active_balance(state, cache) div cfg.CHURN_LIMIT_QUOTIENT
  )
  churn - churn mod EFFECTIVE_BALANCE_INCREMENT.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#new-get_activation_exit_churn_limit
func get_activation_exit_churn_limit*(
    cfg: RuntimeConfig, state: electra.BeaconState, cache: var StateCache):
    Gwei =
  ## Return the churn limit for the current epoch dedicated to activations and
  ## exits.
  min(
    cfg.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT.Gwei,
    get_balance_churn_limit(cfg, state, cache))

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#new-get_consolidation_churn_limit
func get_consolidation_churn_limit*(
    cfg: RuntimeConfig, state: electra.BeaconState, cache: var StateCache):
    Gwei =
  get_balance_churn_limit(cfg, state, cache) -
    get_activation_exit_churn_limit(cfg, state, cache)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#new-compute_exit_epoch_and_update_churn
func compute_exit_epoch_and_update_churn*(
    cfg: RuntimeConfig, state: var electra.BeaconState, exit_balance: Gwei,
    cache: var StateCache): Epoch =
  var earliest_exit_epoch = max(state.earliest_exit_epoch,
    compute_activation_exit_epoch(get_current_epoch(state)))
  let per_epoch_churn = get_activation_exit_churn_limit(cfg, state, cache)

  # New epoch for exits.
  var exit_balance_to_consume =
    if state.earliest_exit_epoch < earliest_exit_epoch:
      per_epoch_churn
    else:
      state.exit_balance_to_consume

  # Exit doesn't fit in the current earliest epoch.
  if exit_balance > exit_balance_to_consume:
    let
      balance_to_process = exit_balance - exit_balance_to_consume
      additional_epochs = (balance_to_process - 1.Gwei) div per_epoch_churn + 1
    earliest_exit_epoch += additional_epochs
    exit_balance_to_consume += additional_epochs * per_epoch_churn

  # Consume the balance and update state variables.
  state.exit_balance_to_consume = exit_balance_to_consume - exit_balance
  state.earliest_exit_epoch = earliest_exit_epoch

  state.earliest_exit_epoch

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#new-compute_consolidation_epoch_and_update_churn
func compute_consolidation_epoch_and_update_churn*(
    cfg: RuntimeConfig, state: var electra.BeaconState,
    consolidation_balance: Gwei, cache: var StateCache): Epoch =
  var earliest_consolidation_epoch = max(state.earliest_consolidation_epoch,
    compute_activation_exit_epoch(get_current_epoch(state)))
  let per_epoch_consolidation_churn =
    get_consolidation_churn_limit(cfg, state, cache)

  # New epoch for consolidations.
  var consolidation_balance_to_consume =
    if state.earliest_consolidation_epoch < earliest_consolidation_epoch:
      per_epoch_consolidation_churn
    else:
      state.consolidation_balance_to_consume

  # Consolidation doesn't fit in the current earliest epoch.
  if consolidation_balance > consolidation_balance_to_consume:
    let
      balance_to_process = consolidation_balance - consolidation_balance_to_consume
      additional_epochs = (balance_to_process - 1.Gwei) div per_epoch_consolidation_churn + 1
    earliest_consolidation_epoch += additional_epochs
    consolidation_balance_to_consume += additional_epochs * per_epoch_consolidation_churn

  # Consume the balance and update state variables.
  state.consolidation_balance_to_consume = consolidation_balance_to_consume - consolidation_balance
  state.earliest_consolidation_epoch = earliest_consolidation_epoch

  state.earliest_consolidation_epoch

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/electra/beacon-chain.md#modified-initiate_validator_exit
func initiate_validator_exit*(
    cfg: RuntimeConfig, state: var electra.BeaconState,
    index: ValidatorIndex, exit_queue_info: ExitQueueInfo,
    cache: var StateCache): Result[ExitQueueInfo, cstring] =
  ## Initiate the exit of the validator with index ``index``.

  # Return if validator already initiated exit
  var validator = state.validators.item(index)
  if validator.exit_epoch != FAR_FUTURE_EPOCH:
    return ok(static(default(ExitQueueInfo)))

  # Compute exit queue epoch [Modified in Electra:EIP7251]
  let exit_queue_epoch = compute_exit_epoch_and_update_churn(
    cfg, state, validator.effective_balance, cache)

  # Set validator exit epoch and withdrawable epoch
  validator.exit_epoch = exit_queue_epoch
  validator.withdrawable_epoch =
    validator.exit_epoch + cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY
  if validator.withdrawable_epoch < validator.exit_epoch:
    return err("Invalid large withdrawable epoch")
  state.validators.mitem(index) = validator

  # The Electra initiate_validator_exit() isn't accidentally quadratic; ignore
  ok(static(default(ExitQueueInfo)))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/bellatrix/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#updated-slash_validator
func get_slashing_penalty*(
    state: ForkyBeaconState, validator_effective_balance: Gwei): Gwei =
  when state is phase0.BeaconState:
    validator_effective_balance div MIN_SLASHING_PENALTY_QUOTIENT
  elif state is altair.BeaconState:
    validator_effective_balance div MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR
  elif state is bellatrix.BeaconState or state is capella.BeaconState or
       state is deneb.BeaconState:
    validator_effective_balance div MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX
  elif state is electra.BeaconState:
    validator_effective_balance div MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA
  else:
    {.fatal: "invalid BeaconState type".}

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/bellatrix/beacon-chain.md#modified-slash_validator
func get_whistleblower_reward*(
    state: phase0.BeaconState | altair.BeaconState | bellatrix.BeaconState |
           capella.BeaconState | deneb.BeaconState,
    validator_effective_balance: Gwei): Gwei =
  validator_effective_balance div WHISTLEBLOWER_REWARD_QUOTIENT

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/electra/beacon-chain.md#modified-slash_validator
func get_whistleblower_reward*(
    state: electra.BeaconState, validator_effective_balance: Gwei): Gwei =
  validator_effective_balance div WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/bellatrix/beacon-chain.md#modified-slash_validator
func get_proposer_reward(state: ForkyBeaconState, whistleblower_reward: Gwei): Gwei =
  when state is phase0.BeaconState:
    whistleblower_reward div PROPOSER_REWARD_QUOTIENT
  elif state is altair.BeaconState or state is bellatrix.BeaconState or
       state is capella.BeaconState or state is deneb.BeaconState or
       state is electra.BeaconState:
    whistleblower_reward * PROPOSER_WEIGHT div WEIGHT_DENOMINATOR
  else:
    {.fatal: "invalid BeaconState type".}

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/bellatrix/beacon-chain.md#modified-slash_validator
proc slash_validator*(
    cfg: RuntimeConfig, state: var ForkyBeaconState,
    slashed_index: ValidatorIndex, pre_exit_queue_info: ExitQueueInfo,
    cache: var StateCache): Result[(Gwei, ExitQueueInfo), cstring] =
  ## Slash the validator with index ``index``.
  let
    epoch = get_current_epoch(state)
    post_exit_queue_info = ? initiate_validator_exit(
      cfg, state, slashed_index, pre_exit_queue_info, cache)

  let validator = addr state.validators.mitem(slashed_index)

  validator.slashed = true
  validator.withdrawable_epoch =
    max(validator.withdrawable_epoch, epoch + EPOCHS_PER_SLASHINGS_VECTOR)
  state.slashings.mitem(int(epoch mod EPOCHS_PER_SLASHINGS_VECTOR)) +=
    validator.effective_balance

  decrease_balance(state, slashed_index,
    get_slashing_penalty(state, validator.effective_balance))

  # The rest doesn't make sense without there being any proposer index, so skip
  let proposer_index = get_beacon_proposer_index(state, cache).valueOr:
    debug "No beacon proposer index and probably no active validators"
    return ok((0.Gwei, post_exit_queue_info))

  # Apply proposer and whistleblower rewards
  let
    # Spec has whistleblower_index as optional param, but it's never used.
    whistleblower_index = proposer_index
    whistleblower_reward =
      get_whistleblower_reward(state, validator.effective_balance)
    proposer_reward = get_proposer_reward(state, whistleblower_reward)

  increase_balance(state, proposer_index, proposer_reward)
  # TODO: evaluate if spec bug / underflow can be triggered
  doAssert(
    whistleblower_reward >= proposer_reward,
    "Spec bug: underflow in slash_validator")
  increase_balance(
    state, whistleblower_index, whistleblower_reward - proposer_reward)

  ok((proposer_reward, post_exit_queue_info))

func genesis_time_from_eth1_timestamp(
    cfg: RuntimeConfig, eth1_timestamp: uint64): uint64 =
  eth1_timestamp + cfg.GENESIS_DELAY

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#genesis-block
func get_initial_beacon_block*(state: phase0.HashedBeaconState):
    phase0.TrustedSignedBeaconBlock =
  # The genesis block is implicitly trusted
  let message = phase0.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  phase0.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/altair/beacon-chain.md#initialize-state-for-pure-altair-testnets-and-test-vectors
func get_initial_beacon_block*(state: altair.HashedBeaconState):
    altair.TrustedSignedBeaconBlock =
  # The genesis block is implicitly trusted
  let message = altair.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  altair.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/bellatrix/beacon-chain.md#testing
func get_initial_beacon_block*(state: bellatrix.HashedBeaconState):
    bellatrix.TrustedSignedBeaconBlock =
  # The genesis block is implicitly trusted
  let message = bellatrix.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  bellatrix.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/capella/beacon-chain.md#testing
func get_initial_beacon_block*(state: capella.HashedBeaconState):
    capella.TrustedSignedBeaconBlock =
  # The genesis block is implicitly trusted
  let message = capella.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  capella.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/beacon-chain.md#testing
func get_initial_beacon_block*(state: deneb.HashedBeaconState):
    deneb.TrustedSignedBeaconBlock =
  # The genesis block is implicitly trusted
  let message = deneb.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  deneb.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

# TODO spec link here when it exists
func get_initial_beacon_block*(state: electra.HashedBeaconState):
    electra.TrustedSignedBeaconBlock =
  # The genesis block is implicitly trusted
  let message = electra.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  electra.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: ForkedHashedBeaconState):
    ForkedTrustedSignedBeaconBlock =
  withState(state):
    ForkedTrustedSignedBeaconBlock.init(get_initial_beacon_block(forkyState))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_block_root_at_slot
func get_block_root_at_slot*(state: ForkyBeaconState, slot: Slot): Eth2Digest =
  ## Return the block root at a recent ``slot``.

  # Potential overflow/wrap shouldn't occur, as get_block_root_at_slot() called
  # from internally controlled sources, but flag this explicitly, in case.
  doAssert slot + SLOTS_PER_HISTORICAL_ROOT > slot

  doAssert state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
  doAssert slot < state.slot
  state.block_roots[slot mod SLOTS_PER_HISTORICAL_ROOT]

func get_block_root_at_slot*(
    state: ForkedHashedBeaconState, slot: Slot): Eth2Digest =
  ## Return the block root at a recent ``slot``.
  withState(state):
    get_block_root_at_slot(forkyState.data, slot)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#get_block_root
func get_block_root*(state: ForkyBeaconState, epoch: Epoch): Eth2Digest =
  ## Return the block root at the start of a recent ``epoch``.
  get_block_root_at_slot(state, epoch.start_slot())

func get_block_root(state: ForkedHashedBeaconState, epoch: Epoch): Eth2Digest =
  ## Return the block root at the start of a recent ``epoch``.
  withState(state):
    get_block_root(forkyState.data, epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#get_total_balance
template get_total_balance(
    state: ForkyBeaconState, validator_indices: untyped): Gwei =
  ## Return the combined effective balance of the ``indices``.
  ## ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
  ## Math safe up to ~10B ETH, after which this overflows uint64.
  var res = 0.Gwei
  for validator_index in validator_indices:
    res += state.validators[validator_index].effective_balance
  max(EFFECTIVE_BALANCE_INCREMENT.Gwei, res)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#is_eligible_for_activation_queue
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#updated-is_eligible_for_activation_queue
func is_eligible_for_activation_queue*(
    fork: static ConsensusFork, validator: Validator): bool =
  ## Check if ``validator`` is eligible to be placed into the activation queue.
  when fork <= ConsensusFork.Deneb:
    validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH and
      validator.effective_balance == MAX_EFFECTIVE_BALANCE.Gwei
  else:
    # [Modified in Electra:EIP7251]
    validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH and
      validator.effective_balance >= MIN_ACTIVATION_BALANCE.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#is_eligible_for_activation
func is_eligible_for_activation*(
    state: ForkyBeaconState, validator: Validator): bool =
  ## Check if ``validator`` is eligible for activation.

  # Placement in queue is finalized
  validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch and
  # Has not yet been activated
    validator.activation_epoch == FAR_FUTURE_EPOCH

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
proc is_valid_indexed_attestation*(
    state: ForkyBeaconState,
    # phase0.SomeIndexedAttestation | electra.SomeIndexedAttestation:
    # https://github.com/nim-lang/Nim/issues/18095
    indexed_attestation:
      phase0.IndexedAttestation | phase0.TrustedIndexedAttestation |
      electra.IndexedAttestation | electra.TrustedIndexedAttestation,
    flags: UpdateFlags): Result[void, cstring] =
  ## Check if ``indexed_attestation`` is not empty, has sorted and unique
  ## indices and has a valid aggregate signature.

  template is_sorted_and_unique(s: untyped): bool =
    var res = true
    for i in 1 ..< s.len:
      if s[i - 1].uint64 >= s[i].uint64:
        res = false
        break
    res

  if len(indexed_attestation.attesting_indices) == 0:
    return err("indexed_attestation: no attesting indices")

  # Not from spec, but this function gets used in front-line roles, not just
  # behind firewall.
  let num_validators = state.validators.lenu64
  if anyIt(indexed_attestation.attesting_indices, it >= num_validators):
    return err("indexed attestation: not all indices valid validators")

  if not is_sorted_and_unique(indexed_attestation.attesting_indices):
    return err("indexed attestation: indices not sorted and unique")

  # Verify aggregate signature
  if not (skipBlsValidation in flags or indexed_attestation.signature is TrustedSig):
    let pubkeys = mapIt(
      indexed_attestation.attesting_indices, state.validators[it].pubkey)
    if not verify_attestation_signature(
        state.fork, state.genesis_validators_root, indexed_attestation.data,
        pubkeys, indexed_attestation.signature):
      return err("indexed attestation: signature verification failure")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_attesting_indices
iterator get_attesting_indices_iter*(state: ForkyBeaconState,
                                     data: AttestationData,
                                     bits: CommitteeValidatorsBits,
                                     cache: var StateCache): ValidatorIndex =
  ## Return the set of attesting indices corresponding to ``data`` and ``bits``
  ## or nothing if `data` is invalid
  ## This iterator must not be called in functions using a
  ## ForkedHashedBeaconState due to https://github.com/nim-lang/Nim/issues/18188
  let committee_index = CommitteeIndex.init(data.index)
  if committee_index.isErr() or bits.lenu64 != get_beacon_committee_len(
      state, data.slot, committee_index.get(), cache):
    trace "get_attesting_indices: invalid attestation data"
  else:
    for index_in_committee, validator_index in get_beacon_committee(
        state, data.slot, committee_index.get(), cache):
      if bits[index_in_committee]:
        yield validator_index

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#modified-get_attesting_indices
iterator get_attesting_indices_iter*(
    state: electra.BeaconState,
    data: AttestationData,
    aggregation_bits: ElectraCommitteeValidatorsBits,
    committee_bits: auto,
    cache: var StateCache): ValidatorIndex =
  ## Return the set of attesting indices corresponding to ``aggregation_bits``
  ## and ``committee_bits``.
  var pos = 0
  for committee_index in get_committee_indices(committee_bits):
    for _, validator_index in get_beacon_committee(
        state, data.slot, committee_index, cache):

      if aggregation_bits[pos]:
        yield validator_index
      pos += 1

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_attesting_indices
func get_attesting_indices*(
    state: ForkyBeaconState, data: AttestationData,
    aggregation_bits: CommitteeValidatorsBits, cache: var StateCache):
    seq[ValidatorIndex] =
  ## Return the set of attesting indices corresponding to ``data`` and ``bits``
  ## or nothing if `data` is invalid

  toSeq(get_attesting_indices_iter(state, data, aggregation_bits, cache))

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#get_attesting_indices
func get_attesting_indices*(
    state: ForkyBeaconState, data: AttestationData,
    aggregation_bits: ElectraCommitteeValidatorsBits, committee_bits: auto,
    cache: var StateCache): seq[ValidatorIndex] =
  ## Return the set of attesting indices corresponding to ``data`` and ``bits``
  ## or nothing if `data` is invalid

  toSeq(get_attesting_indices_iter(state, data, aggregation_bits, committee_bits, cache))

func get_attesting_indices*(state: ForkedHashedBeaconState;
                            data: AttestationData;
                            bits: CommitteeValidatorsBits;
                            cache: var StateCache): seq[ValidatorIndex] =
  # TODO when https://github.com/nim-lang/Nim/issues/18188 fixed, use an
  # iterator

  var idxBuf: seq[ValidatorIndex]
  withState(state):
    for vidx in forkyState.data.get_attesting_indices(data, bits, cache):
      idxBuf.add vidx
  idxBuf

func get_attesting_indices*(state: ForkedHashedBeaconState;
                            data: AttestationData;
                            aggregation_bits: ElectraCommitteeValidatorsBits;
                            committee_bits: auto,
                            cache: var StateCache): seq[ValidatorIndex] =
  # TODO when https://github.com/nim-lang/Nim/issues/18188 fixed, use an
  # iterator

  var idxBuf: seq[ValidatorIndex]
  withState(state):
    when consensusFork >= ConsensusFork.Electra:
      for vidx in forkyState.data.get_attesting_indices(data, aggregation_bits, committee_bits, cache):
        idxBuf.add vidx
  idxBuf

proc is_valid_indexed_attestation(
    state: ForkyBeaconState,
    attestation: SomeAttestation,
    flags: UpdateFlags, cache: var StateCache): Result[void, cstring] =
  # This is a variation on `is_valid_indexed_attestation` that works directly
  # with an attestation instead of first constructing an `IndexedAttestation`
  # and then validating it - for the purpose of validating the signature, the
  # order doesn't matter and we can proceed straight to validating the
  # signature instead

  let sigs = attestation.aggregation_bits.countOnes()
  if sigs == 0:
    return err("is_valid_indexed_attestation: no attesting indices")

  # Verify aggregate signature
  if not (skipBlsValidation in flags or attestation.signature is TrustedSig):
    var
      pubkeys = newSeqOfCap[ValidatorPubKey](sigs)
    for index in get_attesting_indices_iter(
        state, attestation.data, attestation.aggregation_bits, cache):
      pubkeys.add(state.validators[index].pubkey)

    if not verify_attestation_signature(
        state.fork, state.genesis_validators_root, attestation.data,
        pubkeys, attestation.signature):
      return err("indexed attestation: signature verification failure")

  ok()

proc is_valid_indexed_attestation(
    state: ForkyBeaconState,
    attestation: electra.Attestation | electra.TrustedAttestation,
    flags: UpdateFlags, cache: var StateCache): Result[void, cstring] =
  # This is a variation on `is_valid_indexed_attestation` that works directly
  # with an attestation instead of first constructing an `IndexedAttestation`
  # and then validating it - for the purpose of validating the signature, the
  # order doesn't matter and we can proceed straight to validating the
  # signature instead

  let sigs = attestation.aggregation_bits.countOnes()
  if sigs == 0:
    return err("is_valid_indexed_attestation: no attesting indices")

  # Verify aggregate signature
  if not (skipBlsValidation in flags or attestation.signature is TrustedSig):
    var
      pubkeys = newSeqOfCap[ValidatorPubKey](sigs)
    for index in get_attesting_indices_iter(
        state, attestation.data, attestation.aggregation_bits, attestation.committee_bits, cache):
      pubkeys.add(state.validators[index].pubkey)

    if not verify_attestation_signature(
        state.fork, state.genesis_validators_root, attestation.data,
        pubkeys, attestation.signature):
      return err("indexed attestation: signature verification failure")

  ok()

# Attestation validation
# ------------------------------------------------------------------------------------------
# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#attestations
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id

func check_attestation_slot_target*(data: AttestationData): Result[Slot, cstring] =
  if not (data.target.epoch == epoch(data.slot)):
    return err("Target epoch doesn't match attestation slot")

  ok(data.slot)

func check_attestation_target_epoch*(
    data: AttestationData, current_epoch: Epoch): Result[Epoch, cstring] =
  if not (data.target.epoch == get_previous_epoch(current_epoch) or
      data.target.epoch == current_epoch):
    return err("Target epoch not current or previous epoch")

  ok(data.target.epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#attestations
# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#modified-process_attestation
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/deneb/beacon-chain.md#modified-process_attestation
func check_attestation_inclusion(
    consensusFork: static ConsensusFork, attestation_slot: Slot,
    current_slot: Slot): Result[void, cstring] =
  # Check for overflow
  static:
    doAssert SLOTS_PER_EPOCH >= MIN_ATTESTATION_INCLUSION_DELAY
  if attestation_slot + SLOTS_PER_EPOCH <= attestation_slot:
    return err("attestation data.slot overflow, malicious?")

  if not (attestation_slot + MIN_ATTESTATION_INCLUSION_DELAY <= current_slot):
    return err("Attestation too new")

  when consensusFork < ConsensusFork.Deneb:
    if not (current_slot <= attestation_slot + SLOTS_PER_EPOCH):
      return err("Attestation too old")

  ok()

func check_attestation_index*(
    index, committees_per_slot: uint64):
    Result[CommitteeIndex, cstring] =
  CommitteeIndex.init(index, committees_per_slot)

func check_attestation_index(
    data: AttestationData, committees_per_slot: uint64):
    Result[CommitteeIndex, cstring] =
  check_attestation_index(data.index, committees_per_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/altair/beacon-chain.md#get_attestation_participation_flag_indices
func get_attestation_participation_flag_indices(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState,
    data: AttestationData, inclusion_delay: uint64): set[TimelyFlag] =
  ## Return the flag indices that are satisfied by an attestation.
  let justified_checkpoint =
    if data.target.epoch == get_current_epoch(state):
      state.current_justified_checkpoint
    else:
      state.previous_justified_checkpoint

  # Matching roots
  let
    is_matching_source = data.source == justified_checkpoint
    is_matching_target =
      is_matching_source and
        data.target.root == get_block_root(state, data.target.epoch)
    is_matching_head =
      is_matching_target and
        data.beacon_block_root == get_block_root_at_slot(state, data.slot)

  # Checked by check_attestation()
  doAssert is_matching_source

  var participation_flag_indices: set[TimelyFlag]
  if is_matching_source and inclusion_delay <=
      static(integer_squareroot(SLOTS_PER_EPOCH)):
    participation_flag_indices.incl(TIMELY_SOURCE_FLAG_INDEX)
  if is_matching_target and inclusion_delay <= SLOTS_PER_EPOCH:
    participation_flag_indices.incl(TIMELY_TARGET_FLAG_INDEX)
  if is_matching_head and inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY:
    participation_flag_indices.incl(TIMELY_HEAD_FLAG_INDEX)

  participation_flag_indices

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/deneb/beacon-chain.md#modified-get_attestation_participation_flag_indices
func get_attestation_participation_flag_indices(
    state: deneb.BeaconState | electra.BeaconState,
    data: AttestationData, inclusion_delay: uint64): set[TimelyFlag] =
  ## Return the flag indices that are satisfied by an attestation.
  let justified_checkpoint =
    if data.target.epoch == get_current_epoch(state):
      state.current_justified_checkpoint
    else:
      state.previous_justified_checkpoint

  # Matching roots
  let
    is_matching_source = data.source == justified_checkpoint
    is_matching_target =
      is_matching_source and
        data.target.root == get_block_root(state, data.target.epoch)
    is_matching_head =
      is_matching_target and
        data.beacon_block_root == get_block_root_at_slot(state, data.slot)

  # Checked by check_attestation
  doAssert is_matching_source

  var participation_flag_indices: set[TimelyFlag]
  if is_matching_source and inclusion_delay <= integer_squareroot(SLOTS_PER_EPOCH):
    participation_flag_indices.incl(TIMELY_SOURCE_FLAG_INDEX)
  if is_matching_target:  # [Modified in Deneb:EIP7045]
    participation_flag_indices.incl(TIMELY_TARGET_FLAG_INDEX)
  if is_matching_head and inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY:
    participation_flag_indices.incl(TIMELY_HEAD_FLAG_INDEX)

  participation_flag_indices

# TODO these aren't great here
# TODO these duplicate some stuff in state_transition_epoch which uses TotalBalances
# better to centralize around that if feasible

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#get_total_active_balance
func get_total_active_balance*(state: ForkyBeaconState, cache: var StateCache): Gwei =
  ## Return the combined effective balance of the active validators.
  ## Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei
  ## minimum to avoid divisions by zero.

  let epoch = state.get_current_epoch()

  cache.total_active_balance.withValue(epoch, tab) do:
    return tab[]
  do:
    let tab = get_total_balance(
      state, cache.get_shuffled_active_validator_indices(state, epoch))
    cache.total_active_balance[epoch] = tab
    return tab

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/altair/beacon-chain.md#get_base_reward_per_increment
func get_base_reward_per_increment_sqrt(
    total_active_balance_sqrt: uint64): Gwei =
  EFFECTIVE_BALANCE_INCREMENT.Gwei * BASE_REWARD_FACTOR div
    total_active_balance_sqrt

func get_base_reward_per_increment*(
    total_active_balance: Gwei): Gwei =
  get_base_reward_per_increment_sqrt(
    integer_squareroot(distinctBase(total_active_balance)))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#get_base_reward
func get_base_reward*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState | epbs.BeaconState,
    index: ValidatorIndex, base_reward_per_increment: Gwei): Gwei =
  ## Return the base reward for the validator defined by ``index`` with respect
  ## to the current ``state``.
  let increments =
    state.validators[index].effective_balance div
    EFFECTIVE_BALANCE_INCREMENT.Gwei
  increments * base_reward_per_increment

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#attestations
proc check_attestation*(
    state: ForkyBeaconState, attestation: SomeAttestation, flags: UpdateFlags,
    cache: var StateCache, on_chain: static bool = true): Result[void, cstring] =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!

  let
    data = attestation.data
    epoch = ? check_attestation_target_epoch(data, state.get_current_epoch())
    slot = ? check_attestation_slot_target(data)
    committee_index = ? check_attestation_index(
      data,
      get_committee_count_per_slot(state, epoch, cache))

  ? check_attestation_inclusion((typeof state).kind, slot, state.slot)

  let committee_len = get_beacon_committee_len(
    state, slot, committee_index, cache)

  if attestation.aggregation_bits.lenu64 != committee_len:
    return err("Inconsistent aggregation and committee length")

  if epoch == get_current_epoch(state):
    if not (data.source == state.current_justified_checkpoint):
      return err("FFG data not matching current justified epoch")
  else:
    if not (data.source == state.previous_justified_checkpoint):
      return err("FFG data not matching previous justified epoch")

  ? is_valid_indexed_attestation(state, attestation, flags, cache)

  ok()

proc check_attestation*(
    state: electra.BeaconState,
    attestation: electra.Attestation | electra.TrustedAttestation,
    flags: UpdateFlags, cache: var StateCache, on_chain: static bool): Result[void, cstring] =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!

  let
    data = attestation.data
    epoch = ? check_attestation_target_epoch(data, state.get_current_epoch())
    slot = ? check_attestation_slot_target(data)

  ? check_attestation_inclusion((typeof state).kind, slot, state.slot)

  # [Modified in Electra:EIP7549]
  if not (data.index == 0):
    return err("Electra attestation data index not 0")

  when on_chain:
    var participants_count = 0'u64
    debugComment "cache doesn't know about forks"
    for index in attestation.committee_bits.oneIndices:
      if not (index.uint64 < get_committee_count_per_slot(
          state, data.target.epoch, cache)):
        return err("attestation wrong committee index len")
      participants_count +=
        get_beacon_committee_len(state, data.slot, index.CommitteeIndex, cache)

    if not (lenu64(attestation.aggregation_bits) == participants_count):
      return err("attestation wrong aggregation bit length")
  else:
    let
      committee_index = get_committee_index_one(attestation.committee_bits).valueOr:
        return err("Network attestation without single committee index")

    if not (lenu64(attestation.aggregation_bits) ==
        get_beacon_committee_len(state, data.slot, committee_index, cache)):
      return err("attestation wrong aggregation bit length")

  if epoch == get_current_epoch(state):
    if not (data.source == state.current_justified_checkpoint):
      return err("FFG data not matching current justified epoch")
  else:
    if not (data.source == state.previous_justified_checkpoint):
      return err("FFG data not matching previous justified epoch")

  ? is_valid_indexed_attestation(state, attestation, flags, cache)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/capella/beacon-chain.md#new-process_bls_to_execution_change
proc check_bls_to_execution_change*(
    genesisFork: Fork,
    state: capella.BeaconState | deneb.BeaconState | electra.BeaconState,
    signed_address_change: SignedBLSToExecutionChange, flags: UpdateFlags):
    Result[void, cstring] =
  let address_change = signed_address_change.message

  if not (address_change.validator_index < state.validators.lenu64):
    return err("process_bls_to_execution_change: invalid validator index")

  var withdrawal_credentials =
    state.validators.item(address_change.validator_index).withdrawal_credentials

  if not (withdrawal_credentials.data[0] == BLS_WITHDRAWAL_PREFIX):
    return err("process_bls_to_execution_change: invalid withdrawal prefix")

  if not (withdrawal_credentials.data.toOpenArray(1, 31) ==
      eth2digest(address_change.from_bls_pubkey.blob).data.toOpenArray(1, 31)):
    return err("process_bls_to_execution_change: invalid withdrawal credentials")

  doAssert flags + {skipBlsValidation} == {skipBlsValidation}
  if  skipBlsValidation notin flags and
      not verify_bls_to_execution_change_signature(
        genesisFork, state.genesis_validators_root, signed_address_change,
        address_change.from_bls_pubkey, signed_address_change.signature):
    return err("process_bls_to_execution_change: invalid signature")

  ok()

func get_proposer_reward*(
    state: ForkyBeaconState,
    attestation: SomeAttestation,
    base_reward_per_increment: Gwei,
    cache: var StateCache,
    epoch_participation: var EpochParticipationFlags): Gwei =
  let participation_flag_indices = get_attestation_participation_flag_indices(
    state, attestation.data, state.slot - attestation.data.slot)
  for index in get_attesting_indices_iter(
      state, attestation.data, attestation.aggregation_bits, cache):
    let
      base_reward = get_base_reward(state, index, base_reward_per_increment)
    for flag_index, weight in PARTICIPATION_FLAG_WEIGHTS:
      if flag_index in participation_flag_indices and
         not has_flag(epoch_participation.item(index), flag_index):
        asList(epoch_participation)[index] =
          add_flag(epoch_participation.item(index), flag_index)
        # these are all valid; TODO statically verify or do it type-safely
        result += base_reward * weight.uint64

  let proposer_reward_denominator =
    (WEIGHT_DENOMINATOR.uint64 - PROPOSER_WEIGHT.uint64) *
    WEIGHT_DENOMINATOR.uint64 div PROPOSER_WEIGHT.uint64

  result div proposer_reward_denominator

func get_proposer_reward*(
    state: ForkyBeaconState,
    attestation: electra.Attestation | electra.TrustedAttestation,
    base_reward_per_increment: Gwei,
    cache: var StateCache,
    epoch_participation: var EpochParticipationFlags): Gwei =
  let participation_flag_indices = get_attestation_participation_flag_indices(
    state, attestation.data, state.slot - attestation.data.slot)
  for index in get_attesting_indices_iter(
      state, attestation.data, attestation.aggregation_bits, attestation.committee_bits, cache):
    let
      base_reward = get_base_reward(state, index, base_reward_per_increment)
    for flag_index, weight in PARTICIPATION_FLAG_WEIGHTS:
      if flag_index in participation_flag_indices and
         not has_flag(epoch_participation.item(index), flag_index):
        asList(epoch_participation)[index] =
          add_flag(epoch_participation.item(index), flag_index)
        # these are all valid; TODO statically verify or do it type-safely
        result += base_reward * weight.uint64

  let proposer_reward_denominator =
    (WEIGHT_DENOMINATOR.uint64 - PROPOSER_WEIGHT.uint64) *
    WEIGHT_DENOMINATOR.uint64 div PROPOSER_WEIGHT.uint64

  result div proposer_reward_denominator

proc process_attestation*(
    state: var ForkyBeaconState, attestation: SomeAttestation, flags: UpdateFlags,
    base_reward_per_increment: Gwei, cache: var StateCache):
    Result[Gwei, cstring] =
  # In the spec, attestation validation is mixed with state mutation, so here
  # we've split it into two functions so that the validation logic can be
  # reused when looking for suitable blocks to include in attestations.
  #
  # TODO this should be two separate functions, but
  # https://github.com/nim-lang/Nim/issues/18202 means that this being called
  # by process_operations() in state_transition_block fails that way.

  let proposer_index = get_beacon_proposer_index(state, cache).valueOr:
    return err("process_attestation: no beacon proposer index and probably no active validators")

  ? check_attestation(state, attestation, flags, cache)

  when state is phase0.BeaconState:
    template addPendingAttestation(attestations: typed) =
      # The genericSeqAssign generated by the compiler to copy the attestation
      # data sadly is a processing hotspot - the business with the addDefault
      # pointer is here simply to work around the poor codegen
      let pa = attestations.addDefault()
      if pa.isNil:
        return err("process_attestation: too many pending attestations")
      assign(pa[].aggregation_bits, attestation.aggregation_bits)
      pa[].data = attestation.data
      pa[].inclusion_delay = state.slot - attestation.data.slot
      pa[].proposer_index = proposer_index.uint64

    doAssert base_reward_per_increment == 0.Gwei
    if attestation.data.target.epoch == get_current_epoch(state):
      addPendingAttestation(state.current_epoch_attestations)
    else:
      addPendingAttestation(state.previous_epoch_attestations)

    const proposer_reward = 0.Gwei
  else:
    template updateParticipationFlags(epoch_participation: untyped): Gwei =
      let proposer_reward = get_proposer_reward(
        state, attestation, base_reward_per_increment, cache, epoch_participation)
      increase_balance(state, proposer_index, proposer_reward)
      proposer_reward

    doAssert base_reward_per_increment > 0.Gwei
    let proposer_reward =
      if attestation.data.target.epoch == get_current_epoch(state):
        updateParticipationFlags(state.current_epoch_participation)
      else:
        updateParticipationFlags(state.previous_epoch_participation)

  ok(proposer_reward)

proc process_attestation*(
    state: var ForkyBeaconState,
    attestation: electra.Attestation | electra.TrustedAttestation,
    flags: UpdateFlags, base_reward_per_increment: Gwei,
    cache: var StateCache): Result[Gwei, cstring] =
  ? check_attestation(state, attestation, flags, cache, true)

  let proposer_index = get_beacon_proposer_index(state, cache).valueOr:
    return err("process_attestation: no beacon proposer index and probably no active validators")

  template updateParticipationFlags(epoch_participation: untyped): Gwei =
    let proposer_reward = get_proposer_reward(
      state, attestation, base_reward_per_increment, cache, epoch_participation)
    increase_balance(state, proposer_index, proposer_reward)
    proposer_reward

  doAssert base_reward_per_increment > 0.Gwei
  let proposer_reward =
    if attestation.data.target.epoch == get_current_epoch(state):
      updateParticipationFlags(state.current_epoch_participation)
    else:
      updateParticipationFlags(state.previous_epoch_participation)

  ok(proposer_reward)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/altair/beacon-chain.md#get_next_sync_committee_indices
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#modified-get_next_sync_committee_indices
func get_next_sync_committee_keys(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState):
    array[SYNC_COMMITTEE_SIZE, ValidatorPubKey] =
  ## Return the sequence of sync committee indices, with possible duplicates,
  ## for the next sync committee.
  # The sync committe depends on seed and effective balance - it can
  # thus only be computed for the current epoch of the state, after balance
  # updates have been performed

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
    const meb =
      when typeof(state).kind >= ConsensusFork.Electra:
        MAX_EFFECTIVE_BALANCE_ELECTRA.Gwei  # [Modified in Electra:EIP7251]
      else:
        MAX_EFFECTIVE_BALANCE.Gwei

    if effective_balance * MAX_RANDOM_BYTE >= meb * random_byte:
      res[index] = state.validators[candidate_index].pubkey
      inc index
    i += 1'u64
  res

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/capella/beacon-chain.md#has_eth1_withdrawal_credential
func has_eth1_withdrawal_credential*(validator: Validator): bool =
  ## Check if ``validator`` has an 0x01 prefixed "eth1" withdrawal credential.
  validator.withdrawal_credentials.data[0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#new-has_execution_withdrawal_credential
func has_execution_withdrawal_credential*(validator: Validator): bool =
  ## Check if ``validator`` has a 0x01 or 0x02 prefixed withdrawal credential.
  has_compounding_withdrawal_credential(validator) or
    has_eth1_withdrawal_credential(validator)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/capella/beacon-chain.md#is_fully_withdrawable_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#updated-is_fully_withdrawable_validator
func is_fully_withdrawable_validator(
    fork: static ConsensusFork, validator: Validator, balance: Gwei,
    epoch: Epoch): bool =
  ## Check if ``validator`` is fully withdrawable.
  when fork >= ConsensusFork.Electra:
    # [Modified in Electra:EIP7251]
    has_execution_withdrawal_credential(validator) and
      validator.withdrawable_epoch <= epoch and balance > 0.Gwei
  else:
    has_eth1_withdrawal_credential(validator) and
      validator.withdrawable_epoch <= epoch and balance > 0.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#is_partially_withdrawable_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#modified-is_partially_withdrawable_validator
func is_partially_withdrawable_validator(
    fork: static ConsensusFork, validator: Validator, balance: Gwei): bool =
  ## Check if ``validator`` is partially withdrawable.
  when fork >= ConsensusFork.Electra:
    # [Modified in Electra:EIP7251]
    let
      max_effective_balance = get_max_effective_balance(validator)
      has_max_effective_balance =
        validator.effective_balance == max_effective_balance
      has_excess_balance =
        balance > max_effective_balance  # [Modified in Electra:EIP7251]
    has_execution_withdrawal_credential(validator) and
      has_max_effective_balance and has_excess_balance
  else:
    let
      has_max_effective_balance =
        validator.effective_balance == static(MAX_EFFECTIVE_BALANCE.Gwei)
      has_excess_balance = balance > static(MAX_EFFECTIVE_BALANCE.Gwei)
    has_eth1_withdrawal_credential(validator) and
      has_max_effective_balance and has_excess_balance

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#get_validator_max_effective_balance
func get_validator_max_effective_balance*(validator: Validator): Gwei =
  ## Get max effective balance for ``validator``.
  if has_compounding_withdrawal_credential(validator):
    MAX_EFFECTIVE_BALANCE_ELECTRA.Gwei
  else:
    MIN_ACTIVATION_BALANCE.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#new-get_active_balance
func get_active_balance*(
    state: electra.BeaconState, validator_index: ValidatorIndex): Gwei =
  let max_effective_balance =
    get_validator_max_effective_balance(state.validators[validator_index])
  min(state.balances[validator_index], max_effective_balance)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.1/specs/electra/beacon-chain.md#new-queue_excess_active_balance
func queue_excess_active_balance(
    state: var electra.BeaconState, index: uint64) =
  let balance = state.balances.item(index)
  if balance > static(MIN_ACTIVATION_BALANCE.Gwei):
    let excess_balance = balance - static(MIN_ACTIVATION_BALANCE.Gwei)
    state.balances.mitem(index) = static(MIN_ACTIVATION_BALANCE.Gwei)
    let validator = state.validators.item(index)
    # Use bls.G2_POINT_AT_INFINITY as a signature field placeholder and
    # GENESIS_SLOT to distinguish from a pending deposit request
    discard state.pending_deposits.add(PendingDeposit(
      pubkey: validator.pubkey,
      withdrawal_credentials: validator.withdrawal_credentials,
      amount: excess_balance,
      signature: ValidatorSig.infinity,
      slot: GENESIS_SLOT))

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#new-switch_to_compounding_validator
func switch_to_compounding_validator*(
    state: var electra.BeaconState, index: ValidatorIndex) =
  let validator = addr state.validators.mitem(index)
  validator.withdrawal_credentials.data[0] = COMPOUNDING_WITHDRAWAL_PREFIX
  queue_excess_active_balance(state, index.uint64)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#new-get_pending_balance_to_withdraw
func get_pending_balance_to_withdraw*(
    state: electra.BeaconState, validator_index: ValidatorIndex): Gwei =
  var pending_balance: Gwei
  for withdrawal in state.pending_partial_withdrawals:
    if withdrawal.index == validator_index:
      pending_balance += withdrawal.amount

  pending_balance

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#effective-balances-updates
template effective_balance_might_update*(
    balance: Gwei, effective_balance: Gwei): bool =
  const
    HYSTERESIS_INCREMENT =
      EFFECTIVE_BALANCE_INCREMENT.Gwei div HYSTERESIS_QUOTIENT
    DOWNWARD_THRESHOLD = HYSTERESIS_INCREMENT * HYSTERESIS_DOWNWARD_MULTIPLIER
    UPWARD_THRESHOLD = HYSTERESIS_INCREMENT * HYSTERESIS_UPWARD_MULTIPLIER
  balance + DOWNWARD_THRESHOLD < effective_balance or
    effective_balance + UPWARD_THRESHOLD < balance

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/phase0/beacon-chain.md#effective-balances-updates
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.1/specs/electra/beacon-chain.md#updated-process_effective_balance_updates
template get_effective_balance_update*(
    consensusFork: static ConsensusFork, balance: Gwei,
    effective_balance: Gwei, vidx: uint64): Gwei =
  when consensusFork <= ConsensusFork.Deneb:
    min(
      balance - balance mod EFFECTIVE_BALANCE_INCREMENT.Gwei,
      MAX_EFFECTIVE_BALANCE.Gwei)
  else:
    let effective_balance_limit =
      if has_compounding_withdrawal_credential(state.validators.item(vidx)):
        MAX_EFFECTIVE_BALANCE_ELECTRA.Gwei
      else:
        MIN_ACTIVATION_BALANCE.Gwei
    min(
      balance - balance mod EFFECTIVE_BALANCE_INCREMENT.Gwei,
      effective_balance_limit)

template get_updated_effective_balance*(
    consensusFork: static ConsensusFork, balance: Gwei,
    effective_balance: Gwei, vidx: uint64): Gwei =
  if effective_balance_might_update(balance, effective_balance):
    get_effective_balance_update(consensusFork, balance, effective_balance, vidx)
  else:
    balance

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#new-get_expected_withdrawals
template get_expected_withdrawals_aux*(
    state: capella.BeaconState | deneb.BeaconState, epoch: Epoch,
    fetch_balance: untyped): seq[Withdrawal] =
  let
    num_validators = lenu64(state.validators)
    bound = min(len(state.validators), MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
  var
    withdrawal_index = state.next_withdrawal_index
    validator_index {.inject.} = state.next_withdrawal_validator_index
    withdrawals: seq[Withdrawal] = @[]
  for _ in 0 ..< bound:
    let
      validator = state.validators[validator_index]
      balance = fetch_balance
    if is_fully_withdrawable_validator(
        typeof(state).kind, validator, balance, epoch):
      var w = Withdrawal(
        index: withdrawal_index,
        validator_index: validator_index,
        amount: balance)
      w.address.data[0..19] = validator.withdrawal_credentials.data[12..^1]
      withdrawals.add w
      withdrawal_index = WithdrawalIndex(withdrawal_index + 1)
    elif is_partially_withdrawable_validator(
        typeof(state).kind, validator, balance):
      var w = Withdrawal(
        index: withdrawal_index,
        validator_index: validator_index,
        amount: balance - MAX_EFFECTIVE_BALANCE.Gwei)
      w.address.data[0..19] = validator.withdrawal_credentials.data[12..^1]
      withdrawals.add w
      withdrawal_index = WithdrawalIndex(withdrawal_index + 1)
    if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
      break
    validator_index = (validator_index + 1) mod num_validators
  withdrawals

func get_expected_withdrawals*(
    state: capella.BeaconState | deneb.BeaconState): seq[Withdrawal] =
  get_expected_withdrawals_aux(state, get_current_epoch(state)) do:
    state.balances[validator_index]

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#modified-get_expected_withdrawals
# This partials count is used in exactly one place, while in general being able
# to cleanly treat the results of get_expected_withdrawals as a seq[Withdrawal]
# are valuable enough to make that the default version of this spec function.
template get_expected_withdrawals_with_partial_count_aux*(
    state: electra.BeaconState | epbs.BeaconState, epoch: Epoch, fetch_balance: untyped):
    (seq[Withdrawal], uint64) =
  doAssert epoch - get_current_epoch(state) in [0'u64, 1'u64]

  var
    withdrawal_index = state.next_withdrawal_index
    withdrawals: seq[Withdrawal] = @[]
    partial_withdrawals_count: uint64 = 0

  # [New in Electra:EIP7251] Consume pending partial withdrawals
  for withdrawal in state.pending_partial_withdrawals:
    if  withdrawal.withdrawable_epoch > epoch or
        len(withdrawals) == MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP:
      break

    let
      validator = state.validators.item(withdrawal.index)

      # Keep a uniform variable name available for injected code
      validator_index {.inject.} = withdrawal.index

      # Here, can't use the pre-stored effective balance because this template
      # might be called on the next slot and therefore next epoch, after which
      # the effective balance might have updated.
      effective_balance_at_slot =
        if epoch == get_current_epoch(state):
          validator.effective_balance
        else:
          get_updated_effective_balance(
            typeof(state).kind, fetch_balance, validator.effective_balance,
            validator_index)

      has_sufficient_effective_balance =
        effective_balance_at_slot >= static(MIN_ACTIVATION_BALANCE.Gwei)
      has_excess_balance = fetch_balance > static(MIN_ACTIVATION_BALANCE.Gwei)
    if  validator.exit_epoch == FAR_FUTURE_EPOCH and
        has_sufficient_effective_balance and has_excess_balance:
      let
        withdrawable_balance = min(
          fetch_balance - static(MIN_ACTIVATION_BALANCE.Gwei),
          withdrawal.amount)
      var w = Withdrawal(
        index: withdrawal_index,
        validator_index: withdrawal.index,
        amount: withdrawable_balance)
      w.address.data[0..19] = validator.withdrawal_credentials.data[12..^1]
      withdrawals.add w
      withdrawal_index += 1

      inc partial_withdrawals_count

  let
    bound = min(len(state.validators), MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
    num_validators = lenu64(state.validators)
  var validator_index {.inject.} = state.next_withdrawal_validator_index

  # Sweep for remaining.
  for _ in 0 ..< bound:
    let
      validator = state.validators.item(validator_index)
      balance = fetch_balance
    if is_fully_withdrawable_validator(
        typeof(state).kind, validator, balance, epoch):
      var w = Withdrawal(
        index: withdrawal_index,
        validator_index: validator_index,
        amount: balance)
      w.address.data[0..19] = validator.withdrawal_credentials.data[12..^1]
      withdrawals.add w
      withdrawal_index = WithdrawalIndex(withdrawal_index + 1)
    elif is_partially_withdrawable_validator(
        typeof(state).kind, validator, balance):
      var w = Withdrawal(
        index: withdrawal_index,
        validator_index: validator_index,
        # [Modified in Electra:EIP7251]
        amount: balance - get_max_effective_balance(validator))
      w.address.data[0..19] = validator.withdrawal_credentials.data[12..^1]
      withdrawals.add w
      withdrawal_index = WithdrawalIndex(withdrawal_index + 1)
    if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
      break
    validator_index = (validator_index + 1) mod num_validators

  (withdrawals, partial_withdrawals_count)

template get_expected_withdrawals_with_partial_count*(
    state: electra.BeaconState | epbs.BeaconState): (seq[Withdrawal], uint64) =
  get_expected_withdrawals_with_partial_count_aux(
      state, get_current_epoch(state)) do:
    state.balances.item(validator_index)

func get_expected_withdrawals*(state: electra.BeaconState | epbs.BeaconState): seq[Withdrawal] =
  get_expected_withdrawals_with_partial_count(state)[0]

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#get_next_sync_committee
func get_next_sync_committee*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState):
    SyncCommittee =
  ## Return the next sync committee, with possible pubkey duplicates.
  var res: SyncCommittee
  res.pubkeys.data = get_next_sync_committee_keys(state)

  # see signatures_batch, TODO shouldn't be here
  # Deposit processing ensures all keys are valid
  var attestersAgg: AggregatePublicKey
  attestersAgg.init(res.pubkeys.data[0].load().get)
  for i in 1 ..< res.pubkeys.data.len:
    attestersAgg.aggregate(res.pubkeys.data[i].load().get)

  res.aggregate_pubkey = finish(attestersAgg).toPubKey()
  res

func compute_deposit_root(deposits: openArray[DepositData]): Eth2Digest =
  var merkleizer = createMerkleizer2(DEPOSIT_CONTRACT_TREE_DEPTH + 1)
  for i, deposit in deposits:
    let htr = hash_tree_root(deposit)
    merkleizer.addChunk(htr.data)

  mixInLength(merkleizer.getFinalHash(), deposits.len)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.3/specs/phase0/beacon-chain.md#genesis
proc initialize_beacon_state_from_eth1(
    cfg: RuntimeConfig,
    eth1_block_hash: Eth2Digest,
    eth1_timestamp: uint64,
    deposits: openArray[DepositData],
    flags: UpdateFlags = {}): phase0.BeaconState =
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
  # that point :)
  doAssert deposits.lenu64 >= SLOTS_PER_EPOCH

  # TODO https://github.com/nim-lang/Nim/issues/19094
  template state(): untyped = result
  state = phase0.BeaconState(
    fork: genesisFork(cfg),
    genesis_time: genesis_time_from_eth1_timestamp(cfg, eth1_timestamp),
    eth1_data:Eth1Data(
      deposit_count: deposits.lenu64,
      deposit_root: compute_deposit_root(deposits),
      block_hash: eth1_block_hash),
    eth1_deposit_index: deposits.lenu64,
    latest_block_header:
      BeaconBlockHeader(
        body_root: hash_tree_root(default(phase0.BeaconBlockBody))))

  # Seed RANDAO with Eth1 entropy
  state.randao_mixes.fill(eth1_block_hash)

  var pubkeyToIndex = initTable[ValidatorPubKey, ValidatorIndex]()
  for idx, deposit in deposits:
    let
      pubkey = deposit.pubkey
      amount = deposit.amount

    pubkeyToIndex.withValue(pubkey, foundIdx) do:
      # Increase balance by deposit amount
      increase_balance(state, foundIdx[], amount)
    do:
      if skipBlsValidation in flags or
         verify_deposit_signature(cfg, deposit):
        pubkeyToIndex[pubkey] = ValidatorIndex(state.validators.len)
        if not state.validators.add(get_validator_from_deposit(
            state, deposit.pubkey, deposit.withdrawal_credentials,
            deposit.amount)):
          raiseAssert "too many validators"
        if not state.balances.add(amount):
          raiseAssert "same as validators"

      else:
        # Invalid deposits are perfectly possible
        trace "Skipping deposit with invalid signature",
          deposit = shortLog(deposit)

  # Process activations
  for vidx in state.validators.vindices:
    let
      balance = state.balances.item(vidx)
      validator = addr state.validators.mitem(vidx)

    validator.effective_balance = min(
      balance - balance mod EFFECTIVE_BALANCE_INCREMENT.Gwei,
      MAX_EFFECTIVE_BALANCE.Gwei)

    if validator.effective_balance == MAX_EFFECTIVE_BALANCE.Gwei:
      validator.activation_eligibility_epoch = GENESIS_EPOCH
      validator.activation_epoch = GENESIS_EPOCH

  # Set genesis validators root for domain separation and chain versioning
  state.genesis_validators_root = hash_tree_root(state.validators)

  # TODO https://github.com/nim-lang/Nim/issues/19094
  # state

proc initialize_hashed_beacon_state_from_eth1*(
    cfg: RuntimeConfig,
    eth1_block_hash: Eth2Digest,
    eth1_timestamp: uint64,
    deposits: openArray[DepositData],
    flags: UpdateFlags = {}): phase0.HashedBeaconState =
  # TODO https://github.com/nim-lang/Nim/issues/19094
  result = phase0.HashedBeaconState(
    data: initialize_beacon_state_from_eth1(
      cfg, eth1_block_hash, eth1_timestamp, deposits, flags))
  result.root = hash_tree_root(result.data)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/bellatrix/beacon-chain.md#testing
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/capella/beacon-chain.md#testing
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/beacon-chain.md#testing
proc initialize_beacon_state_from_eth1*(
    cfg: RuntimeConfig,
    eth1_block_hash: Eth2Digest,
    eth1_timestamp: uint64,
    deposits: openArray[DepositData],
    execution_payload_header: ForkyExecutionPayloadHeader,
    flags: UpdateFlags = {}): auto =
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
  doAssert deposits.lenu64 >= SLOTS_PER_EPOCH

  const consensusFork = typeof(execution_payload_header).kind
  let
    forkVersion = cfg.forkVersion(consensusFork)
    fork = Fork(
      previous_version: forkVersion,
      current_version: forkVersion,
      epoch: GENESIS_EPOCH)

  # TODO https://github.com/nim-lang/Nim/issues/19094
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

  # Seed RANDAO with Eth1 entropy
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
      if skipBlsValidation in flags or
         verify_deposit_signature(cfg, deposit):
        pubkeyToIndex[pubkey] = ValidatorIndex(state.validators.len)
        if not state.validators.add get_validator_from_deposit(
            state, deposit.pubkey, deposit.withdrawal_credentials,
            deposit.amount):
          raiseAssert "too many validators"
        if not state.balances.add(amount):
          raiseAssert "same as validators"

      else:
        # Invalid deposits are perfectly possible
        trace "Skipping deposit with invalid signature",
          deposit = shortLog(deposit)

  # Initialize epoch participations - TODO (This must be added to the spec)
  var
    empty_participation: EpochParticipationFlags
    inactivity_scores = HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]()

  doAssert empty_participation.asList.setLen(state.validators.len)
  doAssert inactivity_scores.data.setLen(state.validators.len)
  inactivity_scores.resetCache()

  state.previous_epoch_participation = empty_participation
  state.current_epoch_participation = empty_participation
  state.inactivity_scores = inactivity_scores

  # Process activations
  for vidx in state.validators.vindices:
    let
      balance = state.balances.item(vidx)
      validator = addr state.validators.mitem(vidx)

    validator.effective_balance = min(
      balance - balance mod EFFECTIVE_BALANCE_INCREMENT.Gwei,
      MAX_EFFECTIVE_BALANCE.Gwei)

    if validator.effective_balance == MAX_EFFECTIVE_BALANCE.Gwei:
      validator.activation_eligibility_epoch = GENESIS_EPOCH
      validator.activation_epoch = GENESIS_EPOCH

  # Set genesis validators root for domain separation and chain versioning
  state.genesis_validators_root = hash_tree_root(state.validators)

  # Fill in sync committees
  # Note: A duplicate committee is assigned for the current and next committee at genesis
  state.current_sync_committee = get_next_sync_committee(state)
  state.next_sync_committee = get_next_sync_committee(state)

  # [New in Bellatrix] Initialize the execution payload header
  # If empty, will initialize a chain that has not yet gone through the Merge transition
  state.latest_execution_payload_header = execution_payload_header

  # TODO https://github.com/nim-lang/Nim/issues/19094
  # state

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/altair/fork.md#upgrading-the-state
func translate_participation(
    state: var altair.BeaconState,
    pending_attestations: openArray[phase0.PendingAttestation]) =

  var cache = StateCache()
  for attestation in pending_attestations:
    let
      data = attestation.data
      inclusion_delay = attestation.inclusion_delay

      # Translate attestation inclusion info to flag indices
      participation_flag_indices =
        get_attestation_participation_flag_indices(state, data, inclusion_delay)

    # Apply flags to all attesting validators
    for index in get_attesting_indices_iter(
        state, data, attestation.aggregation_bits, cache):
      for flag_index in participation_flag_indices:
        state.previous_epoch_participation[index] =
          add_flag(state.previous_epoch_participation.item(index), flag_index)

func upgrade_to_altair*(cfg: RuntimeConfig, pre: phase0.BeaconState):
    ref altair.BeaconState =
  var
    empty_participation: EpochParticipationFlags
    inactivity_scores = HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]()

  doAssert empty_participation.asList.setLen(pre.validators.len)

  doAssert inactivity_scores.data.setLen(pre.validators.len)
  inactivity_scores.resetCache()

  let post = (ref altair.BeaconState)(
    genesis_time: pre.genesis_time,
    genesis_validators_root: pre.genesis_validators_root,
    slot: pre.slot,
    fork: altairFork(cfg),

    # History
    latest_block_header: pre.latest_block_header,
    block_roots: pre.block_roots,
    state_roots: pre.state_roots,
    historical_roots: pre.historical_roots,

    # Eth1
    eth1_data: pre.eth1_data,
    eth1_data_votes: pre.eth1_data_votes,
    eth1_deposit_index: pre.eth1_deposit_index,

    # Registry
    validators: pre.validators,
    balances: pre.balances,

    # Randomness
    randao_mixes: pre.randao_mixes,

    # Slashings
    slashings: pre.slashings,

    # Attestations
    previous_epoch_participation: empty_participation,
    current_epoch_participation: empty_participation,

    # Finality
    justification_bits: pre.justification_bits,
    previous_justified_checkpoint: pre.previous_justified_checkpoint,
    current_justified_checkpoint: pre.current_justified_checkpoint,
    finalized_checkpoint: pre.finalized_checkpoint,

    # Inactivity
    inactivity_scores: inactivity_scores
  )

  # Fill in previous epoch participation from the pre state's pending
  # attestations
  translate_participation(post[], pre.previous_epoch_attestations.asSeq)

  # Fill in sync committees
  # Note: A duplicate committee is assigned for the current and next committee
  # at the fork boundary
  post[].current_sync_committee = get_next_sync_committee(post[])
  post[].next_sync_committee = get_next_sync_committee(post[])

  post

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/bellatrix/fork.md#upgrading-the-state
func upgrade_to_bellatrix*(cfg: RuntimeConfig, pre: altair.BeaconState):
    ref bellatrix.BeaconState =
  let epoch = get_current_epoch(pre)
  (ref bellatrix.BeaconState)(
    # Versioning
    genesis_time: pre.genesis_time,
    genesis_validators_root: pre.genesis_validators_root,
    slot: pre.slot,
    fork: Fork(
        previous_version: pre.fork.current_version,
        current_version: cfg.BELLATRIX_FORK_VERSION,
        epoch: epoch,
    ),

    # History
    latest_block_header: pre.latest_block_header,
    block_roots: pre.block_roots,
    state_roots: pre.state_roots,
    historical_roots: pre.historical_roots,

    # Eth1
    eth1_data: pre.eth1_data,
    eth1_data_votes: pre.eth1_data_votes,
    eth1_deposit_index: pre.eth1_deposit_index,

    # Registry
    validators: pre.validators,
    balances: pre.balances,

    # Randomness
    randao_mixes: pre.randao_mixes,

    # Slashings
    slashings: pre.slashings,

    # Participation
    previous_epoch_participation: pre.previous_epoch_participation,
    current_epoch_participation: pre.current_epoch_participation,

    # Finality
    justification_bits: pre.justification_bits,
    previous_justified_checkpoint: pre.previous_justified_checkpoint,
    current_justified_checkpoint: pre.current_justified_checkpoint,
    finalized_checkpoint: pre.finalized_checkpoint,

    # Inactivity
    inactivity_scores: pre.inactivity_scores,

    # Sync
    current_sync_committee: pre.current_sync_committee,
    next_sync_committee: pre.next_sync_committee,

    # Execution-layer
    latest_execution_payload_header: default(bellatrix.ExecutionPayloadHeader)
  )

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/capella/fork.md#upgrading-the-state
func upgrade_to_capella*(cfg: RuntimeConfig, pre: bellatrix.BeaconState):
    ref capella.BeaconState =
  let
    epoch = get_current_epoch(pre)
    latest_execution_payload_header = capella.ExecutionPayloadHeader(
      parent_hash: pre.latest_execution_payload_header.parent_hash,
      fee_recipient: pre.latest_execution_payload_header.fee_recipient,
      state_root: pre.latest_execution_payload_header.state_root,
      receipts_root: pre.latest_execution_payload_header.receipts_root,
      logs_bloom: pre.latest_execution_payload_header.logs_bloom,
      prev_randao: pre.latest_execution_payload_header.prev_randao,
      block_number: pre.latest_execution_payload_header.block_number,
      gas_limit: pre.latest_execution_payload_header.gas_limit,
      gas_used: pre.latest_execution_payload_header.gas_used,
      timestamp: pre.latest_execution_payload_header.timestamp,
      extra_data: pre.latest_execution_payload_header.extra_data,
      base_fee_per_gas: pre.latest_execution_payload_header.base_fee_per_gas,
      block_hash: pre.latest_execution_payload_header.block_hash,
      transactions_root: pre.latest_execution_payload_header.transactions_root,
      withdrawals_root: Eth2Digest()  # [New in Capella]
    )

  (ref capella.BeaconState)(
    # Versioning
    genesis_time: pre.genesis_time,
    genesis_validators_root: pre.genesis_validators_root,
    slot: pre.slot,
    fork: Fork(
        previous_version: pre.fork.current_version,
        current_version: cfg.CAPELLA_FORK_VERSION,
        epoch: epoch,
    ),

    # History
    latest_block_header: pre.latest_block_header,
    block_roots: pre.block_roots,
    state_roots: pre.state_roots,
    historical_roots: pre.historical_roots,

    # Eth1
    eth1_data: pre.eth1_data,
    eth1_data_votes: pre.eth1_data_votes,
    eth1_deposit_index: pre.eth1_deposit_index,

    # Registry
    validators: pre.validators,
    balances: pre.balances,

    # Randomness
    randao_mixes: pre.randao_mixes,

    # Slashings
    slashings: pre.slashings,

    # Participation
    previous_epoch_participation: pre.previous_epoch_participation,
    current_epoch_participation: pre.current_epoch_participation,

    # Finality
    justification_bits: pre.justification_bits,
    previous_justified_checkpoint: pre.previous_justified_checkpoint,
    current_justified_checkpoint: pre.current_justified_checkpoint,
    finalized_checkpoint: pre.finalized_checkpoint,

    # Inactivity
    inactivity_scores: pre.inactivity_scores,

    # Sync
    current_sync_committee: pre.current_sync_committee,
    next_sync_committee: pre.next_sync_committee,

    # Execution-layer
    latest_execution_payload_header: latest_execution_payload_header,

    # Withdrawals
    next_withdrawal_index: 0,
    next_withdrawal_validator_index: 0

    # Deep history valid from Capella onwards [New in Capella]
    # historical_summaries initialized to correct default automatically
  )

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/deneb/fork.md#upgrading-the-state
func upgrade_to_deneb*(cfg: RuntimeConfig, pre: capella.BeaconState):
    ref deneb.BeaconState =
  let
    epoch = get_current_epoch(pre)
    latest_execution_payload_header = deneb.ExecutionPayloadHeader(
      parent_hash: pre.latest_execution_payload_header.parent_hash,
      fee_recipient: pre.latest_execution_payload_header.fee_recipient,
      state_root: pre.latest_execution_payload_header.state_root,
      receipts_root: pre.latest_execution_payload_header.receipts_root,
      logs_bloom: pre.latest_execution_payload_header.logs_bloom,
      prev_randao: pre.latest_execution_payload_header.prev_randao,
      block_number: pre.latest_execution_payload_header.block_number,
      gas_limit: pre.latest_execution_payload_header.gas_limit,
      gas_used: pre.latest_execution_payload_header.gas_used,
      timestamp: pre.latest_execution_payload_header.timestamp,
      extra_data: pre.latest_execution_payload_header.extra_data,
      base_fee_per_gas: pre.latest_execution_payload_header.base_fee_per_gas,
      block_hash: pre.latest_execution_payload_header.block_hash,
      transactions_root: pre.latest_execution_payload_header.transactions_root,
      withdrawals_root: pre.latest_execution_payload_header.withdrawals_root,
      blob_gas_used: 0,  # [New in Deneb]
      excess_blob_gas: 0 # [New in Deneb]
    )

  (ref deneb.BeaconState)(
    # Versioning
    genesis_time: pre.genesis_time,
    genesis_validators_root: pre.genesis_validators_root,
    slot: pre.slot,
    fork: Fork(
      previous_version: pre.fork.current_version,
      current_version: cfg.DENEB_FORK_VERSION, # [Modified in Deneb]
      epoch: epoch
    ),

    # History
    latest_block_header: pre.latest_block_header,
    block_roots: pre.block_roots,
    state_roots: pre.state_roots,
    historical_roots: pre.historical_roots,

    # Eth1
    eth1_data: pre.eth1_data,
    eth1_data_votes: pre.eth1_data_votes,
    eth1_deposit_index: pre.eth1_deposit_index,

    # Registry
    validators: pre.validators,
    balances: pre.balances,

    # Randomness
    randao_mixes: pre.randao_mixes,

    # Slashings
    slashings: pre.slashings,

    # Participation
    previous_epoch_participation: pre.previous_epoch_participation,
    current_epoch_participation: pre.current_epoch_participation,

    # Finality
    justification_bits: pre.justification_bits,
    previous_justified_checkpoint: pre.previous_justified_checkpoint,
    current_justified_checkpoint: pre.current_justified_checkpoint,
    finalized_checkpoint: pre.finalized_checkpoint,

    # Inactivity
    inactivity_scores: pre.inactivity_scores,

    # Sync
    current_sync_committee: pre.current_sync_committee,
    next_sync_committee: pre.next_sync_committee,

    # Execution-layer
    latest_execution_payload_header: latest_execution_payload_header,  # [Modified in Deneb]

    # Withdrawals
    next_withdrawal_index: pre.next_withdrawal_index,
    next_withdrawal_validator_index: pre.next_withdrawal_validator_index,

    # Deep history valid from Capella onwards
    historical_summaries: pre.historical_summaries
  )

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/fork.md#upgrading-the-state
func upgrade_to_electra*(
    cfg: RuntimeConfig, pre: deneb.BeaconState, cache: var StateCache):
    ref electra.BeaconState =
  let
    epoch = get_current_epoch(pre)
    latest_execution_payload_header = electra.ExecutionPayloadHeader(
      parent_hash: pre.latest_execution_payload_header.parent_hash,
      fee_recipient: pre.latest_execution_payload_header.fee_recipient,
      state_root: pre.latest_execution_payload_header.state_root,
      receipts_root: pre.latest_execution_payload_header.receipts_root,
      logs_bloom: pre.latest_execution_payload_header.logs_bloom,
      prev_randao: pre.latest_execution_payload_header.prev_randao,
      block_number: pre.latest_execution_payload_header.block_number,
      gas_limit: pre.latest_execution_payload_header.gas_limit,
      gas_used: pre.latest_execution_payload_header.gas_used,
      timestamp: pre.latest_execution_payload_header.timestamp,
      extra_data: pre.latest_execution_payload_header.extra_data,
      base_fee_per_gas: pre.latest_execution_payload_header.base_fee_per_gas,
      block_hash: pre.latest_execution_payload_header.block_hash,
      transactions_root: pre.latest_execution_payload_header.transactions_root,
      withdrawals_root: pre.latest_execution_payload_header.withdrawals_root,
      blob_gas_used: 0,
      excess_blob_gas: 0
    )

  var max_exit_epoch = FAR_FUTURE_EPOCH
  for v in pre.validators:
    if v.exit_epoch != FAR_FUTURE_EPOCH:
      max_exit_epoch =
        if max_exit_epoch == FAR_FUTURE_EPOCH:
          v.exit_epoch
        else:
          max(max_exit_epoch, v.exit_epoch)
  if max_exit_epoch == FAR_FUTURE_EPOCH:
    max_exit_epoch = get_current_epoch(pre)
  let earliest_exit_epoch = max_exit_epoch + 1

  let post = (ref electra.BeaconState)(
    # Versioning
    genesis_time: pre.genesis_time,
    genesis_validators_root: pre.genesis_validators_root,
    slot: pre.slot,
    fork: Fork(
      previous_version: pre.fork.current_version,
      current_version: cfg.ELECTRA_FORK_VERSION, # [Modified in Electra:EIP6110]
      epoch: epoch
    ),

    # History
    latest_block_header: pre.latest_block_header,
    block_roots: pre.block_roots,
    state_roots: pre.state_roots,
    historical_roots: pre.historical_roots,

    # Eth1
    eth1_data: pre.eth1_data,
    eth1_data_votes: pre.eth1_data_votes,
    eth1_deposit_index: pre.eth1_deposit_index,

    # Registry
    validators: pre.validators,
    balances: pre.balances,

    # Randomness
    randao_mixes: pre.randao_mixes,

    # Slashings
    slashings: pre.slashings,

    # Participation
    previous_epoch_participation: pre.previous_epoch_participation,
    current_epoch_participation: pre.current_epoch_participation,

    # Finality
    justification_bits: pre.justification_bits,
    previous_justified_checkpoint: pre.previous_justified_checkpoint,
    current_justified_checkpoint: pre.current_justified_checkpoint,
    finalized_checkpoint: pre.finalized_checkpoint,

    # Inactivity
    inactivity_scores: pre.inactivity_scores,

    # Sync
    current_sync_committee: pre.current_sync_committee,
    next_sync_committee: pre.next_sync_committee,

    # Execution-layer
    latest_execution_payload_header: latest_execution_payload_header,

    # Withdrawals
    next_withdrawal_index: pre.next_withdrawal_index,
    next_withdrawal_validator_index: pre.next_withdrawal_validator_index,

    # Deep history valid from Capella onwards
    historical_summaries: pre.historical_summaries,

    # [New in Electra:EIP6110]
    deposit_requests_start_index: UNSET_DEPOSIT_REQUESTS_START_INDEX,

    # [New in Electra:EIP7251]
    deposit_balance_to_consume: 0.Gwei,
    exit_balance_to_consume: 0.Gwei,
    earliest_exit_epoch: earliest_exit_epoch,
    consolidation_balance_to_consume: 0.Gwei,
    earliest_consolidation_epoch:
      compute_activation_exit_epoch(get_current_epoch(pre))

    # pending_balance_deposits, pending_partial_withdrawals, and
    # pending_consolidations are default empty lists
  )

  post.exit_balance_to_consume =
    get_activation_exit_churn_limit(cfg, post[], cache)
  post.consolidation_balance_to_consume =
    get_consolidation_churn_limit(cfg, post[], cache)

  # [New in Electra:EIP7251]
  # add validators that are not yet active to pending balance deposits
  var pre_activation: seq[(Epoch, uint64)]
  for index, validator in post.validators:
    if validator.activation_epoch == FAR_FUTURE_EPOCH:
      pre_activation.add((validator.activation_eligibility_epoch, index.uint64))
  sort(pre_activation)

  for (_, index) in pre_activation:
    let balance = post.balances.item(index)
    post.balances[index] = 0.Gwei
    let validator = addr post.validators.mitem(index)
    validator[].effective_balance = 0.Gwei
    validator[].activation_eligibility_epoch = FAR_FUTURE_EPOCH
    # Use bls.G2_POINT_AT_INFINITY as a signature field placeholder and
    # GENESIS_SLOT to distinguish from a pending deposit request
    discard post.pending_deposits.add PendingDeposit(
      pubkey: validator[].pubkey,
      withdrawal_credentials: validator[].withdrawal_credentials,
      amount: balance,
      signature: ValidatorSig.infinity,
      slot: GENESIS_SLOT)

  # Ensure early adopters of compounding credentials go through the activation
  # churn
  for index, validator in post.validators:
    if has_compounding_withdrawal_credential(validator):
      queue_excess_active_balance(post[], index.uint64)

  post

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/fork.md#upgrading-the-state
func upgrade_to_epbs*(cfg: RuntimeConfig, pre: deneb.BeaconState):
    ref epbs.BeaconState =
  let epoch = get_current_epoch(pre)

  var max_exit_epoch = FAR_FUTURE_EPOCH
  for v in pre.validators:
    if v.exit_epoch != FAR_FUTURE_EPOCH:
      max_exit_epoch =
        if max_exit_epoch == FAR_FUTURE_EPOCH:
          v.exit_epoch
        else:
          max(max_exit_epoch, v.exit_epoch)
  if max_exit_epoch == FAR_FUTURE_EPOCH:
    max_exit_epoch = get_current_epoch(pre)
  let earliest_exit_epoch = max_exit_epoch + 1

  (ref epbs.BeaconState)(
    # Versioning
    genesis_time: pre.genesis_time,
    genesis_validators_root: pre.genesis_validators_root,
    slot: pre.slot,
    fork: Fork(
      previous_version: pre.fork.current_version,
      current_version: cfg.EIP7732_FORK_VERSION,
      epoch: epoch
    ),

    # History
    latest_block_header: pre.latest_block_header,
    block_roots: pre.block_roots,
    state_roots: pre.state_roots,
    historical_roots: pre.historical_roots,

    # Eth1
    eth1_data: pre.eth1_data,
    eth1_data_votes: pre.eth1_data_votes,
    eth1_deposit_index: pre.eth1_deposit_index,

    # Registry
    validators: pre.validators,
    balances: pre.balances,

    # Randomness
    randao_mixes: pre.randao_mixes,

    # Slashings
    slashings: pre.slashings,

    # Participation
    previous_epoch_participation: pre.previous_epoch_participation,
    current_epoch_participation: pre.current_epoch_participation,

    # Finality
    justification_bits: pre.justification_bits,
    previous_justified_checkpoint: pre.previous_justified_checkpoint,
    current_justified_checkpoint: pre.current_justified_checkpoint,
    finalized_checkpoint: pre.finalized_checkpoint,

    # Inactivity
    inactivity_scores: pre.inactivity_scores,

    # Sync
    current_sync_committee: pre.current_sync_committee,
    next_sync_committee: pre.next_sync_committee,

    # Execution-layer
    latest_execution_payload_header: default(epbs.ExecutionPayloadHeader),

    # Withdrawals
    next_withdrawal_index: pre.next_withdrawal_index,
    next_withdrawal_validator_index: pre.next_withdrawal_validator_index,

    # Deep history valid from Capella onwards
    historical_summaries: pre.historical_summaries,

    deposit_requests_start_index: UNSET_DEPOSIT_REQUESTS_START_INDEX,
    deposit_balance_to_consume: 0.Gwei,
    exit_balance_to_consume: 0.Gwei,
    earliest_exit_epoch: earliest_exit_epoch,
    consolidation_balance_to_consume: 0.Gwei,
    earliest_consolidation_epoch:
      compute_activation_exit_epoch(get_current_epoch(pre)),

    # pending_balance_deposits, pending_partial_withdrawals, and
    # pending_consolidations are default empty lists

    # [New in epbs:EIP7732]
    latest_block_hash: ZERO_HASH,
    latest_full_slot: pre.slot,
    latest_withdrawals_root: ZERO_HASH
  )

func latest_block_root(state: ForkyBeaconState, state_root: Eth2Digest):
    Eth2Digest =
  # The root of the last block that was successfully applied to this state -
  # normally, when a block is applied, the data from the header is stored in
  # the state without the state root - on the next process_slot, the state root
  # is added to the header and the block root can now be computed and added to
  # the block roots table. If process_slot has not yet run on top of the new
  # block, we must fill in the state root ourselves.
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

func get_sync_committee_cache*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState,
    cache: var StateCache): SyncCommitteeCache =
  let period = state.slot.sync_committee_period()

  cache.sync_committees.withValue(period, v) do:
    return v[]

  var
    s = toHashSet(state.current_sync_committee.pubkeys.data)

  for pk in state.next_sync_committee.pubkeys.data:
    s.incl(pk)

  var pubkeyIndices: Table[ValidatorPubKey, ValidatorIndex]
  for vidx in state.validators.vindices:
    let pubkey = state.validators[vidx].pubkey
    if pubkey in s:
      pubkeyIndices[pubkey] = vidx

  var res: SyncCommitteeCache
  try:
    for i in 0..<res.current_sync_committee.len():
      res.current_sync_committee[i] =
        pubkeyIndices[state.current_sync_committee.pubkeys[i]]
      res.next_sync_committee[i] =
        pubkeyIndices[state.next_sync_committee.pubkeys[i]]
  except KeyError:
    raiseAssert "table constructed just above"

  cache.sync_committees[period] = res

  res

func dependent_root*(state: ForkyHashedBeaconState, epoch: Epoch): Eth2Digest =
  ## Return the root of the last block that contributed to the shuffling in the
  ## given epoch
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

func attester_dependent_root*(state: ForkyHashedBeaconState): Eth2Digest =
  state.dependent_root(state.data.slot.epoch.get_previous_epoch)

func latest_block_id*(state: ForkyHashedBeaconState): BlockId =
  ## Block id of the latest block applied to this state
  BlockId(
    root: state.latest_block_root,
    slot: state.data.latest_block_header.slot)

func latest_block_id*(state: ForkedHashedBeaconState): BlockId =
  ## Block id of the latest block applied to this state
  withState(state): forkyState.latest_block_id()

func matches_block(
    state: ForkyHashedBeaconState, block_root: Eth2Digest): bool =
  ## Return true iff the latest block applied to this state matches the given
  ## `block_root`
  block_root == state.latest_block_root

func matches_block*(
    state: ForkedHashedBeaconState, block_root: Eth2Digest): bool =
  withState(state): forkyState.matches_block(block_root)

func matches_block_slot(
    state: ForkyHashedBeaconState, block_root: Eth2Digest, slot: Slot): bool =
  ## Return true iff the latest block applied to this state matches the given
  ## `block_root` and the state slot has been advanced to the given slot
  slot == state.data.slot and block_root == state.latest_block_root
func matches_block_slot*(
    state: ForkedHashedBeaconState, block_root: Eth2Digest, slot: Slot): bool =
  withState(state): forkyState.matches_block_slot(block_root, slot)

func can_advance_slots(
    state: ForkyHashedBeaconState, block_root: Eth2Digest, target_slot: Slot): bool =
  ## Return true iff we can reach the given block/slot combination simply by
  ## advancing 0 or more slots
  target_slot >= state.data.slot and block_root == state.latest_block_root
func can_advance_slots*(
    state: ForkedHashedBeaconState, block_root: Eth2Digest, target_slot: Slot): bool =
  withState(state): forkyState.can_advance_slots(block_root, target_slot)
