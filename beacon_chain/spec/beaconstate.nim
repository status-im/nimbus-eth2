# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  stew/[assign2, staticfor],
  json_serialization/std/sets,
  chronicles,
  ./[eth2_merkleization, forks, signatures, validator],
  ../validator_bucket_sort

from std/algorithm import fill, isSorted, sort
from std/sequtils import anyIt, mapIt

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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/beacon-chain.md#new-is_builder_withdrawal_credential
func is_builder_withdrawal_credential*(
    withdrawal_credentials: Eth2Digest): bool =
  withdrawal_credentials.data[0] == BUILDER_WITHDRAWAL_PREFIX

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/electra/beacon-chain.md#new-has_compounding_withdrawal_credential
func has_compounding_withdrawal_credential*(
    consensusFork: static ConsensusFork, validator: Validator): bool =
  ## Check if ``validator`` has an 0x02 prefixed "compounding" withdrawal
  ## credential.
  is_compounding_withdrawal_credential(validator.withdrawal_credentials)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/electra/beacon-chain.md#new-get_max_effective_balance
func get_max_effective_balance*(
    consensusFork: static ConsensusFork, validator: Validator): Gwei =
  ## Get max effective balance for ``validator``.
  if has_compounding_withdrawal_credential(consensusFork, validator):
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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/electra/beacon-chain.md#modified-get_validator_from_deposit
func get_validator_from_deposit*(
    state: electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
           heze.BeaconState,
    pubkey: ValidatorPubKey,
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
  let max_effective_balance = get_max_effective_balance(type(state).kind, validator)
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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#compute_activation_exit_epoch
func compute_activation_exit_epoch*(epoch: Epoch): Epoch =
  ## Return the epoch during which validator activations and exits initiated in
  ## ``epoch`` take effect.
  epoch + 1 + MAX_SEED_LOOKAHEAD

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/phase0/beacon-chain.md#get_validator_churn_limit
func get_validator_churn_limit*(
      cfg: RuntimeConfig, state: ForkyBeaconState, cache: var StateCache):
    uint64 =
  ## Return the validator churn limit for the current epoch.
  max(
    cfg.MIN_PER_EPOCH_CHURN_LIMIT,
    count_active_validators(
      state, state.get_current_epoch(), cache) div cfg.CHURN_LIMIT_QUOTIENT)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/deneb/beacon-chain.md#new-get_validator_activation_churn_limit
func get_validator_activation_churn_limit*(
      cfg: RuntimeConfig, state: deneb.BeaconState | electra.BeaconState,
      cache: var StateCache): uint64 =
  ## Return the validator activation churn limit for the current epoch.
  min(
    cfg.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT,
    get_validator_churn_limit(cfg, state, cache))

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/phase0/beacon-chain.md#initiate_validator_exit
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
    state: electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
           heze.BeaconState):
    ExitQueueInfo =
  # Electra initiate_validator_exit doesn't have same quadratic aspect given
  # StateCache balance caching
  default(ExitQueueInfo)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#initiate_validator_exit
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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/beacon-chain.md#new-initiate_builder_exit
func initiate_builder_exit*(
    cfg: RuntimeConfig, state: var (gloas.BeaconState | heze.BeaconState),
    builder_index: BuilderIndex) =
  ## Initiate the exit of the builder with index ``index``.

  # Set builder exit epoch
  let builder = addr state.builders.mitem(builder_index)
  builder.withdrawable_epoch =
    get_current_epoch(state) + cfg.MIN_BUILDER_WITHDRAWABILITY_DELAY

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/beacon-chain.md#new-settle_builder_payment
func settle_builder_payment*(
    state: var (gloas.BeaconState | heze.BeaconState),
    payment_index: uint64): Result[void, cstring] =
  if not (payment_index < lenu64(state.builder_pending_payments)):
    return err("settle_builder_payment: payment index incorrect")

  var payment = state.builder_pending_payments.mitem(payment_index)
  if uint64(payment.withdrawal.amount) > 0'u64:
    if not state.builder_pending_withdrawals.add(payment.withdrawal):
      return err("settle_builder_payment: couldn't add to builder_pending_withdrawals")
  state.builder_pending_payments.mitem(payment_index).reset()

  ok()

func get_total_active_balance*(state: ForkyBeaconState, cache: var StateCache): Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#new-get_balance_churn_limit
func get_balance_churn_limit(
    cfg: RuntimeConfig,
    state: electra.BeaconState | fulu.BeaconState,
    cache: var StateCache): Gwei =
  ## Return the churn limit for the current epoch.
  let churn = max(
    cfg.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA.Gwei,
    get_total_active_balance(state, cache) div cfg.CHURN_LIMIT_QUOTIENT
  )
  churn - churn mod EFFECTIVE_BALANCE_INCREMENT.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/electra/beacon-chain.md#new-get_activation_exit_churn_limit
func get_activation_exit_churn_limit*(
    cfg: RuntimeConfig,
    state: electra.BeaconState | fulu.BeaconState,
    cache: var StateCache):
    Gwei =
  ## Return the churn limit for the current epoch dedicated to activations and
  ## exits.
  min(
    cfg.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT.Gwei,
    get_balance_churn_limit(cfg, state, cache))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/gloas/beacon-chain.md#new-get_activation_churn_limit
func get_activation_churn_limit*(
    cfg: RuntimeConfig,
    state: gloas.BeaconState | heze.BeaconState,
    cache: var StateCache): Gwei =
  ## Per-epoch churn limit for activations, rounded to
  ## ``EFFECTIVE_BALANCE_INCREMENT``.
  var churn = max(
    cfg.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA.Gwei,
    get_total_active_balance(state, cache) div cfg.CHURN_LIMIT_QUOTIENT_GLOAS
  )
  churn = churn - churn mod EFFECTIVE_BALANCE_INCREMENT.Gwei
  min(cfg.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS.Gwei, churn)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/gloas/beacon-chain.md#new-get_exit_churn_limit
func get_exit_churn_limit*(
    cfg: RuntimeConfig,
    state: gloas.BeaconState | heze.BeaconState,
    cache: var StateCache): Gwei =
  ## Per-epoch churn limit for exits, rounded to
  ## ``EFFECTIVE_BALANCE_INCREMENT``.
  let churn = max(
    cfg.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA.Gwei,
    get_total_active_balance(state, cache) div cfg.CHURN_LIMIT_QUOTIENT_GLOAS
  )
  churn - churn mod EFFECTIVE_BALANCE_INCREMENT.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#new-get_consolidation_churn_limit
func get_consolidation_churn_limit*(
    cfg: RuntimeConfig,
    state: electra.BeaconState | fulu.BeaconState,
    cache: var StateCache):
    Gwei =
  get_balance_churn_limit(cfg, state, cache) -
    get_activation_exit_churn_limit(cfg, state, cache)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/gloas/beacon-chain.md#modified-get_consolidation_churn_limit
func get_consolidation_churn_limit*(
    cfg: RuntimeConfig,
    state: gloas.BeaconState | heze.BeaconState,
    cache: var StateCache): Gwei =
  ## Per-epoch churn limit reserved for consolidations (EIP-7521).
  let churn =
    get_total_active_balance(state, cache) div
    cfg.CONSOLIDATION_CHURN_LIMIT_QUOTIENT
  churn - churn mod EFFECTIVE_BALANCE_INCREMENT.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#new-compute_exit_epoch_and_update_churn
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/gloas/beacon-chain.md#modified-compute_exit_epoch_and_update_churn
func compute_exit_epoch_and_update_churn*(
    cfg: RuntimeConfig,
    state: var (electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
                heze.BeaconState),
    exit_balance: Gwei,
    cache: var StateCache): Epoch =
  var earliest_exit_epoch = max(state.earliest_exit_epoch,
    compute_activation_exit_epoch(get_current_epoch(state)))
  let per_epoch_churn =
    when typeof(state).kind >= ConsensusFork.Gloas:
      get_exit_churn_limit(cfg, state, cache)
    else:
      get_activation_exit_churn_limit(cfg, state, cache)

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
    cfg: RuntimeConfig,
    state: var (electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
                heze.BeaconState),
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
    cfg: RuntimeConfig,
    state: var (electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
                heze.BeaconState),
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
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/bellatrix/beacon-chain.md#modified-slash_validator
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
  elif state is electra.BeaconState or state is fulu.BeaconState or
       state is gloas.BeaconState or state is heze.BeaconState:
    validator_effective_balance div MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA
  else:
    {.fatal: "invalid BeaconState type".}

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/bellatrix/beacon-chain.md#modified-slash_validator
func get_whistleblower_reward*(
    state: phase0.BeaconState | altair.BeaconState | bellatrix.BeaconState |
           capella.BeaconState | deneb.BeaconState,
    validator_effective_balance: Gwei): Gwei =
  validator_effective_balance div WHISTLEBLOWER_REWARD_QUOTIENT

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/electra/beacon-chain.md#modified-slash_validator
func get_whistleblower_reward*(
    state: electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
           heze.BeaconState,
    validator_effective_balance: Gwei): Gwei =
  validator_effective_balance div WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/bellatrix/beacon-chain.md#modified-slash_validator
func get_proposer_reward(state: ForkyBeaconState, whistleblower_reward: Gwei): Gwei =
  when state is phase0.BeaconState:
    whistleblower_reward div PROPOSER_REWARD_QUOTIENT
  elif state is altair.BeaconState or state is bellatrix.BeaconState or
       state is capella.BeaconState or state is deneb.BeaconState or
       state is electra.BeaconState or state is fulu.BeaconState or
       state is gloas.BeaconState or state is heze.BeaconState:
    whistleblower_reward * PROPOSER_WEIGHT div WEIGHT_DENOMINATOR
  else:
    {.fatal: "invalid BeaconState type".}

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/bellatrix/beacon-chain.md#modified-slash_validator
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/phase0/beacon-chain.md#genesis-block
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

func get_initial_beacon_block*(state: fulu.HashedBeaconState):
    fulu.TrustedSignedBeaconBlock =
  # The genesis block is implicitly trusted
  let message = fulu.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root)
    # parent_root, randao_reveal, eth1_data, signature, and body automatically
    # initialized to default values.
  fulu.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: gloas.HashedBeaconState):
    gloas.TrustedSignedBeaconBlock =
  # The genesis block is implicitly trusted
  let message = gloas.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root,
    body: gloas.TrustedBeaconBlockBody(
      signed_execution_payload_bid: SignedExecutionPayloadBid(
        message: state.data.latest_execution_payload_bid)))
  gloas.TrustedSignedBeaconBlock(
    message: message, root: hash_tree_root(message))

func get_initial_beacon_block*(state: heze.HashedBeaconState):
    heze.TrustedSignedBeaconBlock =
  # The genesis block is implicitly trusted
  let message = heze.TrustedBeaconBlock(
    slot: state.data.slot,
    state_root: state.root,
    body: heze.TrustedBeaconBlockBody(
      signed_execution_payload_bid: SignedExecutionPayloadBid(
        message: state.data.latest_execution_payload_bid)))
  heze.TrustedSignedBeaconBlock(
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#get_total_balance
template get_total_balance(
    state: ForkyBeaconState, validator_indices: untyped): Gwei =
  ## Return the combined effective balance of the ``indices``.
  ## ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
  ## Math safe up to ~10B ETH, after which this overflows uint64.
  var res = 0.Gwei
  for validator_index in validator_indices:
    res += state.validators[validator_index].effective_balance
  max(EFFECTIVE_BALANCE_INCREMENT.Gwei, res)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#is_eligible_for_activation_queue
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#is_eligible_for_activation
func is_eligible_for_activation*(
    state: ForkyBeaconState, validator: Validator): bool =
  ## Check if ``validator`` is eligible for activation.

  # Placement in queue is finalized
  validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch and
  # Has not yet been activated
    validator.activation_epoch == FAR_FUTURE_EPOCH

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
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
iterator get_attesting_indices*(
    state: ForkyBeaconState,
    slot: Slot,
    index: CommitteeIndex,
    aggregation_bits: CommitteeValidatorsBits,
    cache: var StateCache,
): ValidatorIndex =
  ## Return the set of attesting indices corresponding to ``data`` and
  ## ``aggregation_bits`` or nothing if `data` is invalid
  if aggregation_bits.lenu64 == get_beacon_committee_len(state, slot, index, cache):
    for index_in_committee, validator_index in get_beacon_committee(
      state, slot, index, cache
    ):
      if aggregation_bits[index_in_committee]:
        yield validator_index

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#modified-get_attesting_indices
iterator get_attesting_indices*(
    state: ForkyBeaconState,
    slot: Slot,
    committee_bits: AttestationCommitteeBits,
    aggregation_bits: AggregationBits,
    cache: var StateCache): ValidatorIndex =
  ## Return the set of attesting indices corresponding to ``aggregation_bits``
  ## and ``committee_bits``.
  var committee_offset = 0
  for index in get_committee_indices(committee_bits):
    let committee_len = get_beacon_committee_len(state, slot, index, cache).int
    if aggregation_bits.len < committee_offset + committee_len:
      # Would overflow, invalid attestation caught in check_attestation()
      break

    for i, attester_index in get_beacon_committee(state, slot, index, cache):
      if aggregation_bits[committee_offset + i]:
        yield attester_index

    committee_offset += committee_len

# Attestation validation
# ------------------------------------------------------------------------------------------
# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#attestations
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id

func check_attestation_index*(
    index, committees_per_slot: uint64
): Result[CommitteeIndex, cstring] =
  CommitteeIndex.init(index, committees_per_slot)

func check_attestation_index*(
    data: AttestationData, committees_per_slot: uint64
): Result[CommitteeIndex, cstring] =
  check_attestation_index(data.index, committees_per_slot)

# Attestation validation
# ------------------------------------------------------------------------------------------
# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#attestations
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id

func check_attestation_slot_target*(data: AttestationData): Result[Slot, cstring] =
  if not (data.target.epoch == epoch(data.slot)):
    return err("Target epoch doesn't match attestation slot")

  ok(data.slot)

func check_attestation_target_epoch(
    data: AttestationData, current_epoch: Epoch
): Result[Epoch, cstring] =
  if not (
    data.target.epoch == get_previous_epoch(current_epoch) or
    data.target.epoch == current_epoch
  ):
    return err("Target epoch not current or previous epoch")

  ok(data.target.epoch)

func check_attestation_slot_target*(
    data: AttestationData, current_epoch: Epoch
): Result[Slot, cstring] =
  check_attestation_target_epoch(data, current_epoch) and
    check_attestation_slot_target(data)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_attesting_indices
iterator get_attesting_indices*(
    state: ForkyBeaconState,
    attestation: phase0.Attestation | phase0.TrustedAttestation,
    cache: var StateCache,
): ValidatorIndex =
  block iter:
    let
      slot = check_attestation_slot_target(attestation.data, state.get_current_epoch()).valueOr:
        break iter
      committees_per_slot = get_committee_count_per_slot(state, slot.epoch, cache)
      index = check_attestation_index(attestation.data, committees_per_slot).valueOr:
        break iter
    for vidx in state.get_attesting_indices(
      slot, index, attestation.aggregation_bits, cache
    ):
      yield vidx

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/electra/beacon-chain.md#modified-get_attesting_indices
iterator get_attesting_indices*(
    state: ForkyBeaconState,
    attestation: electra.Attestation | electra.TrustedAttestation,
    cache: var StateCache,
): ValidatorIndex =
  block iter:
    let slot = check_attestation_slot_target(attestation.data, get_current_epoch(state)).valueOr:
      break iter

    for vidx in state.get_attesting_indices(
      slot, attestation.committee_bits, attestation.aggregation_bits, cache
    ):
      yield vidx

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_attesting_indices
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/electra/beacon-chain.md#modified-get_attesting_indices
func get_attesting_indices*(
    state: ForkyBeaconState,
    attestation:
      phase0.Attestation | phase0.TrustedAttestation | electra.Attestation |
      electra.TrustedAttestation,
    cache: var StateCache,
): seq[ValidatorIndex] =
  ## Return the set of attesting indices corresponding to ``attestation``
  ## or nothing if `data` is invalid
  for vidx in state.get_attesting_indices(attestation, cache):
    result.add vidx

proc is_valid_indexed_attestation(
    state: ForkyBeaconState,
    attestation:
      phase0.Attestation | phase0.TrustedAttestation |
      electra.Attestation | electra.TrustedAttestation,
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
    for vidx in state.get_attesting_indices(attestation, cache):
      pubkeys.add(state.validators[vidx].pubkey)

    if not verify_attestation_signature(
        state.fork, state.genesis_validators_root, attestation.data,
        pubkeys, attestation.signature):
      return err("indexed attestation: signature verification failure")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#attestations
# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#modified-process_attestation
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/deneb/beacon-chain.md#modified-process_attestation
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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#new-is_attestation_same_slot
func is_attestation_same_slot(
    state: gloas.BeaconState | heze.BeaconState, data: AttestationData): bool =
  ## Checks if the attestation was for the block
  ## proposed at the attestation slot.
  if data.slot == 0:
    return true

  let
    is_matching_blockroot =
      data.beacon_block_root == get_block_root_at_slot(state, data.slot)
    is_current_blockroot =
      data.beacon_block_root != get_block_root_at_slot(state, data.slot - 1)

  is_matching_blockroot and is_current_blockroot

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.9/specs/altair/beacon-chain.md#get_attestation_participation_flag_indices
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
    state: deneb.BeaconState | electra.BeaconState | fulu.BeaconState,
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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/beacon-chain.md#modified-get_attestation_participation_flag_indices
func get_attestation_participation_flag_indices(
    state: gloas.BeaconState | heze.BeaconState, data: AttestationData,
    inclusion_delay: uint64): set[TimelyFlag] =
  ## Return the flag indices that are satisfied by an attestation.
  let justified_checkpoint =
    if data.target.epoch == get_current_epoch(state):
      state.current_justified_checkpoint
    else:
      state.previous_justified_checkpoint

  # Matching roots
  let
    is_matching_source = data.source == justified_checkpoint
    is_matching_target = is_matching_source and
      data.target.root == get_block_root(state, data.target.epoch)
    is_matching_blockroot = is_matching_target and
      data.beacon_block_root == get_block_root_at_slot(state, data.slot)

  var is_matching_payload = false
  if is_attestation_same_slot(state, data):
    doAssert data.index == 0
    is_matching_payload = true
  else:
    let availability_bit =
      if state.execution_payload_availability[
        data.slot mod SLOTS_PER_HISTORICAL_ROOT]: 1'u64
      else: 0'u64
    is_matching_payload = (data.index == availability_bit)

  let is_matching_head = is_matching_blockroot and is_matching_payload

  # Checked by check_attestation
  doAssert is_matching_source

  var participation_flag_indices: set[TimelyFlag]
  if is_matching_source and inclusion_delay <=
      integer_squareroot(SLOTS_PER_EPOCH):
    participation_flag_indices.incl(TIMELY_SOURCE_FLAG_INDEX)
  if is_matching_target:
    participation_flag_indices.incl(TIMELY_TARGET_FLAG_INDEX)
  if is_matching_head and inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY:
    participation_flag_indices.incl(TIMELY_HEAD_FLAG_INDEX)

  participation_flag_indices

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/phase0/beacon-chain.md#get_total_active_balance
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.9/specs/altair/beacon-chain.md#get_base_reward_per_increment
func get_base_reward_per_increment_sqrt(
    total_active_balance_sqrt: uint64): Gwei =
  EFFECTIVE_BALANCE_INCREMENT.Gwei * BASE_REWARD_FACTOR div
    total_active_balance_sqrt

func get_base_reward_per_increment*(
    total_active_balance: Gwei): Gwei =
  get_base_reward_per_increment_sqrt(
    integer_squareroot(distinctBase(total_active_balance)))

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/altair/beacon-chain.md#get_base_reward
func get_base_reward(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState | fulu.BeaconState |
           gloas.BeaconState | heze.BeaconState,
    index: ValidatorIndex, base_reward_per_increment: Gwei): Gwei =
  ## Return the base reward for the validator defined by ``index`` with respect
  ## to the current ``state``.
  let increments =
    state.validators[index].effective_balance div
    EFFECTIVE_BALANCE_INCREMENT.Gwei
  increments * base_reward_per_increment

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#attestations
proc check_attestation*(
    state: ForkyBeaconState,
    attestation: phase0.Attestation | phase0.TrustedAttestation,
    flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!

  let
    data = attestation.data
    epoch = ? check_attestation_target_epoch(data, state.get_current_epoch())
    slot = ? check_attestation_slot_target(data)
    committee_count_per_slot = get_committee_count_per_slot(state, epoch, cache)
    committee_index = ? check_attestation_index(data, committee_count_per_slot)

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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/electra/beacon-chain.md#modified-process_attestation
# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#modified-process_attestation
proc check_attestation*(
    state: electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
           heze.BeaconState,
    attestation: electra.Attestation | electra.TrustedAttestation,
    flags: UpdateFlags, cache: var StateCache):
    Result[void, cstring] =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot. When acting as a proposer, the same rules need to
  ## be followed!

  let
    data = attestation.data
    epoch = ? check_attestation_target_epoch(data, state.get_current_epoch())
    slot = ? check_attestation_slot_target(data)

  ? check_attestation_inclusion((typeof state).kind, slot, state.slot)

  # [Modified in Gloas:EIP7732]
  when typeof(state).kind >= ConsensusFork.Gloas:
    if not (data.index < 2):
      return err("Gloas attestation data index must be less than 2")
    if is_attestation_same_slot(state, data) and data.index != 0:
      return err("Same-slot attestation must have index 0")
  else:
    # [Modified in Electra:EIP7549]
    if not (data.index == 0):
      return err("Electra attestation data index not 0")

  var committee_offset = 0
  for committee_index in attestation.committee_bits.oneIndices:
    if not (committee_index.uint64 < get_committee_count_per_slot(
        state, epoch, cache)):
      return err("attestation wrong committee index len")
    let committee_index = CommitteeIndex(committee_index)
    let committee_len = get_beacon_committee_len(
      state, slot, committee_index, cache)

    if attestation.aggregation_bits.len < committee_offset + committee_len.int:
      # This would overflow; see invalid_too_many_committee_bits test case
      return err("Electra attestation has too many committee bits")

    # This construction modified slightly from spec version to early-exit and
    # not create the actual set, but the result is it uses a flag variable to
    # look similar.
    var committee_attesters_nonzero = false
    for i, attester_index in get_beacon_committee(state, slot, committee_index, cache):
      if attestation.aggregation_bits[committee_offset + i]:
        committee_attesters_nonzero = true
        break
    if not committee_attesters_nonzero:
      return err("Electra attestation committee not present in aggregated bits")

    committee_offset += committee_len.int

  if not (len(attestation.aggregation_bits) == committee_offset):
    return err("attestation wrong aggregation bit length")

  if epoch == get_current_epoch(state):
    if not (data.source == state.current_justified_checkpoint):
      return err("FFG data not matching current justified epoch")
  else:
    if not (data.source == state.previous_justified_checkpoint):
      return err("FFG data not matching previous justified epoch")

  ? is_valid_indexed_attestation(state, attestation, flags, cache)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/capella/beacon-chain.md#new-process_bls_to_execution_change
proc check_bls_to_execution_change*(
    genesis_fork_version: Version,
    state: capella.BeaconState | deneb.BeaconState | electra.BeaconState |
           fulu.BeaconState | gloas.BeaconState | heze.BeaconState,
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
        genesis_fork_version, state.genesis_validators_root, signed_address_change,
        address_change.from_bls_pubkey, signed_address_change.signature):
    return err("process_bls_to_execution_change: invalid signature")

  ok()

func get_proposer_reward*(
    state: ForkyBeaconState,
    attestation:
      phase0.Attestation | phase0.TrustedAttestation |
      electra.Attestation | electra.TrustedAttestation,
    base_reward_per_increment: Gwei,
    cache: var StateCache,
    epoch_participation: var EpochParticipationFlags): Gwei =
  let participation_flag_indices = get_attestation_participation_flag_indices(
    state, attestation.data, state.slot - attestation.data.slot)
  for vidx in state.get_attesting_indices(attestation, cache):
    let
      base_reward = get_base_reward(state, vidx, base_reward_per_increment)
    for flag_index, weight in PARTICIPATION_FLAG_WEIGHTS:
      if flag_index in participation_flag_indices and
         not has_flag(epoch_participation[vidx], flag_index):
        epoch_participation[vidx] =
          add_flag(epoch_participation[vidx], flag_index)
        # these are all valid; TODO statically verify or do it type-safely
        result += base_reward * weight.uint64

  let proposer_reward_denominator =
    (WEIGHT_DENOMINATOR.uint64 - PROPOSER_WEIGHT.uint64) *
    WEIGHT_DENOMINATOR.uint64 div PROPOSER_WEIGHT.uint64

  result div proposer_reward_denominator

proc process_attestation*(
    state: var ForkyBeaconState,
    attestation: phase0.Attestation | phase0.TrustedAttestation,
    flags: UpdateFlags,
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
    state: var (electra.BeaconState | fulu.BeaconState),
    attestation: electra.Attestation | electra.TrustedAttestation,
    flags: UpdateFlags, base_reward_per_increment: Gwei,
    cache: var StateCache): Result[Gwei, cstring] =
  ? check_attestation(state, attestation, flags, cache)

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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#modified-process_attestation
proc process_attestation*(
    state: var (gloas.BeaconState | heze.BeaconState),
    attestation: electra.Attestation | electra.TrustedAttestation,
    flags: UpdateFlags, base_reward_per_increment: Gwei,
    cache: var StateCache): Result[Gwei, cstring] =
  ? check_attestation(state, attestation, flags, cache)

  let proposer_index = get_beacon_proposer_index(state, cache).valueOr:
    return err("process_attestation: no beacon proposer index and probably no active validators")

  # [Modified in Gloas:EIP7732]
  let
    current_epoch_target =
      attestation.data.target.epoch == get_current_epoch(state)
    payment_index =
      if current_epoch_target:
        SLOTS_PER_EPOCH + (attestation.data.slot mod SLOTS_PER_EPOCH)
      else:
        attestation.data.slot mod SLOTS_PER_EPOCH
    participation_flag_indices = get_attestation_participation_flag_indices(
      state, attestation.data, state.slot - attestation.data.slot)

  var payment = state.builder_pending_payments.item(payment_index.int)

  template updateParticipationFlags(epoch_participation: untyped): Gwei =
    var proposer_reward_numerator = 0.Gwei
    for vidx in state.get_attesting_indices(attestation, cache):
      # [New in Gloas:EIP7732]
      # For same-slot attestations, check if we're setting any new flags
      # If we are, this validator hasn't contributed to this slot's quorum yet
      var will_set_new_flag = false
      for flag_index, weight in PARTICIPATION_FLAG_WEIGHTS:
        if flag_index in participation_flag_indices and
           not has_flag(epoch_participation[vidx], flag_index):
          epoch_participation[vidx] =
            add_flag(epoch_participation[vidx], flag_index)
          proposer_reward_numerator +=
            get_base_reward(
              state, vidx, base_reward_per_increment) * weight.uint64
          will_set_new_flag = true

      # [New in Gloas:EIP7732]
      # Add weight for same-slot attestations when any new flag is set
      # This ensures each validator contributes exactly once per slot
      if will_set_new_flag and
          is_attestation_same_slot(state, attestation.data) and
          payment.withdrawal.amount > 0.Gwei:
        payment.weight += state.validators.item(vidx).effective_balance

    let
      proposer_reward_denominator =
        (WEIGHT_DENOMINATOR.uint64 - PROPOSER_WEIGHT.uint64) *
          WEIGHT_DENOMINATOR.uint64 div PROPOSER_WEIGHT.uint64
      proposer_reward =
        proposer_reward_numerator div proposer_reward_denominator
    increase_balance(state, proposer_index, proposer_reward)
    proposer_reward

  doAssert base_reward_per_increment > 0.Gwei
  let proposer_reward =
    if current_epoch_target:
      updateParticipationFlags(state.current_epoch_participation)
    else:
      updateParticipationFlags(state.previous_epoch_participation)

  # Update builder payment weight
  state.builder_pending_payments[payment_index.int] = payment

  ok(proposer_reward)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.9/specs/altair/beacon-chain.md#get_next_sync_committee_indices
func get_next_sync_committee_keys(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState): array[SYNC_COMMITTEE_SIZE, ValidatorPubKey] =
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
    if effective_balance * MAX_RANDOM_BYTE >=
        MAX_EFFECTIVE_BALANCE.Gwei * random_byte:
      res[index] = state.validators[candidate_index].pubkey
      inc index
    i += 1'u64
  res

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/electra/beacon-chain.md#modified-get_next_sync_committee_indices
func get_next_sync_committee_keys(
    state: electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
           heze.BeaconState):
    array[SYNC_COMMITTEE_SIZE, ValidatorPubKey] =
  ## Return the sequence of sync committee indices, with possible duplicates,
  ## for the next sync committee.
  # The sync committe depends on seed and effective balance - it can
  # thus only be computed for the current epoch of the state, after balance
  # updates have been performed

  let epoch = get_current_epoch(state) + 1

  const MAX_RANDOM_VALUE = 65536 - 1  # [Modified in Electra]
  let
    active_validator_indices = get_active_validator_indices(state, epoch)
    active_validator_count = uint64(len(active_validator_indices))
    seed = get_seed(state, epoch, DOMAIN_SYNC_COMMITTEE)
  var
    i = 0'u64
    index = 0
    res: array[SYNC_COMMITTEE_SIZE, ValidatorPubKey]
    hash_buffer: array[40, byte]
    rv_buf: array[8, byte]
  hash_buffer[0..31] = seed.data
  while index < SYNC_COMMITTEE_SIZE:
    hash_buffer[32..39] = uint_to_bytes(uint64(i div 16))  # [Modified in Electra]
    let
      shuffled_index = compute_shuffled_index(
        uint64(i mod active_validator_count), active_validator_count, seed)
      candidate_index = active_validator_indices[shuffled_index]
      random_bytes = eth2digest(hash_buffer).data
      offset = (i mod 16) * 2
      effective_balance = state.validators[candidate_index].effective_balance
    rv_buf[0 .. 1] = random_bytes.toOpenArray(offset, offset + 1)
    let random_value = bytes_to_uint64(rv_buf)
    # [Modified in Electra:EIP7251]
    if effective_balance * MAX_RANDOM_VALUE >=
        MAX_EFFECTIVE_BALANCE_ELECTRA.Gwei * random_value:
      res[index] = state.validators[candidate_index].pubkey
      inc index
    i += 1'u64
  res

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.9/specs/capella/beacon-chain.md#has_eth1_withdrawal_credential
func has_eth1_withdrawal_credential*(validator: Validator): bool =
  ## Check if ``validator`` has an 0x01 prefixed "eth1" withdrawal credential.
  validator.withdrawal_credentials.data[0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/electra/beacon-chain.md#new-has_execution_withdrawal_credential
func has_execution_withdrawal_credential*(
    consensusFork: static ConsensusFork, validator: Validator): bool =
  ## Check if ``validator`` has a 0x01 or 0x02 prefixed withdrawal credential.
  has_compounding_withdrawal_credential(consensusFork, validator) or
    has_eth1_withdrawal_credential(validator)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.9/specs/capella/beacon-chain.md#is_fully_withdrawable_validator
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#updated-is_fully_withdrawable_validator
func is_fully_withdrawable_validator(
    fork: static ConsensusFork, validator: Validator, balance: Gwei,
    epoch: Epoch): bool =
  ## Check if ``validator`` is fully withdrawable.
  when fork >= ConsensusFork.Electra:
    # [Modified in Electra:EIP7251]
    has_execution_withdrawal_credential(fork, validator) and
      validator.withdrawable_epoch <= epoch and balance > 0.Gwei
  else:
    has_eth1_withdrawal_credential(validator) and
      validator.withdrawable_epoch <= epoch and balance > 0.Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#is_partially_withdrawable_validator
# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/electra/beacon-chain.md#modified-is_partially_withdrawable_validator
func is_partially_withdrawable_validator(
    fork: static ConsensusFork, validator: Validator, balance: Gwei): bool =
  ## Check if ``validator`` is partially withdrawable.
  when fork >= ConsensusFork.Electra:
    # [Modified in Electra:EIP7251]
    let
      max_effective_balance = get_max_effective_balance(fork, validator)
      has_max_effective_balance =
        validator.effective_balance == max_effective_balance
      has_excess_balance =
        balance > max_effective_balance  # [Modified in Electra:EIP7251]
    has_execution_withdrawal_credential(fork, validator) and
      has_max_effective_balance and has_excess_balance
  else:
    let
      has_max_effective_balance =
        validator.effective_balance == static(MAX_EFFECTIVE_BALANCE.Gwei)
      has_excess_balance = balance > static(MAX_EFFECTIVE_BALANCE.Gwei)
    has_eth1_withdrawal_credential(validator) and
      has_max_effective_balance and has_excess_balance

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#new-queue_excess_active_balance
func queue_excess_active_balance(
    state: var (electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
                heze.BeaconState),
    index: uint64) =
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/electra/beacon-chain.md#new-switch_to_compounding_validator
func switch_to_compounding_validator*(
    state: var (electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
                heze.BeaconState),
    index: ValidatorIndex) =
  let validator = addr state.validators.mitem(index)
  validator.withdrawal_credentials.data[0] = COMPOUNDING_WITHDRAWAL_PREFIX
  queue_excess_active_balance(state, index.uint64)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/electra/beacon-chain.md#new-get_pending_balance_to_withdraw
func get_pending_balance_to_withdraw*(
    state: electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
           heze.BeaconState,
    validator_index: ValidatorIndex): Gwei =
  var pending_balance: Gwei
  for withdrawal in state.pending_partial_withdrawals:
    if withdrawal.validator_index == validator_index:
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#effective-balances-updates
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
      if has_compounding_withdrawal_credential(consensusFork, state.validators.item(vidx)):
        MAX_EFFECTIVE_BALANCE_ELECTRA.Gwei
      else:
        MIN_ACTIVATION_BALANCE.Gwei
    min(
      balance - balance mod EFFECTIVE_BALANCE_INCREMENT.Gwei,
      effective_balance_limit)

template get_updated_effective_balance(
    consensusFork: static ConsensusFork, balance: Gwei,
    effective_balance: Gwei, vidx: uint64): Gwei =
  if effective_balance_might_update(balance, effective_balance):
    get_effective_balance_update(
      consensusFork, balance, effective_balance, vidx)
  else:
    effective_balance

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#new-get_expected_withdrawals
proc get_expected_withdrawals*(
    state: capella.BeaconState | deneb.BeaconState): seq[Withdrawal] =
  let
    epoch = get_current_epoch(state)
    num_validators = lenu64(state.validators)
    bound = min(len(state.validators), MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
  var
    withdrawal_index = state.next_withdrawal_index
    validator_index = state.next_withdrawal_validator_index
    withdrawals: seq[Withdrawal] = @[]
  for _ in 0 ..< bound:
    let
      validator = state.validators[validator_index]
      balance = state.balances[validator_index]
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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/electra/beacon-chain.md#modified-get_expected_withdrawals
# This partials count is used in exactly one place, while in general being able
# to cleanly treat the results of get_expected_withdrawals as a seq[Withdrawal]
# are valuable enough to make that the default version of this spec function.
template get_expected_withdrawals_with_partial_count_aux*(
    state: electra.BeaconState | fulu.BeaconState,
    epoch: Epoch, fetch_balance: untyped):
    (seq[Withdrawal], uint64) =
  doAssert epoch == get_current_epoch(state)

  var
    withdrawal_index = state.next_withdrawal_index
    withdrawals: seq[Withdrawal] = @[]
    processed_partial_withdrawals_count: uint64 = 0

  # [New in Electra:EIP7251] Consume pending partial withdrawals
  for withdrawal in state.pending_partial_withdrawals:
    if  withdrawal.withdrawable_epoch > epoch or
        len(withdrawals) == MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP:
      break

    let
      validator = state.validators.item(withdrawal.validator_index)

      # Keep a uniform variable name available for injected code
      validator_index {.inject.} = withdrawal.validator_index

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
      total_withdrawn = block:
        var res: Gwei
        for w in withdrawals:
          if w.validator_index == validator_index:
            res += w.amount
        res
      balance = fetch_balance - total_withdrawn
      has_excess_balance = balance > static(MIN_ACTIVATION_BALANCE.Gwei)
    if  validator.exit_epoch == FAR_FUTURE_EPOCH and
        has_sufficient_effective_balance and has_excess_balance:
      let
        withdrawable_balance = min(
          balance - static(MIN_ACTIVATION_BALANCE.Gwei),
          withdrawal.amount)
      var w = Withdrawal(
        index: withdrawal_index,
        validator_index: withdrawal.validator_index,
        amount: withdrawable_balance)
      w.address.data[0..19] = validator.withdrawal_credentials.data[12..^1]
      withdrawals.add w
      withdrawal_index += 1

    processed_partial_withdrawals_count += 1

  let
    bound = min(len(state.validators), MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
    num_validators = lenu64(state.validators)
  var validator_index {.inject.} = state.next_withdrawal_validator_index

  # Sweep for remaining.
  for _ in 0 ..< bound:
    let
      validator = state.validators.item(validator_index)
      # [Modified in Electra:EIP7251]
      partially_withdrawn_balance = block:
        var subtot: Gwei
        for withdrawal in withdrawals:
          if withdrawal.validator_index == validator_index:
            subtot += withdrawal.amount
        subtot
      balance = fetch_balance - partially_withdrawn_balance
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
        amount: balance - get_max_effective_balance(type(state).kind, validator))
      w.address.data[0..19] = validator.withdrawal_credentials.data[12..^1]
      withdrawals.add w
      withdrawal_index = WithdrawalIndex(withdrawal_index + 1)
    if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
      break
    validator_index = (validator_index + 1) mod num_validators

  (withdrawals, processed_partial_withdrawals_count)

template get_expected_withdrawals_with_partial_count*(
    state: electra.BeaconState | fulu.BeaconState):
    (seq[Withdrawal], uint64) =
  get_expected_withdrawals_with_partial_count_aux(
      state, get_current_epoch(state)) do:
    state.balances.item(validator_index)

func get_expected_withdrawals*(
    state: electra.BeaconState | fulu.BeaconState):
    seq[Withdrawal] =
  get_expected_withdrawals_with_partial_count(state)[0]

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#new-convert_builder_index_to_validator_index
func convert_builder_index_to_validator_index(builder_index: BuilderIndex):
    uint64 =
  builder_index or BUILDER_INDEX_FLAG

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#new-convert_validator_index_to_builder_index
func convert_validator_index_to_builder_index*(validator_index: uint64): BuilderIndex =
  validator_index and not BUILDER_INDEX_FLAG

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#new-is_builder_index
func is_builder_index*(validator_index: uint64): bool =
  (validator_index and BUILDER_INDEX_FLAG) != 0

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/beacon-chain.md#new-get_builder_withdrawals
func get_builder_withdrawals(
    state: gloas.BeaconState | heze.BeaconState,
    withdrawal_index: WithdrawalIndex, prior_withdrawals: seq[Withdrawal]):
    (seq[Withdrawal], WithdrawalIndex, uint64) =
  const withdrawals_limit = MAX_WITHDRAWALS_PER_PAYLOAD - 1

  # Safe: prior_withdrawals is always empty when called from get_expected_withdrawals
  doAssert len(prior_withdrawals) <= withdrawals_limit

  var withdrawal_index = withdrawal_index

  var
    processed_count: uint64
    withdrawals: seq[Withdrawal]
  for withdrawal in state.builder_pending_withdrawals:
    let
      all_withdrawals = prior_withdrawals & withdrawals
      has_reached_limit = len(all_withdrawals) == withdrawals_limit
    if has_reached_limit:
      break

    let builder_index = withdrawal.builder_index
    withdrawals.add(Withdrawal(
      index: withdrawal_index,
      validator_index: convert_builder_index_to_validator_index(builder_index),
      address: withdrawal.fee_recipient,
      amount: withdrawal.amount))
    withdrawal_index += WithdrawalIndex(1)
    processed_count += 1

  (withdrawals, withdrawal_index, processed_count)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/capella/beacon-chain.md#new-get_balance_after_withdrawals
func get_balance_after_withdrawals(
    state: gloas.BeaconState | heze.BeaconState, validator_index: uint64,
    withdrawals: seq[Withdrawal]): Gwei =
  var withdrawn: Gwei
  for withdrawal in withdrawals:
    if withdrawal.validator_index == validator_index:
      withdrawn += withdrawal.amount

  state.balances.item(validator_index) - withdrawn

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/electra/beacon-chain.md#new-is_eligible_for_partial_withdrawals
func is_eligible_for_partial_withdrawals(
    validator: Validator, balance: Gwei): bool =
  ## Check if ``validator`` can process a pending partial withdrawal.
  let
    has_sufficient_effective_balance =
      validator.effective_balance >= MIN_ACTIVATION_BALANCE.Gwei
    has_excess_balance = balance > MIN_ACTIVATION_BALANCE.Gwei

  validator.exit_epoch == FAR_FUTURE_EPOCH and
    has_sufficient_effective_balance and has_excess_balance

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/electra/beacon-chain.md#new-get_pending_partial_withdrawals
func get_pending_partial_withdrawals(
    state: gloas.BeaconState | heze.BeaconState,
    withdrawal_index: WithdrawalIndex, prior_withdrawals: seq[Withdrawal]):
    (seq[Withdrawal], WithdrawalIndex, uint64) =
  let
    epoch = get_current_epoch(state)
    withdrawals_limit = min(
      len(prior_withdrawals) + MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP,
      MAX_WITHDRAWALS_PER_PAYLOAD - 1)

  doAssert len(prior_withdrawals) <= withdrawals_limit

  var
    processed_count: uint64
    withdrawals: seq[Withdrawal]
    withdrawal_index = withdrawal_index
  for withdrawal in state.pending_partial_withdrawals:
    let
      all_withdrawals = prior_withdrawals & withdrawals
      is_withdrawable = withdrawal.withdrawable_epoch <= epoch
      has_reached_limit = len(all_withdrawals) == withdrawals_limit
    if not is_withdrawable or has_reached_limit:
      break

    let
      validator_index = withdrawal.validator_index
      validator = state.validators.item(validator_index)
      balance =
        get_balance_after_withdrawals(state, validator_index, all_withdrawals)
    if is_eligible_for_partial_withdrawals(validator, balance):
      let withdrawal_amount =
        min(balance - Gwei(MIN_ACTIVATION_BALANCE), withdrawal.amount)
      var address {.noinit.}: ExecutionAddress
      distinctBase(address)[0 .. 19] = validator.withdrawal_credentials.data.toOpenArray(12, 31)
      withdrawals.add(Withdrawal(
          index: withdrawal_index,
          validator_index: validator_index,
          address: address,
          amount: withdrawal_amount))
      withdrawal_index += WithdrawalIndex(1)

    processed_count += 1

  (withdrawals, withdrawal_index, processed_count)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/beacon-chain.md#new-get_builders_sweep_withdrawals
func get_builders_sweep_withdrawals(
    state: gloas.BeaconState | heze.BeaconState,
    withdrawal_index: WithdrawalIndex, prior_withdrawals: seq[Withdrawal]):
    (seq[Withdrawal], WithdrawalIndex, uint64) =
  let
    epoch = get_current_epoch(state)
    builders_limit =
      min(len(state.builders), MAX_BUILDERS_PER_WITHDRAWALS_SWEEP)
  const withdrawals_limit = MAX_WITHDRAWALS_PER_PAYLOAD - 1

  doAssert len(prior_withdrawals) <= withdrawals_limit

  var withdrawal_index = withdrawal_index

  var
    processed_count: uint64
    withdrawals: seq[Withdrawal]
    builder_index = state.next_withdrawal_builder_index
  for _ in 0 ..< builders_limit:
    let
      all_withdrawals = prior_withdrawals & withdrawals
      has_reached_limit = len(all_withdrawals) == withdrawals_limit
    if has_reached_limit:
      break

    let builder = state.builders.item(builder_index)
    if builder.withdrawable_epoch <= epoch and builder.balance > 0.Gwei:
      withdrawals.add(Withdrawal(
          index: withdrawal_index,
          validator_index:
            convert_builder_index_to_validator_index(builder_index),
          address: builder.execution_address,
          amount: builder.balance))
      withdrawal_index += WithdrawalIndex(1)

    builder_index = BuilderIndex((builder_index + 1) mod state.builders.lenu64)
    processed_count += 1

  (withdrawals, withdrawal_index, processed_count)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/electra/beacon-chain.md#modified-get_validators_sweep_withdrawals
func get_validators_sweep_withdrawals(
    state: gloas.BeaconState | heze.BeaconState,
    withdrawal_index: WithdrawalIndex,
    prior_withdrawals: seq[Withdrawal]):
    (seq[Withdrawal], WithdrawalIndex, uint64) =
  let
    epoch = get_current_epoch(state)
    validators_limit = min(len(state.validators), MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
  const withdrawals_limit = MAX_WITHDRAWALS_PER_PAYLOAD

  # Safe: prior_withdrawals length is bounded by the preceding get_builder_withdrawals
  # and get_partial_withdrawals calls in get_expected_withdrawals
  doAssert len(prior_withdrawals) < withdrawals_limit

  var
    processed_count: uint64
    withdrawals: seq[Withdrawal]
    validator_index = state.next_withdrawal_validator_index
    withdrawal_index = withdrawal_index
  for _ in 0 ..< validators_limit:
    let
      all_withdrawals = prior_withdrawals & withdrawals
      has_reached_limit = len(all_withdrawals) == withdrawals_limit
    if has_reached_limit:
      break

    let
      validator = state.validators.item(validator_index)
      balance =
        get_balance_after_withdrawals(state, validator_index, all_withdrawals)
    var address {.noinit.}: ExecutionAddress
    distinctBase(address)[0 .. 19] =
      validator.withdrawal_credentials.data.toOpenArray(12, 31)
    if is_fully_withdrawable_validator(
        state.typeof.kind, validator, balance, epoch):
      withdrawals.add(Withdrawal(
        index: withdrawal_index,
        validator_index: validator_index,
        address: address,
        amount: balance))
      withdrawal_index += WithdrawalIndex(1)
    elif is_partially_withdrawable_validator(
        state.typeof.kind, validator, balance):
      withdrawals.add(Withdrawal(
        index: withdrawal_index,
        validator_index: validator_index,
        address: address,
        amount:
          balance - get_max_effective_balance(state.typeof.kind, validator)))
      withdrawal_index += WithdrawalIndex(1)

    validator_index = (validator_index + 1) mod lenu64(state.validators)
    processed_count += 1

  (withdrawals, withdrawal_index, processed_count)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#modified-get_expected_withdrawals
func get_expected_withdrawals*(
    state: gloas.BeaconState | heze.BeaconState): ExpectedWithdrawals =
  # [New in Gloas:EIP7732]
  # Get builder withdrawals
  let (builder_withdrawals, builder_withdrawal_index,
       processed_builder_withdrawals_count) =
    get_builder_withdrawals(state, state.next_withdrawal_index, @[])
  var withdrawals = builder_withdrawals

  # Get partial withdrawals
  let (partial_withdrawals, partial_withdrawal_index,
       processed_partial_withdrawals_count) =
    get_pending_partial_withdrawals(state, builder_withdrawal_index, withdrawals)
  withdrawals &= partial_withdrawals

  # [New in Gloas:EIP7732]
  # Get builders sweep withdrawals
  let (builders_sweep_withdrawals, builders_sweep_withdrawal_index,
       processed_builders_sweep_count) =
    get_builders_sweep_withdrawals(
      state, partial_withdrawal_index, withdrawals)
  withdrawals &= builders_sweep_withdrawals

  # Get validators sweep withdrawals
  let (validators_sweep_withdrawals, _, processed_validators_sweep_count) =
    get_validators_sweep_withdrawals(
      state, builders_sweep_withdrawal_index, withdrawals)
  withdrawals &= validators_sweep_withdrawals

  ExpectedWithdrawals(
    withdrawals: withdrawals,
    # [New in Gloas:EIP7732]
    processed_builder_withdrawals_count: processed_builder_withdrawals_count,
    processed_partial_withdrawals_count: processed_partial_withdrawals_count,
    # [New in Gloas:EIP7732]
    processed_builders_sweep_count: processed_builders_sweep_count,
    processed_sweep_withdrawals_count: processed_validators_sweep_count)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/altair/beacon-chain.md#get_next_sync_committee
func get_next_sync_committee*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState | electra.BeaconState | fulu.BeaconState |
           gloas.BeaconState | heze.BeaconState):
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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0/specs/phase0/beacon-chain.md#genesis
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
         verify_deposit_signature(cfg.GENESIS_FORK_VERSION, deposit):
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/altair/fork.md#upgrading-the-state
func translate_participation(
    state: var altair.BeaconState,
    pending_attestations: openArray[phase0.PendingAttestation]) =

  var cache = StateCache()
  for attestation in pending_attestations:
    let
      data = attestation.data
      inclusion_delay = attestation.inclusion_delay
      slot = data.slot
      index = CommitteeIndex.init(data.index).expect("valid index in state")
      # Translate attestation inclusion info to flag indices
      participation_flag_indices =
        get_attestation_participation_flag_indices(state, data, inclusion_delay)

    # Apply flags to all attesting validators
    for vidx in state.get_attesting_indices(
      slot, index, attestation.aggregation_bits, cache
    ):
      for flag_index in participation_flag_indices:
        state.previous_epoch_participation[vidx] =
          add_flag(state.previous_epoch_participation[vidx], flag_index)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#new-get_index_for_new_builder
func get_index_for_new_builder(
    state: gloas.BeaconState | heze.BeaconState): BuilderIndex =
  # TODO probably this cannot make it into production as-is; check for
  # performance issues. It will depend on amount of builders
  for index, builder in state.builders:
    if  builder.withdrawable_epoch <= get_current_epoch(state) and
        builder.balance == 0.Gwei:
      return BuilderIndex(index)
  BuilderIndex(len(state.builders))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/gloas/builder.md#submit-deposit
func builder_execution_address*(
    withdrawal_credentials: Eth2Digest): ExecutionAddress =
  ## The builder's execution address is the last 20 bytes of the withdrawal
  ## credentials; the first byte is the builder version.
  var execution_address {.noinit.}: ExecutionAddress
  distinctBase(execution_address)[0 .. 19] =
    withdrawal_credentials.data.toOpenArray(12, 31)
  execution_address

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/gloas/beacon-chain.md#new-add_builder_to_registry
func add_builder_to_registry*(
    state: var (gloas.BeaconState | heze.BeaconState),
    bucket_sorted_builders: var BucketSortedValidators,
    pubkey: ValidatorPubKey, version: uint8,
    execution_address: ExecutionAddress, amount: Gwei, slot: Slot) =
  let
    index = get_index_for_new_builder(state)
    builder = Builder(
      pubkey: pubkey,
      version: version,
      execution_address: execution_address,
      balance: amount,
      deposit_epoch: slot.epoch,
      withdrawable_epoch: FAR_FUTURE_EPOCH)
  if state.builders.lenu64 == index:
    # TODO handle this potential failure (?) differently
    discard state.builders.add builder
    debugGloasComment "this isn't really safe"
    bucket_sorted_builders.add index.ValidatorIndex
  else:
    state.builders.mitem(index) = builder

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/gloas/fork.md#new-onboard_builders_from_pending_deposits
func onboard_builders_from_pending_deposits*(
    cfg: RuntimeConfig,
    state: var gloas.BeaconState) =
  ## Applies any pending deposit for builders, effectively onboarding builders
  ## at the fork. This one-time onboarding is the only path through the
  ## validator deposit contract that creates builders; from the fork onward,
  ## builders are created and topped up only via `BuilderDepositRequest`.
  debugGloasComment "In the slots leading up to the fork, implementations SHOULD validate pending deposit signatures and cache the results."
  let
    bucket_sorted_validators = sortValidatorBuckets(state.validators.asSeq)
    bucket_sorted_builders = sortValidatorBuckets(state.builders.asSeq)
  var
    pending_deposits: seq[PendingDeposit]
    pending_validator_pubkeys: HashSet[ValidatorPubKey]

  for deposit in state.pending_deposits:
    # Deposits for existing validators stay in the pending queue
    if findValidatorIndex(
        state.validators.asSeq, bucket_sorted_validators[],
        deposit.pubkey).isSome:
      pending_deposits.add(deposit)
      continue

    # Note that applying a deposit below can mutate the state and may add a
    # builder to the registry. For this reason, the list of builder pubkeys
    # must be recomputed each iteration (the bucket sort is kept current).
    let opt_builder_index = findValidatorIndex(
      state.builders.asSeq, bucket_sorted_builders[], deposit.pubkey)

    if opt_builder_index.isNone:
      # Deposits for non-builders stay in the pending queue. If there is a valid
      # pending deposit for a new validator with this pubkey, keep this deposit
      # in the pending queue to be applied to that validator later.
      if not is_builder_withdrawal_credential(deposit.withdrawal_credentials):
        # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/gloas/beacon-chain.md#new-is_pending_validator
        if verify_deposit_signature(
            cfg.GENESIS_FORK_VERSION,
            DepositData(
              pubkey: deposit.pubkey,
              withdrawal_credentials: deposit.withdrawal_credentials,
              amount: deposit.amount,
              signature: deposit.signature)):
          pending_validator_pubkeys.incl(deposit.pubkey)
        pending_deposits.add(deposit)
        continue
      if deposit.pubkey in pending_validator_pubkeys:
        pending_deposits.add(deposit)
        continue
      if not verify_deposit_signature(
          cfg.GENESIS_FORK_VERSION,
          DepositData(
            pubkey: deposit.pubkey,
            withdrawal_credentials: deposit.withdrawal_credentials,
            amount: deposit.amount,
            signature: deposit.signature)):
        continue
      add_builder_to_registry(
        state, bucket_sorted_builders[], deposit.pubkey,
        PAYLOAD_BUILDER_VERSION,
        builder_execution_address(deposit.withdrawal_credentials),
        deposit.amount, deposit.slot)
    else:
      # Top up the balance of the existing builder
      state.builders.mitem(opt_builder_index.get).balance += deposit.amount

  assign(state.pending_deposits,
    typeof(state.pending_deposits).init(pending_deposits))

# {.closure.} prevents stack overflow from inline expansion.
# See: https://github.com/nim-lang/Nim/issues/25287
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#new-compute_ptc
iterator compute_ptc*(
    state: gloas.BeaconState | heze.BeaconState, slot: Slot,
    cache: var StateCache): ValidatorIndex {.closure.} =
  ## Get the payload timeliness committee for the given ``slot``.
  let epoch = slot.epoch()
  var buffer {.noinit.}: array[40, byte]
  buffer[0..31] = get_seed(state, epoch, DOMAIN_PTC_ATTESTER).data
  buffer[32..39] = uint_to_bytes(distinctBase(slot))
  let seed = eth2digest(buffer)

  var indices = newSeqOfCap[ValidatorIndex](PTC_SIZE)

  # Concatenate all committees for this slot in order
  let committees_per_slot = get_committee_count_per_slot(state, epoch, cache)
  for committee_index in get_committee_indices(committees_per_slot):
    let committee = get_beacon_committee(state, slot, committee_index, cache)
    indices.add(committee)

  for candidate_index in compute_balance_weighted_selection(
      state, indices, seed, size=PTC_SIZE, shuffle_indices=false):
    yield candidate_index

# {.closure.} prevents stack overflow from inline expansion.
# See: https://github.com/nim-lang/Nim/issues/25287
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#new-get_ptc
iterator get_ptc*(state: gloas.BeaconState | heze.BeaconState, slot: Slot):
    ValidatorIndex {.closure.} =
  ## Get the payload timeliness committee for the given ``slot``
  let
    epoch = slot.epoch()
    state_epoch = get_current_epoch(state)
    slot_in_epoch = slot mod SLOTS_PER_EPOCH

  if epoch < state_epoch and epoch + 1 != state_epoch:
    return
  if epoch >= state_epoch and epoch > state_epoch + MIN_SEED_LOOKAHEAD:
    return

  let index =
    (epoch + 1 - state_epoch).Epoch.start_slot.uint64 + slot_in_epoch

  for idx in state.ptc_window[index]:
    yield ValidatorIndex(idx)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/heze/beacon-chain.md#new-get_inclusion_list_committee
func get_inclusion_list_committee*(
    state: heze.BeaconState, slot: Slot, cache: var StateCache):
    array[int INCLUSION_LIST_COMMITTEE_SIZE, ValidatorIndex] =
  ## Return the inclusion list committee for the given ``slot``, formed by
  ## cycling through that slot's beacon committees.
  let
    epoch = epoch(slot)
    committees_per_slot = get_committee_count_per_slot(state, epoch, cache)
  var indices: seq[ValidatorIndex]
  for i in 0'u64 ..< committees_per_slot:
    indices.add get_beacon_committee(state, slot, CommitteeIndex(i), cache)
  doAssert indices.len > 0, "get_inclusion_list_committee: no active validators"
  var res: array[int INCLUSION_LIST_COMMITTEE_SIZE, ValidatorIndex]
  for i in 0 ..< int INCLUSION_LIST_COMMITTEE_SIZE:
    res[i] = indices[i mod indices.len]
  res

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/fork.md#new-initialize_ptc_window
func initialize_ptc_window(
    state: var gloas.BeaconState, cache: var StateCache) =
  ## Return the cached PTC window starting from the current epoch.
  ## Used to initialize the ``ptc_window`` field in the beacon state
  ## at genesis and after forks.
  let current_epoch = state.get_current_epoch()
  staticFor epoch_offset, 0 .. MIN_SEED_LOOKAHEAD.int:
    let epoch = current_epoch + epoch_offset
    const base_index = (1 + epoch_offset) * SLOTS_PER_EPOCH
    for slot_offset in 0'u64 ..< SLOTS_PER_EPOCH:
      let slot = epoch.start_slot() + slot_offset
      clearCaches(state.ptc_window, (base_index + slot_offset).Limit)
      var i = 0
      for idx in compute_ptc(state, slot, cache):
        state.ptc_window.data[base_index + slot_offset][i] = uint64(idx)
        inc i

# upgrade_to_altair
func upgrade_to_next*(cfg: RuntimeConfig, pre: phase0.BeaconState, _: var StateCache):
    altair.BeaconState =
  var
    empty_participation: EpochParticipationFlags
    inactivity_scores = HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]()

  doAssert empty_participation.asList.setLen(pre.validators.len)

  doAssert inactivity_scores.data.setLen(pre.validators.len)
  inactivity_scores.resetCache()

  template post: untyped = result
  post = altair.BeaconState(
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
  translate_participation(post, pre.previous_epoch_attestations.asSeq)

  # Fill in sync committees
  # Note: A duplicate committee is assigned for the current and next committee
  # at the fork boundary
  post.current_sync_committee = get_next_sync_committee(post)
  post.next_sync_committee = get_next_sync_committee(post)

  # result = post

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/bellatrix/fork.md#upgrading-the-state
# upgrade_to_bellatrix
func upgrade_to_next*(cfg: RuntimeConfig, pre: altair.BeaconState, _: var StateCache):
    bellatrix.BeaconState =
  let epoch = get_current_epoch(pre)
  bellatrix.BeaconState(
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
# upgrade_to_capella
func upgrade_to_next*(cfg: RuntimeConfig, pre: bellatrix.BeaconState, _: var StateCache):
    capella.BeaconState =
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

  capella.BeaconState(
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/deneb/fork.md#upgrading-the-state
# upgrade_to_deneb
func upgrade_to_next*(cfg: RuntimeConfig, pre: capella.BeaconState, _: var StateCache):
    deneb.BeaconState =
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

  deneb.BeaconState(
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/electra/fork.md#upgrading-the-state
# upgrade_to_electra
func upgrade_to_next*(
    cfg: RuntimeConfig, pre: deneb.BeaconState, cache: var StateCache):
    electra.BeaconState =
  let epoch = get_current_epoch(pre)

  var earliest_exit_epoch =
    compute_activation_exit_epoch(get_current_epoch(pre))
  for v in pre.validators:
    if v.exit_epoch != FAR_FUTURE_EPOCH:
      if v.exit_epoch > earliest_exit_epoch:
        earliest_exit_epoch = v.exit_epoch
  earliest_exit_epoch += 1

  template post: untyped = result
  post = electra.BeaconState(
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
    latest_execution_payload_header: pre.latest_execution_payload_header,

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
    get_activation_exit_churn_limit(cfg, post, cache)
  post.consolidation_balance_to_consume =
    get_consolidation_churn_limit(cfg, post, cache)

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
    if has_compounding_withdrawal_credential(type(post).kind, validator):
      queue_excess_active_balance(post, index.uint64)

  # result = post

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/fulu/fork.md#upgrading-the-state
# upgrade_to_fulu
func upgrade_to_next*(
    cfg: RuntimeConfig, pre: electra.BeaconState, cache: var StateCache):
    fulu.BeaconState =
  let epoch = get_current_epoch(pre)

  fulu.BeaconState(
    # Versioning
    genesis_time: pre.genesis_time,
    genesis_validators_root: pre.genesis_validators_root,
    slot: pre.slot,
    fork: Fork(
      previous_version: pre.fork.current_version,
      current_version: cfg.FULU_FORK_VERSION,
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
    latest_execution_payload_header: pre.latest_execution_payload_header,

    # Withdrawals
    next_withdrawal_index: pre.next_withdrawal_index,
    next_withdrawal_validator_index: pre.next_withdrawal_validator_index,

    # Deep history valid from Capella onwards
    historical_summaries: pre.historical_summaries,

    # [New in Electra:EIP6110]
    deposit_requests_start_index: pre.deposit_requests_start_index,

    # [New in Electra:EIP7251]
    deposit_balance_to_consume: pre.deposit_balance_to_consume,
    exit_balance_to_consume: pre.exit_balance_to_consume,
    earliest_exit_epoch: pre.earliest_exit_epoch,
    consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
    earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
    pending_deposits: pre.pending_deposits,
    pending_partial_withdrawals: pre.pending_partial_withdrawals,
    pending_consolidations: pre.pending_consolidations,
    proposer_lookahead: initialize_proposer_lookahead(pre, cache)
  )

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/fork.md#upgrading-the-state
# upgrade_to_gloas
func upgrade_to_next*(
    cfg: RuntimeConfig, pre: fulu.BeaconState, cache: var StateCache):
    gloas.BeaconState =
  let epoch = get_current_epoch(pre)

  const full_execution_payload_availability = block:
    var res: BitArray[int(SLOTS_PER_HISTORICAL_ROOT)]
    for i in 0 ..< res.len:
      setBit(res, i)
    res

  template post: untyped = result
  post = gloas.BeaconState(
    # Versioning
    genesis_time: pre.genesis_time,
    genesis_validators_root: pre.genesis_validators_root,
    slot: pre.slot,
    fork: Fork(
      previous_version: pre.fork.current_version,
      current_version: cfg.GLOAS_FORK_VERSION,
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

    # [Modified in Gloas:EIP7732]
    latest_execution_payload_bid: gloas.ExecutionPayloadBid(
      block_hash: pre.latest_execution_payload_header.block_hash,
      gas_limit: pre.latest_execution_payload_header.gas_limit,
      execution_requests_root:
        hash_tree_root(default(gloas.ExecutionRequests)),
    ),
    next_withdrawal_index: pre.next_withdrawal_index,
    next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
    historical_summaries: pre.historical_summaries,
    deposit_requests_start_index: pre.deposit_requests_start_index,
    deposit_balance_to_consume: pre.deposit_balance_to_consume,
    exit_balance_to_consume: pre.exit_balance_to_consume,
    earliest_exit_epoch: pre.earliest_exit_epoch,
    consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
    earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
    pending_deposits: pre.pending_deposits,
    pending_partial_withdrawals: pre.pending_partial_withdrawals,
    pending_consolidations: pre.pending_consolidations,
    proposer_lookahead: pre.proposer_lookahead,

    # [New in Gloas:EIP7732]
    # builder_pending_payments, builder_pending_withdrawals, and
    # latest_withdrawals_root are default() values; omit.
    execution_payload_availability: full_execution_payload_availability,
    latest_block_hash: pre.latest_execution_payload_header.block_hash
  )
  onboard_builders_from_pending_deposits(cfg, post)
  initialize_ptc_window(post, cache)
  # result = post

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/heze/fork.md#upgrading-the-state
# upgrade_to_heze
func upgrade_to_next*(
    cfg: RuntimeConfig, pre: gloas.BeaconState, _: var StateCache):
    heze.BeaconState =
  let epoch = get_current_epoch(pre)

  heze.BeaconState(
    # Versioning
    genesis_time: pre.genesis_time,
    genesis_validators_root: pre.genesis_validators_root,
    slot: pre.slot,
    fork: Fork(
      previous_version: pre.fork.current_version,
      current_version: cfg.HEZE_FORK_VERSION,
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

    # Execution
    # [Modified in Heze:EIP7805]
    latest_execution_payload_bid: pre.latest_execution_payload_bid,
    next_withdrawal_index: pre.next_withdrawal_index,
    next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
    historical_summaries: pre.historical_summaries,
    deposit_requests_start_index: pre.deposit_requests_start_index,
    deposit_balance_to_consume: pre.deposit_balance_to_consume,
    exit_balance_to_consume: pre.exit_balance_to_consume,
    earliest_exit_epoch: pre.earliest_exit_epoch,
    consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
    earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
    pending_deposits: pre.pending_deposits,
    pending_partial_withdrawals: pre.pending_partial_withdrawals,
    pending_consolidations: pre.pending_consolidations,
    proposer_lookahead: pre.proposer_lookahead,

    # Gloas (ePBS)
    builders: pre.builders,
    next_withdrawal_builder_index: pre.next_withdrawal_builder_index,
    execution_payload_availability: pre.execution_payload_availability,
    builder_pending_payments: pre.builder_pending_payments,
    builder_pending_withdrawals: pre.builder_pending_withdrawals,
    latest_block_hash: pre.latest_block_hash,
    payload_expected_withdrawals: pre.payload_expected_withdrawals,
    ptc_window: pre.ptc_window
  )

func latest_block_root*(state: ForkyBeaconState, state_root: Eth2Digest):
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
    #
    # In Gloas, state_root is filled in process_execution_payload for keeping
    # the block_root hash the same as block, as state_root would be varied after
    # applying an envelope.
    if state.latest_block_header.state_root.isZero:
      var tmp = state.latest_block_header
      tmp.state_root = state_root
      hash_tree_root(tmp)
    else:
      hash_tree_root(state.latest_block_header)
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
           deneb.BeaconState | electra.BeaconState | fulu.BeaconState |
           gloas.BeaconState | heze.BeaconState,
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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/p2p-interface.md#proposer_preferences
func get_proposer_dependent_root*(
    state: ForkyHashedBeaconState, epoch: Epoch): Eth2Digest =
  ## Return the dependent root for the proposer lookahead at ``epoch``.
  if epoch < MIN_SEED_LOOKAHEAD:
    state.dependent_root(GENESIS_EPOCH)
  else:
    state.dependent_root(epoch - MIN_SEED_LOOKAHEAD)

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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#new-get_indexed_payload_attestation
func get_indexed_payload_attestation*(
    state: gloas.BeaconState | heze.BeaconState, slot: Slot,
    payload_attestation: PayloadAttestation): IndexedPayloadAttestation =
  ## Return the indexed payload attestation corresponding to ``payload_attestation``.
  var
    attesting_indices = newSeqOfCap[uint64](PTC_SIZE)
    i = 0

  for index in get_ptc(state, slot):
    if payload_attestation.aggregation_bits[i]:
      attesting_indices.add(index.uint64)
    inc i

  attesting_indices.sort()

  IndexedPayloadAttestation(
    attesting_indices: List[uint64, Limit PTC_SIZE].init(attesting_indices),
    data: payload_attestation.data,
    signature: payload_attestation.signature
  )

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/beacon-chain.md#new-is_valid_indexed_payload_attestation
proc is_valid_indexed_payload_attestation*(
    state: gloas.BeaconState | heze.BeaconState,
    indexed_payload_attestation: IndexedPayloadAttestation): bool =
  ## Check if ``indexed_payload_attestation`` is not empty, has sorted
  ## and unique indices and has a valid aggregate signature.

  # Verify indices are non-empty and sorted
  if indexed_payload_attestation.attesting_indices.len == 0:
    return false

  if not indexed_payload_attestation.attesting_indices.asSeq.isSorted:
    return false

  # Verify aggregate signature
  let
    pubkeys = mapIt(
      indexed_payload_attestation.attesting_indices,
      state.validators[it].pubkey)
    domain = get_domain(
      state.fork, DOMAIN_PTC_ATTESTER,
      indexed_payload_attestation.data.slot.epoch,
      state.genesis_validators_root)
    signing_root = compute_signing_root(
      indexed_payload_attestation.data, domain)

  blsFastAggregateVerify(
    pubkeys, signing_root.data, indexed_payload_attestation.signature)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#new-is_active_builder
func is_active_builder*(
    state: gloas.BeaconState | heze.BeaconState,
    builder_index: BuilderIndex): bool =
  ## Check if the builder at ``builder_index`` is active for the given ``state``.
  if builder_index.uint64 >= state.builders.lenu64:
    return false
  template builder: untyped = state.builders.item(builder_index)

  # Placement in builder list is finalized and has not initiated exit
  builder.deposit_epoch < state.finalized_checkpoint.epoch and
    builder.withdrawable_epoch == FAR_FUTURE_EPOCH

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#new-get_pending_balance_to_withdraw_for_builder
func get_pending_balance_to_withdraw_for_builder*(
    state: gloas.BeaconState | heze.BeaconState, builder_index: BuilderIndex):
    Gwei =
  var sum: Gwei
  for withdrawal in state.builder_pending_withdrawals:
    if withdrawal.builder_index == builder_index:
      sum += withdrawal.amount

  for payment in state.builder_pending_payments:
    if payment.withdrawal.builder_index == builder_index:
      sum += payment.withdrawal.amount

  sum

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#new-can_builder_cover_bid
func can_builder_cover_bid*(
    state: gloas.BeaconState | heze.BeaconState,
    builder_index: BuilderIndex, bid_amount: Gwei): bool =
  let
    builder_balance = state.builders.item(builder_index).balance
    pending_withdrawals_amount =
      get_pending_balance_to_withdraw_for_builder(state, builder_index)
    min_balance = MIN_DEPOSIT_AMOUNT.Gwei + pending_withdrawals_amount
  if builder_balance < min_balance:
    return false
  builder_balance - min_balance >= bid_amount

func proposalExecutionHead*(
    state: gloas.BeaconState | heze.BeaconState): Eth2Digest =
  debugGloasComment "this empirically matches a current testnet gloas provider behavior"
  # `latest_execution_payload_bid` is empty until the first Gloas block's
  # processed; for a Gloas genesis chain, a genesis state generator seeds
  # `latest_block_hash` with the EL genesis block hash.
  if state.latest_execution_payload_bid.block_hash.isZero():
    state.latest_block_hash
  else:
    state.latest_execution_payload_bid.block_hash
