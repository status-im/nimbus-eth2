# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/assign2,
  json_serialization/std/sets,
  chronicles,
  ../extras,
  ./datatypes/[phase0, altair, bellatrix],
  "."/[eth2_merkleization, forks, signatures, validator]

from std/algorithm import fill
from std/sequtils import anyIt, mapIt, toSeq

from ./datatypes/capella import BeaconState, ExecutionPayloadHeader, Withdrawal

export extras, forks, validator, chronicles

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#increase_balance
func increase_balance*(balance: var Gwei, delta: Gwei) =
  balance += delta

func increase_balance*(
    state: var ForkyBeaconState, index: ValidatorIndex, delta: Gwei) =
  ## Increase the validator balance at index ``index`` by ``delta``.
  if delta != 0: # avoid dirtying the balance cache if not needed
    increase_balance(state.balances.mitem(index), delta)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#decrease_balance
func decrease_balance*(balance: var Gwei, delta: Gwei) =
  balance =
    if delta > balance:
      0'u64
    else:
      balance - delta

func decrease_balance*(
    state: var ForkyBeaconState, index: ValidatorIndex, delta: Gwei) =
  ## Decrease the validator balance at index ``index`` by ``delta``, with
  ## underflow protection.
  if delta != 0: # avoid dirtying the balance cache if not needed
    decrease_balance(state.balances.mitem(index), delta)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.3/specs/phase0/beacon-chain.md#deposits
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#modified-apply_deposit
func get_validator_from_deposit*(deposit: DepositData):
    Validator =
  let
    amount = deposit.amount
    effective_balance = min(
      amount - amount mod EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)

  Validator(
    pubkey: deposit.pubkey,
    withdrawal_credentials: deposit.withdrawal_credentials,
    activation_eligibility_epoch: FAR_FUTURE_EPOCH,
    activation_epoch: FAR_FUTURE_EPOCH,
    exit_epoch: FAR_FUTURE_EPOCH,
    withdrawable_epoch: FAR_FUTURE_EPOCH,
    effective_balance: effective_balance
  )

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_activation_exit_epoch
func compute_activation_exit_epoch*(epoch: Epoch): Epoch =
  ## Return the epoch during which validator activations and exits initiated in
  ## ``epoch`` take effect.
  epoch + 1 + MAX_SEED_LOOKAHEAD

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_validator_churn_limit
func get_validator_churn_limit*(
      cfg: RuntimeConfig, state: ForkyBeaconState, cache: var StateCache):
    uint64 =
  ## Return the validator churn limit for the current epoch.
  max(
    cfg.MIN_PER_EPOCH_CHURN_LIMIT,
    count_active_validators(
      state, state.get_current_epoch(), cache) div cfg.CHURN_LIMIT_QUOTIENT)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#new-get_validator_activation_churn_limit
func get_validator_activation_churn_limit*(
      cfg: RuntimeConfig, state: deneb.BeaconState, cache: var StateCache):
    uint64 =
  ## Return the validator activation churn limit for the current epoch.
  min(
    cfg.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT,
    get_validator_churn_limit(cfg, state, cache))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#initiate_validator_exit
func initiate_validator_exit*(
    cfg: RuntimeConfig, state: var ForkyBeaconState,
    index: ValidatorIndex, cache: var StateCache): Result[void, cstring] =
  ## Initiate the exit of the validator with index ``index``.

  if state.validators.item(index).exit_epoch != FAR_FUTURE_EPOCH:
    return ok() # Before touching cache

  # Return if validator already initiated exit
  let validator = addr state.validators.mitem(index)

  trace "Validator exiting",
    index = index,
    num_validators = state.validators.len,
    current_epoch = get_current_epoch(state),
    validator_slashed = validator.slashed,
    validator_withdrawable_epoch = validator.withdrawable_epoch,
    validator_exit_epoch = validator.exit_epoch,
    validator_effective_balance = validator.effective_balance

  var exit_queue_epoch = compute_activation_exit_epoch(get_current_epoch(state))
  # Compute max exit epoch
  for idx in 0..<state.validators.len:
    let exit_epoch = state.validators.item(idx).exit_epoch
    if exit_epoch != FAR_FUTURE_EPOCH and exit_epoch > exit_queue_epoch:
      exit_queue_epoch = exit_epoch

  var
    exit_queue_churn: int
  for idx in 0..<state.validators.len:
    if state.validators.item(idx).exit_epoch == exit_queue_epoch:
      exit_queue_churn += 1

  if exit_queue_churn.uint64 >= get_validator_churn_limit(cfg, state, cache):
    exit_queue_epoch += 1

  # Set validator exit epoch and withdrawable epoch
  validator.exit_epoch = exit_queue_epoch

  if  validator.exit_epoch + cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY <
      validator.exit_epoch:
    return err("initiate_validator_exit: exit_epoch overflowed")

  validator.withdrawable_epoch =
    validator.exit_epoch + cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY

  ok()

from ./datatypes/deneb import BeaconState

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#modified-slash_validator
func get_slashing_penalty*(state: ForkyBeaconState,
                           validator_effective_balance: Gwei): Gwei =
  # TODO Consider whether this is better than splitting the functions apart; in
  # each case, tradeoffs. Here, it's just changing a couple of constants.
  when state is phase0.BeaconState:
      validator_effective_balance div MIN_SLASHING_PENALTY_QUOTIENT
  elif state is altair.BeaconState:
      validator_effective_balance div MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR
  elif state is bellatrix.BeaconState or state is capella.BeaconState or
       state is deneb.BeaconState:
      validator_effective_balance div MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX
  else:
    {.fatal: "invalid BeaconState type".}

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#modified-slash_validator
func get_whistleblower_reward*(validator_effective_balance: Gwei): Gwei =
  validator_effective_balance div WHISTLEBLOWER_REWARD_QUOTIENT

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#modified-slash_validator
func get_proposer_reward(state: ForkyBeaconState, whistleblower_reward: Gwei): Gwei =
  when state is phase0.BeaconState:
    whistleblower_reward div PROPOSER_REWARD_QUOTIENT
  elif state is altair.BeaconState or state is bellatrix.BeaconState or
       state is capella.BeaconState or state is deneb.BeaconState:
    whistleblower_reward * PROPOSER_WEIGHT div WEIGHT_DENOMINATOR
  else:
    {.fatal: "invalid BeaconState type".}

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#modified-slash_validator
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#modified-slash_validator
proc slash_validator*(
    cfg: RuntimeConfig, state: var ForkyBeaconState,
    slashed_index: ValidatorIndex, cache: var StateCache):
    Result[void, cstring] =
  ## Slash the validator with index ``index``.
  let epoch = get_current_epoch(state)
  ? initiate_validator_exit(cfg, state, slashed_index, cache)

  let validator = addr state.validators.mitem(slashed_index)

  trace "slash_validator: ejecting validator via slashing (validator_leaving)",
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
  state.slashings.mitem(int(epoch mod EPOCHS_PER_SLASHINGS_VECTOR)) +=
    validator.effective_balance

  decrease_balance(state, slashed_index,
    get_slashing_penalty(state, validator.effective_balance))

  # The rest doesn't make sense without there being any proposer index, so skip
  let proposer_index = get_beacon_proposer_index(state, cache).valueOr:
    debug "No beacon proposer index and probably no active validators"
    return ok()

  # Apply proposer and whistleblower rewards
  let
    # Spec has whistleblower_index as optional param, but it's never used.
    whistleblower_index = proposer_index
    whistleblower_reward = get_whistleblower_reward(validator.effective_balance)
    proposer_reward = get_proposer_reward(state, whistleblower_reward)

  increase_balance(state, proposer_index, proposer_reward)
  # TODO: evaluate if spec bug / underflow can be triggered
  doAssert(whistleblower_reward >= proposer_reward, "Spec bug: underflow in slash_validator")
  increase_balance(
    state, whistleblower_index, whistleblower_reward - proposer_reward)

  ok()

func genesis_time_from_eth1_timestamp(
    cfg: RuntimeConfig, eth1_timestamp: uint64): uint64 =
  eth1_timestamp + cfg.GENESIS_DELAY

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#genesis-block
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#initialize-state-for-pure-altair-testnets-and-test-vectors
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#testing
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#testing
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

func get_initial_beacon_block*(state: ForkedHashedBeaconState):
    ForkedTrustedSignedBeaconBlock =
  withState(state):
    ForkedTrustedSignedBeaconBlock.init(get_initial_beacon_block(forkyState))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_block_root_at_slot
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_block_root
func get_block_root*(state: ForkyBeaconState, epoch: Epoch): Eth2Digest =
  ## Return the block root at the start of a recent ``epoch``.
  get_block_root_at_slot(state, epoch.start_slot())

func get_block_root(state: ForkedHashedBeaconState, epoch: Epoch): Eth2Digest =
  ## Return the block root at the start of a recent ``epoch``.
  withState(state):
    get_block_root(forkyState.data, epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_total_balance
template get_total_balance(
    state: ForkyBeaconState, validator_indices: untyped): Gwei =
  ## Return the combined effective balance of the ``indices``.
  ## ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
  ## Math safe up to ~10B ETH, after which this overflows uint64.
  var res = 0.Gwei
  for validator_index in validator_indices:
    res += state.validators[validator_index].effective_balance
  max(EFFECTIVE_BALANCE_INCREMENT, res)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_eligible_for_activation_queue
func is_eligible_for_activation_queue*(validator: Validator): bool =
  ## Check if ``validator`` is eligible to be placed into the activation queue.
  validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH and
    validator.effective_balance == MAX_EFFECTIVE_BALANCE

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_eligible_for_activation
func is_eligible_for_activation*(
    state: ForkyBeaconState, validator: Validator): bool =
  ## Check if ``validator`` is eligible for activation.

  # Placement in queue is finalized
  validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch and
  # Has not yet been activated
    validator.activation_epoch == FAR_FUTURE_EPOCH

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
proc is_valid_indexed_attestation*(
    state: ForkyBeaconState, indexed_attestation: SomeIndexedAttestation,
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_attesting_indices
iterator get_attesting_indices_iter*(state: ForkyBeaconState,
                                     data: AttestationData,
                                     bits: CommitteeValidatorsBits,
                                     cache: var StateCache): ValidatorIndex =
  ## Return the set of attesting indices corresponding to ``data`` and ``bits``
  ## or nothing if `data` is invalid
  ## This iterator must not be called in functions using a
  ## ForkedHashedBeaconState due to https://github.com/nim-lang/Nim/issues/18188

  # Can't be an iterator due to https://github.com/nim-lang/Nim/issues/18188
  let committee_index = CommitteeIndex.init(data.index)
  if committee_index.isErr() or bits.lenu64 != get_beacon_committee_len(
      state, data.slot, committee_index.get(), cache):
    trace "get_attesting_indices: invalid attestation data"
  else:
    for index_in_committee, validator_index in get_beacon_committee(
        state, data.slot, committee_index.get(), cache):
      if bits[index_in_committee]:
        yield validator_index

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_attesting_indices
func get_attesting_indices*(state: ForkyBeaconState,
                            data: AttestationData,
                            bits: CommitteeValidatorsBits,
                            cache: var StateCache): seq[ValidatorIndex] =
  ## Return the set of attesting indices corresponding to ``data`` and ``bits``
  ## or nothing if `data` is invalid

  toSeq(get_attesting_indices_iter(state, data, bits, cache))

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

proc is_valid_indexed_attestation(
    state: ForkyBeaconState, attestation: SomeAttestation, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] =
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

# Attestation validation
# ------------------------------------------------------------------------------------------
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#attestations
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id

func check_attestation_slot_target*(data: AttestationData): Result[Slot, cstring] =
  if not (data.target.epoch == epoch(data.slot)):
    return err("Target epoch doesn't match attestation slot")

  ok(data.slot)

func check_attestation_target_epoch(
    data: AttestationData, current_epoch: Epoch): Result[Epoch, cstring] =
  if not (data.target.epoch == get_previous_epoch(current_epoch) or
      data.target.epoch == current_epoch):
    return err("Target epoch not current or previous epoch")

  ok(data.target.epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#attestations
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#modified-process_attestation
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/deneb/beacon-chain.md#modified-process_attestation
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#get_attestation_participation_flag_indices
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#modified-get_attestation_participation_flag_indices
func get_attestation_participation_flag_indices(
    state: deneb.BeaconState,
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_total_active_balance
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#get_base_reward_per_increment
func get_base_reward_per_increment_sqrt(
    total_active_balance_sqrt: uint64): Gwei =
  EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR div total_active_balance_sqrt

func get_base_reward_per_increment*(
    total_active_balance: Gwei): Gwei =
  get_base_reward_per_increment_sqrt(integer_squareroot(total_active_balance))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#get_base_reward
func get_base_reward(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState,
    index: ValidatorIndex, base_reward_per_increment: Gwei): Gwei =
  ## Return the base reward for the validator defined by ``index`` with respect
  ## to the current ``state``.
  let increments =
    state.validators[index].effective_balance div EFFECTIVE_BALANCE_INCREMENT
  increments * base_reward_per_increment

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#attestations
proc check_attestation*(
    state: ForkyBeaconState, attestation: SomeAttestation, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] =
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#new-process_bls_to_execution_change
proc check_bls_to_execution_change*(
    genesisFork: Fork, state: capella.BeaconState | deneb.BeaconState,
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

func get_proposer_reward*(state: ForkyBeaconState,
                          attestation: SomeAttestation,
                          base_reward_per_increment: Gwei,
                          cache: var StateCache,
                          epoch_participation: var EpochParticipationFlags): uint64 =
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

  return result div proposer_reward_denominator

proc process_attestation*(
    state: var ForkyBeaconState, attestation: SomeAttestation, flags: UpdateFlags,
    base_reward_per_increment: Gwei, cache: var StateCache):
    Result[void, cstring] =
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
  elif state is altair.BeaconState or state is bellatrix.BeaconState or
       state is capella.BeaconState or state is deneb.BeaconState:
    template updateParticipationFlags(epoch_participation: untyped) =
      let proposer_reward = get_proposer_reward(
        state, attestation, base_reward_per_increment, cache, epoch_participation)
      increase_balance(state, proposer_index, proposer_reward)

    doAssert base_reward_per_increment > 0.Gwei
    if attestation.data.target.epoch == get_current_epoch(state):
      updateParticipationFlags(state.current_epoch_participation)
    else:
      updateParticipationFlags(state.previous_epoch_participation)
  else:
    static: doAssert false

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#get_next_sync_committee_indices
func get_next_sync_committee_keys(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState):
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
    if effective_balance * MAX_RANDOM_BYTE >= MAX_EFFECTIVE_BALANCE * random_byte:
      res[index] = state.validators[candidate_index].pubkey
      inc index
    i += 1'u64
  res

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#has_eth1_withdrawal_credential
func has_eth1_withdrawal_credential*(validator: Validator): bool =
  ## Check if ``validator`` has an 0x01 prefixed "eth1" withdrawal credential.
  validator.withdrawal_credentials.data[0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#is_fully_withdrawable_validator
func is_fully_withdrawable_validator(
    validator: Validator, balance: Gwei, epoch: Epoch): bool =
  ## Check if ``validator`` is fully withdrawable.
  has_eth1_withdrawal_credential(validator) and
    validator.withdrawable_epoch <= epoch and balance > 0

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#is_partially_withdrawable_validator
func is_partially_withdrawable_validator(
    validator: Validator, balance: Gwei): bool =
  ## Check if ``validator`` is partially withdrawable.
  let
    has_max_effective_balance =
      validator.effective_balance == MAX_EFFECTIVE_BALANCE
    has_excess_balance = balance > MAX_EFFECTIVE_BALANCE
  has_eth1_withdrawal_credential(validator) and
    has_max_effective_balance and has_excess_balance

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#new-get_expected_withdrawals
func get_expected_withdrawals*(
    state: capella.BeaconState | deneb.BeaconState): seq[Withdrawal] =
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#get_next_sync_committee
func get_next_sync_committee*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState):
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
    eth1_data:
      Eth1Data(block_hash: eth1_block_hash, deposit_count: uint64(len(deposits))),
    latest_block_header:
      BeaconBlockHeader(
        body_root: hash_tree_root(default(phase0.BeaconBlockBody))))

  # Seed RANDAO with Eth1 entropy
  state.randao_mixes.fill(eth1_block_hash)

  var merkleizer = createMerkleizer(DEPOSIT_CONTRACT_LIMIT)
  for i, deposit in deposits:
    let htr = hash_tree_root(deposit)
    merkleizer.addChunk(htr.data)

  # This is already known in the Eth1 monitor, but it would be too
  # much work to refactor all the existing call sites in the test suite
  state.eth1_data.deposit_root = mixInLength(merkleizer.getFinalHash(),
                                             deposits.len)
  state.eth1_deposit_index = deposits.lenu64

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
        if not state.validators.add(get_validator_from_deposit(deposit)):
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
      balance - balance mod EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)

    if validator.effective_balance == MAX_EFFECTIVE_BALANCE:
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#testing
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#testing
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
      block_hash: eth1_block_hash, deposit_count: uint64(len(deposits))),
    latest_block_header: BeaconBlockHeader(
      body_root: hash_tree_root(default consensusFork.BeaconBlockBody)))

  # Seed RANDAO with Eth1 entropy
  state.randao_mixes.data.fill(eth1_block_hash)

  var merkleizer = createMerkleizer(DEPOSIT_CONTRACT_LIMIT)
  for i, deposit in deposits:
    let htr = hash_tree_root(deposit)
    merkleizer.addChunk(htr.data)

  # This is already known in the Eth1 monitor, but it would be too
  # much work to refactor all the existing call sites in the test suite
  state.eth1_data.deposit_root = mixInLength(merkleizer.getFinalHash(),
                                             deposits.len)
  state.eth1_deposit_index = deposits.lenu64

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
        if not state.validators.add(get_validator_from_deposit(deposit)):
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
      balance - balance mod EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)

    if validator.effective_balance == MAX_EFFECTIVE_BALANCE:
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/fork.md#upgrading-the-state
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
           deneb.BeaconState,
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
