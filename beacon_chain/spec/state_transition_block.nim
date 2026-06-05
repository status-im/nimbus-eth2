# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# State transition - block processing as described in
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#block-processing
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/altair/beacon-chain.md#block-processing
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/bellatrix/beacon-chain.md#block-processing
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/capella/beacon-chain.md#block-processing
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/deneb/beacon-chain.md#block-processing
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/electra/beacon-chain.md#block-processing
#
# The entry point is `process_block` which is at the bottom of this file.
#
# General notes about the code:
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * When updating the code, add TODO sections to mark where there are clear
#   improvements to be made - other than that, keep things similar to spec unless
#   motivated by security or performance considerations

import
  chronicles,
  ../extras,
  ./[beaconstate, eth2_merkleization, forks, helpers, validator, signatures],
  kzg4844/kzg_abi, kzg4844/kzg

from std/algorithm import fill, sorted
from std/sequtils import count, foldl, filterIt, mapIt

export extras, phase0, altair

template payload(body: SomeForkyBeaconBlockBody | SomeForkyBlindedBeaconBlockBody): auto =
  # Blinded blocks contain a payload header instead of the full execution
  # payload - where relevant, we assume the blinded parts are valid and just
  # process the consensus-relevant parts.
  when body is SomeForkyBlindedBeaconBlockBody:
    body.execution_payload_header
  else:
    body.execution_payload

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#block-header
func process_block_header*(
    state: var ForkyBeaconState,
    blck: SomeForkyBeaconBlock | SomeForkyBlindedBeaconBlock,
    flags: UpdateFlags, cache: var StateCache): Result[void, cstring] =
  # Verify that the slots match
  if not (blck.slot == state.slot):
    return err("process_block_header: slot mismatch")

  # Verify that the block is newer than latest block header
  if not (blck.slot > state.latest_block_header.slot):
    return err("process_block_header: block not newer than latest block header")

  let proposer_index = get_beacon_proposer_index(state, cache).valueOr:
    return err("process_block_header: proposer missing")

  if not (blck.proposer_index == proposer_index):
    return err("process_block_header: proposer index incorrect")

  # Verify that the parent matches
  if not (blck.parent_root == hash_tree_root(state.latest_block_header)):
    return err("process_block_header: previous block root mismatch")

  # Verify proposer is not slashed
  if state.validators.item(blck.proposer_index).slashed:
    return err("process_block_header: proposer slashed")

  # Cache current block as the new latest block
  state.latest_block_header = BeaconBlockHeader(
    slot: blck.slot,
    proposer_index: blck.proposer_index,
    parent_root: blck.parent_root,
    # state_root: zeroed, overwritten in the next `process_slot` call
    body_root: hash_tree_root(blck.body),
  )

  ok()

func `xor`[T: array](a, b: T): T =
  for i in 0..<result.len:
    result[i] = a[i] xor b[i]

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/phase0/beacon-chain.md#randao
proc process_randao(
    state: var ForkyBeaconState,
    body: SomeForkyBeaconBlockBody | SomeForkyBlindedBeaconBlockBody,
    flags: UpdateFlags, cache: var StateCache): Result[void, cstring] =
  let
    proposer_index = get_beacon_proposer_index(state, cache).valueOr:
      return err("process_randao: proposer index missing, probably along with any active validators")

  # Verify RANDAO reveal
  let epoch = state.get_current_epoch()

  if skipBlsValidation notin flags and body.randao_reveal isnot TrustedSig:
    let proposer_pubkey = state.validators.item(proposer_index).pubkey

    # `state_transition.makeBeaconBlock` ensures this is run with a trusted
    # signature, but unless the full skipBlsValidation is specified, RANDAO
    # epoch signatures still have to be verified.
    if not verify_epoch_signature(
        state.fork, state.genesis_validators_root, epoch, proposer_pubkey,
        body.randao_reveal):

      return err("process_randao: invalid epoch signature")

  # Mix in RANDAO reveal
  let
    mix = get_randao_mix(state, epoch)
    rr = eth2digest(body.randao_reveal.toRaw()).data

  state.randao_mixes.mitem(epoch mod EPOCHS_PER_HISTORICAL_VECTOR).data =
    mix.data xor rr

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#eth1-data
func process_eth1_data(
    state: var ForkyBeaconState,
    body: SomeForkyBeaconBlockBody | SomeForkyBlindedBeaconBlockBody
): Result[void, cstring] =
  if not state.eth1_data_votes.add body.eth1_data:
    # Count is reset  in process_final_updates, so this should never happen
    return err("process_eth1_data: no more room for eth1 data")

  if state.eth1_data_votes.asSeq.count(body.eth1_data).uint64 * 2 >
      SLOTS_PER_ETH1_VOTING_PERIOD:
    state.eth1_data = body.eth1_data
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#is_slashable_validator
func is_slashable_validator(validator: Validator, epoch: Epoch): bool =
  # Check if ``validator`` is slashable.
  (not validator.slashed) and
    (validator.activation_epoch <= epoch) and
    (epoch < validator.withdrawable_epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#proposer-slashings
proc check_proposer_slashing*(
    state: ForkyBeaconState, proposer_slashing: SomeProposerSlashing,
    flags: UpdateFlags):
    Result[ValidatorIndex, cstring] =

  let
    header_1 = proposer_slashing.signed_header_1.message
    header_2 = proposer_slashing.signed_header_2.message

  # Verify header slots match
  if not (header_1.slot == header_2.slot):
    return err("check_proposer_slashing: slot mismatch")

  # Verify header proposer indices match
  if not (header_1.proposer_index == header_2.proposer_index):
    return err("check_proposer_slashing: proposer indices mismatch")

  # Verify the headers are different
  if not (header_1 != header_2):
    return err("check_proposer_slashing: headers not different")

  # Verify the proposer is slashable
  if header_1.proposer_index >= state.validators.lenu64:
    return err("check_proposer_slashing: invalid proposer index")

  let proposer = unsafeAddr state.validators[header_1.proposer_index]
  if not is_slashable_validator(proposer[], get_current_epoch(state)):
    return err("check_proposer_slashing: slashed proposer")

  # Verify signatures
  if skipBlsValidation notin flags:
    for signed_header in [proposer_slashing.signed_header_1,
        proposer_slashing.signed_header_2]:
      if not verify_block_signature(
          state.fork, state.genesis_validators_root, signed_header.message.slot,
          signed_header.message, proposer[].pubkey,
          signed_header.signature):
        return err("check_proposer_slashing: invalid signature")

  # Verified above against state.validators
  ValidatorIndex.init(header_1.proposer_index)

proc check_proposer_slashing*(
    state: var ForkedHashedBeaconState, proposer_slashing: SomeProposerSlashing,
    flags: UpdateFlags): Result[ValidatorIndex, cstring] =
  withState(state):
    check_proposer_slashing(forkyState.data, proposer_slashing, flags)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#proposer-slashings
# https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/beacon-chain.md#modified-process_proposer_slashing
proc process_proposer_slashing*(
    cfg: RuntimeConfig, state: var ForkyBeaconState,
    proposer_slashing: SomeProposerSlashing, flags: UpdateFlags,
    exit_queue_info: ExitQueueInfo, cache: var StateCache):
    Result[(Gwei, ExitQueueInfo), cstring] =
  let proposer_index = ? check_proposer_slashing(state, proposer_slashing, flags)

  # [New in Gloas:EIP7732]
  # Remove the BuilderPendingPayment corresponding to
  # this proposal if it is still in the 2-epoch window.
  when typeof(state).kind >= ConsensusFork.Gloas:
    let
      slot = proposer_slashing.signed_header_1.message.slot
      proposal_epoch = slot.epoch()
      current_epoch = get_current_epoch(state)

    if proposal_epoch == current_epoch:
      let payment_index = SLOTS_PER_EPOCH + (slot mod SLOTS_PER_EPOCH)
      state.builder_pending_payments[payment_index.int] =
        BuilderPendingPayment()
    elif proposal_epoch == get_previous_epoch(state):
      let payment_index = slot mod SLOTS_PER_EPOCH
      state.builder_pending_payments[payment_index.int] =
        BuilderPendingPayment()
  slash_validator(cfg, state, proposer_index, exit_queue_info, cache)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/phase0/beacon-chain.md#is_slashable_attestation_data
func is_slashable_attestation_data(
    data_1: AttestationData, data_2: AttestationData): bool =
  ## Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG
  ## rules.

  # Double vote
  (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
  # Surround vote
    (data_1.source.epoch < data_2.source.epoch and
     data_2.target.epoch < data_1.target.epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/phase0/beacon-chain.md#attester-slashings
proc check_attester_slashing*(
    state: ForkyBeaconState,
    # phase0.SomeAttesterSlashing | electra.SomeAttesterSlashing:
    # https://github.com/nim-lang/Nim/issues/18095
    attester_slashing:
      phase0.AttesterSlashing | phase0.TrustedAttesterSlashing |
      electra.AttesterSlashing | electra.TrustedAttesterSlashing,
    flags: UpdateFlags): Result[seq[ValidatorIndex], cstring] =
  let
    attestation_1 = attester_slashing.attestation_1
    attestation_2 = attester_slashing.attestation_2

  if not is_slashable_attestation_data(
      attestation_1.data, attestation_2.data):
    return err("Attester slashing: surround or double vote check failed")

  if not is_valid_indexed_attestation(state, attestation_1, flags).isOk():
    return err("Attester slashing: invalid attestation 1")

  if not is_valid_indexed_attestation(state, attestation_2, flags).isOk():
    return err("Attester slashing: invalid attestation 2")

  var slashed_indices: seq[ValidatorIndex]

  let attesting_indices_2 = toHashSet(attestation_2.attesting_indices.asSeq)
  for index in sorted(filterIt(
      attestation_1.attesting_indices.asSeq, it in attesting_indices_2),
      system.cmp):
    if is_slashable_validator(
        state.validators[index], get_current_epoch(state)):
      slashed_indices.add ValidatorIndex.init(index).expect(
        "checked by is_valid_indexed_attestation")

  if slashed_indices.len == 0:
    return err("Attester slashing: Trying to slash participant(s) twice")

  ok slashed_indices

proc check_attester_slashing*(
    state: var ForkedHashedBeaconState,
    # phase0.SomeAttesterSlashing | electra.SomeAttesterSlashing:
    # https://github.com/nim-lang/Nim/issues/18095
    attester_slashing:
      phase0.AttesterSlashing | phase0.TrustedAttesterSlashing |
      electra.AttesterSlashing | electra.TrustedAttesterSlashing,
    flags: UpdateFlags): Result[seq[ValidatorIndex], cstring] =
  withState(state):
    check_attester_slashing(forkyState.data, attester_slashing, flags)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#attester-slashings
proc process_attester_slashing*(
    cfg: RuntimeConfig,
    state: var ForkyBeaconState,
    # phase0.SomeAttesterSlashing | electra.SomeAttesterSlashing:
    # https://github.com/nim-lang/Nim/issues/18095
    attester_slashing:
      phase0.AttesterSlashing | phase0.TrustedAttesterSlashing |
      electra.AttesterSlashing | electra.TrustedAttesterSlashing,
    flags: UpdateFlags,
    exit_queue_info: ExitQueueInfo, cache: var StateCache
    ): Result[(Gwei, ExitQueueInfo), cstring] =
  let slashed_attesters =
    ? check_attester_slashing(state, attester_slashing, flags)

  var
    proposer_reward: Gwei
    cur_exit_queue_info = exit_queue_info

  for index in slashed_attesters:
    doAssert strictVerification notin flags or
      cur_exit_queue_info == get_state_exit_queue_info(state)
    let (new_proposer_reward, new_exit_queue_info) = ? slash_validator(
      cfg, state, index, cur_exit_queue_info, cache)
    proposer_reward += new_proposer_reward
    cur_exit_queue_info = new_exit_queue_info

  ok((proposer_reward, cur_exit_queue_info))

from ".."/validator_bucket_sort import
  BucketSortedValidators, add, findValidatorIndex, sortValidatorBuckets

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#new-is_pending_validator
func get_pending_validators*(
    cfg: RuntimeConfig, state: gloas.BeaconState | heze.BeaconState,
    pubkeys: HashSet[ValidatorPubKey]): HashSet[ValidatorPubKey] =
  ## Return the subset of `pubkeys` with a valid pending deposit signature in the
  ## queue.
  ##
  ## Restricted to processed deposit requests to avoid unnecessary BLS verifies.
  if pubkeys.len == 0:
    return static(default(HashSet[ValidatorPubKey]))
  var res: HashSet[ValidatorPubKey]
  for pending_deposit in state.pending_deposits:
    if  pending_deposit.pubkey in pubkeys and
        pending_deposit.pubkey notin res and verify_deposit_signature(
          cfg.GENESIS_FORK_VERSION,
          DepositData(
            pubkey: pending_deposit.pubkey,
            withdrawal_credentials: pending_deposit.withdrawal_credentials,
            amount: pending_deposit.amount,
            signature: pending_deposit.signature)):
      res.incl(pending_deposit.pubkey)
  res

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/phase0/beacon-chain.md#deposits
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/specs/electra/beacon-chain.md#modified-apply_deposit
proc apply_deposit(
    cfg: RuntimeConfig, state: var ForkyBeaconState,
    bucketSortedValidators: var BucketSortedValidators,
    deposit_data: DepositData, flags: UpdateFlags): Result[void, cstring] =
  let
    pubkey = deposit_data.pubkey
    amount = deposit_data.amount
    index = findValidatorIndex(
      state.validators.asSeq, bucketSortedValidators, pubkey)

  if index.isSome():
    # Increase balance by deposit amount
    when typeof(state).kind < ConsensusFork.Electra:
      increase_balance(state, index.get(), amount)
    else:
      discard state.pending_deposits.add PendingDeposit(
        pubkey: pubkey,
        withdrawal_credentials: deposit_data.withdrawal_credentials,
        amount: amount,
        signature: deposit_data.signature,
        # Use GENESIS_SLOT to distinguish from a pending deposit request
        slot: GENESIS_SLOT)
  else:
    # Verify the deposit signature (proof of possession) which is not checked
    # by the deposit contract
    if verify_deposit_signature(cfg.GENESIS_FORK_VERSION, deposit_data):
      when typeof(state).kind >= ConsensusFork.Electra:
        ? add_validator_to_registry(state, deposit_data, 0.Gwei)
        let new_vidx = state.validators.lenu64 - 1
        # [New in Electra:EIP7251]
        discard state.pending_deposits.add PendingDeposit(
          pubkey: pubkey,
          withdrawal_credentials: deposit_data.withdrawal_credentials,
          amount: amount,
          signature: deposit_data.signature,
          slot: GENESIS_SLOT)
      else:
        ? add_validator_to_registry(state, deposit_data, deposit_data.amount)
        let new_vidx = state.validators.lenu64 - 1
      doAssert state.validators.len == state.balances.len
      bucketSortedValidators.add new_vidx.ValidatorIndex
    else:
      # Deposits may come with invalid signatures - in that case, they are not
      # turned into a validator but still get processed to keep the deposit
      # index correct
      trace "Skipping deposit with invalid signature",
        deposit = shortLog(deposit_data)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#deposits
proc process_deposit*(
    cfg: RuntimeConfig, state: var ForkyBeaconState,
    bucketSortedValidators: var BucketSortedValidators,
    deposit: Deposit, flags: UpdateFlags):
    Result[void, cstring] =
  ## Process an Eth1 deposit, registering a validator or increasing its balance.

  # Verify the Merkle branch
  if not is_valid_merkle_branch(
    hash_tree_root(deposit.data),
    deposit.proof,
    DEPOSIT_CONTRACT_TREE_DEPTH + 1,  # Add 1 for the `List` length mix-in
    state.eth1_deposit_index,
    state.eth1_data.deposit_root,
  ):
    return err("process_deposit: deposit Merkle validation failed")

  # Deposits must be processed in order
  state.eth1_deposit_index += 1

  apply_deposit(cfg, state, bucketSortedValidators, deposit.data, flags)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/electra/beacon-chain.md#new-process_deposit_request
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/fulu/beacon-chain.md#modified-process_deposit_request
func process_deposit_request*(
    cfg: RuntimeConfig,
    state: var (electra.BeaconState | fulu.BeaconState),
    deposit_request: DepositRequest,
    flags: UpdateFlags): Result[void, cstring] =
  when state is electra.BeaconState:
    # Set deposit request start index
    if state.deposit_requests_start_index ==
        UNSET_DEPOSIT_REQUESTS_START_INDEX:
      state.deposit_requests_start_index = deposit_request.index

  # Create pending deposit
  if state.pending_deposits.add(PendingDeposit(
      pubkey: deposit_request.pubkey,
      withdrawal_credentials: deposit_request.withdrawal_credentials,
      amount: deposit_request.amount,
      signature: deposit_request.signature,
      slot: state.slot)):
    ok()
  else:
    err("process_deposit_request: couldn't add deposit to pending_deposits")

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#modified-process_deposit_request
func process_deposit_request*(
    cfg: RuntimeConfig, state: var (gloas.BeaconState | heze.BeaconState),
    bucket_sorted_validators: BucketSortedValidators,
    bucket_sorted_builders: var BucketSortedValidators,
    pending_validators: var HashSet[ValidatorPubKey],
    deposit_request: DepositRequest,
    flags: UpdateFlags): Result[void, cstring] =
  # [New in Gloas:EIP7732]
  # Regardless of the withdrawal credentials prefix, if a builder/validator
  # already exists with this pubkey, apply the deposit to their balance
  let
    is_builder = findValidatorIndex(
      state.builders.asSeq, bucket_sorted_builders,
      deposit_request.pubkey).isOk()
    is_validator = findValidatorIndex(
      state.validators.asSeq, bucket_sorted_validators,
      deposit_request.pubkey).isOk()
    is_builder_prefix =
      is_builder_withdrawal_credential(deposit_request.withdrawal_credentials)
  if is_builder or (is_builder_prefix and not is_validator and
      deposit_request.pubkey notin pending_validators):
    # Apply builder deposits immediately
    apply_deposit_for_builder(
      cfg, state, bucket_sorted_builders, deposit_request.pubkey,
      deposit_request.withdrawal_credentials, deposit_request.amount,
      deposit_request.signature, state.slot)
    return ok()

  # Add validator deposits to the queue
  if state.pending_deposits.add(PendingDeposit(
      pubkey: deposit_request.pubkey,
      withdrawal_credentials: deposit_request.withdrawal_credentials,
      amount: deposit_request.amount,
      signature: deposit_request.signature,
      slot: state.slot)):
    if verify_deposit_signature(
        cfg.GENESIS_FORK_VERSION,
        DepositData(
          pubkey: deposit_request.pubkey,
          withdrawal_credentials: deposit_request.withdrawal_credentials,
          amount: deposit_request.amount,
          signature: deposit_request.signature)):
      pending_validators.incl(deposit_request.pubkey)
    ok()
  else:
    err("process_deposit_request: couldn't add deposit to pending_deposits")

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#voluntary-exits
# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/deneb/beacon-chain.md#modified-process_voluntary_exit
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/electra/beacon-chain.md#modified-process_voluntary_exit
proc check_voluntary_exit*(
    cfg: RuntimeConfig,
    state: ForkyBeaconState,
    signed_voluntary_exit: SomeSignedVoluntaryExit,
    flags: UpdateFlags): Result[ValidatorIndex, cstring] =

  template voluntary_exit: untyped = signed_voluntary_exit.message

  if voluntary_exit.validator_index >= state.validators.lenu64:
    return err("Exit: invalid validator index")

  let validator = unsafeAddr state.validators[voluntary_exit.validator_index]

  # Verify the validator is active
  if not is_active_validator(validator[], get_current_epoch(state)):
    return err("Exit: validator not active")

  # Verify exit has not been initiated
  if validator[].exit_epoch != FAR_FUTURE_EPOCH:
    return err("Exit: validator has exited")

  # Exits must specify an epoch when they become valid; they are not valid
  # before then
  if not (get_current_epoch(state) >= voluntary_exit.epoch):
    return err("Exit: exit epoch not passed")

  # Verify the validator has been active long enough
  if not (get_current_epoch(state) >= validator[].activation_epoch +
      cfg.SHARD_COMMITTEE_PERIOD):
    return err("Exit: not in validator set long enough")

  when typeof(state).kind >= ConsensusFork.Electra:
    # Only exit validator if it has no pending withdrawals in the queue
    if not (get_pending_balance_to_withdraw(
        state, voluntary_exit.validator_index.ValidatorIndex) == 0.Gwei):
      return err("Exit: still has pending withdrawals")

  # Verify signature
  if skipBlsValidation notin flags:
    const consensusFork = typeof(state).kind
    let voluntary_exit_fork = consensusFork.voluntary_exit_signature_fork(
      state.fork, cfg.CAPELLA_FORK_VERSION)
    if not verify_voluntary_exit_signature(
        voluntary_exit_fork, state.genesis_validators_root, voluntary_exit,
        validator[].pubkey, signed_voluntary_exit.signature):
      return err("Exit: invalid signature")

  # Checked above
  ValidatorIndex.init(voluntary_exit.validator_index)

proc check_voluntary_exit*(
    cfg: RuntimeConfig, state: ForkedHashedBeaconState,
    signed_voluntary_exit: SomeSignedVoluntaryExit,
    flags: UpdateFlags): Result[ValidatorIndex, cstring] =
  withState(state):
    check_voluntary_exit(cfg, forkyState.data, signed_voluntary_exit, flags)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#voluntary-exits
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#updated-process_voluntary_exit
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#modified-process_voluntary_exit
proc process_voluntary_exit*(
    cfg: RuntimeConfig,
    state: var ForkyBeaconState,
    signed_voluntary_exit: SomeSignedVoluntaryExit,
    flags: UpdateFlags, exit_queue_info: ExitQueueInfo,
    cache: var StateCache): Result[ExitQueueInfo, cstring] =

  when typeof(state).kind >= ConsensusFork.Gloas:
    template voluntary_exit: untyped = signed_voluntary_exit.message
    if is_builder_index(voluntary_exit.validator_index):
      if not (get_current_epoch(state) >= voluntary_exit.epoch):
        return err("Exit: exit epoch not passed")
      let builder_index =
        convert_validator_index_to_builder_index(
          voluntary_exit.validator_index)
      if not is_active_builder(state, builder_index):
        return err("Exit: builder not active")
      if get_pending_balance_to_withdraw_for_builder(
          state, builder_index) != 0.Gwei:
        return err("Exit: builder has pending withdrawals")
      let voluntary_exit_fork = typeof(state).kind.voluntary_exit_signature_fork(
        state.fork, cfg.CAPELLA_FORK_VERSION)
      if not verify_voluntary_exit_signature(
          voluntary_exit_fork, state.genesis_validators_root, voluntary_exit,
          state.builders.item(builder_index).pubkey,
          signed_voluntary_exit.signature):
        return err("Exit: invalid builder signature")
      initiate_builder_exit(cfg, state, builder_index)
      return ok(exit_queue_info)

  let exited_validator =
    ? check_voluntary_exit(cfg, state, signed_voluntary_exit, flags)
  ok(? initiate_validator_exit(
    cfg, state, exited_validator, exit_queue_info, cache))

proc process_bls_to_execution_change*(
    cfg: RuntimeConfig,
    state: var (capella.BeaconState | deneb.BeaconState | electra.BeaconState |
                fulu.BeaconState | gloas.BeaconState | heze.BeaconState),
    signed_address_change: SignedBLSToExecutionChange): Result[void, cstring] =
  ? check_bls_to_execution_change(
    cfg.GENESIS_FORK_VERSION, state, signed_address_change, {})
  let address_change = signed_address_change.message
  var withdrawal_credentials =
    state.validators.item(address_change.validator_index).withdrawal_credentials

  withdrawal_credentials.data[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX
  withdrawal_credentials.data.fill(1, 11, 0)
  withdrawal_credentials.data[12..31] =
    address_change.to_execution_address.data
  state.validators.mitem(address_change.validator_index).withdrawal_credentials =
    withdrawal_credentials

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#new-process_withdrawal_request
func process_withdrawal_request*(
    cfg: RuntimeConfig,
    state: var (electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
                heze.BeaconState),
    bucketSortedValidators: BucketSortedValidators,
    withdrawal_request: WithdrawalRequest, cache: var StateCache) =
  let
    amount = withdrawal_request.amount
    is_full_exit_request = amount == static(FULL_EXIT_REQUEST_AMOUNT.Gwei)

  # If partial withdrawal queue is full, only full exits are processed
  if lenu64(state.pending_partial_withdrawals) ==
      PENDING_PARTIAL_WITHDRAWALS_LIMIT and not is_full_exit_request:
    return

  let
    request_pubkey = withdrawal_request.validator_pubkey
    # Verify pubkey exists
    index = findValidatorIndex(
        state.validators.asSeq, bucketSortedValidators,
        request_pubkey).valueOr:
      return
    validator = state.validators.item(index)

  # Verify withdrawal credentials
  let
    has_correct_credential = has_execution_withdrawal_credential(type(state).kind, validator)
    is_correct_source_address =
      validator.withdrawal_credentials.data.toOpenArray(12, 31) ==
        withdrawal_request.source_address.data

  if not (has_correct_credential and is_correct_source_address):
    return

  # Verify the validator is active
  if not is_active_validator(validator, get_current_epoch(state)):
    return

  # Verify exit has not been initiated
  if validator.exit_epoch != FAR_FUTURE_EPOCH:
    return

  # Verify the validator has been active long enough
  if get_current_epoch(state) <
      validator.activation_epoch + cfg.SHARD_COMMITTEE_PERIOD:
    return

  let pending_balance_to_withdraw =
    get_pending_balance_to_withdraw(state, index)

  if is_full_exit_request:
    # Only exit validator if it has no pending withdrawals in the queue
    if pending_balance_to_withdraw == 0.Gwei:
      discard initiate_validator_exit(cfg, state, index, ExitQueueInfo(), cache)
    return

  let
    has_sufficient_effective_balance =
      validator.effective_balance >= static(MIN_ACTIVATION_BALANCE.Gwei)
    has_excess_balance = state.balances.item(index) >
      static(MIN_ACTIVATION_BALANCE.Gwei) + pending_balance_to_withdraw

  # Only allow partial withdrawals with compounding withdrawal credentials
  if  has_compounding_withdrawal_credential(type(state).kind, validator) and
      has_sufficient_effective_balance and has_excess_balance:
    let
      to_withdraw = min(
        state.balances.item(index) - static(MIN_ACTIVATION_BALANCE.Gwei) -
          pending_balance_to_withdraw,
        amount
      )
      exit_queue_epoch =
        compute_exit_epoch_and_update_churn(cfg, state, to_withdraw, cache)
      withdrawable_epoch =
        exit_queue_epoch + cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY

    # In theory can fail, but failing/early returning here is indistinguishable
    discard state.pending_partial_withdrawals.add(PendingPartialWithdrawal(
      validator_index: index.uint64,
      amount: to_withdraw,
      withdrawable_epoch: withdrawable_epoch,
    ))

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/electra/beacon-chain.md#new-is_valid_switch_to_compounding_request
func is_valid_switch_to_compounding_request(
    state: electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
           heze.BeaconState,
    consolidation_request: ConsolidationRequest,
    source_validator: Validator): bool =
  # Switch to compounding requires source and target be equal
  if consolidation_request.source_pubkey != consolidation_request.target_pubkey:
    return false

  # process_consolidation_request() verifies pubkey exists

  # Verify request has been authorized
  if source_validator.withdrawal_credentials.data.toOpenArray(12, 31) !=
      consolidation_request.source_address.data:
    return false

  # Verify source withdrawal credentials
  if not has_eth1_withdrawal_credential(source_validator):
    return false

  # Verify the source is active
  let current_epoch = get_current_epoch(state)
  if not is_active_validator(source_validator, current_epoch):
    return false

  # Verify exit for source has not been initiated
  if source_validator.exit_epoch != FAR_FUTURE_EPOCH:
    return false

  true

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/electra/beacon-chain.md#new-process_consolidation_request
func process_consolidation_request*(
    cfg: RuntimeConfig,
    state: var (electra.BeaconState | fulu.BeaconState | gloas.BeaconState |
                heze.BeaconState),
    bucketSortedValidators: BucketSortedValidators,
    consolidation_request: ConsolidationRequest,
    cache: var StateCache) =
  let
    request_source_pubkey = consolidation_request.source_pubkey
    source_index = findValidatorIndex(
        state.validators.asSeq, bucketSortedValidators,
        request_source_pubkey).valueOr:
      return

  if is_valid_switch_to_compounding_request(
      state, consolidation_request, state.validators.item(source_index)):
    switch_to_compounding_validator(state, source_index)
    return

  # Verify that source != target, so a consolidation cannot be used as an exit.
  if  consolidation_request.source_pubkey ==
      consolidation_request.target_pubkey:
    return

  # If the pending consolidations queue is full, consolidation requests are
  # ignored
  if  len(state.pending_consolidations) ==
      static(PENDING_CONSOLIDATIONS_LIMIT.int):
    return

  # If there is too little available consolidation churn limit, consolidation
  # requests are ignored
  if  get_consolidation_churn_limit(cfg, state, cache) <=
      static(MIN_ACTIVATION_BALANCE.Gwei):
    return

  # Verify pubkeys exists (source already verified)
  let target_index = findValidatorIndex(
      state.validators.asSeq, bucketSortedValidators,
      consolidation_request.target_pubkey).valueOr:
    return

  let
    source_validator = addr state.validators.mitem(source_index)
    target_validator = state.validators.item(target_index)

  # Verify source withdrawal credentials
  let
    has_correct_credential =
      has_execution_withdrawal_credential(type(state).kind, source_validator[])
    is_correct_source_address =
      source_validator.withdrawal_credentials.data.toOpenArray(12, 31) ==
        consolidation_request.source_address.data
  if not (has_correct_credential and is_correct_source_address):
    return

  # Verify that target has compounding withdrawal credentials
  if not has_compounding_withdrawal_credential(type(state).kind, target_validator):
    return

  # Verify the source and the target are active
  let current_epoch = get_current_epoch(state)

  if not is_active_validator(source_validator[], current_epoch):
    return
  if not is_active_validator(target_validator, current_epoch):
    return

  # Verify exits for source and target have not been initiated
  if source_validator[].exit_epoch != FAR_FUTURE_EPOCH:
    return
  if target_validator.exit_epoch != FAR_FUTURE_EPOCH:
    return

  # Verify the source has been active long enough
  if current_epoch <
      source_validator.activation_epoch + cfg.SHARD_COMMITTEE_PERIOD:
    return

  # Verify the source has no pending withdrawals in the queue
  if get_pending_balance_to_withdraw(state, source_index) > 0.Gwei:
    return

  # Initiate source validator exit and append pending consolidation
  source_validator[].exit_epoch = compute_consolidation_epoch_and_update_churn(
    cfg, state, source_validator[].effective_balance, cache)
  source_validator[].withdrawable_epoch =
    source_validator[].exit_epoch + cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY
  discard state.pending_consolidations.add(PendingConsolidation(
    source_index: source_index.uint64, target_index: target_index.uint64))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/beacon-chain.md#payload-attestations
proc process_payload_attestation*(
    state: var (gloas.BeaconState | heze.BeaconState),
    payload_attestation: PayloadAttestation): Result[void, cstring] =
  # Check that the attestation is for the parent beacon block
  template data: untyped = payload_attestation.data

  if data.beacon_block_root != state.latest_block_header.parent_root:
    return err("process_payload_attestation: beacon block root mismatch")

  # Check that the attestation is for the previous slot
  if data.slot + 1 != state.slot:
    return err("process_payload_attestation: slot mismatch")

  # Verify signature
  let indexed_payload_attestation = get_indexed_payload_attestation(
    state, data.slot, payload_attestation
  )

  if not is_valid_indexed_payload_attestation(state, indexed_payload_attestation):
    return err("process_payload_attestation: invalid signature")

  ok()

type
  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.5.0#/Rewards/getBlockRewards
  BlockRewards* = object
    attestations*: Gwei
    sync_aggregate*: Gwei
    proposer_slashings*: Gwei
    attester_slashings*: Gwei

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/phase0/beacon-chain.md#operations
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/capella/beacon-chain.md#modified-process_operations
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/electra/beacon-chain.md#modified-process_operations
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/fulu/beacon-chain.md#modified-process_operations
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/gloas/beacon-chain.md#modified-process_operations
proc process_operations(
    cfg: RuntimeConfig, state: var ForkyBeaconState,
    body: SomeForkyBeaconBlockBody | SomeForkyBlindedBeaconBlockBody,
    base_reward_per_increment: Gwei,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =
  # Verify that outstanding deposits are processed up to the maximum number of
  # deposits
  const consensusFork = typeof(state).kind

  when consensusFork >= ConsensusFork.Fulu:
    const req_deposits = 0'u64
  elif consensusFork >= ConsensusFork.Electra:
    # Disable former deposit mechanism once all prior deposits are processed
    let
      eth1_deposit_index_limit =
        min(state.eth1_data.deposit_count, state.deposit_requests_start_index)
      req_deposits =
        # Otherwise wraps because unsigned; Python spec semantics would result in
        # negative difference, which would be impossible for len(...) to match.
        if state.eth1_deposit_index < eth1_deposit_index_limit:
          min(
            MAX_DEPOSITS, eth1_deposit_index_limit - state.eth1_deposit_index)
        else:
          0
  else:
    # Otherwise wraps because unsigned; Python spec semantics would result in
    # negative difference, which would be impossible for len(...) to match.
    if state.eth1_data.deposit_count < state.eth1_deposit_index:
      return err("state.eth1_data.deposit_count < state.eth1_deposit_index")
    let req_deposits = min(
      MAX_DEPOSITS, state.eth1_data.deposit_count - state.eth1_deposit_index)

  if body.deposits.lenu64 != req_deposits:
    return err("incorrect number of deposits")

  var operations_rewards: BlockRewards

  # It costs a full validator set scan to construct these values; only do so if
  # there will be some kind of exit.
  # TODO Electra doesn't use exit_queue_info, don't calculate
  var
    exit_queue_info =
      if body.proposer_slashings.len + body.attester_slashings.len +
          body.voluntary_exits.len > 0:
        get_state_exit_queue_info(state)
      else:
        default(ExitQueueInfo)  # not used
    bsv_use =
      when consensusFork in ConsensusFork.Electra .. ConsensusFork.Fulu:
        body.deposits.len + body.execution_requests.withdrawals.len +
          body.execution_requests.consolidations.len > 0
      else:
        body.deposits.len > 0
    bsv =
      if bsv_use:
        sortValidatorBuckets(state.validators.asSeq)
      else:
        nil     # this is a logic error, effectively assert

  for op in body.proposer_slashings:
    let (proposer_slashing_reward, new_exit_queue_info) =
      ? process_proposer_slashing(cfg, state, op, flags, exit_queue_info, cache)
    operations_rewards.proposer_slashings += proposer_slashing_reward
    exit_queue_info = new_exit_queue_info
  for op in body.attester_slashings:
    let (attester_slashing_reward, new_exit_queue_info) =
      ? process_attester_slashing(cfg, state, op, flags, exit_queue_info, cache)
    operations_rewards.attester_slashings += attester_slashing_reward
    exit_queue_info = new_exit_queue_info
  for op in body.attestations:
    operations_rewards.attestations +=
      ? process_attestation(state, op, flags, base_reward_per_increment, cache)
  for op in body.deposits:
    ? process_deposit(cfg, state, bsv[], op, flags)
  for op in body.voluntary_exits:
    exit_queue_info = ? process_voluntary_exit(
      cfg, state, op, flags, exit_queue_info, cache)

  when consensusFork >= ConsensusFork.Capella:
    for op in body.bls_to_execution_changes:
      ? process_bls_to_execution_change(cfg, state, op)

  when consensusFork in ConsensusFork.Electra .. ConsensusFork.Fulu:
    for op in body.execution_requests.deposits:
      ? process_deposit_request(cfg, state, op, {})
    for op in body.execution_requests.withdrawals:
      # [New in Electra:EIP7002:7251]
      process_withdrawal_request(cfg, state, bsv[], op, cache)
    for op in body.execution_requests.consolidations:
      # [New in Electra:EIP7251]
      process_consolidation_request(cfg, state, bsv[], op, cache)

  when consensusFork >= ConsensusFork.Gloas:
    for op in body.payload_attestations:
      # [New in Gloas:EIP7732]
      ? process_payload_attestation(state, op)

  ok(operations_rewards)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#sync-aggregate-processing
func get_participant_reward*(total_active_balance: Gwei): Gwei =
  let
    total_active_increments =
      total_active_balance div EFFECTIVE_BALANCE_INCREMENT.Gwei
    total_base_rewards =
      get_base_reward_per_increment(total_active_balance) *
        total_active_increments
    max_participant_rewards =
      total_base_rewards * SYNC_REWARD_WEIGHT div
        WEIGHT_DENOMINATOR div SLOTS_PER_EPOCH
  max_participant_rewards div SYNC_COMMITTEE_SIZE

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.9/specs/altair/beacon-chain.md#sync-aggregate-processing
func get_proposer_reward*(participant_reward: Gwei): Gwei =
  participant_reward * PROPOSER_WEIGHT div (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT)

proc process_sync_aggregate*(
    state: var (altair.BeaconState | bellatrix.BeaconState |
                capella.BeaconState | deneb.BeaconState | electra.BeaconState |
                fulu.BeaconState | gloas.BeaconState | heze.BeaconState),
    sync_aggregate: SomeSyncAggregate, total_active_balance: Gwei,
    flags: UpdateFlags, cache: var StateCache): Result[Gwei, cstring] =
  if strictVerification in flags and state.slot > 1.Slot:
    template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
    let num_active_participants = countOnes(sync_committee_bits).uint64
    if num_active_participants * 3 < static(sync_committee_bits.len * 2):
      fatal "Low sync committee participation",
        slot = state.slot, num_active_participants
      quit 1

  # Verify sync committee aggregate signature signing over the previous slot
  # block root
  when sync_aggregate.sync_committee_signature isnot TrustedSig:
    var participant_pubkeys: seq[ValidatorPubKey]
    for i in 0 ..< state.current_sync_committee.pubkeys.len:
      if sync_aggregate.sync_committee_bits[i]:
        participant_pubkeys.add state.current_sync_committee.pubkeys.data[i]

    # p2p-interface message validators check for empty sync committees, so it
    # shouldn't run except as part of test suite.
    if participant_pubkeys.len == 0:
      if sync_aggregate.sync_committee_signature != ValidatorSig.infinity():
        return err("process_sync_aggregate: empty sync aggregates need signature of point at infinity")
    else:
      # Empty participants allowed
      let
        previous_slot = max(state.slot, Slot(1)) - 1
        beacon_block_root = get_block_root_at_slot(state, previous_slot)
      if not verify_sync_committee_signature(
          state.fork, state.genesis_validators_root, previous_slot,
          beacon_block_root, participant_pubkeys,
          sync_aggregate.sync_committee_signature):
        return err("process_sync_aggregate: invalid signature")

  # Compute participant and proposer rewards
  let
    participant_reward = get_participant_reward(total_active_balance)
    proposer_reward = state_transition_block.get_proposer_reward(participant_reward)
    proposer_index = get_beacon_proposer_index(state, cache).valueOr:
      # We're processing a block, so this can't happen, in theory (!)
      return err("process_sync_aggregate: no proposer")

  # Apply participant and proposer rewards
  let indices = get_sync_committee_cache(state, cache).current_sync_committee
  var total_proposer_reward: Gwei

  for i in 0 ..< min(
    state.current_sync_committee.pubkeys.len,
    sync_aggregate.sync_committee_bits.len):
    let participant_index = indices[i]
    if sync_aggregate.sync_committee_bits[i]:
      increase_balance(state, participant_index, participant_reward)
      increase_balance(state, proposer_index, proposer_reward)
      increase_balance(total_proposer_reward, proposer_reward)
    else:
      decrease_balance(state, participant_index, participant_reward)

  ok(total_proposer_reward)

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/beacon-chain.md#process_execution_payload
proc process_execution_payload*(
    cfg: RuntimeConfig, state: var bellatrix.BeaconState,
    payload: bellatrix.ExecutionPayload,
    notify_new_payload: bellatrix.ExecutePayload): Result[void, cstring] =
  # Verify consistency of the parent hash with respect to the previous
  # execution payload header
  if is_merge_transition_complete(state):
    if not (payload.parent_hash ==
        state.latest_execution_payload_header.block_hash):
      return err("process_execution_payload: payload and state parent hash mismatch")

  # Verify prev_randao
  if not (payload.prev_randao == get_randao_mix(state, get_current_epoch(state))):
    return err("process_execution_payload: payload and state randomness mismatch")

  # Verify timestamp
  if not (payload.timestamp == cfg.timeParams
      .compute_timestamp_at_slot(state, state.slot)):
    return err("process_execution_payload: invalid timestamp")

  # Verify the execution payload is valid
  if not notify_new_payload(payload):
    return err("process_execution_payload: execution payload invalid")

  # Cache execution payload header
  state.latest_execution_payload_header = payload.toExecutionPayloadHeader()

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#modified-process_execution_payload
proc process_execution_payload*(
    cfg: RuntimeConfig, state: var capella.BeaconState,
    payload: capella.ExecutionPayload,
    notify_new_payload: capella.ExecutePayload): Result[void, cstring] =
  # Verify consistency of the parent hash with respect to the previous
  # execution payload header
  if not (payload.parent_hash ==
      state.latest_execution_payload_header.block_hash):
    return err("process_execution_payload: payload and state parent hash mismatch")

  # Verify prev_randao
  if not (payload.prev_randao == get_randao_mix(state, get_current_epoch(state))):
    return err("process_execution_payload: payload and state randomness mismatch")

  # Verify timestamp
  if not (payload.timestamp == cfg.timeParams
      .compute_timestamp_at_slot(state, state.slot)):
    return err("process_execution_payload: invalid timestamp")

  # Verify the execution payload is valid
  if not notify_new_payload(payload):
    return err("process_execution_payload: execution payload invalid")

  # Cache execution payload header
  state.latest_execution_payload_header = payload.toExecutionPayloadHeader() # [New in Capella]

  ok()

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/deneb.nim
type SomeDenebBeaconBlockBody =
  deneb.BeaconBlockBody | deneb.SigVerifiedBeaconBlockBody |
  deneb.TrustedBeaconBlockBody

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/beacon-chain.md#process_execution_payload
proc process_execution_payload*(
    cfg: RuntimeConfig, state: var deneb.BeaconState,
    body: SomeDenebBeaconBlockBody,
    notify_new_payload: deneb.ExecutePayload): Result[void, cstring] =
  template payload: auto = body.execution_payload

  # Verify consistency of the parent hash with respect to the previous
  # execution payload header
  if not (payload.parent_hash ==
      state.latest_execution_payload_header.block_hash):
    return err("process_execution_payload: payload and state parent hash mismatch")

  # Verify prev_randao
  if not (payload.prev_randao == get_randao_mix(state, get_current_epoch(state))):
    return err("process_execution_payload: payload and state randomness mismatch")

  # Verify timestamp
  if not (payload.timestamp == cfg.timeParams
      .compute_timestamp_at_slot(state, state.slot)):
    return err("process_execution_payload: invalid timestamp")

  # [New in Deneb] Verify commitments are under limit
  if not (lenu64(body.blob_kzg_commitments) <= cfg.MAX_BLOBS_PER_BLOCK):
    return err("process_execution_payload: too many KZG commitments")

  # Verify the execution payload is valid
  if not notify_new_payload(payload):
    return err("process_execution_payload: execution payload invalid")

  # Cache execution payload header
  state.latest_execution_payload_header = payload.toExecutionPayloadHeader() # [New in Deneb]

  ok()

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/electra.nim
type SomeElectraBeaconBlockBody =
  electra.BeaconBlockBody | electra.SigVerifiedBeaconBlockBody |
  electra.TrustedBeaconBlockBody

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#modified-process_execution_payload
proc process_execution_payload*(
    cfg: RuntimeConfig, state: var electra.BeaconState,
    body: SomeElectraBeaconBlockBody | electra_mev.SigVerifiedBlindedBeaconBlockBody,
    notify_new_payload: deneb.ExecutePayload): Result[void, cstring] =
  template payload: auto = body.payload

  # Verify consistency of the parent hash with respect to the previous
  # execution payload header
  if not (payload.parent_hash ==
      state.latest_execution_payload_header.block_hash):
    return err("process_execution_payload: payload and state parent hash mismatch")

  # Verify prev_randao
  if not (payload.prev_randao == get_randao_mix(state, get_current_epoch(state))):
    return err("process_execution_payload: payload and state randomness mismatch")

  # Verify timestamp
  if not (payload.timestamp == cfg.timeParams
      .compute_timestamp_at_slot(state, state.slot)):
    return err("process_execution_payload: invalid timestamp")

  # [New in Deneb] Verify commitments are under limit
  if not (lenu64(body.blob_kzg_commitments) <= cfg.MAX_BLOBS_PER_BLOCK_ELECTRA):
    return err("process_execution_payload: too many KZG commitments")

  when payload is ForkyExecutionPayloadHeader:
    # Assume valid, when blinded
    state.latest_execution_payload_header = payload
  else:
    # Verify the execution payload is valid
    if not notify_new_payload(payload):
      return err("process_execution_payload: execution payload invalid")

    # Cache execution payload header
    state.latest_execution_payload_header = payload.toExecutionPayloadHeader()

  ok()

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/fulu.nim
type SomeFuluBeaconBlockBody =
  fulu.BeaconBlockBody | fulu.SigVerifiedBeaconBlockBody |
  fulu.TrustedBeaconBlockBody

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/fulu/beacon-chain.md#modified-process_execution_payload
proc process_execution_payload*(
    cfg: RuntimeConfig, state: var fulu.BeaconState,
    body: SomeFuluBeaconBlockBody | fulu_mev.SigVerifiedBlindedBeaconBlockBody,
    notify_new_payload: deneb.ExecutePayload): Result[void, cstring] =
  template payload: auto = body.payload()

  # Verify consistency of the parent hash with respect to the previous
  # execution payload header
  if not (payload.parent_hash ==
      state.latest_execution_payload_header.block_hash):
    return err("process_execution_payload: payload and state parent hash mismatch")

  # Verify prev_randao
  if not (payload.prev_randao == get_randao_mix(state, get_current_epoch(state))):
    return err("process_execution_payload: payload and state randomness mismatch")

  # Verify timestamp
  if not (payload.timestamp == cfg.timeParams
      .compute_timestamp_at_slot(state, state.slot)):
    return err("process_execution_payload: invalid timestamp")

  # Verify commitments are under limit
  let blob_params =
    cfg.get_blob_parameters(get_current_epoch(state))
  if not (lenu64(body.blob_kzg_commitments) <= blob_params.MAX_BLOBS_PER_BLOCK):
    return err("process_execution_payload: too many KZG commitments")

  when payload is ForkyExecutionPayloadHeader:
    # Assume valid, when blinded
    state.latest_execution_payload_header = payload
  else:
    # Verify the execution payload is valid
    if not notify_new_payload(payload):
      return err("process_execution_payload: execution payload invalid")

    # Cache execution payload header
    state.latest_execution_payload_header = payload.toExecutionPayloadHeader()

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/gloas/beacon-chain.md#new-apply_parent_execution_payload
proc apply_parent_execution_payload*(
    cfg: RuntimeConfig,
    state: var (gloas.BeaconState | heze.BeaconState),
    requests: ExecutionRequests,
    cache: var StateCache): Result[void, cstring] =
  template parent_bid(): auto = state.latest_execution_payload_bid
  template parent_slot(): auto = parent_bid.slot
  template parent_epoch(): auto = parent_slot.epoch()

  let
    bsv =
      if requests.withdrawals.len + requests.consolidations.len +
          requests.deposits.len > 0:
        sortValidatorBuckets(state.validators.asSeq)
      else:
        nil
    bsb =
      if requests.deposits.len > 0:
        sortValidatorBuckets(state.builders.asSeq)
      else:
        nil
  var requested_deposit_pubkeys =
    initHashSet[ValidatorPubKey](requests.deposits.len)
  for op in requests.deposits:
    requested_deposit_pubkeys.incl op.pubkey
  var pending_validators =
    get_pending_validators(cfg, state, requested_deposit_pubkeys)
  for op in requests.deposits:
    ? process_deposit_request(cfg, state, bsv[], bsb[], pending_validators, op, {})
  for op in requests.withdrawals:
    process_withdrawal_request(cfg, state, bsv[], op, cache)
  for op in requests.consolidations:
    process_consolidation_request(cfg, state, bsv[], op, cache)

  # Settle the builder payment
  if parent_epoch == state.slot.epoch():
    let payment_index = SLOTS_PER_EPOCH + parent_slot mod SLOTS_PER_EPOCH
    ? settle_builder_payment(state, payment_index)
  elif parent_epoch == state.slot.epoch().get_previous_epoch():
    let payment_index = parent_slot mod SLOTS_PER_EPOCH
    ? settle_builder_payment(state, payment_index)
  elif uint64(parent_bid.value) > 0'u64:
    # Parent is older than the previous epoch, its payment entry has been
    # evicted from builder_pending_payments. Append the withdrawal directly.
    discard state.builder_pending_withdrawals.add(
      BuilderPendingWithdrawal(
        fee_recipient: parent_bid.fee_recipient,
        amount: parent_bid.value,
        builder_index: parent_bid.builder_index,
      )
    )

  # Update parent payload availability and latest block hash
  state.execution_payload_availability[
    parent_slot mod SLOTS_PER_HISTORICAL_ROOT] = true
  state.latest_block_hash = parent_bid.block_hash

  ok()

# copy of datatypes/gloas.nim
type SomeGloasBeaconBlock =
  gloas.BeaconBlock | gloas.SigVerifiedBeaconBlock | gloas.TrustedBeaconBlock

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/beacon-chain.md#new-process_execution_payload_bid
proc process_execution_payload_bid*(
    cfg: RuntimeConfig, state: var gloas.BeaconState,
    blck: SomeGloasBeaconBlock): Result[void, cstring] =
  template signed_bid: untyped = blck.body.signed_execution_payload_bid
  template bid: untyped = signed_bid.message
  let
    builder_index = bid.builder_index
    amount = bid.value
    epoch = get_current_epoch(state)

  # For self-builds, amount must be zero regardless of withdrawal credential prefix
  if builder_index == BUILDER_INDEX_SELF_BUILD:
    if amount != 0.Gwei:
      return err("process_execution_payload_bid: self-build must have zero amount")
    if signed_bid.signature != ValidatorSig.infinity():
      return err("process_execution_payload_bid: self-build signature must be infinity")
  else:
    # Verify that the builder is active
    if not is_active_builder(state, builder_index.BuilderIndex):
      return err("payload_bid: builder must be active")
    # Verify that the builder has funds to cover the bid
    if not can_builder_cover_bid(state, builder_index.BuilderIndex, amount):
      return err("payload_bid: builder can't cover the bid")
    # Verify that the bid signature is valid
    if not verify_execution_payload_bid_signature(
        state.fork, state.genesis_validators_root, epoch, signed_bid.message,
        state.builders.item(builder_index).pubkey, signed_bid.signature):
      return err("payload_bid: invalid bid signature")

  # Verify commitments are under limit
  let blob_params = cfg.get_blob_parameters(epoch)
  if lenu64(bid.blob_kzg_commitments) > blob_params.MAX_BLOBS_PER_BLOCK:
    return err("process_execution_payload_bid: too many blob KZG commitments")

  # Verify that the bid is for the current slot
  if bid.slot != blck.slot:
    return err("process_execution_payload_bid: bid slot mismatch")
  # Verify that the bid is for the right parent block
  if bid.parent_block_hash != state.latest_block_hash:
    return err("process_execution_payload_bid: parent block hash mismatch")
  if bid.parent_block_root != blck.parent_root:
    return err("process_execution_payload_bid: parent block root mismatch")
  if not (bid.prev_randao == get_randao_mix(state, epoch)):
    return err("process_execution_payload_bid: RANDAO mismatch")

  # Record the pending payment if there is some payment
  if amount > 0.Gwei:
    let
      pending_payment = BuilderPendingPayment(
        weight: 0.Gwei,
        withdrawal: BuilderPendingWithdrawal(
          fee_recipient: bid.fee_recipient,
          amount: amount,
          builder_index: builder_index.uint64)
      )
    state.builder_pending_payments.mitem(
      SLOTS_PER_EPOCH + (bid.slot mod SLOTS_PER_EPOCH)) = pending_payment

  # Cache the signed execution payload bid
  state.latest_execution_payload_bid = bid

  ok()

# copy of datatypes/heze.nim
type SomeHezeBeaconBlock =
  heze.BeaconBlock | heze.SigVerifiedBeaconBlock | heze.TrustedBeaconBlock

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/gloas/beacon-chain.md#new-process_parent_execution_payload
proc process_parent_execution_payload*(
    cfg: RuntimeConfig,
    state: var (gloas.BeaconState | heze.BeaconState),
    blck: SomeGloasBeaconBlock | SomeHezeBeaconBlock,
    flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] =
  template bid(): auto = blck.body.signed_execution_payload_bid.message
  template parent_bid(): auto = state.latest_execution_payload_bid
  template requests(): auto = blck.body.parent_execution_requests

  # If the parent block was empty, no execution requests are expected
  if bid.parent_block_hash != parent_bid.block_hash:
    if not (requests == default(ExecutionRequests)):
      return err("process_parent_execution_payload: execution requests not empty")
    return ok()

  # Parent was FULL -- verify the bid commitment and apply the payload
  if not (hash_tree_root(requests) == parent_bid.execution_requests_root):
    return err("process_parent_execution_payload: execution requests root mismatch")

  if skipApplyParentExecutionPayload notin flags:
    apply_parent_execution_payload(cfg, state, requests, cache)
  else:
    ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/beacon-chain.md#new-process_execution_payload_bid
proc process_execution_payload_bid*(
    cfg: RuntimeConfig, state: var heze.BeaconState,
    blck: SomeHezeBeaconBlock): Result[void, cstring] =
  template signed_bid: untyped = blck.body.signed_execution_payload_bid
  template bid: untyped = signed_bid.message
  let
    builder_index = bid.builder_index
    amount = bid.value
    epoch = get_current_epoch(state)

  # For self-builds, amount must be zero regardless of withdrawal credential prefix
  if builder_index == BUILDER_INDEX_SELF_BUILD:
    if amount != 0.Gwei:
      return err("process_execution_payload_bid: self-build must have zero amount")
    if signed_bid.signature != ValidatorSig.infinity():
      return err("process_execution_payload_bid: self-build signature must be infinity")
  else:
    # Verify that the builder is active
    if not is_active_builder(state, builder_index.BuilderIndex):
      return err("payload_bid: builder must be active")
    # Verify that the builder has funds to cover the bid
    if not can_builder_cover_bid(state, builder_index.BuilderIndex, amount):
      return err("payload_bid: builder can't cover the bid")
    # Verify that the bid signature is valid
    if not verify_execution_payload_bid_signature(
        state.fork, state.genesis_validators_root, epoch, signed_bid.message,
        state.builders.item(builder_index).pubkey, signed_bid.signature):
      return err("payload_bid: invalid bid signature")

  # Verify commitments are under limit
  let blob_params = cfg.get_blob_parameters(epoch)
  if lenu64(bid.blob_kzg_commitments) > blob_params.MAX_BLOBS_PER_BLOCK:
    return err("process_execution_payload_bid: too many blob KZG commitments")

  # Verify that the bid is for the current slot
  if bid.slot != blck.slot:
    return err("process_execution_payload_bid: bid slot mismatch")
  # Verify that the bid is for the right parent block
  if bid.parent_block_hash != state.latest_block_hash:
    return err("process_execution_payload_bid: parent block hash mismatch")
  if bid.parent_block_root != blck.parent_root:
    return err("process_execution_payload_bid: parent block root mismatch")
  if not (bid.prev_randao == get_randao_mix(state, epoch)):
    return err("process_execution_payload_bid: RANDAO mismatch")

  # Record the pending payment if there is some payment
  if amount > 0.Gwei:
    let
      pending_payment = BuilderPendingPayment(
        weight: 0.Gwei,
        withdrawal: BuilderPendingWithdrawal(
          fee_recipient: bid.fee_recipient,
          amount: amount,
          builder_index: builder_index.uint64)
      )
    state.builder_pending_payments.mitem(
      SLOTS_PER_EPOCH + (bid.slot mod SLOTS_PER_EPOCH)) = pending_payment

  # Cache the signed execution payload bid
  state.latest_execution_payload_bid = bid

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/capella/beacon-chain.md#new-process_withdrawals
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#updated-process_withdrawals
func process_withdrawals*(
    state: var (capella.BeaconState | deneb.BeaconState | electra.BeaconState |
                fulu.BeaconState),
    payload: ForkyExecutionPayloadOrHeader):
    Result[void, cstring] =
  const consensusFork = typeof(state).kind

  when consensusFork >= ConsensusFork.Electra:
    let (expected_withdrawals, partial_withdrawals_count) =
      get_expected_withdrawals_with_partial_count(state)

    # Update pending partial withdrawals [New in Electra:EIP7251]
    # Moved slightly earlier to be in same when block
    state.pending_partial_withdrawals =
      HashList[PendingPartialWithdrawal, Limit PENDING_PARTIAL_WITHDRAWALS_LIMIT].init(
        state.pending_partial_withdrawals.asSeq[partial_withdrawals_count .. ^1])
  else:
    let expected_withdrawals = get_expected_withdrawals(state)

  when payload is ForkyExecutionPayloadHeader:
    if not (payload.withdrawals_root == hash_tree_root(
        List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(
          expected_withdrawals))):
      return err("process_withdrawals: withdrawals_root does not match expected withdrawals")
  else:
    if payload.withdrawals.asSeq() != expected_withdrawals:
      return err("process_withdrawals: payload withdrawals don't match expected withdrawals")

  for withdrawal in expected_withdrawals:
    let validator_index = ValidatorIndex.init(withdrawal.validator_index).valueOr:
        return err("process_withdrawals: invalid validator index")
    decrease_balance(
      state, validator_index, withdrawal.amount)

  # Update the next withdrawal index if this block contained withdrawals
  if len(expected_withdrawals) != 0:
    let latest_withdrawal = expected_withdrawals[^1]
    state.next_withdrawal_index = WithdrawalIndex(latest_withdrawal.index + 1)

  # Update the next validator index to start the next withdrawal sweep
  if len(expected_withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
    # Next sweep starts after the latest withdrawal's validator index
    let next_validator_index =
      (expected_withdrawals[^1].validator_index + 1) mod
        lenu64(state.validators)
    state.next_withdrawal_validator_index = next_validator_index
  else:
    # Advance sweep by the max length of the sweep if there was not a full set
    # of withdrawals
    let next_index =
      state.next_withdrawal_validator_index +
        MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP
    let next_validator_index = next_index mod lenu64(state.validators)
    state.next_withdrawal_validator_index = next_validator_index

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#modified-apply_withdrawals
func apply_withdrawals(
    state: var (gloas.BeaconState | heze.BeaconState),
    withdrawals: seq[Withdrawal]): Result[void, cstring] =
  for withdrawal in withdrawals:
    # [Modified in Gloas:EIP7732]
    if is_builder_index(withdrawal.validator_index):
      let
        builder_index =
          convert_validator_index_to_builder_index(withdrawal.validator_index)
        builder_balance = addr state.builders.mitem(builder_index).balance
      builder_balance[] =
        builder_balance[] - min(withdrawal.amount, builder_balance[])
    else:
      let validator_index =
        ValidatorIndex.init(withdrawal.validator_index).valueOr:
          return err("apply_withdrawals: invalid validator index")
      decrease_balance(state, validator_index, withdrawal.amount)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/capella/beacon-chain.md#new-update_next_withdrawal_index
func update_next_withdrawal_index(
    state: var (gloas.BeaconState | heze.BeaconState),
    withdrawals: seq[Withdrawal]) =
  ## Update the next withdrawal index if this block contained withdrawals
  if len(withdrawals) != 0:
    let latest_withdrawal = withdrawals[^1]
    state.next_withdrawal_index = WithdrawalIndex(latest_withdrawal.index + 1)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#new-update_payload_expected_withdrawals
func update_payload_expected_withdrawals(
    state: var (gloas.BeaconState | heze.BeaconState),
    withdrawals: seq[Withdrawal]) =
  state.payload_expected_withdrawals =
    HashList[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD].init(withdrawals)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/capella/beacon-chain.md#new-update_next_withdrawal_validator_index
func update_next_withdrawal_validator_index(
    state: var (gloas.BeaconState | heze.BeaconState),
    withdrawals: seq[Withdrawal]) =
  # Update the next validator index to start the next withdrawal sweep
  if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
    # Next sweep starts after the latest withdrawal's validator index
    let next_validator_index =
      (withdrawals[^1].validator_index + 1) mod state.validators.lenu64
    state.next_withdrawal_validator_index = next_validator_index
  else:
    # Advance sweep by the max length of the sweep if there was not a full set of withdrawals
    let
      next_index = state.next_withdrawal_validator_index +
        MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP
      next_validator_index = next_index mod state.validators.lenu64
    state.next_withdrawal_validator_index = next_validator_index

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#new-update_builder_pending_withdrawals
func update_builder_pending_withdrawals(
    state: var (gloas.BeaconState | heze.BeaconState),
    processed_builder_withdrawals_count: uint64) =
  state.builder_pending_withdrawals =
    typeof(state.builder_pending_withdrawals).init(
      state.builder_pending_withdrawals.asSeq[processed_builder_withdrawals_count .. ^1])

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/electra/beacon-chain.md#new-update_pending_partial_withdrawals
func update_pending_partial_withdrawals(
    state: var (gloas.BeaconState | heze.BeaconState),
    processed_partial_withdrawals_count: uint64) =
  state.pending_partial_withdrawals =
    typeof(state.pending_partial_withdrawals).init(
      state.pending_partial_withdrawals.asSeq[processed_partial_withdrawals_count .. ^1])

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#new-update_next_withdrawal_builder_index
func update_next_withdrawal_builder_index(
    state: var (gloas.BeaconState | heze.BeaconState),
    processed_builders_sweep_count: uint64) =
  if len(state.builders) > 0:
    # Update the next builder index to start the next withdrawal sweep
    let
      next_index =
        state.next_withdrawal_builder_index + processed_builders_sweep_count
      next_builder_index = BuilderIndex(next_index mod state.builders.lenu64)
    state.next_withdrawal_builder_index = next_builder_index

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/gloas/beacon-chain.md#modified-process_withdrawals
func process_withdrawals*(state: var (gloas.BeaconState | heze.BeaconState)):
    Result[void, cstring] =
  # Return early if the parent block is empty
  if state.latest_block_hash != state.latest_execution_payload_bid.block_hash:
    return ok()

  let expected = get_expected_withdrawals(state)

  # Apply expected withdrawals
  ? apply_withdrawals(state, expected.withdrawals)

  # Update withdrawals fields in the state
  update_next_withdrawal_index(state, expected.withdrawals)
  # [New in Gloas:EIP7732]
  update_payload_expected_withdrawals(state, expected.withdrawals)
  # [New in Gloas:EIP7732]
  update_builder_pending_withdrawals(
    state, expected.processed_builder_withdrawals_count)
  update_pending_partial_withdrawals(state,
    expected.processed_partial_withdrawals_count)
  # [New in Gloas:EIP7732]
  update_next_withdrawal_builder_index(
    state, expected.processed_builders_sweep_count)
  update_next_withdrawal_validator_index(state, expected.withdrawals)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/deneb/beacon-chain.md#kzg_commitment_to_versioned_hash
func kzg_commitment_to_versioned_hash*(
    kzg_commitment: KzgCommitment): VersionedHash {.noinit.} =
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/deneb/beacon-chain.md#blob
  const VERSIONED_HASH_VERSION_KZG = 0x01'u8

  var res {.noinit.}: VersionedHash
  static: assert res.data.len == 32
  res.data[0] = VERSIONED_HASH_VERSION_KZG
  res.data[1 .. 31] = eth2digest(kzg_commitment.bytes).data.toOpenArray(1, 31)
  res

proc validate_blobs*(
    expected_kzg_commitments: seq[KzgCommitment], blobs: seq[KzgBlob],
    proofs: seq[KzgProof]): Result[void, string] =
  let res = verifyBlobKzgProofBatch(blobs, expected_kzg_commitments, proofs).valueOr:
    return err("validate_blobs proof verification error: " & error())

  if not res:
    return err("validate_blobs proof verification failed")

  ok()

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/phase0.nim
type SomePhase0Block =
  phase0.BeaconBlock | phase0.SigVerifiedBeaconBlock | phase0.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var phase0.BeaconState, blck: SomePhase0Block, flags: UpdateFlags,
    cache: var StateCache): Result[BlockRewards, cstring] =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  ok(? process_operations(cfg, state, blck.body, 0.Gwei, flags, cache))

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/altair/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/altair.nim
type SomeAltairBlock =
  altair.BeaconBlock | altair.SigVerifiedBeaconBlock | altair.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var altair.BeaconState, blck: SomeAltairBlock, flags: UpdateFlags,
    cache: var StateCache): Result[BlockRewards, cstring] =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  var operations_rewards = ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  operations_rewards.sync_aggregate = ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance,
    flags, cache)  # [New in Altair]

  ok(operations_rewards)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/bellatrix/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
type SomeBellatrixBlock =
  bellatrix.BeaconBlock | bellatrix.SigVerifiedBeaconBlock | bellatrix.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var bellatrix.BeaconState, blck: SomeBellatrixBlock,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)
  if is_execution_enabled(state, blck.body):
    ? process_execution_payload(
        cfg, state, blck.body.execution_payload,
        func(_: bellatrix.ExecutionPayload): bool = true)  # [New in Bellatrix]
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  var operations_rewards = ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  operations_rewards.sync_aggregate = ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok(operations_rewards)

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
type SomeCapellaBlock =
  capella.BeaconBlock | capella.SigVerifiedBeaconBlock | capella.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var capella.BeaconState, blck: SomeCapellaBlock,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)

  # Consensus specs v1.4.0 unconditionally assume is_execution_enabled is
  # true, but intentionally keep such a check.
  if is_execution_enabled(state, blck.body):
    ? process_withdrawals(
        state, blck.body.execution_payload)  # [New in Capella]
    ? process_execution_payload(
        cfg, state, blck.body.execution_payload,
        func(_: capella.ExecutionPayload): bool = true)  # [Modified in Capella]
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  var operations_rewards = ? process_operations(
    cfg, state, blck.body, base_reward_per_increment,
    flags, cache)  # [Modified in Capella]
  operations_rewards.sync_aggregate = ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok(operations_rewards)

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
type SomeDenebBlock =
  deneb.BeaconBlock | deneb.SigVerifiedBeaconBlock | deneb.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var deneb.BeaconState, blck: SomeDenebBlock,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)

  # Consensus specs v1.4.0 unconditionally assume is_execution_enabled is
  # true, but intentionally keep such a check.
  if is_execution_enabled(state, blck.body):
    ? process_withdrawals(state, blck.body.execution_payload)
    ? process_execution_payload(
        cfg, state, blck.body,
        func(_: deneb.ExecutionPayload): bool = true)  # [Modified in Deneb]
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  var operations_rewards = ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  operations_rewards.sync_aggregate = ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok(operations_rewards)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.1/specs/electra/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
type SomeElectraBlock =
  electra.BeaconBlock | electra.SigVerifiedBeaconBlock | electra.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var electra.BeaconState,
    blck: SomeElectraBlock,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)

  # Consensus specs v1.4.0 unconditionally assume is_execution_enabled is
  # true, but intentionally keep such a check.
  if is_execution_enabled(state, blck.body):
    ? process_withdrawals(state, blck.body.payload)
    ? process_execution_payload(
        cfg, state, blck.body,
        func(_: deneb.ExecutionPayload): bool = true)
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  var operations_rewards = ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  operations_rewards.sync_aggregate = ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok(operations_rewards)

type SomeFuluBlock =
  fulu.BeaconBlock | fulu.SigVerifiedBeaconBlock | fulu.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var fulu.BeaconState,
    blck: SomeFuluBlock | fulu_mev.SigVerifiedBlindedBeaconBlock,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)

  # Consensus specs v1.4.0 unconditionally assume is_execution_enabled is
  # true, but intentionally keep such a check.
  if is_execution_enabled(state, blck.body):
    ? process_withdrawals(state, blck.body.payload)

    ? process_execution_payload(
        cfg, state, blck.body,
        func(_: deneb.ExecutionPayload): bool = true)
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  var operations_rewards = ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  operations_rewards.sync_aggregate = ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok(operations_rewards)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/gloas/fork-choice.md#new-verify_execution_payload_envelope
proc verify_execution_payload_envelope*(
    timeParams: TimeParams,
    fork: Fork,
    state: gloas.HashedBeaconState | heze.HashedBeaconState,
    signed_envelope: SignedExecutionPayloadEnvelope,
    genesis_validators_root: Eth2Digest): Result[void, cstring] =
  template envelope: auto = signed_envelope.message
  template payload: auto = envelope.payload
  template bid: auto = state.data.latest_execution_payload_bid

  # Resolve builder public key
  let builderIndex = envelope.builder_index
  let pubkey =
    if builderIndex == BUILDER_INDEX_SELF_BUILD:
      let proposerIndex = state.data.latest_block_header.proposer_index
      if proposerIndex >= state.data.validators.lenu64:
        return err("verify_execution_payload_envelope: invalid proposer index")
      state.data.validators.item(proposerIndex).pubkey
    else:
      if builderIndex >= state.data.builders.lenu64:
        return err("verify_execution_payload_envelope: invalid builder index")
      state.data.builders.item(builderIndex).pubkey

  # Verify signature
  if not verify_execution_payload_envelope_signature(
      fork, genesis_validators_root,
      payload.slot_number.epoch,
      envelope, pubkey, signed_envelope.signature):
    return err("verify_execution_payload_envelope: invalid signature")

  # Verify consistency with the beacon block
  var header = state.data.latest_block_header
  header.state_root = state.root
  if envelope.beacon_block_root != hash_tree_root(header):
    return err("verify_execution_payload_envelope: beacon_block_root mismatch")
  if envelope.parent_beacon_block_root !=
      state.data.latest_block_header.parent_root:
    return err(
      "verify_execution_payload_envelope: parent_beacon_block_root mismatch")

  # Verify consistency with the committed bid
  if envelope.builder_index != bid.builder_index:
    return err("verify_execution_payload_envelope: builder_index mismatch")
  if payload.prev_randao != bid.prev_randao:
    return err("verify_execution_payload_envelope: prev_randao mismatch")
  if payload.gas_limit != bid.gas_limit:
    return err("verify_execution_payload_envelope: gas_limit mismatch")
  if payload.block_hash != bid.block_hash:
    return err("verify_execution_payload_envelope: block_hash mismatch")
  if hash_tree_root(envelope.execution_requests) != bid.execution_requests_root:
    return err("verify_execution_payload_envelope: execution_requests_root mismatch")

  # Verify the execution payload is valid
  if payload.slot_number != state.data.slot:
    return err("verify_execution_payload_envelope: slot mismatch")
  if payload.parent_hash != state.data.latest_block_hash:
    return err("verify_execution_payload_envelope: parent_hash mismatch")
  if payload.timestamp !=
      timeParams.compute_timestamp_at_slot(state.data, state.data.slot):
    return err("verify_execution_payload_envelope: timestamp mismatch")
  if hash_tree_root(payload.withdrawals) !=
      hash_tree_root(state.data.payload_expected_withdrawals):
    return err("verify_execution_payload_envelope: withdrawals mismatch")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/beacon-chain.md#block-processing
debugGloasComment "readd gloas_mev block and, well the rest too"
type SomeGloasBlock =
  gloas.BeaconBlock | gloas.SigVerifiedBeaconBlock | gloas.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var gloas.BeaconState,
    blck: SomeGloasBlock,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_parent_execution_payload(cfg, state, blck, flags, cache)
  ? process_block_header(state, blck, flags, cache)
  ? process_withdrawals(state)
  ? process_execution_payload_bid(cfg, state, blck)
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  var operations_rewards = ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  operations_rewards.sync_aggregate = ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok(operations_rewards)

type SomeHezeBlock =
  heze.BeaconBlock | heze.SigVerifiedBeaconBlock | heze.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var heze.BeaconState,
    blck: SomeHezeBlock,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_parent_execution_payload(cfg, state, blck, flags, cache)
  ? process_block_header(state, blck, flags, cache)
  ? process_withdrawals(state)
  ? process_execution_payload_bid(cfg, state, blck)
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  var operations_rewards = ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  operations_rewards.sync_aggregate = ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok(operations_rewards)
