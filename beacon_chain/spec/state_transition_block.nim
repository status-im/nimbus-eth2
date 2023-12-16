# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition - block processing, as described in
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#block-processing
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#block-processing
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#block-processing
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#block-processing
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/deneb/beacon-chain.md#block-processing
#
# The entry point is `process_block` which is at the bottom of this file.
#
# General notes about the code:
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * When updating the code, add TODO sections to mark where there are clear
#   improvements to be made - other than that, keep things similar to spec unless
#   motivated by security or performance considerations

{.push raises: [].}

import
  chronicles, metrics,
  ../extras,
  ./datatypes/[phase0, altair, bellatrix, deneb],
  "."/[beaconstate, eth2_merkleization, helpers, validator, signatures],
  kzg4844/kzg_abi, kzg4844/kzg_ex

from std/algorithm import fill, sorted
from std/sequtils import count, filterIt, mapIt
from ./datatypes/capella import
  BeaconState, MAX_WITHDRAWALS_PER_PAYLOAD, SignedBLSToExecutionChange,
  Withdrawal

export extras, phase0, altair

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#block-header
func process_block_header*(
    state: var ForkyBeaconState, blck: SomeForkyBeaconBlock,
    flags: UpdateFlags, cache: var StateCache): Result[void, cstring] =
  # Verify that the slots match
  if not (blck.slot == state.slot):
    return err("process_block_header: slot mismatch")

  # Verify that the block is newer than latest block header
  if not (blck.slot > state.latest_block_header.slot):
    return err("process_block_header: block not newer than latest block header")

  # Verify that proposer index is the correct index
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#randao
proc process_randao(
    state: var ForkyBeaconState, body: SomeForkyBeaconBlockBody,
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#eth1-data
func process_eth1_data(
    state: var ForkyBeaconState,
    body: SomeForkyBeaconBlockBody): Result[void, cstring] =
  if not state.eth1_data_votes.add body.eth1_data:
    # Count is reset  in process_final_updates, so this should never happen
    return err("process_eth1_data: no more room for eth1 data")

  if state.eth1_data_votes.asSeq.count(body.eth1_data).uint64 * 2 >
      SLOTS_PER_ETH1_VOTING_PERIOD:
    state.eth1_data = body.eth1_data
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_slashable_validator
func is_slashable_validator(validator: Validator, epoch: Epoch): bool =
  # Check if ``validator`` is slashable.
  (not validator.slashed) and
    (validator.activation_epoch <= epoch) and
    (epoch < validator.withdrawable_epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#proposer-slashings
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#proposer-slashings
proc process_proposer_slashing*(
    cfg: RuntimeConfig, state: var ForkyBeaconState,
    proposer_slashing: SomeProposerSlashing, flags: UpdateFlags,
    cache: var StateCache):
    Result[void, cstring] =
  let proposer_index = ? check_proposer_slashing(state, proposer_slashing, flags)
  ? slash_validator(cfg, state, proposer_index, cache)
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_slashable_attestation_data
func is_slashable_attestation_data(
    data_1: AttestationData, data_2: AttestationData): bool =
  ## Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG
  ## rules.

  # Double vote
  (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
  # Surround vote
    (data_1.source.epoch < data_2.source.epoch and
     data_2.target.epoch < data_1.target.epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#attester-slashings
proc check_attester_slashing*(
       state: ForkyBeaconState,
       attester_slashing: SomeAttesterSlashing,
       flags: UpdateFlags
     ): Result[seq[ValidatorIndex], cstring] =
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
    state: var ForkedHashedBeaconState, attester_slashing: SomeAttesterSlashing,
    flags: UpdateFlags): Result[seq[ValidatorIndex], cstring] =
  withState(state):
    check_attester_slashing(forkyState.data, attester_slashing, flags)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#attester-slashings
proc process_attester_slashing*(
    cfg: RuntimeConfig,
    state: var ForkyBeaconState,
    attester_slashing: SomeAttesterSlashing,
    flags: UpdateFlags,
    cache: var StateCache
    ): Result[void, cstring] =
  let slashed_attesters =
    ? check_attester_slashing(state, attester_slashing, flags)

  for index in slashed_attesters:
    ? slash_validator(cfg, state, index, cache)

  ok()

func findValidatorIndex*(state: ForkyBeaconState, pubkey: ValidatorPubKey):
    Opt[ValidatorIndex] =
  # This linear scan is unfortunate, but should be fairly fast as we do a simple
  # byte comparison of the key. The alternative would be to build a Table, but
  # given that each block can hold no more than 16 deposits, it's slower to
  # build the table and use it for lookups than to scan it like this.
  # Once we have a reusable, long-lived cache, this should be revisited
  for vidx in state.validators.vindices:
    if state.validators.asSeq[vidx].pubkey == pubkey:
      return Opt[ValidatorIndex].ok(vidx)

proc process_deposit*(cfg: RuntimeConfig,
                      state: var ForkyBeaconState,
                      deposit: Deposit,
                      flags: UpdateFlags): Result[void, cstring] =
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

  let
    pubkey = deposit.data.pubkey
    amount = deposit.data.amount
    index = findValidatorIndex(state, pubkey)

  if index.isSome():
    # Increase balance by deposit amount
    increase_balance(state, index.get(), amount)
  else:
    # Verify the deposit signature (proof of possession) which is not checked
    # by the deposit contract
    if verify_deposit_signature(cfg, deposit.data):
      # New validator! Add validator and balance entries
      if not state.validators.add(get_validator_from_deposit(deposit.data)):
        return err("process_deposit: too many validators")
      if not state.balances.add(amount):
        static: doAssert state.balances.maxLen == state.validators.maxLen
        raiseAssert "adding validator succeeded, so should balances"

      when state is altair.BeaconState or state is bellatrix.BeaconState or
           state is capella.BeaconState or state is deneb.BeaconState:
        if not state.previous_epoch_participation.add(ParticipationFlags(0)):
          return err("process_deposit: too many validators (previous_epoch_participation)")
        if not state.current_epoch_participation.add(ParticipationFlags(0)):
          return err("process_deposit: too many validators (current_epoch_participation)")
        if not state.inactivity_scores.add(0'u64):
          return err("process_deposit: too many validators (inactivity_scores)")

      doAssert state.validators.len == state.balances.len
    else:
      # Deposits may come with invalid signatures - in that case, they are not
      # turned into a validator but still get processed to keep the deposit
      # index correct
      trace "Skipping deposit with invalid signature",
        deposit = shortLog(deposit.data)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#voluntary-exits
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/deneb/beacon-chain.md#modified-process_voluntary_exit
proc check_voluntary_exit*(
    cfg: RuntimeConfig,
    state: ForkyBeaconState,
    signed_voluntary_exit: SomeSignedVoluntaryExit,
    flags: UpdateFlags): Result[ValidatorIndex, cstring] =

  let voluntary_exit = signed_voluntary_exit.message

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

  # Verify signature
  if skipBlsValidation notin flags:
    let exitSignatureFork =
      when typeof(state).kind >= ConsensusFork.Deneb:
        Fork(
          previous_version: cfg.CAPELLA_FORK_VERSION,
          current_version: cfg.CAPELLA_FORK_VERSION,
          epoch: cfg.CAPELLA_FORK_EPOCH)
      else:
        state.fork
    if not verify_voluntary_exit_signature(
        exitSignatureFork, state.genesis_validators_root, voluntary_exit,
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#voluntary-exits
proc process_voluntary_exit*(
    cfg: RuntimeConfig,
    state: var ForkyBeaconState,
    signed_voluntary_exit: SomeSignedVoluntaryExit,
    flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] =
  let exited_validator =
    ? check_voluntary_exit(cfg, state, signed_voluntary_exit, flags)
  ? initiate_validator_exit(cfg, state, exited_validator, cache)
  ok()

proc process_bls_to_execution_change*(
    cfg: RuntimeConfig, state: var (capella.BeaconState | deneb.BeaconState),
    signed_address_change: SignedBLSToExecutionChange): Result[void, cstring] =
  ? check_bls_to_execution_change(
    cfg.genesisFork, state, signed_address_change, {})
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#operations
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#modified-process_operations
proc process_operations(cfg: RuntimeConfig,
                        state: var ForkyBeaconState,
                        body: SomeForkyBeaconBlockBody,
                        base_reward_per_increment: Gwei,
                        flags: UpdateFlags,
                        cache: var StateCache): Result[void, cstring] =
  # Verify that outstanding deposits are processed up to the maximum number of
  # deposits
  let
    req_deposits = min(MAX_DEPOSITS,
                       state.eth1_data.deposit_count - state.eth1_deposit_index)

  if state.eth1_data.deposit_count < state.eth1_deposit_index or
      body.deposits.lenu64 != req_deposits:
    return err("incorrect number of deposits")

  for op in body.proposer_slashings:
    ? process_proposer_slashing(cfg, state, op, flags, cache)
  for op in body.attester_slashings:
    ? process_attester_slashing(cfg, state, op, flags, cache)
  for op in body.attestations:
    ? process_attestation(state, op, flags, base_reward_per_increment, cache)
  for op in body.deposits:
    ? process_deposit(cfg, state, op, flags)
  for op in body.voluntary_exits:
    ? process_voluntary_exit(cfg, state, op, flags, cache)
  when typeof(body).kind >= ConsensusFork.Capella:
    for op in body.bls_to_execution_changes:
      ? process_bls_to_execution_change(cfg, state, op)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#sync-aggregate-processing
func get_participant_reward*(total_active_balance: Gwei): Gwei =
  let
    total_active_increments =
      total_active_balance div EFFECTIVE_BALANCE_INCREMENT
    total_base_rewards =
      get_base_reward_per_increment(total_active_balance) *
        total_active_increments
    max_participant_rewards =
      total_base_rewards * SYNC_REWARD_WEIGHT div
        WEIGHT_DENOMINATOR div SLOTS_PER_EPOCH
  max_participant_rewards div SYNC_COMMITTEE_SIZE

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#sync-aggregate-processing
func get_proposer_reward*(participant_reward: Gwei): Gwei =
  participant_reward * PROPOSER_WEIGHT div (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#sync-aggregate-processing
proc process_sync_aggregate*(
    state: var (altair.BeaconState | bellatrix.BeaconState |
                capella.BeaconState | deneb.BeaconState),
    sync_aggregate: SomeSyncAggregate, total_active_balance: Gwei,
    flags: UpdateFlags,
    cache: var StateCache):
    Result[void, cstring]  =
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

  # TODO could use a sequtils2 zipIt
  for i in 0 ..< min(
    state.current_sync_committee.pubkeys.len,
    sync_aggregate.sync_committee_bits.len):
    let participant_index = indices[i]
    if sync_aggregate.sync_committee_bits[i]:
      increase_balance(state, participant_index, participant_reward)
      increase_balance(state, proposer_index, proposer_reward)
    else:
      decrease_balance(state, participant_index, participant_reward)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/beacon-chain.md#process_execution_payload
proc process_execution_payload*(
    state: var bellatrix.BeaconState, payload: bellatrix.ExecutionPayload,
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
  if not (payload.timestamp == compute_timestamp_at_slot(state, state.slot)):
    return err("process_execution_payload: invalid timestamp")

  # Verify the execution payload is valid
  if not notify_new_payload(payload):
    return err("process_execution_payload: execution payload invalid")

  # Cache execution payload header
  state.latest_execution_payload_header = bellatrix.ExecutionPayloadHeader(
    parent_hash: payload.parent_hash,
    fee_recipient: payload.fee_recipient,
    state_root: payload.state_root,
    receipts_root: payload.receipts_root,
    logs_bloom: payload.logs_bloom,
    prev_randao: payload.prev_randao,
    block_number: payload.block_number,
    gas_limit: payload.gas_limit,
    gas_used: payload.gas_used,
    timestamp: payload.timestamp,
    base_fee_per_gas: payload.base_fee_per_gas,
    block_hash: payload.block_hash,
    extra_data: payload.extra_data,
    transactions_root: hash_tree_root(payload.transactions))

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#modified-process_execution_payload
proc process_execution_payload*(
    state: var capella.BeaconState, payload: capella.ExecutionPayload,
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
  if not (payload.timestamp == compute_timestamp_at_slot(state, state.slot)):
    return err("process_execution_payload: invalid timestamp")

  # Verify the execution payload is valid
  if not notify_new_payload(payload):
    return err("process_execution_payload: execution payload invalid")

  # Cache execution payload header
  state.latest_execution_payload_header = capella.ExecutionPayloadHeader(
    parent_hash: payload.parent_hash,
    fee_recipient: payload.fee_recipient,
    state_root: payload.state_root,
    receipts_root: payload.receipts_root,
    logs_bloom: payload.logs_bloom,
    prev_randao: payload.prev_randao,
    block_number: payload.block_number,
    gas_limit: payload.gas_limit,
    gas_used: payload.gas_used,
    timestamp: payload.timestamp,
    base_fee_per_gas: payload.base_fee_per_gas,
    block_hash: payload.block_hash,
    extra_data: payload.extra_data,
    transactions_root: hash_tree_root(payload.transactions),
    withdrawals_root: hash_tree_root(payload.withdrawals))  # [New in Capella]

  ok()

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/deneb.nim
type SomeDenebBeaconBlockBody =
  deneb.BeaconBlockBody | deneb.SigVerifiedBeaconBlockBody |
  deneb.TrustedBeaconBlockBody

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/beacon-chain.md#process_execution_payload
proc process_execution_payload*(
    state: var deneb.BeaconState, body: SomeDenebBeaconBlockBody,
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
  if not (payload.timestamp == compute_timestamp_at_slot(state, state.slot)):
    return err("process_execution_payload: invalid timestamp")

  # [New in Deneb] Verify commitments are under limit
  if not (lenu64(body.blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK):
    return err("process_execution_payload: too many KZG commitments")

  # Verify the execution payload is valid
  if not notify_new_payload(payload):
    return err("process_execution_payload: execution payload invalid")

  # Cache execution payload header
  state.latest_execution_payload_header = deneb.ExecutionPayloadHeader(
    parent_hash: payload.parent_hash,
    fee_recipient: payload.fee_recipient,
    state_root: payload.state_root,
    receipts_root: payload.receipts_root,
    logs_bloom: payload.logs_bloom,
    prev_randao: payload.prev_randao,
    block_number: payload.block_number,
    gas_limit: payload.gas_limit,
    gas_used: payload.gas_used,
    timestamp: payload.timestamp,
    base_fee_per_gas: payload.base_fee_per_gas,
    block_hash: payload.block_hash,
    extra_data: payload.extra_data,
    transactions_root: hash_tree_root(payload.transactions),
    withdrawals_root: hash_tree_root(payload.withdrawals),
    blob_gas_used: payload.blob_gas_used,     # [New in Deneb]
    excess_blob_gas: payload.excess_blob_gas) # [New in Deneb]

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#new-process_withdrawals
func process_withdrawals*(
    state: var (capella.BeaconState | deneb.BeaconState),
    payload: capella.ExecutionPayload | deneb.ExecutionPayload):
    Result[void, cstring] =
  let expected_withdrawals = get_expected_withdrawals(state)

  if not (len(payload.withdrawals) == len(expected_withdrawals)):
    return err("process_withdrawals: different numbers of payload and expected withdrawals")

  for i in 0 ..< len(expected_withdrawals):
    if expected_withdrawals[i] != payload.withdrawals[i]:
      return err("process_withdrawals: mismatched expected and payload withdrawal")
    let validator_index =
      ValidatorIndex.init(expected_withdrawals[i].validator_index).valueOr:
        return err("process_withdrawals: invalid validator index")
    decrease_balance(
      state, validator_index, expected_withdrawals[i].amount)

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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#kzg_commitment_to_versioned_hash
func kzg_commitment_to_versioned_hash*(
    kzg_commitment: KzgCommitment): VersionedHash =
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#blob
  const VERSIONED_HASH_VERSION_KZG = 0x01'u8

  var res: VersionedHash
  res[0] = VERSIONED_HASH_VERSION_KZG
  res[1 .. 31] = eth2digest(kzg_commitment).data.toOpenArray(1, 31)
  res

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/fork-choice.md#validate_blobs
proc validate_blobs*(expected_kzg_commitments: seq[KzgCommitment],
                     blobs: seq[KzgBlob],
                     proofs: seq[KzgProof]):
                       Result[void, cstring] =
  if expected_kzg_commitments.len != blobs.len:
    return err("validate_blobs: different commitment and blob lengths")

  if proofs.len != blobs.len:
    return err("validate_blobs: different proof and blob lengths")

  let res = verifyProofs(blobs, expected_kzg_commitments, proofs).valueOr:
    return err("validate_blobs: proof verification error")

  if not res:
    return err("validate_blobs: proof verification failed")

  ok()

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/phase0.nim
type SomePhase0Block =
  phase0.BeaconBlock | phase0.SigVerifiedBeaconBlock | phase0.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var phase0.BeaconState, blck: SomePhase0Block, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring]=
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)
  ? process_operations(cfg, state, blck.body, 0.Gwei, flags, cache)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/altair.nim
type SomeAltairBlock =
  altair.BeaconBlock | altair.SigVerifiedBeaconBlock | altair.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var altair.BeaconState, blck: SomeAltairBlock, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring]=
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

  ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance,
    flags, cache)  # [New in Altair]

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
type SomeBellatrixBlock =
  bellatrix.BeaconBlock | bellatrix.SigVerifiedBeaconBlock | bellatrix.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var bellatrix.BeaconState, blck: SomeBellatrixBlock,
    flags: UpdateFlags, cache: var StateCache): Result[void, cstring]=
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)
  if is_execution_enabled(state, blck.body):
    ? process_execution_payload(
        state, blck.body.execution_payload,
        func(_: bellatrix.ExecutionPayload): bool = true)  # [New in Bellatrix]
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
type SomeCapellaBlock =
  capella.BeaconBlock | capella.SigVerifiedBeaconBlock | capella.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var capella.BeaconState, blck: SomeCapellaBlock,
    flags: UpdateFlags, cache: var StateCache): Result[void, cstring]=
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
        state, blck.body.execution_payload,
        func(_: capella.ExecutionPayload): bool = true)  # [Modified in Capella]
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  ? process_operations(
    cfg, state, blck.body, base_reward_per_increment,
    flags, cache)  # [Modified in Capella]
  ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
type SomeDenebBlock =
  deneb.BeaconBlock | deneb.SigVerifiedBeaconBlock | deneb.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var deneb.BeaconState, blck: SomeDenebBlock,
    flags: UpdateFlags, cache: var StateCache): Result[void, cstring]=
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)

  # Consensus specs v1.4.0 unconditionally assume is_execution_enabled is
  # true, but intentionally keep such a check.
  if is_execution_enabled(state, blck.body):
    ? process_withdrawals(state, blck.body.execution_payload)
    ? process_execution_payload(
        state, blck.body,
        func(_: deneb.ExecutionPayload): bool = true)  # [Modified in Deneb]
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)

  let
    total_active_balance = get_total_active_balance(state, cache)
    base_reward_per_increment =
      get_base_reward_per_increment(total_active_balance)
  ? process_operations(
    cfg, state, blck.body, base_reward_per_increment, flags, cache)
  ? process_sync_aggregate(
    state, blck.body.sync_aggregate, total_active_balance, flags, cache)

  ok()
