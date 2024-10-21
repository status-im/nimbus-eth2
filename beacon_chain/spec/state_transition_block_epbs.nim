# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# State transition - block processing for epbs, as described in
#https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#block-processing
import
    metrics,
    ../extras,
    ./datatypes/[phase0, altair, bellatrix, deneb, epbs],
    "."/[beaconstate, eth2_merkleization, helpers, validator, signatures,
            payload_attestations, ptc_status, state_transition_block],
    kzg4844/kzg_ex
from ./datatypes/capella import
    BeaconState, MAX_WITHDRAWALS_PER_PAYLOAD, SignedBLSToExecutionChange,
    Withdrawal
from ./datatypes/electra import PendingPartialWithdrawal

export extras, phase0, altair

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#withdrawals
func process_withdrawals*(state: var epbs.BeaconState):
    Result[void, cstring] =

  # Return early if the parent block was empty
  if not is_parent_block_full(state):
    return err("parent block is empty")

  let (withdrawals, partial_withdrawals_count) =
    get_expected_withdrawals_with_partial_count(state)

  # Update pending partial withdrawals [New in Electra:EIP7251]
  # Moved slightly earlier to be in same when block
  state.pending_partial_withdrawals =
    HashList[PendingPartialWithdrawal, Limit PENDING_PARTIAL_WITHDRAWALS_LIMIT].init(
      state.pending_partial_withdrawals.asSeq[partial_withdrawals_count .. ^1])
  
  var withdrawals_list: List[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]

  # Loop through the withdrawals and add them to withdrawals_list
  for i in 0 ..< min(len(withdrawals), MAX_WITHDRAWALS_PER_PAYLOAD):
    withdrawals_list[i] = withdrawals[i]

  state.latest_withdrawals_root = hash_tree_root(withdrawals_list)

  for i in 0 ..< len(withdrawals):
    let validator_index =
      ValidatorIndex.init(withdrawals[i].validator_index).valueOr:
        return err("process_withdrawals: invalid validator index")
    decrease_balance(
      state, validator_index, withdrawals[i].amount)

  # Update the next withdrawal index if this block contained withdrawals
  if len(withdrawals) != 0:
    let latest_withdrawal = withdrawals[^1]
    state.next_withdrawal_index = WithdrawalIndex(latest_withdrawal.index + 1)

  # Update the next validator index to start the next withdrawal sweep
  if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
    # Next sweep starts after the latest withdrawal's validator index
    let next_validator_index =
      (withdrawals[^1].validator_index + 1) mod
        lenu64(state.validators)
    state.next_withdrawal_validator_index = next_validator_index
  else:
    # Advance sweep by the max length of the sweep if there was not a full set
    # of withdrawals
    let 
      next_index =
        state.next_withdrawal_validator_index +
          MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP
      next_validator_index = next_index mod lenu64(state.validators)
    state.next_withdrawal_validator_index = next_validator_index

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#new-process_execution_payload_header
proc process_execution_payload_header*(state: var epbs.BeaconState,
    blck: epbs.BeaconBlock, ): Result[void, cstring] =

  let signed_header = blck.body.signed_execution_payload_header

  for vidx in state.validators.vindices:
    let pubkey = state.validators.item(vidx).pubkey()

    if not verify_execution_payload_header_signature(
      state.fork, state.genesis_validators_root, signed_header,
      state, pubkey, signed_header.signature):
      return err("payload_header: signature verification failure")

  let 
    header = signed_header.message
    builder_index = header.builder_index
    amount = header.value

  if state.balances.item(builder_index) < amount:
    return err("insufficient balance")

  if header.slot != blck.slot:
    return err("slot mismatch")

  if header.parent_block_hash != state.latest_block_hash:
    return err("parent block hash mismatch")

  if header.parent_block_root != blck.parent_root:
    return err("parent block root mismatch")

  let proposer_index = ValidatorIndex.init(blck.proposer_index).valueOr:
    return err("process_execution_payload_header: proposer index out of range")

  let builder_idx = ValidatorIndex.init(builder_index).valueOr:
    return err("process_execution_payload_header: builder index out of range")

  decrease_balance(state, builder_idx, amount)
  increase_balance(state, proposer_index, amount)

  state.latest_execution_payload_header = header

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#process_payload_attestation
proc process_payload_attestation*(state: var epbs.BeaconState,
    blck: epbs.BeaconBlock, payload_attestation: PayloadAttestation,
    cache: var StateCache, 
    base_reward_per_increment: Gwei): Result[void, cstring] =

    # Check that the attestation is for the parent beacon block
    let data = payload_attestation.data
    if not (data.beacon_block_root == state.latest_block_header.parent_root):
      return err("process_payload_attestation: beacon block and latest block mismatch")

    # Check that the attestation is for the previous slot
    if data.slot + 1 != state.slot:
      return err("process_payload_attestation: slot mismatch")

    # Verify signature
    let indexed_payload_attestation = 
      get_indexed_payload_attestation(
        state, data.slot, payload_attestation, cache
      )
    if not is_valid_indexed_payload_attestation(
      state, indexed_payload_attestation):
      return err("process_payload_attestation: signature verification failed")

    let epoch_participation =
      if state.slot mod SLOTS_PER_EPOCH == 0:
        unsafeAddr state.previous_epoch_participation
      else:
        unsafeAddr state.current_epoch_participation

    let 
      payload_present = data.slot == state.latest_full_slot
      voted_present = data.payload_status == uint8(PAYLOAD_PRESENT)

    const proposer_reward_denominator = 
      (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR div 
      PROPOSER_WEIGHT

    let proposer_index = ValidatorIndex(blck.proposer_index)

    # Return early if the attestation is for the wrong payload status
    if voted_present != payload_present:
      # Unset the flags in case they were set by an equivocating PTC attestation
      var proposer_penalty_numerator: Gwei = Gwei(0)
      for index in indexed_payload_attestation.attesting_indices:
        for flag_index, weight in PARTICIPATION_FLAG_WEIGHTS:
          if has_flag(epoch_participation[].item(index), flag_index):
            epoch_participation[].item(index) = 
             remove_flag(epoch_participation[].item(index), flag_index)
            proposer_penalty_numerator += 
              get_base_reward(state, index, base_reward_per_increment) * weight

      let proposer_penalty = 
        Gwei(2 * proposer_penalty_numerator div Gwei(proposer_reward_denominator))
      decrease_balance(state, proposer_index, proposer_penalty)

    # Reward the proposer and set all the participation flags in case of correct attestations
    var proposer_reward_numerator: Gwei = Gwei(0)
    for index in indexed_payload_attestation.attesting_indices:
      for flag_index, weight in PARTICIPATION_FLAG_WEIGHTS:
        if not has_flag(epoch_participation[].item(index), flag_index):
          epoch_participation[].item(index) = 
            add_flag(epoch_participation[].item(index), flag_index)
          proposer_reward_numerator += 
            get_base_reward(state, index, base_reward_per_increment) * weight

    let proposer_reward = 
      Gwei(proposer_reward_numerator div Gwei(proposer_reward_denominator))
    increase_balance(state, proposer_index, proposer_reward)

    ok()

from ".."/validator_bucket_sort import sortValidatorBuckets

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#modified-process_operations
proc process_operations*(
    cfg: RuntimeConfig, state: var epbs.BeaconState,
    blck: epbs.BeaconBlock, base_reward_per_increment: Gwei,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =

  # Verify that outstanding deposits are processed up to the maximum number of deposits
  let 
    body = blck.body
    req_deposits = min(
      MAX_DEPOSITS, state.eth1_data.deposit_count - state.eth1_deposit_index
    )

  if body.deposits.lenu64 != req_deposits:
    return err("incorrect number of deposits")

  # var operations_rewards: BlockRewards

  # var
  #   exit_queue_info =
  #     if body.proposer_slashings.len + body.attester_slashings.len +
  #       body.voluntary_exits.len > 0:
  #       get_state_exit_queue_info(state)
  #     else:
  #       default(ExitQueueInfo) # not used

  #   bsv_use =
  #       body.deposits.len > 0

    # bsv =
    #   if bsv_use:
    #     sortValidatorBuckets(state.validators.asSeq)
    #   else:
    #     nil  # this is a logic error, effectively assert

  # for op in body.proposer_slashings:
  #   let (proposer_slashing_reward, new_exit_queue_info) =
  #     ? process_proposer_slashing(cfg, state, op, flags, exit_queue_info, cache)
  #   operations_rewards.proposer_slashings += proposer_slashing_reward
  #   exit_queue_info = new_exit_queue_info

  # for op in body.attester_slashings:
  #   let (attester_slashing_reward, new_exit_queue_info) =
  #     ? process_attester_slashing(cfg, state, op, flags, exit_queue_info, cache)
  #   operations_rewards.attester_slashings += attester_slashing_reward
  #   exit_queue_info = new_exit_queue_info

  # for op in body.attestations:
  #   operations_rewards.attestations +=
  #     ? process_attestation(state, op, flags, base_reward_per_increment, cache)

  # for op in body.deposits:
  #   ? process_deposit(cfg, state, bsv[], op, flags)

  # for op in body.voluntary_exits:
  #   exit_queue_info = ? process_voluntary_exit(
  #     cfg, state, op, flags, exit_queue_info, cache
  #   )

  # for op in body.bls_to_execution_changes:
  #   ? process_bls_to_execution_change(cfg, state, op)

  for op in body.payload_attestations:
    ? process_payload_attestation(state, blck, op, cache,
       base_reward_per_increment)


# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#modified-process_execution_payload
proc process_execution_payload*(
    cfg: RuntimeConfig, body: epbs.BeaconBlockBody,
    state: var epbs.BeaconState,
    signed_envelope: SignedExecutionPayloadEnvelope,
    notify_new_payload: epbs.ExecutePayload, 
    # other_body: SomeForkyBeaconBlockBody,
    verify: bool = true): Result[void, cstring] =
    
  if verify:
    for vidx in state.validators.vindices:
      # Get the actual pubkey from the validator
      let pubkey = state.validators.item(vidx).pubkey()

      if not verify_execution_payload_envelope_signature(
        state.fork, state.genesis_validators_root, 
        signed_envelope, state,pubkey, signed_envelope.signature):
        return err("payload_envelope: signature verification failure")

  let
    envelope = signed_envelope.message
    payload = envelope.payload
    previous_state_root = hash_tree_root(state)

  if state.latest_block_header.state_root == ZERO_HASH:
    state.latest_block_header.state_root = previous_state_root

  if not (envelope.beacon_block_root == hash_tree_root(state.latest_block_header)):
    return err("process_execution_payload: beacon block and latest block mismatch")

  let committed_header = state.latest_execution_payload_header
  if not (envelope.builder_index == committed_header.builder_index):
    return err("process_execution_payload: builder mismatch")

  let committed_header_root = hash_tree_root(committed_header.blob_kzg_commitments_root)
  if not (committed_header_root == hash_tree_root(envelope.blob_kzg_commitments)):
    return err("process_execution_payload: Blob KZG commitments root mismatch.")

  if not envelope.payload_withheld:
    if not (hash_tree_root(payload.withdrawals) == state.latest_withdrawals_root):
      return err("process_execution_payload: builder mismatch")

    if not (committed_header.gas_limit == payload.gas_limit):
      return err("process_execution_payload: Gas limit mismatch.")

    if not (committed_header.block_hash == payload.block_hash):
      return err("process_execution_payload: Block hash mismatch.")

    if not (payload.parent_hash == state.latest_block_hash):
      return err("process_execution_payload: parent hash mismatch.")

    if not (payload.prev_randao == get_randao_mix(state, get_current_epoch(state))):
      return err("process_execution_payload: prev_randao mismatch.")

    if not (payload.timestamp == compute_timestamp_at_slot(state, state.slot)):
      return err("process_execution_payload: timestamp mismatch.")

    if not (lenu64(envelope.blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK):
      return err("Blob commitments exceed limit.")

    if not notify_new_payload(payload):
      return err("process_execution_payload: execution payload invalid")

    # # [TODO] process electra operations
    # var
    #   bsv_use =
    #     when typeof(other_body).kind == ConsensusFork.Electra:
    #       other_body.deposits.len + other_body.execution_payload.deposit_requests.len +
    #       other_body.execution_payload.withdrawal_requests.len +
    #       other_body.execution_payload.consolidation_requests.len > 0
    #     else:
    #       other_body.deposits.len > 0
    #   bsv =
    #     if bsv_use:
    #       sortValidatorBuckets(state.validators.asSeq)
    #     else:
    #       nil     # this is a logic error, effectively assert

    # when typeof(other_body).kind == ConsensusFork.Electra:
    #   for op in other_body.execution_payload.deposit_requests:
    #     ? process_deposit_request(cfg, state, bsv[], op, {})
    #   for op in other_body.execution_payload.withdrawal_requests:
    #     process_withdrawal_request(cfg, state, bsv[], op, cache)
    #   for op in other_body.execution_payload.consolidation_requests:
    #     process_consolidation_request(cfg, state, bsv[], op, cache)

    state.latest_block_hash = payload.block_hash
    state.latest_full_slot = state.slot

  if verify:
    doAssert envelope.state_root == hash_tree_root(state)
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#modified-is_merge_transition_complete
func is_merge_transition_complete*(state: epbs.BeaconState): bool =
  true

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#modified-validate_merge_block
func validate_merge_block*(blck: epbs.BeaconBlock): bool =
  true