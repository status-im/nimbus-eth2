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
    chronicles, metrics,
    ../extras,
    ./datatypes/[phase0, altair, bellatrix, deneb, epbs],
    "."/[beaconstate, eth2_merkleization, helpers, validator, signatures,
            payload_attestations],
    kzg4844/kzg_abi, kzg4844/kzg_ex

from ./datatypes/capella import
    BeaconState, MAX_WITHDRAWALS_PER_PAYLOAD, SignedBLSToExecutionChange,
    Withdrawal
from ./datatypes/electra import PendingPartialWithdrawal
from ./state_transition_block import BlockRewards

export extras, phase0, altair
# The entry point is `process_block` which is at the bottom of this file.

func process_withdrawals*(
    state: var (capella.BeaconState | deneb.BeaconState | electra.BeaconState |
            epbs.BeaconState)):
    Result[void, cstring] =
    # return early if the parent block was empty
    if not is_parent_block_full(state):
        return

    when typeof(state).kind >= ConsensusFork.Electra:
        let (withdrawals, partial_withdrawals_count) =
            get_expected_withdrawals_with_partial_count(state)

        # Update pending partial withdrawals [New in Electra:EIP7251]
        # Moved slightly earlier to be in same when block
        state.pending_partial_withdrawals =
            HashList[PendingPartialWithdrawal,
                    Limit PENDING_PARTIAL_WITHDRAWALS_LIMIT].init(
              state.pending_partial_withdrawals.asSeq[
                      partial_withdrawals_count .. ^1])
    else:
        let withdrawals = get_expected_withdrawals(state)

    let withdrawals_list = withdrawals[0 ..< min(len(withdrawals),
            MAX_WITHDRAWALS_PER_PAYLOAD)]

#   withdrawals_list = HashList[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD](withdrawals)

    state.latest_withdrawals_root = hash_tree_root(withdrawals_list)
    for withdrawal in withdrawals:
        decrease_balance(state, withdrawal.validator_index, withdrawal.amount)

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
        let next_index =
            state.next_withdrawal_validator_index +
              MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP
        let next_validator_index = next_index mod lenu64(state.validators)
        state.next_withdrawal_validator_index = next_validator_index

    ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#new-verify_execution_payload_header_signature
func compute_execution_payload_header_signing_root*(
    genesisFork: Fork, genesis_validators_root: Eth2Digest,
    msg: epbs.SignedExecutionPayloadHeader): Eth2Digest =
  # So the epoch doesn't matter when calling get_domain
  doAssert genesisFork.previous_version == genesisFork.current_version

  # Fork-agnostic domain since address changes are valid across forks
  let domain = get_domain(
    genesisFork, DOMAIN_BEACON_BUILDER, GENESIS_EPOCH,
    genesis_validators_root)
  compute_signing_root(msg.message, domain)

proc get_verify_execution_payload_header_signature*(
    genesisFork: Fork, genesis_validators_root: Eth2Digest,
    msg: SignedExecutionPayloadHeader, privkey: ValidatorPrivKey):
    CookedSig =
  let signing_root = compute_execution_payload_header_signing_root(
    genesisFork, genesis_validators_root, msg)
  blsSign(privkey, signing_root.data)

proc verify_execution_payload_header_signature*(
    genesisFork: Fork, genesis_validators_root: Eth2Digest,
    msg: epbs.ExecutionPayloadHeader,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  let signing_root = compute_execution_payload_header_signing_root(
    genesisFork, genesis_validators_root, msg.message)
  blsVerify(pubkey, signing_root.data, signature)

# # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#new-process_execution_payload_header
# proc process_execution_payload_header*(state: var epbs.BeaconState,
#         blck: epbs.BeaconBlock): Result[void, cstring] =
#     # Verify the header signature
#     let signed_header = blck.body.signed_execution_payload_header
#     if not verify_execution_payload_header_signature(state, blck.body.signed_execution_payload_header):
#       return err("invalid execution payload header signature")

#     # Check that the builder has funds to cover the bid
#     let header = signed_header.message
#     let builder_index = header.builder_index
#     let amount = header.value

#     if state.balances.item(builder_index) < amount:
#       return err("insufficient balance")

#     # Verify that the bid is for the current slot
#     if header.slot != blck.slot:
#       return err("slot mismatch")

#     # Verify that the bid is for the right parent block
#     if header.parent_block_hash != state.latest_block_hash:
#       return err("parent block hash mismatch")

#     if header.parent_block_root != blck.parent_root:
#       return err("parent block root mismatch")

#     # Convert proposer index to ValidatorIndex
#     let proposer_index = ValidatorIndex.init(blck.proposer_index).valueOr:
#       return err("process_execution_payload_header: proposer index out of range")

#     # Transfer the funds from the builder to the proposer
#     decrease_balance(state, builder_index, amount)
#     increase_balance(state, proposer_index, amount)

#     # Cache the signed execution payload header
#     state.latest_execution_payload_header = header

#     ok()

from ".."/validator_bucket_sort import sortValidatorBuckets

proc process_operations(
    cfg: RuntimeConfig, state: var ForkyBeaconState,
    body: SomeForkyBeaconBlockBody, base_reward_per_increment: Gwei,
    flags: UpdateFlags, cache: var StateCache): Result[BlockRewards, cstring] =

    # Verify that outstanding deposits are processed up to the maximum number of deposits
    when typeof(body).kind >= ConsensusFork.Epbs:
        let req_deposits = min(
            MAX_DEPOSITS, state.eth1_data.deposit_count -
            state.eth1_deposit_index
        )

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
                default(ExitQueueInfo) # not used

        bsv_use =
            when typeof(body).kind >= ConsensusFork.Electra:
                body.deposits.len + body.execution_payload.deposit_requests.len +
                body.execution_payload.withdrawal_requests.len +
                body.execution_payload.consolidation_requests.len > 0
            else:
                body.deposits.len > 0

        bsv =
            if bsv_use:
                sortValidatorBuckets(state.validators.asSeq)
            else:
                nil  # this is a logic error, effectively assert

    for op in body.proposer_slashings:
        let (proposer_slashing_reward, new_exit_queue_info) =
            ?process_proposer_slashing(cfg, state, op, flags, exit_queue_info, cache)
        operations_rewards.proposer_slashings += proposer_slashing_reward
        exit_queue_info = new_exit_queue_info

    for op in body.attester_slashings:
        let (attester_slashing_reward, new_exit_queue_info) =
            ?process_attester_slashing(cfg, state, op, flags, exit_queue_info, cache)
        operations_rewards.attester_slashings += attester_slashing_reward
        exit_queue_info = new_exit_queue_info

    for op in body.attestations:
        operations_rewards.attestations +=
            ?process_attestation(state, op, flags, base_reward_per_increment, cache)

    for op in body.deposits:
        ?process_deposit(cfg, state, bsv[], op, flags)

    for op in body.voluntary_exits:
        exit_queue_info = ?process_voluntary_exit(
            cfg, state, op, flags, exit_queue_info, cache
        )

    when typeof(body).kind >= ConsensusFork.Capella:
        for op in body.bls_to_execution_changes:
            ?process_bls_to



# # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#process_payload_attestation
# proc processPayloadAttestation*(state: var epbs.BeaconState, payloadAttestation: PayloadAttestation): void =
#   # Check that the attestation is for the parent beacon block
#   let data = payloadAttestation.data
#   assert data.beaconBlockRoot == state.latestBlockHeader.parentRoot

#   # Check that the attestation is for the previous slot
#   assert data.slot + 1 == state.slot

#   # Verify signature
#   let indexedPayloadAttestation = getIndexedPayloadAttestation(state, data.slot, payloadAttestation)
#   assert isValidIndexedPayloadAttestation(state, indexedPayloadAttestation)

#   var epochParticipation: seq[ParticipationFlags]
#   if state.slot mod SLOTS_PER_EPOCH == 0:
#     epochParticipation = state.previousEpochParticipation
#   else:
#     epochParticipation = state.currentEpochParticipation

#   # Return early if the attestation is for the wrong payload status
#   let payloadWasPresent = data.slot == state.latestFullSlot
#   let votedPresent = data.payloadStatus == PAYLOAD_PRESENT
#   let proposerRewardDenominator = (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR div PROPOSER_WEIGHT
#   let proposerIndex = getBeaconProposerIndex(state)

#   if votedPresent != payloadWasPresent:
#     # Unset the flags in case they were set by an equivocating ptc attestation
#     var proposerPenaltyNumerator: Gwei = 0
#     for index in indexedPayloadAttestation.attestingIndices:
#       for flagIndex, weight in PARTICIPATION_FLAG_WEIGHTS:
#         if hasFlag(epochParticipation[index], flagIndex):
#           epochParticipation[index] = removeFlag(epochParticipation[index], flagIndex)
#           proposerPenaltyNumerator += getBaseReward(state, index) * weight
#     # Penalize the proposer
#     let proposerPenalty = Gwei(2 * proposerPenaltyNumerator div proposerRewardDenominator)
#     decreaseBalance(state, proposerIndex, proposerPenalty)
#     return

#   # Reward the proposer and set all the participation flags in case of correct attestations
#   var proposerRewardNumerator: Gwei = 0
#   for index in indexedPayloadAttestation.attestingIndices:
#     for flagIndex, weight in PARTICIPATION_FLAG_WEIGHTS:
#       if not hasFlag(epochParticipation[index], flagIndex):
#         epochParticipation[index] = addFlag(epochParticipation[index], flagIndex)
#         proposerRewardNumerator += getBaseReward(state, index) * weight

#   # Reward proposer
#   let proposerReward = Gwei(proposerRewardNumerator div proposerRewardDenominator)
#   increaseBalance(state, proposerIndex, proposerReward)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#new-verify_execution_payload_envelope_signature
# proc verifyExecutionPayloadEnvelopeSignature*(state: epbs.BeaconState, signedEnvelope: SignedExecutionPayloadEnvelope): bool =
#   let builder = state.validators[signedEnvelope.message.builderIndex]
#   let domain = get_domain(
#     state.fork, DOMAIN_BEACON_BUILDER, GENESIS_EPOCH,
#     state.genesis_validators_root)
#   let signingRoot = compute_signing_root(signedEnvelope.message, domain)
#   blsVerify(builder.pubkey, signingRoot, signedEnvelope.signature)

# type SomeEpbsBeaconBlockBody =
#   epbs.BeaconBlockBody | epbs.SigVerifiedBeaconBlockBody |
#   epbs.TrustedBeaconBlockBody

# # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#modified-process_execution_payload
# proc process_execution_payload*(
#     state: var epbs.BeaconState, signed_envelope: SignedExecutionPayloadEnvelope,
#     execution_engine: epbs.ExecutePayload, verify: bool = True): Result[void, cstring] =
#   template payload: auto = body.execution_payload

# if verify:
#     assert verifyExecutionPayloadEnvelopeSignature(state, signedEnvelope)

#   let envelope = signedEnvelope.message
#   let payload = envelope.payload

#   # Cache latest block header state root
#   let previousStateRoot = hashTreeRoot(state)
#   if state.latest_block_header.state_root == Root():
#     state.latest_block_header.state_root = previousStateRoot

#   # Verify consistency with the beacon block
#   assert envelope.beacon_block_root == hashTreeRoot(state.latest_block_header)

#   # Verify consistency with the committed header
#   let committedHeader = state.latest_execution_payload_header
#   assert envelope.builder_index == committedHeader.builder_index
#   assert committedHeader.blob_kzg_commitments_root == hashTreeRoot(envelope.blob_kzg_commitments)

#   if not envelope.payload_withheld:
#     # Verify the withdrawals root
#     assert hashTreeRoot(payload.withdrawals) == state.latest_withdrawals_root

#     # Verify the gas limit
#     assert committedHeader.gas_limit == payload.gas_limit

#     # Verify the block hash
#     assert committedHeader.block_hash == payload.block_hash

#     # Verify consistency of the parent hash with respect to the previous execution payload
#     assert payload.parent_hash == state.latest_block_hash

#     # Verify prev_randao
#     assert payload.prev_randao == getRandaoMix(state, getCurrentEpoch(state))

#     # Verify timestamp
#     assert payload.timestamp == computeTimestampAtSlot(state, state.slot)

#     # Verify commitments are under limit
#     assert envelope.blob_kzg_commitments.len <= MAX_BLOBS_PER_BLOCK

#     # Verify the execution payload is valid
#     let versionedHashes = envelope.blob_kzg_commitments.map(kzgCommitmentToVersionedHash)
#     assert executionEngine.verifyAndNotifyNewPayload(NewPayloadRequest(
#       execution_payload = payload,
#       versioned_hashes = versionedHashes,
#       parent_beacon_block_root = state.latest_block_header.parent_root
#     ))

#   ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#modified-is_merge_transition_complete
func is_merge_transition_complete*(state: epbs.BeaconState): bool =

    const header =
        default(typeof(state.latest_execution_payload_header))

    # [TODO] = type mismatch Digest & KzgCommitments
    # var kzgs: List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]
    # header.blob_kzg_commitments_root = kzgs.hash_tree_root()

    state.latest_execution_payload_header != header

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#modified-validate_merge_block
# proc validate_merge_block*(block: epbs.BeaconBlock) =
#   """
#   Check the parent PoW block of execution payload is a valid terminal PoW block.

#   Note: Unavailable PoW block(s) may later become available,
#   and a client software MAY delay a call to `validateMergeBlock`
#   until the PoW block(s) become available.
#   """
#   if TERMINAL_BLOCK_HASH != Hash32():
#     # If `TERMINAL_BLOCK_HASH` is used as an override, the activation epoch must be reached.
#     assert computeEpochAtSlot(block.slot) >= TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH
#     assert block.body.signedExecutionPayloadHeader.message.parentBlockHash == TERMINAL_BLOCK_HASH
#     return

#   # Modified in EIP-7732
#   let powBlock = getPoWBlock(block.body.signedExecutionPayloadHeader.message.parentBlockHash)
#   # Check if `powBlock` is available
#   assert powBlock.isSome
#   let powParent = getPoWBlock(powBlock.get.parentHash)
#   # Check if `powParent` is available
#   assert powParent.isSome
#   # Check if `powBlock` is a valid terminal PoW block
#   assert isValidTerminalPoWBlock(powBlock.get, powParent.get)
