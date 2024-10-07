# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  ssz_serialization,
  ./base

export base

const
  # https://eips.ethereum.org/EIPS/eip-7688
  MAX_ATTESTATION_FIELDS* = 8
  MAX_INDEXED_ATTESTATION_FIELDS* = 8
  MAX_EXECUTION_PAYLOAD_FIELDS* = 64
  MAX_EXECUTION_REQUESTS_FIELDS* = 16
  MAX_BEACON_BLOCK_BODY_FIELDS* = 64
  MAX_BEACON_STATE_FIELDS* = 128

  # https://eips.ethereum.org/EIPS/eip-6404
  SECP256K1_SIGNATURE_SIZE* = 65
  MAX_EXECUTION_SIGNATURE_FIELDS* = 16
  MAX_FEES_PER_GAS_FIELDS* = 16
  MAX_CALLDATA_SIZE* = 16_777_216
  MAX_ACCESS_LIST_STORAGE_KEYS* = 524_288
  MAX_ACCESS_LIST_SIZE* = 524_288
  MAX_AUTHORIZATION_PAYLOAD_FIELDS* = 16
  MAX_AUTHORIZATION_LIST_SIZE* = 65_536
  MAX_TRANSACTION_PAYLOAD_FIELDS* = 32

type
  # TODO this apparently is suppposed to be SSZ-equivalent to Bytes32, but
  # current spec doesn't ever SSZ-serialize it or hash_tree_root it
  # TODO make `distinct` then add a REST serialization for it specifically, via
  # basically to0xHex, then fix BlobSidecarInfoObject to use VersionedHash, not
  # string, and rely on REST serialization, rather than serialize VersionedHash
  # field manually
  VersionedHash* = array[32, byte]

  Eip6404ExecutionSignature* {.
      sszStableContainer: MAX_EXECUTION_SIGNATURE_FIELDS.} = object
    secp256k1*: Opt[array[SECP256K1_SIGNATURE_SIZE, byte]]

  TransactionType* = uint8
  ChainId* = uint64

  Eip6404FeesPerGas* {.sszStableContainer: MAX_FEES_PER_GAS_FIELDS.} = object
    regular*: Opt[UInt256]

    # EIP-4844
    blob*: Opt[UInt256]

  Eip6404AccessTuple* = object
    address*: ExecutionAddress
    storage_keys*: List[Eth2Digest, Limit MAX_ACCESS_LIST_STORAGE_KEYS]

  Eip6404AuthorizationPayload* {.
      sszStableContainer: MAX_AUTHORIZATION_PAYLOAD_FIELDS.} = object
    magic*: Opt[TransactionType]
    chain_id*: Opt[ChainId]
    address*: Opt[ExecutionAddress]
    nonce*: Opt[uint64]

  Eip6404Authorization* = object
    payload*: Eip6404AuthorizationPayload
    signature*: Eip6404ExecutionSignature

  Eip6404TransactionPayload* {.
      sszStableContainer: MAX_TRANSACTION_PAYLOAD_FIELDS.} = object
    # EIP-2718
    `type`*: Opt[uint8]

    # EIP-155
    chain_id*: Opt[ChainId]

    nonce*: Opt[uint64]
    max_fees_per_gas*: Opt[Eip6404FeesPerGas]
    gas*: Opt[uint64]
    to*: Opt[ExecutionAddress]
    value*: Opt[UInt256]
    input*: Opt[List[byte, Limit MAX_CALLDATA_SIZE]]

    # EIP-2930
    access_list*: Opt[List[Eip6404AccessTuple, Limit MAX_ACCESS_LIST_SIZE]]

    # EIP-1559
    max_priority_fees_per_gas*: Opt[Eip6404FeesPerGas]

    # EIP-4844
    blob_versioned_hashes*:
      Opt[List[VersionedHash, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]]

    # EIP-7702
    authorization_list*:
      Opt[List[Eip6404Authorization, Limit MAX_AUTHORIZATION_LIST_SIZE]]

  Eip6404Transaction* = object
    payload*: Eip6404TransactionPayload
    signature*: Eip6404ExecutionSignature

  # https://eips.ethereum.org/EIPS/eip-7688
  StableAttestation* {.
      sszStableContainer: MAX_ATTESTATION_FIELDS.} = object
    aggregation_bits*: Opt[ElectraCommitteeValidatorsBits]
    data*: Opt[AttestationData]
    signature*: Opt[ValidatorSig]
    committee_bits*: Opt[AttestationCommitteeBits]

  StableIndexedAttestation* {.
      sszStableContainer: MAX_INDEXED_ATTESTATION_FIELDS.} = object
    attesting_indices*: Opt[List[uint64,
      Limit MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]]
    data*: Opt[AttestationData]
    signature*: Opt[ValidatorSig]

  StableAttesterSlashing* = object
    attestation_1*: StableIndexedAttestation
    attestation_2*: StableIndexedAttestation

  StableExecutionPayload* {.
      sszStableContainer: MAX_EXECUTION_PAYLOAD_FIELDS.} = object
    # Execution block header fields
    parent_hash*: Opt[Eth2Digest]
    fee_recipient*: Opt[ExecutionAddress]
      ## 'beneficiary' in the yellow paper
    state_root*: Opt[Eth2Digest]
    receipts_root*: Opt[Eth2Digest]
    logs_bloom*: Opt[BloomLogs]
    prev_randao*: Opt[Eth2Digest]
      ## 'difficulty' in the yellow paper
    block_number*: Opt[uint64]
      ## 'number' in the yellow paper
    gas_limit*: Opt[uint64]
    gas_used*: Opt[uint64]
    timestamp*: Opt[uint64]
    extra_data*: Opt[List[byte, MAX_EXTRA_DATA_BYTES]]
    base_fee_per_gas*: Opt[UInt256]

    # Extra payload fields
    block_hash*: Opt[Eth2Digest] # Hash of execution block
    transactions*: Opt[List[Eip6404Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]]
    withdrawals*: Opt[List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]]
    blob_gas_used*: Opt[uint64]
    excess_blob_gas*: Opt[uint64]

  StableExecutionPayloadHeader* {.
      sszStableContainer: MAX_EXECUTION_PAYLOAD_FIELDS.} = object
    # Execution block header fields
    parent_hash*: Opt[Eth2Digest]
    fee_recipient*: Opt[ExecutionAddress]
    state_root*: Opt[Eth2Digest]
    receipts_root*: Opt[Eth2Digest]
    logs_bloom*: Opt[BloomLogs]
    prev_randao*: Opt[Eth2Digest]
    block_number*: Opt[uint64]
    gas_limit*: Opt[uint64]
    gas_used*: Opt[uint64]
    timestamp*: Opt[uint64]
    extra_data*: Opt[List[byte, MAX_EXTRA_DATA_BYTES]]
    base_fee_per_gas*: Opt[UInt256]

    # Extra payload fields
    block_hash*: Opt[Eth2Digest]
      ## Hash of execution block
    transactions_root*: Opt[Eth2Digest]
    withdrawals_root*: Opt[Eth2Digest]
    blob_gas_used*: Opt[uint64]
    excess_blob_gas*: Opt[uint64]

  StableExecutionRequests* {.
      sszStableContainer: MAX_EXECUTION_REQUESTS_FIELDS.} = object
    deposits*:
      Opt[List[DepositRequest,
        Limit MAX_DEPOSIT_REQUESTS_PER_PAYLOAD]]
    withdrawals*:
      Opt[List[WithdrawalRequest,
        Limit MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD]]
    consolidations*:
      Opt[List[ConsolidationRequest,
        Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD]]

  StableBeaconBlockBody* {.
      sszStableContainer: MAX_BEACON_BLOCK_BODY_FIELDS.} = object
    randao_reveal*: Opt[ValidatorSig]
    eth1_data*: Opt[Eth1Data]
      ## Eth1 data vote

    graffiti*: Opt[GraffitiBytes]
      ## Arbitrary data

    # Operations
    proposer_slashings*: Opt[List[ProposerSlashing,
      Limit MAX_PROPOSER_SLASHINGS]]
    attester_slashings*: Opt[List[StableAttesterSlashing,
      Limit MAX_ATTESTER_SLASHINGS_ELECTRA]]
    attestations*: Opt[List[StableAttestation, Limit MAX_ATTESTATIONS_ELECTRA]]
    deposits*: Opt[List[Deposit, Limit MAX_DEPOSITS]]
    voluntary_exits*: Opt[List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]]

    sync_aggregate*: Opt[SyncAggregate]

    # Execution
    execution_payload*: Opt[StableExecutionPayload]
    bls_to_execution_changes*: Opt[SignedBLSToExecutionChangeList]
    blob_kzg_commitments*: Opt[KzgCommitments]
    execution_requests*: Opt[StableExecutionRequests]

  StableBeaconState* {.sszStableContainer: MAX_BEACON_STATE_FIELDS.} = object
    # Versioning
    genesis_time*: Opt[uint64]
    genesis_validators_root*: Opt[Eth2Digest]
    slot*: Opt[Slot]
    fork*: Opt[Fork]

    # History
    latest_block_header*: Opt[BeaconBlockHeader]
      ## `latest_block_header.state_root == ZERO_HASH` temporarily

    block_roots*: Opt[HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]]
      ## Needed to process attestations, older to newer

    state_roots*: Opt[HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]]
    historical_roots*: Opt[HashList[Eth2Digest, Limit HISTORICAL_ROOTS_LIMIT]]
      ## Frozen in Capella, replaced by historical_summaries

    # Eth1
    eth1_data*: Opt[Eth1Data]
    eth1_data_votes*: Opt[HashList[Eth1Data,
      Limit(EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH)]]
    eth1_deposit_index*: Opt[uint64]

    # Registry
    validators*: Opt[HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT]]
    balances*: Opt[HashList[Gwei, Limit VALIDATOR_REGISTRY_LIMIT]]

    # Randomness
    randao_mixes*: Opt[HashArray[
      Limit EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest]]

    # Slashings
    slashings*: Opt[HashArray[Limit EPOCHS_PER_SLASHINGS_VECTOR, Gwei]]
      ## Per-epoch sums of slashed effective balances

    # Participation
    previous_epoch_participation*: Opt[EpochParticipationFlags]
    current_epoch_participation*: Opt[EpochParticipationFlags]

    # Finality
    justification_bits*: Opt[JustificationBits]
      ## Bit set for every recent justified epoch

    previous_justified_checkpoint*: Opt[Checkpoint]
    current_justified_checkpoint*: Opt[Checkpoint]
    finalized_checkpoint*: Opt[Checkpoint]

    # Inactivity
    inactivity_scores*: Opt[InactivityScores]

    # Light client sync committees
    current_sync_committee*: Opt[SyncCommittee]
    next_sync_committee*: Opt[SyncCommittee]

    # Execution
    latest_execution_payload_header*: Opt[StableExecutionPayloadHeader]

    # Withdrawals
    next_withdrawal_index*: Opt[WithdrawalIndex]
    next_withdrawal_validator_index*: Opt[uint64]

    # Deep history valid from Capella onwards
    historical_summaries*:
      Opt[HashList[HistoricalSummary, Limit HISTORICAL_ROOTS_LIMIT]]

    deposit_requests_start_index*: Opt[uint64]
    deposit_balance_to_consume*: Opt[Gwei]
    exit_balance_to_consume*: Opt[Gwei]
    earliest_exit_epoch*: Opt[Epoch]
    consolidation_balance_to_consume*: Opt[Gwei]
    earliest_consolidation_epoch*: Opt[Epoch]
    pending_balance_deposits*: Opt[HashList[PendingBalanceDeposit,
      Limit PENDING_BALANCE_DEPOSITS_LIMIT]]

    pending_partial_withdrawals*: Opt[HashList[PendingPartialWithdrawal,
      Limit PENDING_PARTIAL_WITHDRAWALS_LIMIT]]
    pending_consolidations*: Opt[HashList[PendingConsolidation,
      Limit PENDING_CONSOLIDATIONS_LIMIT]]
