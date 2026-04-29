# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Types specific to Fulu (i.e. known to have changed across hard forks) - see
# `base` for types and guidelines common across forks

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

import
  std/typetraits,
  ./[phase0, base, bellatrix, electra, fulu],
  chronicles,
  stew/bitops2,
  json_serialization,
  ssz_serialization/[merkleization, proofs],
  ssz_serialization/types as sszTypes,
  ../[digest, ssz_codec],
  kzg4844/[kzg, kzg_abi]

from ./altair import
  EpochParticipationFlags, InactivityScores, SyncAggregate, SyncCommittee,
  TrustedSyncAggregate, SyncnetBits, num_active_participants
from ./capella import
  BeaconBlockBody, ExecutionBranch, HistoricalSummary,
  SignedBLSToExecutionChange, SignedBLSToExecutionChangeList,
  Withdrawal, EXECUTION_PAYLOAD_GINDEX
from ./deneb import
  Blobs, KzgCommitments, KzgProofs

export json_serialization, base

type
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/fork-choice.md#custom-types
  PayloadStatus* = uint8

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#custom-types
  BuilderIndex* = uint64

const
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/fork-choice.md#constants
  PAYLOAD_TIMELY_THRESHOLD*: uint64 = PTC_SIZE div 2
  PAYLOAD_STATUS_PENDING* = PayloadStatus(0)
  PAYLOAD_STATUS_EMPTY* = PayloadStatus(1)
  PAYLOAD_STATUS_FULL* = PayloadStatus(2)

type
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/p2p-interface.md#modified-datacolumnsidecar
  DataColumnSidecar* = object
    index*: ColumnIndex
    column*: DataColumn
    # [Modified in Gloas:EIP7732]
    # Removed `kzg_commitments`
    kzg_proofs*: deneb.KzgProofs
    # [Modified in Gloas:EIP7732]
    # Removed `signed_block_header`
    # [Modified in Gloas:EIP7732]
    # Removed `kzg_commitments_inclusion_proof`
    # [New in Gloas:EIP7732]
    slot*: Slot
    # [New in Gloas:EIP7732]
    beacon_block_root*: Eth2Digest

  DataColumnSidecars* = seq[ref DataColumnSidecar]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/beacon-chain.md#executionpayload
  ExecutionPayload* = object
    parent_hash*: Eth2Digest
    fee_recipient*: ExecutionAddress
    state_root*: Eth2Digest
    receipts_root*: Eth2Digest
    logs_bloom*: BloomLogs
    prev_randao*: Eth2Digest
    block_number*: uint64
    gas_limit*: uint64
    gas_used*: uint64
    timestamp*: uint64
    extra_data*: List[byte, MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas*: UInt256
    block_hash*: Eth2Digest
    transactions*: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]
    withdrawals*: List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]
    blob_gas_used*: uint64
    excess_blob_gas*: uint64
    # [New in Gloas:EIP7928]
    block_access_list*: List[byte, MAX_BYTES_PER_TRANSACTION]
    # [New in Gloas:EIP7843]
    slot_number*: Slot

  ExecutionPayloadForSigning* = object
    executionPayload*: ExecutionPayload
    blockValue*: Wei
    blobsBundle*: fulu.BlobsBundle # [New in Fulu]
    executionRequests*: seq[seq[byte]]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/beacon-chain.md#executionpayloadbid
  ExecutionPayloadBid* = object
    parent_block_hash*: Eth2Digest
    parent_block_root*: Eth2Digest
    block_hash*: Eth2Digest
    prev_randao*: Eth2Digest
    fee_recipient*: ExecutionAddress
    gas_limit*: uint64
    builder_index*: uint64
    slot*: Slot
    value*: Gwei
    execution_payment*: Gwei
    blob_kzg_commitments*: KzgCommitments
    execution_requests_root*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/beacon-chain.md#signedexecutionpayloadbid
  SignedExecutionPayloadBid* = object
    message*: ExecutionPayloadBid
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/beacon-chain.md#executionpayloadenvelope
  ExecutionPayloadEnvelope* = object
    payload*: ExecutionPayload
    execution_requests*: ExecutionRequests
    builder_index*: uint64
    beacon_block_root*: Eth2Digest

  TrustedExecutionPayloadEnvelope* = object
    payload*: ExecutionPayload
    execution_requests*: ExecutionRequests
    builder_index*: uint64
    beacon_block_root*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#signedexecutionpayloadenvelope
  SignedExecutionPayloadEnvelope* = object
    message*: ExecutionPayloadEnvelope
    signature*: ValidatorSig

  TrustedSignedExecutionPayloadEnvelope* = object
    message*: TrustedExecutionPayloadEnvelope
    signature*: TrustedSig

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#payloadattestationdata
  PayloadAttestationData* = object
    beacon_block_root*: Eth2Digest
    slot*: Slot
    payload_present*: bool
    blob_data_available*: bool

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#payloadattestation
  PayloadAttestation* = object
    aggregation_bits*: BitArray[int PTC_SIZE]
    data*: PayloadAttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#payloadattestationmessage
  PayloadAttestationMessage* = object
    validator_index*: uint64
    data*: PayloadAttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#indexedpayloadattestation
  IndexedPayloadAttestation* = object
    attesting_indices*: List[uint64, Limit PTC_SIZE]
    data*: PayloadAttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#builder
  Builder* = object
    pubkey*: ValidatorPubKey
    version*: uint8
    execution_address*: ExecutionAddress
    balance*: Gwei
    deposit_epoch*: Epoch
    withdrawable_epoch*: Epoch

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#builderpendingwithdrawal
  BuilderPendingWithdrawal* = object
    fee_recipient*: ExecutionAddress
    amount*: Gwei
    builder_index*: uint64

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#builderpendingpayment
  BuilderPendingPayment* = object
    weight*: Gwei
    withdrawal*: BuilderPendingWithdrawal

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/p2p-interface.md#new-proposerpreferences
  ProposerPreferences* = object
    proposal_slot*: Slot
    validator_index*: uint64
    fee_recipient*: ExecutionAddress
    gas_limit*: uint64

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.0/specs/gloas/p2p-interface.md#new-signedproposerpreferences
  SignedProposerPreferences* = object
    message*: ProposerPreferences
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/beacon-chain.md#beaconstate
  BeaconState* = object
    # Versioning
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot
    fork*: Fork

    # History
    latest_block_header*: BeaconBlockHeader
      ## `latest_block_header.state_root == ZERO_HASH` temporarily

    block_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
      ## Needed to process attestations, older to newer

    state_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    historical_roots*: HashList[Eth2Digest, Limit HISTORICAL_ROOTS_LIMIT]
      ## Frozen in Capella, replaced by historical_summaries

    # Eth1
    eth1_data*: Eth1Data
    eth1_data_votes*:
      HashList[Eth1Data, Limit(EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH)]
    eth1_deposit_index*: uint64

    # Registry
    validators*: HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT]
    balances*: HashList[Gwei, Limit VALIDATOR_REGISTRY_LIMIT]

    # Randomness
    randao_mixes*: HashArray[Limit EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest]

    # Slashings
    slashings*: HashArray[Limit EPOCHS_PER_SLASHINGS_VECTOR, Gwei]
      ## Per-epoch sums of slashed effective balances

    # Participation
    previous_epoch_participation*: EpochParticipationFlags
    current_epoch_participation*: EpochParticipationFlags

    # Finality
    justification_bits*: JustificationBits
      ## Bit set for every recent justified epoch

    previous_justified_checkpoint*: Checkpoint
    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint

    # Inactivity
    inactivity_scores*: InactivityScores

    # Light client sync committees
    current_sync_committee*: SyncCommittee
    next_sync_committee*: SyncCommittee

    # [New in Gloas:EIP7732]
    latest_block_hash*: Eth2Digest

    # Withdrawals
    next_withdrawal_index*: WithdrawalIndex
    next_withdrawal_validator_index*: uint64

    # Deep history valid from Capella onwards
    historical_summaries*:
      HashList[HistoricalSummary, Limit HISTORICAL_ROOTS_LIMIT]

    deposit_requests_start_index*: uint64  # [New in Electra:EIP6110]
    deposit_balance_to_consume*: Gwei  # [New in Electra:EIP7251]
    exit_balance_to_consume*: Gwei  # [New in Electra:EIP7251]
    earliest_exit_epoch*: Epoch  # [New in Electra:EIP7251]
    consolidation_balance_to_consume*: Gwei  # [New in Electra:EIP7251]
    earliest_consolidation_epoch*: Epoch  # [New in Electra:EIP7251]
    pending_deposits*: HashList[PendingDeposit, Limit PENDING_DEPOSITS_LIMIT]
      ## [New in Electra:EIP7251]

    # [New in Electra:EIP7251]
    pending_partial_withdrawals*:
      HashList[PendingPartialWithdrawal, Limit PENDING_PARTIAL_WITHDRAWALS_LIMIT]
    pending_consolidations*:
      HashList[PendingConsolidation, Limit PENDING_CONSOLIDATIONS_LIMIT]

    # [New in Fulu:EIP7917]
    proposer_lookahead*:
        HashArray[Limit ((MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH), uint64]

    # [New in Gloas:EIP7732]
    builders*: HashList[Builder, Limit BUILDER_REGISTRY_LIMIT]
    # [New in Gloas:EIP7732]
    next_withdrawal_builder_index*: uint64
    # [New in Gloas:EIP7732]
    execution_payload_availability*: BitArray[int(SLOTS_PER_HISTORICAL_ROOT)]
    # [New in Gloas:EIP7732]
    builder_pending_payments*:
      HashArray[Limit 2 * SLOTS_PER_EPOCH, BuilderPendingPayment]
    # [New in Gloas:EIP7732]
    builder_pending_withdrawals*:
      HashList[BuilderPendingWithdrawal, Limit BUILDER_PENDING_WITHDRAWALS_LIMIT]

    # Execution
    # [Modified in Gloas:EIP7732]
    latest_execution_payload_bid*: gloas.ExecutionPayloadBid

    # [New in Gloas:EIP7732]
    payload_expected_withdrawals*:
      HashList[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]
    # [New in Gloas:EIP7732]
    ptc_window*:
      HashArray[Limit ((2 + MIN_SEED_LOOKAHEAD) * SLOTS_PER_EPOCH),
        HashArray[Limit PTC_SIZE, uint64]]

  # TODO Careful, not nil analysis is broken / incomplete and the semantics will
  #      likely change in future versions of the language:
  #      https://github.com/nim-lang/RFCs/issues/250
  BeaconStateRef* = ref BeaconState not nil
  NilableBeaconStateRef* = ref BeaconState

  # TODO: There should be only a single generic HashedBeaconState definition
  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/phase0/beacon-chain.md#beaconblock
  BeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation

    parent_root*: Eth2Digest
      ## Root hash of the previous block

    state_root*: Eth2Digest
      ## The state root, _after_ this block has been processed

    body*: BeaconBlockBody

  SigVerifiedBeaconBlock* = object
    ## A BeaconBlock that contains verified signatures
    ## but that has not been verified for state transition

    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation

    parent_root*: Eth2Digest
      ## Root hash of the previous block

    state_root*: Eth2Digest
      ## The state root, _after_ this block has been processed

    body*: SigVerifiedBeaconBlockBody

  TrustedBeaconBlock* = object
    ## When we receive blocks from outside sources, they are untrusted and go
    ## through several layers of validation. Blocks that have gone through
    ## validations can be trusted to be well-formed, with a correct signature,
    ## having a parent and applying cleanly to the state that their parent
    ## left them with.
    ##
    ## When loading such blocks from the database, to rewind states for example,
    ## it is expensive to redo the validations (in particular, the signature
    ## checks), thus `TrustedBlock` uses a `TrustedSig` type to mark that these
    ## checks can be skipped.
    ##
    ## TODO this could probably be solved with some type trickery, but there
    ##      too many bugs in nim around generics handling, and we've used up
    ##      the trickery budget in the serialization library already. Until
    ##      then, the type must be manually kept compatible with its untrusted
    ##      cousin.
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: TrustedBeaconBlockBody

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*:
      List[electra.AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[electra.Attestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: SyncAggregate

    # Execution
    bls_to_execution_changes*: SignedBLSToExecutionChangeList

    # [New in Gloas:EIP7732]
    signed_execution_payload_bid*: SignedExecutionPayloadBid
    # [New in Gloas:EIP7732]
    payload_attestations*:
      List[PayloadAttestation, Limit MAX_PAYLOAD_ATTESTATIONS]
    # [New in Gloas:EIP7732]
    parent_execution_requests*: ExecutionRequests

  SigVerifiedBeaconBlockBody* = object
    ## A BeaconBlock body with signatures verified
    ## including:
    ## - Randao reveal
    ## - Attestations
    ## - ProposerSlashing (SignedBeaconBlockHeader)
    ## - AttesterSlashing (IndexedAttestation)
    ## - SignedVoluntaryExits
    ## - SyncAggregate
    ##
    ## However:
    ## - ETH1Data (Deposits) can contain invalid BLS signatures
    ##
    ## The block state transition has NOT been verified
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*:
      List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*:
      List[electra.TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[electra.TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    bls_to_execution_changes*: SignedBLSToExecutionChangeList

    # [New in Gloas:EIP7732]
    signed_execution_payload_bid*: SignedExecutionPayloadBid
    # [New in Gloas:EIP7732]
    payload_attestations*:
      List[PayloadAttestation, Limit MAX_PAYLOAD_ATTESTATIONS]
    # [New in Gloas:EIP7732]
    parent_execution_requests*: ExecutionRequests

  TrustedBeaconBlockBody* = object
    ## A full verified block
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*:
      List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*:
      List[electra.TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[electra.TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    bls_to_execution_changes*: SignedBLSToExecutionChangeList

    # [New in Gloas:EIP7732]
    signed_execution_payload_bid*: SignedExecutionPayloadBid
    # [New in Gloas:EIP7732]
    payload_attestations*:
      List[PayloadAttestation, Limit MAX_PAYLOAD_ATTESTATIONS]
    # [New in Gloas:EIP7732]
    parent_execution_requests*: ExecutionRequests

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/phase0/beacon-chain.md#signedbeaconblock
  SignedBeaconBlock* = object
    message*: BeaconBlock
    signature*: ValidatorSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SigVerifiedSignedBeaconBlock* = object
    ## A SignedBeaconBlock with signatures verified
    ## including:
    ## - Block signature
    ## - BeaconBlockBody
    ##   - Randao reveal
    ##   - Attestations
    ##   - ProposerSlashing (SignedBeaconBlockHeader)
    ##   - AttesterSlashing (IndexedAttestation)
    ##   - SignedVoluntaryExits
    ##
    ##   - ETH1Data (Deposits) can contain invalid BLS signatures
    ##
    ## The block state transition has NOT been verified
    message*: SigVerifiedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  TrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SomeSignedBeaconBlock* =
    SignedBeaconBlock |
    SigVerifiedSignedBeaconBlock |
    TrustedSignedBeaconBlock
  SomeBeaconBlock* =
    BeaconBlock |
    SigVerifiedBeaconBlock |
    TrustedBeaconBlock
  SomeBeaconBlockBody* =
    BeaconBlockBody |
    SigVerifiedBeaconBlockBody |
    TrustedBeaconBlockBody

  BlockContents* = object
    `block`*: gloas.BeaconBlock
    kzg_proofs*: fulu.KzgProofs
    blobs*: Blobs

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#expectedwithdrawals
  ExpectedWithdrawals* = object
    withdrawals*: seq[Withdrawal]
    # [New in Gloas:EIP7732]
    processed_builder_withdrawals_count*: uint64
    processed_partial_withdrawals_count*: uint64
    # [New in Gloas:EIP7732]
    processed_builders_sweep_count*: uint64
    processed_sweep_withdrawals_count*: uint64

func shortLog*(v: DataColumnSidecar): auto =
  (
    index: v.index,
    kzg_proofs: v.kzg_proofs.len,
    slot: v.slot,
    beacon_block_root: shortLog(v.beacon_block_root),
  )

func shortLog*(v: SomeBeaconBlock): auto =
  (
    slot: shortLog(v.slot),
    proposer_index: v.proposer_index,
    parent_root: shortLog(v.parent_root),
    state_root: shortLog(v.state_root),
    eth1data: v.body.eth1_data,
    graffiti: $v.body.graffiti,
    proposer_slashings_len: v.body.proposer_slashings.len(),
    attester_slashings_len: v.body.attester_slashings.len(),
    attestations_len: v.body.attestations.len(),
    deposits_len: v.body.deposits.len(),
    voluntary_exits_len: v.body.voluntary_exits.len(),
    sync_committee_participants: v.body.sync_aggregate.num_active_participants,
    block_number: 0'u64,
    # TODO checksum hex? shortlog?
    block_hash: "",
    parent_hash: "",
    fee_recipient: "",
    bls_to_execution_changes_len: v.body.bls_to_execution_changes.len(),
    blob_kzg_commitments_len: v.body.signed_execution_payload_bid.message.blob_kzg_commitments.len(),
  )

func shortLog*(v: SomeSignedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

func shortLog*(v: ExecutionPayloadBid): auto =
  (
    parent_block_hash: shortLog(v.parent_block_hash),
    parent_block_root: shortLog(v.parent_block_root),
    block_hash: shortLog(v.block_hash),
    fee_recipient: $v.fee_recipient,
    gas_limit: v.gas_limit,
    builder_index: v.builder_index,
    slot: v.slot,
    value: v.value,
  )

func shortLog*(v: ExecutionPayloadEnvelope): auto =
  (
    beacon_block_root: shortLog(v.beacon_block_root),
    builder_index: v.builder_index,
  )

func shortLog*(v: ExecutionPayload): auto =
  (
    parent_hash: shortLog(v.parent_hash),
    fee_recipient: $v.fee_recipient,
    state_root: shortLog(v.state_root),
    receipts_root: shortLog(v.receipts_root),
    prev_randao: shortLog(v.prev_randao),
    block_number: v.block_number,
    gas_limit: v.gas_limit,
    gas_used: v.gas_used,
    timestamp: v.timestamp,
    extra_data: toPrettyString(distinctBase v.extra_data),
    base_fee_per_gas: $(v.base_fee_per_gas),
    block_hash: shortLog(v.block_hash),
    num_transactions: len(v.transactions),
    num_withdrawals: len(v.withdrawals),
    blob_gas_used: $(v.blob_gas_used),
    excess_blob_gas: $(v.excess_blob_gas),
    slot_number: v.slot_number,
  )

func shortLog*(v: PayloadAttestationData): auto =
  (
    beacon_block_root: shortLog(v.beacon_block_root),
    slot: v.slot,
    payload_present: v.payload_present,
    blob_data_available: v.blob_data_available
  )

func shortLog*(v: PayloadAttestationMessage): auto =
  (
    validator_index: v.validator_index,
    data: shortLog(v.data),
    signature: shortLog(v.signature)
  )

func shortLog*(v: ProposerPreferences): auto =
  (
    proposal_slot: v.proposal_slot,
    validator_index: v.validator_index,
    fee_recipient: v.fee_recipient,
    gas_limit: v.gas_limit
  )

func shortLog*(v: SignedProposerPreferences): auto =
  (
    message: shortLog(v.message),
    signature: shortLog(v.signature)
  )

template asSigned*(
    x: SigVerifiedSignedBeaconBlock |
       TrustedSignedBeaconBlock): SignedBeaconBlock =
  isomorphicCast[SignedBeaconBlock](x)

template asSigned*(
    x: TrustedSignedExecutionPayloadEnvelope): SignedExecutionPayloadEnvelope =
  isomorphicCast[SignedExecutionPayloadEnvelope](x)

template asSigVerified*(
    x: SignedBeaconBlock |
       TrustedSignedBeaconBlock): SigVerifiedSignedBeaconBlock =
  isomorphicCast[SigVerifiedSignedBeaconBlock](x)

template asSigVerified*(
    x: BeaconBlock | TrustedBeaconBlock): SigVerifiedBeaconBlock =
  isomorphicCast[SigVerifiedBeaconBlock](x)

template asTrusted*(
    x: SignedBeaconBlock |
       SigVerifiedSignedBeaconBlock): TrustedSignedBeaconBlock =
  isomorphicCast[TrustedSignedBeaconBlock](x)

# Helpers to frequently used values
template slot*(v: ExecutionPayloadEnvelope): Slot = v.payload.slot_number
template slot*(v: SignedExecutionPayloadEnvelope): Slot = v.message.slot

template builder_index*(v: BeaconBlock | TrustedBeaconBlock): uint64 =
  if v.body.signed_execution_payload_bid.message.builder_index ==
      BUILDER_INDEX_SELF_BUILD:
    v.proposer_index
  else:
    v.body.signed_execution_payload_bid.message.builder_index
template builder_index*(
    v: SignedBeaconBlock | TrustedSignedBeaconBlock): uint64 =
  v.message.builder_index

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/electra/light-client/sync-protocol.md#new-constants
const
  EXECUTION_BLOCK_HASH_GINDEX* = get_generalized_index(
    capella.BeaconBlockBody, "execution_payload", "block_hash")
  EXECUTION_BLOCK_HASH_GINDEX_DENEB* = get_generalized_index(
    deneb.BeaconBlockBody, "execution_payload", "block_hash")
  EXECUTION_BLOCK_HASH_GINDEX_GLOAS* = get_generalized_index(BeaconBlockBody,
    "signed_execution_payload_bid", "message", "parent_block_hash")
static:
  doAssert EXECUTION_BLOCK_HASH_GINDEX == 412.GeneralizedIndex
  doAssert EXECUTION_BLOCK_HASH_GINDEX_DENEB == 812.GeneralizedIndex
  doAssert EXECUTION_BLOCK_HASH_GINDEX_GLOAS == 832.GeneralizedIndex

type
  ExecutionBranch* =
    array[log2trunc(EXECUTION_BLOCK_HASH_GINDEX_GLOAS), Eth2Digest]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/gloas/light-client/sync-protocol.md#modified-lightclientheader
  LightClientHeader* = object
    beacon*: BeaconBlockHeader
    # [Modified in Gloas]
    # Removed `execution`
    execution_block_hash*: Eth2Digest
      ## [New in Gloas]
    execution_branch*: ExecutionBranch
      ## [Modified in Gloas]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/altair/light-client/sync-protocol.md#lightclientbootstrap
  LightClientBootstrap* = object
    header*: LightClientHeader
      ## Header matching the requested beacon block root

    current_sync_committee*: SyncCommittee
      ## Current sync committee corresponding to `header.beacon.state_root`
    current_sync_committee_branch*: CurrentSyncCommitteeBranch

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/altair/light-client/sync-protocol.md#lightclientupdate
  LightClientUpdate* = object
    attested_header*: LightClientHeader
      ## Header attested to by the sync committee

    next_sync_committee*: SyncCommittee
      ## Next sync committee corresponding to
      ## `attested_header.beacon.state_root`
    next_sync_committee_branch*: NextSyncCommitteeBranch

    finalized_header*: LightClientHeader
      ## Finalized header corresponding to `attested_header.beacon.state_root`
    finality_branch*: FinalityBranch

    sync_aggregate*: SyncAggregate
      ## Sync committee aggregate signature
    signature_slot*: Slot
      ## Slot at which the aggregate signature was created (untrusted)

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate
  LightClientFinalityUpdate* = object
    attested_header*: LightClientHeader
      ## Header attested to by the sync committee

    finalized_header*: LightClientHeader
      ## Finalized header corresponding to `attested_header.beacon.state_root`
    finality_branch*: FinalityBranch

    sync_aggregate*: SyncAggregate
      ## Sync committee aggregate signature
    signature_slot*: Slot
      ## Slot at which the aggregate signature was created (untrusted)

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/altair/light-client/sync-protocol.md#lightclientoptimisticupdate
  LightClientOptimisticUpdate* = object
    attested_header*: LightClientHeader
      ## Header attested to by the sync committee

    sync_aggregate*: SyncAggregate
      ## Sync committee aggregate signature
    signature_slot*: Slot
      ## Slot at which the aggregate signature was created (untrusted)

  SomeLightClientUpdateWithSyncCommittee* =
    LightClientUpdate

  SomeLightClientUpdateWithFinality* =
    LightClientUpdate |
    LightClientFinalityUpdate

  SomeLightClientUpdate* =
    LightClientUpdate |
    LightClientFinalityUpdate |
    LightClientOptimisticUpdate

  SomeLightClientObject* =
    LightClientBootstrap |
    SomeLightClientUpdate

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/altair/light-client/sync-protocol.md#lightclientstore
  LightClientStore* = object
    finalized_header*: LightClientHeader
      ## Header that is finalized

    current_sync_committee*: SyncCommittee
      ## Sync committees corresponding to the finalized header
    next_sync_committee*: SyncCommittee

    best_valid_update*: Opt[LightClientUpdate]
      ## Best available header to switch finalized head to
      ## if we see nothing else

    optimistic_header*: LightClientHeader
      ## Most recent available reasonably-safe header

    previous_max_active_participants*: uint64
      ## Max number of active participants in a sync committee
      ## (used to calculate safety threshold)
    current_max_active_participants*: uint64

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/gloas/light-client/sync-protocol.md#modified-get_lc_execution_root
func get_lc_execution_root*(
    header: LightClientHeader, cfg: RuntimeConfig): Eth2Digest =
  let epoch = header.beacon.slot.epoch

  # [New in Gloas:EIP7732]
  if epoch >= cfg.GLOAS_FORK_EPOCH:
    return header.execution_block_hash

  template inner: openArray[Eth2Digest] =
    header.execution_branch.toOpenArray(
      0, header.execution_branch.high - log2trunc(EXECUTION_PAYLOAD_GINDEX))

  # [Modified in Gloas:EIP7732]
  if epoch >= cfg.DENEB_FORK_EPOCH:
    if header.beacon.slot == GENESIS_SLOT:
      return hash_tree_root(default(deneb.ExecutionPayloadHeader))
    const BLOCK_HASH_GINDEX = get_generalized_index(
      deneb.ExecutionPayloadHeader, "block_hash")
    return compute_merkle_branch_root(
      header.execution_block_hash,
      inner.toOpenArray(inner.len - log2trunc(BLOCK_HASH_GINDEX), inner.high),
      log2trunc(BLOCK_HASH_GINDEX), get_subtree_index(BLOCK_HASH_GINDEX))

  # [Modified in Gloas:EIP7732]
  if epoch >= cfg.CAPELLA_FORK_EPOCH:
    if header.beacon.slot == GENESIS_SLOT:
      return hash_tree_root(default(capella.ExecutionPayloadHeader))
    const BLOCK_HASH_GINDEX = get_generalized_index(
      capella.ExecutionPayloadHeader, "block_hash")
    return compute_merkle_branch_root(
      header.execution_block_hash,
      inner.toOpenArray(inner.len - log2trunc(BLOCK_HASH_GINDEX), inner.high),
      log2trunc(BLOCK_HASH_GINDEX), get_subtree_index(BLOCK_HASH_GINDEX))

  ZERO_HASH

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/gloas/light-client/sync-protocol.md#modified-is_valid_light_client_header
func is_valid_light_client_header*(
    header: LightClientHeader, cfg: RuntimeConfig): bool =
  let epoch = header.beacon.slot.epoch

  # [New in Gloas:EIP7732]
  if epoch >= cfg.GLOAS_FORK_EPOCH:
    return is_valid_normalized_merkle_branch(
      header.execution_block_hash, header.execution_branch,
      EXECUTION_BLOCK_HASH_GINDEX_GLOAS, header.beacon.body_root)

  # [Modified in Gloas:EIP7732]
  if epoch >= cfg.DENEB_FORK_EPOCH:
    return is_valid_normalized_merkle_branch(
      header.execution_block_hash, header.execution_branch,
      EXECUTION_BLOCK_HASH_GINDEX_DENEB, header.beacon.body_root)

  # [Modified in Gloas:EIP7732]
  if epoch >= cfg.CAPELLA_FORK_EPOCH:
    return is_valid_normalized_merkle_branch(
      header.execution_block_hash, header.execution_branch,
      EXECUTION_BLOCK_HASH_GINDEX, header.beacon.body_root)

  # [Modified in Gloas:EIP7732]
  header.execution_block_hash.isZero and
  header.execution_branch == static(default(ExecutionBranch))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/gloas/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_header_to_gloas*(
    pre: electra.LightClientHeader, cfg: RuntimeConfig): LightClientHeader =
  if pre == static(default(electra.LightClientHeader)):
    return static(default(LightClientHeader))

  let epoch = pre.beacon.slot.epoch

  var header = LightClientHeader(
    beacon: pre.beacon,
    execution_block_hash: pre.execution.block_hash,
    execution_branch: normalize_merkle_branch(
      pre.execution_branch, EXECUTION_BLOCK_HASH_GINDEX_GLOAS))
  template inner: openArray[Eth2Digest] =
    header.execution_branch.toOpenArray(
      0, header.execution_branch.high - log2trunc(EXECUTION_PAYLOAD_GINDEX))

  if epoch >= cfg.DENEB_FORK_EPOCH:
    const BLOCK_HASH_GINDEX = get_generalized_index(
      deneb.ExecutionPayloadHeader, "block_hash")
    pre.execution.build_proof(BLOCK_HASH_GINDEX, inner.toOpenArray(
      inner.len - log2trunc(BLOCK_HASH_GINDEX), inner.high)).expect("OK")

  elif epoch >= cfg.CAPELLA_FORK_EPOCH:
    let execution_header = capella.ExecutionPayloadHeader(
      parent_hash: pre.execution.parent_hash,
      fee_recipient: pre.execution.fee_recipient,
      state_root: pre.execution.state_root,
      receipts_root: pre.execution.receipts_root,
      logs_bloom: pre.execution.logs_bloom,
      prev_randao: pre.execution.prev_randao,
      block_number: pre.execution.block_number,
      gas_limit: pre.execution.gas_limit,
      gas_used: pre.execution.gas_used,
      timestamp: pre.execution.timestamp,
      extra_data: pre.execution.extra_data,
      base_fee_per_gas: pre.execution.base_fee_per_gas,
      block_hash: pre.execution.block_hash,
      transactions_root: pre.execution.transactions_root,
      withdrawals_root: pre.execution.withdrawals_root)
    const BLOCK_HASH_GINDEX = get_generalized_index(
      capella.ExecutionPayloadHeader, "block_hash")
    execution_header.build_proof(BLOCK_HASH_GINDEX, inner.toOpenArray(
      inner.len - log2trunc(BLOCK_HASH_GINDEX), inner.high)).expect("OK")

  header

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/gloas/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_bootstrap_to_gloas*(
    pre: electra.LightClientBootstrap,
    cfg: RuntimeConfig): LightClientBootstrap =
  LightClientBootstrap(
    header: upgrade_lc_header_to_gloas(pre.header, cfg),
    current_sync_committee: pre.current_sync_committee,
    current_sync_committee_branch: pre.current_sync_committee_branch)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/gloas/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_update_to_gloas*(
    pre: electra.LightClientUpdate,
    cfg: RuntimeConfig): LightClientUpdate =
  LightClientUpdate(
    attested_header: upgrade_lc_header_to_gloas(pre.attested_header, cfg),
    next_sync_committee: pre.next_sync_committee,
    next_sync_committee_branch: pre.next_sync_committee_branch,
    finalized_header: upgrade_lc_header_to_gloas(pre.finalized_header, cfg),
    finality_branch: pre.finality_branch,
    sync_aggregate: pre.sync_aggregate,
    signature_slot: pre.signature_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/gloas/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_finality_update_to_gloas*(
    pre: electra.LightClientFinalityUpdate,
    cfg: RuntimeConfig): LightClientFinalityUpdate =
  LightClientFinalityUpdate(
    attested_header: upgrade_lc_header_to_gloas(pre.attested_header, cfg),
    finalized_header: upgrade_lc_header_to_gloas(pre.finalized_header, cfg),
    finality_branch: pre.finality_branch,
    sync_aggregate: pre.sync_aggregate,
    signature_slot: pre.signature_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/gloas/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_optimistic_update_to_gloas*(
    pre: electra.LightClientOptimisticUpdate,
    cfg: RuntimeConfig): LightClientOptimisticUpdate =
  LightClientOptimisticUpdate(
    attested_header: upgrade_lc_header_to_gloas(pre.attested_header, cfg),
    sync_aggregate: pre.sync_aggregate,
    signature_slot: pre.signature_slot)

func shortLog*(v: LightClientHeader): auto =
  (
    beacon: shortLog(v.beacon),
    execution_block_hash: v.execution_block_hash
  )

func shortLog*(v: LightClientBootstrap): auto =
  (
    header: shortLog(v.header)
  )

func shortLog*(v: LightClientUpdate): auto =
  (
    attested: shortLog(v.attested_header),
    has_next_sync_committee:
      v.next_sync_committee != static(default(typeof(v.next_sync_committee))),
    finalized: shortLog(v.finalized_header),
    num_active_participants: v.sync_aggregate.num_active_participants,
    signature_slot: v.signature_slot
  )

func shortLog*(v: LightClientFinalityUpdate): auto =
  (
    attested: shortLog(v.attested_header),
    finalized: shortLog(v.finalized_header),
    num_active_participants: v.sync_aggregate.num_active_participants,
    signature_slot: v.signature_slot
  )

func shortLog*(v: LightClientOptimisticUpdate): auto =
  (
    attested: shortLog(v.attested_header),
    num_active_participants: v.sync_aggregate.num_active_participants,
    signature_slot: v.signature_slot
  )

chronicles.formatIt LightClientBootstrap: shortLog(it)
chronicles.formatIt LightClientUpdate: shortLog(it)
chronicles.formatIt LightClientFinalityUpdate: shortLog(it)
chronicles.formatIt LightClientOptimisticUpdate: shortLog(it)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.6/specs/gloas/light-client/fork.md#upgrading-the-store
func upgrade_lc_store_to_gloas*(
    pre: electra.LightClientStore,
    cfg: RuntimeConfig): LightClientStore =
  let best_valid_update =
    if pre.best_valid_update.isNone:
      Opt.none(LightClientUpdate)
    else:
      Opt.some upgrade_lc_update_to_gloas(pre.best_valid_update.get, cfg)
  LightClientStore(
    finalized_header: upgrade_lc_header_to_gloas(pre.finalized_header, cfg),
    current_sync_committee: pre.current_sync_committee,
    next_sync_committee: pre.next_sync_committee,
    best_valid_update: best_valid_update,
    optimistic_header: upgrade_lc_header_to_gloas(pre.optimistic_header, cfg),
    previous_max_active_participants: pre.previous_max_active_participants,
    current_max_active_participants: pre.current_max_active_participants)
