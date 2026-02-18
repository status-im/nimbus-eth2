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
  "."/[phase0, base, bellatrix, electra, fulu],
  chronicles,
  json_serialization,
  ssz_serialization/[merkleization, proofs],
  ssz_serialization/types as sszTypes,
  ../digest,
  kzg4844/[kzg, kzg_abi]

from ./altair import
  EpochParticipationFlags, InactivityScores, SyncAggregate, SyncCommittee,
  TrustedSyncAggregate, SyncnetBits, num_active_participants
from ./capella import
  ExecutionBranch, HistoricalSummary, SignedBLSToExecutionChange,
  SignedBLSToExecutionChangeList, Withdrawal, EXECUTION_PAYLOAD_GINDEX
from ./deneb import
  Blobs, ExecutionPayload, ExecutionPayloadHeader, KzgCommitments, KzgProofs

export json_serialization, base

type
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/fork-choice.md#custom-types
  PayloadStatus* = uint8

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#custom-types
  BuilderIndex* = uint64

const
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#state-list-lengths
  BUILDER_PENDING_WITHDRAWALS_LIMIT*: uint64 = 1_048_576

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

  ExecutionPayloadForSigning* = object
    executionPayload*: deneb.ExecutionPayload
    blockValue*: Wei
    blobsBundle*: fulu.BlobsBundle # [New in Fulu]
    executionRequests*: seq[seq[byte]]

  # https://github.com/ethereum/beacon-APIs/blob/v5.0.0-alpha.0/apis/eventstream/index.yaml#L164
  ExecutionPayloadInfoObject* = object
    slot*: Slot
    block_root*: Eth2Digest
  
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/beacon-chain.md#executionpayloadbid
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

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/beacon-chain.md#signedexecutionpayloadbid
  SignedExecutionPayloadBid* = object
    message*: ExecutionPayloadBid
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/beacon-chain.md#executionpayloadenvelope
  ExecutionPayloadEnvelope* = object
    payload*: deneb.ExecutionPayload
    execution_requests*: ExecutionRequests
    builder_index*: uint64
    beacon_block_root*: Eth2Digest
    slot*: Slot
    state_root*: Eth2Digest

  TrustedExecutionPayloadEnvelope* = object
    payload*: deneb.ExecutionPayload
    execution_requests*: ExecutionRequests
    builder_index*: uint64
    beacon_block_root*: Eth2Digest
    slot*: Slot
    state_root*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/gloas/beacon-chain.md#signedexecutionpayloadenvelope
  SignedExecutionPayloadEnvelope* = object
    message*: ExecutionPayloadEnvelope
    signature*: ValidatorSig

  TrustedSignedExecutionPayloadEnvelope* = object
    message*: TrustedExecutionPayloadEnvelope
    signature*: ValidatorSig

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

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
  LightClientHeader* = object
    beacon*: BeaconBlockHeader
      ## Beacon block header
    execution*: deneb.ExecutionPayloadHeader
      ## Execution payload header corresponding to `beacon.body_root` (from Capella onward)
    execution_branch*: capella.ExecutionBranch

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/altair/light-client/sync-protocol.md#lightclientbootstrap
  LightClientBootstrap* = object
    header*: LightClientHeader
      ## Header matching the requested beacon block root

    current_sync_committee*: SyncCommittee
      ## Current sync committee corresponding to `header.beacon.state_root`
    current_sync_committee_branch*: electra.CurrentSyncCommitteeBranch

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/altair/light-client/sync-protocol.md#lightclientupdate
  LightClientUpdate* = object
    attested_header*: LightClientHeader
      ## Header attested to by the sync committee

    next_sync_committee*: SyncCommittee
      ## Next sync committee corresponding to
      ## `attested_header.beacon.state_root`
    next_sync_committee_branch*: electra.NextSyncCommitteeBranch

    # Finalized header corresponding to `attested_header.beacon.state_root`
    finalized_header*: LightClientHeader
    finality_branch*: electra.FinalityBranch

    sync_aggregate*: SyncAggregate
      ## Sync committee aggregate signature
    signature_slot*: Slot
      ## Slot at which the aggregate signature was created (untrusted)

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate
  LightClientFinalityUpdate* = object
    # Header attested to by the sync committee
    attested_header*: LightClientHeader

    # Finalized header corresponding to `attested_header.beacon.state_root`
    finalized_header*: LightClientHeader
    finality_branch*: electra.FinalityBranch

    # Sync committee aggregate signature
    sync_aggregate*: SyncAggregate
    # Slot at which the aggregate signature was created (untrusted)
    signature_slot*: Slot

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientoptimisticupdate
  LightClientOptimisticUpdate* = object
    # Header attested to by the sync committee
    attested_header*: LightClientHeader

    # Sync committee aggregate signature
    sync_aggregate*: SyncAggregate
    # Slot at which the aggregate signature was created (untrusted)
    signature_slot*: Slot

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

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/altair/light-client/sync-protocol.md#lightclientstore
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
      ## (used to compute safety threshold)
    current_max_active_participants*: uint64

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#beaconstate
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

    # Execution
    latest_execution_payload_bid*: gloas.ExecutionPayloadBid

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
    # [New in Gloas:EIP7732]
    latest_block_hash*: Eth2Digest
    # [New in Gloas:EIP7732]
    payload_expected_withdrawals*:
      HashList[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]

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

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/beacon-chain.md#beaconblockbody
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

# TODO: There should be only a single generic HashedBeaconState definition
func initHashedBeaconState*(s: BeaconState): HashedBeaconState =
  HashedBeaconState(data: s)

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
    slot: v.slot,
    builder_index: v.builder_index,
    state_root: shortLog(v.state_root)
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
