# beacon_chain
# Copyright (c) 2024-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Types specific to Electra (i.e. known to have changed across hard forks) - see
# `base` for types and guidelines common across forks

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

import
  std/typetraits,
  chronicles,
  json_serialization,
  ssz_serialization/[merkleization, proofs],
  ssz_serialization/types as sszTypes,
  ../[digest, ssz_codec],
  ./[base, phase0, bellatrix]

from kzg4844 import KzgCommitment, KzgProof
from stew/bitops2 import log2trunc
from stew/byteutils import to0xHex
from ./altair import
  EpochParticipationFlags, InactivityScores, SyncAggregate, SyncCommittee,
  TrustedSyncAggregate, num_active_participants
from ./capella import
  ExecutionBranch, HistoricalSummary, SignedBLSToExecutionChange,
  SignedBLSToExecutionChangeList, Withdrawal, EXECUTION_PAYLOAD_GINDEX
from ./deneb import
  Blobs, BlobsBundle, ExecutionPayload, ExecutionPayloadHeader, KzgCommitments,
  KzgProofs

export json_serialization, base, kzg4844

type
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/electra/beacon-chain.md#depositrequest
  DepositRequest* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: Gwei
    signature*: ValidatorSig
    index*: uint64

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#indexedattestation
  IndexedAttestation* = object
    attesting_indices*:
      List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]
    data*: AttestationData
    signature*: ValidatorSig

  TrustedIndexedAttestation* = object
    # The Trusted version, at the moment, implies that the cryptographic signature was checked.
    # It DOES NOT imply that the state transition was verified.
    # Currently the code MUST verify the state transition as soon as the signature is verified
    attesting_indices*:
      List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]
    data*: AttestationData
    signature*: TrustedSig

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/specs/electra/beacon-chain.md#attesterslashing
  AttesterSlashing* = object
    attestation_1*: IndexedAttestation  # [Modified in Electra:EIP7549]
    attestation_2*: IndexedAttestation  # [Modified in Electra:EIP7549]

  TrustedAttesterSlashing* = object
    # The Trusted version, at the moment, implies that the cryptographic signature was checked.
    # It DOES NOT imply that the state transition was verified.
    # Currently the code MUST verify the state transition as soon as the signature is verified
    attestation_1*: TrustedIndexedAttestation  # Modified in Electra:EIP7549]
    attestation_2*: TrustedIndexedAttestation  # Modified in Electra:EIP7549]

  ExecutionPayloadForSigning* = object
    executionPayload*: deneb.ExecutionPayload
    blockValue*: Wei
    blobsBundle*: BlobsBundle
    executionRequests*: seq[seq[byte]]

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/electra/beacon-chain.md#pendingdeposit
  PendingDeposit* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: Gwei
    signature*: ValidatorSig
    slot*: Slot

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/electra/beacon-chain.md#pendingpartialwithdrawal
  PendingPartialWithdrawal* = object
    validator_index*: uint64
    amount*: Gwei
    withdrawable_epoch*: Epoch

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/electra/beacon-chain.md#withdrawalrequest
  WithdrawalRequest* = object
    source_address*: ExecutionAddress
    validator_pubkey*: ValidatorPubKey
    amount*: Gwei

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/electra/beacon-chain.md#pendingconsolidation
  PendingConsolidation* = object
    source_index*: uint64
    target_index*: uint64

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#consolidationrequest
  ConsolidationRequest* = object
    source_address*: ExecutionAddress
    source_pubkey*: ValidatorPubKey
    target_pubkey*: ValidatorPubKey

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/electra/beacon-chain.md#singleattestation
  SingleAttestation* = object
    committee_index*: uint64
    attester_index*: uint64
    data*: AttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/phase0/validator.md#aggregateandproof
  AggregateAndProof* = object
    aggregator_index*: uint64 # `ValidatorIndex` after validation
    aggregate*: Attestation
    selection_proof*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/validator.md#signedaggregateandproof
  SignedAggregateAndProof* = object
    message*: AggregateAndProof
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/electra/beacon-chain.md#executionrequests
  ExecutionRequests* = object
    deposits*:
      List[DepositRequest,
        Limit MAX_DEPOSIT_REQUESTS_PER_PAYLOAD]  # [New in Electra:EIP6110]
    withdrawals*:
      List[WithdrawalRequest,
        Limit MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD]  # [New in Electra:EIP7002:EIP7251]
    consolidations*:
      List[ConsolidationRequest,
        Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD]  # [New in Electra:EIP7251]

  # https://github.com/ethereum/consensus-specs/blob/82133085a1295e93394ebdf71df8f2f6e0962588/specs/electra/beacon-chain.md#beaconstate
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
    latest_execution_payload_header*: deneb.ExecutionPayloadHeader

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
      ## [New in Electra:EIP7251]

  # TODO Careful, not nil analysis is broken / incomplete and the semantics will
  #      likely change in future versions of the language:
  #      https://github.com/nim-lang/RFCs/issues/250
  BeaconStateRef* = ref BeaconState not nil
  NilableBeaconStateRef* = ref BeaconState

  # TODO: There should be only a single generic HashedBeaconState definition
  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#beaconblock
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

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/electra/beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*:
      List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[electra.Attestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: SyncAggregate

    # Execution
    execution_payload*: deneb.ExecutionPayload
    bls_to_execution_changes*: SignedBLSToExecutionChangeList
    blob_kzg_commitments*: KzgCommitments
    execution_requests*: ExecutionRequests  # [New in Electra]

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
      List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    execution_payload*: deneb.ExecutionPayload
    bls_to_execution_changes*: SignedBLSToExecutionChangeList
    blob_kzg_commitments*: KzgCommitments
    execution_requests*: ExecutionRequests  # [New in Electra]

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
      List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    execution_payload*: deneb.ExecutionPayload
    bls_to_execution_changes*: SignedBLSToExecutionChangeList
    blob_kzg_commitments*: KzgCommitments
    execution_requests*: ExecutionRequests  # [New in Electra]

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#signedbeaconblock
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

  ElectraCommitteeValidatorsBits* =
    BitList[Limit MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]

  AttestationCommitteeBits* = BitArray[MAX_COMMITTEES_PER_SLOT.int]

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/electra/beacon-chain.md#attestation
  Attestation* = object
    aggregation_bits*: ElectraCommitteeValidatorsBits
    data*: AttestationData
    signature*: ValidatorSig
    committee_bits*: AttestationCommitteeBits  # [New in Electra:EIP7549]

  TrustedAttestation* = object
    # The Trusted version, at the moment, implies that the cryptographic signature was checked.
    # It DOES NOT imply that the state transition was verified.
    # Currently the code MUST verify the state transition as soon as the signature is verified
    aggregation_bits*: ElectraCommitteeValidatorsBits
    data*: AttestationData
    signature*: TrustedSig
    committee_bits*: AttestationCommitteeBits  # [New in Electra:EIP7549]

  SomeIndexedAttestation* = IndexedAttestation | TrustedIndexedAttestation
  SomeAttesterSlashing* = AttesterSlashing | TrustedAttesterSlashing
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
    `block`*: BeaconBlock
    kzg_proofs*: KzgProofs
    blobs*: Blobs

  BeaconBlockValidatorChanges* = object
    # Collection of exits that are suitable for block production
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    electra_attester_slashings*:
      List[electra.AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    bls_to_execution_changes*:
      List[SignedBLSToExecutionChange, Limit MAX_BLS_TO_EXECUTION_CHANGES]

func shortLog*(v: SomeIndexedAttestation): auto =
  (
    attestating_indices: v.attesting_indices,
    data: shortLog(v.data),
    signature: shortLog(v.signature)
  )

func shortLog*(v: SomeAttesterSlashing): auto =
  (
    attestation_1: shortLog(v.attestation_1),
    attestation_2: shortLog(v.attestation_2),
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
    block_number: v.body.execution_payload.block_number,
    # TODO checksum hex? shortlog?
    block_hash: to0xHex(v.body.execution_payload.block_hash.data),
    parent_hash: to0xHex(v.body.execution_payload.parent_hash.data),
    fee_recipient: to0xHex(v.body.execution_payload.fee_recipient.data),
    bls_to_execution_changes_len: v.body.bls_to_execution_changes.len(),
    blob_kzg_commitments_len: v.body.blob_kzg_commitments.len(),
  )

func shortLog*(v: SomeSignedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/electra/light-client/sync-protocol.md#new-constants
const
  FINALIZED_ROOT_GINDEX_ELECTRA* = get_generalized_index(
    BeaconState, "finalized_checkpoint", "root")
  CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA* = get_generalized_index(
    BeaconState, "current_sync_committee")
  NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA* = get_generalized_index(
    BeaconState, "next_sync_committee")
static:
  doAssert FINALIZED_ROOT_GINDEX_ELECTRA == 169.GeneralizedIndex
  doAssert CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA == 86.GeneralizedIndex
  doAssert NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA == 87.GeneralizedIndex

type
  FinalityBranch* =
    array[log2trunc(FINALIZED_ROOT_GINDEX_ELECTRA), Eth2Digest]

  CurrentSyncCommitteeBranch* =
    array[log2trunc(CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA), Eth2Digest]

  NextSyncCommitteeBranch* =
    array[log2trunc(NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA), Eth2Digest]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
  LightClientHeader* = object
    beacon*: BeaconBlockHeader
    execution*: deneb.ExecutionPayloadHeader
      ## [New in Capella]
    execution_branch*: capella.ExecutionBranch
      ## [New in Capella]

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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/electra/light-client/sync-protocol.md#modified-get_lc_execution_root
func get_lc_execution_root*(
    header: LightClientHeader, cfg: RuntimeConfig): Eth2Digest =
  let epoch = header.beacon.slot.epoch

  # [New in Electra]
  # TODO https://github.com/ethereum/consensus-specs/issues/4557
  if epoch >= cfg.DENEB_FORK_EPOCH:
    return hash_tree_root(header.execution)

  if epoch >= cfg.CAPELLA_FORK_EPOCH:
    let execution_header = capella.ExecutionPayloadHeader(
      parent_hash: header.execution.parent_hash,
      fee_recipient: header.execution.fee_recipient,
      state_root: header.execution.state_root,
      receipts_root: header.execution.receipts_root,
      logs_bloom: header.execution.logs_bloom,
      prev_randao: header.execution.prev_randao,
      block_number: header.execution.block_number,
      gas_limit: header.execution.gas_limit,
      gas_used: header.execution.gas_used,
      timestamp: header.execution.timestamp,
      extra_data: header.execution.extra_data,
      base_fee_per_gas: header.execution.base_fee_per_gas,
      block_hash: header.execution.block_hash,
      transactions_root: header.execution.transactions_root,
      withdrawals_root: header.execution.withdrawals_root)
    return hash_tree_root(execution_header)

  ZERO_HASH

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/deneb/light-client/sync-protocol.md#modified-is_valid_light_client_header
func is_valid_light_client_header*(
    header: LightClientHeader, cfg: RuntimeConfig): bool =
  let epoch = header.beacon.slot.epoch

  if epoch < cfg.DENEB_FORK_EPOCH:
    if header.execution.blob_gas_used != 0 or
        header.execution.excess_blob_gas != 0:
      return false

  if epoch < cfg.CAPELLA_FORK_EPOCH:
    return
      header.execution == static(default(deneb.ExecutionPayloadHeader)) and
      header.execution_branch == static(default(ExecutionBranch))

  is_valid_merkle_branch(
    get_lc_execution_root(header, cfg),
    header.execution_branch,
    log2trunc(EXECUTION_PAYLOAD_GINDEX),
    get_subtree_index(EXECUTION_PAYLOAD_GINDEX),
    header.beacon.body_root)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/electra/light-client/fork.md#normalize_merkle_branch
func normalize_merkle_branch*[N](
    branch: array[N, Eth2Digest],
    gindex: static GeneralizedIndex): auto =
  const depth = log2trunc(gindex)
  var res: array[depth, Eth2Digest]
  when depth >= branch.len:
    const num_extra = depth - branch.len
    res[num_extra ..< depth] = branch
  else:
    const num_extra = branch.len - depth
    for node in branch[0 ..< num_extra]:
      doAssert node.isZero, "Truncation of Merkle branch cannot lose info"
    res[0 ..< depth] = branch[num_extra ..< branch.len]
  res

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/electra/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_header_to_electra*(
    pre: deneb.LightClientHeader): LightClientHeader =
  LightClientHeader(
    beacon: pre.beacon,
    execution: pre.execution,
    execution_branch: pre.execution_branch)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/electra/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_bootstrap_to_electra*(
    pre: deneb.LightClientBootstrap): LightClientBootstrap =
  LightClientBootstrap(
    header: upgrade_lc_header_to_electra(pre.header),
    current_sync_committee: pre.current_sync_committee,
    current_sync_committee_branch: normalize_merkle_branch(
      pre.current_sync_committee_branch, CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/electra/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_update_to_electra*(
    pre: deneb.LightClientUpdate): LightClientUpdate =
  LightClientUpdate(
    attested_header: upgrade_lc_header_to_electra(pre.attested_header),
    next_sync_committee: pre.next_sync_committee,
    next_sync_committee_branch: normalize_merkle_branch(
      pre.next_sync_committee_branch, NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA),
    finalized_header: upgrade_lc_header_to_electra(pre.finalized_header),
    finality_branch: normalize_merkle_branch(
      pre.finality_branch, FINALIZED_ROOT_GINDEX_ELECTRA),
    sync_aggregate: pre.sync_aggregate,
    signature_slot: pre.signature_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/electra/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_finality_update_to_electra*(
    pre: deneb.LightClientFinalityUpdate): LightClientFinalityUpdate =
  LightClientFinalityUpdate(
    attested_header: upgrade_lc_header_to_electra(pre.attested_header),
    finalized_header: upgrade_lc_header_to_electra(pre.finalized_header),
    finality_branch: normalize_merkle_branch(
      pre.finality_branch, FINALIZED_ROOT_GINDEX_ELECTRA),
    sync_aggregate: pre.sync_aggregate,
    signature_slot: pre.signature_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/electra/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_optimistic_update_to_electra*(
    pre: deneb.LightClientOptimisticUpdate): LightClientOptimisticUpdate =
  LightClientOptimisticUpdate(
    attested_header: upgrade_lc_header_to_electra(pre.attested_header),
    sync_aggregate: pre.sync_aggregate,
    signature_slot: pre.signature_slot)

func shortLog*(v: LightClientHeader): auto =
  (
    beacon: shortLog(v.beacon),
    execution: (
      block_hash: v.execution.block_hash,
      block_number: v.execution.block_number)
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
    signature_slot: v.signature_slot,
  )

chronicles.formatIt LightClientBootstrap: shortLog(it)
chronicles.formatIt LightClientUpdate: shortLog(it)
chronicles.formatIt LightClientFinalityUpdate: shortLog(it)
chronicles.formatIt LightClientOptimisticUpdate: shortLog(it)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/light-client/fork.md#upgrading-the-store
func upgrade_lc_store_to_electra*(
    pre: deneb.LightClientStore): LightClientStore =
  let best_valid_update =
    if pre.best_valid_update.isNone:
      Opt.none(LightClientUpdate)
    else:
      Opt.some upgrade_lc_update_to_electra(pre.best_valid_update.get)
  LightClientStore(
    finalized_header: upgrade_lc_header_to_electra(pre.finalized_header),
    current_sync_committee: pre.current_sync_committee,
    next_sync_committee: pre.next_sync_committee,
    best_valid_update: best_valid_update,
    optimistic_header: upgrade_lc_header_to_electra(pre.optimistic_header),
    previous_max_active_participants: pre.previous_max_active_participants,
    current_max_active_participants: pre.current_max_active_participants)

template asSigned*(
    x: SigVerifiedSignedBeaconBlock |
       TrustedSignedBeaconBlock): SignedBeaconBlock =
  isomorphicCast[SignedBeaconBlock](x)

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

from std/sets import toHashSet

iterator getValidatorIndices*(
    attester_slashing: AttesterSlashing | TrustedAttesterSlashing): uint64 =
  template attestation_1(): auto = attester_slashing.attestation_1
  template attestation_2(): auto = attester_slashing.attestation_2

  let attestation_2_indices = toHashSet(attestation_2.attesting_indices.asSeq)
  for validator_index in attestation_1.attesting_indices.asSeq:
    if validator_index notin attestation_2_indices:
      continue
    yield validator_index

func shortLog*(v: ElectraCommitteeValidatorsBits): auto =
  $v.countOnes() & "/" & $v.len()

func shortLog*(v: electra.Attestation | electra.TrustedAttestation): auto =
  (
    aggregation_bits: shortLog(v.aggregation_bits),
    committee_bits: v.committee_bits,
    data: shortLog(v.data),
    signature: shortLog(v.signature)
  )

func shortLog*(v: SingleAttestation): auto =
  (
    committee_index: v.committee_index,
    attester_index: v.attester_index,
    data: shortLog(v.data),
    signature: shortLog(v.signature)
  )

func init*(
    T: type Attestation,
    committee_index: CommitteeIndex,
    indices_in_committee: openArray[uint64],
    committee_len: int,
    data: AttestationData,
    signature: ValidatorSig): Result[T, cstring] =
  var committee_bits: AttestationCommitteeBits
  committee_bits[int(committee_index)] = true

  var bits = ElectraCommitteeValidatorsBits.init(committee_len)
  for index_in_committee in indices_in_committee:
    if index_in_committee >= committee_len.uint64: return err("Invalid index for committee")
    bits.setBit index_in_committee

  ok Attestation(
    aggregation_bits: bits,
    committee_bits: committee_bits,
    data: data,
    signature: signature
  )
