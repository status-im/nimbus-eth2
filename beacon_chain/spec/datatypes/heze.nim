# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Types specific to Heze (i.e. known to have changed across hard forks) - see
# `base` for types and guidelines common across forks

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

import
  std/typetraits,
  ./[phase0, base, bellatrix, electra, fulu],
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
  HistoricalSummary, SignedBLSToExecutionChange,
  SignedBLSToExecutionChangeList, Withdrawal
from ./deneb import
  Blobs, KzgCommitments, KzgProofs
from ./gloas import
  Builder, BuilderPendingPayment, BuilderPendingWithdrawal, PayloadAttestation

export json_serialization, base

type
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/heze/beacon-chain.md#inclusionlist
  InclusionList* = object
    slot*: Slot
    validator_index*: uint64 # `ValidatorIndex` after validation
    inclusion_list_committee_root*: Eth2Digest
    transactions*: List[bellatrix.Transaction, Limit MAX_TRANSACTIONS_PER_PAYLOAD]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/heze/beacon-chain.md#signedinclusionlist
  SignedInclusionList* = object
    message*: InclusionList
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/heze/beacon-chain.md#executionpayloadbid
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
    # [New in Heze:EIP7805]
    inclusion_list_bits*: BitArray[int INCLUSION_LIST_COMMITTEE_SIZE]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/heze/beacon-chain.md#signedexecutionpayloadbid
  SignedExecutionPayloadBid* = object
    # [Modified in Heze:EIP7805]
    message*: ExecutionPayloadBid
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/heze/beacon-chain.md#beaconstate
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
    # [Modified in Heze:EIP7805]
    latest_execution_payload_bid*: ExecutionPayloadBid

    # Withdrawals
    next_withdrawal_index*: WithdrawalIndex
    next_withdrawal_validator_index*: uint64

    # Deep history valid from Capella onwards
    historical_summaries*:
      HashList[HistoricalSummary, Limit HISTORICAL_ROOTS_LIMIT]

    deposit_requests_start_index*: uint64
    deposit_balance_to_consume*: Gwei
    exit_balance_to_consume*: Gwei
    earliest_exit_epoch*: Epoch
    consolidation_balance_to_consume*: Gwei
    earliest_consolidation_epoch*: Epoch
    pending_deposits*: HashList[PendingDeposit, Limit PENDING_DEPOSITS_LIMIT]

    pending_partial_withdrawals*:
      HashList[PendingPartialWithdrawal, Limit PENDING_PARTIAL_WITHDRAWALS_LIMIT]
    pending_consolidations*:
      HashList[PendingConsolidation, Limit PENDING_CONSOLIDATIONS_LIMIT]

    proposer_lookahead*:
        HashArray[Limit ((MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH), uint64]

    builders*: HashList[Builder, Limit BUILDER_REGISTRY_LIMIT]
    next_withdrawal_builder_index*: uint64
    execution_payload_availability*: BitArray[int(SLOTS_PER_HISTORICAL_ROOT)]
    builder_pending_payments*:
      HashArray[Limit 2 * SLOTS_PER_EPOCH, BuilderPendingPayment]
    builder_pending_withdrawals*:
      HashList[BuilderPendingWithdrawal, Limit BUILDER_PENDING_WITHDRAWALS_LIMIT]
    latest_block_hash*: Eth2Digest
    payload_expected_withdrawals*:
      HashList[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]
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
    attestations*: List[electra.Attestation, Limit MAX_ATTESTATIONS_ELECTRA]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: SyncAggregate

    # Execution
    bls_to_execution_changes*: SignedBLSToExecutionChangeList

    signed_execution_payload_bid*: SignedExecutionPayloadBid
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
    attestations*: List[electra.TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    bls_to_execution_changes*: SignedBLSToExecutionChangeList

    signed_execution_payload_bid*: SignedExecutionPayloadBid
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
    attestations*: List[electra.TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    bls_to_execution_changes*: SignedBLSToExecutionChangeList

    signed_execution_payload_bid*: SignedExecutionPayloadBid
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
    `block`*: heze.BeaconBlock
    kzg_proofs*: fulu.KzgProofs
    blobs*: Blobs

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
