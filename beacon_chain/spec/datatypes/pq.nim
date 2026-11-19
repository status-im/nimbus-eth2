# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Types specific to PQ (i.e. known to have changed across hard forks) - see
# `base` for types and guidelines common across forks
#
# https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md
#
# PQ replaces BLS with leanXMSS. Messages that carry no signature any more
# have no `Trusted` counterpart: the untrusted, sig-verified and trusted
# flavours of blocks share the same operation types, so that they remain
# isomorphic.

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
  ../[digest, xmss, pq_vrf],
  kzg4844/[kzg, kzg_abi]

from ./altair import ParticipationFlags
from ./capella import HistoricalSummary, Withdrawal
from ./deneb import Blobs
from ./gloas import
  Builder, AggregationBits, AttestingIndices, BuilderDepositRequests,
  BuilderExitRequests, BuilderPendingPayment, BuilderPendingWithdrawal,
  ConsolidationRequests, DepositRequests, EpochParticipationFlags,
  ExecutionPayload, ExecutionPayloadBid, InactivityScores, KzgCommitments,
  PayloadAttestationData, ProposerPreferences, WithdrawalRequests

export json_serialization, base, xmss, pq_vrf

const
  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#misc
  AGGREGATORS_PER_COMMITTEE*: uint64 = 4

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#xmss
  XMSS_RESERVED_LEAVES*: uint64 = 1'u64 shl 15
  XMSS_ATTESTATION_LEAVES*: uint64 = 1'u64 shl 29
  XMSS_BUILDER_BID_LEAVES*: uint64 = 1'u64 shl 30
  XMSS_LEAVES_PER_SLOT*: uint64 = 8

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#xmss-leaf-offsets
  LEAF_OFFSET_BEACON_PROPOSER*: uint64 = 0
  LEAF_OFFSET_AGGREGATE_AND_PROOF*: uint64 = 1
  LEAF_OFFSET_PTC_ATTESTER*: uint64 = 2
  LEAF_OFFSET_PROPOSER_PREFERENCES*: uint64 = 3
  LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE*: uint64 = 4

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#legacy-domains
  LEGACY_XMSS_PUBKEY_DOMAIN*: byte = 0x00
  LEGACY_VRF_ROOT_DOMAIN*: byte = 0x01

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#execution-layer-triggered-requests
  VALIDATOR_PREREGISTRATION_REQUEST_TYPE*: byte = 0x07
  BUILDER_PREREGISTRATION_REQUEST_TYPE*: byte = 0x08
  VOLUNTARY_EXIT_REQUEST_TYPE*: byte = 0x09

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/p2p-interface.md#configs
  ATTESTATION_SUBNET_COUNT_PQ*: uint64 = 16

type
  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#modified-committeebits
  CommitteeBits* = BitArray[MAX_COMMITTEES_PER_SLOT_PQ.int]

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#new-vrfproof
  VRFProof* = array[VRF_TREE_DEPTH + 1, Eth2Digest]

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#new-attestationproof
  AttestationProof* = List[byte, Limit MAX_STARK_PROOF_SIZE]

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#new-aggregationcommittee
  AggregationCommittee* = seq[uint64]
  AggregationCommittees* = seq[AggregationCommittee]

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#validator
  PqValidator* = object
    pubkey*: XMSSPubkey
    vrf_root*: Eth2Digest
    withdrawal_credentials*: Eth2Digest
    effective_balance*: Gwei
    slashed*: bool
    activation_eligibility_epoch*: Epoch
    activation_epoch*: Epoch
    exit_epoch*: Epoch
    withdrawable_epoch*: Epoch

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#builder
  PqBuilder* = object
    pubkey*: XMSSPubkey
    version*: uint8
    execution_address*: ExecutionAddress
    balance*: Gwei
    deposit_epoch*: Epoch
    withdrawable_epoch*: Epoch

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#attestation
  Attestation* {.sszActiveFields: [1, 1, 0, 1].} = object
    aggregation_bits*: gloas.AggregationBits
    data*: AttestationData
    # [Modified in PQ]
    # Removed `signature`
    committee_bits*: CommitteeBits

  TrustedAttestation* = Attestation

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#indexedattestation
  IndexedAttestation* {.sszActiveFields: [1, 1, 1].} = object
    attesting_indices*: gloas.AttestingIndices
    data*: AttestationData
    # [New in PQ]
    proof*: AttestationProof

  TrustedIndexedAttestation* = IndexedAttestation

  AttesterSlashing* = object
    attestation_1*: IndexedAttestation
    attestation_2*: IndexedAttestation

  TrustedAttesterSlashing* = AttesterSlashing

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#signedbeaconblockheader
  PqSignedBeaconBlockHeader* = object
    message*: BeaconBlockHeader
    signature*: XMSSSignature

  PqProposerSlashing* = object
    signed_header_1*: PqSignedBeaconBlockHeader
    signed_header_2*: PqSignedBeaconBlockHeader

  PqTrustedProposerSlashing* = PqProposerSlashing

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#singleattestation
  PqSingleAttestation* = object
    committee_index*: uint64
    attester_index*: uint64
    data*: AttestationData
    signature*: XMSSSignature

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/validator.md#aggregateandproof
  AggregateAndProof* = object
    aggregator_index*: uint64
    aggregate*: Attestation
    # [Modified in PQ]
    # Removed `selection_proof`
    # [New in PQ]
    proof*: AttestationProof

  SignedAggregateAndProof* = object
    message*: AggregateAndProof
    signature*: XMSSSignature

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#payloadattestationmessage
  PqPayloadAttestationMessage* = object
    validator_index*: uint64
    data*: gloas.PayloadAttestationData
    signature*: XMSSSignature

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#signedexecutionpayloadbid
  SignedExecutionPayloadBid* = object
    message*: gloas.ExecutionPayloadBid
    signature*: XMSSSignature

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/p2p-interface.md#modified-signedproposerpreferences
  PqSignedProposerPreferences* = object
    message*: gloas.ProposerPreferences
    signature*: XMSSSignature

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#validatorpreregistrationrequest
  ValidatorPreregistrationRequest* = object
    pubkey*: XMSSPubkey
    withdrawal_credentials*: Eth2Digest
    vrf_root*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#validatorpreregistration
  ValidatorPreregistration* = object
    pubkey*: XMSSPubkey
    withdrawal_credentials*: Eth2Digest
    vrf_root*: Eth2Digest
    expiry_slot*: Slot

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#builderpreregistrationrequest
  BuilderPreregistrationRequest* = object
    pubkey*: XMSSPubkey
    withdrawal_credentials*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#builderpreregistration
  BuilderPreregistration* = object
    pubkey*: XMSSPubkey
    withdrawal_credentials*: Eth2Digest
    expiry_slot*: Slot

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#voluntaryexitrequest
  VoluntaryExitRequest* = object
    pubkey*: XMSSPubkey

  ValidatorPreregistrationRequests* = seq[ValidatorPreregistrationRequest]
  BuilderPreregistrationRequests* = seq[BuilderPreregistrationRequest]
  VoluntaryExitRequests* = seq[VoluntaryExitRequest]

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#executionrequests
  ExecutionRequests* {.sszActiveFields: [
      1, 1, 1, 1, 1, 0, 0, 1, 1, 1].} = object
    deposits*: DepositRequests
    withdrawals*: WithdrawalRequests
    consolidations*: ConsolidationRequests
    builder_deposits*: BuilderDepositRequests
    builder_exits*: BuilderExitRequests
    # [Modified in PQ]
    # Removed `validator_pq_registrations`
    # Removed `builder_pq_registrations`
    # [New in PQ:EIP8205]
    validator_preregistrations*: ValidatorPreregistrationRequests
    builder_preregistrations*: BuilderPreregistrationRequests
    # [New in PQ]
    voluntary_exits*: VoluntaryExitRequests

  # The envelope's `ExecutionRequests` changes with PQ, so does the envelope.
  PqExecutionPayloadEnvelope* {.sszActiveFields: [1, 1, 1, 1, 1].} = object
    payload*: gloas.ExecutionPayload
    execution_requests*: ExecutionRequests
    builder_index*: uint64
    beacon_block_root*: Eth2Digest
    parent_beacon_block_root*: Eth2Digest

  PqTrustedExecutionPayloadEnvelope* {.sszActiveFields: [1, 1, 1, 1, 1].} = object
    payload*: gloas.ExecutionPayload
    execution_requests*: ExecutionRequests
    builder_index*: uint64
    beacon_block_root*: Eth2Digest
    parent_beacon_block_root*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#signedexecutionpayloadenvelope
  PqSignedExecutionPayloadEnvelope* = object
    message*: PqExecutionPayloadEnvelope
    signature*: XMSSSignature

  PqTrustedSignedExecutionPayloadEnvelope* = object
    message*: PqTrustedExecutionPayloadEnvelope
    signature*: XMSSSignature

  PqSignedExecutionPayloadEnvelopeContents* = object
    signed_execution_payload_envelope*: PqSignedExecutionPayloadEnvelope
    kzg_proofs*: fulu.KzgProofs
    blobs*: deneb.Blobs

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#beaconstate
  BeaconState* {.sszActiveFields: [
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1].} = object
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
    # [Modified in PQ]
    validators*: HashSeq[PqValidator]
    balances*: HashSeq[Gwei]

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

    # [Modified in PQ]
    # Removed `current_sync_committee`
    # Removed `next_sync_committee`

    latest_block_hash*: Eth2Digest

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
    pending_deposits*: HashSeq[PendingDeposit]
    pending_partial_withdrawals*: HashSeq[PendingPartialWithdrawal]
    pending_consolidations*: HashSeq[PendingConsolidation]

    proposer_lookahead*:
        HashArray[Limit ((MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH), uint64]

    # [Modified in PQ]
    builders*: HashSeq[PqBuilder]
    next_withdrawal_builder_index*: uint64
    execution_payload_availability*: BitArray[int(SLOTS_PER_HISTORICAL_ROOT)]
    builder_pending_payments*:
      HashArray[Limit 2 * SLOTS_PER_EPOCH, BuilderPendingPayment]
    builder_pending_withdrawals*: HashSeq[BuilderPendingWithdrawal]

    # Execution
    latest_execution_payload_bid*: gloas.ExecutionPayloadBid

    payload_expected_withdrawals*: HashSeq[Withdrawal]
    ptc_window*:
      HashArray[Limit ((2 + MIN_SEED_LOOKAHEAD) * SLOTS_PER_EPOCH),
        HashArray[Limit PTC_SIZE, uint64]]

    # [Modified in PQ]
    # Removed `validator_pq_registrations`
    # Removed `builder_pq_registrations`
    # [New in PQ:EIP8205]
    validator_preregistrations*: HashSeq[ValidatorPreregistration]
    builder_preregistrations*: HashSeq[BuilderPreregistration]
    # [New in PQ]
    aggregation_committee_window*:
      HashArray[Limit ((2 + MIN_SEED_LOOKAHEAD) * SLOTS_PER_EPOCH),
        AggregationCommittees]

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
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BeaconBlockBody

  SigVerifiedBeaconBlock* = object
    ## A BeaconBlock that contains verified signatures
    ## but that has not been verified for state transition
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: SigVerifiedBeaconBlockBody

  TrustedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: TrustedBeaconBlockBody

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#beaconblockbody
  BeaconBlockBody* {.sszActiveFields: [
      1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1].} = object
    # [Modified in PQ]
    randao_reveal*: VRFProof
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes
    proposer_slashings*: seq[PqProposerSlashing]
    attester_slashings*: seq[AttesterSlashing]
    attestations*: seq[Attestation]
    deposits*: seq[Deposit]
    # [Modified in PQ]
    # Removed `voluntary_exits`
    # Removed `sync_aggregate`
    # Removed `bls_to_execution_changes`
    signed_execution_payload_bid*: SignedExecutionPayloadBid
    # [Modified in PQ]
    # Removed `payload_attestations`
    parent_execution_requests*: ExecutionRequests
    # [New in PQ]
    proof*: AttestationProof

  SigVerifiedBeaconBlockBody* {.sszActiveFields: [
      1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1].} = object
    randao_reveal*: VRFProof
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes
    proposer_slashings*: seq[PqTrustedProposerSlashing]
    attester_slashings*: seq[TrustedAttesterSlashing]
    attestations*: seq[TrustedAttestation]
    deposits*: seq[Deposit]
    signed_execution_payload_bid*: SignedExecutionPayloadBid
    parent_execution_requests*: ExecutionRequests
    proof*: AttestationProof

  TrustedBeaconBlockBody* {.sszActiveFields: [
      1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1].} = object
    randao_reveal*: VRFProof
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes
    proposer_slashings*: seq[PqTrustedProposerSlashing]
    attester_slashings*: seq[TrustedAttesterSlashing]
    attestations*: seq[TrustedAttestation]
    deposits*: seq[Deposit]
    signed_execution_payload_bid*: SignedExecutionPayloadBid
    parent_execution_requests*: ExecutionRequests
    proof*: AttestationProof

  # https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#signedbeaconblock
  SignedBeaconBlock* = object
    message*: BeaconBlock
    signature*: XMSSSignature

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SigVerifiedSignedBeaconBlock* = object
    message*: SigVerifiedBeaconBlock
    signature*: XMSSSignature

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  TrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: XMSSSignature

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
    `block`*: pq.BeaconBlock
    kzg_proofs*: fulu.KzgProofs
    blobs*: Blobs

  PqBeaconBlockValidatorChanges* = object
    # Collection of slashings that are suitable for block production
    proposer_slashings*: seq[PqProposerSlashing]
    attester_slashings*: seq[AttesterSlashing]

  SomeIndexedAttestation* = IndexedAttestation
  SomeAttesterSlashing* = AttesterSlashing

  AnyValidator* = Validator | PqValidator
  AnyBuilder* = gloas.Builder | PqBuilder

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
    voluntary_exits_len: 0,
    sync_committee_participants: -1,
    block_number: 0'u64,
    block_hash: "",
    parent_hash: "",
    fee_recipient: "",
    bls_to_execution_changes_len: 0,
    blob_kzg_commitments_len: v.body.signed_execution_payload_bid.message.blob_kzg_commitments.len(),
  )

func shortLog*(v: SomeSignedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

func shortLog*(v: PqExecutionPayloadEnvelope): auto =
  (
    beacon_block_root: shortLog(v.beacon_block_root),
    parent_beacon_block_root: shortLog(v.parent_beacon_block_root),
    builder_index: v.builder_index,
    block_hash: shortLog(v.payload.block_hash),
    slot: v.payload.slot_number,
  )

func shortLog*(v: PqPayloadAttestationMessage): auto =
  (
    validator_index: v.validator_index,
    data: (
      beacon_block_root: shortLog(v.data.beacon_block_root),
      slot: v.data.slot,
      payload_present: v.data.payload_present,
      blob_data_available: v.data.blob_data_available),
    signature: shortLog(v.signature)
  )

func shortLog*(v: PqSignedProposerPreferences): auto =
  (
    proposal_slot: v.message.proposal_slot,
    validator_index: v.message.validator_index,
    fee_recipient: v.message.fee_recipient,
    target_gas_limit: v.message.target_gas_limit,
    signature: shortLog(v.signature)
  )

func shortLog*(v: Attestation): auto =
  (
    aggregation_bits: $v.aggregation_bits.countOnes() & "/" &
      $v.aggregation_bits.len(),
    committee_bits: v.committee_bits,
    data: shortLog(v.data),
  )

func shortLog*(v: PqSingleAttestation): auto =
  (
    committee_index: v.committee_index,
    attester_index: v.attester_index,
    data: shortLog(v.data),
    signature: shortLog(v.signature)
  )

func shortLog*(v: IndexedAttestation): auto =
  (
    attesting_indices: v.attesting_indices,
    data: shortLog(v.data),
    proof_len: v.proof.len
  )

func shortLog*(v: AttesterSlashing): auto =
  (
    attestation_1: shortLog(v.attestation_1),
    attestation_2: shortLog(v.attestation_2),
  )

func shortLog*(v: PqSignedBeaconBlockHeader): auto =
  (
    message: shortLog(v.message),
    signature: shortLog(v.signature)
  )

func shortLog*(v: PqProposerSlashing): auto =
  (
    signed_header_1: shortLog(v.signed_header_1),
    signed_header_2: shortLog(v.signed_header_2)
  )

func shortLog*(v: AggregateAndProof): auto =
  (
    aggregator_index: v.aggregator_index,
    aggregate: shortLog(v.aggregate),
    proof_len: v.proof.len,
  )

func shortLog*(v: SignedAggregateAndProof): auto =
  (
    message: shortLog(v.message),
    signature: shortLog(v.signature)
  )

chronicles.formatIt PqSingleAttestation: shortLog(it)
chronicles.formatIt SignedAggregateAndProof: shortLog(it)
chronicles.formatIt PqPayloadAttestationMessage: shortLog(it)

template asSigned*(
    x: SigVerifiedSignedBeaconBlock |
       TrustedSignedBeaconBlock): SignedBeaconBlock =
  isomorphicCast[SignedBeaconBlock](x)

template asSigned*(
    x: PqTrustedSignedExecutionPayloadEnvelope): PqSignedExecutionPayloadEnvelope =
  isomorphicCast[PqSignedExecutionPayloadEnvelope](x)

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

import std/sets

iterator getValidatorIndices*(attester_slashing: AttesterSlashing): uint64 =
  template attestation_1(): auto = attester_slashing.attestation_1
  template attestation_2(): auto = attester_slashing.attestation_2

  let attestation_2_indices = toHashSet(attestation_2.attesting_indices)
  for validator_index in attestation_1.attesting_indices:
    if validator_index notin attestation_2_indices:
      continue
    yield validator_index

# Helpers to frequently used values
template slot*(v: PqExecutionPayloadEnvelope): Slot = v.payload.slot_number
template slot*(v: PqSignedExecutionPayloadEnvelope): Slot = v.message.slot

template builder_index*(v: BeaconBlock | TrustedBeaconBlock): uint64 =
  if v.body.signed_execution_payload_bid.message.builder_index ==
      BUILDER_INDEX_SELF_BUILD:
    v.proposer_index
  else:
    v.body.signed_execution_payload_bid.message.builder_index
template builder_index*(
    v: SignedBeaconBlock | TrustedSignedBeaconBlock): uint64 =
  v.message.builder_index

func toVRFProof*(p: VRFProofArray): VRFProof = p

# https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#new-compute_xmss_attestation_leaf_index
func compute_xmss_attestation_leaf_index*(epoch: Epoch): uint64 =
  ## Return the XMSS leaf at which an attestation is signed for target
  ## ``epoch``.
  XMSS_RESERVED_LEAVES + distinctBase(epoch)

# https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#new-compute_xmss_leaf_index
func compute_xmss_leaf_index*(slot: Slot, leaf_offset: uint64): uint64 =
  ## Return the XMSS leaf at which a message of the type given by
  ## ``leaf_offset`` is signed for ``slot``.
  XMSS_RESERVED_LEAVES + XMSS_ATTESTATION_LEAVES + XMSS_BUILDER_BID_LEAVES +
    distinctBase(slot) * XMSS_LEAVES_PER_SLOT + leaf_offset

# https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/specs/_features/pq/beacon-chain.md#new-is_builder_bid_leaf_index
func is_builder_bid_leaf_index*(leaf_index: uint64): bool =
  ## Check if ``leaf_index`` is one of the leaves reserved for builder bids.
  const start = XMSS_RESERVED_LEAVES + XMSS_ATTESTATION_LEAVES
  start <= leaf_index and leaf_index < start + XMSS_BUILDER_BID_LEAVES
