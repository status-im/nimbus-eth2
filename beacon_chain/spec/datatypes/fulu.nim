# beacon_chain
# Copyright (c) 2022-2026 Status Research & Development GmbH
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
  ./[phase0, base, bellatrix, electra],
  chronicles,
  json_serialization,
  ssz_serialization/[merkleization, proofs, bitseqs],
  ssz_serialization/types as sszTypes,
  ../digest,
  kzg4844/[kzg, kzg_abi]

from std/sequtils import mapIt
from std/strutils import join
from stew/byteutils import to0xHex
from ./altair import
  EpochParticipationFlags, InactivityScores, SyncAggregate, SyncCommittee,
  TrustedSyncAggregate, SyncnetBits, num_active_participants
from ./capella import
  HistoricalSummary, SignedBLSToExecutionChange,
  SignedBLSToExecutionChangeList, Withdrawal
from ./deneb import
  Blobs, ExecutionPayload, ExecutionPayloadHeader, KzgCommitments, KzgProofs

export json_serialization, base

const
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/fulu/polynomial-commitments-sampling.md#cells
  FIELD_ELEMENTS_PER_EXT_BLOB = 2 * kzg_abi.FIELD_ELEMENTS_PER_BLOB
  # Number of field elements in a Reed-Solomon extended blob |
  BYTES_PER_CELL* = kzg_abi.FIELD_ELEMENTS_PER_CELL * kzg_abi.BYTES_PER_FIELD_ELEMENT
  # The number of cells in an extended blob |

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/fulu/p2p-interface.md#configuration
  # The number of data column sidecar subnets used in the gossipsub protocol.
  DATA_COLUMN_SIDECAR_SUBNET_COUNT* = 128

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/fulu/das-core.md#custody-setting
  CUSTODY_REQUIREMENT* = 4

type
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/fulu/polynomial-commitments-sampling.md#custom-types
  BLSFieldElement* = KzgBytes32
  G2Point* = array[96, byte]
  PolynomialCoeff* = List[BLSFieldElement, FIELD_ELEMENTS_PER_EXT_BLOB]
  Coset* = array[kzg_abi.FIELD_ELEMENTS_PER_CELL, BLSFieldElement]
  CosetEvals* = array[kzg_abi.FIELD_ELEMENTS_PER_CELL, BLSFieldElement]
  Cell* = KzgCell
  Cells* = KzgCells
  CellsAndProofs* = KzgCellsAndKzgProofs

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/das-core.md#custom-types
  RowIndex* = uint64
  ColumnIndex* = uint64
  CellIndex* = uint64
  CustodyIndex* = uint64

  DataColumn* = List[KzgCell, Limit(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
  DataColumnIndices* = List[ColumnIndex, Limit(NUMBER_OF_COLUMNS)]

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.5/specs/fulu/das-core.md#datacolumnsidecar
  DataColumnSidecar* = object
    index*: ColumnIndex # Index of column in extended matrix
    column*: DataColumn
    kzg_commitments*: KzgCommitments
    kzg_proofs*: deneb.KzgProofs
    signed_block_header*: SignedBeaconBlockHeader
    kzg_commitments_inclusion_proof*:
      array[KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH, Eth2Digest]

  DataColumnSidecars* = seq[ref DataColumnSidecar]

  DataColumnSidecarInfoObject* = object
    block_root*: Eth2Digest
    index*: ColumnIndex
    slot*: Slot
    kzg_commitments*: KzgCommitments

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/p2p-interface.md#datacolumnidentifier
  DataColumnIdentifier* = object
    block_root*: Eth2Digest
    index*: ColumnIndex

  # https://github.com/ethereum/consensus-specs/blob/b8b5fbb8d16f52d42a716fa93289062fe2124c7c/specs/fulu/p2p-interface.md#datacolumnsbyrootidentifier
  DataColumnsByRootIdentifier* = object
    block_root*: Eth2Digest
    indices*: DataColumnIndices

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/fulu/p2p-interface.md#partialdatacolumnpartsmetadata
  PartialDataColumnPartsMetadata* = object
    available*: BitArray[int(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
    requests*: BitArray[int(MAX_BLOB_COMMITMENTS_PER_BLOCK)]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/fulu/partial-columns/p2p-interface.md#partialdatacolumnheader
  PartialDataColumnHeader* = object
    kzg_commitments*: KzgCommitments
    signed_block_header*: SignedBeaconBlockHeader
    kzg_commitments_inclusion_proof*:
      array[KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH, Eth2Digest]

  CellsPresentBits* = BitList[Limit(MAX_BLOB_COMMITMENTS_PER_BLOCK)]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/fulu/partial-columns/p2p-interface.md#partialdatacolumnsidecar
  PartialDataColumnSidecar* = object
    cells_present_bitmap*: CellsPresentBits
    partial_column*: List[KzgCell, Limit(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
    kzg_proofs*: deneb.KzgProofs
    # Optional header, only sent on eager pushes
    header*: List[PartialDataColumnHeader, 1]

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/fulu/das-core.md#matrixentry
  MatrixEntry* = object
    cell*: Cell
    kzg_proof*: KzgProof
    column_index*: ColumnIndex
    row_index*: RowIndex

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.5/specs/fulu/validator.md#blobsbundle
  KzgProofs* = List[KzgProof,
    Limit FIELD_ELEMENTS_PER_EXT_BLOB * MAX_BLOB_COMMITMENTS_PER_BLOCK]

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.5/specs/fulu/validator.md#blobsbundle
  BlobsBundle* = object
    commitments*: KzgCommitments
    proofs*: fulu.KzgProofs
    blobs*: Blobs

  # BitArray needs a compile-time size but NUMBER_OF_CUSTODY_GROUPS is
  # runtime-configurable. We use NUMBER_OF_COLUMNS (compile-time, 128)
  # instead, which is safe because NUMBER_OF_CUSTODY_GROUPS <=
  # NUMBER_OF_COLUMNS always holds: each custody group maps to one or
  # more columns, so there can never be more groups than columns.
  # If NUMBER_OF_CUSTODY_GROUPS shrinks (e.g. to 64 or 32), the array
  # is slightly oversized but still correct — unused high bits stay zero.
  CgcBits* = BitArray[NUMBER_OF_COLUMNS]

  CgcCount* = uint8

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/fulu/p2p-interface.md#enr-structure
  MetaData* = object
    seq_number*: uint64
    attnets*: AttnetBits
    syncnets*: SyncnetBits
    custody_group_count*: uint64

  ExecutionPayloadForSigning* = object
    executionPayload*: deneb.ExecutionPayload
    blockValue*: Wei
    blobsBundle*: fulu.BlobsBundle # [New in Fulu]
    executionRequests*: seq[seq[byte]]

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

    # [New in Fulu:EIP7917]
    proposer_lookahead*:
        HashArray[Limit ((MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH), uint64]

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

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/electra/beacon-chain.md#beaconblockbody
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
      List[electra.TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[electra.TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
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
      List[electra.TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[electra.TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    execution_payload*: deneb.ExecutionPayload
    bls_to_execution_changes*: SignedBLSToExecutionChangeList
    blob_kzg_commitments*: KzgCommitments
    execution_requests*: ExecutionRequests  # [New in Electra]

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
    `block`*: BeaconBlock
    kzg_proofs*: fulu.KzgProofs
    blobs*: Blobs

func shortLog*(v: DataColumnSidecar): auto =
  (
    index: v.index,
    kzg_commitments: v.kzg_commitments.len,
    kzg_proofs: v.kzg_proofs.len,
    block_header: shortLog(v.signed_block_header.message),
  )

func shortLog*(v: PartialDataColumnSidecar): auto =
  (
    cells_present: v.cells_present_bitmap,
    partial_column: v.partial_column.len,
    kzg_proofs: v.kzg_proofs.len,
    has_header: v.header.len > 0,
  )

func shortLog*(v: seq[DataColumnSidecar]): auto =
  "[" & v.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(x: seq[DataColumnIdentifier]): string =
  "[" & x.mapIt(shortLog(it.block_root) & "/" & $it.index).join(", ") & "]"

func shortLog*(xs: seq[DataColumnsByRootIdentifier]): string =
  ## Formats like:  [abcd…/0,2,4,  ef09…/1,3]
  "[" &
    xs.mapIt(
      shortLog(it.block_root) & "/" &
      it.indices.mapIt($it).join(",")
    ).join(", ") &
  "]"

func shortLog*(x: seq[ColumnIndex]): string =
  "<" & x.mapIt($it).join(", ") & ">"

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

const
  KZG_COMMITMENTS_GINDEX* = get_generalized_index(
    BeaconBlockBody, "blob_kzg_commitments")
static:
  doAssert KZG_COMMITMENTS_GINDEX == 27.GeneralizedIndex
