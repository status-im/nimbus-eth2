# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Types specific to Deneb (i.e. known to have changed across hard forks) - see
# `base` for types and guidelines common across forks

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

{.push raises: [].}

import
  chronicles,
  std/[sequtils, strutils],
  stew/[bitops2, byteutils],
  json_serialization,
  ssz_serialization/[merkleization, proofs],
  ssz_serialization/types as sszTypes,
  ../digest,
  "."/[base, phase0, altair, bellatrix, capella]

from kzg4844 import KzgCommitment, KzgProof

export json_serialization, base, kzg4844

const
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/polynomial-commitments.md#constants
  BYTES_PER_FIELD_ELEMENT = 32
  BLS_MODULUS* = "52435875175126190479447740508185965837690552500527637822603658699938581184513".u256

type
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#beaconblockbody
  KzgCommitments* = List[KzgCommitment, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]

  # TODO this apparently is suppposed to be SSZ-equivalent to Bytes32, but
  # current spec doesn't ever SSZ-serialize it or hash_tree_root it
  VersionedHash* = array[32, byte]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#custom-types
  BlobIndex* = uint64

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/polynomial-commitments.md#custom-types
  Blob* = array[BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB, byte]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/p2p-interface.md#blobsidecar
  BlobSidecar* = object
    index*: BlobIndex
      ## Index of blob in block
    blob*: Blob
    kzg_commitment*: KzgCommitment
    kzg_proof*: KzgProof
      ## Allows for quick verification of kzg_commitment
    signed_block_header*: SignedBeaconBlockHeader
    kzg_commitment_inclusion_proof*:
      array[KZG_COMMITMENT_INCLUSION_PROOF_DEPTH, Eth2Digest]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/p2p-interface.md#blobidentifier
  BlobIdentifier* = object
    block_root*: Eth2Digest
    index*: BlobIndex

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#executionpayload
  ExecutionPayload* = object
    # Execution block header fields
    parent_hash*: Eth2Digest
    fee_recipient*: ExecutionAddress
      ## 'beneficiary' in the yellow paper
    state_root*: Eth2Digest
    receipts_root*: Eth2Digest
    logs_bloom*: BloomLogs
    prev_randao*: Eth2Digest
      ## 'difficulty' in the yellow paper
    block_number*: uint64
      ## 'number' in the yellow paper
    gas_limit*: uint64
    gas_used*: uint64
    timestamp*: uint64
    extra_data*: List[byte, MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas*: UInt256

    # Extra payload fields
    block_hash*: Eth2Digest # Hash of execution block
    transactions*: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]
    withdrawals*: List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]
    blob_gas_used*: uint64   # [New in Deneb]
    excess_blob_gas*: uint64 # [New in Deneb]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/validator.md#blobsbundle
  KzgProofs* = List[KzgProof, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]
  Blobs* = List[Blob, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]
  BlobRoots* = List[Eth2Digest, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]

  BlobsBundle* = object
    commitments*: KzgCommitments
    proofs*: KzgProofs
    blobs*: Blobs

  ExecutionPayloadForSigning* = object
    executionPayload*: ExecutionPayload
    blockValue*: Wei
    blobsBundle*: BlobsBundle

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#executionpayloadheader
  ExecutionPayloadHeader* = object
    # Execution block header fields
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

    # Extra payload fields
    block_hash*: Eth2Digest
      ## Hash of execution block
    transactions_root*: Eth2Digest
    withdrawals_root*: Eth2Digest
    blob_gas_used*: uint64   # [New in Deneb:EIP4844]
    excess_blob_gas*: uint64 # [New in Deneb:EIP4844]

  ExecutePayload* = proc(
    execution_payload: ExecutionPayload): bool {.gcsafe, raises: [].}

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
  LightClientHeader* = object
    beacon*: BeaconBlockHeader
      ## Beacon block header

    execution*: ExecutionPayloadHeader
      ## Execution payload header corresponding to `beacon.body_root` (from Capella onward)
    execution_branch*: capella.ExecutionBranch

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientbootstrap
  LightClientBootstrap* = object
    header*: LightClientHeader
      ## Header matching the requested beacon block root

    current_sync_committee*: SyncCommittee
      ## Current sync committee corresponding to `header.beacon.state_root`
    current_sync_committee_branch*: altair.CurrentSyncCommitteeBranch

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientupdate
  LightClientUpdate* = object
    attested_header*: LightClientHeader
      ## Header attested to by the sync committee

    next_sync_committee*: SyncCommittee
      ## Next sync committee corresponding to
      ## `attested_header.beacon.state_root`
    next_sync_committee_branch*: altair.NextSyncCommitteeBranch

    # Finalized header corresponding to `attested_header.beacon.state_root`
    finalized_header*: LightClientHeader
    finality_branch*: altair.FinalityBranch

    sync_aggregate*: SyncAggregate
      ## Sync committee aggregate signature
    signature_slot*: Slot
      ## Slot at which the aggregate signature was created (untrusted)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate
  LightClientFinalityUpdate* = object
    # Header attested to by the sync committee
    attested_header*: LightClientHeader

    # Finalized header corresponding to `attested_header.beacon.state_root`
    finalized_header*: LightClientHeader
    finality_branch*: altair.FinalityBranch

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

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientstore
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

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#beaconstate
  # changes indirectly via ExecutionPayloadHeader
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
    latest_execution_payload_header*: ExecutionPayloadHeader

    # Withdrawals
    next_withdrawal_index*: WithdrawalIndex
    next_withdrawal_validator_index*: uint64

    # Deep history valid from Capella onwards
    historical_summaries*:
      HashList[HistoricalSummary, Limit HISTORICAL_ROOTS_LIMIT]

  # TODO Careful, not nil analysis is broken / incomplete and the semantics will
  #      likely change in future versions of the language:
  #      https://github.com/nim-lang/RFCs/issues/250
  BeaconStateRef* = ref BeaconState not nil
  NilableBeaconStateRef* = ref BeaconState

  # TODO: There should be only a single generic HashedBeaconState definition
  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beaconblock
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

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: SyncAggregate

    # Execution
    execution_payload*: ExecutionPayload  # [Modified in Deneb]
    bls_to_execution_changes*: SignedBLSToExecutionChangeList
    blob_kzg_commitments*: KzgCommitments  # [New in Deneb]

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
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    execution_payload*: ExecutionPayload  # [Modified in Deneb]
    bls_to_execution_changes*: SignedBLSToExecutionChangeList
    blob_kzg_commitments*: KzgCommitments  # [New in Deneb]

  TrustedBeaconBlockBody* = object
    ## A full verified block
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    execution_payload*: ExecutionPayload  # [Modified in Deneb]
    bls_to_execution_changes*: SignedBLSToExecutionChangeList
    blob_kzg_commitments*: KzgCommitments  # [New in Deneb]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#signedbeaconblock
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

  MsgTrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: ValidatorSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  TrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SomeSignedBeaconBlock* =
    SignedBeaconBlock |
    SigVerifiedSignedBeaconBlock |
    MsgTrustedSignedBeaconBlock |
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

# TODO: There should be only a single generic HashedBeaconState definition
func initHashedBeaconState*(s: BeaconState): HashedBeaconState =
  HashedBeaconState(data: s)

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

func shortLog*(v: BlobSidecar): auto =
  (
    index: v.index,
    bloblen: v.blob.len(),
    block_header: shortLog(v.signed_block_header.message),
  )

func shortLog*(v: seq[BlobSidecar]): auto =
  "[" & v.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(v: seq[ref BlobSidecar]): auto =
  "[" & v.mapIt(shortLog(it[])).join(", ") & "]"

func shortLog*(v: SomeSignedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
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
    extra_data_len: len(v.extra_data),
    base_fee_per_gas: $(v.base_fee_per_gas),
    block_hash: shortLog(v.block_hash),
    num_transactions: len(v.transactions),
    num_withdrawals: len(v.withdrawals),
    excess_blob_gas: $(v.excess_blob_gas)
  )

func shortLog*(x: seq[BlobIdentifier]): string =
  "[" & x.mapIt(shortLog(it.block_root) & "/" & $it.index).join(", ") & "]"

func kzg_commitment_inclusion_proof_gindex*(
    index: BlobIndex): GeneralizedIndex =
  # This index is rooted in `BeaconBlockBody`.
  # The first member (`randao_reveal`) is 16, subsequent members +1 each.
  # If there are ever more than 16 members in `BeaconBlockBody`, indices change!
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/ssz/merkle-proofs.md
  const
    # blob_kzg_commitments
    BLOB_KZG_COMMITMENTS_GINDEX =
      27.GeneralizedIndex
    # List + 0 = items, + 1 = len
    BLOB_KZG_COMMITMENTS_BASE_GINDEX =
      (BLOB_KZG_COMMITMENTS_GINDEX shl 1) + 0
    # List depth
    BLOB_KZG_COMMITMENTS_PROOF_DEPTH =
      log2trunc(nextPow2(deneb.KzgCommitments.maxLen.uint64))
    # First item
    BLOB_KZG_COMMITMENTS_FIRST_GINDEX =
      (BLOB_KZG_COMMITMENTS_BASE_GINDEX shl BLOB_KZG_COMMITMENTS_PROOF_DEPTH)
  static: doAssert(
    log2trunc(BLOB_KZG_COMMITMENTS_FIRST_GINDEX) ==
    KZG_COMMITMENT_INCLUSION_PROOF_DEPTH)

  BLOB_KZG_COMMITMENTS_FIRST_GINDEX + index

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/light-client/sync-protocol.md#modified-get_lc_execution_root
func get_lc_execution_root*(
    header: LightClientHeader, cfg: RuntimeConfig): Eth2Digest =
  let epoch = header.beacon.slot.epoch

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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/light-client/sync-protocol.md#modified-is_valid_light_client_header
func is_valid_light_client_header*(
    header: LightClientHeader, cfg: RuntimeConfig): bool =
  let epoch = header.beacon.slot.epoch

  if epoch < cfg.DENEB_FORK_EPOCH:
    if header.execution.blob_gas_used != 0 or
        header.execution.excess_blob_gas != 0:
      return false

  if epoch < cfg.CAPELLA_FORK_EPOCH:
    return
      header.execution == default(ExecutionPayloadHeader) and
      header.execution_branch == default(ExecutionBranch)

  is_valid_merkle_branch(
    get_lc_execution_root(header, cfg),
    header.execution_branch,
    log2trunc(EXECUTION_PAYLOAD_GINDEX),
    get_subtree_index(EXECUTION_PAYLOAD_GINDEX),
    header.beacon.body_root)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_header_to_deneb*(
    pre: capella.LightClientHeader): LightClientHeader =
  LightClientHeader(
    beacon: pre.beacon,
    execution: ExecutionPayloadHeader(
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
        withdrawals_root: pre.execution.withdrawals_root,
        blob_gas_used: 0,     # [New in Deneb:EIP4844]
        excess_blob_gas: 0),  # [New in Deneb:EIP4844]
    execution_branch: pre.execution_branch)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_bootstrap_to_deneb*(
    pre: capella.LightClientBootstrap): LightClientBootstrap =
  LightClientBootstrap(
    header: upgrade_lc_header_to_deneb(pre.header),
    current_sync_committee: pre.current_sync_committee,
    current_sync_committee_branch: pre.current_sync_committee_branch)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_update_to_deneb*(
    pre: capella.LightClientUpdate): LightClientUpdate =
  LightClientUpdate(
    attested_header: upgrade_lc_header_to_deneb(pre.attested_header),
    next_sync_committee: pre.next_sync_committee,
    next_sync_committee_branch: pre.next_sync_committee_branch,
    finalized_header: upgrade_lc_header_to_deneb(pre.finalized_header),
    finality_branch: pre.finality_branch,
    sync_aggregate: pre.sync_aggregate,
    signature_slot: pre.signature_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_finality_update_to_deneb*(
    pre: capella.LightClientFinalityUpdate): LightClientFinalityUpdate =
  LightClientFinalityUpdate(
    attested_header: upgrade_lc_header_to_deneb(pre.attested_header),
    finalized_header: upgrade_lc_header_to_deneb(pre.finalized_header),
    finality_branch: pre.finality_branch,
    sync_aggregate: pre.sync_aggregate,
    signature_slot: pre.signature_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/light-client/fork.md#upgrading-light-client-data
func upgrade_lc_optimistic_update_to_deneb*(
    pre: capella.LightClientOptimisticUpdate): LightClientOptimisticUpdate =
  LightClientOptimisticUpdate(
    attested_header: upgrade_lc_header_to_deneb(pre.attested_header),
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
      v.next_sync_committee != default(typeof(v.next_sync_committee)),
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/light-client/fork.md#upgrading-the-store
func upgrade_lc_store_to_deneb*(
    pre: capella.LightClientStore): LightClientStore =
  let best_valid_update =
    if pre.best_valid_update.isNone:
      Opt.none(LightClientUpdate)
    else:
      Opt.some upgrade_lc_update_to_deneb(pre.best_valid_update.get)
  LightClientStore(
    finalized_header: upgrade_lc_header_to_deneb(pre.finalized_header),
    current_sync_committee: pre.current_sync_committee,
    next_sync_committee: pre.next_sync_committee,
    best_valid_update: best_valid_update,
    optimistic_header: upgrade_lc_header_to_deneb(pre.optimistic_header),
    previous_max_active_participants: pre.previous_max_active_participants,
    current_max_active_participants: pre.current_max_active_participants)

template asSigned*(
    x: SigVerifiedSignedBeaconBlock |
       MsgTrustedSignedBeaconBlock |
       TrustedSignedBeaconBlock): SignedBeaconBlock =
  isomorphicCast[SignedBeaconBlock](x)

template asSigVerified*(
    x: SignedBeaconBlock |
       MsgTrustedSignedBeaconBlock |
       TrustedSignedBeaconBlock): SigVerifiedSignedBeaconBlock =
  isomorphicCast[SigVerifiedSignedBeaconBlock](x)

template asSigVerified*(
    x: BeaconBlock | TrustedBeaconBlock): SigVerifiedBeaconBlock =
  isomorphicCast[SigVerifiedBeaconBlock](x)

template asMsgTrusted*(
    x: SignedBeaconBlock |
       SigVerifiedSignedBeaconBlock |
       TrustedSignedBeaconBlock): MsgTrustedSignedBeaconBlock =
  isomorphicCast[MsgTrustedSignedBeaconBlock](x)

template asTrusted*(
    x: SignedBeaconBlock |
       SigVerifiedSignedBeaconBlock |
       MsgTrustedSignedBeaconBlock): TrustedSignedBeaconBlock =
  isomorphicCast[TrustedSignedBeaconBlock](x)
