# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ".."/datatypes/[altair, capella, deneb]
from stew/byteutils import to0xHex

type
  # https://github.com/ethereum/builder-specs/blob/534e4f81276b8346d785ed9aba12c4c74b927ec6/specs/deneb/builder.md#blindedblobsbundle
  BlindedBlobsBundle* = object
    commitments*: List[KZGCommitment, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]
    proofs*: List[KZGProof, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]
    blob_roots*: List[Eth2Digest, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]

  # https://github.com/ethereum/builder-specs/blob/534e4f81276b8346d785ed9aba12c4c74b927ec6/specs/deneb/builder.md#builderbid
  BuilderBid* = object
    header*: deneb.ExecutionPayloadHeader # [Modified in Deneb]
    blinded_blobs_bundle*: BlindedBlobsBundle # [New in Deneb]
    value*: UInt256
    pubkey*: ValidatorPubKey

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signedbuilderbid
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/capella/builder.md#executionpayloadheader
  # https://github.com/ethereum/builder-specs/blob/534e4f81276b8346d785ed9aba12c4c74b927ec6/specs/deneb/builder.md#executionpayloadheader
  SignedBuilderBid* = object
    message*: BuilderBid
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/capella/builder.md#blindedbeaconblockbody
  # https://github.com/ethereum/builder-specs/blob/0b913daaa491cd889083827375977a6285e684bd/specs/deneb/builder.md#blindedbeaconblockbody
  BlindedBeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    sync_aggregate*: SyncAggregate
    execution_payload_header*:
      capella.ExecutionPayloadHeader
    bls_to_execution_changes*:
      List[SignedBLSToExecutionChange,
        Limit MAX_BLS_TO_EXECUTION_CHANGES]
    blob_kzg_commitments*: KzgCommitments # [New in Deneb]

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#blindedbeaconblock
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/capella/builder.md#blindedbeaconblockbody
  # https://github.com/ethereum/builder-specs/blob/0b913daaa491cd889083827375977a6285e684bd/specs/deneb/builder.md#blindedbeaconblockbody
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody # [Modified in Deneb]

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signedblindedbeaconblock
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/capella/builder.md#blindedbeaconblockbody
  SignedBlindedBeaconBlock* = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/534e4f81276b8346d785ed9aba12c4c74b927ec6/specs/deneb/builder.md#blindedblobsidecar
  BlindedBlobSidecar* = object
    block_root*: Eth2Digest
    index*: uint64
    slot*: uint64
    block_parent_root*: Eth2Digest
    proposer_index*: uint64
    blob_root*: Eth2Digest
    kzg_commitment*: KZGCommitment
    kzg_proof*: KZGProof

  # https://github.com/ethereum/builder-specs/blob/534e4f81276b8346d785ed9aba12c4c74b927ec6/specs/deneb/builder.md#signedblindedblobsidecar
  SignedBlindedBlobSidecar* = object
    message*: BlindedBlobSidecar
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/534e4f81276b8346d785ed9aba12c4c74b927ec6/specs/deneb/builder.md#signedblindedblockcontents
  SignedBlindedBeaconBlockContents* = object
    signed_blinded_block*: SignedBlindedBeaconBlock
    signed_blinded_blob_sidecars*:
      List[SignedBlindedBlobSidecar, Limit MAX_BLOBS_PER_BLOCK]

  # https://github.com/ethereum/builder-specs/blob/534e4f81276b8346d785ed9aba12c4c74b927ec6/specs/deneb/builder.md#executionpayloadandblobsbundle
  ExecutionPayloadAndBlobsBundle* = object
    execution_payload*: deneb.ExecutionPayload
    blobs_bundle*: BlobsBundle

func shortLog*(v: BlindedBeaconBlock): auto =
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
    block_number: v.body.execution_payload_header.block_number,
    # TODO checksum hex? shortlog?
    fee_recipient: to0xHex(v.body.execution_payload_header.fee_recipient.data),
    bls_to_execution_changes_len: v.body.bls_to_execution_changes.len(),
    blob_kzg_commitments_len: 0,  # Deneb compat
  )

func shortLog*(v: SignedBlindedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

# needs to match SignedBlindedBeaconBlock
func shortLog*(v: SignedBlindedBeaconBlockContents): auto =
  (
    blck: shortLog(v.signed_blinded_block.message),
    signature: shortLog(v.signed_blinded_block.signature)
  )
