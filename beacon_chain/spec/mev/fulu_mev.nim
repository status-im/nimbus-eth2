# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ".."/datatypes/[altair, fulu]

from ".."/datatypes/phase0 import AttesterSlashing
from ../datatypes/bellatrix import ExecutionAddress
from ".."/datatypes/capella import SignedBLSToExecutionChange
from ".."/datatypes/deneb import BlobsBundle, KzgCommitments
from ".."/datatypes/electra import
  Attestation, AttesterSlashing, ExecutionRequests
from ".."/eth2_merkleization import hash_tree_root

type
  BuilderBid* = object
    header*: SignedExecutionPayloadHeader
    blob_kzg_commitments*: KzgCommitments
    execution_requests*: ExecutionRequests # [New in Electra]
    value*: UInt256
    pubkey*: ValidatorPubKey

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#signedbuilderbid
  SignedBuilderBid* = object
    message*: BuilderBid
    signature*: ValidatorSig

  BlindedBeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*:
      List[electra.AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
    attestations*: List[electra.Attestation, Limit MAX_ATTESTATIONS_ELECTRA]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    sync_aggregate*: SyncAggregate
    bls_to_execution_changes*:
      List[SignedBLSToExecutionChange,
        Limit MAX_BLS_TO_EXECUTION_CHANGES]
    signed_execution_payload_header*: SignedExecutionPayloadHeader
    payload_attestations*: 
      List[PayloadAttestation, Limit MAX_PAYLOAD_ATTESTATIONS]

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#blindedbeaconblock
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody # [Modified in Deneb]

  MaybeBlindedBeaconBlock* = object
    case isBlinded*: bool
    of false:
      data*: fulu.BlockContents
    of true:
      blindedData*: BlindedBeaconBlock

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#signedblindedbeaconblock
  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/capella/builder.md#blindedbeaconblockbody
  SignedBlindedBeaconBlock* = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/deneb/builder.md#executionpayloadandblobsbundle
  ExecutionPayloadAndBlobsBundle* = object
    execution_payload*: ExecutionPayload
    blobs_bundle*: BlobsBundle

  # Not spec, but suggested by spec
  BlindedExecutionPayloadAndBlobsBundle* = object
    signed_execution_payload_header*: SignedExecutionPayloadHeader
    blob_kzg_commitments*: KzgCommitments # [New in Deneb]

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
    block_number: 0'u64,
    # TODO checksum hex? shortlog?
    block_hash: "",
    parent_hash: "",
    fee_recipient: "",
    bls_to_execution_changes_len: v.body.bls_to_execution_changes.len(),
    blob_kzg_commitments_len: 0,  # Deneb compat
    signed_execution_payload_header: 
      shortLog(v.body.signed_execution_payload_header.message.block_hash),
    payload_attestations_len: v.body.payload_attestations.len()
  )

func shortLog*(v: SignedBlindedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

func toSignedBlindedBeaconBlock*(blck: fulu.SignedBeaconBlock): SignedBlindedBeaconBlock =
  SignedBlindedBeaconBlock(
    message: BlindedBeaconBlock(
      slot: blck.message.slot,
      proposer_index: blck.message.proposer_index,
      parent_root: blck.message.parent_root,
      state_root: blck.message.state_root,
      body: BlindedBeaconBlockBody(
        randao_reveal: blck.message.body.randao_reveal,
        eth1_data: blck.message.body.eth1_data,
        graffiti: blck.message.body.graffiti,
        proposer_slashings: blck.message.body.proposer_slashings,
        attester_slashings: blck.message.body.attester_slashings,
        attestations: blck.message.body.attestations,
        deposits: blck.message.body.deposits,
        voluntary_exits: blck.message.body.voluntary_exits,
        sync_aggregate: blck.message.body.sync_aggregate,
        bls_to_execution_changes: blck.message.body.bls_to_execution_changes,
        signed_execution_payload_header: SignedExecutionPayloadHeader(
          message: ExecutionPayloadHeader(
            parent_block_hash: blck.message.body.
              signed_execution_payload_header.message.parent_block_hash,
            parent_block_root: blck.message.body.
              signed_execution_payload_header.message.parent_block_root,
            block_hash: blck.message.body.
              signed_execution_payload_header.message.block_hash,
            gas_limit: blck.message.body.
              signed_execution_payload_header.message.gas_limit,
            builder_index: blck.message.body.
              signed_execution_payload_header.message.builder_index,
            slot: blck.message.body.
              signed_execution_payload_header.message.slot,
            value: blck.message.body.
              signed_execution_payload_header.message.value,
            blob_kzg_commitments_root: blck.message.body.
              signed_execution_payload_header.message.blob_kzg_commitments_root
          ),
          signature: blck.message.body.
            signed_execution_payload_header.signature
        ),
        payload_attestations: blck.message.body.payload_attestations
      )
    ),
    signature: blck.signature)