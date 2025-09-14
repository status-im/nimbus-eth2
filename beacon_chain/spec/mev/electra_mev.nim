# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import ".."/datatypes/[altair, bellatrix, electra]

from stew/byteutils import to0xHex
from ".."/datatypes/phase0 import AttesterSlashing
from ".."/datatypes/capella import SignedBLSToExecutionChange
from ".."/datatypes/deneb import BlobsBundle, ExecutionPayloadHeader, KzgCommitments
from ".."/eth2_merkleization import hash_tree_root

type
  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#validatorregistrationv1
  ValidatorRegistrationV1* = object
    fee_recipient*: ExecutionAddress
    gas_limit*: uint64
    timestamp*: uint64
    pubkey*: ValidatorPubKey

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#signedvalidatorregistrationv1
  SignedValidatorRegistrationV1* = object
    message*: ValidatorRegistrationV1
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/electra/builder.md#builderbid
  BuilderBid* = object
    header*: deneb.ExecutionPayloadHeader
    blob_kzg_commitments*: KzgCommitments
    execution_requests*: ExecutionRequests # [New in Electra]
    value*: UInt256
    pubkey*: ValidatorPubKey

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#signedbuilderbid
  SignedBuilderBid* = object
    message*: BuilderBid
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/electra/builder.md#blindedbeaconblockbody
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
    execution_payload_header*: deneb.ExecutionPayloadHeader
    bls_to_execution_changes*:
      List[SignedBLSToExecutionChange,
        Limit MAX_BLS_TO_EXECUTION_CHANGES]
    blob_kzg_commitments*: KzgCommitments
    execution_requests*: ExecutionRequests # [New in Electra]

  SigVerifiedBlindedBeaconBlockBody* = object
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*:
      List[electra.TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
    attestations*: List[electra.TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    sync_aggregate*: TrustedSyncAggregate
    execution_payload_header*: deneb.ExecutionPayloadHeader
    bls_to_execution_changes*:
      List[SignedBLSToExecutionChange,
        Limit MAX_BLS_TO_EXECUTION_CHANGES]
    blob_kzg_commitments*: KzgCommitments
    execution_requests*: ExecutionRequests # [New in Electra]

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#blindedbeaconblock
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody # [Modified in Deneb]

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#blindedbeaconblock
  SigVerifiedBlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: SigVerifiedBlindedBeaconBlockBody # [Modified in Deneb]

  MaybeBlindedBeaconBlock* = object
    case isBlinded*: bool
    of false:
      data*: electra.BlockContents
    of true:
      blindedData*: BlindedBeaconBlock

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#signedblindedbeaconblock
  SignedBlindedBeaconBlock* = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/deneb/builder.md#executionpayloadandblobsbundle
  ExecutionPayloadAndBlobsBundle* = object
    execution_payload*: deneb.ExecutionPayload
    blobs_bundle*: BlobsBundle

const
  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#domain-types
  DOMAIN_APPLICATION_BUILDER* = DomainType([byte 0x00, 0x00, 0x00, 0x01])

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/validator.md#constants
  EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION* = 1

  # Spec is 1 second, but mev-boost indirection can induce delay when the relay
  # itself has already consumed the entire second.
  BUILDER_PROPOSAL_DELAY_TOLERANCE* = 1500.milliseconds

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
    block_hash: to0xHex(v.body.execution_payload_header.block_hash.data),
    parent_hash: to0xHex(v.body.execution_payload_header.parent_hash.data),
    fee_recipient: to0xHex(v.body.execution_payload_header.fee_recipient.data),
    bls_to_execution_changes_len: v.body.bls_to_execution_changes.len(),
    blob_kzg_commitments_len: 0,  # Deneb compat
  )

func shortLog*(v: SignedBlindedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

template asSigVerified*(
    x: BlindedBeaconBlock): SigVerifiedBlindedBeaconBlock =
  isomorphicCast[SigVerifiedBlindedBeaconBlock](x)
