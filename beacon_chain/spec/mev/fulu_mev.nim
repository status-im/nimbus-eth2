# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import ".."/datatypes/[altair, bellatrix, fulu]

from stew/byteutils import to0xHex
from ".."/datatypes/phase0 import AttesterSlashing
from ".."/datatypes/capella import SignedBLSToExecutionChange
from ".."/datatypes/deneb import BlobsBundle, ExecutionPayloadHeader, KzgCommitments
from ".."/datatypes/electra import
  Attestation, AttesterSlashing, ExecutionRequests
from ".."/eth2_merkleization import hash_tree_root

type
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
    blob_kzg_commitments*: KzgCommitments # [New in Deneb]
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
    blob_kzg_commitments*: KzgCommitments # [New in Deneb]
    execution_requests*: ExecutionRequests # [New in Electra]

  # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/builder.md#blindedbeaconblock
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody

  SigVerifiedBlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: SigVerifiedBlindedBeaconBlockBody

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
