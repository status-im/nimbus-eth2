# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ".."/datatypes/[altair, capella]
from stew/byteutils import to0xHex

from ../datatypes/bellatrix import ExecutionAddress

type
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#validatorregistrationv1
  ValidatorRegistrationV1* = object
    fee_recipient*: ExecutionAddress
    gas_limit*: uint64
    timestamp*: uint64
    pubkey*: ValidatorPubKey

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signedvalidatorregistrationv1
  SignedValidatorRegistrationV1* = object
    message*: ValidatorRegistrationV1
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#builderbid
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/capella/builder.md#executionpayloadheader
  BuilderBid* = object
    header*: capella.ExecutionPayloadHeader # [Modified in Capella]
    value*: UInt256
    pubkey*: ValidatorPubKey

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signedbuilderbid
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/capella/builder.md#executionpayloadheader
  SignedBuilderBid* = object
    message*: BuilderBid # [Modified in Capella]
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/capella/builder.md#blindedbeaconblockbody
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
      capella.ExecutionPayloadHeader # [Modified in Capella]
    bls_to_execution_changes*:
      List[SignedBLSToExecutionChange,
        Limit MAX_BLS_TO_EXECUTION_CHANGES]  # [New in Capella]

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#blindedbeaconblock
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/capella/builder.md#blindedbeaconblockbody
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody # [Modified in Capella]

  MaybeBlindedBeaconBlock* = object
    case isBlinded*: bool
    of false:
      data*: capella.BeaconBlock
    of true:
      blindedData*: BlindedBeaconBlock

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signedblindedbeaconblock
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/capella/builder.md#blindedbeaconblockbody
  SignedBlindedBeaconBlock* = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig

const
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#domain-types
  DOMAIN_APPLICATION_BUILDER* = DomainType([byte 0x00, 0x00, 0x00, 0x01])

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#constants
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
