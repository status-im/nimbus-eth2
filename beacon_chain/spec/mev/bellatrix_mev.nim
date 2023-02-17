# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ".."/datatypes/[altair, bellatrix]
from stew/byteutils import to0xHex

{.push raises: [].}

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
  BuilderBid* = object
    header*: ExecutionPayloadHeader
    value*: UInt256
    pubkey*: ValidatorPubKey

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signedbuilderbid
  SignedBuilderBid* = object
    message*: BuilderBid
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#blindedbeaconblockbody
  BlindedBeaconBlockBody = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    sync_aggregate*: SyncAggregate
    execution_payload_header*: ExecutionPayloadHeader

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#blindedbeaconblock
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signedblindedbeaconblock
  SignedBlindedBeaconBlock* = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig

const
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#domain-types
  DOMAIN_APPLICATION_BUILDER* = DomainType([byte 0x00, 0x00, 0x00, 0x01])

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#constants
  EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION* = 1
  BUILDER_PROPOSAL_DELAY_TOLERANCE* = 1.seconds

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
  )

func shortLog*(v: SignedBlindedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )
