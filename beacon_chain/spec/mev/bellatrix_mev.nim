# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ".."/datatypes/[altair, bellatrix]

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

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#blindedbeaconblock
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signedblindedbeaconblock
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
    eth1data: default(Eth1Data),
    graffiti: $default(GraffitiBytes),
    proposer_slashings_len: 0,
    attester_slashings_len: 0,
    attestations_len: 0,
    deposits_len: 0,
    voluntary_exits_len: 0,
    sync_committee_participants: 0,
    block_number: 0'u64,
    fee_recipient: "",
    bls_to_execution_changes_len: 0,  # Capella compat
    blob_kzg_commitments_len: 0,  # Deneb compat
  )

func shortLog*(v: SignedBlindedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )
