# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ".."/datatypes/[altair, bellatrix]

{.push raises: [Defect].}

type
  # https://github.com/ethereum/builder-specs/blob/v0.1.0/specs/README.md#validatorregistrationv1
  ValidatorRegistrationV1 = object
    fee_recipient*: ExecutionAddress
    gas_limit*: uint64
    timestamp*: uint64
    pubkey*: ValidatorPubKey

  # https://github.com/ethereum/builder-specs/blob/v0.0.0/specs/README.md#signedvalidatorregistrationv1
  SignedValidatorRegistrationV1* = object
    message*: ValidatorRegistrationV1
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.1.0/specs/README.md#builderbid
  BuilderBid = object
    header*: ExecutionPayloadHeader
    value*: UInt256
    pubkey*: ValidatorPubKey

  # https://github.com/ethereum/builder-specs/blob/v0.1.0/specs/README.md#signedbuilderbid
  SignedBuilderBid* = object
    message*: BuilderBid
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/v0.1.0/specs/README.md#blindedbeaconblockbody
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

  # https://github.com/ethereum/builder-specs/blob/v0.1.0/specs/README.md#blindedbeaconblock
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody

  # https://github.com/ethereum/builder-specs/blob/v0.1.0/specs/README.md#signedblindedbeaconblock
  SignedBlindedBeaconBlock* = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig

const
  # https://github.com/ethereum/builder-specs/blob/v0.0.0/specs/README.md#signing
  DOMAIN_MEV* = DomainType([byte 0x00, 0x00, 0x00, 0x01])
