# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ".."/datatypes/[altair, bellatrix]

{.push raises: [Defect].}

type
  # https://github.com/lightclient/builder-specs/blob/198f9e15c3764b7c3b0fbd9ec8bef3391ceeab61/specs/README.md#validatorregistrationv1
  ValidatorRegistrationV1 = object
    feeRecipient*: ExecutionAddress
    gasLimit*: uint64
    timestamp*: uint64
    pubkey*: ValidatorPubKey

  # https://github.com/lightclient/builder-specs/blob/198f9e15c3764b7c3b0fbd9ec8bef3391ceeab61/specs/README.md#builderbidv1
  BuilderBidV1 = object
    header*: ExecutionPayloadHeader
    value*: Eth2Digest   # uint256
    pubkey*: ValidatorPubKey

  # https://github.com/lightclient/builder-specs/blob/198f9e15c3764b7c3b0fbd9ec8bef3391ceeab61/specs/README.md#blindedbeaconblock
  BlindedBeaconBlock = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody

  # https://github.com/lightclient/builder-specs/blob/198f9e15c3764b7c3b0fbd9ec8bef3391ceeab61/specs/README.md#blindedbeaconblockbody
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

  # TODO current spec PR doesn't have this yet
  # https://github.com/flashbots/mev-boost/blob/thegostep/docs/docs/milestone-1.md#signedblindedbeaconblock
  SignedBlindedBeaconBlock = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig
