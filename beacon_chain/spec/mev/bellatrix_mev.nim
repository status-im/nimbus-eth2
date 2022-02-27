# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import "."/[altair, bellatrix]

{.push raises: [Defect].}

type
  # https://github.com/flashbots/mev-boost/blob/thegostep/docs/docs/milestone-1.md#blindedbeaconblockbody
  # This is forked from bellatrix.BeaconBlockBody with execution_payload
  # replaced with execution_payload_header
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

  # https://github.com/flashbots/mev-boost/blob/thegostep/docs/docs/milestone-1.md#blindedbeaconblock
  # This is forked from bellatrix.BeaconBlock with body replaced with
  # BlindedBeaconBlockBody
  BlindedBeaconBlock = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody

  # https://github.com/flashbots/mev-boost/blob/thegostep/docs/docs/milestone-1.md#signedblindedbeaconblock
  SignedBlindedBeaconBlock = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig
