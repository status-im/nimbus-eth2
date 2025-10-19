# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import ".."/datatypes/altair
from ".."/datatypes/phase0 import Attestation, AttesterSlashing
from ".."/datatypes/bellatrix import ExecutionPayloadHeader
from ".."/eth2_merkleization import hash_tree_root

type
  # https://github.com/ethereum/builder-specs/blob/v0.6.0/specs/bellatrix/builder.md#blindedbeaconblockbody
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
    execution_payload_header*: bellatrix.ExecutionPayloadHeader

  # https://github.com/ethereum/builder-specs/blob/v0.6.0/specs/bellatrix/builder.md#blindedbeaconblock
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody

  # https://github.com/ethereum/builder-specs/blob/v0.6.0/specs/bellatrix/builder.md#signedblindedbeaconblock
  SignedBlindedBeaconBlock* = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig

func shortLog*(v: BlindedBeaconBlock): auto =
  (
    slot: 0'u64,
    proposer_index: 0'u64,
    parent_root: "",
    state_root: "",
    eth1data: default(Eth1Data),
    graffiti: "",
    proposer_slashings_len: 0,
    attester_slashings_len: 0,
    attestations_len: 0,
    deposits_len: 0,
    voluntary_exits_len: 0,
    sync_committee_participants: 0,
    block_number: 0'u64,
    block_hash: "",
    parent_hash: "",
    fee_recipient: "",
    bls_to_execution_changes_len: 0,  # Capella compat
    blob_kzg_commitments_len: 0,  # Deneb compat
  )

func shortLog*(v: SignedBlindedBeaconBlock): auto =
  (
    blck: shortLog(default(BlindedBeaconBlock)),
    signature: ""
  )
