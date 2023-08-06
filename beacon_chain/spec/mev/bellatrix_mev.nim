# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ".."/datatypes/[altair, bellatrix]

{.push raises: [].}

type
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest

  SignedBlindedBeaconBlock* = object
    message*: BlindedBeaconBlock
    signature*: ValidatorSig

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
