# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ".."/datatypes/altair
from ".."/datatypes/bellatrix import ExecutionPayloadHeader
from ".."/eth2_merkleization import hash_tree_root

type
  # https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/bellatrix/builder.md#blindedbeaconblockbody
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

  # https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/bellatrix/builder.md#blindedbeaconblock
  BlindedBeaconBlock* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BlindedBeaconBlockBody

  # https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/bellatrix/builder.md#signedblindedbeaconblock
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

func toSignedBlindedBeaconBlock*(blck: bellatrix.SignedBeaconBlock):
    SignedBlindedBeaconBlock =
  SignedBlindedBeaconBlock(
    message: BlindedBeaconBlock(
      slot: blck.message.slot,
      proposer_index: blck.message.proposer_index,
      parent_root: blck.message.parent_root,
      state_root: blck.message.state_root,
      body: BlindedBeaconBlockBody(
        randao_reveal: blck.message.body.randao_reveal,
        eth1_data: blck.message.body.eth1_data,
        graffiti: blck.message.body.graffiti,
        proposer_slashings: blck.message.body.proposer_slashings,
        attester_slashings: blck.message.body.attester_slashings,
        attestations: blck.message.body.attestations,
        deposits: blck.message.body.deposits,
        voluntary_exits: blck.message.body.voluntary_exits,
        sync_aggregate: blck.message.body.sync_aggregate,
        execution_payload_header: ExecutionPayloadHeader(
          parent_hash: blck.message.body.execution_payload.parent_hash,
          fee_recipient: blck.message.body.execution_payload.fee_recipient,
          state_root: blck.message.body.execution_payload.state_root,
          receipts_root: blck.message.body.execution_payload.receipts_root,
          logs_bloom: blck.message.body.execution_payload.logs_bloom,
          prev_randao: blck.message.body.execution_payload.prev_randao,
          block_number: blck.message.body.execution_payload.block_number,
          gas_limit: blck.message.body.execution_payload.gas_limit,
          gas_used: blck.message.body.execution_payload.gas_used,
          timestamp: blck.message.body.execution_payload.timestamp,
          extra_data: blck.message.body.execution_payload.extra_data,
          base_fee_per_gas:
            blck.message.body.execution_payload.base_fee_per_gas,
          block_hash: blck.message.body.execution_payload.block_hash,
          transactions_root:
            hash_tree_root(blck.message.body.execution_payload.transactions)))),
    signature: blck.signature)
