# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  # Beacon chain internals
  ../beacon_chain/spec/helpers,
  ../beacon_chain/spec/datatypes/[bellatrix, capella],
  ../beacon_chain/spec/mev/[bellatrix_mev, capella_mev, deneb_mev],
  # Test utilities
  unittest2


template do_check() =
  check:
    hash_tree_root(b.message) == hash_tree_root(
      b.toSignedBlindedBeaconBlock.message)
    b.signature == b.toSignedBlindedBeaconBlock.signature

const
  nondefaultEth1Data = Eth1Data(
    deposit_root: Eth2Digest.fromHex(
      "0x55aaf2ee893f67db190d617070bd10d1583b00194fbcfda03d89baa24626f5bb"),
    deposit_count: 1,
    block_hash: Eth2Digest.fromHex(
      "0xe617d58db390a10741ab7d3de0ba9460b5df5e0772e9721fe33c0422a63b2677"))

let nondefaultValidatorSig = ValidatorSig.fromHex(
    "0xac08ca70066c6ea0525aa54dd867f82b86945818cb9305aae30f3bee13275dcf13d6d0680a47e889482ff2bb9a9f3cdb0588746f9e30c04645eda6d01bbd0ce6326ceb695294cb338ebace5b130c5b8f2e4f8efa63d63d5bb255c21a39da9c12")[]

template bellatrix_steps() =
  b.message.slot = 1.Slot
  do_check
  b.message.proposer_index = 1
  do_check
  b.message.state_root = Eth2Digest.fromHex(
    "0xb277ed302ade6685d0f0765fd0659c4b448656ab697409f2935cd9ab7189e48e")
  do_check
  b.message.parent_root = Eth2Digest.fromHex(
    "0x2f6eaa73ec39aeb864884a2371f3e4a8abc29d277074459e46c987418f5df430")
  do_check
  b.message.body.randao_reveal = nondefaultValidatorSig
  do_check
  b.message.body.eth1_data = nondefaultEth1Data
  do_check
  distinctBase(b.message.body.graffiti)[0] = 1
  do_check
  check: b.message.body.proposer_slashings.add(default(ProposerSlashing))
  do_check
  check: b.message.body.attester_slashings.add(default(AttesterSlashing))
  do_check
  check: b.message.body.attestations.add(
    Attestation(aggregation_bits: CommitteeValidatorsBits.init(1)))
  do_check
  check: b.message.body.deposits.add(default(Deposit))
  do_check
  check: b.message.body.voluntary_exits.add(default(SignedVoluntaryExit))
  do_check
  b.message.body.sync_aggregate.sync_committee_signature =
    nondefaultValidatorSig
  do_check
  b.message.body.execution_payload.parent_hash = Eth2Digest.fromHex(
    "0x941bdf6ccf731a7ede6bac0c9533ecee5e3dc5081ea59d57c3fd8c624eeca85d")
  do_check
  b.message.body.execution_payload.fee_recipient =
    ExecutionAddress.fromHex("0x1234567812345678123456781234567812345678")
  do_check
  b.message.body.execution_payload.state_root = Eth2Digest.fromHex(
    "0x9e7d9bca96a9d0af9013ad6abb8708988beef02d58c16ba1a90075960b99c2ff")
  do_check
  b.message.body.execution_payload.receipts_root = Eth2Digest.fromHex(
    "0x0e66a5007cf7bb16f4398adbbd01b34067a80faaef41a0a6be324c5fdb93a6df")
  do_check
  b.message.body.execution_payload.logs_bloom.data[0] = 2
  do_check
  b.message.body.execution_payload.prev_randao = Eth2Digest.fromHex(
    "0x8aa830156370e6a5ec7679d7e5ee712dd87f24fef76a1954a03c1df8c68bc0fd")
  do_check
  b.message.body.execution_payload.block_number = 3
  do_check
  b.message.body.execution_payload.gas_limit = 4
  do_check
  b.message.body.execution_payload.gas_used = 5
  do_check
  b.message.body.execution_payload.timestamp = 6
  do_check
  check: b.message.body.execution_payload.extra_data.add 0'u8
  do_check
  b.message.body.execution_payload.base_fee_per_gas = 7.u256
  do_check
  b.message.body.execution_payload.block_hash = Eth2Digest.fromHex(
    "0x4b1aed517ac48bfbf6ab19846923d5256897fbc934c20ca5b8c486bfe71c6ef1")
  do_check
  check: b.message.body.execution_payload.transactions.add default(Transaction)
  do_check

template capella_steps() =
  check: b.message.body.bls_to_execution_changes.add(
    default(SignedBLSToExecutionChange))
  do_check
  check: b.message.body.execution_payload.withdrawals.add(default(
    Withdrawal))
  do_check

template deneb_steps() =
  check: b.message.body.blob_kzg_commitments.add(default(KzgCommitment))
  do_check

suite "Blinded block conversions":
  test "Bellatrix toSignedBlindedBlock":
    var b = default(bellatrix.SignedBeaconBlock)
    do_check
    bellatrix_steps

  test "Capella toSignedBlindedBlock":
    var b = default(capella.SignedBeaconBlock)
    do_check
    bellatrix_steps
    capella_steps

  test "Deneb toSignedBlindedBlock":
    var b = default(deneb.SignedBeaconBlock)
    do_check
    bellatrix_steps
    capella_steps
    deneb_steps
