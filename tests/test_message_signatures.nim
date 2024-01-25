# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/random,
  unittest2,
  ../beacon_chain/spec/[crypto, helpers, signatures],
  ./testblockutil

suite "Message signatures":
  var rnd = initRand(123)
  let
    fork0 = Fork(current_version: Version [byte 0x40, 0x21, 0x8c, 0xe8])
    fork1 = Fork(current_version: Version [byte 0x3b, 0x4e, 0xf6, 0x1d])
    genesis_validators_root0 = Eth2Digest.fromHex(
      "0x8fbd3b999e4873fb182569b20fb090400332849240da5ceb925db7ff7a8d984b")
    genesis_validators_root1 = Eth2Digest.fromHex(
      "0x78fb3f89983b990a841b98bab7951dccc73a757d2394f496e318db3c4826654e")
    index0 = cast[ValidatorIndex](rnd.next)
    index1 = cast[ValidatorIndex](rnd.next)
    pubkey0 = MockPubKeys[index0]
    privkey0 = MockPrivKeys[index0]
    privkey1 = MockPrivKeys[index1]

  test "Slot signatures":
    let
      slot = default(Slot)
      root = default(Eth2Digest)

    check:
      # Matching public/private keys and genesis validator roots
      verify_block_signature(
        fork0, genesis_validators_root0, slot, root, pubkey0,
        get_block_signature(
          fork0, genesis_validators_root0, slot, root, privkey0).toValidatorSig)

      # Mismatched public/private keys
      not verify_block_signature(
        fork0, genesis_validators_root0, slot, root, pubkey0,
        get_block_signature(
          fork0, genesis_validators_root0, slot, root, privkey1).toValidatorSig)

      # Mismatched forks
      not verify_block_signature(
        fork0, genesis_validators_root0, slot, root, pubkey0,
        get_block_signature(
          fork1, genesis_validators_root0, slot, root, privkey0).toValidatorSig)

      # Mismatched genesis validator roots
      not verify_block_signature(
        fork0, genesis_validators_root0, slot, root, pubkey0,
        get_block_signature(
          fork0, genesis_validators_root1, slot, root, privkey0).toValidatorSig)

  test "Aggregate and proof signatures":
    let aggregate_and_proof = AggregateAndProof(
      aggregate: Attestation(aggregation_bits: CommitteeValidatorsBits.init(8)))

    check:
      # Matching public/private keys and genesis validator roots
      verify_aggregate_and_proof_signature(
        fork0, genesis_validators_root0, aggregate_and_proof, pubkey0,
        get_aggregate_and_proof_signature(
          fork0, genesis_validators_root0, aggregate_and_proof,
          privkey0).toValidatorSig)

      # Mismatched public/private keys
      not verify_aggregate_and_proof_signature(
        fork0, genesis_validators_root0, aggregate_and_proof, pubkey0,
        get_aggregate_and_proof_signature(
          fork0, genesis_validators_root0, aggregate_and_proof,
          privkey1).toValidatorSig)

      # Mismatched forks
      not verify_aggregate_and_proof_signature(
        fork0, genesis_validators_root0, aggregate_and_proof, pubkey0,
        get_aggregate_and_proof_signature(
          fork1, genesis_validators_root0, aggregate_and_proof,
          privkey0).toValidatorSig)

      # Mismatched genesis validator roots
      not verify_aggregate_and_proof_signature(
        fork0, genesis_validators_root0, aggregate_and_proof, pubkey0,
        get_aggregate_and_proof_signature(
          fork0, genesis_validators_root1, aggregate_and_proof,
          privkey0).toValidatorSig)

  test "Attestation signatures":
    let attestation_data = default(AttestationData)

    check:
      # Matching public/private keys and genesis validator roots
      verify_attestation_signature(
        fork0, genesis_validators_root0, attestation_data, [pubkey0],
        get_attestation_signature(
          fork0, genesis_validators_root0, attestation_data,
          privkey0).toValidatorSig)

      # Mismatched public/private keys
      not verify_attestation_signature(
        fork0, genesis_validators_root0, attestation_data, [pubkey0],
        get_attestation_signature(
          fork0, genesis_validators_root0, attestation_data,
          privkey1).toValidatorSig)

      # Mismatched forks
      not verify_attestation_signature(
        fork0, genesis_validators_root0, attestation_data, [pubkey0],
        get_attestation_signature(
          fork1, genesis_validators_root0, attestation_data,
          privkey0).toValidatorSig)

      # Mismatched genesis validator roots
      not verify_attestation_signature(
        fork0, genesis_validators_root0, attestation_data, [pubkey0],
        get_attestation_signature(
          fork0, genesis_validators_root1, attestation_data,
          privkey0).toValidatorSig)

  test "Deposit signatures":
    let preset = default(RuntimeConfig)

    check:
      # Matching public/private keys and genesis validator roots
      verify_deposit_signature(
        preset, DepositData(
          pubkey: pubkey0,
          signature: get_deposit_signature(
            preset, DepositData(pubkey: pubkey0), privkey0).toValidatorSig))

      # Mismatched public/private keys
      not verify_deposit_signature(
        preset, DepositData(
          pubkey: pubkey0,
          signature: get_deposit_signature(
            preset, DepositData(pubkey: pubkey0), privkey1).toValidatorSig))

  test "Voluntary exit signatures":
    let voluntary_exit = default(VoluntaryExit)

    check:
      # Matching public/private keys and genesis validator roots
      verify_voluntary_exit_signature(
        fork0, genesis_validators_root0, voluntary_exit, pubkey0,
        get_voluntary_exit_signature(
          fork0, genesis_validators_root0, voluntary_exit,
          privkey0).toValidatorSig)

      # Mismatched public/private keys
      not verify_voluntary_exit_signature(
        fork0, genesis_validators_root0, voluntary_exit, pubkey0,
        get_voluntary_exit_signature(
          fork0, genesis_validators_root0, voluntary_exit,
          privkey1).toValidatorSig)

      # Mismatched forks
      not verify_voluntary_exit_signature(
        fork0, genesis_validators_root0, voluntary_exit, pubkey0,
        get_voluntary_exit_signature(
          fork1, genesis_validators_root0, voluntary_exit,
          privkey0).toValidatorSig)

      # Mismatched genesis validator roots
      not verify_voluntary_exit_signature(
        fork0, genesis_validators_root0, voluntary_exit, pubkey0,
        get_voluntary_exit_signature(
          fork0, genesis_validators_root1, voluntary_exit,
          privkey0).toValidatorSig)

  test "Sync committee message signatures":
    let
      slot = default(Slot)
      epoch = slot.epoch
      block_root = default(Eth2Digest)

    check:
      # Matching public/private keys and genesis validator roots
      verify_sync_committee_message_signature(
        fork0, genesis_validators_root0, slot, block_root, load(pubkey0).get,
        get_sync_committee_message_signature(
          fork0, genesis_validators_root0, slot, block_root, privkey0).toValidatorSig())

      # Mismatched public/private keys
      not verify_sync_committee_message_signature(
        fork0, genesis_validators_root0, slot, block_root, load(pubkey0).get,
        get_sync_committee_message_signature(
          fork0, genesis_validators_root0, slot, block_root, privkey1).toValidatorSig())
      # Mismatched forks
      not verify_sync_committee_message_signature(
        fork0, genesis_validators_root0, slot, block_root, load(pubkey0).get,
        get_sync_committee_message_signature(
          fork1, genesis_validators_root0, slot, block_root, privkey0).toValidatorSig())

      # Mismatched genesis validator roots
      not verify_sync_committee_message_signature(
        fork0, genesis_validators_root0, slot, block_root, load(pubkey0).get,
        get_sync_committee_message_signature(
          fork0, genesis_validators_root1, slot, block_root, privkey0).toValidatorSig())

  test "Sync committee signed contribution and proof signatures":
    let contribution_and_proof = default(ContributionAndProof)

    check:
      # Matching public/private keys and genesis validator roots
      verify_contribution_and_proof_signature(
        fork0, genesis_validators_root0, contribution_and_proof,
        load(pubkey0).get,
        get_contribution_and_proof_signature(
          fork0, genesis_validators_root0,
          contribution_and_proof, privkey0).toValidatorSig)

      # Mismatched public/private keys
      not verify_contribution_and_proof_signature(
        fork0, genesis_validators_root0, contribution_and_proof,
        load(pubkey0).get,
        get_contribution_and_proof_signature(
          fork0, genesis_validators_root0,
          contribution_and_proof, privkey1).toValidatorSig)

      # Mismatched forks
      not verify_contribution_and_proof_signature(
        fork0, genesis_validators_root0, contribution_and_proof,
        load(pubkey0).get,
        get_contribution_and_proof_signature(
          fork1, genesis_validators_root0,
          contribution_and_proof, privkey0).toValidatorSig)

      # Mismatched genesis validator roots
      not verify_contribution_and_proof_signature(
        fork0, genesis_validators_root0, contribution_and_proof,
        load(pubkey0).get,
        get_contribution_and_proof_signature(
          fork0, genesis_validators_root1,
          contribution_and_proof, privkey0).toValidatorSig)

  test "Sync committee selection proof signatures":
    let
      slot = default(Slot)
      subcommittee_index = default(SyncSubcommitteeIndex)

    check:
      # Matching public/private keys and genesis validator roots
      verify_sync_committee_selection_proof(
        fork0, genesis_validators_root0, slot, subcommittee_index,
        load(pubkey0).get, get_sync_committee_selection_proof(
          fork0, genesis_validators_root0, slot,
          subcommittee_index, privkey0).toValidatorSig)

      # Mismatched public/private keys
      not verify_sync_committee_selection_proof(
        fork0, genesis_validators_root0, slot, subcommittee_index,
        load(pubkey0).get, get_sync_committee_selection_proof(
          fork0, genesis_validators_root0, slot,
          subcommittee_index, privkey1).toValidatorSig)

      # Mismatched forks
      not verify_sync_committee_selection_proof(
        fork0, genesis_validators_root0, slot, subcommittee_index,
        load(pubkey0).get, get_sync_committee_selection_proof(
          fork1, genesis_validators_root0, slot,
          subcommittee_index, privkey0).toValidatorSig)

      # Mismatched genesis validator roots
      not verify_sync_committee_selection_proof(
        fork0, genesis_validators_root0, slot, subcommittee_index,
        load(pubkey0).get, get_sync_committee_selection_proof(
          fork0, genesis_validators_root1, slot,
          subcommittee_index, privkey0).toValidatorSig)
