# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/[crypto, helpers, signatures],
  ../beacon_chain/spec/datatypes/capella,
  ./testblockutil

suite "Message signatures":
  const
    epoch0 = Epoch(0)
    epoch1 = Epoch(1)
    fork0 = Fork(
      previous_version: Version [byte 0x39, 0x21, 0x8c, 0xe8],
      current_version: Version [byte 0x40, 0x21, 0x8c, 0xe8],
      epoch: epoch1,
    )
    fork1 = Fork(
      previous_version: Version [byte 0x3a, 0x4e, 0xf6, 0x1d],
      current_version: Version [byte 0x3b, 0x4e, 0xf6, 0x1d],
      epoch: epoch1,
    )
    slot0 = epoch0.start_slot()
    slot1 = epoch1.start_slot()
    # genesis_validators_root
    gvr0 = Eth2Digest.fromHex(
      "0x8fbd3b999e4873fb182569b20fb090400332849240da5ceb925db7ff7a8d984b"
    )
    gvr1 = Eth2Digest.fromHex(
      "0x78fb3f89983b990a841b98bab7951dccc73a757d2394f496e318db3c4826654e"
    )
  let
    pubkey0 = MockPubKeys[0]
    privkey0 = MockPrivKeys[0]
    pubkey1 = MockPubKeys[1]

  test "Slot signatures":
    let
      root0 = ZERO_HASH
      root1 = gvr1
      sig = get_block_signature(fork0, gvr0, slot0, root0, privkey0).toValidatorSig

    check:
      verify_block_signature(fork0, gvr0, slot0, root0, pubkey0, sig)

      not verify_block_signature(fork1, gvr0, slot0, root0, pubkey0, sig)
      not verify_block_signature(fork0, gvr1, slot0, root0, pubkey0, sig)
      not verify_block_signature(fork0, gvr0, slot1, root0, pubkey0, sig)
      not verify_block_signature(fork0, gvr0, slot0, root1, pubkey0, sig)
      not verify_block_signature(fork0, gvr0, slot0, root0, pubkey1, sig)

  test "Aggregate and proof signatures":
    let
      proof0 = phase0.AggregateAndProof(
        aggregate: phase0.Attestation(aggregation_bits: CommitteeValidatorsBits.init(8))
      )
      proof1 = phase0.AggregateAndProof(
        aggregate: phase0.Attestation(aggregation_bits: CommitteeValidatorsBits.init(7))
      )
      sig =
        get_aggregate_and_proof_signature(fork0, gvr0, proof0, privkey0).toValidatorSig

    check:
      verify_aggregate_and_proof_signature(fork0, gvr0, proof0, pubkey0, sig)

      not verify_aggregate_and_proof_signature(fork1, gvr0, proof0, pubkey0, sig)
      not verify_aggregate_and_proof_signature(fork0, gvr1, proof0, pubkey0, sig)
      not verify_aggregate_and_proof_signature(fork0, gvr0, proof1, pubkey0, sig)
      not verify_aggregate_and_proof_signature(fork0, gvr0, proof0, pubkey1, sig)

  test "Attestation signatures":
    let
      data0 = default(AttestationData)
      data1 = (var t = data0; t.index = t.index + 1; t)
      sig = get_attestation_signature(fork0, gvr0, data0, privkey0).toValidatorSig

    check:
      verify_attestation_signature(fork0, gvr0, data0, [pubkey0], sig)

      not verify_attestation_signature(fork1, gvr0, data0, [pubkey0], sig)
      not verify_attestation_signature(fork0, gvr1, data0, [pubkey0], sig)
      not verify_attestation_signature(fork0, gvr0, data1, [pubkey0], sig)
      not verify_attestation_signature(fork0, gvr0, data0, [pubkey1], sig)

  test "Deposit signatures":
    let
      version0 = fork0.current_version
      version1 = fork1.current_version
      sig = get_deposit_signature(version0, DepositData(pubkey: pubkey0), privkey0).toValidatorSig

    check:
      verify_deposit_signature(version0, DepositData(pubkey: pubkey0, signature: sig))

      not verify_deposit_signature(
        version1, DepositData(pubkey: pubkey0, signature: sig)
      )
      not verify_deposit_signature(
        version0, DepositData(pubkey: pubkey1, signature: sig)
      )

  test "Voluntary exit signatures":
    let
      voluntaryExit = default(VoluntaryExit)
      voluntaryExit2 = (var v = voluntaryExit; v.epoch = v.epoch + 1; v)
      sig = get_voluntary_exit_signature(fork0, gvr0, voluntaryExit, privkey0).toValidatorSig

    check:
      verify_voluntary_exit_signature(fork0, gvr0, voluntaryExit, pubkey0, sig)

      not verify_voluntary_exit_signature(fork1, gvr0, voluntaryExit, pubkey0, sig)
      not verify_voluntary_exit_signature(fork0, gvr1, voluntaryExit, pubkey0, sig)
      not verify_voluntary_exit_signature(fork0, gvr0, voluntaryExit2, pubkey0, sig)
      not verify_voluntary_exit_signature(fork0, gvr0, voluntaryExit, pubkey1, sig)

  test "Sync committee message signatures":
    let
      root0 = ZERO_HASH
      root1 = gvr1
      sig = get_sync_committee_message_signature(fork0, gvr0, slot0, root0, privkey0)
        .toValidatorSig()

    check:
      verify_sync_committee_message_signature(fork0, gvr0, slot0, root0, pubkey0, sig)

      not verify_sync_committee_message_signature(
        fork1, gvr0, slot0, root0, pubkey0, sig
      )
      not verify_sync_committee_message_signature(
        fork0, gvr1, slot0, root0, pubkey0, sig
      )
      not verify_sync_committee_message_signature(
        fork0, gvr0, slot1, root0, pubkey0, sig
      )
      not verify_sync_committee_message_signature(
        fork0, gvr0, slot0, root1, pubkey0, sig
      )
      not verify_sync_committee_message_signature(
        fork0, gvr0, slot0, root0, pubkey1, sig
      )

  test "Sync committee signed contribution and proof signatures":
    let
      proof0 = default(ContributionAndProof)
      proof1 = (var c = proof0; c.aggregator_index = c.aggregator_index + 1; c)
      sig = get_contribution_and_proof_signature(fork0, gvr0, proof0, privkey0).toValidatorSig

    check:
      verify_contribution_and_proof_signature(fork0, gvr0, proof0, pubkey0, sig)

      not verify_contribution_and_proof_signature(fork1, gvr0, proof0, pubkey0, sig)
      not verify_contribution_and_proof_signature(fork0, gvr1, proof0, pubkey0, sig)
      not verify_contribution_and_proof_signature(fork0, gvr0, proof1, pubkey0, sig)
      not verify_contribution_and_proof_signature(fork0, gvr0, proof0, pubkey1, sig)

  test "Sync committee selection proof signatures":
    let
      index0 = SyncSubcommitteeIndex(0)
      index1 = SyncSubcommitteeIndex(1)
      sig = get_sync_committee_selection_proof(fork0, gvr0, slot0, index0, privkey0).toValidatorSig

    check:
      verify_sync_committee_selection_proof(fork0, gvr0, slot0, index0, pubkey0, sig)

      not verify_sync_committee_selection_proof(
        fork1, gvr0, slot0, index0, pubkey0, sig
      )
      not verify_sync_committee_selection_proof(
        fork0, gvr1, slot0, index0, pubkey0, sig
      )
      not verify_sync_committee_selection_proof(
        fork0, gvr0, slot1, index0, pubkey0, sig
      )
      not verify_sync_committee_selection_proof(
        fork0, gvr0, slot0, index1, pubkey0, sig
      )
      not verify_sync_committee_selection_proof(
        fork0, gvr0, slot0, index0, pubkey1, sig
      )

  test "execution payload bid signatures":
    let
      msg0 = default(gloas.ExecutionPayloadBid)
      msg1 = (var v = msg0; v.slot = v.slot + 1; v)
      epoch0 = Epoch(0)
      sig = get_execution_payload_bid_signature(fork0, gvr0, epoch0, msg0, privkey0).toValidatorSig

    check:
      verify_execution_payload_bid_signature(fork0, gvr0, epoch0, msg0, pubkey0, sig)

      not verify_execution_payload_bid_signature(
        fork1, gvr0, epoch0, msg0, pubkey0, sig
      )
      not verify_execution_payload_bid_signature(
        fork0, gvr1, epoch0, msg0, pubkey0, sig
      )
      not verify_execution_payload_bid_signature(
        fork0, gvr0, epoch0, msg1, pubkey0, sig
      )
      not verify_execution_payload_bid_signature(
        fork0, gvr0, epoch0, msg0, pubkey1, sig
      )

  test "execution payload envelope signatures":
    let
      msg0 = default(ExecutionPayloadEnvelope)
      msg1 = (var v = msg0; v.slot = v.slot + 1; v)
      epoch0 = default(Epoch)
      epoch1 = epoch0 + 1
      sig = get_execution_payload_envelope_signature(
        fork0, gvr0, epoch0, msg0, privkey0
      ).toValidatorSig

    check:
      verify_execution_payload_envelope_signature(
        fork0, gvr0, epoch0, msg0, pubkey0, sig
      )

      not verify_execution_payload_envelope_signature(
        fork1, gvr0, epoch0, msg0, pubkey0, sig
      )
      not verify_execution_payload_envelope_signature(
        fork0, gvr1, epoch0, msg0, pubkey0, sig
      )
      not verify_execution_payload_envelope_signature(
        fork0, gvr0, epoch1, msg0, pubkey0, sig
      )
      not verify_execution_payload_envelope_signature(
        fork0, gvr0, epoch0, msg1, pubkey0, sig
      )
      not verify_execution_payload_envelope_signature(
        fork0, gvr0, epoch0, msg0, pubkey1, sig
      )

  test "payload attestation message signatures":
    let
      data0 = default(PayloadAttestationData)
      data1 = (var d = data0; d.slot = d.slot + 1; d)
      sig = get_payload_attestation_message_signature(fork0, gvr0, data0, privkey0).toValidatorSig

    check:
      verify_payload_attestation_message_signature(fork0, gvr0, data0, pubkey0, sig)

      not verify_payload_attestation_message_signature(fork1, gvr0, data0, pubkey0, sig)
      not verify_payload_attestation_message_signature(fork0, gvr1, data0, pubkey0, sig)
      not verify_payload_attestation_message_signature(fork0, gvr0, data1, pubkey0, sig)
      not verify_payload_attestation_message_signature(fork0, gvr0, data0, pubkey1, sig)

  test "inclusion list signatures":
    let
      msg0 = default(InclusionList)
      msg1 = (var m = msg0; m.validator_index = 1; m)
      sig = get_inclusion_list_signature(fork0, gvr0, msg0, privkey0).toValidatorSig

    check:
      verify_inclusion_list_signature(fork0, gvr0, msg0, pubkey0, sig)

      not verify_inclusion_list_signature(fork1, gvr0, msg0, pubkey0, sig)
      not verify_inclusion_list_signature(fork0, gvr1, msg0, pubkey0, sig)
      not verify_inclusion_list_signature(fork0, gvr0, msg1, pubkey0, sig)
      not verify_inclusion_list_signature(fork0, gvr0, msg0, pubkey1, sig)

  test "BLS to execution change signatures":
    let
      change0 = default(SignedBLSToExecutionChange)
      change1 = (var v = change0; v.message.validator_index = 1; v)
      version0 = fork0.current_version
      version1 = fork1.current_version
      sig = get_bls_to_execution_change_signature(
        version0, gvr0, change0.message, privkey0
      ).toValidatorSig

    check:
      verify_bls_to_execution_change_signature(version0, gvr0, change0, pubkey0, sig)

      not verify_bls_to_execution_change_signature(
        version1, gvr0, change0, pubkey0, sig
      )
      not verify_bls_to_execution_change_signature(
        version0, gvr1, change0, pubkey0, sig
      )
      not verify_bls_to_execution_change_signature(
        version0, gvr0, change1, pubkey0, sig
      )
      not verify_bls_to_execution_change_signature(
        version0, gvr0, change0, pubkey1, sig
      )

  test "Builder signatures (ValidatorRegistrationV1)":
    let
      reg0 = default(ValidatorRegistrationV1)
      reg1 = (var v = reg0; v.gas_limit = v.gas_limit + 1; v)
      version0 = fork0.current_version
      version1 = fork1.current_version
      sig = get_builder_signature(version0, reg0, privkey0).toValidatorSig

    check:
      verify_builder_signature(version0, reg0, pubkey0, sig)

      not verify_builder_signature(version1, reg0, pubkey0, sig)
      not verify_builder_signature(version0, reg1, pubkey0, sig)
      not verify_builder_signature(version0, reg0, pubkey1, sig)

    test "proposer preferences message signatures":
      let
        data0 = default(ProposerPreferences)
        data1 = (var d = data0; d.proposal_slot = d.proposal_slot + 1; d)
        sig = get_proposer_preferences_signature(fork0, gvr0, data0, privkey0).toValidatorSig

      check:
        verify_proposer_preferences_signature(fork0, gvr0, data0, pubkey0, sig)

        not verify_proposer_preferences_signature(fork1, gvr0, data0, pubkey0, sig)
        not verify_proposer_preferences_signature(fork0, gvr1, data0, pubkey0, sig)
        not verify_proposer_preferences_signature(fork0, gvr0, data1, pubkey0, sig)
        not verify_proposer_preferences_signature(fork0, gvr0, data0, pubkey1, sig)
