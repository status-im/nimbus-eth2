# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, unittest,
  # Beacon chain internals
  ../../beacon_chain/spec/[crypto, datatypes],
  ../../beacon_chain/[ssz, state_transition, extras],
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state

const SanityBlocksDir = SszTestsDir/const_preset/"phase0"/"sanity"/"blocks"/"pyspec_tests"

template runTest(identifier: string, num_blocks: int): untyped =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  const testDir = SanityBlocksDir / identifier

  proc `testImpl _ blck _ identifier`() =
    let prefix = if existsFile(testDir/"post.ssz"):                             
      "[Valid]   "
    else:              
      "[Invalid] "                                       

    timedTest prefix & identifier:
      var stateRef, postRef: ref BeaconState
      new stateRef
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)

      if existsFile(testDir/"post.ssz"):
        new postRef
        postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      for i in 0 ..< num_blocks:
        let blck = parseTest(testDir/"blocks_" & $i & ".ssz", SSZ, SignedBeaconBlock)

        if postRef.isNil:
          let success = state_transition(stateRef[], blck.message, flags = {})
          doAssert not success, "We didn't expect this invalid block to be processed"
        else:
          # TODO: The EF is using invalid BLS keys so we can't verify them
          let success = state_transition(stateRef[], blck.message, flags = {skipValidation})
          doAssert success, "Failure when applying block " & $i

          # Checks:
          # check: stateRef.hash_tree_root() == postRef.hash_tree_root()
          if i == num_blocks - 1: reportDiff(stateRef, postRef)

  `testImpl _ blck _ identifier`()

suite "Official - Sanity - Blocks " & preset():
  const expected_failures = ["attester_slashing"]
  runTest("attestation", 2)

  when false:
    # Failing due to signature checking in indexed validation checking pending
    # 0.10 BLS verification API with new domain handling.
    runTest("attester_slashing", 1)
  echo "Skipping test: attester_slashing"

  runTest("balance_driven_status_transitions", 1)
  runTest("deposit_in_block", 1)
  runTest("deposit_top_up", 1)
  runTest("empty_block_transition", 1)
  runTest("empty_epoch_transition", 1)

  when const_preset=="minimal":
    runTest("empty_epoch_transition_not_finalizing", 1)
    runTest("eth1_data_votes_consensus", 17)
    runTest("eth1_data_votes_no_consensus", 16)

  runTest("expected_deposit_in_block", 1)
  runTest("high_proposer_index", 1)
  runTest("historical_batch", 1)
  runTest("invalid_block_sig", 1)
  runTest("invalid_state_root", 1)
  runTest("prev_slot_block_transition", 1)
  runTest("proposer_after_inactive_index", 1)
  runTest("proposer_slashing", 1)
  runTest("same_slot_block_transition", 1)
  runTest("skipped_slots", 1)
  runTest("voluntary_exit", 2)
  when const_preset=="minimal":
    runTest("zero_block_sig", 1)
