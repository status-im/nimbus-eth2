# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, unittest, strutils,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes],
  ../../beacon_chain/[ssz, state_transition, extras],
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state,
  ../mocking/mock_blocks

const SanityBlocksDir = SszTestsDir/const_preset/"phase0"/"sanity"/"blocks"/"pyspec_tests"

template runTestOneBlock(testName: string, identifier: untyped): untyped =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  const testDir = SanityBlocksDir / astToStr(identifier)

  proc `testImpl _ blck _ identifier`() =
    test "[Valid]   " & testName & " (" & astToStr(identifier) & ")":
      var stateRef, postRef: ref BeaconState
      new stateRef
      new postRef
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)
      postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)
      let blck = parseTest(testDir/"blocks_0.ssz", SSZ, BeaconBlock)

      # TODO: The EF is using invalid BLS keys so we can't verify them
      let done = state_transition(stateRef[], blck, flags = {skipValidation})

      # Checks:
      check:
        done
        stateRef.hash_tree_root() == postRef.hash_tree_root()
      reportDiff(stateRef, postRef)

  `testImpl _ blck _ identifier`()

suite "Official - Sanity - Blocks " & preset():
  test "[Invalid] Previous slot block transition (prev_slot_block_transition)":
    const testDir = SanityBlocksDir/"prev_slot_block_transition"
    var stateRef: ref BeaconState
    new stateRef
    stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)

    let blck = parseTest(testDir/"blocks_0.ssz", SSZ, BeaconBlock)

    # Check that a block build for an old slot cannot be used for state transition
    expect(AssertionError):
      # assert in process_slots. This should not be triggered
      #                          for blocks from block_pool/network
      let done = state_transition(stateRef[], blck, flags = {skipValidation})

  runTestOneBlock("Same slot block transition", same_slot_block_transition)
  runTestOneBlock("Empty block transition", empty_block_transition)

  when false: # TODO: we need more granular skipValidation
    test "[Invalid] Invalid state root":
      const testDir = SanityBlocksDir/"invalid_state_root"
      var stateRef: ref BeaconState
      new stateRef
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)

      let blck = parseTest(testDir/"blocks_0.ssz", SSZ, BeaconBlock)

      expect(AssertionError):
        let done = state_transition(stateRef[], blck, flags = {skipValidation})

  runTestOneBlock("Skipped Slots", skipped_slots)
  when false: # TODO: failing due to state_roots[8]
    runTestOneBlock("Empty epoch transition", empty_epoch_transition)
    runTestOneBlock("Empty epoch transition not finalizing", empty_epoch_transition_not_finalizing)
  when false: # TODO: Index out of bounds: beaconstate.nim(135) initiate_validator_exit
    runTestOneBlock("Proposer slashing", proposer_slashing)
  when false: # TODO: Assert ./beacon_chain/spec/crypto.nim(156, 12) `x.kind == Real and other.kind == Real`
    runTestOneBlock("Attester slashing", attester_slashing)

  # TODO: Expected deposit in block

  when false: # TODO: Assert ./beacon_chain/spec/crypto.nim(175, 14) `sig.kind == Real and pubkey.kind == Real`
    runTestOneBlock("Deposit in block", deposit_in_block)
  runTestOneBlock("Deposit top up", deposit_top_up)

  # TODO: attestation
  # TODO: voluntary exit

  when false: # TODO: Index out of bounds: beaconstate.nim(135) initiate_validator_exit
    runTestOneBlock("Balance-driven status transitions", balance_driven_status_transitions)

  when false: # TODO: `stateRef3946003.balances[idx3953625] == postRef3946005.balances[idx3953625]`
              #       stateRef3946003.balances[0] = 31998855136
              #       postRef3946005.balances[0] = 31997418334
    runTestOneBlock("Historical batch", historical_batch)
