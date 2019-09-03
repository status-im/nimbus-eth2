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

suite "Official - Sanity - Blocks " & preset():
  test "Previous slot block transition":
    const testDir = SanityBlocksDir/"prev_slot_block_transition"
    var preRef, stateRef: ref BeaconState
    new preRef
    new stateRef
    preRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)
    deepCopy(stateRef, preRef)

    let blck = parseTest(testDir/"blocks_0.ssz", SSZ, BeaconBlock)

    # Check that a block build for an old slot cannot be used for state transition
    expect(AssertionError):
      # assert in process_slots. This should not be triggered
      #                          for blocks from block_pool/network
      let done = state_transition(stateRef[], blck, flags = {skipValidation})

  test "Same slot block transition":
    const testDir = SanityBlocksDir/"same_slot_block_transition"
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
