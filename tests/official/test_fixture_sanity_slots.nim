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
  ../../beacon_chain/spec/datatypes,
  ../../beacon_chain/state_transition,
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state

const SanitySlotsDir = SszTestsDir/const_preset/"phase0"/"sanity"/"slots"/"pyspec_tests"

template runTest(testName: string, identifier: untyped, num_slots: uint64): untyped =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  const testDir = SanitySlotsDir / astToStr(identifier)

  proc `testImpl _ slots _ identifier`() =
    test "Slots - " & testName & " (" & astToStr(identifier) & ")":
      var stateRef, postRef: ref BeaconState
      new stateRef
      new postRef
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)
      postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      process_slots(stateRef[], stateRef.slot + num_slots)
      # check: stateRef.hash_tree_root() == postRef.hash_tree_root()
      reportDiff(stateRef, postRef)

  `testImpl _ slots _ identifier`()

# 1 slot
# ---------------------------------------------------------------

suite "Official - Sanity - Slots " & preset():
  runTest("Advance 1 slot", slots_1, 1)
  runTest("Advance 2 slots", slots_2, 2)

  when false: # TODO: issue in active_index_roots - https://github.com/status-im/nim-beacon-chain/issues/373
    runTest("Advance an empty epoch", empty_epoch, SLOTS_PER_EPOCH)

  when false: # TODO: issue in state_roots
    const DoubleEpoch = SLOTS_PER_EPOCH.uint64*2 # workaround undeclared identifier "double_empty_epoch"
    runTest("Advance 2 empty epochs", double_empty_epoch, DoubleEpoch)

    # This starts in the middle of an epoch
    runTest("Advance over an epoch boundary", over_epoch_boundary, SLOTS_PER_EPOCH)
