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

template runTest(testDir, testName: string, procSuffix: untyped, num_slots: uint64): untyped =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  proc `testImpl _ slots _ procSuffix`() =
    let unitTestName = testDir.rsplit(DirSep, 1)[1]
    test "Slots - " & testName & " (" & unitTestName & ")" & preset():
      var stateRef, postRef: ref BeaconState
      new stateRef
      new postRef
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)
      postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      process_slots(stateRef[], stateRef.slot + num_slots)
      reportDiff(stateRef, postRef)
      # check: stateRef.hash_tree_root() == postRef.hash_tree_root()

  `testImpl _ slots _ procSuffix`()

# 1 slot
# ---------------------------------------------------------------

suite "Official - Sanity - Slots " & preset():

  const Slots1Dir = SszTestsDir/const_preset/"phase0"/"sanity"/"slots"/"pyspec_tests"/"slots_1"
  runTest(Slots1Dir, "Advance 1 slot", procSuffix = 1, num_slots = 1)

  const Slots2Dir = SszTestsDir/const_preset/"phase0"/"sanity"/"slots"/"pyspec_tests"/"slots_2"
  runTest(Slots2Dir, "Advance 2 slots", procSuffix = 2, num_slots = 2)

  when false: # TODO: issue in active_index_roots - https://github.com/status-im/nim-beacon-chain/issues/373
    const EmptyEpochDir = SszTestsDir/const_preset/"phase0"/"sanity"/"slots"/"pyspec_tests"/"empty_epoch"
    runTest(EmptyEpochDir, "Advance an empty epoch", empty_epoch, SLOTS_PER_EPOCH)

  when false: # TODO: issue in state_roots
    const DoubleEpoch = SLOTS_PER_EPOCH.uint64*2 # workaround undeclared identifier "double_empty_epoch"
    const DoubleEmptyEpochDir = SszTestsDir/const_preset/"phase0"/"sanity"/"slots"/"pyspec_tests"/"double_empty_epoch"
    runTest(DoubleEmptyEpochDir, "Advance 2 empty epochs", double_empty_epoch, DoubleEpoch)

    # This starts in the middle of an epoch
    const OverEpochBoundaryDir = SszTestsDir/const_preset/"phase0"/"sanity"/"slots"/"pyspec_tests"/"over_epoch_boundary"
    runTest(OverEpochBoundaryDir, "Advance over an epoch boundary", over_epoch_boundary, SLOTS_PER_EPOCH)
