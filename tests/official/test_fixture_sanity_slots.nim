# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, strutils, unittest,
  # Beacon chain internals
  ../../beacon_chain/spec/datatypes,
  ../../beacon_chain/state_transition,
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state

const SanitySlotsDir = SszTestsDir/const_preset/"phase0"/"sanity"/"slots"/"pyspec_tests"

proc runTest(identifier: string) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402
  let
    testDir = SanitySlotsDir / identifier
    num_slots = readLines(testDir / "slots.yaml", 2)[0].parseInt.uint64

  proc `testImpl _ slots _ identifier`() =
    timedTest "Slots - " & identifier:
      var stateRef, postRef: ref BeaconState
      new stateRef
      new postRef
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)
      postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      process_slots(stateRef[], stateRef.slot + num_slots)
      # check: stateRef.hash_tree_root() == postRef.hash_tree_root()

      reportDiff(stateRef, postRef)

  `testImpl _ slots _ identifier`()

suite "Official - Sanity - Slots " & preset():
  for kind, path in walkDir(SanitySlotsDir, true):
    runTest(path)
