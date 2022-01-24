# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, strutils,
  # Beacon chain internals
  ../../../beacon_chain/spec/[forks, state_transition],
  ../../../beacon_chain/spec/datatypes/bellatrix,
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ../../helpers/debug_state

const SanitySlotsDir = SszTestsDir/const_preset/"bellatrix"/"sanity"/"slots"/"pyspec_tests"

proc runTest(identifier: string) =
  let
    testDir = SanitySlotsDir / identifier
    num_slots = readLines(testDir / "slots.yaml", 2)[0].parseInt.uint64

  proc `testImpl _ slots _ identifier`() =
    test "Slots - " & identifier:
      var
        preState = newClone(parseTest(
          testDir/"pre.ssz_snappy", SSZ, bellatrix.BeaconState))
        fhPreState = (ref ForkedHashedBeaconState)(
          bellatrixData: bellatrix.HashedBeaconState(
            data: preState[], root: hash_tree_root(preState[])),
          kind: BeaconStateFork.Bellatrix)
        cache = StateCache()
        info = ForkedEpochInfo()
      let postState = newClone(parseTest(
        testDir/"post.ssz_snappy", SSZ, bellatrix.BeaconState))

      check:
        process_slots(
          defaultRuntimeConfig, fhPreState[],
          getStateField(fhPreState[], slot) + num_slots, cache, info, {}).isOk()

        getStateRoot(fhPreState[]) == postState[].hash_tree_root()
      let newPreState = newClone(fhPreState.bellatrixData.data)
      reportDiff(newPreState, postState)

  `testImpl _ slots _ identifier`()

suite "EF - Bellatrix - Sanity - Slots " & preset():
  for kind, path in walkDir(SanitySlotsDir, relative = true, checkDir = true):
    runTest(path)
