# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import ../../beacon_chain/spec/forks
import os_ops
from std/strutils import parseInt
from ./fixtures_utils import SszTestsDir, parseTest
from ../testutil import check, preset, suite, test
from ../../beacon_chain/spec/state_transition import process_slots
from ../helpers/debug_state import reportDiff

proc runTest(T: type, testDir, forkName: static[string], identifier: string) =
  let
    testDir = testDir / identifier
    num_slots = readLines(testDir / "slots.yaml", 2)[0].parseInt.uint64

  proc `testImpl _ slots _ identifier`() =
    test "EF - " & forkName & " - Slots - " & identifier & " [Preset: " & const_preset & "]":
      let
        preState = newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, T))
        postState = newClone(parseTest(testDir/"post.ssz_snappy", SSZ, T))
      var
        fhPreState = ForkedHashedBeaconState.new(preState[])
        cache = StateCache()
        info: ForkedEpochInfo

      check:
        process_slots(
          defaultRuntimeConfig,
          fhPreState[], getStateField(fhPreState[], slot) + num_slots, cache,
          info, {}).isOk()

        getStateRoot(fhPreState[]) == postState[].hash_tree_root()

      withState(fhPreState[]):
        when forkyState.data isnot typeof(postState[]):
          doAssert false, "mismatched pre/post forks"
        else:
          reportDiff(forkyState.data, postState[])

  `testImpl _ slots _ identifier`()

func sanitySlotsDir(preset_dir: string): string {.compileTime.} =
  SszTestsDir/const_preset/preset_dir/"sanity"/"slots"/"pyspec_tests"

from ../../beacon_chain/spec/datatypes/phase0 import BeaconState

suite "EF - Phase 0 - Sanity - Slots " & preset():
  const phase0SanitySlotsDir = sanitySlotsDir("phase0")
  for kind, path in walkDir(
      phase0SanitySlotsDir, relative = true, checkDir = true):
    runTest(phase0.BeaconState, phase0SanitySlotsDir, "Phase 0", path)

from ../../beacon_chain/spec/datatypes/altair import BeaconState

suite "EF - Altair - Sanity - Slots " & preset():
  const altairSanitySlotsDir = sanitySlotsDir("altair")
  for kind, path in walkDir(
      altairSanitySlotsDir, relative = true, checkDir = true):
    runTest(altair.BeaconState, altairSanitySlotsDir, "Altair", path)

from ../../beacon_chain/spec/datatypes/bellatrix import BeaconState

suite "EF - Bellatrix - Sanity - Slots " & preset():
  const bellatrixSanitySlotsDir = sanitySlotsDir("bellatrix")
  for kind, path in walkDir(
      bellatrixSanitySlotsDir, relative = true, checkDir = true):
    runTest(bellatrix.BeaconState, bellatrixSanitySlotsDir, "Bellatrix", path)

from ../../../beacon_chain/spec/datatypes/capella import BeaconState

suite "EF - Capella - Sanity - Slots " & preset():
  const capellaSanitySlotsDir = sanitySlotsDir("capella")
  for kind, path in walkDir(
      capellaSanitySlotsDir, relative = true, checkDir = true):
    runTest(capella.BeaconState, capellaSanitySlotsDir, "Capella", path)

from ../../../beacon_chain/spec/datatypes/deneb import BeaconState

suite "EF - Deneb - Sanity - Slots " & preset():
  const denebSanitySlotsDir = sanitySlotsDir("deneb")
  for kind, path in walkDir(
      denebSanitySlotsDir, relative = true, checkDir = true):
    runTest(deneb.BeaconState, denebSanitySlotsDir, "Deneb", path)
