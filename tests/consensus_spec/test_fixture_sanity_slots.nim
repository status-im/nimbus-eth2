# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import ../../beacon_chain/spec/forks
import os_ops
from std/strutils import parseBiggestInt
from ./fixtures_utils import SszTestsDir, parseTest
from ../testutil import check, preset, suite, test
from ../../beacon_chain/spec/state_transition import process_slots
from ../helpers/debug_state import reportDiff

proc runTest(
    T: type,
    testDir, forkName: static[string],
    suiteName, identifier: string) {.raises: [IOError, ValueError].} =
  let
    testDir = testDir / identifier
    num_slots = readLines(testDir / "slots.yaml", 2)[0].parseBiggestInt.uint64

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
        fhPreState[], fhPreState[].slot + num_slots, cache,
        info, {}).isOk()

      fhPreState[].root == postState[].hash_tree_root()

    withState(fhPreState[]):
      when forkyState.data isnot typeof(postState[]):
        doAssert false, "mismatched pre/post forks"
      else:
        reportDiff(forkyState.data, postState[])

func sanitySlotsDir(preset_dir: string): string {.compileTime.} =
  SszTestsDir/const_preset/preset_dir/"sanity"/"slots"/"pyspec_tests"

from ../../beacon_chain/spec/datatypes/phase0 import BeaconState

suite "EF - Phase 0 - Sanity - Slots " & preset():
  const sanitySlotsDir = sanitySlotsDir("phase0")
  for kind, path in walkDir(
      sanitySlotsDir, relative = true, checkDir = true):
    runTest(phase0.BeaconState, sanitySlotsDir, "Phase 0", suiteName, path)

from ../../beacon_chain/spec/datatypes/altair import BeaconState

suite "EF - Altair - Sanity - Slots " & preset():
  const sanitySlotsDir = sanitySlotsDir("altair")
  for kind, path in walkDir(
      sanitySlotsDir, relative = true, checkDir = true):
    runTest(altair.BeaconState, sanitySlotsDir, "Altair", suiteName, path)

from ../../beacon_chain/spec/datatypes/bellatrix import BeaconState

suite "EF - Bellatrix - Sanity - Slots " & preset():
  const sanitySlotsDir = sanitySlotsDir("bellatrix")
  for kind, path in walkDir(
      sanitySlotsDir, relative = true, checkDir = true):
    runTest(bellatrix.BeaconState, sanitySlotsDir, "Bellatrix", suiteName, path)

from ../../beacon_chain/spec/datatypes/capella import BeaconState

suite "EF - Capella - Sanity - Slots " & preset():
  const sanitySlotsDir = sanitySlotsDir("capella")
  for kind, path in walkDir(
      sanitySlotsDir, relative = true, checkDir = true):
    runTest(capella.BeaconState, sanitySlotsDir, "Capella", suiteName, path)

from ../../beacon_chain/spec/datatypes/deneb import BeaconState

suite "EF - Deneb - Sanity - Slots " & preset():
  const sanitySlotsDir = sanitySlotsDir("deneb")
  for kind, path in walkDir(
      sanitySlotsDir, relative = true, checkDir = true):
    runTest(deneb.BeaconState, sanitySlotsDir, "Deneb", suiteName, path)

from ../../beacon_chain/spec/datatypes/electra import BeaconState

suite "EF - Electra - Sanity - Slots " & preset():
  const sanitySlotsDir = sanitySlotsDir("electra")
  for kind, path in walkDir(
      sanitySlotsDir, relative = true, checkDir = true):
    runTest(
      electra.BeaconState, sanitySlotsDir, "Electra", suiteName, path)

from ../../beacon_chain/spec/datatypes/fulu import BeaconState

suite "EF - Fulu - Sanity - Slots " & preset():
  const sanitySlotsDir = sanitySlotsDir("fulu")
  for kind, path in walkDir(
      sanitySlotsDir, relative = true, checkDir = true):
    runTest(
      fulu.BeaconState, sanitySlotsDir, "Fulu", suiteName, path)

from ../../beacon_chain/spec/datatypes/gloas import BeaconState

suite "EF - Gloas - Sanity - Slots " & preset():
  const sanitySlotsDir = sanitySlotsDir("gloas")
  for kind, path in walkDir(
      sanitySlotsDir, relative = true, checkDir = true):
    runTest(
      gloas.BeaconState, sanitySlotsDir, "Gloas", suiteName, path)

from ../../beacon_chain/spec/datatypes/heze import BeaconState

suite "EF - Heze - Sanity - Slots " & preset():
  const sanitySlotsDir = sanitySlotsDir("heze")
  for kind, path in walkDir(
      sanitySlotsDir, relative = true, checkDir = true):
    runTest(
      heze.BeaconState, sanitySlotsDir, "Heze", suiteName, path)
