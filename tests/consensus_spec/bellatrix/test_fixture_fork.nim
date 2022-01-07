# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os,
  # Beacon chain internals
  ../../../beacon_chain/spec/[beaconstate, helpers],
  ../../../beacon_chain/spec/datatypes/[altair, bellatrix],
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ../../helpers/debug_state

const OpForkDir = SszTestsDir/const_preset/"bellatrix"/"fork"/"fork"/"pyspec_tests"

proc runTest(identifier: string) =
  let testDir = OpForkDir / identifier

  proc `testImpl _ fork _ identifier`() =
    test identifier:
      let
        preState = newClone(
          parseTest(testDir/"pre.ssz_snappy", SSZ, altair.BeaconState))
        postState = newClone(
          parseTest(testDir/"post.ssz_snappy", SSZ, bellatrix.BeaconState))

      var cfg = defaultRuntimeConfig

      let upgradedState = upgrade_to_merge(cfg, preState[])
      check: upgradedState[].hash_tree_root() == postState[].hash_tree_root()
      reportDiff(upgradedState, postState)

  `testImpl _ fork _ identifier`()

suite "EF - Bellatrix - Fork " & preset():
  for kind, path in walkDir(OpForkDir, relative = true, checkDir = true):
    runTest(path)
