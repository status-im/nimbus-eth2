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
  ../../../beacon_chain/spec/datatypes/[capella, eip4844],
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ../../helpers/debug_state

const OpForkDir = SszTestsDir/const_preset/"eip4844"/"fork"/"fork"/"pyspec_tests"

proc runTest(identifier: string) =
  let testDir = OpForkDir / identifier

  proc `testImpl _ fork _ identifier`() =
    test identifier:
      let
        preState = newClone(
          parseTest(testDir/"pre.ssz_snappy", SSZ, capella.BeaconState))
        postState = newClone(
          parseTest(testDir/"post.ssz_snappy", SSZ, eip4844.BeaconState))

      let cfg = defaultRuntimeConfig

      let upgradedState = upgrade_to_eip4844(cfg, preState[])
      check: upgradedState[].hash_tree_root() == postState[].hash_tree_root()
      reportDiff(upgradedState, postState)

  `testImpl _ fork _ identifier`()

suite "EF - EIP4844 - Fork " & preset():
  for kind, path in walkDir(OpForkDir, relative = true, checkDir = true):
    runTest(path)
