# beacon_chain
# Copyright (c) 2021-Present Status Research & Development GmbH
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
  ../../../beacon_chain/spec/datatypes/[phase0, altair],
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ../../helpers/debug_state

const OpForkDir = SszTestsDir/const_preset/"altair"/"fork"/"fork"/"pyspec_tests"

proc runTest(identifier: string) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  let testDir = OpForkDir / identifier

  proc `testImpl _ fork _ identifier`() =
    test identifier:
      let
        preState = newClone(
          parseTest(testDir/"pre.ssz_snappy", SSZ, phase0.BeaconState))
        postState = newClone(
          parseTest(testDir/"post.ssz_snappy", SSZ, altair.BeaconState))

      var cfg = defaultRuntimeConfig
      cfg.ALTAIR_FORK_EPOCH = preState[].slot.epoch

      let upgradedState = upgrade_to_altair(cfg, preState[])
      check: upgradedState[].hash_tree_root() == postState[].hash_tree_root()
      reportDiff(upgradedState, postState)

  `testImpl _ fork _ identifier`()

suite "Ethereum Foundation - Altair - Fork " & preset():
  # TODO investigate and fix in miminal presets
  when const_preset == "mainnet":
    for kind, path in walkDir(OpForkDir, relative = true, checkDir = true):
      runTest(path)
