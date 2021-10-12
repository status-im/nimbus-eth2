# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os,
  # Utilities
  stew/results,
  chronicles,
  # Beacon chain internals
  ../../../beacon_chain/spec/[beaconstate, presets, state_transition_block],
  ../../../beacon_chain/spec/datatypes/altair,
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ../../helpers/debug_state

const OperationsDepositsDir = SszTestsDir/const_preset/"altair"/"operations"/"deposit"/"pyspec_tests"

proc runTest(identifier: string) =
  let testDir = OperationsDepositsDir / identifier

  proc `testImpl _ operations_deposits _ identifier`() =

    let prefix =
      if existsFile(testDir/"post.ssz_snappy"):
        "[Valid]   "
      else:
        "[Invalid] "

    test prefix & " " & identifier:
      var
        preState =
          newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, altair.BeaconState))
      let
        deposit = parseTest(testDir/"deposit.ssz_snappy", SSZ, Deposit)
        done = process_deposit(defaultRuntimeConfig, preState[], deposit, {})

      if existsFile(testDir/"post.ssz_snappy"):
        let postState =
          newClone(parseTest(testDir/"post.ssz_snappy", SSZ, altair.BeaconState))

        check:
          done.isOk()
          preState[].hash_tree_root() == postState[].hash_tree_root()
        reportDiff(preState, postState)
      else:
        check: done.isErr() # No post state = processing should fail

  `testImpl _ operations_deposits _ identifier`()

suite "Ethereum Foundation - Altair - Operations - Deposits " & preset():
  for kind, path in walkDir(
      OperationsDepositsDir, relative = true, checkDir = true):
    runTest(path)
