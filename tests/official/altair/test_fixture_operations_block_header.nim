# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
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
  # Beacon chain internals
  ../../../beacon_chain/spec/[state_transition_block],
  ../../../beacon_chain/spec/datatypes/altair,
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ../../helpers/debug_state

const OpBlockHeaderDir = SszTestsDir/const_preset/"altair"/"operations"/"block_header"/"pyspec_tests"

proc runTest(identifier: string) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  let testDir = OpBlockHeaderDir / identifier

  proc `testImpl _ blockheader _ identifier`() =

    let prefix =
      if existsFile(testDir/"post.ssz_snappy"):
        "[Valid]   "
      else:
        "[Invalid] "

    test prefix & identifier:
      let blck = parseTest(testDir/"block.ssz_snappy", SSZ, altair.BeaconBlock)
      var
        cache = StateCache()
        preState =
          newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, altair.BeaconState))

      if existsFile(testDir/"post.ssz_snappy"):
        let
          postState =
            newClone(parseTest(testDir/"post.ssz_snappy", SSZ, altair.BeaconState))
          done = process_block_header(preState[], blck, {}, cache).isOk
        doAssert done, "Valid block header not processed"
        check: preState[].hash_tree_root() == postState[].hash_tree_root()
        reportDiff(preState, postState)
      else:
        let done = process_block_header(preState[], blck, {}, cache).isOk
        doAssert done == false, "We didn't expect this invalid block header to be processed."

  `testImpl _ blockheader _ identifier`()

suite "Ethereum Foundation - Altair - Operations - Block header " & preset():
  for kind, path in walkDir(OpBlockHeaderDir, relative = true, checkDir = true):
    runTest(path)
