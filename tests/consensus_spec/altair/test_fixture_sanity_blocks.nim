# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, sequtils, chronicles,
  # Beacon chain internals
  ../../../beacon_chain/spec/[forks, state_transition],
  ../../../beacon_chain/spec/datatypes/altair,
  # Test utilities
  ../../testutil,
  ../fixtures_utils

const
  FinalityDir = SszTestsDir/const_preset/"altair"/"finality"/"finality"/"pyspec_tests"
  RandomDir = SszTestsDir/const_preset/"altair"/"random"/"random"/"pyspec_tests"
  SanityBlocksDir = SszTestsDir/const_preset/"altair"/"sanity"/"blocks"/"pyspec_tests"

proc runTest(testName, testDir, unitTestName: string) =
  let testPath = testDir / unitTestName

  proc `testImpl _ blck _ testName`() =
    let
      hasPostState = existsFile(testPath/"post.ssz_snappy")
      prefix = if hasPostState: "[Valid]   " else: "[Invalid] "

    test prefix & testName & " - " & unitTestName & preset():
      var
        preState = newClone(parseTest(testPath/"pre.ssz_snappy", SSZ, altair.BeaconState))
        fhPreState = (ref ForkedHashedBeaconState)(altairData: altair.HashedBeaconState(
          data: preState[], root: hash_tree_root(preState[])), kind: BeaconStateFork.Altair)
        cache = StateCache()
        info = ForkedEpochInfo()

      # In test cases with more than 10 blocks the first 10 aren't 0-prefixed,
      # so purely lexicographic sorting wouldn't sort properly.
      let numBlocks = toSeq(walkPattern(testPath/"blocks_*.ssz_snappy")).len
      for i in 0 ..< numBlocks:
        let blck = parseTest(testPath/"blocks_" & $i & ".ssz_snappy", SSZ, altair.SignedBeaconBlock)

        if hasPostState:
          let res = state_transition(
            defaultRuntimeConfig, fhPreState[], blck, cache, info, flags = {},
            noRollback)
          res.expect("block should apply: " & $i)
        else:
          let res = state_transition(
            defaultRuntimeConfig, fhPreState[], blck, cache, info, flags = {},
            noRollback)
          doAssert (i + 1 < numBlocks) or not res.isOk(),
            "We didn't expect these invalid blocks to be processed"

      if hasPostState:
        let postState = newClone(parseTest(testPath/"post.ssz_snappy", SSZ, altair.BeaconState))
        when false:
          reportDiff(fhPreState.altairData.data, postState)
        doAssert getStateRoot(fhPreState[]) == postState[].hash_tree_root()

  `testImpl _ blck _ testName`()

suite "EF - Altair - Sanity - Blocks " & preset():
 for kind, path in walkDir(SanityBlocksDir, relative = true, checkDir = true):
   runTest("EF - Altair - Sanity - Blocks", SanityBlocksDir, path)

suite "EF - Altair - Finality " & preset():
 for kind, path in walkDir(FinalityDir, relative = true, checkDir = true):
   runTest("EF - Altair - Finality", FinalityDir, path)

suite "EF - Altair - Random" & preset():
 for kind, path in walkDir(RandomDir, relative = true, checkDir = true):
   runTest("EF - Altair - Random", RandomDir, path)
