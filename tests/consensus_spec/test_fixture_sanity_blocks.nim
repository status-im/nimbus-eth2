# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  chronicles,
  ../../beacon_chain/spec/forks,
  ../../beacon_chain/spec/state_transition,
  ./os_ops,
  ../testutil

from std/sequtils import toSeq
from std/strutils import toLowerAscii
from ../../beacon_chain/spec/presets import
  const_preset, defaultRuntimeConfig
from ./fixtures_utils import
  SSZ, SszTestsDir, hash_tree_root, parseTest, readSszBytes, toSszType

proc runTest(
    consensusFork: static ConsensusFork,
    testName, testDir: static[string], suiteName, unitTestName: string) =
  let testPath = testDir / unitTestName

  let
    hasPostState = fileExists(testPath/"post.ssz_snappy")
    prefix = if hasPostState: "[Valid]   " else: "[Invalid] "

  test prefix & testName & " - " & unitTestName & preset():
    let preState = newClone(parseTest(testPath/"pre.ssz_snappy",
      SSZ, consensusFork.BeaconState))
    var
      fhPreState = ForkedHashedBeaconState.new(preState[])
      cache = StateCache()
      info = ForkedEpochInfo()

    # In test cases with more than 10 blocks the first 10 aren't 0-prefixed,
    # so purely lexicographic sorting wouldn't sort properly.
    let numBlocks = toSeq(walkPattern(testPath/"blocks_*.ssz_snappy")).len
    for i in 0 ..< numBlocks:
      let blck = parseTest(testPath/"blocks_" & $i & ".ssz_snappy",
        SSZ, consensusFork.SignedBeaconBlock)

      if hasPostState:
        # The return value is the block rewards, which aren't tested here;
        # the .expect() already handles the validaty check.
        discard state_transition(
          defaultRuntimeConfig, fhPreState[], blck, cache, info, flags = {},
          noRollback).expect("should apply block")
      else:
        let res = state_transition(
          defaultRuntimeConfig, fhPreState[], blck, cache, info, flags = {},
          noRollback)
        doAssert (i + 1 < numBlocks) or not res.isOk(),
          "We didn't expect these invalid blocks to be processed"

    if hasPostState:
      let postState = newClone(parseTest(testPath/"post.ssz_snappy",
        SSZ, consensusFork.BeaconState))
      when false:
        reportDiff(hashedPreState.phase0Data.data, postState)
      doAssert getStateRoot(fhPreState[]) == postState[].hash_tree_root()

template runForkBlockTests(consensusFork: static ConsensusFork) =
  const
    forkHumanName = $consensusFork
    forkDirName = forkHumanName.toLowerAscii()
    FinalityDir =
      SszTestsDir/const_preset/forkDirName/"finality"/"finality"/"pyspec_tests"
    RandomDir =
      SszTestsDir/const_preset/forkDirName/"random"/"random"/"pyspec_tests"
    SanityBlocksDir =
      SszTestsDir/const_preset/forkDirName/"sanity"/"blocks"/"pyspec_tests"

  suite "EF - " & forkHumanName & " - Sanity - Blocks " & preset():
    for kind, path in walkDir(SanityBlocksDir, relative = true, checkDir = true):
      consensusFork.runTest(
        "EF - " & forkHumanName & " - Sanity - Blocks",
        SanityBlocksDir, suiteName, path)

  suite "EF - " & forkHumanName & " - Finality " & preset():
    for kind, path in walkDir(FinalityDir, relative = true, checkDir = true):
      consensusFork.runTest(
        "EF - " & forkHumanName & " - Finality",
        FinalityDir, suiteName, path)

  suite "EF - " & forkHumanName & " - Random " & preset():
    for kind, path in walkDir(RandomDir, relative = true, checkDir = true):
      consensusFork.runTest(
        "EF - " & forkHumanName & " - Random",
        RandomDir, suiteName, path)

withAll(ConsensusFork):
  when consensusFork <= ConsensusFork.Deneb:
    runForkBlockTests(consensusFork)
