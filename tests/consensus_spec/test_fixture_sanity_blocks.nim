# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  chronicles,
  ../../beacon_chain/spec/datatypes/phase0,
  ../../beacon_chain/spec/state_transition,
  ./os_ops,
  ../testutil

from std/sequtils import toSeq
from ../../../beacon_chain/spec/forks import
  ForkedEpochInfo, ForkedHashedBeaconState, fromSszBytes, getStateRoot, new
from ../../../beacon_chain/spec/presets import
  const_preset, defaultRuntimeConfig
from ./fixtures_utils import
  SSZ, SszTestsDir, hash_tree_root, parseTest, readSszBytes, toSszType

proc runTest(
    BS, SBB: type, testName, testDir: static[string], unitTestName: string) =
  let testPath = testDir / unitTestName

  proc `testImpl _ blck _ testName`() =
    let
      hasPostState = fileExists(testPath/"post.ssz_snappy")
      prefix = if hasPostState: "[Valid]   " else: "[Invalid] "

    test prefix & testName & " - " & unitTestName & preset():
      let preState = newClone(parseTest(testPath/"pre.ssz_snappy", SSZ, BS))
      var
        fhPreState = ForkedHashedBeaconState.new(preState[])
        cache = StateCache()
        info = ForkedEpochInfo()

      # In test cases with more than 10 blocks the first 10 aren't 0-prefixed,
      # so purely lexicographic sorting wouldn't sort properly.
      let numBlocks = toSeq(walkPattern(testPath/"blocks_*.ssz_snappy")).len
      for i in 0 ..< numBlocks:
        let blck = parseTest(testPath/"blocks_" & $i & ".ssz_snappy", SSZ, SBB)

        if hasPostState:
          state_transition(
            defaultRuntimeConfig, fhPreState[], blck, cache, info, flags = {},
            noRollback).expect("should apply block")
        else:
          let res = state_transition(
            defaultRuntimeConfig, fhPreState[], blck, cache, info, flags = {},
            noRollback)
          doAssert (i + 1 < numBlocks) or not res.isOk(),
            "We didn't expect these invalid blocks to be processed"

      if hasPostState:
        let postState = newClone(parseTest(testPath/"post.ssz_snappy", SSZ, BS))
        when false:
          reportDiff(hashedPreState.phase0Data.data, postState)
        doAssert getStateRoot(fhPreState[]) == postState[].hash_tree_root()

  `testImpl _ blck _ testName`()

template runForkBlockTests(
    forkDirName, forkHumanName: static[string], BeaconStateType,
    BeaconBlockType: untyped) =
  const
    FinalityDir =
      SszTestsDir/const_preset/forkDirName/"finality"/"finality"/"pyspec_tests"
    RandomDir =
      SszTestsDir/const_preset/forkDirName/"random"/"random"/"pyspec_tests"
    SanityBlocksDir =
      SszTestsDir/const_preset/forkDirName/"sanity"/"blocks"/"pyspec_tests"

  suite "EF - " & forkHumanName & " - Sanity - Blocks " & preset():
    for kind, path in walkDir(SanityBlocksDir, relative = true, checkDir = true):
      runTest(
        BeaconStateType, BeaconBlockType,
        "EF - " & forkHumanName & " - Sanity - Blocks", SanityBlocksDir, path)

  suite "EF - " & forkHumanName & " - Finality " & preset():
    for kind, path in walkDir(FinalityDir, relative = true, checkDir = true):
      runTest(
        BeaconStateType, BeaconBlockType,
        "EF - " & forkHumanName & " - Finality", FinalityDir, path)

  suite "EF - " & forkHumanName & " - Random " & preset():
    for kind, path in walkDir(RandomDir, relative = true, checkDir = true):
      runTest(
        BeaconStateType, BeaconBlockType,
        "EF - " & forkHumanName & " - Random", RandomDir, path)

runForkBlockTests(
  "phase0", "Phase 0", phase0.BeaconState, phase0.SignedBeaconBlock)

from ../../../beacon_chain/spec/datatypes/altair import
  BeaconState, SignedBeaconBlock
runForkBlockTests(
  "altair", "Altair", altair.BeaconState, altair.SignedBeaconBlock)

from ../../../beacon_chain/spec/datatypes/bellatrix import
  BeaconState, SignedBeaconBlock
runForkBlockTests(
  "bellatrix", "Bellatrix", bellatrix.BeaconState, bellatrix.SignedBeaconBlock)

from ../../../beacon_chain/spec/datatypes/capella import
  BeaconState, SignedBeaconBlock
runForkBlockTests(
  "capella", "Capella", capella.BeaconState, capella.SignedBeaconBlock)

from ../../../beacon_chain/spec/datatypes/deneb import
  BeaconState, SignedBeaconBlock
runForkBlockTests(
  "deneb", "Deneb", deneb.BeaconState, deneb.SignedBeaconBlock)
