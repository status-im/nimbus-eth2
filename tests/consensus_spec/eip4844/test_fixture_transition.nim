# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  yaml,
  # Standard library
  std/[os, sequtils, strutils],
  # Status internal
  faststreams, streams,
  # Beacon chain internals
  ../../../beacon_chain/spec/[state_transition, forks, helpers],
  ../../../beacon_chain/spec/datatypes/[capella, eip4844],
  # Test utilities
  ../../testutil,
  ../fixtures_utils

const
  TransitionDir = SszTestsDir/const_preset/"eip4844"/"transition"/"core"/"pyspec_tests"

type
  TransitionInfo = object
    post_fork: string
    fork_epoch: int
    blocks_count: int
    fork_block {.defaultVal: -1.}: int
    bls_setting {.defaultVal: 1.}: int

proc runTest(testName, testDir, unitTestName: string) =
  let testPath = testDir / unitTestName

  var transitionInfo: TransitionInfo
  let s = openFileStream(testPath/"meta.yaml")
  defer: close(s)
  yaml.load(s, transitionInfo)

  proc `testImpl _ blck _ testName`() =
    test testName & " - " & unitTestName & preset():
      var
        preState = newClone(parseTest(testPath/"pre.ssz_snappy", SSZ, capella.BeaconState))
        fhPreState = (ref ForkedHashedBeaconState)(capellaData: capella.HashedBeaconState(
          data: preState[], root: hash_tree_root(preState[])), kind: BeaconStateFork.Capella)
        cache = StateCache()
        info = ForkedEpochInfo()
        cfg = defaultRuntimeConfig
      cfg.EIP4844_FORK_EPOCH = transitionInfo.fork_epoch.Epoch

      # In test cases with more than 10 blocks the first 10 aren't 0-prefixed,
      # so purely lexicographic sorting wouldn't sort properly.
      let numBlocks = toSeq(walkPattern(testPath/"blocks_*.ssz_snappy")).len
      for i in 0 ..< numBlocks:
        if i <= transitionInfo.fork_block:
          let blck = parseTest(
            testPath/"blocks_" & $i & ".ssz_snappy", SSZ,
            capella.SignedBeaconBlock)

          let res = state_transition(
            cfg, fhPreState[], blck, cache, info,
            flags = {skipStateRootValidation}, noRollback)
          res.expect("no failure when applying block " & $i)
        else:
          let blck = parseTest(
            testPath/"blocks_" & $i & ".ssz_snappy", SSZ,
            eip4844.SignedBeaconBlock)

          let res = state_transition(
            cfg, fhPreState[], blck, cache, info,
            flags = {skipStateRootValidation}, noRollback)
          res.expect("no failure when applying block " & $i)

      let postState = newClone(parseTest(
        testPath/"post.ssz_snappy", SSZ, eip4844.BeaconState))
      when false:
        reportDiff(fhPreState.data, postState)
      doAssert getStateRoot(fhPreState[]) == postState[].hash_tree_root()

  `testImpl _ blck _ testName`()

suite "EF - EIP4844 - Transition " & preset():
  for kind, path in walkDir(TransitionDir, relative = true, checkDir = true):
    runTest("EF - EIP4844 - Transition", TransitionDir, path)
