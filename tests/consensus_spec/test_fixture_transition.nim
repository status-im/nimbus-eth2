# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  yaml,
  ../../beacon_chain/spec/[state_transition, forks],
  ./os_ops

from std/sequtils import toSeq
from streams import close, openFileStream
from ../testutil import preset, suite, test
from ./fixtures_utils import SszTestsDir, parseTest

type
  TransitionInfo = object
    post_fork: string
    fork_epoch: int
    blocks_count: int
    fork_block {.defaultVal: -1.}: int
    bls_setting {.defaultVal: 1.}: int

proc getTransitionInfo(testPath: string): TransitionInfo =
  var transitionInfo: TransitionInfo
  let s = openFileStream(testPath/"meta.yaml")
  defer: close(s)
  yaml.load(s, transitionInfo)
  transitionInfo

proc runTest(
    AnteBeaconState, PostBeaconState, AnteBeaconBlock, PostBeaconBlock: type,
    cfg: RuntimeConfig, testName, testDir: static[string],
    unitTestName: string, fork_block: int) =
  let testPath = testDir / unitTestName

  proc `testImpl _ blck _ testName`() =
    test testName & " - " & unitTestName & preset():
      let preState =
        newClone(parseTest(testPath/"pre.ssz_snappy", SSZ, AnteBeaconState))
      var
        fhPreState = ForkedHashedBeaconState.new(preState[])
        cache = StateCache()
        info = ForkedEpochInfo()

      # In test cases with more than 10 blocks the first 10 aren't 0-prefixed,
      # so purely lexicographic sorting wouldn't sort properly.
      let numBlocks = toSeq(walkPattern(testPath/"blocks_*.ssz_snappy")).len
      for i in 0 ..< numBlocks:
        if i <= fork_block:
          let
            blck = parseTest(
              testPath/"blocks_" & $i & ".ssz_snappy", SSZ, AnteBeaconBlock)
            res = state_transition(
              cfg, fhPreState[], blck, cache, info,
              flags = {skipStateRootValidation}, noRollback)

          res.expect("no failure when applying block " & $i)
        else:
          let
            blck = parseTest(
              testPath/"blocks_" & $i & ".ssz_snappy", SSZ, PostBeaconBlock)
            res = state_transition(
              cfg, fhPreState[], blck, cache, info,
              flags = {skipStateRootValidation}, noRollback)

          res.expect("no failure when applying block " & $i)

      let postState = newClone(
        parseTest(testPath/"post.ssz_snappy", SSZ, PostBeaconState))
      when false:
        reportDiff(fhPreState.data, postState)
      doAssert getStateRoot(fhPreState[]) == postState[].hash_tree_root()

  `testImpl _ blck _ testName`()

from ../../beacon_chain/spec/datatypes/phase0 import
  BeaconState, SignedBeaconBlock
from ../../beacon_chain/spec/datatypes/altair import
  BeaconState, SignedBeaconBlock

suite "EF - Altair - Transition " & preset():
  const TransitionDir =
    SszTestsDir/const_preset/"altair"/"transition"/"core"/"pyspec_tests"

  for kind, path in walkDir(TransitionDir, relative = true, checkDir = true):
    let transitionInfo = getTransitionInfo(TransitionDir / path)
    var cfg = defaultRuntimeConfig
    cfg.ALTAIR_FORK_EPOCH = transitionInfo.fork_epoch.Epoch
    runTest(
      phase0.BeaconState, altair.BeaconState, phase0.SignedBeaconBlock,
      altair.SignedBeaconBlock, cfg, "EF - Altair - Transition", TransitionDir,
      path, transitionInfo.fork_block)

from ../../beacon_chain/spec/datatypes/bellatrix import
  BeaconState, SignedBeaconBlock

suite "EF - Bellatrix - Transition " & preset():
  const TransitionDir =
    SszTestsDir/const_preset/"bellatrix"/"transition"/"core"/"pyspec_tests"

  for kind, path in walkDir(TransitionDir, relative = true, checkDir = true):
    let transitionInfo = getTransitionInfo(TransitionDir / path)
    var cfg = defaultRuntimeConfig
    cfg.BELLATRIX_FORK_EPOCH = transitionInfo.fork_epoch.Epoch
    runTest(
      altair.BeaconState, bellatrix.BeaconState, altair.SignedBeaconBlock,
      bellatrix.SignedBeaconBlock, cfg, "EF - Bellatrix - Transition",
      TransitionDir, path, transitionInfo.fork_block)

from ../../beacon_chain/spec/datatypes/capella import
  BeaconState, SignedBeaconBlock

suite "EF - Capella - Transition " & preset():
  const TransitionDir =
    SszTestsDir/const_preset/"capella"/"transition"/"core"/"pyspec_tests"

  for kind, path in walkDir(TransitionDir, relative = true, checkDir = true):
    let transitionInfo = getTransitionInfo(TransitionDir / path)
    var cfg = defaultRuntimeConfig
    cfg.CAPELLA_FORK_EPOCH = transitionInfo.fork_epoch.Epoch
    runTest(
      bellatrix.BeaconState, capella.BeaconState, bellatrix.SignedBeaconBlock,
      capella.SignedBeaconBlock, cfg, "EF - Capella - Transition",
      TransitionDir, path, transitionInfo.fork_block)

from ../../beacon_chain/spec/datatypes/deneb import
  BeaconState, SignedBeaconBlock

suite "EF - Deneb - Transition " & preset():
  const TransitionDir =
    SszTestsDir/const_preset/"deneb"/"transition"/"core"/"pyspec_tests"

  for kind, path in walkDir(TransitionDir, relative = true, checkDir = true):
    let transitionInfo = getTransitionInfo(TransitionDir / path)
    var cfg = defaultRuntimeConfig
    cfg.DENEB_FORK_EPOCH = transitionInfo.fork_epoch.Epoch
    runTest(
      capella.BeaconState, deneb.BeaconState, capella.SignedBeaconBlock,
      deneb.SignedBeaconBlock, cfg, "EF - Deneb - Transition",
      TransitionDir, path, transitionInfo.fork_block)
