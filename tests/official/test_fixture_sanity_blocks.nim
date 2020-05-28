# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, sequtils, unittest,
  # Beacon chain internals
  ../../beacon_chain/spec/[crypto, datatypes],
  ../../beacon_chain/[ssz, state_transition],
  # Test utilities
  ../testutil,
  ./fixtures_utils

const SanityBlocksDir = SszTestsDir/const_preset/"phase0"/"sanity"/"blocks"/"pyspec_tests"

proc runTest(identifier: string) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  let testDir = SanityBlocksDir / identifier

  proc `testImpl _ blck _ identifier`() =
    let prefix = if existsFile(testDir/"post.ssz"):
      "[Valid]   "
    else:
      "[Invalid] "

    timedTest prefix & identifier:
      var
        preState = newClone(parseTest(testDir/"pre.ssz", SSZ, BeaconState))
        hasPostState = existsFile(testDir/"post.ssz")
        hashedPreState = (ref HashedBeaconState)(
          data: preState[], root: hash_tree_root(preState[]))

      # In test cases with more than 10 blocks the first 10 aren't 0-prefixed,
      # so purely lexicographic sorting wouldn't sort properly.
      let numBlocks = toSeq(walkPattern(testDir/"blocks_*.ssz")).len
      for i in 0 ..< numBlocks:
        let blck = parseTest(testDir/"blocks_" & $i & ".ssz", SSZ, SignedBeaconBlock)

        if hasPostState:
          let success = state_transition(
            hashedPreState[], blck, flags = {}, noRollback)
          doAssert success, "Failure when applying block " & $i
        else:
          let success = state_transition(
            hashedPreState[], blck, flags = {}, noRollback)
          doAssert (i + 1 < numBlocks) or not success,
            "We didn't expect these invalid blocks to be processed"

      if hasPostState:
        let postState = newClone(parseTest(testDir/"post.ssz", SSZ, BeaconState))
        when false:
          reportDiff(hashedPreState.data, postState)
        doAssert hashedPreState.root == postState[].hash_tree_root()

  `testImpl _ blck _ identifier`()

suiteReport "Official - Sanity - Blocks " & preset():
  for kind, path in walkDir(SanityBlocksDir, true):
    runTest(path)
