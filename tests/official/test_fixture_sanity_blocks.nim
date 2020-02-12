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
  ../../beacon_chain/[ssz, state_transition, extras],
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state

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
      var stateRef, postRef: ref BeaconState
      new stateRef
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)

      if existsFile(testDir/"post.ssz"):
        new postRef
        postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      # In test cases with more than 10 blocks the first 10 aren't 0-prefixed,
      # so purely lexicographic sorting wouldn't sort properly.
      for i in 0 ..< toSeq(walkPattern(testDir/"blocks_*.ssz")).len:
        let blck = parseTest(testDir/"blocks_" & $i & ".ssz", SSZ, SignedBeaconBlock)

        if postRef.isNil:
          let success = state_transition(stateRef[], blck.message, flags = {})
          doAssert not success, "We didn't expect this invalid block to be processed"
        else:
          # TODO: The EF is using invalid BLS keys so we can't verify them
          let success = state_transition(stateRef[], blck.message, flags = {skipValidation})
          doAssert success, "Failure when applying block " & $i

      # check: stateRef.hash_tree_root() == postRef.hash_tree_root()
      if not postRef.isNil:
        reportDiff(stateRef, postRef)

  `testImpl _ blck _ identifier`()

suite "Official - Sanity - Blocks " & preset():
  # Failing due to signature checking in indexed validation checking pending
  # 0.10 BLS verification API with new domain handling.
  const expected_failures = ["attester_slashing"]

  for kind, path in walkDir(SanityBlocksDir, true):
    if path in expected_failures:
      echo "Skipping test: ", path
      continue
    runTest(path)
