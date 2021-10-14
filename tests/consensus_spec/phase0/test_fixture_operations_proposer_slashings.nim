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
  # Beacon chain internals
  ../../../beacon_chain/spec/state_transition_block,
  ../../../beacon_chain/spec/datatypes/phase0,
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ../../helpers/debug_state

when isMainModule:
  import chronicles # or some random compile error happens...

const OpProposerSlashingDir = SszTestsDir/const_preset/"phase0"/"operations"/"proposer_slashing"/"pyspec_tests"

proc runTest(identifier: string) =
  let testDir = OpProposerSlashingDir / identifier

  proc `testImpl_proposer_slashing _ identifier`() =

    let prefix =
      if existsFile(testDir/"post.ssz_snappy"):
        "[Valid]   "
      else:
        "[Invalid] "

    test prefix & identifier:
      var
        cache = StateCache()
        preState =
          newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, phase0.BeaconState))

      let
        proposerSlashing = parseTest(
          testDir/"proposer_slashing.ssz_snappy", SSZ, ProposerSlashing)
        done = process_proposer_slashing(
          defaultRuntimeConfig, preState[], proposerSlashing, {}, cache)

      if existsFile(testDir/"post.ssz_snappy"):
        let postState =
          newClone(parseTest(testDir/"post.ssz_snappy", SSZ, phase0.BeaconState))

        check:
          done.isOk()
          preState[].hash_tree_root() == postState[].hash_tree_root()
        reportDiff(preState, postState)
      else:
        check: done.isErr() # No post state = processing should fail

  `testImpl_proposer_slashing _ identifier`()

suite "Ethereum Foundation - Phase 0 - Operations - Proposer slashing " & preset():
  for kind, path in walkDir(
      OpProposerSlashingDir, relative = true, checkDir = true):
    runTest(path)
