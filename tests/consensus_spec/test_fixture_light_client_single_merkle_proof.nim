# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[os, sequtils, streams],
  # Status libraries
  stew/bitops2,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../../beacon_chain/spec/datatypes/altair,
  ../../../beacon_chain/spec/helpers,
  # Test utilities
  ../testutil,
  ./fixtures_utils

proc runTest(path: string, fork: BeaconStateFork) =
  test "Light client - Single merkle proof - " & path.relativePath(SszTestsDir):
    type
      TestProof = object
        leaf: string
        leaf_index: GeneralizedIndex
        branch: seq[string]

    let
      proof = block:
        let s = openFileStream(path/"proof.yaml")
        defer: close(s)
        var res: TestProof
        yaml.load(s, res)
        res

      state = loadForkedState(path/"state.ssz_snappy", fork)

    withState(state[]):
      var computedProof = newSeq[Eth2Digest](log2trunc(proof.leaf_index))
      build_proof(state.data, proof.leaf_index, computedProof).get

      check:
        computedProof == proof.branch.mapIt(Eth2Digest.fromHex(it))
        is_valid_merkle_branch(
          Eth2Digest.fromHex(proof.leaf),
          computedProof,
          log2trunc(proof.leaf_index),
          get_subtree_index(proof.leaf_index),
          state.root)

suite "EF - Light client - Single merkle proof" & preset():
  const presetPath = SszTestsDir/const_preset
  for kind, path in walkDir(presetPath, relative = true, checkDir = true):
    let testsPath = presetPath/path/"light_client"/"single_merkle_proof"
    if kind != pcDir or not dirExists(testsPath):
      continue
    let
      fork = forkForPathComponent(path).valueOr:
        raiseAssert "Unknown test fork: " & testsPath
      basePath = testsPath/"pyspec_tests"
    for kind, path in walkDir(basePath, relative = true, checkDir = true):
      runTest(basePath/path, fork)
