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
  ../../testutil,
  ../fixtures_utils

const TestsDir =
  SszTestsDir/const_preset/"altair"/"merkle"/"single_proof"/"pyspec_tests"

proc runTest(identifier: string) =
  let testDir = TestsDir / identifier

  proc `testImpl _ merkle_single_proof _ identifier`() =
    test identifier:
      type
        TestProof = object
          leaf: string
          leaf_index: GeneralizedIndex
          branch: seq[string]

      let
        proof = block:
          var s = openFileStream(testDir/"proof.yaml")
          defer: close(s)
          var res: TestProof
          yaml.load(s, res)
          res

        state = newClone(parseTest(testDir/"state.ssz_snappy", SSZ,
                                   altair.BeaconState))

      var computedProof = newSeq[Eth2Digest](log2trunc(proof.leaf_index))
      build_proof(state[], proof.leaf_index, computedProof)

      check:
        computedProof == proof.branch.mapIt(Eth2Digest.fromHex(it))
        is_valid_merkle_branch(Eth2Digest.fromHex(proof.leaf), computedProof,
                               log2trunc(proof.leaf_index),
                               get_subtree_index(proof.leaf_index),
                               hash_tree_root(state[]))

  `testImpl _ merkle_single_proof _ identifier`()

suite "EF - Altair - Merkle - Single proof" & preset():
  for kind, path in walkDir(TestsDir, relative = true, checkDir = true):
    runTest(path)
