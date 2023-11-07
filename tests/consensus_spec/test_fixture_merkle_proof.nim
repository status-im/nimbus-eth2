# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[sequtils, streams],
  # Status libraries
  stew/bitops2,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../beacon_chain/spec/helpers,
  # Test utilities
  ../testutil,
  ./fixtures_utils, ./os_ops

proc runTest[T](suiteName, path: string, objType: typedesc[T]) =
  test "Merkle proof - Single merkle proof - " & path.relativePath(SszTestsDir):
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

      obj = newClone(parseTest(path/"object.ssz_snappy", SSZ, T))

    var computedProof = newSeq[Eth2Digest](log2trunc(proof.leaf_index))
    build_proof(obj[], proof.leaf_index, computedProof).get

    check:
      computedProof == proof.branch.mapIt(Eth2Digest.fromHex(it))
      is_valid_merkle_branch(
        Eth2Digest.fromHex(proof.leaf),
        computedProof,
        log2trunc(proof.leaf_index),
        get_subtree_index(proof.leaf_index),
        hash_tree_root(obj[]))

suite "EF - Merkle proof" & preset():
  const presetPath = SszTestsDir/const_preset
  for kind, path in walkDir(presetPath, relative = true, checkDir = true):
    let testsPath = presetPath/path/"merkle_proof"/"single_merkle_proof"
    if kind != pcDir or not dirExists(testsPath):
      continue
    let fork = forkForPathComponent(path).valueOr:
      test "Merkle proof - Single merkle proof - " & path:
        skip()
      continue
    for kind, path in walkDir(testsPath, relative = true, checkDir = true):
      let suitePath = testsPath/path
      if kind != pcDir or not dirExists(suitePath):
        continue
      let objName = path
      withConsensusFork(fork):
        for kind, path in walkDir(suitePath, relative = true, checkDir = true):
          case objName
          of "BeaconBlockBody":
            runTest(suiteName, suitePath/path, consensusFork.BeaconBlockBody)
          else:
            raiseAssert "Unknown test object: " & suitePath/path
