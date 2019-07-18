# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Merkle tree helpers
# ---------------------------------------------------------------

import
  # Specs
  ../../beacon_chain/spec/[datatypes, digest, beaconstate, helpers],
  ../../beacon_chain/ssz,
  # shims
  stew/objects

func round_step_down*(x: Natural, step: static Natural): int {.inline.} =
  ## Round the input to the previous multiple of "step"
  when (step and (step - 1)) == 0:
    # Step is a power of 2. (If compiler cannot prove that x>0 it does not make the optim)
    result = x and not(step - 1)
  else:
    result = x - x mod step

let ZeroHashes = block:
  # hashes for a merkle tree full of zeros for leafs
  var zh = @[Eth2Digest()]
  for i in 1 ..< DEPOSIT_CONTRACT_TREE_DEPTH:
    let nodehash = withEth2Hash:
      h.update zh[i-1]
      h.update zh[i-1]
    zh.add nodehash
  zh

type SparseMerkleTree*[Depth: static int] = object
  ## Sparse Merkle tree
  # There is an extra "depth" layer to store leaf nodes
  # This stores leaves at depth = 0
  # and the root hash at the last depth
  nnznodes: array[Depth+1, seq[Eth2Digest]]  # nodes that leads to non-zero leaves

proc merkleTreeFromLeaves*(
        values: openarray[Eth2Digest],
        Depth: static[int] = DEPOSIT_CONTRACT_TREE_DEPTH
      ): SparseMerkleTree[Depth] =
  ## Depth should be the same as
  ## verify_merkle_branch / is_valid_merkle_branch

  result.nnznodes[0] = @values

  for depth in 1 .. Depth: # Inclusive range
    let prev_depth_len = result.nnznodes[depth-1].len
    let stop = round_step_down(prev_depth_len, 2)
    for i in countup(0, stop-1, 2):
      # hash by pair of previous nodes
      let nodeHash = withEth2Hash:
        h.update result.nnznodes[depth-1][i]
        h.update result.nnznodes[depth-1][i+1]
      result.nnznodes[depth].add nodeHash

    if prev_depth_len != stop:
      # If length is odd, the last one was skipped,
      # we need to combine it
      # with the zeroHash corresponding to the current depth
      let nodeHash = withEth2Hash:
        h.update result.nnznodes[depth-1][^1]
        h.update ZeroHashes[depth-1]
      result.nnznodes[depth].add nodeHash

proc getMerkleProof*[Depth: static int](
        tree: SparseMerkleTree[Depth],
        index: int,
      ): array[Depth, Eth2Digest] =

  # Descend down the tree according to the bit representation
  # of the index:
  #   - 0 --> go left
  #   - 1 --> go right
  let path = uint32(index)
  for depth in 0 ..< Depth:
    let nodeIdx = int((path shr depth) xor 1)
    if nodeIdx < tree.nnznodes[depth].len:
      result[depth] = tree.nnznodes[depth][nodeIdx]
    else:
      result[depth] = ZeroHashes[depth]

when isMainModule:
  # Check that round-tripping works with verify_merkle_branch (in beaconstate.nim)

  proc toDigest[N: static int](x: array[N, byte]): Eth2Digest =
    result.data[0 .. N-1] = x

  block: # 2-depth round-trip
    let a = [byte 0x01, 0x02, 0x03].toDigest
    let b = [byte 0x04, 0x05, 0x06].toDigest
    let c = [byte 0x07, 0x08, 0x09].toDigest

    let tree = merkleTreeFromLeaves([a, b, c], Depth = 3)
    echo "Tree: ", tree

    let index = 2
    let proof = getMerkleProof(tree, index)
    echo "Proof: ", proof

    # TODO - need compliant implementation of SSZ hash_tree_root
    let root = hash_tree_root([a, b, c])
    echo root

    when false:
      echo verify_merkle_branch(
        a, get_merkle_proof(tree, index = 2),
        depth = 3,
        index = 2,
        root = root
      )
