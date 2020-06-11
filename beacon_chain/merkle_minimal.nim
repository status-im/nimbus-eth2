# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/tests/core/pyspec/eth2spec/utils/merkle_minimal.py

# Merkle tree helpers
# ---------------------------------------------------------------

{.push raises: [Defect].}

import
  sequtils, strutils, macros, bitops,
  # Specs
  ../../beacon_chain/spec/[beaconstate, datatypes, digest, helpers],
  ../../beacon_chain/ssz/merkleization

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
  ## Depth should be the same as is_valid_merkle_branch

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

proc attachMerkleProofs*(deposits: var seq[Deposit]) =
  let deposit_data_roots = mapIt(deposits, it.data.hash_tree_root)
  var
    deposit_data_sums: seq[Eth2Digest]
  for prefix_root in hash_tree_roots_prefix(
      deposit_data_roots, 1'i64 shl DEPOSIT_CONTRACT_TREE_DEPTH):
    deposit_data_sums.add prefix_root

  for val_idx in 0 ..< deposits.len:
    let merkle_tree = merkleTreeFromLeaves(deposit_data_roots[0..val_idx])
    deposits[val_idx].proof[0..31] = merkle_tree.getMerkleProof(val_idx)
    deposits[val_idx].proof[32].data[0..7] = int_to_bytes8((val_idx + 1).uint64)

    doAssert is_valid_merkle_branch(
      deposit_data_roots[val_idx], deposits[val_idx].proof,
      DEPOSIT_CONTRACT_TREE_DEPTH + 1, val_idx.uint64,
      deposit_data_sums[val_idx])

proc testMerkleMinimal*(): bool =
  proc toDigest[N: static int](x: array[N, byte]): Eth2Digest =
    result.data[0 .. N-1] = x

  let a = [byte 0x01, 0x02, 0x03].toDigest
  let b = [byte 0x04, 0x05, 0x06].toDigest
  let c = [byte 0x07, 0x08, 0x09].toDigest

  block: # SSZ Sanity checks vs Python impl
    block: # 3 leaves
      let leaves = List[Eth2Digest, 3](@[a, b, c])
      let root = hash_tree_root(leaves)
      doAssert $root == "9ff412e827b7c9d40fc7df2725021fd579ab762581d1ff5c270316682868456e".toUpperAscii

    block: # 2^3 leaves
      let leaves = List[Eth2Digest, int64(1 shl 3)](@[a, b, c])
      let root = hash_tree_root(leaves)
      doAssert $root == "5248085b588fab1dd1e03f3cd62201602b12e6560665935964f46e805977e8c5".toUpperAscii

    block: # 2^10 leaves
      let leaves = List[Eth2Digest, int64(1 shl 10)](@[a, b, c])
      let root = hash_tree_root(leaves)
      doAssert $root == "9fb7d518368dc14e8cc588fb3fd2749beef9f493fef70ae34af5721543c67173".toUpperAscii

  block: # Round-trips
    # TODO: there is an issue (also in EF specs?)
    #       using hash_tree_root([a, b, c])
    #       doesn't give the same hash as
    #         - hash_tree_root(@[a, b, c])
    #         - sszList(@[a, b, c], int64(nleaves))
    #       which both have the same hash.
    #
    #       hash_tree_root([a, b, c]) gives the same hash as
    #       the last hash of merkleTreeFromLeaves
    #
    #       Running tests with hash_tree_root([a, b, c])
    #       works for depth 2 (3 or 4 leaves)

    macro roundTrips(): untyped =
      result = newStmtList()

      # compile-time unrolled test
      for nleaves in [3, 4, 5, 7, 8, 1 shl 10, 1 shl 32]:
        let depth = fastLog2(nleaves-1) + 1

        result.add quote do:
          block:
            let tree = merkleTreeFromLeaves([a, b, c], Depth = `depth`)
            #echo "Tree: ", tree

            doAssert tree.nnznodes[`depth`].len == 1
            let root = tree.nnznodes[`depth`][0]
            #echo "Root: ", root

            block: # proof for a
              let index = 0

              doAssert is_valid_merkle_branch(
                a, get_merkle_proof(tree, index = index),
                depth = `depth`,
                index = index.uint64,
                root = root
              ), "Failed (depth: " & $`depth` &
                ", nleaves: " & $`nleaves` & ')'

            block: # proof for b
              let index = 1

              doAssert is_valid_merkle_branch(
                b, get_merkle_proof(tree, index = index),
                depth = `depth`,
                index = index.uint64,
                root = root
              ), "Failed (depth: " & $`depth` &
                ", nleaves: " & $`nleaves` & ')'

            block: # proof for c
              let index = 2

              doAssert is_valid_merkle_branch(
                c, get_merkle_proof(tree, index = index),
                depth = `depth`,
                index = index.uint64,
                root = root
              ), "Failed (depth: " & $`depth` &
                ", nleaves: " & $`nleaves` & ')'

    roundTrips()
    true

when isMainModule:
  discard testMerkleMinimal()
