# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0-rc.0/tests/core/pyspec/eth2spec/utils/merkle_minimal.py

# Merkle tree helpers
# ---------------------------------------------------------------

{.push raises: [Defect].}

import
  sequtils, macros,
  stew/endians2,
  # Specs
  ../../beacon_chain/spec/[datatypes, digest],
  ../../beacon_chain/ssz/merkleization

# TODO All tests need to be moved to the test suite.

func round_step_down(x: Natural, step: static Natural): int {.inline.} =
  ## Round the input to the previous multiple of "step"
  when (step and (step - 1)) == 0:
    # Step is a power of 2. (If compiler cannot prove that x>0 it does not make the optim)
    x and not(step - 1)
  else:
    x - x mod step

type SparseMerkleTree*[Depth: static int] = object
  ## Sparse Merkle tree
  # There is an extra "depth" layer to store leaf nodes
  # This stores leaves at depth = 0
  # and the root hash at the last depth
  nnznodes*: array[Depth+1, seq[Eth2Digest]]  # nodes that leads to non-zero leaves

type
  MerkleTreeFragment* = object
    depth: int
    elements: seq[Eth2Digest]

func merkleTreeFromLeaves*(
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
        h.update zeroHashes[depth-1]
      result.nnznodes[depth].add nodeHash

func getMerkleProof*[Depth: static int](tree: SparseMerkleTree[Depth],
                                        index: int,
                                        depositMode = false): array[Depth, Eth2Digest] =
  # Descend down the tree according to the bit representation
  # of the index:
  #   - 0 --> go left
  #   - 1 --> go right
  let path = uint32(index)

  # This is what the nnznodes[depth].len would be if `index` had been the last
  # deposit on the Merkle tree
  var depthLen = index + 1

  for depth in 0 ..< Depth:
    let nodeIdx = int((path shr depth) xor 1)

    # depositMode simulates only having constructed SparseMerkleTree[Depth]
    # through exactly deposit specified.
    if nodeIdx < tree.nnznodes[depth].len and
        (nodeIdx < depthLen or not depositMode):
      result[depth] = tree.nnznodes[depth][nodeIdx]
    else:
      result[depth] = zeroHashes[depth]

    # Round up, i.e. a half-pair of Merkle nodes/leaves still requires a node
    # in the next Merkle tree layer calculated
    depthLen = (depthLen + 1) div 2

func attachMerkleProofs*(deposits: var openarray[Deposit]) =
  let depositsRoots = mapIt(deposits, hash_tree_root(it.data))

  const depositContractLimit = Limit(1'u64 shl (DEPOSIT_CONTRACT_TREE_DEPTH - 1'u64))
  var incrementalMerkleProofs = createMerkleizer(depositContractLimit)
  
  for i in 0 ..< depositsRoots.len:
    incrementalMerkleProofs.addChunkAndGenMerkleProof(depositsRoots[i], deposits[i].proof)
    deposits[i].proof[32].data[0..7] = toBytesLE uint64(i + 1)

