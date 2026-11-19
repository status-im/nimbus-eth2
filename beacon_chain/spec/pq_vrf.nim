# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## VRF trees for the PQ fork's RANDAO.
##
## The VRF tree is a Merkle tree of depth `VRF_TREE_DEPTH` (31) hashed with
## `keccak256`, whose leaf `i` is `keccak256(vrf_seed || uint64_le(i))`.
##
## https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/validator.md#vrf-tree
##
## The spec leaves the seed to the validator and populates all 2**31 leaves.
## Devnet clients instead follow ethpandaops/eth-beacon-genesis@4566af0, which
## derives the seed from the validator's BLS secret key and populates the
## leaves of the first 2**20 slots only, keeping the tree cheap to build:
##
##   vrf_seed  = sha256("vrf-seed" || bls_sk)
##   leaf[i]   = keccak256(vrf_seed || uint64_le(i))   for i < 2**20
##   leaf[i]   = 0x00..00                              otherwise
##
## Only the roots of the 1024 subtrees of 1024 leaves, and the tree above them,
## are kept (64 KiB); a proof recomputes the one subtree it needs.

import
  stew/[byteutils, endians2],
  nimcrypto/[hash, keccak, sha2],
  ./digest

export digest

const
  VRF_TREE_DEPTH* = 31
  VRF_POPULATED_DEPTH* = 20
  VRF_POPULATED_LEAVES* = 1'u64 shl VRF_POPULATED_DEPTH
  VRF_SUBTREE_DEPTH = 10
  VRF_SUBTREE_LEAVES = 1 shl VRF_SUBTREE_DEPTH
  VRF_SUBTREE_COUNT = 1 shl (VRF_POPULATED_DEPTH - VRF_SUBTREE_DEPTH)

type
  VRFProofArray* = array[VRF_TREE_DEPTH + 1, Eth2Digest]

  VrfTree* = object
    seed: array[32, byte]
    upper: seq[seq[Eth2Digest]]
      ## upper[0]: the `VRF_SUBTREE_COUNT` subtree roots (level 10);
      ## upper[^1]: the root of the populated tree (level 20)
    zeros: array[VRF_TREE_DEPTH, Eth2Digest]
    root*: Eth2Digest

# https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/beacon-chain.md#new-keccak256
func keccak256(data: openArray[byte]): Eth2Digest =
  ## Return the Keccak-256 hash of ``data``. Private: `eth/common/hashes`
  ## exports a `keccak256` of its own.
  keccak.keccak256.digest(data)

func hashPair*(a, b: Eth2Digest): Eth2Digest =
  ## The parent of the VRF tree nodes ``a`` (left) and ``b`` (right).
  var buf {.noinit.}: array[64, byte]
  buf[0 ..< 32] = a.data
  buf[32 ..< 64] = b.data
  keccak256(buf)

func vrfSeed*(blsSecretKey: openArray[byte]): array[32, byte] =
  let digest = withEth2Hash:
    h.update("vrf-seed".toBytes)
    h.update(blsSecretKey)
  digest.data

# https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/validator.md#new-compute_vrf_leaf
func compute_vrf_leaf*(vrf_seed: array[32, byte], index: uint64): Eth2Digest =
  ## Return the leaf at ``index`` of the VRF tree derived from ``vrf_seed``.
  var buf {.noinit.}: array[40, byte]
  buf[0 ..< 32] = vrf_seed
  buf[32 ..< 40] = index.toBytesLE()
  keccak256(buf)

func vrfLeaf*(seed: array[32, byte], index: uint64): Eth2Digest =
  ## `compute_vrf_leaf` for the devnet tree, whose leaves above the first
  ## `VRF_POPULATED_LEAVES` are zero.
  if index >= VRF_POPULATED_LEAVES:
    return default(Eth2Digest)
  compute_vrf_leaf(seed, index)

func subtreeLayers(
    seed: array[32, byte], subtree: int): seq[seq[Eth2Digest]] =
  ## All layers of the subtree `subtree`: [0] its leaves, [^1] its root.
  var layers = newSeq[seq[Eth2Digest]](VRF_SUBTREE_DEPTH + 1)
  layers[0] = newSeq[Eth2Digest](VRF_SUBTREE_LEAVES)
  let start = uint64(subtree) * VRF_SUBTREE_LEAVES.uint64
  for i in 0 ..< VRF_SUBTREE_LEAVES:
    layers[0][i] = vrfLeaf(seed, start + i.uint64)
  for level in 1 .. VRF_SUBTREE_DEPTH:
    let prev = addr layers[level - 1]
    layers[level] = newSeq[Eth2Digest](prev[].len div 2)
    for i in 0 ..< layers[level].len:
      layers[level][i] = hashPair(prev[][2 * i], prev[][2 * i + 1])
  layers

func init*(T: type VrfTree, seed: array[32, byte]): VrfTree =
  ## Hashes every populated leaf once (about two million hashes).
  var res = VrfTree(seed: seed)
  for level in 1 ..< VRF_TREE_DEPTH:
    res.zeros[level] = hashPair(res.zeros[level - 1], res.zeros[level - 1])

  res.upper = newSeq[seq[Eth2Digest]](
    VRF_POPULATED_DEPTH - VRF_SUBTREE_DEPTH + 1)
  res.upper[0] = newSeq[Eth2Digest](VRF_SUBTREE_COUNT)
  for k in 0 ..< VRF_SUBTREE_COUNT:
    res.upper[0][k] = subtreeLayers(seed, k)[^1][0]
  for level in 1 ..< res.upper.len:
    let prev = addr res.upper[level - 1]
    res.upper[level] = newSeq[Eth2Digest](prev[].len div 2)
    for i in 0 ..< res.upper[level].len:
      res.upper[level][i] = hashPair(prev[][2 * i], prev[][2 * i + 1])

  var node = res.upper[^1][0]
  for level in VRF_POPULATED_DEPTH ..< VRF_TREE_DEPTH:
    node = hashPair(node, res.zeros[level])
  res.root = node
  res

func fromBlsSecretKey*(
    T: type VrfTree, blsSecretKey: openArray[byte]): VrfTree =
  VrfTree.init(vrfSeed(blsSecretKey))

func proof*(tree: VrfTree, index: uint64): VRFProofArray =
  ## The leaf at `index` followed by its Merkle branch, bottom up.
  doAssert index < (1'u64 shl VRF_TREE_DEPTH)
  var res: VRFProofArray
  res[0] = vrfLeaf(tree.seed, index)

  if index < VRF_POPULATED_LEAVES:
    let
      subtree = int(index shr VRF_SUBTREE_DEPTH)
      layers = subtreeLayers(tree.seed, subtree)
    var node = index and (VRF_SUBTREE_LEAVES.uint64 - 1)
    for level in 0 ..< VRF_SUBTREE_DEPTH:
      res[level + 1] = layers[level][int(node xor 1)]
      node = node shr 1
    node = uint64(subtree)
    for level in VRF_SUBTREE_DEPTH ..< VRF_POPULATED_DEPTH:
      res[level + 1] = tree.upper[level - VRF_SUBTREE_DEPTH][int(node xor 1)]
      node = node shr 1
    for level in VRF_POPULATED_DEPTH ..< VRF_TREE_DEPTH:
      # The populated tree is always the leftmost subtree here
      res[level + 1] = tree.zeros[level]
  else:
    var
      node = index
      first = tree.upper[^1][0]
    for level in 0 ..< VRF_TREE_DEPTH:
      let sibling = node xor 1
      res[level + 1] =
        if level >= VRF_POPULATED_DEPTH and sibling == 0:
          first
        else:
          tree.zeros[level]
      if level >= VRF_POPULATED_DEPTH:
        first = hashPair(first, tree.zeros[level])
      node = node shr 1
  res
