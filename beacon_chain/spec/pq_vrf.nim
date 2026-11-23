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
## Devnet clients follow ethpandaops/eth-beacon-genesis@ff42fce, which derives
## the seed from the validator's BLS secret key and populates all 2**31
## leaves:
##
##   vrf_seed  = sha256("vrf-seed" || bls_sk)
##   leaf[i]   = keccak256(vrf_seed || uint64_le(i))
##
## Hashing a whole tree takes about an hour of CPU time, so only the subtree
## of the first 2**20 slots is hashed here; the nodes above it on the path to
## the root come from a precomputed state (`VrfTreeState`). Of that subtree,
## the roots of the 1024 subtrees of 1024 leaves, and the tree above them,
## are kept (64 KiB); a proof recomputes the one subtree it needs.

import
  results,
  stew/[byteutils, endians2],
  nimcrypto/[hash, keccak, sha2],
  taskpools,
  ./digest

export digest, results, taskpools

const
  VRF_TREE_DEPTH* = 31
  VRF_POPULATED_DEPTH* = 20
  VRF_POPULATED_LEAVES* = 1'u64 shl VRF_POPULATED_DEPTH
  VRF_SUBTREE_DEPTH = 10
  VRF_SUBTREE_LEAVES = 1 shl VRF_SUBTREE_DEPTH
  VRF_SUBTREE_COUNT = 1 shl (VRF_POPULATED_DEPTH - VRF_SUBTREE_DEPTH)
  VRF_TREE_STATE_SIZE* = 32 + 4 + 32 * VRF_TREE_DEPTH

type
  VRFProofArray* = array[VRF_TREE_DEPTH + 1, Eth2Digest]

  VrfTree* = object
    seed: array[32, byte]
    upper: seq[seq[Eth2Digest]]
      ## upper[0]: the `VRF_SUBTREE_COUNT` subtree roots (level 10);
      ## upper[^1]: the root of the populated tree (level 20)
    siblings: array[VRF_TREE_DEPTH, Eth2Digest]
      ## From `VRF_POPULATED_DEPTH` up: the siblings of the populated subtree
      ## on its path to the root
    root*: Opt[Eth2Digest]
      ## Known once a `VrfTreeState` is loaded

  VrfTreeState* = object
    ## A VRF tree at slot 0: its root and the Merkle branch of leaf 0
    root*: Eth2Digest
    siblings*: array[VRF_TREE_DEPTH, Eth2Digest]

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

func subtreeLayers(
    seed: array[32, byte], subtree: int): seq[seq[Eth2Digest]] =
  ## All layers of the subtree `subtree`: [0] its leaves, [^1] its root.
  var layers = newSeq[seq[Eth2Digest]](VRF_SUBTREE_DEPTH + 1)
  layers[0] = newSeq[Eth2Digest](VRF_SUBTREE_LEAVES)
  let start = uint64(subtree) * VRF_SUBTREE_LEAVES.uint64
  for i in 0 ..< VRF_SUBTREE_LEAVES:
    layers[0][i] = compute_vrf_leaf(seed, start + i.uint64)
  for level in 1 .. VRF_SUBTREE_DEPTH:
    let prev = addr layers[level - 1]
    layers[level] = newSeq[Eth2Digest](prev[].len div 2)
    for i in 0 ..< layers[level].len:
      layers[level][i] = hashPair(prev[][2 * i], prev[][2 * i + 1])
  layers

func subtreeRoot(seed: array[32, byte], subtree: int): Eth2Digest =
  ## The root of the subtree `subtree`, hashed without heap allocations.
  var nodes {.noinit.}: array[VRF_SUBTREE_LEAVES, Eth2Digest]
  let start = uint64(subtree) * VRF_SUBTREE_LEAVES.uint64
  for i in 0 ..< VRF_SUBTREE_LEAVES:
    nodes[i] = compute_vrf_leaf(seed, start + i.uint64)
  var width = VRF_SUBTREE_LEAVES
  while width > 1:
    width = width div 2
    for i in 0 ..< width:
      nodes[i] = hashPair(nodes[2 * i], nodes[2 * i + 1])
  nodes[0]

func hashSubtreeRoots(
    seed: array[32, byte], roots: ptr UncheckedArray[Eth2Digest]) =
  for k in 0 ..< VRF_SUBTREE_COUNT:
    roots[k] = subtreeRoot(seed, k)

func prepare(T: type VrfTree, seed: array[32, byte]): VrfTree =
  var res = VrfTree(seed: seed)
  res.upper = newSeq[seq[Eth2Digest]](
    VRF_POPULATED_DEPTH - VRF_SUBTREE_DEPTH + 1)
  res.upper[0] = newSeq[Eth2Digest](VRF_SUBTREE_COUNT)
  res

func subtreeRoots(tree: var VrfTree): ptr UncheckedArray[Eth2Digest] =
  cast[ptr UncheckedArray[Eth2Digest]](addr tree.upper[0][0])

func hashUpper(tree: var VrfTree) =
  for level in 1 ..< tree.upper.len:
    let prev = addr tree.upper[level - 1]
    tree.upper[level] = newSeq[Eth2Digest](prev[].len div 2)
    for i in 0 ..< tree.upper[level].len:
      tree.upper[level][i] = hashPair(prev[][2 * i], prev[][2 * i + 1])

func init*(T: type VrfTree, seed: array[32, byte]): VrfTree =
  ## Hashes every leaf of the first `VRF_POPULATED_LEAVES` once (about two
  ## million hashes).
  var res = VrfTree.prepare(seed)
  hashSubtreeRoots(seed, res.subtreeRoots)
  res.hashUpper()
  res

proc subtreeRootsTask(
    seed: array[32, byte], roots: ptr UncheckedArray[Eth2Digest]): bool {.
    nimcall.} =
  # Task suitable for running in taskpools - look, no GC!
  hashSubtreeRoots(seed, roots)
  true

proc init*(
    T: type VrfTree, taskpool: Taskpool,
    seeds: openArray[array[32, byte]]): seq[VrfTree] =
  ## `VrfTree.init` of every seed, one task per tree on the threads of
  ## ``taskpool``. A task writes the 32 KiB of subtree roots its tree keeps.
  var
    res = newSeq[VrfTree](seeds.len)
    pending = newSeq[Flowvar[bool]](seeds.len)
  for i, seed in seeds:
    res[i] = VrfTree.prepare(seed)
    pending[i] = taskpool.spawn subtreeRootsTask(seed, res[i].subtreeRoots)
  for i in 0 ..< res.len:
    discard sync pending[i]
    res[i].hashUpper()
  res

func isInit*(tree: VrfTree): bool =
  tree.upper.len > 0

func fromBlsSecretKey*(
    T: type VrfTree, blsSecretKey: openArray[byte]): VrfTree =
  VrfTree.init(vrfSeed(blsSecretKey))

func init*(
    T: type VrfTreeState, data: openArray[byte],
    index: uint64): Opt[VrfTreeState] =
  ## The state of validator ``index`` in a file of `VRF_TREE_STATE_SIZE` bytes
  ## per validator index: the root, the leaf index as `uint32` and the branch
  ## of that leaf, bottom up. Only states at leaf 0 are accepted.
  if index >= uint64(data.len div VRF_TREE_STATE_SIZE):
    return Opt.none(VrfTreeState)
  let start = int(index) * VRF_TREE_STATE_SIZE
  for i in 32 ..< 36:
    if data[start + i] != 0:
      return Opt.none(VrfTreeState)
  var res: VrfTreeState
  res.root.data[0 ..< 32] = data.toOpenArray(start, start + 31)
  for level in 0 ..< VRF_TREE_DEPTH:
    let at = start + 36 + 32 * level
    res.siblings[level].data[0 ..< 32] = data.toOpenArray(at, at + 31)
  Opt.some res

func load*(tree: var VrfTree, state: VrfTreeState): bool =
  ## Take the nodes above the populated subtree from ``state``, which has to
  ## be the state of this tree: `false` when its root does not follow from
  ## the leaves hashed here.
  var node = tree.upper[^1][0]
  for level in VRF_POPULATED_DEPTH ..< VRF_TREE_DEPTH:
    node = hashPair(node, state.siblings[level])
  if node != state.root:
    return false
  tree.siblings = state.siblings
  tree.root = Opt.some state.root
  true

func proof*(tree: VrfTree, index: uint64): Opt[VRFProofArray] =
  ## The leaf at `index` followed by its Merkle branch, bottom up. Needs a
  ## loaded `VrfTreeState` and an `index` in the populated subtree.
  if tree.root.isNone or index >= VRF_POPULATED_LEAVES:
    return Opt.none(VRFProofArray)
  var res: VRFProofArray
  res[0] = compute_vrf_leaf(tree.seed, index)

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
    res[level + 1] = tree.siblings[level]
  Opt.some res
