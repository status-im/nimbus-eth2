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
## `keccak256`, with one leaf for each slot. A validator has a secret for each
## slot, and the leaf of the slot commits to it:
##
##   secret[i] = keccak256("VRF_SECRET" || vrf_seed || uint64_le(i))
##   leaf[i]   = keccak256("VRF_LEAF" || secret[i] || uint64_le(i))
##
## A proof reveals the secret of its slot, followed by the branch of the leaf,
## which holds commitments only.
##
## https://github.com/ethereum/consensus-specs/blob/4c296784bb6ff54cbdcf72ebdda2a1057cce8893/specs/_features/pq/validator.md#vrf-tree
##
## Devnet clients follow ethpandaops/eth-beacon-genesis@d1a8253d, which derives
## the seed from the validator's BLS secret key and populates all 2**31
## leaves:
##
##   vrf_seed  = sha256("vrf-seed" || bls_sk)
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
  ./digest

export digest, results

const
  VRF_TREE_DEPTH* = 31
  VRF_POPULATED_DEPTH* = 20
  VRF_POPULATED_LEAVES* = 1'u64 shl VRF_POPULATED_DEPTH
  VRF_SUBTREE_DEPTH = 10
  VRF_SUBTREE_LEAVES = 1 shl VRF_SUBTREE_DEPTH
  VRF_SUBTREE_COUNT* = 1 shl (VRF_POPULATED_DEPTH - VRF_SUBTREE_DEPTH)
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

# https://github.com/ethereum/consensus-specs/blob/4c296784bb6ff54cbdcf72ebdda2a1057cce8893/specs/_features/pq/beacon-chain.md#new-keccak256
func keccak256(data: openArray[byte]): Eth2Digest =
  ## Return the Keccak-256 hash of ``data``. Private: `eth/common/hashes`
  ## exports a `keccak256` of its own.
  keccak.keccak256.digest(data)

func keccak256Hash*(data: openArray[byte]): Eth2Digest =
  ## `keccak256(data)`, under a name that no other module exports.
  keccak256(data)

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

const
  VRF_SECRET_DOMAIN = "VRF_SECRET"
  VRF_LEAF_DOMAIN = "VRF_LEAF"

# https://github.com/ethereum/consensus-specs/blob/4c296784bb6ff54cbdcf72ebdda2a1057cce8893/specs/_features/pq/validator.md#new-compute_vrf_secret
func compute_vrf_secret*(
    vrf_seed: array[32, byte], index: uint64): Eth2Digest =
  ## Return the secret for ``index`` of the VRF tree derived from ``vrf_seed``.
  var buf {.noinit.}: array[VRF_SECRET_DOMAIN.len + 32 + 8, byte]
  buf[0 ..< VRF_SECRET_DOMAIN.len] = VRF_SECRET_DOMAIN.toBytes()
  buf[VRF_SECRET_DOMAIN.len ..< VRF_SECRET_DOMAIN.len + 32] = vrf_seed
  buf[VRF_SECRET_DOMAIN.len + 32 ..< buf.len] = index.toBytesLE()
  keccak256(buf)

# https://github.com/ethereum/consensus-specs/blob/4c296784bb6ff54cbdcf72ebdda2a1057cce8893/specs/_features/pq/beacon-chain.md#new-compute_vrf_leaf
func compute_vrf_leaf*(secret: Eth2Digest, index: uint64): Eth2Digest =
  ## Return the leaf at ``index`` of a VRF tree, which commits to ``secret``.
  var buf {.noinit.}: array[VRF_LEAF_DOMAIN.len + 32 + 8, byte]
  buf[0 ..< VRF_LEAF_DOMAIN.len] = VRF_LEAF_DOMAIN.toBytes()
  buf[VRF_LEAF_DOMAIN.len ..< VRF_LEAF_DOMAIN.len + 32] = secret.data
  buf[VRF_LEAF_DOMAIN.len + 32 ..< buf.len] = index.toBytesLE()
  keccak256(buf)

func vrfLeaf*(vrf_seed: array[32, byte], index: uint64): Eth2Digest =
  ## The leaf at ``index`` of the VRF tree derived from ``vrf_seed``.
  compute_vrf_leaf(compute_vrf_secret(vrf_seed, index), index)

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

const VRF_SUBTREE_ROOTS_SIZE* = 32 * VRF_SUBTREE_COUNT
  ## The roots of the subtrees of the populated part of a tree, in bytes

func init*(
    T: type VrfTree, seed: array[32, byte],
    subtreeRoots: openArray[byte] = []): VrfTree =
  ## Hashes every leaf of the first `VRF_POPULATED_LEAVES` once (about two
  ## million hashes), unless ``subtreeRoots`` holds the
  ## `VRF_SUBTREE_ROOTS_SIZE` bytes of the roots of the tree's subtrees of
  ## `VRF_SUBTREE_LEAVES` leaves, hashed elsewhere.
  var res = VrfTree(seed: seed)
  res.upper = newSeq[seq[Eth2Digest]](
    VRF_POPULATED_DEPTH - VRF_SUBTREE_DEPTH + 1)
  res.upper[0] = newSeq[Eth2Digest](VRF_SUBTREE_COUNT)
  for k in 0 ..< VRF_SUBTREE_COUNT:
    if subtreeRoots.len == VRF_SUBTREE_ROOTS_SIZE:
      res.upper[0][k].data[0 ..< 32] =
        subtreeRoots.toOpenArray(32 * k, 32 * k + 31)
    else:
      res.upper[0][k] = subtreeLayers(seed, k)[^1][0]
  for level in 1 ..< res.upper.len:
    let prev = addr res.upper[level - 1]
    res.upper[level] = newSeq[Eth2Digest](prev[].len div 2)
    for i in 0 ..< res.upper[level].len:
      res.upper[level][i] = hashPair(prev[][2 * i], prev[][2 * i + 1])
  res

func subtreeRoots*(tree: VrfTree): seq[byte] =
  ## The `VRF_SUBTREE_ROOTS_SIZE` bytes of the roots of the subtrees of
  ## `VRF_SUBTREE_LEAVES` leaves of ``tree``, which `init` takes in place of
  ## hashing them again. They hold no secret: a proof reveals such nodes.
  var res = newSeqOfCap[byte](VRF_SUBTREE_ROOTS_SIZE)
  if tree.upper.len > 0:
    for root in tree.upper[0]:
      res.add root.data
  res

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
  ## The secret for `index` followed by the Merkle branch of the leaf at
  ## `index`, bottom up. Needs a loaded `VrfTreeState` and an `index` in the
  ## populated subtree.
  if tree.root.isNone or index >= VRF_POPULATED_LEAVES:
    return Opt.none(VRFProofArray)
  var res: VRFProofArray
  res[0] = compute_vrf_secret(tree.seed, index)

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
