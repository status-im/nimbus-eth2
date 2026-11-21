# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  stew/byteutils,
  ../beacon_chain/spec/xmss

# Vector from Lighthouse `beacon_node/genesis/src/pq.rs`, which matches
# ethpandaops/eth-beacon-genesis@284025a.
const
  blsSecret = "2892f3ba475c3640a67fe730798ad9c4eed3a6d934db85f91c41cfc837ce8834"
  expectedXmssPubkey =
    "0x155a29b971da2b771fdf52c768af63fa03f78f25487e3e0ed03d012b7039d88b"

suite "PQ leanXMSS":
  test "Key derivation matches ethpandaops genesis":
    let
      sk = hexToSeqByte(blsSecret)
      seed = toSha256Digest(@("leanxmss-seed".toBytes) & sk)
      key = newXMSSSecretKey(seed).expect("key")
    check key.pubkey.toHex() == expectedXmssPubkey

  test "Sign and verify":
    let
      key = newXMSSSecretKey(toSha256Digest("seed".toBytes)).expect("key")
      msg = toSha256Digest("message".toBytes)
      leaf = 32768'u64 + 5
    check key.prepare(leaf)
    let sig = key.sign(leaf, msg).expect("sig")
    check:
      sig.getLeafIndex() == leaf
      verify(key.pubkey, leaf, msg, sig)
      not verify(key.pubkey, leaf + 1, msg, sig)
      not verify(key.pubkey, leaf, toSha256Digest("other".toBytes), sig)

import ../beacon_chain/spec/pq_vrf

func opensVrfLeaf(proof: VRFProofArray, index: uint64, root: Eth2Digest): bool =
  ## The branch walk of `is_valid_vrf_proof`
  var value = proof[0]
  for height in 0 ..< VRF_TREE_DEPTH:
    value =
      if ((index shr height) and 1) != 0:
        hashPair(proof[height + 1], value)
      else:
        hashPair(value, proof[height + 1])
  value == root

const
  # eth-beacon-genesis@ff42fce: the nodes of the tree of `blsSecret` at index 1
  # of heights 20 to 30, and its root
  vrfUpperSiblings = [
    "306b0de68dfcc050300f87c40d4df7cbc01b2edb460a7059e22ee5118fb6f938",
    "b04d5364e390a5f2f01d2b920d860ab17944dc98fef7f097705d040bec57a998",
    "f3cde0565c176618f3f9efa93c45ffcf5d8410f6ebae92ea8245065239e0eca6",
    "2a4af9894e7b4d955ba33335ee880b468ab5fc7b147e1bdad062d671706e2684",
    "624e11f95724d80a542281b979c34b06479c606c01bdc5cdbeb298e4f1c2d38c",
    "b228f1392960980fda9654415586a62473b7ec2d96b74c02ddc5b69acd158b78",
    "16b6a77f15f5d99f76acd46e4f73157026eb81daa5995b3e94eb1a485122daec",
    "7f595a87eb53f0359a11e163af538a74ce0b505c865daf56dc46562b38abd0a8",
    "659ae3c303499a8afb799f2869a9e13f5d8667d5cb2ee06feafca8f94ef76ba9",
    "a910c4ceebe63cb21c4fd75a87cf547ecfbdd30516a71a47136f12d6051e9ddd",
    "844492a9139de1100d9e8d46e52326e9b4264c1a7492222111ca0a3f3cbcb3ab"]
  vrfRoot = "0de245dae044dff7cebd723582598a28e778a936246e7c5d976c9f3a1eacac81"

func vrfTreeState(): VrfTreeState =
  var res = VrfTreeState(root: Eth2Digest.fromHex(vrfRoot))
  for i, sibling in vrfUpperSiblings:
    res.siblings[VRF_POPULATED_DEPTH + i] = Eth2Digest.fromHex(sibling)
  res

suite "PQ VRF tree":
  test "VRF seed, leaf and root match ethpandaops genesis":
    # eth-beacon-genesis@ff42fce, `validators.VRFSeed/VRFLeaf/VRFRoot`
    let seed = vrfSeed(hexToSeqByte(blsSecret))
    var tree = VrfTree.init(seed)
    check:
      seed.toHex() ==
        "8b6fe7f8e9b2a6e0ebf8fd5a7b3991329affcd3ff91aec159d33e4b4dedac940"
      compute_vrf_leaf(seed, 0).data.toHex() ==
        "ad0efa4007355a8582ec38a5fb1c0aee0dd046cd48a66108d1c441b9093a5f9f"
      tree.root.isNone
      tree.proof(0).isNone
      tree.load(vrfTreeState())
      tree.root == Opt.some Eth2Digest.fromHex(vrfRoot)

  test "VRF tree rejects the state of another tree":
    var
      tree = VrfTree.fromBlsSecretKey(hexToSeqByte(blsSecret))
      state = vrfTreeState()
    state.siblings[VRF_TREE_DEPTH - 1].data[0] =
      state.siblings[VRF_TREE_DEPTH - 1].data[0] xor 1
    check:
      not tree.load(state)
      tree.root.isNone

  test "VRF proofs open their leaf":
    var tree = VrfTree.fromBlsSecretKey(hexToSeqByte(blsSecret))
    check tree.load(vrfTreeState())
    for index in [0'u64, 5, 1023, 1024, VRF_POPULATED_LEAVES - 1]:
      let proof = tree.proof(index).get
      check:
        proof[0] == compute_vrf_leaf(vrfSeed(hexToSeqByte(blsSecret)), index)
        opensVrfLeaf(proof, index, tree.root.get)
        not opensVrfLeaf(proof, index xor 1, tree.root.get)
    check:
      tree.proof(VRF_POPULATED_LEAVES).isNone
      tree.proof((1'u64 shl VRF_TREE_DEPTH) - 1).isNone

  test "VRF tree states are read by validator index":
    var tree = VrfTree.fromBlsSecretKey(hexToSeqByte(blsSecret))
    check tree.load(vrfTreeState())
    let proof = tree.proof(0).get
    var data = newSeq[byte](2 * VRF_TREE_STATE_SIZE)
    data[VRF_TREE_STATE_SIZE ..< VRF_TREE_STATE_SIZE + 32] = tree.root.get.data
    for level in 0 ..< VRF_TREE_DEPTH:
      let at = VRF_TREE_STATE_SIZE + 36 + 32 * level
      data[at ..< at + 32] = proof[level + 1].data
    let state = VrfTreeState.init(data, 1).get
    var other = VrfTree.fromBlsSecretKey(hexToSeqByte(blsSecret))
    check:
      state.root == tree.root.get
      other.load(state)
      not other.load(VrfTreeState.init(data, 0).get)
      VrfTreeState.init(data, 2).isNone
    data[VRF_TREE_STATE_SIZE + 32] = 1
    check VrfTreeState.init(data, 1).isNone

import std/os, chronos, ../beacon_chain/spec/pq_stark

proc starkFixtures(): auto =
  let
    keys = newXMSSSecretKeys([toSha256Digest("a".toBytes),
                              toSha256Digest("b".toBytes)])
    k0 = keys[0].get
    k1 = keys[1].get
    leaf = 32768'u64 + 7
    msgA = Eth2Digest(data: toSha256Digest("msgA".toBytes))
    msgB = Eth2Digest(data: toSha256Digest("msgB".toBytes))
  discard k0.prepare(leaf)
  discard k1.prepare(leaf)
  (XMSSAggregateStatement(pubkeys: @[k0.pubkey, k1.pubkey],
                          leaf_index: leaf, message: msgA),
   XMSSAggregateStatement(pubkeys: @[k1.pubkey], leaf_index: leaf, message: msgB),
   @[k0.sign(leaf, msgA.data).get, k1.sign(leaf, msgA.data).get],
   @[k1.sign(leaf, msgB.data).get])

suite "PQ STARK backends":
  for kind in [StarkBackendKind.Reference, StarkBackendKind.Sidecar]:
    test "Prove, verify and merge: " & $kind:
      if kind == StarkBackendKind.Sidecar and
          getEnv("PQ_SIDECAR_SOCKET").len == 0:
        skip()
      else:
        let (stA, stB, sigsA, sigsB) = starkFixtures()
        configureStark(StarkConfig(
          kind: kind, socketPath: getEnv("PQ_SIDECAR_SOCKET"),
          logInvRate: DefaultLogInvRate, verifyTimeoutMs: 30_000,
          proveTimeout: 300.seconds))
        let
          pA = waitFor(proveAggregates(@[stA], @[sigsA])).expect("proof A")
          pB = waitFor(proveAggregates(@[stB], @[sigsB])).expect("proof B")
        check:
          verifyAggregates([stA], pA)
          verifyAggregates([stB], pB)
          not verifyAggregates([stB], pA)
          verifyAggregates([], [])
        let merged = waitFor(mergeProofs(@[(@[stA], pA), (@[stB], pB)])).expect("merge")
        check:
          verifyAggregates([stA, stB], merged)
          not verifyAggregates([stA], merged)
