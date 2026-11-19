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

import ssz_serialization/proofs, ../beacon_chain/spec/pq_vrf

suite "PQ VRF tree":
  test "VRF root and proofs match ethpandaops genesis":
    let tree = VrfTree.fromBlsSecretKey(hexToSeqByte(blsSecret))
    check tree.root.data.toHex() ==
      "0fc00857fdae6d29c18f54563c64e166b1fff1c6d943bb2c43e8b096bb60585e"
    for index in [0'u64, 5, 1023, 1024, VRF_POPULATED_LEAVES - 1,
                  VRF_POPULATED_LEAVES, (1'u64 shl VRF_TREE_DEPTH) - 1]:
      let proof = tree.proof(index)
      check:
        proof[0].isZero == (index >= VRF_POPULATED_LEAVES)
        is_valid_merkle_branch(
          proof[0], proof.toOpenArray(1, VRF_TREE_DEPTH), VRF_TREE_DEPTH,
          index, tree.root)
        not is_valid_merkle_branch(
          proof[0], proof.toOpenArray(1, VRF_TREE_DEPTH), VRF_TREE_DEPTH,
          index xor 1, tree.root) or proof[0] == proof[1]

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
