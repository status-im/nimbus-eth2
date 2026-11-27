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
  chronos, taskpools,
  stew/byteutils,
  ../beacon_chain/spec/xmss

# Vector of the genesis tooling of the PQ devnet,
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

  test "Public parameter is the second half of the public key":
    let
      seed = toSha256Digest("seed".toBytes)
      key = newXMSSSecretKey(seed).expect("key")
    check:
      xmssPublicParam(seed) == Opt.some(key.pubkey.publicParam)
      xmssPublicParam(toSha256Digest("other".toBytes)) !=
        Opt.some(key.pubkey.publicParam)
      xmssPublicParam(seed.toOpenArray(0, 30)).isNone

  test "Key loads from its tree cache":
    let
      seed = toSha256Digest("seed".toBytes)
      key = newXMSSSecretKey(seed).expect("key")
      msg = toSha256Digest("message".toBytes)
      attestationLeaf = 7'u64
      slotLeaf = 24576'u64 * 65536 + 3
    check:
      key.treeCache().len == XMSS_CACHED_TOP_TREE_SIZE
      key.prepare(attestationLeaf)
      key.prepare(slotLeaf)
    let cache = key.treeCache()
    # The layout of the files of `--xmss-cache-url`
    check cache.len ==
      XMSS_CACHED_TOP_TREE_SIZE + 2 * XMSS_CACHED_BOTTOM_TREE_SIZE

    let loaded = newXMSSSecretKey(seed, key.pubkey, cache).expect("loaded")
    check loaded.pubkey == key.pubkey
    for leaf in [attestationLeaf, slotLeaf]:
      let sig = loaded.sign(leaf, msg).expect("sig")
      check:
        verify(key.pubkey, leaf, msg, sig)
        # A loaded key signs as the key it was saved from
        sig == key.sign(leaf, msg).expect("sig")

    # A key of the top tree alone builds its bottom trees
    let topOnly = newXMSSSecretKey(
      seed, key.pubkey,
      cache.toOpenArray(0, XMSS_CACHED_TOP_TREE_SIZE - 1)).expect("top only")
    check verify(
      key.pubkey, attestationLeaf, msg,
      topOnly.sign(attestationLeaf, msg).expect("sig"))

  test "Signing in a thread gives the same signatures":
    let
      key = newXMSSSecretKey(toSha256Digest("seed".toBytes)).expect("key")
      msg = toSha256Digest("message".toBytes)
    var taskpool = Taskpool.new(numThreads = 3)
    check key.prepare(7)
    var futures: seq[Future[Opt[XMSSSignature]].Raising([CancelledError])]
    for leaf in 0'u64 ..< 6:
      futures.add key.signAsync(leaf, msg, taskpool)
    for leaf in 0'u64 ..< 6:
      let sig = waitFor(futures[leaf]).expect("sig")
      check:
        verify(key.pubkey, leaf, msg, sig)
        sig == key.sign(leaf, msg).expect("sig")
    check:
      # Beyond the leaves of a key
      waitFor(key.signAsync(1'u64 shl 32, msg, taskpool)).isNone
      # Without a thread to spare, in place
      waitFor(key.signAsync(9, msg, nil)) == key.sign(9, msg)
    taskpool.shutdown()

  test "Trees built in the background are those built in place":
    let
      seeds = [toSha256Digest("one".toBytes), toSha256Digest("two".toBytes)]
      msg = toSha256Digest("message".toBytes)
      # The first leaf of the second tree of slot leaves, at slot 4096
      leaf = (1'u64 shl 15) + (1'u64 shl 29) + (1'u64 shl 30) + 4096 * 8
    var keys: seq[XMSSSecretKeyRef]
    for seed in seeds:
      keys.add newXMSSSecretKey(seed).expect("key")
    check:
      bottomTree(leaf) == bottomTree(leaf - 1) + 1
      bottomTree(leaf) == bottomTree(leaf + 8192 * 8 - 1)
      keys[0].treeCache().len == XMSS_CACHED_TOP_TREE_SIZE
      waitFor(prepareManyAsync(keys, @[leaf, leaf], 2)) == Opt.some 2
      # Built and kept: the cache has the tree
      keys[0].treeCache().len ==
        XMSS_CACHED_TOP_TREE_SIZE + XMSS_CACHED_BOTTOM_TREE_SIZE
      keys[1].treeCache().len ==
        XMSS_CACHED_TOP_TREE_SIZE + XMSS_CACHED_BOTTOM_TREE_SIZE
      # A leaf beyond a key is skipped, nothing to build is not an error
      waitFor(prepareManyAsync(keys, @[1'u64 shl 32, leaf], 1)) == Opt.some 1
      waitFor(prepareManyAsync(
        default(seq[XMSSSecretKeyRef]), default(seq[uint64]), 1)) ==
          Opt.some 0
    for i, key in keys:
      let
        sig = key.sign(leaf + 3, msg).expect("sig")
        inPlace = newXMSSSecretKey(seeds[i]).expect("key")
      check:
        verify(key.pubkey, leaf + 3, msg, sig)
        sig == inPlace.sign(leaf + 3, msg).expect("sig")

  test "Tree cache of another key is refused":
    let
      seed = toSha256Digest("seed".toBytes)
      otherSeed = toSha256Digest("other".toBytes)
      key = newXMSSSecretKey(seed).expect("key")
      other = newXMSSSecretKey(otherSeed).expect("other")
    check key.prepare(7)
    var cache = key.treeCache()
    check:
      newXMSSSecretKey(otherSeed, other.pubkey, cache).isNone
      newXMSSSecretKey(otherSeed, key.pubkey, cache).isNone
      newXMSSSecretKey(seed, other.pubkey, cache).isNone
      # Truncated
      newXMSSSecretKey(
        seed, key.pubkey, cache.toOpenArray(0, cache.len - 2)).isNone
      newXMSSSecretKey(seed, key.pubkey, default(seq[byte])).isNone
    # A damaged top tree, and a damaged bottom tree
    cache[100] = cache[100] xor 1
    check newXMSSSecretKey(seed, key.pubkey, cache).isNone
    cache[100] = cache[100] xor 1
    cache[^1] = cache[^1] xor 1
    check newXMSSSecretKey(seed, key.pubkey, cache).isNone
    cache[^1] = cache[^1] xor 1
    check newXMSSSecretKey(seed, key.pubkey, cache).isSome

import ../beacon_chain/spec/pq_vrf

func opensVrfLeaf(proof: VRFProofArray, index: uint64, root: Eth2Digest): bool =
  ## The branch walk of `is_valid_vrf_proof`
  var value = compute_vrf_leaf(proof[0], index)
  for height in 0 ..< VRF_TREE_DEPTH:
    value =
      if ((index shr height) and 1) != 0:
        hashPair(proof[height + 1], value)
      else:
        hashPair(value, proof[height + 1])
  value == root

const
  # Validator 0 of the mnemonic that devnet tooling defaults to, and from the
  # file of its VRF tree states (eth-beacon-genesis@d1a8253d): the nodes of
  # its tree at index 1 of heights 20 to 30, and its root
  vrfBlsSecret =
    "0dce41fa73ae9f6bdfd51df4d422d75eee174553dba5fd450c4437e4ed3fc903"
  vrfUpperSiblings = [
    "46386632eaeef21168ec0c5d9903a2230e4dcf65937d206cd4af34ba09bc2c34",
    "aa9f0181ab56e376883f2b54cb9b9b936fef369063574da4db74a7777fd9cbf9",
    "3276c74b9dcbe2e137b58e96ee127c6fb2853b2f644394e2944e2347c6cf4c69",
    "ab1b1ecada4971322ee6099d8ea9030b0e38b5a6b1e6f0027ac0ecd98a8cbdba",
    "446d941faa412f0418b74cbdd05504164231b55a0b67ca604c9240e6a69c3894",
    "bcc260fc1c13b8894e9174a5d6e694df79fbda97d0b62ac880b92353de0edb95",
    "1b8e0a58439148e95ad661d98b259ae6a4d82e72f25e58354b8bc43e4745021c",
    "8fb4faa40822d3e4b449322eed3c51c3ae855f6ed915b0b8429a061fc755ce37",
    "12601a539f32b1e0c338b4db274a153526a7fb5c679f9ba6b4335bb692c9e49d",
    "5a56b174ccd3cdc9249196c31edc4ca29266434a5c7d965ae62bea4db9c61f24",
    "502b4f387e8f70dff47cc45d63b467a15588d541198698288299be769c02d0ad"]
  vrfRoot = "75d1866ec07565ce2f2e3d0e368fe0193f868f326f5c469698c4a6e1e70575a7"

func vrfTreeState(): VrfTreeState =
  var res = VrfTreeState(root: Eth2Digest.fromHex(vrfRoot))
  for i, sibling in vrfUpperSiblings:
    res.siblings[VRF_POPULATED_DEPTH + i] = Eth2Digest.fromHex(sibling)
  res

suite "PQ VRF tree":
  test "VRF seed, leaf and root match ethpandaops genesis":
    let seed = vrfSeed(hexToSeqByte(vrfBlsSecret))
    var tree = VrfTree.init(seed)
    check:
      seed.toHex() ==
        "543fc5a4d86e79a434e9741770f7ee17c25bdc31be8d61436d7f9836538b03df"
      compute_vrf_secret(seed, 0).data.toHex() ==
        "605fd4483203e398b3b57eb88f85310d1c29a96be6e420127491acc6953ea063"
      vrfLeaf(seed, 0).data.toHex() ==
        "242966124aab6d1ea65f9661538ea3b66a5f55ca020b2b5eaeab5eb3de9837de"
      # The file of VRF tree states has it as the sibling of leaf 0
      vrfLeaf(seed, 1).data.toHex() ==
        "60961f9391410c89b136d976b68d1c6818c1fce2f5189e2d7dbad4b4b31b73d2"
      tree.root.isNone
      tree.proof(0).isNone
      tree.load(vrfTreeState())
      tree.root == Opt.some Eth2Digest.fromHex(vrfRoot)

  test "VRF tree rejects the state of another tree":
    var
      tree = VrfTree.fromBlsSecretKey(hexToSeqByte(vrfBlsSecret))
      state = vrfTreeState()
    state.siblings[VRF_TREE_DEPTH - 1].data[0] =
      state.siblings[VRF_TREE_DEPTH - 1].data[0] xor 1
    check:
      not tree.load(state)
      tree.root.isNone

  test "VRF proofs reveal the secret their leaf commits to":
    var tree = VrfTree.fromBlsSecretKey(hexToSeqByte(vrfBlsSecret))
    check tree.load(vrfTreeState())
    for index in [0'u64, 5, 1023, 1024, VRF_POPULATED_LEAVES - 1]:
      let proof = tree.proof(index).get
      check:
        proof[0] ==
          compute_vrf_secret(vrfSeed(hexToSeqByte(vrfBlsSecret)), index)
        # The branch holds commitments: the leaf beside this one, not its
        # secret
        proof[1] == vrfLeaf(vrfSeed(hexToSeqByte(vrfBlsSecret)), index xor 1)
        opensVrfLeaf(proof, index, tree.root.get)
        not opensVrfLeaf(proof, index xor 1, tree.root.get)
    check:
      tree.proof(VRF_POPULATED_LEAVES).isNone
      tree.proof((1'u64 shl VRF_TREE_DEPTH) - 1).isNone

  test "VRF trees hashed in a batch are the same trees":
    let
      seeds = [
        vrfSeed(hexToSeqByte(vrfBlsSecret)), toSha256Digest("other".toBytes)]
      roots = vrfSubtreeRoots(seeds, VRF_SUBTREE_COUNT, threads = 2)
    check:
      roots.len == 2
      roots[0].len == VRF_SUBTREE_ROOTS_SIZE
      roots[1].len == VRF_SUBTREE_ROOTS_SIZE
      roots[0] != roots[1]
      vrfSubtreeRoots(default(seq[array[32, byte]]), VRF_SUBTREE_COUNT).len == 0
    var
      tree = VrfTree.init(seeds[0], roots[0])
      hashedHere = VrfTree.init(seeds[0])
      other = VrfTree.init(seeds[0], roots[1])
    check:
      tree.load(vrfTreeState())
      hashedHere.load(vrfTreeState())
      tree.root == Opt.some Eth2Digest.fromHex(vrfRoot)
      # Roots of another tree do not lead to this tree's root
      not other.load(vrfTreeState())
    for index in [0'u64, 1023, 1024, VRF_POPULATED_LEAVES - 1]:
      check tree.proof(index) == hashedHere.proof(index)
    # Every tree of the batch, not only the first
    let
      second = VrfTree.init(seeds[1], roots[1])
      secondHashedHere = VrfTree.init(seeds[1])
    for index in [0'u64, 1023, 1024, 524288, VRF_POPULATED_LEAVES - 1]:
      check second.proof(index) == secondHashedHere.proof(index)

  test "VRF tree states are read by validator index":
    var tree = VrfTree.fromBlsSecretKey(hexToSeqByte(vrfBlsSecret))
    check tree.load(vrfTreeState())
    let proof = tree.proof(0).get
    var data = newSeq[byte](2 * VRF_TREE_STATE_SIZE)
    data[VRF_TREE_STATE_SIZE ..< VRF_TREE_STATE_SIZE + 32] = tree.root.get.data
    for level in 0 ..< VRF_TREE_DEPTH:
      let at = VRF_TREE_STATE_SIZE + 36 + 32 * level
      data[at ..< at + 32] = proof[level + 1].data
    let state = VrfTreeState.init(data, 1).get
    var other = VrfTree.fromBlsSecretKey(hexToSeqByte(vrfBlsSecret))
    check:
      state.root == tree.root.get
      other.load(state)
      not other.load(VrfTreeState.init(data, 0).get)
      VrfTreeState.init(data, 2).isNone
    data[VRF_TREE_STATE_SIZE + 32] = 1
    check VrfTreeState.init(data, 1).isNone

import ../beacon_chain/spec/beaconstate

suite "PQ legacy keys":
  test "Keys of validators that did not register are derived with keccak256":
    # A BLS public key of 48 bytes of 9, and what `keccak256` makes of it
    # with the domain byte of each key appended
    var pubkey: ValidatorPubKey
    for i in 0 ..< pubkey.blob.len:
      pubkey.blob[i] = 9
    check:
      compute_legacy_xmss_pubkey(pubkey).toHex() ==
        "0xa1fc67d0715e7a9d5ef9500cb48db0a97e6ea75ae0f415534ac6278103275930"
      compute_legacy_vrf_root(pubkey).data.toHex() ==
        "90ed2a255339d9034607dd7db88e076707bd8e4f1362f17d2f8a931a012b9e1e"
      is_legacy_pubkey(pubkey)
      compute_deposit_pubkey(pubkey) == compute_legacy_xmss_pubkey(pubkey)

suite "PQ committees":
  test "The committee count per slot follows the cap of the network":
    var cfg = defaultRuntimeConfig
    let validators = 4'u64 * SLOTS_PER_EPOCH * TARGET_COMMITTEE_SIZE
    check:
      cfg.X_MAX_COMMITTEE_COUNT_PER_SLOT == MAX_COMMITTEES_PER_SLOT_PQ
      committeeCountPerSlotPq(validators) == 4
    cfg.X_MAX_COMMITTEE_COUNT_PER_SLOT = 1
    setXMaxCommitteeCountPerSlot(cfg)
    check:
      committeeCountPerSlotPq(validators) == 1
      get_committee_count_per_slot(ConsensusFork.Pq, validators) == 1
      get_committee_count_per_slot(ConsensusFork.Gloas, validators) == 4
    setXMaxCommitteeCountPerSlot(defaultRuntimeConfig)
    check committeeCountPerSlotPq(validators) == 4

import ../beacon_chain/spec/pq_stark

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
  for kind in [StarkBackendKind.Reference, StarkBackendKind.LeanVM]:
    test "Prove, verify and merge: " & $kind:
      block:
        let (stA, stB, sigsA, sigsB) = starkFixtures()
        check configureStark(StarkConfig(
          kind: kind, logInvRate: DefaultLogInvRate)).isOk
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
        # The tests that follow prove nothing with leanVM
        check configureStark(StarkConfig(
          kind: StarkBackendKind.Reference,
          logInvRate: DefaultLogInvRate)).isOk
