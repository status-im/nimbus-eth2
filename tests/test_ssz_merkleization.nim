import
  std/[strutils, sequtils, macros, bitops],
  stew/[bitops2, endians2],
  ../beacon_chain/spec/[beaconstate, datatypes, digest, helpers],
  ../beacon_chain/[ssz, merkle_minimal],
  mocking/mock_deposits

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
                a, tree.getMerkleProof(index = index),
                depth = `depth`,
                index = index.uint64,
                root = root
              ), "Failed (depth: " & $`depth` &
                ", nleaves: " & $`nleaves` & ')'

            block: # proof for b
              let index = 1

              doAssert is_valid_merkle_branch(
                b, tree.getMerkleProof(index = index),
                depth = `depth`,
                index = index.uint64,
                root = root
              ), "Failed (depth: " & $`depth` &
                ", nleaves: " & $`nleaves` & ')'

            block: # proof for c
              let index = 2

              doAssert is_valid_merkle_branch(
                c, tree.getMerkleProof(index = index),
                depth = `depth`,
                index = index.uint64,
                root = root
              ), "Failed (depth: " & $`depth` &
                ", nleaves: " & $`nleaves` & ')'

    roundTrips()
    true

doAssert testMerkleMinimal()

let
  digests = mapIt(1..65, eth2digest toBytesLE(uint64 it))

proc compareTreeVsMerkleizer(hashes: openarray[Eth2Digest], limit: static Limit) =
  const treeHeight = binaryTreeHeight(limit)
  let tree = merkleTreeFromLeaves(hashes, treeHeight)

  var merkleizer = createMerkleizer(limit)
  for hash in hashes:
    merkleizer.addChunk hash.data

  doAssert merkleizer.getFinalHash() == tree.nnznodes[treeHeight - 1][0]

proc testMultiProofsGeneration(preludeRecords: int,
                               totalProofs: int,
                               followUpRecords: int,
                               limit: static Limit) =
  var
    m1 = createMerkleizer(limit)
    m2 = createMerkleizer(limit)

  var preludeHashes = newSeq[Eth2Digest]()
  for i in 0 ..< preludeRecords:
    let hash = eth2digest toBytesLE(uint64(100000000 + i))
    m1.addChunk hash.data
    m2.addChunk hash.data
    preludeHashes.add hash

  var proofsHashes = newSeq[Eth2Digest]()
  for i in 0 ..< totalProofs:
    let hash = eth2digest toBytesLE(uint64(200000000 + i))
    m1.addChunk hash.data
    proofsHashes.add hash

  var proofs = addChunksAndGenMerkleProofs(m2, proofsHashes)

  const treeHeight = binaryTreeHeight(limit)
  let merkleTree = merkleTreeFromLeaves(preludeHashes & proofsHashes,
                                        treeHeight)

  doAssert m1.getFinalHash == merkleTree.nnznodes[treeHeight - 1][0]
  doAssert m1.getFinalHash == m2.getFinalHash

  for i in 0 ..< totalProofs:
    let
      referenceProof = merkle_tree.getMerkleProof(preludeRecords + i, false)
      startPos = i * treeHeight
      endPos = startPos + treeHeight - 1

    doAssert referenceProof == proofs.toOpenArray(startPos, endPos)

  for i in 0 ..< followUpRecords:
    let hash = eth2digest toBytesLE(uint64(300000000 + i))
    m1.addChunk hash.data
    m2.addChunk hash.data

    doAssert m1.getFinalHash == m2.getFinalHash

for prelude in [0, 1, 2, 5, 6, 12, 13, 16]:
  for proofs in [1, 2, 4, 17, 64]:
    for followUpHashes in [0, 1, 2, 5, 7, 8, 15, 48]:
      testMultiProofsGeneration(prelude, proofs, followUpHashes, 128)
      testMultiProofsGeneration(prelude, proofs, followUpHashes, 5000)

func attachMerkleProofsReferenceImpl(deposits: var openarray[Deposit]) =
  let
    deposit_data_roots = mapIt(deposits, it.data.hash_tree_root)
    merkle_tree = merkleTreeFromLeaves(deposit_data_roots)
  var
    deposit_data_sums: seq[Eth2Digest]
  for prefix_root in hash_tree_roots_prefix(
      deposit_data_roots, 1'i64 shl DEPOSIT_CONTRACT_TREE_DEPTH):
    deposit_data_sums.add prefix_root

  for val_idx in 0 ..< deposits.len:
    deposits[val_idx].proof[0..31] = merkle_tree.getMerkleProof(val_idx, true)
    deposits[val_idx].proof[32].data[0..7] = uint_to_bytes8((val_idx + 1).uint64)

    doAssert is_valid_merkle_branch(
      deposit_data_roots[val_idx], deposits[val_idx].proof,
      DEPOSIT_CONTRACT_TREE_DEPTH + 1, val_idx.uint64,
      deposit_data_sums[val_idx])

proc testMerkleizer =
  for i in 0 ..< digests.len:
    compareTreeVsMerkleizer(digests.toOpenArray(0, i), 128)
    compareTreeVsMerkleizer(digests.toOpenArray(0, i), 5000)

  var deposits = mockGenesisBalancedDeposits(65, 100000)
  var depositsCopy = deposits

  attachMerkleProofsReferenceImpl(deposits)
  attachMerkleProofs(depositsCopy)

  for i in 0 ..< deposits.len:
    doAssert deposits[i].proof == depositsCopy[i].proof

testMerkleizer()

