# beacon_chain
# Copyright (c) 2018, 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  sequtils,
  # Status libraries
  stew/bitops2,
  # Beacon chain internals
  ../beacon_chain/spec/[forks, helpers, state_transition],
  # Test utilities
  ./unittest2, mocking/mock_genesis

suite "Spec helpers":
  test "integer_squareroot":
    check:
      integer_squareroot(0'u64) == 0'u64
      integer_squareroot(1'u64) == 1'u64
      integer_squareroot(2'u64) == 1'u64
      integer_squareroot(3'u64) == 1'u64
      integer_squareroot(4'u64) == 2'u64
      integer_squareroot(5'u64) == 2'u64

  test "build_proof - BeaconState":
    var
      forked = newClone(initGenesisState())
      cache = StateCache()
      info = ForkedEpochInfo()
    process_slots(
      defaultRuntimeConfig, forked[], Slot(100), cache, info,
      flags = {}).expect("no failure")

    let
      state = forked[].phase0Data.data
      root = state.hash_tree_root()

    func numLeaves(obj: object): GeneralizedIndex =
      nextPow2(typeof(obj).totalSerializedFields.uint64).GeneralizedIndex

    proc process(anchor: object, index: GeneralizedIndex) =
      var i = index
      anchor.enumInstanceSerializedFields(fieldNameVar, fieldVar):
        let depth = log2trunc(i)
        var proof = newSeq[Eth2Digest](depth)
        build_proof(state, i, proof)
        check: is_valid_merkle_branch(hash_tree_root(fieldVar), proof,
                                      depth, get_subtree_index(i), root)
        when fieldVar is object and not (fieldVar is Eth2Digest):
          let
            numChildLeaves = fieldVar.numLeaves
            childDepth = log2trunc(numChildLeaves)
          process(fieldVar, i shl childDepth)
        i += 1
    process(state, state.numLeaves)

  test "get_branch_indices":
    check:
      toSeq(get_branch_indices(1.GeneralizedIndex)) == []
      toSeq(get_branch_indices(0b101010.GeneralizedIndex)) ==
        [
          0b101011.GeneralizedIndex,
          0b10100.GeneralizedIndex,
          0b1011.GeneralizedIndex,
          0b100.GeneralizedIndex,
          0b11.GeneralizedIndex
        ]

  test "get_path_indices":
    check:
      toSeq(get_path_indices(1.GeneralizedIndex)) == []
      toSeq(get_path_indices(0b101010.GeneralizedIndex)) ==
        [
          0b101010.GeneralizedIndex,
          0b10101.GeneralizedIndex,
          0b1010.GeneralizedIndex,
          0b101.GeneralizedIndex,
          0b10.GeneralizedIndex
        ]

  test "get_helper_indices":
    check:
      get_helper_indices(
        [
          8.GeneralizedIndex,
          9.GeneralizedIndex,
          14.GeneralizedIndex]) ==
        [
          15.GeneralizedIndex,
          6.GeneralizedIndex,
          5.GeneralizedIndex
        ]

  test "verify_merkle_multiproof":
    var nodes: array[16, Eth2Digest]
    for i in countdown(15, 8):
      nodes[i] = eth2digest([i.byte])
    for i in countdown(7, 1):
      nodes[i] = withEth2Hash:
        h.update nodes[2 * i + 0].data
        h.update nodes[2 * i + 1].data

    proc verify(indices_int: openArray[int]) =
      let
        indices = indices_int.mapIt(it.GeneralizedIndex)
        helper_indices = get_helper_indices(indices)
        leaves = indices.mapIt(nodes[it])
        proof = helper_indices.mapIt(nodes[it])
        root = nodes[1]
      checkpoint "Verifying " & $indices & "---" & $helper_indices
      check:
        verify_merkle_multiproof(leaves, proof, indices, root)

    verify([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    for a in 1 .. 15:
      verify([a])
      for b in 1 .. 15:
        verify([a, b])
        for c in 1 .. 15:
          verify([a, b, c])
          for d in 8 .. 15:
            verify([a, b, c, d])
            for e in 1 .. 7:
              verify([a, b, c, d, e])

  test "is_valid_merkle_branch":
    type TestCase = object
      root: string
      proof: seq[string]
      leaf: string
      index: uint64
      valid: bool

    let testCases = @[
      TestCase(
        root:
          "2a23ef2b7a7221eaac2ffb3842a506a981c009ca6c2fcbf20adbc595e56f1a93",
        proof: @[
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        ],
        leaf:
          "0100000000000000000000000000000000000000000000000000000000000000",
        index: 4,
        valid: true
      ),
      TestCase(
        root:
          "2a23ef2b7a7221eaac2ffb3842a506a981c009ca6c2fcbf20adbc595e56f1a93",
        proof: @[
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        ],
        leaf:
          "0100000000000000000000000000000000000000000000000000000000000000",
        index: 6,
        valid: false
      ),
      TestCase(
        root:
          "2a23ef2b7a7221eaac2ffb3842a506a981c009ca6c2fcbf20adbc595e56f1a93",
        proof: @[
          "0100000000000000000000000000000000000000000000000000000000000000",
          "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        ],
        leaf:
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        index: 5,
        valid: true
      ),
      TestCase(
        root:
          "f1824b0084956084591ff4c91c11bcc94a40be82da280e5171932b967dd146e9",
        proof: @[
          "35210d64853aee79d03f30cf0f29c1398706cbbcacaf05ab9524f00070aec91e",
          "f38a181470ef1eee90a29f0af0a9dba6b7e5d48af3c93c29b4f91fa11b777582"
        ],
        leaf:
          "0100000000000000000000000000000000000000000000000000000000000000",
        index: 7,
        valid: true
      ),
      TestCase(
        root:
          "f1824b0084956084591ff4c91c11bcc94a40be82da280e5171932b967dd146e9",
        proof: @[
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
          "0100000000000000000000000000000000000000000000000000000000000000",
          "f38a181470ef1eee90a29f0af0a9dba6b7e5d48af3c93c29b4f91fa11b777582"
        ],
        leaf:
          "6001000000000000000000000000000000000000000000000000000000000000",
        index: 49,
        valid: true
      )
    ]

    for testCase in testCases:
      let
        root = Eth2Digest.fromHex(testCase.root)
        proof = mapIt(testCase.proof, Eth2Digest.fromHex(it))
        leaf = Eth2Digest.fromHex(testCase.leaf)
        index = testCase.index.GeneralizedIndex
        valid = is_valid_merkle_branch(leaf, proof,
                                       log2trunc(index),
                                       get_subtree_index(index),
                                       root)
      if testCase.valid:
        check valid
      else:
        check (not valid)
