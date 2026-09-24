# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  # Status libraries
  stew/bitops2,
  stew/byteutils,
  # Beacon chain internals
  ../beacon_chain/spec/[forks, helpers, state_transition],
  ./teststateutil,
  # Test utilities
  unittest2

suite "Spec helpers":
  test "integer_squareroot":
    check:
      integer_squareroot(1'u64) == 1'u64
      integer_squareroot(2'u64) == 1'u64
      integer_squareroot(3'u64) == 1'u64
      integer_squareroot(4'u64) == 2'u64
      integer_squareroot(5'u64) == 2'u64

      # https://github.com/ethereum/consensus-specs/pull/3600
      integer_squareroot(0'u64) == 0'u64
      integer_squareroot(100'u64) == 10'u64
      integer_squareroot(18446744073709551614'u64) == 4294967295'u64
      integer_squareroot(18446744073709551615'u64) == 4294967295'u64

  test "build_proof - BeaconState":
    let forked = newClone(initGenesisState(defaultRuntimeConfig))
    var
      cache: StateCache
      info: ForkedEpochInfo
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
      anchor.enumInstanceSerializedFields(_, fieldVar):
        let depth = log2trunc(i)
        var proof = newSeq[Eth2Digest](depth)
        state.build_proof(i, proof).get
        check:
          hash_tree_root(fieldVar) == hash_tree_root(state, i).get
          is_valid_merkle_branch(hash_tree_root(fieldVar), proof,
                                 depth, get_subtree_index(i), root)
        when fieldVar is object and not (fieldVar is Eth2Digest):
          let
            numChildLeaves = fieldVar.numLeaves
            childDepth = log2trunc(numChildLeaves)
          process(fieldVar, i shl childDepth)
        i += 1
    process(state, state.numLeaves)

  test "get_default_auth_data":
    const testCases = @[
      ("https://builder.example.com/", "builder.example.com"),
      ("HTTPS://Builder.Example.com:443/bids?x=1", "builder.example.com"),
      ("https://builder.example.com:8080", "builder.example.com"),
      ("https://user:pw@builder.example.com/", "builder.example.com"),
      ("https://10.0.0.5:18550/eth/v1/builder", "10.0.0.5"),
      ("https://[0:0:0:0:0:0:0:1]:8443/", "[::1]"),
      ("https://[::ffff:192.0.2.1]/", "[::ffff:c000:201]"),
      # Extra cases
      ("https://[0:0:0:0:0:0:0:0]/", "[::]"),
      ("https://[1:0:0:0:0:0:0:0]/", "[1::]"),
    ]

    for i in 0 ..< len(testCases):
      let res = get_default_auth_data(testCases[i][0])
      check:
        res.isOk()
        string.fromBytes(res.get().asSeq()) == testCases[i][1]
