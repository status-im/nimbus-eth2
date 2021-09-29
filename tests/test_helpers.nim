# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Status libraries
  stew/bitops2,
  # Beacon chain internals
  ../beacon_chain/spec/[helpers, state_transition],
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
      rewards = RewardInfo()
    doAssert process_slots(defaultRuntimeConfig, forked[], 
                           Slot(100), cache, rewards, flags = {})

    let
      state = forked[].hbsPhase0.data
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
