# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Status libraries
  stew/bitops2,
  eth/common/eth_types as commonEthTypes, eth/common/eth_types_rlp,
  web3/ethtypes,
  # Beacon chain internals
  ../beacon_chain/spec/[forks, helpers, state_transition],
  ../beacon_chain/spec/datatypes/[bellatrix, capella],
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

  test "build_empty_execution_payload - Bellatrix":
    var cfg = defaultRuntimeConfig
    cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
    cfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH

    let state = newClone(initGenesisState(cfg = cfg).bellatrixData)

    proc testCase(recipient: Eth1Address) =
      let payload = build_empty_execution_payload(state[].data, recipient)
      check payload.fee_recipient ==
        bellatrix.ExecutionAddress(data: distinctBase(recipient))

    testCase default(Eth1Address)
    testCase Eth1Address.fromHex("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")

  test "build_empty_execution_payload - Capella":
    var cfg = defaultRuntimeConfig
    cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
    cfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
    cfg.CAPELLA_FORK_EPOCH = GENESIS_EPOCH

    let
      state = newClone(initGenesisState(cfg = cfg).capellaData)
      recipient = Eth1Address.fromHex(
        "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")

    proc testCase(withdrawals: seq[capella.Withdrawal]) =
      let payload = build_empty_execution_payload(
        state[].data, recipient, withdrawals)
      check payload.fee_recipient ==
        bellatrix.ExecutionAddress(data: distinctBase(recipient))
      for i, withdrawal in withdrawals:
        check payload.withdrawals[i] == withdrawal

      let elHeader = payloadToBlockHeader(payload)
      check elHeader.withdrawalsRoot.isSome
      if withdrawals.len == 0:
        check elHeader.withdrawalsRoot.get == EMPTY_ROOT_HASH
      else:
        check elHeader.withdrawalsRoot.get != EMPTY_ROOT_HASH
      check elHeader.blockHash == payload.block_hash

      var bellatrixHeader = elHeader
      bellatrixHeader.withdrawalsRoot.reset()
      check elHeader.blockHash != rlpHash bellatrixHeader

    testCase @[]
    testCase @[
      capella.Withdrawal(
        index: 42,
        validatorIndex: 1337,
        address: bellatrix.ExecutionAddress(data: distinctBase(recipient)),
        amount: 25.Gwei)]
    testCase @[
      capella.Withdrawal(
        index: 1,
        validatorIndex: 1,
        address: bellatrix.ExecutionAddress(data: distinctBase(recipient)),
        amount: 1.Gwei),
      capella.Withdrawal(
        index: 2,
        validatorIndex: 2,
        address: bellatrix.ExecutionAddress(data: distinctBase(recipient)),
        amount: 2.Gwei)]
