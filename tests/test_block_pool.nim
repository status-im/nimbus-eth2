# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, sequtils, unittest,
  ./testutil,
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  ../beacon_chain/[beacon_node_types, block_pool, beacon_chain_db, extras, state_transition, ssz]

suite "Block pool processing" & preset():
  let
    genState = get_genesis_beacon_state(
      makeInitialDeposits(flags = {skipValidation}), 0, Eth1Data(),
        {skipValidation})
    genBlock = get_initial_beacon_block(genState)

  test "loadTailState gets genesis block on first load" & preset():
    var
      pool = BlockPool.init(makeTestDB(genState, genBlock))
      state = pool.loadTailState()
      b0 = pool.get(state.blck.root)

    check:
      state.data.data.slot == GENESIS_SLOT
      b0.isSome()
      toSeq(pool.blockRootsForSlot(GENESIS_SLOT)) == @[state.blck.root]

  test "Simple block add&get" & preset():
    var
      pool = BlockPool.init(makeTestDB(genState, genBlock))
      state = pool.loadTailState()

    let
      b1 = makeBlock(state.data.data, state.blck.root, BeaconBlockBody())
      b1Root = signing_root(b1)

    # TODO the return value is ugly here, need to fix and test..
    discard pool.add(state, b1Root, b1)

    let b1Ref = pool.get(b1Root)

    check:
      b1Ref.isSome()
      b1Ref.get().refs.root == b1Root
      hash_tree_root(state.data.data) == state.data.root

  test "Reverse order block add & get" & preset():
    var
      db = makeTestDB(genState, genBlock)
      pool = BlockPool.init(db)
      state = pool.loadTailState()

    let
      b1 = addBlock(state.data.data, state.blck.root, BeaconBlockBody(), {})
      b1Root = signing_root(b1)
      b2 = addBlock(state.data.data, b1Root, BeaconBlockBody(), {})
      b2Root = signing_root(b2)

    discard pool.add(state, b2Root, b2)

    check:
      pool.get(b2Root).isNone() # Unresolved, shouldn't show up
      FetchRecord(root: b1Root, historySlots: 1) in pool.checkMissing()

    discard pool.add(state, b1Root, b1)

    check: hash_tree_root(state.data.data) == state.data.root

    let
      b1r = pool.get(b1Root)
      b2r = pool.get(b2Root)

    check:
      b1r.isSome()
      b2r.isSome()

      b1r.get().refs.children[0] == b2r.get().refs
      b2r.get().refs.parent == b1r.get().refs
      toSeq(pool.blockRootsForSlot(b1.slot)) == @[b1Root]
      toSeq(pool.blockRootsForSlot(b2.slot)) == @[b2Root]

    db.putHeadBlock(b2Root)

    # check that init also reloads block graph
    var
      pool2 = BlockPool.init(db)

    check:
      hash_tree_root(state.data.data) == state.data.root
      pool2.get(b1Root).isSome()
      pool2.get(b2Root).isSome()
