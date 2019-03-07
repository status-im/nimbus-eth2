# Nimbus
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import  options, unittest, sequtils, strutils, eth/trie/[db],
  ../beacon_chain/[beacon_chain_db, ssz],
  ../beacon_chain/spec/[datatypes, digest, crypto]

suite "Beacon chain DB":

  test "empty database":
    var
      db = init(BeaconChainDB, newMemoryDB())

    check:
      db.getState(Eth2Digest()).isNone
      db.getBlock(Eth2Digest()).isNone

  test "sanity check blocks":
    var
      db = init(BeaconChainDB, newMemoryDB())

    let
      blck = BeaconBlock()
      root = hash_tree_root_final(blck)

    db.putBlock(blck)

    check:
      db.containsBlock(root)
      db.getBlock(root).get() == blck

  test "sanity check states":
    var
      db = init(BeaconChainDB, newMemoryDB())

    let
      state = BeaconState()
      root = hash_tree_root_final(state)

    db.putState(state)

    check:
      db.containsState(root)
      db.getState(root).get() == state

  test "find ancestors":
    var
      db = init(BeaconChainDB, newMemoryDB())
      x: ValidatorSig
      y = init(ValidatorSig, x.getBytes())

     # Silly serialization check that fails without the right import
    check: x == y

    let
      a0 = BeaconBlock(slot: 0)
      a0r = hash_tree_root_final(a0)
      a1 = BeaconBlock(slot: 1, parent_root: a0r)
      a1r = hash_tree_root_final(a1)
      a2 = BeaconBlock(slot: 2, parent_root: a1r)
      a2r = hash_tree_root_final(a2)

    doAssert toSeq(db.getAncestors(a0r)) == []
    doAssert toSeq(db.getAncestors(a2r)) == []

    db.putBlock(a2)

    doAssert toSeq(db.getAncestors(a0r)) == []
    doAssert toSeq(db.getAncestors(a2r)) == [(a2r, a2)]

    db.putBlock(a1)

    doAssert toSeq(db.getAncestors(a0r)) == []
    doAssert toSeq(db.getAncestors(a2r)) == [(a2r, a2), (a1r, a1)]

    db.putBlock(a0)

    doAssert toSeq(db.getAncestors(a0r)) == [(a0r, a0)]
    doAssert toSeq(db.getAncestors(a2r)) == [(a2r, a2), (a1r, a1), (a0r, a0)]
