# Nimbus
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import  options, unittest, strutils, eth/trie/[db],
  ../beacon_chain/[beacon_chain_db, ssz],
  ../beacon_chain/spec/[datatypes, digest, crypto]

suite "Beacon chain DB":
  var
    db = init(BeaconChainDB, newMemoryDB())

  test "empty database":
    check:
      db.getState(Eth2Digest()).isNone
      db.getBlock(Eth2Digest()).isNone

  test "find ancestors":
    var x: ValidatorSig
    var y = init(ValidatorSig, x.getBytes())

    check: x == y

    let
      a0 = BeaconBlock(slot: 0)
      a1 = BeaconBlock(slot: 1, parent_root: hash_tree_root_final(a0))
      a2 = BeaconBlock(slot: 2, parent_root: hash_tree_root_final(a1))

    # TODO check completely kills compile times here
    doAssert db.getAncestors(a0) == [a0]
    doAssert db.getAncestors(a2) == [a2]

    db.putBlock(a2)

    doAssert db.getAncestors(a0) == [a0]
    doAssert db.getAncestors(a2) == [a2]

    db.putBlock(a1)

    doAssert db.getAncestors(a0) == [a0]
    doAssert db.getAncestors(a2) == [a2, a1]

    db.putBlock(a0)

    doAssert db.getAncestors(a0) == [a0]
    doAssert db.getAncestors(a2) == [a2, a1, a0]

    let tmp = db.getAncestors(a2) do (b: BeaconBlock) -> bool:
      b.slot == 1
    doAssert tmp == [a2, a1]
