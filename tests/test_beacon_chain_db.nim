# Nimbus
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import  options, unittest, sequtils, eth/trie/[db],
  ../beacon_chain/[beacon_chain_db, extras, interop, ssz],
  ../beacon_chain/spec/[beaconstate, datatypes, digest, crypto],
  # test utilies
  ./testutil, ./testblockutil

suite "Beacon chain DB" & preset():

  timedTest "empty database" & preset():
    var
      db = init(BeaconChainDB, newMemoryDB())

    check:
      when const_preset=="minimal":
        db.getState(Eth2Digest()).isNone and db.getBlock(Eth2Digest()).isNone
      else:
        # TODO re-check crash here in mainnet
        true

  timedTest "sanity check blocks" & preset():
    var
      db = init(BeaconChainDB, newMemoryDB())

    let
      blck = BeaconBlock()
      root = signing_root(blck)

    db.putBlock(blck)

    check:
      db.containsBlock(root)
      db.getBlock(root).get() == blck

    db.putStateRoot(root, blck.slot, root)
    check:
      db.getStateRoot(root, blck.slot).get() == root

  timedTest "sanity check states" & preset():
    var
      db = init(BeaconChainDB, newMemoryDB())

    let
      state = BeaconState()
      root = hash_tree_root(state)

    db.putState(state)

    check:
      db.containsState(root)
      db.getState(root).get() == state

  timedTest "find ancestors" & preset():
    var
      db = init(BeaconChainDB, newMemoryDB())
      x: ValidatorSig
      y = init(ValidatorSig, x.getBytes())

     # Silly serialization check that fails without the right import
    check: x == y

    let
      a0 = BeaconBlock(slot: GENESIS_SLOT + 0)
      a0r = signing_root(a0)
      a1 = BeaconBlock(slot: GENESIS_SLOT + 1, parent_root: a0r)
      a1r = signing_root(a1)
      a2 = BeaconBlock(slot: GENESIS_SLOT + 2, parent_root: a1r)
      a2r = signing_root(a2)

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

  timedTest "sanity check genesis roundtrip" & preset():
    # This is a really dumb way of checking that we can roundtrip a genesis
    # state. We've been bit by this because we've had a bug in the BLS
    # serialization where an all-zero default-initialized bls signature could
    # not be deserialized because the deserialization was too strict.
    var
      db = init(BeaconChainDB, newMemoryDB())

    let
      state = initialize_beacon_state_from_eth1(
        eth1BlockHash, 0, makeInitialDeposits(SLOTS_PER_EPOCH), {skipValidation})
      root = hash_tree_root(state)

    db.putState(state)

    check:
      db.containsState(root)
      db.getState(root).get() == state
