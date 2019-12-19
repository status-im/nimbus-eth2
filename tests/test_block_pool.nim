# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  options, sequtils, unittest, chronicles,
  ./testutil, ./testblockutil,
  ../beacon_chain/spec/[beaconstate, datatypes, digest],
  ../beacon_chain/[beacon_node_types, block_pool, beacon_chain_db, extras, ssz]

when const_preset == "minimal": # Too much stack space used on mainnet
  suite "Block pool processing" & preset():
    setup:
      var
        db = makeTestDB(SLOTS_PER_EPOCH)
        pool = BlockPool.init(db)
        state = pool.loadTailState().data.data
        b1 = addBlock(state, pool.tail.root, BeaconBlockBody())
        b1Root = hash_tree_root(b1.message)
        b2 = addBlock(state, b1Root, BeaconBlockBody())
        b2Root = hash_tree_root(b2.message)

    timedTest "getRef returns nil for missing blocks":
      check:
        pool.getRef(default Eth2Digest) == nil

    timedTest "loadTailState gets genesis block on first load" & preset():
      var
        b0 = pool.get(pool.tail.root)

      check:
        b0.isSome()
        toSeq(pool.blockRootsForSlot(GENESIS_SLOT)) == @[pool.tail.root]

    timedTest "Simple block add&get" & preset():
      let
        b1Add = pool.add(b1Root, b1)
        b1Get = pool.get(b1Root)

      check:
        b1Get.isSome()
        b1Get.get().refs.root == b1Root
        b1Add.root == b1Get.get().refs.root

      let
        b2Add = pool.add(b2Root, b2)
        b2Get = pool.get(b2Root)

      check:
        b2Get.isSome()
        b2Get.get().refs.root == b2Root
        b2Add.root == b2Get.get().refs.root

    timedTest "Reverse order block add & get" & preset():
      discard pool.add(b2Root, b2)

      check:
        pool.get(b2Root).isNone() # Unresolved, shouldn't show up
        FetchRecord(root: b1Root, historySlots: 1) in pool.checkMissing()

      discard pool.add(b1Root, b1)

      let
        b1Get = pool.get(b1Root)
        b2Get = pool.get(b2Root)

      check:
        b1Get.isSome()
        b2Get.isSome()

        b1Get.get().refs.children[0] == b2Get.get().refs
        b2Get.get().refs.parent == b1Get.get().refs
        toSeq(pool.blockRootsForSlot(b1.message.slot)) == @[b1Root]
        toSeq(pool.blockRootsForSlot(b2.message.slot)) == @[b2Root]

      db.putHeadBlock(b2Root)

      # The heads structure should have been updated to contain only the new
      # b2 head
      check:
        pool.heads.mapIt(it.blck) == @[b2Get.get().refs]

      # check that init also reloads block graph
      var
        pool2 = BlockPool.init(db)

      check:
        pool2.get(b1Root).isSome()
        pool2.get(b2Root).isSome()

    timedTest "isAncestorOf sanity" & preset():
      let
        a = BlockRef(slot: Slot(1))
        b = BlockRef(slot: Slot(2), parent: a)
        c = BlockRef(slot: Slot(3), parent: b)

      check:
        a.isAncestorOf(a)
        a.isAncestorOf(b)
        a.isAncestorOf(c)
        b.isAncestorOf(c)

        not c.isAncestorOf(a)
        not c.isAncestorOf(b)
        not b.isAncestorOf(a)

    timedTest "Can add same block twice" & preset():
      let
        b10 = pool.add(b1Root, b1)
        b11 = pool.add(b1Root, b1)

      check:
        b10 == b11
        not b10.isNil

    timedTest "updateHead updates head and headState" & preset():
      let
        b1Add = pool.add(b1Root, b1)

      pool.updateHead(b1Add)

      check:
        pool.head.blck == b1Add
        pool.headState.data.data.slot == b1Add.slot
