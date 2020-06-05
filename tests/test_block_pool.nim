# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  options, sequtils, unittest,
  ./testutil, ./testblockutil,
  ../beacon_chain/spec/[datatypes, digest, validator],
  ../beacon_chain/[beacon_node_types, block_pool, state_transition, ssz]

suiteReport "BlockRef and helpers" & preset():
  timedTest "isAncestorOf sanity" & preset():
    let
      s0 = BlockRef(slot: Slot(0))
      s1 = BlockRef(slot: Slot(1), parent: s0)
      s2 = BlockRef(slot: Slot(2), parent: s1)

    check:
      s0.isAncestorOf(s0)
      s0.isAncestorOf(s1)
      s0.isAncestorOf(s2)
      s1.isAncestorOf(s1)
      s1.isAncestorOf(s2)

      not s2.isAncestorOf(s0)
      not s2.isAncestorOf(s1)
      not s1.isAncestorOf(s0)

  timedTest "getAncestorAt sanity" & preset():
    let
      s0 = BlockRef(slot: Slot(0))
      s1 = BlockRef(slot: Slot(1), parent: s0)
      s2 = BlockRef(slot: Slot(2), parent: s1)
      s4 = BlockRef(slot: Slot(4), parent: s2)

    check:
      s0.getAncestorAt(Slot(0)) == s0
      s0.getAncestorAt(Slot(1)) == s0

      s1.getAncestorAt(Slot(0)) == s0
      s1.getAncestorAt(Slot(1)) == s1

      s4.getAncestorAt(Slot(0)) == s0
      s4.getAncestorAt(Slot(1)) == s1
      s4.getAncestorAt(Slot(2)) == s2
      s4.getAncestorAt(Slot(3)) == s2
      s4.getAncestorAt(Slot(4)) == s4

suiteReport "BlockSlot and helpers" & preset():
  timedTest "atSlot sanity" & preset():
    let
      s0 = BlockRef(slot: Slot(0))
      s1 = BlockRef(slot: Slot(1), parent: s0)
      s2 = BlockRef(slot: Slot(2), parent: s1)
      s4 = BlockRef(slot: Slot(4), parent: s2)

    check:
      s0.atSlot(Slot(0)).blck == s0
      s0.atSlot(Slot(0)) == s1.atSlot(Slot(0))
      s1.atSlot(Slot(1)).blck == s1

      s4.atSlot(Slot(0)).blck == s0

  timedTest "parent sanity" & preset():
    let
      s0 = BlockRef(slot: Slot(0))
      s00 = BlockSlot(blck: s0, slot: Slot(0))
      s01 = BlockSlot(blck: s0, slot: Slot(1))
      s2 = BlockRef(slot: Slot(2), parent: s0)
      s22 = BlockSlot(blck: s2, slot: Slot(2))
      s24 = BlockSlot(blck: s2, slot: Slot(4))

    check:
      s00.parent == BlockSlot(blck: nil, slot: Slot(0))
      s01.parent == s00
      s22.parent == s01
      s24.parent == BlockSlot(blck: s2, slot: Slot(3))
      s24.parent.parent == s22

suiteReport "Block pool processing" & preset():
  setup:
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      pool = BlockPool.init(db)
      stateData = newClone(pool.loadTailState())
      cache = get_empty_per_epoch_cache()
      b1 = addTestBlock(stateData.data, pool.tail.root, cache)
      b1Root = hash_tree_root(b1.message)
      b2 = addTestBlock(stateData.data, b1Root, cache)
      b2Root {.used.} = hash_tree_root(b2.message)

  timedTest "getRef returns nil for missing blocks":
    check:
      pool.getRef(default Eth2Digest) == nil

  timedTest "loadTailState gets genesis block on first load" & preset():
    let
      b0 = pool.get(pool.tail.root)

    check:
      b0.isSome()

  timedTest "Simple block add&get" & preset():
    let
      b1Add = pool.add(b1Root, b1)[]
      b1Get = pool.get(b1Root)

    check:
      b1Get.isSome()
      b1Get.get().refs.root == b1Root
      b1Add.root == b1Get.get().refs.root
      pool.heads.len == 1
      pool.heads[0].blck == b1Add

    let
      b2Add = pool.add(b2Root, b2)[]
      b2Get = pool.get(b2Root)

    check:
      b2Get.isSome()
      b2Get.get().refs.root == b2Root
      b2Add.root == b2Get.get().refs.root
      pool.heads.len == 1
      pool.heads[0].blck == b2Add

    # Skip one slot to get a gap
    check:
      process_slots(stateData.data, stateData.data.data.slot + 1)

    let
      b4 = addTestBlock(stateData.data, b2Root, cache)
      b4Root = hash_tree_root(b4.message)
      b4Add = pool.add(b4Root, b4)[]

    check:
      b4Add.parent == b2Add

    pool.updateHead(b4Add)

    var blocks: array[3, BlockRef]

    check:
      pool.getBlockRange(Slot(0), 1, blocks.toOpenArray(0, 0)) == 0
      blocks[0..<1] == [pool.tail]

      pool.getBlockRange(Slot(0), 1, blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [pool.tail, b1Add]

      pool.getBlockRange(Slot(0), 2, blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [pool.tail, b2Add]

      pool.getBlockRange(Slot(0), 3, blocks.toOpenArray(0, 1)) == 1
      blocks[0..<2] == [nil, pool.tail] # block 3 is missing!

      pool.getBlockRange(Slot(2), 2, blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [b2Add, b4Add] # block 3 is missing!

      # empty length
      pool.getBlockRange(Slot(2), 2, blocks.toOpenArray(0, -1)) == 0

      # No blocks in sight
      pool.getBlockRange(Slot(5), 1, blocks.toOpenArray(0, 1)) == 2

      # No blocks in sight either due to gaps
      pool.getBlockRange(Slot(3), 2, blocks.toOpenArray(0, 1)) == 2
      blocks[0..<2] == [BlockRef nil, nil] # block 3 is missing!

  timedTest "Reverse order block add & get" & preset():
    check: pool.add(b2Root, b2).error == MissingParent

    check:
      pool.get(b2Root).isNone() # Unresolved, shouldn't show up
      FetchRecord(root: b1Root, historySlots: 1) in pool.checkMissing()

    check: pool.add(b1Root, b1).isOk

    let
      b1Get = pool.get(b1Root)
      b2Get = pool.get(b2Root)

    check:
      b1Get.isSome()
      b2Get.isSome()

      b1Get.get().refs.children[0] == b2Get.get().refs
      b2Get.get().refs.parent == b1Get.get().refs

    pool.updateHead(b2Get.get().refs)

    # The heads structure should have been updated to contain only the new
    # b2 head
    check:
      pool.heads.mapIt(it.blck) == @[b2Get.get().refs]

    # check that init also reloads block graph
    var
      pool2 = BlockPool.init(db)

    check:
      # ensure we loaded the correct head state
      pool2.head.blck.root == b2Root
      hash_tree_root(pool2.headState.data.data) == b2.message.state_root
      pool2.get(b1Root).isSome()
      pool2.get(b2Root).isSome()
      pool2.heads.len == 1
      pool2.heads[0].blck.root == b2Root

  timedTest "Can add same block twice" & preset():
    let
      b10 = pool.add(b1Root, b1)[]
      b11 = pool.add(b1Root, b1)[]

    check:
      b10 == b11
      not b10.isNil

  timedTest "updateHead updates head and headState" & preset():
    let
      b1Add = pool.add(b1Root, b1)[]

    pool.updateHead(b1Add)

    check:
      pool.head.blck == b1Add
      pool.headState.data.data.slot == b1Add.slot

  timedTest "updateStateData sanity" & preset():
    let
      b1Add = pool.add(b1Root, b1)[]
      b2Add = pool.add(b2Root, b2)[]
      bs1 = BlockSlot(blck: b1Add, slot: b1.message.slot)
      bs1_3 = b1Add.atSlot(3.Slot)
      bs2_3 = b2Add.atSlot(3.Slot)

    var tmpState = newClone(pool.headState)

    # move to specific block
    pool.updateStateData(tmpState[], bs1)

    check:
      tmpState.blck == b1Add
      tmpState.data.data.slot == bs1.slot

    # Skip slots
    pool.updateStateData(tmpState[], bs1_3) # skip slots

    check:
      tmpState.blck == b1Add
      tmpState.data.data.slot == bs1_3.slot

    # Move back slots, but not blocks
    pool.updateStateData(tmpState[], bs1_3.parent())
    check:
      tmpState.blck == b1Add
      tmpState.data.data.slot == bs1_3.parent().slot

    # Move to different block and slot
    pool.updateStateData(tmpState[], bs2_3)
    check:
      tmpState.blck == b2Add
      tmpState.data.data.slot == bs2_3.slot

    # Move back slot and block
    pool.updateStateData(tmpState[], bs1)
    check:
      tmpState.blck == b1Add
      tmpState.data.data.slot == bs1.slot

    # Move back to genesis
    pool.updateStateData(tmpState[], bs1.parent())
    check:
      tmpState.blck == b1Add.parent
      tmpState.data.data.slot == bs1.parent.slot

when const_preset == "minimal":  # These require some minutes in mainnet
  import ../beacon_chain/spec/helpers

  suiteReport "BlockPool finalization tests" & preset():
    setup:
      var
        db = makeTestDB(SLOTS_PER_EPOCH)
        pool = BlockPool.init(db)
        cache = get_empty_per_epoch_cache()

    timedTest "prune heads on finalization" & preset():
      block:
        # Create a fork that will not be taken
        var
          blck = makeTestBlock(pool.headState.data, pool.head.blck.root, cache)
        check: pool.add(hash_tree_root(blck.message), blck).isOk

      for i in 0 ..< (SLOTS_PER_EPOCH * 6):
        if i == 1:
          # There are 2 heads now because of the fork at slot 1
          check:
            pool.tail.children.len == 2
            pool.heads.len == 2
        var
          blck = makeTestBlock(
            pool.headState.data, pool.head.blck.root, cache,
            attestations = makeFullAttestations(
              pool.headState.data.data, pool.head.blck.root,
              pool.headState.data.data.slot, cache, {}))
        let added = pool.add(hash_tree_root(blck.message), blck)[]
        pool.updateHead(added)

      check:
        pool.heads.len() == 1
        pool.head.justified.slot.compute_epoch_at_slot() == 5
        pool.tail.children.len == 1

      let
        pool2 = BlockPool.init(db)

      # check that the state reloaded from database resembles what we had before
      check:
        pool2.tail.root == pool.tail.root
        pool2.head.blck.root == pool.head.blck.root
        pool2.finalizedHead.blck.root == pool.finalizedHead.blck.root
        pool2.finalizedHead.slot == pool.finalizedHead.slot
        hash_tree_root(pool2.headState.data.data) ==
          hash_tree_root(pool.headState.data.data)
        hash_tree_root(pool2.justifiedState.data.data) ==
          hash_tree_root(pool.justifiedState.data.data)

    timedTest "init with gaps" & preset():
      var cache = get_empty_per_epoch_cache()
      for i in 0 ..< (SLOTS_PER_EPOCH * 6 - 2):
        var
          blck = makeTestBlock(
            pool.headState.data, pool.head.blck.root, cache,
            attestations = makeFullAttestations(
              pool.headState.data.data, pool.head.blck.root,
              pool.headState.data.data.slot, cache, {}))
        let added = pool.add(hash_tree_root(blck.message), blck)[]
        pool.updateHead(added)

      # Advance past epoch so that the epoch transition is gapped
      check:
        process_slots(
          pool.headState.data, Slot(SLOTS_PER_EPOCH * 6 + 2) )

      var blck = makeTestBlock(
        pool.headState.data, pool.head.blck.root, cache,
        attestations = makeFullAttestations(
          pool.headState.data.data, pool.head.blck.root,
          pool.headState.data.data.slot, cache, {}))

      let added = pool.add(hash_tree_root(blck.message), blck)[]
      pool.updateHead(added)

      let
        pool2 = BlockPool.init(db)

      # check that the state reloaded from database resembles what we had before
      check:
        pool2.tail.root == pool.tail.root
        pool2.head.blck.root == pool.head.blck.root
        pool2.finalizedHead.blck.root == pool.finalizedHead.blck.root
        pool2.finalizedHead.slot == pool.finalizedHead.slot
        hash_tree_root(pool2.headState.data.data) ==
          hash_tree_root(pool.headState.data.data)
        hash_tree_root(pool2.justifiedState.data.data) ==
          hash_tree_root(pool.justifiedState.data.data)
