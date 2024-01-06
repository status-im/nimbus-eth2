# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ../beacon_chain/consensus_object_pools/block_dag

func `$`(x: BlockRef): string = shortLog(x)

suite "BlockRef and helpers":
  test "isAncestorOf sanity":
    let
      s0 = BlockRef(bid: BlockId(slot: Slot(0)))
      s1 = BlockRef(bid: BlockId(slot: Slot(1)), parent: s0)
      s2 = BlockRef(bid: BlockId(slot: Slot(2)), parent: s1)

    check:
      s0.isAncestorOf(s0)
      s0.isAncestorOf(s1)
      s0.isAncestorOf(s2)
      s1.isAncestorOf(s1)
      s1.isAncestorOf(s2)

      not s2.isAncestorOf(s0)
      not s2.isAncestorOf(s1)
      not s1.isAncestorOf(s0)

  test "get_ancestor sanity":
    let
      s0 = BlockRef(bid: BlockId(slot: Slot(0)))
      s1 = BlockRef(bid: BlockId(slot: Slot(1)), parent: s0)
      s2 = BlockRef(bid: BlockId(slot: Slot(2)), parent: s1)
      s4 = BlockRef(bid: BlockId(slot: Slot(4)), parent: s2)

    check:
      s0.get_ancestor(Slot(0)) == s0
      s0.get_ancestor(Slot(1)) == s0

      s1.get_ancestor(Slot(0)) == s0
      s1.get_ancestor(Slot(1)) == s1

      s4.get_ancestor(Slot(0)) == s0
      s4.get_ancestor(Slot(1)) == s1
      s4.get_ancestor(Slot(2)) == s2
      s4.get_ancestor(Slot(3)) == s2
      s4.get_ancestor(Slot(4)) == s4

suite "BlockSlot and helpers":
  test "atSlot sanity":
    let
      s0 = BlockRef(bid: BlockId(slot: Slot(0)))
      s1 = BlockRef(bid: BlockId(slot: Slot(1)), parent: s0)
      s2 = BlockRef(bid: BlockId(slot: Slot(2)), parent: s1)
      s4 = BlockRef(bid: BlockId(slot: Slot(4)), parent: s2)
      se1 = BlockRef(bid:
        BlockId(slot: Epoch(1).start_slot()), parent: s2)
      se2 = BlockRef(bid:
        BlockId(slot: Epoch(2).start_slot()), parent: se1)

    check:
      s0.atSlot(Slot(0)).blck == s0
      s0.atSlot(Slot(0)) == s1.atSlot(Slot(0))
      s1.atSlot(Slot(1)).blck == s1

      s4.atSlot(Slot(0)).blck == s0

      s4.atSlot() == s4.atSlot(s4.slot)

  test "parent sanity":
    let
      root = block:
        var d: Eth2Digest
        d.data[0] = 1
        d
      s0 = BlockRef(bid: BlockId(slot: Slot(0)))
      s00 = BlockSlot(blck: s0, slot: Slot(0))
      s01 = BlockSlot(blck: s0, slot: Slot(1))
      s2 = BlockRef(bid: BlockId(slot: Slot(2), root: root), parent: s0)
      s22 = BlockSlot(blck: s2, slot: Slot(2))
      s24 = BlockSlot(blck: s2, slot: Slot(4))

    check:
      s00.parent == BlockSlot(blck: nil, slot: Slot(0))
      s01.parent == s00
      s01.parentOrSlot == s00
      s22.parent == s01
      s22.parentOrSlot == BlockSlot(blck: s0, slot: Slot(2))
      s24.parent == BlockSlot(blck: s2, slot: Slot(3))
      s24.parent.parent == s22

      s22.isProposed()
      not s24.isProposed()

suite "BlockId and helpers":
  test "atSlot sanity":
    let
      s0 = BlockRef(bid: BlockId(slot: Slot(0)))
      s1 = BlockRef(bid: BlockId(slot: Slot(1)), parent: s0)
      s2 = BlockRef(bid: BlockId(slot: Slot(2)), parent: s1)
      s4 = BlockRef(bid: BlockId(slot: Slot(4)), parent: s2)

    check:
      s0.atSlot(Slot(0)).blck == s0
      s0.atSlot(Slot(0)) == s1.atSlot(Slot(0))
      s1.atSlot(Slot(1)).blck == s1

      s4.atSlot(Slot(0)).blck == s0

  test "parent sanity":
    let
      s0 = BlockRef(bid: BlockId(slot: Slot(0)))
      s00 = BlockSlot(blck: s0, slot: Slot(0))
      s01 = BlockSlot(blck: s0, slot: Slot(1))
      s2 = BlockRef(bid: BlockId(slot: Slot(2)), parent: s0)
      s22 = BlockSlot(blck: s2, slot: Slot(2))
      s24 = BlockSlot(blck: s2, slot: Slot(4))

    check:
      s00.parent == BlockSlot(blck: nil, slot: Slot(0))
      s01.parent == s00
      s01.parentOrSlot == s00
      s22.parent == s01
      s22.parentOrSlot == BlockSlot(blck: s0, slot: Slot(2))
      s24.parent == BlockSlot(blck: s2, slot: Slot(3))
      s24.parent.parent == s22
