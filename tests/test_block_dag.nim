# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
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

  test "commonAncestor sanity":
    #             s0
    #            /  \
    #           s1  s3
    #          /      \
    #         s2      s6
    #        /  \       \
    #       s4  s5      s7
    #        \
    #         s8
    #          \
    #           s9
    let
      s0 = BlockRef(bid: BlockId(slot: Slot(0)))
      s1 = BlockRef(bid: BlockId(slot: Slot(1)), parent: s0)
      s2 = BlockRef(bid: BlockId(slot: Slot(2)), parent: s1)
      s3 = BlockRef(bid: BlockId(slot: Slot(3)), parent: s0)
      s4 = BlockRef(bid: BlockId(slot: Slot(4)), parent: s2)
      s5 = BlockRef(bid: BlockId(slot: Slot(5)), parent: s2)
      s6 = BlockRef(bid: BlockId(slot: Slot(6)), parent: s3)
      s7 = BlockRef(bid: BlockId(slot: Slot(7)), parent: s6)
      s8 = BlockRef(bid: BlockId(slot: Slot(8)), parent: s4)
      s9 = BlockRef(bid: BlockId(slot: Slot(9)), parent: s8)

    check:
      commonAncestor(s0, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s0, s1, Slot(0)) == Opt.some(s0)
      commonAncestor(s0, s2, Slot(0)) == Opt.some(s0)
      commonAncestor(s0, s3, Slot(0)) == Opt.some(s0)
      commonAncestor(s0, s4, Slot(0)) == Opt.some(s0)
      commonAncestor(s0, s5, Slot(0)) == Opt.some(s0)
      commonAncestor(s0, s6, Slot(0)) == Opt.some(s0)
      commonAncestor(s0, s7, Slot(0)) == Opt.some(s0)
      commonAncestor(s0, s8, Slot(0)) == Opt.some(s0)
      commonAncestor(s0, s9, Slot(0)) == Opt.some(s0)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s0, b, Slot(1)) == Opt.none(BlockRef)

    check:
      commonAncestor(s1, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s1, s1, Slot(0)) == Opt.some(s1)
      commonAncestor(s1, s2, Slot(0)) == Opt.some(s1)
      commonAncestor(s1, s3, Slot(0)) == Opt.some(s0)
      commonAncestor(s1, s4, Slot(0)) == Opt.some(s1)
      commonAncestor(s1, s5, Slot(0)) == Opt.some(s1)
      commonAncestor(s1, s6, Slot(0)) == Opt.some(s0)
      commonAncestor(s1, s7, Slot(0)) == Opt.some(s0)
      commonAncestor(s1, s8, Slot(0)) == Opt.some(s1)
      commonAncestor(s1, s9, Slot(0)) == Opt.some(s1)
    for b in [s0, s3, s6, s7]:
      check commonAncestor(s1, b, Slot(1)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s1, b, Slot(2)) == Opt.none(BlockRef)

    check:
      commonAncestor(s2, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s2, s1, Slot(0)) == Opt.some(s1)
      commonAncestor(s2, s2, Slot(0)) == Opt.some(s2)
      commonAncestor(s2, s3, Slot(0)) == Opt.some(s0)
      commonAncestor(s2, s4, Slot(0)) == Opt.some(s2)
      commonAncestor(s2, s5, Slot(0)) == Opt.some(s2)
      commonAncestor(s2, s6, Slot(0)) == Opt.some(s0)
      commonAncestor(s2, s7, Slot(0)) == Opt.some(s0)
      commonAncestor(s2, s8, Slot(0)) == Opt.some(s2)
      commonAncestor(s2, s9, Slot(0)) == Opt.some(s2)
    for b in [s0, s3, s6, s7]:
      check commonAncestor(s2, b, Slot(1)) == Opt.none(BlockRef)
    for b in [s0, s1, s3, s6, s7]:
      check commonAncestor(s2, b, Slot(2)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s2, b, Slot(3)) == Opt.none(BlockRef)

    check:
      commonAncestor(s3, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s3, s1, Slot(0)) == Opt.some(s0)
      commonAncestor(s3, s2, Slot(0)) == Opt.some(s0)
      commonAncestor(s3, s3, Slot(0)) == Opt.some(s3)
      commonAncestor(s3, s4, Slot(0)) == Opt.some(s0)
      commonAncestor(s3, s5, Slot(0)) == Opt.some(s0)
      commonAncestor(s3, s6, Slot(0)) == Opt.some(s3)
      commonAncestor(s3, s7, Slot(0)) == Opt.some(s3)
      commonAncestor(s3, s8, Slot(0)) == Opt.some(s0)
      commonAncestor(s3, s9, Slot(0)) == Opt.some(s0)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check commonAncestor(s3, b, Slot(1)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check commonAncestor(s3, b, Slot(2)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check commonAncestor(s3, b, Slot(3)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s3, b, Slot(4)) == Opt.none(BlockRef)

    check:
      commonAncestor(s4, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s4, s1, Slot(0)) == Opt.some(s1)
      commonAncestor(s4, s2, Slot(0)) == Opt.some(s2)
      commonAncestor(s4, s3, Slot(0)) == Opt.some(s0)
      commonAncestor(s4, s4, Slot(0)) == Opt.some(s4)
      commonAncestor(s4, s5, Slot(0)) == Opt.some(s2)
      commonAncestor(s4, s6, Slot(0)) == Opt.some(s0)
      commonAncestor(s4, s7, Slot(0)) == Opt.some(s0)
      commonAncestor(s4, s8, Slot(0)) == Opt.some(s4)
      commonAncestor(s4, s9, Slot(0)) == Opt.some(s4)
    for b in [s0, s3, s6, s7]:
      check commonAncestor(s4, b, Slot(1)) == Opt.none(BlockRef)
    for b in [s0, s1, s3, s6, s7]:
      check commonAncestor(s4, b, Slot(2)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check commonAncestor(s4, b, Slot(3)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check commonAncestor(s4, b, Slot(4)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s4, b, Slot(5)) == Opt.none(BlockRef)

    check:
      commonAncestor(s5, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s5, s1, Slot(0)) == Opt.some(s1)
      commonAncestor(s5, s2, Slot(0)) == Opt.some(s2)
      commonAncestor(s5, s3, Slot(0)) == Opt.some(s0)
      commonAncestor(s5, s4, Slot(0)) == Opt.some(s2)
      commonAncestor(s5, s5, Slot(0)) == Opt.some(s5)
      commonAncestor(s5, s6, Slot(0)) == Opt.some(s0)
      commonAncestor(s5, s7, Slot(0)) == Opt.some(s0)
      commonAncestor(s5, s8, Slot(0)) == Opt.some(s2)
      commonAncestor(s5, s9, Slot(0)) == Opt.some(s2)
    for b in [s0, s3, s6, s7]:
      check commonAncestor(s5, b, Slot(1)) == Opt.none(BlockRef)
    for b in [s0, s1, s3, s6, s7]:
      check commonAncestor(s5, b, Slot(2)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s6, s7, s8, s9]:
      check commonAncestor(s5, b, Slot(3)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s6, s7, s8, s9]:
      check commonAncestor(s5, b, Slot(4)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s6, s7, s8, s9]:
      check commonAncestor(s5, b, Slot(5)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s5, b, Slot(6)) == Opt.none(BlockRef)

    check:
      commonAncestor(s6, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s6, s1, Slot(0)) == Opt.some(s0)
      commonAncestor(s6, s2, Slot(0)) == Opt.some(s0)
      commonAncestor(s6, s3, Slot(0)) == Opt.some(s3)
      commonAncestor(s6, s4, Slot(0)) == Opt.some(s0)
      commonAncestor(s6, s5, Slot(0)) == Opt.some(s0)
      commonAncestor(s6, s6, Slot(0)) == Opt.some(s6)
      commonAncestor(s6, s7, Slot(0)) == Opt.some(s6)
      commonAncestor(s6, s8, Slot(0)) == Opt.some(s0)
      commonAncestor(s6, s9, Slot(0)) == Opt.some(s0)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check commonAncestor(s6, b, Slot(1)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check commonAncestor(s6, b, Slot(2)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check commonAncestor(s6, b, Slot(3)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check commonAncestor(s6, b, Slot(4)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check commonAncestor(s6, b, Slot(5)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check commonAncestor(s6, b, Slot(6)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s6, b, Slot(7)) == Opt.none(BlockRef)

    check:
      commonAncestor(s7, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s7, s1, Slot(0)) == Opt.some(s0)
      commonAncestor(s7, s2, Slot(0)) == Opt.some(s0)
      commonAncestor(s7, s3, Slot(0)) == Opt.some(s3)
      commonAncestor(s7, s4, Slot(0)) == Opt.some(s0)
      commonAncestor(s7, s5, Slot(0)) == Opt.some(s0)
      commonAncestor(s7, s6, Slot(0)) == Opt.some(s6)
      commonAncestor(s7, s7, Slot(0)) == Opt.some(s7)
      commonAncestor(s7, s8, Slot(0)) == Opt.some(s0)
      commonAncestor(s7, s9, Slot(0)) == Opt.some(s0)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check commonAncestor(s7, b, Slot(1)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check commonAncestor(s7, b, Slot(2)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check commonAncestor(s7, b, Slot(3)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check commonAncestor(s7, b, Slot(4)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check commonAncestor(s7, b, Slot(5)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check commonAncestor(s7, b, Slot(6)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s8, s9]:
      check commonAncestor(s7, b, Slot(7)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s7, b, Slot(8)) == Opt.none(BlockRef)

    check:
      commonAncestor(s8, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s8, s1, Slot(0)) == Opt.some(s1)
      commonAncestor(s8, s2, Slot(0)) == Opt.some(s2)
      commonAncestor(s8, s3, Slot(0)) == Opt.some(s0)
      commonAncestor(s8, s4, Slot(0)) == Opt.some(s4)
      commonAncestor(s8, s5, Slot(0)) == Opt.some(s2)
      commonAncestor(s8, s6, Slot(0)) == Opt.some(s0)
      commonAncestor(s8, s7, Slot(0)) == Opt.some(s0)
      commonAncestor(s8, s8, Slot(0)) == Opt.some(s8)
      commonAncestor(s8, s9, Slot(0)) == Opt.some(s8)
    for b in [s0, s3, s6, s7]:
      check commonAncestor(s8, b, Slot(1)) == Opt.none(BlockRef)
    for b in [s0, s1, s3, s6, s7]:
      check commonAncestor(s8, b, Slot(2)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check commonAncestor(s8, b, Slot(3)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check commonAncestor(s8, b, Slot(4)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check commonAncestor(s8, b, Slot(5)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check commonAncestor(s8, b, Slot(6)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check commonAncestor(s8, b, Slot(7)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check commonAncestor(s8, b, Slot(8)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s8, b, Slot(9)) == Opt.none(BlockRef)

    check:
      commonAncestor(s9, s0, Slot(0)) == Opt.some(s0)
      commonAncestor(s9, s1, Slot(0)) == Opt.some(s1)
      commonAncestor(s9, s2, Slot(0)) == Opt.some(s2)
      commonAncestor(s9, s3, Slot(0)) == Opt.some(s0)
      commonAncestor(s9, s4, Slot(0)) == Opt.some(s4)
      commonAncestor(s9, s5, Slot(0)) == Opt.some(s2)
      commonAncestor(s9, s6, Slot(0)) == Opt.some(s0)
      commonAncestor(s9, s7, Slot(0)) == Opt.some(s0)
      commonAncestor(s9, s8, Slot(0)) == Opt.some(s8)
      commonAncestor(s9, s9, Slot(0)) == Opt.some(s9)
    for b in [s0, s3, s6, s7]:
      check commonAncestor(s9, b, Slot(1)) == Opt.none(BlockRef)
    for b in [s0, s1, s3, s6, s7]:
      check commonAncestor(s9, b, Slot(2)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check commonAncestor(s9, b, Slot(3)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check commonAncestor(s9, b, Slot(4)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check commonAncestor(s9, b, Slot(5)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check commonAncestor(s9, b, Slot(6)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check commonAncestor(s9, b, Slot(7)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check commonAncestor(s9, b, Slot(8)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8]:
      check commonAncestor(s9, b, Slot(9)) == Opt.none(BlockRef)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check commonAncestor(s9, b, Slot(10)) == Opt.none(BlockRef)

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
