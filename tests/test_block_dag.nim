# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/sequtils,
  unittest2,
  ../beacon_chain/consensus_object_pools/block_dag,
  ../beacon_chain/fork_choice/fast_confirmation

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

suite "get_ancestor_info":
  func makeRoot(v: byte): Eth2Digest =
    result.data[0] = v

  func makeBlock(slot: Slot, parent: BlockRef): BlockRef =
    BlockRef(
      bid: BlockId(slot: slot, root: makeRoot(byte(distinctBase(slot) + 1))),
      parent: parent)

  func makeChain(slots: openArray[Slot]): seq[BlockRef] =
    result.setLen(slots.len)
    for i, s in slots:
      result[i] = makeBlock(s, if i > 0: result[i - 1] else: nil)

  func makeFullChain(last: Slot): seq[BlockRef] =
    makeChain(toSeq(0.Slot .. last))

  template checkAllSlotsFilled(current_slot: Slot) =
    let
      prev_epoch_start = (current_slot.epoch - 1).start_slot
      chain = makeFullChain(current_slot)
      res = get_ancestor_info(chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].blck == chain[^1]
      res[^2].blck == chain[distinctBase(prev_epoch_start)]
      res[^1].blck == chain[distinctBase(prev_epoch_start) - 1]

  test "All slots filled - mid epoch":
    checkAllSlotsFilled(3.Epoch.start_slot + 3)

  test "All slots filled - start of epoch":
    checkAllSlotsFilled(3.Epoch.start_slot)

  test "All slots filled - end of epoch":
    checkAllSlotsFilled(4.Epoch.start_slot - 1)

  template checkTerminal(current_slot, terminal_slot: Slot) =
    let
      chain = makeFullChain(current_slot)
      terminal_bid = chain[distinctBase(terminal_slot)].bid
      res = get_ancestor_info(chain[^1], terminal_bid, current_slot)
    check:
      res.lenu64 == current_slot - terminal_slot + 1
      res[0].blck == chain[^1]
      res[1].blck == chain[^2]
      res[^1].blck == chain[distinctBase(terminal_slot)]

  test "Terminal in prev epoch":
    checkTerminal(
      current_slot = 3.Epoch.start_slot + 3,
      terminal_slot = 2.Epoch.start_slot + 4)

  test "Terminal in current epoch":
    checkTerminal(
      current_slot = 3.Epoch.start_slot + 3,
      terminal_slot = 3.Epoch.start_slot + 1)

  test "Terminal not an ancestor":
    let
      current_slot = 3.Epoch.start_slot + 3
      chain = makeFullChain(current_slot)
      fakeBid = BlockId(slot: 1.Epoch.start_slot + 2, root: makeRoot(255))
      res = get_ancestor_info(chain[^1], fakeBid, current_slot)
    check res.lenu64 == 0

  test "Gap in current epoch":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeChain(
        toSeq(0.Slot .. 3.Epoch.start_slot) &
        toSeq(3.Epoch.start_slot + 2 .. 3.Epoch.start_slot + 3))
      res = get_ancestor_info(chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].blck == chain[^1]
      res[1].blck == chain[^2]
      res[current_slot - (3.Epoch.start_slot + 1)].blck ==
        chain[distinctBase(3.Epoch.start_slot)]
      res[current_slot - (3.Epoch.start_slot + 0)].blck ==
        chain[distinctBase(3.Epoch.start_slot)]
      res[^1].blck == chain[distinctBase(prev_epoch_start) - 1]

  test "Gap crossing epoch boundary":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeChain(
        toSeq(0.Slot .. 2.Epoch.start_slot - 3) &
        toSeq(2.Epoch.start_slot + 2 .. 3.Epoch.start_slot + 3))
      res = get_ancestor_info(chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].blck == chain[^1]
      res[current_slot - (2.Epoch.start_slot + 2)].blck ==
        chain[distinctBase(2.Epoch.start_slot) - 2]
      res[current_slot - (2.Epoch.start_slot + 1)].blck ==
        chain[distinctBase(2.Epoch.start_slot) - 3]
      res[^2].blck == chain[distinctBase(2.Epoch.start_slot) - 3]
      res[^1].blck == chain[distinctBase(2.Epoch.start_slot) - 3]

  test "Entire prev epoch empty":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeChain [
        #[0]# 0.Slot,
        #[1]# 1.Epoch.start_slot - 1,
        #[2]# 3.Epoch.start_slot,
        #[3]# 3.Epoch.start_slot + 1,
        #[4]# 3.Epoch.start_slot + 2,
        #[5]# 3.Epoch.start_slot + 3]
      res = get_ancestor_info(chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].blck == chain[^1]
      res[current_slot - (3.Epoch.start_slot + 0)].blck == chain[2]
      res[current_slot - (3.Epoch.start_slot - 1)].blck == chain[1]
      res[^2].blck == chain[1]
      res[^1].blck == chain[1]

  test "Sparse chain with terminal mid-gap":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeChain [
        #[0]# 0.Slot,
        #[1]# 1.Epoch.start_slot - 3,
        #[2]# 1.Epoch.start_slot + 2,
        #[3]# 2.Epoch.start_slot + 4,
        #[4]# 3.Epoch.start_slot,
        #[5]# 3.Epoch.start_slot + 3]
      terminal = BlockId(slot: 2.Epoch.start_slot + 2, root: chain[2].bid.root)
      res = get_ancestor_info(chain[^1], terminal, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].blck == chain[^1]
      res[current_slot - (3.Epoch.start_slot + 2)].blck == chain[4]
      res[current_slot - (3.Epoch.start_slot + 0)].blck == chain[4]
      res[current_slot - (3.Epoch.start_slot - 1)].blck == chain[3]
      res[current_slot - (2.Epoch.start_slot + 4)].blck == chain[3]
      res[current_slot - (2.Epoch.start_slot + 3)].blck == chain[2]
      res[current_slot - (2.Epoch.start_slot + 2)].blck == chain[2]
      res[^2].blck == chain[2]
      res[^1].blck == chain[2]

  template checkEarlyEpoch(current_slot: Slot) =
    let
      chain = makeFullChain(current_slot)
      res = get_ancestor_info(chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == distinctBase(current_slot) + 1
      res[0].blck == chain[^1]
      res[^1].blck == chain[0]

  test "Current_slot = 0":
    let
      current_slot = 0.Slot
      chain = makeFullChain(current_slot)
      res = get_ancestor_info(chain[0], chain[0].bid, current_slot)
    check:
      res.lenu64 == 1
      res[0].blck == chain[0]

  test "Current_slot = 1":
    let
      current_slot = 1.Slot
      chain = makeFullChain(current_slot)
      res = get_ancestor_info(chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == 2
      res[0].blck == chain[^1]
      res[1].blck == chain[0]

  test "Mid epoch 0":
    checkEarlyEpoch((SLOTS_PER_EPOCH div 2).Slot)

  test "Start of epoch 1":
    checkEarlyEpoch(1.Epoch.start_slot)

  test "Start of epoch 2":
    checkAllSlotsFilled(2.Epoch.start_slot)

  test "Only genesis":
    let
      current_slot = 2.Epoch.start_slot
      prev_epoch_start = 1.Epoch.start_slot
      chain = makeChain [0.Slot]
      res = get_ancestor_info(chain[0], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].blck == chain[0]
      res[^1].blck == chain[0]
