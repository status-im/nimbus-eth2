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

from ../beacon_chain/consensus_object_pools/blockchain_dag import
  ForkChoiceBalance, SlashedBit

from ../beacon_chain/spec/datatypes/phase0 import BeaconState

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

func makeVote(root: Eth2Digest, slot: Slot): VoteTracker =
  VoteTracker(current_root: root, next_root: root, slot: slot)

func makeVote(chain: seq[BlockRef], slot: Slot): VoteTracker =
  doAssert chain[distinctBase(slot)].bid.slot == slot
  makeVote(chain[distinctBase(slot)].bid.root, slot)

func makeEquivocation(): VoteTracker =
  makeVote(ZERO_HASH, FAR_FUTURE_SLOT)

func makeBackend(votes: seq[VoteTracker]): ForkChoiceBackend =
  ForkChoiceBackend(votes: votes)

suite "get_ancestor_info":
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
      fake_bid = BlockId(slot: 1.Epoch.start_slot + 2, root: makeRoot(255))
      res = get_ancestor_info(chain[^1], fake_bid, current_slot)
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

  test "Only one block after genesis":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeChain [0.Slot, 2.Epoch.start_slot + 2]
      res = get_ancestor_info(chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].blck == chain[1]
      res[current_slot - (2.Epoch.start_slot + 2)].blck == chain[1]
      res[current_slot - (2.Epoch.start_slot + 1)].blck == chain[0]
      res[^1].blck == chain[0]

suite "get_ancestor_support_by_slot":
  func get_ancestor_support_by_slot(
      self: ForkChoiceBackend, balance_source: BalanceSource,
      blck: BlockRef, terminal_bid: BlockId,
      current_slot: Slot): seq[SlotInfo] =
    self.get_ancestor_support_by_slot(
      balance_source, @[blck], blck, terminal_bid, current_slot)

  func makeBalance(eb: Gwei): ForkChoiceBalance =
    ForkChoiceBalance(distinctBase(eb))

  func asSlashed(balance: ForkChoiceBalance): ForkChoiceBalance =
    ForkChoiceBalance(distinctBase(balance) or SlashedBit)

  func withAssignedSlots(
      balance: ForkChoiceBalance, slots: varargs[Slot]): ForkChoiceBalance =
    result = balance
    for slot in slots:
      let
        i = slot.epoch.shuffling_index
        offset = AttesterDutyOffsets[i]
        duty_mask = (slot.since_epoch_start + 1) shl offset
      result = ForkChoiceBalance(distinctBase(result) or duty_mask)

  func makeBalanceSource(
      balances: seq[ForkChoiceBalance],
      current_epoch: Epoch): BalanceSource =
    result = BalanceSource(
      info: BalanceCheckpoint(balances: balances),
      shuffling_epochs: DefaultShufflingEpochs)
    for epoch in countdown(current_epoch, max(current_epoch, 2.Epoch) - 2):
      result.shuffling_epochs[epoch.shuffling_index] = epoch

  test "Basic support":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[
        chain.makeVote(current_slot - 1),
        chain.makeVote(current_slot - 2),
        chain.makeVote(prev_epoch_start + 4)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(current_slot - 1),
          makeBalance(20.Gwei).withAssignedSlots(current_slot - 2),
          makeBalance(30.Gwei).withAssignedSlots(prev_epoch_start + 4)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].support == 0.Gwei
      res[1].support == 10.Gwei
      res[2].support == 20.Gwei
      res[current_slot - (prev_epoch_start + 4)].support == 30.Gwei
      res[0].total_support == 0.Gwei
      res[1].total_support == 10.Gwei
      res[2].total_support == 30.Gwei
      res[current_slot - (prev_epoch_start + 4)].total_support == 60.Gwei
      res[^1].total_support == 60.Gwei
      res[0].adversarial == 0.Gwei
      res[^1].total_adversarial == 0.Gwei

  test "No match":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[makeVote(makeRoot(255), 3.Epoch.start_slot + 1)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(3.Epoch.start_slot + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].support == 0.Gwei
      res[2].support == 0.Gwei
      res[^1].total_support == 0.Gwei

  test "Votes outside range":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[
        chain.makeVote(1.Epoch.start_slot),
        chain.makeVote(prev_epoch_start - 1)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(1.Epoch.start_slot),
          makeBalance(20.Gwei).withAssignedSlots(prev_epoch_start - 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[^1].total_support == 0.Gwei

  test "Slashed validator":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[chain.makeVote(3.Epoch.start_slot + 1)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).asSlashed.withAssignedSlots(
          3.Epoch.start_slot + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[2].support == 0.Gwei
      res[^1].total_support == 0.Gwei
      res[^1].total_adversarial == 0.Gwei

  test "Equivocating, single slot in range":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[makeEquivocation()])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(
            1.Epoch.start_slot + 2,
            2.Epoch.start_slot,
            3.Epoch.start_slot + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - 2.Epoch.start_slot].adversarial == 10.Gwei
      res[0].total_adversarial == 0.Gwei
      res[current_slot - 2.Epoch.start_slot].total_adversarial == 10.Gwei
      res[^1].total_adversarial == 10.Gwei

  test "Equivocating, cross-epoch, same block":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeChain [0.Slot, 2.Epoch.start_slot - 1, current_slot]
      backend = makeBackend(@[makeEquivocation()])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(
            1.Epoch.start_slot + 2,
            2.Epoch.start_slot + 1,
            3.Epoch.start_slot + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - (3.Epoch.start_slot + 1)].adversarial == 10.Gwei
      res[current_slot - (2.Epoch.start_slot + 1)].adversarial == 0.Gwei
      res[0].total_adversarial == 0.Gwei
      res[current_slot - (3.Epoch.start_slot + 1)].total_adversarial == 10.Gwei
      res[^1].total_adversarial == 10.Gwei

  test "Equivocating, cross-epoch, different blocks":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[makeEquivocation()])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(
            1.Epoch.start_slot + 2,
            2.Epoch.start_slot + 4,
            3.Epoch.start_slot + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - (3.Epoch.start_slot + 1)].adversarial == 10.Gwei
      res[current_slot - (2.Epoch.start_slot + 4)].adversarial == 10.Gwei
      res[0].total_adversarial == 0.Gwei
      res[current_slot - (3.Epoch.start_slot + 1)].total_adversarial == 10.Gwei
      res[^1].total_adversarial == 10.Gwei

  test "Equivocating, assigned slot at current_slot":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[makeEquivocation()])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(
            1.Epoch.start_slot + 2,
            2.Epoch.start_slot + 4,
            3.Epoch.start_slot + 3)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[0].adversarial == 0.Gwei
      res[current_slot - (2.Epoch.start_slot + 4)].adversarial == 10.Gwei
      res[0].total_adversarial == 0.Gwei
      res[current_slot - (2.Epoch.start_slot + 4)].total_adversarial == 10.Gwei

  test "Equivocating, last block before previous epoch":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeChain [0.Slot, 2.Epoch.start_slot, current_slot]
      backend = makeBackend(@[makeEquivocation()])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(
            3.Epoch.start_slot + 1,
            2.Epoch.start_slot + 4,
            1.Epoch.start_slot + 2)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - (3.Epoch.start_slot + 1)].adversarial == 10.Gwei
      res[current_slot - (2.Epoch.start_slot + 4)].adversarial == 0.Gwei
      res[^1].adversarial == 10.Gwei
      res[current_slot - (3.Epoch.start_slot + 1)].total_adversarial ==
        10.Gwei
      res[^1].total_adversarial == 10.Gwei

  test "Equivocating, duties on different blocks":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeChain [
        0.Slot, 5.Slot, 2.Epoch.start_slot,
        2.Epoch.start_slot + 6, current_slot]
      backend = makeBackend(@[makeEquivocation()])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(
            3.Epoch.start_slot + 1,
            2.Epoch.start_slot + 4,
            1.Epoch.start_slot + 2)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - (3.Epoch.start_slot + 1)].adversarial == 10.Gwei
      res[current_slot - (2.Epoch.start_slot + 4)].adversarial == 10.Gwei
      res[^1].adversarial == 10.Gwei
      res[current_slot - (3.Epoch.start_slot + 1)].total_adversarial ==
        10.Gwei
      res[^1].total_adversarial == 10.Gwei

  test "Mixed validators":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[
        chain.makeVote(3.Epoch.start_slot + 1),
        makeEquivocation(),
        chain.makeVote(1.Epoch.start_slot),
        chain.makeVote(2.Epoch.start_slot + 4)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(3.Epoch.start_slot + 1),
          makeBalance(20.Gwei).withAssignedSlots(
            1.Epoch.start_slot + 2,
            2.Epoch.start_slot + 2,
            3.Epoch.start_slot + 1),
          makeBalance(30.Gwei).withAssignedSlots(1.Epoch.start_slot),
          makeBalance(40.Gwei).asSlashed.withAssignedSlots(
            2.Epoch.start_slot + 4)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - (3.Epoch.start_slot + 1)].support == 10.Gwei
      res[current_slot - (3.Epoch.start_slot + 1)].adversarial == 20.Gwei
      res[current_slot - (2.Epoch.start_slot + 2)].adversarial == 20.Gwei
      res[current_slot - (2.Epoch.start_slot + 4)].support == 0.Gwei
      res[^1].total_support == 10.Gwei
      res[^1].total_adversarial == 20.Gwei

  test "Empty result":
    let
      current_slot = 3.Epoch.start_slot + 3
      chain = makeFullChain(current_slot)
      fake_bid = BlockId(slot: 1.Epoch.start_slot + 2, root: makeRoot(255))
      backend = makeBackend(@[chain.makeVote(3.Epoch.start_slot + 1)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(3.Epoch.start_slot + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], fake_bid, current_slot)
    check res.len == 0

  test "Early epochs":
    let
      current_slot = (SLOTS_PER_EPOCH div 2).Slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[chain.makeVote(2.Slot)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(2.Slot)],
        0.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == distinctBase(current_slot) + 1
      res[current_slot - 2.Slot].support == 10.Gwei
      res[^1].total_support == 10.Gwei

  test "Early epochs with 3 shufflings":
    let
      current_slot = 2.Epoch.start_slot + 3
      prev_epoch_start = 1.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[
        chain.makeVote(1.Epoch.start_slot + 2),
        chain.makeVote(2.Epoch.start_slot + 1)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(1.Epoch.start_slot + 2),
          makeBalance(20.Gwei).withAssignedSlots(2.Epoch.start_slot + 1)],
        2.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - (1.Epoch.start_slot + 2)].support == 10.Gwei
      res[current_slot - (2.Epoch.start_slot + 1)].support == 20.Gwei
      res[^1].total_support == 30.Gwei

  test "Gap in chain":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      gap_slot = 3.Epoch.start_slot + 1
      chain = makeChain(
        toSeq(0.Slot .. 3.Epoch.start_slot) &
        toSeq(gap_slot + 1 .. current_slot))
      backend = makeBackend(@[
        makeVote(chain[distinctBase(3.Epoch.start_slot)].bid.root, gap_slot)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(gap_slot)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - gap_slot].support == 10.Gwei
      res[current_slot - 3.Epoch.start_slot].total_support == 10.Gwei
      res[^1].total_support == 10.Gwei

  test "Stale view, no assigned slot at stale block":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      stale_slot = 2.Epoch.start_slot + 4
      vote_slot = 3.Epoch.start_slot + 2
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[
        makeVote(chain[distinctBase(stale_slot)].bid.root, vote_slot)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(vote_slot)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - stale_slot].total_support == 10.Gwei

  test "Running totals verification":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      backend = makeBackend(@[
        chain.makeVote(current_slot - 1),
        chain.makeVote(3.Epoch.start_slot + 1),
        chain.makeVote(2.Epoch.start_slot + 4),
        makeEquivocation(),
        makeEquivocation()])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(current_slot - 1),
          makeBalance(20.Gwei).withAssignedSlots(3.Epoch.start_slot + 1),
          makeBalance(30.Gwei).withAssignedSlots(2.Epoch.start_slot + 4),
          makeBalance(40.Gwei).withAssignedSlots(
            1.Epoch.start_slot + 2,
            2.Epoch.start_slot + 2,
            3.Epoch.start_slot + 1),
          makeBalance(50.Gwei).withAssignedSlots(
            1.Epoch.start_slot + 2,
            2.Epoch.start_slot + 6,
            3.Epoch.start_slot + 0)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2

      res[0].support == 0.Gwei
      res[1].support == 10.Gwei
      res[current_slot - (3.Epoch.start_slot + 1)].support == 20.Gwei
      res[current_slot - (2.Epoch.start_slot + 4)].support == 30.Gwei

      res[current_slot - (3.Epoch.start_slot + 1)].adversarial == 40.Gwei
      res[current_slot - (3.Epoch.start_slot + 0)].adversarial == 50.Gwei
      res[current_slot - (2.Epoch.start_slot + 6)].adversarial == 50.Gwei
      res[current_slot - (2.Epoch.start_slot + 2)].adversarial == 40.Gwei

      res[0].total_support == 0.Gwei
      res[1].total_support == 10.Gwei
      res[current_slot - (3.Epoch.start_slot + 1)].total_support == 30.Gwei
      res[current_slot - (2.Epoch.start_slot + 4)].total_support == 60.Gwei
      res[^1].total_support == 60.Gwei

      res[0].total_adversarial == 0.Gwei
      res[1].total_adversarial == 0.Gwei
      res[current_slot - (3.Epoch.start_slot + 1)].total_adversarial == 40.Gwei
      res[current_slot - 3.Epoch.start_slot].total_adversarial == 90.Gwei
      res[^1].total_adversarial == 90.Gwei

  test "Non-canonical, single vote":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      fork_slot = 3.Epoch.start_slot
      head2 = BlockRef(
        bid: BlockId(slot: fork_slot + 1, root: makeRoot(200)),
        parent: chain[distinctBase(fork_slot)])
      backend = makeBackend(@[
        makeVote(head2.bid.root, fork_slot + 1)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(fork_slot + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, @[chain[^1], head2],
        chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - fork_slot].total_support == 10.Gwei
      res[^1].total_support == 10.Gwei

  test "Non-canonical, deep fork":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      fork_slot = 2.Epoch.start_slot + 4
      fork_blck = BlockRef(
        bid: BlockId(slot: fork_slot + 1, root: makeRoot(200)),
        parent: chain[distinctBase(fork_slot)])
      head2 = BlockRef(
        bid: BlockId(slot: fork_slot + 2, root: makeRoot(201)),
        parent: fork_blck)
      backend = makeBackend(@[
        makeVote(head2.bid.root, fork_slot + 2),
        makeVote(fork_blck.bid.root, fork_slot + 1)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(fork_slot + 2),
          makeBalance(20.Gwei).withAssignedSlots(fork_slot + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, @[chain[^1], head2],
        chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - fork_slot].total_support == 30.Gwei
      res[^1].total_support == 30.Gwei

  test "Non-canonical, three forks":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      fork_slot = 3.Epoch.start_slot
      head2 = BlockRef(
        bid: BlockId(slot: fork_slot + 1, root: makeRoot(200)),
        parent: chain[distinctBase(fork_slot)])
      head3 = BlockRef(
        bid: BlockId(slot: fork_slot + 1, root: makeRoot(201)),
        parent: chain[distinctBase(fork_slot)])
      head4 = BlockRef(
        bid: BlockId(slot: fork_slot + 2, root: makeRoot(202)),
        parent: head2)
      backend = makeBackend(@[
        makeVote(head2.bid.root, fork_slot + 1),
        makeVote(head3.bid.root, fork_slot + 1),
        makeVote(head4.bid.root, fork_slot + 2)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(fork_slot + 1),
          makeBalance(20.Gwei).withAssignedSlots(fork_slot + 1),
          makeBalance(30.Gwei).withAssignedSlots(fork_slot + 2)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, @[chain[^1], head2, head3, head4],
        chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - fork_slot].total_support == 60.Gwei
      res[^1].total_support == 60.Gwei

  test "Non-canonical, mixed with canonical":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      fork_slot = 3.Epoch.start_slot
      head2 = BlockRef(
        bid: BlockId(slot: fork_slot + 1, root: makeRoot(200)),
        parent: chain[distinctBase(fork_slot)])
      backend = makeBackend(@[
        chain.makeVote(fork_slot + 1),
        makeVote(head2.bid.root, fork_slot + 1)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(fork_slot + 1),
          makeBalance(20.Gwei).withAssignedSlots(fork_slot + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, @[chain[^1], head2],
        chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[current_slot - (fork_slot + 1)].support == 10.Gwei
      res[current_slot - (fork_slot + 0)].total_support == 30.Gwei
      res[^1].total_support == 30.Gwei

  test "Non-canonical, fork before range":
    let
      current_slot = 3.Epoch.start_slot + 3
      prev_epoch_start = 2.Epoch.start_slot
      chain = makeFullChain(current_slot)
      head2 = BlockRef(
        bid: BlockId(
          slot: prev_epoch_start + 1, root: makeRoot(200)),
        parent: chain[distinctBase(prev_epoch_start) - 2])
      backend = makeBackend(@[makeVote(head2.bid.root, prev_epoch_start + 1)])
      balance_source = makeBalanceSource(
        @[makeBalance(10.Gwei).withAssignedSlots(prev_epoch_start + 1)],
        3.Epoch)
      res = backend.get_ancestor_support_by_slot(
        balance_source, @[chain[^1], head2],
        chain[^1], chain[0].bid, current_slot)
    check:
      res.lenu64 == current_slot - prev_epoch_start + 2
      res[^1].total_support == 0.Gwei

  test "assign_shufflings replaces duties":
    var dst = makeBalanceSource(
      @[makeBalance(10.Gwei).withAssignedSlots(
          3.Epoch.start_slot + 1,
          2.Epoch.start_slot + 4,
          1.Epoch.start_slot + 2)],
      3.Epoch)
    let src = makeBalanceSource(
      @[makeBalance(10.Gwei).withAssignedSlots(
          3.Epoch.start_slot + 3,
          2.Epoch.start_slot + 2,
          1.Epoch.start_slot + 5)],
      3.Epoch)
    dst.assign_shufflings(src)
    check toSeq(dst.assigned_slots(0.ValidatorIndex)) == @[
      3.Epoch.start_slot + 3,
      2.Epoch.start_slot + 2,
      1.Epoch.start_slot + 5]

  test "assign_shufflings dst longer than src":
    var dst = makeBalanceSource(
      @[makeBalance(10.Gwei).withAssignedSlots(
          3.Epoch.start_slot + 1,
          2.Epoch.start_slot + 4,
          1.Epoch.start_slot + 2),
        makeBalance(20.Gwei).withAssignedSlots(
          3.Epoch.start_slot + 3,
          2.Epoch.start_slot + 2,
          1.Epoch.start_slot + 5)],
      3.Epoch)
    let src = makeBalanceSource(
      @[makeBalance(10.Gwei).withAssignedSlots(
          3.Epoch.start_slot + 5,
          2.Epoch.start_slot + 1,
          1.Epoch.start_slot + 7)],
      3.Epoch)
    dst.assign_shufflings(src)
    check:
      toSeq(dst.assigned_slots(0.ValidatorIndex)) == @[
        3.Epoch.start_slot + 5,
        2.Epoch.start_slot + 1,
        1.Epoch.start_slot + 7]
      toSeq(dst.assigned_slots(1.ValidatorIndex)).len == 0

suite "get_current_target_score":
  func makeValidator(eb: Gwei, slashed = false, active = true): Validator =
    Validator(
      effective_balance: eb,
      slashed: slashed,
      activation_epoch: 0.Epoch,
      exit_epoch: if active: FAR_FUTURE_EPOCH else: 0.Epoch)

  func makeState(
      slot: Slot, validators: openArray[Validator]): ref phase0.BeaconState =
    result = (ref phase0.BeaconState)()
    result.slot = slot
    for v in validators:
      doAssert result.validators.add(v)

  func singleVoterScore(validator: Validator, vote_slot: Slot): Gwei =
    let
      current_slot = 3.Epoch.start_slot + 3
      target_slot = current_slot.epoch.start_slot
      chain = makeFullChain(current_slot)
      target = chain[distinctBase(target_slot)]
      heads = @[chain[^1]]
      state = makeState(current_slot, @[validator])
      backend = makeBackend(@[chain.makeVote(vote_slot)])
    backend.get_current_target_score(state[], target, heads)

  test "Basic support":
    check singleVoterScore(
      makeValidator(10.Gwei), 3.Epoch.start_slot + 1) == 10.Gwei

  test "Vote for target at epoch start":
    check singleVoterScore(
      makeValidator(10.Gwei), 3.Epoch.start_slot) == 10.Gwei

  test "Slashed excluded":
    check singleVoterScore(
      makeValidator(10.Gwei, slashed = true), 3.Epoch.start_slot + 1) == 0.Gwei

  test "Inactive excluded":
    check singleVoterScore(
      makeValidator(10.Gwei, active = false), 3.Epoch.start_slot + 1) == 0.Gwei

  test "Vote in previous epoch":
    check singleVoterScore(
      makeValidator(10.Gwei), 2.Epoch.start_slot + 4) == 0.Gwei

  test "Equivocating excluded":
    let
      current_slot = 3.Epoch.start_slot + 3
      target_slot = current_slot.epoch.start_slot
      chain = makeFullChain(current_slot)
      target = chain[distinctBase(target_slot)]
      heads = @[chain[^1]]
      state = makeState(current_slot, @[makeValidator(10.Gwei)])
      backend = makeBackend(@[makeEquivocation()])
    check backend.get_current_target_score(state[], target, heads) == 0.Gwei

  test "Vote for unknown block":
    let
      current_slot = 3.Epoch.start_slot + 3
      target_slot = current_slot.epoch.start_slot
      chain = makeFullChain(current_slot)
      target = chain[distinctBase(target_slot)]
      heads = @[chain[^1]]
      state = makeState(current_slot, @[makeValidator(10.Gwei)])
      backend = makeBackend(@[makeVote(makeRoot(255), target_slot + 1)])
    check backend.get_current_target_score(state[], target, heads) == 0.Gwei

  test "Multiple voters":
    let
      current_slot = 3.Epoch.start_slot + 4
      target_slot = current_slot.epoch.start_slot
      chain = makeFullChain(current_slot)
      target = chain[distinctBase(target_slot)]
      heads = @[chain[^1]]
      state = makeState(current_slot, @[
        makeValidator(10.Gwei),
        makeValidator(20.Gwei),
        makeValidator(30.Gwei)])
      backend = makeBackend(@[
        chain.makeVote(target_slot + 1),
        chain.makeVote(target_slot + 2),
        chain.makeVote(target_slot + 3)])
    check backend.get_current_target_score(state[], target, heads) == 60.Gwei

  test "Multiple heads":
    let
      current_slot = 3.Epoch.start_slot + 3
      target_slot = current_slot.epoch.start_slot
      chain = makeFullChain(current_slot)
      target = chain[distinctBase(target_slot)]
      head1 = makeBlock(target_slot + 1, target)
      head2 = makeBlock(target_slot + 2, target)
      heads = @[head1, head2]
      state = makeState(current_slot, @[
        makeValidator(10.Gwei),
        makeValidator(20.Gwei)])
      backend = makeBackend(@[
        makeVote(head1.root, target_slot + 1),
        makeVote(head2.root, target_slot + 2)])
    check backend.get_current_target_score(state[], target, heads) == 30.Gwei

  test "Empty votes":
    let
      current_slot = 3.Epoch.start_slot + 3
      target_slot = current_slot.epoch.start_slot
      chain = makeFullChain(current_slot)
      target = chain[distinctBase(target_slot)]
      heads = @[chain[^1]]
      state = makeState(current_slot, newSeq[Validator]())
      backend = makeBackend(newSeq[VoteTracker]())
    check backend.get_current_target_score(state[], target, heads) == 0.Gwei

  test "Gap at epoch start":
    let
      current_slot = 3.Epoch.start_slot + 3
      target_slot = current_slot.epoch.start_slot
      chain = makeChain(
        toSeq(0.Slot .. target_slot - 1) &
        toSeq(target_slot + 1 .. current_slot))
      target = chain[distinctBase(target_slot) - 1]
      heads = @[chain[^1]]
      state = makeState(current_slot, @[
        makeValidator(10.Gwei),
        makeValidator(20.Gwei)])
      backend = makeBackend(@[
        makeVote(chain[distinctBase(target_slot)].bid.root, target_slot + 1),
        makeVote(chain[^1].bid.root, current_slot - 1)])
    check:
      target.slot == target_slot - 1
      backend.get_current_target_score(state[], target, heads) == 30.Gwei

  test "Mixed":
    let
      current_slot = 3.Epoch.start_slot + 3
      target_slot = current_slot.epoch.start_slot
      chain = makeFullChain(current_slot)
      target = chain[distinctBase(target_slot)]
      head2 = makeBlock(target_slot + 1, target)
      heads = @[chain[^1], head2]
      state = makeState(current_slot, @[
        #[0]# makeValidator(10.Gwei),
        #[1]# makeValidator(20.Gwei, slashed = true),
        #[2]# makeValidator(30.Gwei, active = false),
        #[3]# makeValidator(40.Gwei),
        #[4]# makeValidator(50.Gwei),
        #[5]# makeValidator(60.Gwei),
        #[6]# makeValidator(70.Gwei)])
      backend = makeBackend(@[
        #[0]# chain.makeVote(target_slot + 1),
        #[1]# chain.makeVote(target_slot + 2),
        #[2]# chain.makeVote(target_slot + 1),
        #[3]# makeEquivocation(),
        #[4]# chain.makeVote(2.Epoch.start_slot + 4),
        #[5]# makeVote(makeRoot(255), target_slot + 1),
        #[6]# makeVote(head2.root, target_slot + 1)])
    check backend.get_current_target_score(state[], target, heads) == 80.Gwei
