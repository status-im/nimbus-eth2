# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/datatypes/constants,
  ../beacon_chain/spec/forks,
  ../beacon_chain/sync/[block_buffer, sync_queue]

type
  SlotRange = object
    slota, slotb: Slot

func init(t: typedesc[SlotRange], a, b: Slot): SlotRange =
  SlotRange(slota: a, slotb: b)

iterator items(srange: SlotRange): Slot =
  if srange.slota <= srange.slotb:
    for slot in countup(uint64(srange.slota), uint64(srange.slotb)):
      yield Slot(slot)
  else:
    for slot in countdown(uint64(srange.slota), uint64(srange.slotb)):
      yield Slot(slot)

proc createRoot(i: int): Eth2Digest =
  var res = Eth2Digest()
  res.data[0] = byte(i and 255)
  res

proc createBlock(
    slot: Slot,
    root, parent_root: Eth2Digest
): ref ForkedSignedBeaconBlock =
  newClone ForkedSignedBeaconBlock.init(
    deneb.SignedBeaconBlock(
      message: deneb.BeaconBlock(slot: slot, parent_root: parent_root),
      root: root))

suite "BlocksRangeBuffer test suite":
  test "Add and query blocks test [forward]":
    var buffer = BlocksRangeBuffer.init(SyncQueueKind.Forward)
    const TestChain = [
      (Slot(1923340), createRoot(1), createRoot(0)),
      (Slot(1923341), createRoot(2), createRoot(1)),
      (Slot(1923342), createRoot(3), createRoot(2)),
      (Slot(1923345), createRoot(4), createRoot(3)),
      (Slot(1923350), createRoot(5), createRoot(4))
    ]
    for vector in TestChain:
      check buffer.add(createBlock(vector[0], vector[1], vector[2])).isOk()
    for slot in SlotRange.init(Slot(1923330), Slot(1923339)):
      check isNil(buffer[slot]) == true
    check:
      isNil(buffer[GENESIS_SLOT]) == true
      isNil(buffer[Slot(1923340)]) == false
      buffer[Slot(1923340)][].slot == Slot(1923340)
      isNil(buffer[Slot(1923341)]) == false
      buffer[Slot(1923341)][].slot == Slot(1923341)
      isNil(buffer[Slot(1923342)]) == false
      buffer[Slot(1923342)][].slot == Slot(1923342)
      isNil(buffer[Slot(1923343)]) == true
      isNil(buffer[Slot(1923344)]) == true
      isNil(buffer[Slot(1923345)]) == false
      buffer[Slot(1923345)][].slot == Slot(1923345)
      isNil(buffer[Slot(1923346)]) == true
      isNil(buffer[Slot(1923347)]) == true
      isNil(buffer[Slot(1923348)]) == true
      isNil(buffer[Slot(1923349)]) == true
      isNil(buffer[Slot(1923350)]) == false
      buffer[Slot(1923350)][].slot == Slot(1923350)
      isNil(buffer[Slot(1923351)]) == true
      isNil(buffer[FAR_FUTURE_SLOT]) == true

  test "Add and query blocks test [backward]":
    var buffer = BlocksRangeBuffer.init(SyncQueueKind.Backward)
    const TestChain = [
      (Slot(1923340), createRoot(5), createRoot(4)),
      (Slot(1923339), createRoot(4), createRoot(3)),
      (Slot(1923338), createRoot(3), createRoot(2)),
      (Slot(1923335), createRoot(2), createRoot(1)),
      (Slot(1923330), createRoot(1), createRoot(0))
    ]
    for vector in TestChain:
      let res = buffer.add(createBlock(vector[0], vector[1], vector[2]))
      check res.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923341)):
      check isNil(buffer[slot]) == true
    check:
      isNil(buffer[FAR_FUTURE_SLOT]) == true
      isNil(buffer[Slot(1923340)]) == false
      buffer[Slot(1923340)][].slot == Slot(1923340)
      isNil(buffer[Slot(1923339)]) == false
      buffer[Slot(1923339)][].slot == Slot(1923339)
      isNil(buffer[Slot(1923338)]) == false
      buffer[Slot(1923338)][].slot == Slot(1923338)
      isNil(buffer[Slot(1923337)]) == true
      isNil(buffer[Slot(1923336)]) == true
      isNil(buffer[Slot(1923335)]) == false
      buffer[Slot(1923335)][].slot == Slot(1923335)
      isNil(buffer[Slot(1923334)]) == true
      isNil(buffer[Slot(1923333)]) == true
      isNil(buffer[Slot(1923332)]) == true
      isNil(buffer[Slot(1923331)]) == true
      isNil(buffer[Slot(1923330)]) == false
      buffer[Slot(1923330)][].slot == Slot(1923330)
      isNil(buffer[Slot(1923329)]) == true
      isNil(buffer[GENESIS_SLOT]) == true

  test "Block insertion test [forward]":
    var buffer = BlocksRangeBuffer.init(SyncQueueKind.Forward)
    const TestChain = [
      (Slot(1923340), createRoot(1), createRoot(0)),
      (Slot(1923341), createRoot(2), createRoot(1)),
      (Slot(1923342), createRoot(3), createRoot(2)),
      (Slot(1923345), createRoot(4), createRoot(3)),
      (Slot(1923350), createRoot(5), createRoot(4))
    ]
    for vector in TestChain:
      check buffer.add(createBlock(vector[0], vector[1], vector[2])).isOk()

    check:
      len(buffer) == 11

    let r1 =
      buffer.add(createBlock(Slot(1923350), createRoot(6), createRoot(0)))
    check:
      r1.isErr() == true
      r1.error == VerifierError.MissingParent

    let r2 =
      buffer.add(createBlock(Slot(1923350), createRoot(7), createRoot(4)))
    check:
      r2.isOk() == true
      buffer[Slot(1923350)][].root == createRoot(7)
      len(buffer) == 11

    let r3 =
      buffer.add(createBlock(Slot(1923349), createRoot(8), createRoot(3)))
    check:
      r3.isErr() == true
      r3.error == VerifierError.MissingParent

    let r4 =
      buffer.add(createBlock(Slot(1923349), createRoot(8), createRoot(4)))
    check:
      r4.isOk() == true
      isNil(buffer[Slot(1923350)]) == true
      buffer[Slot(1923349)][].root == createRoot(8)
      len(buffer) == 10

    let r5 =
      buffer.add(createBlock(Slot(1923346), createRoot(9), createRoot(2)))
    check:
      r5.isErr() == true
      r5.error == VerifierError.MissingParent

    let r6 =
      buffer.add(createBlock(Slot(1923346), createRoot(9), createRoot(4)))
    check r6.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923347)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923346)][].root == createRoot(9)
      len(buffer) == 7

    let r7 =
      buffer.add(createBlock(Slot(1923345), createRoot(10), createRoot(3)))
    check r7.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923346)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923345)][].root == createRoot(10)
      len(buffer) == 6

    let r8 =
      buffer.add(createBlock(Slot(1923345), createRoot(11), createRoot(3)))
    check r8.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923346)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923345)][].root == createRoot(11)
      len(buffer) == 6

    let r9 =
      buffer.add(createBlock(Slot(1923344), createRoot(12), createRoot(3)))
    check r9.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923345)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923344)][].root == createRoot(12)
      len(buffer) == 5

    let r10 =
      buffer.add(createBlock(Slot(1923343), createRoot(13), createRoot(3)))
    check r10.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923344)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923343)][].root == createRoot(13)
      len(buffer) == 4

    let r11 =
      buffer.add(createBlock(Slot(1923342), createRoot(14), createRoot(2)))
    check r11.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923343)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923342)][].root == createRoot(14)
      len(buffer) == 3

    let r12 =
      buffer.add(createBlock(Slot(1923341), createRoot(15), createRoot(1)))
    check r12.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923342)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923341)][].root == createRoot(15)
      len(buffer) == 2

    let r13 =
      buffer.add(createBlock(Slot(1923340), createRoot(16), createRoot(0)))
    check r13.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923341)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923340)][].root == createRoot(16)
      len(buffer) == 1

    let r14 =
      buffer.add(createBlock(Slot(1923339), createRoot(17), createRoot(0)))
    check r14.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923340)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923339)][].root == createRoot(17)
      len(buffer) == 1

    let r15 =
      buffer.add(createBlock(Slot(1923335), createRoot(18), createRoot(0)))
    check r15.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923336)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923335)][].root == createRoot(18)
      len(buffer) == 1

    let r16 =
      buffer.add(createBlock(Slot(1923330), createRoot(19), createRoot(0)))
    check r16.isOk() == true
    for slot in SlotRange.init(Slot(1923350), Slot(1923331)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923330)][].root == createRoot(19)
      len(buffer) == 1

    let r17 =
      buffer.add(createBlock(Slot(1923329), createRoot(20), createRoot(0)))
    check:
      r17.isOk()
      len(buffer) == 1
      buffer[Slot(1923329)][].root == createRoot(20)

  test "Block insertion test [backward]":
    var buffer = BlocksRangeBuffer.init(SyncQueueKind.Backward)
    const TestChain = [
      (Slot(1923340), createRoot(5), createRoot(4)),
      (Slot(1923339), createRoot(4), createRoot(3)),
      (Slot(1923338), createRoot(3), createRoot(2)),
      (Slot(1923335), createRoot(2), createRoot(1)),
      (Slot(1923330), createRoot(1), createRoot(0))
    ]
    for vector in TestChain:
      check buffer.add(createBlock(vector[0], vector[1], vector[2])).isOk()

    check:
      len(buffer) == 11

    let r1 =
      buffer.add(createBlock(Slot(1923330), createRoot(6), createRoot(0)))
    check:
      r1.isErr() == true
      r1.error == VerifierError.MissingParent

    let r2 =
      buffer.add(createBlock(Slot(1923330), createRoot(1), createRoot(10)))
    check:
      r2.isOk() == true
      buffer[Slot(1923330)][].root == createRoot(1)
      len(buffer) == 11

    let r3 =
      buffer.add(createBlock(Slot(1923331), createRoot(8), createRoot(3)))
    check:
      r3.isErr() == true
      r3.error == VerifierError.MissingParent

    let r4 =
      buffer.add(createBlock(Slot(1923331), createRoot(1), createRoot(11)))
    check:
      r4.isOk() == true
      isNil(buffer[Slot(1923330)]) == true
      buffer[Slot(1923331)][].root == createRoot(1)
      len(buffer) == 10

    let r5 =
      buffer.add(createBlock(Slot(1923334), createRoot(9), createRoot(2)))
    check:
      r5.isErr() == true
      r5.error == VerifierError.MissingParent

    let r6 =
      buffer.add(createBlock(Slot(1923334), createRoot(1), createRoot(12)))
    check r6.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923333)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923334)][].root == createRoot(1)
      len(buffer) == 7

    let r7 =
      buffer.add(createBlock(Slot(1923335), createRoot(2), createRoot(13)))
    check r7.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923334)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923335)][].root == createRoot(2)
      len(buffer) == 6

    let r8 =
      buffer.add(createBlock(Slot(1923335), createRoot(2), createRoot(14)))
    check r8.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923334)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923335)][].root == createRoot(2)
      len(buffer) == 6

    let r9 =
      buffer.add(createBlock(Slot(1923336), createRoot(2), createRoot(15)))
    check r9.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923335)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923336)][].root == createRoot(2)
      len(buffer) == 5

    let r10 =
      buffer.add(createBlock(Slot(1923337), createRoot(2), createRoot(16)))
    check r10.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923336)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923337)][].root == createRoot(2)
      len(buffer) == 4

    let r11 =
      buffer.add(createBlock(Slot(1923338), createRoot(3), createRoot(17)))
    check r11.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923337)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923338)][].root == createRoot(3)
      len(buffer) == 3

    let r12 =
      buffer.add(createBlock(Slot(1923339), createRoot(4), createRoot(18)))
    check r12.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923338)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923339)][].root == createRoot(4)
      len(buffer) == 2

    let r13 =
      buffer.add(createBlock(Slot(1923340), createRoot(16), createRoot(0)))
    check r13.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923339)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923340)][].root == createRoot(16)
      len(buffer) == 1

    let r14 =
      buffer.add(createBlock(Slot(1923341), createRoot(17), createRoot(0)))
    check r14.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923340)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923341)][].root == createRoot(17)
      len(buffer) == 1

    let r15 =
      buffer.add(createBlock(Slot(1923345), createRoot(18), createRoot(0)))
    check r15.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923344)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923345)][].root == createRoot(18)
      len(buffer) == 1

    let r16 =
      buffer.add(createBlock(Slot(1923350), createRoot(19), createRoot(0)))
    check r16.isOk() == true
    for slot in SlotRange.init(Slot(1923330), Slot(1923349)):
      check isNil(buffer[slot]) == true
    check:
      buffer[Slot(1923350)][].root == createRoot(19)
      len(buffer) == 1

    let r17 =
      buffer.add(createBlock(Slot(1923351), createRoot(20), createRoot(0)))
    check:
      r17.isOk()
      len(buffer) == 1
      buffer[Slot(1923351)][].root == createRoot(20)

  test "Buffer advance test [forward]":
    var buffer = BlocksRangeBuffer.init(SyncQueueKind.Forward)
    const TestChain = [
      (Slot(1923340), createRoot(1), createRoot(0)),
      (Slot(1923341), createRoot(2), createRoot(1)),
      (Slot(1923342), createRoot(3), createRoot(2)),
      (Slot(1923345), createRoot(4), createRoot(3)),
      (Slot(1923350), createRoot(5), createRoot(4))
    ]
    const TestVectors = [
      (Slot(1923320), Slot(1923340), Slot(1923350), 11),
      (Slot(1923330), Slot(1923340), Slot(1923350), 11),
      (Slot(1923335), Slot(1923340), Slot(1923350), 11),
      (Slot(1923340), Slot(1923340), Slot(1923350), 11),
      (Slot(1923341), Slot(1923341), Slot(1923350), 10),
      (Slot(1923342), Slot(1923342), Slot(1923350), 9),
      (Slot(1923343), Slot(1923345), Slot(1923350), 6),
      (Slot(1923344), Slot(1923345), Slot(1923350), 6),
      (Slot(1923345), Slot(1923345), Slot(1923350), 6),
      (Slot(1923346), Slot(1923350), Slot(1923350), 1),
      (Slot(1923347), Slot(1923350), Slot(1923350), 1),
      (Slot(1923348), Slot(1923350), Slot(1923350), 1),
      (Slot(1923349), Slot(1923350), Slot(1923350), 1),
      (Slot(1923350), Slot(1923350), Slot(1923350), 1)
    ]
    for vector in TestChain:
      check buffer.add(createBlock(vector[0], vector[1], vector[2])).isOk()

    check:
      buffer.startSlot == Slot(1923340)
      buffer.lastSlot == Slot(1923350)
      len(buffer) == 11

    for vector in TestVectors:
      buffer.advance(vector[0])
      check:
        buffer.startSlot == vector[1]
        buffer.lastSlot == vector[2]
        len(buffer) == vector[3]

    buffer.advance(Slot(1923351))
    check:
      len(buffer) == 0

  test "Buffer advance test [backward]":
    var buffer = BlocksRangeBuffer.init(SyncQueueKind.Backward)
    const TestChain = [
      (Slot(1923340), createRoot(5), createRoot(4)),
      (Slot(1923339), createRoot(4), createRoot(3)),
      (Slot(1923338), createRoot(3), createRoot(2)),
      (Slot(1923335), createRoot(2), createRoot(1)),
      (Slot(1923330), createRoot(1), createRoot(0))
    ]
    const TestVectors = [
      (Slot(1923360), Slot(1923340), Slot(1923330), 11),
      (Slot(1923350), Slot(1923340), Slot(1923330), 11),
      (Slot(1923345), Slot(1923340), Slot(1923330), 11),
      (Slot(1923340), Slot(1923340), Slot(1923330), 11),
      (Slot(1923339), Slot(1923339), Slot(1923330), 10),
      (Slot(1923338), Slot(1923338), Slot(1923330), 9),
      (Slot(1923337), Slot(1923335), Slot(1923330), 6),
      (Slot(1923336), Slot(1923335), Slot(1923330), 6),
      (Slot(1923335), Slot(1923335), Slot(1923330), 6),
      (Slot(1923334), Slot(1923330), Slot(1923330), 1),
      (Slot(1923333), Slot(1923330), Slot(1923330), 1),
      (Slot(1923332), Slot(1923330), Slot(1923330), 1),
      (Slot(1923331), Slot(1923330), Slot(1923330), 1),
      (Slot(1923330), Slot(1923330), Slot(1923330), 1)
    ]

    for vector in TestChain:
      check buffer.add(createBlock(vector[0], vector[1], vector[2])).isOk()

    check:
      buffer.startSlot == Slot(1923340)
      buffer.lastSlot == Slot(1923330)
      len(buffer) == 11

    for vector in TestVectors:
      buffer.advance(vector[0])
      check:
        buffer.startSlot == vector[1]
        buffer.lastSlot == vector[2]
        len(buffer) == vector[3]

    buffer.advance(Slot(1923329))
    check:
      len(buffer) == 0

  test "Buffer invalidate test [forward]":
    const TestChain = [
      (Slot(1923340), createRoot(1), createRoot(0)),
      (Slot(1923341), createRoot(2), createRoot(1)),
      (Slot(1923342), createRoot(3), createRoot(2)),
      (Slot(1923345), createRoot(4), createRoot(3)),
      (Slot(1923350), createRoot(5), createRoot(4))
    ]
    const TestVectors = [
      (GENESIS_SLOT, GENESIS_SLOT, GENESIS_SLOT, 0),
      (Slot(1923339), GENESIS_SLOT, GENESIS_SLOT, 0),
      (Slot(1923340), GENESIS_SLOT, GENESIS_SLOT, 0),
      (Slot(1923341), Slot(1923340), Slot(1923340), 1),
      (Slot(1923342), Slot(1923340), Slot(1923341), 2),
      (Slot(1923343), Slot(1923340), Slot(1923342), 3),
      (Slot(1923344), Slot(1923340), Slot(1923342), 3),
      (Slot(1923345), Slot(1923340), Slot(1923342), 3),
      (Slot(1923346), Slot(1923340), Slot(1923345), 6),
      (Slot(1923347), Slot(1923340), Slot(1923345), 6),
      (Slot(1923348), Slot(1923340), Slot(1923345), 6),
      (Slot(1923349), Slot(1923340), Slot(1923345), 6),
      (Slot(1923350), Slot(1923340), Slot(1923345), 6),
      (Slot(1923351), Slot(1923340), Slot(1923350), 11)
    ]
    for vector in TestVectors:
      var buffer = BlocksRangeBuffer.init(SyncQueueKind.Forward)
      for blck in TestChain:
        check buffer.add(createBlock(blck[0], blck[1], blck[2])).isOk()

      check:
        buffer.startSlot == Slot(1923340)
        buffer.lastSlot == Slot(1923350)
        len(buffer) == 11

      buffer.invalidate(vector[0])
      check:
        len(buffer) == vector[3]
      if len(buffer) > 0:
        check:
          buffer.startSlot == vector[1]
          buffer.lastSlot == vector[2]

  test "Buffer invalidate test [backward]":
    const TestChain = [
      (Slot(1923340), createRoot(5), createRoot(4)),
      (Slot(1923339), createRoot(4), createRoot(3)),
      (Slot(1923338), createRoot(3), createRoot(2)),
      (Slot(1923335), createRoot(2), createRoot(1)),
      (Slot(1923330), createRoot(1), createRoot(0))
    ]
    const TestVectors = [
      (FAR_FUTURE_SLOT, FAR_FUTURE_SLOT, FAR_FUTURE_SLOT, 0),
      (Slot(1923341), FAR_FUTURE_SLOT, FAR_FUTURE_SLOT, 0),
      (Slot(1923340), FAR_FUTURE_SLOT, FAR_FUTURE_SLOT, 0),
      (Slot(1923339), Slot(1923340), Slot(1923340), 1),
      (Slot(1923338), Slot(1923340), Slot(1923339), 2),
      (Slot(1923337), Slot(1923340), Slot(1923338), 3),
      (Slot(1923336), Slot(1923340), Slot(1923338), 3),
      (Slot(1923335), Slot(1923340), Slot(1923338), 3),
      (Slot(1923334), Slot(1923340), Slot(1923335), 6),
      (Slot(1923333), Slot(1923340), Slot(1923335), 6),
      (Slot(1923332), Slot(1923340), Slot(1923335), 6),
      (Slot(1923331), Slot(1923340), Slot(1923335), 6),
      (Slot(1923330), Slot(1923340), Slot(1923335), 6),
      (Slot(1923329), Slot(1923340), Slot(1923330), 11)
    ]
    for vector in TestVectors:
      var buffer = BlocksRangeBuffer.init(SyncQueueKind.Backward)
      for blck in TestChain:
        check buffer.add(createBlock(blck[0], blck[1], blck[2])).isOk()

      check:
        buffer.startSlot == Slot(1923340)
        buffer.lastSlot == Slot(1923330)
        len(buffer) == 11

      buffer.invalidate(vector[0])
      check:
        len(buffer) == vector[3]
      if len(buffer) > 0:
        check:
          buffer.startSlot == vector[1]
          buffer.lastSlot == vector[2]

  test "Range peek test [forward]":
    var buffer = BlocksRangeBuffer.init(SyncQueueKind.Forward)
    const TestChain = [
      (Slot(1923340), createRoot(1), createRoot(0)),
      (Slot(1923341), createRoot(2), createRoot(1)),
      (Slot(1923342), createRoot(3), createRoot(2)),
      (Slot(1923345), createRoot(4), createRoot(3)),
      (Slot(1923350), createRoot(5), createRoot(4))
    ]
    const TestVectors = [
      (Slot(1923320), Slot(1923360), 5,
        @[Slot(1923340), Slot(1923341), Slot(1923342), Slot(1923345),
          Slot(1923350)]),
      (Slot(1923330), Slot(1923360), 5,
        @[Slot(1923340), Slot(1923341), Slot(1923342), Slot(1923345),
          Slot(1923350)]),
      (Slot(1923340), Slot(1923360), 5,
        @[Slot(1923340), Slot(1923341), Slot(1923342), Slot(1923345),
          Slot(1923350)]),
      (Slot(1923341), Slot(1923360), 4,
        @[Slot(1923341), Slot(1923342), Slot(1923345), Slot(1923350)]),
      (Slot(1923342), Slot(1923360), 3,
        @[Slot(1923342), Slot(1923345), Slot(1923350)]),
      (Slot(1923343), Slot(1923360), 2, @[Slot(1923345), Slot(1923350)]),
      (Slot(1923344), Slot(1923350), 2, @[Slot(1923345), Slot(1923350)]),
      (Slot(1923345), Slot(1923345), 1, @[Slot(1923345)]),
      (Slot(1923346), Slot(1923350), 1, @[Slot(1923350)]),
      (Slot(1923350), Slot(1923350), 1, @[Slot(1923350)]),
      (Slot(1923350), Slot(1923360), 1, @[Slot(1923350)]),
      (Slot(1923351), Slot(1923360), 0, default(seq[Slot])),
      (Slot(1923320), Slot(1923329), 0, default(seq[Slot])),
      (Slot(1923320), Slot(1923340), 1, @[Slot(1923340)]),
      (Slot(1923330), Slot(1923341), 2, @[Slot(1923340), Slot(1923341)]),
      (Slot(1923341), Slot(1923342), 2, @[Slot(1923341), Slot(1923342)]),
      (Slot(1923341), Slot(1923344), 2, @[Slot(1923341), Slot(1923342)])
    ]
    for vector in TestChain:
      check buffer.add(createBlock(vector[0], vector[1], vector[2])).isOk()

    for vector in TestVectors:
      let
        count = int(vector[1] - vector[0] + 1)
        res = buffer.peekRange(SyncRange.init(vector[0], uint64(count)))
      check len(res) == vector[2]
      for i in 0 ..< len(vector[3]):
        check res[i][].slot == vector[3][i]

  test "Range peek test [backward]":
    var buffer = BlocksRangeBuffer.init(SyncQueueKind.Backward)
    const TestChain = [
      (Slot(1923340), createRoot(5), createRoot(4)),
      (Slot(1923339), createRoot(4), createRoot(3)),
      (Slot(1923338), createRoot(3), createRoot(2)),
      (Slot(1923335), createRoot(2), createRoot(1)),
      (Slot(1923330), createRoot(1), createRoot(0))
    ]
    const TestVectors = [
      (Slot(1923320), Slot(1923360), 5,
        @[Slot(1923330), Slot(1923335), Slot(1923338), Slot(1923339),
          Slot(1923340)]),
      (Slot(1923330), Slot(1923360), 5,
        @[Slot(1923330), Slot(1923335), Slot(1923338), Slot(1923339),
          Slot(1923340)]),
      (Slot(1923330), Slot(1923360), 5,
        @[Slot(1923330), Slot(1923335), Slot(1923338), Slot(1923339),
          Slot(1923340)]),
      (Slot(1923331), Slot(1923360), 4,
        @[Slot(1923335), Slot(1923338), Slot(1923339), Slot(1923340)]),
      (Slot(1923332), Slot(1923360), 4,
        @[Slot(1923335), Slot(1923338), Slot(1923339), Slot(1923340)]),
      (Slot(1923333), Slot(1923360), 4,
        @[Slot(1923335), Slot(1923338), Slot(1923339), Slot(1923340)]),
      (Slot(1923334), Slot(1923360), 4,
        @[Slot(1923335), Slot(1923338), Slot(1923339), Slot(1923340)]),
      (Slot(1923335), Slot(1923360), 4,
        @[Slot(1923335), Slot(1923338), Slot(1923339), Slot(1923340)]),
      (Slot(1923336), Slot(1923360), 3,
        @[Slot(1923338), Slot(1923339), Slot(1923340)]),
      (Slot(1923337), Slot(1923360), 3,
        @[Slot(1923338), Slot(1923339), Slot(1923340)]),
      (Slot(1923338), Slot(1923360), 3,
        @[Slot(1923338), Slot(1923339), Slot(1923340)]),
      (Slot(1923339), Slot(1923360), 2, @[Slot(1923339), Slot(1923340)]),
      (Slot(1923340), Slot(1923360), 1, @[Slot(1923340)]),
      (Slot(1923341), Slot(1923341), 0, default(seq[Slot])),
      (Slot(1923320), Slot(1923320), 0, default(seq[Slot])),
      (Slot(1923360), Slot(1923360), 0, default(seq[Slot])),
      (Slot(1923310), Slot(1923330), 1, @[Slot(1923330)]),
      (Slot(1923340), Slot(1923340), 1, @[Slot(1923340)]),
      (Slot(1923340), Slot(1923341), 1, @[Slot(1923340)]),
      (Slot(1923336), Slot(1923338), 1, @[Slot(1923338)]),
      (Slot(1923335), Slot(1923338), 2, @[Slot(1923335), Slot(1923338)]),
      (Slot(1923337), Slot(1923339), 2, @[Slot(1923338), Slot(1923339)]),
      (Slot(1923339), Slot(1923360), 2, @[Slot(1923339), Slot(1923340)])
    ]

    for vector in TestChain:
      check buffer.add(createBlock(vector[0], vector[1], vector[2])).isOk()

    for vector in TestVectors:
      let
        count = int(vector[1] - vector[0] + 1)
        res = buffer.peekRange(SyncRange.init(vector[0], uint64(count)))
      check len(res) == vector[2]
      for i in 0 ..< len(vector[3]):
        check res[i][].slot == vector[3][i]

  test "Range peek real test cases [forward]":
    var
      buffer1 = BlocksRangeBuffer.init(SyncQueueKind.Forward)
      buffer2 = BlocksRangeBuffer.init(SyncQueueKind.Forward)

    const TestChain = [
      (Slot(1254722), createRoot(1), createRoot(0)),
      (Slot(1254723), createRoot(2), createRoot(1)),
      (Slot(1254724), createRoot(3), createRoot(2)),
      (Slot(1254725), createRoot(4), createRoot(3)),
      (Slot(1254726), createRoot(5), createRoot(4)),
      (Slot(1254727), createRoot(6), createRoot(5)),
      (Slot(1254728), createRoot(7), createRoot(6)),
      (Slot(1254729), createRoot(8), createRoot(7)),
      (Slot(1254731), createRoot(9), createRoot(8)),
      (Slot(1254732), createRoot(10), createRoot(9)),
      (Slot(1254733), createRoot(11), createRoot(10)),
      (Slot(1254734), createRoot(12), createRoot(11)),
      (Slot(1254735), createRoot(13), createRoot(12)),
      (Slot(1254736), createRoot(14), createRoot(13)),
      (Slot(1254737), createRoot(15), createRoot(14)),
      (Slot(1254738), createRoot(16), createRoot(15)),
      (Slot(1254739), createRoot(17), createRoot(16)),
      (Slot(1254740), createRoot(18), createRoot(17)),
      (Slot(1254741), createRoot(19), createRoot(18)),
      (Slot(1254743), createRoot(20), createRoot(19)),
      (Slot(1254745), createRoot(21), createRoot(20)),
      (Slot(1254746), createRoot(22), createRoot(21)),
      (Slot(1254747), createRoot(23), createRoot(22)),
      (Slot(1254748), createRoot(24), createRoot(23)),
      (Slot(1254749), createRoot(25), createRoot(24)),
      (Slot(1254750), createRoot(26), createRoot(25)),
      (Slot(1254752), createRoot(27), createRoot(26)),
      (Slot(1254753), createRoot(28), createRoot(27))
    ]

    const TestVectors = [
      (Slot(1254720), Slot(1254751), 26,
       @[Slot(1254722), Slot(1254723), Slot(1254724), Slot(1254725),
         Slot(1254726), Slot(1254727), Slot(1254728), Slot(1254729),
         Slot(1254731), Slot(1254732), Slot(1254733), Slot(1254734),
         Slot(1254735), Slot(1254736), Slot(1254737), Slot(1254738),
         Slot(1254739), Slot(1254740), Slot(1254741), Slot(1254743),
         Slot(1254745), Slot(1254746), Slot(1254747), Slot(1254748),
         Slot(1254749), Slot(1254750)])
    ]

    for vector in TestChain:
      check buffer1.add(createBlock(vector[0], vector[1], vector[2])).isOk()
      check buffer2.add(createBlock(vector[0], vector[1], vector[2])).isOk()

    for vector in TestVectors:
      let
        count = int(vector[1] - vector[0] + 1)
        res1 = buffer1.peekRange(SyncRange.init(vector[0], uint64(count)))
        res2 = buffer2.peekRange(SyncRange.init(vector[0], uint64(count)))
      check:
        len(res1) == vector[2]
        len(res2) == vector[2]

      for i in 0 ..< len(res1):
        check res1[i][].slot == vector[3][i]
      for i in 0 ..< len(res2):
        check res2[i][].slot == vector[3][i]
