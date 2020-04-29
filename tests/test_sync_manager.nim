{.used.}

import unittest
import chronos
import ../beacon_chain/sync_manager

suite "SyncManager test suite":
  proc createChain(start, finish: Slot): seq[SignedBeaconBlock] =
    doAssert(start <= finish)
    let count = int(finish - start + 1'u64)
    result = newSeq[SignedBeaconBlock](count)
    var curslot = start
    for item in result.mitems():
      item.message.slot = curslot
      curslot = curslot + 1'u64

  test "[SyncQueue] Start and finish slots equal":
    var queue = SyncQueue.init(Slot(0), Slot(0), 1'u64, nil)
    check len(queue) == 1
    var r11 = queue.pop(Slot(0))
    check len(queue) == 0
    queue.push(r11)
    check len(queue) == 1
    var r11e = queue.pop(Slot(0))
    check:
      len(queue) == 0
      r11e == r11
      r11.slot == Slot(0) and r11.count == 1'u64 and r11.step == 1'u64

  test "[SyncQueue] Two full requests success/fail":
    var queue = SyncQueue.init(Slot(0), Slot(1), 1'u64, nil)
    check len(queue) == 2
    var r21 = queue.pop(Slot(1))
    check len(queue) == 1
    var r22 = queue.pop(Slot(1))
    check len(queue) == 0
    queue.push(r22)
    check len(queue) == 1
    queue.push(r21)
    check len(queue) == 2
    var r21e = queue.pop(Slot(1))
    check len(queue) == 1
    var r22e = queue.pop(Slot(1))
    check:
      len(queue) == 0
      r21 == r21e
      r22 == r22e
      r21.slot == Slot(0) and r21.count == 1'u64 and r21.step == 1'u64
      r22.slot == Slot(1) and r22.count == 1'u64 and r22.step == 1'u64

  test "[SyncQueue] Full and incomplete success/fail start from zero":
    var queue = SyncQueue.init(Slot(0), Slot(4), 2'u64, nil)
    check len(queue) == 5
    var r31 = queue.pop(Slot(4))
    check len(queue) == 3
    var r32 = queue.pop(Slot(4))
    check len(queue) == 1
    var r33 = queue.pop(Slot(4))
    check len(queue) == 0
    queue.push(r33)
    check len(queue) == 1
    queue.push(r32)
    check len(queue) == 3
    queue.push(r31)
    check len(queue) == 5
    var r31e = queue.pop(Slot(4))
    check len(queue) == 3
    var r32e = queue.pop(Slot(4))
    check len(queue) == 1
    var r33e = queue.pop(Slot(4))
    check:
      len(queue) == 0
      r31 == r31e
      r32 == r32e
      r33 == r33e
      r31.slot == Slot(0) and r31.count == 2'u64 and r31.step == 1'u64
      r32.slot == Slot(2) and r32.count == 2'u64 and r32.step == 1'u64
      r33.slot == Slot(4) and r33.count == 1'u64 and r33.step == 1'u64

  test "[SyncQueue] Full and incomplete success/fail start from non-zero":
    var queue = SyncQueue.init(Slot(1), Slot(5), 3'u64, nil)
    check len(queue) == 5
    var r41 = queue.pop(Slot(5))
    check len(queue) == 2
    var r42 = queue.pop(Slot(5))
    check len(queue) == 0
    queue.push(r42)
    check len(queue) == 2
    queue.push(r41)
    check len(queue) == 5
    var r41e = queue.pop(Slot(5))
    check len(queue) == 2
    var r42e = queue.pop(Slot(5))
    check:
      len(queue) == 0
      r41 == r41e
      r42 == r42e
      r41.slot == Slot(1) and r41.count == 3'u64 and r41.step == 1'u64
      r42.slot == Slot(4) and r42.count == 2'u64 and r42.step == 1'u64

  test "[SyncQueue] Smart and stupid success/fail":
    var queue = SyncQueue.init(Slot(0), Slot(4), 5'u64, nil)
    check len(queue) == 5
    var r51 = queue.pop(Slot(3))
    check len(queue) == 1
    var r52 = queue.pop(Slot(4))
    check len(queue) == 0
    queue.push(r52)
    check len(queue) == 1
    queue.push(r51)
    check len(queue) == 5
    var r51e = queue.pop(Slot(3))
    check len(queue) == 1
    var r52e = queue.pop(Slot(4))
    check:
      len(queue) == 0
      r51 == r51e
      r52 == r52e
      r51.slot == Slot(0) and r51.count == 4'u64 and r51.step == 1'u64
      r52.slot == Slot(4) and r52.count == 1'u64 and r52.step == 1'u64

  test "[SyncQueue] One smart and one stupid + debt split + empty":
    var queue = SyncQueue.init(Slot(0), Slot(4), 5'u64, nil)
    check len(queue) == 5
    var r61 = queue.pop(Slot(4))
    check len(queue) == 0
    queue.push(r61)
    var r61e = queue.pop(Slot(2))
    check len(queue) == 2
    var r62e = queue.pop(Slot(2))
    check len(queue) == 2
    check r62e.isEmpty()
    var r63e = queue.pop(Slot(3))
    check len(queue) == 1
    var r64e = queue.pop(Slot(4))
    check:
      len(queue) == 0
      r61.slot == Slot(0) and r61.count == 5'u64 and r61.step == 1'u64
      r61e.slot == Slot(0) and r61e.count == 3'u64 and r61e.step == 1'u64
      r62e.isEmpty()
      r63e.slot == Slot(3) and r63e.count == 1'u64 and r63e.step == 1'u64
      r64e.slot == Slot(4) and r64e.count == 1'u64 and r64e.step == 1'u64

  test "[SyncQueue] Async unordered push start from zero":
    proc test(): Future[bool] {.async.} =
      var counter = 0

      proc receiver(list: openarray[SignedBeaconBlock]): bool =
        result = true
        for item in list:
          if item.message.slot == Slot(counter):
            inc(counter)
          else:
            result = false
            break

      var chain = createChain(Slot(0), Slot(2))
      var queue = SyncQueue.init(Slot(0), Slot(2), 1'u64, receiver, 1)
      var r11 = queue.pop(Slot(2))
      var r12 = queue.pop(Slot(2))
      var r13 = queue.pop(Slot(2))
      var f13 = queue.push(r13, @[chain[2]])
      var f12 = queue.push(r12, @[chain[1]])
      await sleepAsync(100.milliseconds)
      doAssert(f12.finished == false)
      doAssert(f13.finished == false)
      doAssert(counter == 0)
      var f11 = queue.push(r11, @[chain[0]])
      doAssert(counter == 1)
      doAssert(f11.finished == true and f11.failed == false)
      await sleepAsync(100.milliseconds)
      doAssert(f12.finished == true and f12.failed == false)
      doAssert(f13.finished == true and f13.failed == false)
      doAssert(counter == 3)
      result = true

    check waitFor(test())

  test "[SyncQueue] Async unordered push with not full start from non-zero":
    proc test(): Future[bool] {.async.} =
      var counter = 5

      proc receiver(list: openarray[SignedBeaconBlock]): bool =
        result = true
        for item in list:
          if item.message.slot == Slot(counter):
            inc(counter)
          else:
            result = false
            break
      var chain = createChain(Slot(5), Slot(11))
      var queue = SyncQueue.init(Slot(5), Slot(11), 2'u64, receiver, 2)
      var r21 = queue.pop(Slot(11))
      var r22 = queue.pop(Slot(11))
      var r23 = queue.pop(Slot(11))
      var r24 = queue.pop(Slot(11))

      var f24 = queue.push(r24, @[chain[6]])
      var f22 = queue.push(r22, @[chain[2], chain[3]])
      doAssert(f24.finished == false)
      doAssert(f22.finished == true and f22.failed == false)
      doAssert(counter == 5)
      var f21 = queue.push(r21, @[chain[0], chain[1]])
      doAssert(f21.finished == true and f21.failed == false)
      await sleepAsync(100.milliseconds)
      doAssert(f24.finished == true and f24.failed == false)
      doAssert(counter == 9)
      var f23 = queue.push(r23, @[chain[4], chain[5]])
      doAssert(f23.finished == true and f23.failed == false)
      doAssert(counter == 12)
      await sleepAsync(100.milliseconds)
      doAssert(counter == 12)
      result = true

    check waitFor(test())
