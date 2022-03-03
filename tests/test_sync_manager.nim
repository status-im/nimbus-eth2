{.used.}

import std/strutils
import unittest2
import chronos
import ../beacon_chain/gossip_processing/block_processor,
       ../beacon_chain/sync/sync_manager,
       ../beacon_chain/spec/datatypes/phase0,
       ../beacon_chain/spec/forks

type
  SomeTPeer = ref object

proc `$`(peer: SomeTPeer): string =
  "SomeTPeer"

template shortLog(peer: SomeTPeer): string =
  $peer

proc updateScore(peer: SomeTPeer, score: int) =
  discard

proc getFirstSlotAtFinalizedEpoch(): Slot =
  Slot(0)

proc getSafeSlot(): Slot =
  Slot(1024)

type
  BlockEntry = object
    blck*: ForkedSignedBeaconBlock
    resfut*: Future[Result[void, BlockError]]

proc collector(queue: AsyncQueue[BlockEntry]): BlockVerifier =
  # This sets up a fake block verifiation collector that simply puts the blocks
  # in the async queue, similar to how BlockProcessor does it - as far as
  # testing goes, this is risky because it might introduce differences between
  # the BlockProcessor and this test
  proc verify(signedBlock: ForkedSignedBeaconBlock): Future[Result[void, BlockError]] =
    let fut = newFuture[Result[void, BlockError]]()
    try: queue.addLastNoWait(BlockEntry(blck: signedBlock, resfut: fut))
    except CatchableError as exc: raiseAssert exc.msg
    return fut

  return verify
suite "SyncManager test suite":
  proc createChain(start, finish: Slot): seq[ref ForkedSignedBeaconBlock] =
    doAssert(start <= finish)
    let count = int(finish - start + 1'u64)
    var res = newSeq[ref ForkedSignedBeaconBlock](count)
    var curslot = start
    for item in res.mitems():
      item = new ForkedSignedBeaconBlock
      item[].phase0Data.message.slot = curslot
      curslot = curslot + 1'u64
    res

  proc getSlice(chain: openArray[ref ForkedSignedBeaconBlock], startSlot: Slot,
                request: SyncRequest[SomeTPeer]): seq[ref ForkedSignedBeaconBlock] =
    let
      startIndex = int(request.slot - startSlot)
      finishIndex = int(request.slot - startSlot) + int(request.count) - 1
    var res = newSeq[ref ForkedSignedBeaconBlock](1 + finishIndex - startIndex)
    for i in 0..<res.len:
      res[i] = newClone(chain[i + startIndex][])
    res

  template startAndFinishSlotsEqual(kind: SyncQueueKind) =
    let p1 = SomeTPeer()
    let aq = newAsyncQueue[BlockEntry]()

    var queue = SyncQueue.init(SomeTPeer, kind,
                               Slot(0), Slot(0), 1'u64,
                               getFirstSlotAtFinalizedEpoch, collector(aq))
    check:
      len(queue) == 1
      pendingLen(queue) == 0
      debtLen(queue) == 0
    var r11 = queue.pop(Slot(0), p1)
    check:
      len(queue) == 1
      pendingLen(queue) == 1
      debtLen(queue) == 0
    queue.push(r11)
    check:
      pendingLen(queue) == 1
      len(queue) == 1
      debtLen(queue) == 1
    var r11e = queue.pop(Slot(0), p1)
    check:
      len(queue) == 1
      pendingLen(queue) == 1
      debtLen(queue) == 0
      r11e == r11
      r11.item == p1
      r11e.item == r11.item
      r11.slot == Slot(0) and r11.count == 1'u64 and r11.step == 1'u64

  template passThroughLimitsTest(kind: SyncQueueKind) =
    let
      p1 = SomeTPeer()
      p2 = SomeTPeer()

    let Checks =
      case kind
      of SyncQueueKind.Forward:
        @[
          # Tests with zero start.
          (Slot(0), Slot(0), 1'u64, (Slot(0), 1'u64),
           1'u64, 0'u64, 0'u64, 1'u64, 1'u64, 0'u64),
          (Slot(0), Slot(0), 16'u64, (Slot(0), 1'u64),
           1'u64, 0'u64, 0'u64, 1'u64, 1'u64, 0'u64),
          (Slot(0), Slot(1), 2'u64, (Slot(0), 2'u64),
           2'u64, 0'u64, 0'u64, 2'u64, 2'u64, 0'u64),
          (Slot(0), Slot(1), 16'u64, (Slot(0), 2'u64),
           2'u64, 0'u64, 0'u64, 2'u64, 2'u64, 0'u64),
          (Slot(0), Slot(15), 16'u64, (Slot(0), 16'u64),
           16'u64, 0'u64, 0'u64, 16'u64, 16'u64, 0'u64),
          (Slot(0), Slot(15), 32'u64, (Slot(0), 16'u64),
           16'u64, 0'u64, 0'u64, 16'u64, 16'u64, 0'u64),
          # Tests with non-zero start.
          (Slot(1021), Slot(1021), 1'u64, (Slot(1021), 1'u64),
           1'u64, 0'u64, 0'u64, 1'u64, 1'u64, 0'u64),
          (Slot(1021), Slot(1021), 16'u64, (Slot(1021), 1'u64),
           1'u64, 0'u64, 0'u64, 1'u64, 1'u64, 0'u64),
          (Slot(1021), Slot(1022), 2'u64, (Slot(1021), 2'u64),
           2'u64, 0'u64, 0'u64, 2'u64, 2'u64, 0'u64),
          (Slot(1021), Slot(1022), 16'u64, (Slot(1021), 2'u64),
           2'u64, 0'u64, 0'u64, 2'u64, 2'u64, 0'u64),
          (Slot(1021), Slot(1036), 16'u64, (Slot(1021), 16'u64),
           16'u64, 0'u64, 0'u64, 16'u64, 16'u64, 0'u64),
          (Slot(1021), Slot(1036), 32'u64, (Slot(1021), 16'u64),
           16'u64, 0'u64, 0'u64, 16'u64, 16'u64, 0'u64),
        ]
      of SyncQueueKind.Backward:
        @[
          # Tests with zero finish.
          (Slot(0), Slot(0), 1'u64, (Slot(0), 1'u64),
           1'u64, 0'u64, 0'u64, 1'u64, 1'u64, 0'u64),
          (Slot(0), Slot(0), 16'u64, (Slot(0), 1'u64),
           1'u64, 0'u64, 0'u64, 1'u64, 1'u64, 0'u64),
          (Slot(1), Slot(0), 2'u64, (Slot(0), 2'u64),
           2'u64, 0'u64, 0'u64, 2'u64, 2'u64, 0'u64),
          (Slot(1), Slot(0), 16'u64, (Slot(0), 2'u64),
           2'u64, 0'u64, 0'u64, 2'u64, 2'u64, 0'u64),
          (Slot(15), Slot(0), 16'u64, (Slot(0), 16'u64),
           16'u64, 0'u64, 0'u64, 16'u64, 16'u64, 0'u64),
          (Slot(15), Slot(0), 32'u64, (Slot(0), 16'u64),
           16'u64, 0'u64, 0'u64, 16'u64, 16'u64, 0'u64),
          # Tests with non-zero finish.
          (Slot(1021), Slot(1021), 1'u64, (Slot(1021), 1'u64),
           1'u64, 0'u64, 0'u64, 1'u64, 1'u64, 0'u64),
          (Slot(1021), Slot(1021), 16'u64, (Slot(1021), 1'u64),
           1'u64, 0'u64, 0'u64, 1'u64, 1'u64, 0'u64),
          (Slot(1022), Slot(1021), 2'u64, (Slot(1021), 2'u64),
           2'u64, 0'u64, 0'u64, 2'u64, 2'u64, 0'u64),
          (Slot(1022), Slot(1021), 16'u64, (Slot(1021), 2'u64),
           2'u64, 0'u64, 0'u64, 2'u64, 2'u64, 0'u64),
          (Slot(1036), Slot(1021), 16'u64, (Slot(1021), 16'u64),
           16'u64, 0'u64, 0'u64, 16'u64, 16'u64, 0'u64),
          (Slot(1036), Slot(1021), 32'u64, (Slot(1021), 16'u64),
           16'u64, 0'u64, 0'u64, 16'u64, 16'u64, 0'u64),
        ]

    for item in Checks:
      let aq = newAsyncQueue[BlockEntry]()
      var queue = SyncQueue.init(SomeTPeer, kind,
                                 item[0], item[1], item[2],
                                 getFirstSlotAtFinalizedEpoch, collector(aq))
      check:
        len(queue) == item[4]
        pendingLen(queue) == item[5]
        debtLen(queue) == item[6]
      var req1 = queue.pop(max(item[0], item[1]), p1)
      check:
        len(queue) == item[7]
        pendingLen(queue) == item[8]
        debtLen(queue) == item[9]
      var req2 = queue.pop(max(item[0], item[1]), p2)
      check:
        req1.isEmpty() == false
        req1.slot == item[3][0]
        req1.count == item[3][1]
        req1.step == 1'u64
        req2.isEmpty() == true

  template twoFullRequests(kkind: SyncQueueKind) =
    let aq = newAsyncQueue[BlockEntry]()
    var queue =
      case kkind
      of SyncQueueKind.Forward:
        SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                       Slot(0), Slot(1), 1'u64,
                       getFirstSlotAtFinalizedEpoch, collector(aq))
      of SyncQueueKind.Backward:
        SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                       Slot(1), Slot(0), 1'u64,
                       getFirstSlotAtFinalizedEpoch, collector(aq))

    let p1 = SomeTPeer()
    let p2 = SomeTPeer()
    check:
      len(queue) == 2
      pendingLen(queue) == 0
      debtLen(queue) == 0
    var r21 = queue.pop(Slot(1), p1)
    check:
      len(queue) == 2
      pendingLen(queue) == 1
      debtLen(queue) == 0
    var r22 = queue.pop(Slot(1), p2)
    check:
      len(queue) == 2
      pendingLen(queue) == 2
      debtLen(queue) == 0
    queue.push(r22)
    check:
      len(queue) == 2
      pendingLen(queue) == 2
      debtLen(queue) == 1
    queue.push(r21)
    check:
      len(queue) == 2
      pendingLen(queue) == 2
      debtLen(queue) == 2
    var r21e = queue.pop(Slot(1), p1)
    check:
      len(queue) == 2
      pendingLen(queue) == 2
      debtLen(queue) == 1
    var r22e = queue.pop(Slot(1), p2)
    check:
      len(queue) == 2
      pendingLen(queue) == 2
      debtLen(queue) == 0
      r21 == r21e
      r22 == r22e
      r21.item == p1
      r22.item == p2
      r21.item == r21e.item
      r22.item == r22e.item
    case kkind
    of SyncQueueKind.Forward:
      check:
        r21.slot == Slot(0) and r21.count == 1'u64 and r21.step == 1'u64
        r22.slot == Slot(1) and r22.count == 1'u64 and r22.step == 1'u64
    of SyncQueueKind.Backward:
      check:
        r21.slot == Slot(1) and r21.count == 1'u64 and r21.step == 1'u64
        r22.slot == Slot(0) and r22.count == 1'u64 and r22.step == 1'u64

  template done(b: BlockEntry) =
    b.resfut.complete(Result[void, BlockError].ok())
  template fail(b: BlockEntry, e: untyped) =
    b.resfut.complete(Result[void, BlockError].err(e))

  template smokeTest(kkind: SyncQueueKind, start, finish: Slot,
                     chunkSize: uint64) =
    let aq = newAsyncQueue[BlockEntry]()

    var counter =
      case kkind
      of SyncQueueKind.Forward:
        int(start)
      of SyncQueueKind.Backward:
        int(finish)

    proc backwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          sblock.done()
        else:
          sblock.fail(BlockError.Invalid)
        dec(counter)

    proc forwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          inc(counter)
          sblock.done()
        else:
          sblock.fail(BlockError.Invalid)

    var
      queue =
        case kkind
        of SyncQueueKind.Forward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                         start, finish, chunkSize,
                         getFirstSlotAtFinalizedEpoch, collector(aq))
        of SyncQueueKind.Backward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                         finish, start, chunkSize,
                         getFirstSlotAtFinalizedEpoch, collector(aq))
      chain = createChain(start, finish)
      validatorFut =
        case kkind
        of SyncQueueKind.Forward:
          forwardValidator(aq)
        of SyncQueueKind.Backward:
          backwardValidator(aq)

    let p1 = SomeTPeer()

    proc runSmokeTest() {.async.} =
      while true:
        var request = queue.pop(finish, p1)
        if request.isEmpty():
          break
        await queue.push(request, getSlice(chain, start, request))
      await validatorFut.cancelAndWait()

    waitFor runSmokeTest()
    case kkind
    of SyncQueueKind.Forward:
      check (counter - 1) == int(finish)
    of SyncQueueKind.Backward:
      check (counter + 1) == int(start)

  template unorderedAsyncTest(kkind: SyncQueueKind, startSlot: Slot) =
    let
      aq = newAsyncQueue[BlockEntry]()
      chunkSize = 3'u64
      numberOfChunks = 3'u64
      finishSlot = Slot(startSlot + numberOfChunks * chunkSize - 1'u64)
      queueSize = 1

    var counter =
      case kkind
      of SyncQueueKind.Forward:
        int(startSlot)
      of SyncQueueKind.Backward:
        int(finishSlot)

    proc backwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          sblock.done()
        else:
          sblock.fail(BlockError.Invalid)
        dec(counter)

    proc forwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          inc(counter)
          sblock.done()
        else:
          sblock.fail(BlockError.Invalid)

    var
      chain = createChain(startSlot, finishSlot)
      queue =
        case kkind
        of SyncQueueKind.Forward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                         startSlot, finishSlot, chunkSize,
                         getFirstSlotAtFinalizedEpoch, collector(aq),
                         queueSize)
        of SyncQueueKind.Backward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                         finishSlot, startSlot, chunkSize,
                         getFirstSlotAtFinalizedEpoch, collector(aq),
                         queueSize)
      validatorFut =
        case kkind
        of SyncQueueKind.Forward:
          forwardValidator(aq)
        of SyncQueueKind.Backward:
          backwardValidator(aq)

    let
      p1 = SomeTPeer()
      p2 = SomeTPeer()
      p3 = SomeTPeer()

    proc runTest(): Future[bool] {.async.} =
      var r11 = queue.pop(finishSlot, p1)
      var r12 = queue.pop(finishSlot, p2)
      var r13 = queue.pop(finishSlot, p3)

      var f13 = queue.push(r13, chain.getSlice(startSlot, r13))
      await sleepAsync(100.milliseconds)
      check:
        f13.finished == false
        case kkind
        of SyncQueueKind.Forward: counter == int(startSlot)
        of SyncQueueKind.Backward: counter == int(finishSlot)

      var f11 = queue.push(r11, chain.getSlice(startSlot, r11))
      await sleepAsync(100.milliseconds)
      check:
        case kkind
        of SyncQueueKind.Forward: counter == int(startSlot + chunkSize)
        of SyncQueueKind.Backward: counter == int(finishSlot - chunkSize)
        f11.finished == true and f11.failed == false
        f13.finished == false

      var f12 = queue.push(r12, chain.getSlice(startSlot, r12))
      await allFutures(f11, f12, f13)
      check:
        f12.finished == true and f12.failed == false
        f13.finished == true and f13.failed == false
      check:
        case kkind
        of SyncQueueKind.Forward: counter == int(finishSlot) + 1
        of SyncQueueKind.Backward: counter == int(startSlot) - 1
        r11.item == p1
        r12.item == p2
        r13.item == p3
      await validatorFut.cancelAndWait()
      return true

    check waitFor(runTest()) == true

  for k in {SyncQueueKind.Forward, SyncQueueKind.Backward}:
    let prefix = "[SyncQueue#" & $k & "] "

    test prefix & "Start and finish slots equal":
      startAndFinishSlotsEqual(k)

    test prefix & "Pass through established limits test":
      passThroughLimitsTest(k)

    test prefix & "Two full requests success/fail":
      twoFullRequests(k)

    test prefix & "Smoke test":
      const SmokeTests = [
        (Slot(0), Slot(547), 61'u64),
        (Slot(193), Slot(389), 79'u64),
        (Slot(1181), Slot(1399), 41'u64)
      ]
      for item in SmokeTests:
        smokeTest(k, item[0], item[1], item[2])

    test prefix & "Async unordered push test":
      const UnorderedTests = [
        Slot(0), Slot(100)
      ]
      for item in UnorderedTests:
        unorderedAsyncTest(k, item)

  test "[SyncQueue#Forward] Async unordered push with rewind test":
    let
      aq = newAsyncQueue[BlockEntry]()
      startSlot = Slot(0)
      chunkSize = SLOTS_PER_EPOCH
      numberOfChunks = 4'u64
      finishSlot = Slot(startSlot + numberOfChunks * chunkSize - 1'u64)
      queueSize = 1

    var counter = int(startSlot)

    proc forwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          withBlck(sblock.blck):
            if blck.message.proposer_index == 0xDEADBEAF'u64:
              sblock.fail(BlockError.MissingParent)
            else:
              inc(counter)
              sblock.done()
        else:
          sblock.fail(BlockError.Invalid)

    var
      chain = createChain(startSlot, finishSlot)
      queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                             startSlot, finishSlot, chunkSize,
                             getFirstSlotAtFinalizedEpoch, collector(aq),
                             queueSize)
      validatorFut = forwardValidator(aq)

    let
      p1 = SomeTPeer()
      p2 = SomeTPeer()
      p3 = SomeTPeer()
      p4 = SomeTPeer()
      p5 = SomeTPeer()
      p6 = SomeTPeer()
      p7 = SomeTPeer()
      p8 = SomeTPeer()

    proc runTest(): Future[bool] {.async.} =
      var r11 = queue.pop(finishSlot, p1)
      var r12 = queue.pop(finishSlot, p2)
      var r13 = queue.pop(finishSlot, p3)
      var r14 = queue.pop(finishSlot, p4)

      var f14 = queue.push(r14, chain.getSlice(startSlot, r14))
      await sleepAsync(100.milliseconds)
      check:
        f14.finished == false
        counter == int(startSlot)

      var f12 = queue.push(r12, chain.getSlice(startSlot, r12))
      await sleepAsync(100.milliseconds)
      check:
        counter == int(startSlot)
        f12.finished == false
        f14.finished == false

      var f11 = queue.push(r11, chain.getSlice(startSlot, r11))
      await allFutures(f11, f12)
      check:
        counter == int(startSlot + chunkSize + chunkSize)
        f11.finished == true and f11.failed == false
        f12.finished == true and f12.failed == false
        f14.finished == false

      var missingSlice = chain.getSlice(startSlot, r13)
      withBlck(missingSlice[0][]):
        blck.message.proposer_index = 0xDEADBEAF'u64
      var f13 = queue.push(r13, missingSlice)
      await allFutures(f13, f14)
      check:
        f11.finished == true and f11.failed == false
        f12.finished == true and f12.failed == false
        f13.finished == true and f13.failed == false
        f14.finished == true and f14.failed == false
        queue.inpSlot == Slot(SLOTS_PER_EPOCH)
        queue.outSlot == Slot(SLOTS_PER_EPOCH)
        queue.debtLen == 0

      # Recovery process
      counter = int(SLOTS_PER_EPOCH)

      var r15 = queue.pop(finishSlot, p5)
      var r16 = queue.pop(finishSlot, p6)
      var r17 = queue.pop(finishSlot, p7)
      var r18 = queue.pop(finishSlot, p8)

      check r18.isEmpty() == true

      var f17 = queue.push(r17, chain.getSlice(startSlot, r17))
      await sleepAsync(100.milliseconds)
      check f17.finished == false

      var f16 = queue.push(r16, chain.getSlice(startSlot, r16))
      await sleepAsync(100.milliseconds)
      check f16.finished == false

      var f15 = queue.push(r15, chain.getSlice(startSlot, r15))
      await allFutures(f15, f16, f17)
      check:
        f15.finished == true and f15.failed == false
        f16.finished == true and f16.failed == false
        f17.finished == true and f17.failed == false
        counter == int(finishSlot) + 1

      await validatorFut.cancelAndWait()
      return true

    check waitFor(runTest()) == true

  test "Process all unviable blocks":
    let
      aq = newAsyncQueue[BlockEntry]()
      startSlot = Slot(0)
      chunkSize = SLOTS_PER_EPOCH
      numberOfChunks = 1'u64
      finishSlot = Slot(startSlot + numberOfChunks * chunkSize - 1'u64)
      queueSize = 1

    var counter = int(startSlot)

    proc forwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        withBlck(sblock.blck):
          sblock.fail(BlockError.UnviableFork)
          inc(counter)

    var
      chain = createChain(startSlot, finishSlot)
      queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                             startSlot, finishSlot, chunkSize,
                             getFirstSlotAtFinalizedEpoch, collector(aq),
                             queueSize)
      validatorFut = forwardValidator(aq)

    let
      p1 = SomeTPeer()

    proc runTest(): Future[bool] {.async.} =
      var r11 = queue.pop(finishSlot, p1)

      # Push a single request that will fail with all blocks being unviable
      var f11 = queue.push(r11, chain.getSlice(startSlot, r11))
      discard await f11.withTimeout(100.milliseconds)

      check:
        f11.finished == true
        counter == int(startSlot + chunkSize) # should process all unviable blocks
        debtLen(queue) == chunkSize # The range must be retried

      await validatorFut.cancelAndWait()
      return true

    check waitFor(runTest()) == true

  test "[SyncQueue#Backward] Async unordered push with rewind test":
    let
      aq = newAsyncQueue[BlockEntry]()
      startSlot = Slot(0)
      chunkSize = SLOTS_PER_EPOCH
      numberOfChunks = 4'u64
      finishSlot = Slot(startSlot + numberOfChunks * chunkSize - 1'u64)
      queueSize = 1

    var
      lastSafeSlot: Slot
      counter = int(finishSlot)

    proc getSafeSlot(): Slot =
      lastSafeSlot

    proc backwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          withBlck(sblock.blck):
            if blck.message.proposer_index == 0xDEADBEAF'u64:
              sblock.fail(BlockError.MissingParent)
            else:
              lastSafeSlot = sblock.blck.slot
              dec(counter)
              sblock.done()
        else:
          sblock.fail(BlockError.Invalid)

    var
      chain = createChain(startSlot, finishSlot)
      queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                             finishSlot, startSlot, chunkSize,
                             getSafeSlot, collector(aq), queueSize)
      validatorFut = backwardValidator(aq)

    let
      p1 = SomeTPeer()
      p2 = SomeTPeer()
      p3 = SomeTPeer()
      p4 = SomeTPeer()
      p5 = SomeTPeer()
      p6 = SomeTPeer()
      p7 = SomeTPeer()

    proc runTest(): Future[bool] {.async.} =
      var r11 = queue.pop(finishSlot, p1)
      var r12 = queue.pop(finishSlot, p2)
      var r13 = queue.pop(finishSlot, p3)
      var r14 = queue.pop(finishSlot, p4)

      var f14 = queue.push(r14, chain.getSlice(startSlot, r14))
      await sleepAsync(100.milliseconds)
      check:
        f14.finished == false
        counter == int(finishSlot)

      var f12 = queue.push(r12, chain.getSlice(startSlot, r12))
      await sleepAsync(100.milliseconds)
      check:
        counter == int(finishSlot)
        f12.finished == false
        f14.finished == false

      var f11 = queue.push(r11, chain.getSlice(startSlot, r11))
      await allFutures(f11, f12)
      check:
        counter == int(finishSlot - chunkSize - chunkSize)
        f11.finished == true and f11.failed == false
        f12.finished == true and f12.failed == false
        f14.finished == false

      var missingSlice = chain.getSlice(startSlot, r13)
      withBlck(missingSlice[0][]):
        blck.message.proposer_index = 0xDEADBEAF'u64
      var f13 = queue.push(r13, missingSlice)
      await allFutures(f13, f14)
      check:
        f11.finished == true and f11.failed == false
        f12.finished == true and f12.failed == false
        f13.finished == true and f13.failed == false
        f14.finished == true and f14.failed == false

      # Recovery process
      counter = int(SLOTS_PER_EPOCH) + 1

      var r15 = queue.pop(finishSlot, p5)
      var r16 = queue.pop(finishSlot, p6)
      var r17 = queue.pop(finishSlot, p7)

      check r17.isEmpty() == true

      var f16 = queue.push(r16, chain.getSlice(startSlot, r16))
      await sleepAsync(100.milliseconds)
      check f16.finished == false

      var f15 = queue.push(r15, chain.getSlice(startSlot, r15))
      await allFutures(f15, f16)
      check:
        f15.finished == true and f15.failed == false
        f16.finished == true and f16.failed == false
        counter == int(startSlot) - 1

      await validatorFut.cancelAndWait()
      return true

    check waitFor(runTest()) == true

  test "[SyncQueue] hasEndGap() test":
    let chain1 = createChain(Slot(1), Slot(1))
    let chain2 = newSeq[ref ForkedSignedBeaconBlock]()

    for counter in countdown(32'u64, 2'u64):
      let req = SyncRequest[SomeTPeer](slot: Slot(1), count: counter,
                                      step: 1'u64)
      let sr = SyncResult[SomeTPeer](request: req, data: chain1)
      check sr.hasEndGap() == true

    let req = SyncRequest[SomeTPeer](slot: Slot(1), count: 1'u64, step: 1'u64)
    let sr1 = SyncResult[SomeTPeer](request: req, data: chain1)
    let sr2 = SyncResult[SomeTPeer](request: req, data: chain2)
    check:
      sr1.hasEndGap() == false
      sr2.hasEndGap() == true

  test "[SyncQueue] getLastNonEmptySlot() test":
    let chain1 = createChain(Slot(10), Slot(10))
    let chain2 = newSeq[ref ForkedSignedBeaconBlock]()

    for counter in countdown(32'u64, 2'u64):
      let req = SyncRequest[SomeTPeer](slot: Slot(10), count: counter,
                                       step: 1'u64)
      let sr = SyncResult[SomeTPeer](request: req, data: chain1)
      check sr.getLastNonEmptySlot() == Slot(10)

    let req = SyncRequest[SomeTPeer](slot: Slot(100), count: 1'u64, step: 1'u64)
    let sr = SyncResult[SomeTPeer](request: req, data: chain2)
    check sr.getLastNonEmptySlot() == Slot(100)

  test "[SyncQueue] contains() test":
    proc checkRange[T](req: SyncRequest[T]): bool =
      var slot = req.slot
      var counter = 0'u64
      while counter < req.count:
        if not(req.contains(slot)):
          return false
        slot = slot + req.step
        counter = counter + 1'u64
      return true

    var req1 = SyncRequest[SomeTPeer](slot: Slot(5), count: 10'u64, step: 1'u64)
    var req2 = SyncRequest[SomeTPeer](slot: Slot(1), count: 10'u64, step: 2'u64)
    var req3 = SyncRequest[SomeTPeer](slot: Slot(2), count: 10'u64, step: 3'u64)
    var req4 = SyncRequest[SomeTPeer](slot: Slot(3), count: 10'u64, step: 4'u64)
    var req5 = SyncRequest[SomeTPeer](slot: Slot(4), count: 10'u64, step: 5'u64)

    check:
      req1.checkRange() == true
      req2.checkRange() == true
      req3.checkRange() == true
      req4.checkRange() == true
      req5.checkRange() == true

      req1.contains(Slot(4)) == false
      req1.contains(Slot(15)) == false

      req2.contains(Slot(0)) == false
      req2.contains(Slot(21)) == false
      req2.contains(Slot(20)) == false

      req3.contains(Slot(0)) == false
      req3.contains(Slot(1)) == false
      req3.contains(Slot(32)) == false
      req3.contains(Slot(31)) == false
      req3.contains(Slot(30)) == false

      req4.contains(Slot(0)) == false
      req4.contains(Slot(1)) == false
      req4.contains(Slot(2)) == false
      req4.contains(Slot(43)) == false
      req4.contains(Slot(42)) == false
      req4.contains(Slot(41)) == false
      req4.contains(Slot(40)) == false

      req5.contains(Slot(0)) == false
      req5.contains(Slot(1)) == false
      req5.contains(Slot(2)) == false
      req5.contains(Slot(3)) == false
      req5.contains(Slot(54)) == false
      req5.contains(Slot(53)) == false
      req5.contains(Slot(52)) == false
      req5.contains(Slot(51)) == false
      req5.contains(Slot(50)) == false

  test "[SyncQueue] checkResponse() test":
    let chain = createChain(Slot(10), Slot(20))
    let r1 = SyncRequest[SomeTPeer](slot: Slot(11), count: 1'u64, step: 1'u64)
    let r21 = SyncRequest[SomeTPeer](slot: Slot(11), count: 2'u64, step: 1'u64)
    let r22 = SyncRequest[SomeTPeer](slot: Slot(11), count: 2'u64, step: 2'u64)

    check:
      checkResponse(r1, @[chain[1]]) == true
      checkResponse(r1, @[]) == true
      checkResponse(r1, @[chain[1], chain[1]]) == false
      checkResponse(r1, @[chain[0]]) == false
      checkResponse(r1, @[chain[2]]) == false

      checkResponse(r21, @[chain[1]]) == true
      checkResponse(r21, @[]) == true
      checkResponse(r21, @[chain[1], chain[2]]) == true
      checkResponse(r21, @[chain[2]]) == true
      checkResponse(r21, @[chain[1], chain[2], chain[3]]) == false
      checkResponse(r21, @[chain[0], chain[1]]) == false
      checkResponse(r21, @[chain[0]]) == false
      checkResponse(r21, @[chain[2], chain[1]]) == false
      checkResponse(r21, @[chain[2], chain[1]]) == false
      checkResponse(r21, @[chain[2], chain[3]]) == false
      checkResponse(r21, @[chain[3]]) == false

      checkResponse(r22, @[chain[1]]) == true
      checkResponse(r22, @[]) == true
      checkResponse(r22, @[chain[1], chain[3]]) == true
      checkResponse(r22, @[chain[3]]) == true
      checkResponse(r22, @[chain[1], chain[3], chain[5]]) == false
      checkResponse(r22, @[chain[0], chain[1]]) == false
      checkResponse(r22, @[chain[1], chain[2]]) == false
      checkResponse(r22, @[chain[2], chain[3]]) == false
      checkResponse(r22, @[chain[3], chain[4]]) == false
      checkResponse(r22, @[chain[4], chain[5]]) == false
      checkResponse(r22, @[chain[4]]) == false
      checkResponse(r22, @[chain[3], chain[1]]) == false

  test "[SyncQueue#Forward] getRewindPoint() test":
    let aq = newAsyncQueue[BlockEntry]()
    block:
      var queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                                 Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                                 1'u64, getFirstSlotAtFinalizedEpoch,
                                 collector(aq), 2)
      let finalizedSlot = start_slot(Epoch(0'u64))
      let startSlot = start_slot(Epoch(0'u64)) + 1'u64
      let finishSlot = start_slot(Epoch(2'u64))

      for i in uint64(startSlot) ..< uint64(finishSlot):
        check queue.getRewindPoint(Slot(i), finalizedSlot) == finalizedSlot

    block:
      var queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                                 Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                                 1'u64, getFirstSlotAtFinalizedEpoch,
                                 collector(aq), 2)
      let finalizedSlot = start_slot(Epoch(1'u64))
      let startSlot = start_slot(Epoch(1'u64)) + 1'u64
      let finishSlot = start_slot(Epoch(3'u64))

      for i in uint64(startSlot) ..< uint64(finishSlot) :
        check queue.getRewindPoint(Slot(i), finalizedSlot) == finalizedSlot

    block:
      var queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                                 Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                                 1'u64, getFirstSlotAtFinalizedEpoch,
                                 collector(aq), 2)
      let finalizedSlot = start_slot(Epoch(0'u64))
      let failSlot = Slot(0xFFFF_FFFF_FFFF_FFFFF'u64)
      let failEpoch = epoch(failSlot)

      var counter = 1'u64
      for i in 0 ..< 64:
        if counter >= failEpoch:
          break
        let rewindEpoch = failEpoch - counter
        let rewindSlot = start_slot(rewindEpoch)
        check queue.getRewindPoint(failSlot, finalizedSlot) == rewindSlot
        counter = counter shl 1

    block:
      var queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                                 Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                                 1'u64, getFirstSlotAtFinalizedEpoch,
                                 collector(aq), 2)
      let finalizedSlot = start_slot(Epoch(1'u64))
      let failSlot = Slot(0xFFFF_FFFF_FFFF_FFFFF'u64)
      let failEpoch = epoch(failSlot)
      var counter = 1'u64
      for i in 0 ..< 64:
        if counter >= failEpoch:
          break
        let rewindEpoch = failEpoch - counter
        let rewindSlot = start_slot(rewindEpoch)
        check queue.getRewindPoint(failSlot, finalizedSlot) == rewindSlot
        counter = counter shl 1

  test "[SyncQueue#Backward] getRewindPoint() test":
    let aq = newAsyncQueue[BlockEntry]()
    block:
      var queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                                 Slot(1024), Slot(0),
                                 1'u64, getSafeSlot, collector(aq), 2)
      let safeSlot = getSafeSlot()
      for i in countdown(1023, 0):
        check queue.getRewindPoint(Slot(i), safeSlot) == safeSlot
