# beacon_chain
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import std/[strutils, sequtils]
import unittest2
import chronos
import ../beacon_chain/gossip_processing/block_processor,
       ../beacon_chain/sync/sync_manager,
       ../beacon_chain/spec/datatypes/phase0,
       ../beacon_chain/spec/forks

type
  SomeTPeer = ref object
    score: int

proc `$`(peer: SomeTPeer): string =
  "SomeTPeer"

template shortLog(peer: SomeTPeer): string =
  $peer

proc updateScore(peer: SomeTPeer, score: int) =
  peer[].score += score

proc updateStats(peer: SomeTPeer, index: SyncResponseKind, score: uint64) =
  discard

proc getStats(peer: SomeTPeer, index: SyncResponseKind): uint64 =
  0

func getStaticSlotCb(slot: Slot): GetSlotCallback =
  proc getSlot(): Slot =
    slot
  getSlot

type
  BlockEntry = object
    blck*: ForkedSignedBeaconBlock
    resfut*: Future[Result[void, VerifierError]]

proc collector(queue: AsyncQueue[BlockEntry]): BlockVerifier =
  # This sets up a fake block verifiation collector that simply puts the blocks
  # in the async queue, similar to how BlockProcessor does it - as far as
  # testing goes, this is risky because it might introduce differences between
  # the BlockProcessor and this test
  proc verify(signedBlock: ForkedSignedBeaconBlock, blobs: Opt[BlobSidecars],
              maybeFinalized: bool):
      Future[Result[void, VerifierError]] =
    let fut = newFuture[Result[void, VerifierError]]()
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

  func createBlobs(slots: seq[Slot]): seq[ref BlobSidecar] =
    var res = newSeq[ref BlobSidecar](len(slots))
    for (i, item) in res.mpairs():
      item = new BlobSidecar
      item[].signed_block_header.message.slot = slots[i]
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
                               getStaticSlotCb(Slot(0)),
                               collector(aq))
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
      r11.slot == Slot(0) and r11.count == 1'u64

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
                                 getStaticSlotCb(item[0]),
                                 collector(aq))
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
        req2.isEmpty() == true

  template twoFullRequests(kkind: SyncQueueKind) =
    let aq = newAsyncQueue[BlockEntry]()
    var queue =
      case kkind
      of SyncQueueKind.Forward:
        SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                       Slot(0), Slot(1), 1'u64,
                       getStaticSlotCb(Slot(0)), collector(aq))
      of SyncQueueKind.Backward:
        SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                       Slot(1), Slot(0), 1'u64,
                       getStaticSlotCb(Slot(1)), collector(aq))

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
        r21.slot == Slot(0) and r21.count == 1'u64
        r22.slot == Slot(1) and r22.count == 1'u64
    of SyncQueueKind.Backward:
      check:
        r21.slot == Slot(1) and r21.count == 1'u64
        r22.slot == Slot(0) and r22.count == 1'u64

  template done(b: BlockEntry) =
    b.resfut.complete(Result[void, VerifierError].ok())
  template fail(b: BlockEntry, e: untyped) =
    b.resfut.complete(Result[void, VerifierError].err(e))

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
          sblock.fail(VerifierError.Invalid)
        dec(counter)

    proc forwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          inc(counter)
          sblock.done()
        else:
          sblock.fail(VerifierError.Invalid)

    var
      queue =
        case kkind
        of SyncQueueKind.Forward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                         start, finish, chunkSize,
                         getStaticSlotCb(start), collector(aq))
        of SyncQueueKind.Backward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                         finish, start, chunkSize,
                         getStaticSlotCb(finish), collector(aq))
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
        await queue.push(request, getSlice(chain, start, request),
                         Opt.none(seq[BlobSidecars]))
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
          sblock.fail(VerifierError.Invalid)
        dec(counter)

    proc forwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          inc(counter)
          sblock.done()
        else:
          sblock.fail(VerifierError.Invalid)

    var
      chain = createChain(startSlot, finishSlot)
      queue =
        case kkind
        of SyncQueueKind.Forward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                         startSlot, finishSlot, chunkSize,
                         getStaticSlotCb(startSlot), collector(aq),
                         queueSize)
        of SyncQueueKind.Backward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                         finishSlot, startSlot, chunkSize,
                         getStaticSlotCb(finishSlot), collector(aq),
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

      var f13 = queue.push(r13, chain.getSlice(startSlot, r13),
                           Opt.none(seq[BlobSidecars]))
      await sleepAsync(100.milliseconds)
      check:
        f13.finished == false
        case kkind
        of SyncQueueKind.Forward: counter == int(startSlot)
        of SyncQueueKind.Backward: counter == int(finishSlot)

      var f11 = queue.push(r11, chain.getSlice(startSlot, r11),
                           Opt.none(seq[BlobSidecars]))
      await sleepAsync(100.milliseconds)
      check:
        case kkind
        of SyncQueueKind.Forward: counter == int(startSlot + chunkSize)
        of SyncQueueKind.Backward: counter == int(finishSlot - chunkSize)
        f11.finished == true and f11.failed == false
        f13.finished == false

      var f12 = queue.push(r12, chain.getSlice(startSlot, r12),
                           Opt.none(seq[BlobSidecars]))
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

  template partialGoodResponseTest(kkind: SyncQueueKind, start, finish: Slot,
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
          dec(counter)
          sblock.done()
        elif sblock.blck.slot < Slot(counter):
          # There was a gap, report missing parent
          sblock.fail(VerifierError.MissingParent)
        else:
          sblock.fail(VerifierError.Duplicate)

    proc getBackwardSafeSlotCb(): Slot =
      min((Slot(counter).epoch + 1).start_slot, finish)

    proc forwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          inc(counter)
          sblock.done()
        elif sblock.blck.slot > Slot(counter):
          # There was a gap, report missing parent
          sblock.fail(VerifierError.MissingParent)
        else:
          sblock.fail(VerifierError.Duplicate)

    proc getFowardSafeSlotCb(): Slot =
      max(Slot(max(counter, 1) - 1).epoch.start_slot, start)

    var
      queue =
        case kkind
        of SyncQueueKind.Forward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                         start, finish, chunkSize,
                         getFowardSafeSlotCb, collector(aq))
        of SyncQueueKind.Backward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                         finish, start, chunkSize,
                         getBackwardSafeSlotCb, collector(aq))
      chain = createChain(start, finish)
      validatorFut =
        case kkind
        of SyncQueueKind.Forward:
          forwardValidator(aq)
        of SyncQueueKind.Backward:
          backwardValidator(aq)

    let p1 = SomeTPeer()

    var expectedScore = 0
    proc runTest() {.async.} =
      while true:
        var request = queue.pop(finish, p1)
        if request.isEmpty():
          break
        var response = getSlice(chain, start, request)
        if response.len >= (SLOTS_PER_EPOCH + 3).int:
          # Create gap close to end of response, to simulate behaviour where
          # the remote peer is sending valid data but does not have it fully
          # available (e.g., still doing backfill after checkpoint sync)
          case kkind
          of SyncQueueKind.Forward:
            response.delete(response.len - 2)
          of SyncQueueKind.Backward:
            response.delete(1)
          expectedScore += PeerScoreMissingValues
        if response.len >= 1:
          # Ensure requested values are past `safeSlot`
          case kkind
          of SyncQueueKind.Forward:
            check response[0][].slot >= getFowardSafeSlotCb()
          else:
            check response[^1][].slot <= getBackwardSafeSlotCb()
        await queue.push(request, response, Opt.none(seq[BlobSidecars]))
      await validatorFut.cancelAndWait()

    waitFor runTest()
    case kkind
    of SyncQueueKind.Forward:
      check (counter - 1) == int(finish)
    of SyncQueueKind.Backward:
      check (counter + 1) == int(start)
    check p1.score >= expectedScore

  template outOfBandAdvancementTest(kkind: SyncQueueKind, start, finish: Slot,
                                    chunkSize: uint64) =
    let aq = newAsyncQueue[BlockEntry]()

    var counter =
      case kkind
      of SyncQueueKind.Forward:
        int(start)
      of SyncQueueKind.Backward:
        int(finish)

    proc failingValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        sblock.fail(VerifierError.Invalid)

    proc getBackwardSafeSlotCb(): Slot =
      let progress = (uint64(int(finish) - counter) div chunkSize) * chunkSize
      finish - progress

    proc getFowardSafeSlotCb(): Slot =
      let progress = (uint64(counter - int(start)) div chunkSize) * chunkSize
      start + progress

    template advanceSafeSlot() =
      case kkind
      of SyncQueueKind.Forward:
        counter += int(chunkSize)
        if counter > int(finish) + 1:
          counter = int(finish) + 1
          break
      of SyncQueueKind.Backward:
        counter -= int(chunkSize)
        if counter < int(start) - 1:
          counter = int(start) - 1
          break

    var
      queue =
        case kkind
        of SyncQueueKind.Forward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                         start, finish, chunkSize,
                         getFowardSafeSlotCb, collector(aq))
        of SyncQueueKind.Backward:
          SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                         finish, start, chunkSize,
                         getBackwardSafeSlotCb, collector(aq))
      chain = createChain(start, finish)
      validatorFut = failingValidator(aq)

    let
      p1 = SomeTPeer()
      p2 = SomeTPeer()

    proc runTest() {.async.} =
      while true:
        var
          request1 = queue.pop(finish, p1)
          request2 = queue.pop(finish, p2)
        if request1.isEmpty():
          break

        # Simulate failing request 2.
        queue.push(request2)
        check debtLen(queue) == request2.count

        # Advance `safeSlot` out of band.
        advanceSafeSlot()

        # Handle request 1. Should be re-enqueued as it simulates `Invalid`.
        let response1 = getSlice(chain, start, request1)
        await queue.push(request1, response1, Opt.none(seq[BlobSidecars]))
        check debtLen(queue) == request2.count + request1.count

        # Request 1 should be discarded as it is no longer relevant.
        # Request 2 should be re-issued.
        var request3 = queue.pop(finish, p1)
        check:
          request3 == request2
          debtLen(queue) == 0

        # Handle request 3. Should be re-enqueued as it simulates `Invalid`.
        let response3 = getSlice(chain, start, request3)
        await queue.push(request3, response3, Opt.none(seq[BlobSidecars]))
        check debtLen(queue) == request3.count

        # Request 2 should be re-issued.
        var request4 = queue.pop(finish, p1)
        check:
          request4 == request2
          debtLen(queue) == 0

        # Advance `safeSlot` out of band.
        advanceSafeSlot()

        # Handle request 4. Should be re-enqueued as it simulates `Invalid`.
        let response4 = getSlice(chain, start, request4)
        await queue.push(request4, response4, Opt.none(seq[BlobSidecars]))
        check debtLen(queue) == request4.count

        # Advance `safeSlot` out of band.
        advanceSafeSlot()

        # Fetch a request. It should take into account the new `safeSlot`.
        let request5 = queue.pop(finish, p1)
        if request5.isEmpty():
          break
        case kkind
        of SyncQueueKind.Forward:
          check request5.slot >= getFowardSafeSlotCb()
        else:
          check request5.lastSlot <= getBackwardSafeSlotCb()
        queue.push(request5)

      await validatorFut.cancelAndWait()

    waitFor runTest()
    case kkind
    of SyncQueueKind.Forward:
      check (counter - 1) == int(finish)
    of SyncQueueKind.Backward:
      check (counter + 1) == int(start)

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

    test prefix & "Good response with missing values towards end":
      const PartialGoodResponseTests = [
        (Slot(0), Slot(200), (SLOTS_PER_EPOCH + 3).uint64)
      ]
      for item in PartialGoodResponseTests:
        partialGoodResponseTest(k, item[0], item[1], item[2])

    test prefix & "Handle out-of-band sync progress advancement":
      const OutOfBandAdvancementTests = [
        (Slot(0), Slot(500), SLOTS_PER_EPOCH.uint64)
      ]
      for item in OutOfBandAdvancementTests:
        outOfBandAdvancementTest(k, item[0], item[1], item[2])

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
            if forkyBlck.message.proposer_index == 0xDEADBEAF'u64:
              sblock.fail(VerifierError.MissingParent)
            else:
              inc(counter)
              sblock.done()
        else:
          sblock.fail(VerifierError.Invalid)

    var
      chain = createChain(startSlot, finishSlot)
      queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                             startSlot, finishSlot, chunkSize,
                             getStaticSlotCb(startSlot), collector(aq),
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

      var f14 = queue.push(r14, chain.getSlice(startSlot, r14),
                           Opt.none(seq[BlobSidecars]))
      await sleepAsync(100.milliseconds)
      check:
        f14.finished == false
        counter == int(startSlot)

      var f12 = queue.push(r12, chain.getSlice(startSlot, r12),
                           Opt.none(seq[BlobSidecars]))
      await sleepAsync(100.milliseconds)
      check:
        counter == int(startSlot)
        f12.finished == false
        f14.finished == false

      var f11 = queue.push(r11, chain.getSlice(startSlot, r11),
                           Opt.none(seq[BlobSidecars]))
      await allFutures(f11, f12)
      check:
        counter == int(startSlot + chunkSize + chunkSize)
        f11.finished == true and f11.failed == false
        f12.finished == true and f12.failed == false
        f14.finished == false

      var missingSlice = chain.getSlice(startSlot, r13)
      withBlck(missingSlice[0][]):
        forkyBlck.message.proposer_index = 0xDEADBEAF'u64
      var f13 = queue.push(r13, missingSlice,
                           Opt.none(seq[BlobSidecars]))
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

      var f17 = queue.push(r17, chain.getSlice(startSlot, r17),
                           Opt.none(seq[BlobSidecars]))
      await sleepAsync(100.milliseconds)
      check f17.finished == false

      var f16 = queue.push(r16, chain.getSlice(startSlot, r16),
                           Opt.none(seq[BlobSidecars]))
      await sleepAsync(100.milliseconds)
      check f16.finished == false

      var f15 = queue.push(r15, chain.getSlice(startSlot, r15),
                           Opt.none(seq[BlobSidecars]))
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
          sblock.fail(VerifierError.UnviableFork)
          inc(counter)

    var
      chain = createChain(startSlot, finishSlot)
      queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                             startSlot, finishSlot, chunkSize,
                             getStaticSlotCb(startSlot), collector(aq),
                             queueSize)
      validatorFut = forwardValidator(aq)

    let
      p1 = SomeTPeer()

    proc runTest(): Future[bool] {.async.} =
      var r11 = queue.pop(finishSlot, p1)

      # Push a single request that will fail with all blocks being unviable
      var f11 = queue.push(r11, chain.getSlice(startSlot, r11),
                           Opt.none(seq[BlobSidecars]))
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
      lastSafeSlot = finishSlot
      counter = int(finishSlot)

    proc getSafeSlot(): Slot =
      lastSafeSlot

    proc backwardValidator(aq: AsyncQueue[BlockEntry]) {.async.} =
      while true:
        let sblock = await aq.popFirst()
        if sblock.blck.slot == Slot(counter):
          withBlck(sblock.blck):
            if forkyBlck.message.proposer_index == 0xDEADBEAF'u64:
              sblock.fail(VerifierError.MissingParent)
            else:
              lastSafeSlot = sblock.blck.slot
              dec(counter)
              sblock.done()
        else:
          sblock.fail(VerifierError.Invalid)

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

      var f14 = queue.push(r14, chain.getSlice(startSlot, r14),
                           Opt.none(seq[BlobSidecars]))
      await sleepAsync(100.milliseconds)
      check:
        f14.finished == false
        counter == int(finishSlot)

      var f12 = queue.push(r12, chain.getSlice(startSlot, r12),
                           Opt.none(seq[BlobSidecars]))
      await sleepAsync(100.milliseconds)
      check:
        counter == int(finishSlot)
        f12.finished == false
        f14.finished == false

      var f11 = queue.push(r11, chain.getSlice(startSlot, r11),
                           Opt.none(seq[BlobSidecars]))
      await allFutures(f11, f12)
      check:
        counter == int(finishSlot - chunkSize - chunkSize)
        f11.finished == true and f11.failed == false
        f12.finished == true and f12.failed == false
        f14.finished == false

      var missingSlice = chain.getSlice(startSlot, r13)
      withBlck(missingSlice[0][]):
        forkyBlck.message.proposer_index = 0xDEADBEAF'u64
      var f13 = queue.push(r13, missingSlice, Opt.none(seq[BlobSidecars]))
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

      var f16 = queue.push(r16, chain.getSlice(startSlot, r16),
                           Opt.none(seq[BlobSidecars]))
      await sleepAsync(100.milliseconds)
      check f16.finished == false

      var f15 = queue.push(r15, chain.getSlice(startSlot, r15),
                           Opt.none(seq[BlobSidecars]))
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
      let req = SyncRequest[SomeTPeer](slot: Slot(1), count: counter)
      let sr = SyncResult[SomeTPeer](request: req, data: chain1)
      check sr.hasEndGap() == true

    let req = SyncRequest[SomeTPeer](slot: Slot(1), count: 1'u64)
    let sr1 = SyncResult[SomeTPeer](request: req, data: chain1)
    let sr2 = SyncResult[SomeTPeer](request: req, data: chain2)
    check:
      sr1.hasEndGap() == false
      sr2.hasEndGap() == true

  test "[SyncQueue] getLastNonEmptySlot() test":
    let chain1 = createChain(Slot(10), Slot(10))
    let chain2 = newSeq[ref ForkedSignedBeaconBlock]()

    for counter in countdown(32'u64, 2'u64):
      let req = SyncRequest[SomeTPeer](slot: Slot(10), count: counter)
      let sr = SyncResult[SomeTPeer](request: req, data: chain1)
      check sr.getLastNonEmptySlot() == Slot(10)

    let req = SyncRequest[SomeTPeer](slot: Slot(100), count: 1'u64)
    let sr = SyncResult[SomeTPeer](request: req, data: chain2)
    check sr.getLastNonEmptySlot() == Slot(100)

  test "[SyncQueue] contains() test":
    proc checkRange[T](req: SyncRequest[T]): bool =
      var slot = req.slot
      var counter = 0'u64
      while counter < req.count:
        if not(req.contains(slot)):
          return false
        slot = slot + 1
        counter = counter + 1'u64
      return true

    var req1 = SyncRequest[SomeTPeer](slot: Slot(5), count: 10'u64)

    check:
      req1.checkRange() == true

      req1.contains(Slot(4)) == false
      req1.contains(Slot(15)) == false

  test "[SyncQueue] checkResponse() test":
    let chain = createChain(Slot(10), Slot(20))
    let r1 = SyncRequest[SomeTPeer](slot: Slot(11), count: 1'u64)
    let r21 = SyncRequest[SomeTPeer](slot: Slot(11), count: 2'u64)
    let slots = mapIt(chain, it[].slot)

    check:
      checkResponse(r1, @[slots[1]]) == true
      checkResponse(r1, @[]) == true
      checkResponse(r1, @[slots[1], slots[1]]) == false
      checkResponse(r1, @[slots[0]]) == false
      checkResponse(r1, @[slots[2]]) == false

      checkResponse(r21, @[slots[1]]) == true
      checkResponse(r21, @[]) == true
      checkResponse(r21, @[slots[1], slots[2]]) == true
      checkResponse(r21, @[slots[2]]) == true
      checkResponse(r21, @[slots[1], slots[2], slots[3]]) == false
      checkResponse(r21, @[slots[0], slots[1]]) == false
      checkResponse(r21, @[slots[0]]) == false
      checkResponse(r21, @[slots[2], slots[1]]) == false
      checkResponse(r21, @[slots[2], slots[1]]) == false
      checkResponse(r21, @[slots[2], slots[3]]) == false
      checkResponse(r21, @[slots[3]]) == false

  test "[SyncManager] groupBlobs() test":
    var blobs = createBlobs(@[Slot(11), Slot(11), Slot(12), Slot(14)])
    var blocks = createChain(Slot(10), Slot(15))

    let req = SyncRequest[SomeTPeer](slot: Slot(10))
    let groupedRes = groupBlobs(req, blocks, blobs)

    check:
      groupedRes.isOk()

    let grouped = groupedRes.get()

    check:
      len(grouped) == 6
      # slot 10
      len(grouped[0]) == 0
      # slot 11
      len(grouped[1]) == 2
      grouped[1][0].signed_block_header.message.slot == Slot(11)
      grouped[1][1].signed_block_header.message.slot == Slot(11)
      # slot 12
      len(grouped[2]) == 1
      grouped[2][0].signed_block_header.message.slot == Slot(12)
      # slot 13
      len(grouped[3]) == 0
      # slot 14
      len(grouped[4]) == 1
      grouped[4][0].signed_block_header.message.slot == Slot(14)
      # slot 15
      len(grouped[5]) == 0

    # Add block with a gap from previous block.
    let block17 = new (ref ForkedSignedBeaconBlock)
    block17[].phase0Data.message.slot = Slot(17)
    blocks.add(block17)
    let groupedRes2 = groupBlobs(req, blocks, blobs)

    check:
      groupedRes2.isOk()
    let grouped2 = groupedRes2.get()
    check:
      len(grouped2) == 7
      len(grouped2[6]) == 0 # slot 17

    let blob18 = new (ref BlobSidecar)
    blob18[].signed_block_header.message.slot = Slot(18)
    blobs.add(blob18)
    let groupedRes3 = groupBlobs(req, blocks, blobs)

    check:
      groupedRes3.isErr()



  test "[SyncQueue#Forward] getRewindPoint() test":
    let aq = newAsyncQueue[BlockEntry]()
    block:
      var queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                                 Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                                 1'u64, getStaticSlotCb(Slot(0)),
                                 collector(aq), 2)
      let finalizedSlot = start_slot(Epoch(0'u64))
      let startSlot = start_slot(Epoch(0'u64)) + 1'u64
      let finishSlot = start_slot(Epoch(2'u64))

      for i in uint64(startSlot) ..< uint64(finishSlot):
        check queue.getRewindPoint(Slot(i), finalizedSlot) == finalizedSlot

    block:
      var queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                                 Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                                 1'u64, getStaticSlotCb(Slot(0)),
                                 collector(aq), 2)
      let finalizedSlot = start_slot(Epoch(1'u64))
      let startSlot = start_slot(Epoch(1'u64)) + 1'u64
      let finishSlot = start_slot(Epoch(3'u64))

      for i in uint64(startSlot) ..< uint64(finishSlot) :
        check queue.getRewindPoint(Slot(i), finalizedSlot) == finalizedSlot

    block:
      var queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                                 Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                                 1'u64, getStaticSlotCb(Slot(0)),
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
                                 1'u64, getStaticSlotCb(Slot(0)),
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
      let getSafeSlot = getStaticSlotCb(Slot(1024))
      var queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
                                 Slot(1024), Slot(0),
                                 1'u64, getSafeSlot, collector(aq), 2)
      let safeSlot = getSafeSlot()
      for i in countdown(1023, 0):
        check queue.getRewindPoint(Slot(i), safeSlot) == safeSlot
