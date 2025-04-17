# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[deques, heapqueue, tables, strutils, sequtils, math, typetraits]
import stew/base10, chronos, chronicles, results
import
  ../spec/[helpers, forks],
  ../networking/[peer_pool, eth2_network],
  ../gossip_processing/block_processor,
  ../consensus_object_pools/block_pools_types

export base, phase0, altair, merge, chronos, chronicles, results,
       block_pools_types, helpers

type
  GetSlotCallback* = proc(): Slot {.gcsafe, raises: [].}
  GetBoolCallback* = proc(): bool {.gcsafe, raises: [].}
  ProcessingCallback* = proc() {.gcsafe, raises: [].}
  BlockVerifier* =  proc(signedBlock: ForkedSignedBeaconBlock,
                         blobs: Opt[BlobSidecars], maybeFinalized: bool):
      Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).}

  SyncRange* = object
    slot*: Slot
    count*: uint64

  SyncPosition* = object
    qindex*: int
    sindex*: int

  SyncQueueKind* {.pure.} = enum
    Forward, Backward

  SyncRequest*[T] = object
    kind*: SyncQueueKind
    data*: SyncRange
    item*: T

  SyncQueueItem[T] = object
    requests: seq[SyncRequest[T]]
    data: SyncRange
    failuresCount: Natural

  SyncWaiterItem[T] = ref object
    future: Future[void].Raising([CancelledError])
    request: SyncRequest[T]
    resetFlag: bool

  SyncProcessError {.pure.} = enum
    Invalid,
    MissingParent,
    GoodAndMissingParent,
    UnviableFork,
    Duplicate,
    Empty,
    NoError

  SyncBlock = object
    slot: Slot
    root: Eth2Digest

  SyncProcessingResult = object
    code: SyncProcessError
    blck: Opt[SyncBlock]

  GapItem[T] = object
    data: SyncRange
    item: T

  RewindPoint = object
    failSlot: Slot
    epochCount: uint64

  SyncQueue*[T] = ref object
    kind*: SyncQueueKind
    inpSlot*: Slot
    outSlot*: Slot
    startSlot*: Slot
    finalSlot*: Slot
    rewind: Opt[RewindPoint]
    chunkSize: uint64
    requestsCount: Natural
    failureResetThreshold: Natural
    requests: Deque[SyncQueueItem[T]]
    getSafeSlot: GetSlotCallback
    blockVerifier: BlockVerifier
    waiters: seq[SyncWaiterItem[T]]
    gapList: seq[GapItem[T]]
    lock: AsyncLock
    ident: string

chronicles.formatIt SyncQueueKind: toLowerAscii($it)

proc `$`*(srange: SyncRange): string =
  "[" & Base10.toString(uint64(srange.slot)) & ":" &
  Base10.toString(uint64(srange.slot + srange.count - 1)) & "]"

template shortLog[T](req: SyncRequest[T]): string =
  $req.data & "@" & Base10.toString(req.data.count)

chronicles.expandIt SyncRequest:
  `it` = shortLog(it)
  peer = shortLog(it.item)
  direction = toLowerAscii($it.kind)

chronicles.formatIt Opt[SyncBlock]:
  if it.isSome():
    Base10.toString(uint64(it.get().slot)) & "@" & shortLog(it.get().root)
  else:
    "<n/a>"

func getShortMap*[T](
    req: SyncRequest[T],
    data: openArray[ref ForkedSignedBeaconBlock]
): string =
  ## Returns all slot numbers in ``data`` as placement map.
  var
    res = newStringOfCap(req.data.count)
    slider = req.data.slot
    last = 0

  for i in 0 ..< req.data.count:
    if last < len(data):
      for k in last ..< len(data):
        if slider == data[k][].slot:
          res.add('x')
          last = k + 1
          break
        elif slider < data[k][].slot:
          res.add('.')
          break
    else:
      res.add('.')
    slider = slider + 1
  res

proc getShortMap*[T](req: SyncRequest[T],
                     data: openArray[ref BlobSidecar]): string =
  var
    res = newStringOfCap(req.data.count)
    slider = req.data.slot
    last = 0

  for i in 0 ..< req.data.count:
    if last < len(data):
      var counter = 0
      for k in last ..< len(data):
        if slider < data[k][].signed_block_header.message.slot:
          break
        elif slider == data[k][].signed_block_header.message.slot:
          inc(counter)
      last = last + counter
      if counter == 0:
        res.add('.')
      else:
        res.add($counter)
    else:
      res.add('.')
    slider = slider + 1
  res

proc getShortMap*[T](
    req: SyncRequest[T],
    blobs: openArray[BlobSidecars]
): string =
  var
    res = newStringOfCap(req.data.count)
    slider = req.data.slot
    notFirst = false

  for i in 0 ..< int(req.data.count):
    if i >= len(blobs):
      res.add('.'.repeat(int(req.data.count) - len(res)))
      return res

    if len(blobs[i]) > 0:
      let slot = blobs[i][0][].signed_block_header.message.slot
      if not(notFirst):
        doAssert(slot >= slider, "Incorrect slot number in blobs list")
        let firstCount = int(slot - slider)
        res.add('.'.repeat(firstCount))
        res.add(Base10.toString(lenu64(blobs[i])))
        slider = slot
        notFirst = true
      else:
        if slot == slider:
          res.add(Base10.toString(lenu64(blobs[i])))
        else:
          res.add('.')
    else:
      if notFirst: res.add('.')
    if notFirst: inc(slider)
  res

proc getShortMap*[T](
    req: SyncRequest[T],
    data: Opt[seq[BlobSidecars]]
): string =
  if data.isNone():
    return '.'.repeat(req.data.count)
  getShortMap(req, data.get())

func init*(t: typedesc[SyncRange], slot: Slot, count: uint64): SyncRange =
  SyncRange(slot: slot, count: count)

func init(t: typedesc[SyncProcessError],
          kind: VerifierError): SyncProcessError =
  case kind
  of VerifierError.Invalid:
    SyncProcessError.Invalid
  of VerifierError.MissingParent:
    SyncProcessError.MissingParent
  of VerifierError.UnviableFork:
    SyncProcessError.UnviableFork
  of VerifierError.Duplicate:
    SyncProcessError.Duplicate

func init(t: typedesc[SyncBlock], slot: Slot, root: Eth2Digest): SyncBlock =
  SyncBlock(slot: slot, root: root)

func init(t: typedesc[SyncProcessError]): SyncProcessError =
  SyncProcessError.NoError

func init(t: typedesc[SyncProcessingResult], se: SyncProcessError,
          slot: Slot, root: Eth2Digest): SyncProcessingResult =
  SyncProcessingResult(blck: Opt.some(SyncBlock.init(slot, root)), code: se)

func init(t: typedesc[SyncProcessingResult],
          se: SyncProcessError): SyncProcessingResult =
  SyncProcessingResult(code: se)

func init(t: typedesc[SyncProcessingResult], se: SyncProcessError,
          sblck: SyncBlock): SyncProcessingResult =
  SyncProcessingResult(blck: Opt.some(sblck), code: se)

func init(t: typedesc[SyncProcessingResult], ve: VerifierError,
          slot: Slot, root: Eth2Digest): SyncProcessingResult =
  SyncProcessingResult(blck: Opt.some(SyncBlock.init(slot, root)),
                       code: SyncProcessError.init(ve))

func init(t: typedesc[SyncProcessingResult], ve: VerifierError,
          sblck: SyncBlock): SyncProcessingResult =
  SyncProcessingResult(blck: Opt.some(sblck), code: SyncProcessError.init(ve))

func init*[T](t: typedesc[SyncRequest], kind: SyncQueueKind,
              item: T): SyncRequest[T] =
  SyncRequest[T](
    kind: kind,
    data: SyncRange(slot: FAR_FUTURE_SLOT, count: 0'u64),
    item: item
  )

func init*[T](t: typedesc[SyncRequest], kind: SyncQueueKind,
              data: SyncRange, item: T): SyncRequest[T] =
  SyncRequest[T](kind: kind, data: data, item: item)

func init[T](t: typedesc[SyncQueueItem],
             req: SyncRequest[T]): SyncQueueItem[T] =
  SyncQueueItem[T](data: req.data, requests: @[req])

func init[T](t: typedesc[GapItem], req: SyncRequest[T]): GapItem[T] =
  GapItem[T](data: req.data, item: req.item)

func next(srange: SyncRange): SyncRange {.inline.} =
  let slot = srange.slot + srange.count
  if slot == FAR_FUTURE_SLOT:
    # Finish range
    srange
  elif slot < srange.slot:
    # Range that causes uint64 overflow, fixing.
    SyncRange.init(slot, uint64(FAR_FUTURE_SLOT - srange.count))
  else:
    if slot + srange.count < slot:
      SyncRange.init(slot, uint64(FAR_FUTURE_SLOT - srange.count))
    else:
      SyncRange.init(slot, srange.count)

func prev(srange: SyncRange): SyncRange {.inline.} =
  if srange.slot == GENESIS_SLOT:
    # Start range
    srange
  else:
    let slot = srange.slot - srange.count
    if slot > srange.slot:
      # Range that causes uint64 underflow, fixing.
      SyncRange.init(GENESIS_SLOT, uint64(srange.slot))
    else:
      SyncRange.init(slot, srange.count)

func contains(srange: SyncRange, slot: Slot): bool {.inline.} =
  ## Returns `true` if `slot` is in range of `srange`.
  if (srange.slot + srange.count) < srange.slot:
    (slot >= srange.slot) and (slot <= FAR_FUTURE_SLOT)
  else:
    (slot >= srange.slot) and (slot < (srange.slot + srange.count))

func `>`(a, b: SyncRange): bool {.inline.} =
  ## Returns `true` if range `a` is above of range `b`.
  (a.slot > b.slot) and (a.slot + a.count - 1 > b.slot)

func `<`(a, b: SyncRange): bool {.inline.} =
  ## Returns `true` if range `a` is below of range `b`.
  (a.slot < b.slot) and (a.slot + a.count - 1 < b.slot)

func `==`(a, b: SyncRange): bool {.inline.} =
  (a.slot == b.slot) and (a.count == b.count)

func `==`[T](a, b: SyncRequest[T]): bool {.inline.} =
  (a.kind == b.kind) and (a.item == b.item) and (a.data == b.data)

proc hasEndGap*[T](
    sr: SyncRequest[T],
    data: openArray[ref ForkedSignedBeaconBlock]
): bool {.inline.} =
  ## Returns ``true`` if response chain of blocks has gap at the end.
  if len(data) == 0:
    return true
  if data[^1][].slot != (sr.data.slot + sr.data.count - 1'u64):
    return true
  false

proc updateLastSlot*[T](sq: SyncQueue[T], last: Slot) {.inline.} =
  ## Update last slot stored in queue ``sq`` with value ``last``.
  sq.finalSlot = last

proc getRewindPoint*[T](sq: SyncQueue[T], failSlot: Slot,
                        safeSlot: Slot): Slot =
  case sq.kind
  of SyncQueueKind.Forward:
    # Calculate the latest finalized epoch.
    let finalizedEpoch = epoch(safeSlot)

    # Calculate failure epoch.
    let failEpoch = epoch(failSlot)

    # Calculate exponential rewind point in number of epochs.
    let epochCount =
      if sq.rewind.isSome():
        let rewind = sq.rewind.get()
        if failSlot == rewind.failSlot:
          # `MissingParent` happened at same slot so we increase rewind point by
          # factor of 2.
          if failEpoch > finalizedEpoch:
            let rewindPoint = rewind.epochCount shl 1
            if rewindPoint < rewind.epochCount:
              # If exponential rewind point produces `uint64` overflow we will
              # make rewind to latest finalized epoch.
              failEpoch - finalizedEpoch
            else:
              if (failEpoch < rewindPoint) or
                 (failEpoch - rewindPoint < finalizedEpoch):
                # If exponential rewind point points to position which is far
                # behind latest finalized epoch.
                failEpoch - finalizedEpoch
              else:
                rewindPoint
          else:
            warn "Trying to rewind over the last finalized epoch",
                 finalized_slot = safeSlot,
                 fail_slot = failSlot,
                 finalized_epoch = finalizedEpoch,
                 fail_epoch = failEpoch,
                 rewind_epoch_count = rewind.epochCount,
                 finalized_epoch = finalizedEpoch,
                 sync_ident = sq.ident,
                 direction = sq.kind,
                 topics = "syncman"
            0'u64
        else:
          # `MissingParent` happened at different slot so we going to rewind for
          # 1 epoch only.
          if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
            warn "Сould not rewind further than the last finalized epoch",
                 finalized_slot = safeSlot,
                 fail_slot = failSlot,
                 finalized_epoch = finalizedEpoch,
                 fail_epoch = failEpoch,
                 rewind_epoch_count = rewind.epochCount,
                 finalized_epoch = finalizedEpoch,
                 sync_ident = sq.ident,
                 direction = sq.kind,
                 topics = "syncman"
            0'u64
          else:
            1'u64
      else:
        # `MissingParent` happened first time.
        if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
          warn "Сould not rewind further than the last finalized epoch",
               finalized_slot = safeSlot,
               fail_slot = failSlot,
               finalized_epoch = finalizedEpoch,
               fail_epoch = failEpoch,
               finalized_epoch = finalizedEpoch,
               sync_ident = sq.ident,
               direction = sq.kind,
               topics = "syncman"
          0'u64
        else:
          1'u64

    if epochCount == 0'u64:
      warn "Unable to continue syncing, please restart the node",
           finalized_slot = safeSlot,
           fail_slot = failSlot,
           finalized_epoch = finalizedEpoch,
           fail_epoch = failEpoch,
           finalized_epoch = finalizedEpoch,
           sync_ident = sq.ident,
           direction = sq.kind,
           topics = "syncman"
      # Calculate the rewind epoch, which will be equal to last rewind point or
      # finalizedEpoch
      let rewindEpoch =
        if sq.rewind.isNone():
          finalizedEpoch
        else:
          epoch(sq.rewind.get().failSlot) - sq.rewind.get().epochCount
      rewindEpoch.start_slot()
    else:
      # Calculate the rewind epoch, which should not be less than the latest
      # finalized epoch.
      let rewindEpoch = failEpoch - epochCount
      # Update and save new rewind point in SyncQueue.
      sq.rewind = Opt.some(
        RewindPoint(failSlot: failSlot, epochCount: epochCount))
      rewindEpoch.start_slot()
  of SyncQueueKind.Backward:
    # While we perform backward sync, the only possible slot we could rewind is
    # latest stored block.
    if failSlot == safeSlot:
      warn "Unable to continue syncing, please restart the node",
           safe_slot = safeSlot,
           fail_slot = failSlot,
           sync_ident = sq.ident,
           direction = sq.kind,
           topics = "syncman"
    safeSlot

func init*[T](t1: typedesc[SyncQueue], t2: typedesc[T],
              queueKind: SyncQueueKind,
              start, final: Slot,
              chunkSize: uint64,
              requestsCount: Natural,
              failureResetThreshold: Natural,
              getSafeSlotCb: GetSlotCallback,
              blockVerifier: BlockVerifier,
              ident: string = "main"): SyncQueue[T] =
  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  doAssert(requestsCount > 0, "Number of requests should not be zero")

  SyncQueue[T](
    kind: queueKind,
    startSlot: start,
    finalSlot: final,
    chunkSize: chunkSize,
    requestsCount: requestsCount,
    failureResetThreshold: failureResetThreshold,
    getSafeSlot: getSafeSlotCb,
    inpSlot: start,
    outSlot: start,
    blockVerifier: blockVerifier,
    requests: initDeque[SyncQueueItem[T]](),
    lock: newAsyncLock(),
    ident: ident
  )

func contains[T](requests: openArray[SyncRequest[T]], source: T): bool =
  for req in requests:
    if req.item == source:
      return true
  false

func find[T](sq: SyncQueue[T], req: SyncRequest[T]): Opt[SyncPosition] =
  if len(sq.requests) == 0:
    return Opt.none(SyncPosition)

  case sq.kind
  of SyncQueueKind.Forward:
    if (req.data < sq.requests[0].data) or (req.data > sq.requests[^1].data):
      return Opt.none(SyncPosition)
  of SyncQueueKind.Backward:
    if (req.data > sq.requests[0].data) or (req.data < sq.requests[^1].data) :
      return Opt.none(SyncPosition)

  for qindex, qitem in sq.requests.pairs():
    for sindex, request in qitem.requests.pairs():
      if request == req:
        return Opt.some(SyncPosition(qindex: qindex, sindex: sindex))

  Opt.none(SyncPosition)

proc del[T](sq: SyncQueue[T], position: SyncPosition) =
  doAssert(len(sq.requests) > position.qindex)
  doAssert(len(sq.requests[position.qindex].requests) > position.sindex)
  del(sq.requests[position.qindex].requests, position.sindex)

proc del[T](sq: SyncQueue[T], request: SyncRequest[T]) =
  let pos = sq.find(request).valueOr:
    return
  sq.del(pos)

proc rewardForGaps[T](sq: SyncQueue[T], score: int) =
  mixin updateScore, getStats

  for gap in sq.gapList:
    if score < 0:
      # Every empty response increases penalty by 25%, but not more than 200%.
      let
        emptyCount = gap.item.getStats(SyncResponseKind.Empty)
        goodCount = gap.item.getStats(SyncResponseKind.Good)

      if emptyCount <= goodCount:
        gap.item.updateScore(score)
      else:
        let
          weight = int(min(emptyCount - goodCount, 8'u64))
          newScore = score + score * weight div 4
        gap.item.updateScore(newScore)
        debug "Peer received gap penalty",
              peer = gap.item,
              penalty = newScore,
              sync_ident = sq.ident,
              direction = sq.kind,
              topics = "syncman"

    else:
      gap.item.updateScore(score)

proc pop*[T](sq: SyncQueue[T], peerMaxSlot: Slot, item: T): SyncRequest[T] =
  # Searching requests queue for an empty space.
  var count = 0
  for qitem in sq.requests.mitems():
    if len(qitem.requests) < sq.requestsCount:
      if item notin qitem.requests:
        return
          if qitem.data.slot > peerMaxSlot:
            # Peer could not satisfy our request, returning empty one.
            SyncRequest.init(sq.kind, item)
          else:
            doAssert(count < sq.requestsCount,
                     "You should not pop so many requests for single peer")
            let request = SyncRequest.init(sq.kind, qitem.data, item)
            qitem.requests.add(request)
            request
      else:
        inc(count)

  doAssert(count < sq.requestsCount,
           "You should not pop so many requests for single peer")

  # No empty spaces has been found in queue, so we adding new request.
  let newrange =
    if len(sq.requests) > 0:
      # All requests are filled, adding one more request.
      let lastrange = sq.requests[^1].data
      if sq.finalSlot in lastrange:
        # Requests queue is already at finish position, we are not going to add
        # one more request range.
        return SyncRequest.init(sq.kind, item)

      case sq.kind
      of SyncQueueKind.Forward:
        lastrange.next()
      of SyncQueueKind.Backward:
        lastrange.prev()
    else:
      case sq.kind
      of SyncQueueKind.Forward:
        SyncRange.init(sq.inpSlot, sq.chunkSize)
      of SyncQueueKind.Backward:
        SyncRange.init(sq.inpSlot - (sq.chunkSize - 1), sq.chunkSize)

  if newrange.slot > peerMaxSlot:
    # Peer could not satisfy our request, returning empty one.
    SyncRequest.init(sq.kind, item)
  else:
    let request = SyncRequest.init(sq.kind, newrange, item)
    sq.requests.addLast(SyncQueueItem.init(request))
    request

proc wakeupWaiters[T](sq: SyncQueue[T], resetFlag = false) =
  ## Wakeup one or all blocked waiters.
  for item in sq.waiters:
    item.resetFlag = resetFlag
    if not(item.future.finished()):
      item.future.complete()

proc waitForChanges[T](
    sq: SyncQueue[T]
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Create new waiter and wait for completion from `wakeupWaiters()`.
  let
    future =
      Future[void].Raising([CancelledError]).init("SyncQueue.waitForChanges")
    item = SyncWaiterItem[T](future: future, resetFlag: false)

  sq.waiters.add(item)

  try:
    await future
    item.resetFlag
  finally:
    sq.waiters.delete(sq.waiters.find(item))

proc wakeupAndWaitWaiters[T](
    sq: SyncQueue[T]
) {.async: (raises: [CancelledError]).} =
  ## This procedure will perform wakeupWaiters(true) and blocks until last
  ## waiter will be awakened.
  let waitChanges = sq.waitForChanges()
  sq.wakeupWaiters(true)
  discard await waitChanges

template advanceImpl(kind, slot: untyped, number: uint64) =
  case kind
  of SyncQueueKind.Forward:
    if slot + number < slot:
      slot = FAR_FUTURE_SLOT
    else:
      slot = slot + number
  of SyncQueueKind.Backward:
    if slot - number > slot:
      slot = GENESIS_SLOT
    else:
      slot = slot - number

proc advanceOutput[T](sq: SyncQueue[T], number: uint64) =
  advanceImpl(sq.kind, sq.outSlot, number)

proc advanceInput[T](sq: SyncQueue[T], number: uint64) =
  advanceImpl(sq.kind, sq.inpSlot, number)

proc advanceQueue[T](sq: SyncQueue[T]) =
  if len(sq.requests) > 0:
    let item = sq.requests.popFirst()
    sq.advanceInput(item.data.count)
    sq.advanceOutput(item.data.count)
  else:
    sq.advanceInput(sq.chunkSize)
    sq.advanceOutput(sq.chunkSize)
  sq.wakeupWaiters()

proc resetQueue[T](sq: SyncQueue[T]) =
  sq.requests.reset()

proc clearAndWakeup*[T](sq: SyncQueue[T]) =
  # Reset queue and wakeup all the waiters.
  sq.resetQueue()
  sq.wakeupWaiters(true)

proc isEmpty*[T](sr: SyncRequest[T]): bool =
  # Returns `true` if request `sr` is empty.
  sr.data.count == 0'u64

proc resetWait[T](
    sq: SyncQueue[T],
    toSlot: Slot
) {.async: (raises: [CancelledError], raw: true).} =
  sq.inpSlot = toSlot
  sq.outSlot = toSlot
  # We are going to wakeup all the waiters and wait for last one.
  sq.resetQueue()
  sq.wakeupAndWaitWaiters()

func getOpt(blobs: Opt[seq[BlobSidecars]], i: int): Opt[BlobSidecars] =
  if blobs.isSome:
    Opt.some(blobs.get()[i])
  else:
    Opt.none(BlobSidecars)

iterator blocks(
    kind: SyncQueueKind,
    blcks: seq[ref ForkedSignedBeaconBlock],
    blobs: Opt[seq[BlobSidecars]]
): (ref ForkedSignedBeaconBlock, Opt[BlobSidecars]) =
  case kind
  of SyncQueueKind.Forward:
    for i in countup(0, len(blcks) - 1):
      yield (blcks[i], blobs.getOpt(i))
  of SyncQueueKind.Backward:
    for i in countdown(len(blcks) - 1, 0):
      yield (blcks[i], blobs.getOpt(i))

proc push*[T](sq: SyncQueue[T], sr: SyncRequest[T]) =
  ## Push failed request back to queue.
  let pos = sq.find(sr).valueOr:
    debug "Request is not relevant anymore", request = sr
    return
  sq.del(pos)

proc process[T](
    sq: SyncQueue[T],
    sr: SyncRequest[T],
    blcks: seq[ref ForkedSignedBeaconBlock],
    blobs: Opt[seq[BlobSidecars]],
    maybeFinalized: bool
): Future[SyncProcessingResult] {.
  async: (raises: [CancelledError]).} =
  var
    slot: Opt[SyncBlock]
    unviableBlock: Opt[SyncBlock]
    dupBlock: Opt[SyncBlock]

  if len(blcks) == 0:
    return SyncProcessingResult.init(SyncProcessError.Empty)

  for blk, blb in blocks(sq.kind, blcks, blobs):
    let res = await sq.blockVerifier(blk[], blb, maybeFinalized)
    if res.isOk():
      slot = Opt.some(SyncBlock.init(blk[].slot, blk[].root))
    else:
      case res.error()
      of VerifierError.MissingParent:
        if slot.isSome() or dupBlock.isSome():
          return SyncProcessingResult.init(
            SyncProcessError.GoodAndMissingParent, blk[].slot, blk[].root)
        else:
          return SyncProcessingResult.init(res.error(), blk[].slot, blk[].root)
      of VerifierError.Duplicate:
        # Keep going, happens naturally
        if dupBlock.isNone():
          dupBlock = Opt.some(SyncBlock.init(blk[].slot, blk[].root))
      of VerifierError.UnviableFork:
        # Keep going so as to register other unviable blocks with the
        # quarantine
        if unviableBlock.isNone():
          # Remember the first unviable block, so we can log it
          unviableBlock = Opt.some(SyncBlock.init(blk[].slot, blk[].root))
      of VerifierError.Invalid:
        return SyncProcessingResult.init(res.error(), blk[].slot, blk[].root)

  if unviableBlock.isSome():
    return SyncProcessingResult.init(VerifierError.UnviableFork,
                                     unviableBlock.get())
  if dupBlock.isSome():
    return SyncProcessingResult.init(VerifierError.Duplicate,
                                     dupBlock.get())

  SyncProcessingResult.init(SyncProcessError.NoError, slot.get())

func isError(e: SyncProcessError): bool =
  case e
  of SyncProcessError.Empty, SyncProcessError.NoError,
     SyncProcessError.Duplicate, SyncProcessError.GoodAndMissingParent:
    false
  of SyncProcessError.Invalid, SyncProcessError.UnviableFork,
     SyncProcessError.MissingParent:
    true

proc push*[T](
    sq: SyncQueue[T],
    sr: SyncRequest[T],
    data: seq[ref ForkedSignedBeaconBlock],
    blobs: Opt[seq[BlobSidecars]],
    maybeFinalized: bool = false,
    processingCb: ProcessingCallback = nil
) {.async: (raises: [CancelledError]).} =
  ## Push successful result to queue ``sq``.
  mixin updateScore, updateStats, getStats

  template findPosition(sq, sr: untyped): SyncPosition =
    sq.find(sr).valueOr:
      debug "Request is not relevant anymore",
            request = sr, sync_ident = sq.ident, topics = "syncman"
      # Request is not in queue anymore, probably reset happened.
      return

  # This is backpressure handling algorithm, this algorithm is blocking
  # all pending `push` requests if `request` is not in range.
  var
    position =
      block:
        var pos: SyncPosition
        while true:
          pos = sq.findPosition(sr)

          if pos.qindex == 0:
            # Exiting loop when request is first in queue.
            break

          try:
            let res = await sq.waitForChanges()
            if res:
              # SyncQueue reset happen
              debug "Request is not relevant anymore, reset has happened",
                    request = sr,
                    sync_ident = sq.ident,
                    topics = "syncman"
              return
          except CancelledError as exc:
            # Removing request from queue.
            sq.del(sr)
            raise exc
        pos

  await sq.lock.acquire()
  try:
    position = sq.findPosition(sr)

    if not(isNil(processingCb)):
      processingCb()

    let pres = await sq.process(sr, data, blobs, maybeFinalized)

    # We need to update position, because while we waiting for `process()` to
    # complete - clearAndWakeup() could be invoked which could clean whole the
    # queue (invalidating all the positions).
    position = sq.findPosition(sr)

    case pres.code
    of SyncProcessError.Empty:
      # Empty responses does not affect failures count
      debug "Received empty response",
            request = sr,
            blocks_count = len(data),
            blocks_map = getShortMap(sr, data),
            blobs_map = getShortMap(sr, blobs),
            sync_ident = sq.ident,
            topics = "syncman"

      sr.item.updateStats(SyncResponseKind.Empty, 1'u64)
      sq.gapList.add(GapItem.init(sr))
      sq.advanceQueue()

    of SyncProcessError.Duplicate:
      # Duplicate responses does not affect failures count
      debug "Received duplicate response",
            request = sr,
            blocks_count = len(data),
            blocks_map = getShortMap(sr, data),
            blobs_map = getShortMap(sr, blobs),
            sync_ident = sq.ident,
            topics = "syncman"
      sq.gapList.reset()
      sq.advanceQueue()

    of SyncProcessError.Invalid:
      debug "Block pool rejected peer's response",
            request = sr,
            invalid_block = pres.blck,
            failures_count = sq.requests[position.qindex].failuresCount,
            blocks_count = len(data),
            blocks_map = getShortMap(sr, data),
            blobs_map = getShortMap(sr, blobs),
            sync_ident = sq.ident,
            topics = "syncman"

      inc(sq.requests[position.qindex].failuresCount)
      sq.del(position)

    of SyncProcessError.UnviableFork:
      notice "Received blocks from an unviable fork",
             request = sr,
             unviable_block = pres.blck,
             failures_count = sq.requests[position.qindex].failuresCount,
             blocks_count = len(data),
             blocks_map = getShortMap(sr, data),
             blobs_map = getShortMap(sr, blobs),
             sync_ident = sq.ident,
             topics = "syncman"

      sr.item.updateScore(PeerScoreUnviableFork)
      inc(sq.requests[position.qindex].failuresCount)
      sq.del(position)

    of SyncProcessError.MissingParent:
      debug "Unexpected missing parent",
             request = sr,
             missing_parent_block = pres.blck,
             failures_count = sq.requests[position.qindex].failuresCount,
             blocks_count = len(data),
             blocks_map = getShortMap(sr, data),
             blobs_map = getShortMap(sr, blobs),
             sync_ident = sq.ident,
             direction = sq.kind,
             topics = "syncman"

      sr.item.updateScore(PeerScoreMissingValues)
      sq.rewardForGaps(PeerScoreMissingValues)
      sq.gapList.reset()
      inc(sq.requests[position.qindex].failuresCount)
      sq.del(position)

    of SyncProcessError.GoodAndMissingParent:
      # Responses which has at least one good block and a gap does not affect
      # failures count
      debug "Unexpected missing parent, but no rewind needed",
            request = sr,
            finalized_slot = sq.getSafeSlot(),
            missing_parent_block = pres.blck,
            failures_count = sq.requests[position.qindex].failuresCount,
            blocks_count = len(data),
            blocks_map = getShortMap(sr, data),
            blobs_map = getShortMap(sr, blobs),
            sync_ident = sq.ident,
            topics = "syncman"

      sr.item.updateScore(PeerScoreMissingValues)
      sq.del(position)

    of SyncProcessError.NoError:
      sr.item.updateScore(PeerScoreGoodValues)
      sr.item.updateStats(SyncResponseKind.Good, 1'u64)
      sq.rewardForGaps(PeerScoreGoodValues)
      sq.gapList.reset()

      if sr.hasEndGap(data):
        sq.gapList.add(GapItem.init(sr))

      sq.advanceQueue()

    if pres.code.isError():
      if sq.requests[position.qindex].failuresCount >= sq.failureResetThreshold:
        let point = sq.getRewindPoint(pres.blck.get().slot, sq.getSafeSlot())
        debug "Multiple repeating errors occured, rewinding",
              failures_count = sq.requests[position.qindex].failuresCount,
              rewind_slot = point,
              sync_ident = sq.ident,
              direction = sq.kind,
              topics = "syncman"
        await sq.resetWait(point)

  except CancelledError as exc:
    sq.del(sr)
    raise exc
  finally:
    try:
      sq.lock.release()
    except AsyncLockError:
      raiseAssert "Lock is not acquired"

proc checkResponse*[T](req: SyncRequest[T],
                       data: openArray[Slot]): Result[void, cstring] =
  if len(data) == 0:
    # Impossible to verify empty response.
    return ok()

  if lenu64(data) > req.data.count:
    # Number of blocks in response should be less or equal to number of
    # requested blocks.
    return err("Too many blocks received")

  var
    slot = req.data.slot
    rindex = 0'u64
    dindex = 0

  while (rindex < req.data.count) and (dindex < len(data)):
    if slot < data[dindex]:
      discard
    elif slot == data[dindex]:
      inc(dindex)
    else:
      return err("Incorrect order or duplicate blocks found")
    slot += 1'u64
    rindex += 1'u64

  if dindex != len(data):
    return err("Some of the blocks are outside the requested range")

  ok()

proc checkBlobsResponse*[T](
    req: SyncRequest[T],
    data: openArray[Slot],
    maxBlobsPerBlockElectra: uint64): Result[void, cstring] =
  if len(data) == 0:
    # Impossible to verify empty response.
    return ok()

  if lenu64(data) > (req.data.count * maxBlobsPerBlockElectra):
    # Number of blobs in response should be less or equal to number of
    # requested (blocks * MAX_BLOBS_PER_BLOCK_ELECTRA).
    # NOTE: This is not strict check, proper check will be done in blobs
    # validation.
    return err("Too many blobs received")

  var
    pslot = data[0]
    counter = 0'u64
  for slot in data:
    if slot notin req.data:
      return err("Some of the blobs are not in requested range")
    if slot < pslot:
      return err("Incorrect order")
    if slot == pslot:
      inc(counter)
      if counter > maxBlobsPerBlockElectra:
        # NOTE: This is not strict check, proper check will be done in blobs
        # validation.
        return err("Number of blobs in the block exceeds the limit")
    else:
      counter = 1'u64
    pslot = slot

  ok()

proc len*[T](sq: SyncQueue[T]): uint64 {.inline.} =
  ## Returns number of slots left in queue ``sq``.
  case sq.kind
  of SyncQueueKind.Forward:
    if sq.finalSlot >= sq.outSlot:
      sq.finalSlot + 1'u64 - sq.outSlot
    else:
      0'u64
  of SyncQueueKind.Backward:
    if sq.outSlot >= sq.finalSlot:
      sq.outSlot + 1'u64 - sq.finalSlot
    else:
      0'u64

proc total*[T](sq: SyncQueue[T]): uint64 {.inline.} =
  ## Returns total number of slots in queue ``sq``.
  case sq.kind
  of SyncQueueKind.Forward:
    if sq.finalSlot >= sq.startSlot:
      sq.finalSlot + 1'u64 - sq.startSlot
    else:
      0'u64
  of SyncQueueKind.Backward:
    if sq.startSlot >= sq.finalSlot:
      sq.startSlot + 1'u64 - sq.finalSlot
    else:
      0'u64

proc progress*[T](sq: SyncQueue[T]): uint64 =
  ## How many useful slots we've synced so far, adjusting for how much has
  ## become obsolete by time movements
  sq.total() - len(sq)
