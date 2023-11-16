# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[heapqueue, tables, strutils, sequtils, math]
import stew/[results, base10], chronos, chronicles
import
  ../spec/datatypes/[base, phase0, altair],
  ../spec/[helpers, forks],
  ../networking/[peer_pool, eth2_network],
  ../gossip_processing/block_processor,
  ../consensus_object_pools/block_pools_types

export base, phase0, altair, merge, chronos, chronicles, results,
       block_pools_types, helpers

logScope:
  topics = "syncqueue"

type
  GetSlotCallback* = proc(): Slot {.gcsafe, raises: [].}
  ProcessingCallback* = proc() {.gcsafe, raises: [].}
  BlockVerifier* =  proc(signedBlock: ForkedSignedBeaconBlock,
                         blobs: Opt[BlobSidecars], maybeFinalized: bool):
      Future[Result[void, VerifierError]] {.gcsafe, raises: [].}

  SyncQueueKind* {.pure.} = enum
    Forward, Backward

  SyncRequest*[T] = object
    kind*: SyncQueueKind
    index*: uint64
    slot*: Slot
    count*: uint64
    item*: T

  SyncResult*[T] = object
    request*: SyncRequest[T]
    data*: seq[ref ForkedSignedBeaconBlock]
    blobs*: Opt[seq[BlobSidecars]]

  GapItem*[T] = object
    start*: Slot
    finish*: Slot
    item*: T

  SyncWaiter* = ref object
    future: Future[void]
    reset: bool

  RewindPoint = object
    failSlot: Slot
    epochCount: uint64

  SyncQueue*[T] = ref object
    kind*: SyncQueueKind
    inpSlot*: Slot
    outSlot*: Slot
    startSlot*: Slot
    finalSlot*: Slot
    chunkSize*: uint64
    queueSize*: int
    counter*: uint64
    pending*: Table[uint64, SyncRequest[T]]
    gapList*: seq[GapItem[T]]
    waiters: seq[SyncWaiter]
    getSafeSlot*: GetSlotCallback
    debtsQueue: HeapQueue[SyncRequest[T]]
    debtsCount: uint64
    readyQueue: HeapQueue[SyncResult[T]]
    rewind: Option[RewindPoint]
    blockVerifier: BlockVerifier
    ident*: string

chronicles.formatIt SyncQueueKind: toLowerAscii($it)

template shortLog*[T](req: SyncRequest[T]): string =
  Base10.toString(uint64(req.slot)) & ":" &
  Base10.toString(req.count) & "@" &
  Base10.toString(req.index)

chronicles.expandIt SyncRequest:
  `it` = shortLog(it)
  peer = shortLog(it.item)
  direction = toLowerAscii($it.kind)

proc getShortMap*[T](req: SyncRequest[T],
                     data: openArray[ref ForkedSignedBeaconBlock]): string =
  ## Returns all slot numbers in ``data`` as placement map.
  var res = newStringOfCap(req.count)
  var slider = req.slot
  var last = 0
  for i in 0 ..< req.count:
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
  ## Returns all slot numbers in ``data`` as placement map.
  var res = newStringOfCap(req.count * MAX_BLOBS_PER_BLOCK)
  var cur : uint64 = 0
  for slot in req.slot..<req.slot+req.count:
    if cur >= lenu64(data):
      res.add('|')
      continue
    if slot == data[cur].signed_block_header.message.slot:
      for k in cur..<cur+MAX_BLOBS_PER_BLOCK:
        if k >= lenu64(data) or slot != data[k].signed_block_header.message.slot:
          res.add('|')
          break
        else:
          inc(cur)
          res.add('x')
    else:
      res.add('|')
  res

proc contains*[T](req: SyncRequest[T], slot: Slot): bool {.inline.} =
  slot >= req.slot and slot < req.slot + req.count

proc cmp*[T](a, b: SyncRequest[T]): int =
  cmp(uint64(a.slot), uint64(b.slot))

proc checkResponse*[T](req: SyncRequest[T],
                       data: openArray[Slot]): bool =
  if len(data) == 0:
    # Impossible to verify empty response.
    return true

  if uint64(len(data)) > req.count:
    # Number of blocks in response should be less or equal to number of
    # requested blocks.
    return false

  var slot = req.slot
  var rindex = 0'u64
  var dindex = 0

  while (rindex < req.count) and (dindex < len(data)):
    if slot < data[dindex]:
      discard
    elif slot == data[dindex]:
      inc(dindex)
    else:
      return false
    slot += 1'u64
    rindex += 1'u64

  if dindex == len(data):
    return true
  else:
    return false

proc init[T](t1: typedesc[SyncRequest], kind: SyncQueueKind, start: Slot,
             finish: Slot, t2: typedesc[T]): SyncRequest[T] =
  let count = finish - start + 1'u64
  SyncRequest[T](kind: kind, slot: start, count: count)

proc init[T](t1: typedesc[SyncRequest], kind: SyncQueueKind, slot: Slot,
             count: uint64, item: T): SyncRequest[T] =
  SyncRequest[T](kind: kind, slot: slot, count: count, item: item)

proc init[T](t1: typedesc[SyncRequest], kind: SyncQueueKind, start: Slot,
             finish: Slot, item: T): SyncRequest[T] =
  let count = finish - start + 1'u64
  SyncRequest[T](kind: kind, slot: start, count: count, item: item)

proc empty*[T](t: typedesc[SyncRequest], kind: SyncQueueKind,
               t2: typedesc[T]): SyncRequest[T] {.inline.} =
  SyncRequest[T](kind: kind, count: 0'u64)

proc setItem*[T](sr: var SyncRequest[T], item: T) =
  sr.item = item

proc isEmpty*[T](sr: SyncRequest[T]): bool {.inline.} =
  (sr.count == 0'u64)

proc init*[T](t1: typedesc[SyncQueue], t2: typedesc[T],
              queueKind: SyncQueueKind,
              start, final: Slot, chunkSize: uint64,
              getSafeSlotCb: GetSlotCallback,
              blockVerifier: BlockVerifier,
              syncQueueSize: int = -1,
              ident: string = "main"): SyncQueue[T] =
  ## Create new synchronization queue with parameters
  ##
  ## ``start`` and ``final`` are starting and final Slots.
  ##
  ## ``chunkSize`` maximum number of slots in one request.
  ##
  ## ``syncQueueSize`` maximum queue size for incoming data.
  ## If ``syncQueueSize > 0`` queue will help to keep backpressure under
  ## control. If ``syncQueueSize <= 0`` then queue size is unlimited (default).

  # SyncQueue is the core of sync manager, this data structure distributes
  # requests to peers and manages responses from peers.
  #
  # Because SyncQueue is async data structure it manages backpressure and
  # order of incoming responses and it also resolves "joker's" problem.
  #
  # Joker's problem
  #
  # According to pre-v0.12.0 Ethereum consensus network specification
  # > Clients MUST respond with at least one block, if they have it and it
  # > exists in the range. Clients MAY limit the number of blocks in the
  # > response.
  # https://github.com/ethereum/consensus-specs/blob/v0.11.3/specs/phase0/p2p-interface.md#L590
  #
  # Such rule can lead to very uncertain responses, for example let slots from
  # 10 to 12 will be not empty. Client which follows specification can answer
  # with any response from this list (X - block, `-` empty space):
  #
  # 1.   X X X
  # 2.   - - X
  # 3.   - X -
  # 4.   - X X
  # 5.   X - -
  # 6.   X - X
  # 7.   X X -
  #
  # If peer answers with `1` everything will be fine and `block_processor`
  # will be able to process all 3 blocks.
  # In case of `2`, `3`, `4`, `6` - `block_processor` will fail immediately
  # with chunk and report "parent is missing" error.
  # But in case of `5` and `7` blocks will be processed by `block_processor`
  # without any problems, however it will start producing problems right from
  # this uncertain last slot. SyncQueue will start producing requests for next
  # blocks, but all the responses from this point will fail with "parent is
  # missing" error. Lets call such peers "jokers", because they are joking
  # with responses.
  #
  # To fix "joker" problem we going to perform rollback to the latest finalized
  # epoch's first slot.
  #
  # Note that as of spec v0.12.0, well-behaving clients are forbidden from
  # answering this way. However, it still makes sense to attempt to handle
  # this case to increase compatibility (e.g., with weak subjectivity nodes
  # that are still backfilling blocks)
  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  SyncQueue[T](
    kind: queueKind,
    startSlot: start,
    finalSlot: final,
    chunkSize: chunkSize,
    queueSize: syncQueueSize,
    getSafeSlot: getSafeSlotCb,
    waiters: newSeq[SyncWaiter](),
    counter: 1'u64,
    pending: initTable[uint64, SyncRequest[T]](),
    debtsQueue: initHeapQueue[SyncRequest[T]](),
    inpSlot: start,
    outSlot: start,
    blockVerifier: blockVerifier,
    ident: ident
  )

proc `<`*[T](a, b: SyncRequest[T]): bool =
  doAssert(a.kind == b.kind)
  case a.kind
  of SyncQueueKind.Forward:
    a.slot < b.slot
  of SyncQueueKind.Backward:
    a.slot > b.slot

proc `<`*[T](a, b: SyncResult[T]): bool =
  doAssert(a.request.kind == b.request.kind)
  case a.request.kind
  of SyncQueueKind.Forward:
    a.request.slot < b.request.slot
  of SyncQueueKind.Backward:
    a.request.slot > b.request.slot

proc `==`*[T](a, b: SyncRequest[T]): bool =
  (a.kind == b.kind) and (a.slot == b.slot) and (a.count == b.count)

proc lastSlot*[T](req: SyncRequest[T]): Slot =
  ## Returns last slot for request ``req``.
  req.slot + req.count - 1'u64

proc makePending*[T](sq: SyncQueue[T], req: var SyncRequest[T]) =
  req.index = sq.counter
  sq.counter = sq.counter + 1'u64
  sq.pending[req.index] = req

proc updateLastSlot*[T](sq: SyncQueue[T], last: Slot) {.inline.} =
  ## Update last slot stored in queue ``sq`` with value ``last``.
  sq.finalSlot = last

proc wakeupWaiters[T](sq: SyncQueue[T], reset = false) =
  ## Wakeup one or all blocked waiters.
  for item in sq.waiters:
    if reset:
      item.reset = true

    if not(item.future.finished()):
      item.future.complete()

proc waitForChanges[T](sq: SyncQueue[T]): Future[bool] {.async.} =
  ## Create new waiter and wait for completion from `wakeupWaiters()`.
  var waitfut = newFuture[void]("SyncQueue.waitForChanges")
  let waititem = SyncWaiter(future: waitfut)
  sq.waiters.add(waititem)
  try:
    await waitfut
    return waititem.reset
  finally:
    sq.waiters.delete(sq.waiters.find(waititem))

proc wakeupAndWaitWaiters[T](sq: SyncQueue[T]) {.async.} =
  ## This procedure will perform wakeupWaiters(true) and blocks until last
  ## waiter will be awakened.
  var waitChanges = sq.waitForChanges()
  sq.wakeupWaiters(true)
  discard await waitChanges

proc clearAndWakeup*[T](sq: SyncQueue[T]) =
  sq.pending.clear()
  sq.wakeupWaiters(true)

proc resetWait*[T](sq: SyncQueue[T], toSlot: Option[Slot]) {.async.} =
  ## Perform reset of all the blocked waiters in SyncQueue.
  ##
  ## We adding one more waiter to the waiters sequence and
  ## call wakeupWaiters(true). Because our waiter is last in sequence of
  ## waiters it will be resumed only after all waiters will be awakened and
  ## finished.

  # We are clearing pending list, so that all requests that are still running
  # around (still downloading, but not yet pushed to the SyncQueue) will be
  # expired. Its important to perform this call first (before await), otherwise
  # you can introduce race problem.
  sq.pending.clear()

  # We calculating minimal slot number to which we will be able to reset,
  # without missing any blocks. There 3 sources:
  # 1. Debts queue.
  # 2. Processing queue (`inpSlot`, `outSlot`).
  # 3. Requested slot `toSlot`.
  #
  # Queue's `outSlot` is the lowest slot we added to `block_pool`, but
  # `toSlot` slot can be less then `outSlot`. `debtsQueue` holds only not
  # added slot requests, so it can't be bigger then `outSlot` value.
  let minSlot =
    case sq.kind
    of SyncQueueKind.Forward:
      if toSlot.isSome():
        min(toSlot.get(), sq.outSlot)
      else:
        sq.outSlot
    of SyncQueueKind.Backward:
      if toSlot.isSome():
        toSlot.get()
      else:
        sq.outSlot
  sq.debtsQueue.clear()
  sq.debtsCount = 0
  sq.readyQueue.clear()
  sq.inpSlot = minSlot
  sq.outSlot = minSlot
  # We are going to wakeup all the waiters and wait for last one.
  await sq.wakeupAndWaitWaiters()

proc isEmpty*[T](sr: SyncResult[T]): bool {.inline.} =
  ## Returns ``true`` if response chain of blocks is empty (has only empty
  ## slots).
  len(sr.data) == 0

proc hasEndGap*[T](sr: SyncResult[T]): bool {.inline.} =
  ## Returns ``true`` if response chain of blocks has gap at the end.
  let lastslot = sr.request.slot + sr.request.count - 1'u64
  if len(sr.data) == 0:
    return true
  if sr.data[^1][].slot != lastslot:
    return true
  return false

proc getLastNonEmptySlot*[T](sr: SyncResult[T]): Slot {.inline.} =
  ## Returns last non-empty slot from result ``sr``. If response has only
  ## empty slots, original request slot will be returned.
  if len(sr.data) == 0:
    # If response has only empty slots we going to use original request slot
    sr.request.slot
  else:
    sr.data[^1][].slot

proc processGap[T](sq: SyncQueue[T], sr: SyncResult[T]) =
  if sr.isEmpty():
    let gitem = GapItem[T](start: sr.request.slot,
                           finish: sr.request.slot + sr.request.count - 1'u64,
                           item: sr.request.item)
    sq.gapList.add(gitem)
  else:
    if sr.hasEndGap():
      let gitem = GapItem[T](start: sr.getLastNonEmptySlot() + 1'u64,
                             finish: sr.request.slot + sr.request.count - 1'u64,
                             item: sr.request.item)
      sq.gapList.add(gitem)
    else:
      sq.gapList.reset()

proc rewardForGaps[T](sq: SyncQueue[T], score: int) =
  mixin updateScore, getStats
  logScope:
    sync_ident = sq.ident
    direction = sq.kind
    topics = "syncman"

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
        debug "Peer received gap penalty", peer = gap.item,
              penalty = newScore
    else:
      gap.item.updateScore(score)

proc toDebtsQueue[T](sq: SyncQueue[T], sr: SyncRequest[T]) =
  sq.debtsQueue.push(sr)
  sq.debtsCount = sq.debtsCount + sr.count

proc getRewindPoint*[T](sq: SyncQueue[T], failSlot: Slot,
                        safeSlot: Slot): Slot =
  logScope:
    sync_ident = sq.ident
    direction = sq.kind
    topics = "syncman"

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
                 finalized_slot = safeSlot, fail_slot = failSlot,
                 finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
                 rewind_epoch_count = rewind.epochCount,
                 finalized_epoch = finalizedEpoch
            0'u64
        else:
          # `MissingParent` happened at different slot so we going to rewind for
          # 1 epoch only.
          if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
            warn "Сould not rewind further than the last finalized epoch",
                 finalized_slot = safeSlot, fail_slot = failSlot,
                 finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
                 rewind_epoch_count = rewind.epochCount,
                 finalized_epoch = finalizedEpoch
            0'u64
          else:
            1'u64
      else:
        # `MissingParent` happened first time.
        if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
          warn "Сould not rewind further than the last finalized epoch",
               finalized_slot = safeSlot, fail_slot = failSlot,
               finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
               finalized_epoch = finalizedEpoch
          0'u64
        else:
          1'u64

    if epochCount == 0'u64:
      warn "Unable to continue syncing, please restart the node",
           finalized_slot = safeSlot, fail_slot = failSlot,
           finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
           finalized_epoch = finalizedEpoch
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
      sq.rewind = some(RewindPoint(failSlot: failSlot, epochCount: epochCount))
      rewindEpoch.start_slot()
  of SyncQueueKind.Backward:
    # While we perform backward sync, the only possible slot we could rewind is
    # latest stored block.
    if failSlot == safeSlot:
      warn "Unable to continue syncing, please restart the node",
           safe_slot = safeSlot, fail_slot = failSlot
    safeSlot

# This belongs inside the blocks iterator below, but can't be there due to
# https://github.com/nim-lang/Nim/issues/21242
func getOpt(blobs: Opt[seq[BlobSidecars]], i: int): Opt[BlobSidecars] =
  if blobs.isSome:
    Opt.some(blobs.get()[i])
  else:
    Opt.none(BlobSidecars)

iterator blocks[T](sq: SyncQueue[T],
                   sr: SyncResult[T]): (ref ForkedSignedBeaconBlock, Opt[BlobSidecars]) =
  case sq.kind
  of SyncQueueKind.Forward:
    for i in countup(0, len(sr.data) - 1):
      yield (sr.data[i], sr.blobs.getOpt(i))
  of SyncQueueKind.Backward:
    for i in countdown(len(sr.data) - 1, 0):
      yield (sr.data[i], sr.blobs.getOpt(i))

proc advanceOutput*[T](sq: SyncQueue[T], number: uint64) =
  case sq.kind
  of SyncQueueKind.Forward:
    sq.outSlot = sq.outSlot + number
  of SyncQueueKind.Backward:
    sq.outSlot = sq.outSlot - number

proc advanceInput[T](sq: SyncQueue[T], number: uint64) =
  case sq.kind
  of SyncQueueKind.Forward:
    sq.inpSlot = sq.inpSlot + number
  of SyncQueueKind.Backward:
    sq.inpSlot = sq.inpSlot - number

proc notInRange[T](sq: SyncQueue[T], sr: SyncRequest[T]): bool =
  case sq.kind
  of SyncQueueKind.Forward:
    (sq.queueSize > 0) and (sr.slot > sq.outSlot)
  of SyncQueueKind.Backward:
    (sq.queueSize > 0) and (sr.lastSlot < sq.outSlot)

func numAlreadyKnownSlots[T](sq: SyncQueue[T], sr: SyncRequest[T]): uint64 =
  ## Compute the number of slots covered by a given `SyncRequest` that are
  ## already known and, hence, no longer relevant for sync progression.
  let
    outSlot = sq.outSlot
    lowSlot = sr.slot
    highSlot = sr.lastSlot
  case sq.kind
  of SyncQueueKind.Forward:
    if outSlot > highSlot:
      # Entire request is no longer relevant.
      sr.count
    elif outSlot > lowSlot:
      # Request is only partially relevant.
      outSlot - lowSlot
    else:
      # Entire request is still relevant.
      0
  of SyncQueueKind.Backward:
    if lowSlot > outSlot:
      # Entire request is no longer relevant.
      sr.count
    elif highSlot > outSlot:
      # Request is only partially relevant.
      highSlot - outSlot
    else:
      # Entire request is still relevant.
      0

proc push*[T](sq: SyncQueue[T], sr: SyncRequest[T],
              data: seq[ref ForkedSignedBeaconBlock],
              blobs: Opt[seq[BlobSidecars]],
              maybeFinalized: bool = false,
              processingCb: ProcessingCallback = nil) {.async.} =
  logScope:
    sync_ident = sq.ident
    topics = "syncman"

  ## Push successful result to queue ``sq``.
  mixin updateScore, updateStats, getStats

  if sr.index notin sq.pending:
    # If request `sr` not in our pending list, it only means that
    # SyncQueue.resetWait() happens and all pending requests are expired, so
    # we swallow `old` requests, and in such way sync-workers are able to get
    # proper new requests from SyncQueue.
    return

  sq.pending.del(sr.index)

  # This is backpressure handling algorithm, this algorithm is blocking
  # all pending `push` requests if `request.slot` not in range.
  while true:
    if sq.notInRange(sr):
      let reset = await sq.waitForChanges()
      if reset:
        # SyncQueue reset happens. We are exiting to wake up sync-worker.
        return
    else:
      let syncres = SyncResult[T](request: sr, data: data, blobs: blobs)
      sq.readyQueue.push(syncres)
      break

  while len(sq.readyQueue) > 0:
    let reqres =
      case sq.kind
      of SyncQueueKind.Forward:
        let minSlot = sq.readyQueue[0].request.slot
        if sq.outSlot < minSlot:
          none[SyncResult[T]]()
        else:
          some(sq.readyQueue.pop())
      of SyncQueueKind.Backward:
        let maxslot = sq.readyQueue[0].request.slot +
                      (sq.readyQueue[0].request.count - 1'u64)
        if sq.outSlot > maxslot:
          none[SyncResult[T]]()
        else:
          some(sq.readyQueue.pop())

    let item =
      if reqres.isSome():
        reqres.get()
      else:
        let rewindSlot = sq.getRewindPoint(sq.outSlot, sq.getSafeSlot())
        warn "Got incorrect sync result in queue, rewind happens",
             blocks_map = getShortMap(sq.readyQueue[0].request,
                                      sq.readyQueue[0].data),
             blocks_count = len(sq.readyQueue[0].data),
             output_slot = sq.outSlot, input_slot = sq.inpSlot,
             rewind_to_slot = rewindSlot, request = sq.readyQueue[0].request
        await sq.resetWait(some(rewindSlot))
        break

    if processingCb != nil:
      processingCb()

    # Validating received blocks one by one
    var
      hasInvalidBlock = false
      unviableBlock: Option[(Eth2Digest, Slot)]
      missingParentSlot: Option[Slot]
      goodBlock: Option[Slot]

      # TODO when https://github.com/nim-lang/Nim/issues/21306 is fixed in used
      # Nim versions, remove workaround and move `res` into for loop
      res: Result[void, VerifierError]

    var i=0
    for blk, blb in sq.blocks(item):
      res = await sq.blockVerifier(blk[], blb, maybeFinalized)
      inc(i)

      if res.isOk():
        goodBlock = some(blk[].slot)
      else:
        case res.error()
        of VerifierError.MissingParent:
          missingParentSlot = some(blk[].slot)
          break
        of VerifierError.Duplicate:
          # Keep going, happens naturally
          discard
        of VerifierError.UnviableFork:
          # Keep going so as to register other unviable blocks with the
          # quarantine
          if unviableBlock.isNone:
            # Remember the first unviable block, so we can log it
            unviableBlock = some((blk[].root, blk[].slot))

        of VerifierError.Invalid:
          hasInvalidBlock = true

          let req = item.request
          notice "Received invalid sequence of blocks", request = req,
                  blocks_count = len(item.data),
                  blocks_map = getShortMap(req, item.data)
          req.item.updateScore(PeerScoreBadValues)
          break

    # When errors happen while processing blocks, we retry the same request
    # with, hopefully, a different peer
    let retryRequest =
      hasInvalidBlock or unviableBlock.isSome() or missingParentSlot.isSome()
    if not(retryRequest):
      let numSlotsAdvanced = item.request.count - sq.numAlreadyKnownSlots(sr)
      sq.advanceOutput(numSlotsAdvanced)

      if goodBlock.isSome():
        # If there no error and response was not empty we should reward peer
        # with some bonus score - not for duplicate blocks though.
        item.request.item.updateScore(PeerScoreGoodValues)
        item.request.item.updateStats(SyncResponseKind.Good, 1'u64)

        # BlockProcessor reports good block, so we can reward all the peers
        # who sent us empty responses.
        sq.rewardForGaps(PeerScoreGoodValues)
        sq.gapList.reset()
      else:
        # Response was empty
        item.request.item.updateStats(SyncResponseKind.Empty, 1'u64)

      sq.processGap(item)

      if numSlotsAdvanced > 0:
        sq.wakeupWaiters()
    else:
      debug "Block pool rejected peer's response", request = item.request,
            blocks_map = getShortMap(item.request, item.data),
            blocks_count = len(item.data),
            ok = goodBlock.isSome(),
            unviable = unviableBlock.isSome(),
            missing_parent = missingParentSlot.isSome()
      # We need to move failed response to the debts queue.
      sq.toDebtsQueue(item.request)

      if unviableBlock.isSome():
        let req = item.request
        notice "Received blocks from an unviable fork", request = req,
              blockRoot = unviableBlock.get()[0],
              blockSlot = unviableBlock.get()[1],
              blocks_count = len(item.data),
              blocks_map = getShortMap(req, item.data)
        req.item.updateScore(PeerScoreUnviableFork)

      if missingParentSlot.isSome():
        var
          resetSlot: Option[Slot]
          failSlot = missingParentSlot.get()

        # If we got `VerifierError.MissingParent` it means that peer returns
        # chain of blocks with holes or `block_pool` is in incomplete state. We
        # going to rewind the SyncQueue some distance back (2ⁿ, where n∈[0,∞],
        # but no more than `finalized_epoch`).
        let
          req = item.request
          safeSlot = sq.getSafeSlot()
          gapsCount = len(sq.gapList)

        # We should penalize all the peers which responded with gaps.
        sq.rewardForGaps(PeerScoreMissingValues)
        sq.gapList.reset()

        case sq.kind
        of SyncQueueKind.Forward:
          if goodBlock.isSome():
            # `VerifierError.MissingParent` and `Success` present in response,
            # it means that we just need to request this range one more time.
            debug "Unexpected missing parent, but no rewind needed",
                  request = req, finalized_slot = safeSlot,
                  last_good_slot = goodBlock.get(),
                  missing_parent_slot = missingParentSlot.get(),
                  blocks_count = len(item.data),
                  blocks_map = getShortMap(req, item.data),
                  gaps_count = gapsCount
            req.item.updateScore(PeerScoreMissingValues)
          else:
            if safeSlot < req.slot:
              let rewindSlot = sq.getRewindPoint(failSlot, safeSlot)
              debug "Unexpected missing parent, rewind happens",
                   request = req, rewind_to_slot = rewindSlot,
                   rewind_point = sq.rewind, finalized_slot = safeSlot,
                   blocks_count = len(item.data),
                   blocks_map = getShortMap(req, item.data),
                   gaps_count = gapsCount
              resetSlot = some(rewindSlot)
            else:
              error "Unexpected missing parent at finalized epoch slot",
                  request = req, rewind_to_slot = safeSlot,
                  blocks_count = len(item.data),
                  blocks_map = getShortMap(req, item.data),
                  gaps_count = gapsCount
              req.item.updateScore(PeerScoreBadValues)
        of SyncQueueKind.Backward:
          if safeSlot > failSlot:
            let rewindSlot = sq.getRewindPoint(failSlot, safeSlot)
            # It's quite common peers give us fewer blocks than we ask for
            debug "Gap in block range response, rewinding", request = req,
                 rewind_to_slot = rewindSlot, rewind_fail_slot = failSlot,
                 finalized_slot = safeSlot, blocks_count = len(item.data),
                 blocks_map = getShortMap(req, item.data)
            resetSlot = some(rewindSlot)
            req.item.updateScore(PeerScoreMissingValues)
          else:
            error "Unexpected missing parent at safe slot", request = req,
                  to_slot = safeSlot, blocks_count = len(item.data),
                  blocks_map = getShortMap(req, item.data)
            req.item.updateScore(PeerScoreBadValues)

        if resetSlot.isSome():
          await sq.resetWait(resetSlot)
          case sq.kind
          of SyncQueueKind.Forward:
            debug "Rewind to slot has happened", reset_slot = resetSlot.get(),
                  queue_input_slot = sq.inpSlot, queue_output_slot = sq.outSlot,
                  rewind_point = sq.rewind, direction = sq.kind
          of SyncQueueKind.Backward:
            debug "Rewind to slot has happened", reset_slot = resetSlot.get(),
                  queue_input_slot = sq.inpSlot, queue_output_slot = sq.outSlot,
                  direction = sq.kind

      break

proc push*[T](sq: SyncQueue[T], sr: SyncRequest[T]) =
  ## Push failed request back to queue.
  if sr.index notin sq.pending:
    # If request `sr` not in our pending list, it only means that
    # SyncQueue.resetWait() happens and all pending requests are expired, so
    # we swallow `old` requests, and in such way sync-workers are able to get
    # proper new requests from SyncQueue.
    return
  sq.pending.del(sr.index)
  sq.toDebtsQueue(sr)

proc handlePotentialSafeSlotAdvancement[T](sq: SyncQueue[T]) =
  # It may happen that sync progress advanced to a newer `safeSlot`, either
  # by a response that started with good values and only had errors late, or
  # through an out-of-band mechanism, e.g., VC / REST.
  # If that happens, advance to the new `safeSlot` to avoid repeating requests
  # for data that is considered immutable and no longer relevant.
  let safeSlot = sq.getSafeSlot()
  func numSlotsBehindSafeSlot(slot: Slot): uint64 =
    case sq.kind
    of SyncQueueKind.Forward:
      if safeSlot > slot:
        safeSlot - slot
      else:
        0
    of SyncQueueKind.Backward:
      if slot > safeSlot:
        slot - safeSlot
      else:
        0

  let
    numOutSlotsAdvanced = sq.outSlot.numSlotsBehindSafeSlot
    numInpSlotsAdvanced =
      case sq.kind
      of SyncQueueKind.Forward:
        sq.inpSlot.numSlotsBehindSafeSlot
      of SyncQueueKind.Backward:
        if sq.inpSlot == 0xFFFF_FFFF_FFFF_FFFF'u64:
          0'u64
        else:
          sq.inpSlot.numSlotsBehindSafeSlot
  if numOutSlotsAdvanced != 0 or numInpSlotsAdvanced != 0:
    debug "Sync progress advanced out-of-band",
      safeSlot, outSlot = sq.outSlot, inpSlot = sq.inpSlot
    if numOutSlotsAdvanced != 0:
      sq.advanceOutput(numOutSlotsAdvanced)
    if numInpSlotsAdvanced != 0:
      sq.advanceInput(numInpSlotsAdvanced)
    sq.wakeupWaiters()

func updateRequestForNewSafeSlot[T](sq: SyncQueue[T], sr: var SyncRequest[T]) =
  # Requests may have originated before the latest `safeSlot` advancement.
  # Update it to not request any data prior to `safeSlot`.
  let
    outSlot = sq.outSlot
    lowSlot = sr.slot
    highSlot = sr.lastSlot
  case sq.kind
  of SyncQueueKind.Forward:
    if outSlot <= lowSlot:
      # Entire request is still relevant.
      discard
    elif outSlot <= highSlot:
      # Request is only partially relevant.
      let
        numSlotsDone = outSlot - lowSlot
      sr.slot += numSlotsDone
      sr.count -= numSlotsDone
    else:
      # Entire request is no longer relevant.
      sr.count = 0
  of SyncQueueKind.Backward:
    if outSlot >= highSlot:
      # Entire request is still relevant.
      discard
    elif outSlot >= lowSlot:
      # Request is only partially relevant.
      let
        numSlotsDone = highSlot - outSlot
      sr.count -= numSlotsDone
    else:
      # Entire request is no longer relevant.
      sr.count = 0

proc pop*[T](sq: SyncQueue[T], maxslot: Slot, item: T): SyncRequest[T] =
  ## Create new request according to current SyncQueue parameters.
  sq.handlePotentialSafeSlotAdvancement()
  while len(sq.debtsQueue) > 0:
    if maxslot < sq.debtsQueue[0].slot:
      # Peer's latest slot is less than starting request's slot.
      return SyncRequest.empty(sq.kind, T)
    if maxslot < sq.debtsQueue[0].lastSlot():
      # Peer's latest slot is less than finishing request's slot.
      return SyncRequest.empty(sq.kind, T)
    var sr = sq.debtsQueue.pop()
    sq.debtsCount = sq.debtsCount - sr.count
    sq.updateRequestForNewSafeSlot(sr)
    if sr.isEmpty:
      continue
    sr.setItem(item)
    sq.makePending(sr)
    return sr

  case sq.kind
  of SyncQueueKind.Forward:
    if maxslot < sq.inpSlot:
      # Peer's latest slot is less than queue's input slot.
      return SyncRequest.empty(sq.kind, T)
    if sq.inpSlot > sq.finalSlot:
      # Queue's input slot is bigger than queue's final slot.
      return SyncRequest.empty(sq.kind, T)
    let lastSlot = min(maxslot, sq.finalSlot)
    let count = min(sq.chunkSize, lastSlot + 1'u64 - sq.inpSlot)
    var sr = SyncRequest.init(sq.kind, sq.inpSlot, count, item)
    sq.advanceInput(count)
    sq.makePending(sr)
    sr
  of SyncQueueKind.Backward:
    if sq.inpSlot == 0xFFFF_FFFF_FFFF_FFFF'u64:
      return SyncRequest.empty(sq.kind, T)
    if sq.inpSlot < sq.finalSlot:
      return SyncRequest.empty(sq.kind, T)
    let (slot, count) =
      block:
        let baseSlot = sq.inpSlot + 1'u64
        if baseSlot - sq.finalSlot < sq.chunkSize:
          let count = uint64(baseSlot - sq.finalSlot)
          (baseSlot - count, count)
        else:
          (baseSlot - sq.chunkSize, sq.chunkSize)
    if (maxslot + 1'u64) < slot + count:
      # Peer's latest slot is less than queue's input slot.
      return SyncRequest.empty(sq.kind, T)
    var sr = SyncRequest.init(sq.kind, slot, count, item)
    sq.advanceInput(count)
    sq.makePending(sr)
    sr

proc debtLen*[T](sq: SyncQueue[T]): uint64 =
  sq.debtsCount

proc pendingLen*[T](sq: SyncQueue[T]): uint64 =
  case sq.kind
  of SyncQueueKind.Forward:
    # When moving forward `outSlot` will be <= of `inpSlot`.
    sq.inpSlot - sq.outSlot
  of SyncQueueKind.Backward:
    # When moving backward `outSlot` will be >= of `inpSlot`
    sq.outSlot - sq.inpSlot

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
  sq.total - sq.len
