# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[heapqueue, tables, strutils, sequtils, math]
import stew/base10, chronos, chronicles, results
import
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/rest_types,
  ../spec/[helpers, forks, network, peerdas_helpers],
  ../networking/[peer_pool, peer_scores, eth2_network],
  ../gossip_processing/block_processor,
  ../beacon_clock,
  "."/[sync_protocol, column_syncer, sync_queue]

export phase0, altair, merge, chronos, chronicles, results,
       helpers, peer_scores, sync_queue, forks, sync_protocol

type
  ColumnSyncWaiter* = ref object
    future: Future[void].Raising([CancelledError])
    reset: bool

  ColumnSyncRequest*[T] = object
    slot*: Slot
    count*: uint64
    item*: T

  ColumnSyncResult*[T] = object
    request*: T
    columns*: Opt[seq[DataColumnSidecars]]

  ColumnSyncerAssist*[T] = ref object
    inpSlot*: Slot
    outSlot*: Slot
    startSlot*: Slot
    finalSlot*: Slot
    chunkSize*: uint64
    queueSize*: int
    counter*: uint64
    received_table*: OrderedTable[(Eth2Digest, Slot), DataColumnSidecars]
      ## An in-memory table to store DataColumnSidecars against their Slot
      ## and extracted block root, the reason for having block root as a
      ## part of the key is to effectively repairing strategies if the
      ## remote peers reply with just a part of columns than what they
      ## were supposed to, additionally, this entire loop is independent
      ## to block/blobs sync hence, this is the only plausible way for
      ## us store columns against a block.
      ##
      ## Instead of checking whether block was Proposed or Orphaned or
      ## any similar situation, one can simply lookup the table and infer
      ## either there were no columns against that block, or there was no
      ## block that was mutually agreed as valid, in any case we do not
      ## have columns for that slot.
    pending*: Table[uint64, ColumnSyncRequest[T]]
    gapList*: seq[GapItem[T]]
    waiters*: seq[ColumnSyncWaiter]
    getSafeSlot*: GetSlotCallback
    debtsQueue: HeapQueue[ColumnSyncResult[T]]
    debtsCount: uint64
    readyQueue: HeapQueue[ColumnSyncResult[T]]
    rewind: Option[RewindPoint]

proc init[T](t: typedesc[ColumnSyncRequest],
             start: Slot,
             finish: Slot):
             ColumnSyncRequest[T] =
  let count = finish - start + 1'u64
  ColumnSyncRequest[T](slot: start, count: count)

proc init[T](t: typedesc[ColumnSyncRequest],
             start: Slot,
             count: uint64,
             item: T):
             ColumnSyncRequest[T] =
  ColumnSyncRequest[T](slot: start, count: count, item: item)

proc init[T](t: typedesc[ColumnSyncRequest],
             start: Slot,
             finish: Slot,
             item: T):
             ColumnSyncRequest[T] =
  let count = finish - start + 1'u64
  ColumnSyncRequest[T](slot: start, count: count, item: item)

proc empty*[T](t: typedesc[ColumnSyncRequest]):
               ColumnSyncRequest[T] {.inline.} =
  ColumnSyncRequest[T](count: 0'u64)

proc setItem*[T](r: var ColumnSyncRequest[T], item: T):
                 bool {.inline.} =
  r.item = item

proc isReqEmpty*[T](r: ColumnSyncRequest[T]):
                    bool {.inline.} =
  (r.count == 0'u64)

template shortLog*[T](req: ColumnSyncRequest[T]): string =
  Base10.toString(uint64(req.slot)) & ":" &
  Base10.toString(req.count) & "@" &
  Base10.toString(req.index)

proc contains*[T](req: ColumnSyncRequest, slot: Slot): bool {.inline.} =
  slot >= req.slot and slot < req.slot + req.count

proc cmp*[T](a, b: ColumnSyncRequest[T]): int =
  cmp(uint64(a.slot), uint64(b.slot))

proc checkDataColumnResponse*[T](req: ColumnSyncRequest[T],
                                 data: openArray[Slot]):
                                 Result[void, string] =
  if data.len == 0:
    return ok()

  if lenu64(data) > (req.count * NUMBER_OF_COLUMNS):
    # Number of data columns in the response should be less than
    # or equal to (MAX_BLOBS_PER_BLOCK_FULU * NUMBER_OF_COLUMNS).
    return err ("Too many data columns have been received")

  var
    pSlot = data[0]
    counter = 0'u64
  for slot in data:
    if (slot < req.slot) or (slot >= req.slot + req.count):
      return err ("Some of the data columns are not in the range")
    if slot < pSlot:
      return err ("Data columns have been sent in incorrect order")
    if slot == pSlot:
      inc counter
      # keeping this constant Electra until Fulu comes in
      if counter > MAX_BLOBS_PER_BLOCK_ELECTRA:
        return err ("Number of data columns in the block has exceeded the limit")
    else:
      counter = 1'u64
    pSlot = slot

  ok()

proc init*[T](t1: typedesc[ColumnSyncerAssist],
              start, final: Slot, chunkSize: uint64,
              getSafeSlotCb: GetSlotCallback):
              ColumnSyncerAssist[T] =

  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  ColumnSyncerAssist[T](
    startSlot: start,
    finalSlot: final,
    chunkSize: chunkSize,
    getSafeSlot: getSafeSlotCb,
    counter: 1'u64,
    received_table: initTable[(Eth2Digest, Slot), DataColumnSidecars](),
    pending: initTable[uint64, ColumnSyncRequest[T]](),
    inpSlot: start,
    outSlot: start
  )

proc `==`*[T](a, b: ColumnSyncRequest[T]): bool =
  (a.slot == b.slot) and (a.count == b.count)

proc lastSlot*[T](r: ColumnSyncRequest[T]): Slot =
  ## Returns last slot for request
  r.slot + r.count - 1'u64

proc makePending*[T](cas: ColumnSyncerAssist[T], req: var ColumnSyncRequest[T]) =
  req.index = cas.counter
  cas.counter = cas.counter + 1'u64

proc updateLastSlot*[T](cas: ColumnSyncerAssist[T], last: Slot) {.inline.} =
  cas.finalSlot = last

proc wakeUpWaiters[T](cas: ColumnSyncerAssist[T], reset = false) =
  ## Wakeup one or all blocked waiters
  for item in cas.waiters:
    if reset:
      item.reset = true

    if not(item.future.finished()):
      item.future.complete()

proc waitForChanges[T](cas: ColumnSyncerAssist[T]):
                       Future[bool]
                       {.async: (raises: [CancelledError]).} =
  ## Create new waiter and wait for completion from `wakeUpWaiters()`.
  let
    waitFut =
      Future[void].Raising([CancelledError]).init("ColumnSyncerAssist.waitForChanges")
    waitItem =
      ColumnSyncWaiter(future: waitfut)
  cas.waiters.add(waitItem)
  try:
    await waitFut
    return waitItem.reset
  finally:
    cas.waiters.delete(cas.waiters.find(waitItem))

proc wakeupAndWaitWaiters[T](cas: ColumnSyncerAssist[T])
                            {.async: (raises: [CancelledError]).} =
  ## This proc will perform wakeUpWaiters(true) and block until
  ## last waiter will be awakened
  var waitChanges = cas.waitForChanges()
  cas.wakeupWaiters(true)
  discard await waitChanges

proc clearAndWakeup*[T](cas: ColumnSyncerAssist[T]) =
  cas.pending.clear()
  cas.wakeUpWaiters(true)

proc isEmpty*[T](sr: ColumnSyncResult[T]): bool {.inline.} =
  ## Returns ``true`` if response chain of blocks is empty (has only
  ## empty slots).
  len(sr.data) == 0

proc hasEndGap*[T](sr: ColumnSyncResult[T]): bool {.inline.} =
  ## Returns ``true`` if response chain of blocks has a gap at the end
  let lastSlot =
    sr.request.slot + sr.request.count - 1'u64
  if len(sr.data) == 0:
    return true
  if sr.data[^1][].slot != lastslot:
    return true
  return false

proc getLastNonEmptySlot*[T](sr: ColumnSyncResult[T]): Slot {.inline.} =
  ## Returns last non-empty slot from result. If response has only
  ## empty slots, original request slot will be returned.
  if len(sr.data) == 0:
    # If response has only empty slots we are going to use original
    # request slot
    sr.request.slot
  else:
    sr.data[^1][].slot

proc processGap[T](cas: ColumnSyncerAssist[T], sr: ColumnSyncResult[T]) =
  if sr.isEmpty():
    let gitem = GapItem[T](start: sr.request.slot,
                           finish: sr.request.slot + sr.request.count - 1'u64,
                           item: sr.request.item)
    cas.gapList.add(gitem)
  else:
    if sr.hasEndGap():
      let gitem = GapItem[T](start: sr.getLastNonEmptySlot() + 1'u64,
                             finish: sr.request.slot + sr.request.count - 1'u64,
                             item: sr.request.item)
      cas.gapList.add(gitem)
    else:
      cas.gapList.reset()

proc rewardForGaps[T](cas: ColumnSyncerAssist[T], score: int) =
  mixin updateScore, getStats

  for gap in cas.gapList:
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
        debug "Peer received gap penalty, for missing columns in response",
              peer = gap.item, penalty = newScore
    else:
      gap.item.updateScore(score)

proc toDebtsQueue[T](cas: ColumnSyncerAssist[T], sr: ColumnSyncResult[T]) =
  cas.debtsQueue.push(sr)


proc getRewindPoint*[T](cas: ColumnSyncerAssist[T], failSlot: Slot,
                        safeSlot: Slot): Slot =
  # Calculate the latest finalized epoch
  let finalizedEpoch = epoch(safeSlot)

  # Calculate the failure epoch
  let failEpoch = epoch(failSlot)

  # Calculate exponential rewind point in number of epochs
  let epochCount =
    if cas.rewind.isSome():
      let rewind = cas.rewind.get()
      if failSlot == rewind.failSlot:
        # `MissingParent` happened at same slot so we increase rewind point by
        # factor of 2
        if failEpoch > finalizedEpoch:
          let rewindPoint = rewind.epochCount shl 1
          if rewindPoint < rewind.epochCount:
            # If exponential rewind point produces `uint64` overflow we will
            # make rewind to latest finalized epoch
            failEpoch - finalizedEpoch
          else:
            if (failEpoch < rewindPoint) or
               (failEpoch - rewindPoint < finalizedEpoch):
              # If exponential rewind points to position which is far
              # behind latest finalized epoch
              failEpoch - finalizedEpoch
            else:
              rewindPoint
        else:
          warn "ColumnSyncer: Trying to rewind over the last finalized epoch",
               finalized_slot = safeSlot, fail_slot = failSlot,
               finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
               rewind_epoch_count = rewind.epochCount,
               finalized_epoch = finalizedEpoch
          0'u64
      else:
        # `MissingParent` happened at different slot so we are going to
        # rewind 1 epoch only
        if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
          warn "ColumnSyncer: Could not rewind further than the last finalized epoch",
               finalized_slot = safeSlot, fail_slot = failSlot,
               finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
               rewind_epoch_count = rewind.epochCount,
               finalizedEpoch = finalizedEpoch
          0'u64
        else:
          1'u64

    else:
      # `MissingParent` happened first time.
      if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
        warn "ColumnSyncer: Could not rewind further than the last finalized epoch",
             finalized_slot = safeSlot, fail_slot = failSlot,
             finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
             rewind_epoch_count = rewind.epochCount,
             finalizedEpoch = finalizedEpoch
        0'u64
      else:
        1'u64

  if epochCount == 0'u64:
    warn "ColumnSyncer: Unable to continue syncing, please restart the node",
         finalized_slot = safeSlot, fail_slot = failSlot,
         finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
         finalized_epoch = finalizedEpoch

    # Calculate the rewind epoch, which will be equal to last rewind point or
    # finalizedEpoch
    let rewindEpoch =
      if cas.rewind.isNone():
        finalizedEpoch
      else:
        epoch(cas.rewind.get().failSlot) - cas.rewind.get().epochCount
    rewindEpoch.start_slot()
  else:
    # Calculate the rewind epoch, which should not be less than the latest
    # finalized epoch.
    let rewindEpoch = failEpoch - epochCount
    # Update and save new rewind point in ColumnSyncerAssist
    cas.rewind = some(RewindPoint(failSlot: failSlot, epochCount: epochCount))
    rewindEpoch.start_slot()


proc advanceOutput*[T](cas: ColumnSyncerAssist[T], number: uint64) =
  cas.inpSlot = cas.inpSlot + number

proc notInRange[T](cas: ColumnSyncerAssist[T], sr: ColumnSyncResult[T]): bool =
  (cas.slot > cas.outSlot)

func numAlreadyKnownSlots[T](cas: ColumnSyncerAssist[T], sr: ColumnSyncResult[T]): uint64 =
  ## Compute the number of slots covered by a given `ColumnSyncRequest` that are
  ## already known and, hence, no relevant for column sync progression
  let
    outSlot = cas.outSlot
    lowSlot = cas.slot
    highSlot = sr.lastSlot

  if outSlot > highSlot:
    # Entire request is no longer relevant
    sr.count
  elif outSlot > lowSlot:
    # Request is only partially relevant
    outSlot - lowSlot
  else:
    # Entire request is still relevant
    0

proc handlePotentialSafeSlotAdvancement[T](cas: ColumnSyncerAssist[T]) =
  # It may happen that sync progress advanced to a newer `safeSlot`, either
  # by a response that started with good values and only had errors late,
  # or through an out-of-bound mechanism, e.g., VC/REST.
  # If that happens, advance to the new `safeSlot` to avoid repeating requests
  # for data is considered immutable and no longer relevant.

  let safeSlot = cas.getSafeSlot()
  func numSlotBehindSafeSlot(slot: Slot): uint64 =
    if safeSlot > slot:
      safeSlot - slot
    else:
      0

  let
    numOutSlotsAdvanced = cas.outSlot.numSlotBehindSafeSlot
    numInpSlotsAdvanced =
      cas.inpSlot.numSlotBehindSafeSlot

  if numOutSlotsAdvanced != 0 or numInpSlotsAdvanced != 0:
    debug "ColumnSyncer: Sync progress out-of-band",
      safeSlot, outSlot = cas.outSlot, inpSlot = cas.inpSlot
    if numOutSlotsAdvanced != 0:
      cas.advanceOutput(numOutSlotsAdvanced)
    if numInpSlotsAdvanced != 0:
      cas.advanceInput(numInpSlotsAdvanced)
    cas.wakeupWaiters()

func updateRequestForNewSafeSlot[T](cas: ColumnSyncerAssist[T], sr: ColumnSyncResult[T]) =
  # Requests may have originated before the latest `safeSlot` advancement.
  # Update it to not request any data prior to `safeSlot`.

  let
    outSlot = cas.outSlot
    lowSlot = sr.slot
    highSlot = cas.lastSlot

  if outSlot <= lowSlot:
    # Entire request is still relevant
    discard
  elif outSlot <= highSlot:
    # Request is only partially relevant
    let
      numSlotsDone = outSlot - lowSlot
    cas.slot += numSlotsDone
    cas.count -= numSlotsDone
  else:
    # Entire request is no longer relevant
    cas.count = 0

proc pop*[T](cas: ColumnSyncerAssist[T], maxSlot: Slot, item: T): ColumnSyncRequest[T] =
  ## Create new request according to current ColumnSyncerAssist parameters.
  cas.handlePotentialSlotAdvancement()
  while len(cas.debtsQueue) > 0:
    if maxSlot < cas.debtsQueue[0].slot:
      # Peer's latest slot is less than starting request's slot
      return ColumnSyncRequest.empty(T)
    if maxSlot < cas.debtsQueue[0].lastSlot():
      # Peer's latest slot is less than finishing request's slot
      return ColumnSyncResult.empty(T)
    var sr = cas.debtsQueue.pop()
    cas.debtsQueue = cas.debtsCount - sr.count
    cas.updateRequestForNewSafeSlot(sr)
    if sr.isEmpty():
      continue
    sr.setItem(item)
    cas.makePending(sr)
    return sr

  if maxSlot < cas.inpSlot:
    # Peer's latest slot is less than queue's input slot.
    return ColumnSyncRequest.empty(T)
  if cas.inpSlot > cas.finalSlot:
    # Queue's input slot is bigger than queue's final slot.
    return ColumnSyncRequest.empty(T)
  let
    lastSlot = min(maxSlot, cas.finalSlot)
    count = min(cas.chunkSize, lastSlot + 1'u64 - cas.inpSlot)
  var sr = ColumnSyncRequest.init(cas.inpSlot, count, item)
  cas.advanceInput(count)
  cas.makePending(sr)
  sr

proc debtLen*[T](cas: ColumnSyncerAssist[T]): uint64 =
  cas.debtsCount

proc pendingLen*[T](cas: ColumnSyncerAssist[T]): uint64 =
  # As we move forward `outSlot` will be  <= of `inpSlot`.
  cas.inpSlot = cas.outSlot

proc len*[T](cas: ColumnSyncerAssist[T]): uint64 {.inline.} =
  ## Returns number of slots left in ``cas``
  if cas.finalSlot >= cas.outSlot:
    cas.finalSlot + 1'u64 - cas.outSlot
  else:
    0'u64

proc total*[T](cas: ColumnSyncerAssist[T]): uint64 {.inline.} =
  ## Returns total number of slots in queue ``sq``.
  if cas.finalSlot >= cas.startSlot:
    cas.finalSlot + 1'u64 - cas.finalSlot
  else:
    0'u64

proc progress*[T](cas: ColumnSyncerAssist[T]): uint64 =
  ## How many useful slots we've synced so far, adjusting for how much has
  ## become obsolete by time movements
  cas.total - cas.len
















