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
  ../spec/[helpers, forks, network],
  ../networking/[peer_pool, peer_scores, eth2_network],
  ../gossip_processing/block_processor,
  ../beacon_clock,
  "."/[sync_protocol, sync_queue]

type
  PeerdasBlockVerifier* = proc(signedBlock: ForkedSignedBeaconBlock,
                               columns: Opt[DataColumnSidecars],
                               maybeFinalized: bool):
      Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).}

  ColumnSyncWaiter* = ref object
    future: Future[void].Raising([CancelledError])
    reset: bool

  ColumnSyncerDirection* {.pure.} = enum
    Forward, Backward

  ColumnSyncRequest*[T] = object
    direction*: ColumnSyncerDirection
    index*: uint64
    slot*: Slot
    count*: uint64
    item*: T

  ColumnSyncResult*[T] = object
    request*: T
    data*: seq[ref ForkedSignedBeaconBlock]
    columns*: Opt[seq[DataColumnSidecars]]

  ColumnSyncerAssist*[T] = ref object
    direction*: ColumnSyncerDirection
    inpSlot*: Slot
    outSlot*: Slot
    startSlot*: Slot
    finalSlot*: Slot
    chunkSize*: uint64
    queueSize*: int
    counter*: uint64
    pending*: Table[uint64, ColumnSyncRequest[T]]
    gapList*: seq[GapItem[T]]
    waiters*: seq[ColumnSyncWaiter]
    getSafeSlot*: GetSlotCallback
    debtsQueue: HeapQueue[ColumnSyncResult[T]]
    debtsCount: uint64
    readyQueue: HeapQueue[ColumnSyncResult[T]]
    rewind: Option[RewindPoint]
    peerdasBlockVerifier: PeerdasBlockVerifier

proc init[T](t1: typedesc[ColumnSyncRequest], direction: ColumnSyncerDirection, start: Slot,
             finish: Slot, t2: typedesc[T]): ColumnSyncRequest[T] =
  let count = finish - start + 1'u64
  ColumnSyncRequest[T](direction: direction, slot: start, count: count)

proc init[T](t1: typedesc[ColumnSyncRequest], direction: ColumnSyncerDirection, slot: Slot,
             count: uint64, item: T): ColumnSyncRequest[T] =
  ColumnSyncRequest[T](direction: direction, slot: slot, count: count, item: item)

proc init[T](t1: typedesc[ColumnSyncRequest], direction: ColumnSyncerDirection, start: Slot,
             finish: Slot, item: T): ColumnSyncRequest[T] =
  let count = finish - start + 1'u64
  ColumnSyncRequest[T](direction: direction, slot: start, count: count, item: item)

proc empty*[T](t: typedesc[ColumnSyncRequest], direction: ColumnSyncerDirection,
               t2: typedesc[T]): ColumnSyncRequest[T] {.inline.} =
  ColumnSyncRequest[T](direction: direction, count: 0'u64)

proc setItem*[T](sr: var ColumnSyncRequest[T], item: T) =
  sr.item = item

proc isEmpty*[T](sr: ColumnSyncRequest[T]): bool {.inline.} =
  (sr.count == 0'u64)

template shortLog*[T](req: ColumnSyncRequest[T]): string =
  Base10.toString(uint64(req.slot)) & ":" &
  Base10.toString(req.count) & "@" &
  Base10.toString(req.index)

proc contains*[T](req: ColumnSyncRequest, slot: Slot): bool {.inline.} =
  slot >= req.slot and slot < req.slot + req.count

proc cmp*[T](a, b: ColumnSyncRequest[T]): int =
  cmp(uint64(a.slot), uint64(b.slot))

proc checkDataColumnsResponse*[T](req: ColumnSyncRequest[T],
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

proc init*[T](t1: typedesc[ColumnSyncerAssist], t2: typedesc[T],
              direction: ColumnSyncerDirection,
              start, final: Slot, chunkSize: uint64,
              getSafeSlotCb: GetSlotCallback,
              peerdasBlockVerifier: PeerdasBlockVerifier,
              syncQueueSize: int = -1):
              ColumnSyncerAssist[T] =

  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  ColumnSyncerAssist[T](
    direction: direction,
    startSlot: start,
    finalSlot: final,
    chunkSize: chunkSize,
    queueSize: syncQueueSize,
    getSafeSlot: getSafeSlotCb,
    waiters: newSeq[ColumnSyncWaiter](),
    counter: 1'u64,
    pending: initTable[uint64, ColumnSyncRequest[T]](),
    debtsQueue: initHeapQueue[ColumnSyncResult[T]](),
    inpSlot: start,
    outSlot: start,
    peerdasBlockVerifier: peerdasBlockVerifier)

proc `<`*[T](a, b: ColumnSyncRequest[T]): bool =
  doAssert(a.direction == b.direction)
  case a.direction
  of ColumnSyncerDirection.Forward:
    a.slot < b.slot
  of ColumnSyncerDirection.Backward:
    a.slot > b.slot

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

proc resetWait*[T](cas: ColumnSyncerAssist[T], toSlot: Option[Slot]) {.async: (raises: [CancelledError]).} =
  cas.pending.clear()

  let minSlot =
    case cas.direction
    of ColumnSyncerDirection.Forward:
      if toSlot.isSome():
        min(toSlot.get(), cas.outSlot)
      else:
        cas.outSlot
    of ColumnSyncerDirection.Backward:
      if toSlot.isSome():
        toSlot.get()
      else:
        cas.outSlot
  cas.debtsQueue.clear()
  cas.debtsCount = 0
  cas.readyQueue.clear()
  cas.inpSlot = minSlot
  cas.outSlot = minSlot
  # Waking up all waiters and wait for last one.
  await cas.wakeupAndWaitWaiters()

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
  cas.debtsCount = cas.debtsCount + sr.count

proc getRewindPoint*[T](cas: ColumnSyncerAssist[T], failSlot: Slot,
                        safeSlot: Slot): Slot =
  logScope:
    direction = cas.kind

  case cas.direction
  of ColumnSyncerDirection.Forward:
    # Calculate the latest finalized epoch
    let finalizedEpoch = epoch(safeSlot)

    # Calculate failure epoch
    let failEpoch = epoch(failSlot)

    # Calculate exponential rewind point in number of epochs.
    let epochCount =
      if cas.rewind.isSome():
        let rewind = cas.rewind.get()
        if failSlot == rewind.failSlot:
          # `MissingParent` happened at same slot so we increase rewind point by
          # factor of 2.
          if failEpoch > finalizedEpoch:
            let rewindPoint = rewind.epochCount shl 1
            if rewindPoint < rewind.epochCount:
              # If exponential rewind point produces `uint64` overflow we will
              # make rewind to latest finalized epoch
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
          # `MissingParent` happened at different slot so we are going to rewind
          # for 1 epoch only.
          if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
            warn "Could not rewind further than the last finalized epoch",
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
          warn "Could not rewind further than the last finalized slot",
               finalized_slot = safeSlot, fail_slot = failSlot,
               finalized_epoch = finalizedEpoch, fail_epoch = failEpoch
          0'u64
        else:
          1'u64

    if epochCount == 0'u64:
      warn "Unable to continue syncing, please restart the node",
           finalized_slot = safeSlot, fail_slot = failSlot,
           finalized_epoch = finalizedEpoch, fail_epoch = failEpoch
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
      cas.rewind = some(RewindPoint(failSlot, epochCount: epochCount))
      rewindEpoch.start_slot()

  of ColumnSyncerDirection.Backward:
    # While we perform backward sync, the only possible slot we could rewind is
    # the latest stored block.
    if failSlot == safeSlot:
      warn "Unable to continue syncing, please restart the node",
           safe_slot = safeSlot, fail_slot = failSlot
    safeSlot

func getOpt(columns: Opt[seq[DataColumnSidecars]], i: int): Opt[DataColumnSidecars] =
  if columns.isSome:
    Opt.some(columns.get()[i])
  else:
    Opt.none(DataColumnSidecars)

iterator peerdas_blocks[T](cas: ColumnSyncerAssist[T],
                           sr: ColumnSyncResult[T]): (ref ForkedSignedBeaconBlock, Opt[DataColumnSidecars]) =
  case cas.direction
  of ColumnSyncerDirection.Forward:
    for i in countup(0, len(sr.data) - 1):
      yield (sr.data[i], sr.columns.getOpt(i))
  of ColumnSyncerDirection.Backward:
    for i in countdown(len(sr.data) - 1, 0):
      yield (sr.data[i], sr.columns.getOpt(i))

proc advanceOutput*[T](cas: ColumnSyncerAssist[T], number: uint64) =
  case cas.direction
  of ColumnSyncerDirection.Forward:
    cas.outSlot = cas.outSlot + number
  of ColumnSyncerDirection.Backward:
    cas.outSlot = cas.outSlot - number

proc advanceInput[T](cas: ColumnSyncerAssist[T], number: uint64) =
  case cas.direction
  of ColumnSyncerDirection.Forward:
    cas.inpSlot = cas.inpSlot + number
  of ColumnSyncerDirection.Backward:
    cas.inpSlot = cas.inpSlot - number

proc notInRange[T](cas: ColumnSyncerAssist[T], sr: ColumnSyncResult[T]): uint64 =
  case cas.direction:
  of ColumnSyncerDirection.Forward:
    (cas.queueSize > 0) and (sr.slot > cas.outSlot)
  of ColumnSyncerDirection.Backward:
    (cas.queueSize > 0) and (sr.lastSlot < cas.outSlot)

func numAlreadyKnownSlots[T](cas: ColumnSyncerAssist, sr: ColumnSyncResult[T]): uint64 =
  ## Compute the number of slots covered by a given `ColumnSyncResult` that are
  ## already known and, hence, no relevant for sync progressions
  let
    outSlot = cas.outSlot
    lowSlot = sr.slot
    highSlot = sr.lastSlot
  case cas.direction
  of ColumnSyncerDirection.Forward:
    if outSlot > highSlot:
      # Entire request is no longer relevant.
      sr.count
    elif outSlot > lowSlot:
      # Request is only partially relevant.
      outSlot - lowSlot
    else:
      # Entire request is still relevant.
      0
  of ColumnSyncerDirection.Backward:
    if lowSlot > outSlot:
      # Entire request is no longer relevant
      sr.count
    elif highSlot > outSlot:
      # Request is only partially relevant
      highSlot - outSlot
    else:
      # Entire request is still relevant
      0

proc push*[T](cas: ColumnSyncerAssist[T], sr: ColumnSyncRequest[T],
              data: seq[ref ForkedSignedBeaconBlock],
              columns: Opt[seq[DataColumnSidecars]],
              maybeFinalized: bool = false,
              processingCb: ProcessingCallback = nil)
              {.async: (raises: [CancelledError]).} =

  ## Push successful result to queue
  mixin updateScore, updateStats, getStats
  if sr.index notin cas.pending:
    # If request sr not in our pending list, it only means that
    # ColumnSyncerAssist.resetWait() happens and all pending requests are expired, so
    # we swallow `old` requests, and in such a way sync workers are able to get
    # proper new requests from ColumnSyncerAssist
    return

  cas.pending.del(sr.index)

  while true:
    if cas.notInRange(sr):
      let reset = await cas.waitForChanges()
      if reset:
        # ColumnSyncerAssist reset
        return
    else:
      let syncres = ColumnSyncResult[T](request: sr, data: data, columns: columns)
      cas.readyQueue.push(syncres)
      break

  while len(cas.readyQueue) > 0:
    let reqres =
      case cas.direction
      of ColumnSyncerDirection.Forward:
        let minSlot = cas.readyQueue[0].request.slot
        if cas.outSlot < minSlot:
          none[ColumnSyncResult[T]]()
        else:
          some(cas.readyQueue.pop())
      of ColumnSyncerDirection.Backward:
        let maxSlot = cas.readyQueue[0].request.slot +
                      (cas.readyQueue[0].request.count - 1'u64)
        if cas.outSlot > maxSlot:
          none[ColumnSyncResult[T]]()
        else:
          some(cas.readyQueue.pop())

    let item =
      if reqres.isSome():
        reqres.get()
      else:
        let rewindSlot = cas.getRewindPoint(cas.outSlot, cas.getSafeSlot())
        warn "Got incorrect column sync result in queue, rewinding",
             blocks_count = len(cas.readyQueue[0].data),
             output_slot = cas.outSlot, input_slot = cas.inpSlot,
             rewind_to_slot = rewindSlot, request = cas.readyQueue[0].request
        await cas.resetWait(some(rewindSlot))
        break

    if processingCb != nil:
      processingCb()

    # Validating received blocks one by one
    var
      hasInvalidBlock = false
      unviableBlock: Option[(Eth2Digest, Slot)]
      missingParentSlot: Option[Slot]
      goodBlock: Option[Slot]

      res: Result[void, VerifierError]

    var i=0
    for blk, col in cas.peerdas_blocks(item):
      res = await cas.peerdasBlockVerifier(blk[], cols, maybeFinalized)
      inc i

      if res.isOk:
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
          # Keep going as to register other unviable blocks with the
          # quarantine
          if unviableBlock.isNone:
            # Remember the first unviable block, so we can log it
            unviableBlock = some((blk[].root, blk[].slot))

        of VerifierError.Invalid:
          hasInvalidBlock = true

          let req = item.request
          notice "Received invalid sequence of blocks", request = req,
                 blocks_count = len(item.data)
          req.item.updateScore(PeerScoreBadValues)
          break

    # When errors happen while processing blocks, we retry the same request
    # with, hopefully, a different peer
    let retryRequest =
      hasInvalidBlock or unviableBlock.isSome() or missingParentSlot.isSome()
    if not(retryRequest):
      let numSlotsAdvanced = item.request.count - cas.numAlreadyKnownSlots(sr)
      cas.advanceOutput(numSlotsAdvanced)

      if goodBlock.isSome():
        # If there no error and response was not empty we should reward peer
        # with some bonus score - not for duplicate blocks though.
        item.request.item.updateScore(PeerScoreGoodValues)
        item.request.item.updateScore(SyncResponseKind.Good, 1'u64)

        # BlockProcessor reports good block, so we can reward all the peers
        # who sent us empty response.
        cas.rewardForGaps(PeerScoreGoodValues)
        cas.gapList.reset()
      else:
        # Response was empty
        item.request.item.updateStats(SyncResponseKind.Empty, 1'u64)

      cas.processGap(item)

      if numSlotsAdvanced > 0:
        cas.wakeupWaiters()

    else:
      debug "Block pool rejected peer's response", request = item.request,
            blocks_count = len(item.data),
            ok = goodBlock.isSome(),
            unviable = unviableBlock.isSome(),
            missing_parent = missingParentSlot.isSome()

      # We need to move failed response to the debts queue.
      cas.toDebtsQueue(item.request)

      if unviableBlock.isSome():
        let req = item.request
        notice "Received blocks from an unviable fork", request = req,
               blockRoot = unviableBlock.get()[0],
               blockSlot = unviableBlock.get()[1],
               blocks_count = len(item.data)
        req.item.updateScore(PeerScoreUnviableFork)

      if missingParentSlot.isSome():
        var
          resetSlot: Option[Slot]
          failSlot = missingParentSlot.get()

        # If we get `VerfierError.MissingParent` it means that peer returns
        # chain of blocks with holes or `block_pool` is in incomplete state. We
        # going to rewind the ColumnSyncerAssist some distance back, but no more
        # than `finalized_epoch`.

        let
          req = item.request
          safeSlot = cas.getSafeSlot()
          gapsCount = len(cas.gapList)

        # We should penalize all the peers which responded with gaps.
        cas.rewardForGaps(PeerScoreMissingValues)
        cas.gapList.reset()

        case cas.direction
        of ColumnSyncerDirection.Forward:
          if goodBlock.isSome():
            # `VerifierError.MissingParent` and `Success` present in response,
            # it means that we to request this range one more time.
            debug "Unexpected missing parent, but no rewind needed",
                  request = req, finalized_slot = safeSlot,
                  last_good_slot = goodBlock.get(),
                  missing_parent_slot = missingParentSlot.get(),
                  blocks_count = len(item.data)
            req.item.updateScore(PeerScoreUnviableFork)
          else:
            if safeSlot < req.slot:
              let rewindSlot = cas.getRewindPoint(failSlot, safeSlot)
              debug "Unexpected missing parent, rewind needed",
                    request = req, rewind_to_slot = rewindSlot,
                    rewind_point = cas.rewind, finalized_slot = safeSlot,
                    blocks_count = len(item.data),
                    gaps_count = gapsCount
              resetSlot = some(rewindSlot)
            else:
              error "Unexpected missing parent at finalized epoch slot",
                    request = req, rewind_to_slot = safeSlot,
                    blocks_count = len(item.data),
                    gaps_count = gapsCount
              req.item.updateScore(PeerScoreBadValues)
        of ColumnSyncerDirection.Backward:
          if safeSlot > failSlot:
            let rewindSlot = cas.getRewindPoint(failSlot, safeSlot)
            # It's quite common peers us fewer blocks than we ask for
            debug "Gap in block range response, rewinding", request = req,
                 rewind_to_slot = rewindSlot, rewind_fail_slot = failSlot,
                 finalized_slot = safeSlot, blocks_count = len(item.data)
            resetSlot = some(rewindSlot)
            req.item.updateScore(PeerScoreMissingValues)
          else:
            error "Unexpected missing parent at safe slot", request = req,
                  to_slot= safeSlot, blocks_count = len(item.data)
            req.item.updateScore(PeerScoreBadValues)

        if resetSlot.isSome():
          await cas.resetWait(resetSlot)
          case cas.direction
          of ColumnSyncerDirection.Forward:
            debug "Rewind to slot has happened", reset_slot = resetSlot.get(),
                  queue_input_slot = cas.inpSlot, queue_output_slot = cas.outSlot,
                  rewind_point = cas.rewind, direction = cas.direction
          of ColumnSyncerDirection.Backward:
            debug "Rewind to slot has happened", reset_slot = resetSlot.get(),
                  queue_input_slot = cas.inpSlot, queue_output_slot = cas.outSlot,
                  direction = cas.direction
      break

proc push*[T](cas: ColumnSyncerAssist[T], sr: ColumnSyncRequest[T]) =
  ## Push failed request back to queue
  if sr.index notin cas.pending:
    # If request `sr` not in our pending list, it only a newer `safeSlot`, either
    # ColumnSyncerAssist.resetWait() happens and all pending requests are expired,
    # so we swallow `old` requests, and in such way sync workers are able to get
    # proper new requests from ColumnSyncerAssist
    return
  cas.pending.del(sr.index)
  cas.toDebtsQueue(sr)

proc handlePotentialSafeSlotAdvancement[T](cas: ColumnSyncerAssist[T]) =
  # It may happen that sync progress advanced to a newer `safeSlot`, either
  # by a response that started with good values and only had errors late,
  # or through an out-of-bound mechanism, e.g., VC/REST.
  # If that happens, advance to the new `safeSlot` to avoid repeating requests
  # for data is considered immutable and no longer relevant.

  let safeSlot = cas.getSafeSlot()
  func numSlotsBehindSafeSlot(slot: Slot): uint64 =
    case cas.direction
    of ColumnSyncerDirection.Forward:
      if safeSlot > slot:
        safeSlot - slot
      else:
        0
    of ColumnSyncerDirection.Backward:
      if slot > safeSlot:
        slot - safeSlot
      else:
        0

  let
    numOutSlotsAdvanced = cas.outSlot.numSlotsBehindSafeSlot
    numInpSlotsAdvanced =
      case cas.direction
      of ColumnSyncerDirection.Forward:
        cas.inpSlot.numSlotsBehindSafeSlot
      of ColumnSyncerDirection.Backward:
        if cas.inpSlot == 0xFFFF_FFFF_FFFF_FFFF'u64:
          0'u64
        else:
          cas.inpSlot.numSlotBehindSafeSlot

  if numOutSlotsAdvanced != 0 or numInpSlotsAdvanced != 0:
    debug "Sync progress advanced out-of-bound",
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
    highSlot = sr.lastSlot
  case cas.direction
  of ColumnSyncerDirection.Forward:
    if outSlot <= lowSlot:
      # Entire request is still relevant
      discard
    elif outSlot <= highSlot:
      # Request is only partially relevant.
      let
        numSlotsDone = outSlot - lowSlot
      sr.slot += numSlotsDone
      sr.count -= numSlotsDone
    else:
      # Entire request is no longer relevant
      sr.count = 0
  of ColumnSyncerDirection.Backward:
    if outSlot >= highSlot:
      # Entire request is still relevant
      discard
    elif outSlot >= lowSlot:
      # Request is only partially relevant
      let
        numSlotsDone = highSlot - outSlot
      sr.count -= numSlotsDone
    else:
      # Entire request is no longer relevant.
      sr.count = 0

proc pop*[T](cas: ColumnSyncerAssist[T], maxSlot: Slot, item: T): ColumnSyncRequest[T] =
  ## Create new request according to current `ColumnSyncerAssist` parameters
  cas.handlePotentialSafeSlotAdvancement()
  while len(cas.debtsQueue) > 0:
    if maxSlot < cas.debtsQueue[0].slot:
      # Peer's latest slot is less than starting request's slot
      return ColumnSyncRequest.empty(cas.direction, T)
    if maxSlot < cas.debtsQueue[0].slot:
      # Peer's latest slot is less than finishing request's slot
      return ColumnSyncRequest.empty(cas.direction, T)
    var sr = cas.debtsQueue.pop()
    cas.debtsCount = cas.debtsCount - sr.count
    cas.updateRequestForNewSafeSlot(sr)
    if sr.isEmpty:
      continue
    sr.setItem(item)
    cas.makePending(sr)
    return sr

  case cas.direction
  of ColumnSyncerDirection.Forward:
    if maxSlot < cas.inpSlot:
      # Peer's latest slot is less than queue's input slot
      return ColumnSyncRequest.empty(cas.direction, T)
    if cas.inpSlot > cas.finalSlot:
      # Queue's input slot is bigger than queue's final slot
      return ColumnSyncRequest.empty(cas.direction, T)
    let lastSlot = min(maxSlot, cas.finalSlot)
    let count = min(cas.chunkSize, lastSlot + 1'u64 - cas.inpSlot)
    var sr = ColumnSyncRequest.init(cas.direction, cas.inpSlot, count, item)
    cas.advanceInput(count)
    cas.makePending(sr)
    sr

  of ColumnSyncerDirection.Backward:
    if cas.inpSlot == 0xFFFF_FFFF_FFFF_FFFF'u64:
      return ColumnSyncRequest.empty(cas.direction, T)
    if cas.inpSlot < cas.finalSlot:
      return ColumnSyncRequest.empty(cas.direction, T)
    let (slot, count) =
      block:
        let baseSlot = cas.inpSlot + 1'u64
        if baseSlot - cas.finalSlot < cas.chunkSize:
          let count = uint64(baseSlot - cas.finalSlot)
          (baseSlot - count, count)
        else:
          (baseSlot - cas.chunkSize, cas.chunkSize)
    if (maxSlot + 1'u64) < slot + count:
      # Peer's latest slot is less than queue's input slot.
      return ColumnSyncRequest.empty(cas.direction, T)
    var sr = ColumnSyncRequest.init(cas.direction, slot, count, item)
    cas.advanceInput(count)
    cas.makePending(sr)
    sr

proc debtLen*[T](cas: ColumnSyncerAssist[T]): uint64 =
  cas.debtsCount

proc pendingLen*[T](cas: ColumnSyncerAssist[T]): uint64 {.inline.} =
  ## Returns total number of slots in queue
  case cas.direction
  of ColumnSyncerDirection.Forward:
    # When moving forward `outSlot` will be <= of `inpSlot`
    cas.inpSlot - cas.outSlot
  of ColumnSyncerDirection.Backward:
    # When moving backward `outSlot` will be >= of `outSlot`
    cas.outSlot - cas.inpSlot

proc len*[T](cas: ColumnSyncerAssist[T]): uint64 {.inline.} =
  ## Returns number of slots left in queue
  case cas.direction
  of ColumnSyncerDirection.Forward:
    if cas.finalSlot >= cas.outSlot:
      cas.finalSlot + 1'u64 - cas.outSlot
    else:
      0'u64
  of ColumnSyncerDirection.Backward:
    if cas.outSlot >= cas.finalSlot:
      cas.outSlot + 1'u64 - cas.finalSlot
    else:
      0'u64

proc total*[T](cas: ColumnSyncerAssist[T]): uint64 {.inline.} =
  ## Returns total number of slots in queue
  case cas.direction
  of ColumnSyncerDirection.Forward:
    if cas.finalSlot >= cas.startSlot:
      cas.finalSlot + 1'u64 - cas.startSlot
    else:
      0'u64
  of ColumnSyncerDirection.Backward:
    if cas.startSlot >= cas.finalSlot:
      cas.startSlot + 1'u64 - cas.finalSlot
    else:
      0'u64

proc progress*[T](cas: ColumnSyncerAssist[T]): uint64 =
  ## How many useful slots we've synced so far, adjusting for how much has
  ## become obsolete by time movements
  cas.total - cas.len
















