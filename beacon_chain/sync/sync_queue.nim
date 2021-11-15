# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import std/[options, heapqueue, tables, strutils, sequtils, math, algorithm]
import stew/results, chronos, chronicles
import
  ../spec/datatypes/[base, phase0, altair, merge],
  ../spec/eth2_apis/rpc_types,
  ../spec/[helpers, forks],
  ../networking/[peer_pool, eth2_network],
  ../gossip_processing/block_processor,
  ../consensus_object_pools/block_pools_types,
  ./peer_scores

export base, phase0, altair, merge, chronos, chronicles, results,
       block_pools_types, helpers, peer_scores

logScope:
  topics = "syncqueue"

type
  GetSlotCallback* = proc(): Slot {.gcsafe, raises: [Defect].}

  SyncQueueKind* {.pure.} = enum
    Forward, Backward

  SyncRequest*[T] = object
    kind: SyncQueueKind
    index*: uint64
    slot*: Slot
    count*: uint64
    step*: uint64
    item*: T

  SyncResult*[T] = object
    request*: SyncRequest[T]
    data*: seq[ForkedSignedBeaconBlock]

  SyncWaiter*[T] = object
    future: Future[bool]
    request: SyncRequest[T]

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
    opcounter*: uint64
    pending*: Table[uint64, SyncRequest[T]]
    waiters: seq[SyncWaiter[T]]
    getFinalizedSlot*: GetSlotCallback
    debtsQueue: HeapQueue[SyncRequest[T]]
    debtsCount: uint64
    readyQueue: HeapQueue[SyncResult[T]]
    rewind: Option[RewindPoint]
    blockProcessor: ref BlockProcessor

  SyncManagerError* = object of CatchableError
  BeaconBlocksRes* = NetRes[seq[ForkedSignedBeaconBlock]]

proc validate*[T](sq: SyncQueue[T],
                  blk: ForkedSignedBeaconBlock
                 ): Future[Result[void, BlockError]] =
  let resfut = newFuture[Result[void, BlockError]]("sync.manager.validate")
  sq.blockProcessor[].addBlock(blk, resfut)
  resfut

proc getShortMap*[T](req: SyncRequest[T],
                     data: openArray[ForkedSignedBeaconBlock]): string =
  ## Returns all slot numbers in ``data`` as placement map.
  var res = newStringOfCap(req.count)
  var slider = req.slot
  var last = 0
  for i in 0 ..< req.count:
    if last < len(data):
      for k in last ..< len(data):
        if slider == data[k].slot:
          res.add('x')
          last = k + 1
          break
        elif slider < data[k].slot:
          res.add('.')
          break
    else:
      res.add('.')
    slider = slider + req.step
  res

proc contains*[T](req: SyncRequest[T], slot: Slot): bool {.inline.} =
  slot >= req.slot and slot < req.slot + req.count * req.step and
    ((slot - req.slot) mod req.step == 0)

proc cmp*[T](a, b: SyncRequest[T]): int =
  cmp(uint64(a.slot), uint64(b.slot))

proc checkResponse*[T](req: SyncRequest[T],
                       data: openArray[ForkedSignedBeaconBlock]): bool =
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
    if slot < data[dindex].slot:
      discard
    elif slot == data[dindex].slot:
      inc(dindex)
    else:
      return false
    slot = slot + req.step
    rindex = rindex + 1'u64

  if dindex == len(data):
    return true
  else:
    return false

proc getFullMap*[T](req: SyncRequest[T],
                    data: openArray[ForkedSignedBeaconBlock]): string =
  # Returns all slot numbers in ``data`` as comma-delimeted string.
  mapIt(data, $it.message.slot).join(", ")

# proc init[T](t1: typedesc[SyncRequest], t2: typedesc[T], slot: Slot,
#               count: uint64): SyncRequest[T] =
#   SyncRequest[T](slot: slot, count: count, step: 1'u64)

proc init[T](t1: typedesc[SyncRequest], kind: SyncQueueKind, start: Slot,
             finish: Slot, t2: typedesc[T]): SyncRequest[T] =
  let count = finish - start + 1'u64
  SyncRequest[T](kind: kind, slot: start, count: count, step: 1'u64)

proc init[T](t1: typedesc[SyncRequest], kind: SyncQueueKind, slot: Slot,
             count: uint64, item: T): SyncRequest[T] =
  SyncRequest[T](slot: slot, count: count, item: item, step: 1'u64)

proc init[T](t1: typedesc[SyncRequest], kind: SyncQueueKind, start: Slot,
             finish: Slot, item: T): SyncRequest[T] =
  let count = finish - start + 1'u64
  SyncRequest[T](kind: kind, slot: start, count: count, step: 1'u64, item: item)

proc empty*[T](t: typedesc[SyncRequest], kind: SyncQueueKind,
               t2: typedesc[T]): SyncRequest[T] {.inline.} =
  SyncRequest[T](kind: kind, step: 0'u64, count: 0'u64)

proc setItem*[T](sr: var SyncRequest[T], item: T) =
  sr.item = item

proc isEmpty*[T](sr: SyncRequest[T]): bool {.inline.} =
  (sr.step == 0'u64) and (sr.count == 0'u64)

proc init*[T](t1: typedesc[SyncQueue], t2: typedesc[T],
              queueKind: SyncQueueKind,
              start, final: Slot, chunkSize: uint64,
              getFinalizedSlotCb: GetSlotCallback,
              blockProcessor: ref BlockProcessor,
              syncQueueSize: int = -1): SyncQueue[T] =
  ## Create new synchronization queue with parameters
  ##
  ## ``start`` and ``last`` are starting and finishing Slots.
  ##
  ## ``chunkSize`` maximum number of slots in one request.
  ##
  ## ``syncQueueSize`` maximum queue size for incoming data. If ``syncQueueSize > 0``
  ## queue will help to keep backpressure under control. If ``syncQueueSize <= 0``
  ## then queue size is unlimited (default).
  ##
  ## ``updateCb`` procedure which will be used to send downloaded blocks to
  ## consumer. Procedure should return ``false`` only when it receives
  ## incorrect blocks, and ``true`` if sequence of blocks is correct.

  # SyncQueue is the core of sync manager, this data structure distributes
  # requests to peers and manages responses from peers.
  #
  # Because SyncQueue is async data structure it manages backpressure and
  # order of incoming responses and it also resolves "joker's" problem.
  #
  # Joker's problem
  #
  # According to current Ethereum2 network specification
  # > Clients MUST respond with at least one block, if they have it and it
  # > exists in the range. Clients MAY limit the number of blocks in the
  # > response.
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
  # If peer answers with `1` everything will be fine and `block_pool` will be
  # able to process all 3 blocks. In case of `2`, `3`, `4`, `6` - `block_pool`
  # will fail immediately with chunk and report "parent is missing" error.
  # But in case of `5` and `7` blocks will be processed by `block_pool` without
  # any problems, however it will start producing problems right from this
  # uncertain last slot. SyncQueue will start producing requests for next
  # blocks, but all the responses from this point will fail with "parent is
  # missing" error. Lets call such peers "jokers", because they are joking
  # with responses.
  #
  # To fix "joker" problem we going to perform rollback to the latest finalized
  # epoch's first slot.
  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  result = SyncQueue[T](
    startSlot: start,
    finalSlot: final,
    chunkSize: chunkSize,
    queueSize: syncQueueSize,
    getFinalizedSlot: getFinalizedSlotCb,
    waiters: newSeq[SyncWaiter[T]](),
    counter: 1'u64,
    pending: initTable[uint64, SyncRequest[T]](),
    debtsQueue: initHeapQueue[SyncRequest[T]](),
    inpSlot: start,
    outSlot: start,
    blockProcessor: blockProcessor
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
  (a.kind == b.kind) and (a.slot == b.slot) and (a.count == b.count) and
    (a.step == b.step)

proc lastSlot*[T](req: SyncRequest[T]): Slot =
  ## Returns last slot for request ``req``.
  req.slot + req.count - 1'u64

proc makePending*[T](sq: SyncQueue[T], req: var SyncRequest[T]) =
  req.index = sq.counter
  sq.counter = sq.counter + 1'u64
  sq.pending[req.index] = req

proc updateLastSlot*[T](sq: SyncQueue[T], last: Slot) {.inline.} =
  ## Update last slot stored in queue ``sq`` with value ``last``.
  case sq.kind
  of SyncQueueKind.Forward:
    doAssert(sq.finalSlot <= last,
             "Last slot could not be lower then stored one " &
             $sq.finalSlot & " <= " & $last)
    sq.finalSlot = last
  of SyncQueueKind.Backward:
    doAssert(sq.finalSlot >= last,
             "Last slot could not be higher then stored one " &
             $sq.finalSlot & " >= " & $last)
    sq.finalSlot = last

proc wakeupWaiters[T](sq: SyncQueue[T], flag = true) =
  ## Wakeup one or all blocked waiters.
  for item in sq.waiters:
    if not(item.future.finished()):
      item.future.complete(flag)

proc waitForChanges[T](sq: SyncQueue[T],
                       req: SyncRequest[T]): Future[bool] {.async.} =
  ## Create new waiter and wait for completion from `wakeupWaiters()`.
  var waitfut = newFuture[bool]("SyncQueue.waitForChanges")
  let waititem = SyncWaiter[T](future: waitfut, request: req)
  sq.waiters.add(waititem)
  try:
    result = await waitfut
  finally:
    sq.waiters.delete(sq.waiters.find(waititem))

proc wakeupAndWaitWaiters[T](sq: SyncQueue[T]) {.async.} =
  ## This procedure will perform wakeupWaiters(false) and blocks until last
  ## waiter will be awakened.
  var waitChanges = sq.waitForChanges(SyncRequest.empty(sq.kind, T))
  sq.wakeupWaiters(false)
  discard await waitChanges

proc resetWait*[T](sq: SyncQueue[T], toSlot: Option[Slot]) {.async.} =
  ## Perform reset of all the blocked waiters in SyncQueue.
  ##
  ## We adding one more waiter to the waiters sequence and
  ## call wakeupWaiters(false). Because our waiter is last in sequence of
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
  var minSlot = sq.outSlot
  if toSlot.isSome():
    minSlot = min(toSlot.get(), sq.outSlot)
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
  if sr.data[^1].slot != lastslot:
    return true
  return false

proc getLastNonEmptySlot*[T](sr: SyncResult[T]): Slot {.inline.} =
  ## Returns last non-empty slot from result ``sr``. If response has only
  ## empty slots, original request slot will be returned.
  if len(sr.data) == 0:
    # If response has only empty slots we going to use original request slot
    sr.request.slot
  else:
    sr.data[^1].slot

proc toDebtsQueue[T](sq: SyncQueue[T], sr: SyncRequest[T]) =
  sq.debtsQueue.push(sr)
  sq.debtsCount = sq.debtsCount + sr.count

proc getRewindPoint*[T](sq: SyncQueue[T], failSlot: Slot,
                        finalizedSlot: Slot): Slot =
  # Calculate the latest finalized epoch.
  let finalizedEpoch = compute_epoch_at_slot(finalizedSlot)

  # Calculate failure epoch.
  let failEpoch = compute_epoch_at_slot(failSlot)

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
               finalized_slot = finalizedSlot, fail_slot = failSlot,
               finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
               rewind_epoch_count = rewind.epochCount,
               finalized_epoch = finalizedEpoch
          0'u64
      else:
        # `MissingParent` happened at different slot so we going to rewind for
        # 1 epoch only.
        if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
          warn "Сould not rewind further than the last finalized epoch",
               finalized_slot = finalizedSlot, fail_slot = failSlot,
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
             finalized_slot = finalizedSlot, fail_slot = failSlot,
             finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
             finalized_epoch = finalizedEpoch
        0'u64
      else:
        1'u64

  if epochCount == 0'u64:
    warn "Unable to continue syncing, please restart the node",
         finalized_slot = finalizedSlot, fail_slot = failSlot,
         finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
         finalized_epoch = finalizedEpoch
    # Calculate the rewind epoch, which will be equal to last rewind point or
    # finalizedEpoch
    let rewindEpoch =
      if sq.rewind.isNone():
        finalizedEpoch
      else:
        compute_epoch_at_slot(sq.rewind.get().failSlot) -
          sq.rewind.get().epochCount
    compute_start_slot_at_epoch(rewindEpoch)
  else:
    # Calculate the rewind epoch, which should not be less than the latest
    # finalized epoch.
    let rewindEpoch = failEpoch - epochCount
    # Update and save new rewind point in SyncQueue.
    sq.rewind = some(RewindPoint(failSlot: failSlot, epochCount: epochCount))
    compute_start_slot_at_epoch(rewindEpoch)

proc push*[T](sq: SyncQueue[T], sr: SyncRequest[T],
              data: seq[ForkedSignedBeaconBlock]) {.async, gcsafe.} =
  ## Push successful result to queue ``sq``.
  mixin updateScore

  if sr.index notin sq.pending:
    # If request `sr` not in our pending list, it only means that
    # SyncQueue.resetWait() happens and all pending requests are expired, so
    # we swallow `old` requests, and in such way sync-workers are able to get
    # proper new requests from SyncQueue.
    return

  sq.pending.del(sr.index)

  # This is backpressure handling algorithm, this algorithm is blocking
  # all pending `push` requests if `request.slot` not in range:
  # [current_queue_slot, current_queue_slot + sq.queueSize * sq.chunkSize].
  var exitNow = false
  while true:
    if (sq.queueSize > 0) and
       (sr.slot >= sq.outSlot + uint64(sq.queueSize) * sq.chunkSize):
      let res = await sq.waitForChanges(sr)
      if res:
        continue
      else:
        # SyncQueue reset happens. We are exiting to wake up sync-worker.
        exitNow = true
        break
    let syncres = SyncResult[T](request: sr, data: data)
    sq.readyQueue.push(syncres)
    exitNow = false
    break

  if exitNow:
    return

  while len(sq.readyQueue) > 0:
    let minSlot = sq.readyQueue[0].request.slot
    if sq.outSlot != minSlot:
      break
    let item = sq.readyQueue.pop()

    # Validating received blocks one by one
    var res: Result[void, BlockError]
    var failSlot: Option[Slot]
    if len(item.data) > 0:
      for blk in item.data:
        trace "Pushing block", block_root = blk.root,
                               block_slot = blk.slot
        res = await sq.validate(blk)
        if not(res.isOk):
          failSlot = some(blk.slot)
          break
    else:
      res = Result[void, BlockError].ok()

    # Increase progress counter, so watch task will be able to know that we are
    # not stuck.
    inc(sq.opcounter)

    if res.isOk:
      sq.outSlot = sq.outSlot + item.request.count
      if len(item.data) > 0:
        # If there no error and response was not empty we should reward peer
        # with some bonus score.
        item.request.item.updateScore(PeerScoreGoodBlocks)
      sq.wakeupWaiters()
    else:
      debug "Block pool rejected peer's response", peer = item.request.item,
            request_slot = item.request.slot,
            request_count = item.request.count,
            request_step = item.request.step,
            blocks_map = getShortMap(item.request, item.data),
            blocks_count = len(item.data), errCode = res.error,
            topics = "syncman"

      var resetSlot: Option[Slot]

      if res.error == BlockError.MissingParent:
        # If we got `BlockError.MissingParent` it means that peer returns chain
        # of blocks with holes or `block_pool` is in incomplete state. We going
        # to rewind to the first slot at latest finalized epoch.
        let req = item.request
        let finalizedSlot = sq.getFinalizedSlot()
        if finalizedSlot < req.slot:
          let rewindSlot = sq.getRewindPoint(failSlot.get(), finalizedSlot)
          warn "Unexpected missing parent, rewind happens",
               peer = req.item, rewind_to_slot = rewindSlot,
               rewind_epoch_count = sq.rewind.get().epochCount,
               rewind_fail_slot = failSlot.get(),
               finalized_slot = finalized_slot,
               request_slot = req.slot, request_count = req.count,
               request_step = req.step, blocks_count = len(item.data),
               blocks_map = getShortMap(req, item.data), topics = "syncman"
          resetSlot = some(rewindSlot)
          req.item.updateScore(PeerScoreMissingBlocks)
        else:
          error "Unexpected missing parent at finalized epoch slot",
                peer = req.item, to_slot = finalizedSlot,
                request_slot = req.slot, request_count = req.count,
                request_step = req.step, blocks_count = len(item.data),
                blocks_map = getShortMap(req, item.data), topics = "syncman"
          req.item.updateScore(PeerScoreBadBlocks)
      elif res.error == BlockError.Invalid:
        let req = item.request
        warn "Received invalid sequence of blocks", peer = req.item,
              request_slot = req.slot, request_count = req.count,
              request_step = req.step, blocks_count = len(item.data),
              blocks_map = getShortMap(req, item.data), topics = "syncman"
        req.item.updateScore(PeerScoreBadBlocks)
      else:
        let req = item.request
        warn "Received unexpected response from block_pool", peer = req.item,
             request_slot = req.slot, request_count = req.count,
             request_step = req.step, blocks_count = len(item.data),
             blocks_map = getShortMap(req, item.data), errorCode = res.error,
             topics = "syncman"
        req.item.updateScore(PeerScoreBadBlocks)

      # We need to move failed response to the debts queue.
      sq.toDebtsQueue(item.request)
      if resetSlot.isSome():
        await sq.resetWait(resetSlot)
        debug "Rewind to slot was happened", reset_slot = reset_slot.get(),
              queue_input_slot = sq.inpSlot, queue_output_slot = sq.outSlot,
              rewind_epoch_count = sq.rewind.get().epochCount,
              rewind_fail_slot = sq.rewind.get().failSlot,
              reset_slot = resetSlot, topics = "syncman"
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

proc pop*[T](sq: SyncQueue[T], maxslot: Slot, item: T): SyncRequest[T] =
  if len(sq.debtsQueue) > 0:
    if maxSlot < sq.debtsQueue[0].slot:
      return SyncRequest.empty(sq.kind, T)

    var sr = sq.debtsQueue.pop()
    if sr.lastSlot() <= maxSlot:
      sq.debtsCount = sq.debtsCount - sr.count
      sr.setItem(item)
      sq.makePending(sr)
      return sr

    var sr1 = SyncRequest.init(sq.kind, sr.slot, maxslot, item)
    let sr2 = SyncRequest.init(sq.kind, maxslot + 1'u64, sr.lastSlot(), T)
    sq.debtsQueue.push(sr2)
    sq.debtsCount = sq.debtsCount - sr1.count
    sq.makePending(sr1)
    return sr1
  else:
    if maxSlot < sq.inpSlot:
      return SyncRequest.empty(sq.kind, T)

    if sq.inpSlot > sq.finalSlot:
      return SyncRequest.empty(sq.kind, T)

    let lastSlot = min(maxslot, sq.finalSlot)
    let count = min(sq.chunkSize, lastSlot + 1'u64 - sq.inpSlot)
    var sr = SyncRequest.init(sq.kind, sq.inpSlot, count, item)
    sq.inpSlot = sq.inpSlot + count
    sq.makePending(sr)
    return sr

proc len*[T](sq: SyncQueue[T]): uint64 {.inline.} =
  ## Returns number of slots left in queue ``sq``.
  if sq.inpSlot > sq.lastSlot:
    result = sq.debtsCount
  else:
    result = sq.lastSlot - sq.inpSlot + 1'u64 - sq.debtsCount

proc total*[T](sq: SyncQueue[T]): uint64 {.inline.} =
  ## Returns total number of slots in queue ``sq``.
  sq.lastSlot - sq.startSlot + 1'u64

proc progress*[T](sq: SyncQueue[T]): uint64 =
  ## Returns queue's ``sq`` progress string.
  let curSlot = sq.outSlot - sq.startSlot
  (curSlot * 100'u64) div sq.total()
