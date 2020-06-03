import chronicles
import options, deques, heapqueue, tables, strutils, sequtils, math, algorithm
import stew/results, chronos, chronicles
import spec/datatypes, spec/digest, peer_pool, eth2_network
import eth/async_utils

import block_pools/block_pools_types
export datatypes, digest, chronos, chronicles, results, block_pools_types

logScope:
  topics = "syncman"

const
  PeerScoreNoStatus* = -100
    ## Peer did not answer `status` request.
  PeerScoreStaleStatus* = -50
    ## Peer's `status` answer do not progress in time.
  PeerScoreGoodStatus* = 50
    ## Peer's `status` answer is fine.
  PeerScoreNoBlocks* = -100
    ## Peer did not respond in time on `blocksByRange` request.
  PeerScoreGoodBlocks* = 100
    ## Peer's `blocksByRange` answer is fine.
  PeerScoreBadBlocks* = -1000
    ## Peer's response contains incorrect blocks.
  PeerScoreBadResponse* = -1000
    ## Peer's response is not in requested range.
  PeerScoreJokeBlocks* = -200
    ## Peer response contains too many empty blocks.

type
  SyncFailureKind* = enum
    StatusInvalid,
    StatusDownload,
    StatusStale,
    EmptyProblem,
    BlockDownload,
    BadResponse

  GetSlotCallback* = proc(): Slot {.gcsafe, raises: [Defect].}

  UpdateLocalBlocksCallback* =
    proc(list: openarray[SignedBeaconBlock]): Result[void, BlockError] {.
      gcsafe.}

  SyncUpdateCallback*[T] =
    proc(req: SyncRequest[T],
         list: openarray[SignedBeaconBlock]): Result[void, BlockError] {.
      gcsafe.}

  SyncRequest*[T] = object
    index*: uint64
    slot*: Slot
    count*: uint64
    step*: uint64
    item*: T

  SyncResult*[T] = object
    request*: SyncRequest[T]
    data*: seq[SignedBeaconBlock]

  SyncWaiter*[T] = object
    future: Future[bool]
    request: SyncRequest[T]

  SyncQueue*[T] = ref object
    inpSlot*: Slot
    outSlot*: Slot

    startSlot*: Slot
    lastSlot: Slot
    chunkSize*: uint64
    queueSize*: int

    counter*: uint64
    pending*: Table[uint64, SyncRequest[T]]

    waiters: seq[SyncWaiter[T]]
    syncUpdate*: SyncUpdateCallback[T]

    debtsQueue: HeapQueue[SyncRequest[T]]
    debtsCount: uint64
    readyQueue: HeapQueue[SyncResult[T]]

    zeroPoint: Option[Slot]
    suspects: seq[SyncResult[T]]

  SyncManager*[A, B] = ref object
    pool: PeerPool[A, B]
    responseTimeout: chronos.Duration
    sleepTime: chronos.Duration
    maxStatusAge: uint64
    maxHeadAge: uint64
    maxRecurringFailures: int
    toleranceValue: uint64
    getLocalHeadSlot: GetSlotCallback
    getLocalWallSlot: GetSlotCallback
    syncUpdate: SyncUpdateCallback[A]
    chunkSize: uint64
    queue: SyncQueue[A]
    failures: seq[SyncFailure[A]]
    inProgress*: bool

  SyncMoment* = object
    stamp*: chronos.Moment
    slot*: Slot

  SyncFailure*[T] = object
    kind*: SyncFailureKind
    peer*: T
    stamp*: chronos.Moment

  SyncManagerError* = object of CatchableError
  BeaconBlocksRes* = NetRes[seq[SignedBeaconBlock]]

proc getShortMap*[T](req: SyncRequest[T],
                     data: openarray[SignedBeaconBlock]): string =
  ## Returns all slot numbers in ``data`` as placement map.
  var res = newStringOfCap(req.count)
  var slider = req.slot
  var last = 0
  for i in 0 ..< req.count:
    if last < len(data):
      for k in last ..< len(data):
        if slider == data[k].message.slot:
          res.add('x')
          last = k + 1
          break
        elif slider < data[k].message.slot:
          res.add('.')
          break
    else:
      res.add('.')
    slider = slider + req.step
  result = res

proc contains*[T](req: SyncRequest[T], slot: Slot): bool {.inline.} =
  slot >= req.slot and slot < req.slot + req.count * req.step and
    ((slot - req.slot) mod req.step == 0)

proc cmp*[T](a, b: SyncRequest[T]): int =
  result = cmp(uint64(a.slot), uint64(b.slot))

proc checkResponse*[T](req: SyncRequest[T],
                       data: openarray[SignedBeaconBlock]): bool =
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
    if slot < data[dindex].message.slot:
      discard
    elif slot == data[dindex].message.slot:
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
                    data: openarray[SignedBeaconBlock]): string =
  # Returns all slot numbers in ``data`` as comma-delimeted string.
  result = mapIt(data, $it.message.slot).join(", ")

proc init*[T](t1: typedesc[SyncRequest], t2: typedesc[T], slot: Slot,
              count: uint64): SyncRequest[T] {.inline.} =
  result = SyncRequest[T](slot: slot, count: count, step: 1'u64)

proc init*[T](t1: typedesc[SyncRequest], t2: typedesc[T], start: Slot,
              finish: Slot): SyncRequest[T] {.inline.} =
  let count = finish - start + 1'u64
  result = SyncRequest[T](slot: start, count: count, step: 1'u64)

proc init*[T](t1: typedesc[SyncRequest], t2: typedesc[T], slot: Slot,
              count: uint64, item: T): SyncRequest[T] {.inline.} =
  result = SyncRequest[T](slot: slot, count: count, item: item, step: 1'u64)

proc init*[T](t1: typedesc[SyncRequest], t2: typedesc[T], start: Slot,
              finish: Slot, item: T): SyncRequest[T] {.inline.} =
  let count = finish - start + 1'u64
  result = SyncRequest[T](slot: start, count: count, step: 1'u64, item: item)

proc init*[T](t1: typedesc[SyncFailure], kind: SyncFailureKind,
              peer: T): SyncFailure[T] {.inline.} =
  result = SyncFailure[T](kind: kind, peer: peer, stamp: now(chronos.Moment))

proc empty*[T](t: typedesc[SyncRequest],
               t2: typedesc[T]): SyncRequest[T] {.inline.} =
  result = SyncRequest[T](step: 0'u64, count: 0'u64)

proc setItem*[T](sr: var SyncRequest[T], item: T) =
  sr.item = item

proc isEmpty*[T](sr: SyncRequest[T]): bool {.inline.} =
  result = (sr.step == 0'u64) and (sr.count == 0'u64)

proc init*[T](t1: typedesc[SyncQueue], t2: typedesc[T],
              start, last: Slot, chunkSize: uint64,
              updateCb: SyncUpdateCallback[T],
              queueSize: int = -1): SyncQueue[T] =
  ## Create new synchronization queue with parameters
  ##
  ## ``start`` and ``last`` are starting and finishing Slots.
  ##
  ## ``chunkSize`` maximum number of slots in one request.
  ##
  ## ``queueSize`` maximum queue size for incoming data. If ``queueSize > 0``
  ## queue will help to keep backpressure under control. If ``queueSize <= 0``
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
  # To fix "joker" problem i'm going to introduce "zero-point" which will
  # represent first non-empty slot in gap at the end of requested chunk.
  # If SyncQueue receives chunk of blocks with gap at the end and this chunk
  # will be successfully processed by `block_pool` it will set `zero_point` to
  # the first uncertain (empty) slot. For example:
  #
  # Case 1
  #   X  X  X  X  X  -
  #   3  4  5  6  7  8
  #
  # Case2
  #   X  X  -  -  -  -
  #   3  4  5  6  7  8
  #
  # In Case 1 `zero-point` will be equal to 8, in Case 2 `zero-point` will be
  # set to 5.
  #
  # When `zero-point` is set and the next received chunk of blocks will be
  # empty, then peer produced this chunk of blocks will be added to suspect
  # list.
  #
  # If the next chunk of blocks has at least one non-empty block and this chunk
  # will be successfully processed by `block_pool`, then `zero-point` will be
  # reset and suspect list will be cleared.
  #
  # If the `block_pool` failed to process next chunk of blocks, SyncQueue will
  # perform rollback to `zero-point` and penalize all the peers in suspect list.

  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  result = SyncQueue[T](
    startSlot: start,
    lastSlot: last,
    chunkSize: chunkSize,
    queueSize: queueSize,
    syncUpdate: updateCb,
    waiters: newSeq[SyncWaiter[T]](),
    counter: 1'u64,
    pending: initTable[uint64, SyncRequest[T]](),
    debtsQueue: initHeapQueue[SyncRequest[T]](),
    inpSlot: start,
    outSlot: start
  )

proc `<`*[T](a, b: SyncRequest[T]): bool {.inline.} =
  result = (a.slot < b.slot)

proc `<`*[T](a, b: SyncResult[T]): bool {.inline.} =
  result = (a.request.slot < b.request.slot)

proc `==`*[T](a, b: SyncRequest[T]): bool {.inline.} =
  result = ((a.slot == b.slot) and (a.count == b.count) and
            (a.step == b.step))

proc lastSlot*[T](req: SyncRequest[T]): Slot {.inline.} =
  ## Returns last slot for request ``req``.
  result = req.slot + req.count - 1'u64

proc makePending*[T](sq: SyncQueue[T], req: var SyncRequest[T]) =
  req.index = sq.counter
  sq.counter = sq.counter + 1'u64
  sq.pending[req.index] = req

proc updateLastSlot*[T](sq: SyncQueue[T], last: Slot) {.inline.} =
  ## Update last slot stored in queue ``sq`` with value ``last``.
  doAssert(sq.lastSlot <= last,
           "Last slot could not be lower then stored one " &
           $sq.lastSlot & " <= " & $last)
  sq.lastSlot = last

proc wakeupWaiters[T](sq: SyncQueue[T], flag = true) {.inline.} =
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
  var waitChanges = sq.waitForChanges(SyncRequest.empty(T))
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
  # 3. Requested slot `toSlot` (which can be `zero-point` slot).
  #
  # Queue's `outSlot` is the lowest slot we added to `block_pool`, but
  # `zero-point` slot can be less then `outSlot`. `debtsQueue` holds only not
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
  if sr.data[^1].message.slot != lastslot:
    return true
  return false

proc getLastNonEmptySlot*[T](sr: SyncResult[T]): Slot {.inline.} =
  ## Returns last non-empty slot from result ``sr``. If response has only
  ## empty slots, original request slot will be returned.
  if len(sr.data) == 0:
    # If response has only empty slots we going to use original request slot
    sr.request.slot
  else:
    sr.data[^1].message.slot

proc toDebtsQueue[T](sq: SyncQueue[T], sr: SyncRequest[T]) {.inline.} =
  sq.debtsQueue.push(sr)
  sq.debtsCount = sq.debtsCount + sr.count

proc push*[T](sq: SyncQueue[T], sr: SyncRequest[T],
              data: seq[SignedBeaconBlock]) {.async, gcsafe.} =
  ## Push successfull result to queue ``sq``.
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
        # SyncQueue reset happens (it can't be `zero-point` reset, or continous
        # failure reset). We are exiting to wake up sync-worker.
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
    let res = sq.syncUpdate(item.request, item.data)
    if res.isOk:
      if sq.zeroPoint.isSome():
        if item.isEmpty():
          # If the `zeropoint` is set and response is empty, we will add this
          # request to suspect list.
          debug "Adding peer to suspect list", peer = item.request.item,
                request_slot = item.request.slot,
                request_count = item.request.count,
                request_step = item.request.step,
                response_count = len(item.data), topics = "syncman"
          sq.suspects.add(item)
        else:
          # If the `zeropoint` is set and response is not empty, we will clean
          # suspect list and reset `zeropoint`.
          sq.suspects.setLen(0)
          sq.zeroPoint = none[Slot]()
          # At this point `zeropoint` is unset, but received response can have
          # gap at the end.
          if item.hasEndGap():
            debug "Zero-point reset and new zero-point found",
                  peer = item.request.item, request_slot = item.request.slot,
                  request_count = item.request.count,
                  request_step = item.request.step,
                  response_count = len(item.data),
                  blocks_map = getShortMap(item.request, item.data),
                  topics = "syncman"
            sq.suspects.add(item)
            sq.zeroPoint = some(item.getLastNonEmptySlot())
          else:
            debug "Zero-point reset", peer = item.request.item,
                  request_slot = item.request.slot,
                  request_count = item.request.count,
                  request_step = item.request.step,
                  response_count = len(item.data),
                  blocks_map = getShortMap(item.request, item.data),
                  topics = "syncman"
      else:
        # If the `zeropoint` is not set and response has gap at the end, we
        # will add first suspect to the suspect list and set `zeropoint`.
        if item.hasEndGap():
          debug "New zero-point found", peer = item.request.item,
                request_slot = item.request.slot,
                request_count = item.request.count,
                request_step = item.request.step,
                response_count = len(item.data),
                blocks_map = getShortMap(item.request, item.data),
                topics = "syncman"
          sq.suspects.add(item)
          sq.zeroPoint = some(item.getLastNonEmptySlot())

      sq.outSlot = sq.outSlot + item.request.count
      sq.wakeupWaiters()
    else:
      debug "Block pool rejected peer's response", peer = item.request.item,
            request_slot = item.request.slot,
            request_count = item.request.count,
            request_step = item.request.step,
            blocks_map = getShortMap(item.request, item.data),
            blocks_count = len(item.data), errCode = res.error

      var resetSlot: Option[Slot]

      if res.error == BlockError.MissingParent:
        if sq.zeroPoint.isSome():
          # If the `zeropoint` is set and we are unable to store response in
          # `block_pool` we are going to revert suspicious responses list.

          # If `zeropoint` is set, suspicious list should not be empty.
          var req: SyncRequest[T]
          if isEmpty(sq.suspects[0]):
            # If initial suspicious response is an empty list, then previous
            # chunk of blocks did not have a gap at the end. So we are going to
            # request suspicious response one more time without any changes.
            req = sq.suspects[0].request
          else:
            # If initial suspicious response is not an empty list, we are going
            # to request only gap at the end of the suspicious response.
            let startSlot = sq.suspects[0].getLastNonEmptySlot() + 1'u64
            let lastSlot = sq.suspects[0].request.lastSlot()
            req = SyncRequest.init(T, startSlot, lastSlot)

          debug "Resolve joker's problem", request_slot = req.slot,
                                           request_count = req.count,
                                           request_step = req.step,
                                         suspects_count = (len(sq.suspects) - 1)

          sq.suspects[0].request.item.updateScore(PeerScoreJokeBlocks)

          sq.toDebtsQueue(req)
          # We move all left suspicious responses to the debts queue.
          if len(sq.suspects) > 1:
            for i in 1 ..< len(sq.suspects):
              sq.toDebtsQueue(sq.suspects[i].request)
              sq.suspects[i].request.item.updateScore(PeerScoreJokeBlocks)

          # Reset state to the `zeropoint`.
          sq.suspects.setLen(0)
          resetSlot = sq.zeroPoint
          sq.zeroPoint = none[Slot]()
        else:
          # If we got `BlockError.MissingParent` and `zero-point` is not set
          # it means that peer returns chain of blocks with holes.
          let req = item.request
          warn "Received sequence of blocks with holes", peer = req.item,
               request_slot = req.slot, request_count = req.count,
               request_step = req.step, blocks_count = len(item.data),
               blocks_map = getShortMap(req, item.data)
          req.item.updateScore(PeerScoreBadBlocks)
      elif res.error == BlockError.Invalid:
        let req = item.request
        warn "Received invalid sequence of blocks", peer = req.item,
              request_slot = req.slot, request_count = req.count,
              request_step = req.step, blocks_count = len(item.data),
              blocks_map = getShortMap(req, item.data)
        req.item.updateScore(PeerScoreBadBlocks)
      else:
        let req = item.request
        warn "Received unexpected response from block_pool", peer = req.item,
             request_slot = req.slot, request_count = req.count,
             request_step = req.step, blocks_count = len(item.data),
             blocks_map = getShortMap(req, item.data), errorCode = res.error
        req.item.updateScore(PeerScoreBadBlocks)

      # We need to move failed response to the debts queue.
      sq.toDebtsQueue(item.request)
      if resetSlot.isSome():
        await sq.resetWait(resetSlot)
        debug "Zero-point reset happens", queue_input_slot = sq.inpSlot,
                                          queue_output_slot = sq.outSlot
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
      return SyncRequest.empty(T)

    var sr = sq.debtsQueue.pop()
    if sr.lastSlot() <= maxSlot:
      sq.debtsCount = sq.debtsCount - sr.count
      sr.setItem(item)
      sq.makePending(sr)
      return sr

    var sr1 = SyncRequest.init(T, sr.slot, maxslot, item)
    let sr2 = SyncRequest.init(T, maxslot + 1'u64, sr.lastSlot())
    sq.debtsQueue.push(sr2)
    sq.debtsCount = sq.debtsCount - sr1.count
    sq.makePending(sr1)
    return sr1
  else:
    if maxSlot < sq.inpSlot:
      return SyncRequest.empty(T)

    if sq.inpSlot > sq.lastSlot:
      return SyncRequest.empty(T)

    let lastSlot = min(maxslot, sq.lastSlot)
    let count = min(sq.chunkSize, lastSlot + 1'u64 - sq.inpSlot)
    var sr = SyncRequest.init(T, sq.inpSlot, count, item)
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
  result = sq.lastSlot - sq.startSlot + 1'u64

proc progress*[T](sq: SyncQueue[T]): uint64 =
  ## Returns queue's ``sq`` progress string.
  let curSlot = sq.outSlot - sq.startSlot
  result = (curSlot * 100'u64) div sq.total()

proc now*(sm: typedesc[SyncMoment], slot: Slot): SyncMoment {.inline.} =
  result = SyncMoment(stamp: now(chronos.Moment), slot: slot)

proc speed*(start, finish: SyncMoment): float {.inline.} =
  ## Returns number of slots per second.
  let slots = finish.slot - start.slot
  let dur = finish.stamp - start.stamp
  let secs = float(chronos.seconds(1).nanoseconds)
  if isZero(dur):
    result = 0.0
  else:
    let v = float(slots) * (secs / float(dur.nanoseconds))
    # We doing round manually because stdlib.round is deprecated
    result = round(v * 10000) / 10000

proc newSyncManager*[A, B](pool: PeerPool[A, B],
                           getLocalHeadSlotCb: GetSlotCallback,
                           getLocalWallSlotCb: GetSlotCallback,
                           updateLocalBlocksCb: UpdateLocalBlocksCallback,
                           maxStatusAge = uint64(SLOTS_PER_EPOCH * 4),
                           maxHeadAge = uint64(SLOTS_PER_EPOCH * 4),
                           sleepTime = (int(SLOTS_PER_EPOCH) *
                                        int(SECONDS_PER_SLOT)).seconds,
                           chunkSize = uint64(SLOTS_PER_EPOCH),
                           toleranceValue = uint64(1),
                           maxRecurringFailures = 3
                           ): SyncManager[A, B] =

  proc syncUpdate(req: SyncRequest[A],
      list: openarray[SignedBeaconBlock]): Result[void, BlockError] {.gcsafe.} =
    let peer = req.item
    let res = updateLocalBlocksCb(list)
    if res.isOk:
      peer.updateScore(PeerScoreGoodBlocks)
    return res

  let queue = SyncQueue.init(A, getLocalHeadSlotCb(), getLocalWallSlotCb(),
                             chunkSize, syncUpdate, 2)

  result = SyncManager[A, B](
    pool: pool,
    maxStatusAge: maxStatusAge,
    getLocalHeadSlot: getLocalHeadSlotCb,
    syncUpdate: syncUpdate,
    getLocalWallSlot: getLocalWallSlotCb,
    maxHeadAge: maxHeadAge,
    maxRecurringFailures: maxRecurringFailures,
    sleepTime: sleepTime,
    chunkSize: chunkSize,
    queue: queue
  )

proc getBlocks*[A, B](man: SyncManager[A, B], peer: A,
                      req: SyncRequest): Future[BeaconBlocksRes] {.async.} =
  mixin beaconBlocksByRange, getScore, `==`
  doAssert(not(req.isEmpty()), "Request must not be empty!")
  debug "Requesting blocks from peer", peer = peer,
        slot = req.slot, slot_count = req.count, step = req.step,
        peer_score = peer.getScore(), topics = "syncman"
  var workFut = awaitne beaconBlocksByRange(peer, req.slot, req.count, req.step)
  if workFut.failed():
    debug "Error, while waiting getBlocks response", peer = peer,
          slot = req.slot, slot_count = req.count, step = req.step,
          errMsg = workFut.readError().msg, topics = "syncman"
  else:
    let res = workFut.read()
    if res.isErr:
      debug "Error, while reading getBlocks response",
            peer = peer, slot = req.slot, count = req.count,
            step = req.step, topics = "syncman"
    result = res

template headAge(): uint64 =
  wallSlot - headSlot

template peerAge(): uint64 =
  if peerSlot > wallSlot: 0'u64 else: wallSlot - peerSlot

proc syncWorker*[A, B](man: SyncManager[A, B],
                       peer: A): Future[A] {.async.} =
  # Sync worker is the lowest level loop which performs syncing with single
  # peer.
  #
  # Logic here is pretty simple:
  # 1. Obtain request from SyncQueue.
  # 2. Send this request to a peer and obtain response.
  # 3. Push response to the SyncQueue, (doesn't matter if it success or failure)
  # 4. Update main SyncQueue last slot with wall time slot number.
  # 5. From time to time we also requesting peer's status information.
  # 6. If our current head slot is near equal to peer's head slot we are
  #    exiting this loop and finishing that sync-worker task.
  # 7. Repeat

  mixin getKey, getScore, getHeadSlot

  debug "Starting syncing with peer", peer = peer,
                                      peer_score = peer.getScore(),
                                      topics = "syncman"
  try:
    while true:
      var wallSlot = man.getLocalWallSlot()
      var headSlot = man.getLocalHeadSlot()
      var peerSlot = peer.getHeadSlot()

      man.queue.updateLastSlot(wallSlot)

      debug "Peer's syncing status", wall_clock_slot = wallSlot,
            remote_head_slot = peerSlot, local_head_slot = headSlot,
            peer_score = peer.getScore(), peer = peer, topics = "syncman"

      if peerSlot > wallSlot + man.toleranceValue:
        # Our wall timer is broken, or peer's status information is invalid.
        debug "Local timer is broken or peer's status information is invalid",
              wall_clock_slot = wallSlot, remote_head_slot = peerSlot,
              local_head_slot = headSlot, peer = peer,
              tolerance_value = man.toleranceValue,
              peer_score = peer.getScore(), topics = "syncman"
        let failure = SyncFailure.init(SyncFailureKind.StatusInvalid, peer)
        man.failures.add(failure)
        break

      if peerAge >= man.maxStatusAge:
        # Peer's status information is very old, we going to update it.
        debug "Updating peer's status information", wall_clock_slot = wallSlot,
              remote_head_slot = peerSlot, local_head_slot = headSlot,
              peer = peer, peer_score = peer.getScore(), topics = "syncman"
        let res = await peer.updateStatus()
        if not(res):
          peer.updateScore(PeerScoreNoStatus)
          debug "Failed to get remote peer's status, exiting", peer = peer,
                peer_score = peer.getScore(), peer_head_slot = peerSlot,
                topics = "syncman"
          let failure = SyncFailure.init(SyncFailureKind.StatusDownload, peer)
          man.failures.add(failure)
          break

        let newPeerSlot = peer.getHeadSlot()
        if peerSlot >= newPeerSlot:
          peer.updateScore(PeerScoreStaleStatus)
          debug "Peer's status information is stale, exiting",
                wall_clock_slot = wallSlot, remote_old_head_slot = peerSlot,
                local_head_slot = headSlot,
                remote_new_head_slot = newPeerSlot,
                peer = peer, peer_score = peer.getScore(), topics = "syncman"
          let failure = SyncFailure.init(SyncFailureKind.StatusStale, peer)
          man.failures.add(failure)
          break

        debug "Peer's status information updated", wall_clock_slot = wallSlot,
              remote_old_head_slot = peerSlot, local_head_slot = headSlot,
              remote_new_head_slot = newPeerSlot, peer = peer,
              peer_score = peer.getScore(), topics = "syncman"
        peer.updateScore(PeerScoreGoodStatus)
        peerSlot = newPeerSlot

      if (peerAge <= man.maxHeadAge) and (headAge <= man.maxHeadAge):
        debug "We are in sync with peer, exiting", wall_clock_slot = wallSlot,
              remote_head_slot = peerSlot, local_head_slot = headSlot,
              peer = peer, peer_score = peer.getScore(), topics = "syncman"
        break

      let req = man.queue.pop(peerSlot, peer)
      if req.isEmpty():
        debug "Empty request received from queue, exiting", peer = peer,
              local_head_slot = headSlot, remote_head_slot = peerSlot,
              queue_input_slot = man.queue.inpSlot,
              queue_output_slot = man.queue.outSlot,
              queue_last_slot = man.queue.lastSlot,
              peer_score = peer.getScore(), topics = "syncman"
        # Sometimes when syncing is almost done but last requests are still
        # pending, this can fall into endless cycle, when low number of peers
        # are available in PeerPool. We going to wait for RESP_TIMEOUT time,
        # so all pending requests should be finished at this moment.
        await sleepAsync(RESP_TIMEOUT)
        let failure = SyncFailure.init(SyncFailureKind.EmptyProblem, peer)
        man.failures.add(failure)
        break

      debug "Creating new request for peer", wall_clock_slot = wallSlot,
            remote_head_slot = peerSlot, local_head_slot = headSlot,
            request_slot = req.slot, request_count = req.count,
            request_step = req.step, peer = peer,
            peer_score = peer.getScore(), topics = "syncman"

      let blocks = await man.getBlocks(peer, req)
      if blocks.isOk:
        let data = blocks.get()
        let smap = getShortMap(req, data)
        debug "Received blocks on request", blocks_count = len(data),
              blocks_map = smap, request_slot = req.slot,
              request_count = req.count, request_step = req.step,
              peer = peer, peer_score = peer.getScore(), topics = "syncman"

        if not(checkResponse(req, data)):
          peer.updateScore(PeerScoreBadResponse)
          warn "Received blocks sequence is not in requested range",
               blocks_count = len(data), blocks_map = smap,
               request_slot = req.slot, request_count = req.count,
               request_step = req.step, peer = peer,
               peer_score = peer.getScore(), topics = "syncman"
          let failure = SyncFailure.init(SyncFailureKind.BadResponse, peer)
          man.failures.add(failure)
          break

        # Scoring will happen in `syncUpdate`.
        await man.queue.push(req, data)
        # Cleaning up failures.
        man.failures.setLen(0)
      else:
        peer.updateScore(PeerScoreNoBlocks)
        man.queue.push(req)
        debug "Failed to receive blocks on request",
              request_slot = req.slot, request_count = req.count,
              request_step = req.step, peer = peer,
              peer_score = peer.getScore(), topics = "syncman"
        let failure = SyncFailure.init(SyncFailureKind.BlockDownload, peer)
        man.failures.add(failure)
        break

    result = peer
  finally:
    man.pool.release(peer)

proc sync*[A, B](man: SyncManager[A, B]) {.async.} =
  # This procedure manages main loop of SyncManager and in this loop it
  # performs
  # 1. It checks for current sync status, "are we synced?".
  # 2. If we are in active syncing, it tries to acquire peers from PeerPool and
  #    spawns new sync-workers.
  # 3. It stops spawning sync-workers when we are "in sync".
  # 4. It calculates syncing performance.
  mixin getKey, getScore
  var pending = newSeq[Future[A]]()
  var acquireFut: Future[A]
  var wallSlot, headSlot: Slot
  var syncSpeed: float = 0.0

  template workersCount(): int =
    if isNil(acquireFut): len(pending) else: (len(pending) - 1)

  proc watchTask() {.async.} =
    while true:
      let lsm1 = SyncMoment.now(man.getLocalHeadSlot())
      await sleepAsync(chronos.seconds(int(SECONDS_PER_SLOT)))
      let lsm2 = SyncMoment.now(man.getLocalHeadSlot())
      if workersCount() == 0:
        syncSpeed = 0.0
      else:
        if (lsm2.slot - lsm1.slot == 0'u64) and (workersCount() > 1):
          debug "Syncing process is not progressing, reset the queue",
                workers_count = workersCount(),
                to_slot = man.queue.outSlot,
                local_head_slot = lsm1.slot
          await man.queue.resetWait(none[Slot]())
        else:
          syncSpeed = speed(lsm1, lsm2)

  debug "Synchronization loop started", topics = "syncman"

  traceAsyncErrors watchTask()

  while true:
    wallSlot = man.getLocalWallSlot()
    headSlot = man.getLocalHeadSlot()

    var progress: uint64
    if headSlot <= man.queue.lastSlot:
      progress = man.queue.progress()
    else:
      progress = 100'u64

    debug "Synchronization loop start tick", wall_head_slot = wallSlot,
          local_head_slot = headSlot, queue_status = progress,
          queue_start_slot = man.queue.startSlot,
          queue_last_slot = man.queue.lastSlot,
          workers_count = workersCount(), topics = "syncman"

    if headAge <= man.maxHeadAge:
      debug "Synchronization loop sleeping", wall_head_slot = wallSlot,
              local_head_slot = headSlot, workers_count = workersCount(),
              difference = (wallSlot - headSlot),
              max_head_age = man.maxHeadAge, topics = "syncman"
      if len(pending) == 0:
        man.inProgress = false
        await sleepAsync(man.sleepTime)
      else:
        var peerFut = one(pending)
        # We do not care about result here because we going to check peerFut
        # later.
        discard await withTimeout(peerFut, man.sleepTime)
    else:
      man.inProgress = true

      if isNil(acquireFut):
        acquireFut = man.pool.acquire()
        pending.add(acquireFut)

      debug "Synchronization loop waiting for new peer",
              wall_head_slot = wallSlot, local_head_slot = headSlot,
              workers_count = workersCount(), topics = "syncman"
      var peerFut = one(pending)
      # We do not care about result here, because we going to check peerFut
      # later.
      discard await withTimeout(peerFut, man.sleepTime)

    var temp = newSeqOfCap[Future[A]](len(pending))
    # Update slots to with more recent data
    wallSlot = man.getLocalWallSlot()
    headSlot = man.getLocalHeadSlot()
    for fut in pending:
      if fut.finished():
        if fut == acquireFut:
          # We acquired new peer from PeerPool.
          if acquireFut.failed():
            debug "Synchronization loop failed to get new peer",
                  wall_head_slot = wallSlot, local_head_slot = headSlot,
                  workers_count = workersCount(),
                  errMsg = acquireFut.readError().msg, topics = "syncman"
          else:
            var peer = acquireFut.read()
            if headAge <= man.maxHeadAge:
              # If we are already in sync, we going to release just acquired
              # peer and do not acquire peers
              debug "Synchronization loop reached sync barrier", peer = peer,
                    wall_head_slot = wallSlot, local_head_slot = headSlot,
                    peer_score = peer.getScore(), topics = "syncman"
              man.pool.release(peer)
            else:
              if headSlot > man.queue.lastSlot:
                man.queue = SyncQueue.init(A, headSlot, wallSlot,
                                           man.chunkSize, man.syncUpdate, 2)
              debug "Synchronization loop starting new worker", peer = peer,
                    wall_head_slot = wallSlot, local_head_slot = headSlot,
                    peer_score = peer.getScore(), topics = "syncman"
              temp.add(syncWorker(man, peer))

          acquireFut = nil
          if headAge > man.maxHeadAge:
            acquireFut = man.pool.acquire()
            temp.add(acquireFut)
        else:
          # Worker finished its work
          if fut.failed():
            debug "Synchronization loop got worker finished with an error",
                   wall_head_slot = wallSlot, local_head_slot = headSlot,
                   errMsg = fut.readError().msg, topics = "syncman"
          else:
            let peer = fut.read()
            debug "Synchronization loop got worker finished",
                   wall_head_slot = wallSlot, local_head_slot = headSlot,
                   peer = peer, peer_score = peer.getScore(),
                   topics = "syncman"
      else:
        if fut == acquireFut:
          if headAge <= man.maxHeadAge:
            debug "Synchronization loop reached sync barrier",
                   wall_head_slot = wallSlot, local_head_slot = headSlot,
                   topics = "syncman"
            acquireFut = nil
            fut.cancel()
          else:
            temp.add(fut)
        else:
          temp.add(fut)

    pending = temp

    if len(man.failures) > man.maxRecurringFailures and (workersCount() > 1):
      debug "Number of recurring failures exceeds limit, reseting queue",
            workers_count = workers_count(), rec_failures = len(man.failures)
      await man.queue.resetWait(none[Slot]())

    debug "Synchronization loop end tick", wall_head_slot = wallSlot,
          local_head_slot = headSlot, workers_count = workersCount(),
          waiting_for_new_peer = $not(isNil(acquireFut)),
          sync_speed = syncSpeed, queue_slot = man.queue.outSlot,
          topics = "syncman"
