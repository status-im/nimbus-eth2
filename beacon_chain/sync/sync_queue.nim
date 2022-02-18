# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import std/[options, heapqueue, tables, strutils, sequtils, math, algorithm]
import stew/[byteutils, results], chronos, chronicles
import
  ../spec/datatypes/[base, phase0, altair],
  ../spec/eth2_apis/rpc_types,
  ../spec/[helpers, forks],
  ../networking/[peer_pool, eth2_network],
  ../gossip_processing/block_processor,
  ../consensus_object_pools/block_pools_types

export base, phase0, altair, merge, chronos, chronicles, results,
       block_pools_types, helpers

logScope:
  topics = "syncqueue"

type
  SyncEndpoint*[K, V, R] =
    (K, V, R) # https://github.com/nim-lang/Nim/issues/19531

  GetSyncKeyCallback*[K] =
    proc(): K {.gcsafe, raises: [Defect].}
  ProcessingCallback* =
    proc() {.gcsafe, raises: [Defect].}
  SyncValueVerifier*[V] =
    proc(v: V): Future[Result[void, BlockError]] {.gcsafe, raises: [Defect].}

  SyncQueueKind* {.pure.} = enum
    Forward, Backward

  SyncRequest*[T; E: SyncEndpoint] = object
    kind: SyncQueueKind
    index*: uint64
    start*: E.K
    count*: uint64
    step*: uint64
    item*: T

  SyncResult*[T; E: SyncEndpoint] = object
    request*: SyncRequest[T, E]
    data*: seq[E.R]

  SyncWaiter* = ref object
    future: Future[void]
    reset: bool

  RewindPoint[K] = object
    failKey: K
    count: uint64

  SyncQueue*[T; E: SyncEndpoint] = ref object
    kind*: SyncQueueKind
    inpKey*: E.K
    outKey*: E.K
    startKey*: E.K
    finalKey*: E.K
    chunkSize*: uint64
    queueSize*: int
    counter*: uint64
    pending*: Table[uint64, SyncRequest[T, E]]
    waiters: seq[SyncWaiter]
    getSafeKey*: GetSyncKeyCallback[E.K]
    debtsQueue: HeapQueue[SyncRequest[T, E]]
    debtsCount: uint64
    readyQueue: HeapQueue[SyncResult[T, E]]
    rewind: Option[RewindPoint[E.K]]
    valueVerifier: SyncValueVerifier[E.V]

chronicles.formatIt SyncQueueKind: $it

template declareSyncKey(K: typedesc): untyped {.dirty.} =
  type
    `Get K Callback`* = GetSyncKeyCallback[K]
    `K RewindPoint`* = RewindPoint[K]

template declareSyncValue(name: untyped, V: typedesc): untyped {.dirty.} =
  type
    `name Verifier`* = SyncValueVerifier[V]

template declareSyncEndpoint(name: untyped, K, V: typedesc,
                             isRefWrapped = false): untyped {.dirty.} =
  when isRefWrapped:
    type `name SyncEndpoint`* = SyncEndpoint[K, V, ref V]
  else:
    type `name SyncEndpoint`* = SyncEndpoint[K, V, V]

  type
    `name SyncRequest`*[T] = SyncRequest[T, `name SyncEndpoint`]
    `name SyncResult`*[T] = SyncResult[T, `name SyncEndpoint`]
    `name SyncQueue`*[T] = SyncQueue[T, `name SyncEndpoint`]

  template `init name SyncQueue`*[T](t2: typedesc[T],
                                     queueKind: SyncQueueKind,
                                     start, final: K, chunkSize: uint64,
                                     getSafeKeyCb: GetSyncKeyCallback[K],
                                     valueVerifier: SyncValueVerifier[V],
                                     syncQueueSize: int = -1
                                     ): `name SyncQueue`[T] =
    `name SyncEndpoint`.initSyncQueue(t2, queueKind, start, final,
                                      chunkSize, getSafeKeyCb, valueVerifier,
                                      syncQueueSize)

declareSyncKey Slot
declareSyncKey SyncCommitteePeriod

declareSyncValue Block, ForkedSignedBeaconBlock
declareSyncValue Update, altair.LightClientUpdate

declareSyncEndpoint BeaconBlocks,
  Slot, ForkedSignedBeaconBlock, isRefWrapped = true
declareSyncEndpoint LightClientUpdates,
  SyncCommitteePeriod, altair.LightClientUpdate

func key[E](v: E.R, e: typedesc[E]): E.K =
  when E is BeaconBlocksSyncEndpoint:
    v[].slot
  elif E is LightClientUpdatesSyncEndpoint:
    v.attested_header.slot.sync_committee_period
  else: static: raiseAssert false

proc getShortMap*[T, E](req: SyncRequest[T, E],
                        data: openArray[E.R]): string =
  ## Returns all key values in ``data`` as placement map.
  var res = newStringOfCap(req.count)
  var slider = req.start
  var last = 0
  for i in 0 ..< req.count:
    if last < len(data):
      for k in last ..< len(data):
        if slider == data[k].key(E):
          res.add('x')
          last = k + 1
          break
        elif slider < data[k].key(E):
          res.add('.')
          break
    else:
      res.add('.')
    slider = slider + req.step
  res

proc contains*[T, E](req: SyncRequest[T, E], key: E.K): bool {.inline.} =
  key >= req.start and key < req.start + req.count * req.step and
    ((key - req.start) mod req.step == 0)

proc cmp*[T, E](a, b: SyncRequest[T, E]): int =
  cmp(uint64(a.start), uint64(b.start))

proc checkResponse*[T, E](req: SyncRequest[T, E],
                          data: openArray[E.R]): bool =
  if len(data) == 0:
    # Impossible to verify empty response.
    return true

  if uint64(len(data)) > req.count:
    # Number of blocks in response should be less or equal to number of
    # requested blocks.
    return false

  var key = req.start
  var rindex = 0'u64
  var dindex = 0

  while (rindex < req.count) and (dindex < len(data)):
    if key < data[dindex].key(E):
      discard
    elif key == data[dindex].key(E):
      inc(dindex)
    else:
      return false
    key = key + req.step
    rindex = rindex + 1'u64

  if dindex == len(data):
    return true
  else:
    return false

proc getFullMap*[T, E](req: SyncRequest[T, E], data: openArray[E.R]): string =
  # Returns all key values in ``data`` as comma-delimeted string.
  mapIt(data, $it.key(E)).join(", ")

proc init[T, E](t1: typedesc[SyncRequest], kind: SyncQueueKind,
                start, final: E.K, t2: typedesc[T], t3: typedesc[E]
                ): SyncRequest[T, E] =
  let count = final - start + 1'u64
  SyncRequest[T, E](
    kind: kind, start: start, count: count, step: 1'u64)

proc init[T, E](t1: typedesc[SyncRequest], kind: SyncQueueKind,
                start: E.K, count: uint64, item: T, t3: typedesc[E]
                ): SyncRequest[T, E] =
  SyncRequest[T, E](
    kind: kind, start: start, count: count, step: 1'u64, item: item)

proc init[T, E](t1: typedesc[SyncRequest], kind: SyncQueueKind,
                start, final: E.K, item: T, t3: typedesc[E]
                ): SyncRequest[T, E] =
  let count = final - start + 1'u64
  SyncRequest[T, E](
    kind: kind, start: start, count: count, step: 1'u64, item: item)

proc empty*[T, E](t1: typedesc[SyncRequest], kind: SyncQueueKind,
                  t2: typedesc[T], t3: typedesc[E]
                  ): SyncRequest[T, E] {.inline.} =
  SyncRequest[T, E](kind: kind, count: 0'u64, step: 0'u64)

proc setItem*[T, E](sr: var SyncRequest[T, E], item: T) =
  sr.item = item

proc isEmpty*[T, E](sr: SyncRequest[T, E]): bool {.inline.} =
  (sr.step == 0'u64) and (sr.count == 0'u64)

proc init[K](t1: typedesc[RewindPoint],
             failKey: K, count: uint64): RewindPoint[K] =
  RewindPoint[K](failKey: failKey, count: count)

proc initSyncQueue*[T, E](e: typedesc[E], t2: typedesc[T],
                          queueKind: SyncQueueKind,
                          start, final: E.K, chunkSize: uint64,
                          getSafeKeyCb: GetSyncKeyCallback[E.K],
                          valueVerifier: SyncValueVerifier[E.V],
                          syncQueueSize: int = -1): SyncQueue[T, E] =
  ## Create new synchronization queue with parameters
  ##
  ## ``start`` and ``final`` are starting and final keys.
  ##
  ## ``chunkSize`` maximum number of keys in one request.
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
  #
  # The logic for syncing blocks also applies during `LightClientUpdate` sync.
  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  SyncQueue[T, E](
    kind: queueKind,
    startKey: start,
    finalKey: final,
    chunkSize: chunkSize,
    queueSize: syncQueueSize,
    getSafeKey: getSafeKeyCb,
    waiters: newSeq[SyncWaiter](),
    counter: 1'u64,
    pending: initTable[uint64, SyncRequest[T, E]](),
    debtsQueue: initHeapQueue[SyncRequest[T, E]](),
    inpKey: start,
    outKey: start,
    valueVerifier: valueVerifier
  )

proc `<`*[T, E](a, b: SyncRequest[T, E]): bool =
  doAssert(a.kind == b.kind)
  case a.kind
  of SyncQueueKind.Forward:
    a.start < b.start
  of SyncQueueKind.Backward:
    a.start > b.start

proc `<`*[T, E](a, b: SyncResult[T, E]): bool =
  doAssert(a.request.kind == b.request.kind)
  case a.request.kind
  of SyncQueueKind.Forward:
    a.request.start < b.request.start
  of SyncQueueKind.Backward:
    a.request.start > b.request.start

proc `==`*[T, E](a, b: SyncRequest[T, E]): bool =
  (a.kind == b.kind) and (a.start == b.start) and (a.count == b.count) and
    (a.step == b.step)

proc lastKey*[T, E](req: SyncRequest[T, E]): E.K =
  ## Returns last key for request ``req``.
  req.start + req.count - 1'u64

proc makePending*[T, E](sq: SyncQueue[T, E], req: var SyncRequest[T, E]) =
  req.index = sq.counter
  sq.counter = sq.counter + 1'u64
  sq.pending[req.index] = req

proc updateLastKey*[T, E](sq: SyncQueue[T, E], last: E.K) {.inline.} =
  ## Update last key stored in queue ``sq`` with value ``last``.
  case sq.kind
  of SyncQueueKind.Forward:
    doAssert(sq.finalKey <= last,
             "Last key could not be lower then stored one " &
             $sq.finalKey & " <= " & $last)
    sq.finalKey = last
  of SyncQueueKind.Backward:
    doAssert(sq.finalKey >= last,
             "Last key could not be higher then stored one " &
             $sq.finalKey & " >= " & $last)
    sq.finalKey = last

proc wakeupWaiters[T, E](sq: SyncQueue[T, E], reset = false) =
  ## Wakeup one or all blocked waiters.
  for item in sq.waiters:
    if reset:
      item.reset = true

    if not(item.future.finished()):
      item.future.complete()

proc waitForChanges[T, E](sq: SyncQueue[T, E]): Future[bool] {.async.} =
  ## Create new waiter and wait for completion from `wakeupWaiters()`.
  var waitfut = newFuture[void]("SyncQueue.waitForChanges")
  let waititem = SyncWaiter(future: waitfut)
  sq.waiters.add(waititem)
  try:
    await waitfut
    return waititem.reset
  finally:
    sq.waiters.delete(sq.waiters.find(waititem))

proc wakeupAndWaitWaiters[T, E](sq: SyncQueue[T, E]) {.async.} =
  ## This procedure will perform wakeupWaiters(true) and blocks until last
  ## waiter will be awakened.
  var waitChanges = sq.waitForChanges()
  sq.wakeupWaiters(true)
  discard await waitChanges

proc clearAndWakeup*[T, E](sq: SyncQueue[T, E]) =
  sq.pending.clear()
  sq.wakeupWaiters(true)

proc resetWait*[T, E](sq: SyncQueue[T, E], toKey: Option[E.K]) {.async.} =
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

  # We calculating minimal key value to which we will be able to reset,
  # without missing any values. There 3 sources:
  # 1. Debts queue.
  # 2. Processing queue (`inpKey`, `outKey`).
  # 3. Requested key `toKey`.
  #
  # Queue's `outKey` is the lowest key we added to value `processor`, but
  # `toKey` key can be less then `outKey`. `debtsQueue` holds only not
  # added key requests, so it can't be bigger then `outKey` value.
  let minKey =
    case sq.kind
    of SyncQueueKind.Forward:
      if toKey.isSome():
        min(toKey.get(), sq.outKey)
      else:
        sq.outKey
    of SyncQueueKind.Backward:
      if toKey.isSome():
        toKey.get()
      else:
        sq.outKey
  sq.debtsQueue.clear()
  sq.debtsCount = 0
  sq.readyQueue.clear()
  sq.inpKey = minKey
  sq.outKey = minKey
  # We are going to wakeup all the waiters and wait for last one.
  await sq.wakeupAndWaitWaiters()

proc isEmpty*[T, E](sr: SyncResult[T, E]): bool {.inline.} =
  ## Returns ``true`` if response chain of values is empty (has only empty
  ## keys).
  len(sr.data) == 0

proc hasEndGap*[T, E](sr: SyncResult[T, E]): bool {.inline.} =
  ## Returns ``true`` if response chain of values has gap at the end.
  let lastKey = sr.request.start + sr.request.count - 1'u64
  if len(sr.data) == 0:
    return true
  if sr.data[^1].key(E) != lastKey:
    return true
  return false

proc getLastNonEmptyKey*[T, E](sr: SyncResult[T, E]): E.K {.inline.} =
  ## Returns last non-empty key from result ``sr``. If response has only
  ## empty keys, original request key will be returned.
  if len(sr.data) == 0:
    # If response has only empty keys we going to use original request key
    sr.request.start
  else:
    sr.data[^1].key(E)

proc toDebtsQueue[T, E](sq: SyncQueue[T, E], sr: SyncRequest[T, E]) =
  sq.debtsQueue.push(sr)
  sq.debtsCount = sq.debtsCount + sr.count

proc getRewindPoint*[T](sq: BeaconBlocksSyncQueue[T],
                        failSlot, safeSlot: Slot): Slot =
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
        if failSlot == rewind.failKey:
          # `MissingParent` happened at same slot so we increase rewind point by
          # factor of 2.
          if failEpoch > finalizedEpoch:
            let rewindPoint = rewind.count shl 1
            if rewindPoint < rewind.count:
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
                 rewind_epoch_count = rewind.count,
                 finalized_epoch = finalizedEpoch, direction = sq.kind,
                 topics = "syncman"
            0'u64
        else:
          # `MissingParent` happened at different slot so we going to rewind for
          # 1 epoch only.
          if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
            warn "Сould not rewind further than the last finalized epoch",
                 finalized_slot = safeSlot, fail_slot = failSlot,
                 finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
                 rewind_epoch_count = rewind.count,
                 finalized_epoch = finalizedEpoch, direction = sq.kind,
                 topics = "syncman"
            0'u64
          else:
            1'u64
      else:
        # `MissingParent` happened first time.
        if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
          warn "Сould not rewind further than the last finalized epoch",
               finalized_slot = safeSlot, fail_slot = failSlot,
               finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
               finalized_epoch = finalizedEpoch, direction = sq.kind,
               topics = "syncman"
          0'u64
        else:
          1'u64

    if epochCount == 0'u64:
      warn "Unable to continue syncing, please restart the node",
           finalized_slot = safeSlot, fail_slot = failSlot,
           finalized_epoch = finalizedEpoch, fail_epoch = failEpoch,
           finalized_epoch = finalizedEpoch, direction = sq.kind,
           topics = "syncman"
      # Calculate the rewind epoch, which will be equal to last rewind point or
      # finalizedEpoch
      let rewindEpoch =
        if sq.rewind.isNone():
          finalizedEpoch
        else:
          epoch(sq.rewind.get().failKey) - sq.rewind.get().count
      rewindEpoch.start_slot()
    else:
      # Calculate the rewind epoch, which should not be less than the latest
      # finalized epoch.
      let rewindEpoch = failEpoch - epochCount
      # Update and save new rewind point in SyncQueue.
      sq.rewind = some(RewindPoint.init(failSlot, epochCount))
      rewindEpoch.start_slot()
  of SyncQueueKind.Backward:
    # While we perform backward sync, the only possible slot we could rewind is
    # latest stored block.
    if failSlot == safeSlot:
      warn "Unable to continue syncing, please restart the node",
           safe_slot = safeSlot, fail_slot = failSlot, direction = sq.kind,
           topics = "syncman"
    safeSlot

proc getRewindPoint[T](sq: LightClientUpdatesSyncQueue[T],
                       failPeriod, safePeriod: SyncCommitteePeriod
                       ): SyncCommitteePeriod =
  case sq.kind
  of SyncQueueKind.Forward:
    # One `LightClientUpdate` per sync committee period needs to be obtained.
    # There is no concept of "empty slots". Retry sync from `safePeriod`.
    # Note that in contrast to block sync, there may be multiple valid
    # `LightClientUpdate` per sync committee period. Hence, it is necessary
    # to keep retrying to fetch a better one, even though prior results were
    # not satisfactory. `light_client_processor` will eventually start to
    # attempt force-updating the light client if sync progress seems to stall.
    let periodCount = failPeriod - safePeriod
    sq.rewind = some(RewindPoint.init(failPeriod, periodCount))
    safePeriod
  of SyncQueueKind.Backward:
    let periodCount = safePeriod - failPeriod
    sq.rewind = some(RewindPoint.init(failPeriod, periodCount))
    safePeriod

iterator values*[T, E](sq: SyncQueue[T, E], sr: SyncResult[T, E]): E.R =
  case sq.kind
  of SyncQueueKind.Forward:
    for i in countup(0, len(sr.data) - 1):
      yield sr.data[i]
  of SyncQueueKind.Backward:
    for i in countdown(len(sr.data) - 1, 0):
      yield sr.data[i]

proc advanceOutput*[T, E](sq: SyncQueue[T, E], number: uint64) =
  case sq.kind
  of SyncQueueKind.Forward:
    sq.outKey = sq.outKey + number
  of SyncQueueKind.Backward:
    sq.outKey = sq.outKey - number

proc advanceInput[T, E](sq: SyncQueue[T, E], number: uint64) =
  case sq.kind
  of SyncQueueKind.Forward:
    sq.inpKey = sq.inpKey + number
  of SyncQueueKind.Backward:
    sq.inpKey = sq.inpKey - number

proc notInRange[T, E](sq: SyncQueue[T, E], sr: SyncRequest[T, E]): bool =
  case sq.kind
  of SyncQueueKind.Forward:
    (sq.queueSize > 0) and (sr.start != sq.outKey)
  of SyncQueueKind.Backward:
    (sq.queueSize > 0) and (sr.start + sr.count - 1'u64 != sq.outKey)

proc push*[T, E](sq: SyncQueue[T, E], sr: SyncRequest[T, E], data: seq[E.R],
                 processingCb: ProcessingCallback = nil) {.async.} =
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
  # all pending `push` requests if `request.start` not in range.
  while true:
    if sq.notInRange(sr):
      let reset = await sq.waitForChanges()
      if reset:
        # SyncQueue reset happens. We are exiting to wake up sync-worker.
        return
    else:
      let syncres = SyncResult[T, E](request: sr, data: data)
      sq.readyQueue.push(syncres)
      break

  while len(sq.readyQueue) > 0:
    let reqres =
      case sq.kind
      of SyncQueueKind.Forward:
        let minKey = sq.readyQueue[0].request.start
        if sq.outKey != minKey:
          none[SyncResult[T, E]]()
        else:
          some(sq.readyQueue.pop())
      of SyncQueueKind.Backward:
        let maxKey = sq.readyQueue[0].request.start +
                     (sq.readyQueue[0].request.count - 1'u64)
        if sq.outKey != maxKey:
          none[SyncResult[T, E]]()
        else:
          some(sq.readyQueue.pop())

    let item =
      if reqres.isSome():
        reqres.get()
      else:
        let rewindKey = sq.getRewindPoint(sq.outKey, sq.getSafeKey())
        when E is BeaconBlocksSyncEndpoint:
          warn "Got incorrect sync result in queue, rewind happens",
               request_slot = sq.readyQueue[0].request.start,
               request_count = sq.readyQueue[0].request.count,
               request_step = sq.readyQueue[0].request.step,
               blocks_map = getShortMap[T, E](sq.readyQueue[0].request,
                                              sq.readyQueue[0].data),
               blocks_count = len(sq.readyQueue[0].data),
               output_slot = sq.outKey, input_slot = sq.inpKey,
               peer = sq.readyQueue[0].request.item,
               rewind_to_slot = rewindKey,
               direction = sq.readyQueue[0].request.kind, topics = "syncman"
        elif E is LightClientUpdatesSyncEndpoint:
          warn "Got incorrect sync result in queue, rewind happens",
               request_period = sq.readyQueue[0].request.start,
               request_count = sq.readyQueue[0].request.count,
               request_step = sq.readyQueue[0].request.step,
               updates_map = getShortMap[T, E](sq.readyQueue[0].request,
                                               sq.readyQueue[0].data),
               updates_count = len(sq.readyQueue[0].data),
               output_period = sq.outKey, input_period = sq.inpKey,
               peer = sq.readyQueue[0].request.item,
               rewind_to_period = rewindKey,
               direction = sq.readyQueue[0].request.kind, topics = "syncman"
        else: static: raiseAssert false
        await sq.resetWait(some(rewindKey))
        break

    if processingCb != nil:
      processingCb()

    # Validating received values one by one
    type UnviableTuple = (Eth2Digest, E.K)
    var
      hasOkValue = false
      hasInvalidValue = false
      unviableValue: Option[UnviableTuple]
      missingParentKey: Option[E.K]

      # compiler segfault if this is moved into the for loop, at time of writing
      res: Result[void, BlockError]

    for value in sq.values(item):
      res =
        when E.R is ref E.V:
          await sq.valueVerifier(value[])
        else:
          await sq.valueVerifier(value)
      if res.isOk():
        hasOkValue = true
      else:
        case res.error()
        of BlockError.MissingParent:
          missingParentKey = some(value.key(E))
          break
        of BlockError.Duplicate:
          # Keep going, happens naturally
          discard
        of BlockError.UnviableFork:
          if unviableValue.isNone:
            # Remember the first unviable value, so we can log it
            func root(v: ref ForkedSignedBeaconBlock): Eth2Digest =
              v[].root
            func root(v: altair.LightClientUpdate): Eth2Digest =
              v.fork_version.hash_tree_root()
            unviableValue = some((value.root, value.key(E)))
          when E.V is ForkedSignedBeaconBlock:
            # Keep going so as to register other unviable blocks with the
            # quarantine
            discard
          elif E.V is altair.LightClientUpdate:
            break
          else: static: raiseAssert false
        of BlockError.Invalid:
          hasInvalidValue = true

          let req = item.request
          when E is BeaconBlocksSyncEndpoint:
            warn "Received invalid sequence of blocks", peer = req.item,
                 request_slot = req.start, request_count = req.count,
                 request_step = req.step, blocks_count = len(item.data),
                 blocks_map = getShortMap[T, E](req, item.data),
                 direction = req.kind, topics = "syncman"
          elif E is LightClientUpdatesSyncEndpoint:
            warn "Received invalid sequence of updates", peer = req.item,
                 request_period = req.start, request_count = req.count,
                 request_step = req.step, updates_count = len(item.data),
                 updates_map = getShortMap[T, E](req, item.data),
                 direction = req.kind, topics = "syncman"
          else: static: raiseAssert false
          req.item.updateScore(PeerScoreBadBlocks)
          break

    # When errors happen while processing values, we retry the same request
    # with, hopefully, a different peer
    let retryRequest =
      hasInvalidValue or unviableValue.isSome() or missingParentKey.isSome()
    if not retryRequest:
      sq.advanceOutput(item.request.count)

      if hasOkValue:
        # If there no error and response was not empty we should reward peer
        # with some bonus score - not for duplicate values though.
        item.request.item.updateScore(PeerScoreGoodBlocks)

      sq.wakeupWaiters()
    else:
      when E is BeaconBlocksSyncEndpoint:
        debug "Block pool rejected peer's response", peer = item.request.item,
              request_slot = item.request.start,
              request_count = item.request.count,
              request_step = item.request.step,
              blocks_map = getShortMap[T, E](item.request, item.data),
              blocks_count = len(item.data),
              ok = hasOkValue,
              unviable = unviableValue.isSome(),
              missing_parent = missingParentKey.isSome(),
              direction = item.request.kind, topics = "syncman"
      elif E is LightClientUpdatesSyncEndpoint:
        debug "Light client processor rejected peer's response",
              peer = item.request.item,
              request_period = item.request.start,
              request_count = item.request.count,
              request_step = item.request.step,
              updates_map = getShortMap[T, E](item.request, item.data),
              updates_count = len(item.data),
              ok = hasOkValue,
              unviable = unviableValue.isSome(),
              missing_parent = missingParentKey.isSome(),
              direction = item.request.kind, topics = "syncman"
      else: static: raiseAssert false

      # We need to move failed response to the debts queue.
      sq.toDebtsQueue(item.request)

      if unviableValue.isSome:
        let req = item.request
        when E is BeaconBlocksSyncEndpoint:
          notice "Received blocks from an unviable fork",
                 blockRoot = unviableValue.get()[0],
                 blockSlot = unviableValue.get()[1], peer = req.item,
                 request_slot = req.start, request_count = req.count,
                 request_step = req.step, blocks_count = len(item.data),
                 blocks_map = getShortMap[T, E](req, item.data),
                 direction = req.kind, topics = "syncman"
        elif E is LightClientUpdatesSyncEndpoint:
          template versionString(v: Eth2Digest): string =
            byteutils.toHex(v.data.toOpenArray(0, sizeof(Version) - 1))
          notice "Received updates from an unviable fork",
                 updateVersion = unviableValue.get()[0].versionString,
                 updatePeriod = unviableValue.get()[1], peer = req.item,
                 request_period = req.start, request_count = req.count,
                 request_step = req.step, updates_count = len(item.data),
                 updates_map = getShortMap[T, E](req, item.data),
                 direction = req.kind, topics = "syncman"
        else: static: raiseAssert false
        req.item.updateScore(PeerScoreUnviableFork)

      if missingParentKey.isSome:
        var
          resetKey: Option[E.K]
          failKey = missingParentKey.get()

        # If we got `BlockError.MissingParent` it means that peer returns chain
        # of values with holes or `block_processor` is in incomplete state.
        # For blocks we will rewind to the first slot at latest finalized epoch.
        # For light client updates we will rewind to first period needing data.
        let
          req = item.request
          safeKey = sq.getSafeKey()
        case sq.kind
        of SyncQueueKind.Forward:
          if safeKey < failKey:
            let rewindKey = sq.getRewindPoint(failKey, safeKey)
            when E is BeaconBlocksSyncEndpoint:
              warn "Unexpected missing parent, rewind happens",
                   peer = req.item, rewind_to_slot = rewindKey,
                   rewind_epoch_count = sq.rewind.get().count,
                   rewind_fail_slot = failKey,
                   finalized_slot = safeKey,
                   request_slot = req.start, request_count = req.count,
                   request_step = req.step, blocks_count = len(item.data),
                   blocks_map = getShortMap[T, E](req, item.data),
                   direction = req.kind, topics = "syncman"
            elif E is LightClientUpdatesSyncEndpoint:
              warn "Unexpected missing parent, rewind happens",
                   peer = req.item, rewind_to_period = rewindKey,
                   rewind_period_count = sq.rewind.get().count,
                   rewind_fail_period = failKey,
                   finalized_period = safeKey,
                   request_period = req.start, request_count = req.count,
                   request_step = req.step, updates_count = len(item.data),
                   updates_map = getShortMap[T, E](req, item.data),
                   direction = req.kind, topics = "syncman"
            else: static: raiseAssert false
            resetKey = some(rewindKey)
            req.item.updateScore(PeerScoreMissingBlocks)
          else:
            when E is BeaconBlocksSyncEndpoint:
              error "Unexpected missing parent at finalized epoch slot",
                    peer = req.item, to_slot = safeKey,
                    request_slot = req.start, request_count = req.count,
                    request_step = req.step, blocks_count = len(item.data),
                    blocks_map = getShortMap[T, E](req, item.data),
                    direction = req.kind, topics = "syncman"
            elif E is LightClientUpdatesSyncEndpoint:
              error "Unexpected missing parent at finalized period",
                    peer = req.item, to_period = safeKey,
                    request_period = req.start, request_count = req.count,
                    request_step = req.step, updates_count = len(item.data),
                    updates_map = getShortMap[T, E](req, item.data),
                    direction = req.kind, topics = "syncman"
            else: static: raiseAssert false
            req.item.updateScore(PeerScoreBadBlocks)
        of SyncQueueKind.Backward:
          if safeKey > failKey:
            let rewindKey = sq.getRewindPoint(failKey, safeKey)
            when E is BeaconBlocksSyncEndpoint:
              # It's quite common peers give us fewer values than we ask for
              info "Gap in block range response, rewinding",
                   peer = req.item, rewind_to_slot = rewindKey,
                   rewind_fail_slot = failKey,
                   finalized_slot = safeKey,
                   request_slot = req.start, request_count = req.count,
                   request_step = req.step, blocks_count = len(item.data),
                   blocks_map = getShortMap[T, E](req, item.data),
                   direction = req.kind, topics = "syncman"
            elif E is LightClientUpdatesSyncEndpoint:
              info "Gap in `BestLightClientUpdatesByRange` response, rewinding",
                   peer = req.item, rewind_to_period = rewindKey,
                   rewind_fail_period = failKey,
                   finalized_period = safeKey,
                   request_period = req.start, request_count = req.count,
                   request_step = req.step, updates_count = len(item.data),
                   updates_map = getShortMap[T, E](req, item.data),
                   direction = req.kind, topics = "syncman"
            else: static: raiseAssert false
            resetKey = some(rewindKey)
            req.item.updateScore(PeerScoreMissingBlocks)
          else:
            when E is BeaconBlocksSyncEndpoint:
              error "Unexpected missing parent at safe slot",
                    peer = req.item, to_slot = safeKey,
                    request_slot = req.start, request_count = req.count,
                    request_step = req.step, blocks_count = len(item.data),
                    blocks_map = getShortMap[T, E](req, item.data),
                    direction = req.kind, topics = "syncman"
            elif E is LightClientUpdatesSyncEndpoint:
              error "Unexpected missing parent at safe period",
                    peer = req.item, to_period = safeKey,
                    request_period = req.start, request_count = req.count,
                    request_step = req.step, updates_count = len(item.data),
                    updates_map = getShortMap[T, E](req, item.data),
                    direction = req.kind, topics = "syncman"
            else: static: raiseAssert false
            req.item.updateScore(PeerScoreBadBlocks)

        if resetKey.isSome():
          await sq.resetWait(resetKey)
          case sq.kind
          of SyncQueueKind.Forward:
            when E.K is Slot:
              debug "Rewind to slot has happened",
                    reset_slot = resetKey.get(),
                    queue_input_slot = sq.inpKey,
                    queue_output_slot = sq.outKey,
                    rewind_epoch_count = sq.rewind.get().count,
                    rewind_fail_slot = sq.rewind.get().failKey,
                    direction = sq.kind, topics = "syncman"
            elif E.K is SyncCommitteePeriod:
              debug "Rewind to period has happened",
                    reset_period = resetKey.get(),
                    queue_input_period = sq.inpKey,
                    queue_output_period = sq.outKey,
                    rewind_period_count = sq.rewind.get().count,
                    rewind_fail_period = sq.rewind.get().failKey,
                    direction = sq.kind, topics = "syncman"
            else: static: raiseAssert false
          of SyncQueueKind.Backward:
            when E.K is Slot:
              debug "Rewind to slot has happened",
                    reset_slot = resetKey.get(),
                    queue_input_slot = sq.inpKey,
                    queue_output_slot = sq.outKey,
                    direction = sq.kind, topics = "syncman"
            elif E.K is SyncCommitteePeriod:
              debug "Rewind to period has happened",
                    reset_period = resetKey.get(),
                    queue_input_period = sq.inpKey,
                    queue_output_period = sq.outKey,
                    direction = sq.kind, topics = "syncman"
            else: static: raiseAssert false

      break

proc push*[T, E](sq: SyncQueue[T, E], sr: SyncRequest[T, E]) =
  ## Push failed request back to queue.
  if sr.index notin sq.pending:
    # If request `sr` not in our pending list, it only means that
    # SyncQueue.resetWait() happens and all pending requests are expired, so
    # we swallow `old` requests, and in such way sync-workers are able to get
    # proper new requests from SyncQueue.
    return
  sq.pending.del(sr.index)
  sq.toDebtsQueue(sr)

proc pop*[T, E](sq: SyncQueue[T, E],
                maxKey: E.K, item: T): SyncRequest[T, E] =
  ## Create new request according to current SyncQueue parameters.
  if len(sq.debtsQueue) > 0:
    if maxKey < sq.debtsQueue[0].start:
      # Peer's latest key is less than starting request's key.
      return SyncRequest.empty(sq.kind, T, E)
    if maxKey < sq.debtsQueue[0].lastKey():
      # Peer's latest key is less than finishing request's key.
      return SyncRequest.empty(sq.kind, T, E)
    var sr = sq.debtsQueue.pop()
    sq.debtsCount = sq.debtsCount - sr.count
    sr.setItem(item)
    sq.makePending(sr)
    sr
  else:
    case sq.kind
    of SyncQueueKind.Forward:
      if maxKey < sq.inpKey:
        # Peer's latest key is less than queue's input key.
        return SyncRequest.empty(sq.kind, T, E)
      if sq.inpKey > sq.finalKey:
        # Queue's input key is bigger than queue's final key.
        return SyncRequest.empty(sq.kind, T, E)
      let lastKey = min(maxKey, sq.finalKey)
      let count = min(sq.chunkSize, lastKey + 1'u64 - sq.inpKey)
      var sr = SyncRequest.init(sq.kind, sq.inpKey, count, item, E)
      sq.advanceInput(count)
      sq.makePending(sr)
      sr
    of SyncQueueKind.Backward:
      if sq.inpKey == 0xFFFF_FFFF_FFFF_FFFF'u64:
        return SyncRequest.empty(sq.kind, T, E)
      if sq.inpKey < sq.finalKey:
        return SyncRequest.empty(sq.kind, T, E)
      let (key, count) =
        block:
          let baseKey = sq.inpKey + 1'u64
          if baseKey - sq.finalKey < sq.chunkSize:
            let count = uint64(baseKey - sq.finalKey)
            (baseKey - count, count)
          else:
            (baseKey - sq.chunkSize, sq.chunkSize)
      if (maxKey + 1'u64) < key + count:
        # Peer's latest key is less than queue's input key.
        return SyncRequest.empty(sq.kind, T, E)
      var sr = SyncRequest.init(sq.kind, key, count, item, E)
      sq.advanceInput(count)
      sq.makePending(sr)
      sr

proc debtLen*[T, E](sq: SyncQueue[T, E]): uint64 =
  sq.debtsCount

proc pendingLen*[T, E](sq: SyncQueue[T, E]): uint64 =
  case sq.kind
  of SyncQueueKind.Forward:
    # When moving forward `outKey` will be <= of `inpKey`.
    sq.inpKey - sq.outKey
  of SyncQueueKind.Backward:
    # When moving backward `outKey` will be >= of `inpKey`
    sq.outKey - sq.inpKey

proc len*[T, E](sq: SyncQueue[T, E]): uint64 {.inline.} =
  ## Returns number of keys left in queue ``sq``.
  case sq.kind
  of SyncQueueKind.Forward:
    sq.finalKey + 1'u64 - sq.outKey
  of SyncQueueKind.Backward:
    sq.outKey + 1'u64 - sq.finalKey

proc total*[T, E](sq: SyncQueue[T, E]): uint64 {.inline.} =
  ## Returns total number of keys in queue ``sq``.
  case sq.kind
  of SyncQueueKind.Forward:
    sq.finalKey + 1'u64 - sq.startKey
  of SyncQueueKind.Backward:
    sq.startKey + 1'u64 - sq.finalKey

proc progress*[T, E](sq: SyncQueue[T, E]): uint64 =
  ## How many keys we've synced so far
  case sq.kind
  of SyncQueueKind.Forward:
    sq.outKey - sq.startKey
  of SyncQueueKind.Backward:
    sq.startKey - sq.outKey
