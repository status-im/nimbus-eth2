import chronicles
import options, deques, heapqueue, tables, strutils
import stew/bitseqs, chronos, chronicles
import spec/datatypes, spec/digest, peer_pool
export datatypes, digest, chronos, chronicles

logScope:
  topics = "syncman"

const MAX_REQUESTED_BLOCKS* = 20'u64

type
  GetSlotCallback* =
    proc(): Slot {.gcsafe.}

  UpdateLocalBlocksCallback* =
    proc(list: openarray[SignedBeaconBlock]): bool {.gcsafe.}

  SyncRequest* = object
    slot*: Slot
    count*: uint64
    step*: uint64
    group*: int

  SyncResult* = object
    request*: SyncRequest
    data*: seq[SignedBeaconBlock]

  SyncQueue* = ref object
    inpSlot*: Slot
    outSlot*: Slot

    startSlot*: Slot
    lastSlot: Slot
    chunkSize*: uint64
    queueSize*: int

    notFullEvent*: AsyncEvent
    syncUpdate*: UpdateLocalBlocksCallback

    debtsQueue: HeapQueue[SyncRequest]
    debtsCount: uint64
    readyQueue: HeapQueue[SyncResult]
    readyData: seq[seq[SignedBeaconBlock]]

  SyncManager*[A, B] = ref object
    pool: PeerPool[A, B]
    failuresCount: int
    failurePause: chronos.Duration
    responseTimeout: chronos.Duration
    sleepTime: chronos.Duration
    statusSlots: uint64
    syncBarrierSlots: uint64
    getLocalHeadSlot: GetSlotCallback
    getLocalWallSlot: GetSlotCallback
    updateLocalBlocks: UpdateLocalBlocksCallback
    queue: SyncQueue

  SyncManagerError* = object of CatchableError
  OptionBeaconBlocks* = Option[seq[SignedBeaconBlock]]

proc init*(t: typedesc[SyncRequest], slot: Slot,
           count: uint64): SyncRequest {.inline.} =
  result = SyncRequest(slot: slot, count: count, step: 1'u64)

proc init*(t: typedesc[SyncRequest], start: Slot,
           finish: Slot): SyncRequest {.inline.} =
  let count = finish - start + 1'u64
  result = SyncRequest(slot: start, count: count, step: 1'u64)

proc empty*(t: typedesc[SyncRequest]): SyncRequest {.inline.} =
  result = SyncRequest(slot: Slot(0), count: 0'u64)

proc isEmpty*(sr: SyncRequest): bool {.inline.} =
  result = (sr.slot == Slot(0)) and (sr.count == 0'u64)

proc init*(t: typedesc[SyncQueue], start, last: Slot, chunkSize: uint64,
           updateCb: UpdateLocalBlocksCallback,
           queueSize: int = -1): SyncQueue =
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
  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  result = SyncQueue(
    startSlot: start,
    lastSlot: last,
    chunkSize: chunkSize,
    queueSize: queueSize,
    syncUpdate: updateCb,
    notFullEvent: newAsyncEvent(),
    debtsQueue: initHeapQueue[SyncRequest](),
    inpSlot: start,
    outSlot: start
  )

proc `<`*(a, b: SyncRequest): bool {.inline.} =
  result = (a.slot < b.slot)

proc `<`*(a, b: SyncResult): bool {.inline.} =
  result = (a.request.slot < b.request.slot)

proc `==`*(a, b: SyncRequest): bool {.inline.} =
  result = ((a.slot == b.slot) and (a.count == b.count) and
            (a.step == b.step))

proc lastSlot*(req: SyncRequest): Slot {.inline.} =
  ## Returns last slot for request ``req``.
  result = req.slot + req.count - 1'u64

proc updateLastSlot*(sq: SyncQueue, last: Slot) {.inline.} =
  ## Update last slot stored in queue ``sq`` with value ``last``.
  doAssert(sq.lastSlot <= last,
           "Last slot could not be lower then stored one " &
           $sq.lastSlot & " <= " & $last)
  sq.lastSlot = last

proc push*(sq: SyncQueue, sr: SyncRequest,
           data: seq[SignedBeaconBlock]) {.async, gcsafe.} =
  ## Push successfull result to queue ``sq``.
  while true:
    if (sq.queueSize > 0) and (sr.slot >= sq.outSlot + uint64(sq.queueSize)):
      await sq.notFullEvent.wait()
      sq.notFullEvent.clear()
      continue
    let res = SyncResult(request: sr, data: data)
    sq.readyQueue.push(res)
    break

  while len(sq.readyQueue) > 0:
    let minSlot = sq.readyQueue[0].request.slot
    if sq.outSlot != minSlot:
      break
    let item = sq.readyQueue.pop()
    if not(sq.syncUpdate(item.data)):
      sq.debtsQueue.push(item.request)
      sq.debtsCount = sq.debtsCount + item.request.count
      break
    sq.outSlot = sq.outSlot + item.request.count
    sq.notFullEvent.fire()

proc push*(sq: SyncQueue, sr: SyncRequest) =
  ## Push failed request back to queue.
  sq.debtsQueue.push(sr)
  sq.debtsCount = sq.debtsCount + sr.count

proc pop*(sq: SyncQueue, maxslot: Slot): SyncRequest =
  if len(sq.debtsQueue) > 0:
    if maxSlot < sq.debtsQueue[0].slot:
      return SyncRequest.empty()

    let sr = sq.debtsQueue.pop()
    if sr.lastSlot() <= maxSlot:
      return sr

    let sr1 = SyncRequest.init(sr.slot, maxslot)
    let sr2 = SyncRequest.init(maxslot, sr.lastSlot())
    sq.debtsQueue.push(sr2)
    return sr1
  else:
    if maxSlot < sq.inpSlot:
      return SyncRequest.empty()

    if sq.inpSlot > sq.lastSlot:
      return SyncRequest.empty()

    let lastSlot = min(maxslot, sq.lastSlot)
    let count = min(sq.chunkSize, lastSlot + 1'u64 - sq.inpSlot)
    let sr = SyncRequest.init(sq.inpSlot, count)
    sq.inpSlot = sq.inpSlot + count
    return sr

proc len*(sq: SyncQueue): uint64 {.inline.} =
  ## Returns number of slots left in queue ``sq``.
  if sq.inpSlot > sq.lastSlot:
    result = sq.debtsCount
  else:
    result = sq.lastSlot - sq.inpSlot + 1'u64 + sq.debtsCount

proc total*(sq: SyncQueue): uint64 {.inline.} =
  ## Returns total number of slots in queue ``sq``.
  result = sq.lastSlot - sq.startSlot + 1'u64

proc progress*(sq: SyncQueue): string =
  ## Returns queue's ``sq`` progress string.
  let curSlot = sq.outSlot - sq.startSlot
  result = $curSlot & "/" & $sq.total()

proc newSyncManager*[A, B](pool: PeerPool[A, B],
                           getLocalHeadSlotCb: GetSlotCallback,
                           getLocalWallSlotCb: GetSlotCallback,
                           updateLocalBlocksCb: UpdateLocalBlocksCallback,
                           statusSlots = uint64(SLOTS_PER_EPOCH * 4),
                           responseTimeout = 10.seconds,
                           syncBarrierSlots = uint64(SLOTS_PER_EPOCH * 4),
                           sleepTime = (int(SLOTS_PER_EPOCH) *
                                        int(SECONDS_PER_SLOT)).seconds,
                           chunkSize = uint64(SLOTS_PER_EPOCH)
                           ): SyncManager[A, B] =
  let queue = SyncQueue.init(getLocalHeadSlotCb(), getLocalWallSlotCb(),
                             chunkSize, updateLocalBlocksCb, 2)
  result = SyncManager[A, B](
    pool: pool,
    statusSlots: statusSlots,
    getLocalHeadSlot: getLocalHeadSlotCb,
    updateLocalBlocks: updateLocalBlocksCb,
    getLocalWallSlot: getLocalWallSlotCb,
    responseTimeout: responseTimeout,
    syncBarrierSlots: syncBarrierSlots,
    sleepTime: sleepTime,
    queue: queue
  )

proc getBlocks*[A, B](man: SyncManager[A, B], peer: A,
                      req: SyncRequest): Future[OptionBeaconBlocks] {.async.} =
  mixin beaconBlocksByRange, `==`
  doAssert(not(req.isEmpty()))

  debug "Requesting blocks from peer", peer = $peer,
        slot = $req.slot, slot_count = $req.count, step = $req.step,
        timeout = $man.responseTimeout, topics = "syncman"

  var workFut = beaconBlocksByRange(peer, req.slot, req.count, req.step)
  if man.responseTimeout != InfiniteDuration:
    discard awaitne withTimeout(workFut, man.responseTimeout)
  else:
    discard awaitne workFut

  if not(workFut.finished()):
    debug "Timeout reached, while waiting for getBlocks response", peer = $peer,
          slot = $req.slot, slot_count = $req.count, step = $req.step,
          timeout = $man.responseTimeout, state = $workFut.state,
          topics = "syncman"
    # workFut.cancel()
  else:
    if workFut.failed():
      debug "Error, while waiting getBlocks response", peer = $peer,
            slot = $req.slot, slot_count = $req.count, step = $req.step,
            errMsg = workFut.readError().msg, topics = "syncman"
    else:
      let res = workFut.read()
      if res.isNone():
        debug "Error, while reading getBlocks response",
              peer = $peer, slot = $req.slot, count = $req.count,
              step = $req.step, topics = "syncman"
      result = res

proc syncWorker*[A, B](man: SyncManager[A, B],
                       peer: A): Future[A] {.async.} =
  mixin getKey, getHeadSlot

  debug "Starting syncing with peer", peer = $peer, topics = "syncman"

  try:
    while true:
      var wallSlot = man.getLocalWallSlot()
      var headSlot = man.getLocalHeadSlot()
      var peerSlot = peer.getHeadSlot()

      debug "Peer's syncing status", wall_clock_slot = $wallSlot,
            remote_head_slot = $peerSlot, local_head_slot = $headSlot,
            peer = $peer, topics = "syncman"

      if peerSlot > wallSlot:
        # Our wall timer is broken, or peer's status information is invalid.
        debug "Local timer is broken or peer's status information is invalid",
              wall_clock_slot = $wallSlot, remote_head_slot = $peerSlot,
              local_head_slot = $headSlot, peer = $peer, topics = "syncman"
        break

      if wallSlot - peerSlot >= man.statusSlots:
        # Peer's status information is very old, we going to update it.
        debug "Updating peer's status information", wall_clock_slot = $wallSlot,
              remote_head_slot = $peerSlot, local_head_slot = $headSlot,
              peer = $peer, topics = "syncman"
        let res = await peer.updateStatus()
        if not(res):
          debug "Failed to get remote peer's status", peer = $peer,
                peer_head_slot = $peerSlot, topics = "syncman"
          break

        let newPeerSlot = peer.getHeadSlot()
        if peerSlot >= newPeerSlot:
          debug "Peer's status information is stale, exiting",
                wall_clock_slot = $wallSlot, remote_old_head_slot = $peerSlot,
                local_head_slot = $headSlot,
                remote_new_head_slot = $newPeerSlot,
                peer = $peer, topics = "syncman"
          break

        debug "Peer's status information updated", wall_clock_slot = $wallSlot,
              remote_old_head_slot = $peerSlot, local_head_slot = $headSlot,
              remote_new_head_slot = $newPeerSlot, peer = $peer,
              topics = "syncman"

        peerSlot = newPeerSlot

      man.queue.updateLastSlot(wallSlot)

      if (wallSlot - peerSlot <= man.syncBarrierSlots) and
         (wallSlot - headSlot <= man.syncBarrierSlots):
        debug "We are in sync with peer, exiting", wall_clock_slot = $wallSlot,
              remote_head_slot = $peerSlot, local_head_slot = $headSlot,
              peer = $peer, topics = "syncman"
        break

      let req = man.queue.pop(peerSlot)
      if req.isEmpty():
        debug "Empty request received from queue, exiting", peer = $peer,
              local_head_slot = $headSlot, remote_head_slot = $peerSlot,
              queue_input_slot = $man.queue.inpSlot,
              queue_output_slot = $man.queue.outSlot,
              queue_last_slot = $man.queue.lastSlot,
              topics = "syncman"
        break

      debug "Creating new request for peer", wall_clock_slot = $wallSlot,
            remote_head_slot = $peerSlot, local_head_slot = $headSlot,
            request_slot = $req.slot, request_count = $req.count,
            request_step = $req.step, peer = $peer, topics = "syncman"

      let blocks = await man.getBlocks(peer, req)
      if blocks.isSome():
        let data = blocks.get()
        debug "Received blocks on request", blocks_count = $len(data),
              request_slot = $req.slot, request_count = $req.count,
              request_step = $req.step, peer = $peer, topics = "syncman"
        await man.queue.push(req, data)
      else:
        debug "Failed to receive blocks on request",
              request_slot = $req.slot, request_count = $req.count,
              request_step = $req.step, peer = $peer, topics = "syncman"
        man.queue.push(req)

    result = peer
  finally:
    man.pool.release(peer)

proc sync*[A, B](man: SyncManager[A, B]) {.async.} =
  mixin getKey
  var pending = newSeq[Future[A]]()
  var acquireFut: Future[A]
  var wallSlot, headSlot: Slot

  template workersCount(): string =
    if isNil(acquireFut): $len(pending) else: $(len(pending) - 1)

  template isSyncBarrierReached(): bool =
    wallSlot - headSlot <= man.syncBarrierSlots

  debug "Synchronization loop started", topics = "syncman"

  while true:
    wallSlot = man.getLocalWallSlot()
    headSlot = man.getLocalHeadSlot()

    debug "Synchronization loop start tick", wall_head_slot = $wallSlot,
          local_head_slot = $headSlot,
          workers_count = workersCount(), topics = "syncman"

    if isSyncBarrierReached():
      debug "Synchronization loop sleeping", wall_head_slot = $wallSlot,
              local_head_slot = $headSlot, workers_count = workersCount(),
              difference = $(wallSlot - headSlot),
              barrier = $man.syncBarrierSlots, topics = "syncman"
      if len(pending) == 0:
        await sleepAsync(man.sleepTime)
      else:
        var peerFut = one(pending)
        # We do not care about result here because we going to check peerFut
        # later.
        discard await withTimeout(peerFut, man.sleepTime)
    else:
      if isNil(acquireFut):
        acquireFut = man.pool.acquire()
        pending.add(acquireFut)

      debug "Synchronization loop waiting for new peer",
              wall_head_slot = $wallSlot, local_head_slot = $headSlot,
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
                  wall_head_slot = $wallSlot, local_head_slot = $headSlot,
                  workers_count = workersCount(),
                  errMsg = acquireFut.readError().msg, topics = "syncman"
          else:
            var peer = acquireFut.read()
            if isSyncBarrierReached():
              # If we are already in sync, we going to release just acquired
              # peer and do not acquire peers
              debug "Synchronization loop reached sync barrier", peer = $peer,
                    wall_head_slot = $wallSlot, local_head_slot = $headSlot,
                    topics = "syncman"
              man.pool.release(peer)
            else:
              debug "Synchronization loop starting new worker", peer = $peer,
                    wall_head_slot = $wallSlot, local_head_slot = $headSlot,
                    topics = "syncman"
              temp.add(syncWorker(man, peer))

          acquireFut = nil
          if not(isSyncBarrierReached()):
            acquireFut = man.pool.acquire()
            temp.add(acquireFut)
        else:
          # Worker finished its work
          if fut.failed():
            debug "Synchronization loop got worker finished with an error",
                   wall_head_slot = $wallSlot, local_head_slot = $headSlot,
                   errMsg = fut.readError().msg, topics = "syncman"
          else:
            let peer = fut.read()
            debug "Synchronization loop got worker finished",
                   wall_head_slot = $wallSlot, local_head_slot = $headSlot,
                   peer = $peer, topics = "syncman"
      else:
        if fut == acquireFut:
          if isSyncBarrierReached():
            debug "Synchronization loop reached sync barrier",
                   wall_head_slot = $wallSlot, local_head_slot = $headSlot,
                   topics = "syncman"
            acquireFut = nil
            fut.cancel()
          else:
            temp.add(fut)
        else:
          temp.add(fut)

    pending = temp
    debug "Synchronization loop end tick", wall_head_slot = $wallSlot,
          local_head_slot = $headSlot, workers_count = workersCount(),
          waiting_for_new_peer = $not(isNil(acquireFut)),
          topics = "syncman"
