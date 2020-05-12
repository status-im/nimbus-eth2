import chronicles
import options, deques, heapqueue, tables, strutils, sequtils
import stew/bitseqs, chronos, chronicles
import spec/datatypes, spec/digest, peer_pool
export datatypes, digest, chronos, chronicles

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
    ## Peer' `blocksByRange` answer is fine.

type
  GetSlotCallback* = proc(): Slot {.gcsafe, raises: [Defect].}

  UpdateLocalBlocksCallback* =
    proc(list: openarray[SignedBeaconBlock]): bool {.gcsafe.}

  SyncRequest* = object
    slot*: Slot
    count*: uint64
    step*: uint64

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

  SyncManager*[A, B] = ref object
    pool: PeerPool[A, B]
    responseTimeout: chronos.Duration
    sleepTime: chronos.Duration
    maxStatusAge: uint64
    maxHeadAge: uint64
    toleranceValue: uint64
    getLocalHeadSlot: GetSlotCallback
    getLocalWallSlot: GetSlotCallback
    updateLocalBlocks: UpdateLocalBlocksCallback
    chunkSize: uint64
    queue: SyncQueue

  SyncManagerError* = object of CatchableError
  OptionBeaconBlocks* = Option[seq[SignedBeaconBlock]]

proc getShortMap*(req: SyncRequest,
                  data: openarray[SignedBeaconBlock]): string =
  ## Returns all slot numbers in ``data`` as placement map.
  var res = newStringOfCap(req.count)
  var slider = req.slot
  for i in 0 ..< req.count:
    for item in data.items():
      if slider == item.message.slot:
        res.add('x')
        break
      elif slider < item.message.slot:
        res.add('.')
        break
    slider = slider + req.step
  result = res

proc getFullMap*(req: SyncRequest,
                 data: openarray[SignedBeaconBlock]): string =
  # Returns all slot numbers in ``data`` as comma-delimeted string.
  result = mapIt(data, $it.message.slot).join(", ")

proc init*(t: typedesc[SyncRequest], slot: Slot,
           count: uint64): SyncRequest {.inline.} =
  result = SyncRequest(slot: slot, count: count, step: 1'u64)

proc init*(t: typedesc[SyncRequest], start: Slot,
           finish: Slot): SyncRequest {.inline.} =
  let count = finish - start + 1'u64
  result = SyncRequest(slot: start, count: count, step: 1'u64)

proc empty*(t: typedesc[SyncRequest]): SyncRequest {.inline.} =
  result = SyncRequest(step: 0'u64, count: 0'u64)

proc isEmpty*(sr: SyncRequest): bool {.inline.} =
  result = (sr.step == 0'u64) and (sr.count == 0'u64)

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
    if (sq.queueSize > 0) and
       (sr.slot >= sq.outSlot + uint64(sq.queueSize) * sq.chunkSize):
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
      sq.debtsCount = sq.debtsCount - sr.count
      return sr

    let sr1 = SyncRequest.init(sr.slot, maxslot)
    let sr2 = SyncRequest.init(maxslot + 1'u64, sr.lastSlot())
    sq.debtsQueue.push(sr2)
    sq.debtsCount = sq.debtsCount - sr1.count
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

proc progress*(sq: SyncQueue): uint64 =
  ## Returns queue's ``sq`` progress string.
  let curSlot = sq.outSlot - sq.startSlot
  result = (curSlot * 100'u64) div sq.total()

proc newSyncManager*[A, B](pool: PeerPool[A, B],
                           getLocalHeadSlotCb: GetSlotCallback,
                           getLocalWallSlotCb: GetSlotCallback,
                           updateLocalBlocksCb: UpdateLocalBlocksCallback,
                           maxStatusAge = uint64(SLOTS_PER_EPOCH * 4),
                           maxHeadAge = uint64(SLOTS_PER_EPOCH * 4),
                           sleepTime = (int(SLOTS_PER_EPOCH) *
                                        int(SECONDS_PER_SLOT)).seconds,
                           chunkSize = uint64(SLOTS_PER_EPOCH),
                           toleranceValue = uint64(1)
                           ): SyncManager[A, B] =
  let queue = SyncQueue.init(getLocalHeadSlotCb(), getLocalWallSlotCb(),
                             chunkSize, updateLocalBlocksCb, 2)
  result = SyncManager[A, B](
    pool: pool,
    maxStatusAge: maxStatusAge,
    getLocalHeadSlot: getLocalHeadSlotCb,
    updateLocalBlocks: updateLocalBlocksCb,
    getLocalWallSlot: getLocalWallSlotCb,
    maxHeadAge: maxHeadAge,
    sleepTime: sleepTime,
    chunkSize: chunkSize,
    queue: queue
  )

proc getBlocks*[A, B](man: SyncManager[A, B], peer: A,
                      req: SyncRequest): Future[OptionBeaconBlocks] {.async.} =
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
    if res.isNone():
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
          break

        let newPeerSlot = peer.getHeadSlot()
        if peerSlot >= newPeerSlot:
          debug "Peer's status information is stale, exiting",
                wall_clock_slot = wallSlot, remote_old_head_slot = peerSlot,
                local_head_slot = headSlot,
                remote_new_head_slot = newPeerSlot,
                peer = peer, peer_score = peer.getScore(), topics = "syncman"
          peer.updateScore(PeerScoreStaleStatus)
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

      let req = man.queue.pop(peerSlot)
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
        break

      debug "Creating new request for peer", wall_clock_slot = wallSlot,
            remote_head_slot = peerSlot, local_head_slot = headSlot,
            request_slot = req.slot, request_count = req.count,
            request_step = req.step, peer = peer,
            peer_score = peer.getScore(), topics = "syncman"

      let blocks = await man.getBlocks(peer, req)
      if blocks.isSome():
        let data = blocks.get()
        let smap = getShortMap(req, data)
        debug "Received blocks on request", blocks_count = len(data),
              blocks_map = smap, request_slot = req.slot,
              request_count = req.count, request_step = req.step,
              peer = peer, peer_score = peer.getScore(), topics = "syncman"
        await man.queue.push(req, data)
        debug "Received blocks got accepted", blocks_count = len(data),
              blocks_map = smap, request_slot = req.slot,
              request_count = req.count, request_step = req.step,
              peer = peer, peer_score = peer.getScore(), topics = "syncman"
        peer.updateScore(PeerScoreGoodBlocks)
      else:
        peer.updateScore(PeerScoreNoBlocks)
        man.queue.push(req)
        debug "Failed to receive blocks on request",
              request_slot = req.slot, request_count = req.count,
              request_step = req.step, peer = peer,
              peer_score = peer.getScore(), topics = "syncman"
        break

    result = peer
  finally:
    man.pool.release(peer)

proc sync*[A, B](man: SyncManager[A, B]) {.async.} =
  mixin getKey, getScore
  var pending = newSeq[Future[A]]()
  var acquireFut: Future[A]
  var wallSlot, headSlot: Slot

  template workersCount(): int =
    if isNil(acquireFut): len(pending) else: (len(pending) - 1)

  debug "Synchronization loop started", topics = "syncman"

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
            elif not peer.hasInitialStatus:
              # TODO Don't even consider these peers!
              debug "Peer not ready", peer
              man.pool.release(peer)
              # TODO goes into tight loop without this
              await sleepAsync(RESP_TIMEOUT)
            else:
              if headSlot > man.queue.lastSlot:
                man.queue = SyncQueue.init(headSlot, wallSlot, man.chunkSize,
                                           man.updateLocalBlocks, 2)
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
    debug "Synchronization loop end tick", wall_head_slot = wallSlot,
          local_head_slot = headSlot, workers_count = workersCount(),
          waiting_for_new_peer = $not(isNil(acquireFut)),
          topics = "syncman"
