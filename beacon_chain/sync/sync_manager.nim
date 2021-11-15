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
  ./peer_scores, ./sync_queue

export base, phase0, altair, merge, chronos, chronicles, results,
       block_pools_types, helpers, peer_scores, sync_queue

logScope:
  topics = "syncman"

const
  SyncWorkersCount* = 10
    ## Number of sync workers to spawn

  StatusUpdateInterval* = chronos.minutes(1)
    ## Minimum time between two subsequent calls to update peer's status

  StatusExpirationTime* = chronos.minutes(2)
    ## Time time it takes for the peer's status information to expire.

type
  SyncFailureKind* = enum
    StatusInvalid,
    StatusDownload,
    StatusStale,
    EmptyProblem,
    BlockDownload,
    BadResponse

  SyncWorkerStatus* {.pure.} = enum
    Sleeping, WaitingPeer, UpdatingStatus, Requesting, Downloading, Processing

  SyncWorker*[A, B] = object
    future: Future[void]
    status: SyncWorkerStatus

  SyncManager*[A, B] = ref object
    pool: PeerPool[A, B]
    responseTimeout: chronos.Duration
    sleepTime: chronos.Duration
    maxStatusAge: uint64
    maxHeadAge: uint64
    toleranceValue: uint64
    getLocalHeadSlot: GetSlotCallback
    getLocalWallSlot: GetSlotCallback
    getFinalizedSlot: GetSlotCallback
    workers: array[SyncWorkersCount, SyncWorker[A, B]]
    notInSyncEvent: AsyncEvent
    rangeAge: uint64
    inRangeEvent*: AsyncEvent
    notInRangeEvent*: AsyncEvent
    chunkSize: uint64
    queue: SyncQueue[A]
    syncFut: Future[void]
    blockProcessor: ref BlockProcessor
    inProgress*: bool
    insSyncSpeed*: float
    avgSyncSpeed*: float
    timeLeft*: Duration
    syncCount*: uint64
    syncStatus*: string

  SyncMoment* = object
    stamp*: chronos.Moment
    slot*: Slot

  SyncFailure*[T] = object
    kind*: SyncFailureKind
    peer*: T
    stamp*: chronos.Moment

  SyncManagerError* = object of CatchableError
  BeaconBlocksRes* = NetRes[seq[ForkedSignedBeaconBlock]]

proc init*[T](t1: typedesc[SyncFailure], kind: SyncFailureKind,
              peer: T): SyncFailure[T] =
  SyncFailure[T](kind: kind, peer: peer, stamp: now(chronos.Moment))

proc now*(sm: typedesc[SyncMoment], slot: Slot): SyncMoment {.inline.} =
  SyncMoment(stamp: now(chronos.Moment), slot: slot)

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
                           getFinalizedSlotCb: GetSlotCallback,
                           blockProcessor: ref BlockProcessor,
                           maxStatusAge = uint64(SLOTS_PER_EPOCH * 4),
                           maxHeadAge = uint64(SLOTS_PER_EPOCH * 1),
                           sleepTime = (int(SLOTS_PER_EPOCH) *
                                        int(SECONDS_PER_SLOT)).seconds,
                           chunkSize = uint64(SLOTS_PER_EPOCH),
                           toleranceValue = uint64(1),
                           rangeAge = uint64(SLOTS_PER_EPOCH * 4)
                           ): SyncManager[A, B] =

  let queue = SyncQueue.init(A, SyncQueueKind.Forward, getLocalHeadSlotCb(),
                             getLocalWallSlotCb(), chunkSize,
                             getFinalizedSlotCb, blockProcessor, 1)

  result = SyncManager[A, B](
    pool: pool,
    maxStatusAge: maxStatusAge,
    getLocalHeadSlot: getLocalHeadSlotCb,
    getLocalWallSlot: getLocalWallSlotCb,
    getFinalizedSlot: getFinalizedSlotCb,
    maxHeadAge: maxHeadAge,
    sleepTime: sleepTime,
    chunkSize: chunkSize,
    queue: queue,
    blockProcessor: blockProcessor,
    notInSyncEvent: newAsyncEvent(),
    inRangeEvent: newAsyncEvent(),
    notInRangeEvent: newAsyncEvent(),
    rangeAge: rangeAge
  )

proc getBlocks*[A, B](man: SyncManager[A, B], peer: A,
                      req: SyncRequest): Future[BeaconBlocksRes] {.async.} =
  mixin beaconBlocksByRange, getScore, `==`
  doAssert(not(req.isEmpty()), "Request must not be empty!")
  debug "Requesting blocks from peer", peer = peer,
        slot = req.slot, slot_count = req.count, step = req.step,
        peer_score = peer.getScore(), peer_speed = peer.netKbps(),
        topics = "syncman"
  if peer.useSyncV2():
    var workFut = awaitne beaconBlocksByRange_v2(peer, req.slot, req.count, req.step)
    if workFut.failed():
      debug "Error, while waiting getBlocks response", peer = peer,
            slot = req.slot, slot_count = req.count, step = req.step,
            errMsg = workFut.readError().msg, peer_speed = peer.netKbps(),
            topics = "syncman"
    else:
      let res = workFut.read()
      if res.isErr:
        debug "Error, while reading getBlocks response",
              peer = peer, slot = req.slot, count = req.count,
              step = req.step, peer_speed = peer.netKbps(),
              topics = "syncman", error = $res.error()
      result = res
  else:
    var workFut = awaitne beaconBlocksByRange(peer, req.slot, req.count, req.step)
    if workFut.failed():
      debug "Error, while waiting getBlocks response", peer = peer,
            slot = req.slot, slot_count = req.count, step = req.step,
            errMsg = workFut.readError().msg, peer_speed = peer.netKbps(),
            topics = "syncman"
    else:
      let res = workFut.read()
      if res.isErr:
        debug "Error, while reading getBlocks response",
              peer = peer, slot = req.slot, count = req.count,
              step = req.step, peer_speed = peer.netKbps(),
              topics = "syncman", error = $res.error()
      result = res.map() do (blcks: seq[phase0.SignedBeaconBlock]) -> auto: blcks.mapIt(ForkedSignedBeaconBlock.init(it))

template headAge(): uint64 =
  wallSlot - headSlot

template queueAge(): uint64 =
  wallSlot - man.queue.outSlot

template peerStatusAge(): Duration =
  Moment.now() - peer.state(BeaconSync).statusLastTime

proc syncStep[A, B](man: SyncManager[A, B], index: int, peer: A) {.async.} =
  let wallSlot = man.getLocalWallSlot()
  let headSlot = man.getLocalHeadSlot()
  var peerSlot = peer.getHeadSlot()

  # We updating SyncQueue's last slot all the time
  man.queue.updateLastSlot(wallSlot)

  debug "Peer's syncing status", wall_clock_slot = wallSlot,
        remote_head_slot = peerSlot, local_head_slot = headSlot,
        peer_score = peer.getScore(), peer = peer, index = index,
        peer_speed = peer.netKbps(), topics = "syncman"

  # Check if peer's head slot is bigger than our wall clock slot.
  if peerSlot > wallSlot + man.toleranceValue:
    warn "Local timer is broken or peer's status information is invalid",
          wall_clock_slot = wallSlot, remote_head_slot = peerSlot,
          local_head_slot = headSlot, peer = peer, index = index,
          tolerance_value = man.toleranceValue, peer_speed = peer.netKbps(),
          peer_score = peer.getScore(), topics = "syncman"
    discard SyncFailure.init(SyncFailureKind.StatusInvalid, peer)
    return

  # Check if we need to update peer's status information
  if peerStatusAge >= StatusExpirationTime:
    # Peer's status information is very old, its time to update it
    man.workers[index].status = SyncWorkerStatus.UpdatingStatus
    trace "Updating peer's status information", wall_clock_slot = wallSlot,
          remote_head_slot = peerSlot, local_head_slot = headSlot,
          peer = peer, peer_score = peer.getScore(), index = index,
          peer_speed = peer.netKbps(), topics = "syncman"

    try:
      let res = await peer.updateStatus()
      if not(res):
        peer.updateScore(PeerScoreNoStatus)
        debug "Failed to get remote peer's status, exiting", peer = peer,
              peer_score = peer.getScore(), peer_head_slot = peerSlot,
              peer_speed = peer.netKbps(), index = index, topics = "syncman"
        discard SyncFailure.init(SyncFailureKind.StatusDownload, peer)
        return
    except CatchableError as exc:
      debug "Unexpected exception while updating peer's status",
            peer = peer, peer_score = peer.getScore(),
            peer_head_slot = peerSlot, peer_speed = peer.netKbps(),
            index = index, errMsg = exc.msg, topics = "syncman"
      return

    let newPeerSlot = peer.getHeadSlot()
    if peerSlot >= newPeerSlot:
      peer.updateScore(PeerScoreStaleStatus)
      debug "Peer's status information is stale",
            wall_clock_slot = wallSlot, remote_old_head_slot = peerSlot,
            local_head_slot = headSlot, remote_new_head_slot = newPeerSlot,
            peer = peer, peer_score = peer.getScore(), index = index,
            peer_speed = peer.netKbps(), topics = "syncman"
    else:
      debug "Peer's status information updated", wall_clock_slot = wallSlot,
            remote_old_head_slot = peerSlot, local_head_slot = headSlot,
            remote_new_head_slot = newPeerSlot, peer = peer,
            peer_score = peer.getScore(), peer_speed = peer.netKbps(),
            index = index, topics = "syncman"
      peer.updateScore(PeerScoreGoodStatus)
      peerSlot = newPeerSlot

  if headAge <= man.maxHeadAge:
    info "We are in sync with network", wall_clock_slot = wallSlot,
          remote_head_slot = peerSlot, local_head_slot = headSlot,
          peer = peer, peer_score = peer.getScore(), index = index,
          peer_speed = peer.netKbps(), topics = "syncman"
    # We clear SyncManager's `notInSyncEvent` so all the workers will become
    # sleeping soon.
    man.notInSyncEvent.clear()
    return

  if headSlot >= peerSlot - man.maxHeadAge:
    debug "We are in sync with peer; refreshing peer's status information",
          wall_clock_slot = wallSlot, remote_head_slot = peerSlot,
          local_head_slot = headSlot, peer = peer, peer_score = peer.getScore(),
          index = index, peer_speed = peer.netKbps(), topics = "syncman"

    man.workers[index].status = SyncWorkerStatus.UpdatingStatus

    if peerStatusAge <= StatusUpdateInterval:
      await sleepAsync(StatusUpdateInterval - peerStatusAge)

    try:
      let res = await peer.updateStatus()
      if not(res):
        peer.updateScore(PeerScoreNoStatus)
        debug "Failed to get remote peer's status, exiting", peer = peer,
              peer_score = peer.getScore(), peer_head_slot = peerSlot,
              peer_speed = peer.netKbps(), index = index, topics = "syncman"
        discard SyncFailure.init(SyncFailureKind.StatusDownload, peer)
        return
    except CatchableError as exc:
      debug "Unexpected exception while updating peer's status",
            peer = peer, peer_score = peer.getScore(),
            peer_head_slot = peerSlot, peer_speed = peer.netKbps(),
            index = index, errMsg = exc.msg, topics = "syncman"
      return

    let newPeerSlot = peer.getHeadSlot()
    if peerSlot >= newPeerSlot:
      peer.updateScore(PeerScoreStaleStatus)
      debug "Peer's status information is stale",
            wall_clock_slot = wallSlot, remote_old_head_slot = peerSlot,
            local_head_slot = headSlot, remote_new_head_slot = newPeerSlot,
            peer = peer, peer_score = peer.getScore(), index = index,
            peer_speed = peer.netKbps(), topics = "syncman"
    else:
      # This is not very good solution because we should not discriminate and/or
      # penalize peers which are in sync process too, but their latest head is
      # lower then our latest head. We should keep connections with such peers
      # (so this peers are able to get in sync using our data), but we should
      # not use this peers for syncing because this peers are useless for us.
      # Right now we decreasing peer's score a bit, so it will not be
      # disconnected due to low peer's score, but new fresh peers could replace
      # peers with low latest head.
      if headSlot >= newPeerSlot - man.maxHeadAge:
        # Peer's head slot is still lower then ours.
        debug "Peer's head slot is lower then local head slot",
              wall_clock_slot = wallSlot, remote_old_head_slot = peerSlot,
              local_head_slot = headSlot, remote_new_head_slot = newPeerSlot,
              peer = peer, peer_score = peer.getScore(),
              peer_speed = peer.netKbps(), index = index, topics = "syncman"
        peer.updateScore(PeerScoreUseless)
      else:
        debug "Peer's status information updated", wall_clock_slot = wallSlot,
              remote_old_head_slot = peerSlot, local_head_slot = headSlot,
              remote_new_head_slot = newPeerSlot, peer = peer,
              peer_score = peer.getScore(), peer_speed = peer.netKbps(),
              index = index, topics = "syncman"
        peer.updateScore(PeerScoreGoodStatus)
        peerSlot = newPeerSlot

    return

  man.workers[index].status = SyncWorkerStatus.Requesting
  let req = man.queue.pop(peerSlot, peer)
  if req.isEmpty():
    # SyncQueue could return empty request in 2 cases:
    # 1. There no more slots in SyncQueue to download (we are synced, but
    #    our ``notInSyncEvent`` is not yet cleared).
    # 2. Current peer's known head slot is too low to satisfy request.
    #
    # To avoid endless loop we going to wait for RESP_TIMEOUT time here.
    # This time is enough for all pending requests to finish and it is also
    # enough for main sync loop to clear ``notInSyncEvent``.
    debug "Empty request received from queue, exiting", peer = peer,
          local_head_slot = headSlot, remote_head_slot = peerSlot,
          queue_input_slot = man.queue.inpSlot,
          queue_output_slot = man.queue.outSlot,
          queue_last_slot = man.queue.finalSlot,
          peer_speed = peer.netKbps(), peer_score = peer.getScore(),
          index = index, topics = "syncman"
    await sleepAsync(RESP_TIMEOUT)
    return

  debug "Creating new request for peer", wall_clock_slot = wallSlot,
        remote_head_slot = peerSlot, local_head_slot = headSlot,
        request_slot = req.slot, request_count = req.count,
        request_step = req.step, peer = peer, peer_speed = peer.netKbps(),
        peer_score = peer.getScore(), index = index, topics = "syncman"

  man.workers[index].status = SyncWorkerStatus.Downloading

  try:
    let blocks = await man.getBlocks(peer, req)
    if blocks.isOk:
      let data = blocks.get()
      let smap = getShortMap(req, data)
      debug "Received blocks on request", blocks_count = len(data),
            blocks_map = smap, request_slot = req.slot,
            request_count = req.count, request_step = req.step,
            peer = peer, peer_score = peer.getScore(),
            peer_speed = peer.netKbps(), index = index, topics = "syncman"

      if not(checkResponse(req, data)):
        peer.updateScore(PeerScoreBadResponse)
        warn "Received blocks sequence is not in requested range",
             blocks_count = len(data), blocks_map = smap,
             request_slot = req.slot, request_count = req.count,
             request_step = req.step, peer = peer,
             peer_score = peer.getScore(), peer_speed = peer.netKbps(),
             index = index, topics = "syncman"
        discard SyncFailure.init(SyncFailureKind.BadResponse, peer)
        return

      # Scoring will happen in `syncUpdate`.
      man.workers[index].status = SyncWorkerStatus.Processing
      await man.queue.push(req, data)
    else:
      peer.updateScore(PeerScoreNoBlocks)
      man.queue.push(req)
      debug "Failed to receive blocks on request",
            request_slot = req.slot, request_count = req.count,
            request_step = req.step, peer = peer, index = index,
            peer_score = peer.getScore(), peer_speed = peer.netKbps(),
            topics = "syncman"
      discard SyncFailure.init(SyncFailureKind.BlockDownload, peer)
      return

  except CatchableError as exc:
    debug "Unexpected exception while receiving blocks",
            request_slot = req.slot, request_count = req.count,
            request_step = req.step, peer = peer, index = index,
            peer_score = peer.getScore(), peer_speed = peer.netKbps(),
            errMsg = exc.msg, topics = "syncman"
    return

proc syncWorker[A, B](man: SyncManager[A, B], index: int) {.async.} =
  mixin getKey, getScore, getHeadSlot

  debug "Starting syncing worker", index = index, topics = "syncman"

  while true:
    man.workers[index].status = SyncWorkerStatus.Sleeping
    # This event is going to be set until we are not in sync with network
    await man.notInSyncEvent.wait()
    man.workers[index].status = SyncWorkerStatus.WaitingPeer
    let peer = await man.pool.acquire()
    await man.syncStep(index, peer)
    man.pool.release(peer)

proc getWorkersStats[A, B](man: SyncManager[A, B]): tuple[map: string,
                                                          sleeping: int,
                                                          waiting: int,
                                                          pending: int] =
  var map = newString(len(man.workers))
  var sleeping, waiting, pending: int
  for i in 0 ..< len(man.workers):
    var ch: char
    case man.workers[i].status
      of SyncWorkerStatus.Sleeping:
        ch = 's'
        inc(sleeping)
      of SyncWorkerStatus.WaitingPeer:
        ch = 'w'
        inc(waiting)
      of SyncWorkerStatus.UpdatingStatus:
        ch = 'U'
        inc(pending)
      of SyncWorkerStatus.Requesting:
        ch = 'R'
        inc(pending)
      of SyncWorkerStatus.Downloading:
        ch = 'D'
        inc(pending)
      of SyncWorkerStatus.Processing:
        ch = 'P'
        inc(pending)
    map[i] = ch
  (map, sleeping, waiting, pending)

proc guardTask[A, B](man: SyncManager[A, B]) {.async.} =
  var pending: array[SyncWorkersCount, Future[void]]

  # Starting all the synchronization workers.
  for i in 0 ..< len(man.workers):
    let future = syncWorker[A, B](man, i)
    man.workers[i].future = future
    pending[i] = future

  # Wait for synchronization worker's failure and replace it with new one.
  while true:
    let failFuture = await one(pending)
    let index = pending.find(failFuture)
    if failFuture.failed():
      warn "Synchronization worker stopped working unexpectedly with an error",
            index = index, errMsg = failFuture.error.msg
    else:
      warn "Synchronization worker stopped working unexpectedly without error",
            index = index

    let future = syncWorker[A, B](man, index)
    man.workers[index].future = future
    pending[index] = future

proc toTimeLeftString(d: Duration): string =
  var v = d
  var res = ""
  let ndays = chronos.days(v)
  if ndays > 0:
    res = res & (if ndays < 10: "0" & $ndays else: $ndays) & "d"
    v = v - chronos.days(ndays)

  let nhours = chronos.hours(v)
  if nhours > 0:
    res = res & (if nhours < 10: "0" & $nhours else: $nhours) & "h"
    v = v - chronos.hours(nhours)
  else:
    res =  res & "00h"

  let nmins = chronos.minutes(v)
  if nmins > 0:
    res = res & (if nmins < 10: "0" & $nmins else: $nmins) & "m"
    v = v - chronos.minutes(nmins)
  else:
    res = res & "00m"
  res

proc syncLoop[A, B](man: SyncManager[A, B]) {.async.} =
  mixin getKey, getScore
  var pauseTime = 0

  asyncSpawn man.guardTask()

  debug "Synchronization loop started", topics = "syncman"

  proc averageSpeedTask() {.async.} =
    while true:
      let wallSlot = man.getLocalWallSlot()
      let headSlot = man.getLocalHeadSlot()
      let lsm1 = SyncMoment.now(man.getLocalHeadSlot())
      await sleepAsync(chronos.seconds(int(SECONDS_PER_SLOT)))
      let lsm2 = SyncMoment.now(man.getLocalHeadSlot())
      let bps =
        if lsm2.slot - lsm1.slot == 0'u64:
          0.0
        else:
          speed(lsm1, lsm2)
      inc(man.syncCount)
      man.insSyncSpeed = bps
      man.avgSyncSpeed = man.avgSyncSpeed +
                         (bps - man.avgSyncSpeed) / float(man.syncCount)
      let nsec = (float(wallSlot - headSlot) / man.avgSyncSpeed) *
                 1_000_000_000.0
      man.timeLeft = chronos.nanoseconds(int64(nsec))

  asyncSpawn averageSpeedTask()

  while true:
    let wallSlot = man.getLocalWallSlot()
    let headSlot = man.getLocalHeadSlot()

    let (map, sleeping, waiting, pending) = man.getWorkersStats()

    debug "Current syncing state", workers_map = map,
          sleeping_workers_count = sleeping,
          waiting_workers_count = waiting,
          pending_workers_count = pending,
          wall_head_slot = wallSlot, local_head_slot = headSlot,
          pause_time = $chronos.seconds(pauseTime),
          avg_sync_speed = man.avgSyncSpeed, ins_sync_speed = man.insSyncSpeed,
          topics = "syncman"

    # Update status string
    man.syncStatus = map & ":" & $pending & ":" &
                     man.avgSyncSpeed.formatBiggestFloat(ffDecimal, 4) & ":" &
                     man.timeLeft.toTimeLeftString() &
                     " (" & $man.queue.outSlot & ")"

    if headAge <= man.maxHeadAge:
      man.notInSyncEvent.clear()
      # We are marking SyncManager as not working only when we are in sync and
      # all sync workers are in `Sleeping` state.
      if pending > 0:
        debug "Synchronization loop waits for workers completion",
              wall_head_slot = wallSlot, local_head_slot = headSlot,
              difference = (wallSlot - headSlot), max_head_age = man.maxHeadAge,
              sleeping_workers_count = sleeping,
              waiting_workers_count = waiting, pending_workers_count = pending,
              topics = "syncman"
        man.inProgress = true
      else:
        debug "Synchronization loop sleeping", wall_head_slot = wallSlot,
              local_head_slot = headSlot, difference = (wallSlot - headSlot),
              max_head_age = man.maxHeadAge, topics = "syncman"
        man.inProgress = false
    else:
      if not(man.notInSyncEvent.isSet()):
        # We get here only if we lost sync for more then `maxHeadAge` period.
        if pending == 0:
          man.queue = SyncQueue.init(A, SyncQueueKind.Forward,
                                     man.getLocalHeadSlot(),
                                     man.getLocalWallSlot(),
                                     man.chunkSize, man.getFinalizedSlot,
                                     man.blockProcessor, 1)
          man.notInSyncEvent.fire()
          man.inProgress = true
      else:
        man.notInSyncEvent.fire()
        man.inProgress = true

    if queueAge <= man.rangeAge:
      # We are in requested range ``man.rangeAge``.
      man.inRangeEvent.fire()
      man.notInRangeEvent.clear()
    else:
      # We are not in requested range anymore ``man.rangeAge``.
      man.inRangeEvent.clear()
      man.notInRangeEvent.fire()

    await sleepAsync(chronos.seconds(2))

proc start*[A, B](man: SyncManager[A, B]) =
  ## Starts SyncManager's main loop.
  man.syncFut = man.syncLoop()

proc getInfo*[A, B](man: SyncManager[A, B]): RpcSyncInfo =
  ## Returns current synchronization information for RPC call.
  let wallSlot = man.getLocalWallSlot()
  let headSlot = man.getLocalHeadSlot()
  let sync_distance = wallSlot - headSlot
  (
    head_slot: headSlot,
    sync_distance: sync_distance,
    is_syncing: man.inProgress
  )
