# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import std/[options, heapqueue, tables, strutils, sequtils, algorithm]
import stew/[results, base10], chronos, chronicles
import
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/rest_types,
  ../spec/[helpers, forks, network],
  ../networking/[peer_pool, peer_scores, eth2_network],
  ../beacon_clock,
  "."/[sync_protocol, sync_queue]

export phase0, altair, merge, chronos, chronicles, results,
       helpers, peer_scores, sync_queue, forks, sync_protocol

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
  SyncWorkerStatus* {.pure.} = enum
    Sleeping, WaitingPeer, UpdatingStatus, Requesting, Downloading, Queueing,
    Processing

  SyncManagerFlag* {.pure.} = enum
    NoMonitor

  SyncWorker*[A, B] = object
    future: Future[void]
    status: SyncWorkerStatus

  SyncManager*[A, B] = ref object
    pool: PeerPool[A, B]
    responseTimeout: chronos.Duration
    maxHeadAge: uint64
    getLocalHeadSlot: GetSlotCallback
    getLocalWallSlot: GetSlotCallback
    getSafeSlot: GetSlotCallback
    getFirstSlot: GetSlotCallback
    getLastSlot: GetSlotCallback
    progressPivot: Slot
    workers: array[SyncWorkersCount, SyncWorker[A, B]]
    notInSyncEvent: AsyncEvent
    rangeAge: uint64
    chunkSize: uint64
    queue: SyncQueue[A]
    syncFut: Future[void]
    blockVerifier: BlockVerifier
    inProgress*: bool
    insSyncSpeed*: float
    avgSyncSpeed*: float
    syncStatus*: string
    direction: SyncQueueKind
    ident*: string
    flags: set[SyncManagerFlag]

  SyncMoment* = object
    stamp*: chronos.Moment
    slots*: uint64

  SyncManagerError* = object of CatchableError
  BeaconBlocksRes* = NetRes[seq[ref ForkedSignedBeaconBlock]]

proc now*(sm: typedesc[SyncMoment], slots: uint64): SyncMoment {.inline.} =
  SyncMoment(stamp: now(chronos.Moment), slots: slots)

proc speed*(start, finish: SyncMoment): float {.inline.} =
  ## Returns number of slots per second.
  if finish.slots <= start.slots or finish.stamp <= start.stamp:
    0.0 # replays for example
  else:
    let
      slots = float(finish.slots - start.slots)
      dur = toFloatSeconds(finish.stamp - start.stamp)
    slots / dur

proc initQueue[A, B](man: SyncManager[A, B]) =
  case man.direction
  of SyncQueueKind.Forward:
    man.queue = SyncQueue.init(A, man.direction, man.getFirstSlot(),
                               man.getLastSlot(), man.chunkSize,
                               man.getSafeSlot, man.blockVerifier, 1,
                               man.ident)
  of SyncQueueKind.Backward:
    let
      firstSlot = man.getFirstSlot()
      lastSlot = man.getLastSlot()
      startSlot = if firstSlot == lastSlot:
                    # This case should never be happened in real life because
                    # there is present check `needsBackfill().
                    firstSlot
                  else:
                    Slot(firstSlot - 1'u64)
    man.queue = SyncQueue.init(A, man.direction, startSlot, lastSlot,
                               man.chunkSize, man.getSafeSlot,
                               man.blockVerifier, 1,
                               man.ident)

proc newSyncManager*[A, B](pool: PeerPool[A, B],
                           direction: SyncQueueKind,
                           getLocalHeadSlotCb: GetSlotCallback,
                           getLocalWallSlotCb: GetSlotCallback,
                           getFinalizedSlotCb: GetSlotCallback,
                           getBackfillSlotCb: GetSlotCallback,
                           getFrontfillSlotCb: GetSlotCallback,
                           progressPivot: Slot,
                           blockVerifier: BlockVerifier,
                           maxHeadAge = uint64(SLOTS_PER_EPOCH * 1),
                           chunkSize = uint64(SLOTS_PER_EPOCH),
                           flags: set[SyncManagerFlag] = {},
                           ident = "main"
                           ): SyncManager[A, B] =
  let (getFirstSlot, getLastSlot, getSafeSlot) = case direction
  of SyncQueueKind.Forward:
    (getLocalHeadSlotCb, getLocalWallSlotCb, getFinalizedSlotCb)
  of SyncQueueKind.Backward:
    (getBackfillSlotCb, getFrontfillSlotCb, getBackfillSlotCb)

  var res = SyncManager[A, B](
    pool: pool,
    getLocalHeadSlot: getLocalHeadSlotCb,
    getLocalWallSlot: getLocalWallSlotCb,
    getSafeSlot: getSafeSlot,
    getFirstSlot: getFirstSlot,
    getLastSlot: getLastSlot,
    progressPivot: progressPivot,
    maxHeadAge: maxHeadAge,
    chunkSize: chunkSize,
    blockVerifier: blockVerifier,
    notInSyncEvent: newAsyncEvent(),
    direction: direction,
    ident: ident,
    flags: flags
  )
  res.initQueue()
  res

proc getBlocks*[A, B](man: SyncManager[A, B], peer: A,
                      req: SyncRequest): Future[BeaconBlocksRes] {.async.} =
  mixin beaconBlocksByRange, getScore, `==`

  logScope:
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    sync_ident = man.ident
    direction = man.direction
    topics = "syncman"

  doAssert(not(req.isEmpty()), "Request must not be empty!")
  debug "Requesting blocks from peer", request = req
  try:
    let res =
      if peer.useSyncV2():
        await beaconBlocksByRange_v2(peer, req.slot, req.count, 1'u64)
      else:
        (await beaconBlocksByRange(peer, req.slot, req.count, 1'u64)).map(
          proc(blcks: seq[phase0.SignedBeaconBlock]): auto =
            blcks.mapIt(newClone(ForkedSignedBeaconBlock.init(it))))

    if res.isErr():
      debug "Error, while reading getBlocks response", request = req,
             error = $res.error()
      return
    return res
  except CancelledError:
    debug "Interrupt, while waiting getBlocks response", request = req
    return
  except CatchableError as exc:
    debug "Error, while waiting getBlocks response", request = req,
          errName = exc.name, errMsg = exc.msg
    return

proc remainingSlots(man: SyncManager): uint64 =
  if man.direction == SyncQueueKind.Forward:
    man.getLastSlot() - man.getFirstSlot()
  else:
    man.getFirstSlot() - man.getLastSlot()

proc syncStep[A, B](man: SyncManager[A, B], index: int, peer: A) {.async.} =
  logScope:
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    index = index
    sync_ident = man.ident
    topics = "syncman"

  var
    headSlot = man.getLocalHeadSlot()
    wallSlot = man.getLocalWallSlot()
    peerSlot = peer.getHeadSlot()

  block: # Check that peer status is recent and relevant
    logScope:
      peer = peer
      direction = man.direction

    debug "Peer's syncing status", wall_clock_slot = wallSlot,
          remote_head_slot = peerSlot, local_head_slot = headSlot

    let
      peerStatusAge = Moment.now() - peer.state(BeaconSync).statusLastTime
      needsUpdate =
        # Latest status we got is old
        peerStatusAge >= StatusExpirationTime or
        # The point we need to sync is close to where the peer is
        man.getFirstSlot() >= peerSlot

    if needsUpdate:
      man.workers[index].status = SyncWorkerStatus.UpdatingStatus

      # Avoid a stampede of requests, but make them more frequent in case the
      # peer is "close" to the slot range of interest
      if peerStatusAge < StatusExpirationTime div 2:
        await sleepAsync(StatusExpirationTime div 2 - peerStatusAge)

      trace "Updating peer's status information", wall_clock_slot = wallSlot,
            remote_head_slot = peerSlot, local_head_slot = headSlot

      try:
        let res = await peer.updateStatus()
        if not(res):
          peer.updateScore(PeerScoreNoStatus)
          debug "Failed to get remote peer's status, exiting",
                peer_head_slot = peerSlot

          return
      except CatchableError as exc:
        debug "Unexpected exception while updating peer's status",
              peer_head_slot = peerSlot, errName = exc.name, errMsg = exc.msg
        return

      let newPeerSlot = peer.getHeadSlot()
      if peerSlot >= newPeerSlot:
        peer.updateScore(PeerScoreStaleStatus)
        debug "Peer's status information is stale",
              wall_clock_slot = wallSlot, remote_old_head_slot = peerSlot,
              local_head_slot = headSlot, remote_new_head_slot = newPeerSlot
      else:
        debug "Peer's status information updated", wall_clock_slot = wallSlot,
              remote_old_head_slot = peerSlot, local_head_slot = headSlot,
              remote_new_head_slot = newPeerSlot
        peer.updateScore(PeerScoreGoodStatus)
        peerSlot = newPeerSlot

    # Time passed - enough to move slots, if sleep happened
    headSlot = man.getLocalHeadSlot()
    wallSlot = man.getLocalWallSlot()

  if man.remainingSlots() <= man.maxHeadAge:
    logScope:
      peer = peer
      direction = man.direction

    case man.direction
    of SyncQueueKind.Forward:
      info "We are in sync with network", wall_clock_slot = wallSlot,
            remote_head_slot = peerSlot, local_head_slot = headSlot
    of SyncQueueKind.Backward:
      info "Backfill complete", wall_clock_slot = wallSlot,
            remote_head_slot = peerSlot, local_head_slot = headSlot

    # We clear SyncManager's `notInSyncEvent` so all the workers will become
    # sleeping soon.
    man.notInSyncEvent.clear()
    return

  # Find out if the peer potentially can give useful blocks - in the case of
  # forward sync, they can be useful if they have blocks newer than our head -
  # in the case of backwards sync, they're useful if they have blocks newer than
  # the backfill point
  if man.getFirstSlot() >= peerSlot:
    # This is not very good solution because we should not discriminate and/or
    # penalize peers which are in sync process too, but their latest head is
    # lower then our latest head. We should keep connections with such peers
    # (so this peers are able to get in sync using our data), but we should
    # not use this peers for syncing because this peers are useless for us.
    # Right now we decreasing peer's score a bit, so it will not be
    # disconnected due to low peer's score, but new fresh peers could replace
    # peers with low latest head.
    debug "Peer's head slot is lower then local head slot", peer = peer,
          wall_clock_slot = wallSlot, remote_head_slot = peerSlot,
          local_last_slot = man.getLastSlot(),
          local_first_slot = man.getFirstSlot(),
          direction = man.direction
    peer.updateScore(PeerScoreUseless)
    return

  if man.direction == SyncQueueKind.Forward:
    # Wall clock keeps ticking, so we need to update the queue
    man.queue.updateLastSlot(man.getLastSlot())

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
          queue_last_slot = man.queue.finalSlot, direction = man.direction
    await sleepAsync(RESP_TIMEOUT)
    return

  debug "Creating new request for peer", wall_clock_slot = wallSlot,
        remote_head_slot = peerSlot, local_head_slot = headSlot,
        request = req

  man.workers[index].status = SyncWorkerStatus.Downloading

  try:
    let blocks = await man.getBlocks(peer, req)
    if blocks.isOk():
      let data = blocks.get()
      let smap = getShortMap(req, data)
      debug "Received blocks on request", blocks_count = len(data),
            blocks_map = smap, request = req

      if not(checkResponse(req, data)):
        peer.updateScore(PeerScoreBadResponse)
        warn "Received blocks sequence is not in requested range",
             blocks_count = len(data), blocks_map = smap,
             request = req
        return

      # Scoring will happen in `syncUpdate`.
      man.workers[index].status = SyncWorkerStatus.Queueing
      await man.queue.push(req, data, proc() =
        man.workers[index].status = SyncWorkerStatus.Processing)
    else:
      peer.updateScore(PeerScoreNoBlocks)
      man.queue.push(req)
      debug "Failed to receive blocks on request", request = req
      return

  except CatchableError as exc:
    debug "Unexpected exception while receiving blocks", request = req,
          errName = exc.name, errMsg = exc.msg
    return

proc syncWorker[A, B](man: SyncManager[A, B], index: int) {.async.} =
  mixin getKey, getScore, getHeadSlot

  logScope:
    index = index
    sync_ident = man.ident
    direction = man.direction
    topics = "syncman"

  debug "Starting syncing worker"

  while true:
    var peer: A = nil
    let doBreak =
      try:
        man.workers[index].status = SyncWorkerStatus.Sleeping
        # This event is going to be set until we are not in sync with network
        await man.notInSyncEvent.wait()
        man.workers[index].status = SyncWorkerStatus.WaitingPeer
        peer = await man.pool.acquire()
        await man.syncStep(index, peer)
        man.pool.release(peer)
        false
      except CancelledError:
        if not(isNil(peer)):
          man.pool.release(peer)
        true
      except CatchableError as exc:
        debug "Unexpected exception in sync worker",
              peer = peer, peer_score = peer.getScore(),
              peer_speed = peer.netKbps(),
              errName = exc.name, errMsg = exc.msg
        true
    if doBreak:
      break

  debug "Sync worker stopped"

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
      of SyncWorkerStatus.Queueing:
        ch = 'Q'
        inc(pending)
      of SyncWorkerStatus.Processing:
        ch = 'P'
        inc(pending)
    map[i] = ch
  (map, sleeping, waiting, pending)

proc guardTask[A, B](man: SyncManager[A, B]) {.async.} =
  logScope:
    index = index
    sync_ident = man.ident
    direction = man.direction
    topics = "syncman"

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
            errName = failFuture.error.name, errMsg = failFuture.error.msg
    else:
      warn "Synchronization worker stopped working unexpectedly without error"

    let future = syncWorker[A, B](man, index)
    man.workers[index].future = future
    pending[index] = future

proc toTimeLeftString*(d: Duration): string =
  if d == InfiniteDuration:
    "--h--m"
  else:
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

proc syncClose[A, B](man: SyncManager[A, B], guardTaskFut: Future[void],
                     speedTaskFut: Future[void]) {.async.} =
  guardTaskFut.cancel()
  speedTaskFut.cancel()
  await allFutures(guardTaskFut, speedTaskFut)
  let pendingTasks =
    block:
      var res: seq[Future[void]]
      for worker in man.workers:
        doAssert(worker.status in {Sleeping, WaitingPeer})
        worker.future.cancel()
        res.add(worker.future)
      res
  await allFutures(pendingTasks)

proc syncLoop[A, B](man: SyncManager[A, B]) {.async.} =
  logScope:
    sync_ident = man.ident
    direction = man.direction
    topics = "syncman"

  mixin getKey, getScore
  var pauseTime = 0

  var guardTaskFut = man.guardTask()

  debug "Synchronization loop started"

  proc averageSpeedTask() {.async.} =
    while true:
      # Reset sync speeds between each loss-of-sync event
      man.avgSyncSpeed = 0
      man.insSyncSpeed = 0

      await man.notInSyncEvent.wait()

      # Give the node time to connect to peers and get the sync process started
      await sleepAsync(seconds(SECONDS_PER_SLOT.int64))

      var
        stamp = SyncMoment.now(man.queue.progress())
        syncCount = 0

      while man.inProgress:
        await sleepAsync(seconds(SECONDS_PER_SLOT.int64))

        let
          newStamp = SyncMoment.now(man.queue.progress())
          slotsPerSec = speed(stamp, newStamp)

        syncCount += 1

        man.insSyncSpeed = slotsPerSec
        man.avgSyncSpeed =
          man.avgSyncSpeed + (slotsPerSec - man.avgSyncSpeed) / float(syncCount)

        stamp = newStamp

  var averageSpeedTaskFut = averageSpeedTask()

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
          avg_sync_speed = man.avgSyncSpeed, ins_sync_speed = man.insSyncSpeed

    let
      pivot = man.progressPivot
      progress =
        case man.queue.kind
        of SyncQueueKind.Forward:
          man.queue.outSlot - pivot
        of SyncQueueKind.Backward:
          pivot - man.queue.outSlot
      total =
        case man.queue.kind
        of SyncQueueKind.Forward:
          man.queue.finalSlot + 1'u64 - pivot
        of SyncQueueKind.Backward:
          pivot + 1'u64 - man.queue.finalSlot
      remaining = total - progress
      done =
        if total > 0:
          progress.float / total.float
        else:
          1.0
      timeleft =
        if man.avgSyncSpeed >= 0.001:
          Duration.fromFloatSeconds(remaining.float / man.avgSyncSpeed)
        else:
          InfiniteDuration
      currentSlot = Base10.toString(
        if man.queue.kind == SyncQueueKind.Forward:
          max(uint64(man.queue.outSlot), 1'u64) - 1'u64
        else:
          uint64(man.queue.outSlot) + 1'u64
      )

    # Update status string
    man.syncStatus = timeleft.toTimeLeftString() & " (" &
                    (done * 100).formatBiggestFloat(ffDecimal, 2) & "%) " &
                    man.avgSyncSpeed.formatBiggestFloat(ffDecimal, 4) &
                    "slots/s (" & map & ":" & currentSlot & ")"

    if man.remainingSlots() <= man.maxHeadAge:
      man.notInSyncEvent.clear()
      # We are marking SyncManager as not working only when we are in sync and
      # all sync workers are in `Sleeping` state.
      if pending > 0:
        debug "Synchronization loop waits for workers completion",
              wall_head_slot = wallSlot, local_head_slot = headSlot,
              difference = (wallSlot - headSlot), max_head_age = man.maxHeadAge,
              sleeping_workers_count = sleeping,
              waiting_workers_count = waiting, pending_workers_count = pending
        # We already synced, so we should reset all the pending workers from
        # any state they have.
        man.queue.clearAndWakeup()
        man.inProgress = true
      else:
        case man.direction
        of SyncQueueKind.Forward:
          if man.inProgress:
            if SyncManagerFlag.NoMonitor in man.flags:
              await man.syncClose(guardTaskFut, averageSpeedTaskFut)
              man.inProgress = false
              debug "Forward synchronization process finished, exiting",
                    wall_head_slot = wallSlot, local_head_slot = headSlot,
                    difference = (wallSlot - headSlot),
                    max_head_age = man.maxHeadAge
              break
            else:
              man.inProgress = false
              debug "Forward synchronization process finished, sleeping",
                    wall_head_slot = wallSlot, local_head_slot = headSlot,
                    difference = (wallSlot - headSlot),
                    max_head_age = man.maxHeadAge
          else:
            debug "Synchronization loop sleeping", wall_head_slot = wallSlot,
                  local_head_slot = headSlot,
                  difference = (wallSlot - headSlot),
                  max_head_age = man.maxHeadAge
        of SyncQueueKind.Backward:
          # Backward syncing is going to be executed only once, so we exit loop
          # and stop all pending tasks which belongs to this instance (sync
          # workers, guard task and speed calculation task).
          # We first need to cancel and wait for guard task, because otherwise
          # it will be able to restore cancelled workers.
          await man.syncClose(guardTaskFut, averageSpeedTaskFut)
          man.inProgress = false
          debug "Backward synchronization process finished, exiting",
                wall_head_slot = wallSlot, local_head_slot = headSlot,
                backfill_slot = man.getLastSlot(),
                max_head_age = man.maxHeadAge
          break
    else:
      if not(man.notInSyncEvent.isSet()):
        # We get here only if we lost sync for more then `maxHeadAge` period.
        if pending == 0:
          man.initQueue()
          man.notInSyncEvent.fire()
          man.inProgress = true
          debug "Node lost sync for more then preset period",
                period = man.maxHeadAge, wall_head_slot = wallSlot,
                local_head_slot = headSlot,
                missing_slots = man.remainingSlots(),
                progress = float(man.queue.progress())
      else:
        man.notInSyncEvent.fire()
        man.inProgress = true

    await sleepAsync(chronos.seconds(2))

proc start*[A, B](man: SyncManager[A, B]) =
  ## Starts SyncManager's main loop.
  man.syncFut = man.syncLoop()
