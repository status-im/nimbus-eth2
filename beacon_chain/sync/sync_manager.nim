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
  ../spec/eth2_apis/rpc_types,
  ../spec/[helpers, forks],
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

  SyncWorker*[A, B] = object
    future: Future[void]
    status: SyncWorkerStatus

  SyncManager*[A, B; E: SyncEndpoint] = ref object
    pool: PeerPool[A, B]
    responseTimeout: chronos.Duration
    maxHeadAge*: uint64
    toleranceValue: uint64
    getLocalHeadKey: GetSyncKeyCallback[E.K]
    getLocalWallKey: GetSyncKeyCallback[E.K]
    getSafeKey: GetSyncKeyCallback[E.K]
    getFirstKey: GetSyncKeyCallback[E.K]
    getLastKey: GetSyncKeyCallback[E.K]
    progressPivot*: E.K
    workers: array[SyncWorkersCount, SyncWorker[A, B]]
    notInSyncEvent: AsyncEvent
    rangeAge: uint64
    chunkSize: uint64
    queue: SyncQueue[A, E]
    syncFut: Future[void]
    valueVerifier: SyncValueVerifier[E.V]
    inProgress*: bool
    insSyncSpeed*: float
    avgSyncSpeed*: float
    syncStatus*: string
    direction: SyncQueueKind

  SyncMoment* = object
    stamp*: chronos.Moment
    slots*: uint64

  SyncManagerError* = object of CatchableError
  SyncValueRes*[R] = NetRes[seq[R]]

template declareSyncManager(name: untyped): untyped {.dirty.} =
  type
    `name SyncManager`*[A, B] = SyncManager[A, B, `name SyncEndpoint`]
    `name Res`* = SyncValueRes[`name SyncEndpoint`.R]

  template `new name SyncManager`*[A, B](
      pool: PeerPool[A, B],
      direction: SyncQueueKind,
      getLocalHeadKeyCb: GetSyncKeyCallback[`name SyncEndpoint`.K],
      getLocalWallKeyCb: GetSyncKeyCallback[`name SyncEndpoint`.K],
      getFinalizedKeyCb: GetSyncKeyCallback[`name SyncEndpoint`.K],
      getBackfillKeyCb: GetSyncKeyCallback[`name SyncEndpoint`.K],
      progressPivot: `name SyncEndpoint`.K,
      valueVerifier: SyncValueVerifier[`name SyncEndpoint`.V],
      maxHeadAge = uint64(SLOTS_PER_EPOCH * 1),
      chunkSize = uint64(SLOTS_PER_EPOCH),
      toleranceValue = uint64(1)
  ): `name SyncManager`[A, B] =
    `name SyncEndpoint`.newSyncManager(
      pool, direction, getLocalHeadKeyCb, getLocalWallKeyCb, getFinalizedKeyCb,
      getBackfillKeyCb, progressPivot, valueVerifier, maxHeadAge, chunkSize,
      toleranceValue)

declareSyncManager BeaconBlocks
declareSyncManager LightClientUpdates

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

proc initQueue[A, B, E](man: SyncManager[A, B, E]) =
  case man.direction
  of SyncQueueKind.Forward:
    man.queue = E.initSyncQueue(A, man.direction, man.getFirstKey(),
                                man.getLastKey(), man.chunkSize,
                                man.getSafeKey, man.valueVerifier, 1)
  of SyncQueueKind.Backward:
    let
      firstKey = man.getFirstKey()
      lastKey = man.getLastKey()
      startKey = if firstKey == lastKey:
                   # This case should never be happened in real life because
                   # there is present check `needsBackfill().
                   firstKey
                 else:
                   E.K(firstKey - 1'u64)
    man.queue = E.initSyncQueue(A, man.direction, firstKey, lastKey,
                                man.chunkSize, man.getSafeKey,
                                man.valueVerifier, 1)

proc newSyncManager*[A, B, E](e: typedesc[E], pool: PeerPool[A, B],
                              direction: SyncQueueKind,
                              getLocalHeadKeyCb: GetSyncKeyCallback[E.K],
                              getLocalWallKeyCb: GetSyncKeyCallback[E.K],
                              getFinalizedKeyCb: GetSyncKeyCallback[E.K],
                              getBackfillKeyCb: GetSyncKeyCallback[E.K],
                              progressPivot: E.K,
                              valueVerifier: SyncValueVerifier[E.V],
                              maxHeadAge = uint64(SLOTS_PER_EPOCH * 1),
                              chunkSize = uint64(SLOTS_PER_EPOCH),
                              toleranceValue = uint64(1)
                              ): SyncManager[A, B, E] =
  let (getFirstKey, getLastKey, getSafeKey) = case direction
  of SyncQueueKind.Forward:
    (getLocalHeadKeyCb, getLocalWallKeyCb, getFinalizedKeyCb)
  of SyncQueueKind.Backward:
    (getBackfillKeyCb, GetSyncKeyCallback[E.K](proc(): E.K = E.K(0)),
     getBackfillKeyCb)

  var res = SyncManager[A, B, E](
    pool: pool,
    getLocalHeadKey: getLocalHeadKeyCb,
    getLocalWallKey: getLocalWallKeyCb,
    getSafeKey: getSafeKey,
    getFirstKey: getFirstKey,
    getLastKey: getLastKey,
    progressPivot: progressPivot,
    maxHeadAge: maxHeadAge,
    chunkSize: chunkSize,
    valueVerifier: valueVerifier,
    notInSyncEvent: newAsyncEvent(),
    direction: direction
  )
  res.initQueue()
  res

proc doRequest*[A, B](man: BeaconBlocksSyncManager[A, B], peer: A,
                      req: BeaconBlocksSyncRequest[A]
                      ): Future[BeaconBlocksRes] {.async.} =
  mixin beaconBlocksByRange, getScore, `==`
  doAssert(not(req.isEmpty()), "Request must not be empty!")
  debug "Requesting blocks from peer", peer = peer,
        slot = req.start, slot_count = req.count, step = req.step,
        peer_score = peer.getScore(), peer_speed = peer.netKbps(),
        direction = man.direction, topics = "syncman"
  try:
    let res =
      if peer.useSyncV2():
        await beaconBlocksByRange_v2(peer, req.start, req.count, req.step)
      else:
        (await beaconBlocksByRange(peer, req.start, req.count, req.step)).map(
          proc(blcks: seq[phase0.SignedBeaconBlock]): auto =
            blcks.mapIt(newClone(ForkedSignedBeaconBlock.init(it))))

    if res.isErr():
      debug "Error, while reading beaconBlocksByRange response",
              peer = peer, slot = req.start, count = req.count,
              step = req.step, peer_speed = peer.netKbps(),
              direction = man.direction, topics = "syncman",
              error = $res.error()
      return
    return res
  except CancelledError:
    debug "Interrupt, while waiting beaconBlocksByRange response", peer = peer,
          slot = req.start, slot_count = req.count, step = req.step,
          peer_speed = peer.netKbps(), direction = man.direction,
          topics = "syncman"
    return
  except CatchableError as exc:
    debug "Error, while waiting beaconBlocksByRange response", peer = peer,
          slot = req.start, slot_count = req.count, step = req.step,
          errName = exc.name, errMsg = exc.msg, peer_speed = peer.netKbps(),
          direction = man.direction, topics = "syncman"
    return

proc doRequest*[A, B](man: LightClientUpdatesSyncManager[A, B], peer: A,
                      req: LightClientUpdatesSyncRequest[A]
                      ): Future[LightClientUpdatesRes] {.async.} =
  mixin bestLightClientUpdatesByRange
  doAssert(not(req.isEmpty()), "Request must not be empty!")
  debug "Requesting updates from peer", peer = peer,
        period = req.start, period_count = req.count, step = req.step,
        peer_score = peer.getScore(), peer_speed = peer.netKbps(),
        direction = man.direction, topics = "syncman"
  let res =
    try:
      await bestLightClientUpdatesByRange(peer, req.start, req.count, req.step)
    except CancelledError:
      debug "Interrupt, while waiting bestLightClientUpdatesByRange response",
            peer = peer, period = req.start, period_count = req.count,
            step = req.step, peer_speed = peer.netKbps(),
            direction = man.direction, topics = "syncman"
      return
    except CatchableError as exc:
      debug "Error, while waiting bestLightClientUpdatesByRange response",
            peer = peer, period = req.start, period_count = req.count,
            step = req.step, errName = exc.name, errMsg = exc.msg,
            peer_speed = peer.netKbps(), direction = man.direction,
            topics = "syncman"
      return
  if res.isErr():
    debug "Error, while reading bestLightClientUpdatesByRange response",
          peer = peer, period = req.start, count = req.count,
          step = req.step, peer_speed = peer.netKbps(),
          direction = man.direction, error = $res.error(),
          topics = "syncman"
    return
  return res

proc remainingKeys(man: SyncManager): uint64 =
  if man.direction == SyncQueueKind.Forward:
    man.getLastKey() - man.getFirstKey()
  else:
    man.getFirstKey() - man.getLastKey()

func slotToKey[E: SyncEndpoint](slot: Slot, e: typedesc[E]): E.K =
  when E.K is Slot:
    slot
  elif E.K is SyncCommitteePeriod:
    slot.sync_committee_period
  else: static: raiseAssert false

proc syncStep[A, B, E](man: SyncManager[A, B, E],
                       index: int, peer: A) {.async.} =
  var
    headKey = man.getLocalHeadKey()
    wallKey = man.getLocalWallKey()
    peerSlot = peer.getHeadSlot()
    peerKey = peerSlot.slotToKey(E)

  block: # Check that peer status is recent and relevant
    when E.K is Slot:
      debug "Peer's syncing status", wall_clock_slot = wallKey,
            remote_head_slot = peerKey, local_head_slot = headKey,
            peer_score = peer.getScore(), peer = peer, index = index,
            peer_speed = peer.netKbps(), direction = man.direction,
            topics = "syncman"
    elif E.K is SyncCommitteePeriod:
      debug "Peer's syncing status", wall_clock_period = wallKey,
            remote_head_period = peerKey, local_head_period = headKey,
            peer_score = peer.getScore(), peer = peer, index = index,
            peer_speed = peer.netKbps(), direction = man.direction,
            topics = "syncman"
    else: static: raiseAssert false

    let
      peerStatusAge = Moment.now() - peer.state(BeaconSync).statusLastTime
      needsUpdate =
        # Latest status we got is old
        peerStatusAge >= StatusExpirationTime or
        # The point we need to sync is close to where the peer is
        man.getFirstKey() >= peerKey

    if needsUpdate:
      man.workers[index].status = SyncWorkerStatus.UpdatingStatus

      # Avoid a stampede of requests, but make them more frequent in case the
      # peer is "close" to the key range of interest
      if peerStatusAge < StatusExpirationTime div 2:
        await sleepAsync(StatusExpirationTime div 2 - peerStatusAge)

      when E.K is Slot:
        trace "Updating peer's status information", wall_clock_slot = wallKey,
              remote_head_slot = peerKey, local_head_slot = headKey,
              peer = peer, peer_score = peer.getScore(), index = index,
              peer_speed = peer.netKbps(), direction = man.direction,
              topics = "syncman"
      elif E.K is SyncCommitteePeriod:
        trace "Updating peer's status information", wall_clock_period = wallKey,
              remote_head_period = peerKey, local_head_period = headKey,
              peer = peer, peer_score = peer.getScore(), index = index,
              peer_speed = peer.netKbps(), direction = man.direction,
              topics = "syncman"
      else: static: raiseAssert false

      try:
        let res = await peer.updateStatus()
        if not(res):
          peer.updateScore(PeerScoreNoStatus)
          debug "Failed to get remote peer's status, exiting", peer = peer,
                peer_score = peer.getScore(), peer_head_slot = peerSlot,
                peer_speed = peer.netKbps(), index = index,
                direction = man.direction, topics = "syncman"
          return
      except CatchableError as exc:
        debug "Unexpected exception while updating peer's status",
              peer = peer, peer_score = peer.getScore(),
              peer_head_slot = peerSlot, peer_speed = peer.netKbps(),
              index = index, errMsg = exc.msg, direction = man.direction,
              topics = "syncman"
        return

      let
        newPeerSlot = peer.getHeadSlot()
        newPeerKey = newPeerSlot.slotToKey(E)
      if peerSlot >= newPeerSlot:
        peer.updateScore(PeerScoreStaleStatus)
        when E.K is Slot:
          debug "Peer's status information is stale",
                wall_clock_slot = wallKey, remote_old_head_slot = peerSlot,
                local_head_slot = headKey, remote_new_head_slot = newPeerSlot,
                peer = peer, peer_score = peer.getScore(), index = index,
                peer_speed = peer.netKbps(), direction = man.direction,
                topics = "syncman"
        elif E.K is SyncCommitteePeriod:
          debug "Peer's status information is stale",
                wall_clock_period = wallKey, remote_old_head_slot = peerSlot,
                local_head_period = headKey, remote_new_head_slot = newPeerSlot,
                peer = peer, peer_score = peer.getScore(), index = index,
                peer_speed = peer.netKbps(), direction = man.direction,
                topics = "syncman"
        else: static: raiseAssert false
      else:
        when E.K is Slot:
          debug "Peer's status information updated",
                wall_clock_slot = wallKey,
                remote_old_head_slot = peerKey, local_head_slot = headKey,
                remote_new_head_slot = newPeerKey, peer = peer,
                peer_score = peer.getScore(), peer_speed = peer.netKbps(),
                index = index, direction = man.direction, topics = "syncman"
        elif E.K is SyncCommitteePeriod:
          debug "Peer's status information updated",
                wall_clock_period = wallKey,
                remote_old_head_period = peerKey, local_head_period = headKey,
                remote_new_head_period = newPeerKey, peer = peer,
                peer_score = peer.getScore(), peer_speed = peer.netKbps(),
                index = index, direction = man.direction, topics = "syncman"
        else: static: raiseAssert false
        peer.updateScore(PeerScoreGoodStatus)
        peerSlot = newPeerSlot
        peerKey = newPeerKey

    # Time passed - enough to move to newer key, if sleep happened
    headKey = man.getLocalHeadKey()
    wallKey = man.getLocalWallKey()

    if peerKey > wallKey + man.toleranceValue:
      # If the peer reports a head newer than our wall clock, something is
      # wrong: our clock is off or the peer is on a different network (or
      # dishonest)
      peer.updateScore(PeerScoreHeadTooNew)

      when E.K is Slot:
        warn "Peer reports a head newer than our wall clock - clock out of sync?",
              wall_clock_slot = wallKey, remote_head_slot = peerKey,
              local_head_slot = headKey, peer = peer, index = index,
              tolerance_value = man.toleranceValue, peer_speed = peer.netKbps(),
              peer_score = peer.getScore(), direction = man.direction,
              topics = "syncman"
      elif E.K is SyncCommitteePeriod:
        warn "Peer reports a head newer than our wall clock - clock out of sync?",
              wall_clock_period = wallKey, remote_head_period = peerKey,
              local_head_period = headKey, peer = peer, index = index,
              tolerance_value = man.toleranceValue, peer_speed = peer.netKbps(),
              peer_score = peer.getScore(), direction = man.direction,
              topics = "syncman"
      else: static: raiseAssert false
      return

  if man.remainingKeys() <= man.maxHeadAge:
    case man.direction
    of SyncQueueKind.Forward:
      when E is BeaconBlocksSyncEndpoint:
        info "We are in sync with network", wall_clock_slot = wallKey,
              remote_head_slot = peerKey, local_head_slot = headKey,
              peer = peer, peer_score = peer.getScore(), index = index,
              peer_speed = peer.netKbps(), direction = man.direction,
              topics = "syncman"
      elif E is LightClientUpdatesSyncEndpoint:
        info "Light client synced to recent head", wall_clock_period = wallKey,
              remote_head_period = peerKey, local_head_period = headKey,
              peer = peer, peer_score = peer.getScore(), index = index,
              peer_speed = peer.netKbps(), direction = man.direction,
              topics = "syncman"
      else: static: raiseAssert false
    of SyncQueueKind.Backward:
      when E is BeaconBlocksSyncEndpoint:
        info "Backfill complete", wall_clock_slot = wallKey,
              remote_head_slot = peerKey, local_head_slot = headKey,
              peer = peer, peer_score = peer.getScore(), index = index,
              peer_speed = peer.netKbps(), direction = man.direction,
              topics = "syncman"
      elif E is LightClientUpdatesSyncEndpoint:
        info "Light client backfill complete", wall_clock_period = wallKey,
              remote_head_period = peerKey, local_head_period = headKey,
              peer = peer, peer_score = peer.getScore(), index = index,
              peer_speed = peer.netKbps(), direction = man.direction,
              topics = "syncman"
      else: static: raiseAssert false

    # We clear SyncManager's `notInSyncEvent` so all the workers will become
    # sleeping soon.
    man.notInSyncEvent.clear()
    return

  # Find out if the peer potentially can give useful values - in the case of
  # forward sync, they can be useful if they have values newer than our head -
  # in the case of backwards sync, they're useful if they have values newer than
  # the backfill point
  if man.getFirstKey() >= peerKey:
    # This is not very good solution because we should not discriminate and/or
    # penalize peers which are in sync process too, but their latest head is
    # lower then our latest head. We should keep connections with such peers
    # (so this peers are able to get in sync using our data), but we should
    # not use this peers for syncing because this peers are useless for us.
    # Right now we decreasing peer's score a bit, so it will not be
    # disconnected due to low peer's score, but new fresh peers could replace
    # peers with low latest head.
    when E.K is Slot:
      debug "Peer's head slot is lower then local head slot",
            wall_clock_slot = wallKey, remote_head_slot = peerKey,
            local_last_slot = man.getLastKey(),
            local_first_slot = man.getFirstKey(), peer = peer,
            peer_score = peer.getScore(),
            peer_speed = peer.netKbps(), index = index,
            direction = man.direction, topics = "syncman"
    elif E.K is SyncCommitteePeriod:
      debug "Peer's head period is lower then local head period",
            wall_clock_period = wallKey, remote_head_period = peerKey,
            local_last_period = man.getLastKey(),
            local_first_period = man.getFirstKey(), peer = peer,
            peer_score = peer.getScore(),
            peer_speed = peer.netKbps(), index = index,
            direction = man.direction, topics = "syncman"
    else: static: raiseAssert false
    peer.updateScore(PeerScoreUseless)
    return

  if man.direction == SyncQueueKind.Forward:
    # Wall clock keeps ticking, so we need to update the queue
    man.queue.updateLastKey(man.getLastKey())

  man.workers[index].status = SyncWorkerStatus.Requesting
  let req = man.queue.pop(peerKey, peer)
  if req.isEmpty():
    # SyncQueue could return empty request in 2 cases:
    # 1. There no more keys in SyncQueue to download (we are synced, but
    #    our ``notInSyncEvent`` is not yet cleared).
    # 2. Current peer's known head key is too low to satisfy request.
    #
    # To avoid endless loop we going to wait for RESP_TIMEOUT time here.
    # This time is enough for all pending requests to finish and it is also
    # enough for main sync loop to clear ``notInSyncEvent``.
    when E.K is Slot:
      debug "Empty request received from queue, exiting", peer = peer,
            local_head_slot = headKey, remote_head_slot = peerKey,
            queue_input_slot = man.queue.inpKey,
            queue_output_slot = man.queue.outKey,
            queue_last_slot = man.queue.finalKey,
            peer_speed = peer.netKbps(), peer_score = peer.getScore(),
            index = index, direction = man.direction, topics = "syncman"
    elif E.K is SyncCommitteePeriod:
      debug "Empty request received from queue, exiting", peer = peer,
            local_head_period = headKey, remote_head_period = peerKey,
            queue_input_period = man.queue.inpKey,
            queue_output_period = man.queue.outKey,
            queue_last_period = man.queue.finalKey,
            peer_speed = peer.netKbps(), peer_score = peer.getScore(),
            index = index, direction = man.direction, topics = "syncman"
    else: static: raiseAssert false
    await sleepAsync(RESP_TIMEOUT)
    return

  when E.K is Slot:
    debug "Creating new request for peer", wall_clock_slot = wallKey,
          remote_head_slot = peerKey, local_head_slot = headKey,
          request_slot = req.start, request_count = req.count,
          request_step = req.step, peer = peer, peer_speed = peer.netKbps(),
          peer_score = peer.getScore(), index = index,
          direction = man.direction, topics = "syncman"
  elif E.K is SyncCommitteePeriod:
    debug "Creating new request for peer", wall_clock_period = wallKey,
          remote_head_period = peerKey, local_head_period = headKey,
          request_period = req.start, request_count = req.count,
          request_step = req.step, peer = peer, peer_speed = peer.netKbps(),
          peer_score = peer.getScore(), index = index,
          direction = man.direction, topics = "syncman"
  else: static: raiseAssert false

  man.workers[index].status = SyncWorkerStatus.Downloading

  try:
    let response = await man.doRequest(peer, req)
    if response.isOk():
      let data = response.get()
      let smap = getShortMap[A, E](req, data)
      when E is BeaconBlocksSyncEndpoint:
        debug "Received blocks on request", blocks_count = len(data),
              blocks_map = smap, request_slot = req.start,
              request_count = req.count, request_step = req.step,
              peer = peer, peer_score = peer.getScore(),
              peer_speed = peer.netKbps(), index = index,
              direction = man.direction, topics = "syncman"
      elif E is LightClientUpdatesSyncEndpoint:
        debug "Received updates on request", updates_count = len(data),
              updates_map = smap, request_period = req.start,
              request_count = req.count, request_step = req.step,
              peer = peer, peer_score = peer.getScore(),
              peer_speed = peer.netKbps(), index = index,
              direction = man.direction, topics = "syncman"
      else: static: raiseAssert false

      if not(checkResponse(req, data)):
        peer.updateScore(PeerScoreBadResponse)
        when E is BeaconBlocksSyncEndpoint:
          warn "Received blocks sequence is not in requested range",
              blocks_count = len(data), blocks_map = smap,
              request_slot = req.start, request_count = req.count,
              request_step = req.step, peer = peer,
              peer_score = peer.getScore(), peer_speed = peer.netKbps(),
              index = index, direction = man.direction, topics = "syncman"
        elif E is LightClientUpdatesSyncEndpoint:
          warn "Received updates sequence is not in requested range",
              updates_count = len(data), updates_map = smap,
              request_period = req.start, request_count = req.count,
              request_step = req.step, peer = peer,
              peer_score = peer.getScore(), peer_speed = peer.netKbps(),
              index = index, direction = man.direction, topics = "syncman"
        else: static: raiseAssert false
        return

      # Scoring will be done inside of SyncQueue.
      man.workers[index].status = SyncWorkerStatus.Queueing
      await man.queue.push(req, data, proc() =
        man.workers[index].status = SyncWorkerStatus.Processing)
    else:
      peer.updateScore(PeerScoreNoBlocks)
      man.queue.push(req)
      when E is BeaconBlocksSyncEndpoint:
        debug "Failed to receive blocks on request",
              request_slot = req.start, request_count = req.count,
              request_step = req.step, peer = peer, index = index,
              peer_score = peer.getScore(), peer_speed = peer.netKbps(),
              direction = man.direction, topics = "syncman"
      elif E is LightClientUpdatesSyncEndpoint:
        debug "Failed to receive updates on request",
              request_period = req.start, request_count = req.count,
              request_step = req.step, peer = peer, index = index,
              peer_score = peer.getScore(), peer_speed = peer.netKbps(),
              direction = man.direction, topics = "syncman"
      else: static: raiseAssert false
      return

  except CatchableError as exc:
    when E is BeaconBlocksSyncEndpoint:
      debug "Unexpected exception while receiving blocks",
            request_slot = req.start, request_count = req.count,
            request_step = req.step, peer = peer, index = index,
            peer_score = peer.getScore(), peer_speed = peer.netKbps(),
            errName = exc.name, errMsg = exc.msg, direction = man.direction,
            topics = "syncman"
    elif E is LightClientUpdatesSyncEndpoint:
      debug "Unexpected exception while receiving blocks",
            request_period = req.start, request_count = req.count,
            request_step = req.step, peer = peer, index = index,
            peer_score = peer.getScore(), peer_speed = peer.netKbps(),
            errName = exc.name, errMsg = exc.msg, direction = man.direction,
            topics = "syncman"
    else: static: raiseAssert false
    return

proc syncWorker[A, B, E](man: SyncManager[A, B, E], index: int) {.async.} =
  mixin getKey, getScore, getHeadSlot

  debug "Starting syncing worker", index = index, direction = man.direction,
                                   topics = "syncman"

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
              peer = peer, index = index,
              peer_score = peer.getScore(), peer_speed = peer.netKbps(),
              errName = exc.name, errMsg = exc.msg, direction = man.direction,
              topics = "syncman"
        true
    if doBreak:
      break

  debug "Sync worker stopped", index = index, direction = man.direction,
                               topics = "syncman"

proc getWorkersStats[A, B, E](man: SyncManager[A, B, E]): tuple[map: string,
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

proc guardTask[A, B, E](man: SyncManager[A, B, E]) {.async.} =
  var pending: array[SyncWorkersCount, Future[void]]

  # Starting all the synchronization workers.
  for i in 0 ..< len(man.workers):
    let future = syncWorker[A, B, E](man, i)
    man.workers[i].future = future
    pending[i] = future

  # Wait for synchronization worker's failure and replace it with new one.
  while true:
    let failFuture = await one(pending)
    let index = pending.find(failFuture)
    if failFuture.failed():
      warn "Synchronization worker stopped working unexpectedly with an error",
            index = index, errMsg = failFuture.error.msg,
            direction = man.direction
    else:
      warn "Synchronization worker stopped working unexpectedly without error",
            index = index, direction = man.direction

    let future = syncWorker[A, B, E](man, index)
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

func slots[K](keys: K): Slot =
  when K is Slot:
    keys
  elif K is SyncCommitteePeriod:
    keys.start_slot
  else:
    static: raiseAssert false

proc syncLoop[A, B, E](man: SyncManager[A, B, E]) {.async.} =
  mixin getKey, getScore
  var pauseTime = 0

  var guardTaskFut = man.guardTask()

  debug "Synchronization loop started", topics = "syncman",
        direction = man.direction

  proc averageSpeedTask() {.async.} =
    while true:
      # Reset sync speeds between each loss-of-sync event
      man.avgSyncSpeed = 0
      man.insSyncSpeed = 0

      await man.notInSyncEvent.wait()

      # Give the node time to connect to peers and get the sync process started
      await sleepAsync(seconds(SECONDS_PER_SLOT.int64))

      var
        stamp = SyncMoment.now(E.K(man.queue.progress()).slots.uint64)
        syncCount = 0

      while man.inProgress:
        await sleepAsync(seconds(SECONDS_PER_SLOT.int64))

        let
          newStamp = SyncMoment.now(E.K(man.queue.progress()).slots.uint64)
          slotsPerSec = speed(stamp, newStamp)

        syncCount += 1

        man.insSyncSpeed = slotsPerSec
        man.avgSyncSpeed =
          man.avgSyncSpeed + (slotsPerSec - man.avgSyncSpeed) / float(syncCount)

        stamp = newStamp

  var averageSpeedTaskFut = averageSpeedTask()

  while true:
    let wallKey = man.getLocalWallKey()
    let headKey = man.getLocalHeadKey()

    let (map, sleeping, waiting, pending) = man.getWorkersStats()

    when E.K is Slot:
      debug "Current syncing state", workers_map = map,
            sleeping_workers_count = sleeping,
            waiting_workers_count = waiting,
            pending_workers_count = pending,
            wall_head_slot = wallKey, local_head_slot = headKey,
            pause_time = $chronos.seconds(pauseTime),
            avg_sync_speed = man.avgSyncSpeed,
            ins_sync_speed = man.insSyncSpeed,
            direction = man.direction, topics = "syncman"
    elif E.K is SyncCommitteePeriod:
      debug "Current syncing state", workers_map = map,
            sleeping_workers_count = sleeping,
            waiting_workers_count = waiting,
            pending_workers_count = pending,
            wall_head_period = wallKey, local_head_period = headKey,
            pause_time = $chronos.seconds(pauseTime),
            avg_sync_speed = man.avgSyncSpeed,
            ins_sync_speed = man.insSyncSpeed,
            direction = man.direction, topics = "syncman"
    else: static: doAssert false

    let
      pivot = man.progressPivot
      progress = float(
        if man.queue.kind == SyncQueueKind.Forward: man.queue.outKey - pivot
        else: pivot - man.queue.outKey)
      total = float(
        if man.queue.kind == SyncQueueKind.Forward: man.queue.finalKey - pivot
        else: pivot - man.queue.finalKey)
      remaining = total - progress
      done = if total > 0.0: progress / total else: 1.0
      timeleft =
        if man.avgSyncSpeed >= 0.001:
          Duration.fromFloatSeconds(remaining / man.avgSyncSpeed)
        else: InfiniteDuration
      currentKey =
        if man.queue.kind == SyncQueueKind.Forward:
          max(uint64(man.queue.outKey), 1'u64) - 1'u64
        else:
          uint64(man.queue.outKey) + 1'u64
      currentSlot = Base10.toString(E.K(currentKey).slots.uint64)

    # Update status string
    man.syncStatus = timeLeft.toTimeLeftString() & " (" &
                    (done * 100).formatBiggestFloat(ffDecimal, 2) & "%) " &
                    man.avgSyncSpeed.formatBiggestFloat(ffDecimal, 4) &
                    "slots/s (" & map & ":" & currentSlot & ")"

    if man.remainingKeys() <= man.maxHeadAge:
      man.notInSyncEvent.clear()
      # We are marking SyncManager as not working only when we are in sync and
      # all sync workers are in `Sleeping` state.
      if pending > 0:
        when E.K is Slot:
          debug "Synchronization loop waits for workers completion",
                wall_head_slot = wallKey, local_head_slot = headKey,
                difference = (wallKey - headKey), max_head_age = man.maxHeadAge,
                sleeping_workers_count = sleeping,
                waiting_workers_count = waiting,
                pending_workers_count = pending,
                direction = man.direction, topics = "syncman"
        elif E.K is SyncCommitteePeriod:
          debug "Synchronization loop waits for workers completion",
                wall_head_period = wallKey, local_head_period = headKey,
                difference = (wallKey - headKey), max_head_age = man.maxHeadAge,
                sleeping_workers_count = sleeping,
                waiting_workers_count = waiting,
                pending_workers_count = pending,
                direction = man.direction, topics = "syncman"
        else: static: doAssert false
        # We already synced, so we should reset all the pending workers from
        # any state they have.
        man.queue.clearAndWakeup()
        man.inProgress = true
      else:
        case man.direction
        of SyncQueueKind.Forward:
          if man.inProgress:
            man.inProgress = false
            when E.K is Slot:
              debug "Forward synchronization process finished, sleeping",
                    wall_head_slot = wallKey, local_head_slot = headKey,
                    difference = (wallKey - headKey),
                    max_head_age = man.maxHeadAge, direction = man.direction,
                    topics = "syncman"
            elif E.K is SyncCommitteePeriod:
              debug "Forward synchronization process finished, sleeping",
                    wall_head_period = wallKey, local_head_period = headKey,
                    difference = (wallKey - headKey),
                    max_head_age = man.maxHeadAge, direction = man.direction,
                    topics = "syncman"
            else: static: doAssert false
          else:
            when E.K is Slot:
              debug "Synchronization loop sleeping",
                    wall_head_slot = wallKey, local_head_slot = headKey,
                    difference = (wallKey - headKey),
                    max_head_age = man.maxHeadAge, direction = man.direction,
                    topics = "syncman"
            elif E.K is SyncCommitteePeriod:
              debug "Synchronization loop sleeping",
                    wall_head_period = wallKey, local_head_period = headKey,
                    difference = (wallKey - headKey),
                    max_head_age = man.maxHeadAge, direction = man.direction,
                    topics = "syncman"
            else: static: doAssert false
        of SyncQueueKind.Backward:
          # Backward syncing is going to be executed only once, so we exit loop
          # and stop all pending tasks which belongs to this instance (sync
          # workers, guard task and speed calculation task).
          # We first need to cancel and wait for guard task, because otherwise
          # it will be able to restore cancelled workers.
          guardTaskFut.cancel()
          averageSpeedTaskFut.cancel()
          await allFutures(guardTaskFut, averageSpeedTaskFut)
          let pendingTasks =
            block:
              var res: seq[Future[void]]
              for worker in man.workers:
                # Because `pending == 0` there should be no active workers.
                doAssert(worker.status in {Sleeping, WaitingPeer})
                worker.future.cancel()
                res.add(worker.future)
              res
          await allFutures(pendingTasks)
          man.inProgress = false
          when E.K is Slot:
            debug "Backward synchronization process finished, exiting",
                  wall_head_slot = wallKey, local_head_slot = headKey,
                  backfill_slot = man.getLastKey(),
                  max_head_age = man.maxHeadAge, direction = man.direction,
                  topics = "syncman"
          elif E.K is SyncCommitteePeriod:
            debug "Backward synchronization process finished, exiting",
                  wall_head_period = wallKey, local_head_period = headKey,
                  backfill_period = man.getLastKey(),
                  max_head_age = man.maxHeadAge, direction = man.direction,
                  topics = "syncman"
          else: static: doAssert false
          break
    else:
      if not(man.notInSyncEvent.isSet()):
        # We get here only if we lost sync for more then `maxHeadAge` period.
        if pending == 0:
          man.initQueue()
          man.notInSyncEvent.fire()
          man.inProgress = true
          when E.K is Slot:
            debug "Node lost sync for more then preset period",
                  period = man.maxHeadAge, wall_head_slot = wallKey,
                  local_head_slot = headKey,
                  missing_slots = man.remainingKeys(),
                  progress = float(man.queue.progress()),
                  topics = "syncman"
          elif E.K is SyncCommitteePeriod:
            debug "Node lost sync for more then preset period",
                  period = man.maxHeadAge, wall_head_period = wallKey,
                  local_head_period = headKey,
                  missing_periods = man.remainingKeys(),
                  progress = float(man.queue.progress()),
                  topics = "syncman"
          else: static: doAssert false
      else:
        man.notInSyncEvent.fire()
        man.inProgress = true

    await sleepAsync(chronos.seconds(2))

proc start*[A, B, E](man: SyncManager[A, B, E]) =
  ## Starts SyncManager's main loop.
  man.syncFut = man.syncLoop()

proc stop*[A, B, E](man: SyncManager[A, B, E]) =
  ## Stops SyncManager's main loop.
  if man.syncFut != nil:
    man.syncFut.cancel()
    man.syncFut = nil

proc getInfo*[A, B, E](man: SyncManager[A, B, E]): RpcSyncInfo =
  ## Returns current synchronization information for RPC call.
  let wallSlot = man.getLocalWallKey().slots
  let headSlot = man.getLocalHeadKey().slots
  let sync_distance = wallSlot - headSlot
  (
    head_slot: headSlot,
    sync_distance: sync_distance,
    is_syncing:
      when E is BeaconBlocksSyncEndpoint:
        man.inProgress
      elif E is LightClientUpdatesSyncEndpoint:
        # Avoid intermittent reporting of `false` during transition
        # from light client sync into full beacon blocks sync.
        true
      else: static: doAssert false
  )
