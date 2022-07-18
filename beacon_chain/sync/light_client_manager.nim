# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import chronos, chronicles, stew/base10
import
  eth/p2p/discoveryv5/random2,
  ../spec/datatypes/[altair],
  ../networking/eth2_network,
  ../beacon_clock,
  "."/sync_protocol, "."/sync_manager
export sync_manager

logScope:
  topics = "lcman"

type
  Nothing = object
  ResponseError = object of CatchableError
  Endpoint[K, V] =
    (K, V) # https://github.com/nim-lang/Nim/issues/19531
  Bootstrap =
    Endpoint[Eth2Digest, altair.LightClientBootstrap]
  UpdatesByRange =
    Endpoint[Slice[SyncCommitteePeriod], altair.LightClientUpdate]
  FinalityUpdate =
    Endpoint[Nothing, altair.LightClientFinalityUpdate]
  OptimisticUpdate =
    Endpoint[Nothing, altair.LightClientOptimisticUpdate]

  ValueVerifier[V] =
    proc(v: V): Future[Result[void, BlockError]] {.gcsafe, raises: [Defect].}
  BootstrapVerifier* =
    ValueVerifier[altair.LightClientBootstrap]
  UpdateVerifier* =
    ValueVerifier[altair.LightClientUpdate]
  FinalityUpdateVerifier* =
    ValueVerifier[altair.LightClientFinalityUpdate]
  OptimisticUpdateVerifier* =
    ValueVerifier[altair.LightClientOptimisticUpdate]

  GetTrustedBlockRootCallback* =
    proc(): Option[Eth2Digest] {.gcsafe, raises: [Defect].}
  GetBoolCallback* =
    proc(): bool {.gcsafe, raises: [Defect].}
  GetSyncCommitteePeriodCallback* =
    proc(): SyncCommitteePeriod {.gcsafe, raises: [Defect].}

  LightClientManager* = object
    network: Eth2Node
    rng: ref HmacDrbgContext
    getTrustedBlockRoot: GetTrustedBlockRootCallback
    bootstrapVerifier: BootstrapVerifier
    updateVerifier: UpdateVerifier
    finalityUpdateVerifier: FinalityUpdateVerifier
    optimisticUpdateVerifier: OptimisticUpdateVerifier
    isLightClientStoreInitialized: GetBoolCallback
    isNextSyncCommitteeKnown: GetBoolCallback
    getFinalizedPeriod: GetSyncCommitteePeriodCallback
    getOptimisticPeriod: GetSyncCommitteePeriodCallback
    getBeaconTime: GetBeaconTimeFn
    loopFuture: Future[void]

func init*(
    T: type LightClientManager,
    network: Eth2Node,
    rng: ref HmacDrbgContext,
    getTrustedBlockRoot: GetTrustedBlockRootCallback,
    bootstrapVerifier: BootstrapVerifier,
    updateVerifier: UpdateVerifier,
    finalityUpdateVerifier: FinalityUpdateVerifier,
    optimisticUpdateVerifier: OptimisticUpdateVerifier,
    isLightClientStoreInitialized: GetBoolCallback,
    isNextSyncCommitteeKnown: GetBoolCallback,
    getFinalizedPeriod: GetSyncCommitteePeriodCallback,
    getOptimisticPeriod: GetSyncCommitteePeriodCallback,
    getBeaconTime: GetBeaconTimeFn
): LightClientManager =
  ## Initialize light client manager.
  LightClientManager(
    network: network,
    rng: rng,
    getTrustedBlockRoot: getTrustedBlockRoot,
    bootstrapVerifier: bootstrapVerifier,
    updateVerifier: updateVerifier,
    finalityUpdateVerifier: finalityUpdateVerifier,
    optimisticUpdateVerifier: optimisticUpdateVerifier,
    isLightClientStoreInitialized: isLightClientStoreInitialized,
    isNextSyncCommitteeKnown: isNextSyncCommitteeKnown,
    getFinalizedPeriod: getFinalizedPeriod,
    getOptimisticPeriod: getOptimisticPeriod,
    getBeaconTime: getBeaconTime
  )

proc isGossipSupported*(
    self: LightClientManager,
    period: SyncCommitteePeriod
): bool =
  ## Indicate whether the light client is sufficiently synced to accept gossip.
  if not self.isLightClientStoreInitialized():
    return false

  let
    finalizedPeriod = self.getFinalizedPeriod()
    isNextSyncCommitteeKnown = self.isNextSyncCommitteeKnown()
  if isNextSyncCommitteeKnown:
    period <= finalizedPeriod + 1
  else:
    period <= finalizedPeriod

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#getlightclientbootstrap
proc doRequest(
    e: typedesc[Bootstrap],
    peer: Peer,
    blockRoot: Eth2Digest
): Future[NetRes[altair.LightClientBootstrap]] {.
    raises: [Defect, IOError].} =
  peer.lightClientBootstrap(blockRoot)

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#lightclientupdatesbyrange
type LightClientUpdatesByRangeResponse = NetRes[seq[altair.LightClientUpdate]]
proc doRequest(
    e: typedesc[UpdatesByRange],
    peer: Peer,
    periods: Slice[SyncCommitteePeriod]
): Future[LightClientUpdatesByRangeResponse] {.
    async, raises: [Defect, IOError].} =
  let
    startPeriod = periods.a
    lastPeriod = periods.b
    reqCount = min(periods.len, MAX_REQUEST_LIGHT_CLIENT_UPDATES).uint64
  let response = await peer.lightClientUpdatesByRange(startPeriod, reqCount)
  if response.isOk:
    if response.get.lenu64 > reqCount:
      raise newException(ResponseError, "Too many values in response" &
        " (" & Base10.toString(response.get.lenu64) &
        " > " & Base10.toString(reqCount.uint) & ")")
    var expectedPeriod = startPeriod
    for update in response.get:
      let
        attestedPeriod = update.attested_header.slot.sync_committee_period
        signaturePeriod = update.signature_slot.sync_committee_period
      if attestedPeriod != update.signature_slot.sync_committee_period:
        raise newException(ResponseError, "Conflicting sync committee periods" &
          " (signature: " & Base10.toString(distinctBase(signaturePeriod)) &
          " != " & Base10.toString(distinctBase(attestedPeriod)) & ")")
      if attestedPeriod < expectedPeriod:
        raise newException(ResponseError, "Unexpected sync committee period" &
          " (" & Base10.toString(distinctBase(attestedPeriod)) &
          " < " & Base10.toString(distinctBase(expectedPeriod)) & ")")
      if attestedPeriod > expectedPeriod:
        if attestedPeriod > lastPeriod:
          raise newException(ResponseError, "Sync committee period too high" &
            " (" & Base10.toString(distinctBase(attestedPeriod)) &
            " > " & Base10.toString(distinctBase(lastPeriod)) & ")")
        expectedPeriod = attestedPeriod
      inc expectedPeriod
  return response

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#getlightclientfinalityupdate
proc doRequest(
    e: typedesc[FinalityUpdate],
    peer: Peer
): Future[NetRes[altair.LightClientFinalityUpdate]] {.
    raises: [Defect, IOError].} =
  peer.lightClientFinalityUpdate()

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#getlightclientoptimisticupdate
proc doRequest(
    e: typedesc[OptimisticUpdate],
    peer: Peer
): Future[NetRes[altair.LightClientOptimisticUpdate]] {.
    raises: [Defect, IOError].} =
  peer.lightClientOptimisticUpdate()

template valueVerifier[E](
    self: LightClientManager,
    e: typedesc[E]
): ValueVerifier[E.V] =
  when E.V is altair.LightClientBootstrap:
    self.bootstrapVerifier
  elif E.V is altair.LightClientUpdate:
    self.updateVerifier
  elif E.V is altair.LightClientFinalityUpdate:
    self.finalityUpdateVerifier
  elif E.V is altair.LightClientOptimisticUpdate:
    self.optimisticUpdateVerifier
  else: static: doAssert false

iterator values(v: auto): auto =
  ## Local helper for `workerTask` to share the same implementation for both
  ## scalar and aggregate values, by treating scalars as 1-length aggregates.
  when v is seq:
    for i in v:
      yield i
  else:
    yield v

proc workerTask[E](
    self: LightClientManager,
    e: typedesc[E],
    key: E.K
): Future[bool] {.async.} =
  var
    peer: Peer
    didProgress = false
  try:
    peer = self.network.peerPool.acquireNoWait()
    let value =
      when E.K is Nothing:
        await E.doRequest(peer)
      else:
        await E.doRequest(peer, key)
    if value.isOk:
      var applyReward = false
      for val in value.get.values:
        let res = await self.valueVerifier(E)(val)
        if res.isErr:
          case res.error
          of BlockError.MissingParent:
            # Stop, requires different request to progress
            return didProgress
          of BlockError.Duplicate:
            # Ignore, a concurrent request may have already fulfilled this
            when E.V is altair.LightClientBootstrap:
              didProgress = true
            else:
              discard
          of BlockError.UnviableFork:
            # Descore, peer is on an incompatible fork version
            notice "Received value from an unviable fork", value = val.shortLog,
              endpoint = E.name, peer, peer_score = peer.getScore()
            peer.updateScore(PeerScoreUnviableFork)
            return didProgress
          of BlockError.Invalid:
            # Descore, received data is malformed
            warn "Received invalid value", value = val.shortLog,
              endpoint = E.name, peer, peer_score = peer.getScore()
            peer.updateScore(PeerScoreBadBlocks)
            return didProgress
        else:
          # Reward, peer returned something useful
          applyReward = true
          didProgress = true
      if applyReward:
        peer.updateScore(PeerScoreGoodBlocks)
    else:
      peer.updateScore(PeerScoreNoBlocks)
      debug "Failed to receive value on request", value,
        endpoint = E.name, peer, peer_score = peer.getScore()
  except ResponseError as exc:
    warn "Received invalid response", error = exc.msg,
      endpoint = E.name, peer, peer_score = peer.getScore()
    peer.updateScore(PeerScoreBadBlocks)
  except CancelledError as exc:
    raise exc
  except PeerPoolError as exc:
    debug "Failed to acquire peer", exc = exc.msg
  except CatchableError as exc:
    if peer != nil:
      peer.updateScore(PeerScoreNoBlocks)
      debug "Unexpected exception while receiving value", exc = exc.msg,
        endpoint = E.name, peer, peer_score = peer.getScore()
    raise exc
  finally:
    if peer != nil:
      self.network.peerPool.release(peer)
  return didProgress

proc query[E](
    self: LightClientManager,
    e: typedesc[E],
    key: E.K
): Future[bool] {.async.} =
  const PARALLEL_REQUESTS = 2
  var workers: array[PARALLEL_REQUESTS, Future[bool]]

  let
    progressFut = newFuture[void]("lcmanProgress")
    doneFut = newFuture[void]("lcmanDone")
  var
    numCompleted = 0
    maxCompleted = workers.len

  proc handleFinishedWorker(future: pointer) =
    try:
      let didProgress = cast[Future[bool]](future).read()
      if didProgress and not progressFut.finished:
        progressFut.complete()
    except CancelledError as exc:
      if not progressFut.finished:
        progressFut.cancel()
    except CatchableError as exc:
      discard
    finally:
      inc numCompleted
      if numCompleted == maxCompleted:
        doneFut.complete()

  try:
    # Start concurrent workers
    for i in 0 ..< workers.len:
      try:
        workers[i] = self.workerTask(e, key)
        workers[i].addCallback(handleFinishedWorker)
      except CancelledError as exc:
        raise exc
      except CatchableError as exc:
        workers[i] = newFuture[bool]()
        workers[i].complete(false)

    # Wait for any worker to report progress, or for all workers to finish
    discard await race(progressFut, doneFut)
  finally:
    for i in 0 ..< maxCompleted:
      if workers[i] == nil:
        maxCompleted = i
        if numCompleted == maxCompleted:
          doneFut.complete()
        break
      if not workers[i].finished:
        workers[i].cancel()
    while true:
      try:
        await allFutures(workers[0 ..< maxCompleted])
        break
      except CancelledError as exc:
        continue
    while true:
      try:
        await doneFut
        break
      except CancelledError as exc:
        continue

  if not progressFut.finished:
    progressFut.cancel()
  return progressFut.completed

template query(
    self: LightClientManager,
    e: typedesc[UpdatesByRange],
    key: SyncCommitteePeriod
): Future[bool] =
  self.query(e, key .. key)

template query[E](
    self: LightClientManager,
    e: typedesc[E]
): Future[bool] =
  self.query(e, Nothing())

type SchedulingMode = enum
  Soon,
  CurrentPeriod,
  NextPeriod

func fetchTime(
    self: LightClientManager,
    wallTime: BeaconTime,
    schedulingMode: SchedulingMode
): BeaconTime =
  let
    remainingTime =
      case schedulingMode:
      of Soon:
        chronos.seconds(0)
      of CurrentPeriod:
        let
          wallPeriod = wallTime.slotOrZero().sync_committee_period
          deadlineSlot = (wallPeriod + 1).start_slot - 1
          deadline = deadlineSlot.start_beacon_time()
        chronos.nanoseconds((deadline - wallTime).nanoseconds)
      of NextPeriod:
        chronos.seconds(
          (SLOTS_PER_SYNC_COMMITTEE_PERIOD * SECONDS_PER_SLOT).int64)
    minDelay = max(remainingTime div 8, chronos.seconds(30))
    jitterSeconds = (minDelay * 2).seconds
    jitterDelay = chronos.seconds(self.rng[].rand(jitterSeconds).int64)
  return wallTime + minDelay + jitterDelay

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#light-client-sync-process
proc loop(self: LightClientManager) {.async.} =
  var nextFetchTime = self.getBeaconTime()
  while true:
    # Periodically wake and check for changes
    let wallTime = self.getBeaconTime()
    if wallTime < nextFetchTime or
        self.network.peerPool.lenAvailable < 1:
      await sleepAsync(chronos.seconds(2))
      continue

    # Obtain bootstrap data once a trusted block root is supplied
    if not self.isLightClientStoreInitialized():
      let trustedBlockRoot = self.getTrustedBlockRoot()
      if trustedBlockRoot.isNone:
        await sleepAsync(chronos.seconds(2))
        continue

      let didProgress = await self.query(Bootstrap, trustedBlockRoot.get)
      if not didProgress:
        nextFetchTime = self.fetchTime(wallTime, Soon)
      continue

    # Fetch updates
    var allowWaitNextPeriod = false
    let
      finalized = self.getFinalizedPeriod()
      optimistic = self.getOptimisticPeriod()
      current = wallTime.slotOrZero().sync_committee_period
      isNextSyncCommitteeKnown = self.isNextSyncCommitteeKnown()

      didProgress =
        if finalized == optimistic and not isNextSyncCommitteeKnown:
          if finalized >= current:
            await self.query(UpdatesByRange, finalized)
          else:
            await self.query(UpdatesByRange, finalized ..< current)
        elif finalized + 1 < current:
          await self.query(UpdatesByRange, finalized + 1 ..< current)
        elif finalized != optimistic:
          await self.query(FinalityUpdate)
        else:
          allowWaitNextPeriod = true
          await self.query(OptimisticUpdate)

      schedulingMode =
        if not didProgress or not self.isGossipSupported(current):
          Soon
        elif not allowWaitNextPeriod:
          CurrentPeriod
        else:
          NextPeriod

    nextFetchTime = self.fetchTime(wallTime, schedulingMode)

proc start*(self: var LightClientManager) =
  ## Start light client manager's loop.
  doAssert self.loopFuture == nil
  self.loopFuture = self.loop()

proc stop*(self: var LightClientManager) {.async.} =
  ## Stop light client manager's loop.
  if self.loopFuture != nil:
    await self.loopFuture.cancelAndWait()
    self.loopFuture = nil
