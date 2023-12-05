# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronos, chronicles
import
  ../spec/network,
  ../networking/eth2_network,
  ../beacon_clock,
  "."/[light_client_sync_helpers, sync_protocol, sync_manager]
export sync_manager

logScope:
  topics = "lcman"

type
  Nothing = object
  ResponseError = object of CatchableError
  Endpoint[K, V] =
    (K, V) # https://github.com/nim-lang/Nim/issues/19531
  Bootstrap =
    Endpoint[Eth2Digest, ForkedLightClientBootstrap]
  UpdatesByRange =
    Endpoint[
      tuple[startPeriod: SyncCommitteePeriod, count: uint64],
      ForkedLightClientUpdate]
  FinalityUpdate =
    Endpoint[Nothing, ForkedLightClientFinalityUpdate]
  OptimisticUpdate =
    Endpoint[Nothing, ForkedLightClientOptimisticUpdate]

  ValueVerifier[V] =
    proc(v: V): Future[Result[void, VerifierError]] {.gcsafe, raises: [].}
  BootstrapVerifier* =
    ValueVerifier[ForkedLightClientBootstrap]
  UpdateVerifier* =
    ValueVerifier[ForkedLightClientUpdate]
  FinalityUpdateVerifier* =
    ValueVerifier[ForkedLightClientFinalityUpdate]
  OptimisticUpdateVerifier* =
    ValueVerifier[ForkedLightClientOptimisticUpdate]

  GetTrustedBlockRootCallback* =
    proc(): Option[Eth2Digest] {.gcsafe, raises: [].}
  GetBoolCallback* =
    proc(): bool {.gcsafe, raises: [].}
  GetSyncCommitteePeriodCallback* =
    proc(): SyncCommitteePeriod {.gcsafe, raises: [].}

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

  period.isGossipSupported(
    finalizedPeriod = self.getFinalizedPeriod(),
    isNextSyncCommitteeKnown = self.isNextSyncCommitteeKnown())

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientbootstrap
proc doRequest(
    e: typedesc[Bootstrap],
    peer: Peer,
    blockRoot: Eth2Digest
): Future[NetRes[ForkedLightClientBootstrap]] {.
    raises: [IOError].} =
  peer.lightClientBootstrap(blockRoot)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#lightclientupdatesbyrange
type LightClientUpdatesByRangeResponse =
  NetRes[List[ForkedLightClientUpdate, MAX_REQUEST_LIGHT_CLIENT_UPDATES]]
proc doRequest(
    e: typedesc[UpdatesByRange],
    peer: Peer,
    key: tuple[startPeriod: SyncCommitteePeriod, count: uint64]
): Future[LightClientUpdatesByRangeResponse] {.
    async.} =
  let (startPeriod, count) = key
  doAssert count > 0 and count <= MAX_REQUEST_LIGHT_CLIENT_UPDATES
  let response = await peer.lightClientUpdatesByRange(startPeriod, count)
  if response.isOk:
    let e = distinctBase(response.get)
      .checkLightClientUpdates(startPeriod, count)
    if e.isErr:
      raise newException(ResponseError, e.error)
  return response

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientfinalityupdate
proc doRequest(
    e: typedesc[FinalityUpdate],
    peer: Peer
): Future[NetRes[ForkedLightClientFinalityUpdate]] =
  peer.lightClientFinalityUpdate()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientoptimisticupdate
proc doRequest(
    e: typedesc[OptimisticUpdate],
    peer: Peer
): Future[NetRes[ForkedLightClientOptimisticUpdate]] =
  peer.lightClientOptimisticUpdate()

template valueVerifier[E](
    self: LightClientManager,
    e: typedesc[E]
): ValueVerifier[E.V] =
  when E.V is ForkedLightClientBootstrap:
    self.bootstrapVerifier
  elif E.V is ForkedLightClientUpdate:
    self.updateVerifier
  elif E.V is ForkedLightClientFinalityUpdate:
    self.finalityUpdateVerifier
  elif E.V is ForkedLightClientOptimisticUpdate:
    self.optimisticUpdateVerifier
  else: static: doAssert false

iterator values(v: auto): auto =
  ## Local helper for `workerTask` to share the same implementation for both
  ## scalar and aggregate values, by treating scalars as 1-length aggregates.
  when v is List:
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
      for val in value.get().values:
        let res = await self.valueVerifier(E)(val)
        if res.isErr:
          case res.error
          of VerifierError.MissingParent:
            # Stop, requires different request to progress
            return didProgress
          of VerifierError.Duplicate:
            # Ignore, a concurrent request may have already fulfilled this
            when E.V is ForkedLightClientBootstrap:
              didProgress = true
            else:
              discard
          of VerifierError.UnviableFork:
            # Descore, peer is on an incompatible fork version
            withForkyObject(val):
              when lcDataFork > LightClientDataFork.None:
                notice "Received value from an unviable fork",
                  value = forkyObject,
                  endpoint = E.name, peer, peer_score = peer.getScore()
              else:
                notice "Received value from an unviable fork",
                  endpoint = E.name, peer, peer_score = peer.getScore()
            peer.updateScore(PeerScoreUnviableFork)
            return didProgress
          of VerifierError.Invalid:
            # Descore, received data is malformed
            withForkyObject(val):
              when lcDataFork > LightClientDataFork.None:
                warn "Received invalid value", value = forkyObject.shortLog,
                  endpoint = E.name, peer, peer_score = peer.getScore()
              else:
                warn "Received invalid value",
                  endpoint = E.name, peer, peer_score = peer.getScore()
            peer.updateScore(PeerScoreBadValues)
            return didProgress
        else:
          # Reward, peer returned something useful
          applyReward = true
          didProgress = true
      if applyReward:
        peer.updateScore(PeerScoreGoodValues)
    else:
      peer.updateScore(PeerScoreNoValues)
      debug "Failed to receive value on request", value,
        endpoint = E.name, peer, peer_score = peer.getScore()
  except ResponseError as exc:
    warn "Received invalid response", error = exc.msg,
      endpoint = E.name, peer, peer_score = peer.getScore()
    peer.updateScore(PeerScoreBadValues)
  except CancelledError as exc:
    raise exc
  except PeerPoolError as exc:
    debug "Failed to acquire peer", exc = exc.msg
  except CatchableError as exc:
    if peer != nil:
      peer.updateScore(PeerScoreNoValues)
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
    except CancelledError:
      if not progressFut.finished:
        progressFut.cancelSoon()
    except CatchableError:
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
      except CatchableError:
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
        workers[i].cancelSoon()
    while true:
      try:
        await allFutures(workers[0 ..< maxCompleted])
        break
      except CancelledError:
        continue
    while true:
      try:
        await doneFut
        break
      except CancelledError:
        continue

  if not progressFut.finished:
    progressFut.cancelSoon()
  return progressFut.completed

template query[E](
    self: LightClientManager,
    e: typedesc[E]
): Future[bool] =
  self.query(e, Nothing())

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/light-client.md#light-client-sync-process
proc loop(self: LightClientManager) {.async.} =
  var nextSyncTaskTime = self.getBeaconTime()
  while true:
    # Periodically wake and check for changes
    let wallTime = self.getBeaconTime()
    if wallTime < nextSyncTaskTime or
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
      nextSyncTaskTime =
        if didProgress:
          wallTime
        else:
          wallTime + self.rng.computeDelayWithJitter(chronos.seconds(0))
      continue

    # Fetch updates
    let
      current = wallTime.slotOrZero().sync_committee_period

      syncTask = nextLightClientSyncTask(
        current = current,
        finalized = self.getFinalizedPeriod(),
        optimistic = self.getOptimisticPeriod(),
        isNextSyncCommitteeKnown = self.isNextSyncCommitteeKnown())

      didProgress =
        case syncTask.kind
        of LcSyncKind.UpdatesByRange:
          await self.query(UpdatesByRange,
            (startPeriod: syncTask.startPeriod, count: syncTask.count))
        of LcSyncKind.FinalityUpdate:
          await self.query(FinalityUpdate)
        of LcSyncKind.OptimisticUpdate:
          await self.query(OptimisticUpdate)

    nextSyncTaskTime = wallTime + self.rng.nextLcSyncTaskDelay(
      wallTime,
      finalized = self.getFinalizedPeriod(),
      optimistic = self.getOptimisticPeriod(),
      isNextSyncCommitteeKnown = self.isNextSyncCommitteeKnown(),
      didLatestSyncTaskProgress = didProgress)

proc start*(self: var LightClientManager) =
  ## Start light client manager's loop.
  doAssert self.loopFuture == nil
  self.loopFuture = self.loop()

proc stop*(self: var LightClientManager) {.async.} =
  ## Stop light client manager's loop.
  if self.loopFuture != nil:
    await self.loopFuture.cancelAndWait()
    self.loopFuture = nil
