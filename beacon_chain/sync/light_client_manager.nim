# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import chronos, chronicles, stew/base10
import
  eth/p2p/discoveryv5/random2,
  ../spec/datatypes/[altair],
  ../networking/eth2_network,
  "."/sync_protocol, "."/sync_manager
export sync_manager

logScope:
  topics = "lcman"

type
  Nothing = object
  ResponseError = object of CatchableError
  Endpoint[K, V] =
    (K, V) # https://github.com/nim-lang/Nim/issues/19531
  BestLightClientUpdatesByRangeEndpoint =
    Endpoint[Slice[SyncCommitteePeriod], altair.LightClientUpdate]
  LatestLightClientUpdateEndpoint =
    Endpoint[Nothing, altair.LightClientUpdate]
  OptimisticLightClientUpdateEndpoint =
    Endpoint[Nothing, OptimisticLightClientUpdate]
  LightClientBootstrapEndpoint =
    Endpoint[Eth2Digest, altair.LightClientBootstrap]

  ValueVerifier[V] =
    proc(v: V): Future[Result[void, BlockError]] {.gcsafe, raises: [Defect].}
  LightClientBootstrapVerifier* =
    ValueVerifier[altair.LightClientBootstrap]
  LightClientUpdateVerifier* =
    ValueVerifier[altair.LightClientUpdate]
  OptimisticLightClientUpdateVerifier* =
    ValueVerifier[OptimisticLightClientUpdate]

  GetTrustedBlockRootCallback* =
    proc(): Option[Eth2Digest] {.gcsafe, raises: [Defect].}
  GetBoolCallback* =
    proc(): bool {.gcsafe, raises: [Defect].}
  GetSyncCommitteePeriodCallback* =
    proc(): SyncCommitteePeriod {.gcsafe, raises: [Defect].}

  LightClientManager* = object
    network: Eth2Node
    rng: ref BrHmacDrbgContext
    bootstrapVerifier: LightClientBootstrapVerifier
    updateVerifier: LightClientUpdateVerifier
    optimisticUpdateVerifier: OptimisticLightClientUpdateVerifier
    getTrustedBlockRoot: GetTrustedBlockRootCallback
    getLocalWallPeriod: GetSyncCommitteePeriodCallback
    getFinalizedPeriod: GetSyncCommitteePeriodCallback
    isLightClientStoreInitialized: GetBoolCallback
    isNextSyncCommitteeKnown: GetBoolCallback
    loopFuture: Future[void]

func init*(
    T: type LightClientManager,
    network: Eth2Node,
    rng: ref BrHmacDrbgContext,
    bootstrapVerifier: LightClientBootstrapVerifier,
    updateVerifier: LightClientUpdateVerifier,
    optimisticUpdateVerifier: OptimisticLightClientUpdateVerifier,
    getTrustedBlockRoot: GetTrustedBlockRootCallback,
    getLocalWallPeriod: GetSyncCommitteePeriodCallback,
    getFinalizedPeriod: GetSyncCommitteePeriodCallback,
    isLightClientStoreInitialized: GetBoolCallback,
    isNextSyncCommitteeKnown: GetBoolCallback
): LightClientManager =
  ## Initialize light client manager.
  LightClientManager(
    network: network,
    rng: rng,
    bootstrapVerifier: bootstrapVerifier,
    updateVerifier: updateVerifier,
    optimisticUpdateVerifier: optimisticUpdateVerifier,
    getTrustedBlockRoot: getTrustedBlockRoot,
    getLocalWallPeriod: getLocalWallPeriod,
    getFinalizedPeriod: getFinalizedPeriod,
    isLightClientStoreInitialized: isLightClientStoreInitialized,
    isNextSyncCommitteeKnown: isNextSyncCommitteeKnown
  )

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#bestlightclientupdatesbyrange
from ../spec/light_client_sync import get_active_header
from sync_protocol import MAX_REQUEST_LIGHT_CLIENT_UPDATES
type BestLightClientUpdatesByRangeResp = NetRes[seq[altair.LightClientUpdate]]
proc doRequest(
    e: typedesc[BestLightClientUpdatesByRangeEndpoint],
    peer: Peer,
    periods: Slice[SyncCommitteePeriod]
): Future[BestLightClientUpdatesByRangeResp] {.
    async, raises: [Defect, IOError].} =
  let
    startPeriod = periods.a
    lastPeriod = periods.b
    reqCount = min(periods.len, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
  let response =
    await peer.bestLightClientUpdatesByRange(startPeriod, reqCount.uint64)
  if response.isOk:
    if response.get.len > reqCount:
      raise newException(ResponseError, "Too many values in response" &
        " (" & Base10.toString(response.get.lenu64) &
        " > " & Base10.toString(reqCount.uint) & ")")
    var expectedPeriod = startPeriod
    for update in response.get:
      let period = update.get_active_header().slot.sync_committee_period
      if period < expectedPeriod:
        raise newException(ResponseError, "Unexpected sync committee period" &
          " (" & Base10.toString(distinctBase(period)) &
          " < " & Base10.toString(distinctBase(expectedPeriod)) & ")")
      if period > expectedPeriod:
        if period > lastPeriod:
          raise newException(ResponseError, "Sync committee period too high" &
            " (" & Base10.toString(distinctBase(period)) &
            " > " & Base10.toString(distinctBase(lastPeriod)) & ")")
        expectedPeriod = period
      inc expectedPeriod
  return response

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#getlatestlightclientupdate
proc doRequest(
    e: typedesc[LatestLightClientUpdateEndpoint],
    peer: Peer
): Future[NetRes[altair.LightClientUpdate]] {.
    raises: [Defect, IOError].} =
  peer.latestLightClientUpdate()

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#getoptimisticlightclientupdate
proc doRequest(
    e: typedesc[OptimisticLightClientUpdateEndpoint],
    peer: Peer
): Future[NetRes[OptimisticLightClientUpdate]] {.
    raises: [Defect, IOError].} =
  peer.optimisticLightClientUpdate()

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#getlightclientbootstrap
proc doRequest(
    e: typedesc[LightClientBootstrapEndpoint],
    peer: Peer,
    blockRoot: Eth2Digest
): Future[NetRes[altair.LightClientBootstrap]] {.
    raises: [Defect, IOError].} =
  peer.lightClientBootstrap(blockRoot)

template valueVerifier[E](
    self: LightClientManager,
    e: typedesc[E]
): ValueVerifier[E.V] =
  when E.V is altair.LightClientBootstrap:
    self.bootstrapVerifier
  elif E.V is altair.LightClientUpdate:
    self.updateVerifier
  elif E.V is OptimisticLightClientUpdate:
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
    peer = await self.network.peerPool.acquire()
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
            # Ignore, a concurrent request may have queried this already
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
  except CatchableError as exc:
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
  let start = SyncMoment.now(0)

  const PARALLEL_REQUESTS = 2
  var workers: array[PARALLEL_REQUESTS, Future[bool]]

  # Start concurrent workers
  for i in 0 ..< workers.len:
    try:
      workers[i] = self.workerTask(e, key)
    except CatchableError as exc:
      for j in 0 ..< i:
        if not workers[j].finished:
          workers[j].cancel()
      return false

  # Wait for any worker to report progress,
  # or for all workers to finish
  proc cancelAll() =
    for i in 0 ..< workers.len:
      if not workers[i].finished:
        workers[i].cancel()

  var anyDidProgress = false
  proc handleFinishedWorker(future: pointer) =
    try:
      let didProgress = cast[Future[bool]](future).read()
      if didProgress:
        anyDidProgress = true
        cancelAll()
    except CatchableError as exc:
      cancelAll()

  for i in 0 ..< workers.len:
    workers[i].addCallback(handleFinishedWorker)
  await allFutures(workers)

  return anyDidProgress

template query[E](
    self: LightClientManager,
    e: typedesc[E]
): Future[bool] =
  self.query(e, Nothing())

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#sync-via-libp2p
proc loop(self: LightClientManager) {.async.} =
  var nextFetchTick = Moment.now()
  while true:
    # Obtain bootstrap data once a trusted block root is supplied
    while not self.isLightClientStoreInitialized():
      let trustedBlockRoot = self.getTrustedBlockRoot()
      if trustedBlockRoot.isNone:
        await sleepAsync(chronos.seconds(2))
        continue

      let didProgress = await self.query(
        LightClientBootstrapEndpoint,
        trustedBlockRoot.get)
      if not didProgress:
        await sleepAsync(chronos.seconds(60))
        continue

    # Determine whether latest light client data can be applied
    let
      currentPeriod = self.getLocalWallPeriod()
      finalizedPeriod = self.getFinalizedPeriod()
      isNextSyncCommitteeKnown = self.isNextSyncCommitteeKnown()
      isInSync =
        if isNextSyncCommitteeKnown:
          currentPeriod in [finalizedPeriod, finalizedPeriod + 1]
        else:
          currentPeriod == finalizedPeriod

    # If not in sync, request light client data for older periods
    if not isInSync:
      doAssert currentPeriod > finalizedPeriod
      let didProgress = await self.query(
        BestLightClientUpdatesByRangeEndpoint,
        finalizedPeriod ..< currentPeriod)
      if not didProgress:
        await sleepAsync(chronos.seconds(60))
        continue

      if self.getFinalizedPeriod() >= (currentPeriod - 1):
        # Fetch a single optimistic update to avoid waiting for gossip
        discard await self.query(OptimisticLightClientUpdateEndpoint)

      nextFetchTick = Moment.now()
      continue

    # Fetch a full update periodically to keep track of next sync committee
    if Moment.now() >= nextFetchTick:
      const SECONDS_PER_PERIOD =
        SLOTS_PER_SYNC_COMMITTEE_PERIOD * SECONDS_PER_SLOT
      let
        didProgress = await self.query(LatestLightClientUpdateEndpoint)
        delaySeconds =
          if didProgress:
            const
              minDelaySeconds = SECONDS_PER_PERIOD div 8
              jitterSeconds = SECONDS_PER_PERIOD div 4
            (minDelaySeconds + self.rng[].rand(jitterSeconds).uint64).int64
          else:
            const
              minDelaySeconds = SECONDS_PER_PERIOD div 64
              jitterSeconds = SECONDS_PER_PERIOD div 32
            (minDelaySeconds + self.rng[].rand(jitterSeconds).uint64).int64
      nextFetchTick = Moment.fromNow(chronos.seconds(delaySeconds))

    # Periodically wake and check if still in sync
    await sleepAsync(chronos.seconds(2))

proc start*(self: var LightClientManager) =
  ## Start light client manager's loop.
  doAssert self.loopFuture == nil
  self.loopFuture = self.loop()

proc stop*(self: var LightClientManager) {.async.} =
  ## Stop light client manager's loop.
  if self.loopFuture != nil:
    await self.loopFuture.cancelAndWait()
    self.loopFuture = nil
