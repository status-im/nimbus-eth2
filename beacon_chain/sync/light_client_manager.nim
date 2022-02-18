# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import chronos, chronicles
import
  eth/p2p/discoveryv5/random2,
  ../spec/datatypes/[altair],
  ../networking/eth2_network,
  "."/sync_protocol, "."/sync_manager

logScope:
  topics = "lcman"

type
  Nothing = object
  LightClientEndpoint[K, V] =
    (K, V) # https://github.com/nim-lang/Nim/issues/19531
  LatestLightClientUpdateEndpoint =
    LightClientEndpoint[Nothing, altair.LightClientUpdate]
  OptimisticLightClientUpdateEndpoint =
    LightClientEndpoint[Nothing, altair.OptimisticLightClientUpdate]
  LightClientBootstrapEndpoint =
    LightClientEndpoint[Eth2Digest, altair.LightClientBootstrap]

  ValueVerifier[V] =
    proc(v: V): Future[Result[void, BlockError]] {.gcsafe, raises: [Defect].}
  LightClientBootstrapVerifier* =
    ValueVerifier[altair.LightClientBootstrap]
  LightClientUpdateVerifier* =
    ValueVerifier[altair.LightClientUpdate]
  OptimisticLightClientUpdateVerifier* =
    ValueVerifier[altair.OptimisticLightClientUpdate]

  CanApplyLatestLightClientUpdatesCallback* =
    proc(): bool {.gcsafe, raises: [Defect].}

  LightClientManager* = object
    network: Eth2Node
    rng: ref BrHmacDrbgContext
    bootstrapVerifier: LightClientBootstrapVerifier
    updateVerifier: LightClientUpdateVerifier
    optimisticUpdateVerifier: OptimisticLightClientUpdateVerifier
    canApplyLatestUpdates: CanApplyLatestLightClientUpdatesCallback
    loopFuture: Future[void]

func init*(
    T: type LightClientManager,
    network: Eth2Node,
    rng: ref BrHmacDrbgContext,
    bootstrapVerifier: LightClientBootstrapVerifier,
    updateVerifier: LightClientUpdateVerifier,
    optimisticUpdateVerifier: OptimisticLightClientUpdateVerifier,
    canApplyLatestUpdatesCallback: CanApplyLatestLightClientUpdatesCallback
): LightClientManager =
  ## Initialize light client manager.
  LightClientManager(
    network: network,
    rng: rng,
    bootstrapVerifier: bootstrapVerifier,
    updateVerifier: updateVerifier,
    optimisticUpdateVerifier: optimisticUpdateVerifier,
    canApplyLatestUpdates: canApplyLatestUpdatesCallback
  )

proc doRequest(
    e: typedesc[LightClientBootstrapEndpoint],
    peer: Peer,
    blockRoot: Eth2Digest
): Future[NetRes[altair.LightClientBootstrap]] {.
    raises: [Defect, IOError].} =
  peer.lightClientBootstrap(blockRoot)

proc doRequest(
    e: typedesc[LatestLightClientUpdateEndpoint],
    peer: Peer
): Future[NetRes[altair.LightClientUpdate]] {.
    raises: [Defect, IOError].} =
  peer.latestLightClientUpdate()

proc doRequest(
    e: typedesc[OptimisticLightClientUpdateEndpoint],
    peer: Peer
): Future[NetRes[altair.OptimisticLightClientUpdate]] {.
    raises: [Defect, IOError].} =
  peer.optimisticLightClientUpdate()

template valueVerifier[E](
    self: LightClientManager,
    e: typedesc[E]
): ValueVerifier[E.V] =
  when E.V is altair.LightClientBootstrap:
    self.bootstrapVerifier
  elif E.V is altair.LightClientUpdate:
    self.updateVerifier
  elif E.V is altair.OptimisticLightClientUpdate:
    self.optimisticUpdateVerifier
  else: static: doAssert false

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
      let
        val = value.get
        res = await self.valueVerifier(E)(val)
      if res.isErr:
        case res.error
        of BlockError.MissingParent:
          # Ignore, may have lost sync and require other request to progress
          discard
        of BlockError.Duplicate:
          # Ignore, a concurrent request may have fulfilled this already
          when E.V is altair.LightClientBootstrap:
            didProgress = true
          else:
            discard
        of BlockError.UnviableFork:
          # Descore, peer is on an incompatible fork version
          notice "Received value from an unviable fork", value = val.shortLog,
            endpoint = E.name, peer, peer_score = peer.getScore()
          peer.updateScore(PeerScoreUnviableFork)
        of BlockError.Invalid:
          # Descore, received data is malformed
          warn "Received invalid value", value = val.shortLog,
            endpoint = E.name, peer, peer_score = peer.getScore()
          peer.updateScore(PeerScoreBadBlocks)
      else:
        # Reward, peer returned something useful
        peer.updateScore(PeerScoreGoodBlocks)
        didProgress = true
    else:
      peer.updateScore(PeerScoreNoBlocks)
      debug "Failed to receive value on request", value,
        endpoint = E.name, peer, peer_score = peer.getScore()
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

proc fulfill[E](
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

template fulfill[E](
    self: LightClientManager,
    e: typedesc[E]
): Future[bool] =
  self.fulfill(e, Nothing())

proc loop(
    self: LightClientManager,
    trustedBlockRoot: Option[Eth2Digest]) {.async.} =
  # Obtain bootstrap data if a trusted block root is supplied
  if trustedBlockRoot.isSome:
    while true:
      if await self.fulfill(LightClientBootstrapEndpoint, trustedBlockRoot.get):
        break
      await sleepAsync(chronos.seconds(60))

  while true:
    # While we are out of sync, latest values will not apply
    while not self.canApplyLatestUpdates():
      await sleepAsync(chronos.seconds(2))

    # Fetch 1 `OptimisticLightClientUpdate` to avoid waiting for gossip
    try:
      discard await self.fulfill(OptimisticLightClientUpdateEndpoint)
    except CatchableError as exc:
      raise exc

    # Periodically fetch `LightClientUpdate` to advance sync committee period
    var nextFetchTick = Moment.now()
    while self.canApplyLatestUpdates():
      if Moment.now() > nextFetchTick:
        const SECONDS_PER_PERIOD =
          SLOTS_PER_SYNC_COMMITTEE_PERIOD * SECONDS_PER_SLOT
        let
          didProgress = await self.fulfill(LatestLightClientUpdateEndpoint)
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
      await sleepAsync(chronos.seconds(2))

proc start*(
    self: var LightClientManager,
    trustedBlockRoot: Option[Eth2Digest]) =
  ## Start light client manager's loop.
  doAssert self.loopFuture == nil
  self.loopFuture = self.loop(trustedBlockRoot)

proc stop*(self: var LightClientManager) =
  ## Stop light client manager's loop.
  if self.loopFuture != nil:
    self.loopFuture.cancel()
    self.loopFuture = nil
