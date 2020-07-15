import options, sequtils, strutils
import chronos, chronicles
import spec/[datatypes, digest], eth2_network, beacon_node_types, sync_protocol,
       sync_manager, ssz/merkleization

logScope:
  topics = "requman"

const
  MAX_REQUEST_BLOCKS* = 4 # Specification's value is 1024.
    ## Maximum number of blocks, which can be requested by beaconBlocksByRoot.
  PARALLEL_REQUESTS* = 2
    ## Number of peers we using to resolve our request.

type
  RequestManager* = object
    network*: Eth2Node
    queue*: AsyncQueue[FetchRecord]
    responseHandler*: FetchAncestorsResponseHandler
    loopFuture: Future[void]

  FetchAncestorsResponseHandler = proc (b: SignedBeaconBlock) {.gcsafe.}

func shortLog*(x: seq[Eth2Digest]): string =
  "[" & x.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(x: seq[FetchRecord]): string =
  "[" & x.mapIt(shortLog(it.root)).join(", ") & "]"

proc init*(T: type RequestManager, network: Eth2Node,
           responseCb: FetchAncestorsResponseHandler): T =
  T(
    network: network, queue: newAsyncQueue[FetchRecord](),
    responseHandler: responseCb
  )

proc checkResponse(roots: openArray[Eth2Digest],
                   blocks: openArray[SignedBeaconBlock]): bool =
  ## This procedure checks peer's response.
  var checks = @roots
  if len(blocks) > len(roots):
    return false
  for blk in blocks:
    let res = checks.find(blk.root)
    if res == -1:
      return false
    else:
      checks.del(res)
  return true

proc fetchAncestorBlocksFromNetwork(rman: RequestManager,
                                    items: seq[Eth2Digest]) {.async.} =
  var peer: Peer
  try:
    peer = await rman.network.peerPool.acquire()
    debug "Requesting blocks by root", peer = peer, blocks = shortLog(items),
                                       peer_score = peer.getScore()

    let blocks = await peer.beaconBlocksByRoot(BlockRootsList items)
    if blocks.isOk:
      let ublocks = blocks.get()
      if checkResponse(items, ublocks):
        for b in ublocks:
          rman.responseHandler(b)
        peer.updateScore(PeerScoreGoodBlocks)
      else:
        peer.updateScore(PeerScoreBadResponse)
    else:
      peer.updateScore(PeerScoreNoBlocks)

  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    debug "Error while fetching ancestor blocks", exc = exc.msg,
          items = shortLog(items), peer = peer, peer_score = peer.getScore()
    raise exc
  finally:
    if not(isNil(peer)):
      rman.network.peerPool.release(peer)

proc requestManagerLoop(rman: RequestManager) {.async.} =
  var rootList = newSeq[Eth2Digest]()
  var workers = newSeq[Future[void]](PARALLEL_REQUESTS)
  while true:
    try:
      rootList.setLen(0)
      let req = await rman.queue.popFirst()
      rootList.add(req.root)

      var count = min(MAX_REQUEST_BLOCKS - 1, len(rman.queue))
      while count > 0:
        rootList.add(rman.queue.popFirstNoWait().root)
        dec(count)

      let start = SyncMoment.now(Slot(0))

      for i in 0 ..< PARALLEL_REQUESTS:
        workers[i] = rman.fetchAncestorBlocksFromNetwork(rootList)

      # We do not care about
      await allFutures(workers)

      let finish = SyncMoment.now(Slot(0) + uint64(len(rootList)))

      var succeed = 0
      for worker in workers:
        if worker.finished() and not(worker.failed()):
          inc(succeed)

      debug "Request manager tick", blocks_count = len(rootList),
                                    succeed = succeed,
                                    failed = (len(workers) - succeed),
                                    queue_size = len(rman.queue),
                                    sync_speed = speed(start, finish)

    except CatchableError as exc:
      debug "Got a problem in request manager", exc = exc.msg

proc start*(rman: var RequestManager) =
  ## Start Request Manager's loop.
  rman.loopFuture = requestManagerLoop(rman)

proc stop*(rman: RequestManager) =
  ## Stop Request Manager's loop.
  if not(isNil(rman.loopFuture)):
    rman.loopFuture.cancel()

proc fetchAncestorBlocks*(rman: RequestManager, roots: seq[FetchRecord]) =
  ## Enqueue list missing blocks roots ``roots`` for download by
  ## Request Manager ``rman``.
  for item in roots:
    rman.queue.addLastNoWait(item)
