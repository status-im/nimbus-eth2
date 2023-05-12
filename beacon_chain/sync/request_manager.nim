# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[sequtils, strutils]
import chronos, chronicles
import
  ../spec/datatypes/[phase0, deneb],
  ../spec/[forks, network],
  ../networking/eth2_network,
  ../consensus_object_pools/block_quarantine,
  ../consensus_object_pools/blob_quarantine,
  "."/sync_protocol, "."/sync_manager,
  ../gossip_processing/block_processor

from ../beacon_clock import GetBeaconTimeFn
export block_quarantine, sync_manager

logScope:
  topics = "requman"

const
  SYNC_MAX_REQUESTED_BLOCKS* = 32 # Spec allows up to MAX_REQUEST_BLOCKS.
    ## Maximum number of blocks which will be requested in each
    ## `beaconBlocksByRoot` invocation.
  PARALLEL_REQUESTS* = 2
    ## Number of peers we using to resolve our request.

  BLOB_GOSSIP_WAIT_TIME_NS* = 2 * 1_000_000_000
    ## How long to wait for blobs to arrive over gossip before fetching.

type
  BlockVerifier* =
    proc(signedBlock: ForkedSignedBeaconBlock, maybeFinalized: bool):
      Future[Result[void, VerifierError]] {.gcsafe, raises: [Defect].}
  RequestManager* = object
    network*: Eth2Node
    inpBlockQueue*: AsyncQueue[FetchRecord]
    inpBlobQueue: AsyncQueue[BlobIdentifier]
    getBeaconTime: GetBeaconTimeFn
    quarantine: ref Quarantine
    blobQuarantine: ref BlobQuarantine
    blockVerifier: BlockVerifier
    blockLoopFuture: Future[void]
    blobLoopFuture: Future[void]

func shortLog*(x: seq[Eth2Digest]): string =
  "[" & x.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(x: seq[FetchRecord]): string =
  "[" & x.mapIt(shortLog(it.root)).join(", ") & "]"

proc init*(T: type RequestManager, network: Eth2Node,
              denebEpoch: Epoch,
              getBeaconTime: GetBeaconTimeFn,
              quarantine: ref Quarantine,
              blobQuarantine: ref BlobQuarantine,
              blockVerifier: BlockVerifier): RequestManager =
  RequestManager(
    network: network,
    inpBlockQueue: newAsyncQueue[FetchRecord](),
    inpBlobQueue: newAsyncQueue[BlobIdentifier](),
    getBeaconTime: getBeaconTime,
    quarantine: quarantine,
    blobQuarantine: blobQuarantine,
    blockVerifier: blockVerifier,
  )

proc checkResponse(roots: openArray[Eth2Digest],
                   blocks: openArray[ref ForkedSignedBeaconBlock]): bool =
  ## This procedure checks peer's response.
  var checks = @roots
  if len(blocks) > len(roots):
    return false
  for blk in blocks:
    let res = checks.find(blk[].root)
    if res == -1:
      return false
    else:
      checks.del(res)
  true

proc checkResponse(idList: seq[BlobIdentifier],
                   blobs: openArray[ref BlobSidecar]): bool =
  if len(blobs) > len(idList):
    return false
  for blob in blobs:
    var found = false
    for id in idList:
      if id.block_root == blob.block_root and
         id.index == blob.index:
          found = true
          break
    if not found:
        return false
  true

proc fetchAncestorBlocksFromNetwork(rman: RequestManager,
                                    items: seq[Eth2Digest]) {.async.} =
  var peer: Peer
  try:
    peer = await rman.network.peerPool.acquire()
    debug "Requesting blocks by root", peer = peer, blocks = shortLog(items),
                                       peer_score = peer.getScore()

    let blocks = (await beaconBlocksByRoot_v2(peer, BlockRootsList items))

    if blocks.isOk:
      let ublocks = blocks.get()
      if checkResponse(items, ublocks.asSeq()):
        var
          gotGoodBlock = false
          gotUnviableBlock = false

        for b in ublocks:
          let ver = await rman.blockVerifier(b[], false)
          if ver.isErr():
            case ver.error()
            of VerifierError.MissingParent:
              # Ignoring because the order of the blocks that
              # we requested may be different from the order in which we need
              # these blocks to apply.
              discard
            of VerifierError.Duplicate:
              # Ignoring because these errors could occur due to the
              # concurrent/parallel requests we made.
              discard
            of VerifierError.UnviableFork:
              # If they're working a different fork, we'll want to descore them
              # but also process the other blocks (in case we can register the
              # other blocks as unviable)
              gotUnviableBlock = true
            of VerifierError.Invalid:
              # We stop processing blocks because peer is either sending us
              # junk or working a different fork
              notice "Received invalid block",
                peer = peer, blocks = shortLog(items),
                peer_score = peer.getScore()
              peer.updateScore(PeerScoreBadValues)

              return # Stop processing this junk...
          else:
            gotGoodBlock = true

        if gotUnviableBlock:
          notice "Received blocks from an unviable fork",
            peer = peer, blocks = shortLog(items),
            peer_score = peer.getScore()
          peer.updateScore(PeerScoreUnviableFork)
        elif gotGoodBlock:
          debug "Request manager got good block",
            peer = peer, blocks = shortLog(items)

          # We reward peer only if it returns something.
          peer.updateScore(PeerScoreGoodValues)

      else:
        peer.updateScore(PeerScoreBadResponse)
    else:
      peer.updateScore(PeerScoreNoValues)

  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    peer.updateScore(PeerScoreNoValues)
    debug "Error while fetching ancestor blocks", exc = exc.msg,
          items = shortLog(items), peer = peer, peer_score = peer.getScore()
    raise exc
  finally:
    if not(isNil(peer)):
      rman.network.peerPool.release(peer)

proc fetchBlobsFromNetwork(self: RequestManager,
                           idList: seq[BlobIdentifier]) {.async.} =
  var peer: Peer

  try:
    peer = await self.network.peerPool.acquire()
    debug "Requesting blobs by root", peer = peer, blobs = shortLog(idList),
                                             peer_score = peer.getScore()

    let blobs = (await blobSidecarsByRoot(peer, BlobIdentifierList idList))

    if blobs.isOk:
      let ublobs = blobs.get()
      if not checkResponse(idList, ublobs.asSeq()):
        peer.updateScore(PeerScoreBadResponse)
        return

      for b in ublobs:
        self.blobQuarantine[].put(b)
      var curRoot: Eth2Digest
      for b in ublobs:
        if b.block_root != curRoot:
          curRoot = b.block_root
          if (let o = self.quarantine[].popBlobless(curRoot); o.isSome):
            let b = o.unsafeGet()
            discard await self.blockVerifier(ForkedSignedBeaconBlock.init(b), false)
            # TODO:
            # If appropriate, return a VerifierError.InvalidBlob from verification,
            # check for it here, and penalize the peer accordingly.

  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    peer.updateScore(PeerScoreNoValues)
    debug "Error while fetching blobs", exc = exc.msg,
          idList = shortLog(idList), peer = peer, peer_score = peer.getScore()
    raise exc
  finally:
    if not(isNil(peer)):
      self.network.peerPool.release(peer)


proc requestManagerBlockLoop(rman: RequestManager) {.async.} =
  var rootList = newSeq[Eth2Digest]()
  var workers = newSeq[Future[void]](PARALLEL_REQUESTS)
  while true:
    try:
      rootList.setLen(0)
      let req = await rman.inpBlockQueue.popFirst()
      rootList.add(req.root)

      var count = min(SYNC_MAX_REQUESTED_BLOCKS - 1, len(rman.inpBlockQueue))
      while count > 0:
        rootList.add(rman.inpBlockQueue.popFirstNoWait().root)
        dec(count)

      let start = SyncMoment.now(0)

      for i in 0 ..< PARALLEL_REQUESTS:
        workers[i] = rman.fetchAncestorBlocksFromNetwork(rootList)

      # We do not care about
      await allFutures(workers)

      let finish = SyncMoment.now(uint64(len(rootList)))

      var succeed = 0
      for worker in workers:
        if worker.finished() and not(worker.failed()):
          inc(succeed)

      debug "Request manager block tick", blocks_count = len(rootList),
                                          succeed = succeed,
                                          failed = (len(workers) - succeed),
                                          queue_size = len(rman.inpBlockQueue),
                                          sync_speed = speed(start, finish)

    except CatchableError as exc:
      debug "Got a problem in request manager", exc = exc.msg

proc requestManagerBlobLoop(rman: RequestManager) {.async.} =
  var idList = newSeq[BlobIdentifier]()
  var workers = newSeq[Future[void]](PARALLEL_REQUESTS)
  while true:
    try:
      idList.setLen(0)
      let id = await rman.inpBlobQueue.popFirst()
      idList.add(id)

      var count = min(MAX_REQUEST_BLOB_SIDECARS - 1, lenu64(rman.inpBlobQueue))
      while count > 0:
        idList.add(rman.inpBlobQueue.popFirstNoWait())
        dec(count)

      let start = SyncMoment.now(0)

      for i in 0 ..< PARALLEL_REQUESTS:
        workers[i] = rman.fetchBlobsFromNetwork(idList)

      await allFutures(workers)

      var succeed = 0
      for worker in workers:
        if worker.finished() and not(worker.failed()):
          inc(succeed)

      debug "Request manager blob tick", blobs_count = len(idList),
                                         succeed = succeed,
                                         failed = (len(workers) - succeed),
                                         queue_size = len(rman.inpBlobQueue)

    except CatchableError as exc:
      debug "Got a problem in request manager", exc = exc.msg

proc start*(rman: var RequestManager) =
  ## Start Request Manager's loops.
  rman.blockLoopFuture = rman.requestManagerBlockLoop()
  rman.blobLoopFuture = rman.requestManagerBlobLoop()

proc stop*(rman: RequestManager) =
  ## Stop Request Manager's loop.
  if not(isNil(rman.blockLoopFuture)):
    rman.blockLoopFuture.cancel()
  if not(isNil(rman.blobLoopFuture)):
    rman.blobLoopFuture.cancel()

proc fetchAncestorBlocks*(rman: RequestManager, roots: seq[FetchRecord]) =
  ## Enqueue list missing blocks roots ``roots`` for download by
  ## Request Manager ``rman``.
  for item in roots:
    try:
      rman.inpBlockQueue.addLastNoWait(item)
    except AsyncQueueFullError: raiseAssert "unbounded queue"


proc fetchMissingBlobs*(rman: RequestManager,
                        recs: seq[BlobFetchRecord]) =
  var idList: seq[BlobIdentifier]
  for r in recs:
    for idx in r.indices:
      idList.add(BlobIdentifier(block_root: r.block_root, index: idx))

  for id in idList:
    try:
      rman.inpBlobQueue.addLastNoWait(id)
    except AsyncQueueFullError: raiseAssert "unbounded queue"
