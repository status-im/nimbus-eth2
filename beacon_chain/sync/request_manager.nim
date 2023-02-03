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
  ../spec/datatypes/[phase0],
  ../spec/forks,
  ../networking/eth2_network,
  ../consensus_object_pools/block_quarantine,
  "."/sync_protocol, "."/sync_manager
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

type
  BlockVerifier* =
    proc(signedBlock: ForkedSignedBeaconBlock, maybeFinalized: bool):
      Future[Result[void, VerifierError]] {.gcsafe, raises: [Defect].}
  BlockBlobsVerifier* =
    proc(signedBlock: ForkedSignedBeaconBlock, blobs: eip4844.BlobsSidecar):
      Future[Result[void, VerifierError]] {.gcsafe, raises: [Defect].}

  RequestManager* = object
    network*: Eth2Node
    inpQueue*: AsyncQueue[FetchRecord]
    cfg: RuntimeConfig
    getBeaconTime: GetBeaconTimeFn
    blockVerifier: BlockVerifier
    blockBlobsVerifier: BlockBlobsVerifier
    loopFuture: Future[void]

func shortLog*(x: seq[Eth2Digest]): string =
  "[" & x.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(x: seq[FetchRecord]): string =
  "[" & x.mapIt(shortLog(it.root)).join(", ") & "]"

proc init*(T: type RequestManager, network: Eth2Node,
              cfg: RuntimeConfig,
              getBeaconTime: GetBeaconTimeFn,
              blockVerifier: BlockVerifier,
              blockBlobsVerifier: BlockBlobsVerifier): RequestManager =
  RequestManager(
    network: network,
    inpQueue: newAsyncQueue[FetchRecord](),
    cfg: cfg,
    getBeaconTime: getBeaconTime,
    blockVerifier: blockVerifier,
    blockBlobsVerifier: blockBlobsVerifier,
  )

proc checkResponse(roots: openArray[Eth2Digest],
                   blocks: openArray[ref SignedBeaconBlockAndBlobsSidecar]): bool =
  ## This procedure checks peer's response.
  var checks = @roots
  if len(blocks) > len(roots):
    return false
  for item in blocks:
    let res = checks.find(item[].beacon_block.root)
    if res == -1:
      return false
    else:
      checks.del(res)
  true

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
  return true

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

proc fetchAncestorBlocksAndBlobsFromNetwork(rman: RequestManager,
                                            items: seq[Eth2Digest]) {.async.} =
  var peer: Peer
  try:
    peer = await rman.network.peerPool.acquire()
    debug "Requesting blocks and sidecars by root",
      peer = peer, blocks = shortLog(items), peer_score = peer.getScore()

    let blocks = (await beaconBlockAndBlobsSidecarByRoot_v1(peer, BlockRootsList items))

    if blocks.isOk:
      let ublocks = blocks.get()
      if checkResponse(items, ublocks.asSeq()):
        var
          gotGoodBlock = false
          gotUnviableBlock = false

        for b in ublocks:
          let ver = await rman.blockBlobsVerifier(ForkedSignedBeaconBlock.init(b[].beacon_block), b[].blobs_sidecar)
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
              notice "Received invalid block and blobs",
                peer = peer, blocks = shortLog(items),
                peer_score = peer.getScore()
              peer.updateScore(PeerScoreBadValues)

              return # Stop processing this junk...
          else:
            gotGoodBlock = true

        if gotUnviableBlock:
          notice "Received blocks and blobs from an unviable fork",
            peer = peer, blocks = shortLog(items),
            peer_score = peer.getScore()
          peer.updateScore(PeerScoreUnviableFork)
        elif gotGoodBlock:
          # We reward peer only if it returns something.
          peer.updateScore(PeerScoreGoodValues)
      else:
        let err = blocks.error()
        case err.kind
        of ReceivedErrorResponse:
          if err.responseCode == ResourceUnavailable:
            if not(isNil(peer)):
              rman.network.peerPool.release(peer)
            await rman.fetchAncestorBlocksFromNetwork(items)
            return
          else:
            peer.updateScore(PeerScoreBadResponse)
        else:
          discard
    else:
      peer.updateScore(PeerScoreNoValues)

  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    peer.updateScore(PeerScoreNoValues)
    debug "Error while fetching ancestor blocks and blobs", exc = exc.msg,
          items = shortLog(items), peer = peer, peer_score = peer.getScore()
    raise exc
  finally:
    if not(isNil(peer)):
      rman.network.peerPool.release(peer)


proc isBlobsTime(rman: RequestManager): bool =
  rman.getBeaconTime().slotOrZero.epoch >= rman.cfg.EIP4844_FORK_EPOCH

proc requestManagerLoop(rman: RequestManager) {.async.} =
  var rootList = newSeq[Eth2Digest]()
  var workers = newSeq[Future[void]](PARALLEL_REQUESTS)
  while true:
    try:
      rootList.setLen(0)
      let req = await rman.inpQueue.popFirst()
      rootList.add(req.root)

      var count = min(SYNC_MAX_REQUESTED_BLOCKS - 1, len(rman.inpQueue))
      while count > 0:
        rootList.add(rman.inpQueue.popFirstNoWait().root)
        dec(count)

      let start = SyncMoment.now(0)

      # As soon as EIP4844_FORK_EPOCH comes around in wall time, we
      # switch to requesting blocks and blobs. In the vicinity of the
      # transition, that means that we *may* request blobs for a
      # pre-eip4844. In that case, we get ResourceUnavailable from the
      # peer and fall back to requesting blocks only.
      let getBlobs = rman.isBlobsTime()
      for i in 0 ..< PARALLEL_REQUESTS:
        workers[i] = if getBlobs:
                       rman.fetchAncestorBlocksAndBlobsFromNetwork(rootList)
                     else:
                       rman.fetchAncestorBlocksFromNetwork(rootList)

      # We do not care about
      await allFutures(workers)

      let finish = SyncMoment.now(uint64(len(rootList)))

      var succeed = 0
      for worker in workers:
        if worker.finished() and not(worker.failed()):
          inc(succeed)

      debug "Request manager tick", blocks_count = len(rootList),
                                    succeed = succeed,
                                    failed = (len(workers) - succeed),
                                    queue_size = len(rman.inpQueue),
                                    sync_speed = speed(start, finish)

    except CatchableError as exc:
      debug "Got a problem in request manager", exc = exc.msg

proc start*(rman: var RequestManager) =
  ## Start Request Manager's loop.
  rman.loopFuture = rman.requestManagerLoop()

proc stop*(rman: RequestManager) =
  ## Stop Request Manager's loop.
  if not(isNil(rman.loopFuture)):
    rman.loopFuture.cancel()

proc fetchAncestorBlocks*(rman: RequestManager, roots: seq[FetchRecord]) =
  ## Enqueue list missing blocks roots ``roots`` for download by
  ## Request Manager ``rman``.
  for item in roots:
    try:
      rman.inpQueue.addLastNoWait(item)
    except AsyncQueueFullError: raiseAssert "unbounded queue"
