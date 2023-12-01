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

  POLL_INTERVAL = 1.seconds

type
  BlockVerifierFn* =
    proc(signedBlock: ForkedSignedBeaconBlock, maybeFinalized: bool):
      Future[Result[void, VerifierError]] {.gcsafe, raises: [].}
  InhibitFn* = proc: bool {.gcsafe, raises:[].}

  RequestManager* = object
    network*: Eth2Node
    getBeaconTime: GetBeaconTimeFn
    inhibit: InhibitFn
    quarantine: ref Quarantine
    blobQuarantine: ref BlobQuarantine
    blockVerifier: BlockVerifierFn
    blockLoopFuture: Future[void]
    blobLoopFuture: Future[void]

func shortLog*(x: seq[Eth2Digest]): string =
  "[" & x.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(x: seq[FetchRecord]): string =
  "[" & x.mapIt(shortLog(it.root)).join(", ") & "]"

proc init*(T: type RequestManager, network: Eth2Node,
              denebEpoch: Epoch,
              getBeaconTime: GetBeaconTimeFn,
              inhibit: InhibitFn,
              quarantine: ref Quarantine,
              blobQuarantine: ref BlobQuarantine,
              blockVerifier: BlockVerifierFn): RequestManager =
  RequestManager(
    network: network,
    getBeaconTime: getBeaconTime,
    inhibit: inhibit,
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
    let block_root = hash_tree_root(blob.signed_block_header.message)
    var found = false
    for id in idList:
      if id.block_root == block_root and
         id.index == blob.index:
          found = true
          break
    if not found:
        return false
  true

proc requestBlocksByRoot(rman: RequestManager, items: seq[Eth2Digest]) {.async.} =
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
            peer = peer, blocks = shortLog(items), ublocks = len(ublocks)

          # We reward peer only if it returns something.
          peer.updateScore(PeerScoreGoodValues)

      else:
        debug "Mismatching response to blocks by root",
          peer = peer, blocks = shortLog(items), ublocks = len(ublocks)
        peer.updateScore(PeerScoreBadResponse)
    else:
      debug "Blocks by root request failed",
        peer = peer, blocks = shortLog(items), err = blocks.error()
      peer.updateScore(PeerScoreNoValues)

  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    peer.updateScore(PeerScoreNoValues)
    debug "Error while fetching blocks by root", exc = exc.msg,
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
        debug "Mismatched response to blobs by root",
          peer = peer, blobs = shortLog(idList), ublobs = len(ublobs)
        peer.updateScore(PeerScoreBadResponse)
        return

      for b in ublobs:
        self.blobQuarantine[].put(b)
      var curRoot: Eth2Digest
      for b in ublobs:
        let block_root = hash_tree_root(b.signed_block_header.message)
        if block_root != curRoot:
          curRoot = block_root
          if (let o = self.quarantine[].popBlobless(curRoot); o.isSome):
            let b = o.unsafeGet()
            discard await self.blockVerifier(ForkedSignedBeaconBlock.init(b), false)
            # TODO:
            # If appropriate, return a VerifierError.InvalidBlob from verification,
            # check for it here, and penalize the peer accordingly.
    else:
      debug "Blobs by root request failed",
        peer = peer, blobs = shortLog(idList), err = blobs.error()
      peer.updateScore(PeerScoreNoValues)

  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    peer.updateScore(PeerScoreNoValues)
    debug "Error while fetching blobs by root", exc = exc.msg,
          idList = shortLog(idList), peer = peer, peer_score = peer.getScore()
    raise exc
  finally:
    if not(isNil(peer)):
      self.network.peerPool.release(peer)

proc requestManagerBlockLoop(rman: RequestManager) {.async.} =
  while true:
    # TODO This polling could be replaced with an AsyncEvent that is fired
    #      from the quarantine when there's work to do
    await sleepAsync(POLL_INTERVAL)

    if rman.inhibit():
      continue

    let blocks = mapIt(rman.quarantine[].checkMissing(
      SYNC_MAX_REQUESTED_BLOCKS), it.root)
    if blocks.len == 0:
      continue

    debug "Requesting detected missing blocks", blocks = shortLog(blocks)
    try:
      let start = SyncMoment.now(0)

      var workers: array[PARALLEL_REQUESTS, Future[void]]

      for i in 0 ..< PARALLEL_REQUESTS:
        workers[i] = rman.requestBlocksByRoot(blocks)

      await allFutures(workers)

      let finish = SyncMoment.now(uint64(len(blocks)))

      var succeed = 0
      for worker in workers:
        if worker.completed():
          inc(succeed)

      debug "Request manager block tick", blocks = shortLog(blocks),
                                          succeed = succeed,
                                          failed = (len(workers) - succeed),
                                          sync_speed = speed(start, finish)

    except CancelledError:
      break
    except CatchableError as exc:
      warn "Unexpected error in request manager block loop", exc = exc.msg


proc getMissingBlobs(rman: RequestManager): seq[BlobIdentifier] =
  let
    wallTime = rman.getBeaconTime()
    wallSlot = wallTime.slotOrZero()
    delay = wallTime - wallSlot.start_beacon_time()
    waitDur = TimeDiff(nanoseconds: BLOB_GOSSIP_WAIT_TIME_NS)

  var fetches: seq[BlobIdentifier]
  for blobless in rman.quarantine[].peekBlobless():

    # give blobs a chance to arrive over gossip
    if blobless.message.slot == wallSlot and delay < waitDur:
      debug "Not handling missing blobs early in slot"
      continue

    if not rman.blobQuarantine[].hasBlobs(blobless):
      let missing = rman.blobQuarantine[].blobFetchRecord(blobless)
      if len(missing.indices) == 0:
        warn "quarantine missing blobs, but missing indices is empty",
         blk=blobless.root,
         commitments=len(blobless.message.body.blob_kzg_commitments)
      for idx in missing.indices:
        let id = BlobIdentifier(block_root: blobless.root, index: idx)
        if id notin fetches:
          fetches.add(id)
    else:
      # this is a programming error should it occur.
      warn "missing blob handler found blobless block with all blobs",
         blk=blobless.root,
         commitments=len(blobless.message.body.blob_kzg_commitments)
      discard rman.blockVerifier(ForkedSignedBeaconBlock.init(blobless),
                                 false)
      rman.quarantine[].removeBlobless(blobless)
  fetches


proc requestManagerBlobLoop(rman: RequestManager) {.async.} =
  while true:
  # TODO This polling could be replaced with an AsyncEvent that is fired
  #      from the quarantine when there's work to do
    await sleepAsync(POLL_INTERVAL)
    if rman.inhibit():
      continue

    let fetches = rman.getMissingBlobs()
    if fetches.len > 0:
      debug "Requesting detected missing blobs", blobs = shortLog(fetches)
      try:
        let start = SyncMoment.now(0)
        var workers: array[PARALLEL_REQUESTS, Future[void]]
        for i in 0 ..< PARALLEL_REQUESTS:
          workers[i] = rman.fetchBlobsFromNetwork(fetches)

        await allFutures(workers)
        let finish = SyncMoment.now(uint64(len(fetches)))

        var succeed = 0
        for worker in workers:
          if worker.finished() and not(worker.failed()):
            inc(succeed)

        debug "Request manager blob tick",
             blobs_count = len(fetches),
             succeed = succeed,
             failed = (len(workers) - succeed),
             sync_speed = speed(start, finish)

      except CancelledError:
        break
      except CatchableError as exc:
        warn "Unexpected error in request manager blob loop", exc = exc.msg

proc start*(rman: var RequestManager) =
  ## Start Request Manager's loops.
  rman.blockLoopFuture = rman.requestManagerBlockLoop()
  rman.blobLoopFuture = rman.requestManagerBlobLoop()

proc stop*(rman: RequestManager) =
  ## Stop Request Manager's loop.
  if not(isNil(rman.blockLoopFuture)):
    rman.blockLoopFuture.cancelSoon()
  if not(isNil(rman.blobLoopFuture)):
    rman.blobLoopFuture.cancelSoon()
