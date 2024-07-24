# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[strutils, sequtils, algorithm]
import stew/base10, chronos, chronicles, results, nimcrypto/utils
import
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/rest_types,
  ../spec/[helpers, forks, network, forks_light_client],
  ../networking/[peer_pool, peer_scores, eth2_network],
  ../gossip_processing/block_processor,
  ../[beacon_clock, beacon_node],
  ./[sync_types, sync_manager, sync_queue]

export sync_types

const
  PARALLEL_REQUESTS* = 3
  ## Number of peers we using to resolve our request.

type
  BlockAndBlob* = object
    blck*: ForkedSignedBeaconBlock
    blob*: Opt[BlobSidecars]

  BlockAndBlobRes* = Result[BlockAndBlob, string]

proc getLatestBeaconHeader*(
    overseer: SyncOverseerRef
): Future[BeaconBlockHeader] {.async: (raises: [CancelledError]).} =
  let eventKey = overseer.eventQueue.register()

  defer:
    overseer.eventQueue.unregister(eventKey)

  let events =
    try:
      await overseer.eventQueue.waitEvents(eventKey)
    except CancelledError as exc:
      raise exc
    except AsyncEventQueueFullError:
      raiseAssert "AsyncEventQueueFullError should not be happened!"

  withForkyHeader(events[^1]):
    when lcDataFork > LightClientDataFork.None:
      forkyHeader.beacon
    else:
      raiseAssert "Should not be happened"

proc getPeerBlock*(
    overseer: SyncOverseerRef,
    slot: Slot,
): Future[BlockAndBlobRes] {.async: (raises: [CancelledError]).} =
  let peer = await overseer.pool.acquire()
  try:
    let
      request = SyncRequest[Peer](kind: SyncQueueKind.Forward,
                                  slot: slot, count: 1'u64, item: peer)
      res = (await getSyncBlockData(peer, request, true)).valueOr:
        return err(error)

    if len(res.blocks) == 0:
      return err("Empty sequence received")

    let
      blob =
        if res.blobs.isSome():
          Opt.some(res.blobs.get()[0])
        else:
          Opt.none(BlobSidecars)
    ok(BlockAndBlob(blck: res.blocks[0][], blob: blob))
  finally:
    overseer.pool.release(peer)

proc `==`(a, b: BeaconBlockHeader): bool =
  (a.slot == b.slot) and (a.proposer_index == b.proposer_index) and
  (a.parent_root.data == b.parent_root.data) and
  (a.state_root.data == b.state_root.data) and
  (a.body_root.data == b.body_root.data)

proc getBlock*(
    overseer: SyncOverseerRef,
    slot: Slot,
    blockHeader: Opt[BeaconBlockHeader]
): Future[BlockAndBlob] {.async: (raises: [CancelledError]).} =
  var workers:
    array[PARALLEL_REQUESTS, Future[BlockAndBlobRes].Raising([CancelledError])]

  while true:
    for i in 0 ..< PARALLEL_REQUESTS:
      workers[i] = overseer.getPeerBlock(slot)

    try:
      await allFutures(workers)
    except CancelledError as exc:
      let pending =
        workers.filterIt(not(it.finished())).mapIt(cancelAndWait(it))
      await noCancel allFutures(pending)
      raise exc

    var results: seq[BlockAndBlob]
    for i in 0 ..< PARALLEL_REQUESTS:
      if workers[i].value.isOk:
        results.add(workers[i].value.get())

    if blockHeader.isSome:
      if len(results) > 0:
        for item in results:
          withBlck(item.blck):
            if forkyBlck.message.toBeaconBlockHeader() == blockHeader.get():
              return item
    else:
      # TODO (cheatfate): Compare received blocks
      if len(results) > 0:
        return results[0]

proc isBackfillEmpty(backfill: BeaconBlockSummary): bool =
  (backfill.slot == GENESIS_SLOT) and isFullZero(backfill.parent_root.data)

proc mainLoop*(
    overseer: SyncOverseerRef
): Future[void] {.async: (raises: []).} =
  if not(isBackfillEmpty(overseer.dag.backfill)):
    # Backfill is already running.
    if overseer.dag.needsBackfill:
      if not overseer.forwardSync.inProgress:
        overseer.backwardSync.start()
  else:
    overseer.statusMsg = Opt.some("awaiting block header")
    let blockHeader =
      try:
        await overseer.getLatestBeaconHeader()
      except CancelledError:
        return

    notice "Received beacon block header",
           backfill = shortLog(overseer.dag.backfill),
           beacon_header = shortLog(blockHeader),
           current_slot = overseer.beaconClock.now().slotOrZero()

    overseer.statusMsg = Opt.some("retrieving block")

    let
      blck =
        try:
          await overseer.getBlock(blockHeader.slot, Opt.some(blockHeader))
        except CancelledError:
          return
      blobsCount = if blck.blob.isNone(): 0 else: len(blck.blob.get())

    notice "Received beacon block", blck = shortLog(blck.blck),
                                    blobs_count = blobsCount

    # Updating backfill information to satisfy addBackfillBlock() requirements.
    # Right after first block being added addBackfillBlock() will update
    # backfill information properly.
    overseer.dag.backfill =
      BeaconBlockSummary(slot: blockHeader.slot + 1,
                         parent_root: blck.blck.root)

    overseer.statusMsg = Opt.some("storing block")
    let res =
      withBlck(blck.blck):
        overseer.dag.addBackfillBlock(forkyBlck.asSigVerified(), blck.blob)
    if res.isErr():
      warn "Unable to store initial block",
           backfill = shortLog(overseer.dag.backfill),
           error = res.error
      return
    overseer.statusMsg = Opt.none(string)

    notice "Initial block being stored",
           backfill = shortLog(overseer.dag.backfill),
           blck = shortLog(blck.blck), blobs_count = blobsCount

    overseer.backwardSync.start()

  try:
    await overseer.backwardSync.join()
  except CancelledError:
    return

  notice "Start state rebuild mechanism"

proc start*(overseer: SyncOverseerRef) =
  overseer.loopFuture = overseer.mainLoop()

proc stop*(overseer: SyncOverseerRef) {.async: (raises: []).} =
  doAssert(not(isNil(overseer.loopFuture)),
           "SyncOverseer was not started yet")
  if not(overseer.loopFuture.finished()):
    await cancelAndWait(overseer.loopFuture)
