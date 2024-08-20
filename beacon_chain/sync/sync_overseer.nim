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
  ../consensus_object_pools/blockchain_list,
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/rest_types,
  ../spec/[helpers, forks, network, forks_light_client],
  ../networking/[peer_pool, peer_scores, eth2_network],
  ../gossip_processing/block_processor,
  ../[beacon_clock, beacon_node],
  ./[sync_types, sync_manager, sync_queue]

from ../consensus_object_pools/spec_cache import get_attesting_indices

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

proc isUntrustedBackfillEmpty(clist: ChainListRef): bool =
  clist.tail.isNone()

proc needsUntrustedBackfill(clist: ChainListRef, dag: ChainDagRef): bool =
  clist.tail.get().slot > dag.horizon

proc rebuildState(overseer: SyncOverseerRef): Future[void] {.
     async: (raises: [CancelledError]).} =
  overseer.statusMsg = Opt.some("rebuilding state")
  let
    consensusManager = overseer.consensusManager
    dag = consensusManager.dag
    attestationPool = consensusManager.attestationPool
    validatorMonitor = overseer.validatorMonitor
    batchVerifier = overseer.batchVerifier
    clist =
      block:
        let res = ChainListRef.init(overseer.clist.path, dag.head.slot)
        if res.isErr():
          fatal "Unable to read backfill data", reason = res.error,
                path = overseer.clist.path
          return
        res.get()

  var
    blocks: seq[BlockData]
    processEpoch: Epoch = FAR_FUTURE_EPOCH

  let handle = clist.handle.get()

  while true:
    let res = getChainFileTail(handle.handle)
    if res.isErr():
      fatal "Unable to read backfill data", reason = res.error
      return
    let bres = res.get()
    if bres.isNone():
      return

    let
      data = bres.get()
      blockEpoch = data.blck.slot.epoch()

    proc onBlockAdded(blckRef: BlockRef,
      blck: ForkedTrustedSignedBeaconBlock, epochRef: EpochRef,
      unrealized: FinalityCheckpoints) {.gcsafe, raises: [].} =

      let wallTime = overseer.getBeaconTimeFn()
      withBlck(blck):
        attestationPool[].addForkChoice(
          epochRef, blckRef, unrealized, forkyBlck.message, wallTime)

        validatorMonitor[].registerBeaconBlock(
          MsgSource.sync, wallTime, forkyBlck.message)

        for attestation in forkyBlck.message.body.attestations:
          for validator_index in
            dag.get_attesting_indices(attestation, true):
            validatorMonitor[].registerAttestationInBlock(
              attestation.data, validator_index, forkyBlck.message.slot)

        withState(dag[].clearanceState):
          when (consensusFork >= ConsensusFork.Altair) and
               (type(forkyBlck) isnot phase0.TrustedSignedBeaconBlock):
            for i in forkyBlck.message.body.sync_aggregate.
              sync_committee_bits.oneIndices():
              validatorMonitor[].registerSyncAggregateInBlock(
                forkyBlck.message.slot, forkyBlck.root,
                forkyState.data.current_sync_committee.pubkeys.data[i])

    if blockEpoch != processEpoch:
      if len(blocks) != 0:
        let
          tick = Moment.now()
          res = addBackfillBlockData(dag, batchVerifier[], blocks, onBlockAdded)
        if res.isErr():
          fatal "Unable to process block data", reason = res.error
          quit 1

        let updateTick = Moment.now()
        debug "Fill status", elapsed = updateTick - tick,
              blocks_count = len(blocks)

        for bdata in blocks:
          withBlck(bdata.blck):
            let ures =
              await updateHead(
                consensusManager, validatorMonitor,
                overseer.getBeaconTimeFn, forkyBlck,
                NewPayloadStatus.noResponse)
            if ures.isErr():
              fatal "Unable to follow head", reason = ures.error
              quit 1

        debug "Update head status", elapsed = Moment.now() - updateTick,
              blocks_count = len(blocks)

        blocks.setLen(0)
      processEpoch = blockEpoch

    if data.blck.slot != GENESIS_SLOT:
      blocks.add(data)

proc mainLoop*(
    overseer: SyncOverseerRef
): Future[void] {.async: (raises: []).} =
  let dag = overseer.consensusManager.dag

  if not(isBackfillEmpty(dag.backfill)):
    # Backfill is already running.
    if dag.needsBackfill:
      if not overseer.forwardSync.inProgress:
        overseer.backwardSync.start()
        try:
          await overseer.backwardSync.join()
        except CancelledError:
          return

  if not(isUntrustedBackfillEmpty(overseer.clist)):
    if needsUntrustedBackfill(overseer.clist, dag):
      if not overseer.forwardSync.inProgress:
        overseer.untrustedSync.start()
  else:
    overseer.statusMsg = Opt.some("awaiting light client")
    let blockHeader =
      try:
        await overseer.getLatestBeaconHeader()
      except CancelledError:
        return

    notice "Received light client block header",
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

    overseer.statusMsg = Opt.some("storing block")
    let res = overseer.clist.addBackfillBlockData(blck.blck, blck.blob)
    if res.isErr():
      warn "Unable to store initial block", reason = res.error
      return
    overseer.statusMsg = Opt.none(string)

    notice "Initial block being stored",
           blck = shortLog(blck.blck), blobs_count = blobsCount

    overseer.untrustedSync.start()

  try:
    await overseer.untrustedSync.join()
  except CancelledError:
    return

  notice "Start state rebuild mechanism"

  try:
    await overseer.rebuildState()
  except CancelledError:
    return

proc start*(overseer: SyncOverseerRef) =
  overseer.loopFuture = overseer.mainLoop()

proc stop*(overseer: SyncOverseerRef) {.async: (raises: []).} =
  doAssert(not(isNil(overseer.loopFuture)),
           "SyncOverseer was not started yet")
  if not(overseer.loopFuture.finished()):
    await cancelAndWait(overseer.loopFuture)
