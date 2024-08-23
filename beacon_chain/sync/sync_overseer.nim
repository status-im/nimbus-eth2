# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[strutils, sequtils]
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

logScope:
  topics = "overseer"

const
  PARALLEL_REQUESTS* = 3
    ## Number of peers we using to resolve our request.
  BLOCKS_PROCESS_CHUNK_SIZE* = 2
    ## Number of blocks sent to processing (CPU heavy task).

type
  BlockDataRes* = Result[BlockData, string]

proc init*(t: typedesc[BlockDataChunk],
           data: openArray[BlockData]): BlockDataChunk =
  BlockDataChunk(
    blocks: @data,
    resfut:
      Future[Result[void, string]].Raising([CancelledError]).init(
        "blockdata.chunk")
  )

proc shortLog*(c: BlockDataChunk): string =
  let
    map =
      (c.blocks.mapIt(shortLog(it.blck.root) & ":" & $it.blck.slot)).
        join(", ")
    futureState = if c.resfut.finished(): "pending" else: "completed"
  "[" & map & "]:" & futureState

iterator chunks*(data: openArray[BlockData],
                 maxCount: Positive): BlockDataChunk =
  for i in countup(0, len(data) - 1, maxCount):
    yield BlockDataChunk.init(
      data.toOpenArray(i, min(i + maxCount, len(data)) - 1))

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
): Future[BlockDataRes] {.async: (raises: [CancelledError]).} =
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
    ok(BlockData(blck: res.blocks[0][], blob: blob))
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
): Future[BlockData] {.async: (raises: [CancelledError]).} =
  var workers:
    array[PARALLEL_REQUESTS, Future[BlockDataRes].Raising([CancelledError])]

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

    var results: seq[BlockData]
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

func speed(start, finish: Moment, entities: int): float =
  if entities <= 0:
    0.0
  else:
    float(entities) / toFloatSeconds(finish - start)

proc updatePerformance(overseer: SyncOverseerRef, startTick: Moment,
                       entities: int) =
  let dag = overseer.consensusManager.dag
  doAssert(overseer.clist.head.isSome() and overseer.clist.tail.isSome())
  let
    clistHeadSlot = overseer.clist.head.get().slot
    clistTailSlot = overseer.clist.tail.get().slot
  doAssert(clistHeadSlot >= dag.head.slot)
  let slotsPerSec = speed(startTick, Moment.now(), entities)

  inc(overseer.avgSpeedCounter)
  overseer.avgSpeed = overseer.avgSpeed +
    (slotsPerSec - overseer.avgSpeed) / float(overseer.avgSpeedCounter)

  let
    total = clistHeadSlot - clistTailSlot
    progress = dag.head.slot - clistTailSlot
    done = float(progress) / float(total)
    remaining = total - progress
    timeleft =
      if overseer.avgSpeed >= 0.001:
        Duration.fromFloatSeconds(remaining.float / overseer.avgSpeed)
      else:
        InfiniteDuration

  # Update status string
  overseer.statusMsg = Opt.some(
    timeleft.toTimeLeftString() & " (" &
    (done * 100).formatBiggestFloat(ffDecimal, 2) & "%) " &
    overseer.avgSpeed.formatBiggestFloat(ffDecimal, 4) &
    "slots/s (" & $dag.head.slot & ")")

proc blockProcessingLoop(overseer: SyncOverseerRef): Future[void] {.
     async: (raises: [CancelledError]).} =
  let
    consensusManager = overseer.consensusManager
    dag = consensusManager.dag
    attestationPool = consensusManager.attestationPool
    validatorMonitor = overseer.validatorMonitor

  proc onBlockAdded(
    blckRef: BlockRef, blck: ForkedTrustedSignedBeaconBlock, epochRef: EpochRef,
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

  block mainLoop:
    while true:
      let bchunk = await overseer.blocksQueue.popFirst()

      for bdata in bchunk.blocks:
        block:
          let res = addBackfillBlockData(dag, bdata, onBlockAdded)
          if res.isErr():
            let msg = "Unable to add block data to database [" &
                      $res.error & "]"
            bchunk.resfut.complete(Result[void, string].err(msg))
            continue

        withBlck(bdata.blck):
          let res =
            try:
              await updateHead(consensusManager, validatorMonitor,
                overseer.getBeaconTimeFn, forkyBlck,
                NewPayloadStatus.noResponse)
            except CancelledError as exc:
              let msg = "Unable to update head [interrupted]"
              bchunk.resfut.complete(Result[void, string].err(msg))
              break mainLoop
          if res.isErr():
            let msg = "Unable to update head [" & res.error & "]"
            bchunk.resfut.complete(Result[void, string].err(msg))
            continue

      bchunk.resfut.complete(Result[void, string].ok())

proc verifyBlockProposer(
    dag: ChainDagRef,
    signedBlock: ForkedSignedBeaconBlock
): Result[void, cstring] =
  let
    fork = getStateField(dag.clearanceState, fork)
    genesis_validators_root =
      getStateField(dag.clearanceState, genesis_validators_root)

  withBlck(signedBlock):
    let proposerKey =
      dag.db.immutableValidators.load(forkyBlck.message.proposer_index).valueOr:
        return err("Unable to find proposer key")

    if not(verify_block_signature(fork, genesis_validators_root,
                                  forkyBlck.message.slot, forkyBlck.message,
                                  proposerKey, forkyBlck.signature)):
      return err("Signature verification failed")

    ok()

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

  overseer.avgSpeed = 0.0
  overseer.avgSpeedCounter = 0

  block mainLoop:
    while true:
      let res = getChainFileTail(handle.handle)
      if res.isErr():
        fatal "Unable to read backfill data", reason = res.error
        quit 1
      let bres = res.get()
      if bres.isNone():
        return

      let
        data = bres.get()
        blockEpoch = data.blck.slot.epoch()

      if blockEpoch != processEpoch:
        if len(blocks) != 0:
          let
            startTick = Moment.now()
            blocksOnly = blocks.mapIt(it.blck)

          verifyBlockProposer(dag, batchVerifier[], blocksOnly).isOkOr:
            for signedBlock in blocksOnly:
              let res = verifyBlockProposer(dag, signedBlock)
              if res.isErr():
                fatal "Unable to verify block proposer",
                      blck = shortLog(signedBlock),
                      reason = res.error
                quit 1

          let verifyTick = Moment.now()

          for bchunk in blocks.chunks(BLOCKS_PROCESS_CHUNK_SIZE):
            try:
              overseer.blocksQueue.addLastNoWait(bchunk)
            except AsyncQueueFullError:
              raiseAssert "Should not be happened with unbound AsyncQueue"
            let res = await bchunk.resfut
            if res.isErr():
              fatal "Unable to add block data to database", reason = res.error
              quit 1

          let updateTick = Moment.now()
          debug "Number of blocks injected",
                blocks_count = len(blocks),
                head = shortLog(dag.head),
                finalized = shortLog(getStateField(
                  dag.headState, finalized_checkpoint)),
                signature_time = verifyTick - startTick,
                store_update_time = updateTick - verifyTick

          overseer.updatePerformance(startTick, len(blocks))
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

  let blockProcessingFut = overseer.blockProcessingLoop()

  try:
    await overseer.rebuildState()
  except CancelledError:
    await cancelAndWait(blockProcessingFut)
    return

proc start*(overseer: SyncOverseerRef) =
  overseer.loopFuture = overseer.mainLoop()

proc stop*(overseer: SyncOverseerRef) {.async: (raises: []).} =
  doAssert(not(isNil(overseer.loopFuture)),
           "SyncOverseer was not started yet")
  if not(overseer.loopFuture.finished()):
    await cancelAndWait(overseer.loopFuture)
