# beacon_chain
# Copyright (c) 2019-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  chronos,
  ../consensus_object_pools/block_clearance_light_client,
  ../networking/eth2_network,
  ../beacon_clock,
  ./request_manager

logScope:
  topics = "optsync"

type
  MsgTrustedBlockProcessor* =
    proc(signedBlock: ForkedMsgTrustedSignedBeaconBlock): Future[void] {.
      gcsafe, raises: [Defect].}

  SyncStrategy {.pure.} = enum
    None,
    RequestManager,
    SyncManager

  LCOptimisticSync* = ref object
    network: Eth2Node
    getBeaconTime: GetBeaconTimeFn
    optimisticProcessor: MsgTrustedBlockProcessor
    safeSlotsToImportOptimistically: uint16
    lcBlocks: LCBlocks
    blockVerifier: request_manager.BlockVerifier
    requestManager: RequestManager
    finalizedBid, optimisticBid: BlockId
    lastReportedSlot: Slot
    finalizedIsExecutionBlock: Option[bool]
    syncStrategy: SyncStrategy
    syncFut, processFut: Future[void]

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/sync/optimistic.md
proc reportOptimisticCandidateBlock(optSync: LCOptimisticSync) {.gcsafe.} =
  if optSync.processFut != nil:
    return

  # Check if finalized is execution block (implies that justified is, too)
  if optSync.finalizedIsExecutionBlock.isNone:
    let
      finalizedSlot = optSync.lcBlocks.getFinalizedSlot()
      finalizedBlock = optSync.lcBlocks.getBlockAtSlot(finalizedSlot)
    if finalizedBlock.isOk:
      optSync.finalizedIsExecutionBlock =
        withBlck(finalizedBlock.get):
          some blck.message.is_execution_block()

  let
    currentSlot = optSync.lcBlocks.getHeadSlot()
    maxSlot =
      if optSync.finalizedIsExecutionBlock.get(false):
        # If finalized is execution block, can import any later block
        currentSlot
      else:
        # Else, block must be deep (min `SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY`)
        let minAge = optSync.safeSlotsToImportOptimistically
        max(currentSlot, minAge.Slot) - minAge.uint64

  if maxSlot > optSync.lastReportedSlot:
    const minGapSize = SLOTS_PER_EPOCH
    var signedBlock: Opt[ForkedMsgTrustedSignedBeaconBlock]
    if maxSlot - optSync.lastReportedSlot >= minGapSize:
      # Large gap, skip to latest
      signedBlock = optSync.lcBlocks.getLatestBlockThroughSlot(maxSlot)
    elif optSync.lcBlocks.getFrontfillSlot() <= optSync.lastReportedSlot + 1 and
        optSync.lcBlocks.getBackfillSlot() > optSync.lastReportedSlot + 1:
      # Small gap, but still downloading
      discard
    else:
      # Report next sequential block (even if it is slightly outdated)
      for slot in optSync.lastReportedSlot + 1 .. maxSlot:
        signedBlock = optSync.lcBlocks.getBlockAtSlot(slot)
        if signedBlock.isOk:
          break

    if signedBlock.isOk and signedBlock.get.slot > optSync.lastReportedSlot:
      optSync.lastReportedSlot = signedBlock.get.slot
      optSync.processFut = optSync.optimisticProcessor(signedBlock.get)

      proc handleFinishedProcess(future: pointer) =
        optSync.processFut = nil
        optSync.reportOptimisticCandidateBlock()

      optSync.processFut.addCallback(handleFinishedProcess)

proc initLCOptimisticSync*(
    network: Eth2Node,
    getBeaconTime: GetBeaconTimeFn,
    optimisticProcessor: MsgTrustedBlockProcessor,
    safeSlotsToImportOptimistically: uint16): LCOptimisticSync =
  const numExtraSlots = 2 * SLOTS_PER_EPOCH.int + 1
  let maxSlots = safeSlotsToImportOptimistically.int + numExtraSlots

  let optSync = LCOptimisticSync(
    network: network,
    getBeaconTime: getBeaconTime,
    optimisticProcessor: optimisticProcessor,
    safeSlotsToImportOptimistically: safeSlotsToImportOptimistically,
    lcBlocks: initLCBlocks(maxSlots))

  proc blockVerifier(signedBlock: ForkedSignedBeaconBlock):
      Future[Result[void, BlockError]] =
    let res = optSync.lcBlocks.addBlock(signedBlock)
    if res.isOk:
      if optSync.syncStrategy == SyncStrategy.RequestManager:
        let root = optSync.lcBlocks.getBackfillRoot()
        if root.isSome:
          optSync.requestManager.fetchAncestorBlocks(
            @[FetchRecord(root: root.get)])
        else:
          if not optSync.syncFut.finished:
            optSync.syncFut.cancel()

      optSync.reportOptimisticCandidateBlock()

    let resfut = newFuture[Result[void, BlockError]]("lcOptSyncBlockVerifier")
    resfut.complete(res)
    resfut

  optSync.blockVerifier = blockVerifier
  optSync.requestManager = RequestManager.init(network, optSync.blockVerifier)

  optSync

proc start*(optSync: LCOptimisticSync) =
  optSync.requestManager.start()

func supportsRetarget(syncStrategy: SyncStrategy): bool =
  case syncStrategy
  of SyncStrategy.None, SyncStrategy.RequestManager:
    true
  of SyncStrategy.SyncManager:
    false

proc syncUsingRequestManager(optSync: LCOptimisticSync) {.async.} =
  let startTick = Moment.now()

  var cancellationRequested = false
  while not cancellationRequested:
    let root = optSync.lcBlocks.getBackfillRoot()
    if root.isNone:
      break

    if optSync.requestManager.inpQueue.empty:
      optSync.requestManager.fetchAncestorBlocks(@[FetchRecord(root: root.get)])

    try:
      await chronos.sleepAsync(chronos.seconds(10))
    except CancelledError as exc:
      cancellationRequested = true

  debug "LC optimistic sync complete",
    headSlot = optSync.lcBlocks.getHeadSlot(),
    finalizedSlot = optSync.lcBlocks.getFinalizedSlot(),
    backfillSlot = optSync.lcBlocks.getBackfillSlot(),
    frontfillSlot = optSync.lcBlocks.getFrontfillSlot(),
    syncStrategy = optSync.syncStrategy,
    cancellationRequested,
    syncDur = Moment.now() - startTick

proc syncUsingSyncManager(optSync: LCOptimisticSync) {.async.} =
  let startTick = Moment.now()

  func getLocalHeadSlot(): Slot =
    optSync.lcBlocks.getHeadSlot() + 1

  proc getLocalWallSlot(): Slot =
    optSync.getBeaconTime().slotOrZero

  var cancellationRequested = false
  func getProgressSlot(): Slot =
    if not cancellationRequested:
      optSync.lcBlocks.getBackfillSlot()
    else:
      # Report out-of-band completion of sync
      optSync.lcBlocks.getFrontfillSlot()

  func getFinalizedSlot(): Slot =
    getProgressSlot()

  func getBackfillSlot(): Slot =
    getProgressSlot()

  func getFrontfillSlot(): Slot =
    optSync.lcBlocks.getFrontfillSlot()

  let lcOptSyncManager = newSyncManager[Peer, PeerID](
    optSync.network.peerPool, SyncQueueKind.Backward, getLocalHeadSlot,
    getLocalWallSlot, getFinalizedSlot, getBackfillSlot, getFrontfillSlot,
    progressPivot = optSync.lcBlocks.getHeadSlot(), optSync.blockVerifier,
    maxHeadAge = 0, flags = {SyncManagerFlag.NoMonitor}, ident = "lcOptSync")
  lcOptSyncManager.start()
  while lcOptSyncManager.inProgress:
    try:
      await chronos.sleepAsync(chronos.seconds(10))
    except CancelledError as exc:
      cancellationRequested = true

  debug "LC optimistic sync complete",
    headSlot = optSync.lcBlocks.getHeadSlot(),
    finalizedSlot = optSync.lcBlocks.getFinalizedSlot(),
    backfillSlot = optSync.lcBlocks.getBackfillSlot(),
    frontfillSlot = optSync.lcBlocks.getFrontfillSlot(),
    syncStrategy = optSync.syncStrategy,
    cancellationRequested,
    syncDur = Moment.now() - startTick

proc continueSync(optSync: LCOptimisticSync) {.gcsafe.} =
  let
    currentHeadSlot = optSync.lcBlocks.getHeadSlot()
    targetHeadSlot = optSync.optimisticBid.slot
    headDiff =
      if targetHeadSlot > currentHeadSlot:
        targetHeadSlot - currentHeadSlot
      else:
        currentHeadSlot - targetHeadSlot

    currentFinalizedSlot = optSync.lcBlocks.getFinalizedSlot()
    targetFinalizedSlot = optSync.finalizedBid.slot

    backfillSlot = optSync.lcBlocks.getBackfillSlot()
    frontfillSlot = optSync.lcBlocks.getFrontfillSlot()
    syncDistance =
      if backfillSlot > frontfillSlot:
        backfillSlot - frontfillSlot
      else:
        0

  # If sync is complete, work is done
  if currentHeadSlot == targetHeadSlot and
      currentFinalizedSlot == targetFinalizedSlot and
      syncDistance == 0:
    return

  # Cancel ongoing sync if sync target jumped
  if headDiff >= SLOTS_PER_EPOCH and optSync.syncFut != nil:
    if not optSync.syncFut.finished:
      optSync.syncFut.cancel()
    return

  # When retargeting ongoing sync is not possible, cancel on finality change
  if not optSync.syncStrategy.supportsRetarget:
    if currentFinalizedSlot != targetFinalizedSlot and optSync.syncFut != nil:
      if not optSync.syncFut.finished:
        optSync.syncFut.cancel()
    return

  # Set new sync target
  let
    finalizedBid = optSync.finalizedBid
    optimisticBid = optSync.optimisticBid
  doAssert optimisticBid.slot >= finalizedBid.slot
  if optSync.lcBlocks.getHeadSlot() != optimisticBid.slot:
    optSync.lcBlocks.setHeadBid(optimisticBid)
  if optSync.lcBlocks.getFinalizedSlot() != finalizedBid.slot:
    optSync.lcBlocks.setFinalizedBid(finalizedBid)
    optSync.finalizedIsExecutionBlock.reset()
    optSync.reportOptimisticCandidateBlock()

  if optSync.syncFut == nil:
    # Select sync strategy
    optSync.syncFut =
      if headDiff >= SLOTS_PER_EPOCH:
        optSync.syncStrategy = SyncStrategy.SyncManager
        optSync.syncUsingSyncManager()
      else:
        optSync.syncStrategy = SyncStrategy.RequestManager
        optSync.syncUsingRequestManager()

    # Continue syncing until complete
    proc handleFinishedSync(future: pointer) =
      optSync.syncStrategy.reset()
      optSync.syncFut = nil
      optSync.continueSync()
    optSync.syncFut.addCallback(handleFinishedSync)

proc setOptimisticHeader*(
    optSync: LCOptimisticSync, optimisticHeader: BeaconBlockHeader) =
  optSync.optimisticBid = optimisticHeader.toBlockId
  optSync.continueSync()

proc setFinalizedHeader*(
    optSync: LCOptimisticSync, finalizedHeader: BeaconBlockHeader) =
  optSync.finalizedBid = finalizedHeader.toBlockId
  if optSync.finalizedBid.slot > optSync.optimisticBid.slot:
    optSync.optimisticBid = optSync.finalizedBid
  optSync.continueSync()
