# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
{.push raises: [].}

import std/[sequtils, strutils, sets, algorithm]
import chronos, chronicles, results
import
  ../spec/eth2_apis/rest_types,
  ../spec/[helpers, forks, network, peerdas_helpers, column_map],
  ../networking/[peer_pool, eth2_network],
  ../consensus_object_pools/[consensus_manager, block_pools_types,
      blockchain_dag, block_quarantine, blob_quarantine],
  ../gossip_processing/block_processor,
  ../[beacon_clock],
  ./[sync_types, sync_dag, sync_queue, sync_protocol, response_utils,
     block_buffer]

from ../consensus_object_pools/spec_cache import get_attesting_indices
from nimcrypto/utils import isFullZero

export sync_types

logScope:
  topics = "sync"

const
  SyncDeviationSlotsCount = 1
    ## Number of slot allowed for deviation to continue backfilling job
  RootSyncEpochsActivationCount = 2'u64
    ## Number of epochs before latest known finalized epoch, when root sync
    ## starts working.
  ConcurrentRequestsCount* = 3
    ## Number of requests performed by single peer in one syncing step
  RepeatingFailuresCount* = 2
    ## Number of repeating errors before starting rewind process.
  StatusStalePeriod* = 5
    ## Number of slots before peer's status information could be stale.
  GenesisCheckpoint = Checkpoint(root: Eth2Digest(), epoch: GENESIS_EPOCH)

func shortLog(optblkid: Opt[BlockId]): string =
  if optblkid.isNone():
    "<n/a>"
  else:
    shortLog(optblkid.get())

template cleanupList(a: untyped) =
  for mitem in a.mitems():
    mitem = nil
  a.reset()

template cleanupRecordsList(a: untyped) =
  for mitem in a.mitems():
    mitem.sidecar = nil
  a.reset()

func shortLog(digests: openArray[Eth2Digest]): string =
  "[" & digests.mapIt(shortLog(it)).join(",") & "]"

func shortLog(blocks: openArray[ref ForkedSignedBeaconBlock]): string =
  "[" & blocks.mapIt(
    "(slot:" & $it[].slot() & ",root: " & shortLog(it[].root) & ")").
    join(",") & "]"

func shortLog(bids: openArray[BlockId]): string =
  "[" & bids.mapIt(
    "(slot:" & $it.slot & ",root:" & shortLog(it.root) & ")").join(",") & "]"

func shortLog(blobs: Opt[seq[ref BlobSidecar]]): string =
  if blobs.isNone():
    "<missing blobs>"
  else:
    $len(blobs.get())

func shortLog(cols: Opt[seq[ref fulu.DataColumnSidecar]]): string =
  if cols.isNone():
    "<missing columns>"
  else:
    $len(cols.get())

func slimLog(blobs: openArray[ref BlobSidecar]): string =
  "[" & blobs.mapIt(
    "(slot: " & $it[].signed_block_header.message.slot &
    ", index: " & $it[].index & ")").join(",") & "]"

func slimLog(columns: openArray[ref fulu.DataColumnSidecar]): string =
  "[" & columns.mapIt(
    "(slot: " & $it[].signed_block_header.message.slot &
    ", index: " & $it[].index & ")").join(",") & "]"

template blobsCount(blck: ForkedSignedBeaconBlock): int =
  withBlck(blck):
    when consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
      len(forkyBlck.message.body.blob_kzg_commitments)
    else:
      0

func slimLog(blck: ref ForkedSignedBeaconBlock): string =
  "(" & $blck.kind & ",slot:" & $blck[].slot() &
    ",root:" & shortLog(blck[].root()) &
    ",parent_root:" & shortLog(blck[].parent_root()) &
    ",blobs_count:" & $blck[].blobsCount() & ")"

func slimLog(blocks: openArray[ref ForkedSignedBeaconBlock]): string =
  "[" & blocks.mapIt(slimLog(it)).join(",") & "]"

proc getEaSlotLog(peer: Peer): string =
  let res = peer.getEarliestAvailableSlot().valueOr:
    return "<n/a>"
  $res

func isGenesis(checkpoint: Checkpoint): bool =
  (checkpoint.epoch == GenesisCheckpoint.epoch) and
    (checkpoint.root == GenesisCheckpoint.root)

func increaseBlocksCount(
    overseer: SyncOverseerRef2,
    blocksCount: var int,
    fork: ConsensusFork
) =
  # We increase by 1/4, but not bigger than fork's limit value.
  let
    maxCount =
      case fork
      of ConsensusFork.Phase0 .. ConsensusFork.Fulu:
        int(MAX_REQUEST_BLOCKS_DENEB)
      of ConsensusFork.Gloas:
        int(MAX_REQUEST_BLOCKS_DENEB)
    res = blocksCount + max(1, blocksCount div 4)

  if res > maxCount:
    blocksCount = maxCount
  else:
    blocksCount = res

func increaseSidecarsCount(
    overseer: SyncOverseerRef2,
    sidecarsCount: var int,
    fork: ConsensusFork
) =
  # We increase by 1/4, but not bigger than fork's limit value.
  let
    cfg = overseer.consensusManager.dag.cfg
    maxCount =
      case fork
      of ConsensusFork.Phase0 .. ConsensusFork.Deneb:
        int(cfg.MAX_REQUEST_BLOB_SIDECARS)
      of ConsensusFork.Electra:
        int(cfg.MAX_REQUEST_BLOB_SIDECARS_ELECTRA)
      of ConsensusFork.Fulu:
        int(cfg.MAX_REQUEST_DATA_COLUMN_SIDECARS)
      of ConsensusFork.Gloas:
        int(cfg.MAX_REQUEST_DATA_COLUMN_SIDECARS)

    res = sidecarsCount + max(1, sidecarsCount div 4)

  if res > maxCount:
    sidecarsCount = maxCount
  else:
    sidecarsCount = res

func decreaseSidecarsCount(sidecarsCount: var int) =
  if sidecarsCount == 1:
    return
  sidecarsCount = sidecarsCount div 2

func decreaseBlocksCount(blocksCount: var int) =
  if blocksCount == 1:
    return
  blocksCount = blocksCount div 2

func getColumnsDistribution(
    overseer: SyncOverseerRef2
): string =
  var res: seq[string]
  let custodyMap = overseer.columnQuarantine[].custodyMap
  if len(overseer.columnsState.distribution) == 0:
    return "[]"
  for index in custodyMap:
    let count = overseer.columnsState.distribution.getOrDefault(index, 0)
    res.add($uint64(index) & ": " & $count)
  "[" & res.join(", ") & "]"

func getColumnsFillRate(
    overseer: SyncOverseerRef2
): string =
  let custodyMap = overseer.columnQuarantine[].custodyMap
  if len(overseer.columnsState.distribution) == 0:
    return "0.00%"
  var columns = 0
  for index in custodyMap:
    let tmp = overseer.columnsState.distribution.getOrDefault(index, 0)
    if tmp > 0: inc(columns)
  let
    columnsCount =
      if len(custodyMap) == NUMBER_OF_COLUMNS:
        NUMBER_OF_COLUMNS div 2 + 1
      else:
        len(custodyMap)
    fillRate = (float(columns) * 100.0) / float(columnsCount)
  fillRate.formatBiggestFloat(ffDecimal, 2) & "%"

func getMissingColumnsLog(
    overseer: SyncOverseerRef2,
    blocks: openArray[ref ForkedSignedBeaconBlock]
): string =
  var res: seq[string]
  for blck in blocks:
    withBlck(blck[]):
      when consensusFork == ConsensusFork.Fulu:
        res.add(
          if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
            shortLog(forkyBlck.root) & ":[]"
          else:
            let map =
              overseer.columnQuarantine[].getMissingColumnsMap(forkyBlck.root)
            shortLog(forkyBlck.root) & ":" & $map
        )
      else:
        raiseAssert "Unsupported fork"
  "[" & res.join(",") & "]"

func getLastSeenHeadLog(
    overseer: SyncOverseerRef2
): string =
  if overseer.lastSeenHead.isNone():
    "[n/a]"
  else:
    shortLog(overseer.lastSeenHead.get())

func getLastSeenFinalizedHeadLog(
  overseer: SyncOverseerRef2
): string =
  if overseer.lastSeenCheckpoint.isNone():
    "[n/a]"
  else:
    shortLog(overseer.lastSeenCheckpoint.get())

func consensusForkAtEpoch(
    overseer: SyncOverseerRef2,
    epoch: Epoch
): ConsensusFork =
  overseer.consensusManager.dag.cfg.consensusForkAtEpoch(epoch)

template contains*(
    buffer: BlocksRangeBuffer,
    request: SyncRequest[Peer]
): bool =
  buffer.contains(request.data.slot, request.data.count)

func getSidecarsHorizon(
    overseer: SyncOverseerRef2,
    fork: ConsensusFork
): uint64 =
  let dag = overseer.consensusManager.dag
  if fork < ConsensusFork.Deneb:
    raiseAssert "Incorrect fork"
  elif fork < ConsensusFork.Fulu:
    dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS * SLOTS_PER_EPOCH
  elif fork == ConsensusFork.Fulu:
    dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS * SLOTS_PER_EPOCH
  else:
    raiseAssert "Unsupported fork"

proc getBlobsHorizon(overseer: SyncOverseerRef2): Epoch =
  let
    dag = overseer.consensusManager.dag
    currentEpoch = overseer.beaconClock.currentSlot().epoch()
    horizon = dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS
    tempEpoch =
      if currentEpoch < horizon:
        GENESIS_EPOCH
      else:
        currentEpoch - horizon
    tempFork = overseer.consensusForkAtEpoch(tempEpoch)

  if tempFork < ConsensusFork.Deneb:
    dag.cfg.DENEB_FORK_EPOCH
  else:
    tempEpoch

proc getColumnsHorizon(overseer: SyncOverseerRef2): Epoch =
  let
    dag = overseer.consensusManager.dag
    currentEpoch = overseer.beaconClock.currentSlot().epoch()
    horizon = dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS
    tempEpoch =
      if currentEpoch < horizon:
        GENESIS_EPOCH
      else:
        currentEpoch - horizon
    tempFork = overseer.consensusForkAtEpoch(tempEpoch)

  if tempFork < ConsensusFork.Fulu:
    dag.cfg.FULU_FORK_EPOCH
  else:
    tempEpoch

proc shouldGetBlobs(overseer: SyncOverseerRef2, slot: Slot): bool =
  if overseer.config.historyMode == HistoryMode.Archive:
    let dag = overseer.consensusManager.dag
    if slot.epoch() >= dag.cfg.DENEB_FORK_EPOCH:
      return true
    return false
  slot.epoch() >= overseer.getBlobsHorizon()

proc shouldGetColumns(overseer: SyncOverseerRef2, slot: Slot): bool =
  if overseer.config.historyMode == HistoryMode.Archive:
    let dag = overseer.consensusManager.dag
    if slot.epoch() >= dag.cfg.FULU_FORK_EPOCH:
      return true
    return false
  slot.epoch() >= overseer.getColumnsHorizon()

proc getPeerColumnMap(
    overseer: SyncOverseerRef2,
    peer: Peer
): ColumnMap =
  let
    cfg = overseer.consensusManager.dag.cfg
    nodeId = peer.fetchNodeIdFromPeerId()
    custodyGroupCount = peer.lookupCgcFromPeer()
  ColumnMap.init(cfg.get_custody_groups(nodeId, custodyGroupCount))

proc getPeerColumnMap(
    overseer: SyncOverseerRef2,
    peerEntry: PeerEntryRef
): ColumnMap =
  if peerEntry.columnsMap.isNone():
    let map = overseer.getPeerColumnMap(peerEntry.peer)
    peerEntry.columnsMap = Opt.some(map)
    map
  else:
    peerEntry.columnsMap.get()

proc checkDataAvailable(
    overseer: SyncOverseerRef2,
    peer: Peer,
    direction: SyncQueueKind,
    srange: SyncRange
): bool =
  let eaSlot = peer.getEarliestAvailableSlot().valueOr:
    return true
  case direction
  of SyncQueueKind.Forward:
    srange.start_slot() >= eaSlot
  of SyncQueueKind.Backward:
    srange.last_slot() >= eaSlot

proc startPeer(
  overseer: SyncOverseerRef2, peer: Peer): Future[void] {.async: (raises: []).}

func getFrontfillSlot(overseer: SyncOverseerRef2): Slot =
  let dag = overseer.consensusManager.dag
  max(dag.frontfill.get(BlockId()).slot, dag.horizon)

func getLastAddedBackfillSlot(overseer: SyncOverseerRef2): Slot =
  let dag = overseer.consensusManager.dag
  if dag.backfill.parent_root != dag.tail.root:
    dag.backfill.slot
  else:
    dag.tail.slot

func getMissingIndicesLog(
    overseer: SyncOverseerRef2,
    blck: ref ForkedSignedBeaconBlock
): string =
  withBlck(blck[]):
    when consensusFork < ConsensusFork.Deneb:
      raiseAssert "Invalid fork"
    elif consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
      let indices =
        overseer.blobQuarantine[].getMissingSidecarIndices(
          forkyBlck.root, forkyBlck)
      indexLog(indices)
    elif consensusFork == ConsensusFork.Fulu:
      let indices =
        if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
          default(seq[ColumnIndex])
        else:
          overseer.columnQuarantine[].getMissingSidecarIndices(forkyBlck.root)
      indexLog(indices)
    else:
      raiseAssert "Unsupported fork"

proc getForwardSidecarStartSlot(overseer: SyncOverseerRef2): Slot =
  let
    dag = overseer.consensusManager.dag
    checkpoint = overseer.lastSeenCheckpoint.get()
    lastSlot = checkpoint.epoch.start_slot()
    consensusFork = consensusForkAtEpoch(dag.cfg, checkpoint.epoch)

  if consensusFork < ConsensusFork.Deneb:
    return max(dag.finalizedHead.slot, dag.cfg.DENEB_FORK_EPOCH.start_slot())

  let horizon = overseer.getSidecarsHorizon(consensusFork)
  if lastSlot < horizon:
    max(dag.finalizedHead.slot, GENESIS_SLOT)
  else:
    max(dag.finalizedHead.slot, lastSlot - horizon)

proc getBackfillSidecarFinalSlot(overseer: SyncOverseerRef2): Slot =
  let
    dag = overseer.consensusManager.dag
    backfillSlot = overseer.getLastAddedBackfillSlot()
    currentSlot = overseer.beaconClock.currentSlot()
    consensusFork = consensusForkAtEpoch(dag.cfg, currentSlot.epoch())

  if consensusFork < ConsensusFork.Deneb:
    return min(backfillSlot, (dag.cfg.DENEB_FORK_EPOCH).start_slot)

  let horizon = overseer.getSidecarsHorizon(consensusFork)
  if dag.finalizedHead.slot < horizon:
    min(backfillSlot, GENESIS_SLOT)
  else:
    min(backfillSlot, dag.finalizedHead.slot - horizon)

proc createQueues(
    overseer: SyncOverseerRef2
) =
  let
    dag = overseer.consensusManager.dag
    checkpoint = overseer.lastSeenCheckpoint.get()

  func getFirstSlotAtFinalizedEpoch(): Slot =
    dag.finalizedHead.slot

  func getLastAddedBackfillSlot(): Slot =
    overseer.getLastAddedBackfillSlot()

  func forkAtEpoch(epoch: Epoch): ConsensusFork =
    consensusForkAtEpoch(dag.cfg, epoch)

  template declareBlockVerifier(
      procName: untyped,
      direction: static SyncQueueKind
  ): untyped =
    proc `procName`(
        signedBlock: ref ForkedSignedBeaconBlock,
        maybeFinalized: bool
    ): Future[Result[void, VerifierError]] {.
      async: (raises: [CancelledError]).} =
      doAssert(not(isNil(signedBlock)), "Block reference should not be nil")
      withBlck(signedBlock[]):
        when consensusFork < ConsensusFork.Deneb:
          (await overseer.blockProcessor.addBlock(
            MsgSource.sync, forkyBlck, noSidecars,
            maybeFinalized = maybeFinalized))
        elif consensusFork < ConsensusFork.Fulu:
          if overseer.shouldGetBlobs(forkyBlck.message.slot):
            # We add all the blocks to BlockBuffer, just to avoid BlockProcessor
            # `MissingParent` errors which could be generated, because some of
            # the blocks was added to BlockBuffer and some of the blocks
            # transferred to BlockProcessor.
            debug "Block buffered",
              fork = consensusFork,
              block_root = forkyBlck.root,
              blck = shortLog(forkyBlck),
              verifier = "block"

            when direction == SyncQueueKind.Forward:
              overseer.fblockBuffer.add(signedBlock)
            elif direction == SyncQueueKind.Backward:
              overseer.bblockBuffer.add(signedBlock)
          else:
            let commitmentsLen =
              len(forkyBlck.message.body.blob_kzg_commitments)

            if commitmentsLen > 0:
              (await overseer.blockProcessor.addBlock(
                MsgSource.sync, forkyBlck, Opt.none(BlobSidecars),
                maybeFinalized = maybeFinalized))
            else:
              (await overseer.blockProcessor.addBlock(
                MsgSource.sync, forkyBlck, Opt.some(default(BlobSidecars)),
                maybeFinalized = maybeFinalized))

        elif consensusFork == ConsensusFork.Fulu:
          if overseer.shouldGetColumns(forkyBlck.message.slot):
            # We add all the blocks to BlockBuffer, just to avoid BlockProcessor
            # `MissingParent` errors which could be generated, because some of
            # the blocks was added to BlockBuffer and some of the blocks
            # transferred to BlockProcessor.
            debug "Block buffered",
              fork = consensusFork,
              block_root = forkyBlck.root,
              blck = shortLog(forkyBlck),
              verifier = "block"

            when direction == SyncQueueKind.Forward:
              overseer.fblockBuffer.add(signedBlock)
            elif direction == SyncQueueKind.Backward:
              overseer.bblockBuffer.add(signedBlock)
          else:
            let commitmentsLen =
              len(forkyBlck.message.body.blob_kzg_commitments)

            if commitmentsLen > 0:
              (await overseer.blockProcessor.addBlock(
                MsgSource.sync, forkyBlck, Opt.none(fulu.DataColumnSidecars),
                maybeFinalized = maybeFinalized))
            else:
              (await overseer.blockProcessor.addBlock(
                MsgSource.sync, forkyBlck,
                Opt.some(default(fulu.DataColumnSidecars)),
                maybeFinalized = maybeFinalized))
        else:
          raiseAssert "Unsupported fork"

  declareBlockVerifier(forwardBlockVerifier, SyncQueueKind.Forward)
  declareBlockVerifier(backwardBlockVerifier, SyncQueueKind.Backward)

  proc sidecarsVerifier(
      signedBlock: ref ForkedSignedBeaconBlock,
      maybeFinalized: bool
  ): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
    doAssert(not(isNil(signedBlock)), "Block reference should not be nil")
    withBlck(signedBlock[]):
      when consensusFork < ConsensusFork.Deneb:
        raiseAssert "Incorrect block consensus fork"
      elif consensusFork < ConsensusFork.Fulu:
        let
          commitmentsLen = len(forkyBlck.message.body.blob_kzg_commitments)
          bres =
            if commitmentsLen > 0:
              if overseer.shouldGetBlobs(forkyBlck.message.slot):
                let res = overseer.blobQuarantine[].popSidecars(forkyBlck)
                if res.isNone():
                  debug "Block verification failed, because sidecars missing",
                    fork = consensusFork,
                    block_root = signedBlock[].root,
                    blck = shortLog(forkyBlck),
                    verifier = "sidecar"
                  return err(VerifierError.MissingSidecars)
                res
              else:
                Opt.none(seq[ref BlobSidecar])
            else:
              Opt.some(default(seq[ref BlobSidecar]))

        (await overseer.blockProcessor.addBlock(
          MsgSource.sync, forkyBlck, bres,
          maybeFinalized = maybeFinalized))
      elif consensusFork == ConsensusFork.Fulu:
        let
          commitmentsLen = len(forkyBlck.message.body.blob_kzg_commitments)
          cres =
            if commitmentsLen > 0:
              if overseer.shouldGetColumns(forkyBlck.message.slot):
                let res =
                  if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
                    Opt.some(default(fulu.DataColumnSidecars))
                  else:
                    overseer.columnQuarantine[].popSidecars(forkyBlck.root)
                if res.isNone():
                  debug "Block verification failed, because sidecars missing",
                    fork = consensusFork,
                    block_root = signedBlock[].root,
                    blck = shortLog(forkyBlck),
                    missing_sidecars =
                      overseer.getMissingIndicesLog(signedBlock),
                    verifier = "sidecar"
                  return err(VerifierError.MissingSidecars)
                res
              else:
                Opt.none(seq[ref fulu.DataColumnSidecar])
            else:
              Opt.some(default(seq[ref fulu.DataColumnSidecar]))

        (await overseer.blockProcessor.addBlock(
          MsgSource.sync, forkyBlck, cres,
          maybeFinalized = maybeFinalized))
      else:
        raiseAssert "Unsupported fork"

  let
    localHead = dag.finalizedHead.slot
    backfillSlot = overseer.getLastAddedBackfillSlot()
    frontfillSlot = overseer.getFrontfillSlot()

  overseer.fqueue =
    SyncQueue.init(
      Peer, SyncQueueKind.Forward,
      localHead, checkpoint.epoch.start_slot(),
      uint64(overseer.blocksChunkSize),
      ConcurrentRequestsCount,
      RepeatingFailuresCount,
      getFirstSlotAtFinalizedEpoch,
      forwardBlockVerifier, forkAtEpoch, "fblock")
  overseer.fsqueue =
    SyncQueue.init(
      Peer, SyncQueueKind.Forward,
      overseer.getForwardSidecarStartSlot(),
      checkpoint.epoch.start_slot(),
      uint64(overseer.blocksChunkSize),
      ConcurrentRequestsCount,
      RepeatingFailuresCount,
      getFirstSlotAtFinalizedEpoch,
      sidecarsVerifier, forkAtEpoch, "fsidecar")
  overseer.bqueue =
    if dag.needsBackfill():
      SyncQueue.init(
        Peer, SyncQueueKind.Backward,
        backfillSlot, frontfillSlot,
        uint64(overseer.blocksChunkSize),
        ConcurrentRequestsCount,
        RepeatingFailuresCount,
        getLastAddedBackfillSlot,
        backwardBlockVerifier, forkAtEpoch, "bblock")
    else:
      nil
  overseer.bsqueue =
    if dag.needsBackfill():
      SyncQueue.init(
        Peer, SyncQueueKind.Backward,
        backfillSlot,
        overseer.getBackfillSidecarFinalSlot(),
        uint64(overseer.blocksChunkSize),
        ConcurrentRequestsCount,
        RepeatingFailuresCount,
        getLastAddedBackfillSlot,
        sidecarsVerifier, forkAtEpoch, "bsidecar")
    else:
      nil

proc updateQueues(
    overseer: SyncOverseerRef2
) =
  let
    dag = overseer.consensusManager.dag
    checkpoint = overseer.lastSeenCheckpoint.get()
    localHead = dag.finalizedHead.slot

  if overseer.fqueue.running():
    # Forward syncing is in progress.
    overseer.fqueue.updateLastSlot(checkpoint.epoch.start_slot())
  else:
    # Forward sync is not active, but we keep it up-to date.
    overseer.fqueue.reset(localHead, checkpoint.epoch.start_slot())

  if overseer.fsqueue.running():
    # Forward syncing is in progress.
    overseer.fsqueue.updateLastSlot(checkpoint.epoch.start_slot())
  else:
    # Forward sync is not active, but we keep it up-to date.
    overseer.fsqueue.reset(
      overseer.getForwardSidecarStartSlot(), checkpoint.epoch.start_slot())

  if not(isNil(overseer.bqueue)):
    if not(overseer.bqueue.running()):
      let
        startSlot = dag.backfill.slot
        finishSlot =
          if dag.horizon >= startSlot:
            startSlot
          else:
            dag.horizon
      overseer.bqueue.reset(startSlot, finishSlot)

  if not(isNil(overseer.bsqueue)):
    if not(overseer.bsqueue.running()):
      let
        startSlot = dag.backfill.slot
        finishSlot = overseer.getBackfillSidecarFinalSlot()
      overseer.bsqueue.reset(startSlot, finishSlot)

proc updateColumnStatistics(
    overseer: SyncOverseerRef2,
    peer: Peer,
    map: ColumnMap,
    remove: bool
) =
  let
    custodyMap = overseer.columnQuarantine[].custodyMap
    difference = custodyMap and map

  if remove:
    if len(difference) > 0:
      dec(overseer.columnsState.usefulCount)
      for index in difference:
        overseer.columnsState.distribution.mgetOrPut(index, 0).dec()
    else:
      dec(overseer.columnsState.uselessCount)
  else:
    if len(difference) > 0:
      inc(overseer.columnsState.usefulCount)
      for index in difference:
        overseer.columnsState.distribution.mgetOrPut(index, 0).inc()
    else:
      inc(overseer.columnsState.uselessCount)

proc initPeer(
    overseer: SyncOverseerRef2,
    peer: Peer,
): PeerEntryRef[Peer] =
  let dag = overseer.consensusManager.dag
  if dag.head.slot.epoch >= dag.cfg.FULU_FORK_EPOCH:
    let map = overseer.getPeerColumnMap(peer)
    overseer.updateColumnStatistics(peer, map, false)
    overseer.sdag.peers.mgetOrPut(
      peer.getKey(), PeerEntryRef.init(peer, map))
  else:
    overseer.sdag.peers.mgetOrPut(peer.getKey(), PeerEntryRef.init(peer))

proc updatePeerStatus(overseer: SyncOverseerRef2, peer: Peer) =
  let
    blockId =
      peer.getHeadBlockId()
    checkpoint =
      peer.getFinalizedCheckpoint()
    hentry =
      overseer.sdag.roots.mgetOrPut(
        blockId.root, SyncDagEntryRef.init(blockId))
    fentry =
      if checkpoint.isGenesis():
        nil
      else:
        overseer.sdag.roots.mgetOrPut(
          checkpoint.root, SyncDagEntryRef.init(checkpoint))
    missingHeadRoot =
      if DagEntryFlag.Pending in hentry.flags:
        # Missing parent situation
        Opt.some(hentry.blockId.root)
      else:
        # Parent is present, so we searching for first missing one.
        let root = getPendingParentRoot(hentry)
        if root.isSome() and (root.get() == GenesisCheckpoint.root):
          Opt.none(Eth2Digest)
        else:
          root
    missingFinalizedRoot =
      if not(isNil(fentry)) and (DagEntryFlag.Pending in fentry.flags):
        # Missing parent situation
        Opt.some(fentry.blockId.root)
      else:
        Opt.none(Eth2Digest)
    pendingRoots =
      block:
        var res: seq[Eth2Digest]
        if missingHeadRoot.isSome(): res.add(missingHeadRoot.get())
        if missingFinalizedRoot.isSome(): res.add(missingFinalizedRoot.get())
        res

  if overseer.lastSeenCheckpoint.isNone():
    overseer.lastSeenCheckpoint = Opt.some(checkpoint)
    overseer.createQueues()
  else:
    if checkpoint.epoch > overseer.lastSeenCheckpoint.get().epoch:
      overseer.lastSeenCheckpoint = Opt.some(checkpoint)
      overseer.updateQueues()

  if overseer.lastSeenHead.isNone():
    overseer.lastSeenHead = Opt.some(blockId)
  else:
    if blockId.slot > overseer.lastSeenHead.get().slot:
      overseer.lastSeenHead = Opt.some(blockId)

  let entry = overseer.sdag.peers.getOrDefault(peer.getKey())
  if isNil(entry):
    return

  for root in pendingRoots:
    entry.pendingRoots.addLast(root)

  if not(isNil(fentry)) and (DagEntryFlag.Pending notin fentry.flags):
    # Finalized root is already present in SyncDag.
    fentry.flags.incl(DagEntryFlag.Finalized)

proc updatePeer(
    overseer: SyncOverseerRef2,
    peerId: PeerId,
    peerMustPresent: bool,
    block_slot: Slot,
    block_root: Eth2Digest,
    block_parent_root: Eth2Digest,
    sidecarsMissed: bool
) =
  let peerEntry = overseer.sdag.peers.getOrDefault(peerId)
  if isNil(peerEntry) and peerMustPresent:
    return

  let
    missingParentRoot =
      overseer.sdag.updateRoot(block_root, block_slot, block_parent_root,
        sidecarsMissed)

  if missingParentRoot.isSome() and
     (missingParentRoot.get() != GenesisCheckpoint.root):
    if not(isNil(peerEntry)):
      peerEntry.pendingRoots.addLast(missingParentRoot.get())
    else:
      if missingParentRoot.get() == block_parent_root:
        # We only change global `missingRoots` if we got a block without
        # parent.
        let bid = BlockId(slot: block_slot, root: block_root)
        debug "Peer is anonymous, adding root to global missing roots table",
          bid = shortLog(bid), parent_root = shortLog(block_parent_root)
        overseer.missingRoots.incl(missingParentRoot.get())

proc updatePeer(
    overseer: SyncOverseerRef2,
    peerId: PeerId,
    peerMustPresent: bool,
    blck: ref ForkedSignedBeaconBlock,
    missingSidecars: bool
) =
  let (slot, root, parentRoot) =
    withBlck(blck[]):
      (forkyBlck.message.slot, forkyBlck.root, forkyBlck.message.parent_root)
  overseer.updatePeer(
    peerId, peerMustPresent, slot, root, parentRoot, missingSidecars)

proc updatePeer(
    overseer: SyncOverseerRef2,
    peerId: PeerId,
    peerMustPresent: bool,
    blck: ForkedSignedBeaconBlock,
    missingSidecars: bool
) =
  let (slot, root, parentRoot) =
    withBlck(blck):
      (forkyBlck.message.slot, forkyBlck.root, forkyBlck.message.parent_root)
  overseer.updatePeer(
    peerId, peerMustPresent, slot, root,  parentRoot, missingSidecars)

func finalizedDistance*(
    overseer: SyncOverseerRef2
): Opt[uint64] =
  let
    dag = overseer.consensusManager.dag
    checkpoint = dag.headState.finalized_checkpoint

  if overseer.lastSeenCheckpoint.isNone():
    return Opt.none(uint64)

  let lastSeenEpoch = overseer.lastSeenCheckpoint.get().epoch
  if lastSeenEpoch > checkpoint.epoch:
    Opt.some(lastSeenEpoch - checkpoint.epoch)
  else:
    Opt.some(0'u64)

func backfillDistance*(
    overseer: SyncOverseerRef2
): uint64 =
  let
    dag = overseer.consensusManager.dag

  if dag.backfill.slot <= dag.horizon:
    0'u64
  else:
    dag.backfill.slot - dag.horizon

proc networkSyncDistance*(
    overseer: SyncOverseerRef2
): Opt[uint64] =
  let
    dag = overseer.consensusManager.dag
    localHead = dag.head.slot

  if overseer.lastSeenHead.isNone():
    return Opt.none(uint64)

  let lastSeenHead = overseer.lastSeenHead.get().slot
  if lastSeenHead > localHead:
    Opt.some(lastSeenHead - localHead)
  else:
    Opt.some(0'u64)

proc wallSyncDistance*(
    overseer: SyncOverseerRef2
): uint64 =
  let
    dag = overseer.consensusManager.dag
    wallSlot = overseer.beaconClock.currentSlot()
    headSlot = dag.head.slot
  wallSlot - headSlot

proc finalizedDistance*(
  overseer: SyncOverseerRef2,
  peer: Peer
): uint64 =
  let
    dag = overseer.consensusManager.dag
    checkpoint = dag.headState.finalized_checkpoint
    peerCheckpoint = peer.getFinalizedCheckpoint()

  if peerCheckpoint.epoch > checkpoint.epoch:
    peerCheckpoint.epoch - checkpoint.epoch
  else:
    0'u64

proc syncDistance*(
    overseer: SyncOverseerRef2,
    peer: Peer
): uint64 =
  let
    dag = overseer.consensusManager.dag
    localHead = dag.head.slot
    peerHead = peer.getHeadBlockId().slot

  if peerHead > localHead:
    peerHead - localHead
  else:
    0'u64

proc verifyBlock(
    overseer: SyncOverseerRef2,
    signedBlock: ref ForkedSignedBeaconBlock,
    maybeFinalized: bool
): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
  withBlck(signedBlock[]):
    when consensusFork > ConsensusFork.Fulu:
      raiseAssert "Unsupported fork"
    elif consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
      if overseer.shouldGetBlobs(forkyBlck.message.slot):
        let bres =
          overseer.blobQuarantine[].popSidecars(forkyBlck.root, forkyBlck)
        if bres.isSome():
          let res =
            await overseer.blockProcessor.addBlock(
              MsgSource.sync, forkyBlck, bres,
              maybeFinalized = maybeFinalized)
          if res.isErr() and (res.error == VerifierError.MissingParent):
            # In this case block will be stored in quarantine, so we need to
            # preserve blobs in blob quarantine.
            overseer.blobQuarantine[].put(forkyBlck.root, bres.get())
          res
        else:
          overseer.rblockBuffer.add(signedBlock)
          Result[void, VerifierError].err(VerifierError.MissingSidecars)
      else:
        await overseer.blockProcessor.addBlock(
          MsgSource.sync, forkyBlck, Opt.none(BlobSidecars),
          maybeFinalized = maybeFinalized)
    elif consensusFork == ConsensusFork.Fulu:
      if overseer.shouldGetColumns(forkyBlck.message.slot):
        let cres =
          if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
            Opt.some(default(fulu.DataColumnSidecars))
          else:
            overseer.columnQuarantine[].popSidecars(forkyBlck.root)
        if cres.isSome():
          let res =
            await overseer.blockProcessor.addBlock(
              MsgSource.sync, forkyBlck, cres,
              maybeFinalized = maybeFinalized)
          if res.isErr() and (res.error == VerifierError.MissingParent):
            # In this case block will be stored in quarantine, so we need to
            # preserve columns in column quarantine.
            overseer.columnQuarantine[].put(forkyBlck.root, cres.get())
          res
        else:
          overseer.rblockBuffer.add(signedBlock)
          Result[void, VerifierError].err(VerifierError.MissingSidecars)
      else:
        await overseer.blockProcessor.addBlock(
          MsgSource.sync, forkyBlck, Opt.none(fulu.DataColumnSidecars),
          maybeFinalized = maybeFinalized)
    else:
      await overseer.blockProcessor.addBlock(
        MsgSource.sync, forkyBlck, noSidecars, maybeFinalized = maybeFinalized)

proc verifyBlock(
    overseer: SyncOverseerRef2,
    signedBlock: ForkedSignedBeaconBlock,
    maybeFinalized: bool
): Future[Result[void, VerifierError]] {.
  async: (raw: true, raises: [CancelledError]).} =
  verifyBlock(overseer, newClone signedBlock, maybeFinalized)

proc getStatusPeriod*(
    overseer: SyncOverseerRef2,
    peer: Peer
): chronos.Duration =
  let
    dag = overseer.consensusManager.dag
    localHead = dag.head.bid
    peerHead = peer.getHeadBlockId()
    peerFinalizedCheckpoint = peer.getFinalizedCheckpoint()
    secondsPerSlot = int(dag.cfg.timeParams.SLOT_DURATION.seconds)

  if peerFinalizedCheckpoint.epoch < overseer.lastSeenCheckpoint.get.epoch:
    # Peer is not in sync with the network.
    return chronos.seconds(10 * secondsPerSlot)

  if localHead.slot.epoch() < peerFinalizedCheckpoint.epoch:
    # We are behind peer's finalized checkpoint, performing forward syncing.
    # 10 slots (mainnet: 2.minutes)
    return chronos.seconds(10 * secondsPerSlot)

  if (localHead.slot >= peerHead.slot) and
     (localHead.slot < overseer.lastSeenHead.get.slot):
    # Peer's head slot is behind ours, but we still not in sync with network.
    # So we need to refresh status information immediately.
    return chronos.seconds(0)

  if peerHead.slot < overseer.lastSeenHead.get.slot:
    # Peer's head is behind network's peer head.
    return chronos.seconds(1 * secondsPerSlot)

  if localHead.slot == overseer.lastSeenHead.get.slot:
    # Node is optimistically synced
    return chronos.seconds(5 * secondsPerSlot)

  # Node is almost synced, but still behind peer's head.
  chronos.seconds(1 * secondsPerSlot)

func getMissingSidecarsRoots(entry: SyncDagEntryRef): seq[BlockId] =
  var res: seq[BlockId]
  if DagEntryFlag.MissingSidecars in entry.flags:
    res.add(entry.blockId)
  for currentEntry in entry.parents():
    if DagEntryFlag.MissingSidecars in currentEntry.flags:
      res.add(currentEntry.blockId)
    if DagEntryFlag.Finalized in currentEntry.flags:
      break
  res.reversed()

func cleanMissingSidecarsRoots(entry: SyncDagEntryRef) =
  if DagEntryFlag.MissingSidecars in entry.flags:
    entry.flags.excl(DagEntryFlag.MissingSidecars)
  for currentEntry in entry.parents():
    entry.flags.excl(DagEntryFlag.MissingSidecars)

func getBlock(
    blocks: openArray[ref ForkedSignedBeaconBlock],
    root: Eth2Digest,
    slot: Slot
): ref ForkedSignedBeaconBlock =
  for blck in blocks:
    if (blck[].root == root) and (blck[].slot == slot):
      return blck
  nil

proc doPeerPause(
    overseer: SyncOverseerRef2,
    peer: Peer,
    loopTime: chronos.Moment
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    dag = overseer.consensusManager.dag
    timeParams = dag.cfg.timeParams
    peerHead = peer.getHeadBlockId()
    peerEntry =
      block:
        let res = overseer.sdag.peers.getOrDefault(peer.getKey())
        if isNil(res): return
        res
    hentry =
      block:
        let res = overseer.sdag.roots.getOrDefault(peerHead.root)
        if isNil(res): return
        res

  logScope:
    peer = peer
    peer_head = shortLog(peerHead)
    peer_finalized_head = shortLog(peer.getFinalizedCheckpoint())
    peer_ea_slot = getEaSlotLog(peer)
    peer_agent = $peer.getRemoteAgent()
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()

  var doSleep = false

  if overseer.finalizedDistance().get() > 1'u64:
    ## We are in forward syncing.
    if dag.finalizedHead.slot.epoch >= peer.getFinalizedCheckpoint().epoch:
      doSleep = true
  else:
    ## We are in sync or almost in sync.
    if len(peerEntry.pendingRoots) == 0 and
       len(overseer.missingRoots) == 0 and
       len(getMissingSidecarsRoots(hentry)) == 0:
      doSleep = true

    if not(dag.needsBackfill()):
      doSleep = true

  if not(doSleep) and (Moment.now() - loopTime) < 50.milliseconds:
    debug "Endless loop detected for peer"
    doSleep = true

  if doSleep:
    let
      currentTime = overseer.beaconClock.now()
      currentSlot = overseer.beaconClock.currentSlot()
      timeToSlot =
        if overseer.syncDistance(peer) == 0:
          let
            next = currentSlot + 1
            nanos =
              (next.start_beacon_time(timeParams) - currentTime).nanoseconds
          if nanos <= 0:
            ZeroDuration
          else:
            nanoseconds(nanos)
        else:
          1.seconds

    # Without this check peer.getFuture() could return absolutely new Future,
    # which will never be finished, because peer is already disconnected.
    if peer.connectionState != ConnectionState.Connected:
      return false

    let
      peerFut = peer.getFuture().join()
      timeFut = sleepAsync(timeToSlot)

    try:
      debug "Peer is entering sleeping state", sleep_time = timeToSlot
      discard await race(timeFut, peerFut)
      if peerFut.finished():
        await cancelAndWait(timeFut)
        return false
      await cancelAndWait(peerFut)
    except CancelledError as exc:
      await cancelAndWait(timeFut, peerFut)
      raise exc
  true

proc doPeerUpdateStatus(
    overseer: SyncOverseerRef2,
    peer: Peer
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    dag = overseer.consensusManager.dag
    peerHead = peer.getHeadBlockId()
    peerFinalizedCheckpoint = peer.getFinalizedCheckpoint()
    peerStatusAge = Moment.now() - peer.getStatusLastTime()
    statusPeriod = overseer.getStatusPeriod(peer)

  logScope:
    peer = peer

  if peerStatusAge < statusPeriod:
    # Peer's status information is still relevant
    return true

  debug "Requesting fresh status information from peer",
    peer_head = shortLog(peerHead),
    peer_finalized_head = shortLog(peerFinalizedCheckpoint),
    status_age = peerStatusAge,
    status_period = statusPeriod

  if not(await peer.updateStatus()):
    debug "Failed to obtain fresh status information from peer"
    peer.updateScore(PeerScoreNoStatus)
    return false

  let
    newPeerHead = peer.getHeadBlockId()

  if peerHead.slot >= newPeerHead.slot:
    let stalePeriod =
      (dag.cfg.timeParams.SLOT_DURATION * StatusStalePeriod)
    if peerStatusAge >= stalePeriod:
      peer.updateScore(PeerScoreStaleStatus)
      debug "Peer's status information is stale",
        peer_head = shortLog(newPeerHead),
        peer_finalized_head = shortLog(peer.getFinalizedCheckpoint()),
        status_age = Moment.now() - peer.getStatusLastTime(),
        status_period = overseer.getStatusPeriod(peer)
  else:
    # Updating data structures about newly received Peer's status information.
    overseer.updatePeerStatus(peer)
    peer.updateScore(PeerScoreGoodStatus)
    debug "Peer status information updated",
      peer_head = shortLog(newPeerHead),
      peer_finalized_head = shortLog(peer.getFinalizedCheckpoint()),
      status_age = Moment.now() - peer.getStatusLastTime(),
      status_period = overseer.getStatusPeriod(peer)

  true

proc doPeerUpdateRoots(
    overseer: SyncOverseerRef2,
    peer: Peer,
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    peerEntry =
      block:
        let res = overseer.sdag.peers.getOrDefault(peer.getKey())
        if isNil(res): return false
        res
  var
    roots =
      block:
        var
          res: seq[Eth2Digest]
          counter = 0
        # Add peer missing roots
        while counter < peerEntry.maxBlocksPerRequest:
          if len(peerEntry.pendingRoots) > 0:
            res.add(peerEntry.pendingRoots.popFirst())
            inc(counter)
          else:
            break
        # Add global missing roots.
        for item in overseer.missingRoots:
          if counter < peerEntry.maxBlocksPerRequest:
            res.add(item)
            inc(counter)
          else:
            break
        res

  template restoreRoots() =
    # We should return all the roots back to the pending queue.
    for index in countdown(len(roots) - 1, 0):
      peerEntry.pendingRoots.addFirst(roots[index])

  template removeRoot(root: Eth2Digest) =
    let index = roots.find(root)
    if index >= 0:
      # We perform O(n) delete to keep order of roots.
      roots.delete(index)
    overseer.missingRoots.excl(root)

  logScope:
    peer = peer
    block_roots = shortLog(roots)
    roots_count = len(roots)
    max_blocks_per_request = peerEntry.maxBlocksPerRequest
    peer_agent = $peer.getRemoteAgent()
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    data_type = "blocks"

  if len(roots) == 0:
    debug "No pending roots available for peer"
    return true

  debug "Requesting blocks by root from peer"

  let
    blocks =
      try:
        (await beaconBlocksByRoot_v2(peer, BlockRootsList roots)).valueOr:
          debug "Blocks by root request failed", reason = error, version = 2
          peer.updateScore(PeerScoreNoValues)
          return false
      except CancelledError as exc:
        restoreRoots()
        raise exc

  debug "Received blocks by root on request",
    blocks = slimLog(blocks.asSeq()), blocks_count = len(blocks)

  checkResponse(roots, blocks.asSeq()).isOkOr:
    restoreRoots()
    debug "Incorrect blocks by root received",
      blocks = slimLog(blocks.asSeq()), blocks_count = len(blocks),
      reason = $error
    peer.updateScore(PeerScoreBadResponse)
    return false

  debug "Blocks by root passed response validation",
        blocks = slimLog(blocks.asSeq()), blocks_count = len(blocks)

  if len(roots) > len(blocks):
    # Number of requested roots is bigger than number of received blocks.
    if len(roots) == 1:
      restoreRoots()
      debug "Empty response received for single root request",
        blocks = slimLog(blocks.asSeq()), blocks_count = len(blocks)
      peer.updateScore(PeerScoreBadResponse)
      return false
    peerEntry.maxBlocksPerRequest.decreaseBlocksCount()
  else:
    let consensusFork = blocks[0][].kind
    overseer.increaseBlocksCount(
      peerEntry.maxBlocksPerRequest, consensusFork)

  for signedBlock in blocks.asSeq():
    # maybeFinalized = false because we are working in range `>finalizedEpoch`.
    let res =
      try:
        await overseer.verifyBlock(signedBlock, maybeFinalized = false)
      except CancelledError as exc:
        restoreRoots()
        raise exc

    if res.isErr() and (res.error == VerifierError.Invalid):
      debug "Block verification NOT passed",
        fork = signedBlock[].kind,
        block_root = shortLog(signedBlock[].root),
        reason = $res.error
      restoreRoots()
      peer.updateScore(PeerScoreBadResponse)
      return false
    let missingSidecars =
      if res.isErr() and (res.error == VerifierError.MissingSidecars):
        true
      else:
        false
    if res.isErr():
      if missingSidecars:
        debug "Block missing sidecars",
          fork = signedBlock[].kind,
          missing_sidecars = overseer.getMissingIndicesLog(signedBlock),
          reason = $res.error
      else:
        debug "Block verification passed",
          fork = signedBlock[].kind,
          block_root = shortLog(signedBlock[].root),
          reason = $res.error
    else:
      debug "Block verification passed",
        fork = signedBlock[].kind,
        block_root = shortLog(signedBlock[].root),
        reason = "ok"
    # Update SyncDAG with block
    overseer.updatePeer(peer.getKey(), true, signedBlock, missingSidecars)
    removeRoot(signedBlock[].root)

  true

proc doPeerUpdateRootsSidecars(
    overseer: SyncOverseerRef2,
    peer: Peer
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    dag = overseer.consensusManager.dag
    peerEntry =
      block:
        let res = overseer.sdag.peers.getOrDefault(peer.getKey())
        if isNil(res): return false
        res
    peerHead = peer.getHeadBlockId()
    headEntry =
      block:
        let res = overseer.sdag.roots.getOrDefault(peerHead.root)
        if isNil(res): return false
        res
    bids = headEntry.getMissingSidecarsRoots()

  var
    emptyBlobBlocks: seq[ref ForkedSignedBeaconBlock]
    emptyColumnBlocks: seq[ref ForkedSignedBeaconBlock]
    blobRoots: seq[BlobIdentifier]
    columnRoots: seq[DataColumnsByRootIdentifier]
    columnsCount = 0

  logScope:
    peer = peer
    max_blocks_per_request = peerEntry.maxBlocksPerRequest
    max_sidecars_per_request = peerEntry.maxSidecarsPerRequest
    peer_agent = $peer.getRemoteAgent()
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()

  if len(bids) == 0:
    debug "No pending sidecars available for peer"
    return true

  debug "Preparing sidecars by root for peer",
    block_ids = shortLog(bids), block_ids_count = len(bids)

  for bid in bids:
    let signedBlock =
      block:
        var res: ref ForkedSignedBeaconBlock
        res = overseer.rblockBuffer.getOrDefault(bid.root)
        if isNil(res):
          let qres = overseer.blockQuarantine[].peekSidecarless(bid.root)
          if qres.isNone():
            continue
          res = newClone qres.get()
        res

    withBlck(signedBlock[]):
      when consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
        let requests =
          overseer.blobQuarantine[].fetchMissingSidecars(
            bid.root, forkyBlck)
        emptyBlobBlocks.add(signedBlock)
        for request in requests:
          blobRoots.add(request)
          if len(blobRoots) >= peerEntry.maxSidecarsPerRequest:
            break
      elif consensusFork == ConsensusFork.Fulu:
        let
          peerMap = overseer.getPeerColumnMap(peerEntry)
          request =
            if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
              DataColumnsByRootIdentifier()
            else:
              overseer.columnQuarantine[].fetchMissingSidecars(
                bid.root, peerMap)
        if len(request.indices) > 0:
          # len(request.indices) == 0 when we already have data column sidecars
          # which peer could provide.
          emptyColumnBlocks.add(signedBlock)
          columnRoots.add(request)
          columnsCount.inc(len(request.indices))
          if columnsCount >= peerEntry.maxSidecarsPerRequest:
            break
      elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Capella:
        raiseAssert "Should not be happen!"
      else:
        raiseAssert "Unsupported fork"

  ##
  ## Blob sidecars processing
  ##
  if len(blobRoots) > 0:
    logScope:
      roots = shortLog(blobRoots)
      roots_count = len(blobRoots)
      data_type = "blobs"

    debug "Requesting blob sidecars by root from peer"

    defer:
      # Preemptively cleanup blocks range on exit
      cleanupList(emptyBlobBlocks)

    let
      blobSidecars =
        (await blobSidecarsByRoot(peer, BlobIdentifierList blobRoots,
          maxResponseItems = len(blobRoots))).valueOr:
          debug "Blobs by root request failed", reason = error
          peer.updateScore(PeerScoreNoValues)
          return false

    debug "Received blob sidecars by root on request",
      blobs = slimLog(blobSidecars.asSeq()), blobs_count = len(blobSidecars)

    var
      records =
        groupSidecars(blobRoots, blobSidecars.asSeq()).valueOr:
          debug "Response to blobs by root is incorrect",
            blobs = slimLog(blobSidecars.asSeq()),
            blobs_count = len(blobSidecars), reason = error
          peer.updateScore(PeerScoreBadResponse)
          return false

    for record in records:
      overseer.blobQuarantine[].put(record.block_root, record.sidecar)

    defer:
      # Preemptively cleanup sidecar records list on exit
      cleanupRecordsList(records)

    if len(records) < len(blobRoots):
      if len(blobRoots) == 1:
        debug "Empty response received for single root request",
          blobs = slimLog(blobSidecars.asSeq()),
          blobs_count = len(blobSidecars)
        peer.updateScore(PeerScoreBadResponse)
        return false
      # Number of received sidecars is less than number of requested.
      peerEntry.maxSidecarsPerRequest.decreaseSidecarsCount()
    else:
      overseer.increaseSidecarsCount(
        peerEntry.maxSidecarsPerRequest, ConsensusFork.Electra)

    debug "Processing block and sidecars by root",
      blocks = slimLog(emptyBlobBlocks)

    for signedBlock in emptyBlobBlocks:
      debug "Processing block by root", blck = slimLog(signedBlock)
      withBlck(signedBlock[]):
        when consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
          let entry = overseer.sdag.roots.getOrDefault(forkyBlck.root)
          if not(isNil(entry)) and (DagEntryFlag.MissingSidecars in entry.flags):
            let res = await overseer.verifyBlock(signedBlock, false)
            if res.isErr():
              debug "Block processor response", reason = res.error,
                blck = slimLog(signedBlock)
              case res.error
              of VerifierError.Invalid:
                peer.updateScore(PeerScoreBadResponse)
                entry.flags.excl(DagEntryFlag.MissingSidecars)
                overseer.rblockBuffer.remove(forkyBlck.root)
                return false
              of VerifierError.UnviableFork:
                peer.updateScore(PeerScoreUnviableFork)
                entry.flags.incl(DagEntryFlag.Unviable)
                entry.flags.excl(DagEntryFlag.MissingSidecars)
                overseer.rblockBuffer.remove(forkyBlck.root)
                return false
              of VerifierError.MissingParent, VerifierError.Duplicate:
                # This flags means that we have sidecars.
                entry.flags.excl(DagEntryFlag.MissingSidecars)
                peer.updateScore(PeerScoreGoodValues)
                overseer.rblockBuffer.remove(forkyBlck.root)
              of VerifierError.MissingSidecars:
                # We still missing sidecars.
                discard
            else:
              debug "Block processor response", reason = "ok",
                blck = slimLog(signedBlock)
              overseer.rblockBuffer.remove(forkyBlck.root)
              peer.updateScore(PeerScoreGoodValues)
              entry.flags.excl(DagEntryFlag.MissingSidecars)
        else:
          raiseAssert "Should not be happen!"

  ##
  ## Data column sidecars processing.
  ##
  if len(columnRoots) > 0:
    logScope:
      head = shortLog(dag.head)
      roots = shortLog(columnRoots)
      roots_count = columnsCount
      peer_map = shortLog(overseer.getPeerColumnMap(peerEntry))
      data_type = "columns"

    debug "Requesting data column sidecars by root from peer"

    defer:
      # Preemptively cleanup blocks range on exit
      cleanupList(emptyColumnBlocks)

    let
      consensusFork = ConsensusFork.Fulu
        # This `consensusFork` is only used for request sidecars amount
        # adjustments.
      columnSidecars =
        (await dataColumnSidecarsByRoot(peer,
          DataColumnsByRootIdentifierList columnRoots)).valueOr:
            debug "Data columns by root request failed", reason = error
            peer.updateScore(PeerScoreNoValues)
            return false

    debug "Received data column sidecars by root on request",
      columns = slimLog(columnSidecars.asSeq()),
      columns_count = len(columnSidecars)

    var
      records =
        groupSidecars(
          columnRoots, columnsCount, columnSidecars.asSeq()).valueOr:
            debug "Response to data columns by root is incorrect",
              columns = slimLog(columnSidecars.asSeq()),
              columns_count = len(columnSidecars), reason = error
            peer.updateScore(PeerScoreBadResponse)
            return false

    defer:
      # Preemptively cleanup sidecar records list on exit
      cleanupRecordsList(records)

    for record in records:
      overseer.columnQuarantine[].put(record.block_root, record.sidecar)

    if len(records) < columnsCount:
      if columnsCount == 1:
        debug "Empty response received for single root request",
          columns = slimLog(columnSidecars.asSeq()),
          columns_count = len(columnSidecars)
        peer.updateScore(PeerScoreBadResponse)
        return false
      # Number of received sidecars is less than number of requested.
      peerEntry.maxSidecarsPerRequest.decreaseSidecarsCount()
    else:
      overseer.increaseSidecarsCount(
        peerEntry.maxSidecarsPerRequest, consensusFork)

    debug "Processing blocks and sidecars by root",
      blocks = slimLog(emptyColumnBlocks)

    for signedBlock in emptyColumnBlocks:
      debug "Processing single block and sidecars by root",
        blck = slimLog(signedBlock)
      withBlck(signedBlock[]):
        when consensusFork == ConsensusFork.Fulu:
          let entry = overseer.sdag.roots.getOrDefault(forkyBlck.root)
          if not(isNil(entry)) and (DagEntryFlag.MissingSidecars in entry.flags):
            let res = await overseer.verifyBlock(signedBlock, false)
            if res.isErr():
              debug "Block and sidecars by root processor response",
                reason = res.error, blck = slimLog(signedBlock)
              case res.error
              of VerifierError.Invalid:
                entry.flags.excl(DagEntryFlag.MissingSidecars)
                peer.updateScore(PeerScoreBadResponse)
                overseer.rblockBuffer.remove(forkyBlck.root)
                return false
              of VerifierError.UnviableFork:
                entry.flags.excl(DagEntryFlag.MissingSidecars)
                peer.updateScore(PeerScoreUnviableFork)
                entry.flags.incl(DagEntryFlag.Unviable)
                overseer.rblockBuffer.remove(forkyBlck.root)
                return false
              of VerifierError.MissingParent, VerifierError.Duplicate:
                # This flags means that we have sidecars.
                entry.flags.excl(DagEntryFlag.MissingSidecars)
                overseer.rblockBuffer.remove(forkyBlck.root)
              of VerifierError.MissingSidecars:
                # We still missing sidecars.
                discard
            else:
              debug "Block and sidecars by root processor response",
                reason = "ok", blck = slimLog(signedBlock)
              overseer.rblockBuffer.remove(forkyBlck.root)
              peer.updateScore(PeerScoreGoodValues)
              entry.flags.excl(DagEntryFlag.MissingSidecars)
        else:
          raiseAssert "Should not be happen!"
  true

template bsqueue(
    overseer: SyncOverseerRef2,
    direction: SyncQueueKind
): untyped =
  case direction
  of SyncQueueKind.Forward:
    overseer.fqueue
  of SyncQueueKind.Backward:
    overseer.bqueue

template ssqueue(
    overseer: SyncOverseerRef2,
    direction: SyncQueueKind
): untyped =
  case direction
  of SyncQueueKind.Forward:
    overseer.fsqueue
  of SyncQueueKind.Backward:
    overseer.bsqueue

template sbuffer(
    overseer: SyncOverseerRef2,
    direction: SyncQueueKind
): var BlocksRangeBuffer =
  case direction
  of SyncQueueKind.Forward:
    overseer.fblockBuffer
  of SyncQueueKind.Backward:
    overseer.bblockBuffer

proc doRangeSyncStep(
    overseer: SyncOverseerRef2,
    peer: Peer,
    direction: SyncQueueKind
): Future[bool] {.async: (raises: [CancelledError]).} =
  if isNil(overseer.sdag.peers.getOrDefault(peer.getKey())):
    return false

  let
    dag = overseer.consensusManager.dag
    checkpoint = peer.getFinalizedCheckpoint()

  let request =
    overseer.bsqueue(direction).pop(checkpoint.epoch.start_slot(), peer)

  logScope:
    peer = peer
    request = request
    head = shortLog(dag.head)
    block_buffer = shortLog(overseer.sbuffer(direction))
    blocks_queue = shortLog(overseer.bsqueue(direction))
    sidecars_queue = shortLog(overseer.ssqueue(direction))
    peer_checkpoint = shortLog(checkpoint)
    peer_head = shortLog(peer.getHeadBlockId())
    peer_ea_slot = getEaSlotLog(peer)
    last_seen_head = overseer.getLastSeenHeadLog()
    last_seen_finalized = overseer.getLastSeenFinalizedHeadLog()
    peer_agent = $peer.getRemoteAgent()
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    direction = direction

  if request.isEmpty():
    debug "Empty request received from blocks queue"
    return true

  debug "New blocks range request"

  try:
    let
      blocks =
        (await beaconBlocksByRange_v2(
          peer, request.data.slot, request.data.count, 1'u64)).valueOr:
            debug "Failed to get block range from peer", reason = error
            overseer.bsqueue(direction).push(request)
            return false

    debug "Received blocks range on request",
      blocks_count = len(blocks),
      blocks_map = getShortMap(request, blocks.toSeq())

    checkResponse(request.data, blocks.asSeq()).isOkOr:
      debug "Incorrect range of blocks received",
        blocks_count = len(blocks),
        blocks_map = getShortMap(request, blocks.toSeq()), reason = $error
      peer.updateScore(PeerScoreBadResponse)
      overseer.bsqueue(direction).push(request)
      return false

    debug "Sending blocks range to processor",
      blocks_count = len(blocks),
      blocks_map = getShortMap(request, blocks.asSeq())

    let resp =
      await overseer.bsqueue(direction).push(
        request, blocks.asSeq(), maybeFinalized = true)

    debug "Blocks queue response",
      code = resp.code, count = resp.count, blck = shortLog(resp.blck),
      blocks_count = len(blocks),
      blocks_map = getShortMap(request, blocks.asSeq()),
      block_buffer = shortLog(overseer.sbuffer(direction)),
      blocks_queue = shortLog(overseer.bsqueue(direction)),
      sidecars_queue = shortLog(overseer.bsqueue(direction))

    if resp.count > 0:
      peer.updateScore(PeerScoreGoodValues)
      true
    elif resp.count == 0:
      true
    else:
      let rewindPoint = overseer.bsqueue(direction).inpSlot

      logScope:
        code = resp.code
        count = resp.count
        rewind_point = rewindPoint
        blck = shortLog(resp.blck)

      let before = shortLog(overseer.sbuffer(direction))
      case direction
      of SyncQueueKind.Forward:
        overseer.fblockBuffer.invalidate(rewindPoint)
      of SyncQueueKind.Backward:
        overseer.bblockBuffer.invalidate(rewindPoint)
      debug "Blocks queue rewind detected, invalidating block buffer",
        block_buffer_before = before
      false

  except CancelledError as exc:
    overseer.bsqueue(direction).push(request)
    raise exc

proc doRangeSidecarsStep(
    overseer: SyncOverseerRef2,
    peer: Peer,
    direction: SyncQueueKind
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    dag = overseer.consensusManager.dag
    checkpoint = peer.getFinalizedCheckpoint()
    peerEntry =
      block:
        let res = overseer.sdag.peers.getOrDefault(peer.getKey())
        if isNil(res): return false
        res

  block:
    let
      blockSlot = overseer.bsqueue(direction).inpSlot
      blockRange =
        SyncRange.init(blockSlot, uint64(overseer.blocksChunkSize))

    logScope:
      peer = peer
      block_slot = blockSlot
      block_range = $blockRange
      head = shortLog(dag.head)
      block_buffer = shortLog(overseer.sbuffer(direction))
      blocks_queue = shortLog(overseer.bsqueue(direction))
      sidecars_queue = shortLog(overseer.ssqueue(direction))
      peer_checkpoint = shortLog(checkpoint)
      peer_head = shortLog(peer.getHeadBlockId())
      direction = direction

    let notInRange =
      case direction
      of SyncQueueKind.Forward:
        blockRange.last_slot < overseer.ssqueue(direction).startSlot
      of SyncQueueKind.Backward:
        blockRange.last_slot < overseer.ssqueue(direction).finalSlot
    if notInRange:
      debug "Sidecars queue is not in range, skipping step"
      return true

  let request =
    overseer.ssqueue(direction).pop(checkpoint.epoch.start_slot(), peer)

  logScope:
    peer = peer
    request = request
    head = shortLog(dag.head)
    block_buffer = shortLog(overseer.sbuffer(direction))
    blocks_queue = shortLog(overseer.bsqueue(direction))
    sidecars_queue = shortLog(overseer.ssqueue(direction))
    blob_quarantine = shortLog(overseer.blobQuarantine[])
    column_quarantine = shortLog(overseer.columnQuarantine[])
    peer_checkpoint = shortLog(checkpoint)
    peer_head = shortLog(peer.getHeadBlockId())
    peer_ea_slot = getEaSlotLog(peer)
    peer_agent = $peer.getRemoteAgent()
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    direction = direction

  if request.isEmpty():
    debug "Empty request received from sidecars queue"
    return true

  debug "New sidecars range request"

  if not(overseer.checkDataAvailable(peer, direction, request.data)):
    debug "Request cannot be satisfied by the peer",
      peer_ea_slot = peer.getEarliestAvailableSlot().get()
    peer.updateScore(PeerScoreNoValues)
    overseer.ssqueue(direction).push(request)
    return true

  let consensusFork = dag.cfg.consensusForkAtEpoch(
    request.data.start_slot().epoch)

  let resp =
    case consensusFork
    of ConsensusFork.Phase0 .. ConsensusFork.Capella:
      SyncPushResponse()
    of ConsensusFork.Deneb, ConsensusFork.Electra:
      try:
        let
          data =
            (await blobSidecarsByRange(peer, request.data.slot,
              request.data.count, maxResponseItems =
                (request.data.count *
                   dag.cfg.MAX_BLOBS_PER_BLOCK_ELECTRA).Limit)
            ).valueOr:
              peer.updateScore(PeerScoreNoValues)
              debug "Failed to receive blob sidecars range on request",
                reason = $error
              overseer.ssqueue(direction).push(request)
              return false

        debug "Received blob sidecars range from peer",
          blobs_map = getShortMap(request, data.toSeq())

        var
          grouped = groupSidecars(request.data, data.asSeq()).valueOr:
            peer.updateScore(PeerScoreBadResponse)
            debug "Received invalid blob sidecars range",
              reason = $error, blobs_count = len(data),
              blobs = slimLog(data.asSeq())
            overseer.ssqueue(direction).push(request)
            return false
          blocks = overseer.sbuffer(direction).peekRange(request.data)

        defer:
          # Preemptively cleanup blocks range sidecar records list on exit
          cleanupList(blocks)
          cleanupRecordsList(grouped)

          # Early detection of empty response.
        let
          sindex = validateBlocks(blocks, grouped).valueOr:
            peer.updateScore(PeerScoreMissingValues)
            debug "Received non-complete blob sidecars range",
              reason = $error, blobs_count = len(data),
              blobs_map = getShortMap(request, grouped),
              blocks_map = getShortMap(request, blocks),
              block_blobs_map = getBlockBlobsMap(request, blocks),
              blobs = slimLog(data.asSeq()),
              blocks = slimLog(blocks)
            overseer.ssqueue(direction).push(request)
            return false

        if (len(blocks) == 0) and (len(grouped) > 0):
          # Case when we have no blocks, but a lot of blobs.
          debug "Received blobs range that, do not have corresponding blocks " &
                "range"
          overseer.ssqueue(direction).push(request)
          return false

        if sindex != len(grouped):
          let missing =
            block:
              var res: seq[Eth2Digest]
              for item in grouped.toOpenArray(sindex, len(grouped) - 1):
                if (len(res) == 0) or (res[^1] != item.block_root):
                  res.add(item.block_root)
              "[" & res.mapIt(shortLog(it)).join(",") & "]"
          debug "Received blobs range indicates that some blocks in " &
                "corresponding range are missing", missing_blocks = missing

        for record in grouped:
          overseer.blobQuarantine[].put(record.block_root, record.sidecar)

        debug "Sending sidecars range to processor",
          blobs_map = getShortMap(request, grouped),
          blocks_count = len(blocks),
          blocks_map = getShortMap(request, blocks),
          blobs = slimLog(data.asSeq())

        let res = await overseer.ssqueue(direction).push(
          request, blocks, maybeFinalized = true)

        debug "Sidecars queue response",
          code = res.code, count = res.count, blck = shortLog(res.blck),
          blobs_map = getShortMap(request, grouped),
          blocks_count = len(blocks),
          blocks_map = getShortMap(request, blocks),
          blobs = slimLog(data.asSeq())

        # In case we not advance - we should cleanup blob/column quarantines on
        # fatal errors.
        if res.count <= 0:
          if res.code in [SyncProcessError.Invalid,
                          SyncProcessError.UnviableFork]:
            for signed in blocks:
              overseer.blobQuarantine[].remove(signed[].root)
        res

      except CancelledError as exc:
        overseer.ssqueue(direction).push(request)
        raise exc

    of ConsensusFork.Fulu:
      try:
        var
          blocks = overseer.sbuffer(direction).peekRange(request.data)

        let
          custodyMap = overseer.columnQuarantine[].custodyMap
          peerMap = overseer.getPeerColumnMap(peerEntry)
          intersectMap = custodyMap and peerMap

        defer:
          # Preemptively cleanup blocks range on exit
          cleanupList(blocks)

        # Here we perform check if remote peer has compatible columns or not.
        if len(intersectMap) == 0:
          peer.updateScore(PeerScoreNoValues)
          debug "Peer does not have compatible columns",
            custody_map = shortLog(custodyMap),
            peer_map = shortLog(peerMap)
          overseer.ssqueue(direction).push(request)
          return true

        let (columnsNeeded, columnsHave) =
          if len(blocks) > 0:
            # Here we perform check if remote peer can provide columns that we
            # do not have already.
            var
              res1 = false
              res2 = false
            for blck in blocks:
              let
                missingMap =
                  withBlck(blck[]):
                    when consensusFork == ConsensusFork.Fulu:
                      if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
                        ColumnMap()
                      else:
                        overseer.columnQuarantine[].getMissingColumnsMap(
                          forkyBlck.root)
                    else:
                      raiseAssert "Should not happen!"
              if not(missingMap.empty()):
                # We have missing columns.
                res1 = true
                let newOnlyMap = missingMap and intersectMap
                if not(newOnlyMap.empty()):
                  # Peer has something that we don't have.
                  res2 = true
                  break
            (res1, res2)
          else:
            # This is undefined case, because its impossible to obtain
            # blocks.
            (false, false)

        let missingLog = overseer.getMissingColumnsLog(blocks)

        debug "Peer columns compatibility",
           custody_map = shortLog(custodyMap),
           peer_map = shortLog(peerMap),
           intersect_map = shortLog(intersectMap),
           missing_log = missingLog

        if (len(blocks) > 0) and (columnsNeeded and not(columnsHave)):
          peer.updateScore(PeerScoreNoValues)
          debug "Peer has compatible columns that we already have",
            custody_map = shortLog(custodyMap),
            peer_map = shortLog(peerMap),
            intersect_map = shortLog(intersectMap),
            missing_log = missingLog
          overseer.ssqueue(direction).push(request)
          return true

        if (len(blocks) == 0) or (columnsNeeded and columnsHave):
          # We only download sidecars if we miss it and peer have it.
          let
            data =
              (await dataColumnSidecarsByRange(
                peer, request.data.slot, request.data.count,
                List[ColumnIndex, NUMBER_OF_COLUMNS](
                  intersectMap.items().toSeq()))).valueOr:
                    peer.updateScore(PeerScoreNoValues)
                    debug "Failed to receive data column sidecars range " &
                          "on request", reason = $error
                    overseer.ssqueue(direction).push(request)
                    return false

          debug "Received data columns sidecars range from peer",
            columns_map = getShortMap(request, intersectMap, data.toSeq()),
            peer_map = shortLog(peerMap),
            intersection_map = shortLog(intersectMap),
            columns = slimLog(data.asSeq()),
            missing_log = missingLog

          var
            grouped =
              groupSidecars(request.data, intersectMap, data.asSeq()).valueOr:
                peer.updateScore(PeerScoreBadResponse)
                debug "Received invalid data column sidecars range",
                  reason = $error, columns_count = len(data),
                  columns = slimLog(data.asSeq())
                overseer.ssqueue(direction).push(request)
                return false

          defer:
            # Preemptively cleanup sidecar records list on exit
            cleanupRecordsList(grouped)

          # Early detection of empty response.
          let
            sindex = validateBlocks(blocks, grouped, intersectMap).valueOr:
              peer.updateScore(PeerScoreMissingValues)
              debug "Received non-complete data column sidecars range",
                reason = $error, columns_count = len(data),
                columns = shortLog(grouped)
              overseer.ssqueue(direction).push(request)
              return false

          if (len(blocks) == 0) and (len(grouped) > 0):
            # Case when we have no blocks, but a lot of blobs.
            debug "Received columns range which do not have corresponding " &
                  "blocks range"
            overseer.ssqueue(direction).push(request)
            return false

          if sindex != len(grouped):
            let missing =
              block:
                var res: seq[Eth2Digest]
                for item in grouped.toOpenArray(sindex, len(grouped) - 1):
                  if (len(res) == 0) or (res[^1] != item.block_root):
                    res.add(item.block_root)
                "[" & res.mapIt(shortLog(it)).join(",") & "]"
            debug "Received columns range indicates that some blocks in " &
                  "corresponding range are missing", missing_blocks = missing

          for record in grouped:
            overseer.columnQuarantine[].put(record.block_root, record.sidecar)

        else:
          debug "Sidecars are already downloaded",
            custody_map = shortLog(custodyMap),
            peer_map = shortLog(peerMap),
            intersect_map = shortLog(intersectMap),
            missing_log = missingLog,
            columns_needed = columnsNeeded, columns_have = columnsHave

        debug "Sending sidecars range to processor",
          peer_map = shortLog(peerMap),
          blocks_count = len(blocks),
          blocks_map = getShortMap(request, blocks)

        let res = await overseer.ssqueue(direction).push(
          request, blocks, maybeFinalized = true)

        debug "Sidecars queue response",
          code = res.code, count = res.count, blck = shortLog(res.blck),
          peer_map = shortLog(peerMap),
          blocks_count = len(blocks),
          blocks_map = getShortMap(request, blocks)

        if res.code == SyncProcessError.MissingSidecars:
          let
            blck = getBlock(blocks, res.blck.get().root, res.blck.get().slot)
          doAssert(not(isNil(blck)), "Should not be nil")
          debug "Sidecars range still missing items",
            blck = slimLog(blck),
            peer_map = shortLog(peerMap),
            missing_sidecars = overseer.getMissingIndicesLog(blck)

        # In case we not advance - we should cleanup blob/column quarantines on
        # fatal errors.
        if res.count <= 0:
          if res.code in [SyncProcessError.Invalid,
                          SyncProcessError.UnviableFork]:
            for signed in blocks:
              overseer.columnQuarantine[].remove(signed[].root)
        res

      except CancelledError as exc:
        overseer.ssqueue(direction).push(request)
        raise exc

    of ConsensusFork.Gloas:
      raiseAssert "Unsupported fork"

  if resp.count > 0:
    peer.updateScore(PeerScoreGoodValues)
    case direction
    of SyncQueueKind.Forward:
      let advanceSlot =
        min(overseer.bsqueue(direction).inpSlot,
          overseer.ssqueue(direction).inpSlot)
      debug "Pruning sync data structures",
        advance_slot = advanceSlot, prune_epoch = advanceSlot.epoch()
      overseer.fblockBuffer.advance(advanceSlot)
    of SyncQueueKind.Backward:
      let advanceSlot =
        max(overseer.bsqueue(direction).inpSlot,
          overseer.ssqueue(direction).inpSlot)
      debug "Pruning sync data structures",
        advance_slot = advanceSlot, prune_epoch = advanceSlot.epoch()
      overseer.bblockBuffer.advance(advanceSlot)
    true
  elif resp.count == 0:
    true
  else:
    let rewindPoint = overseer.ssqueue(direction).inpSlot

    logScope:
      code = resp.code
      count = resp.count
      rewind_point = rewindPoint
      blck = shortLog(resp.blck)

    let before = shortLog(overseer.sbuffer(direction))
    case direction
    of SyncQueueKind.Forward:
      overseer.fblockBuffer.invalidate(rewindPoint)
    of SyncQueueKind.Backward:
      overseer.bblockBuffer.invalidate(rewindPoint)
    debug "Blocks queue rewind detected, invalidating block buffer",
      block_buffer_before = before

    case direction
    of SyncQueueKind.Forward:
      if rewindPoint < overseer.bsqueue(direction).startSlot:
        debug "Sidecars queue is not in range yet, no syncing needed"
        return false

      if rewindPoint >= overseer.bsqueue(direction).inpSlot:
        debug "Blocks queue is far behind, no syncing needed"
        return false

      debug "Sidecars queue got rewind, syncing blocks queue"
      await overseer.bsqueue(direction).resetWait(rewindPoint)
      debug "Sync queues are in sync"

    of SyncQueueKind.Backward:
      if rewindPoint > overseer.bsqueue(direction).startSlot:
        debug "Sidecars queue is not in range yet, no syncing needed"
        return false

      if rewindPoint <= overseer.bsqueue(direction).inpSlot:
        debug "Blocks queue is far behind, no syncing needed"
        return false

      debug "Sidecars queue got rewind, syncing blocks queue"
      await overseer.bsqueue(direction).resetWait(rewindPoint)
      debug "Sync queues are in sync"

    false

func getLastSeenFinalizedEpoch(
    overseer: SyncOverseerRef2,
): Epoch =
  if overseer.lastSeenCheckpoint.isNone():
    return GENESIS_EPOCH
  overseer.lastSeenCheckpoint.get().epoch

func getLastSeenHeadSlot(
    overseer: SyncOverseerRef2
): Slot =
  if overseer.lastSeenHead.isNone():
    return GENESIS_SLOT
  overseer.lastSeenHead.get().slot

proc startPeer(
    overseer: SyncOverseerRef2,
    peer: Peer
): Future[void] {.async: (raises: []).} =
  let dag = overseer.consensusManager.dag

  logScope:
    peer = peer
    peer_agent = $peer.getRemoteAgent()
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    peer_head = shortLog(peer.getHeadBlockId())
    peer_checkpoint = shortLog(peer.getFinalizedCheckpoint())

  try:
    debug "Peer loop established"

    while true:
      let loopTime = Moment.now()
      if not(await overseer.doPeerUpdateStatus(peer)):
        return
      if not(overseer.pool.checkPeerScore(peer)):
        return

      let peerEntry = overseer.sdag.peers.getOrDefault(peer.getKey())
      if isNil(peerEntry):
        return

      if overseer.finalizedDistance().get() < RootSyncEpochsActivationCount:
        debug "Peer current root state",
          local_head = dag.head.slot,
          head_distance = overseer.syncDistance(peer)

        if not(await overseer.doPeerUpdateRoots(peer)):
          return
        if not(overseer.pool.checkPeerScore(peer)):
          return

        if not(await overseer.doPeerUpdateRootsSidecars(peer)):
          return
        if not(overseer.pool.checkPeerScore(peer)):
          return

      let checkpoint = dag.headState.finalized_checkpoint

      if overseer.finalizedDistance().get() > 1'u64:
        # TODO (cheatfate): we should check for WSP.
        debug "Peer current forward state",
          local_checkpoint = shortLog(checkpoint),
          peer_finalized_distance = overseer.finalizedDistance(peer),
          finalized_distance = overseer.finalizedDistance().get(),
          forward_block_buffer = shortLog(overseer.fblockBuffer)

        if not(overseer.fblockBuffer.almostFull()):
          if not(await overseer.doRangeSyncStep(peer, SyncQueueKind.Forward)):
            return
          if not(overseer.pool.checkPeerScore(peer)):
            return

        if not(await overseer.doRangeSidecarsStep(peer, SyncQueueKind.Forward)):
          return
        if not(overseer.pool.checkPeerScore(peer)):
          return

      if dag.needsBackfill():
        debug "Peer current backfill state",
          needs_backfill = dag.needsBackfill(),
          backfill_slot = dag.backfill.slot,
          backfill_distance = overseer.backfillDistance(),
          backward_block_buffer = shortLog(overseer.bblockBuffer)
        if overseer.wallSyncDistance() <= SyncDeviationSlotsCount:
          if not(overseer.bblockBuffer.almostFull()):
            if not(
              await overseer.doRangeSyncStep(peer, SyncQueueKind.Backward)):
              return
            if not(overseer.pool.checkPeerScore(peer)):
              return

          if not(
            await overseer.doRangeSidecarsStep(peer, SyncQueueKind.Backward)):
            return
          if not(overseer.pool.checkPeerScore(peer)):
            return

      if not(await overseer.doPeerPause(peer, loopTime)):
        return

  except CancelledError:
    discard
  finally:
    # Cleanup
    var entry: PeerEntryRef[Peer]
    if overseer.sdag.peers.pop(peer.getKey(), entry):
      overseer.pool.release(peer)
    if entry.columnsMap.isSome():
      overseer.updateColumnStatistics(peer, entry.columnsMap.get(), true)
    debug "Remote peer disconnected"

proc speed(
    startslot, lastslot: Slot,
    starttime, lasttime: chronos.Moment
): float {.inline.} =
  ## Returns number of slots per second.
  if (lastslot <= startslot) or (lasttime <= starttime):
    0.0 # replays for example
  else:
    float(lastslot - startslot) / toFloatSeconds(lasttime - starttime)

proc toTimeLeftString(d: Duration): string =
  if d == InfiniteDuration:
    return "--h--m"

  var v = d
  var res = ""
  let ndays = chronos.days(v)
  if ndays > 0:
    res = res & (if ndays < 10: "0" & $ndays else: $ndays) & "d"
    v = v - chronos.days(ndays)

  let nhours = chronos.hours(v)
  if nhours > 0:
    res = res & (if nhours < 10: "0" & $nhours else: $nhours) & "h"
    v = v - chronos.hours(nhours)
  else:
    res =  res & "00h"

  let nmins = chronos.minutes(v)
  if nmins > 0:
    res = res & (if nmins < 10: "0" & $nmins else: $nmins) & "m"
    v = v - chronos.minutes(nmins)
  else:
    res = res & "00m"
  res

type
  SyncPerformance = object
    average: float
    count: int
    done: float
    timeLeft: chronos.Duration

func init(t: typedesc[SyncPerformance]): SyncPerformance =
  SyncPerformance()

func update(
    performance: var SyncPerformance,
    slota, slotb: Slot,
    timea, timeb: chronos.Moment,
    total: uint64,
    remains: uint64
) =
  let
    forwardSlotsPerSec = speed(slota, slotb, timea, timeb)
    remainsFloat = float(remains)
    totalFloat = float(total)
  inc(performance.count)
  performance.average =
    performance.average +
      (forwardSlotsPerSec - performance.average) / float(performance.count)
  performance.done =
    if totalFloat == 0.0:
      0.0
    else:
      (totalFloat - remainsFloat) / totalFloat
  performance.timeLeft =
    if performance.average >= 0.001:
      Duration.fromFloatSeconds(remainsFloat / performance.average)
    else:
      InfiniteDuration

func formatString(performance: SyncPerformance): string =
  performance.timeLeft.toTimeLeftString() & " (" &
    (performance.done * 100.0).formatBiggestFloat(ffDecimal, 2) & "%) " &
    performance.average.formatBiggestFloat(ffDecimal, 4) & "slots/s"

proc maintenanceLoop(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =
  try:
    debug "Overseer maintenance established"

    while true:
      await sleepAsync(1.seconds)
      if overseer.finalizedDistance.isSome() and
        (overseer.finalizedDistance().get() == 0'u64):
        # We perform reset of forward block buffer when forward syncing
        # finished
        overseer.fblockBuffer.reset()
      if overseer.backfillDistance() == 0'u64:
        # We perform reset of backfill block buffer when backfill process
        # finished
        overseer.bblockBuffer.reset()

  except CancelledError:
    discard

proc timeMonitoringLoop(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =
  let
    dag = overseer.consensusManager.dag
    bootForwardSlot = dag.head.slot
    bootBackwardSlot = dag.backfill.slot

  func forwardRemains(slot: Slot): uint64 =
    let
      checkpoint = overseer.lastSeenCheckpoint.valueOr:
        return 0'u64
      checkpointSlot = checkpoint.epoch.start_slot()
    if slot >= checkpointSlot:
      return 0'u64
    checkpointSlot - slot

  func backwardRemains(slot: Slot): uint64 =
    if slot < dag.horizon():
      return 0'u64
    slot - dag.horizon()

  template forwardRemains(): uint64 = forwardRemains(dag.head.slot)
  template forwardTotal(): uint64 = forwardRemains(bootForwardSlot)
  template backwardRemains(): uint64 = backwardRemains(dag.backfill.slot)
  template backwardTotal(): uint64 = backwardRemains(bootBackwardSlot)

  try:
    debug "Time/performance monitoring established"

    var
      forwardPerf = SyncPerformance.init()
      backwardPerf = SyncPerformance.init()

    while true:
      let
        startTime = Moment.now()
        startForwardSlot = dag.head.slot
        startBackwardSlot = dag.backfill.slot

      await sleepAsync(5.seconds)

      let
        lastTime = Moment.now()
        lastForwardSlot = dag.head.slot
        lastBackwardSlot = dag.backfill.slot

      if overseer.fqueue.running() or overseer.fsqueue.running():
        forwardPerf.update(
          startForwardSlot, lastForwardSlot, startTime, lastTime,
          forwardTotal(), forwardRemains())
      if overseer.bqueue.running() or overseer.bsqueue.running():
        # Reverse order of slots here for a reason.
        backwardPerf.update(
          lastBackwardSlot, startBackwardSlot, startTime, lastTime,
          backwardTotal(), backwardRemains())

      let
        finalizedDistance =
          if overseer.finalizedDistance().isNone():
            "[n/a]"
          else:
            $overseer.finalizedDistance().get()
        backfillDistance = $overseer.backfillDistance()
        lastSeenSyncDagPath =
          if overseer.lastSeenHead.isNone():
            "[none]"
          else:
            overseer.sdag.getShortRootMap(overseer.lastSeenHead.get().root)

      overseer.statusMessages[0] =
        if overseer.finalizedDistance.isNone():
          "[initializing]"
        else:
          if overseer.finalizedDistance().get() > 0'u64:
            forwardPerf.formatString()
          else:
            "[finished]"
      overseer.statusMessages[1] =
        if overseer.backfillDistance() > 0'u64:
          backwardPerf.formatString()
        else:
          "[finished]"

      debug "Overseer debug statistics",
        wall_slot = overseer.beaconClock.currentSlot(),
        head = shortLog(dag.head),
        finalized = shortLog(dag.headState.finalized_checkpoint),
        last_seen_head = overseer.getLastSeenHeadLog(),
        last_seen_finalized = overseer.getLastSeenFinalizedHeadLog(),
        finalized_distance = finalizedDistance,
        backfill_distance = backfillDistance,
        blob_horizon = overseer.getBlobsHorizon().start_slot(),
        column_horizon = overseer.getColumnsHorizon().start_slot(),
        sdag_peer_entries_count = len(overseer.sdag.peers),
        sdag_roots_count = len(overseer.sdag.roots),
        sdag_slots_count = len(overseer.sdag.slots),
        forward_sync_status = overseer.statusMessages[0],
        backward_sync_status = overseer.statusMessages[1],
        forward_block_buffer = shortLog(overseer.fblockBuffer),
        backward_block_buffer = shortLog(overseer.bblockBuffer),
        forward_blocks_sync_queue = shortLog(overseer.fqueue),
        forward_sidecars_sync_queue = shortLog(overseer.fsqueue),
        backfill_blocks_sync_queue = shortLog(overseer.bqueue),
        backfill_sidecars_sync_queue = shortLog(overseer.bsqueue),
        root_block_buffer_length = len(overseer.rblockBuffer),
        blob_quarantine = shortLog(overseer.blobQuarantine[]),
        column_quarantine = shortLog(overseer.columnQuarantine[]),
        useful_peers = overseer.columnsState.usefulCount,
        useless_peers = overseer.columnsState.uselessCount,
        distribution = overseer.getColumnsDistribution(),
        columns_fill_rate = overseer.getColumnsFillRate(),
        last_seen_syncdag_path = lastSeenSyncDagPath

  except CancelledError:
    discard

proc gossipMonitoringLoop(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =
  try:
    let eventKey = overseer.blockGossipBus.register()
    debug "Gossip block monitoring established"
    while true:
      let
        events = await overseer.blockGossipBus.waitEvents(eventKey, 1)
        event = events[0]

        consensusFork = event.blck.kind
        (blockId, missingSidecars) =
          withBlck(event.blck):
            when consensusFork < ConsensusFork.Deneb:
              (
                BlockId(slot: forkyBlck.message.slot, root: forkyBlck.root),
                true
              )
            elif consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
              let res =
                if forkyBlck.root in overseer.blockQuarantine[].sidecarless:
                  if overseer.blobQuarantine[].hasSidecars(
                    forkyBlck.root, forkyBlck):
                    false
                  else:
                    true
                else:
                  false
              (BlockId(slot: forkyBlck.message.slot, root: forkyBlck.root), res)
            elif consensusFork == ConsensusFork.Fulu:
              let res =
                if forkyBlck.root in overseer.blockQuarantine[].sidecarless:
                  if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
                    false
                  else:
                    if overseer.columnQuarantine[].hasSidecars(forkyBlck.root):
                      false
                    else:
                      true
                else:
                  false
              (BlockId(slot: forkyBlck.message.slot, root: forkyBlck.root), res)
            else:
              raiseAssert "Unsupported fork"

      let peerLog =
        if isFullZero(event.src):
          # `libp2p` return an empty 'src' when this field is not filled.
          "[anonymous]"
        else:
          shortLog(event.src)

      debug "Got block from gossip event", block_root = blockId.root,
        block_slot = blockId.slot, peer = peerLog,
        fork = consensusFork, missing_sidecars = missingSidecars

      discard overseer.sdag.roots.mgetOrPut(
        blockId.root, SyncDagEntryRef.init(blockId))

      overseer.updatePeer(event.src, false, event.blck, missingSidecars)
  except AsyncEventQueueFullError:
    raiseAssert "Unlimited AsyncEventQueue should not raise exception"
  except CancelledError:
    discard

  debug "Gossip block monitoring stopped"

proc blockMonitoringLoop(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =
  try:
    let
      dag = overseer.consensusManager.dag
      eventKey = overseer.blocksQueueBus.register()

    debug "Block monitoring established"
    while true:
      let
        events = await overseer.blocksQueueBus.waitEvents(eventKey, 1)
        event = events[0]
        entry = overseer.sdag.roots.getOrDefault(event.block_root)

      logScope:
        block_root = shortLog(event.block_root)
        block_slot = event.slot
        last_seen_slot = overseer.getLastSeenHeadSlot()
        last_seen_finalized_epoch = overseer.getLastSeenFinalizedEpoch()

      debug "Got block event"

      if event.slot.epoch() >= overseer.getLastSeenFinalizedEpoch():
        # We clearing `MissingSidecars` flag from all the ancestors of the
        # block, because if event received, it means that block is validated and
        # stored in DAG, so the block and all its ancestors has all the sidecars
        # with it.
        if not(isNil(entry)):
          debug "Block processed, cleaning flags"
          cleanMissingSidecarsRoots(entry)

      let blck = dag.getBlockRef(event.block_root).valueOr:
        continue
      if isNil(blck.parent):
        continue
      let
        slot = blck.bid.slot
        blockRoot = blck.bid.root
        parentRoot = blck.parent.bid.root
        blockId = BlockId(slot: slot, root: blockRoot)

      if isNil(entry):
        debug "Got block event, which is not known",
          block_root = shortLog(blockRoot), block_slot = slot,
          parent_root = shortLog(parentRoot)

        discard
          overseer.sdag.roots.mgetOrPut(
            blockId.root, SyncDagEntryRef.init(blockId))

      overseer.updatePeer(
        overseer.localPeerId, false, slot, blockRoot, parentRoot, false)

  except AsyncEventQueueFullError:
    raiseAssert "Unlimited AsyncEventQueue should not raise exception"
  except CancelledError:
    discard

  debug "Block monitoring stopped"

proc finalMonitoringLoop(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =
  try:
    let
      dag = overseer.consensusManager.dag
      eventKey = overseer.blockFinalizationBus.register()
    debug "Finalization monitoring established"

    while true:
      let
        events = await overseer.blockFinalizationBus.waitEvents(eventKey, 1)
        event = events[0]
        checkpoint = dag.headState.finalized_checkpoint

      doAssert(dag.finalizedHead.slot > GENESIS_SLOT)
      let
        slot = dag.finalizedHead.slot
        blockRoot = dag.finalizedHead.blck.root
        parentRoot =
          block:
            let parentBid = dag.getBlockIdAtSlot(slot - 1)
            doAssert(parentBid.isSome(),
              "Parent block of recently finalized block should be available")
            parentBid.get().bid.root

      debug "Got finalized head event",
        block_root = shortLog(event.block_root),
        state_root = shortLog(event.state_root), epoch = event.epoch,
        checkpoint = shortLog(checkpoint), parent_root = shortLog(parentRoot),
        block_slot = slot,
        last_seen_epoch = overseer.getLastSeenFinalizedEpoch()

      if event.epoch > overseer.getLastSeenFinalizedEpoch():
        debug "Got finalized head event, which is not known",
          block_root = shortLog(event.block_root),
          state_root = shortLog(event.state_root), epoch = event.epoch,
          checkpoint = shortLog(checkpoint), parent_root = shortLog(parentRoot),
          block_slot = slot

        let fentry =
          overseer.sdag.roots.mgetOrPut(
            checkpoint.root, SyncDagEntryRef.init(checkpoint))

        # In case this entry already exists in DAG we should mark it.
        fentry.flags.incl(DagEntryFlag.Finalized)

        # sidecarsMissing == false in this case because this block was recently
        # selected as finalized head, so it is sure has sidecars already.
        overseer.updatePeer(
          overseer.localPeerId, false, slot, blockRoot, parentRoot, false)

      # Pruning SyncDag.
      overseer.sdag.prune(event.epoch)
      # Pruning BlocksRootBuffer.
      overseer.rblockBuffer.prune(event.epoch)

  except AsyncEventQueueFullError:
    raiseAssert "Unlimited AsyncEventQueue should not raise exception"
  except CancelledError:
    discard

  debug "Finalization monitoring stopped"

proc lateBlockMonitoringLoop*(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =
  let
    dag = overseer.consensusManager.dag
    quarantine = overseer.consensusManager.quarantine

  debug "Late block monitoring established"

  try:
    while true:
      let
        wallSlot = overseer.beaconClock.currentSlot()
        syncedSlot =
          if overseer.lastSeenHead.isNone():
            wallSlot
          else:
            overseer.lastSeenHead.get.slot

      if syncedSlot > dag.head.slot:
        var blockFound = false
        block checkOrphansLoop:
          for blck in quarantine[].pop(dag.head.root):
            debug "Processing late block from orphans",
              block_root = shortLog(blck.root)
            let res = await overseer.verifyBlock(blck, maybeFinalized = false)
            if res.isErr():
              debug "Late orphan block processor response", reason = res.error,
                block_root = shortLog(blck.root)
              if res.error == VerifierError.MissingSidecars:
                let entry = overseer.sdag.roots.getOrDefault(blck.root)
                if not(isNil(entry)):
                  debug "Late orphan block is already known, updating flags",
                    reason = res.error,
                    missing_sidecars =
                      (DagEntryFlag.MissingSidecars in entry.flags)
                  entry.flags.incl(DagEntryFlag.MissingSidecars)
                  continue
                let blockId = BlockId(slot: blck.slot, root: blck.root)
                debug "Late orphan block is not known, adding new entry",
                  bid = shortLog(blockId)
                discard
                  overseer.sdag.roots.mgetOrPut(
                    blockId.root, SyncDagEntryRef.init(blockId))
                overseer.updatePeer(
                  overseer.localPeerId, peerMustPresent = false,
                  blockId.slot, blockId.root,
                  blck.parent_root,
                  sidecarsMissed = true)
            else:
              debug "Late orphan block processor response", reason = "ok",
                block_root = shortLog(blck.root)
              # If block was added succesfully block penvelopeQuarantinerocessor will continue
              # process of adding blocks from quarantine.
              break checkOrphansLoop

        if blockFound:
          continue

        block checkSidecarlessLoop:
          for blck in quarantine[].popSidecarlessBlocks(dag.head.root):
            debug "Processing late block from sidecarless",
              block_root = shortLog(blck.root)
            let res = await overseer.verifyBlock(blck, maybeFinalized = false)
            if res.isErr():
              debug "Late sidecarless block processor response", reason = res.error,
                block_root = shortLog(blck.root)
              if res.error == VerifierError.MissingSidecars:
                let entry = overseer.sdag.roots.getOrDefault(blck.root)
                if not(isNil(entry)):
                  debug "Late sidecarless block is already known, updating flags",
                    reason = res.error,
                    missing_sidecars =
                      (DagEntryFlag.MissingSidecars in entry.flags)
                  entry.flags.incl(DagEntryFlag.MissingSidecars)
                  continue
                let blockId = BlockId(slot: blck.slot, root: blck.root)
                debug "Late sidecarlass block is not known, adding new entry",
                  bid = shortLog(blockId)
                discard
                  overseer.sdag.roots.mgetOrPut(
                    blockId.root, SyncDagEntryRef.init(blockId))
                overseer.updatePeer(
                  overseer.localPeerId, peerMustPresent = false,
                  blockId.slot, blockId.root,
                  blck.parent_root,
                  sidecarsMissed = true)
            else:
              debug "Late sidecarless block processor response", reason = "ok",
                block_root = shortLog(blck.root)
              # If block was added succesfully block penvelopeQuarantinerocessor will continue
              # process of adding blocks from quarantine.
              break checkSidecarlessLoop

      await sleepAsync(5.seconds)

  except CancelledError:
    discard

  debug "Late block monitoring stopped"

proc mainLoop*(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =
  let dag = overseer.consensusManager.dag

  logScope:
    wall_slot = overseer.beaconClock.currentSlot()
    head_slot = dag.head.slot
    finalized_checkpoint = shortLog(dag.headState.finalized_checkpoint)
    horizon = dag.horizon()
    fulu_fork_epoch = dag.cfg.FULU_FORK_EPOCH
    backfill_slot = dag.backfill.slot

  overseer.fblockBuffer =
    BlocksRangeBuffer.init(SyncQueueKind.Forward, 320)
  overseer.bblockBuffer =
    BlocksRangeBuffer.init(SyncQueueKind.Backward, 320)

  info "Sync overseer started"

  let
    gossipMonitoringLoopFut = overseer.gossipMonitoringLoop()
    blockMonitoringLoopFut = overseer.blockMonitoringLoop()
    finalMonitoringLoopFut = overseer.finalMonitoringLoop()
    timeMonitoringLoopFut = overseer.timeMonitoringLoop()
    maintenanceLoopFut = overseer.maintenanceLoop()
    lateBlockMonitoringLoopFut = overseer.lateBlockMonitoringLoop()

  while true:
    let peer =
      try:
        await overseer.pool.acquire()
      except CancelledError:
        # TODO (cheatfate): Release all peers?
        debug "Sync overseer interrupted"
        await cancelAndWait(
          gossipMonitoringLoopFut, blockMonitoringLoopFut,
          finalMonitoringLoopFut, timeMonitoringLoopFut,
          maintenanceLoopFut, lateBlockMonitoringLoopFut)
        return
    let entry = overseer.initPeer(peer)
    overseer.updatePeerStatus(peer)
    entry.peerLoopFut = overseer.startPeer(peer)

proc start*(overseer: SyncOverseerRef2) =
  overseer.loopFuture = overseer.mainLoop()

proc stop*(overseer: SyncOverseerRef2) {.async: (raises: []).} =
  doAssert(not(isNil(overseer.loopFuture)),
           "SyncOverseer was not started yet")
  if not(overseer.loopFuture.finished()):
    await cancelAndWait(overseer.loopFuture)

proc syncDistance*(overseer: SyncOverseerRef2): uint64 =
  let
    wallSlot = overseer.beaconClock.currentSlot()
    dag = overseer.consensusManager.dag
    syncedSlot =
      if overseer.lastSeenHead.isNone():
        wallSlot
      else:
        overseer.lastSeenHead.get.slot

  if syncedSlot < dag.head.slot:
    return 0'u64

  if (syncedSlot - dag.head.slot) < SyncDeviationSlotsCount:
    0'u64
  else:
    syncedSlot - dag.head.slot

proc syncInProgress*(overseer: SyncOverseerRef2): bool =
  overseer.syncDistance() > 0

proc syncStatusMessage*(
    overseer: SyncOverseerRef2,
): string =
  let
    dag = overseer.consensusManager.dag
    wallSlot = overseer.beaconClock.currentSlot()
    optimistic = not(dag.head.executionValid)
    optSuffix = if optimistic: " [opt]" else: ""
    lcSuffix =
      if overseer.consensusManager[].shouldSyncOptimistically(wallSlot):
        " - lc: " & $shortLog(overseer.consensusManager[].optimisticHead)
      else:
        ""
  if overseer.lastSeenCheckpoint.isNone():
    return "pending"

  let epoch = overseer.getLastSeenFinalizedEpoch()
  if dag.head.slot.epoch() < epoch:
    return overseer.statusMessages[0] & optSuffix & lcSuffix

  if dag.needsBackfill():
    return "backfill: " & overseer.statusMessages[1]

  "synced" & optSuffix & lcSuffix
