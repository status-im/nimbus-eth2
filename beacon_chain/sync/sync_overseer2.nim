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
  ../spec/[helpers, forks, network, column_map],
  ../networking/[peer_pool, eth2_network],
  ../consensus_object_pools/[consensus_manager, block_pools_types,
      blockchain_dag, block_quarantine, column_quarantine],
  ../gossip_processing/block_processor,
  ../[beacon_clock],
  ./[sync_types, sync_dag, sync_queue, sync_protocol, response_utils,
     block_buffer, validator_custody]

from ../consensus_object_pools/spec_cache import get_attesting_indices

export sync_types

logScope:
  topics = "sync"

const
  SyncDeviationSlotsCount = 1
    ## Number of slot allowed for deviation to continue backfilling job
  RootSyncEpochsActivationCount = 5'u64
    ## Number of epochs before latest known finalized epoch, when root sync
    ## starts working.
  ConcurrentRequestsCount* = 3
    ## Number of requests performed by single peer in one syncing step
  RepeatingFailuresCount* = 2
    ## Number of repeating errors before starting rewind process.
  StatusStalePeriod* = 5
    ## Number of slots before peer's status information could be stale.
  GenesisCheckpoint = Checkpoint(root: Eth2Digest(), epoch: GENESIS_EPOCH)

type
  BlocksSource {.pure.} = enum
    OrphansQuarantine,
    SidecarlessQuarantine

  ColumnsDistribution* = object
    counts*: string
    fillRate*: string
    inboundPeers*: int
    outboundPeers*: int
    supernodePeers*: int
    usefulPeers*: int
    uselessPeers*: int

  PeerColumnData* = object
    intersectMap: ColumnMap
    missingCount: string
    missingLog: string

func shortLog(optblkid: Opt[BlockId]): string =
  if optblkid.isNone():
    "<n/a>"
  else:
    shortLog(optblkid.get())

template cleanupRecordsList(a: untyped) =
  for mitem in a.mitems():
    mitem.sidecar = nil
  a.reset()

template rsrcUnavailable(err: Eth2NetworkingError): bool =
  (error.kind == ReceivedErrorResponse) and
    (err.responseCode == ResourceUnavailable)

func shortLog(digests: openArray[Eth2Digest]): string =
  "[" & digests.mapIt(shortLog(it)).join(",") & "]"

func shortLog(data: array[2, int]): string =
  $data[0] & "/" & $data[1]

func shortLog(bids: openArray[BlockId]): string =
  "[" & bids.mapIt(shortLog(it)).join(",") & "]"

func shortLog(cols: Opt[seq[ref fulu.DataColumnSidecar]]): string =
  if cols.isNone():
    "<missing columns>"
  else:
    $len(cols.get())

func slimLog(columns: openArray[ref fulu.DataColumnSidecar]): string =
  var slot = FAR_FUTURE_SLOT
  var res = "["
  for col in columns:
    if slot != col[].signed_block_header.message.slot:
      slot = col[].signed_block_header.message.slot
      if res[^1] != '[':
        res.add(",")
      res.add($slot & "/")
    else:
      res.add(',')
    res.add($col[].index)
  res.add(']')
  res

func slimLog(blck: ForkedSignedBeaconBlock): string =
  "(" & $blck.kind & ",slot:" & $blck.slot() &
    ",root:" & shortLog(blck.root()) &
    ",parent_root:" & shortLog(blck.parent_root()) & ")"

func slimLog(blocks: openArray[ref ForkedSignedBeaconBlock]): string =
  "[" & blocks.mapIt(slimLog(it[])).join(",") & "]"

func slimLog(blocks: openArray[ForkedSignedBeaconBlock]): string =
  "[" & blocks.mapIt(slimLog(it)).join(",") & "]"

proc getEaSlotLog(peer: Peer): string =
  let res = peer.getEarliestAvailableSlot().valueOr:
    return "<n/a>"
  $res

func eraBorderSlot(overseer: SyncOverseerRef2): Opt[Slot] =
  if overseer.eraBid.isSome():
    let
      eraSlot = overseer.eraBid.get().slot
      borderSlot =
        if eraSlot + 1 < eraSlot:
          FAR_FUTURE_SLOT
        else:
          eraSlot + 1
    return Opt.some(borderSlot)
  Opt.none(Slot)

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
      of ConsensusFork.Heze:
        raiseAssert "Unsupported fork!"
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
      of ConsensusFork.Heze:
        raiseAssert "Unsupported fork!"

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

proc getColumnsDistribution(overseer: SyncOverseerRef2): ColumnsDistribution =
  var
    res: seq[string]
    indices: array[NUMBER_OF_COLUMNS, int]
    useful: int
    useless: int
    supernodes: int
    inbound: int
    outbound: int

  let custodyMap = overseer.validatorCustody.getMap()

  for entry in overseer.sdag.peers.values():
    let
      peerMap = entry.peer.getColumnMapOrDefault()
      intersection = (custodyMap and peerMap)

    if entry.peer.direction == PeerType.Outgoing:
      inc(outbound)
    else:
      inc(inbound)

    if len(intersection) == 0:
      inc(useless)
    else:
      inc(useful)

    if len(peerMap) == NUMBER_OF_COLUMNS:
      inc(supernodes)

    for index in intersection.items():
      indices[int(index)] += 1

  var columns = 0
  for index in custodyMap:
    let count = indices[int(index)]
    if count != 0:
      inc(columns)
    res.add($count)
  let fillRate = (float(columns) * 100.0) / float(len(custodyMap))

  ColumnsDistribution(
    counts: "[" & res.join(",") & "]",
    fillRate: fillRate.formatBiggestFloat(ffDecimal, 2) & "%",
    inboundPeers: inbound,
    outboundPeers: outbound,
    supernodePeers: supernodes,
    usefulPeers: useful,
    uselessPeers: useless
  )

func getMissingColumnsLog(
    overseer: SyncOverseerRef2,
    items: openArray[SyncResponseItem]
): (string, string) =
  var
    res: seq[string]
    missingCount = 0.0
    totalCount = 0.0

  let blocksColumnsCount = float(len(overseer.validatorCustody.getMap()))

  for item in items:
    withBlck(item.signedBlock[]):
      when consensusFork == ConsensusFork.Fulu:
        if len(forkyBlck.message.body.blob_kzg_commitments) > 0:
          let map =
            overseer.columnQuarantine[].getMissingColumnsMap(forkyBlck.root)
          res.add(shortLog(forkyBlck.root) & ":" & $map)
          missingCount += float(len(map))
          totalCount += blocksColumnsCount
      elif consensusFork == ConsensusFork.Gloas:
        if len(forkyBlck.message.body.signed_execution_payload_bid.
               message.blob_kzg_commitments) > 0:
          let map =
            overseer.gloasColumnQuarantine[].getMissingColumnsMap(
              forkyBlck.root)
          res.add(shortLog(forkyBlck.root) & ":" & $map)
          missingCount += float(len(map))
          totalCount += blocksColumnsCount
      else:
        raiseAssert "Unsupported fork"

  let missing =
    if totalCount > 0.0:
      ((missingCount * 100.0) / totalCount).formatBiggestFloat(ffDecimal, 2) &
        "%"
    else:
      "0.00%"

  (missing, "[" & res.join(",") & "]")

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
  if fork < ConsensusFork.Fulu:
    raiseAssert "Incorrect fork"
  elif fork == ConsensusFork.Fulu:
    dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS * SLOTS_PER_EPOCH
  elif fork == ConsensusFork.Gloas:
    dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS * SLOTS_PER_EPOCH
  else:
    raiseAssert "Unsupported fork"

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

proc shouldGetColumns(overseer: SyncOverseerRef2, slot: Slot): bool =
  if overseer.config.historyMode == HistoryMode.Archive:
    let dag = overseer.consensusManager.dag
    if slot.epoch() >= dag.cfg.FULU_FORK_EPOCH:
      return true
    return false
  slot.epoch() >= overseer.getColumnsHorizon()

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

  if overseer.eraBid.isSome():
    max(max(dag.frontfill.get(BlockId()).slot, dag.horizon),
      overseer.eraBorderSlot().get())
  else:
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
      shortLog(default(ColumnMap))
    elif consensusFork == ConsensusFork.Fulu:
      let map =
        if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
          default(ColumnMap)
        else:
          overseer.columnQuarantine[].getMissingColumnsMap(forkyBlck.root)
      shortLog(map)
    elif consensusFork == ConsensusFork.Gloas:
      let map =
        if len(forkyBlck.message.body.signed_execution_payload_bid.
               message.blob_kzg_commitments) == 0:
          default(ColumnMap)
        else:
          overseer.gloasColumnQuarantine[].getMissingColumnsMap(forkyBlck.root)
      shortLog(map)
    else:
      raiseAssert "Unsupported fork"

proc getForwardSidecarStartSlot(overseer: SyncOverseerRef2): Slot =
  let
    dag = overseer.consensusManager.dag
    currentSlot = overseer.beaconClock.currentSlot()
    consensusFork = consensusForkAtEpoch(dag.cfg, currentSlot.epoch())

  if consensusFork < ConsensusFork.Fulu:
    return max(dag.finalizedHead.slot, dag.cfg.FULU_FORK_EPOCH.start_slot())

  let horizon = overseer.getSidecarsHorizon(consensusFork)
  if currentSlot < horizon:
    max(dag.finalizedHead.slot, GENESIS_SLOT)
  else:
    max(dag.finalizedHead.slot, currentSlot - horizon)

proc getBackfillSidecarFinalSlot(overseer: SyncOverseerRef2): Slot =
  let
    dag = overseer.consensusManager.dag
    backfillSlot = overseer.getLastAddedBackfillSlot()
    currentSlot = overseer.beaconClock.currentSlot()
    consensusFork = consensusForkAtEpoch(dag.cfg, currentSlot.epoch())

  if consensusFork < ConsensusFork.Fulu:
    return min(backfillSlot, (dag.cfg.FULU_FORK_EPOCH).start_slot)

  let
    horizon = overseer.getSidecarsHorizon(consensusFork)
    slot =
      if dag.finalizedHead.slot < horizon:
        min(backfillSlot, GENESIS_SLOT)
      else:
        min(backfillSlot, dag.finalizedHead.slot - horizon)
  # Because we do not have any markers for backfilled sidecars, there is no way
  # to track which sidecars are being stored in database, so if ERA files are
  # present we backfill only up to ERA files head.
  max(slot, overseer.getFrontfillSlot())

template isBackward(direction: SyncQueueKind): bool =
  direction == SyncQueueKind.Backward

template tbsqueue(
    overseer: SyncOverseerRef2,
    direction: SyncQueueKind
): untyped =
  case direction
  of SyncQueueKind.Forward:
    overseer.fqueue
  of SyncQueueKind.Backward:
    overseer.bqueue

template tssqueue(
    overseer: SyncOverseerRef2,
    direction: SyncQueueKind
): untyped =
  case direction
  of SyncQueueKind.Forward:
    overseer.fsqueue
  of SyncQueueKind.Backward:
    overseer.bsqueue

template tsbuffer(
    overseer: SyncOverseerRef2,
    direction: SyncQueueKind
): untyped =
  case direction
  of SyncQueueKind.Forward:
    overseer.fblockBuffer
  of SyncQueueKind.Backward:
    overseer.bblockBuffer

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

  proc peerMap(peer: Peer): ColumnMap =
    peer.getColumnMapOrDefault()

  func missingMap(blockRoot: Eth2Digest): ColumnMap =
    overseer.columnQuarantine[].getMissingColumnsMap(blockRoot)

  func localMap(): ColumnMap =
    overseer.validatorCustody.getMap()

  template declareBlockVerifier(
      procName: untyped,
      direction: static SyncQueueKind
  ): untyped =
    proc `procName`(
        item: SyncResponseItem,
        maybeFinalized: bool
    ): Future[Result[void, VerifierError]] {.
      async: (raises: [CancelledError]).} =
      withBlck(item.signedBlock[]):
        when consensusFork < ConsensusFork.Fulu:
          (await overseer.blockProcessor.addBlock(
            MsgSource.sync, forkyBlck, noSidecars,
            maybeFinalized = maybeFinalized))
        elif consensusFork == ConsensusFork.Fulu:
          if overseer.shouldGetColumns(forkyBlck.message.slot):
            # TODO (cheatfate): templates does not support `var` arguments.
            let res =
              when direction == SyncQueueKind.Forward:
                overseer.fblockBuffer.add(item)
              elif direction == SyncQueueKind.Backward:
                overseer.bblockBuffer.add(item)
            if res.isOk():
              debug "Block buffered",
                fork = consensusFork,
                block_root = forkyBlck.root,
                blck = shortLog(forkyBlck),
                verifier = "block"
            res
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
        elif consensusFork == ConsensusFork.Gloas:
          if overseer.shouldGetColumns(forkyBlck.message.slot):
            # TODO (cheatfate): templates does not support `var` arguments.
            let res =
              when direction == SyncQueueKind.Forward:
                overseer.fblockBuffer.add(item)
              elif direction == SyncQueueKind.Backward:
                overseer.bblockBuffer.add(item)
            if res.isOk():
              let payloadLog =
                if isNil(item.signedPayloadEnvelope):
                  "not available"
                else:
                  shortLog(
                    item.signedPayloadEnvelope[].message.beacon_block_root)
              debug "Block and payload buffered",
                fork = consensusFork,
                block_root = forkyBlck.root,
                blck = shortLog(forkyBlck),
                payload = payloadLog,
                verifier = "block"
            res
          else:
            let
              commitmentsLen =
                len(forkyBlck.message.body.signed_execution_payload_bid.
                  message.blob_kzg_commitments)
              bres =
                if commitmentsLen > 0:
                  (await overseer.blockProcessor.addBlock(MsgSource.sync,
                    forkyBlck, Opt.none(gloas.DataColumnSidecars),
                    maybeFinalized = maybeFinalized))
                else:
                  (await overseer.blockProcessor.addBlock(MsgSource.sync,
                    forkyBlck, Opt.some(default(gloas.DataColumnSidecars)),
                    maybeFinalized = maybeFinalized))

            if bres.isErr() or isNil(item.signedPayloadEnvelope):
              return bres

            if commitmentsLen > 0:
              (await overseer.blockProcessor.addPayload(
                forkyBlck, item.signedPayloadEnvelope[],
                Opt.none(gloas.DataColumnSidecars)))
            else:
              (await overseer.blockProcessor.addPayload(
                forkyBlck, item.signedPayloadEnvelope[],
                Opt.some(default(gloas.DataColumnSidecars))))
        else:
          raiseAssert "Unsupported fork"

  declareBlockVerifier(forwardBlockVerifier, SyncQueueKind.Forward)
  declareBlockVerifier(backwardBlockVerifier, SyncQueueKind.Backward)

  proc sidecarsVerifier(
      item: SyncResponseItem,
      maybeFinalized: bool
  ): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
    let dag = overseer.consensusManager.dag
    withBlck(item.signedBlock[]):
      when consensusFork < ConsensusFork.Fulu:
        await overseer.blockProcessor.addBlock(MsgSource.sync, forkyBlck,
          noSidecars, maybeFinalized = maybeFinalized)
      elif consensusFork == ConsensusFork.Fulu:
        let
          commitmentsLen = len(forkyBlck.message.body.blob_kzg_commitments)
          cres =
            if commitmentsLen > 0:
              if overseer.shouldGetColumns(forkyBlck.message.slot):
                let res =
                  overseer.columnQuarantine[].popSidecars(forkyBlck.root)
                if res.isNone():
                  debug "Block verification failed, because sidecars missing",
                    fork = consensusFork,
                    block_root = item.root,
                    blck = shortLog(forkyBlck),
                    missing_sidecars =
                      overseer.getMissingIndicesLog(item.signedBlock),
                    verifier = "sidecar"
                  return err(VerifierError.MissingSidecars)
                res
              else:
                Opt.none(seq[ref fulu.DataColumnSidecar])
            else:
              Opt.some(default(seq[ref fulu.DataColumnSidecar]))

        if cres.isSome() and overseer.eraBid.isSome() and
           dag.needsBackfill() and
           (forkyBlck.message.slot <= dag.backfill.slot) and
           (forkyBlck.message.slot < overseer.eraBid.get().slot):
          # In case if sidecars present, we are in backfill mode and block's
          # slot is already present in ERA files, we going to verify sidecars
          # only and store sidecars in database.
          # TODO (cheatfate)
          (await overseer.blockProcessor.addBlock(
            MsgSource.sync, forkyBlck, cres,
            maybeFinalized = maybeFinalized))
          #overseer.blockProcessor.addBackfillSidecars(
          #  forkyBlck, cres.get(), Opt.none(SignedExecutionPayloadEnvelope))
        else:
          (await overseer.blockProcessor.addBlock(
            MsgSource.sync, forkyBlck, cres,
            maybeFinalized = maybeFinalized))
      elif consensusFork == ConsensusFork.Gloas:
        let
          commitmentsLen =
            len(forkyBlck.message.body.signed_execution_payload_bid.
                message.blob_kzg_commitments)
          cres =
            if commitmentsLen > 0:
              if overseer.shouldGetColumns(forkyBlck.message.slot):
                let res =
                  overseer.gloasColumnQuarantine[].popSidecars(forkyBlck.root)
                if res.isNone():
                  debug "Block verification failed, because sidecars missing",
                    fork = consensusFork,
                    block_root = item.root,
                    blck = shortLog(forkyBlck),
                    missing_sidecars =
                      overseer.getMissingIndicesLog(item.signedBlock),
                    verifier = "sidecar"
                  return err(VerifierError.MissingSidecars)
                res
              else:
                Opt.none(seq[ref gloas.DataColumnSidecar])
            else:
              Opt.some(default(seq[ref gloas.DataColumnSidecar]))

        if cres.isSome() and overseer.eraBid.isSome() and
           dag.needsBackfill() and
           (forkyBlck.message.slot <= dag.backfill.slot) and
           (forkyBlck.message.slot < overseer.eraBid.get().slot):
          # In case if sidecars present, we are in backfill mode and block's
          # slot is already present in ERA files, we going to verify sidecars
          # only and store sidecars in database.
          # TODO (cheatfate)
          (await overseer.blockProcessor.addBlock(
            MsgSource.sync, forkyBlck, cres,
            maybeFinalized = maybeFinalized))
          #overseer.blockProcessor.addBackfillSidecars(
          #  forkyBlck, cres.get(), Opt.some(item.signedPayloadEnvelope[]))
        else:
          (await overseer.blockProcessor.addBlock(
            MsgSource.sync, forkyBlck, cres,
            maybeFinalized = maybeFinalized))
      else:
        raiseAssert "Unsupported fork"

  let
    backfillSlot = overseer.getLastAddedBackfillSlot()

  overseer.fqueue =
    SyncQueue.init(
      Peer, BlockCompleteness, SyncQueueKind.Forward,
      dag.finalizedHead.slot, checkpoint.epoch.start_slot(),
      uint64(overseer.blocksChunkSize),
      ConcurrentRequestsCount,
      RepeatingFailuresCount,
      getFirstSlotAtFinalizedEpoch,
      forwardBlockVerifier, forkAtEpoch, "fblock")
  overseer.fsqueue =
    SyncQueue.init(
      Peer, ColumnCompleteness, SyncQueueKind.Forward,
      overseer.getForwardSidecarStartSlot(),
      checkpoint.epoch.start_slot(),
      uint64(overseer.blocksChunkSize),
      ConcurrentRequestsCount,
      RepeatingFailuresCount,
      maxSidecars(1'u64), # 3 * SLOTS_PER_EPOCH distance
      getFirstSlotAtFinalizedEpoch,
      sidecarsVerifier, forkAtEpoch,
      localMap, peerMap, missingMap, "fsidecar")
  overseer.bqueue =
    if dag.needsBackfill():
      SyncQueue.init(
        Peer, BlockCompleteness, SyncQueueKind.Backward,
        backfillSlot, overseer.getFrontfillSlot(),
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
        Peer, ColumnCompleteness, SyncQueueKind.Backward,
        backfillSlot,
        overseer.getBackfillSidecarFinalSlot(),
        uint64(overseer.blocksChunkSize),
        ConcurrentRequestsCount,
        RepeatingFailuresCount,
        maxSidecars(1'u64), # 3 * SLOTS_PER_EPOCH distance
        getLastAddedBackfillSlot,
        sidecarsVerifier, forkAtEpoch,
        localMap, peerMap, missingMap, "bsidecar")
    else:
      nil

proc updateQueues(
    overseer: SyncOverseerRef2
) =
  let dag = overseer.consensusManager.dag

  block:
    logScope:
      forward_blocks_queue = shortLog(overseer.fqueue)
      forward_sidecars_queue = shortLog(overseer.fsqueue)
      forward_block_buffer = shortLog(overseer.fblockBuffer)

    let
      checkpoint = overseer.lastSeenCheckpoint.get()
      lastSlot = checkpoint.epoch.start_slot()
      old_forward_blocks_queue = shortLog(overseer.fqueue)
      old_forward_sidecars_queue = shortLog(overseer.fsqueue)

    if overseer.fqueue.running() or overseer.fsqueue.running():
      # Forward syncing is in progress.
      overseer.fqueue.updateLastSlot(lastSlot)
      overseer.fsqueue.updateLastSlot(lastSlot)

      debug "Forward queues has been expanded", last_slot = lastSlot,
        old_forward_blocks_queue = old_forward_blocks_queue,
        old_forward_sidecars_queue = old_forward_sidecars_queue
    else:
      # Forward sync is not active, but we keep it up-to date.
      let
        localHead = dag.finalizedHead.slot
        startBlocksSlot = localHead
        startSidecarsSlot = overseer.getForwardSidecarStartSlot()

      overseer.fqueue.reset(startBlocksSlot, lastSlot)
      overseer.fsqueue.reset(startSidecarsSlot, lastSlot)
      overseer.fblockBuffer.reset()

      debug "Forward queues has been reset",
        start_blocks_slot = startBlocksSlot,
        start_sidecars_slot = startSidecarsSlot,
        last_slot = lastSlot,
        old_forward_blocks_queue = old_forward_blocks_queue,
        old_forward_sidecars_queue = old_forward_sidecars_queue

  block:
    logScope:
      backward_blocks_queue = shortLog(overseer.bqueue)
      backward_sidecars_queue = shortLog(overseer.bsqueue)
      backward_block_buffer = shortLog(overseer.bblockBuffer)

    if not(isNil(overseer.bqueue)):
      if not(overseer.bqueue.running()) and not(overseer.bsqueue.running()):
        let
          startSlot = overseer.getLastAddedBackfillSlot()
          lastBlocksSlot = overseer.getFrontfillSlot()
          lastSidecarsSlot = overseer.getBackfillSidecarFinalSlot()
          old_backward_blocks_queue = shortLog(overseer.bqueue)
          old_backward_sidecars_queue = shortLog(overseer.bsqueue)

        overseer.bqueue.reset(startSlot, lastBlocksSlot)
        overseer.bsqueue.reset(startSlot, lastSidecarsSlot)
        overseer.bblockBuffer.reset()

        debug "Backfill queues has been reset",
          start_slot = startSlot,
          last_blocks_slot = lastBlocksSlot,
          last_sidecars_slot = lastSidecarsSlot,
          old_backward_blocks_queue = old_backward_blocks_queue,
          old_backward_sidecars_queue = old_backward_sidecars_queue

proc initPeer(
    overseer: SyncOverseerRef2,
    peer: Peer,
): PeerEntryRef[Peer] =
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
    entry.pendingRoots.add(root)

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
    sidecarsMissed: bool,
    envelopeMissed: bool,
    src: DagBlockSourceType
) =
  let peerEntry = overseer.sdag.peers.getOrDefault(peerId)
  if isNil(peerEntry) and peerMustPresent:
    return

  let
    missingParentRoot =
      overseer.sdag.updateRoot(block_root, block_slot, block_parent_root,
        sidecarsMissed, envelopeMissed, src)

  if missingParentRoot.isSome() and
     (missingParentRoot.get() != GenesisCheckpoint.root):
    if not(isNil(peerEntry)):
      peerEntry.pendingRoots.add(missingParentRoot.get())
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
    missingSidecars: bool,
    missingEnvelope: bool,
    src: DagBlockSourceType
) =
  let (slot, root, parentRoot) =
    withBlck(blck[]):
      (forkyBlck.message.slot, forkyBlck.root, forkyBlck.message.parent_root)
  overseer.updatePeer(
    peerId, peerMustPresent, slot, root, parentRoot, missingSidecars,
    missingEnvelope, src)

proc updatePeer(
    overseer: SyncOverseerRef2,
    peerId: PeerId,
    peerMustPresent: bool,
    blck: ForkedSignedBeaconBlock,
    missingSidecars: bool,
    missingEnvelope: bool,
    src: DagBlockSourceType
) =
  let (slot, root, parentRoot) =
    withBlck(blck):
      (forkyBlck.message.slot, forkyBlck.root, forkyBlck.message.parent_root)
  overseer.updatePeer(
    peerId, peerMustPresent, slot, root,  parentRoot, missingSidecars,
    missingEnvelope, src)

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

  if overseer.eraBid.isSome():
    if dag.backfill.parent_root == overseer.eraBid.get().root:
      return 0'u64
    let destSlot = overseer.eraBid.get().slot
    if dag.backfill.slot < destSlot:
      0'u64
    else:
      dag.backfill.slot - destSlot
  else:
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
    when consensusFork < ConsensusFork.Fulu:
      await overseer.blockProcessor.addBlock(
        MsgSource.sync, forkyBlck, noSidecars, maybeFinalized = maybeFinalized)
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
            overseer.columnQuarantine[].put(forkyBlck.root, cres.get(), false)
          res
        else:
          overseer.blockQuarantine[].addSidecarless(forkyBlck)
          Result[void, VerifierError].err(VerifierError.MissingSidecars)
      else:
        await overseer.blockProcessor.addBlock(
          MsgSource.sync, forkyBlck, Opt.none(fulu.DataColumnSidecars),
          maybeFinalized = maybeFinalized)
    elif consensusFork == ConsensusFork.Gloas:
      if overseer.shouldGetColumns(forkyBlck.message.slot):
        let cres =
          if len(forkyBlck.message.body.signed_execution_payload_bid.
                 message.blob_kzg_commitments) == 0:
            Opt.some(default(gloas.DataColumnSidecars))
          else:
            overseer.gloasColumnQuarantine[].popSidecars(forkyBlck.root)
        if cres.isSome():
          let res =
            await overseer.blockProcessor.addBlock(
              MsgSource.sync, forkyBlck, cres,
              maybeFinalized = maybeFinalized)
          if res.isErr() and (res.error == VerifierError.MissingParent):
            # In this case block will be stored in quarantine, so we need to
            # preserve columns in column quarantine.
            overseer.gloasColumnQuarantine[].put(
              forkyBlck.root, cres.get(), false)
          res
        else:
          overseer.blockQuarantine[].addSidecarless(forkyBlck)
          Result[void, VerifierError].err(VerifierError.MissingSidecars)
      else:
        await overseer.blockProcessor.addBlock(
          MsgSource.sync, forkyBlck, Opt.none(gloas.DataColumnSidecars),
          maybeFinalized = maybeFinalized)
    else:
      raiseAssert "Unsupported fork"

proc verifyBlock(
    overseer: SyncOverseerRef2,
    signedBlock: ForkedSignedBeaconBlock,
    maybeFinalized: bool
): Future[Result[void, VerifierError]] {.
  async: (raw: true, raises: [CancelledError]).} =
  verifyBlock(overseer, newClone signedBlock, maybeFinalized)

proc getStatusPeriod(
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
    return chronos.seconds(secondsPerSlot div 2)

  if localHead.slot == overseer.lastSeenHead.get.slot:
    # Node is optimistically synced
    return chronos.seconds(5 * secondsPerSlot)

  # Node is almost synced, but still behind peer's head.
  chronos.seconds(secondsPerSlot div 2)

proc getMetadataPeriod(
    overseer: SyncOverseerRef2,
    peer: Peer
): chronos.Duration =
  let
    dag = overseer.consensusManager.dag
    currentEpoch = overseer.beaconClock.currentSlot().epoch()

  if currentEpoch < dag.cfg.FULU_FORK_EPOCH:
    1.hours
  else:
    5.minutes

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
    items: openArray[SyncResponseItem],
    root: Eth2Digest,
    slot: Slot
): ref ForkedSignedBeaconBlock =
  for item in items:
    if (item.root == root) and (item.slot == slot):
      return item.signedBlock
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

    debug "Peer is entering sleeping state", sleep_time = timeToSlot
    # Without this check peer.getFuture() could return absolutely new Future,
    # which will never be finished, because peer is already disconnected.
    if peer.connectionState != ConnectionState.Connected:
      await sleepAsync(timeToSlot)
      return false
    else:
      let
        peerFut = peer.getFuture().join()
        timeFut = sleepAsync(timeToSlot)
      try:
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
    head = shortLog(dag.head)
    finalized = shortLog(dag.headState.finalized_checkpoint)

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

proc doPeerUpdateMetadata(
    overseer: SyncOverseerRef2,
    peer: Peer
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    peerMetadataAge = Moment.now() - peer.getMetadataLastTime()
    metadataPeriod = overseer.getMetadataPeriod(peer)

  if peerMetadataAge < metadataPeriod:
    # Peer's metadata information is still relevant
    return true

  logScope:
    peer = peer

  let
    map = peer.getColumnMapOrDefault()
    cgc = peer.lookupCgcFromPeer().valueOr:
      CUSTODY_REQUIREMENT

  debug "Requesting fresh metadata information from peer",
    metadata_age = peerMetadataAge,
    metadata_period = metadataPeriod,
    cgc = cgc,
    column_map = map

  if not(await peer.updateMetadata()):
    debug "Failed to obtain fresh metadata information from peer"
    peer.updateScore(PeerScoreNoStatus)
    return false

  peer.resetColumnMap()

  let
    newMap = peer.getColumnMapOrDefault()
    newCgc = peer.lookupCgcFromPeer().valueOr:
      CUSTODY_REQUIREMENT

  debug "Peer metadata information updated",
    old_cgc = cgc, old_map = map,
    new_cgc = newCgc, new_map = newMap

  true

proc doRootSyncStep(
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
        # Creating list of roots without duplicates.
        var
          dupcheck: HashSet[Eth2Digest]
          res: seq[Eth2Digest]
          counter = 0
        # Add global missing roots.
        for item in overseer.missingRoots:
          if counter < peerEntry.maxBlocksPerRequest:
            if item notin dupcheck:
              dupcheck.incl(item)
              res.add(item)
              inc(counter)
          else:
            break
        # Add peer missing roots
        while counter < peerEntry.maxBlocksPerRequest:
          if len(peerEntry.pendingRoots) > 0:
            let blockRoot = peerEntry.pendingRoots.pop()
            if blockRoot notin dupcheck:
              dupcheck.incl(blockRoot)
              res.add(blockRoot)
              inc(counter)
          else:
            break
        res

  template restoreRoots() =
    # We should return all the roots back to the pending queue.
    for index in countdown(len(roots) - 1, 0):
      peerEntry.pendingRoots.add(roots[index])

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
    peerEntry.maxBlocksPerRequest.decreaseBlocksCount()
  else:
    let consensusFork = blocks[0][].kind
    overseer.increaseBlocksCount(
      peerEntry.maxBlocksPerRequest, consensusFork)

  for signedBlock in blocks.asSeq():
    # maybeFinalized = false because we are working in range `>finalizedEpoch`.
    let
      res =
        try:
          await overseer.verifyBlock(signedBlock, maybeFinalized = false)
        except CancelledError as exc:
          restoreRoots()
          raise exc
      bid =
        BlockId(slot: signedBlock[].slot(), root: signedBlock[].root())

    logScope:
      fork = signedBlock[].kind
      bid = shortLog(bid)

    if res.isErr() and (res.error == VerifierError.Invalid):
      debug "Block verification NOT passed", reason = $res.error
      restoreRoots()
      peer.updateScore(PeerScoreBadResponse)
      return false
    let
      missingSidecars =
        if res.isErr() and (res.error == VerifierError.MissingSidecars):
          true
        else:
          false
      source =
        if res.isErr():
          case res.error
          of VerifierError.Invalid:
            peer.updateScore(PeerScoreBadResponse)
            debug "Block verification NOT passed", reason = $res.error
            restoreRoots()
            return false
          of VerifierError.MissingParent:
            peer.updateScore(PeerScoreGoodValues)
            debug "Block verification passed", reason = $res.error
            peerEntry.pendingRoots.add(signedBlock[].parent_root())
            DagBlockSourceType.Orphan
          of VerifierError.Duplicate:
            peer.updateScore(PeerScoreGoodValues)
            DagBlockSourceType.Dag
          of VerifierError.UnviableFork:
            peer.updateScore(PeerScoreUnviableFork)
            debug "Block is unviable",
              missing_sidecars = overseer.getMissingIndicesLog(signedBlock),
              reason = $res.error
            DagBlockSourceType.Unviable
          of VerifierError.MissingSidecars:
            peer.updateScore(PeerScoreGoodValues)
            debug "Block missing sidecars",
              missing_sidecars = overseer.getMissingIndicesLog(signedBlock),
              reason = $res.error
            DagBlockSourceType.Sidecarless
        else:
          peer.updateScore(PeerScoreGoodValues)
          debug "Block verification passed", reason = "ok"
          DagBlockSourceType.Dag

    # Update SyncDAG with block
    overseer.updatePeer(
      peer.getKey(), true, signedBlock, missingSidecars,
      missingEnvelope = true, source)
    removeRoot(signedBlock[].root)

  true

proc doRootSidecarsSyncStep(
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
    peerMap = peer.getColumnMapOrDefault()

  logScope:
    peer = peer
    peer_map = shortLog(peerMap)
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

  let
    columnBlocks =
      block:
        var
          res: seq[ForkedSignedBeaconBlock]
          checks: HashSet[Eth2Digest]
        # Global missing sidecars
        for root in overseer.missingSidecars:
          let
            signedBlock =
              overseer.blockQuarantine[].peekSidecarless(root).valueOr:
                debug "Block without sidecars disappeared from quarantine",
                  block_root = shortLog(root)
                overseer.missingRoots.incl(root)
                continue
            root = signedBlock.root()
          if root notin checks:
            checks.incl(root)
            res.add(signedBlock)
        # Peer's missing sidecars
        for bid in bids:
          let
            signedBlock =
              overseer.blockQuarantine[].peekSidecarless(bid.root).valueOr:
                debug "Block without sidecars disappeared from quarantine",
                  bid = shortLog(bid)
                overseer.missingRoots.incl(bid.root)
                continue
            root = signedBlock.root()
          if root notin checks:
            checks.incl(root)
            res.add(signedBlock)
        res
    (columnRoots, columnCount) =
      block:
        var
          resRoots: seq[DataColumnsByRootIdentifier]
          resCount = 0
        for signedBlock in columnBlocks:
          withBlck(signedBlock):
            when consensusFork == ConsensusFork.Fulu:
              let
                blockRoot = signedBlock.root
                request =
                  if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
                    DataColumnsByRootIdentifier()
                  else:
                    overseer.columnQuarantine[].fetchMissingSidecars(
                      blockRoot, peerMap)
              if len(request.indices) > 0:
                resRoots.add(request)
                resCount.inc(len(request.indices))
                if resCount >= peerEntry.maxSidecarsPerRequest:
                  break
            elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Electra:
              raiseAssert "Should not be happen!"
            else:
              raiseAssert "Unsupported fork"
        (resRoots, resCount)
  ##
  ## Data column sidecars processing.
  ##
  if len(columnRoots) == 0:
    debug "No pending data column sidecars available for peer"
    return true

  logScope:
    head = shortLog(dag.head)
    roots = shortLog(columnRoots)
    roots_count = columnCount
    data_type = "columns"

  debug "Requesting data column sidecars by root from peer"

  let
    columnSidecars =
      (await dataColumnSidecarsByRoot(peer,
        DataColumnsByRootIdentifierList columnRoots)).valueOr:
          debug "Data columns by root request failed", reason = error
          peer.updateScore(PeerScoreNoValues)
          return false

  debug "Received data column sidecars by root on request",
    columns_count = len(columnSidecars),
    columns = slimLog(columnSidecars.asSeq())

  var
    records =
      groupSidecars(
        columnRoots, columnCount, columnSidecars.asSeq()).valueOr:
          debug "Response to data columns by root is incorrect",
            columns = slimLog(columnSidecars.asSeq()),
            columns_count = len(columnSidecars), reason = error
          peer.updateScore(PeerScoreBadResponse)
          return false

  for record in records:
    overseer.columnQuarantine[].put(record.block_root, record.sidecar, false)

  if len(records) == 0:
    peer.updateScore(PeerScoreNoValues)
    debug "Empty response received for root request",
      columns = slimLog(columnSidecars.asSeq()),
      columns_count = len(columnSidecars)
    return true

  if len(records) < columnCount:
    # Number of received sidecars is less than number of requested.
    peerEntry.maxSidecarsPerRequest.decreaseSidecarsCount()
  else:
    overseer.increaseSidecarsCount(
      peerEntry.maxSidecarsPerRequest, ConsensusFork.Fulu)

  # Peer provided at least some sidecars, so we award it with reward.
  peer.updateScore(PeerScoreGoodValues)

  debug "Processing blocks and sidecars by root",
    blocks = slimLog(columnBlocks)

  for signedBlock in columnBlocks:
    debug "Processing single block and sidecars by root",
      blck = slimLog(signedBlock)
    withBlck(signedBlock):
      when consensusFork == ConsensusFork.Fulu:
        let entry = overseer.sdag.roots.getOrDefault(forkyBlck.root)
        if not(isNil(entry)):
          let res = await overseer.verifyBlock(signedBlock, false)
          if res.isErr():
            debug "Block and sidecars by root processor response",
              reason = res.error, blck = slimLog(signedBlock)
            case res.error
            of VerifierError.Invalid:
              peer.updateScore(PeerScoreBadValues)
              entry.flags.incl(
                {DagEntryFlag.Pending, DagEntryFlag.MissingSidecars})
              entry.parent = nil
              overseer.blockQuarantine[].remove(forkyBlck)
              overseer.columnQuarantine[].remove(forkyBlck.root)
              # We add this block's root into global missing root table, so
              # all other peers will try to re-download it again.
              overseer.missingRoots.incl(forkyBlck.root)
              return false
            of VerifierError.UnviableFork:
              # TODO (cheatfate): Think about this part!
              peer.updateScore(PeerScoreUnviableFork)
              entry.flags.excl(DagEntryFlag.MissingSidecars)
              entry.flags.incl(DagEntryFlag.Unviable)
              discard overseer.blockQuarantine[].addUnviable(
                forkyBlck.root, UnviableKind.UnviableFork)
              return false
            of VerifierError.MissingParent:
              peer.updateScore(PeerScoreGoodValues)
              entry.flags.excl(DagEntryFlag.MissingSidecars)
              peerEntry.pendingRoots.add(forkyBlck.message.parent_root)
              overseer.missingSidecars.excl(forkyBlck.root)
            of VerifierError.Duplicate:
              # This flags means that we have sidecars.
              peer.updateScore(PeerScoreGoodValues)
              entry.flags.excl(DagEntryFlag.MissingSidecars)
              overseer.missingSidecars.excl(forkyBlck.root)
            of VerifierError.MissingSidecars:
              # We still missing sidecars.
              discard
          else:
            peer.updateScore(PeerScoreGoodValues)
            debug "Block and sidecars by root processor response",
              reason = "ok", blck = slimLog(signedBlock)
            overseer.blockQuarantine[].remove(forkyBlck)
            entry.flags.excl(DagEntryFlag.MissingSidecars)
            overseer.missingSidecars.excl(forkyBlck.root)
      else:
        raiseAssert "Should not be happen!"
  true

proc doRangeSyncStep(
    overseer: SyncOverseerRef2,
    peer: Peer,
    direction: SyncQueueKind
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    peerEntry =
      block:
        let res = overseer.sdag.peers.getOrDefault(peer.getKey())
        if isNil(res):
          debug "Peer entry does not exist anymore", peer = peer
          return false
        res
    dag = overseer.consensusManager.dag
    checkpoint = peer.getFinalizedCheckpoint()
    request =
      overseer.tbsqueue(direction).pop(checkpoint.epoch.start_slot(), peer)

  logScope:
    peer = peer
    request = request
    head = shortLog(dag.head)
    block_buffer = shortLog(overseer.tsbuffer(direction))
    blocks_queue = shortLog(overseer.tbsqueue(direction))
    sidecars_queue = shortLog(overseer.tssqueue(direction))
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
    debug "Empty request received from blocks queue",
      reason = request.reason
    return true

  let consensusFork = dag.cfg.consensusForkAtEpoch(
    request.data.start_slot().epoch)

  if direction.isBackward() and peerEntry.minBackBlockSlot.isSome():
    if request.data.slot <= peerEntry.minBackBlockSlot.get():
      debug "Peer has already reported that this block range is unavailable",
        min_backfill_block_slot = peerEntry.minBackBlockSlot.get()
      overseer.tbsqueue(direction).push(request)
      return true

  debug "New blocks range request"

  try:
    let
      blocks =
        (await beaconBlocksByRange_v2(
          peer, request.data.slot, request.data.count, 1'u64)).valueOr:
            debug "Failed to get block range from peer", reason = error
            overseer.tbsqueue(direction).push(request)
            if direction.isBackward() and rsrcUnavailable(error):
              # `ResourceUnavailable` is not critical for backfilling.
              if peerEntry.minBackBlockSlot.isNone() or
                request.data.slot < peerEntry.minBackBlockSlot.get():
                peerEntry.minBackBlockSlot = Opt.some(request.data.slot)
              return true
            else:
              peer.updateScore(PeerScoreNoValues)
              return false
    var items = blocks.toSeq().toResponse()

    debug "Received blocks range on request",
      blocks_count = len(items),
      blocks_map = getShortMap(request, items)

    checkResponse(request.data, items).isOkOr:
      debug "Incorrect range of blocks received",
        blocks_count = len(items),
        blocks_map = getShortMap(request, items), reason = $error
      peer.updateScore(PeerScoreBadResponse)
      overseer.tbsqueue(direction).push(request)
      return false

    let combined =
      if consensusFork == ConsensusFork.Gloas:
        let
          payloads =
            (await executionPayloadEnvelopesByRange(
              peer, request.data.slot, request.data.count)).valueOr:
                debug "Failed to get payloads range from peer", reason = error
                overseer.tbsqueue(direction).push(request)
                if direction.isBackward() and rsrcUnavailable(error):
                  # `ResourceUnavailable` is not critical for backfilling.
                  return true
                else:
                  peer.updateScore(PeerScoreNoValues)
                  return false
        items.toResponse(payloads.asSeq())
      elif consensusFork < ConsensusFork.Gloas:
        0
      else:
        raiseAssert("Unsupported fork!")

    debug "Sending blocks range to processor",
      blocks_count = len(items),
      blocks_combined = combined,
      blocks_map = getShortMap(request, items)

    let resp =
      await overseer.tbsqueue(direction).push(
        request, items, maybeFinalized = true)

    debug "Blocks queue response",
      code = resp.code, count = resp.count, blck = shortLog(resp.blck),
      blocks_count = len(items),
      blocks_map = getShortMap(request, items),
      block_buffer = shortLog(overseer.tsbuffer(direction)),
      blocks_queue = shortLog(overseer.tbsqueue(direction)),
      sidecars_queue = shortLog(overseer.tbsqueue(direction))

    if resp.count > 0:
      peer.updateScore(PeerScoreGoodValues)
      true
    elif resp.count == 0:
      true
    else:
      let rewindPoint = overseer.tbsqueue(direction).inpSlot

      logScope:
        code = resp.code
        count = resp.count
        rewind_point = rewindPoint
        blck = shortLog(resp.blck)

      let before = shortLog(overseer.tsbuffer(direction))
      # TODO (cheatfate): templates does not support `var` arguments.
      case direction
      of SyncQueueKind.Forward:
        overseer.fblockBuffer.invalidate(rewindPoint)
      of SyncQueueKind.Backward:
        overseer.bblockBuffer.invalidate(rewindPoint)
      debug "Blocks queue rewind detected, invalidating block buffer",
        block_buffer_before = before
      false

  except CancelledError as exc:
    overseer.tbsqueue(direction).push(request)
    raise exc

proc peekBackfillRange(
    overseer: SyncOverseerRef2,
    srange: SyncRange
): seq[SyncResponseItem] =
  var
    res: seq[SyncResponseItem]
    bids = newSeq[BlockId](int(srange.count))

  let
    dag = overseer.consensusManager.dag
    endIndex = int(srange.count) - 1
    startIndex =
      dag.getBlockRange(srange.slot, bids.toOpenArray(0, endIndex))

  for i in startIndex .. endIndex:
    withConsensusFork(dag.cfg.consensusForkAtEpoch(bids[i].slot.epoch())):
      when consensusFork == ConsensusFork.Fulu:
        let blck = dag.getBlock(bids[i], consensusFork.SignedBeaconBlock)
        if blck.isNone():
          continue
        res.add(
          SyncResponseItem.init(
            newClone ForkedSignedBeaconBlock.init(blck.get()), nil))
      else:
        raiseAssert "Unsupported fork"
  res

proc peekRange(
    overseer: SyncOverseerRef2,
    direction: SyncQueueKind,
    srange: SyncRange
): seq[SyncResponseItem] =
  if direction == SyncQueueKind.Forward:
    return overseer.tsbuffer(direction).peekRange(srange)
  if overseer.eraBid.isNone():
    return overseer.tsbuffer(direction).peekRange(srange)
  let notEraSlot = overseer.eraBorderSlot().get()
  if srange > notEraSlot:
    return overseer.tsbuffer(direction).peekRange(srange)
  if srange < notEraSlot:
    return overseer.peekBackfillRange(srange)
  let
    (eraRange, netRange) = srange.split(notEraSlot)
    eraBlocks = overseer.peekBackfillRange(eraRange)
    netBlocks = overseer.tsbuffer(direction).peekRange(netRange)
  eraBlocks & netBlocks

proc checkPeerColumnSidecars(
    overseer: SyncOverseerRef2,
    peer: Peer,
    items: var seq[SyncResponseItem],
    request: SyncRequest[Peer],
    direction: SyncQueueKind
): Result[PeerColumnData, bool] =
  let
    dag = overseer.consensusManager.dag
    consensusFork = dag.cfg.consensusForkAtEpoch(
      request.data.start_slot().epoch)
    custodyMap = overseer.validatorCustody.getMap()
    peerMap = peer.getColumnMapOrDefault()
    checkpoint = peer.getFinalizedCheckpoint()
    intersectMap = custodyMap and peerMap

  logScope:
    peer = peer
    request = request
    head = shortLog(dag.head)
    block_buffer = shortLog(overseer.tsbuffer(direction))
    blocks_queue = shortLog(overseer.tbsqueue(direction))
    sidecars_queue = shortLog(overseer.tssqueue(direction))
    column_quarantine = shortLog(overseer.columnQuarantine[])
    peer_checkpoint = shortLog(checkpoint)
    peer_head = shortLog(peer.getHeadBlockId())
    peer_ea_slot = getEaSlotLog(peer)
    peer_agent = $peer.getRemoteAgent()
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    direction = direction

  # Here we perform check if remote peer has compatible columns or not.
  if len(intersectMap) == 0:
    debug "Peer does not have compatible columns",
      custody_map = shortLog(custodyMap),
      peer_map = shortLog(peerMap)
    if not(direction.isBackward()):
      # Backfilling is optional, so we not penalize peers which does not
      # have compatible sidecars.
      peer.updateScore(PeerScoreNoValues)
    return err(true)

  let (columnsNeeded, columnsHave) =
    if len(items) > 0:
      # Here we perform check if remote peer can provide columns that we
      # do not have already.
      var
        res1 = false
        res2 = false
      for item in items:
        let
          missingMap =
            withBlck(item.signedBlock[]):
              when consensusFork == ConsensusFork.Fulu:
                if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
                  ColumnMap()
                else:
                  overseer.columnQuarantine[].getMissingColumnsMap(
                    forkyBlck.root)
              elif consensusFork == ConsensusFork.Gloas:
                if len(forkyBlck.message.body.signed_execution_payload_bid.
                       message.blob_kzg_commitments) == 0:
                  ColumnMap()
                else:
                  overseer.gloasColumnQuarantine[].getMissingColumnsMap(
                    forkyBlck.root)
              else:
                raiseAssert "Unsupported fork!"

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
      # This is undefined case, because its impossible to obtain blocks.
      (false, false)

  let (missingCount, missingLog) = overseer.getMissingColumnsLog(items)

  debug "Peer columns compatibility",
     custody_map = shortLog(custodyMap),
     peer_map = shortLog(peerMap),
     intersect_map = shortLog(intersectMap),
     missing_count = missingCount,
     missing_log = missingLog

  if (len(items) > 0) and (columnsNeeded and not(columnsHave)):
    debug "Peer has compatible columns that we already have",
      custody_map = shortLog(custodyMap),
      peer_map = shortLog(peerMap),
      intersect_map = shortLog(intersectMap),
      missing_count = missingCount,
      missing_log = missingLog
    return err(true)

  ok(
    PeerColumnData(
      intersectMap: intersectMap,
      missingCount: missingCount,
      missingLog: missingLog))

proc doRangeSidecarsStep(
    overseer: SyncOverseerRef2,
    peer: Peer,
    direction: SyncQueueKind
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    peerEntry =
      block:
        let res = overseer.sdag.peers.getOrDefault(peer.getKey())
        if isNil(res):
          debug "Peer entry does not exist anymore", peer = peer
          return false
        res
    dag = overseer.consensusManager.dag
    checkpoint = peer.getFinalizedCheckpoint()
    peerMap = peer.getColumnMapOrDefault()

  block:
    let
      blockSlot = overseer.tbsqueue(direction).inpSlot
      blockRange =
        SyncRange.init(blockSlot, uint64(overseer.blocksChunkSize))

    logScope:
      peer = peer
      block_slot = blockSlot
      block_range = $blockRange
      head = shortLog(dag.head)
      block_buffer = shortLog(overseer.tsbuffer(direction))
      blocks_queue = shortLog(overseer.tbsqueue(direction))
      sidecars_queue = shortLog(overseer.tssqueue(direction))
      peer_map = shortLog(peerMap)
      peer_checkpoint = shortLog(checkpoint)
      peer_head = shortLog(peer.getHeadBlockId())
      direction = direction

    let notInRange =
      case direction
      of SyncQueueKind.Forward:
        blockRange.last_slot < overseer.tssqueue(direction).startSlot
      of SyncQueueKind.Backward:
        blockRange.last_slot < overseer.tssqueue(direction).finalSlot
    if notInRange:
      debug "Sidecars queue is not in range, skipping step"
      return true

  let request =
    overseer.tssqueue(direction).pop(checkpoint.epoch.start_slot(), peer)

  logScope:
    peer = peer
    request = request
    head = shortLog(dag.head)
    block_buffer = shortLog(overseer.tsbuffer(direction))
    blocks_queue = shortLog(overseer.tbsqueue(direction))
    sidecars_queue = shortLog(overseer.tssqueue(direction))
    column_quarantine = shortLog(overseer.columnQuarantine[])
    peer_map = shortLog(peerMap)
    peer_checkpoint = shortLog(checkpoint)
    peer_head = shortLog(peer.getHeadBlockId())
    peer_ea_slot = getEaSlotLog(peer)
    peer_agent = $peer.getRemoteAgent()
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    direction = direction

  if request.isEmpty():
    debug "Empty request received from sidecars queue",
      reason = request.reason
    return true

  if direction.isBackward() and peerEntry.minBackCarSlot.isSome():
    if request.data.slot <= peerEntry.minBackCarSlot.get():
      debug "Peer has already reported that this sidecar range is unavailable",
        min_backfill_sidecar_slot = peerEntry.minBackCarSlot.get()
      overseer.tssqueue(direction).push(request)
      return true

  debug "New sidecars range request"

  if not(overseer.checkDataAvailable(peer, direction, request.data)):
    debug "Request cannot be satisfied by the peer",
      peer_ea_slot = peer.getEarliestAvailableSlot().get()
    overseer.tssqueue(direction).push(request)
    if not(direction.isBackward()):
      # Backfilling is optional, so we not penalize peers which does not have
      # enough sidecars.
      peer.updateScore(PeerScoreNoValues)
    return true

  let consensusFork = dag.cfg.consensusForkAtEpoch(
    request.data.start_slot().epoch)

  let resp =
    case consensusFork
    of ConsensusFork.Phase0 .. ConsensusFork.Electra:
      SyncPushResponse()
    of ConsensusFork.Fulu:
      try:
        # blocks
        var items = overseer.peekRange(direction, request.data)

        let pdata =
          overseer.checkPeerColumnSidecars(
            peer, items, request, direction).valueOr:
            for mitem in items.mitems():
              mitem = default(SyncResponseItem)
            overseer.tssqueue(direction).push(request)
            return error

        # We only download sidecars if we miss it and peer have it.
        let
          data =
            (await dataColumnSidecarsByRange(
              peer, request.data.slot, request.data.count,
              List[ColumnIndex, NUMBER_OF_COLUMNS](
                pdata.intersectMap.items().toSeq()))).valueOr:
              debug "Failed to get data column sidecars range from peer",
                reason = $error
              overseer.tssqueue(direction).push(request)
              if direction.isBackward() and rsrcUnavailable(error):
                # `ResourceUnavailable` is not critical for backfilling.
                if peerEntry.minBackCarSlot.isNone() or
                  request.data.slot < peerEntry.minBackCarSlot.get():
                  peerEntry.minBackCarSlot = Opt.some(request.data.slot)
                return true
              else:
                peer.updateScore(PeerScoreNoValues)
                return false

        debug "Received data columns sidecars range from peer",
          columns_map = getShortMap(request, pdata.intersectMap, data.toSeq()),
          peer_map = shortLog(peerMap),
          intersection_map = shortLog(pdata.intersectMap),
          columns = slimLog(data.asSeq()),
          missing_log = pdata.missingLog

        var
          grouped =
            groupSidecars(request.data, pdata.intersectMap,
              data.asSeq()).valueOr:
              peer.updateScore(PeerScoreBadResponse)
              debug "Received invalid data column sidecars range",
                reason = $error, columns_count = len(data),
                columns = slimLog(data.asSeq())
              overseer.tssqueue(direction).push(request)
              return false

        defer:
          # Preemptively cleanup sidecar records list on exit
          cleanupRecordsList(grouped)

        # Early detection of empty response.
        let
          (sindex, bcount) =
            validateBlocks(items, grouped, pdata.intersectMap).valueOr:
              peer.updateScore(PeerScoreMissingValues)
              debug "Received non-complete data column sidecars range",
                reason = $error, columns_count = len(data),
                map = shortLog(pdata.intersectMap),
                blocks = shortLog(items),
                columns = shortLog(grouped)
              overseer.tssqueue(direction).push(request)
              return false

        if (sindex == 0) and (bcount > 0):
          # Empty response case, when we sure that blocks with sidecars
          # exists in the range.
          debug "Received empty columns range"
          peer.updateScore(PeerScoreMissingValues)
          overseer.tssqueue(direction).push(request)
          return false

        for record in grouped:
          overseer.columnQuarantine[].put(
            record.block_root, record.sidecar, false)

        peer.updateScore(PeerScoreGoodValues)

        if (len(items) == 0) and (len(grouped) > 0):
          # Case when we have no blocks, but a lot of blobs.
          debug "Received columns range which do not have corresponding " &
                "blocks range"
          overseer.tssqueue(direction).push(request)
          return false

        debug "Sending sidecars range to processor",
          peer_map = shortLog(peerMap),
          blocks_count = len(items),
          blocks_map = getShortMap(request, items)

        let res = await overseer.tssqueue(direction).push(
          request, items, maybeFinalized = true)

        debug "Sidecars queue response",
          code = res.code, count = res.count, blck = shortLog(res.blck),
          peer_map = shortLog(peerMap),
          blocks_count = len(items),
          blocks_map = getShortMap(request, items)

        if res.code == SyncProcessError.MissingSidecars:
          let
            blck = getBlock(items, res.blck.get().root, res.blck.get().slot)
          doAssert(not(isNil(blck)), "Should not be nil")
          debug "Sidecars range still missing items",
            blck = slimLog(blck[]),
            peer_map = shortLog(peerMap),
            missing_sidecars = overseer.getMissingIndicesLog(blck)

        # In case we not advance - we should cleanup blob/column quarantines on
        # fatal errors.
        if res.count <= 0:
          if res.code in [SyncProcessError.Invalid,
                          SyncProcessError.UnviableFork,
                          SyncProcessError.NoRelevant]:
            for item in items:
              overseer.columnQuarantine[].remove(item.signedBlock[].root)
        res

      except CancelledError as exc:
        overseer.tssqueue(direction).push(request)
        raise exc

    of ConsensusFork.Gloas:
      raiseAssert "Unsupported fork"

    of ConsensusFork.Heze:
      raiseAssert "Unsupported fork"

  if resp.count > 0:
    peer.updateScore(PeerScoreGoodValues)
    # TODO (cheatfate): templates does not support `var` arguments.
    case direction
    of SyncQueueKind.Forward:
      let advanceSlot =
        min(overseer.tbsqueue(direction).inpSlot,
          overseer.tssqueue(direction).inpSlot)
      debug "Pruning sync data structures",
        advance_slot = advanceSlot, prune_epoch = advanceSlot.epoch()
      overseer.fblockBuffer.advance(advanceSlot)
    of SyncQueueKind.Backward:
      let advanceSlot =
        max(overseer.tbsqueue(direction).inpSlot,
          overseer.tssqueue(direction).inpSlot)
      debug "Pruning sync data structures",
        advance_slot = advanceSlot, prune_epoch = advanceSlot.epoch()
      overseer.bblockBuffer.advance(advanceSlot)
    true
  elif resp.count == 0:
    true
  else:
    let rewindPoint = overseer.tssqueue(direction).inpSlot

    logScope:
      code = resp.code
      count = resp.count
      rewind_point = rewindPoint
      blck = shortLog(resp.blck)

    let before = shortLog(overseer.tsbuffer(direction))
    # TODO (cheatfate): templates does not support `var` arguments.
    case direction
    of SyncQueueKind.Forward:
      overseer.fblockBuffer.invalidate(rewindPoint)
    of SyncQueueKind.Backward:
      overseer.bblockBuffer.invalidate(rewindPoint)
    debug "Blocks queue rewind detected, invalidating block buffer",
      block_buffer_before = before

    case direction
    of SyncQueueKind.Forward:
      if rewindPoint < overseer.tbsqueue(direction).startSlot:
        debug "Sidecars queue is not in range yet, no syncing needed"
        return false

      if rewindPoint >= overseer.tbsqueue(direction).inpSlot:
        debug "Blocks queue is far behind, no syncing needed"
        return false

      debug "Sidecars queue got rewind, syncing blocks queue"
      await overseer.tbsqueue(direction).resetWait(rewindPoint)
      debug "Sync queues are in sync"

    of SyncQueueKind.Backward:
      if rewindPoint > overseer.tbsqueue(direction).startSlot:
        debug "Sidecars queue is not in range yet, no syncing needed"
        return false

      if rewindPoint <= overseer.tbsqueue(direction).inpSlot:
        debug "Blocks queue is far behind, no syncing needed"
        return false

      debug "Sidecars queue got rewind, syncing blocks queue"
      await overseer.tbsqueue(direction).resetWait(rewindPoint)
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
        break
      if not(overseer.pool.checkPeerScore(peer)):
        break

      if not(await overseer.doPeerUpdateMetadata(peer)):
        break
      if not(overseer.pool.checkPeerScore(peer)):
        break

      let peerEntry = overseer.sdag.peers.getOrDefault(peer.getKey())
      if isNil(peerEntry):
        break

      if overseer.finalizedDistance().get() < RootSyncEpochsActivationCount:
        debug "Peer current root state",
          local_head = dag.head.slot,
          head_distance = overseer.syncDistance(peer)

        if not(await overseer.doRootSyncStep(peer)):
          break
        if not(overseer.pool.checkPeerScore(peer)):
          break

        if not(await overseer.doRootSidecarsSyncStep(peer)):
          break
        if not(overseer.pool.checkPeerScore(peer)):
          break

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
            break
          if not(overseer.pool.checkPeerScore(peer)):
            break

        if not(await overseer.doRangeSidecarsStep(peer, SyncQueueKind.Forward)):
          break
        if not(overseer.pool.checkPeerScore(peer)):
          break

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
              break
            if not(overseer.pool.checkPeerScore(peer)):
              break

      if dag.needsBackfill() or overseer.bsqueue.running():
        if overseer.wallSyncDistance() <= SyncDeviationSlotsCount:
          if not(
            await overseer.doRangeSidecarsStep(peer, SyncQueueKind.Backward)):
            break
          if not(overseer.pool.checkPeerScore(peer)):
            break

      if not(await overseer.doPeerPause(peer, loopTime)):
        break

  except CancelledError:
    discard

  let reason =
    if not(overseer.pool.checkPeerScore(peer)):
      PeerScoreLow
    else:
      CommunicationTimeout

  var entry: PeerEntryRef[Peer]
  if overseer.sdag.peers.pop(peer.getKey(), entry):
    overseer.pool.release(peer)

  try:
    await peer.disconnect(reason)
  except CancelledError:
    discard

  debug "Peer loop stopped", reason = reason

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
    if overseer.eraBid.isSome():
      if dag.backfill.parent_root == overseer.eraBid.get().root:
        return 0'u64
      let destSlot = overseer.eraBorderSlot.get()
      if slot < destSlot:
        return 0'u64
      slot - destSlot
    else:
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
        dist = overseer.getColumnsDistribution()
        stabilityDistance =
          block:
            let res =
              overseer.validatorCustody.getStabilityDistance(
                overseer.beaconClock.currentSlot())
            if res.isNone():
              "not available"
            else:
              $res.get()
        eraBid =
          if overseer.eraBid.isSome():
            shortLog(overseer.eraBid.get())
          else:
            "not available"

      overseer.statusMessages[0] =
        if overseer.finalizedDistance.isNone():
          "[initializing]"
        else:
          # We use here `1` instead of `0` to avoid noise which happen when
          # other clients finalize earlier or before we do.
          if overseer.finalizedDistance().get() > 1'u64:
            forwardPerf.formatString()
          else:
            "[finished]"
      overseer.statusMessages[1] =
        if not(dag.needsBackfill()):
          "[finished]"
        else:
          if overseer.backfillDistance() > 0'u64:
            if overseer.bqueue.running():
              if overseer.wallSyncDistance() <= SyncDeviationSlotsCount:
                backwardPerf.formatString()
              else:
                "[paused]"
            else:
              "[waiting]"
          else:
            "[finished]"

      debug "Overseer debug statistics",
        wall_slot = overseer.beaconClock.currentSlot(),
        head = shortLog(dag.head),
        tail = shortLog(dag.tail),
        era_bid = eraBid,
        backfill_slot = dag.backfill.slot,
        backfill_parent_root = shortLog(dag.backfill.parent_root),
        finalized = shortLog(dag.headState.finalized_checkpoint),
        last_seen_head = overseer.getLastSeenHeadLog(),
        last_seen_finalized = overseer.getLastSeenFinalizedHeadLog(),
        finalized_distance = finalizedDistance,
        backfill_distance = backfillDistance,
        column_horizon = overseer.getColumnsHorizon().start_slot(),
        sdag_peer_entries_count = len(overseer.sdag.peers),
        sdag_roots_count = len(overseer.sdag.roots),
        sdag_slots_count = len(overseer.sdag.slots),
        forward_sync_status = overseer.statusMessages[0],
        backward_sync_status = overseer.statusMessages[1],
        forward_block_buffer = shortLog(overseer.fblockBuffer),
        backward_block_buffer = shortLog(overseer.bblockBuffer),
        forward_blocks_queue = shortLog(overseer.fqueue),
        forward_sidecars_queue = shortLog(overseer.fsqueue),
        backfill_blocks_queue = shortLog(overseer.bqueue),
        backfill_sidecars_queue = shortLog(overseer.bsqueue),
        sidecarless_quarantine = len(overseer.blockQuarantine.sidecarless),
        column_quarantine = shortLog(overseer.columnQuarantine[]),
        useful_peers = dist.usefulPeers,
        useless_peers = dist.uselessPeers,
        supernodes_peers = dist.supernodePeers,
        inbound_peers = dist.inboundPeers,
        outbound_peers = dist.outboundPeers,
        columns_count = len(overseer.validatorCustody.getMap()),
        counts = dist.counts,
        columns_fill_rate = dist.fillRate,
        custody_groups_count = overseer.validatorCustody.getGroupsCount(),
        custody_state = shortLog(overseer.validatorCustody.getCurrentState()),
        custody_stability = stabilityDistance,
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
            when consensusFork < ConsensusFork.Fulu:
              (
                BlockId(slot: forkyBlck.message.slot, root: forkyBlck.root),
                true
              )
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

      let src =
        if missingSidecars:
          DagBlockSourceType.Sidecarless
        else:
          DagBlockSourceType.Dag

      debug "Got block from gossip event", bid = shortLog(blockId),
        fork = consensusFork, missing_sidecars = missingSidecars, source = src

      discard overseer.sdag.roots.mgetOrPut(
        blockId.root, SyncDagEntryRef.init(blockId))

      overseer.updatePeer(
        event.src, false, event.blck, missingSidecars,
        missingEnvelope = false, src)
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
        overseer.localPeerId, false, slot, blockRoot, parentRoot, false, false,
        DagBlockSourceType.Dag)

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
          overseer.localPeerId, false, slot, blockRoot, parentRoot,
          false, false, DagBlockSourceType.Dag)

      # Pruning SyncDag.
      overseer.sdag.prune(event.epoch)

  except AsyncEventQueueFullError:
    raiseAssert "Unlimited AsyncEventQueue should not raise exception"
  except CancelledError:
    discard

  debug "Finalization monitoring stopped"

proc missingBlocksMonitoringLoop(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =

  debug "Block quarantine monitoring established"

  try:
    while true:
        await overseer.blockQuarantine[].missingEvent.wait()

        let missingRoots = overseer.blockQuarantine[].checkMissing(high(int))

        for record in missingRoots:
          let entry = overseer.sdag.roots.getOrDefault(record.root)
          if not(isNil(entry)):
            entry.flags.incl(DagEntryFlag.Pending)
          else:
            overseer.missingRoots.incl(record.root)
            debug "Missing block root inserted into queue",
               block_root = record.root

        overseer.blockQuarantine[].missingEvent.clear()

  except CancelledError:
    discard

  debug "Block quarantine monitoring stopped"

proc missingSidecarsMonitoringLoop(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =

  debug "Sidecarless quarantine monitoring established"

  try:
    let dag = overseer.consensusManager.dag
    while true:
      await overseer.blockQuarantine[].sidecarlessEvent.wait()

      let missingSidecars =
        block:
          var res: seq[Eth2Digest]
          for signedBlock in overseer.blockQuarantine[].peekSidecarless():
            withBlck(signedBlock):
              let
                slot = forkyBlck.message.slot
                root = forkyBlck.root
              if slot >= dag.head.slot:
                res.add(root)
          res

      for root in missingSidecars:
        let entry = overseer.sdag.roots.getOrDefault(root)
        if not(isNil(entry)):
          entry.flags.incl(DagEntryFlag.MissingSidecars)
        else:
          overseer.missingSidecars.incl(root)
          debug "Missing sidecars block root inserted into queue",
             block_root = shortLog(root)

      overseer.blockQuarantine[].sidecarlessEvent.clear()

  except CancelledError:
    discard

  debug "Sidecarless quarantine monitoring stopped"

iterator popBlocks(
    overseer: SyncOverseerRef2,
    src: BlocksSource,
    root: Eth2Digest
): ForkedSignedBeaconBlock =
  let
    quarantine = overseer.consensusManager.quarantine

  case src
  of BlocksSource.OrphansQuarantine:
    for blck in quarantine[].pop(root):
      yield blck
  of BlocksSource.SidecarlessQuarantine:
    for blck in quarantine[].popSidecarlessBlocks(root):
      yield blck

proc checkData(
    overseer: SyncOverseerRef2,
    head: BlockId,
    src: BlocksSource
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    dag = overseer.consensusManager.dag
    quarantine = overseer.blockQuarantine

  logScope:
    source = $src
    local_head = shortLog(head)

  var recovery: seq[ForkedSignedBeaconBlock]
  defer:
    case src
    of BlocksSource.OrphansQuarantine:
      for blck in recovery:
        withBlck(blck):
          discard quarantine[].addOrphan(dag.finalizedHead.slot, forkyBlck)
    of BlocksSource.SidecarlessQuarantine:
      for blck in recovery:
        withBlck(blck):
          when consensusFork >= ConsensusFork.Deneb:
            discard quarantine[].addSidecarless(
              dag.finalizedHead.slot, forkyBlck)
          else:
            raiseAssert "Incorrect block's fork"

  for blck in overseer.popBlocks(src, head.root):
    let blockId = BlockId(slot: blck.slot, root: blck.root)
    logScope:
      bid = shortLog(blockId)

    debug "Processing late block"
    let res = await overseer.verifyBlock(blck, maybeFinalized = false)
    if res.isErr():
      debug "Late block processor response", reason = res.error
      # In case of error we should recover block in data structure.
      recovery.add(blck)

      if res.error == VerifierError.MissingSidecars:
        let entry = overseer.sdag.roots.getOrDefault(blockId.root)
        if not(isNil(entry)):
          debug "Late block is already known, updating flags",
            reason = res.error,
            missing_sidecars = (DagEntryFlag.MissingSidecars in entry.flags)
          entry.flags.incl(DagEntryFlag.MissingSidecars)
          continue

        debug "Late block is not known, adding new entry"

        discard
          overseer.sdag.roots.mgetOrPut(
            blockId.root, SyncDagEntryRef.init(blockId))
        overseer.updatePeer(
          overseer.localPeerId,
          peerMustPresent = false,
          blockId.slot, blockId.root,
          blck.parent_root,
          sidecarsMissed = true,
          envelopeMissed = true,
          DagBlockSourceType.Dag)
    else:
      debug "Late block processor response", reason = "ok"
      # If block was added succesfully block processor will continue
      # process of adding blocks from quarantine.
      return true

  false

proc recoverBlocks(
    overseer: SyncOverseerRef2,
    head: BlockId,
) =

  logScope:
    source = "syncdag"
    local_head = shortLog(head)

  for entry in overseer.sdag.ancestors(head.root):
    if DagEntryFlag.Pending notin entry[].flags:
      debug "Recover late block", bid = shortLog(entry[].blockId)
      # Mark entry as missing block.
      entry[].flags.incl(DagEntryFlag.Pending)

proc lateBlockMonitoringLoop*(
    overseer: SyncOverseerRef2
): Future[void] {.async: (raises: []).} =
  let
    dag = overseer.consensusManager.dag

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
        head = dag.head.bid

      if wallSlot > dag.head.slot:
        debug "Check for late blocks", synced_slot = syncedSlot,
          head = shortLog(head), distance = syncedSlot - dag.head.slot

        if not(await overseer.checkData(
          head, BlocksSource.OrphansQuarantine)):
          debug "No ancestor orphan blocks found for current head"
          if not(await overseer.checkData(
            head, BlocksSource.SidecarlessQuarantine)):
            debug "No ancestor sidecarless blocks found for current head"
            # Recover missing blocks from the network.
            overseer.recoverBlocks(head)
        await sleepAsync(500.milliseconds)
      else:
        await sleepAsync(1.seconds)

  except CancelledError:
    discard

  debug "Late block monitoring stopped"

proc peerPoolFilter(peer: Peer): bool {.gcsafe, raises: [].} =
  # We use this callback because `nim-libp2p` does not disconnect immediately.
  if peer.connectionState in [Disconnecting, Disconnected]:
    false
  else:
    true

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
    lateBlockMonitoringLoopFut = overseer.lateBlockMonitoringLoop()
    missingBlocksMonitoringLoopFut = overseer.missingBlocksMonitoringLoop()
    missingSidecarsMonitoringLoopFut = overseer.missingSidecarsMonitoringLoop()

  while true:
    let peer =
      try:
        await overseer.pool.acquire({Incoming, Outgoing}, peerPoolFilter)
      except CancelledError:
        debug "Sync overseer interrupted"
        var pending: seq[Future[void].Raising([])]
        for entry in overseer.sdag.peers.values():
          pending.add(entry.peerLoopFut)
        await cancelAndWait(pending)
        await cancelAndWait(
          gossipMonitoringLoopFut, blockMonitoringLoopFut,
          finalMonitoringLoopFut, timeMonitoringLoopFut,
          lateBlockMonitoringLoopFut, missingBlocksMonitoringLoopFut,
          missingSidecarsMonitoringLoopFut)
        return
    var entry = overseer.initPeer(peer)
    overseer.updatePeerStatus(peer)
    entry.peerLoopFut = overseer.startPeer(peer)

proc initEraInformation(overseer: SyncOverseerRef2) =
  let
    dag = overseer.consensusManager.dag
    eraDir = overseer.config.eraDir()

  logScope:
    era_dir = eraDir

  var
    lastEra: Era
    bid: Opt[BlockId]
    eraFile = EraFile.latest(dag.cfg, eraDir).valueOr:
      debug "ERA files are not available", era_dir = eraDir
      return

  let latestEra = eraFile.era

  while true:
    bid = dag.era.getHeadBlockId(eraFile).valueOr:
      warn "Unable to obtain block information from era file",
        reason = error, era = eraFile.era, era_path = eraFile.path
      return
    if bid.isSome():
      break
    if eraFile.era == Era(0):
      break

    let era = eraFile.era - 1
    eraFile = EraFile.getEraFile(dag.cfg, eraDir, era).valueOr:
      debug "Some ERA files are not available", era = era
      return
    lastEra = era

  if bid.isSome():
    debug "Latest ERA head has been found",
      latest_block_id = shortLog(bid.get())
    overseer.eraBid = Opt.some(bid.get())
  else:
    warn "Unable to find latest ERA head",
      latest_era = latestEra, last_era = lastEra

proc start*(overseer: SyncOverseerRef2) =
  overseer.initEraInformation()
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
      if overseer.consensusManager[].shouldSyncViaLightClient(wallSlot):
        " - lc: " & $shortLog(overseer.consensusManager[].lightClientHead)
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

proc debugRootSyncJsonDump*(overseer: SyncOverseerRef2): string =
  let
    localHead = overseer.consensusManager.dag.head.bid
    head = overseer.lastSeenHead.valueOr:
      return "{\"roots\":{}}"
    entry = overseer.sdag.roots.getOrDefault(head.root)

  func currentHead(entry: SyncDagEntryRef): bool =
    (entry.blockId.slot == localHead.slot) and
      (entry.blockId.root == localHead.root)

  func getSource(entry: SyncDagEntryRef): string =
    var res: seq[string]
    if DagBlockSourceType.Dag in entry.source:
      res.add("dag")
    if DagBlockSourceType.Orphan in entry.source:
      res.add("orphan")
    if DagBlockSourceType.Sidecarless in entry.source:
      res.add("sidecarless")
    if DagBlockSourceType.Unviable in entry.source:
      res.add("unviable")
    "[" & res.join(",") & "]"

  func getLocation(entry: SyncDagEntryRef): string =
    var res: seq[string]
    if currentHead(entry):
      return "[\"dag\"]"

    let root = entry.blockId.root

    if overseer.blockQuarantine[].checkOrphan(root):
      res.add("\"orphan\"")
    if root in overseer.blockQuarantine[].sidecarless:
      res.add("\"sidecarless\"")
    "[" & res.join(",") & "]"

  func getMissingMap(entry: SyncDagEntryRef): string =
    if currentHead(entry):
      "[]"
    else:
      $(overseer.columnQuarantine[].getMissingColumnsMap(entry.blockId.root))

  func getFlags(entry: SyncDagEntryRef): string =
    var res: seq[string]
    if DagEntryFlag.Local in entry.flags:
      res.add("\"local\"")
    if DagEntryFlag.Unviable in entry.flags:
      res.add("\"unviable\"")
    if DagEntryFlag.Finalized in entry.flags:
      res.add("\"finalized\"")
    if DagEntryFlag.Pending in entry.flags:
      res.add("\"pending\"")
    if DagEntryFlag.MissingSidecars in entry.flags:
      res.add("\"missing_sidecars\"")
    if currentHead(entry):
      res.add("\"current_head\"")
    "[" & res.join(",") & "]"

  func getBid(entry: SyncDagEntryRef): string =
    shortLog(entry.blockId)

  func getParent(entry: SyncDagEntryRef): string =
    if isNil(entry.parent):
      "unavailable"
    else:
      getBid(entry.parent)

  func getItem(entry: SyncDagEntryRef): string =
    "\"" & getBid(entry) & "\":{" &
      "\"flags\":" & getFlags(entry) & "," &
      "\"source\":" & getSource(entry) & "," &
      "\"missing_map\":" & getMissingMap(entry) & "," &
      "\"locations\":" & getLocation(entry) & "," &
      "\"parent_root\":\"" & getParent(entry) & "\"" &
    "}"

  var items: seq[string]

  if isNil(entry):
    return "{\"roots\":{}}"

  items.add(getItem(entry))
  for centry in entry.parents():
    if isNil(centry):
      break
    if centry.blockId.slot < localHead.slot:
      # No need to move further than the current head.
      break
    items.add(getItem(centry))

  "{\"roots\":{" & items.join(",") & "}}"
