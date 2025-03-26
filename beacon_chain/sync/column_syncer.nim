# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[strutils, sequtils, algorithm]
import stew/base10, chronos, chronicles, results
import
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/rest_types,
  ../spec/[helpers, forks, network, peerdas_helpers],
  ../networking/[peer_pool, peer_scores, eth2_network],
  ../gossip_processing/block_processor,
  ../beacon_clock,
  "."/[sync_protocol, sync_queue, column_syncer_assist]

export phase0, altair, merge, chronos, chronicles, results,
       helpers, peer_scores, sync_queue, forks, sync_protocol

logScope:
  topics = "columnsync"

const
  ColumnSyncWorkerCount* = 15
    ## Number of workers to spawn for column syncing

  StatusUpdateInterval* = chronos.minutes(1)

  StatusExpirationTime* = chronos.minutes(2)

type
  ColumnSyncerStatus* {.pure.} = enum
    Sleeping, WaitingPeer, UpdatingStatus, Requesting, Downloading,
    Queueing, Processing

  ColumnAndBlockResponse* = object
    blk*: ref ForkedSignedBeaconBlock
    columns*: Opt[DataColumnSidecars]

  ColumnSyncerFlag* {.pure.} = enum
    Greedy, Impartial

  ColumnSyncerMode* {.pure.} = enum
    NoMonitor, NoGenesisSync

  ColumnSyncer*[A, B] = object
    future: Future[void].Raising([CancelledError])
    status: ColumnSyncerStatus

  ColumnManager*[A, B] = ref object
    pool: PeerPool[A, B]
    cfg*: RuntimeConfig
    amIsupernode*: bool
    custody_columns_set*: HashSet[ColumnIndex]
    custody_columns_list*: List[ColumnIndex, NUMBER_OF_COLUMNS]
    column_syncer_table*: OrderedTable[Slot, ColumnAndBlockResponse]
    FULU_FORK_EPOCH: Epoch
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: uint64
    responseTimeout: chronos.Duration
    maxHeadAge: uint64
    assist*: ColumnSyncerAssist[A]
    getLocalHeadSlot: GetSlotCallback
    getLocalWallSlot: GetSlotCallback
    getSafeSlot: GetSlotCallback
    getFirstSlot: GetSlotCallback
    getLastSlot: GetSlotCallback
    progressPivot: Slot
    workers: array[ColumnSyncWorkerCount, ColumnSyncer[A, B]]
    notInSyncEvent: AsyncEvent
    shutdownEvent: AsyncEvent
    rangeAge: uint64
    chunkSize: uint64
    columnSyncFut: Future[void].Raising([CancelledError])
    peerdasBlockVerifier: PeerdasBlockVerifier
    inProgress*: bool
    insSyncSpeed*: float
    avgSyncSpeed*: float
    syncStatus*: string
    direction: ColumnSyncerDirection
    flags: set[ColumnSyncerFlag]
    modes: set[ColumnSyncerMode]

  ColumnSyncTimestamp* = object
    timestamp*: chronos.Moment
    slots*: uint64

  BeaconBlocksRes =
    NetRes[List[ref ForkedSignedBeaconBlock, Limit MAX_REQUEST_BLOCKS]]

  DataColumnSidecarsRes =
    NetRes[List[ref DataColumnSidecar, Limit(NUMBER_OF_COLUMNS)]]

proc now*(cst: typedesc[ColumnSyncTimestamp],
          slots: uint64):
          ColumnSyncTimestamp {.inline.} =
  ColumnSyncTimestamp(timestamp: now(chronos.Moment), slots: slots)

proc speed*(start, finish: ColumnSyncTimestamp): float {.inline.} =
  ## Returns the number of slots per second
  ## it is syncing columns with
  if finish.slots <= start.slots or finish.timestamp <= start.timestamp:
    0.0
  else:
    let
      slots = float(finish.slots - start.slots)
      dur = toFloatSeconds(finish.timestamp - start.timestamp)
    slots / dur

proc initColumnSyncerAssist[A, B](man: ColumnManager[A, B]) =
  case man.direction
  of ColumnSyncerDirection.Forward:
    man.assist = ColumnSyncerAssist.init(A, man.direction, man.getFirstSlot(),
                                         man.getLastSlot(), man.chunkSize,
                                         man.getSafeSlot, man.peerdasBlockVerifier, 1)
  of ColumnSyncerDirection.Backward:
    let
      firstSlot = man.getFirstSlot()
      lastSlot = man.getLastSlot()
      startSlot = if firstSlot == lastSlot:
                    # This case should never happen in real life because
                    # there is present check `needsBackfill()`.
                    firstSlot
                  else:
                    firstSlot - 1'u64
    man.assist = ColumnSyncerAssist.init(A, man.direction, startSlot, lastSlot,
                                         man.chunkSize, man.getSafeSlot,
                                         man.peerdasBlockVerifier, 1)

proc newColumnManager*[A, B](
    pool: PeerPool[A, B],
    cfg: RuntimeConfig,
    amIsupernode: bool,
    custody_columns_set: HashSet[ColumnIndex],
    custody_columns_list: List[ColumnIndex, NUMBER_OF_COLUMNS],
    fuluEpoch: Epoch,
    minEpochsForBlobSidecarsRequests: uint64,
    direction: ColumnSyncerDirection,
    getLocalHeadSlotCb: GetSlotCallback,
    getLocalWallSlotCb: GetSlotCallback,
    getFinalizedSlotCb: GetSlotCallback,
    getBackfillSlotCb: GetSlotCallback,
    getFrontfillSlotCb: GetSlotCallback,
    progressPivot: Slot,
    peerdasBlockVerifier: PeerdasBlockVerifier,
    shutdownEvent: AsyncEvent,
    maxHeadAge = uint64(SLOTS_PER_EPOCH * 1),
    chunkSize = uint64(SLOTS_PER_EPOCH),
    flags: set[ColumnSyncerFlag] = {},
    modes: set[ColumnSyncerMode] = {}
): ColumnManager[A, B] =

  let (getFirstSlot, getLastSlot, getSafeSlot) = case direction
  of ColumnSyncerDirection.Forward:
    (getLocalHeadSlotCb, getLocalWallSlotCb, getFinalizedSlotCb)
  of ColumnSyncerDirection.Backward:
    (getBackfillSlotCb, getFrontfillSlotCb, getBackfillSlotCb)

  var res = ColumnManager[A, B](
    pool: pool,
    cfg: cfg,
    amIsupernode: amIsupernode,
    custody_columns_set: custody_columns_set,
    custody_columns_list: custody_columns_list,
    column_syncer_table: initOrderedTable[Slot, ColumnAndBlockResponse](),
    FULU_FORK_EPOCH: fuluEpoch,
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: minEpochsForBlobSidecarsRequests,
    getLocalHeadSlot: getLocalHeadSlotCb,
    getLocalWallSlot: getLocalWallSlotCb,
    getSafeSlot: getSafeSlot,
    getFirstSlot: getFirstSlot,
    getLastSlot: getLastSlot,
    progressPivot: progressPivot,
    shutdownEvent: shutdownEvent,
    maxHeadAge: maxHeadAge,
    chunkSize: chunkSize,
    peerdasBlockVerifier: peerdasBlockVerifier,
    notInSyncEvent: newAsyncEvent(),
    direction: direction,
    flags: flags,
    modes: modes
  )
  res.initColumnSyncerAssist()
  res

proc fetchBlocksForColumnNavigation[A, B](man: ColumnManager[A, B], peer: A,
                                            req: ColumnSyncRequest[A]): Future[BeaconBlocksRes]
                                            {.async: (raises: [CancelledError], raw: true).} =
  mixin getScore, `==`

  logScope:
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    direction = man.direction

  doAssert(not(req.isEmpty()), "Request must not be empty!")
  debug "Requesting blocks from peer", request = req

  beaconBlocksByRange_v2(peer, req.slot, req.count, 1'u64)

proc shouldGetDataColumns[A, B](
    man: ColumnManager[A, B],
    s: Slot): bool =
  let
    wallEpoch = man.getLocalWallSlot().epoch
    epoch = s.epoch()
  (epoch >= man.FULU_FORK_EPOCH) and
  (wallEpoch < man.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS or
   epoch >= wallEpoch - man.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS)

proc shouldGetDataColumns[A, B](
    man: ColumnManager[A, B],
    r: ColumnSyncRequest[A]): bool =
  man.shouldGetDataColumns(r.slot) or man.shouldGetDataColumns(r.slot + (r.count - 1))

proc checkDataColumns(data_columns: seq[DataColumnSidecars]):
                      Result[void, string] =
  for data_column_sidecars in data_columns:
    for data_column_sidecar in data_column_sidecars:
      ? data_column_sidecar[].verify_data_column_sidecar_inclusion_proof()
      let sync_check_dc =
        data_column_sidecar[].verify_data_column_sidecar_kzg_proofs()
      if sync_check_dc.isErr:
        return err("Invalid data column received while column syncing")

proc intersectionColumns[A, B](
    man: ColumnManager[A, B],
    peer: A): List[ColumnIndex, NUMBER_OF_COLUMNS] =
  let remoteNodeId =
    fetchNodeIdFromPeerId(peer)
  intersection(man.custody_columns_set,
               resolve_columns_from_custody_groups(remoteNodeId, max(SAMPLES_PER_SLOT.uint64,
                                                   peer.lookupCgcFromPeer()).toHashSet()))

proc refreshColumnScoring[A, B](
    man: ColumnManager[A, B]) =

  for peer in availablePeers(man.pool):

    if peer.lookupCgcFromPeer() >=
      (NUMBER_OF_CUSTODY_GROUPS.uint64 div 2):
        ## This is a supernode we will positively
        ## score the peer now to prevent disconnection
        peer.updateScore(PeerScoreSupernode)

    else:
      let
        remoteNodeId = fetchNodeIdFromPeerId(peer)
        remoteColumns =
          remoteNodeId.resolve_column_sets_from_custody_groups(
            max(SAMPLES_PER_SLOT.uint64,
            peer.lookupCgcFromPeer()))
        intersecting_columns =
          intersection(man.custody_columns_set,
                       remoteColumns)

      if intersecting_columns.len > 0:
        ## This peer has custody columns that
        ## are a subset or superset of what we locally
        ## custody hence we will positively score
        ## the peer to prevent disconnection
        peer.updateScore(PeerScoreIntersectingColumns)

proc getDataColumnSidecars[A, B](man: ColumnManager[A, B],
                                 peer: A,
                                 r: ColumnSyncRequest[A],
                                 req_cols: List[ColumnIndex, NUMBER_OF_COLUMNS]):
                                 Future[DataColumnSidecarsRes] =
  mixin getScore, `==`

  logScope:
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()

  doAssert(not(req.isEmpty()), "Request must not be empty")
  debug "Requesting data column sidecars from peer", request = req
  dataColumnSidecarsByRange(peer, r.slot, r.count, req_cols)

proc filterRelevantPeers[A, B](man: ColumnManager[A, B],
                               peers: seq[A],
                               w_index: int):
                               seq[A] =
  ## This iterates over the available peers
  ## and returns a refreshed peer list based on
  ## whichever's peer status is recent and relevant
  for peer in peers:
    var
      headSlot = man.getLocalHeadSlot()
      wallSlot = man.getLocalWallSlot()
      peerSlot = peer.getHeadSlot()
      refreshed_peer_set: seq[A]

    debug "Peer's syncing status", wall_clock_slot = wallSlot,
          remote_head_slot = peerSlot, local_head_slot = headSlot

    let
      peerStatusAge = Moment.now() - peer.getStatusLastTime()
      needsUpdate =
        # Latest update we got is old
        peerStatusAge >= StatusExpirationTime or
        man.getFirstSlot() >= peerSlot

    if needsUpdate:
      man.workers[w_index].status = ColumnSyncerStatus.UpdatingStatus

      # Avoiding overflow of requests, but make them more frequent in case the
      # peer is `close` to the slot range of our interest
      if peerStatusAge < StatusExpirationTime div 2:
        await sleepAsync(StatusExpirationTime div 2 - peerStatusAge)

      trace "Updating peer's status information", wall_clock_slot = wallSlot,
            remote_head_slot = peerSlot, local_head_slot = headSlot

      if not(await peer.updateStatus()):
        peer.updateScore(PeerScoreNoStatus)
        debug "Failed to get remote peer's status, not including in refreshed list",
              peer_head_slot = peerSlot

      let newPeerSlot = peer.getHeadSlot()
      if peerSlot >= newPeerSlot:
        peer.updateScore(PeerScoreStaleStatus)
        debug "Peer's status information is stale",
               wall_clock_slot = wallSlot, remote_old_head_slot = peerSlot,
               local_head_slot = headSlot, remote_new_head_slot = newPeerSlot

      else:
        debug "Peer's status information updated", wall_clock_slot = wallSlot,
              remote_head_slot = peerSlot, local_head_slot = headSlot,
              remote_new_head_slot = newPeerSlot
        peer.updateScore(PeerScoreGoodStatus)
        peerSlot = newPeerSlot
        refreshed_peer_set.add(set)

func groupAndFillColumnTable*[A, B](
    man: ColumnManager[A, B],
    blocks: seq[ref ForkedSignedBeaconBlock],
    columns: seq[ref DataColumnSidecar]
): Result[void, string] =
  var grouped = newSeqOfCap[DataColumnSidecars](blocks.len)
  var column_cursor = 0
  for block_idx, blck in blocks:
    withBlck(blck[]):
      when consensusFork >= ConsensusFork.Fulu:
        template kzgs: untyped = forkyBlck.message.body.blob_kzg_commitments
        if kzgs.len == 0:
          # It means there were no columns published against this block
          # So we will make a table entry for BlockAndColumnResponse
          # where columns will be None
          man.column_syncer_table[forkyBlck.message.slot] =
            ColumnAndBlockResponse(
              blk: forkyBlck,
              columns: Opt.none(DataColumnSidecars))
          continue

        let header = forkyBlck.toSignedBeaconBlockHeader()
        for column_idx in 0..<columns.len:
          let column_sidecar = columns[column_idx]
          if column_cursor >= columns.len:
            return err("DataColumnSidecar: Response is too short")
          if column_sidecar.signed_block_header == header:
            grouped[block_idx].add(column_sidecar)
          else:
            return err("DataColumnSidecar: unexpected signed_block_header")
          inc column_cursor
        # Make a table entry for the grouped columns
        man.column_syncer_table[forkyBlck.message.slot] =
          ColumnAndBlockResponse(
            blk: forkyBlck,
            columns: Opt.some(grouped[block_idx]))
  ok()

func serializeColumnTable*[A, B](
    man: ColumnManager[A, B]
): Result[seq[DataColumnSidecars], string] =
  # Iterate through the column syncer table
  for k, v in man.column_syncer_table.pairs():
    # Checking if the table has all the required columns
    if man.amIsupernode:
      if v.columns.len >= (man.cfg.NUMBER_OF_COLUMNS div 2) and
          v.columns.isSome():
        let
          recovered_cps =
            recover_cells_and_proofs(v.columns.get().mapIt(it[]))
          reconstructed_columns =
            get_data_column_sidecars(v.blk[], recovered_cps.get()).mapIt(newClone it)


        # Populate that particular entry with reconstructed columns
        man.column_syncer_table[k] =
          ColumnAndBlockResponse(
            blk: v.blk,
            columns: Opt.some(reconstructed_columns))

      elif v.columns.len < (NUMBER_OF_COLUMNS div 2) and v.columns.isSome():
        return err ("Requisite number of columns not yet reached")

    elif man.amIsupernode == false:
      if v.columns.len == max(man.cfg.CUSTODY_REQUIREMENT, man.cfg.SAMPLES_PER_SLOT) and
          v.columns.isSome:

        # Do nothing, table entry is fine
      elif v.columns.len == max(man.cfg.CUSTODY_REQUIREMENT, man.cfg.SAMPLES_PER_SLOT) and
          v.columns.isSome:
        discard

        # Retry as custody has not been reached yet
        return err ("Requisite number of columns not yet reached")

    else:
      discard

  var grouped_serialized_columns: seq[DataColumnSidecars]
  # Iterate once more to serialize the entries
  for _, v in man.column_syncer_table.pairs():
    grouped_serialized_columns.add(v)

  ok(grouped_serialized_columns)

## Nimbus cares about the representation of home
## stakers and solo stakers, and we understand supernodes
## stand against the same ethos even if supernodes pose as
## a critical modification in terms of peerdas development
##
## Hence, to stand with our values, we shall provide the user
## 2 separate modes of column syncing:
##
## 1 - Greedy: In the `Greedy` mode we give a greater preference
##     to supernodes or nodes that custody more than 50% of all
##     data columns in the network for a given slot. Thereby, using
##     either them or we are able to recover all data columns.
##
##     We read this by checking whether the remote peer's advertised
##     custody group count (cgc) is greater than half of the total
##     columns per slot or not.
##
## 2 - Impartial: In the `Impartial` mode we consider every peer as
##     `equal` instead of intersecting what columns we custody and they
##     custody, we range request all the columns with what
##     they can serve per slot, until we move to the goal of
##     reconstructability.
##
##     This way no peer in the Peer Pool becomes redundant, they were
##     previously useful for blocks, and now they are useful for columns
##     too.
##
##     Slot \ Custody |  0  |  1  |  2  |  3  |  4  | ..n |
##     -------------- | --- | --- | --- | --- | --- | --- |
##      0             |  X  |  X  |     |  X  |  X  |  X  |
##      1             |  X  |  X  |  X  |     |     |  X  |
##      2             |  X  |     |  X  |  X  |  X  |     |
##      3             |  X  |  X  |     |  X  |  X  |  X  |
##      4             |     |  X  |  X  |     |  X  |  X  |
##    ..m             |  X  |     |  X  |  X  |     |  X  |
##
##
##     where say,         Peerₐ → Column 1, 4, 17
##                        Peerᵦ → Column 3, 5, 33
##                        Peer𝒸 → Column 5, 45, 111
##
##                                  ||
##                    after         ||
##                reconstruction    \/
##
##
##     Slot \ Custody |  0  |  1  |  2  |  3  |  4  | ..n |
##     -------------- | --- | --- | --- | --- | --- | --- |
##      0             |  X  |  X  |  X  |  X  |  X  |  X  |
##      1             |  X  |  X  |  X  |  X  |  X  |  X  |
##      2             |  X  |  X  |  X  |  X  |  X  |  X  |
##      3             |  X  |  X  |  X  |  X  |  X  |  X  |
##      4             |  X  |  X  |  X  |  X  |  X  |  X  |
##    ..m             |  X  |  X  |  X  |  X  |  X  |  X  |
##

proc columnSyncStrategyImpartial[A, B](
    man: ColumnManager[A, B], index: int, peer: A
) {.async: (raises: [CancelledError]).} =
  logScope:
    peer_score = peer.getScore()
    peer_speed = peer.netKbps()
    index = index

  var
    headSlot = man.getLocalHeadSlot()
    wallSlot = man.getLocalWallSlot()
    peerSlot = peer.getHeadSlot()

  block:
    logScope:
      peer = peer

    debug "Peer's syncing status", wall_clock_slot = wallSlot,
          remote_head_slot = peerSlot, local_head_slot = headSlot

    let
      peerStatusAge = Moment.now() - peer.getStatusLastTime()
      needsUpdate =
        # Latest status we got is old
        peerStatusAge >= StatusExpirationTime or
        # The point we need to sync is close to where the peer is
        man.getFirstSlot() >= peerSlot

    if needsUpdate:
      man.workers[index].status = ColumnSyncerStatus.UpdatingStatus

      if peerStatusAge < StatusExpirationTime div 2:
        await sleepAsync(StatusExpirationTime div 2 - peerStatusAge)

      trace "Updating peer's status information", wall_clock_slot = wallSlot,
            remote_head_slot = peerSlot, local_head_slot = headSlot

      if not(await peer.updateStatus()):
        peer.updateScore(PeerScoreNoStatus)
        debug "Failed to get remote peer's status, exiting",
              peer_head_slot = peerSlot
        return

      let newPeerSlot = peer.getHeadSlot()
      if peerSlot >= newPeerSlot:
        peer.updateScore(PeerScoreStaleStatus)
        debug "Peer's status information is stale",
              wall_clock_slot = wallSlot, remote_old_head_slot = peerSlot,
              local_head_slot = headSlot, remote_new_head_slot = newPeerSlot
      else:
        debug "Peer's status information updated", wall_clock_slot = wallSlot,
              remote_old_head_slot = peerSlot, local_head_slot = headSlot,
              remote_new_head_slot = newPeerSlot
        peer.updateScore(PeerScoreGoodStatus)
        peerSlot = newPeerSlot

    # Time passed - enough to move slots, if sleep happened
    headSlot = man.getLocalHeadSlot()
    wallSlot = man.getLocalWallSlot()

  if man.remainingSlots() <= man.maxHeadAge:
    logScope:
      peer = peer

    info "We are in sync with the network", wall_clock_slot = wallSlot,
         remote_head_slot = peerSlot, local_head_slot = headSlot

    # We clear ColumnManager's `notInSyncEvent` so all the workers will become
    # sleeping down.
    man.notInSyncEvent.clear()
    return

  if man.getFirstSlot() >= peerSlot:
    debug "Peer's head slot is lower than local head slot", peer = peer,
          wall_clock_slot = wallSlot, remote_head_slot = peerSlot,
          local_last_slot = man.getLastSlot(),
          local_first_slot = man.getFirstSlot()
    peer.updateScore(PeerScoreUseless)
    return

  # Wall clock keeps ticking, so we need to update the queue
  man.assist.updateLastSlot(man.getLastSlot())

  man.workers[index].status = ColumnSyncerStatus.Requesting
  let req = man.assist.pop(peerSlot, peer)
  if req.isEmpty():
    debug "Empty request received from queue", peer = peer,
          local_head_slot = headSlot, remote_head_slot = peerSlot,
          queue_input_slot = man.assist.inpSlot,
          queue_output_slot = man.assist.outSlot,
          queue_last_slot = man.assist.finalSlot
    await sleepAsync(RESP_TIMEOUT_DUR)
    return

  debug "Creating new request for peer", wall_clock_slot = wallSlot,
        remote_head_slot = peerSlot, local_head_slot = headSlot,
        request = req

  man.workers[index].status = ColumnSyncerStatus.Downloading

  let blocks = await man.fetchBlocksForColumnNavigation(peer, req)
  if blocks.isErr():
    peer.updateScore(PeerScoreNoValues)
    man.queue.push(req)
    debug "Failed to receive blocks on request",
          request = req, err = blocks.error
    return
  let blockData = blocks.get().asSeq()
  debug "Received blocks on request",
         blocks_count = len(blockData),
         request = req

  let slots = mapIt(blockData, it[].slot)
  checkResponse(req, slots).isOkOr:
    peer.updateScore(PeerScoreBadResponse)
    man.queue.push(req)
    warn "Incorrect blocks sequence received",
          blocks_count = len(blockData),
          blocks_map = getShortMap(req, blockData),
          request = req,
          reason = error
    return

  let
    remoteNodeId =
      fetchNodeIdFromPeerId(peer)
    serveable_columns =
      man.cfg.resolve_columns_from_custody_groups(remoteNodeId, max(SAMPLES_PER_SLOT.uint64,
                                                peer.lookupCgcFromPeer()))
  let columnData =
    if shouldGetDataColumns:
      let columns =
        await man.getDataColumnSidecars(peer, serveable_columns)
      if columns.isErr:
        peer.updateScore(PeerScoreNoValues)
        man.assist.push(req)
        debug "Failed to receive columns on request",
              request = req, err = columns.error
        return
      let columnData = columns.get().asSeq()
      debug "Received data columns on request",
            columns_count = len(columnData)
      if len(columnData) > 0:
        let slots = mapIt(columnData, it[].signed_block_header.message.slot)
        checkDataColumnsResponse(req, slots).isOkOr:
          peer.updateScore(PeerScoreBadResponse)
          man.assist.push(req)
          warn "Incorrect columns sequence received",
               columns_count = len(columnData),
               request = req,
               reason = error
          return

      man.groupAndFillColumnTable(blockData, columnData).valueOr:
        peer.updateScore(PeerScoreNoValues)
        man.assist.push(req)
        info "Received column sequence is inconsistent",
             request = req, msg = error
        return

      let finalColumns =
        man.serializeColumnTable().valueOr:
          warn "Issue in grouping reconstructed columns",
               request = req, msg = error
      finalColumns.checkDataColumns().isOkOr:
        peer.updateScore(PeerScoreBadResponse)
        man.assist.push(req)
        warn "Columns verification failed",
             columns_count = len(columnData),
             request = req,
             reason = error
        return

      # Reset the column syncer table for the next batch
      man.column_syncer_table = initOrderedTable[Slot, ColumnAndBlockResponse]()
      Opt.some(finalColumns)
    else:
      Opt.none(seq[DataColumnSidecars])

  if len(columnData) == 0 and req.contains(man.getSafeSlot()):
    peer.updateScore(PeerScoreNoValues)
    debug "Response does not include known-to-exist block",
          request = req
    return

  # Scoring will happen in `syncUpdate`
  man.workers[index].status = ColumnSyncerStatus.Queueing

  let
    peerFinalized = peer.getFinalizedEpoch().start_slot()
    lastSlot = req.slot + req.count
    # The peer claims the block is finalized - our own block processing will
    # verify this point down the line
    maybeFinalized = lastSlot < peerFinalized

  await man.assist.push(
    req, blockData, columnData,
    maybeFinalized, proc() =
    man.workers[index].status = ColumnSyncerStatus.Processing)

proc columnSyncStrategyGreedy[A, B](
    man: ColumnManager[A, B],
    peers: seq[A],
    w_index: int)
    {.async: (raises: [CancelledError]).} =

  var
    accumulator = 0
    requested_peer: A = nil

  for peer in man.filterRelevantPeers(peers, w_index):
    ## Look for the broadest intersection set among the peers
    if man.intersectionColumns(peer).len > accumulator:
      accumulator = man.intersectionColumns(peer).len
      requested_peer = peer

  # Extract the intersection columns between local and peer to request
  let int_cols = man.intersectionColumns(requested_peer)

  if man.remainingSlots() <= man.maxHeadAge:
    info "We have synced all columns from the network", wall_clock_slot = wallSlot,
          remote_head_slot = peerSlot, local_head_slot = headSlot

  # Putting all ColumnSync workers to sleep
  man.notInSyncEvent.clear()
  return

  var
    headSlot = man.getLocalHeadSlot()
    wallSlot = man.getLocalWallSlot()
    reqPeerSlot = requested_peer.getHeadSlot()

  if man.getFirstSlot() >= reqPeerSlot:
    debug "Peer's head slot is lower than local head slot", peer = requested_peer,
          wall_clock_slot = wallSlot, remote_head_slot = reqPeerSlot,
          local_last_slot = man.getLastSlot(),
          local_first_slot = man.getFirstSlot()
    requested_peer.updateScore(PeerScoreUseless)
    return

  # Wall clock keeps ticking, so we need an update
  man.assist.updateLastSlot(man.getLastSlot())

  man.workers[w_index].status = ColumnSyncerStatus.Requesting
  let req = man.assist.pop(reqPeerSlot, requested_peer)
  if req.isEmpty():
    debug "Empty request received from syncer assist, exiting", peer = peer,
          local_head_slot = headSlot, remote_head_slot = reqPeerSlot,
          queue_input_slot = man.assist.inpSlot,
          queue_output_slot = man.queue.outSlot,
          queue_last_slot = man.assist.finalSlot
    await sleepAsync(RESP_TIMEOUT_DUR)
    return

  debug "Creating a new request for the peer", wall_clock_slot = wallSlot,
          remote_head_slot = reqPeerSlot, local_head_slot = headSlot,
          request = req

  man.workers[w_index].status = ColumnSyncerStatus.Downloading

  let blocks = await man.fetchBlocksForColumnNavigation(requested_peer, req)
  if blocks.isErr():
    requested_peer.updateScore(PeerScoreNoValues)
    man.assist.push(req)
    debug "Failed to receive blocks on request",
          request = req, err = blocks.error
    return

  let blockData = blocks.get().asSeq()
  debug "Received blocks on request",
        blocks_count = len(blockData),
        request = req

  debug "Requesting common columns from the best peer"
  let columnData =
    if shouldGetDataColumns:
      let columns =
        await man.getDataColumnSidecars(requested_peer, intersectionColumns)
      if columns.isErr():
        requested_peer.updateScore(PeerScoreNoValues)
        man.assist.push(req)
        debug "Failed to receive columns on request",
              request = req, err = columns.error
        return
      let columnData = columns.get().asSeq()
      debug "Received data columns on request",
            columns_count = len(columnData),
            request = req

      if len(columnData) > 0:
        let slots = mapIt(columnData, it[].signed_block_header.message.slot)
        checkDataColumnsResponse(req, slots).isOkOr:
          requested_peer.updateScore(PeerScoreBadResponse)
          man.assist.push(req)
          warn "Incorrect columns sequence received",
                columns_count = len(columnData),
                request = req,
                reason = error
          return

      man.groupAndFillColumnTable(blockData, columnData).valueOr:
        requested_peer.updateScore(PeerScoreNoValues)
        man.assist.push(req)
        info "Received columns sequence is inconsistent",
              request = req, msg = error
        return

      let finalColumns =
        man.serializeColumnTable().valueOr:
          warn "Issue in grouping reconstructed columns",
                request = req, msg = error
      finalColumns.checkDataColumns().isOkOr:
        requested_peer.updateScore(PeerScoreBadResponse)
        man.assist.push(req)
        warn "Columns verification failed",
              columns_count = len(columnData),
              request = req,
              reason = error
        return
      # Reset the column syncer table for the next batch
      man.column_syncer_table = initOrderedTable[Slot, ColumnAndBlockResponse]()
      Opt.some(finalColumns)
    else:
      Opt.none(seq[DataColumnSidecars])

  if len(columnData) == 0 and req.contains(man.getSafeSlot()):
    requested_peer.updateScore(PeerScoreNoValues)
    debug "Response does not include known-to-exist block",
          request = req
    return

  # Scoring will happen in `syncUpdate`
  man.workers[w_index].status = ColumnSyncerStatus.Queueing

  let
    peerFinalized = requested_peer.getFinalizedEpoch().start_slot()
    lastSlot = req.slot + req.count
    # The peer claims the block is finalized - our own block processing will
    # verify this point down the line
    maybeFinalized = lastSlot < peerFinalized

  await man.assist.push(
    req, blockData, columnData,
    maybeFinalized, proc() =
    man.workers[index].status = ColumnSyncerStatus.Processing)

proc columnSyncWorkerGreedy[A, B](
    man: ColumnManager[A, B],
    index: int
) {.async: (raises: [CancelledError]).} =
  mixin getKey, getScore, getHeadSlot

  debug "Starting column syncer in `Greedy` mode"
  var usefulPeers, uselessPeers: seq[A]

  try:
    while true:
      man.workers[index].status = ColumnSyncerStatus.Sleeping
      # This event is going to be set until we are not in sync with the network
      await man.notInSyncEvent.wait()
      man.workers[index].status = ColumnSyncerStatus.WaitingPeer
      for peer in availablePeers(man.pool):
        peer = await man.pool.acquire()
        if intersection(
            man.custody_columns_set,
            resolve_columns_from_custody_groups(fetchNodeIdFromPeerId(peer),
                                                max(SAMPLES_PER_SLOT.uint64,
                                                peer.lookupCgcFromPeer()).toHashSet())):
          usefulPeers.add(peer)
        else:
          uselessPeers.add(peer)

        if peer.lookupCgcFromPeer() == NUMBER_OF_COLUMNS.uint64:
          break
      # send back the useless peers back to pool
      man.pool.release(uselessPeers)
      uselessPeers.mapIt(nil)

      # send the useful peers to `columnSyncingStrategy`
      await man.columnSyncStrategyGreedy(usefulPeers, index)

      man.pool.release(usefulPeers)
      usefulPeers.mapIt(nil)
  finally:
    for peer in usefulPeers & uselessPeers:
      if not isNil(peer):
        man.pool.release(peer)

proc columnSyncWorkerImparital[A, B](
    man: ColumnManager[A, B],
    index: int
) {.async: (raises: [CancelledError]).} =
  mixin getKey, getScore, getHeadSlot

  debug "Starting column syncer in `Impartial` mode"
  var peer: A = nil
  try:
    while true:
      man.workers[index].status = ColumnSyncerStatus.Sleeping
      # This event if going to be set until we are not in sync with the network
      await man.notInSyncEvent.wait()
      man.workers[index].status = ColumnSyncerStatus.WaitingPeer
      peer = await man.pool.acquire()
      await man.columnSyncStrategyImpartial(index, peer)
      man.pool.release(peer)
      peer = nil
  finally:
    if not(isNil(peer)):
      man.pool.release(peer)

  debug "Column syncer has stopped."

proc getColumnSyncerStats[A, B](man: ColumnManager[A, B]):
                                tuple[map: string,
                                      sleeping: int,
                                      waiting: int,
                                      pending: int] =
  var map = newString(len(man.workers))
  var sleeping, waiting, pending: int
  for i in 0..<len(man.workers):
    var ch: char
    case man.workers[i].status
      of ColumnSyncerStatus.Sleeping:
        ch = 's'
        inc(sleeping)
      of ColumnSyncerStatus.WaitingPeer:
        ch = 'w'
        inc(waiting)
      of ColumnSyncerStatus.UpdatingStatus:
        ch = 'U'
        inc(pending)
      of ColumnSyncerStatus.Requesting:
        ch = 'R'
        inc(pending)
      of ColumnSyncerStatus.Downloading:
        ch = 'D'
        inc(pending)
      of ColumnSyncerStatus.Queueing:
        ch = 'Q'
        inc(pending)
      of ColumnSyncerStatus.Processing:
        ch = 'P'
        inc(pending)
    map[i] = ch
  (map, sleeping, waiting, pending)

proc startColumnSyncWorkers[A, B](man: ColumnManager[A, B]) =
  # Starting all the column sync workers
  if ColumnSyncerFlag.Greedy in man.flags:
    for i in 0..<len(man.workers):
      man.workers[i].future =
        columnSyncWorkerGreedy[A, B](man, i)
  if ColumnSyncerFlag.Impartial in man.flags:
    for i in 0..<len(man.workers):
      man.workers[i].future =
        columnSyncWorkerImparital[A, B](man, i)

proc stopColumnSyncWorkers[A, B](man: ColumnManager[A, B]) =
  # Cancelling all the column sync workers
  let pending = man.workers.mapIt(it.future.cancelAndWait())
  await noCancel allFutures(pending)

proc timeLeftForColumnSyncer*(d: Duration): string =
  if d == InfiniteDuration:
    "--h--m"
  else:
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

proc columnSyncClose[A, B](
    man: ColumnManager[A, B],
    speedTaskFut: Future[void]
) {.async: (raises: []).} =
  var pending: seq[FutureBase]
  if not(speedTaskFut.finished()):
    pending.add(speedTaskFut.cancelAndWait())
  for worker in man.workers:
    doAssert(worker.status in {Sleeping, WaitingPeer})
    pending.add(worker.future.cancelAndWait())
  await noCancel allFutures(pending)

proc columnSyncLoop[A, B](
    man: ColumnManager[A, B]
) {.async: (raises: []).} =

  logScope:
    direction = man.direction

  mixin getKey, getScore
  var pauseTime = 0

  man.startColumnSyncWorkers()

  debug "Column sync loop has started"

  proc averageSpeedTask() {.async: (raises: [CancelledError]).} =
    while true:
      # Reset column sync speeds between each loss-of-sync event
      man.avgSyncSpeed = 0
      man.insSyncSpeed = 0

      await man.notInSyncEvent.wait()

      # Give the node time to connect to peers and get the column sync started
      await sleepAsync(seconds(SECONDS_PER_SLOT.int64))

      var
        stamp = ColumnSyncTimestamp.now(man.assist.progress())
        syncCount = 0

      while man.inProgress:
        await sleepAsync(seconds(SECONDS_PER_SLOT.int64))

        let
          newStamp = ColumnSyncTimestamp.now(man.assist.progress())
          slotsPerSec = speed(stamp, newStamp)

        syncCount += 1

        man.insSyncSpeed = slotsPerSec
        man.avgSyncSpeed =
          man.avgSyncSpeed + (slotsPerSec - man.avgSyncSpeed) / float(syncCount)

        stamp = newStamp

  let averageSpeedTaskFut = averageSpeedTask()

  while true:
    let wallSlot = man.getLocalWallSlot()
    let headSlot = man.getLocalHeadSlot()

    let (map, sleeping, waiting, pending) = man.getWorkersStats()

    case man.assist.direction
    of ColumnSyncerDirection.Forward:
      debug "Current column syncing state", workers_map = map,
            sleeping_workers_count = sleeping,
            waiting_workers_count = waiting,
            pending_workers_count = pending,
            wall_head_slot = wallSlot,
            local_head_slot = headSlot,
            pause_time = $chronos.seconds(pauseTime),
            avg_sync_speed = man.avgSyncSpeed.formatBiggestFloat(ffDecimal, 4),
            ins_sync_speed = man.insSyncSpeed.formatBiggestFloat(ffDecimal, 4)

    let
      pivot = man.progressPivot
      progress =
        case man.assist.direction
        of ColumnSyncerDirection.Forward:
          if man.assist.outSlot >= pivot:
            man.assist.outSlot - pivot
          else:
            0'u64
        of ColumnSyncerDirection.Backward:
          if pivot >= man.assist.direction:
            pivot - man.assist.outSlot
          else:
            0'u64
      total =
        case man.assist.direction
        of ColumnSyncerDirection.Forward:
          if man.assist.finalSlot >= pivot:
            man.assist.finalSlot + 1'u64 - pivot
          else:
            0'u64
        of ColumnSyncerDirection.Backward:
          if pivot >= man.assist.finalSlot:
            pivot + 1'u64 - man.assist.finalSlot
          else:
            0'u64
      remaining = total - progress
      done =
        if total > 0:
          progress.float / total.float
        else:
          1.0
      timeleft =
        if man.avgSyncSpeed >= 0.001:
          Duration.fromFloatSeconds(remaining.float / man.avgSyncSpeed)
        else:
          InfiniteDuration
      currentSlot = Base10.toString(
        if man.assist.direction == ColumnSyncerDirection.Forward:
          max(uint64(man.assist.outSlot), 1'u64) - 1'u64
        else:
          uint64(man.assist.outSlot) + 1'u64
      )

    # Update status string
    man.syncStatus = timeleft.timeLeftForColumnSyncer() & " (" &
                     (done * 100).formatBiggestFloat(ffDecimal, 2) & "%) " &
                     man.avgSyncSpeed.formatBiggestFloat(ffDecimal, 4) &
                     "slots/s (" & map & ":" & currentSlot & ")"

    if man.remainingSlots() <= man.maxHeadAge:
      man.notInSyncEvent.clear()
      # We are marking SyncManager as not working only when we are in sync and
      # all sync workers are in `Sleeping` state.
      if pending > 0:
        debug "Synchronization loop waits for workers completion",
              wall_head_slot = wallSlot, local_head_slot = headSlot,
              difference = (wallSlot - headSlot), max_head_age = man.maxHeadAge,
              sleeping_workers_count = sleeping,
              waiting_workers_count = waiting, pending_workers_count = pending
        # We already synced, so we should reset all the pending workers from
        # any state they have.
        man.assist.clearAndWakeup()
        man.inProgress = true
      else:
        case man.direction
        of ColumnSyncerDirection.Forward:
          if man.inProgress:
            if ColumnSyncerMode.NoMonitor in man.modes:
              await man.columnSyncClose(averageSpeedTaskFut)
              man.inProgress = false
              debug "Forward column sync process finished, exiting",
                    wall_head_slot = wallSlot, local_head_slot = headSlot,
                    difference = (wallSlot - headSlot),
                    max_head_age = man.maxHeadAge
              break
            else:
              man.inProgress = false
              debug "Forward column sync process finished, sleeping",
                    wall_head_slot = wallSlot, local_head_slot = headSlot,
                    difference = (wallSlot - headSlot),
                    max_head_age = man.maxHeadAge
          else:
            debug "Column sync loop sleeping", wall_head_slot = wallSlot,
                  local_head_slot = headSlot,
                  difference = (wallSlot - headSlot),
                  max_head_Age = man.maxHeadAge
        of ColumnSyncerDirection.Backward:
          await man.columnSyncClose(averageSpeedTaskFut)
          man.inProgress = false
          debug "Backward column sync process finished, exiting",
                wall_head_slot = wallSlot, local_head_slot = headSlot,
                backfill_slot = man.getLastSlot(),
                max_head_Age = man.maxHeadAge
          break
    else:
      if not(man.notInSyncEvent.isSet()):
        # We get here only if we lost sync for more than `maxHeadAge` period.
        if pending == 0:
          man.initColumnSyncerAssist()
          man.notInSyncEvent.fire()
          man.inProgress = true
          debug "Node lost column sync for more than preset period",
                period = man.maxHeadAge, wall_head_slot = wallSlot,
                local_head_slot = headSlot,
                missing_slots = man.remainingSlots(),
                progress = float(man.assist.progress())
        else:
          man.notInSyncEvent.fire()
          man.inProgress = true

    await sleepAsync(chronos.seconds(2))

proc start*[A, B](man: ColumnManager[A, B]) =
  man.columnSyncerFut = man.columnSyncLoop()

proc updatePivot*[A, B](man: ColumnManager[A, B], pivot: Slot) =
  man.progressPivot = pivot

proc join*[A, B](
    man: ColumnManager[A, B]
): Future[void] {.async: (raw: true, raises: [CancelledError]).} =
  if man.columnSyncFut.isNil():
    let retFuture =
      Future[void].Raising([CancelledError]).init("nimbus-eth2.join()")
    retFuture.complete()
    retFuture
  else:
    man.columnSyncFut.join()
