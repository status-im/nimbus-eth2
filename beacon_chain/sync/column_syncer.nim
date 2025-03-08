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

  ColumnSyncerTable* = object
    column_table*: OrderedTable[(Eth2Digest, Slot), DataColumnSidecars]
      ## An in-memory table to store DataColumnSidecars against their Slot
      ## and extracted block root, the reason for having block root as a
      ## part of the key is to effectively repairing strategies if the
      ## remote peers reply with just a part of columns than what they
      ## were supposed to, additionally, this entire loop is independent
      ## to block/blobs sync hence, this is the only plausible way for
      ## us store columns against a block.
      ##
      ## Instead of checking whether block was Proposed or Orphaned or
      ## any similar anomaly, one can simply lookup the table and infer
      ## either there were no columns against that block, or there was no
      ## block that was mutually agreed as valid, in any case we do not
      ## have columns for that slot.

  ColumnSyncerFlag* {.pure.} = enum
    Greedy, Impartial

  ColumnSyncer*[A, B] = object
    future: Future[void].Raising([CancelledError])
    status: ColumnSyncerStatus

  ColumnManager*[A, B] = ref object
    pool: PeerPool[A, B]
    FULU_FORK_EPOCH: Epoch
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: uint64
    responseTimeout: chronos.Duration
    maxHeadAge: uint64
    amIsupernode*: bool
    custody_columns_set*: HashSet[ColumnIndex]
    custody_columns_list*: List[ColumnIndex, NUMBER_OF_COLUMNS]
    column_syncer_table*: OrderedTable[Eth2Digest , DataColumnSidecars]
      ## An in-memory table to store DataColumnSidecars against their
      ## extracted block root, the reason for having block root as a
      ## part of the key is to effectively repairing strategies if the
      ## remote peers reply with just a part of columns than what they
      ## were supposed to, additionally, this entire loop is independent
      ## to block/blobs sync hence, this is the only plausible way for
      ## us store columns against a block.
      ##
      ## Instead of checking whether block was Proposed or Orphaned or
      ## any similar anomaly, one can simply lookup the table and infer
      ## either there were no columns against that block, or there was no
      ## block that was mutually agreed as valid, in any case we do not
      ## have columns for that slot.

    assist*: ColumnSyncerAssist[A]
    getLocalHeadSlot: GetSlotCallback
    getLocalWallSlot: GetSlotCallback
    getSafeSlot: GetSlotCallback
    getFirstSlot: GetSlotCallback
    progressPivot: Slot
    workers: array[ColumnSyncWorkerCount, ColumnSyncer[A, B]]
    notInSyncEvent: AsyncEvent
    shutdownEvent: AsyncEvent
    rangeAge: uint64
    chunkSize: uint64
    columnSyncFut: Future[void].Raising([CancelledError])
    inProgress*: bool
    insSyncSpeed*: float
    avgSyncSpeed*: float
    syncStatus*: string
    flags: set[ColumnSyncerFlag]

  ColumnSyncTimestamp* = object
    timestamp*: chronos.Moment
    slots*: uint64

  DataColumnSidecarsRes =
    NetRes[List[ref DataColumnSidecar, Limit(MAX_REQUEST_BLOB_SIDECARS_ELECTRA)]]

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
  man.assist = ColumnSyncerAssist.init(A, man.getFirstSlot(),
                                       man.getLastSlot(), man.chunkSize,
                                       man.getSafeSlot(), 1)

proc newColumnManager*[A, B](
    pool: PeerPool[A, B],
    fuluEpoch: Epoch,
    minEpochsForBlobSidecarsRequests: uint64,
    getLocalHeadSlotCb: GetSlotCallback,
    getLocalWallSlotCb: GetSlotCallback,
    getFinalizedSlotCb: GetSlotCallback,
    progressPivot: Slot,
    shutdownEvent: AsyncEvent,
    maxHeadAge = uint64(SLOTS_PER_EPOCH * 1),
    chunkSize = uint64(SLOTS_PER_EPOCH),
    flags: set[ColumnSyncerFlag]
): ColumnManager[A, B] =

  let (getFirstSlot, getLastSlot, getSafeSlot) =
    (getLocalHeadSlotCb, getLocalWallSlotCb, getFinalizedSlotCb)

  var res = ColumnManager[A, B](
    pool: pool,
    FULU_FORK_EPOCH: fuluEpoch,
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: minEpochsForBlobSidecarsRequests,
    getFirstSlot: getLocalHeadSlotCb,
    getLastSlot: getLocalWallSlotCb,
    getSafeSlot: getFinalizedSlotCb,
    progressPivot: progressPivot,
    shutdownEvent: shutdownEvent,
    maxHeadAge: maxHeadAge,
    chunkSize: chunkSize,
    flags: flags
  )
  res.initColumnSyncerAssist()
  res

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
  intersection(man.custody_columns_set,
               resolve_column_sets_from_custody_groups(max(SAMPLES_PER_SLOT.uint64,
                                                       peer.lookupCgcFromPeer())))

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
                               w_index: int):
                               seq[A] =
  ## This iterates over the available peers
  ## and returns a refreshed peer list based on
  ## whichever's peer status is recent and relevant
  for peer in availablePeers(man.pool):
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
    columns: seq[ref DataColumnSidecar]
): Result[void, string] =

  ## As we are NOT iterating through blocks as well
  ## grouping columns can be complicated task. To tackle that we use the following
  ## spec:
  ## Clients MUST send data column sidecars in consecutive (slot, index) order
  for i in 0..<columns.len:
    var start, finish: int = 0
    var acc: ColumnIndex = 0

    if columns[i][].index == 0.ColumnIndex or columns[i][].index > acc:
      start = finish
      finish = i
      acc = columns[i][].index

      # Extract the block root from signed beacon block header
      let block_root =
        hash_tree_root(columns[i][].signed_block_header.message)

      var extracted_columns =
        newSeqOfCap[seq[ref DataColumnSidecar]](NUMBER_OF_COLUMNS)

      extracted_columns = columns[start..<finish]

      # Make a table entry to ColumnSyncerTable
      man.column_syncer_table[block_root] = extracted_columns

      return ok()

    else:
      return err("DataColumnSidecar: sorted (slot, index) order is violated")

func serializeColumnTable*[A, B](
    man: ColumnManager[A, B]
): Result[seq[DataColumnSidecars], string] =
  # Iterate through the key values in the table
  for k, v in man.column_syncer_table.pairs():
    # Checking if the table has all required columns
    if man.column_syncer_table[k].len == NUMBER_OF_COLUMNS:
      let
        recovered_cps =
          recover_cells_and_proofs(man.column_syncer_table[k].mapIt(it[]))
        consistent_block_header =
          man.column_syncer_table[k][0][].signed_block_header
        consistent_kzg_commitments =
          man.column_syncer_table[k][0][].kzg_commitments
        consistent_inclusion_proof =
          man.column_syncer_table[k][0][].kzg_commitments_inclusion_proof
        reconstructed_columns =
          get_data_column_sidecars(consistent_block_header,
                                   consistent_inclusion_proof,
                                   consistent_kzg_commitments,
                                   recovered_cps.get()).mapIt(newClone it)

      # Populate that particular entry with reconstructed columns now
      man.column_syncer_table[k] = reconstructed_columns

  var grouped_serialized_columns: seq[DataColumnSidecars]
  # Iterate once more to serialize the entries
  for _,v in man.column_syncer_table.pairs():
    grouped_serialized_columns.add(v)

  ok(grouped_serialized_columns)

proc columnSyncerStrategy[A, B](
    man: ColumnManager[A, B],
    w_index: int):
    {.async: (raises: [CancelledError]).} =

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
  if ColumnSyncerFlag.Impartial in man.flags:


  if ColumnSyncerFlag.Greedy in man.flags:
    var
      accumulator = 0
      requested_peer: A = nil

    for peer in man.filterRelevantPeers(w_index):
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
    debug "Requesting common columns from the best peer"
    let columnData =
      if shouldGetDataColumns:
        let columns =
          await man.getDataColumnSidecars(requested_peer, intersectionColumns)
        if columns.isErr():
          peer.updateScore(PeerScoreNoValues)
          debug "Failed to receive blobs on request",
                request = req, err = blobs.error
          return
        let columnData = columns.get().asSeq()
        debug "Received data columns on request",
               columns_count = len(columnData),
               request = req

        if len(columnData) > 0:
          let slots = mapIt(columnData, it[].signed_block_header.message.slot)
          checkDataColumnsResponse(req, slots).isOkOr:
            peer.updateScore(PeerScoreBadResponse)
            warn "Incorrect blobs sequence received",
                  columns_count = len(columnData),
                  request = req,
                  reason = error
            return

        man.groupAndFillColumnTable(columnData).valueOr:
          peer.updateScore(PeerScoreNoValues)
          info "Received columns sequence is inconsistent",
                request = req, msg = error
          return

        let finalColumns =
          man.serializeColumnTable().valueOr:
            warn "Issue in grouping reconstructed columns",
                  request = req, msg = error
          return
        finalColumns.checkDataColumns().isOkOr:
          peer.updateScore(PeerScoreBadResponse)
          warn "Columns verification failed",
               columns_count = len(columnData),
               request = req,
               reason = error
          return
        Opt.some(finalColumns)
      else:
        Opt.none(seq[DataColumnSidecars])

  if len(columnData) == 0 and req.contains(man.getSafeSlot()):
    peer.updateScore(PeerScoreNoValues)
    debug "Response does not include known-to-exist block",
          request = req
    return

  # Scoring will happen in `syncUpdate`.
  man.workers[w_index].status = ColumnSyncerStatus.Queueing
  let
    peerFinalized










