# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[sequtils, sets],
  chronicles,
  chronos,
  taskpools,
  kzg4844/kzg,
  metrics,
  ssz_serialization/[proofs, types],
  ../spec/[forks, helpers, peerdas_helpers, column_map],
  ../spec/datatypes/[fulu, gloas],
  ../sync/validator_custody,
  ../beacon_chain_db,
  ../beacon_clock,
  ./blockchain_dag

logScope: topics = "column_reconstruction_backfiller"

declareCounter beacon_column_reconstruction_attempts_total,
  "Total column reconstruction attempts by the backfiller service"

declareCounter beacon_column_reconstruction_success_total,
  "Successful column reconstructions by the backfiller service"

declareCounter beacon_column_reconstruction_failures_total,
  "Failed column reconstruction attempts by the backfiller service"

declareGauge beacon_column_reconstruction_backfill_slot,
  "Slot most recently selected for reconstruction by the backfiller service"

declareGauge beacon_column_reconstruction_earliest_available_slot,
  "Earliest slot from which the full column matrix can be served, as extended " &
  "by the reconstruction backfiller"

const
  # Spec: a node "SHOULD reconstruct the full data matrix" once it holds
  # 50%+ of the columns, i.e. NUMBER_OF_COLUMNS / 2 == 64 on mainnet.
  ColumnsRequiredForReconstruction = NUMBER_OF_COLUMNS div 2

  # Idle delay between bitmap re-scans when there's no slot pending
  # reconstruction. Roughly one slot so we pick up newly arrived columns
  # without busy-waiting.
  IdleSleepDuration = chronos.seconds(12)

  # Brief yield between back-to-back reconstructions so the taskpool and
  # other duties (sig verification, gossip) aren't fully starved.
  WorkYieldDuration = chronos.milliseconds(50)

type
  SlotRecon = enum
    Unknown      ## Not yet inspected by the backfiller.
    NoColumns    ## Slot has no block, or the block has zero blob commitments.
    TooFew       ## Block has blobs but <64 columns present — cannot recover.
    Full         ## All 128 columns are now present (original or reconstructed).

  ColumnReconstructionBackfiller* = object
    dag: ChainDAGRef
    validatorCustody: ValidatorCustodyRef
    beaconClock: BeaconClock
    taskpool: Taskpool
    # Sliding bitmap over [bitmapStartSlot..head]. Each entry is the
    # backfiller's last-known reconstruction status for that slot. Kept in
    # memory only — on restart we rebuild via a fresh backward scan.
    slotStates: seq[SlotRecon]
    bitmapStartSlot: Slot

  ColumnReconstructionBackfillerRef* = ref ColumnReconstructionBackfiller

proc new*(
    t: typedesc[ColumnReconstructionBackfillerRef],
    dag: ChainDAGRef,
    validatorCustody: ValidatorCustodyRef,
    beaconClock: BeaconClock,
    taskpool: Taskpool
): ColumnReconstructionBackfillerRef =
  ColumnReconstructionBackfillerRef(
    dag: dag,
    validatorCustody: validatorCustody,
    beaconClock: beaconClock,
    taskpool: taskpool,
    bitmapStartSlot: FAR_FUTURE_SLOT)

func retentionStartSlot(self: ColumnReconstructionBackfillerRef): Slot =
  ## Earliest slot still within the data-column retention window.
  ## Mirrors the prune horizon used by `pruneDataColumns`
  ## (MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, ~18 days).
  let
    headSlot = self.dag.head.slot
    retentionEpochs = self.dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS
    retentionSlots = retentionEpochs * SLOTS_PER_EPOCH
    fuluStartSlot = self.dag.cfg.FULU_FORK_EPOCH.start_slot()
  if uint64(headSlot) <= retentionSlots:
    fuluStartSlot
  else:
    max(headSlot - retentionSlots, fuluStartSlot)

proc syncBitmap(self: ColumnReconstructionBackfillerRef) =
  ## Resize and slide the bitmap so it spans the current
  ## [retentionStart..head] window. New top entries are `Unknown`; entries
  ## that fall behind the retention horizon are dropped.
  let
    retentionStart = self.retentionStartSlot()
    head = self.dag.head.slot

  if self.bitmapStartSlot == FAR_FUTURE_SLOT:
    self.bitmapStartSlot = retentionStart
    if head >= retentionStart:
      self.slotStates = newSeq[SlotRecon](int(head - retentionStart) + 1)
    return

  if head >= self.bitmapStartSlot:
    let wanted = int(head - self.bitmapStartSlot) + 1
    if wanted > self.slotStates.len:
      self.slotStates.setLen(wanted)

  if retentionStart > self.bitmapStartSlot:
    let drop = int(retentionStart - self.bitmapStartSlot)
    if drop >= self.slotStates.len:
      self.slotStates.setLen(0)
    else:
      self.slotStates.delete(0 .. drop - 1)
    self.bitmapStartSlot = retentionStart

func slotIdx(self: ColumnReconstructionBackfillerRef, slot: Slot): int =
  int(slot - self.bitmapStartSlot)

proc markSlot(
    self: ColumnReconstructionBackfillerRef, slot: Slot, state: SlotRecon) =
  if slot < self.bitmapStartSlot:
    return
  let idx = self.slotIdx(slot)
  if idx >= 0 and idx < self.slotStates.len:
    self.slotStates[idx] = state

proc pickNextSlot(self: ColumnReconstructionBackfillerRef): Opt[Slot] =
  ## Walk backward from head, returning the highest-slot entry whose state
  ## is still `Unknown` (never inspected) or that we have re-marked as a
  ## reconstruction candidate. `Full`/`NoColumns`/`TooFew` slots are
  ## skipped — they have nothing for us to do.
  if self.slotStates.len == 0:
    return Opt.none(Slot)

  let head = self.dag.head.slot
  if head < self.bitmapStartSlot:
    return Opt.none(Slot)

  var s = head
  while true:
    let idx = self.slotIdx(s)
    if idx >= 0 and idx < self.slotStates.len:
      if self.slotStates[idx] == Unknown:
        return Opt.some(s)
    if s == self.bitmapStartSlot:
      break
    s = s - 1
  Opt.none(Slot)

func isFullyServable(state: SlotRecon): bool =
  ## A slot can be served with the complete column matrix when every column is
  ## present (`Full`) or when it legitimately carries none — an empty slot or a
  ## block with zero blob commitments (`NoColumns`). `TooFew`/`Unknown` slots
  ## cannot (yet) be served in full and therefore break the continuous trail.
  state in {Full, NoColumns}

func headContiguousBottom(self: ColumnReconstructionBackfillerRef): Slot =
  ## Lowest slot of the unbroken run of fully-servable slots ending at the
  ## head. The continuous "we hold all NUMBER_OF_COLUMNS columns" period is
  ## therefore `[result..head]`. Returns `head + 1` when even the head isn't
  ## servable yet (empty run).
  let head = self.dag.head.slot
  if self.slotStates.len == 0 or head < self.bitmapStartSlot:
    return head + 1
  var bottom = head + 1
  while bottom > self.bitmapStartSlot:
    let idx = self.slotIdx(bottom - 1)
    if idx < 0 or idx >= self.slotStates.len:
      break
    if not self.slotStates[idx].isFullyServable:
      break
    bottom = bottom - 1
  bottom

proc updateEarliestAvailableSlot(self: ColumnReconstructionBackfillerRef) =
  ## Keep `dag.eaSlot` at the bottom of the unbroken run of fully-servable
  ## slots ending at the head, so that `[eaSlot..head]` always denotes a
  ## continuous period over which we hold the full `NUMBER_OF_COLUMNS` matrix.
  ##
  ## Reconstruction fills the matrix head-first; as the unbroken run grows
  ## downward we lower `eaSlot` so peers learn of the longer servable history.
  ## We anchor the walk *at the head* (not at the current `eaSlot`) so we never
  ## extend the advertised window across a still-unfilled gap, and we only ever
  ## lower it — a momentarily un-inspected tip, or columns still arriving for
  ## the current slot, must not retract history we have already guaranteed.
  if self.slotStates.len == 0:
    return
  let bottom = self.headContiguousBottom()
  if bottom < self.dag.eaSlot:
    self.dag.eaSlot = bottom
    beacon_column_reconstruction_earliest_available_slot.set(int64(bottom))
    debug "Extended earliest available slot to reconstructed trail",
      eaSlot = bottom, head = self.dag.head.slot

proc retryTrailBlocker(self: ColumnReconstructionBackfillerRef) =
  ## The slot just below the head-contiguous run is what stops `eaSlot` from
  ## descending. If it is only `TooFew` (has some columns but fewer than the
  ## `ColumnsRequiredForReconstruction` threshold) re-arm it as `Unknown` so a
  ## later pass re-counts it: columns arriving via gossip/sync since we last
  ## looked may have pushed it over the threshold, letting the continuous
  ## period — and `eaSlot` — extend further. A genuinely under-filled slot
  ## simply settles back to `TooFew`, at the cost of one re-count per idle tick.
  let bottom = self.headContiguousBottom()
  if bottom <= self.bitmapStartSlot:
    return
  let idx = self.slotIdx(bottom - 1)
  if idx >= 0 and idx < self.slotStates.len and self.slotStates[idx] == TooFew:
    self.slotStates[idx] = Unknown

proc countExistingColumns(
    db: BeaconChainDB,
    consensusFork: ConsensusFork,
    blockRoot: Eth2Digest
): HashSet[uint64] =
  var present: HashSet[uint64]
  for i in 0'u64 ..< NUMBER_OF_COLUMNS.uint64:
    # Columns are stored in a per-fork table, so the right fork must be
    # consulted: Fulu sidecars live in `fulu_columns`, Gloas in `gloas_columns`.
    let found =
      case consensusFork
      of ConsensusFork.Fulu:
        db.containsDataColumnSidecar(ConsensusFork.Fulu, blockRoot, i)
      of ConsensusFork.Gloas:
        db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot, i)
      else:
        false
    if found:
      present.incl(i)
  present

proc loadExistingColumns[T: fulu.DataColumnSidecar | gloas.DataColumnSidecar](
    db: BeaconChainDB,
    blockRoot: Eth2Digest,
    indices: HashSet[uint64]
): seq[ref T] =
  var columns = newSeqOfCap[ref T](indices.len)
  for i in 0'u64 ..< NUMBER_OF_COLUMNS.uint64:
    if i notin indices:
      continue
    let colData = new T
    if db.getDataColumnSidecar(blockRoot, i, colData[]):
      columns.add(colData)
  columns

proc reconstructAndStore[
    T: fulu.DataColumnSidecar | gloas.DataColumnSidecar](
    self: ColumnReconstructionBackfillerRef,
    slot: Slot,
    blockRoot: Eth2Digest,
    have: HashSet[uint64],
    columns: seq[ref T]
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Run the parallel cell+proof recovery and persist every column the
  ## caller did not already have. Returns true on full success.
  beacon_column_reconstruction_attempts_total.inc()
  beacon_column_reconstruction_backfill_slot.set(int64(slot))

  let startTime = Moment.now()
  # `recover_cells_and_proofs_parallel` is concrete over Fulu sidecars (its
  # taskpool `spawn` can't be instantiated generically). Recovery only reads
  # `index`/`column`, so adapt Gloas sidecars to that shape; Fulu ones pass
  # through unchanged.
  let recoverInput =
    when T is fulu.DataColumnSidecar:
      columns
    else:
      columns.mapIt((ref fulu.DataColumnSidecar)(
        index: it[].index, column: it[].column))
  let recovered = (await recover_cells_and_proofs_parallel(
      self.taskpool, recoverInput)).valueOr:
    beacon_column_reconstruction_failures_total.inc()
    debug "Column reconstruction failed",
      slot, blockRoot, haveCount = columns.len, reason = error
    return false

  let
    recoveredTime = Moment.now()
    rowCount = recovered.len

  var reconstructed = newSeqOfCap[ref T](NUMBER_OF_COLUMNS - columns.len)
  for i in 0'u64 ..< NUMBER_OF_COLUMNS.uint64:
    if i in have:
      continue
    var
      cells = newSeq[Cell](rowCount)
      proofs = newSeq[kzg.KzgProof](rowCount)
    for j in 0 ..< rowCount:
      cells[j] = recovered[j].cells[i]
      proofs[j] = recovered[j].proofs[i]
    # Per-block constants (commitments/header/proof for Fulu,
    # slot/beacon_block_root for Gloas) are identical across every column of a
    # block, so they're copied from any sidecar we already hold.
    when T is gloas.DataColumnSidecar:
      reconstructed.add (ref gloas.DataColumnSidecar)(
        index: ColumnIndex(i),
        column: DataColumn.init(cells),
        kzg_proofs: deneb.KzgProofs.init(proofs),
        slot: columns[0][].slot,
        beacon_block_root: columns[0][].beacon_block_root)
    else:
      reconstructed.add (ref fulu.DataColumnSidecar)(
        index: ColumnIndex(i),
        column: DataColumn.init(cells),
        kzg_commitments: columns[0][].kzg_commitments,
        kzg_proofs: deneb.KzgProofs.init(proofs),
        signed_block_header: columns[0][].signed_block_header,
        kzg_commitments_inclusion_proof:
          columns[0][].kzg_commitments_inclusion_proof)

  self.dag.db.putDataColumnSidecars(reconstructed)
  beacon_column_reconstruction_success_total.inc()

  debug "Stored reconstructed columns",
    slot, blockRoot,
    haveCount = columns.len,
    addedCount = reconstructed.len,
    recoveryTime = recoveredTime - startTime,
    storeTime = Moment.now() - recoveredTime
  true

proc reconstructSlot[T: fulu.DataColumnSidecar | gloas.DataColumnSidecar](
    self: ColumnReconstructionBackfillerRef,
    slot: Slot,
    blockRoot: Eth2Digest,
    have: HashSet[uint64],
    _: typedesc[T]
): Future[SlotRecon] {.async: (raises: [CancelledError]).} =
  ## Load the columns we hold, recover the rest and persist them. Returns the
  ## resulting slot state: `Full` on success, `TooFew` if columns were pruned
  ## out from under us between the count and the load, or `Unknown` on a
  ## recoverable failure (so a later pass retries once more columns arrive).
  let columns = loadExistingColumns[T](self.dag.db, blockRoot, have)
  if columns.len < ColumnsRequiredForReconstruction:
    return TooFew
  if await self.reconstructAndStore(slot, blockRoot, have, columns):
    Full
  else:
    Unknown

proc processSlot(
    self: ColumnReconstructionBackfillerRef,
    slot: Slot) {.async: (raises: [CancelledError]).} =
  let blockFork = self.dag.cfg.consensusForkAtEpoch(slot.epoch)
  # Data columns currently only exist for Fulu and Gloas; pre-Fulu slots carry
  # none and later forks (Heze+) don't yet have a column store wired up.
  if blockFork notin {ConsensusFork.Fulu, ConsensusFork.Gloas}:
    self.markSlot(slot, NoColumns)
    return

  let bsi = self.dag.getBlockIdAtSlot(slot).valueOr:
    self.markSlot(slot, NoColumns)
    return

  # `getBlockIdAtSlot` returns the most recent block at or before `slot`;
  # if that block is not the proposed block for this slot, the slot is
  # empty and there is nothing to reconstruct.
  if not bsi.isProposed():
    self.markSlot(slot, NoColumns)
    return

  let blockRoot = bsi.bid.root
  let have = countExistingColumns(self.dag.db, blockFork, blockRoot)
  let count = have.len

  if count.uint64 == NUMBER_OF_COLUMNS:
    self.markSlot(slot, Full)
    return

  if count == 0:
    # Distinguish "block legitimately has zero blobs" from "we never
    # received any columns" — only the latter is a reconstruction miss.
    let forked = self.dag.getForkedBlock(bsi.bid).valueOr:
      self.markSlot(slot, NoColumns)
      return
    var blockHadBlobs = false
    withBlck(forked):
      when consensusFork >= ConsensusFork.Gloas:
        # [Modified in Gloas:EIP7732] commitments live under the payload bid.
        blockHadBlobs = forkyBlck.message.body
          .signed_execution_payload_bid.message.blob_kzg_commitments.len > 0
      elif consensusFork >= ConsensusFork.Fulu:
        blockHadBlobs = forkyBlck.message.body.blob_kzg_commitments.len > 0
    if not blockHadBlobs:
      self.markSlot(slot, NoColumns)
    else:
      self.markSlot(slot, TooFew)
    return

  if count < ColumnsRequiredForReconstruction:
    self.markSlot(slot, TooFew)
    return

  # On reconstruction failure `reconstructSlot` returns `Unknown`, leaving the
  # slot eligible for a later retry.
  let state =
    case blockFork
    of ConsensusFork.Gloas:
      await self.reconstructSlot(slot, blockRoot, have, gloas.DataColumnSidecar)
    else:
      await self.reconstructSlot(slot, blockRoot, have, fulu.DataColumnSidecar)
  self.markSlot(slot, state)

proc run*(
    self: ColumnReconstructionBackfillerRef) {.async: (raises: []).} =
  debug "Column reconstruction backfiller started"
  try:
    while true:
      # Reconstruction is only possible once we custody at least half the
      # matrix, so it's only a duty of nodes currently holding that many
      # columns — i.e. a (light)supernode. Custody is dynamic: a node out of
      # sync drops to limited custody, so re-check every pass and idle (rather
      # than terminate) whenever our inferred custody falls below the
      # reconstruction threshold, resuming once it climbs back.
      if self.validatorCustody.getMap().len < ColumnsRequiredForReconstruction:
        await sleepAsync(IdleSleepDuration)
        continue

      self.syncBitmap()
      self.updateEarliestAvailableSlot()

      let target = self.pickNextSlot()
      if target.isNone():
        # No un-inspected slots remain. If the continuous trail from the head
        # is held up by a slot that's merely short on columns, re-arm it so the
        # next pass can pick up any columns that have since arrived.
        self.retryTrailBlocker()
        await sleepAsync(IdleSleepDuration)
        continue

      await self.processSlot(target.get())
      self.updateEarliestAvailableSlot()
      await sleepAsync(WorkYieldDuration)
  except CancelledError:
    discard
  debug "Column reconstruction backfiller stopped"
