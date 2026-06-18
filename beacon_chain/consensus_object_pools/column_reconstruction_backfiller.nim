# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/deques,
  chronicles,
  chronos,
  taskpools,
  kzg4844/kzg,
  metrics,
  ../spec/[forks, helpers, peerdas_helpers, column_map],
  ../sync/validator_custody,
  ../beacon_chain_db,
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
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/fulu/das-core.md#reconstruction-and-cross-seeding
  ColumnsRequiredForReconstruction = NUMBER_OF_COLUMNS div 2

  # Idle delay between bitmap re-scans when there's no slot pending
  # reconstruction. Roughly one slot so we pick up newly arrived columns
  # without busy-waiting.
  IdleSleepDuration = chronos.seconds(12)

  # Brief yield between back-to-back reconstructions so the taskpool and
  # other duties (sig verification, gossip) aren't fully starved.
  WorkYieldDuration = chronos.milliseconds(50)

type
  SlotRecon {.pure.} = enum
    Unknown   ## Not yet inspected by the backfiller.
    TooFew    ## Block has blobs but <64 columns present — cannot recover yet.
    Servable  ## Slot can be served with the full matrix: all 128 columns are
              ## present (original or reconstructed), or it legitimately carries
              ## none — an empty slot or a block with zero blob commitments.
              ## The backfiller treats both the same: nothing left to do.

  ColumnReconstructionBackfiller* = object
    dag: ChainDAGRef
    validatorCustody: ValidatorCustodyRef
    taskpool: Taskpool
    # Sliding bitmap over [bitmapStartSlot..head]. Each entry is the
    # backfiller's last-known reconstruction status for that slot. Kept in
    # memory only — on restart we rebuild via a fresh backward scan.
    slotStates: Deque[SlotRecon]
    bitmapStartSlot: Slot

  ColumnReconstructionBackfillerRef* = ref ColumnReconstructionBackfiller

func new*(
    t: typedesc[ColumnReconstructionBackfillerRef],
    dag: ChainDAGRef,
    validatorCustody: ValidatorCustodyRef,
    taskpool: Taskpool
): ColumnReconstructionBackfillerRef =
  ColumnReconstructionBackfillerRef(
    dag: dag,
    validatorCustody: validatorCustody,
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

func syncBitmap(self: ColumnReconstructionBackfillerRef) =
  ## Resize and slide the bitmap so it spans the current
  ## [retentionStart..head] window. New top entries are `Unknown`; entries
  ## that fall behind the retention horizon are dropped.
  let
    retentionStart = self.retentionStartSlot()
    head = self.dag.head.slot

  if self.bitmapStartSlot == FAR_FUTURE_SLOT:
    self.bitmapStartSlot = retentionStart
    if head >= retentionStart:
      let initialLen = int(head - retentionStart) + 1
      self.slotStates = initDeque[SlotRecon](initialLen)
      for _ in 0 ..< initialLen:
        self.slotStates.addLast(SlotRecon.Unknown)
    return

  if head >= self.bitmapStartSlot:
    let wanted = int(head - self.bitmapStartSlot) + 1
    while self.slotStates.len < wanted:
      self.slotStates.addLast(SlotRecon.Unknown)

  if retentionStart > self.bitmapStartSlot:
    let drop = int(retentionStart - self.bitmapStartSlot)
    if drop >= self.slotStates.len:
      self.slotStates.clear()
    else:
      self.slotStates.shrink(fromFirst = drop)
    self.bitmapStartSlot = retentionStart

func slotIdx(self: ColumnReconstructionBackfillerRef, slot: Slot): int =
  int(slot - self.bitmapStartSlot)

func markSlot(
    self: ColumnReconstructionBackfillerRef, slot: Slot, state: SlotRecon) =
  if slot < self.bitmapStartSlot:
    return
  let idx = self.slotIdx(slot)
  if idx >= 0 and idx < self.slotStates.len:
    self.slotStates[idx] = state

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
    if self.slotStates[idx] != SlotRecon.Servable:
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

func onColumnsStored*(
    self: ColumnReconstructionBackfillerRef, slot: Slot) =
  ## Event hook invoked when data columns are newly persisted for `slot`
  ## (see `BlockProcessor.onDataColumnsStored`).
  ##
  ## Columns reach an *already-inspected* slot only via sync/req-resp: gossip
  ## delivers columns solely for the current slot, in real time, and never
  ## backfills history, so by the time we have descended to a slot and marked
  ## it `TooFew` no further gossip will arrive for it. A timer-driven re-count
  ## would therefore almost never coincide with an actual arrival. Instead we
  ## re-arm precisely on the arrival: a slot previously found `TooFew` may now
  ## hold enough columns to cross the `ColumnsRequiredForReconstruction`
  ## threshold, so mark it `Unknown` for the next pass to re-count (and, if it
  ## was the trail-blocker, let `eaSlot` extend further). Slots in any other
  ## state are left untouched — `Servable` slots need no redo and `Unknown`
  ## is already queued.
  if slot < self.bitmapStartSlot:
    return
  let idx = self.slotIdx(slot)
  if idx >= 0 and idx < self.slotStates.len and
      self.slotStates[idx] == SlotRecon.TooFew:
    self.slotStates[idx] = SlotRecon.Unknown

proc existingColumns(
    db: BeaconChainDB,
    consensusFork: ConsensusFork,
    blockRoot: Eth2Digest
): ColumnMap =
  ## The set of columns currently persisted for `blockRoot`. Columns are stored
  ## in a per-fork table keyed by fork, which `containsDataColumnSidecar`
  ## already dispatches on, so no per-fork branching is needed here.
  var present: ColumnMap
  for i in 0'u64 ..< NUMBER_OF_COLUMNS.uint64:
    if db.containsDataColumnSidecar(consensusFork, blockRoot, i):
      present.incl(i)
  present

proc loadExistingColumns[T: fulu.DataColumnSidecar | gloas.DataColumnSidecar](
    db: BeaconChainDB,
    blockRoot: Eth2Digest,
    indices: ColumnMap
): seq[ref T] =
  var
    columns = newSeqOfCap[ref T](indices.len)
    colData = new T
  for i in indices:
    if db.getDataColumnSidecar(blockRoot, uint64(i), colData[]):
      columns.add(colData)
      colData = new T
  columns

proc reconstructAndStore[
    T: fulu.DataColumnSidecar | gloas.DataColumnSidecar](
    self: ColumnReconstructionBackfillerRef,
    slot: Slot,
    blockRoot: Eth2Digest,
    have: ColumnMap,
    columns: seq[ref T]
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Run the parallel cell+proof recovery and persist every column the
  ## caller did not already have. Returns true on full success.
  beacon_column_reconstruction_attempts_total.inc()
  beacon_column_reconstruction_backfill_slot.set(int64(slot))

  let
    startTime = Moment.now()
    recovered = (await recover_cells_and_proofs_parallel(
      self.taskpool, columns)).valueOr:
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
    have: ColumnMap,
    _: typedesc[T]
): Future[SlotRecon] {.async: (raises: [CancelledError]).} =
  ## Returns the resulting slot state: `Servable` on success,
  ## `TooFew` if columns were pruned out from under us between
  ## inspecting and loading them, or `Unknown` on a recoverable
  ## failure (so a later pass retries once more columns arrive).
  let columns = loadExistingColumns[T](self.dag.db, blockRoot, have)
  if columns.len < ColumnsRequiredForReconstruction:
    return SlotRecon.TooFew
  if await self.reconstructAndStore(slot, blockRoot, have, columns):
    SlotRecon.Servable
  else:
    SlotRecon.Unknown

proc processSlot(
    self: ColumnReconstructionBackfillerRef,
    slot: Slot) {.async: (raises: [CancelledError]).} =
  let blockFork = self.dag.cfg.consensusForkAtEpoch(slot.epoch)
  # Data columns only exist from Fulu onward; pre-Fulu slots carry none.
  if blockFork notin {ConsensusFork.Fulu, ConsensusFork.Gloas, ConsensusFork.Heze}:
    self.markSlot(slot, SlotRecon.Servable)
    return

  # Gloas and every newer fork (Heze, ...) share the Gloas data column format
  let columnFork =
    if blockFork >= ConsensusFork.Gloas: ConsensusFork.Gloas else: blockFork

  let bsi = self.dag.getBlockIdAtSlot(slot).valueOr:
    self.markSlot(slot, SlotRecon.Servable)
    return

  if not bsi.isProposed():
    self.markSlot(slot, SlotRecon.Servable)
    return

  let
    blockRoot = bsi.bid.root
    have = existingColumns(self.dag.db, columnFork, blockRoot)

  if have.lenu64 == NUMBER_OF_COLUMNS:
    self.markSlot(slot, SlotRecon.Servable)
    return

  let count = have.len
  if count == 0:
    # Distinguish "a block having zero blobs" from "no/below
    # threshold columns were found" — only the latter is a reconstruction miss.
    let forked = self.dag.getForkedBlock(bsi.bid).valueOr:
      self.markSlot(slot, SlotRecon.Servable)
      return
    var blockHadBlobs = false
    withBlck(forked):
      when consensusFork >= ConsensusFork.Gloas:
        # [Modified in Gloas:EIP7732] commitments live under the payload bid.
        blockHadBlobs = forkyBlck.message.body
          .signed_execution_payload_bid.message.blob_kzg_commitments.len > 0
      elif consensusFork == ConsensusFork.Fulu:
        blockHadBlobs = forkyBlck.message.body.blob_kzg_commitments.len > 0
    if not blockHadBlobs:
      self.markSlot(slot, SlotRecon.Servable)
    else:
      self.markSlot(slot, SlotRecon.TooFew)
    return

  if count < ColumnsRequiredForReconstruction:
    self.markSlot(slot, SlotRecon.TooFew)
    return

  # On reconstruction failure `reconstructSlot` returns `Unknown`, leaving the
  # slot eligible for a later retry.
  let state =
    if columnFork == ConsensusFork.Fulu:
      await self.reconstructSlot(slot, blockRoot, have, fulu.DataColumnSidecar)
    else:
      debugHezeComment "need to confirm Heze data columns stay identical to Gloas"
      await self.reconstructSlot(slot, blockRoot, have, gloas.DataColumnSidecar)
  self.markSlot(slot, state)

func frontierSlot(self: ColumnReconstructionBackfillerRef): Opt[Slot] =
  ## The single slot whose reconstruction can extend `eaSlot`: the one
  ## immediately below the head-anchored run of fully-servable slots. `eaSlot`
  ## can only descend through a *contiguous* servable run from the head, so the
  ## only useful work is at that frontier — reconstructing slots below it is
  ## pointless, as they are guaranteed to stay behind `eaSlot` until the
  ## frontier itself is filled. We therefore walk strictly backwards from the
  ## head, one slot at a time, instead of sweeping the whole retention window.
  ##
  ## Returns `none` when the run already reaches the bottom of the bitmap, or
  ## when the frontier slot has been inspected and found unrecoverable
  ## (`TooFew`): rather than spin on it we idle until `onColumnsStored` re-arms
  ## it as `Unknown` the moment more columns for it are persisted.
  if self.slotStates.len == 0:
    return Opt.none(Slot)
  let bottom = self.headContiguousBottom()
  if bottom <= self.bitmapStartSlot:
    return Opt.none(Slot)
  let
    frontier = bottom - 1
    idx = self.slotIdx(frontier)
  if idx >= 0 and idx < self.slotStates.len and
      self.slotStates[idx] == SlotRecon.Unknown:
    return Opt.some(frontier)
  Opt.none(Slot)

proc run*(
    self: ColumnReconstructionBackfillerRef) {.async: (raises: []).} =
  debug "Column reconstruction backfiller started"
  try:
    while true:
      # Custody is dynamic: a node out of sync drops to limited custody,
      # so re-check every pass and idle (rather than terminate) whenever
      # our inferred custody falls below the reconstruction threshold,
      # resuming once it climbs back.
      if self.validatorCustody.getMap().len < ColumnsRequiredForReconstruction:
        await sleepAsync(IdleSleepDuration)
        continue

      self.syncBitmap()
      self.updateEarliestAvailableSlot()

      let target = self.frontierSlot()
      if target.isNone():
        # Either `eaSlot` already reaches as far back as we retain, or the
        # frontier slot is blocked on too few columns. A blocker is re-armed by
        # `onColumnsStored` the instant more columns are persisted for it, so
        # there's nothing to retry on a timer here — just idle until then.
        await sleepAsync(IdleSleepDuration)
        continue

      await self.processSlot(target.get())
      self.updateEarliestAvailableSlot()
      await sleepAsync(WorkYieldDuration)
  except CancelledError:
    discard
  debug "Column reconstruction backfiller stopped"
