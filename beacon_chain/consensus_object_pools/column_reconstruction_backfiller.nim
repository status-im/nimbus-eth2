# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
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
  "Earliest slot from which the full column matrix can be served, as " &
  "extended by the reconstruction backfiller"

const
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.10/specs/fulu/das-core.md#reconstruction-and-cross-seeding
  ColumnsRequiredForReconstruction = NUMBER_OF_COLUMNS div 2

  # Idle delay when there's no slot pending reconstruction (caught up, blocked,
  # or in limited custody). Roughly one slot so we pick up a new head or newly
  # arrived columns without busy-waiting.
  IdleSleepDuration = chronos.seconds(12)

  # Brief yield between back-to-back reconstructions so the taskpool and
  # other duties (sig verification, gossip) aren't fully starved.
  WorkYieldDuration = chronos.milliseconds(50)

type
  SlotRecon {.pure.} = enum
    ## Outcome of inspecting/reconstructing a single slot (see `processSlot`).
    Unknown   ## Recoverable failure (e.g. recovery errored); retry on a later
              ## pass.
    TooFew    ## Block has blobs but <64 columns present — cannot recover yet.
    Servable  ## Slot can be served with the full matrix: all 128 columns are
              ## present (original or reconstructed), or it legitimately carries
              ## none — an empty slot or a block with zero blob commitments.
              ## The backfiller treats both the same: nothing left to do.

  ColumnReconstructionBackfiller* = object
    dag: ChainDAGRef
    validatorCustody: ValidatorCustodyRef
    taskpool: Taskpool
    # Reconstruction progress as O(1) slot cursors (no per-slot map). The
    # established, fully-servable run is the contiguous range
    # `[runBottom..runTop]`; `frontier` is the slot currently being worked.
    runBottom: Slot
      ## Durable bottom of the servable run; drives `dag.eaSlot`. Its finalized
      ## part is immutable, so it survives reorgs and Limited-custody spells.
      ## `FAR_FUTURE_SLOT` = empty run.
    runTop: Slot
      ## Top of the servable run; `== head` once caught up, lower while a gap
      ## above it is being refilled. `FAR_FUTURE_SLOT` = empty run.
    frontier: Slot
      ## Slot under reconstruction: head-first while a gap above `runTop` is
      ## refilled, then below `runBottom` to extend history. `FAR_FUTURE_SLOT`
      ## = idle (nothing to do).
    frontierBlocked: bool
      ## `frontier` is `TooFew`; idle until `onColumnsStored` re-arms it.
    lastHeadRoot: Eth2Digest
      ## Previous canonical head, to distinguish an extension from a reorg.

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
    runBottom: FAR_FUTURE_SLOT,
    runTop: FAR_FUTURE_SLOT,
    frontier: FAR_FUTURE_SLOT)

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

func servableBottom(self: ColumnReconstructionBackfillerRef): Slot =
  ## Earliest slot of the contiguous servable-from-head run. While a gap above
  ## `runTop` is being refilled only `[frontier+1..head]` connects to the head;
  ## the run below the gap does not, so it must not be advertised yet.
  let head = self.dag.head.slot
  if self.runTop == FAR_FUTURE_SLOT:
    head + 1
  elif self.runTop >= head:
    self.runBottom
  else:
    self.frontier + 1

proc updateEarliestAvailableSlot(self: ColumnReconstructionBackfillerRef) =
  ## Advertise the earliest slot from which we can serve the full column matrix.
  ## Set both ways: a reorg that breaks the trail retracts the advertisement
  ## instead of over-claiming slots we can no longer serve.
  ## https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/fulu/p2p-interface.md#status-v2
  let bottom = self.servableBottom()
  if bottom == self.dag.eaSlot:
    return
  self.dag.eaSlot = bottom
  beacon_column_reconstruction_earliest_available_slot.set(int64(bottom))
  debug "Updated earliest available slot",
    eaSlot = bottom, head = self.dag.head.slot

func onColumnsStored*(
    self: ColumnReconstructionBackfillerRef, slot: Slot) =
  ## Event hook invoked when data columns are newly persisted for `slot`
  ## (see `BlockProcessor.onDataColumnsStored`).
  ##
  ## At most one slot — `frontier` — is ever blocked on `TooFew` at a time, and
  ## gossip only ever delivers columns for that slot or newer, never backfilling
  ## below it. So an arrival on exactly `frontier` is the only one that can lift
  ## the block; clear it and the next pass re-counts. Arrivals elsewhere need no
  ## action: the frontier re-reads the database when it descends to them.
  if self.frontierBlocked and slot == self.frontier:
    self.frontierBlocked = false

proc existingColumns(
    db: BeaconChainDB,
    consensusFork: ConsensusFork,
    blockRoot: Eth2Digest
): ColumnMap =
  ## The columns currently persisted for `blockRoot`. Early exit as soon as too few
  ## columns remain for reconstruction to ever be possible, so the returned set
  ## is exhaustive only when it holds at least `ColumnsRequiredForReconstruction`
  ## columns; below that the outcome is "too few" regardless of the exact set,
  ## and the caller only checks the count.
  var present: ColumnMap
  for i in 0'u64 ..< NUMBER_OF_COLUMNS.uint64:
    if db.containsDataColumnSidecar(consensusFork, blockRoot, i):
      present.incl(i)
    let remaining = NUMBER_OF_COLUMNS - int(i) - 1  # columns not yet looked up
    if present.len + remaining < ColumnsRequiredForReconstruction:
      break
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

  let startTime = Moment.now()
  let recovered = (await recover_cells_and_proofs_parallel(
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
    slot: Slot): Future[SlotRecon] {.async: (raises: [CancelledError]).} =
  ## Resolve, and where possible achieve, the servable state of `slot` on the
  ## *current* canonical chain. The canonical block is read fresh each call, so
  ## a reorg that re-mapped this slot is handled implicitly.
  let blockFork = self.dag.cfg.consensusForkAtEpoch(slot.epoch)
  static: doAssert high(ConsensusFork) == ConsensusFork.Heze,
    "review whether the new fork's data columns are reconstructable here"
  if blockFork < ConsensusFork.Fulu:
    return SlotRecon.Servable

  let columnFork =
    if blockFork >= ConsensusFork.Gloas: ConsensusFork.Gloas
    else: ConsensusFork.Fulu

  let bsi = self.dag.getBlockIdAtSlot(slot).valueOr:
    return SlotRecon.Servable

  if not bsi.isProposed():
    return SlotRecon.Servable

  let
    blockRoot = bsi.bid.root
    have = existingColumns(self.dag.db, columnFork, blockRoot)

  if have.lenu64 == NUMBER_OF_COLUMNS:
    return SlotRecon.Servable

  let count = have.len
  if count == 0:
    # Distinguish "a block having zero blobs" from "no/below
    # threshold columns were found" — only the latter is a reconstruction miss.
    let forked = self.dag.getForkedBlock(bsi.bid).valueOr:
      return SlotRecon.Servable
    var blockHadBlobs = false
    withBlck(forked):
      when consensusFork >= ConsensusFork.Gloas:
        # [Modified in Gloas:EIP7732] commitments live under the payload bid.
        blockHadBlobs = forkyBlck.message.body
          .signed_execution_payload_bid.message.blob_kzg_commitments.len > 0
      elif consensusFork == ConsensusFork.Fulu:
        blockHadBlobs = forkyBlck.message.body.blob_kzg_commitments.len > 0
    return if blockHadBlobs: SlotRecon.TooFew else: SlotRecon.Servable

  if count < ColumnsRequiredForReconstruction:
    return SlotRecon.TooFew

  # On reconstruction failure `reconstructSlot` returns `Unknown`, leaving the
  # slot eligible for a later retry.
  if columnFork == ConsensusFork.Fulu:
    await self.reconstructSlot(slot, blockRoot, have, fulu.DataColumnSidecar)
  else:
    debugHezeComment "need to confirm Heze data columns stay identical to Gloas"
    await self.reconstructSlot(slot, blockRoot, have, gloas.DataColumnSidecar)

proc reconcileHead(
    self: ColumnReconstructionBackfillerRef,
    head: Slot, headRoot: Eth2Digest, finalized: Slot) =
  ## Handle the head moving: restart filling from the new head downwards.
  ## If the head just extended the same chain, the whole run is still good.
  ## If it was a reorg, only slots after the finalized checkpoint can have
  ## changed, so we throw away the run above finalized and refill it; the
  ## finalized part below never changes and is reused as-is.
  if headRoot == self.lastHeadRoot:
    return
  let extension =
    # An extension is a head whose predecessor is its ancestor; if the old head
    # is already gone (finalized away), any divergence is at/below finalized,
    # which the clamp covers, so treat it as a (conservative) non-extension.
    block:
      let old = self.dag.getBlockRef(self.lastHeadRoot)
      old.isSome and old.get.isAncestorOf(self.dag.head)
  self.lastHeadRoot = headRoot
  self.frontierBlocked = false
  if not extension and self.runTop != FAR_FUTURE_SLOT and
      self.runTop > finalized:
    self.runTop = finalized
    if self.runBottom != FAR_FUTURE_SLOT and self.runBottom > self.runTop:
      # The entire established run was post-finalized — fully invalidated.
      self.runBottom = FAR_FUTURE_SLOT
      self.runTop = FAR_FUTURE_SLOT
  self.frontier = head

proc step(
    self: ColumnReconstructionBackfillerRef): Future[bool]
    {.async: (raises: [CancelledError]).} =
  ## Perform one unit of work. Returns true when a slot was reconstructed (the
  ## caller yields briefly to keep backfilling), false when there is nothing to
  ## do or the frontier is blocked (the caller idles).
  let
    head = self.dag.head.slot
    finalized = self.dag.finalizedHead.slot
    retentionStart = self.retentionStartSlot()

  self.reconcileHead(head, self.dag.head.root, finalized)

  # Follow the advancing retention floor
  if self.runBottom < retentionStart:
    self.runBottom = retentionStart
  if self.frontier < retentionStart:
    self.frontier = FAR_FUTURE_SLOT
    self.frontierBlocked = false  # the blocked slot aged out of retention

  # Step the frontier to the slot just below `anchor`, or retire it
  # (`FAR_FUTURE_SLOT`) when that next slot would fall on/under the retention
  # floor — there's nothing older left worth reconstructing.
  template descendFrontierBelow(anchor: Slot) =
    self.frontier =
      if anchor <= retentionStart: FAR_FUTURE_SLOT
      else: anchor - 1

  # Refresh the advertisement before awaiting work, so a reorg that just broke
  # the trail retracts now rather than over-claiming across the refill.
  self.updateEarliestAvailableSlot()

  if self.frontier == FAR_FUTURE_SLOT or self.frontierBlocked:
    return false

  # The descending frontier reached the established run: the gap above it is
  # filled, so extend the run to the head and continue below its bottom.
  if self.runTop != FAR_FUTURE_SLOT and self.runBottom != FAR_FUTURE_SLOT and
      self.frontier >= self.runBottom and self.frontier <= self.runTop:
    self.runTop = head
    descendFrontierBelow(self.runBottom)
    if self.frontier == FAR_FUTURE_SLOT:
      self.updateEarliestAvailableSlot()
      return false

  let state = await self.processSlot(self.frontier)
  case state
  of SlotRecon.TooFew:
    self.frontierBlocked = true
  of SlotRecon.Unknown:
    discard  # transient failure; retry next pass
  of SlotRecon.Servable:
    if self.runTop == FAR_FUTURE_SLOT:
      # establish the first run from the head
      self.runTop = head
      self.runBottom = self.frontier
    elif self.frontier > self.runTop:
      discard  # gap-fill above the island; merges on a later pass
    else:
      # extend the run into history
      self.runBottom = self.frontier
    descendFrontierBelow(self.frontier)

  self.updateEarliestAvailableSlot()
  state == SlotRecon.Servable

proc run*(
    self: ColumnReconstructionBackfillerRef) {.async: (raises: []).} =
  debug "Column reconstruction backfiller started"
  try:
    while true:
      # Custody is dynamic: a node out of sync drops to limited custody,
      # so re-check every pass and idle (rather than terminate) whenever
      # our inferred custody falls below the reconstruction threshold,
      # resuming once it climbs back. Idling leaves the cursors untouched, so we
      # resume exactly where we left off.
      if self.validatorCustody.getMap().len < ColumnsRequiredForReconstruction:
        await sleepAsync(IdleSleepDuration)
        continue

      # A blocked frontier is re-armed by `onColumnsStored` the instant more
      # columns land, so there's nothing to retry on a timer — idle until then.
      let worked = await self.step()
      await sleepAsync(if worked: WorkYieldDuration else: IdleSleepDuration)
  except CancelledError:
    discard
  debug "Column reconstruction backfiller stopped"
