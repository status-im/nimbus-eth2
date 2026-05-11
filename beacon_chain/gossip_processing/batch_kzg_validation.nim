# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/deques,
  metrics,
  chronicles, chronos,
  ../spec/[helpers, peerdas_helpers],
  ../spec/datatypes/[fulu, gloas],
  ../consensus_object_pools/blockchain_dag,
  ./batch_validation

export batch_validation.BatchResult

logScope:
  topics = "batch_kzg_validation"

declareCounter batch_kzg_verifications,
  "Number of column-sidecar batches verified via batched KZG"
declareCounter batch_kzg_fallbacks,
  "Number of column-sidecar batches that fell back to per-sidecar KZG"
declareCounter batch_kzg_batches_skipped,
  "Number of column-sidecar batches dropped because they aged out of relevance"

const
  BatchKzgAccumTime* = 10.milliseconds
    ## Mirrors `BatchAttAccumTime` from BLS batching: how long the loop waits
    ## for more sidecars before running a batch.
  BatchKzgSize* = 64
    ## Threshold for immediate trigger of a batch verification. Each item is
    ## an entire column (many cells/proofs) so the optimal batch size is
    ## smaller than the BLS equivalent; tune as we measure.

type
  AnyDataColumnSidecar* =
    fulu.DataColumnSidecar | gloas.DataColumnSidecar

  EagerKzg* = proc(): bool {.gcsafe, raises: [].}
    ## Callback gating eager batch processing — return `true` to start a
    ## batch as soon as it is full instead of waiting out the accumulation
    ## window. Mirrors `Eager` from `batch_validation` for the BLS path.

  KzgBatchItem[T] = object
    sidecar: ref T
    fut: Future[BatchResult].Raising([CancelledError])

  KzgBatch[T] = object
    created: Moment
    blockRoot: Eth2Digest
    commitments: KzgCommitments
    items: seq[KzgBatchItem[T]]

  BatchKzg*[T] = object
    batches: Deque[ref KzgBatch[T]]
    dag: ChainDAGRef
    eager: EagerKzg
    pruneTime: Moment
    processor: Future[void].Raising([CancelledError])

proc new*[T: AnyDataColumnSidecar](
    R: type BatchKzg[T], dag: ChainDAGRef, eager: EagerKzg
): ref BatchKzg[T] =
  (ref BatchKzg[T])(
    dag: dag,
    eager: eager,
    pruneTime: Moment.now())

func full[T](batch: KzgBatch[T]): bool =
  batch.items.len >= BatchKzgSize

func half[T](batch: KzgBatch[T]): bool =
  batch.items.len >= (BatchKzgSize div 2)

proc complete[T](item: var KzgBatchItem[T], r: BatchResult) =
  if item.fut != nil:
    item.fut.complete(r)
    item.fut = nil

proc skip[T](batch: var KzgBatch[T]) =
  for it in batch.items.mitems():
    it.complete(BatchResult.Timeout)

proc completeAll[T](batch: var KzgBatch[T], r: BatchResult) =
  for it in batch.items.mitems():
    it.complete(r)

func sidecarBlockRoot(sidecar: fulu.DataColumnSidecar): Eth2Digest =
  hash_tree_root(sidecar.signed_block_header.message)

func sidecarBlockRoot(sidecar: gloas.DataColumnSidecar): Eth2Digest =
  sidecar.beacon_block_root

proc lookupCommitments(
    dag: ChainDAGRef, sidecar: fulu.DataColumnSidecar
): Opt[KzgCommitments] =
  # Fulu sidecars carry their own commitments — no block lookup required.
  Opt.some(sidecar.kzg_commitments)

proc lookupCommitments(
    dag: ChainDAGRef, sidecar: gloas.DataColumnSidecar
): Opt[KzgCommitments] =
  let
    bsi = dag.getBlockIdAtSlot(sidecar.slot).valueOr:
      return Opt.none(KzgCommitments)
    forkedBlock = dag.getForkedBlock(bsi.bid).valueOr:
      return Opt.none(KzgCommitments)
  withBlck(forkedBlock):
    when consensusFork == ConsensusFork.Gloas:
      if forkyBlck.root != sidecar.beacon_block_root:
        return Opt.none(KzgCommitments)
      Opt.some(
        forkyBlck.message.body.signed_execution_payload_bid.message
          .blob_kzg_commitments)
    else:
      Opt.none(KzgCommitments)

proc processBatch[T](
    batchKzg: ref BatchKzg[T], batch: ref KzgBatch[T]
) {.async: (raises: [CancelledError]).} =
  if batch[].items.len == 0:
    return

  let
    startTick = Moment.now()
    slotDuration = batchKzg.dag.cfg.timeParams.SLOT_DURATION

  # Stale batches are dropped: callers receive Timeout (→ IGNORE) so we
  # neither relay nor descore over a verification we never finished.
  if batch[].created + slotDuration < startTick:
    if batchKzg.pruneTime + slotDuration < startTick:
      notice "KZG batch queue pruned, skipping column validation",
        batches = batchKzg.batches.len
      batchKzg.pruneTime = startTick
    batch[].skip()
    batch_kzg_batches_skipped.inc()
    return

  var sidecars = newSeqOfCap[T](batch[].items.len)
  for it in batch[].items:
    sidecars.add(it.sidecar[])

  trace "kzg batch - starting",
    items = sidecars.len, blockRoot = batch[].blockRoot
  let ok = verify_data_column_sidecar_kzg_proofs(
    sidecars, batch[].commitments).isOk

  if ok:
    batch[].completeAll(BatchResult.Valid)
    batch_kzg_verifications.inc()
  else:
    # Whole-batch verify failed; re-run per-sidecar to identify the bad
    # apple(s). Items that pass individually still ACCEPT.
    batch_kzg_fallbacks.inc()
    debug "kzg batch - failure, falling back per-sidecar",
      items = batch[].items.len
    for it in batch[].items.mitems():
      let v = verify_data_column_sidecar_kzg_proofs(
        it.sidecar[], batch[].commitments)
      it.complete(if v.isOk: BatchResult.Valid else: BatchResult.Invalid)

  trace "kzg batch - finished",
    items = batch[].items.len, ok, dur = Moment.now() - startTick

proc processLoop[T](
    batchKzg: ref BatchKzg[T]
) {.async: (raises: [CancelledError]).} =
  while batchKzg[].batches.len > 0:
    if not batchKzg[].batches.peekFirst()[].full() or
        not batchKzg[].eager():
      await sleepAsync(BatchKzgAccumTime)
      if not batchKzg[].batches.peekFirst()[].half():
        await sleepAsync(BatchKzgAccumTime div 2)

    let batch = batchKzg[].batches.popFirst()
    await batchKzg.processBatch(batch)

proc scheduleProcessor[T](batchKzg: ref BatchKzg[T]) =
  if batchKzg.processor == nil or batchKzg.processor.finished():
    batchKzg.processor = batchKzg.processLoop()

proc getBatch[T](
    batchKzg: ref BatchKzg[T], blockRoot: Eth2Digest,
    commitments: KzgCommitments
): ref KzgBatch[T] =
  # Only extend the most recently opened batch when block-root matches —
  # `verify_data_column_sidecar_kzg_proofs` needs a single commitments slice
  # per batch, so mixing roots would force per-sidecar fallback anyway.
  if batchKzg[].batches.len > 0:
    let last = batchKzg[].batches.peekLast()
    if last[].blockRoot == blockRoot and not last[].full():
      return last
  let batch = (ref KzgBatch[T])(
    created: Moment.now(),
    blockRoot: blockRoot,
    commitments: commitments)
  batchKzg[].batches.addLast(batch)
  batch

proc scheduleColumnKzgCheck*[T: AnyDataColumnSidecar](
    batchKzg: ref BatchKzg[T], sidecar: ref T
): Future[BatchResult] {.async: (raises: [CancelledError], raw: true).} =
  ## Park a sidecar onto the pending KZG batch and return a future that
  ## resolves once the batch (or a per-sidecar fallback) has verified it.
  ## Caller maps Valid → ACCEPT, Invalid → REJECT, Timeout → IGNORE.
  let fut = newFuture[BatchResult]("scheduleColumnKzgCheck")

  let blockRoot = sidecarBlockRoot(sidecar[])
  let commitmentsOpt = lookupCommitments(batchKzg.dag, sidecar[])
  if commitmentsOpt.isNone():
    # Block not (yet) available — we can't verify KZG. IGNORE so the caller
    # neither relays nor descores; the sidecar may arrive again once the
    # block is in the dag.
    fut.complete(BatchResult.Timeout)
    return fut

  let batch = batchKzg.getBatch(blockRoot, commitmentsOpt.get())
  batch[].items.add KzgBatchItem[T](sidecar: sidecar, fut: fut)
  batchKzg.scheduleProcessor()
  fut
