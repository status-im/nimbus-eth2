# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Standard library
  std/tables,

  # Status libraries
  chronicles,
  chronos,
  kzg4844/kzg,
  metrics,
  ssz_serialization/[proofs, types],

  # Internals
  ../consensus_object_pools/[
     block_pools_types, block_quarantine, column_quarantine],
  ../gossip_processing/block_processor,
  ../networking/eth2_network,
  ../spec/[column_map, forks, helpers, network, peerdas_helpers],
  ../sync/validator_custody,
  ./el_manager

from std/enumerate import enumerate
from std/sequtils import filterIt
from stew/assign2 import assign

declareCounter beacon_engine_getblobs_requests_total,
  "Total engine_getBlobs invocations issued by the sidecarless retrieval service"

declareCounter beacon_engine_getblobs_hits_total,
  "engine_getBlobs invocations that returned every blob referenced by the block"

declareGauge beacon_engine_getblobs_slot_hit_rate,
  "engine_getBlobs hit rate (0..1) for the most recently completed slot with at least one request"

declareCounter beacon_engine_getblobs_skipped_total,
  "engine_getBlobs invocations not issued because an in-flight fetch for the same block root already retrieved the blobs"

type
  GetBlobsService* = object
    blockGossipBus: AsyncEventQueue[EventBeaconBlockGossipPeerObject]
    fuluColumnSidecarBus: AsyncEventQueue[ref fulu.DataColumnSidecar]
    blockProcessor: ref BlockProcessor
    fuluColumnQuarantine: ref FuluColumnQuarantine
    gloasColumnQuarantine: ref GloasColumnQuarantine
    validatorCustody: ValidatorCustodyRef
    network: Eth2Node
    # Per-slot engine_getBlobs accounting. `slotInFlight` is the slot whose
    # counts are currently accumulating; when a request lands for a different
    # slot we flush the previous slot's ratio to the gauge and reset.
    slotInFlight: Slot
    slotRequests: uint64
    slotHits: uint64
    # Roots for which the column-first path has already invoked the EL.
    # Bounds the per-block fan-out: each custody column arriving via gossip
    # would otherwise trigger a redundant getBlobsV2 roundtrip.
    columnFirstFetched: Table[Eth2Digest, Slot]
    # Roots with an EL fetch in flight, keeping at most one engine_getBlobs
    # request per root outstanding across both paths. `columnFirstFetched`
    # cannot do this: it is only written once the roundtrip completes, so
    # both paths read it as empty for the duration of the request.
    elFetchInFlight: Table[Eth2Digest, Future[void]]

  GetBlobsServiceRef* = ref GetBlobsService

proc new*(
    t: typedesc[GetBlobsServiceRef],
    blockGossipBus: AsyncEventQueue[EventBeaconBlockGossipPeerObject],
    fuluColumnSidecarBus: AsyncEventQueue[ref fulu.DataColumnSidecar],
    blockProcessor: ref BlockProcessor,
    fuluColumnQuarantine: ref FuluColumnQuarantine,
    gloasColumnQuarantine: ref GloasColumnQuarantine,
    validatorCustody: ValidatorCustodyRef,
    network: Eth2Node
): GetBlobsServiceRef =
  GetBlobsServiceRef(
    blockGossipBus: blockGossipBus,
    fuluColumnSidecarBus: fuluColumnSidecarBus,
    blockProcessor: blockProcessor,
    fuluColumnQuarantine: fuluColumnQuarantine,
    gloasColumnQuarantine: gloasColumnQuarantine,
    validatorCustody: validatorCustody,
    network: network,
    slotInFlight: FAR_FUTURE_SLOT)

proc recordEngineGetBlobs(
    self: GetBlobsServiceRef, slot: Slot, hit: bool) =
  ## Record a single engine_getBlobs request + outcome against per-slot
  ## accounting. On slot transition, flushes the previous slot's hit rate to
  ## the gauge before counting the new request.
  if slot != self.slotInFlight:
    if self.slotRequests > 0:
      beacon_engine_getblobs_slot_hit_rate.set(
        self.slotHits.float / self.slotRequests.float)
    self.slotInFlight = slot
    self.slotRequests = 0
    self.slotHits = 0
  inc self.slotRequests
  beacon_engine_getblobs_requests_total.inc()
  if hit:
    inc self.slotHits
    beacon_engine_getblobs_hits_total.inc()

proc markFetchInFlight(
    self: GetBlobsServiceRef, root: Eth2Digest): Future[void] =
  ## Claim `root` for an EL fetch. Hand the marker to `clearFetchInFlight`
  ## once the fetch settles.
  let marker = newFuture[void]("getBlobsService.elFetch")
  self.elFetchInFlight[root] = marker
  marker

proc clearFetchInFlight(
    self: GetBlobsServiceRef, root: Eth2Digest, marker: Future[void]) =
  ## Release the claim on `root` and wake anyone waiting on it.
  self.elFetchInFlight.del(root)
  marker.complete()

proc redistributeColumns[T: fulu.DataColumnSidecar | gloas.DataColumnSidecar](
    self: GetBlobsServiceRef,
    columns: seq[ref T]
) {.async: (raises: [CancelledError]).} =
  ## Publish each column to its respective gossip subnet.
  var workers = newSeqOfCap[Future[SendResult]](columns.len)
  for col in columns:
    let subnet = compute_subnet_for_data_column_sidecar(col[].index)
    workers.add self.network.broadcastDataColumnSidecar(subnet, col)
    await sleepAsync(5.milliseconds)
  let results = await allFinished(workers)
  for r in results:
    doAssert r.finished()
    if r.failed():
      debug "Failed to redistribute data column from EL blobpool",
        error = r.error[].msg

proc attemptGetBlobs*(
    self: GetBlobsServiceRef,
    root: Eth2Digest) {.async: (raises: [CancelledError]).} =
  let
    elManager = self.blockProcessor[].consensusManager.elManager
    quarantine = self.blockProcessor[].consensusManager.quarantine

  # Peek the sidecarless block instead of popping: we must not hold the block
  # outside the quarantine across an async yield, or sidecars arriving via
  # gossip during the EL roundtrip will fail to find a sidecarless entry to
  # enqueue against. The block is only claimed (popped) once we are
  # committed to enqueueing it below.
  let sidecarlessBlock = quarantine[].getSidecarless(root).valueOr:
    return

  withBlck(sidecarlessBlock):
    when consensusFork == ConsensusFork.Fulu:
      # A column sidecar arriving ahead of the block may have a fetch for this
      # root in flight already; wait for it instead of asking the EL for the
      # same blobs twice. `join`, so cancelling here leaves that fetch alone.
      let inFlight = self.elFetchInFlight.getOrDefault(forkyBlck.root)
      if inFlight != nil:
        await inFlight.join()
        # Gossip columns completing during the wait can claim the block.
        if quarantine[].getSidecarless(forkyBlck.root).isNone():
          return

      # If the column-first path already populated quarantine for this root,
      # skip the EL fetch and enqueue with the existing columns.
      if forkyBlck.root in self.columnFirstFetched:
        let sidecarsOpt =
          self.fuluColumnQuarantine[].popSidecars(forkyBlck.root)
        if sidecarsOpt.isSome():
          if not quarantine[].removeSidecarless(forkyBlck.root):
            return
          debug "Added data columns from EL blobpool to quarantine",
            root = forkyBlck.root, slot = forkyBlck.message.slot
          self.columnFirstFetched.del(forkyBlck.root)
          if inFlight != nil:
            # Waiting on that fetch is what kept us from issuing our own.
            beacon_engine_getblobs_skipped_total.inc()
          self.blockProcessor.enqueueBlock(
            MsgSource.gossip, forkyBlck, sidecarsOpt)
          return
        # Columns vanished (pruned?) — fall through to EL fetch as fallback.

      template kzg_commitments_count(): int =
        forkyBlck.message.body.blob_kzg_commitments.len

      var
        blobs: seq[kzg.KzgBlob]
        flat_proof: seq[kzg.KzgProof]

      let fetchMarker = self.markFetchInFlight(forkyBlck.root)
      defer: self.clearFetchInFlight(forkyBlck.root, fetchMarker)

      let blobsEl = (await elManager.getBlobsV2(forkyBlck)).valueOr:
        self.recordEngineGetBlobs(forkyBlck.message.slot, hit = false)
        return
      # check lengths of blobs with KZG commitments of the signed block
      if blobsEl.len != kzg_commitments_count():
        self.recordEngineGetBlobs(forkyBlck.message.slot, hit = false)
        return
      self.recordEngineGetBlobs(forkyBlck.message.slot, hit = true)

      blobs.setLen(blobsEl.len)
      flat_proof = newSeqOfCap[kzg.KzgProof](
        blobsEl.len * fulu_preset.CELLS_PER_EXT_BLOB)
      # TODO https://github.com/nim-lang/Nim/issues/25848 means that
      # enumerate(...) is required for lent to trigger
      for i, item in enumerate(blobsEl):
        assign(blobs[i].bytes, item.blob.data)
        for proof in item.proofs:
          flat_proof.add kzg.KzgProof(bytes: proof.data)

      # Keep only the recovered columns we custody; leave the block in
      # sidecarless if none match so gossip or other mechanisms can still
      # make use of it.
      let batch = assemble_data_column_sidecars(
        forkyBlck, blobs, flat_proof, self.validatorCustody.getMap())

      if batch.len == 0:
        return

      asyncSpawn self.redistributeColumns(batch.filterIt(
        not self.fuluColumnQuarantine[].hasSidecar(forkyBlck.root, it[].index)))

      # Claim the block now that we are committed to enqueueing it. If it
      # was already removed in the meantime (e.g. gossip delivered sidecars
      # during our await), another path owns it — abandon silently.
      if not quarantine[].removeSidecarless(root):
        return

      debug "Added data columns from EL blobpool to quarantine",
        root = forkyBlck.root,
        slot = forkyBlck.message.slot,
        batch_len = batch.len
      self.fuluColumnQuarantine[].put(forkyBlck.root, batch, verified = true)

      let sidecarsOpt = self.fuluColumnQuarantine[].popSidecars(forkyBlck.root)

      self.blockProcessor.enqueueBlock(MsgSource.gossip, forkyBlck, sidecarsOpt)
    elif consensusFork == ConsensusFork.Heze:
      debugHezeComment "EL engine_getBlobs dispatch not yet wired for Heze"
    else:
      discard

proc attemptGetBlobs*(
    self: GetBlobsServiceRef,
    blck: gloas.SignedBeaconBlock) {.async: (raises: [CancelledError]).} =
  ## Gloas variant: invoked directly with the gossiped block, because Gloas
  ## blocks don't sit in the sidecarless quarantine — they're enqueued
  ## immediately with `noSidecars`, and the column sidecars are needed by the
  ## envelope flow rather than by block processing. We populate
  ## `gloasColumnQuarantine` so the envelope verifier (which pops from it
  ## keyed by block_root) finds the reconstructed columns when it runs.
  let elManager = self.blockProcessor[].consensusManager.elManager

  template kzg_commitments(): auto =
    blck.message.body.signed_execution_payload_bid.message.blob_kzg_commitments

  if kzg_commitments.len == 0:
    return

  let blobsEl = (await elManager.getBlobsV2(blck)).valueOr:
    self.recordEngineGetBlobs(blck.message.slot, hit = false)
    return
  if blobsEl.len != kzg_commitments.len:
    self.recordEngineGetBlobs(blck.message.slot, hit = false)
    return
  self.recordEngineGetBlobs(blck.message.slot, hit = true)

  var
    blobs = newSeqOfCap[kzg.KzgBlob](blobsEl.len)
    flat_proof = newSeqOfCap[kzg.KzgProof](
      blobsEl.len * fulu_preset.CELLS_PER_EXT_BLOB)
  for item in blobsEl:
    blobs.add kzg.KzgBlob(bytes: item.blob.data)
    for proof in item.proofs:
      flat_proof.add kzg.KzgProof(bytes: proof.data)
  let batch = assemble_data_column_sidecars(
    blck, blobs, flat_proof, self.validatorCustody.getMap())

  if batch.len == 0:
    return

  asyncSpawn self.redistributeColumns(batch.filterIt(
    not self.gloasColumnQuarantine[].hasSidecar(blck.root, it[].index)))

  debug "Added data columns from EL blobpool to gloas quarantine",
    root = blck.root,
    slot = blck.message.slot,
    batch_len = batch.len
  self.gloasColumnQuarantine[].put(blck.root, batch, verified = true)

  # If the envelope is already orphaned waiting on sidecars, re-enqueuing the
  # payload will pop it and continue processing; otherwise this just marks
  # the envelope as missing (idempotent with the original block-time
  # enqueue).
  self.blockProcessor.enqueuePayload(blck)

proc attemptGetBlobsFromColumn(
    self: GetBlobsServiceRef,
    sidecar: ref fulu.DataColumnSidecar) {.async: (raises: [CancelledError]).} =
  ## Column-first variant: invoked when a column sidecar arrives via gossip
  ## before the block has been seen. Uses the per-column metadata
  ## (signed_block_header, kzg_commitments, kzg_commitments_inclusion_proof)
  ## to derive versioned hashes and reconstruct columns from EL blobs, then
  ## stores the recovered custody columns in the quarantine. Does NOT enqueue
  ## a block — when the block later arrives via gossip, eth2_processor will
  ## see the columns already waiting and proceed.
  let
    elManager = self.blockProcessor[].consensusManager.elManager
    quarantine = self.blockProcessor[].consensusManager.quarantine
    dag = self.blockProcessor[].consensusManager.dag

  # Prune roots whose block never showed up.
  block:
    var toDelete: seq[Eth2Digest]
    for block_root, slot in self.columnFirstFetched:
      if slot <= dag.finalizedHead.slot:
        toDelete.add block_root
    for block_root in toDelete:
      self.columnFirstFetched.del(block_root)

  let
    block_root = hash_tree_root(sidecar[].signed_block_header.message)
    slot = sidecar[].signed_block_header.message.slot

  # Dedup: only fire EL fetch once per block_root. Subsequent column
  # arrivals for the same block are no-ops on this path.
  if block_root in self.columnFirstFetched:
    return

  # If the sidecarless block is already in the block quarantine, the
  # block-first path (consumeBlockGossip - attemptGetBlobs) owns this
  # block — leave it alone.
  if quarantine[].getSidecarless(block_root).isSome():
    return

  # Claim the root before yielding, so a block arriving mid-flight waits for
  # this fetch rather than issuing an identical one. Released either way, so
  # a fetch that came up empty is still retried by later column arrivals.
  let fetchMarker = self.markFetchInFlight(block_root)
  defer: self.clearFetchInFlight(block_root, fetchMarker)

  let blobsEl = (await elManager.getBlobsV2(sidecar[].kzg_commitments)).valueOr:
    self.recordEngineGetBlobs(slot, hit = false)
    return
  if blobsEl.len != sidecar[].kzg_commitments.len:
    self.recordEngineGetBlobs(slot, hit = false)
    return
  self.recordEngineGetBlobs(slot, hit = true)

  var
    blobs = newSeqOfCap[kzg.KzgBlob](blobsEl.len)
    flat_proof = newSeqOfCap[kzg.KzgProof](
      blobsEl.len * fulu_preset.CELLS_PER_EXT_BLOB)
  for item in blobsEl:
    blobs.add kzg.KzgBlob(bytes: item.blob.data)
    for proof in item.proofs:
      flat_proof.add kzg.KzgProof(bytes: proof.data)

  let batch = assemble_data_column_sidecars(
    sidecar[].signed_block_header,
    sidecar[].kzg_commitments,
    sidecar[].kzg_commitments_inclusion_proof,
    blobs, flat_proof, self.validatorCustody.getMap())

  if batch.len == 0:
    return

  asyncSpawn self.redistributeColumns(batch.filterIt(
    not self.fuluColumnQuarantine[].hasSidecar(block_root, it[].index)))

  debug "Added data columns from EL blobpool to quarantine (column-first)",
    root = block_root,
    slot = slot,
    batch_len = batch.len
  self.fuluColumnQuarantine[].put(block_root, batch, verified = true)
  # Mark only after a successful put so failed attempts can be retried by
  # subsequent column arrivals for the same root.
  self.columnFirstFetched[block_root] = slot

proc consumeBlockGossip(
    self: GetBlobsServiceRef) {.async: (raises: []).} =
  let ticket = self.blockGossipBus.register()
  try:
    while true:
      let events = await self.blockGossipBus.waitEvents(ticket)
      for event in events:
        withBlck(event.blck):
          when consensusFork == ConsensusFork.Fulu:
            await self.attemptGetBlobs(forkyBlck.root)
          elif consensusFork == ConsensusFork.Gloas:
            await self.attemptGetBlobs(forkyBlck)
          else:
            discard
  except AsyncEventQueueFullError:
    raiseAssert "Unlimited AsyncEventQueue should not raise exception"
  except CancelledError:
    discard
  finally:
    self.blockGossipBus.unregister(ticket)

proc consumeColumnSidecars(
    self: GetBlobsServiceRef) {.async: (raises: []).} =
  let ticket = self.fuluColumnSidecarBus.register()
  try:
    while true:
      let events = await self.fuluColumnSidecarBus.waitEvents(ticket)
      for event in events:
        await self.attemptGetBlobsFromColumn(event)
  except AsyncEventQueueFullError:
    raiseAssert "Unlimited AsyncEventQueue should not raise exception"
  except CancelledError:
    discard
  finally:
    self.fuluColumnSidecarBus.unregister(ticket)

proc run*(self: GetBlobsServiceRef) {.async: (raises: []).} =
  debug "Engine GetBlobs service started"
  try:
    await allFutures(
      self.consumeBlockGossip(),
      self.consumeColumnSidecars())
  except CancelledError:
    discard
  debug "Engine GetBlobs service stopped"
