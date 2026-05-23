# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Standard library
  std/[sequtils, sets],

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

declareCounter beacon_engine_getblobs_requests_total,
  "Total engine_getBlobs invocations issued by the sidecarless retrieval service"

declareCounter beacon_engine_getblobs_hits_total,
  "engine_getBlobs invocations that returned every blob referenced by the block"

declareGauge beacon_engine_getblobs_slot_hit_rate,
  "engine_getBlobs hit rate (0..1) for the most recently completed slot with at least one request"

type
  GetBlobsService* = object
    blockGossipBus*: AsyncEventQueue[EventBeaconBlockGossipPeerObject]
    fuluColumnSidecarBus*: AsyncEventQueue[ref fulu.DataColumnSidecar]
    blockProcessor*: ref BlockProcessor
    dataColumnQuarantine*: ref ColumnQuarantine
    validatorCustody*: ValidatorCustodyRef
    network*: Eth2Node
    # Per-slot engine_getBlobs accounting. `slotInFlight` is the slot whose
    # counts are currently accumulating; when a request lands for a different
    # slot we flush the previous slot's ratio to the gauge and reset.
    slotInFlight: Slot
    slotRequests: uint64
    slotHits: uint64
    # Roots for which the column-first path has already invoked the EL.
    # Bounds the per-block fan-out: each custody column arriving via gossip
    # would otherwise trigger a redundant getBlobsV2 roundtrip.
    columnFirstFetched: HashSet[Eth2Digest]

  GetBlobsServiceRef* = ref GetBlobsService

proc new*(
    t: typedesc[GetBlobsServiceRef],
    blockGossipBus: AsyncEventQueue[EventBeaconBlockGossipPeerObject],
    fuluColumnSidecarBus: AsyncEventQueue[ref fulu.DataColumnSidecar],
    blockProcessor: ref BlockProcessor,
    dataColumnQuarantine: ref ColumnQuarantine,
    validatorCustody: ValidatorCustodyRef,
    network: Eth2Node
): GetBlobsServiceRef =
  GetBlobsServiceRef(
    blockGossipBus: blockGossipBus,
    fuluColumnSidecarBus: fuluColumnSidecarBus,
    blockProcessor: blockProcessor,
    dataColumnQuarantine: dataColumnQuarantine,
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

proc redistributeColumns(
    self: GetBlobsServiceRef,
    columns: fulu.DataColumnSidecars,
    skipIndex = Opt.none(ColumnIndex)
) {.async: (raises: [CancelledError]).} =
  ## Publish each reconstructed column to its respective gossip subnet.
  ## `skipIndex` lets the column-first path avoid re-publishing the column
  ## that already arrived via gossip.
  var workers = newSeqOfCap[Future[SendResult]](columns.len)
  for col in columns:
    if skipIndex.isSome and col[].index == skipIndex.get():
      continue
    let subnet = compute_subnet_for_data_column_sidecar(col[].index)
    workers.add self.network.broadcastDataColumnSidecar(subnet, col)
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
      # If the column-first path already populated quarantine for this root,
      # skip the EL fetch and enqueue with the existing columns.
      if forkyBlck.root in self.columnFirstFetched:
        let sidecarsOpt =
          self.dataColumnQuarantine[].popSidecars(forkyBlck.root)
        if sidecarsOpt.isSome():
          if not quarantine[].removeSidecarless(forkyBlck.root):
            return
          debug "Added data columns from EL blobpool to quarantine",
            root = forkyBlck.root, slot = forkyBlck.message.slot
          self.columnFirstFetched.excl(forkyBlck.root)
          self.blockProcessor.enqueueBlock(
            MsgSource.gossip, forkyBlck, sidecarsOpt)
          return
        # Columns vanished (pruned?) — fall through to EL fetch as fallback.

      let blobsEl = (await elManager.getBlobsV2(forkyBlck)).valueOr:
        self.recordEngineGetBlobs(forkyBlck.message.slot, hit = false)
        return
      # check lengths of blobs with KZG commitments of the signed block
      if blobsEl.len != forkyBlck.message.body.blob_kzg_commitments.len:
        self.recordEngineGetBlobs(forkyBlck.message.slot, hit = false)
        return
      self.recordEngineGetBlobs(forkyBlck.message.slot, hit = true)

      var flat_proof = newSeqOfCap[kzg.KzgProof](
        blobsEl.len * fulu_preset.CELLS_PER_EXT_BLOB)
      for item in blobsEl:
        for proof in item.proofs:
          flat_proof.add kzg.KzgProof(bytes: proof.data)
      let recovered_columns = assemble_data_column_sidecars(
        forkyBlck,
        blobsEl.mapIt(kzg.KzgBlob(bytes: it.blob.data)),
        flat_proof)

      # Redistribute every reconstructed column to its subnet before any
      # custody-based filtering — peers on subnets we don't custody still
      # need them.
      await self.redistributeColumns(recovered_columns)

      # Keep only the recovered columns we custody; leave the block in
      # sidecarless if none match so gossip or other mechanisms can still
      # make use of it.
      let custodyMap = self.validatorCustody.getMap()
      var batch = newSeqOfCap[ref fulu.DataColumnSidecar](len(custodyMap))
      for col in recovered_columns:
        if col[].index in custodyMap:
          batch.add col

      if batch.len == 0:
        return

      # Claim the block now that we are committed to enqueueing it. If it
      # was already removed in the meantime (e.g. gossip delivered sidecars
      # during our await), another path owns it — abandon silently.
      if not quarantine[].removeSidecarless(root):
        return

      debug "Added data columns from EL blobpool to quarantine",
        root = forkyBlck.root,
        slot = forkyBlck.message.slot,
        batch_len = batch.len
      self.dataColumnQuarantine[].put(forkyBlck.root, batch)

      let sidecarsOpt = self.dataColumnQuarantine[].popSidecars(forkyBlck.root)

      self.blockProcessor.enqueueBlock(MsgSource.gossip, forkyBlck, sidecarsOpt)
    elif consensusFork == ConsensusFork.Gloas:
      debugGloasComment "EL engine_getBlobs dispatch not yet wired for Gloas"
    elif consensusFork == ConsensusFork.Heze:
      debugHezeComment "EL engine_getBlobs dispatch not yet wired for Heze"
    else:
      discard

proc attemptGetBlobsFromColumn*(
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

  let blobsEl = (await elManager.getBlobsV2(sidecar[].kzg_commitments)).valueOr:
    self.recordEngineGetBlobs(slot, hit = false)
    return
  if blobsEl.len != sidecar[].kzg_commitments.len:
    self.recordEngineGetBlobs(slot, hit = false)
    return
  self.recordEngineGetBlobs(slot, hit = true)

  var flat_proof = newSeqOfCap[kzg.KzgProof](
    blobsEl.len * fulu_preset.CELLS_PER_EXT_BLOB)
  for item in blobsEl:
    for proof in item.proofs:
      flat_proof.add kzg.KzgProof(bytes: proof.data)

  let recovered_columns = assemble_data_column_sidecars(
    sidecar[].signed_block_header,
    sidecar[].kzg_commitments,
    sidecar[].kzg_commitments_inclusion_proof,
    blobsEl.mapIt(kzg.KzgBlob(bytes: it.blob.data)),
    flat_proof)

  # Redistribute reconstructed columns to their subnets. Skip the trigger
  # column: it already reached us via gossip and was published by its
  # originator, so re-broadcasting it is wasted work (gossipsub would
  # dedupe at peers anyway).
  await self.redistributeColumns(
    recovered_columns, skipIndex = Opt.some(sidecar[].index))

  let custodyMap = self.validatorCustody.getMap()
  var batch = newSeqOfCap[ref fulu.DataColumnSidecar](len(custodyMap))
  for col in recovered_columns:
    if col.index in custodyMap:
      batch.add newClone(col)

  if batch.len == 0:
    return

  debug "Added data columns from EL blobpool to quarantine (column-first)",
    root = block_root,
    slot = slot,
    batch_len = batch.len
  self.dataColumnQuarantine[].put(block_root, batch)
  # Mark only after a successful put so failed attempts can be retried by
  # subsequent column arrivals for the same root.
  self.columnFirstFetched.incl(block_root)

proc consumeBlockGossip(
    self: GetBlobsServiceRef) {.async: (raises: []).} =
  let ticket = self.blockGossipBus.register()
  try:
    while true:
      let events = await self.blockGossipBus.waitEvents(ticket)
      for event in events:
        withBlck(event.blck):
          when consensusFork >= ConsensusFork.Fulu:
            await self.attemptGetBlobs(forkyBlck.root)
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
