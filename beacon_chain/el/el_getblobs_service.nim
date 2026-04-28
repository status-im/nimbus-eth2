# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Standard library
  std/sequtils,

  # Status libraries
  chronicles,
  chronos,
  kzg4844/kzg,
  metrics,
  ssz_serialization/[proofs, types],

  # Internals
  ../consensus_object_pools/[blob_quarantine,
     block_pools_types, block_quarantine],
  ../gossip_processing/block_processor,
  ../spec/[column_map, forks, helpers, peerdas_helpers],
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
    blockProcessor*: ref BlockProcessor
    dataColumnQuarantine*: ref ColumnQuarantine
    validatorCustody*: ValidatorCustodyRef
    # Per-slot engine_getBlobs accounting. `slotInFlight` is the slot whose
    # counts are currently accumulating; when a request lands for a different
    # slot we flush the previous slot's ratio to the gauge and reset.
    slotInFlight: Slot
    slotRequests: uint64
    slotHits: uint64

  GetBlobsServiceRef* = ref GetBlobsService

proc new*(
    t: typedesc[GetBlobsServiceRef],
    blockGossipBus: AsyncEventQueue[EventBeaconBlockGossipPeerObject],
    blockProcessor: ref BlockProcessor,
    dataColumnQuarantine: ref ColumnQuarantine,
    validatorCustody: ValidatorCustodyRef
): GetBlobsServiceRef =
  GetBlobsServiceRef(
    blockGossipBus: blockGossipBus,
    blockProcessor: blockProcessor,
    dataColumnQuarantine: dataColumnQuarantine,
    validatorCustody: validatorCustody,
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

      # Keep only the recovered columns we custody; leave the block in
      # sidecarless if none match so gossip or other mechanisms can still
      # make use of it.
      let custodyMap = self.validatorCustody.getMap()
      var batch = newSeqOfCap[ref fulu.DataColumnSidecar](len(custodyMap))
      for col in recovered_columns:
        if col.index in custodyMap:
          batch.add newClone(col)

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

proc run*(self: GetBlobsServiceRef) {.async: (raises: []).} =
  let ticket = self.blockGossipBus.register()
  debug "Engine GetBlobs service started"
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
  debug "Engine GetBlobs service stopped"
