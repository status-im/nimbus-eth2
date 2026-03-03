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
  ssz_serialization/[proofs, types],

  # Internals
  ../consensus_object_pools/[blob_quarantine,
     block_pools_types, block_quarantine],
  ../gossip_processing/block_processor,
  ../spec/[forks, helpers, peerdas_helpers],
  ./el_manager

type
  GetBlobsService* = object
    blockGossipBus*: AsyncEventQueue[EventBeaconBlockGossipPeerObject]
    blockProcessor*: ref BlockProcessor
    dataColumnQuarantine*: ref ColumnQuarantine

  GetBlobsServiceRef* = ref GetBlobsService

proc new*(
    t: typedesc[GetBlobsServiceRef],
    blockGossipBus: AsyncEventQueue[EventBeaconBlockGossipPeerObject],
    blockProcessor: ref BlockProcessor,
    dataColumnQuarantine: ref ColumnQuarantine
): GetBlobsServiceRef =
  GetBlobsServiceRef(
    blockGossipBus: blockGossipBus,
    blockProcessor: blockProcessor,
    dataColumnQuarantine: dataColumnQuarantine)

proc attemptGetBlobs*(
    self: GetBlobsServiceRef,
    root: Eth2Digest) {.async: (raises: [CancelledError]).}=
  let
    elManager = self.blockProcessor[].consensusManager.elManager
    quarantine = self.blockProcessor[].consensusManager.quarantine

  if (let o = quarantine[].popSidecarless(root); o.isSome):
    let columnlessBlock = o.get()
    withBlck(columnlessBlock):
      debugGloasComment ""
      when consensusFork == ConsensusFork.Fulu:
        let blobsFromElOpt =
          await elManager.getBlobsV2(forkyBlck)
        if blobsFromElOpt.isSome():
          let blobsEl = blobsFromElOpt.get()
          # check lengths of blobs with KZG commitments of the signed block
          if blobsEl.len == forkyBlck.message.body.blob_kzg_commitments.len:
            # we have received all columns from the EL
            # hence we can safely remove the columnless block from quarantine
            var flat_proof = newSeqOfCap[kzg.KzgProof](blobsEl.len * fulu_preset.CELLS_PER_EXT_BLOB)
            for item in blobsEl:
              for proof in item.proofs:
                flat_proof.add kzg.KzgProof(bytes: proof.data)
            let recovered_columns = assemble_data_column_sidecars(
              forkyBlck,
              blobsEl.mapIt(kzg.KzgBlob(bytes: it.blob.data)),
              flat_proof)
            # Send notification to event stream
            # and add these columns to column quarantine
            const MaxColsPerPut = (NUMBER_OF_COLUMNS div 2) + 1
            var batch =
              newSeqOfCap[ref fulu.DataColumnSidecar](MaxColsPerPut)

            for col in recovered_columns:
              if col.index notin self.dataColumnQuarantine[].custodyColumns:
                continue
              batch.add newClone(col)
              if batch.len == MaxColsPerPut:
                break

            if batch.len > 0:
              debug "Added data columns from EL blobpool to quarantine",
                root = forkyBlck.root
              self.dataColumnQuarantine[].put(forkyBlck.root, batch)

              let sidecarsOpt =
                self.dataColumnQuarantine[].popSidecars(forkyBlck.root)

              self.blockProcessor.enqueueBlock(MsgSource.gossip, forkyBlck, sidecarsOpt)
            else:
              # Something went wrong while assembling columns, push the columnless block
              # back into quarantine
              quarantine[].addSidecarless(forkyBlck)

proc run*(self: GetBlobsServiceRef) {.async: (raises: []).} =
  let ticket = self.blockGossipBus.register()
  debug "Engine GetBlobs service started"
  try:
    while true:
      let events = await self.blockGossipBus.waitEvents(ticket)
      for event in events:
        withBlck(event.blck):
          debugGloasComment ""
          when consensusFork == ConsensusFork.Fulu:
            await self.attemptGetBlobs(forkyBlck.root)
          else:
            discard
  except AsyncEventQueueFullError:
    raiseAssert "Unlimited AsyncEventQueue should not raise exception"
  except CancelledError:
    discard
  debug "Engine GetBlobs service stopped"
