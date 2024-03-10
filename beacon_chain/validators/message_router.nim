{.push raises: [].}

import
  stew/results,
  std/sequtils,
  chronos,
  chronicles,
  ../spec/network,
  ./activity_metrics,
  ../spec/datatypes/deneb
from  ../spec/state_transition_block import validate_blobs

type
  BlobSidecars* = seq[ref BlobSidecar]
  MessageRouter* = object

from ".."/consensus_object_pools/block_dag import BlockRef
from ".."/consensus_object_pools/block_pools_types import ChainDAGRef, VerifierError
import ".."/spec/forks


proc addBlock*(
    #self: var BlockProcessor,
    blck: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars], maybeFinalized = false,
    validationDur = Duration()): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
  return ok()
type RouteBlockResult = Result[Opt[BlockRef], string]
proc routeSignedBeaconBlock*(
    router: ref MessageRouter, blck: ForkySignedBeaconBlock,
    blobsOpt: Opt[seq[BlobSidecar]], dag: ChainDAGRef):
    Future[RouteBlockResult] {.async: (raises: [CancelledError]).} =
  block:
    when typeof(blck).kind >= ConsensusFork.Deneb:
      if blobsOpt.isSome:
        let blobs = blobsOpt.get()
        let kzgCommits = blck.message.body.blob_kzg_commitments.asSeq
        if blobs.len > 0 or kzgCommits.len > 0:
          let res = validate_blobs(kzgCommits, blobs.mapIt(it.blob),
                                   blobs.mapIt(it.kzg_proof))
          if res.isErr():
            warn "blobs failed validation",
              blockRoot = shortLog(blck.root),
              blobs = shortLog(blobs),
              blck = shortLog(blck.message),
              signature = shortLog(blck.signature),
              msg = res.error()
            return err(res.error())

  let
    delay = 0
    # The block (and blobs, if present) passed basic gossip validation
    # - we can "safely" broadcast it now. In fact, per the spec, we
    # should broadcast it even if it later fails to apply to our
    # state.

  var blobRefs = Opt.none(BlobSidecars)
  let added = await addBlock(
    ForkedSignedBeaconBlock.init(blck), blobRefs)

  # The boolean we return tells the caller whether the block was integrated
  # into the chain
  if added.isErr():
    return if added.error() != VerifierError.Duplicate:
      warn "Unable to add routed block to block pool",
        blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
        signature = shortLog(blck.signature), err = added.error()
      ok(Opt.none(BlockRef))
    else:
      # If it's duplicate, there's an existing BlockRef to return. The block
      # shouldn't be finalized already because that requires a couple epochs
      # before occurring, so only check non-finalized resolved blockrefs.
      let blockRef = dag.getBlockRef(blck.root)
      if blockRef.isErr:
        warn "Unable to add routed duplicate block to block pool",
          blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
          signature = shortLog(blck.signature), err = added.error()
      ok(blockRef)


  let blockRef = dag.getBlockRef(blck.root)
  if blockRef.isErr:
    warn "Block finalised while waiting for block processor",
      blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
      signature = shortLog(blck.signature)
  ok(blockRef)
