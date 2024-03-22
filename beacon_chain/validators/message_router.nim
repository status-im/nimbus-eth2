import
  stew/results,
  chronos,
  chronicles
import ".."/spec/forks

type
  BlobSidecar = int
  BlobSidecars = seq[ref BlobSidecar]
  VerifierError {.pure.} = enum
    Invalid
    MissingParent
    UnviableFork
    Duplicate

from ".."/consensus_object_pools/block_dag import BlockRef, init
import ".."/spec/digest
import ".."/spec/datatypes/base
func getBlockRef(root: Eth2Digest): Opt[BlockRef] =
  let newRef = BlockRef.init(
    root,
    0.Slot)
  return ok(newRef)
from ".."/spec/datatypes/phase0 import shortLog

proc addBlock(
    blck: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars], maybeFinalized = false,
    validationDur = Duration()): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
  return ok()
type RouteBlockResult = Result[Opt[BlockRef], string]
proc routeSignedBeaconBlock*(
    blck: ForkySignedBeaconBlock,
    blobsOpt: Opt[seq[BlobSidecar]]):
    Future[RouteBlockResult] {.async: (raises: [CancelledError]).} =
  block:
    when typeof(blck).kind >= ConsensusFork.Deneb:
      if blobsOpt.isSome:
        let blobs = blobsOpt.get()
        let kzgCommits = blck.message.body.blob_kzg_commitments.asSeq
        if blobs.len > 0 or kzgCommits.len > 0:
          if false:
            warn "blobs failed validation",
              blockRoot = shortLog(blck.root),
              blobs = shortLog(blobs),
              blck = shortLog(blck.message),
              signature = shortLog(blck.signature),
              msg = ""
            return err("")

  var blobRefs = Opt.none(BlobSidecars)
  let added = await addBlock(
    ForkedSignedBeaconBlock.init(blck), blobRefs)

  if added.isErr():
    return if added.error() != VerifierError.Duplicate:
      warn "Unable to add routed block to block pool"
      ok(Opt.none(BlockRef))
    else:
      # If it's duplicate, there's an existing BlockRef to return. The block
      # shouldn't be finalized already because that requires a couple epochs
      # before occurring, so only check non-finalized resolved blockrefs.
      if false:
        warn "Unable to add routed duplicate block to block pool"
      ok(Opt.none(BlockRef))


  let blockRef = getBlockRef(default(Eth2Digest))
  if blockRef.isErr:
    warn "Block finalised while waiting for block processor"
  ok(blockRef)
