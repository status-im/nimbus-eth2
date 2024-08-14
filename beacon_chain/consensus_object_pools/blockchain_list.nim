# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/sequtils, chronicles, chronos, metrics,
       ../spec/forks,
       ../[beacon_chain_file, beacon_clock]

from ./block_pools_types import VerifierError, BlockData
from ../spec/state_transition_block import validate_blobs
from std/os import `/`

export beacon_chain_file

const
  ChainFileName = "nbc.bfdata"

type
  ChainListRef* = ref object
    fileName*: string
    head*: Opt[BlockData]
    tail*: Opt[BlockData]
    handle*: Opt[ChainFileHandle]

template chainFilePath(directory: string): string =
  directory / ChainFileName

proc init*(T: type ChainListRef, directory: string): ChainListRef =
  let
    filename = directory.chainFilePath()
    res = ChainFileData.init(filename)
  if res.isErr():
    fatal "Unexpected failure while reading backfill data", reason = res.error
    quit 1
  let datares = res.get()
  if datares.isNone():
    ChainListRef(fileName: filename)
  else:
    ChainListRef(
      fileName: filename,
      head: Opt.some(datares.get().head),
      tail: Opt.some(datares.get().tail))

proc init*(T: type ChainListRef, directory: string,
           slot: Slot): Result[ChainListRef, string] =
  let
    filename = directory.chainFilePath()
    handle =
      block:
        let res = ChainFileHandle.init(filename)
        if res.isErr():
          fatal "Unexpected failure while reading backfill data",
                reason = res.error
          quit 1
        res.get()
  let offset {.used.} = ? seekForSlot(handle, slot)
  ok(ChainListRef(
    fileName: filename,
    head: Opt.some(handle.data.head),
    tail: Opt.some(handle.data.tail),
    handle: Opt.some(handle)))

proc close*(clist: ChainListRef): Result[void, string] =
  if clist.handle.isNone():
    return ok()
  ? clist.handle.get().close()
  ok()

template slot*(data: BlockData): Slot =
  data.blck.slot

template parent_root*(data: ForkedSignedBeaconBlock): Eth2Digest =
  withBlck(data): forkyBlck.message.parent_root

template parent_root*(data: BlockData): Eth2Digest =
  data.blck.parent_root()

template root*(data: BlockData): Eth2Digest =
  withBlck(data.blck): forkyBlck.root

template shortLog*(x: BlockData): string =
  let count = if x.blob.isSome(): $len(x.blob.get()) else: "0"
  $(x.slot()) & "@" & shortLog(x.parent_root()) & "#" & count

template shortLog*(x: Opt[BlockData]): string =
  if x.isNone():
    "[none]"
  else:
    shortLog(x.get())

proc checkBlobs(signedBlock: ForkedSignedBeaconBlock,
                blobsOpt: Opt[BlobSidecars]): Result[void, VerifierError] =
  withBlck(signedBlock):
    when consensusFork >= ConsensusFork.Deneb:
      if blobsOpt.isSome():
        let
          blobs = blobsOpt.get()
          commits = forkyBlck.message.body.blob_kzg_commitments.asSeq

        if len(blobs) > 0 or len(commits) > 0:
          let res =
            validate_blobs(commits, blobs.mapIt(KzgBlob(bytes: it.blob)),
                           blobs.mapIt(it.kzg_proof))
          if res.isErr():
            debug "Blob validation failed",
                  block_root = shortLog(forkyBlck.root),
                  blobs = shortLog(blobs),
                  blck = shortLog(forkyBlck.message),
                  kzg_commits = mapIt(commits, shortLog(it)),
                  signature = shortLog(forkyBlck.signature),
                  msg = res.error()
            return err(VerifierError.Invalid)
  ok()

proc addBackfillBlockData*(
    clist: ChainListRef, signedBlock: ForkedSignedBeaconBlock,
    blobsOpt: Opt[BlobSidecars]): Result[void, VerifierError] =
  doAssert(not(isNil(clist)))

  logScope:
    backfill_tail = shortLog(clist.tail)
    signed_block_slot = signedBlock.slot
    signed_block_root = signedBlock.root
    signed_block_parent_root = signedBlock.parent_root

  let
    verifyBlockTick = Moment.now()

  if clist.tail.isNone():
    block:
      let res = checkBlobs(signedBlock, blobsOpt)
      if res.isErr():
        return err(res.error)

    let
      storeBlockTick = Moment.now()
      res = store(clist.fileName, signedBlock, blobsOpt)
    if res.isErr():
      fatal "Unexpected failure while trying to store data",
            filename = clist.fileName, reason = res.error()
      quit 1

    clist.tail = Opt.some(BlockData(blck: signedBlock, blob: blobsOpt))

    if clist.head.isNone():
      clist.head = Opt.some(BlockData(blck: signedBlock, blob: blobsOpt))

    debug "Initial block backfilled",
          verify_block_duration = shortLog(storeBlockTick - verifyBlockTick),
          store_block_duration = shortLog(Moment.now() - storeBlockTick)

    return ok()

  let tail = clist.tail.get()

  if signedBlock.slot == tail.slot:
    if signedBlock.root == tail.root:
      debug "Duplicate block"
      return err(VerifierError.Duplicate)
    else:
      debug "Block from unviable fork"
      return err(VerifierError.UnviableFork)
  elif signedBlock.slot > tail.slot:
    debug "Block from unviable fork"
    return err(VerifierError.UnviableFork)

  if tail.parent_root != signedBlock.root:
    debug "Block does not match expected backfill root"
    return err(VerifierError.MissingParent)

  block:
    let res = checkBlobs(signedBlock, blobsOpt)
    if res.isErr():
      return err(res.error)

  let
    storeBlockTick = Moment.now()
    res = store(clist.fileName, signedBlock, blobsOpt)
  if res.isErr():
    fatal "Unexpected failure while trying to store data",
           filename = clist.fileName, reason = res.error()
    quit 1

  debug "Block backfilled",
        verify_block_duration = shortLog(storeBlockTick - verifyBlockTick),
        store_block_duration = shortLog(Moment.now() - storeBlockTick)

  clist.tail = Opt.some(BlockData(blck: signedBlock, blob: blobsOpt))

  ok()

proc untrustedBackfillVerifier*(
    clist: ChainListRef,
    signedBlock: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars],
    maybeFinalized: bool
): Future[Result[void, VerifierError]] {.
  async: (raises: [CancelledError], raw: true).} =
  let retFuture = newFuture[Result[void, VerifierError]]()
  retFuture.complete(clist.addBackfillBlockData(signedBlock, blobs))
  retFuture
