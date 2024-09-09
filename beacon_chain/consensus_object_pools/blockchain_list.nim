# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/sequtils, chronicles, chronos, metrics,
       ../spec/forks,
       ../[beacon_chain_file, beacon_clock],
       ../sszdump

from ./block_pools_types import VerifierError, BlockData
from ../spec/state_transition_block import validate_blobs
from std/os import `/`

export beacon_chain_file

const
  ChainFileName = "nbc.bfdata"

type
  ChainListRef* = ref object
    path*: string
    handle*: Opt[ChainFileHandle]

template chainFilePath*(directory: string): string =
  directory / ChainFileName

template filePath*(clist: ChainListRef): string =
  chainFilePath(clist.path)

proc init*(T: type ChainListRef, directory: string): ChainListRef =
  let
    filename = directory.chainFilePath()
    handle =
      if not(isFilePresent(filename)):
        Opt.none(ChainFileHandle)
      else:
        let
          flags = {ChainFileFlag.Repair}
          res = ChainFileHandle.init(filename, flags)
        if res.isErr():
          fatal "Unexpected failure while loading backfill data",
                filename = filename, reason = res.error
          quit 1
        Opt.some(res.get())
  ChainListRef(path: directory, handle: handle)

proc init*(T: type ChainListRef, directory: string,
           slot: Slot): Result[ChainListRef, string] =
  let
    flags = {ChainFileFlag.Repair, ChainFileFlag.OpenAlways}
    filename = directory.chainFilePath()
    handle = ? ChainFileHandle.init(filename, flags)
    offset {.used.} = ? seekForSlot(handle, slot)
  ok(ChainListRef(path: directory, handle: Opt.some(handle)))

proc seekForSlot*(clist: ChainListRef, slot: Slot): Result[void, string] =
  if clist.handle.isNone():
    let
      flags = {ChainFileFlag.Repair, ChainFileFlag.OpenAlways}
      filename = clist.path.chainFilePath()
      handle = ? ChainFileHandle.init(filename, flags)
    clist.handle = Opt.some(handle)

  let offset {.used.} = ? seekForSlot(clist.handle.get(), slot)
  ok()

proc close*(clist: ChainListRef): Result[void, string] =
  if clist.handle.isNone():
    return ok()
  ? clist.handle.get().close()
  ok()

proc clear*(clist: ChainListRef): Result[void, string] =
  ? clist.close()
  ? clearFile(clist.path.chainFilePath())
  clist.handle = Opt.none(ChainFileHandle)
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

func tail*(clist: ChainListRef): Opt[BlockData] =
  if clist.handle.isSome():
    clist.handle.get().data.tail
  else:
    Opt.none(BlockData)

func head*(clist: ChainListRef): Opt[BlockData] =
  if clist.handle.isSome():
    clist.handle.get().data.head
  else:
    Opt.none(BlockData)

proc setHead*(clist: ChainListRef, bdata: BlockData) =
  doAssert(clist.handle.isSome())
  var handle = clist.handle.get()
  handle.setHead(bdata)
  clist.handle = Opt.some(handle)

proc setTail*(clist: ChainListRef, bdata: BlockData) =
  doAssert(clist.handle.isSome())
  var handle = clist.handle.get()
  handle.setTail(bdata)
  clist.handle = Opt.some(handle)

proc store*(clist: ChainListRef, signedBlock: ForkedSignedBeaconBlock,
            blobs: Opt[BlobSidecars]): Result[void, string] =
  if clist.handle.isNone():
    let
      filename = clist.path.chainFilePath()
      flags = {ChainFileFlag.Repair, ChainFileFlag.OpenAlways}
      handle = ? ChainFileHandle.init(filename, flags)
    clist.handle = Opt.some(handle)
    store(handle, signedBlock, blobs, true)
  else:
    store(clist.handle.get(), signedBlock, blobs, true)

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

  let verifyBlockTick = Moment.now()

  if clist.tail.isNone():
    ? checkBlobs(signedBlock, blobsOpt)

    let storeBlockTick = Moment.now()

    store(clist, signedBlock, blobsOpt).isOkOr:
      fatal "Unexpected failure while trying to store data",
            filename = chainFilePath(clist.path), reason = error
      quit 1

    let bdata = BlockData(blck: signedBlock, blob: blobsOpt)
    clist.setTail(bdata)
    if clist.head.isNone():
      clist.setHead(bdata)

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

  ? checkBlobs(signedBlock, blobsOpt)

  let storeBlockTick = Moment.now()

  store(clist, signedBlock, blobsOpt).isOkOr:
    fatal "Unexpected failure while trying to store data",
           filename = chainFilePath(clist.path), reason = error
    quit 1

  debug "Block backfilled",
        verify_block_duration = shortLog(storeBlockTick - verifyBlockTick),
        store_block_duration = shortLog(Moment.now() - storeBlockTick)

  clist.setTail(BlockData(blck: signedBlock, blob: blobsOpt))

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
