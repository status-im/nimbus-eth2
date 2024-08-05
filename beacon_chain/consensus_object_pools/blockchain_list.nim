# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronicles, chronos, metrics,
       ../spec/forks,
       ../beacon_chain_file

from ./block_pools_types import VerifierError, BlockData, ChainListRef
from std/os import `/`

type
  ChainListRes* = Result[void, VerifierError]

const
  ChainFileName = "backfill.dat"

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

template slot*(data: BlockData): Slot =
  data.blck.slot

template parent_root*(data: BlockData): Eth2Digest =
  withBlck(data.blck): forkyBlck.message.parent_root

template shortLog*(x: BlockData): string =
  let count = if x.blob.isSome(): $len(x.blob.get()) else: "0"
  $(x.slot()) & "@" & shortLog(x.parent_root()) & count

template shortLog*(x: Opt[BlockData]): string =
  if x.isNone():
    "[none]"
  else:
    shortLog(x.get())

proc addBackfillBlockData*(
    clist: ChainListRef, signedBlock: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars]): Result[void, VerifierError] =
  doAssert(not(isNil(clist)))

  logScope:
    backfill_tail = shortLog(clist.tail)
    slot = signedBlock.slot
    signed_block = shortLog(signedBlock)

  if clist.tail.isNone():
    let
      storeBlockTick = Moment.now()
      res = store(clist.fileName, signedBlock, blobs)
    if res.isErr():
      fatal "Unexpected failure while trying to store data",
            filename = clist.fileName, reason = res.error()
      quit 1
    clist.tail = Opt.some(BlockData(blck: signedBlock, blob: blobs))

    if clist.head.isNone():
      clist.head = Opt.some(BlockData(blck: signedBlock, blob: blobs))

    debug "Initial block backfilled",
          store_block_duration = storeBlockTick - Moment.now()

    return ok()

  if signedBlock.slot >= clist.tail.get().slot:
    debug "Block from unviable fork"
    return err(VerifierError.UnviableFork)

  if clist.tail.get().parent_root != signedBlock.root:
    debug "Block does not match expected backfill root"
    return err(VerifierError.MissingParent)

  let
    storeBlockTick = Moment.now()
    res = store(clist.fileName, signedBlock, blobs)
  if res.isErr():
    fatal "Unexpected failure while trying to store data",
           filename = clist.fileName, reason = res.error()
    quit 1

  clist.tail = Opt.some(BlockData(blck: signedBlock, blob: blobs))

  debug "Block backfilled",
        store_block_duration = storeBlockTick - Moment.now()
  ok()

# proc untrustedBackfillVerifier*(
#     clist: ChainListRef,
#     signedBlock: ForkedSignedBeaconBlock,
#     blobs: Opt[BlobSidecars],
#     maybeFinalized: bool
# ): Future[ChainListRes] {.async: (raises: [CancelledError], raw: true).} =
#   let retFuture = newFuture[ChainListRes]()
#   retFuture.complete(clist.addBackfillBlockData(signedBlock, blobs))
#   retFuture

proc untrustedBackfillVerifier*(
    clist: ChainListRef,
    signedBlock: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars],
    maybeFinalized: bool
): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError], raw: true).} =
  let retFuture = newFuture[Result[void, VerifierError]]()
  retFuture.complete(clist.addBackfillBlockData(signedBlock, blobs))
  retFuture
