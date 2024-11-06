# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  results, unittest2, stew/io2, nimcrypto/hash,
  ../beacon_chain/spec/forks,
  ../beacon_chain/beacon_chain_file

template onDiskChunkSize(data: int): int =
  sizeof(ChainFileFooter) + sizeof(ChainFileHeader) + data

const
  FixtureFile =
    currentSourcePath().dirname() & DirSep & "fixtures" & DirSep &
    "bfdata-test.bin"

  Block0Root =
    "4bbd1c7468626d6520e27a534ce9f3ee305160860367431528404697c60ce222".toDigest
  Block0BlobsCount = 1
  Block0BlockChunkSize = 45127
  Block0Blob0ChunkSize = 7043
  Block1Root =
    "133a92629a94cb9664eea57a649ee2d4a16fa48cac93aa5ccc0e9df727b5d9bd".toDigest
  Block1BlobsCount = 3
  Block1BlockChunkSize = 36321
  Block1Blob0ChunkSize = 7090
  Block1Blob1ChunkSize = 7016
  Block1Blob2ChunkSize = 131886
  Block2Root =
    "f92b453230c5b1914c5b8f868bdd9692d38b5231b8e365f2b8049b1d22cca396".toDigest
  Block2BlobsCount = 3
  Block2BlockChunkSize = 36248
  Block2Blob0ChunkSize = 7090
  Block2Blob1ChunkSize = 7090
  Block2Blob2ChunkSize = 7056

  Block0FullSize = onDiskChunkSize(Block0BlockChunkSize) +
                   onDiskChunkSize(Block0Blob0ChunkSize)
  Block1FullSize = onDiskChunkSize(Block1BlockChunkSize) +
                   onDiskChunkSize(Block1Blob0ChunkSize) +
                   onDiskChunkSize(Block1Blob1ChunkSize) +
                   onDiskChunkSize(Block1Blob2ChunkSize)
  Block2FullSize = onDiskChunkSize(Block2BlockChunkSize) +
                   onDiskChunkSize(Block2Blob0ChunkSize) +
                   onDiskChunkSize(Block2Blob1ChunkSize) +
                   onDiskChunkSize(Block2Blob2ChunkSize)

type
  AutoRepairObject = object
    data: ChainFileData
    size: int64

suite "Beacon chain file test suite":
  var fixtureData: seq[byte]

  proc doAutoCheckRepairTest(id, size: int): Result[AutoRepairObject, string] =
    let path =
      block:
        let res = getTempPath().valueOr:
          return err(ioErrorMsg(error))
        res & DirSep & "tmp_" & $id & "_" & $size & ".tmp"
    discard removeFile(path)
    io2.writeFile(path, fixtureData.toOpenArray(0, size - 1)).isOkOr:
      return err(ioErrorMsg(error))
    let
      flags = {ChainFileFlag.Repair}
      fres = ? ChainFileHandle.init(path, flags)
    closeFile(fres.handle).isOkOr:
      return err(ioErrorMsg(error))
    let filesize = getFileSize(path).valueOr:
      return err(ioErrorMsg(error))
    removeFile(path).isOkOr:
      return err(ioErrorMsg(error))
    ok(AutoRepairObject(data: fres.data, size: filesize))

  template check01(adata: untyped): untyped =
    check:
      adata.data.head.isSome()
      adata.data.tail.isSome()
    let
      head = adata.data.head.get()
      tail = adata.data.tail.get()
      headRoot = withBlck(head.blck): forkyBlck.root
      tailRoot = withBlck(tail.blck): forkyBlck.root

    check:
      head.blob.isSome()
      tail.blob.isSome()
      headRoot == Block0Root
      tailRoot == Block1Root
      len(head.blob.get()) == Block0BlobsCount
      len(tail.blob.get()) == Block1BlobsCount
      adata.size == Block0FullSize + Block1FullSize

  template check0(adata: untyped): untyped =
    check:
      adata.data.head.isSome()
      adata.data.tail.isSome()
    let
      head = adata.data.head.get()
      tail = adata.data.tail.get()
      headRoot = withBlck(head.blck): forkyBlck.root
      tailRoot = withBlck(tail.blck): forkyBlck.root

    check:
      head.blob.isSome()
      tail.blob.isSome()
      headRoot == Block0Root
      tailRoot == Block0Root
      len(head.blob.get()) == Block0BlobsCount
      len(tail.blob.get()) == Block0BlobsCount
      adata.size == Block0FullSize

  test "Fixture file validation":
    check isFile(FixtureFile) == true
    fixtureData = readAllBytes(FixtureFile).valueOr:
      default(seq[byte])
    check len(fixtureData) > 0

    let hres = ChainFileHandle.init(FixtureFile, {})
    check hres.isOk()
    let handle = hres.get()
    check:
      handle.head.isSome()
      handle.tail.isSome()
    let
      head = handle.head.get()
      tail = handle.tail.get()
      headRoot = withBlck(head.blck): forkyBlck.root
      tailRoot = withBlck(tail.blck): forkyBlck.root
    check:
      head.blob.isSome()
      tail.blob.isSome()
      headRoot == Block0Root
      tailRoot == Block2Root
      len(head.blob.get()) == Block0BlobsCount
      len(tail.blob.get()) == Block2BlobsCount
    let cres = close(handle)
    check cres.isOk()

  test "Auto check/repair test (missing footer)":
    let
      hiLimit = len(fixtureData) - 1
      loLimit = len(fixtureData) - sizeof(ChainFileFooter)
    var counter = 1

    for size in countdown(hiLimit, loLimit):
      let tres = doAutoCheckRepairTest(counter, size)
      check tres.isOk()
      let adata = tres.get()
      check01(adata)
      inc(counter)

  test "Auto check/repair test (missing last chunk)":
    var size = len(fixtureData)

    block:
      size -= onDiskChunkSize(Block2Blob2ChunkSize)
      let tres = doAutoCheckRepairTest(1, size)
      check tres.isOk()
      let adata = tres.get()
      check01(adata)

    block:
      size -= onDiskChunkSize(Block2Blob1ChunkSize)
      let tres = doAutoCheckRepairTest(2, size)
      check tres.isOk()
      let adata = tres.get()
      check01(adata)

    block:
      size -= onDiskChunkSize(Block2Blob0ChunkSize)
      let tres = doAutoCheckRepairTest(3, size)
      check tres.isOk()
      let adata = tres.get()
      check01(adata)

    block:
      size -= onDiskChunkSize(Block2BlockChunkSize)
      let tres = doAutoCheckRepairTest(4, size)
      check tres.isOk()
      let adata = tres.get()
      check01(adata)

    block:
      size -= onDiskChunkSize(Block1Blob2ChunkSize)
      let tres = doAutoCheckRepairTest(5, size)
      check tres.isOk()
      let adata = tres.get()
      check0(adata)

    block:
      size -= onDiskChunkSize(Block1Blob1ChunkSize)
      let tres = doAutoCheckRepairTest(6, size)
      check tres.isOk()
      let adata = tres.get()
      check0(adata)

    block:
      size -= onDiskChunkSize(Block1Blob0ChunkSize)
      let tres = doAutoCheckRepairTest(7, size)
      check tres.isOk()
      let adata = tres.get()
      check0(adata)

    block:
      size -= onDiskChunkSize(Block1BlockChunkSize)
      let tres = doAutoCheckRepairTest(8, size)
      check tres.isOk()
      let adata = tres.get()
      check0(adata)

    block:
      size -= onDiskChunkSize(Block0Blob0ChunkSize)
      let tres = doAutoCheckRepairTest(9, size)
      check tres.isOk()
      let adata = tres.get()
      check:
        adata.data.head.isNone()
        adata.data.tail.isNone()
        adata.size == 0

    block:
      size -= onDiskChunkSize(Block0BlockChunkSize)
      let tres = doAutoCheckRepairTest(10, size)
      check tres.isOk()
      let adata = tres.get()
      check:
        adata.data.head.isNone()
        adata.data.tail.isNone()
        adata.size == 0

  test "Auto check/repair test (only header)":
    var size = len(fixtureData)

    block:
      size -= onDiskChunkSize(Block2Blob2ChunkSize)
      let tres = doAutoCheckRepairTest(1, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check01(adata)

    block:
      size -= onDiskChunkSize(Block2Blob1ChunkSize)
      let tres = doAutoCheckRepairTest(2, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check01(adata)

    block:
      size -= onDiskChunkSize(Block2Blob0ChunkSize)
      let tres = doAutoCheckRepairTest(3, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check01(adata)

    block:
      size -= onDiskChunkSize(Block2BlockChunkSize)
      let tres = doAutoCheckRepairTest(4, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check01(adata)

    block:
      size -= onDiskChunkSize(Block1Blob2ChunkSize)
      let tres = doAutoCheckRepairTest(5, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check0(adata)

    block:
      size -= onDiskChunkSize(Block1Blob1ChunkSize)
      let tres = doAutoCheckRepairTest(6, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check0(adata)

    block:
      size -= onDiskChunkSize(Block1Blob0ChunkSize)
      let tres = doAutoCheckRepairTest(7, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check0(adata)

    block:
      size -= onDiskChunkSize(Block1BlockChunkSize)
      let tres = doAutoCheckRepairTest(8, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check0(adata)

    block:
      size -= onDiskChunkSize(Block0Blob0ChunkSize)
      let tres = doAutoCheckRepairTest(9, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check:
        adata.data.head.isNone()
        adata.data.tail.isNone()
        adata.size == 0

    block:
      size -= onDiskChunkSize(Block0BlockChunkSize)
      let tres = doAutoCheckRepairTest(10, size + sizeof(ChainFileHeader))
      check tres.isOk()
      let adata = tres.get()
      check:
        adata.data.head.isNone()
        adata.data.tail.isNone()
        adata.size == 0

  test "Auto check/repair test (missing data)":
    let
      limit1 = Block0FullSize + Block1FullSize + Block2FullSize
      limit2 = Block0FullSize + Block1FullSize
      limit3 = Block0FullSize
    var
      size = len(fixtureData)
      counter = 1

    while size > 0:
      size = max(0, size - 4096)
      let tres = doAutoCheckRepairTest(counter, size)
      check tres.isOk()
      let adata = tres.get()
      if (size < limit1) and (size >= limit2):
        check01(adata)
      elif (size < limit2) and (size >= limit3):
        check0(adata)
      else:
        check:
          adata.data.head.isNone()
          adata.data.tail.isNone()
          adata.size == 0
      inc(counter)
