# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import results, snappy, stew/[io2, endians2]
import ./spec/[eth2_ssz_serialization, eth2_merkleization, forks]
from ./consensus_object_pools/block_pools_types import BlockData
export results

type
  ChainFileHeader = object
    header: uint32
    version: uint32
    kind: uint64
    comprSize: uint32
    plainSize: uint32
    slot: uint64

  ChainFileFooter = object
    kind: uint64
    comprSize: uint32
    plainSize: uint32
    slot: uint64

  Chunk = object
    header: ChainFileHeader
    footer: ChainFileFooter
    data: seq[byte]

  ChainFileData* = object
    head*: BlockData
    tail*: BlockData

  ChainFileHandle* = object
    data*: ChainFileData
    handle*: IoHandle

  ChainFileErrorType* {.pure.} = enum
    IoError,          # OS input/output error
    IncorrectSize,    # Incorrect/unexpected size of chunk
    IncompleteFooter, # Incomplete footer was read
    IncompleteHeader, # Incomplete header was read
    IncompleteData,   # Incomplete data was read
    FooterError,      # Incorrect chunk's footer
    HeaderError,      # Incorrect chunk's header
    MismatchError     # Header and footer not from same chunk

  ChainFileCheckResult* {.pure.} = enum
    FileMissing,
    FileEmpty,
    FileOk,
    FileRepaired,
    FileCorrupted

  ChainFileError* = object
    kind*: ChainFileErrorType
    message*: string

const
  ChainFileHeaderSize* = 32
  ChainFileFooterSize* = 24
  ChainFileVersion = 1'u32
  ChainFileHeaderValue = 0x424D494E'u32
  ChainFileBufferSize* = 4096
  MaxChunkSize* = uint64(
    high(uint32) - ChainFileHeaderSize - ChainFileFooterSize)
  ChainFileHeaderArray = ChainFileHeaderValue.toBytesLE()
  IncompleteWriteError = "Unable to write data to file, disk full?"

proc init(t: typedesc[ChainFileError], k: ChainFileErrorType,
              m: string): ChainFileError =
  ChainFileError(kind: k, message: m)

template init(t: typedesc[ChainFileHeader],
              kind: uint64, clength, plength: uint32,
              number: uint64): ChainFileHeader =
  ChainFileHeader(
    header: ChainFileHeaderValue,
    version: ChainFileVersion,
    kind: kind,
    comprSize: clength,
    plainSize: plength,
    slot: number)

template init(t: typedesc[ChainFileFooter],
              kind: uint64, clength, plength: uint32,
              number: uint64): ChainFileFooter =
  ChainFileFooter(
    kind: kind,
    comprSize: clength,
    plainSize: plength,
    slot: number)

template unmaskKind(k: uint64): uint64 =
  k and not(0x8000_0000_0000_0000'u64)

template maskKind(k: uint64): uint64 =
  k or 0x8000_0000_0000_0000'u64

template isLast(k: uint64): bool =
  (k and 0x8000_0000_0000_0000'u64) != 0'u64

proc checkKind(kind: uint64): Result[void, string] =
  let hkind = unmaskKind(kind)
  if hkind notin [0'u64, 1, 2, 3, 4, 5, 64, 65]:
    return err("Unsuppoted chunk kind value")
  ok()

proc check(a: ChainFileHeader): Result[void, string] =
  if a.header != ChainFileHeaderValue:
    return err("Incorrect chunk header [NIMB]")
  if a.version != 1'u32:
    return err("Unsuppoted chunk version")
  if a.comprSize >= MaxChunkSize:
    return err("Incorrect compressed size in chunk header")
  if a.plainSize >= MaxChunkSize:
    return err("Incorrect plain size in chunk header")
  ? checkKind(a.kind)
  ok()

proc check(a: ChainFileFooter): Result[void, string] =
  if a.comprSize >= MaxChunkSize:
    return err("Incorrect compressed size in chunk header")
  if a.plainSize >= MaxChunkSize:
    return err("Incorrect plain size in chunk header")
  ? a.kind.checkKind()
  ok()

proc check(a: ChainFileFooter, b: ChainFileHeader): Result[void, string] =
  if a.kind != b.kind:
    return err("Footer and header reports different chunk kind")
  if a.comprSize != b.comprSize:
    return err("Footer and header reports different compressed size")
  if a.plainSize != b.plainSize:
    return err("Footer and header reports different plain size")
  if a.slot != b.slot:
    return err("Footer and header reports different slots")
  ok()

proc init(t: typedesc[ChainFileHeader],
          data: openArray[byte]): Result[ChainFileHeader, string] =
  doAssert(len(data) >= ChainFileHeaderSize)
  let header =
    ChainFileHeader(
      header: uint32.fromBytesLE(data.toOpenArray(0, 3)),
      version: uint32.fromBytesLE(data.toOpenArray(4, 7)),
      kind: uint64.fromBytesLE(data.toOpenArray(8, 15)),
      comprSize: uint32.fromBytesLE(data.toOpenArray(16, 19)),
      plainSize: uint32.fromBytesLE(data.toOpenArray(20, 23)),
      slot: uint64.fromBytesLE(data.toOpenArray(24, 31)))
  ? check(header)
  ok(header)

proc init(t: typedesc[ChainFileFooter],
          data: openArray[byte]): Result[ChainFileFooter, string] =
  doAssert(len(data) >= ChainFileFooterSize)
  let footer =
    ChainFileFooter(
      kind: uint64.fromBytesLE(data.toOpenArray(0, 7)),
      comprSize: uint32.fromBytesLE(data.toOpenArray(8, 11)),
      plainSize: uint32.fromBytesLE(data.toOpenArray(12, 15)),
      slot: uint64.fromBytesLE(data.toOpenArray(16, 23)))
  ? check(footer)
  ok(footer)

template `[]=`(data: var openArray[byte], slice: Slice[int],
               src: array[4, byte]) =
  var k = 0
  for i in slice:
    data[i] = src[k]
    inc(k)

template `[]=`(data: var openArray[byte], slice: Slice[int],
               src: array[8, byte]) =
  var k = 0
  for i in slice:
    data[i] = src[k]
    inc(k)

proc store(a: ChainFileHeader, data: var openArray[byte]) =
  doAssert(len(data) >= ChainFileHeaderSize)
  data[0 .. 3] = a.header.toBytesLE()
  data[4 .. 7] = a.version.toBytesLE()
  data[8 .. 15] = a.kind.toBytesLE()
  data[16 .. 19] = a.comprSize.toBytesLE()
  data[20 .. 23] = a.plainSize.toBytesLE()
  data[24 .. 31] = a.slot.toBytesLE()

proc store(a: ChainFileFooter, data: var openArray[byte]) =
  doAssert(len(data) >= ChainFileFooterSize)
  data[0 .. 7] = a.kind.toBytesLE()
  data[8 .. 11] = a.comprSize.toBytesLE()
  data[12 .. 15] = a.plainSize.toBytesLE()
  data[16 .. 23] = a.slot.toBytesLE()

proc init(t: typedesc[Chunk], kind, slot: uint64, plainSize: uint32,
          data: openArray[byte]): seq[byte] =
  doAssert(uint64(len(data)) < MaxChunkSize)

  var
    dst = newSeq[byte](len(data) + ChainFileHeaderSize + ChainFileFooterSize)

  let
    header = ChainFileHeader.init(kind, uint32(len(data)), plainSize, slot)
    footer = ChainFileFooter.init(kind, uint32(len(data)), plainSize, slot)

  var offset = 0
  header.store(dst.toOpenArray(offset, offset + ChainFileHeaderSize - 1))
  offset += ChainFileHeaderSize

  if len(data) > 0:
    copyMem(addr dst[offset], unsafeAddr data[0], len(data))
    offset += len(data)

  footer.store(dst.toOpenArray(offset, offset + ChainFileFooterSize - 1))
  dst

template getBlockChunkKind(kind: ConsensusFork, last: bool): uint64 =
  let res =
    case kind
    of ConsensusFork.Phase0: 0'u64
    of ConsensusFork.Altair: 1'u64
    of ConsensusFork.Bellatrix: 2'u64
    of ConsensusFork.Capella: 3'u64
    of ConsensusFork.Deneb: 4'u64
    of ConsensusFork.Electra: 5'u64
  if last:
    maskKind(res)
  else:
    res

template getBlobChunkKind(kind: ConsensusFork, last: bool): uint64 =
  let res =
    case kind
    of ConsensusFork.Phase0, ConsensusFork.Altair, ConsensusFork.Bellatrix,
       ConsensusFork.Capella:
      raiseAssert("Blobs are not supported yet")
    of ConsensusFork.Deneb:
      64'u64 + 0'u64
    of ConsensusFork.Electra:
      64'u64 + 1'u64
  if last:
    maskKind(res)
  else:
    res

proc getBlockConsensusFork(header: ChainFileHeader): ConsensusFork =
  let hkind = unmaskKind(header.kind)
  case hkind
  of 0'u64: ConsensusFork.Phase0
  of 1'u64: ConsensusFork.Altair
  of 2'u64: ConsensusFork.Bellatrix
  of 3'u64: ConsensusFork.Capella
  of 4'u64: ConsensusFork.Deneb
  of 5'u64: ConsensusFork.Electra
  else: raiseAssert("Should not be happened")

template isBlock(h: ChainFileHeader | ChainFileFooter): bool =
  let hkind = unmaskKind(h.kind)
  (hkind >= 0) and (hkind < 64)

template isBlob(h: ChainFileHeader | ChainFileFooter): bool =
  let hkind = unmaskKind(h.kind)
  (hkind >= 64) and (hkind < 128)

template isLast(h: ChainFileHeader | ChainFileFooter): bool =
  h.kind.isLast()

proc store*(chunkfile: string, signedBlock: ForkedSignedBeaconBlock,
            blobs: Opt[BlobSidecars], compressed = true): Result[void, string] =
  let
    flags = {OpenFlags.Append, OpenFlags.Create}
    handle = openFile(chunkfile, flags).valueOr:
      return err(ioErrorMsg(error))
    origOffset = getFilePos(handle).valueOr:
      discard closeFile(handle)
      return err(ioErrorMsg(error))

  block:
    let
      kind = getBlockChunkKind(signedBlock.kind, blobs.isNone())
      (data, plainSize) =
        if compressed:
          withBlck(signedBlock):
            let res = SSZ.encode(forkyBlck)
            (snappy.encode(res), len(res))
        else:
          withBlck(signedBlock):
            let res = SSZ.encode(forkyBlck)
            (res, len(res))
      slot = signedBlock.slot
      buffer = Chunk.init(kind, uint64(slot), uint32(plainSize), data)
      wrote = writeFile(handle, buffer).valueOr:
        discard truncate(handle, origOffset)
        discard closeFile(handle)
        return err(ioErrorMsg(error))
    if wrote != uint(len(buffer)):
      discard truncate(handle, origOffset)
      discard closeFile(handle)
      return err(IncompleteWriteError)

  if blobs.isSome():
    let blobSidecars = blobs.get()
    for index, blob in blobSidecars.pairs():
      let
        kind =
          getBlobChunkKind(signedBlock.kind, (index + 1) == len(blobSidecars))
        (data, plainSize) =
          if compressed:
            let res = SSZ.encode(blob[])
            (snappy.encode(res), len(res))
          else:
            let res = SSZ.encode(blob[])
            (res, len(res))
        slot = blob[].signed_block_header.message.slot
        buffer =
          Chunk.init(kind, uint64(slot), uint32(plainSize), data)
        wrote = writeFile(handle, buffer).valueOr:
          discard truncate(handle, origOffset)
          discard closeFile(handle)
          return err(ioErrorMsg(error))
      if wrote != uint(len(buffer)):
        discard truncate(handle, origOffset)
        discard closeFile(handle)
        return err(IncompleteWriteError)

  closeFile(handle).isOkOr:
    return err(ioErrorMsg(error))

  ok()

proc readChunkForward(handle: IoHandle,
                      dataRead: bool): Result[Opt[Chunk], ChainFileError] =
  # This function only reads chunk header and footer, but does not read actual
  # chunk data.
  var
    buffer = newSeq[byte](max(ChainFileHeaderSize, ChainFileFooterSize))
    data: seq[byte]
    bytesRead: uint

  bytesRead =
    readFile(handle, buffer.toOpenArray(0, ChainFileHeaderSize - 1)).valueOr:
      return err(
        ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

  if bytesRead == 0'u:
    # End of file.
    return ok(Opt.none(Chunk))

  if bytesRead != uint(ChainFileHeaderSize):
    return err(
      ChainFileError.init(ChainFileErrorType.IncompleteHeader,
                          "Unable to read chunk header data, incorrect file?"))

  let
    header = ChainFileHeader.init(
      buffer.toOpenArray(0, ChainFileHeaderSize - 1)).valueOr:
        return err(
          ChainFileError.init(ChainFileErrorType.HeaderError, error))

  if not(dataRead):
    setFilePos(handle, int64(header.comprSize),
               SeekPosition.SeekCurrent).isOkOr:
      return err(
        ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))
  else:
    data.setLen(int64(header.comprSize))
    bytesRead =
      readFile(handle, data.toOpenArray(0, len(data) - 1)).valueOr:
        return err(
          ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

    if bytesRead != uint(header.comprSize):
      return err(
        ChainFileError.init(ChainFileErrorType.IncompleteData,
                            "Unable to read chunk data, incorrect file?"))

  bytesRead =
    readFile(handle, buffer.toOpenArray(0, ChainFileFooterSize - 1)).valueOr:
      return err(
        ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

  if bytesRead != uint(ChainFileFooterSize):
    return err(
      ChainFileError.init(ChainFileErrorType.IncompleteFooter,
                          "Unable to read chunk footer data, incorrect file?"))

  let
    footer = ChainFileFooter.init(
      buffer.toOpenArray(0, ChainFileFooterSize - 1)).valueOr:
        return err(
          ChainFileError.init(ChainFileErrorType.FooterError, error))

  check(footer, header).isOkOr:
    return err(
      ChainFileError.init(ChainFileErrorType.MismatchError, error))

  if not(dataRead):
    ok(Opt.some(Chunk(header: header, footer: footer)))
  else:
    ok(Opt.some(Chunk(header: header, footer: footer, data: data)))

proc readChunkBackward(handle: IoHandle,
                       dataRead: bool): Result[Opt[Chunk], ChainFileError] =
  # This function only reads chunk header and footer, but does not read actual
  # chunk data.
  var
    buffer = newSeq[byte](max(ChainFileHeaderSize, ChainFileFooterSize))
    data: seq[byte]
    bytesRead: uint

  let offset = getFilePos(handle).valueOr:
    return err(
      ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

  if offset == 0:
    return ok(Opt.none(Chunk))

  if offset <= (ChainFileHeaderSize + ChainFileFooterSize):
    return err(
      ChainFileError.init(ChainFileErrorType.IncorrectSize,
                          "File position is incorrect"))

  setFilePos(handle, -ChainFileFooterSize, SeekPosition.SeekCurrent).isOkOr:
    return err(
      ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

  bytesRead =
    readFile(handle, buffer.toOpenArray(0, ChainFileFooterSize - 1)).valueOr:
      return err(
        ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

  if bytesRead != ChainFileFooterSize:
    return err(
      ChainFileError.init(ChainFileErrorType.IncompleteFooter,
                          "Unable to read chunk footer data, incorrect file?"))
  let
    footer = ChainFileFooter.init(
      buffer.toOpenArray(0, ChainFileFooterSize - 1)).valueOr:
        return err(
          ChainFileError.init(ChainFileErrorType.FooterError, error))

  block:
    let position =
      -(ChainFileHeaderSize + ChainFileFooterSize + int64(footer.comprSize))
    setFilePos(handle, position, SeekPosition.SeekCurrent).isOkOr:
      return err(
        ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

  bytesRead =
    readFile(handle, buffer.toOpenArray(0, ChainFileHeaderSize - 1)).valueOr:
      return err(
        ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

  if bytesRead != ChainFileHeaderSize:
    return err(
      ChainFileError.init(ChainFileErrorType.IncompleteHeader,
                          "Unable to read chunk header data, incorrect file?"))

  let
    header = ChainFileHeader.init(
      buffer.toOpenArray(0, ChainFileHeaderSize - 1)).valueOr:
        return err(
          ChainFileError.init(ChainFileErrorType.HeaderError, error))

  check(footer, header).isOkOr:
    return err(
      ChainFileError.init(ChainFileErrorType.MismatchError, error))

  if not(dataRead):
    let position = int64(-ChainFileHeaderSize)
    setFilePos(handle, position, SeekPosition.SeekCurrent).isOkOr:
      return err(
        ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))
  else:
    data.setLen(int64(header.comprSize))
    bytesRead =
      readFile(handle, data.toOpenArray(0, len(data) - 1)).valueOr:
        return err(
          ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

    if bytesRead != uint(header.comprSize):
      return err(
        ChainFileError.init(ChainFileErrorType.IncompleteData,
                            "Unable to read chunk data, incorrect file?"))

    let position = -(ChainFileHeaderSize + int64(header.comprSize))
    setFilePos(handle, position, SeekPosition.SeekCurrent).isOkOr:
      return err(
        ChainFileError.init(ChainFileErrorType.IoError, ioErrorMsg(error)))

  if not(dataRead):
    ok(Opt.some(Chunk(header: header, footer: footer)))
  else:
    ok(Opt.some(Chunk(header: header, footer: footer, data: data)))

proc decodeBlock(
    header: ChainFileHeader,
    data: openArray[byte]
): Result[ForkedSignedBeaconBlock, string] =
  if header.plainSize > uint64(high(uint32)):
    return err("Size of block is enormously big")

  let
    fork = header.getBlockConsensusFork()
    decompressed = snappy.decode(data, uint32(header.plainSize))
    blck =
      try:
        case fork
        of ConsensusFork.Phase0:
          ForkedSignedBeaconBlock.init(
            SSZ.decode(decompressed, phase0.SignedBeaconBlock))
        of ConsensusFork.Altair:
          ForkedSignedBeaconBlock.init(
            SSZ.decode(decompressed, altair.SignedBeaconBlock))
        of ConsensusFork.Bellatrix:
          ForkedSignedBeaconBlock.init(
            SSZ.decode(decompressed, bellatrix.SignedBeaconBlock))
        of ConsensusFork.Capella:
          ForkedSignedBeaconBlock.init(
            SSZ.decode(decompressed, capella.SignedBeaconBlock))
        of ConsensusFork.Deneb:
          ForkedSignedBeaconBlock.init(
            SSZ.decode(decompressed, deneb.SignedBeaconBlock))
        of ConsensusFork.Electra:
          ForkedSignedBeaconBlock.init(
            SSZ.decode(decompressed, electra.SignedBeaconBlock))
      except SerializationError as exc:
        return err("Incorrect block format")
  ok(blck)

proc decodeBlob(
    header: ChainFileHeader,
    data: openArray[byte]
): Result[BlobSidecar, string] =
  if header.plainSize > uint64(high(uint32)):
    return err("Size of blob is enormously big")

  let
    decompressed = snappy.decode(data, uint32(header.plainSize))
    blob =
      try:
        SSZ.decode(decompressed, BlobSidecar)
      except SerializationError:
        return err("Incorrect blob format")
  ok(blob)

proc getChainFileTail*(handle: IoHandle): Result[Opt[BlockData], string] =
  var sidecars: BlobSidecars
  while true:
    let chunk =
      block:
        let res = readChunkBackward(handle, true).valueOr:
          return err(error.message)
        if res.isNone():
          if len(sidecars) == 0:
            return ok(Opt.none(BlockData))
          else:
            return err("Blobs without block encountered, incorrect file?")
        res.get()
    if chunk.header.isBlob():
      let blob = ? decodeBlob(chunk.header, chunk.data)
      sidecars.add(newClone blob)
    else:
      let blck = ? decodeBlock(chunk.header, chunk.data)
      return
        if len(sidecars) == 0:
          ok(Opt.some(BlockData(blck: blck)))
        else:
          ok(Opt.some(BlockData(blck: blck, blob: Opt.some(sidecars))))

proc getChainFileHead(handle: IoHandle): Result[Opt[BlockData], string] =
  var
    offset: int64 = 0
    endOfFile = false

  let
    blck =
      block:
        let chunk =
          block:
            let res = readChunkForward(handle, true).valueOr:
              return err(error.message)
            if res.isNone():
              return ok(Opt.none(BlockData))
            res.get()
        if not(chunk.header.isBlock()):
          return err("Unexpected blob chunk encountered")
        ? decodeBlock(chunk.header, chunk.data)
    blob =
      block:
        var sidecars: BlobSidecars
        block mainLoop:
          while true:
            offset = getFilePos(handle).valueOr:
              return err(ioErrorMsg(error))
            let chunk =
              block:
                let res = readChunkForward(handle, true).valueOr:
                  return err(error.message)
                if res.isNone():
                  endOfFile = true
                  break mainLoop
                res.get()
            if chunk.header.isBlob():
              let blob = ? decodeBlob(chunk.header, chunk.data)
              sidecars.add(newClone blob)
            else:
              break mainLoop

        if len(sidecars) > 0:
          Opt.some(sidecars)
        else:
          Opt.none(BlobSidecars)

  if not(endOfFile):
    setFilePos(handle, offset, SeekPosition.SeekBegin).isOkOr:
      return err(ioErrorMsg(error))

  ok(Opt.some(BlockData(blck: blck, blob: blob)))

proc seekForSlotBackward*(handle: IoHandle,
                          slot: Slot): Result[Opt[int64], string] =
  ## Search from the beginning of the file for the first chunk of data
  ## identified by slot ``slot``.
  ## This procedure updates current file position to the beginning of the found
  ## chunk and returns this position as the result.
  block:
    let res = setFilePos(handle, 0, SeekPosition.SeekEnd)
    if res.isErr():
      return err(ioErrorMsg(res.error))

  while true:
    let chunk =
      block:
        let res = readChunkBackward(handle, false).valueOr:
          return err(error.message)
        if res.isNone():
          return ok(Opt.none(int64))
        res.get()

    if chunk.header.slot == slot:
      block:
        let
          position =
            ChainFileHeaderSize + ChainFileFooterSize +
            int64(chunk.header.comprSize)
          res = setFilePos(handle, position, SeekPosition.SeekCurrent)
        if res.isErr():
          return err(ioErrorMsg(res.error))
      block:
        let res = getFilePos(handle)
        if res.isErr():
          return err(ioErrorMsg(res.error))
        return ok(Opt.some(res.get()))

proc seekForSlotForward*(handle: IoHandle,
                         slot: Slot): Result[Opt[int64], string] =
  ## Search from the end of the file for the last chunk of data identified by
  ## slot ``slot``.
  ## This procedure updates current file position to the beginning of the found
  ## chunk and returns this position as the result.
  block:
    let res = setFilePos(handle, 0, SeekPosition.SeekBegin)
    if res.isErr():
      return err(ioErrorMsg(res.error))

  while true:
    let chunk =
      block:
        let res = readChunkForward(handle, false).valueOr:
          return err(error.message)
        if res.isNone():
          return ok(Opt.none(int64))
        res.get()

    if chunk.header.slot == slot:
      block:
        let
          position =
            -(ChainFileHeaderSize + ChainFileFooterSize +
              int64(chunk.header.comprSize))
          res = setFilePos(handle, position, SeekPosition.SeekCurrent)
        if res.isErr():
          return err(ioErrorMsg(res.error))
      block:
        let res = getFilePos(handle)
        if res.isErr():
          return err(ioErrorMsg(res.error))
        return ok(Opt.some(res.get()))

proc search(data: openArray[byte], srch: openArray[byte],
            state: var int): Opt[int] =
  doAssert(len(srch) > 0)
  for index in countdown(len(data) - 1, 0):
    if data[index] == srch[len(srch) - 1 - state]:
      inc(state)
      if state == len(srch):
        return Opt.some(index)
    else:
      state = 0
  Opt.none(int)

proc seekForChunkBackward(
    handle: IoHandle,
    bufferSize = ChainFileBufferSize
): Result[Opt[int64], string] =
  var
    state = 0
    data = newSeq[byte](bufferSize)
    bytesRead: uint = 0

  while true:
    let
      position = getFilePos(handle).valueOr:
        return err(ioErrorMsg(error))
      offset = max(0'i64, position - int64(bufferSize))

    setFilePos(handle, offset, SeekPosition.SeekBegin).isOkOr:
      return err(ioErrorMsg(error))

    bytesRead = readFile(handle, data).valueOr:
      return err(ioErrorMsg(error))

    let indexOpt = search(data.toOpenArray(0, int(bytesRead) - 1),
                          ChainFileHeaderArray, state)

    if indexOpt.isNone():
      setFilePos(handle, offset, SeekPosition.SeekBegin).isOkOr:
        return err(ioErrorMsg(error))
      continue

    let chunkOffset = -(int64(bufferSize) - int64(indexOpt.get()))

    setFilePos(handle, chunkOffset, SeekPosition.SeekCurrent).isOkOr:
      return err(ioErrorMsg(error))

    let chunk = readChunkForward(handle, false).valueOr:
      # Incorrect chunk detected, so we start our searching again
      state = 0
      setFilePos(handle, offset, SeekPosition.SeekBegin).isOkOr:
        return err(ioErrorMsg(error))
      continue

    if chunk.isNone():
      return err("File has been changed, while repairing")

    if chunk.get().header.isLast():
      let finishOffset = getFilePos(handle).valueOr:
        return err(ioErrorMsg(error))
      return ok(Opt.some(finishOffset))

  ok(Opt.none(int64))

proc checkRepair*(filename: string,
                  repair: bool): Result[ChainFileCheckResult, string] =
  if not(isFile(filename)):
    return ok(ChainFileCheckResult.FileMissing)

  let
    handle = openFile(filename, {OpenFlags.Read, OpenFlags.Write}).valueOr:
      return err(ioErrorMsg(error))
    filesize = getFileSize(handle).valueOr:
      discard closeFile(handle)
      return err(ioErrorMsg(error))

  if filesize == 0'i64:
    closeFile(handle).isOkOr:
      return err(ioErrorMsg(error))
    return ok(ChainFileCheckResult.FileEmpty)

  setFilePos(handle, 0'i64, SeekPosition.SeekEnd).isOkOr:
    discard closeFile(handle)
    return err(ioErrorMsg(error))

  let res = readChunkBackward(handle, false)
  if res.isOk():
    let chunk = res.get()
    if chunk.isNone():
      discard closeFile(handle)
      return err("File was changed while reading")

    if chunk.get().header.isLast():
      # Last chunk being marked as last, everything is fine.
      closeFile(handle).isOkOr:
        return err(ioErrorMsg(error))
      return ok(ChainFileCheckResult.FileOk)

    # Last chunk was not marked properly, searching for the proper last chunk.
    while true:
      let nres = readChunkBackward(handle, false)
      if nres.isErr():
        discard closeFile(handle)
        return err(nres.error.message)

      let cres = nres.get()
      if cres.isNone():
        # We reached start of file.
        return
          if repair:
            truncate(handle, 0).isOkOr:
              discard closeFile(handle)
              return err(ioErrorMsg(error))
            closeFile(handle).isOkOr:
              return err(ioErrorMsg(error))
            ok(ChainFileCheckResult.FileRepaired)
          else:
            closeFile(handle).isOkOr:
              return err(ioErrorMsg(error))
            ok(ChainFileCheckResult.FileCorrupted)

      if cres.get().header.isLast():
        return
          if repair:
            let
              position = getFilePos(handle).valueOr:
                discard closeFile(handle)
                return err(ioErrorMsg(error))
              offset = position + int64(cres.get().header.comprSize) +
                       ChainFileHeaderSize + ChainFileFooterSize
            truncate(handle, offset).isOkOr:
              discard closeFile(handle)
              return err(ioErrorMsg(error))

            closeFile(handle).isOkOr:
              return err(ioErrorMsg(error))

            ok(ChainFileCheckResult.FileRepaired)
          else:
            closeFile(handle).isOkOr:
              return err(ioErrorMsg(error))
            ok(ChainFileCheckResult.FileCorrupted)

    ok(ChainFileCheckResult.FileCorrupted)
  else:
    setFilePos(handle, 0'i64, SeekPosition.SeekEnd).isOkOr:
      discard closeFile(handle)
      return err(ioErrorMsg(error))

    let position = seekForChunkBackward(handle).valueOr:
      discard closeFile(handle)
      return err(error)

    if position.isNone():
      discard closeFile(handle)
      return ok(ChainFileCheckResult.FileCorrupted)

    if repair:
      truncate(handle, position.get()).isOkOr:
        discard closeFile(handle)
        return err(ioErrorMsg(error))
      closeFile(handle).isOkOr:
        return err(ioErrorMsg(error))
      ok(ChainFileCheckResult.FileRepaired)
    else:
      closeFile(handle).isOkOr:
        return err(ioErrorMsg(error))
      ok(ChainFileCheckResult.FileCorrupted)

proc init*(t: typedesc[ChainFileHandle],
           filename: string,
           repair: bool = true): Result[ChainFileHandle, string] =
  if not(isFile(filename)):
    # We return None if file is missing, because its not an error.
    return err("File not found")

  block:
    let res = checkRepair(filename, repair)
    if res.isErr():
      return err(res.error)
    if res.get() notin {ChainFileCheckResult.FileMissing, FileEmpty, FileOk,
                        FileRepaired}:
      return err("Chain file data is corrupted")

  let
    handle =
      block:
        let res = openFile(filename, {OpenFlags.Read})
        if res.isErr():
          return err(ioErrorMsg(res.error))
        res.get()
    head =
      block:
        let res = getChainFileHead(handle)
        if res.isErr():
          discard closeFile(handle)
          return err(res.error)
        let cres = res.get()
        if cres.isNone():
          # Empty file is ok.
          discard closeFile(handle)
          return err("Unexpected end of file encountered")
        cres.get()

  block:
    let res = setFilePos(handle, 0'i64, SeekPosition.SeekEnd)
    if res.isErr():
      discard closeFile(handle)
      return err(ioErrorMsg(res.error))

  let
    tail =
      block:
        let res = getChainFileTail(handle)
        if res.isErr():
          discard closeFile(handle)
          return err(res.error)
        let tres = res.get()
        if tres.isNone():
          discard closeFile(handle)
          return err("Unexpected end of file encountered")
        tres.get()

  ok(ChainFileHandle(
      handle: handle,
      data: ChainFileData(head: head, tail: tail)))

proc close*(ch: ChainFileHandle): Result[void, string] =
  closeFile(ch.handle).isOkOr:
    return err(ioErrorMsg(error))
  ok()

proc init*(t: typedesc[ChainFileData],
           filename: string): Result[Opt[ChainFileData], string] =
  if not(isFile(filename)):
    # We return None if file is missing, because its not an error.
    return ok(Opt.none(ChainFileData))

  block:
    let res = checkRepair(filename, true)
    if res.isErr():
      return err(res.error)
    if res.get() notin {ChainFileCheckResult.FileMissing, FileEmpty, FileOk,
                        FileRepaired}:
      return err("Chain file data is corrupted")

  let
    handle =
      block:
        let res = openFile(filename, {OpenFlags.Read})
        if res.isErr():
          return err(ioErrorMsg(res.error))
        res.get()
    head =
      block:
        let res = getChainFileHead(handle)
        if res.isErr():
          discard closeFile(handle)
          return err(res.error)
        let cres = res.get()
        if cres.isNone():
          # Empty file is ok.
          discard closeFile(handle)
          return ok(Opt.none(ChainFileData))
        cres.get()

  block:
    let res = setFilePos(handle, 0'i64, SeekPosition.SeekEnd)
    if res.isErr():
      discard closeFile(handle)
      return err(ioErrorMsg(res.error))

  let
    tail =
      block:
        let res = getChainFileTail(handle)
        if res.isErr():
          discard closeFile(handle)
          return err(res.error)
        let tres = res.get()
        if tres.isNone():
          discard closeFile(handle)
          return err("Unexpected end of file encountered")
        tres.get()

  block:
    let res = closeFile(handle)
    if res.isErr():
      return err(ioErrorMsg(res.error))

  ok(Opt.some(ChainFileData(head: head, tail: tail)))

proc seekForSlot*(ch: ChainFileHandle,
                  slot: Slot): Result[Opt[int64], string] =
  let
    headRange =
      if ch.data.head.blck.slot() >= slot:
        ch.data.head.blck.slot() - slot
      else:
        slot - ch.data.head.blck.slot()
    tailRange =
      if ch.data.tail.blck.slot() >= slot:
        ch.data.tail.blck.slot() - slot
      else:
        slot - ch.data.tail.blck.slot()
    offset =
      if headRange <= tailRange:
        ? seekForSlotForward(ch.handle, slot)
      else:
        ? seekForSlotBackward(ch.handle, slot)
  ok(offset)

proc clearFile*(filename: string): Result[void, string] =
  removeFile(filename).isOkOr:
    return err(ioErrorMsg(error))
  ok()
