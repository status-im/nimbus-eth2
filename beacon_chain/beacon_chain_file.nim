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
    size: uint64

  ChainFileFooter = object
    kind: uint64
    size: uint64

  Chunk = object
    header: ChainFileHeader
    footer: ChainFileFooter
    data: seq[byte]

  ChainFileData* = object
    head*: BlockData
    tail*: BlockData

const
  ChainFileHeaderSize* = 24
  ChainFileFooterSize* = 16
  ChainFileVersion = 1'u32
  ChainFileHeaderValue = 0x424D494E'u32
  IncompleteWriteError = "Unable to write data to file, disk full?"

template init(t: typedesc[ChainFileHeader], kind: uint64,
              length: uint64): ChainFileHeader =
  ChainFileHeader(
    header: ChainFileHeaderValue,
    version: ChainFileVersion,
    kind: kind,
    size: length)

template init(t: typedesc[ChainFileHeader], kind: uint64, length: uint64,
              version: uint32): ChainFileHeader =
  ChainFileHeader(
    header: ChainFileHeaderValue,
    version: version,
    kind: kind,
    size: length)

template init(t: typedesc[ChainFileFooter], kind: uint64,
              length: uint64): ChainFileFooter =
  ChainFileFooter(kind: kind, size: length)

proc check(a: ChainFileHeader): Result[void, string] =
  if a.header != ChainFileHeaderValue:
    return err("Invalid chunk header")
  if a.version != 1'u32:
    return err("Unsuppoted chunk version")
  if a.kind notin [0'u64, 1, 2, 3, 4, 5, 64, 65]:
    return err("Unsuppoted chunk kind value")
  ok()

proc check(a: ChainFileFooter): Result[void, string] =
  if a.kind notin [0'u64, 1, 2, 3, 4, 5, 64, 65]:
    return err("Unsuppoted chunk kind value")
  ok()

proc check(a: ChainFileFooter, b: ChainFileHeader): Result[void, string] =
  if a.kind != b.kind:
    return err("Footer and header reports different chunk kind")
  if a.size != b.size:
    return err("Footer and header reports different size")
  ok()

proc init(t: typedesc[ChainFileHeader],
          data: openArray[byte]): Result[ChainFileHeader, string] =
  doAssert(len(data) >= ChainFileHeaderSize)
  let header =
    ChainFileHeader(
      header: uint32.fromBytesLE(data.toOpenArray(0, 3)),
      version: uint32.fromBytesLE(data.toOpenArray(4, 7)),
      kind: uint64.fromBytesLE(data.toOpenArray(8, 15)),
      size: uint64.fromBytesLE(data.toOpenArray(16, 23)))
  ? check(header)
  ok(header)

proc init(t: typedesc[ChainFileFooter],
          data: openArray[byte]): Result[ChainFileFooter, string] =
  doAssert(len(data) >= ChainFileFooterSize)
  let footer =
    ChainFileFooter(
      kind: uint64.fromBytesLE(data.toOpenArray(0, 7)),
      size: uint64.fromBytesLE(data.toOpenArray(8, 15)))
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
  data[16 .. 23] = a.size.toBytesLE()

proc store(a: ChainFileFooter, data: var openArray[byte]) =
  doAssert(len(data) >= ChainFileFooterSize)
  data[0 .. 7] = a.kind.toBytesLE()
  data[8 .. 15] = a.size.toBytesLE()

proc init(t: typedesc[Chunk], kind: uint64,
          data: openArray[byte]): seq[byte] =
  var
    dst = newSeq[byte](len(data) + ChainFileHeaderSize + ChainFileFooterSize)
  let
    header = ChainFileHeader.init(kind, uint64(len(data)))
    footer = ChainFileFooter.init(kind, uint64(len(data)))

  var offset = 0
  header.store(dst.toOpenArray(offset, offset + ChainFileHeaderSize - 1))
  offset += ChainFileHeaderSize

  if len(data) > 0:
    copyMem(addr dst[offset], unsafeAddr data[0], len(data))
    offset += len(data)

  footer.store(dst.toOpenArray(offset, offset + ChainFileFooterSize - 1))
  dst

template getBlockChunkKind(kind: ConsensusFork): uint64 =
  case kind
  of ConsensusFork.Phase0: 0'u64
  of ConsensusFork.Altair: 1'u64
  of ConsensusFork.Bellatrix: 2'u64
  of ConsensusFork.Capella: 3'u64
  of ConsensusFork.Deneb: 4'u64
  of ConsensusFork.Electra: 5'u64

template getBlobChunkKind(kind: ConsensusFork): uint64 =
  case kind
  of ConsensusFork.Phase0, ConsensusFork.Altair, ConsensusFork.Bellatrix,
     ConsensusFork.Capella:
    raiseAssert("Blobs are not supported yet")
  of ConsensusFork.Deneb:
    64'u64 + 0'u64
  of ConsensusFork.Electra:
    64'u64 + 1'u64

proc getBlockConsensusFork(header: ChainFileHeader): ConsensusFork =
  case header.kind
  of 0'u64: ConsensusFork.Phase0
  of 1'u64: ConsensusFork.Altair
  of 2'u64: ConsensusFork.Bellatrix
  of 3'u64: ConsensusFork.Capella
  of 4'u64: ConsensusFork.Deneb
  of 5'u64: ConsensusFork.Electra
  else: raiseAssert("Should not be happened")

template isBlock(h: ChainFileHeader): bool =
  (h.kind >= 0) and (h.kind < 64)

template isBlob(h: ChainFileHeader): bool =
  (h.kind >= 64) and (h.kind < 128)

proc store*(chunkfile: string, signedBlock: ForkedSignedBeaconBlock,
            blobs: Opt[BlobSidecars]): Result[void, string] =
  let
    flags = {OpenFlags.Append, OpenFlags.Create}
    handle = openFile(chunkfile, flags).valueOr:
      return err(ioErrorMsg(error))
    origOffset = getFilePos(handle).valueOr:
      discard closeFile(handle)
      return err(ioErrorMsg(error))

  block:
    let
      kind = getBlockChunkKind(signedBlock.kind)
      data = withBlck(signedBlock): snappy.encode(SSZ.encode(forkyBlck))
      buffer = Chunk.init(kind, data)
      wrote = writeFile(handle, buffer).valueOr:
        discard truncate(handle, origOffset)
        discard closeFile(handle)
        return err(ioErrorMsg(error))
    if wrote != uint(len(buffer)):
      discard truncate(handle, origOffset)
      discard closeFile(handle)
      return err(IncompleteWriteError)

  if blobs.isSome():
    for blob in blobs.get():
      let
        kind = getBlobChunkKind(signedBlock.kind)
        data = snappy.encode(SSZ.encode(blob[]))
        buffer = Chunk.init(kind, data)
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

proc readChunkForward(handle: IoHandle): Result[Opt[Chunk], string] =
  var
    data = newSeq[byte](ChainFileHeaderSize + ChainFileFooterSize)
    bytesRead: uint

  bytesRead =
    readFile(handle, data.toOpenArray(0, ChainFileHeaderSize - 1)).valueOr:
      return err(ioErrorMsg(error))

  if bytesRead == 0:
    # End of file.
    return ok(Opt.none(Chunk))

  if bytesRead != ChainFileHeaderSize:
    return err("Unable to read chunk header data, incorrect file?")

  let
    header = ChainFileHeader.init(
      data.toOpenArray(0, ChainFileHeaderSize - 1)).valueOr:
        return err(error)

  data.setLen(header.size + ChainFileFooterSize)

  bytesRead = readFile(handle, data).valueOr:
    return err(ioErrorMsg(error))

  if bytesRead != uint(len(data)):
    return err("Unable to read chunk data, incorrect file?")

  let
    position = int(header.size)
    footer = ChainFileFooter.init(
      data.toOpenArray(position, position + ChainFileFooterSize - 1)).valueOr:
        return err(error)

  check(footer, header).isOkOr:
    return err(error)

  data.setLen(header.size)
  ok(Opt.some(Chunk(header: header, footer: footer, data: data)))

proc readChunkBackward(handle: IoHandle): Result[Opt[Chunk], string] =
  var
    data = newSeq[byte](ChainFileHeaderSize + ChainFileFooterSize)
    bytesRead: uint

  let offset = getFilePos(handle).valueOr:
    return err(ioErrorMsg(error))

  if offset == 0:
    return ok(Opt.none(Chunk))

  if offset <= (ChainFileHeaderSize + ChainFileFooterSize):
    return err("File position is incorrect")

  setFilePos(handle, -ChainFileFooterSize, SeekPosition.SeekCurrent).isOkOr:
    return err(ioErrorMsg(error))

  bytesRead =
    readFile(handle, data.toOpenArray(0, ChainFileFooterSize - 1)).valueOr:
      return err(ioErrorMsg(error))

  if bytesRead != ChainFileFooterSize:
    return err("Unable to read chunk footer data, incorrect file?")

  let
    footer = ChainFileFooter.init(
      data.toOpenArray(0, ChainFileFooterSize - 1)).valueOr:
        return err(error)

  block:
    let position =
      -(ChainFileHeaderSize + ChainFileFooterSize + int64(footer.size))
    setFilePos(handle, position, SeekPosition.SeekCurrent).isOkOr:
      return err(ioErrorMsg(error))

  data.setLen(ChainFileHeaderSize + int64(footer.size))

  bytesRead = readFile(handle, data).valueOr:
    return err(ioErrorMsg(error))

  if bytesRead != uint(len(data)):
    return err("Unable to read chunk data, incorrect file?")

  let
    header = ChainFileHeader.init(
      data.toOpenArray(0, ChainFileHeaderSize - 1)).valueOr:
        return err(error)

  check(footer, header).isOkOr:
    return err(error)

  block:
    let position = -(ChainFileHeaderSize + int64(footer.size))
    # Set file position again, because it was moved when data was read.
    setFilePos(handle, position, SeekPosition.SeekCurrent).isOkOr:
      return err(ioErrorMsg(error))

  moveMem(addr data[0], addr data[ChainFileHeaderSize], int(header.size))
  data.setLen(int(header.size))
  ok(Opt.some(Chunk(header: header, footer: footer, data: data)))

proc decodeBlock(
    header: ChainFileHeader,
    data: openArray[byte]
): Result[ForkedSignedBeaconBlock, string] =
  let
    fork = header.getBlockConsensusFork()
    decompressed = snappy.decode(data)
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
      except SerializationError:
        return err("Incorrect block format")
  ok(blck)

proc decodeBlob(
    header: ChainFileHeader,
    data: openArray[byte]
): Result[BlobSidecar, string] =
  let
    decompressed = snappy.decode(data)
    blob =
      try:
        SSZ.decode(decompressed, BlobSidecar)
      except SerializationError:
        return err("Incorrect blob format")
  ok(blob)

proc getChainFileTail(handle: IoHandle): Result[Opt[BlockData], string] =
  var sidecars: BlobSidecars
  while true:
    let chunk =
      block:
        let res = ? readChunkBackward(handle)
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
            let res = ? readChunkForward(handle)
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
                let res = ? readChunkForward(handle)
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

proc init*(t: typedesc[ChainFileData],
           filename: string): Result[Opt[ChainFileData], string] =
  if not(isFile(filename)):
    # We return None if file is missing, because its not an error.
    return ok(Opt.none(ChainFileData))

  let
    flags = {OpenFlags.Read}
    handle =
      block:
        let res = openFile(filename, flags)
        if res.isErr():
          return err(ioErrorMsg(res.error))
        res.get()
    head =
      block:
        let res = getChainFileHead(handle)
        if res.isErr():
          discard closeFile(handle)
          return err(res.error)
        let hres = res.get()
        if hres.isNone():
          # Empty file is also ok.
          return ok(Opt.none(ChainFileData))
        hres.get()

  block:
    let res = setFilePos(handle, 0, SeekPosition.SeekEnd)
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
          return err("Unexpected end of file encountered")
        tres.get()

  block:
    let res = closeFile(handle)
    if res.isErr():
      return err(ioErrorMsg(res.error))

  ok(Opt.some(ChainFileData(head: head, tail: tail)))

iterator forwardWalk*(filename: string): Result[BlockData, string] {.
         closure.} =
  # Iterates over all the items in chain-file ``filename`` in forward order
  # (from the first one to last one).
  let
    flags = {OpenFlags.Read}
    handle =
      block:
        let res = openFile(filename, flags)
        if res.isErr():
          yield err(ioErrorMsg(res.error))
          return
        res.get()

  while true:
    let chres = getChainFileHead(handle)
    if chres.isErr():
      discard closeFile(handle)
      yield err(chres.error)
    let bres = chres.get()
    if bres.isNone():
      let cres = closeFile(handle)
      if cres.isErr():
        yield err(ioErrorMsg(cres.error))
      return
    yield ok(bres.get())

iterator backwardWalk*(filename: string): Result[BlockData, string] {.
         closure.} =
  # Iterates over all the items in chain-file ``filename`` in backward order
  # (from the last one to first one).
  let
    flags = {OpenFlags.Read}
    handle =
      block:
        let res = openFile(filename, flags)
        if res.isErr():
          yield err(ioErrorMsg(res.error))
          return
        res.get()

  block:
    let res = setFilePos(handle, 0, SeekPosition.SeekEnd)
    if res.isErr():
      yield err(ioErrorMsg(res.error))
      return

  while true:
    let chres = getChainFileTail(handle)
    if chres.isErr():
      discard closeFile(handle)
      yield err(chres.error)
    let bres = chres.get()
    if bres.isNone():
      let cres = closeFile(handle)
      if cres.isErr():
        yield err(ioErrorMsg(cres.error))
      return
    yield ok(bres.get())
