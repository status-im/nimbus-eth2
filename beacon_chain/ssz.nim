# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# SSZ Serialization (simple serialize)
# See https://github.com/ethereum/eth2.0-specs/blob/master/specs/simple-serialize.md

# TODO Cannot override push, even though the function is annotated
# nim-beacon-chain/beacon_chain/ssz.nim(212, 18) Error: can raise an unlisted exception: IOError
#{.push raises: [Defect].}

# TODO Many RVO bugs, careful
# https://github.com/nim-lang/Nim/issues/14470
# https://github.com/nim-lang/Nim/issues/14126

import
  options, algorithm, options, strformat, typetraits,
  stew/[bitops2, bitseqs, endians2, objects, varints, ptrops],
  stew/ranges/ptr_arith, stew/shims/macros,
  faststreams/[inputs, outputs, buffers],
  serialization, serialization/testing/tracing,
  ./spec/[crypto, datatypes, digest],
  ./ssz/[types, bytes_reader],
  ../nbench/bench_lab

# ################### Helper functions ###################################

export
  serialization, types, bytes_reader

when defined(serialization_tracing):
  import
    typetraits

const
  bytesPerChunk = 32
  bitsPerChunk = bytesPerChunk * 8

type
  SszReader* = object
    stream: InputStream

  SszWriter* = object
    stream: OutputStream

  SszChunksMerkleizer = object
    combinedChunks: ptr UncheckedArray[Eth2Digest]
    totalChunks: uint64
    topIndex: int

  SizePrefixed*[T] = distinct T
  SszMaxSizeExceeded* = object of SerializationError

  VarSizedWriterCtx = object
    fixedParts: WriteCursor
    offset: int

  FixedSizedWriterCtx = object

serializationFormat SSZ,
                    Reader = SszReader,
                    Writer = SszWriter,
                    PreferedOutput = seq[byte]

template loadFile*(Format: type SSZ,
                   file: string,
                   RecordType: distinct type): auto =
  let bytes = readFile(file)
  decode(SSZ, toOpenArrayByte(string bytes, 0, bytes.high), RecordType)

template bytes(x: BitSeq): untyped =
  seq[byte](x)

template sizePrefixed*[TT](x: TT): untyped =
  type T = TT
  SizePrefixed[T](x)

proc init*(T: type SszReader, stream: InputStream): T {.raises: [Defect].} =
  T(stream: stream)

method formatMsg*(
  err: ref SszSizeMismatchError,
  filename: string): string {.gcsafe, raises: [Defect].} =
  try:
    &"SSZ size mismatch, element {err.elementSize}, actual {err.actualSszSize}, type {err.deserializedType}, file {filename}"
  except CatchableError:
    "SSZ size mismatch"

template toSszType*(x: auto): auto =
  mixin toSszType

  # Please note that BitArray doesn't need any special treatment here
  # because it can be considered a regular fixed-size object type.

  when x is Slot|Epoch|ValidatorIndex|enum: uint64(x)
  elif x is Eth2Digest: x.data
  elif x is BlsCurveType: toRaw(x)
  elif x is ForkDigest|Version: distinctBase(x)
  else: x

proc writeFixedSized(s: var (OutputStream|WriteCursor), x: auto) {.raises: [Defect, IOError].} =
  mixin toSszType

  when x is byte:
    s.write x
  elif x is bool:
    s.write byte(ord(x))
  elif x is UintN:
    when cpuEndian == bigEndian:
      s.write toBytesLE(x)
    else:
      s.writeMemCopy x
  elif x is array:
    when x[0] is byte:
      trs "APPENDING FIXED SIZE BYTES", x
      s.write x
    else:
      for elem in x:
        trs "WRITING FIXED SIZE ARRAY ELEMENT"
        s.writeFixedSized toSszType(elem)
  elif x is tuple|object:
    enumInstanceSerializedFields(x, fieldName, field):
      trs "WRITING FIXED SIZE FIELD", fieldName
      s.writeFixedSized toSszType(field)
  else:
    unsupported x.type

template writeOffset(cursor: var WriteCursor, offset: int) =
  write cursor, toBytesLE(uint32 offset)

template supports*(_: type SSZ, T: type): bool =
  mixin toSszType
  anonConst compiles(fixedPortionSize toSszType(declval T))

func init*(T: type SszWriter, stream: OutputStream): T {.raises: [Defect].} =
  result.stream = stream

template enumerateSubFields(holder, fieldVar, body: untyped) =
  when holder is array:
    for fieldVar in holder: body
  else:
    enumInstanceSerializedFields(holder, _{.used.}, fieldVar): body

proc writeVarSizeType(w: var SszWriter, value: auto) {.gcsafe.}

proc beginRecord*(w: var SszWriter, TT: type): auto {.raises: [Defect].} =
  type T = TT
  when isFixedSize(T):
    FixedSizedWriterCtx()
  else:
    const offset = when T is array: len(T) * offsetSize
                   else: fixedPortionSize(T)
    VarSizedWriterCtx(offset: offset,
                      fixedParts: w.stream.delayFixedSizeWrite(offset))

template writeField*(w: var SszWriter,
                     ctx: var auto,
                     fieldName: string,
                     field: auto) =
  mixin toSszType
  when ctx is FixedSizedWriterCtx:
    writeFixedSized(w.stream, toSszType(field))
  else:
    type FieldType = type toSszType(field)

    when isFixedSize(FieldType):
      writeFixedSized(ctx.fixedParts, toSszType(field))
    else:
      trs "WRITING OFFSET ", ctx.offset, " FOR ", fieldName
      writeOffset(ctx.fixedParts, ctx.offset)
      let initPos = w.stream.pos
      trs "WRITING VAR SIZE VALUE OF TYPE ", name(FieldType)
      when FieldType is BitList:
        trs "BIT SEQ ", bytes(field)
      writeVarSizeType(w, toSszType(field))
      ctx.offset += w.stream.pos - initPos

template endRecord*(w: var SszWriter, ctx: var auto) =
  when ctx is VarSizedWriterCtx:
    finalize ctx.fixedParts

proc writeSeq[T](w: var SszWriter, value: seq[T])
                {.raises: [Defect, IOError].} =
  # Please note that `writeSeq` exists in order to reduce the code bloat
  # produced from generic instantiations of the unique `List[N, T]` types.
  when isFixedSize(T):
    trs "WRITING LIST WITH FIXED SIZE ELEMENTS"
    for elem in value:
      w.stream.writeFixedSized toSszType(elem)
    trs "DONE"
  else:
    trs "WRITING LIST WITH VAR SIZE ELEMENTS"
    var offset = value.len * offsetSize
    var cursor = w.stream.delayFixedSizeWrite offset
    for elem in value:
      cursor.writeFixedSized uint32(offset)
      let initPos = w.stream.pos
      w.writeVarSizeType toSszType(elem)
      offset += w.stream.pos - initPos
    finalize cursor
    trs "DONE"

proc writeVarSizeType(w: var SszWriter, value: auto) {.raises: [Defect, IOError].} =
  trs "STARTING VAR SIZE TYPE"
  mixin toSszType
  type T = type toSszType(value)

  when T is List:
    # We reduce code bloat by forwarding all `List` types to a general `seq[T]` proc.
    writeSeq(w, asSeq value)
  elif T is BitList:
    # ATTENTION! We can reuse `writeSeq` only as long as our BitList type is implemented
    # to internally match the binary representation of SSZ BitLists in memory.
    writeSeq(w, bytes value)
  elif T is object|tuple|array:
    trs "WRITING OBJECT OR ARRAY"
    var ctx = beginRecord(w, T)
    enumerateSubFields(value, field):
      writeField w, ctx, astToStr(field), field
    endRecord w, ctx
  else:
    unsupported type(value)

proc writeValue*(w: var SszWriter, x: auto) {.gcsafe, raises: [Defect, IOError].} =
  mixin toSszType
  type T = type toSszType(x)

  when isFixedSize(T):
    w.stream.writeFixedSized toSszType(x)
  else:
    w.writeVarSizeType toSszType(x)

func sszSize*(value: auto): int {.gcsafe, raises: [Defect].}

func sszSizeForVarSizeList[T](value: openarray[T]): int =
  result = len(value) * offsetSize
  for elem in value:
    result += sszSize(toSszType elem)

func sszSize*(value: auto): int {.gcsafe, raises: [Defect].} =
  mixin toSszType
  type T = type toSszType(value)

  when isFixedSize(T):
    anonConst fixedPortionSize(T)

  elif T is array|List:
    type E = ElemType(T)
    when isFixedSize(E):
      len(value) * anonConst(fixedPortionSize(E))
    elif T is array:
      sszSizeForVarSizeList(value)
    else:
      sszSizeForVarSizeList(asSeq value)

  elif T is BitList:
    return len(bytes(value))

  elif T is object|tuple:
    result = anonConst fixedPortionSize(T)
    enumInstanceSerializedFields(value, _, field):
      type FieldType = type toSszType(field)
      when not isFixedSize(FieldType):
        result += sszSize(toSszType field)

  else:
    unsupported T

proc writeValue*[T](w: var SszWriter, x: SizePrefixed[T]) {.raises: [Defect, IOError].} =
  var cursor = w.stream.delayVarSizeWrite(10)
  let initPos = w.stream.pos
  w.writeValue T(x)
  let length = uint64(w.stream.pos - initPos)
  when false:
    discard
    # TODO varintBytes is sub-optimal at the moment
    # cursor.writeAndFinalize length.varintBytes
  else:
    var buf: VarintBuffer
    buf.writeVarint length
    cursor.finalWrite buf.writtenBytes

proc readValue*[T](r: var SszReader, val: var T) {.raises: [Defect, MalformedSszError, SszSizeMismatchError, IOError].} =
  when isFixedSize(T):
    const minimalSize = fixedPortionSize(T)
    if r.stream.readable(minimalSize):
      readSszValue(r.stream.read(minimalSize), val)
    else:
      raise newException(MalformedSszError, "SSZ input of insufficient size")
  else:
    # TODO Read the fixed portion first and precisely measure the size of
    # the dynamic portion to consume the right number of bytes.
    readSszValue(r.stream.read(r.stream.len.get), val)

const
  zeroChunk = default array[32, byte]

func hash(a, b: openArray[byte]): Eth2Digest =
  result = withEth2Hash:
    trs "MERGING BRANCHES "
    trs toHex(a)
    trs toHex(b)

    h.update a
    h.update b
  trs "HASH RESULT ", result

func mergeBranches(existing: Eth2Digest, newData: openarray[byte]): Eth2Digest =
  result = withEth2Hash:
    trs "MERGING BRANCHES OPEN ARRAY"
    trs toHex(existing.data)
    trs toHex(newData)

    h.update existing.data
    h.update newData

    let paddingBytes = bytesPerChunk - newData.len
    if paddingBytes > 0:
      trs "USING ", paddingBytes, " PADDING BYTES"
      h.update zeroChunk.toOpenArray(0, paddingBytes - 1)
  trs "HASH RESULT ", result

template mergeBranches(a, b: Eth2Digest): Eth2Digest =
  hash(a.data, b.data)

func computeZeroHashes: array[sizeof(Limit) * 8, Eth2Digest] =
  result[0] = Eth2Digest(data: zeroChunk)
  for i in 1 .. result.high:
    result[i] = mergeBranches(result[i - 1], result[i - 1])

const zeroHashes = computeZeroHashes()

func addChunk(merkleizer: var SszChunksMerkleizer, data: openarray[byte]) =
  doAssert data.len > 0 and data.len <= bytesPerChunk

  if not getBitLE(merkleizer.totalChunks, 0):
    let chunkStartAddr = addr merkleizer.combinedChunks[0].data[0]
    copyMem(chunkStartAddr, unsafeAddr data[0], data.len)
    zeroMem(chunkStartAddr.offset(data.len), bytesPerChunk - data.len)
    trs "WROTE BASE CHUNK ", merkleizer.combinedChunks[0], " ", data.len
  else:
    var hash = mergeBranches(merkleizer.combinedChunks[0], data)

    for i in 1 .. merkleizer.topIndex:
      trs "ITERATING"
      if getBitLE(merkleizer.totalChunks, i):
        trs "CALLING MERGE BRANCHES"
        hash = mergeBranches(merkleizer.combinedChunks[i], hash)
      else:
        trs "WRITING FRESH CHUNK AT ", i, " = ", hash
        merkleizer.combinedChunks[i] = hash
        break

  inc merkleizer.totalChunks

template createMerkleizer(totalElements: static Limit): SszChunksMerkleizer =
  trs "CREATING A MERKLEIZER FOR ", totalElements

  const treeHeight = bitWidth nextPow2(uint64 totalElements)
  var combinedChunks {.noInit.}: array[treeHeight, Eth2Digest]

  SszChunksMerkleizer(
    combinedChunks: cast[ptr UncheckedArray[Eth2Digest]](addr combinedChunks),
    topIndex: treeHeight - 1,
    totalChunks: 0)

func getFinalHash(merkleizer: var SszChunksMerkleizer): Eth2Digest =
  if merkleizer.totalChunks == 0:
    return zeroHashes[merkleizer.topIndex]

  let
    bottomHashIdx = firstOne(merkleizer.totalChunks) - 1
    submittedChunksHeight = bitWidth(merkleizer.totalChunks - 1)
    topHashIdx = merkleizer.topIndex

  trs "BOTTOM HASH ", bottomHashIdx
  trs "SUBMITTED HEIGHT ", submittedChunksHeight
  trs "TOP HASH IDX ", topHashIdx

  if bottomHashIdx != submittedChunksHeight:
    # Our tree is not finished. We must complete the work in progress
    # branches and then extend the tree to the right height.
    result = mergeBranches(merkleizer.combinedChunks[bottomHashIdx],
                           zeroHashes[bottomHashIdx])

    for i in bottomHashIdx + 1 ..< topHashIdx:
      if getBitLE(merkleizer.totalChunks, i):
        result = mergeBranches(merkleizer.combinedChunks[i], result)
        trs "COMBINED"
      else:
        result = mergeBranches(result, zeroHashes[i])
        trs "COMBINED WITH ZERO"

  elif bottomHashIdx == topHashIdx:
    # We have a perfect tree (chunks == 2**n) at just the right height!
    result = merkleizer.combinedChunks[bottomHashIdx]
  else:
    # We have a perfect tree of user chunks, but we have more work to
    # do - we must extend it to reach the desired height
    result = mergeBranches(merkleizer.combinedChunks[bottomHashIdx],
                           zeroHashes[bottomHashIdx])

    for i in bottomHashIdx + 1 ..< topHashIdx:
      result = mergeBranches(result, zeroHashes[i])

func mixInLength(root: Eth2Digest, length: int): Eth2Digest =
  var dataLen: array[32, byte]
  dataLen[0..<8] = uint64(length).toBytesLE()
  hash(root.data, dataLen)

func hash_tree_root*(x: auto): Eth2Digest {.gcsafe, raises: [Defect].}

template merkleizeFields(totalElements: static Limit, body: untyped): Eth2Digest =
  var merkleizer {.inject.} = createMerkleizer(totalElements)

  template addField(field) =
    let hash = hash_tree_root(field)
    trs "MERKLEIZING FIELD ", astToStr(field), " = ", hash
    addChunk(merkleizer, hash.data)
    trs "CHUNK ADDED"

  body

  getFinalHash(merkleizer)

template writeBytesLE(chunk: var array[bytesPerChunk, byte], atParam: int,
                      val: SomeUnsignedInt) =
  let at = atParam
  chunk[at ..< at + sizeof(val)] = toBytesLE(val)

func chunkedHashTreeRootForBasicTypes[T](merkleizer: var SszChunksMerkleizer,
                                         arr: openarray[T]): Eth2Digest =
  static:
    doAssert T is BasicType

  when T is byte:
    var
      remainingBytes = arr.len
      pos = cast[ptr byte](unsafeAddr arr[0])

    while remainingBytes >= bytesPerChunk:
      merkleizer.addChunk(makeOpenArray(pos, bytesPerChunk))
      pos = offset(pos, bytesPerChunk)
      remainingBytes -= bytesPerChunk

    if remainingBytes > 0:
      merkleizer.addChunk(makeOpenArray(pos, remainingBytes))

  elif T is bool or cpuEndian == littleEndian:
    let
      baseAddr = cast[ptr byte](unsafeAddr arr[0])
      len = arr.len * sizeof(T)
    return chunkedHashTreeRootForBasicTypes(merkleizer, makeOpenArray(baseAddr, len))

  else:
    static:
      doAssert T is UintN
      doAssert bytesPerChunk mod sizeof(Т) == 0

    const valuesPerChunk = bytesPerChunk div sizeof(Т)

    var writtenValues = 0

    var chunk: array[bytesPerChunk, byte]
    while writtenValues < arr.len - valuesPerChunk:
      for i in 0 ..< valuesPerChunk:
        chunk.writeBytesLE(i * sizeof(T), arr[writtenValues + i])
      merkleizer.addChunk chunk
      inc writtenValues, valuesPerChunk

    let remainingValues = arr.len - writtenValues
    if remainingValues > 0:
      var lastChunk: array[bytesPerChunk, byte]
      for i in 0 ..< remainingValues:
        chunk.writeBytesLE(i * sizeof(T), arr[writtenValues + i])
      merkleizer.addChunk lastChunk

  getFinalHash(merkleizer)

func bitListHashTreeRoot(merkleizer: var SszChunksMerkleizer, x: BitSeq): Eth2Digest =
  # TODO: Switch to a simpler BitList representation and
  #       replace this with `chunkedHashTreeRoot`
  trs "CHUNKIFYING BIT SEQ WITH TOP INDEX ", merkleizer.topIndex

  var
    totalBytes = bytes(x).len
    lastCorrectedByte = bytes(x)[^1]

  if lastCorrectedByte == byte(1):
    if totalBytes == 1:
      # This is an empty bit list.
      # It should be hashed as a tree containing all zeros:
      return mergeBranches(zeroHashes[merkleizer.topIndex],
                           zeroHashes[0]) # this is the mixed length

    totalBytes -= 1
    lastCorrectedByte = bytes(x)[^2]
  else:
    let markerPos = log2trunc(lastCorrectedByte)
    lastCorrectedByte.clearBit(markerPos)

  var
    bytesInLastChunk = totalBytes mod bytesPerChunk
    fullChunks = totalBytes div bytesPerChunk

  if bytesInLastChunk == 0:
    fullChunks -= 1
    bytesInLastChunk = 32

  for i in 0 ..< fullChunks:
    let
      chunkStartPos = i * bytesPerChunk
      chunkEndPos = chunkStartPos + bytesPerChunk - 1

    merkleizer.addChunk bytes(x).toOpenArray(chunkStartPos, chunkEndPos)

  var
    lastChunk: array[bytesPerChunk, byte]
    chunkStartPos = fullChunks * bytesPerChunk

  for i in 0 .. bytesInLastChunk - 2:
    lastChunk[i] = bytes(x)[chunkStartPos + i]

  lastChunk[bytesInLastChunk - 1] = lastCorrectedByte

  merkleizer.addChunk lastChunk.toOpenArray(0, bytesInLastChunk - 1)
  let contentsHash = merkleizer.getFinalHash
  mixInLength contentsHash, x.len

func maxChunksCount(T: type, maxLen: int64): int64 =
  when T is BitList|BitArray:
    (maxLen + bitsPerChunk - 1) div bitsPerChunk
  elif T is array|List:
    type E = ElemType(T)
    when E is BasicType:
      (maxLen * sizeof(E) + bytesPerChunk - 1) div bytesPerChunk
    else:
      maxLen
  else:
    unsupported T # This should never happen

func hashTreeRootAux[T](x: T): Eth2Digest =
  when T is SignedBeaconBlock:
    unsupported T # Blocks are identified by htr(BeaconBlock) so we avoid these
  elif T is bool|char:
    result.data[0] = byte(x)
  elif T is SomeUnsignedInt:
    when cpuEndian == bigEndian:
      result.data[0..<sizeof(x)] = toBytesLE(x)
    else:
      copyMem(addr result.data[0], unsafeAddr x, sizeof x)
  elif (when T is array: ElemType(T) is BasicType else: false):
    type E = ElemType(T)
    when sizeof(T) <= sizeof(result.data):
      when E is byte|bool or cpuEndian == littleEndian:
        copyMem(addr result.data[0], unsafeAddr x, sizeof x)
      else:
        var pos = 0
        for e in x:
          writeBytesLE(result.data, pos, e)
          pos += sizeof(E)
    else:
      trs "FIXED TYPE; USE CHUNK STREAM"
      var markleizer = createMerkleizer(maxChunksCount(T, x.len))
      chunkedHashTreeRootForBasicTypes(markleizer, x)
  elif T is BitArray:
    hashTreeRootAux(x.bytes)
  elif T is array|object|tuple:
    trs "MERKLEIZING FIELDS"
    const totalFields = when T is array: len(x)
                        else: totalSerializedFields(T)
    merkleizeFields(totalFields):
      x.enumerateSubFields(f):
        addField f
  #elif isCaseObject(T):
  #  # TODO implement this
  else:
    unsupported T

func hash_tree_root*(x: auto): Eth2Digest {.raises: [Defect], nbench.} =
  trs "STARTING HASH TREE ROOT FOR TYPE ", name(type(x))
  mixin toSszType
  result = when x is List|BitList:
    const maxLen = static(x.maxLen)
    type T = type(x)
    const limit = maxChunksCount(T, maxLen)
    var merkleizer = createMerkleizer(limit)

    when x is BitList:
      merkleizer.bitListHashTreeRoot(BitSeq x)
    else:
      type E = ElemType(T)
      let contentsHash = when E is BasicType:
        chunkedHashTreeRootForBasicTypes(merkleizer, asSeq x)
      else:
        for elem in x:
          let elemHash = hash_tree_root(elem)
          merkleizer.addChunk(elemHash.data)
        merkleizer.getFinalHash()
      mixInLength(contentsHash, x.len)
  else:
    hashTreeRootAux toSszType(x)

  trs "HASH TREE ROOT FOR ", name(type x), " = ", "0x", $result

iterator hash_tree_roots_prefix*[T](lst: openarray[T], limit: static Limit): Eth2Digest =
  # This is a particular type's instantiation of a general fold, reduce,
  # accumulation, prefix sums, etc family of operations. As long as that
  # Eth1 deposit case is the only notable example -- the usual uses of a
  # list involve, at some point, tree-hashing it -- finalized hashes are
  # the only abstraction that escapes from this module this way.
  var merkleizer = createMerkleizer(limit)
  for i, elem in lst:
    merkleizer.addChunk(hash_tree_root(elem).data)
    yield mixInLength(merkleizer.getFinalHash(), i + 1)
