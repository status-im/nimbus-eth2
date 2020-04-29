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

import
  stew/shims/macros, options, algorithm, options,
  stew/[bitops2, bitseqs, endians2, objects, varints, ptrops, ranges/ptr_arith], stint,
  faststreams/input_stream, serialization, serialization/testing/tracing,
  ./spec/[crypto, datatypes, digest],
  ./ssz/[types, bytes_reader]

# ################### Helper functions ###################################

export
  serialization, types, bytes_reader

when defined(serialization_tracing):
  import
    typetraits, stew/ranges/ptr_arith

const
  bytesPerChunk = 32
  bitsPerChunk = bytesPerChunk * 8
  maxChunkTreeDepth = 25
  defaultMaxObjectSize = 1 * 1024 * 1024

type
  SszReader* = object
    stream: InputStream
    maxObjectSize: int

  SszWriter* = object
    stream: OutputStream

  BasicType = char|bool|SomeUnsignedInt|StUint|ValidatorIndex

  SszChunksMerkleizer = ref object
    combinedChunks: array[maxChunkTreeDepth, Eth2Digest]
    totalChunks: uint64
    limit: uint64

  SszHashingStream = ref object of OutputStream
    merkleizer: SszChunksMerkleizer

  TypeWithMaxLen*[T; maxLen: static int64] = distinct T

  SizePrefixed*[T] = distinct T
  SszMaxSizeExceeded* = object of SerializationError

  VarSizedWriterCtx = object
    fixedParts: WriteCursor
    offset: int

  FixedSizedWriterCtx = object

  ByteList = seq[byte]

serializationFormat SSZ,
                    Reader = SszReader,
                    Writer = SszWriter,
                    PreferedOutput = seq[byte]

template sizePrefixed*[TT](x: TT): untyped =
  type T = TT
  SizePrefixed[T](x)

proc init*(T: type SszReader,
           stream: InputStream,
           maxObjectSize = defaultMaxObjectSize): T {.raises: [Defect].} =
  T(stream: stream, maxObjectSize: maxObjectSize)

proc mount*(F: type SSZ, stream: InputStream, T: type): T {.raises: [Defect].} =
  mixin readValue
  var reader = init(SszReader, stream)
  reader.readValue(T)

method formatMsg*(err: ref SszSizeMismatchError, filename: string): string {.gcsafe, raises: [Defect].} =
  # TODO: implement proper error string
  "Serialisation error while processing " & filename

when false:
  # TODO: Nim can't handle yet this simpler definition. File an issue.
  template valueOf[T; N](x: TypeWithMaxLen[T, N]): auto = T(x)
else:
  proc unwrapImpl[T; N: static int64](x: ptr TypeWithMaxLen[T, N]): ptr T =
    cast[ptr T](x)

  template valueOf(x: TypeWithMaxLen): auto =
    let xaddr = unsafeAddr x
    unwrapImpl(xaddr)[]

template sszList*(x: seq|array, maxLen: static int64): auto =
  TypeWithMaxLen[type(x), maxLen](x)

template toSszType*(x: auto): auto =
  mixin toSszType

  when x is Slot|Epoch|ValidatorIndex|enum: uint64(x)
  elif x is Eth2Digest: x.data
  elif x is BlsCurveType: toRaw(x)
  elif x is BitSeq|BitList: ByteList(x)
  elif x is TypeWithMaxLen: toSszType valueOf(x)
  elif useListType and x is List: seq[x.T](x)
  else: x

proc writeFixedSized(c: var WriteCursor, x: auto) {.raises: [Defect, IOError].} =
  mixin toSszType

  when x is byte:
    c.append x
  elif x is bool|char:
    c.append byte(ord(x))
  elif x is SomeUnsignedInt:
    let value = x.toBytesLE()
    trs "APPENDING INT ", x, " = ", value
    c.appendMemCopy value
  elif x is StUint:
    c.appendMemCopy x # TODO: Is this always correct?
  elif x is array|string|seq|openarray:
    when x[0] is byte:
      trs "APPENDING FIXED SIZE BYTES", x
      c.append x
    else:
      for elem in x:
        trs "WRITING FIXED SIZE ARRAY ELEMENT"
        c.writeFixedSized toSszType(elem)
  elif x is tuple|object:
    enumInstanceSerializedFields(x, fieldName, field):
      trs "WRITING FIXED SIZE FIELD", fieldName
      c.writeFixedSized toSszType(field)
  else:
    unsupported x.type

template writeFixedSized(s: OutputStream, x: auto) =
  writeFixedSized(s.cursor, x)

template supports*(_: type SSZ, T: type): bool =
  mixin toSszType
  anonConst compiles(fixedPortionSize toSszType(declval T))

func init*(T: type SszWriter, stream: OutputStream): T {.raises: [Defect].} =
  result.stream = stream

template enumerateSubFields(holder, fieldVar, body: untyped) =
  when holder is array|string|seq|openarray:
    for fieldVar in holder: body
  else:
    enumInstanceSerializedFields(holder, _, fieldVar): body

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
      ctx.fixedParts.writeFixedSized toSszType(field)
    else:
      trs "WRITING OFFSET ", ctx.offset, " FOR ", fieldName
      ctx.fixedParts.writeFixedSized uint32(ctx.offset)
      let initPos = w.stream.pos
      trs "WRITING VAR SIZE VALUE OF TYPE ", name(FieldType)
      when FieldType is BitSeq:
        trs "BIT SEQ ", ByteList(field)
      writeVarSizeType(w, toSszType(field))
      ctx.offset += w.stream.pos - initPos

template endRecord*(w: var SszWriter, ctx: var auto) =
  when ctx is VarSizedWriterCtx:
    finalize ctx.fixedParts

proc writeVarSizeType(w: var SszWriter, value: auto) {.raises: [Defect, IOError].} =
  trs "STARTING VAR SIZE TYPE"
  mixin toSszType
  type T = type toSszType(value)

  when T is seq|string|openarray:
    type E = ElemType(T)
    const isFixed = when E is Option: false
                    else: isFixedSize(E)
    when isFixed:
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

  elif T is object|tuple|array:
    trs "WRITING OBJECT OR ARRAY"
    var ctx = beginRecord(w, T)
    enumerateSubFields(value, field):
      writeField w, ctx, astToStr(field), field
    endRecord w, ctx

proc writeValue*(w: var SszWriter, x: auto) {.gcsafe, raises: [Defect, IOError].} =
  mixin toSszType
  type T = type toSszType(x)

  when isFixedSize(T):
    w.stream.writeFixedSized toSszType(x)
  elif T is array|seq|openarray|string|object|tuple:
    w.writeVarSizeType toSszType(x)
  else:
    unsupported type(x)

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
    buf.appendVarint length
    cursor.writeAndFinalize buf.writtenBytes

template fromSszBytes*[T; N](_: type TypeWithMaxLen[T, N],
                             bytes: openarray[byte]): auto =
  mixin fromSszBytes
  fromSszBytes(T, bytes)

proc readValue*[T](r: var SszReader, val: var T) {.raises: [Defect, MalformedSszError, SszSizeMismatchError].} =
  when isFixedSize(T):
    const minimalSize = fixedPortionSize(T)
    if r.stream.readable(minimalSize):
      val = readSszValue(r.stream.read(minimalSize), T)
    else:
      raise newException(MalformedSszError, "SSZ input of insufficient size")
  else:
    # TODO Read the fixed portion first and precisely measure the size of
    # the dynamic portion to consume the right number of bytes.
    val = readSszValue(r.stream.read(r.stream.endPos), T)

proc readValue*[T](r: var SszReader, val: var SizePrefixed[T]) {.raises: [Defect].} =
  let length = r.stream.readVarint(uint64)
  if length > r.maxObjectSize:
    raise newException(SszMaxSizeExceeded,
                       "Maximum SSZ object size exceeded: " & $length)
  val = readSszValue(r.stream.read(length), T)

const
  zeroChunk = default array[32, byte]

func hash(a, b: openArray[byte]): Eth2Digest =
  result = withEth2Hash:
    trs "MERGING BRANCHES "
    trs a
    trs b

    h.update a
    h.update b
  trs "HASH RESULT ", result

func mergeBranches(existing: Eth2Digest, newData: openarray[byte]): Eth2Digest =
  result = withEth2Hash:
    trs "MERGING BRANCHES OPEN ARRAY"
    trs existing.data
    trs newData

    h.update existing.data
    h.update newData

    let paddingBytes = bytesPerChunk - newData.len
    if paddingBytes > 0:
      trs "USING ", paddingBytes, " PADDING BYTES"
      h.update zeroChunk[0 ..< paddingBytes]
  trs "HASH RESULT ", result

template mergeBranches(a, b: Eth2Digest): Eth2Digest =
  hash(a.data, b.data)

func computeZeroHashes: array[100, Eth2Digest] =
  result[0] = Eth2Digest(data: zeroChunk)
  for i in 1 .. result.high:
    result[i] = mergeBranches(result[i - 1], result[i - 1])

let zeroHashes = computeZeroHashes()

func getZeroHashWithoutSideEffect(idx: int): Eth2Digest =
  # TODO this is a work-around for the somewhat broken side
  # effects analysis of Nim - reading from global let variables
  # is considered a side-effect.
  {.noSideEffect.}:
    zeroHashes[idx]

func addChunk(merkleizer: SszChunksMerkleizer, data: openarray[byte]) =
  doAssert data.len > 0 and data.len <= bytesPerChunk

  if not getBitLE(merkleizer.totalChunks, 0):
    let chunkStartAddr = addr merkleizer.combinedChunks[0].data[0]
    copyMem(chunkStartAddr, unsafeAddr data[0], data.len)
    zeroMem(chunkStartAddr.offset(data.len), bytesPerChunk - data.len)
    trs "WROTE BASE CHUNK ", merkleizer.combinedChunks[0]
  else:
    var hash = mergeBranches(merkleizer.combinedChunks[0], data)

    for i in 1 .. high(merkleizer.combinedChunks):
      trs "ITERATING"
      if getBitLE(merkleizer.totalChunks, i):
        trs "CALLING MERGE BRANCHES"
        hash = mergeBranches(merkleizer.combinedChunks[i], hash)
      else:
        trs "WRITING FRESH CHUNK AT ", i, " = ", hash
        merkleizer.combinedChunks[i] = hash
        break

  inc merkleizer.totalChunks

func getFinalHash(merkleizer: SszChunksMerkleizer): Eth2Digest =
  let limit = merkleizer.limit

  if merkleizer.totalChunks == 0:
    let limitHeight = if limit != 0: bitWidth(limit - 1) else: 0
    return getZeroHashWithoutSideEffect(limitHeight)

  let
    bottomHashIdx = firstOne(merkleizer.totalChunks) - 1
    submittedChunksHeight = bitWidth(merkleizer.totalChunks - 1)
    topHashIdx = if limit <= 1: submittedChunksHeight
                 else: max(submittedChunksHeight, bitWidth(limit - 1))

  trs "BOTTOM HASH ", bottomHashIdx
  trs "SUBMITTED HEIGHT ", submittedChunksHeight
  trs "LIMIT ", limit

  if bottomHashIdx != submittedChunksHeight:
    # Our tree is not finished. We must complete the work in progress
    # branches and then extend the tree to the right height.
    result = mergeBranches(merkleizer.combinedChunks[bottomHashIdx],
                           getZeroHashWithoutSideEffect(bottomHashIdx))

    for i in bottomHashIdx + 1 ..< topHashIdx:
      if getBitLE(merkleizer.totalChunks, i):
        result = mergeBranches(merkleizer.combinedChunks[i], result)
        trs "COMBINED"
      else:
        result = mergeBranches(result, getZeroHashWithoutSideEffect(i))
        trs "COMBINED WITH ZERO"

  elif bottomHashIdx == topHashIdx:
    # We have a perfect tree (chunks == 2**n) at just the right height!
    result = merkleizer.combinedChunks[bottomHashIdx]
  else:
    # We have a perfect tree of user chunks, but we have more work to
    # do - we must extend it to reach the desired height
    result = mergeBranches(merkleizer.combinedChunks[bottomHashIdx],
                           getZeroHashWithoutSideEffect(bottomHashIdx))

    for i in bottomHashIdx + 1 ..< topHashIdx:
      result = mergeBranches(result, getZeroHashWithoutSideEffect(i))

let SszHashingStreamVTable = OutputStreamVTable(
  writePageSync: proc (s: OutputStream, data: openarray[byte])
                      {.nimcall, gcsafe, raises: [Defect, IOError].} =
    trs "ADDING STREAM CHUNK ", data
    SszHashingStream(s).merkleizer.addChunk(data)
  ,
  flushSync: proc (s: OutputStream) {.nimcall, gcsafe.} =
    discard
)

func newSszHashingStream(merkleizer: SszChunksMerkleizer): OutputStream =
  result = SszHashingStream(vtable: vtableAddr SszHashingStreamVTable,
                            pageSize: bytesPerChunk,
                            maxWriteSize: bytesPerChunk,
                            minWriteSize: bytesPerChunk,
                            merkleizer: merkleizer)
  result.initWithSinglePage()

func mixInLength(root: Eth2Digest, length: int): Eth2Digest =
  var dataLen: array[32, byte]
  dataLen[0..<8] = uint64(length).toBytesLE()
  hash(root.data, dataLen)

func merkleizeSerializedChunks(merkleizer: SszChunksMerkleizer,
                               obj: auto): Eth2Digest =
  try:
    var hashingStream = newSszHashingStream merkleizer
    {.noSideEffect.}:
      # We assume there are no side-effects here, because the
      # SszHashingStream is keeping all of its output in memory.
      hashingStream.writeFixedSized obj
      hashingStream.flush
    merkleizer.getFinalHash
  except IOError as e:
    # Hashing shouldn't raise in theory but because of abstraction
    # tax in the faststreams library, we have to do this at runtime
    raiseAssert($e.msg)

func merkleizeSerializedChunks(obj: auto): Eth2Digest =
  merkleizeSerializedChunks(SszChunksMerkleizer(), obj)

func hash_tree_root*(x: auto): Eth2Digest {.gcsafe, raises: [Defect].}

template merkleizeFields(body: untyped): Eth2Digest {.dirty.} =
  var merkleizer {.inject.} = SszChunksMerkleizer()

  template addField(field) =
    let hash = hash_tree_root(field)
    trs "MERKLEIZING FIELD ", astToStr(field), " = ", hash
    addChunk(merkleizer, hash.data)
    trs "CHUNK ADDED"

  template addField2(field) {.used.}=
    const maxLen = fieldMaxLen(field)
    when maxLen > 0:
      type FieldType = type field
      addField TypeWithMaxLen[FieldType, maxLen](field)
    else:
      addField field

  body

  merkleizer.getFinalHash

func bitlistHashTreeRoot(merkleizer: SszChunksMerkleizer, x: BitSeq): Eth2Digest =
  trs "CHUNKIFYING BIT SEQ WITH LIMIT ", merkleizer.limit

  var
    totalBytes = ByteList(x).len
    lastCorrectedByte = ByteList(x)[^1]

  if lastCorrectedByte == byte(1):
    if totalBytes == 1:
      # This is an empty bit list.
      # It should be hashed as a tree containing all zeros:
      let treeHeight = if merkleizer.limit == 0: 0
                       else: log2trunc(merkleizer.limit)
      return mergeBranches(getZeroHashWithoutSideEffect(treeHeight),
                           getZeroHashWithoutSideEffect(0)) # this is the mixed length

    totalBytes -= 1
    lastCorrectedByte = ByteList(x)[^2]
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

    merkleizer.addChunk ByteList(x).toOpenArray(chunkEndPos, chunkEndPos)

  var
    lastChunk: array[bytesPerChunk, byte]
    chunkStartPos = fullChunks * bytesPerChunk

  for i in 0 .. bytesInLastChunk - 2:
    lastChunk[i] = ByteList(x)[chunkStartPos + i]

  lastChunk[bytesInLastChunk - 1] = lastCorrectedByte

  merkleizer.addChunk lastChunk.toOpenArray(0, bytesInLastChunk - 1)
  let contentsHash = merkleizer.getFinalHash
  mixInLength contentsHash, x.len

func hashTreeRootImpl[T](x: T): Eth2Digest =
  when T is SignedBeaconBlock:
    unsupported T # Blocks are identified by htr(BeaconBlock) so we avoid these
  elif T is uint64:
    trs "UINT64; LITTLE-ENDIAN IDENTITY MAPPING"
    result.data[0..<8] = x.toBytesLE()
  elif (when T is array: ElemType(T) is byte and
      sizeof(T) == sizeof(Eth2Digest) else: false):
    # TODO is this sizeof comparison guranteed? it's whole structure vs field
    trs "ETH2DIGEST; IDENTITY MAPPING"
    Eth2Digest(data: x)
  elif (T is BasicType) or (when T is array: ElemType(T) is BasicType else: false):
    trs "FIXED TYPE; USE CHUNK STREAM"
    merkleizeSerializedChunks x
  elif T is string or (when T is (seq|openarray): ElemType(T) is BasicType else: false):
    trs "TYPE WITH LENGTH"
    mixInLength merkleizeSerializedChunks(x), x.len
  elif T is array|object|tuple:
    trs "MERKLEIZING FIELDS"
    merkleizeFields:
      x.enumerateSubFields(f):
        const maxLen = fieldMaxLen(f)
        when maxLen > 0:
          type FieldType = type f
          addField TypeWithMaxLen[FieldType, maxLen](f)
        else:
          addField f
  elif T is seq:
    trs "SEQ WITH VAR SIZE"
    let hash = merkleizeFields(for e in x: addField e)
    mixInLength hash, x.len
  #elif isCaseObject(T):
  #  # TODO implement this
  else:
    unsupported T

func maxChunksCount(T: type, maxLen: static int64): int64 {.compileTime.} =
  when T is BitList:
    (maxLen + bitsPerChunk - 1) div bitsPerChunk
  elif T is seq:
    type E = ElemType(T)
    when E is BasicType:
      (maxLen * sizeof(E) + bytesPerChunk - 1) div bytesPerChunk
    else:
      maxLen
  else:
    unsupported T # This should never happen

func hash_tree_root*(x: auto): Eth2Digest {.raises: [Defect].} =
  trs "STARTING HASH TREE ROOT FOR TYPE ", name(type(x))
  mixin toSszType
  when x is TypeWithMaxLen:
    const maxLen = x.maxLen
    type T = type valueOf(x)
    const limit = maxChunksCount(T, maxLen)
    var merkleizer = SszChunksMerkleizer(limit: uint64(limit))

    when T is BitList:
      result = merkleizer.bitlistHashTreeRoot(BitSeq valueOf(x))
    elif T is seq:
      type E = ElemType(T)
      let contentsHash = when E is BasicType:
        merkleizeSerializedChunks(merkleizer, valueOf(x))
      else:
        for elem in valueOf(x):
          let elemHash = hash_tree_root(elem)
          merkleizer.addChunk(elemHash.data)
        merkleizer.getFinalHash()
      result = mixInLength(contentsHash, valueOf(x).len)
    else:
      unsupported T # This should never happen
  else:
    result = hashTreeRootImpl toSszType(x)

  trs "HASH TREE ROOT FOR ", name(type x), " = ", "0x", $result

iterator hash_tree_roots_prefix*[T](lst: openarray[T], limit: auto):
    Eth2Digest =
  # This is a particular type's instantiation of a general fold, reduce,
  # accumulation, prefix sums, etc family of operations. As long as that
  # Eth1 deposit case is the only notable example -- the usual uses of a
  # list involve, at some point, tree-hashing it -- finalized hashes are
  # the only abstraction that escapes from this module this way.
  var merkleizer = SszChunksMerkleizer(limit: uint64(limit))
  for i, elem in lst:
    merkleizer.addChunk(hash_tree_root(elem).data)
    yield mixInLength(merkleizer.getFinalHash(), i + 1)
