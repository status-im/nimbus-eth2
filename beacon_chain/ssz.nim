# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# SSZ Serialization (simple serialize)
# See https://github.com/ethereum/eth2.0-specs/blob/master/specs/simple-serialize.md

import
  endians, stew/shims/macros, options, algorithm, options,
  stew/[bitops2, bitseqs, objects, varints, ptrops, ranges/ptr_arith], stint,
  faststreams/input_stream, serialization, serialization/testing/tracing,
  nimcrypto/sha2, blscurve,
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
    stream: ByteStreamVar
    maxObjectSize: int

  SszWriter* = object
    stream: OutputStreamVar

  BasicType = char|bool|SomeUnsignedInt|StUint|ValidatorIndex

  SszChunksMerkelizer = ref object of RootObj
    combinedChunks: array[maxChunkTreeDepth, Eth2Digest]
    totalChunks: uint64
    limit: uint64

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
           stream: ByteStreamVar,
           maxObjectSize = defaultMaxObjectSize): T =
  T(stream: stream, maxObjectSize: maxObjectSize)

proc mount*(F: type SSZ, stream: ByteStreamVar, T: type): T =
  mixin readValue
  var reader = init(SszReader, stream)
  reader.readValue(T)

method formatMsg*(err: ref SszSizeMismatchError, filename: string): string {.gcsafe.} =
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
  elif x is BlsValue|BlsCurveType: getBytes(x)
  elif x is BitSeq|BitList: ByteList(x)
  elif x is ref|ptr: toSszType x[]
  elif x is Option: toSszType x.get
  elif x is TypeWithMaxLen: toSszType valueOf(x)
  elif useListType and x is List: seq[x.T](x)
  else: x

func writeFixedSized(c: var WriteCursor, x: auto) =
  mixin toSszType

  when x is byte:
    c.append x
  elif x is bool|char:
    c.append byte(ord(x))
  elif x is SomeUnsignedInt:
    when system.cpuEndian == bigEndian:
      ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
      ## All integers are serialized as **little endian**.
      var bytes: array[sizeof(x), byte]
      when x.sizeof == 8: littleEndian64(addr bytes[0], x.unsafeAddr)
      elif x.sizeof == 4: littleEndian32(addr bytes[0], x.unsafeAddr)
      elif x.sizeof == 2: littleEndian16(addr bytes[0], x.unsafeAddr)
      elif x.sizeof == 1: copyMem(addr bytes[0], x.unsafeAddr, sizeof(x))
      else: unsupported x.type
      c.append bytes
    else:
      let valueAddr {.used.} = unsafeAddr x
      trs "APPENDING INT ", x, " = ", makeOpenArray(cast[ptr byte](valueAddr), sizeof(x))
      c.appendMemCopy x
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

template writeFixedSized(s: OutputStreamVar, x: auto) =
  writeFixedSized(s.cursor, x)

template supports*(_: type SSZ, T: type): bool =
  mixin toSszType
  anonConst compiles(fixedPortionSize toSszType(default(T)))

func init*(T: type SszWriter, stream: OutputStreamVar): T =
  result.stream = stream

template enumerateSubFields(holder, fieldVar, body: untyped) =
  when holder is array|string|seq|openarray:
    for fieldVar in holder: body
  else:
    enumInstanceSerializedFields(holder, _, fieldVar): body

func writeVarSizeType(w: var SszWriter, value: auto) {.gcsafe.}

func beginRecord*(w: var SszWriter, TT: type): auto =
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

func writeVarSizeType(w: var SszWriter, value: auto) =
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
        when elem is Option:
          if not isSome(elem): continue
        elif elem is ptr|ref:
          if isNil(elem): continue
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

func writeValue*(w: var SszWriter, x: auto) {.gcsafe.} =
  mixin toSszType
  type T = type toSszType(x)

  when isFixedSize(T):
    w.stream.writeFixedSized toSszType(x)
  elif T is array|seq|openarray|string|object|tuple:
    w.writeVarSizeType toSszType(x)
  else:
    unsupported type(x)

func writeValue*[T](w: var SszWriter, x: SizePrefixed[T]) =
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

proc readValue*[T](r: var SszReader, val: var T) =
  when isFixedSize(T):
    const minimalSize = fixedPortionSize(T)
    if r.stream[].ensureBytes(minimalSize):
      val = readSszValue(r.stream.readBytes(minimalSize), T)
    else:
      raise newException(MalformedSszError, "SSZ input of insufficient size")
  else:
    # TODO Read the fixed portion first and precisely measure the size of
    # the dynamic portion to consume the right number of bytes.
    val = readSszValue(r.stream.readBytes(r.stream.endPos), T)

proc readValue*[T](r: var SszReader, val: var SizePrefixed[T]) =
  let length = r.stream.readVarint(uint64)
  if length > r.maxObjectSize:
    raise newException(SszMaxSizeExceeded,
                       "Maximum SSZ object size exceeded: " & $length)
  val = readSszValue(r.stream.readBytes(length), T)

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

func addChunk(merkelizer: SszChunksMerkelizer, data: openarray[byte]) =
  doAssert data.len > 0 and data.len <= bytesPerChunk

  if not getBitLE(merkelizer.totalChunks, 0):
    let chunkStartAddr = addr merkelizer.combinedChunks[0].data[0]
    copyMem(chunkStartAddr, unsafeAddr data[0], data.len)
    zeroMem(chunkStartAddr.offset(data.len), bytesPerChunk - data.len)
    trs "WROTE BASE CHUNK ", merkelizer.combinedChunks[0]
  else:
    var hash = mergeBranches(merkelizer.combinedChunks[0], data)

    for i in 1 .. high(merkelizer.combinedChunks):
      trs "ITERATING"
      if getBitLE(merkelizer.totalChunks, i):
        trs "CALLING MERGE BRANCHES"
        hash = mergeBranches(merkelizer.combinedChunks[i], hash)
      else:
        trs "WRITING FRESH CHUNK AT ", i, " = ", hash
        merkelizer.combinedChunks[i] = hash
        break

  inc merkelizer.totalChunks

func getFinalHash(merkelizer: SszChunksMerkelizer): Eth2Digest =
  let limit = merkelizer.limit

  if merkelizer.totalChunks == 0:
    let limitHeight = if limit != 0: bitWidth(limit - 1) else: 0
    return getZeroHashWithoutSideEffect(limitHeight)

  let
    bottomHashIdx = firstOne(merkelizer.totalChunks) - 1
    submittedChunksHeight = bitWidth(merkelizer.totalChunks - 1)
    topHashIdx = if limit <= 1: submittedChunksHeight
                 else: max(submittedChunksHeight, bitWidth(limit - 1))

  trs "BOTTOM HASH ", bottomHashIdx
  trs "SUBMITTED HEIGHT ", submittedChunksHeight
  trs "LIMIT ", limit

  if bottomHashIdx != submittedChunksHeight:
    # Our tree is not finished. We must complete the work in progress
    # branches and then extend the tree to the right height.
    result = mergeBranches(merkelizer.combinedChunks[bottomHashIdx],
                           getZeroHashWithoutSideEffect(bottomHashIdx))

    for i in bottomHashIdx + 1 ..< topHashIdx:
      if getBitLE(merkelizer.totalChunks, i):
        result = mergeBranches(merkelizer.combinedChunks[i], result)
        trs "COMBINED"
      else:
        result = mergeBranches(result, getZeroHashWithoutSideEffect(i))
        trs "COMBINED WITH ZERO"

  elif bottomHashIdx == topHashIdx:
    # We have a perfect tree (chunks == 2**n) at just the right height!
    result = merkelizer.combinedChunks[bottomHashIdx]
  else:
    # We have a perfect tree of user chunks, but we have more work to
    # do - we must extend it to reach the desired height
    result = mergeBranches(merkelizer.combinedChunks[bottomHashIdx],
                           getZeroHashWithoutSideEffect(bottomHashIdx))

    for i in bottomHashIdx + 1 ..< topHashIdx:
      result = mergeBranches(result, getZeroHashWithoutSideEffect(i))

let HashingStreamVTable = OutputStreamVTable(
  writePage: proc (s: OutputStreamVar, data: openarray[byte])
                  {.nimcall, gcsafe, raises: [IOError].} =
    trs "ADDING STREAM CHUNK ", data
    SszChunksMerkelizer(s.outputDevice).addChunk(data)
  ,
  flush: proc (s: OutputStreamVar) {.nimcall, gcsafe.} =
    discard
)

func getVtableAddresWithoutSideEffect: ptr OutputStreamVTable =
  # TODO this is a work-around for the somewhat broken side
  # effects analysis of Nim - reading from global let variables
  # is considered a side-effect.
  {.noSideEffect.}:
    unsafeAddr HashingStreamVTable

func newSszHashingStream(merkelizer: SszChunksMerkelizer): ref OutputStream =
  new result
  result.initWithSinglePage(pageSize = bytesPerChunk,
                            maxWriteSize = bytesPerChunk,
                            minWriteSize = bytesPerChunk)
  result.outputDevice = merkelizer
  result.vtable = getVtableAddresWithoutSideEffect()

func mixInLength(root: Eth2Digest, length: int): Eth2Digest =
  var dataLen: array[32, byte]
  var lstLen = uint64(length)
  littleEndian64(addr dataLen[0], addr lstLen)
  hash(root.data, dataLen)

func merkelizeSerializedChunks(merkelizer: SszChunksMerkelizer,
                               obj: auto): Eth2Digest =
  var hashingStream = newSszHashingStream merkelizer
  hashingStream.writeFixedSized obj
  hashingStream.flush
  merkelizer.getFinalHash

func merkelizeSerializedChunks(obj: auto): Eth2Digest =
  merkelizeSerializedChunks(SszChunksMerkelizer(), obj)

func hash_tree_root*(x: auto): Eth2Digest {.gcsafe.}

template merkelizeFields(body: untyped): Eth2Digest {.dirty.} =
  var merkelizer {.inject.} = SszChunksMerkelizer()

  template addField(field) =
    let hash = hash_tree_root(field)
    trs "MERKLEIZING FIELD ", astToStr(field), " = ", hash
    addChunk(merkelizer, hash.data)
    trs "CHUNK ADDED"

  template addField2(field) {.used.}=
    const maxLen = fieldMaxLen(field)
    when maxLen > 0:
      type FieldType = type field
      addField TypeWithMaxLen[FieldType, maxLen](field)
    else:
      addField field

  body

  merkelizer.getFinalHash

func bitlistHashTreeRoot(merkelizer: SszChunksMerkelizer, x: BitSeq): Eth2Digest =
  trs "CHUNKIFYING BIT SEQ WITH LIMIT ", merkelizer.limit

  var
    totalBytes = ByteList(x).len
    lastCorrectedByte = ByteList(x)[^1]

  if lastCorrectedByte == byte(1):
    if totalBytes == 1:
      # This is an empty bit list.
      # It should be hashed as a tree containing all zeros:
      let treeHeight = if merkelizer.limit == 0: 0
                       else: log2trunc(merkelizer.limit)
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

    merkelizer.addChunk ByteList(x).toOpenArray(chunkEndPos, chunkEndPos)

  var
    lastChunk: array[bytesPerChunk, byte]
    chunkStartPos = fullChunks * bytesPerChunk

  for i in 0 .. bytesInLastChunk - 2:
    lastChunk[i] = ByteList(x)[chunkStartPos + i]

  lastChunk[bytesInLastChunk - 1] = lastCorrectedByte

  merkelizer.addChunk lastChunk.toOpenArray(0, bytesInLastChunk - 1)
  let contentsHash = merkelizer.getFinalHash
  mixInLength contentsHash, x.len

func hashTreeRootImpl[T](x: T): Eth2Digest =
  when T is uint64:
    trs "UINT64; LITTLE-ENDIAN IDENTITY MAPPING"
    when system.cpuEndian == bigEndian:
      littleEndian64(addr result.data[0], x.unsafeAddr)
    else:
      let valueAddr = unsafeAddr x
      result.data[0..7] = makeOpenArray(cast[ptr byte](valueAddr), 8)
  elif (when T is array: ElemType(T) is byte and
      sizeof(T) == sizeof(Eth2Digest) else: false):
    # TODO is this sizeof comparison guranteed? it's whole structure vs field
    trs "ETH2DIGEST; IDENTITY MAPPING"
    Eth2Digest(data: x)
  elif (T is BasicType) or (when T is array: ElemType(T) is BasicType else: false):
    trs "FIXED TYPE; USE CHUNK STREAM"
    merkelizeSerializedChunks x
  elif T is string or (when T is (seq|openarray): ElemType(T) is BasicType else: false):
    trs "TYPE WITH LENGTH"
    mixInLength merkelizeSerializedChunks(x), x.len
  elif T is array|object|tuple:
    trs "MERKELIZING FIELDS"
    merkelizeFields:
      x.enumerateSubFields(f):
        const maxLen = fieldMaxLen(f)
        when maxLen > 0:
          type FieldType = type f
          addField TypeWithMaxLen[FieldType, maxLen](f)
        else:
          addField f
  elif T is seq:
    trs "SEQ WITH VAR SIZE"
    let hash = merkelizeFields(for e in x: addField e)
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

func hash_tree_root*(x: auto): Eth2Digest =
  trs "STARTING HASH TREE ROOT FOR TYPE ", name(type(x))
  mixin toSszType
  when x is SignedBeaconBlock:
    doassert false
  when x is TypeWithMaxLen:
    const maxLen = x.maxLen
    type T = type valueOf(x)
    const limit = maxChunksCount(T, maxLen)
    var merkelizer = SszChunksMerkelizer(limit: uint64(limit))

    when T is BitList:
      result = merkelizer.bitlistHashTreeRoot(BitSeq valueOf(x))
    elif T is seq:
      type E = ElemType(T)
      let contentsHash = when E is BasicType:
        merkelizeSerializedChunks(merkelizer, valueOf(x))
      else:
        for elem in valueOf(x):
          let elemHash = hash_tree_root(elem)
          merkelizer.addChunk(elemHash.data)
        merkelizer.getFinalHash()
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
  var merkelizer = SszChunksMerkelizer(limit: uint64(limit))
  for i, elem in lst:
    merkelizer.addChunk(hash_tree_root(elem).data)
    yield mixInLength(merkelizer.getFinalHash(), i + 1)
