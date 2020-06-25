{.push raises: [Defect].}

import
  tables, options, typetraits, strformat,
  stew/shims/macros, stew/[byteutils, bitops2, objects],
  serialization/[object_serialization, errors],
  ./spec_types, ./bitseqs,
  ../spec/digest

export bitseqs

const
  offsetSize* = 4
  bytesPerChunk* = 32

type
  UintN* = SomeUnsignedInt # TODO: Add StUint here
  BasicType* = bool|UintN

  Limit* = int64

# A few index types from here onwards:
# * dataIdx - leaf index starting from 0 to maximum length of collection
# * chunkIdx - leaf data index after chunking starting from 0
# * vIdx - virtual index in merkle tree - the root is found at index 1, its
#          two children at 2, 3 then 4, 5, 6, 7 etc

func nextPow2Int64(x: int64): int64 =
  # TODO the nextPow2 in bitops2 works with uint64 - there's a bug in the nim
  #      compiler preventing it to be used - it seems that a conversion to
  #      uint64 cannot be done with the static maxLen :(
  var v = x - 1

  # round down, make sure all bits are 1 below the threshold, then add 1
  v = v or v shr 1
  v = v or v shr 2
  v = v or v shr 4
  when bitsof(x) > 8:
    v = v or v shr 8
  when bitsof(x) > 16:
    v = v or v shr 16
  when bitsof(x) > 32:
    v = v or v shr 32

  v + 1

template dataPerChunk(T: type): int =
  # How many data items fit in a chunk
  when T is BasicType:
    bytesPerChunk div sizeof(T)
  else:
    1

template chunkIdx*(T: type, dataIdx: int64): int64 =
  # Given a data index, which chunk does it belong to?
  dataIdx div dataPerChunk(T)

template maxChunkIdx*(T: type, maxLen: int64): int64 =
  # Given a number of data items, how many chunks are needed?
  # TODO compiler bug:
  # beacon_chain/ssz/types.nim(75, 53) Error: cannot generate code for: maxLen
  # nextPow2(chunkIdx(T, maxLen + dataPerChunk(T) - 1).uint64).int64
  nextPow2Int64(chunkIdx(T, maxLen + dataPerChunk(T) - 1))

template layer*(vIdx: int64): int =
  ## Layer 0 = layer at which the root hash is
  ## We place the root hash at index 1 which simplifies the math and leaves
  ## index 0 for the mixed-in-length
  log2trunc(vIdx.uint64).int

type
  List*[T; maxLen: static Limit] = distinct seq[T]
  BitList*[maxLen: static Limit] = distinct BitSeq

  HashArray*[maxLen: static Limit; T] = object
    data*: array[maxLen, T]
    hashes* {.dontSerialize.}: array[maxChunkIdx(T, maxLen), Eth2Digest]

  HashList*[T; maxLen: static Limit] = object
    data*: List[T, maxLen]
    hashes* {.dontSerialize.}: seq[Eth2Digest]
    indices* {.dontSerialize.}: array[int(layer(maxChunkIdx(T, maxLen))) + 1, int64]

  # Note for readers:
  # We use `array` for `Vector` and
  #        `BitArray` for `BitVector`

  SszError* = object of SerializationError

  MalformedSszError* = object of SszError

  SszSizeMismatchError* = object of SszError
    deserializedType*: cstring
    actualSszSize*: int
    elementSize*: int

template asSeq*(x: List): auto = distinctBase(x)

template init*[T](L: type List, x: seq[T], N: static Limit): auto =
  List[T, N](x)

template init*[T, N](L: type List[T, N], x: seq[T]): auto =
  List[T, N](x)

template `$`*(x: List): auto = $(distinctBase x)
template add*(x: var List, val: auto) = add(distinctBase x, val)
template len*(x: List): auto = len(distinctBase x)
template setLen*(x: var List, val: auto) = setLen(distinctBase x, val)
template low*(x: List): auto = low(distinctBase x)
template high*(x: List): auto = high(distinctBase x)
template `[]`*(x: List, idx: auto): untyped = distinctBase(x)[idx]
template `[]=`*(x: var List, idx: auto, val: auto) = distinctBase(x)[idx] = val
template `==`*(a, b: List): bool = distinctBase(a) == distinctBase(b)

template `&`*(a, b: List): auto = (type(a)(distinctBase(a) & distinctBase(b)))

template items* (x: List): untyped = items(distinctBase x)
template pairs* (x: List): untyped = pairs(distinctBase x)
template mitems*(x: var List): untyped = mitems(distinctBase x)
template mpairs*(x: var List): untyped = mpairs(distinctBase x)

template init*(L: type BitList, x: seq[byte], N: static Limit): auto =
  BitList[N](data: x)

template init*[N](L: type BitList[N], x: seq[byte]): auto =
  L(data: x)

template init*(T: type BitList, len: int): auto = T init(BitSeq, len)
template len*(x: BitList): auto = len(BitSeq(x))
template bytes*(x: BitList): auto = seq[byte](x)
template `[]`*(x: BitList, idx: auto): auto = BitSeq(x)[idx]
template `[]=`*(x: var BitList, idx: auto, val: bool) = BitSeq(x)[idx] = val
template `==`*(a, b: BitList): bool = BitSeq(a) == BitSeq(b)
template setBit*(x: var BitList, idx: int) = setBit(BitSeq(x), idx)
template clearBit*(x: var BitList, idx: int) = clearBit(BitSeq(x), idx)
template overlaps*(a, b: BitList): bool = overlaps(BitSeq(a), BitSeq(b))
template combine*(a: var BitList, b: BitList) = combine(BitSeq(a), BitSeq(b))
template isSubsetOf*(a, b: BitList): bool = isSubsetOf(BitSeq(a), BitSeq(b))
template `$`*(a: BitList): string = $(BitSeq(a))

iterator items*(x: BitList): bool =
  for i in 0 ..< x.len:
    yield x[i]

template isCached*(v: Eth2Digest): bool =
  ## An entry is "in the cache" if the first 8 bytes are zero - conveniently,
  ## Nim initializes values this way, and while there may be false positives,
  ## that's fine.
  v.data.toOpenArray(0, 7) != [byte 0, 0, 0, 0, 0, 0, 0, 0]
template clearCache*(v: var Eth2Digest) =
  v.data[0..<8] = [byte 0, 0, 0, 0, 0, 0, 0, 0]

template maxChunks*(a: HashList|HashArray): int64 =
  ## Layer where data is
  maxChunkIdx(a.T, a.maxLen)

template maxDepth*(a: HashList|HashArray): int =
  ## Layer where data is
  layer(nextPow2(a.maxChunks.uint64).int64)

template chunkIdx(a: HashList|HashArray, dataIdx: int64): int64 =
  chunkIdx(a.T, dataIdx)

proc clearCaches*(a: var HashArray, dataIdx: auto) =
  ## Clear all cache entries after data at dataIdx has been modified
  var idx = 1 shl (a.maxDepth - 1) + (chunkIdx(a, dataIdx) div 2)
  while idx != 0:
    clearCache(a.hashes[idx])
    idx = idx div 2

func nodesAtLayer*(layer, depth, leaves: int): int =
  ## Given a number of leaves, how many nodes do you need at a given layer
  ## in a binary tree structure?
  let leavesPerNode = 1'i64 shl (depth - layer)
  int((leaves + leavesPerNode - 1) div leavesPerNode)

func cacheNodes*(depth, leaves: int): int =
  ## Total number of nodes needed to cache a tree of a given depth with
  ## `leaves` items in it (the rest zero-filled)
  var res = 0
  for i in 0..<depth:
    res += nodesAtLayer(i, depth, leaves)
  res

proc clearCaches*(a: var HashList, dataIdx: int64) =
  if a.hashes.len == 0:
    return

  var
    idx = 1'i64 shl (a.maxDepth - 1) + (chunkIdx(a, dataIdx) div 2)
    layer = a.maxDepth - 1
  while idx > 0:
    let
      idxInLayer = idx - (1'i64 shl layer)
      layerIdx = idxInlayer + a.indices[layer]
    if layerIdx < a.indices[layer + 1]:
      clearCache(a.hashes[layerIdx])

    idx = idx div 2
    layer = layer - 1

  clearCache(a.hashes[0])

proc growHashes*(a: var HashList) =
  # Ensure that the hash cache is big enough for the data in the list
  let
    leaves = int(
      chunkIdx(a, a.data.len() + dataPerChunk(a.T) - 1))
    newSize = 1 + cacheNodes(a.maxDepth, leaves)

  if a.hashes.len >= newSize:
    return

  var
    newHashes = newSeq[Eth2Digest](newSize)
    newIndices = default(type a.indices)

  if a.hashes.len != newSize:
    newIndices[0] = nodesAtLayer(0, a.maxDepth, leaves)
    for i in 1..a.maxDepth:
      newIndices[i] = newIndices[i - 1] + nodesAtLayer(i - 1, a.maxDepth, leaves)

  for i in 1..<a.maxDepth:
    for j in 0..<(a.indices[i] - a.indices[i-1]):
      newHashes[newIndices[i - 1] + j] = a.hashes[a.indices[i - 1] + j]

  swap(a.hashes, newHashes)
  a.indices = newIndices

template len*(a: type HashArray): auto = int(a.maxLen)

template add*(x: var HashList, val: auto) =
  add(x.data, val)
  x.growHashes()
  clearCaches(x, x.data.len() - 1)

template len*(x: HashList|HashArray): auto = len(x.data)
template low*(x: HashList|HashArray): auto = low(x.data)
template high*(x: HashList|HashArray): auto = high(x.data)
template `[]`*(x: HashList|HashArray, idx: auto): auto = x.data[idx]

proc `[]`*(a: var HashArray, b: auto): var a.T =
  clearCaches(a, b.Limit)
  a.data[b]

proc `[]=`*(a: var HashArray, b: auto, c: auto) =
  clearCaches(a, b.Limit)
  a.data[b] = c

proc `[]`*(x: var HashList, idx: auto): var x.T =
  clearCaches(x, idx.int64)
  x.data[idx]

proc `[]=`*(x: var HashList, idx: auto, val: auto) =
  clearCaches(x, idx.int64)
  x.data[idx] = val

template `==`*(a, b: HashList|HashArray): bool = a.data == b.data
template asSeq*(x: HashList): auto = asSeq(x.data)
template `$`*(x: HashList): auto = $(x.data)

template items* (x: HashList|HashArray): untyped = items(x.data)
template pairs* (x: HashList|HashArray): untyped = pairs(x.data)

template fill*(a: var HashArray, c: auto) =
  mixin fill
  fill(a.data, c)
template sum*[maxLen; T](a: var HashArray[maxLen, T]): T =
  mixin sum
  sum(a.data)

macro unsupported*(T: typed): untyped =
  # TODO: {.fatal.} breaks compilation even in `compiles()` context,
  # so we use this macro instead. It's also much better at figuring
  # out the actual type that was used in the instantiation.
  # File both problems as issues.
  error "SSZ serialization of the type " & humaneTypeName(T) & " is not supported"

template ElemType*(T: type HashArray): untyped =
  T.T

template ElemType*(T: type HashList): untyped =
  T.T

template ElemType*(T: type array): untyped =
  type(default(T)[low(T)])

template ElemType*(T: type seq): untyped =
  type(default(T)[0])

template ElemType*(T: type List): untyped =
  T.T

func isFixedSize*(T0: type): bool {.compileTime.} =
  mixin toSszType, enumAllSerializedFields

  type T = type toSszType(declval T0)

  when T is BasicType:
    return true
  elif T is array|HashArray:
    return isFixedSize(ElemType(T))
  elif T is object|tuple:
    enumAllSerializedFields(T):
      when not isFixedSize(FieldType):
        return false
    return true

func fixedPortionSize*(T0: type): int {.compileTime.} =
  mixin enumAllSerializedFields, toSszType

  type T = type toSszType(declval T0)

  when T is BasicType: sizeof(T)
  elif T is array|HashArray:
    type E = ElemType(T)
    when isFixedSize(E): int(len(T)) * fixedPortionSize(E)
    else: int(len(T)) * offsetSize
  elif T is object|tuple:
    enumAllSerializedFields(T):
      when isFixedSize(FieldType):
        result += fixedPortionSize(FieldType)
      else:
        result += offsetSize
  else:
    unsupported T0

# TODO This should have been an iterator, but the VM can't compile the
# code due to "too many registers required".
proc fieldInfos*(RecordType: type): seq[tuple[name: string,
                                              offset: int,
                                              fixedSize: int,
                                              branchKey: string]] =
  mixin enumAllSerializedFields

  var
    offsetInBranch = {"": 0}.toTable
    nestedUnder = initTable[string, string]()

  enumAllSerializedFields(RecordType):
    const
      isFixed = isFixedSize(FieldType)
      fixedSize = when isFixed: fixedPortionSize(FieldType)
                  else: 0
      branchKey = when  fieldCaseDiscriminator.len == 0: ""
                  else: fieldCaseDiscriminator & ":" & $fieldCaseBranches
      fieldSize = when isFixed: fixedSize
                  else: offsetSize

    nestedUnder[fieldName] = branchKey

    var fieldOffset: int
    offsetInBranch.withValue(branchKey, val):
      fieldOffset = val[]
      val[] += fieldSize
    do:
      try:
        let parentBranch = nestedUnder.getOrDefault(fieldCaseDiscriminator, "")
        fieldOffset = offsetInBranch[parentBranch]
        offsetInBranch[branchKey] = fieldOffset + fieldSize
      except KeyError as e:
        raiseAssert e.msg

    result.add((fieldName, fieldOffset, fixedSize, branchKey))

func getFieldBoundingOffsetsImpl(RecordType: type,
                                 fieldName: static string):
     tuple[fieldOffset, nextFieldOffset: int, isFirstOffset: bool] {.compileTime.} =
  result = (-1, -1, false)
  var fieldBranchKey: string
  var isFirstOffset = true

  for f in fieldInfos(RecordType):
    if fieldName == f.name:
      result[0] = f.offset
      if f.fixedSize > 0:
        result[1] = result[0] + f.fixedSize
        return
      else:
        fieldBranchKey = f.branchKey
      result.isFirstOffset = isFirstOffset

    elif result[0] != -1 and
         f.fixedSize == 0 and
         f.branchKey == fieldBranchKey:
      # We have found the next variable sized field
      result[1] = f.offset
      return

    if f.fixedSize == 0:
      isFirstOffset = false

func getFieldBoundingOffsets*(RecordType: type,
                              fieldName: static string):
     tuple[fieldOffset, nextFieldOffset: int, isFirstOffset: bool] {.compileTime.} =
  ## Returns the start and end offsets of a field.
  ##
  ## For fixed-size fields, the start offset points to the first
  ## byte of the field and the end offset points to 1 byte past the
  ## end of the field.
  ##
  ## For variable-size fields, the returned offsets point to the
  ## statically known positions of the 32-bit offset values written
  ## within the SSZ object. You must read the 32-bit values stored
  ## at the these locations in order to obtain the actual offsets.
  ##
  ## For variable-size fields, the end offset may be -1 when the
  ## designated field is the last variable sized field within the
  ## object. Then the SSZ object boundary known at run-time marks
  ## the end of the variable-size field.
  type T = RecordType
  anonConst getFieldBoundingOffsetsImpl(T, fieldName)

template enumerateSubFields*(holder, fieldVar, body: untyped) =
  when holder is array|HashArray:
    for fieldVar in holder: body
  else:
    enumInstanceSerializedFields(holder, _{.used.}, fieldVar): body

method formatMsg*(
  err: ref SszSizeMismatchError,
  filename: string): string {.gcsafe, raises: [Defect].} =
  try:
    &"SSZ size mismatch, element {err.elementSize}, actual {err.actualSszSize}, type {err.deserializedType}, file {filename}"
  except CatchableError:
    "SSZ size mismatch"
