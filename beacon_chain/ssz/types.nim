{.push raises: [Defect].}

import
  tables, options, typetraits,
  stew/shims/macros, stew/[objects, bitseqs],
  serialization/[object_serialization, errors]

const
  offsetSize* = 4

type
  BasicType* = char|bool|SomeUnsignedInt

  SszError* = object of SerializationError

  MalformedSszError* = object of SszError

  SszSizeMismatchError* = object of SszError
    deserializedType*: cstring
    actualSszSize*: int
    elementSize*: int

  SszChunksLimitExceeded* = object of SszError

  SszSchema* = ref object
    nodes*: seq[SszNode]

  SszTypeKind* = enum
    sszNull
    sszUInt
    sszBool
    sszList
    sszVector
    sszBitList
    sszBitVector
    sszRecord

  SszType* = ref object
    case kind*: SszTypeKind
    of sszUInt, sszBitVector:
      bits*: int
    of sszBool, sszNull, sszBitList:
      discard
    of sszVector:
      size*: int
      vectorElemType*: SszType
    of sszList:
      listElemType*: SszType
    of sszRecord:
      schema*: SszSchema

  SszNodeKind* = enum
    Field
    Union

  SszNode* = ref object
    name*: string
    typ*: SszType
    case kind: SszNodeKind
    of Union:
      variants*: seq[SszSchema]
    of Field:
      discard

  List*[T; maxLen: static int64] = distinct seq[T]
  BitList*[maxLen: static int] = distinct BitSeq

template add*(x: List, val: x.T) = add(distinctBase x, val)
template len*(x: List): auto = len(distinctBase x)
template low*(x: List): auto = low(distinctBase x)
template high*(x: List): auto = high(distinctBase x)
template `[]`*(x: List, idx: auto): auto = distinctBase(x)[idx]
template `[]=`*[T; N](x: List[T, N], idx: auto, val: T) = seq[T](x)[idx] = val
template `==`*(a, b: List): bool = distinctBase(a) == distinctBase(b)
template asSeq*(x: List): auto = distinctBase x
template `&`*[T; N](a, b: List[T, N]): List[T, N] = List[T, N](seq[T](a) & seq[T](b))
template `$`*(x: List): auto = $(distinctBase x)

template items* (x: List): untyped = items(distinctBase x)
template pairs* (x: List): untyped = pairs(distinctBase x)
template mitems*(x: List): untyped = mitems(distinctBase x)
template mpairs*(x: List): untyped = mpairs(distinctBase x)

template init*(T: type BitList, len: int): auto = T init(BitSeq, len)
template len*(x: BitList): auto = len(BitSeq(x))
template bytes*(x: BitList): auto = bytes(BitSeq(x))
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

macro unsupported*(T: typed): untyped =
  # TODO: {.fatal.} breaks compilation even in `compiles()` context,
  # so we use this macro instead. It's also much better at figuring
  # out the actual type that was used in the instantiation.
  # File both problems as issues.
  error "SSZ serialization of the type " & humaneTypeName(T) & " is not supported"

template ElemType*(T: type[array]): untyped =
  type(default(T)[low(T)])

template ElemType*[T](A: type[openarray[T]]): untyped =
  T

template ElemType*(T: type[seq|string|List]): untyped =
  type(default(T)[0])

func isFixedSize*(T0: type): bool {.compileTime.} =
  mixin toSszType, enumAllSerializedFields

  when T0 is openarray:
    return false
  else:
    type T = type toSszType(declval T0)

    when T is BasicType:
      return true
    elif T is array:
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
  elif T is array:
    type E = ElemType(T)
    when isFixedSize(E): len(T) * fixedPortionSize(E)
    else: len(T) * offsetSize
  elif T is seq|string|openarray: offsetSize
  elif T is object|tuple:
    enumAllSerializedFields(T):
      when isFixedSize(FieldType):
        result += fixedPortionSize(FieldType)
      else:
        result += offsetSize
  else:
    unsupported T0

func sszSchemaType*(T0: type): SszType {.compileTime.} =
  mixin toSszType, enumAllSerializedFields
  type T = type toSszType(declval T0)

  when T is bool:
    SszType(kind: sszBool)
  elif T is uint8|char:
    SszType(kind: sszUInt, bits: 8)
  elif T is uint16:
    SszType(kind: sszUInt, bits: 16)
  elif T is uint32:
    SszType(kind: sszUInt, bits: 32)
  elif T is uint64:
    SszType(kind: sszUInt, bits: 64)
  elif T is seq|string:
    SszType(kind: sszList, listElemType: sszSchemaType(ElemType(T)))
  elif T is array:
    SszType(kind: sszVector, vectorElemType: sszSchemaType(ElemType(T)))
  elif T is BitArray:
    SszType(kind: sszBitVector, bits: T.bits)
  elif T is BitSeq:
    SszType(kind: sszBitList)
  elif T is object|tuple:
    var recordSchema = SszSchema()
    var caseBranches = initTable[string, SszSchema]()
    caseBranches[""] = recordSchema
    # TODO case objects are still not supported here.
    # `recordFields` has to be refactored to properly
    # report nested discriminator fields.
    enumAllSerializedFields(T):
      recordSchema.nodes.add SszNode(
        name: fieldName,
        typ: sszSchemaType(FieldType),
        kind: Field)
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
     tuple[fieldOffset, nextFieldOffset: int] {.compileTime.} =
  result = (-1, -1)
  var fieldBranchKey: string

  for f in fieldInfos(RecordType):
    if fieldName == f.name:
      result[0] = f.offset
      if f.fixedSize > 0:
        result[1] = result[0] + f.fixedSize
        return
      else:
        fieldBranchKey = f.branchKey

    elif result[0] != -1 and
         f.fixedSize == 0 and
         f.branchKey == fieldBranchKey:
      # We have found the next variable sized field
      result[1] = f.offset
      return

func getFieldBoundingOffsets*(RecordType: type,
                              fieldName: static string):
     tuple[fieldOffset, nextFieldOffset: int] {.compileTime.} =
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
