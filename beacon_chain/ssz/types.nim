import
  tables, options,
  stew/shims/shims_macros, stew/[objects, bitseqs],
  serialization/[object_serialization, errors]

const
  useListType* = false
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

when useListType:
  type List*[T; maxLen: static int] = distinct seq[T]
else:
  type List*[T; maxLen: static int] = seq[T]

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

  when T0 is openarray|Option|ref|ptr:
    return false
  else:
    type T = type toSszType(default T0)

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
  type T = type toSszType(default T0)

  when T is BasicType: sizeof(T)
  elif T is array:
    type E = ElemType(T)
    when isFixedSize(E): len(T) * fixedPortionSize(E)
    else: len(T) * offsetSize
  elif T is seq|string|openarray|ref|ptr|Option: offsetSize
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
  type T = type toSszType(default T0)

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
      let parentBranch = nestedUnder.getOrDefault(fieldCaseDiscriminator, "")
      fieldOffset = offsetInBranch[parentBranch]
      offsetInBranch[branchKey] = fieldOffset + fieldSize

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
