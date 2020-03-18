import
  macros, stew/[ptrops, objects], stew/ranges/ptr_arith,
  ./types, ./bytes_reader

type
  MemRange* = object
    startAddr*: ptr byte
    length*: int

  SszNavigator*[T] = object
    m: MemRange
  
  SszOffsetFinder*[T] = object
    # nav*: SszNavigator[T]
    fieldList*: seq[string]

func sszMount*(data: openarray[byte], T: type): SszNavigator[T] =
  let startAddr = unsafeAddr data[0]
  SszNavigator[T](m: MemRange(startAddr: startAddr, length: data.len))

template sszMount*(data: MemRange, T: type): SszNavigator[T] =
  SszNavigator[T](m: data)

template sszMount*(T: type): SszOffsetFinder =
  SszOffsetFinder[T]()

# template getOffSetInfo*(n: SszOffsetFinder): (int, int, bool) =
#   (n.startOffset, n.length, n.dynamicType)

template getMemRange*(n: SszNavigator): MemRange =
  # Please note that this accessor was created intentionally.
  # We don't want to expose the `m` field, because the navigated
  # type may have a field by that name. We wan't any dot field
  # access to be redirected to the navigated type.
  # For this reason, this template should always be used with
  # the function call syntax `getMemRange(n)`.
  n.m

template checkBounds(m: MemRange, offset: int) =
  if offset > m.length:
    raise newException(MalformedSszError, "Malformed SSZ")

template toOpenArray(m: MemRange): auto =
  makeOpenArray(m.startAddr, m.length)

proc navigateToField*[T](n: SszNavigator[T],
                         fieldName: static string,
                         FieldType: type): SszNavigator[FieldType] =
  mixin toSszType
  type SszFieldType = type toSszType(default FieldType)
  const boundingOffsets = getFieldBoundingOffsets(T, fieldName)
  checkBounds(n.m, boundingOffsets[1])
  when isFixedSize(SszFieldType):
    SszNavigator[FieldType](m: MemRange(
      startAddr: offset(n.m.startAddr, boundingOffsets[0]),
      length: boundingOffsets[1] - boundingOffsets[0]))
  else:
    template readOffset(off): int =
      int fromSszBytes(uint32, makeOpenArray(offset(n.m.startAddr, off),
                                             sizeof(uint32)))
    let
      startOffset = readOffset boundingOffsets[0]
      endOffset = when boundingOffsets[1] == -1: n.m.length
                  else: readOffset boundingOffsets[1]

    if endOffset < startOffset or endOffset > n.m.length:
       raise newException(MalformedSszError, "Incorrect offset values")

    SszNavigator[FieldType](m: MemRange(
      startAddr: offset(n.m.startAddr, startOffset),
      length: endOffset - startOffset))

# proc navigateToField*[T](n: SszNavigator[T],
#                           fieldName: static string,
#                           FieldType: type,
#                           readOffset: proc(off: int):int): SszNavigator[FieldType] =
#     mixin toSszType
#     type SszFieldType = type toSszType(default FieldType)
#     const boundingOffsets = getFieldBoundingOffsets(T, fieldName)
#     checkBounds(n.m, boundingOffsets[1])
#     when isFixedSize(SszFieldType):
#       SszNavigator[FieldType](m: MemRange(
#       startAddr: offset(n.m.startAddr, boundingOffsets[0]),
#       length: boundingOffsets[1] - boundingOffsets[0]))
#     else:
#       # template readOffset(off): int =
#       #   int fromSszBytes(uint32, makeOpenArray(offset(n.m.startAddr, off),
#       #                           sizeof(uint32)))
#       let
#         startOffset = readOffset boundingOffsets[0]
#         endOffset = when boundingOffsets[1] == -1: n.m.length
#                     else: readOffset boundingOffsets[1]

#     if endOffset < startOffset or endOffset > n.m.length:
#       raise newException(MalformedSszError, "Incorrect offset values")

#     SszNavigator[FieldType](m: MemRange(
#       startAddr: offset(n.m.startAddr, startOffset),
#       length: endOffset - startOffset))

template get*[T](n:SszOffsetFinder[T], data: openArray[byte]) =
  type RecType = T
  
  var nav = sszMount(data, RecType)
  for field in n.fieldList:
    enumAllSerializedFields(RecType):
      if fieldName == field:
        let newNav = navigateToField(nav, fieldName, FieldType)
        echo newNav




template `.`*[T](n: SszNavigator[T], field: untyped): auto =
  type RecType = T
  type FieldType = type(default(RecType).field)
  navigateToField(n, astToStr(field), FieldType)

template `.`*[T](n: SszOffsetFinder[T], field: untyped): SszOffsetFinder[T] =
  SszOffsetFinder[T](fieldList: n.fieldList & astToStr(field))

func indexVarSizeList(m: MemRange, idx: int): MemRange =
  template readOffset(pos): int =
    int fromSszBytes(uint32, makeOpenArray(offset(m.startAddr, pos), offsetSize))

  let offsetPos = offsetSize * idx
  checkBounds(m, offsetPos + offsetSize)

  let firstOffset = readOffset 0
  let listLen = firstOffset div offsetSize

  if idx >= listLen:
    # TODO: Use a RangeError here?
    # This would require the user to check the `len` upfront
    raise newException(MalformedSszError, "Indexing past the end")

  let elemPos = readOffset offsetPos
  checkBounds(m, elemPos)

  let endPos = if idx < listLen - 1:
    let nextOffsetPos = offsetPos + offsetSize
    # TODO. Is there a way to remove this bounds check?
    checkBounds(m, nextOffsetPos + offsetSize)
    readOffset(offsetPos + nextOffsetPos)
  else:
    m.length

  MemRange(startAddr: m.startAddr.offset(elemPos), length: endPos - elemPos)

template indexList(n, idx, T: untyped): untyped =
  type R = T
  mixin toSszType
  type ElemType = type toSszType(default R)
  when isFixedSize(ElemType):
    const elemSize = fixedPortionSize(ElemType)
    let elemPos = idx * elemSize
    checkBounds(n.m, elemPos + elemSize)
    SszNavigator[R](m: MemRange(startAddr: offset(n.m.startAddr, elemPos),
                                length: elemSize))
  else:
    SszNavigator[R](m: indexVarSizeList(n.m, idx))

template `[]`*[T](n: SszNavigator[seq[T]], idx: int): SszNavigator[T] =
  indexList n, idx, T

template `[]`*[R, T](n: SszNavigator[array[R, T]], idx: int): SszNavigator[T] =
  indexList(n, idx, T)

func `[]`*[T](n: SszNavigator[T]): T =
  mixin toSszType, fromSszBytes
  type SszRepr = type(toSszType default(T))
  when type(SszRepr) is type(T):
    readSszValue(toOpenArray(n.m), T)
  else:
    fromSszBytes(T, toOpenArray(n.m))

converter derefNavigator*[T](n: SszNavigator[T]): T =
  n[]

