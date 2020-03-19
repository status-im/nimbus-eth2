import
  stew/[ptrops, objects], stew/ranges/ptr_arith,
  ./types, ./bytes_reader

type
  MemRange* = object
    startAddr*: ptr byte
    length*: int

  SszNavigator*[T] = object
    m: MemRange

  SszDelayedNavigator*[T] = object
    fieldList*: seq[string]

  OffsetGetter = proc(off:int):int

func sszMount*(data: openarray[byte], T: type): SszNavigator[T] =
  let startAddr = unsafeAddr data[0]
  SszNavigator[T](m: MemRange(startAddr: startAddr, length: data.len))

template sszMount*(data: MemRange, T: type): SszNavigator[T] =
  SszNavigator[T](m: data)

template sszMount*(T: type): SszDelayedNavigator =
  SszDelayedNavigator[T]()

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

func navigateToField*[T](n: SszNavigator[T],
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



# proc navigateToField*(m: MemRange, RecType: type, fieldName: string, FieldType: type, readOff: OffsetGetter):(MemRange, type) =
#   mixin toSszType
#   type SszFieldType = type toSszType(default FieldType)
#   const boundingOffsets = getFieldBoundingOffsets(RecType, fieldName)
#   checkBounds(m, boundingOffsets[1])
#   when isFixedSize(SszFieldType):
#     (m: MemRange(startAddr: offset(m.startAddr, boundingOffsets[0]),
#       length: boundingOffsets[1] - boundingOffsets[0]), FieldType)
#   else:
#     let
#       startOffset = readOff(boundingOffsets[0])
#       endOffset = when boundingOffsets[1] == -1: n.m.length
#                   else: readOff(boundingOffsets[1])

#     if endOffset < startOffset or endOffset > m.length:
#        raise newException(MalformedSszError, "Incorrect offset values")

#     (m: MemRange(
#       startAddr: offset(m.startAddr, startOffset),
#       length: endOffset - startOffset), FieldType)
    

# template get*[T](n:SszDelayedNavigator[T], startingOff: int, length: int, readOff:OffsetGetter) =
#   # let startAddr = unsafeAddr data[0]
#   # var mem = MemRange(startAddr: startAddr, length: data.len)
#   var fieldInfo : tuple[off: int, lgth: int,  FieldType: type]
#   fieldInfo = (off: startingOff, lgth:length, FieldType: T)
#   type RecType = T
#   for field in n.fieldList:
#     enumAllSerializedFields(RecType):
#       if field == fieldName:
#         fieldInfo = navigateToField(fieldInfo[0], fieldInfo[1], fieldInfo[3], field, FieldType)


template `.`*[T](n: SszNavigator[T], field: untyped): auto =
  type RecType = T
  type FieldType = type(default(RecType).field)
  navigateToField(n, astToStr(field), FieldType)

template `.`*[T](n: SszDelayedNavigator[T], field: untyped): SszDelayedNavigator[T] =
  SszDelayedNavigator[T](fieldList: n.fieldList & astToStr(field))

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

