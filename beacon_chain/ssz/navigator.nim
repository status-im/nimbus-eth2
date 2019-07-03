import
  stew/objects, stew/ranges/ptr_arith,
  ./types, ./bytes_reader

type
  MemRange = object
    startAddr: ptr byte
    length: int

  SszNavigator*[T] = object
    m: MemRange

func sszMount*(data: openarray[byte], T: type): SszNavigator[T] =
  let startAddr = unsafeAddr data[0]
  SszNavigator[T](m: MemRange(startAddr: startAddr, length: data.len))

template checkBounds(m: MemRange, offset: int) =
  if offset > m.length:
    raise newException(MalformedSszError, "Malformed SSZ")

template toOpenArray(m: MemRange): auto =
  makeOpenArray(m.startAddr, m.length)

func navigateToField[T](n: SszNavigator[T],
                        fieldName: static string,
                        FieldType: type): SszNavigator[FieldType] =
  mixin toSszType
  type SszFieldType = type toSszType(default FieldType)

  const boundingOffsets = getFieldBoundingOffsets(T, fieldName)
  checkBounds(n.m, boundingOffsets[1])

  when isFixedSize(SszFieldType):
    SszNavigator[FieldType](m: MemRange(
      startAddr: shift(n.m.startAddr, boundingOffsets[0]),
      length: boundingOffsets[1] - boundingOffsets[0]))
  else:
    template readOffset(offset): int =
      int fromSszBytes(uint32, makeOpenArray(shift(n.m.startAddr, offset),
                                             sizeof(uint32)))
    let
      startOffset = readOffset boundingOffsets[0]
      endOffset = when boundingOffsets[1] == -1: n.m.length
                  else: readOffset boundingOffsets[1]

    if endOffset < startOffset or endOffset > n.m.length:
       raise newException(MalformedSszError, "Incorrect offset values")

    SszNavigator[FieldType](m: MemRange(
      startAddr: shift(n.m.startAddr, startOffset),
      length: endOffset - startOffset))

template `.`*[T](n: SszNavigator[T], field: untyped): auto =
  type RecType = T
  type FieldType = type(default(RecType).field)
  navigateToField(n, astToStr(field), FieldType)

func `[]`*[T](n: SszNavigator[T]): T =
  readSszValue(toOpenArray(n.m), T)

converter derefNavigator*[T](n: SszNavigator[T]): T =
  n[]

