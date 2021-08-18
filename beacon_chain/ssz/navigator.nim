# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}
{.pragma: raisesssz, raises: [Defect, MalformedSszError, SszSizeMismatchError].}

import
  stew/[ptrops, objects], stew/ranges/ptr_arith,
  ./codec, ./types

export codec, types

type
  MemRange* = object
    startAddr*: ptr byte
    length*: int

  SszNavigator*[T] = object
    m: MemRange

func sszMount*(data: openArray[byte], T: type): SszNavigator[T] =
  let startAddr = unsafeAddr data[0]
  SszNavigator[T](m: MemRange(startAddr: startAddr, length: data.len))

func sszMount*(data: openArray[char], T: type): SszNavigator[T] =
  let startAddr = cast[ptr byte](unsafeAddr data[0])
  SszNavigator[T](m: MemRange(startAddr: startAddr, length: data.len))

template sszMount*(data: MemRange, T: type): SszNavigator[T] =
  SszNavigator[T](m: data)

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
                         FieldType: type): SszNavigator[FieldType] {.raisesssz.} =
  mixin toSszType
  type SszFieldType = type toSszType(declval FieldType)

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

template `.`*[T](n: SszNavigator[T], field: untyped): auto =
  type RecType = T
  type FieldType = type(default(RecType).field)
  navigateToField(n, astToStr(field), FieldType)

func indexVarSizeList(m: MemRange, idx: int): MemRange {.raisesssz.} =
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
  type ElemType = type toSszType(declval R)
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

func `[]`*[T](n: SszNavigator[T]): T {.raisesssz.} =
  mixin toSszType, fromSszBytes
  type SszRepr = type toSszType(declval T)
  when type(SszRepr) is type(T) or T is List:
    readSszValue(toOpenArray(n.m), result)
  else:
    fromSszBytes(T, toOpenArray(n.m))

converter derefNavigator*[T](n: SszNavigator[T]): T {.raisesssz.} =
  n[]

