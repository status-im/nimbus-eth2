{.push raises: [Defect].}
{.pragma: raisesssz, raises: [Defect, MalformedSszError, SszSizeMismatchError].}

import
  typetraits, options,
  stew/[bitseqs, endians2, objects, bitseqs], serialization/testing/tracing,
  ../spec/[digest, datatypes], ./types

const
  maxListAllocation = 1 * 1024 * 1024 * 1024 # 1 GiB

template raiseIncorrectSize(T: type) =
  const typeName = name(T)
  raise newException(MalformedSszError,
                     "SSZ " & typeName & " input of incorrect size")

template setOutputSize[R, T](a: var array[R, T], length: int) =
  if length != a.len:
    raiseIncorrectSize a.type

proc setOutputSize(list: var List, length: int) {.inline, raisesssz.} =
  if int64(length) > list.maxLen:
    raise newException(MalformedSszError, "SSZ list maximum size exceeded")
  list.setLen length

# fromSszBytes copies the wire representation to a Nim variable,
# assuming there's enough data in the buffer
func fromSszBytes*(T: type UintN, data: openarray[byte]): T {.raisesssz.} =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **little endian**.
  if data.len != sizeof(result):
    raiseIncorrectSize T

  T.fromBytesLE(data)

func fromSszBytes*(T: type bool, data: openarray[byte]): T {.raisesssz.} =
  # TODO: spec doesn't say what to do if the value is >1 - we'll use the C
  #       definition for now, but maybe this should be a parse error instead?
  if data.len != 1 or byte(data[0]) > byte(1):
    raise newException(MalformedSszError, "invalid boolean value")
  data[0] == 1

func fromSszBytes*(T: type Eth2Digest, data: openarray[byte]): T {.raisesssz.} =
  if data.len != sizeof(result.data):
    raiseIncorrectSize T
  copyMem(result.data.addr, unsafeAddr data[0], sizeof(result.data))

template fromSszBytes*(T: type Slot, bytes: openarray[byte]): Slot =
  Slot fromSszBytes(uint64, bytes)

template fromSszBytes*(T: type Epoch, bytes: openarray[byte]): Epoch =
  Epoch fromSszBytes(uint64, bytes)

func fromSszBytes*(T: type ForkDigest, bytes: openarray[byte]): T {.raisesssz.} =
  if bytes.len != sizeof(result):
    raiseIncorrectSize T
  copyMem(result.addr, unsafeAddr bytes[0], sizeof(result))

func fromSszBytes*(T: type Version, bytes: openarray[byte]): T {.raisesssz.} =
  if bytes.len != sizeof(result):
    raiseIncorrectSize T
  copyMem(result.addr, unsafeAddr bytes[0], sizeof(result))

template fromSszBytes*(T: type enum, bytes: openarray[byte]): auto  =
  T fromSszBytes(uint64, bytes)

template fromSszBytes*(T: type BitSeq, bytes: openarray[byte]): auto =
  BitSeq @bytes

proc `[]`[T, U, V](s: openArray[T], x: HSlice[U, V]) {.error:
  "Please don't use openarray's [] as it allocates a result sequence".}

# func readOpenArray[T](result: var openarray[T], input: openarray[byte]) =

template checkForForbiddenBits(ResulType: type,
                               input: openarray[byte],
                               expectedBits: static int) =
  ## This checks if the input contains any bits set above the maximum
  ## sized allowed. We only need to check the last byte to verify this:
  const bitsInLastByte = (expectedBits mod 8)
  when bitsInLastByte != 0:
    # As an example, if there are 3 bits expected in the last byte,
    # we calculate a bitmask equal to 11111000. If the input has any
    # raised bits in range of the bitmask, this would be a violation
    # of the size of the BitArray:
    const forbiddenBitsMask = byte(byte(0xff) shl bitsInLastByte)

    if (input[^1] and forbiddenBitsMask) != 0:
      raiseIncorrectSize ResulType

func readSszValue*(input: openarray[byte], T: type): T {.raisesssz.} =
  mixin fromSszBytes, toSszType

  type T {.used.} = type(result)

  template readOffsetUnchecked(n: int): int {.used.}=
    int fromSszBytes(uint32, input.toOpenArray(n, n + offsetSize - 1))

  template readOffset(n: int): int {.used.} =
    let offset = readOffsetUnchecked(n)
    if offset > input.len:
      raise newException(MalformedSszError, "SSZ list element offset points past the end of the input")
    offset

  #when result is List:
  #  result.setOutputSize input.len
  #  readOpenArray(toSeq result, input)

  #elif result is array:
  #  result.checkOutputSize input.len
  #  readOpenArray(result, input)

  when result is BitList:
    if input.len == 0:
      raise newException(MalformedSszError, "Invalid empty SSZ BitList value")

    const maxExpectedSize = (result.maxLen div 8) + 1
    result = T readSszValue(input, List[byte, maxExpectedSize])

    let resultBytesCount = len bytes(result)

    if bytes(result)[resultBytesCount - 1] == 0:
      raise newException(MalformedSszError, "SSZ BitList is not properly terminated")

    if resultBytesCount == maxExpectedSize:
      checkForForbiddenBits(T, input, result.maxLen + 1)

  elif result is List|array:
    type ElemType = type result[0]
    when ElemType is byte:
      result.setOutputSize input.len
      if input.len > 0:
        copyMem(addr result[0], unsafeAddr input[0], input.len)

    elif isFixedSize(ElemType):
      const elemSize = fixedPortionSize(ElemType)
      if input.len mod elemSize != 0:
        var ex = new SszSizeMismatchError
        ex.deserializedType = cstring typetraits.name(T)
        ex.actualSszSize = input.len
        ex.elementSize = elemSize
        raise ex
      result.setOutputSize input.len div elemSize
      trs "READING LIST WITH LEN ", result.len
      for i in 0 ..< result.len:
        trs "TRYING TO READ LIST ELEM ", i
        let offset = i * elemSize
        result[i] = readSszValue(input.toOpenArray(offset, offset + elemSize - 1), ElemType)
      trs "LIST READING COMPLETE"

    else:
      if input.len == 0:
        # This is an empty list.
        # The default initialization of the return value is fine.
        return
      elif input.len < offsetSize:
        raise newException(MalformedSszError, "SSZ input of insufficient size")

      var offset = readOffset 0

      trs "GOT OFFSET ", offset
      let resultLen = offset div offsetSize
      trs "LEN ", resultLen

      if resultLen == 0:
        # If there are too many elements, other constraints detect problems
        # (not monotonically increasing, past end of input, or last element
        # not matching up with its nextOffset properly)
        raise newException(MalformedSszError, "SSZ list incorrectly encoded of zero length")

      result.setOutputSize resultLen
      for i in 1 ..< resultLen:
        let nextOffset = readOffset(i * offsetSize)
        if nextOffset <= offset:
          raise newException(MalformedSszError, "SSZ list element offsets are not monotonically increasing")
        else:
          result[i - 1] = readSszValue(input.toOpenArray(offset, nextOffset - 1), ElemType)
        offset = nextOffset

      result[resultLen - 1] = readSszValue(input.toOpenArray(offset, input.len - 1), ElemType)

  # TODO: Should be possible to remove BitArray from here
  elif result is UintN|bool|enum:
    trs "READING BASIC TYPE ", type(result).name, "  input=", input.len
    result = fromSszBytes(type(result), input)
    trs "RESULT WAS ", repr(result)

  elif result is BitArray:
    if sizeof(result) != input.len:
      raiseIncorrectSize T
    checkForForbiddenBits(T, input, result.bits)
    copyMem(addr result.bytes[0], unsafeAddr input[0], input.len)

  elif result is object|tuple:
    const minimallyExpectedSize = fixedPortionSize(T)
    if input.len < minimallyExpectedSize:
      raise newException(MalformedSszError, "SSZ input of insufficient size")

    enumInstanceSerializedFields(result, fieldName, field):
      const boundingOffsets = T.getFieldBoundingOffsets(fieldName)
      trs "BOUNDING OFFSET FOR FIELD ", fieldName, " = ", boundingOffsets

      type FieldType = type field
      type SszType = type toSszType(declval FieldType)

      when isFixedSize(SszType):
        const
          startOffset = boundingOffsets[0]
          endOffset = boundingOffsets[1]
        trs "FIXED FIELD ", startOffset, "-", endOffset
      else:
        let
          startOffset = readOffsetUnchecked(boundingOffsets[0])
          endOffset = if boundingOffsets[1] == -1: input.len
                      else: readOffsetUnchecked(boundingOffsets[1])
        trs "VAR FIELD ", startOffset, "-", endOffset
        if startOffset > endOffset:
          raise newException(MalformedSszError, "SSZ field offsets are not monotonically increasing")
        elif endOffset > input.len:
          raise newException(MalformedSszError, "SSZ field offset points past the end of the input")
        elif startOffset < minimallyExpectedSize:
          raise newException(MalformedSszError, "SSZ field offset points outside bounding offsets")

      # TODO The extra type escaping here is a work-around for a Nim issue:
      when type(FieldType) is type(SszType):
        trs "READING NATIVE ", fieldName, ": ", name(SszType)
        field = typeof(field) readSszValue(
          input.toOpenArray(startOffset, endOffset - 1),
          SszType)
        trs "READING COMPLETE ", fieldName

      elif FieldType is List:
        # TODO
        # The `typeof(field)` coercion below is required to deal with a Nim
        # bug. For some reason, Nim gets confused about the type of the list
        # returned from the `readSszValue` function. This could be a generics
        # caching issue caused by the use of distinct types. Such an issue
        # would be very scary in general, but in this particular situation
        # it shouldn't matter, because the different flavours of `List[T, N]`
        # won't produce different serializations.
        field = typeof(field) readSszValue(
          input.toOpenArray(startOffset, endOffset - 1),
          FieldType)

      else:
        trs "READING FOREIGN ", fieldName, ": ", name(SszType)
        field = fromSszBytes(
          FieldType,
          input.toOpenArray(startOffset, endOffset - 1))

  else:
    unsupported T
