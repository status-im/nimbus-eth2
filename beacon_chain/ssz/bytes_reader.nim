{.push raises: [Defect].}
{.pragma: raisesssz, raises: [Defect, MalformedSszError, SszSizeMismatchError].}

import
  typetraits, options,
  stew/[bitseqs, endians2, objects, bitseqs], serialization/testing/tracing,
  ../spec/[digest, datatypes], ./types

const
  maxListAllocation = 1 * 1024 * 1024 * 1024 # 1 GiB

template setOutputSize[R, T](a: var array[R, T], length: int) =
  if length != a.len:
    raise newException(MalformedSszError, "SSZ input of insufficient size")

proc setOutputSize[T](s: var seq[T], length: int) {.inline, raisesssz.} =
  if sizeof(T) * length > maxListAllocation:
    raise newException(MalformedSszError, "SSZ list size is too large to fit in memory")
  s.setLen length

proc setOutputSize(s: var string, length: int) {.inline, raisesssz.} =
  if length > maxListAllocation:
    raise newException(MalformedSszError, "SSZ string is too large to fit in memory")
  s.setLen length

# fromSszBytes copies the wire representation to a Nim variable,
# assuming there's enough data in the buffer
func fromSszBytes*(T: type SomeInteger, data: openarray[byte]): T {.raisesssz.} =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **little endian**.
  if data.len < sizeof(result):
    raise newException(MalformedSszError, "SSZ input of insufficient size")

  T.fromBytesLE(data)

func fromSszBytes*(T: type bool, data: openarray[byte]): T {.raisesssz.} =
  # TODO: spec doesn't say what to do if the value is >1 - we'll use the C
  #       definition for now, but maybe this should be a parse error instead?
  if data.len == 0 or data[0] > byte(1):
    raise newException(MalformedSszError, "invalid boolean value")
  data[0] == 1

func fromSszBytes*(T: type Eth2Digest, data: openarray[byte]): T {.raisesssz.} =
  if data.len < sizeof(result.data):
    raise newException(MalformedSszError, "SSZ input of insufficient size")
  copyMem(result.data.addr, unsafeAddr data[0], sizeof(result.data))

template fromSszBytes*(T: type Slot, bytes: openarray[byte]): Slot =
  Slot fromSszBytes(uint64, bytes)

template fromSszBytes*(T: type Epoch, bytes: openarray[byte]): Epoch =
  Epoch fromSszBytes(uint64, bytes)

template fromSszBytes*(T: type enum, bytes: openarray[byte]): auto  =
  T fromSszBytes(uint64, bytes)

template fromSszBytes*(T: type BitSeq, bytes: openarray[byte]): auto =
  BitSeq @bytes

func fromSszBytes*[N](T: type BitList[N], bytes: openarray[byte]): auto {.raisesssz.} =
  if bytes.len == 0:
    # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/ssz/simple-serialize.md#bitlistn
    # "An additional 1 bit is added to the end, at index e where e is the
    # length of the bitlist (not the limit), so that the length in bits will
    # also be known."
    # It's not possible to have a literally 0-byte (raw) Bitlist.
    # https://github.com/status-im/nim-beacon-chain/issues/931
    raise newException(MalformedSszError, "SSZ input Bitlist too small")
  BitList[N] @bytes

func fromSszBytes*[N](T: type BitArray[N], bytes: openarray[byte]): T {.raisesssz.} =
  # A bit vector doesn't have a marker bit, but we'll use the helper from
  # nim-stew to determine the position of the leading (marker) bit.
  # If it's outside the BitArray size, we have an overflow:
  if bitsLen(bytes) > N - 1:
    raise newException(MalformedSszError, "SSZ bit array overflow")
  copyMem(addr result.bytes[0], unsafeAddr bytes[0], bytes.len)

proc `[]`[T, U, V](s: openArray[T], x: HSlice[U, V]) {.error:
  "Please don't use openarray's [] as it allocates a result sequence".}

func readSszValue*(input: openarray[byte], T: type): T {.raisesssz.} =
  mixin fromSszBytes, toSszType

  type T {.used.} = type(result)

  template readOffset(n: int): int {.used.}=
    int fromSszBytes(uint32, input.toOpenArray(n, n + offsetSize - 1))

  when useListType and result is List:
    type ElemType = type result[0]
    result = T readSszValue(input, seq[ElemType])

  elif result is ptr|ref:
    new result
    result[] = readSszValue(input, type(result[]))

  elif result is Option:
    if input.len > 0:
      result = some readSszValue(input, result.T)

  elif result is string|seq|openarray|array:
    type ElemType = type result[0]
    when ElemType is byte|char:
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
        elif nextOffset > input.len:
          raise newException(MalformedSszError, "SSZ list element offset points past the end of the input")
        else:
          result[i - 1] = readSszValue(input.toOpenArray(offset, nextOffset - 1), ElemType)
        offset = nextOffset

      result[resultLen - 1] = readSszValue(input.toOpenArray(offset, input.len - 1), ElemType)

  elif result is SomeInteger|bool|enum|BitArray:
    trs "READING BASIC TYPE ", type(result).name, "  input=", input.len
    result = fromSszBytes(type(result), input)
    trs "RESULT WAS ", repr(result)

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
          startOffset = readOffset(boundingOffsets[0])
          endOffset = if boundingOffsets[1] == -1: input.len
                      else: readOffset(boundingOffsets[1])
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
        field = readSszValue(
          input.toOpenArray(startOffset, endOffset - 1),
          SszType)
        trs "READING COMPLETE ", fieldName

      elif useListType and FieldType is List:
        field = readSszValue(
          input.toOpenArray(startOffset, endOffset - 1),
          FieldType)

      else:
        trs "READING FOREIGN ", fieldName, ": ", name(SszType)
        field = fromSszBytes(
          FieldType,
          input.toOpenArray(startOffset, endOffset - 1))

  else:
    unsupported T
