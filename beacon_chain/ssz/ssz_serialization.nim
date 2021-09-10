# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}
{.pragma: raisesssz, raises: [Defect, MalformedSszError, SszSizeMismatchError].}

## SSZ serialization for core SSZ types, as specified in:
# https://github.com/ethereum/consensus-specs/blob/v1.0.1/ssz/simple-serialize.md#serialization

import
  std/typetraits,
  stew/[endians2, leb128, objects],
  serialization, serialization/testing/tracing,
  ./codec, ./bitseqs, ./types

export
  serialization, codec, types, bitseqs

type
  SszReader* = object
    stream: InputStream

  SszWriter* = object
    stream: OutputStream

  SizePrefixed*[T] = distinct T
  SszMaxSizeExceeded* = object of SerializationError

  VarSizedWriterCtx = object
    fixedParts: WriteCursor
    offset: int

  FixedSizedWriterCtx = object

serializationFormat SSZ

SSZ.setReader SszReader
SSZ.setWriter SszWriter, PreferredOutput = seq[byte]

template sizePrefixed*[TT](x: TT): untyped =
  type T = TT
  SizePrefixed[T](x)

proc init*(T: type SszReader,
           stream: InputStream): T =
  T(stream: stream)

proc writeFixedSized(s: var (OutputStream|WriteCursor), x: auto) {.raises: [Defect, IOError].} =
  mixin toSszType

  when x is byte:
    s.write x
  elif x is bool:
    s.write byte(ord(x))
  elif x is UintN:
    when cpuEndian == bigEndian:
      s.write toBytesLE(x)
    else:
      s.writeMemCopy x
  elif x is array:
    when x[0] is byte:
      trs "APPENDING FIXED SIZE BYTES", x
      s.write x
    else:
      for elem in x:
        trs "WRITING FIXED SIZE ARRAY ELEMENT"
        s.writeFixedSized toSszType(elem)
  elif x is tuple|object:
    enumInstanceSerializedFields(x, fieldName, field):
      trs "WRITING FIXED SIZE FIELD", fieldName
      s.writeFixedSized toSszType(field)
  else:
    unsupported x.type

template writeOffset(cursor: var WriteCursor, offset: int) =
  write cursor, toBytesLE(uint32 offset)

template supports*(_: type SSZ, T: type): bool =
  mixin toSszType
  anonConst compiles(fixedPortionSize toSszType(declval T))

func init*(T: type SszWriter, stream: OutputStream): T =
  result.stream = stream

proc writeVarSizeType(w: var SszWriter, value: auto) {.gcsafe, raises: [Defect, IOError].}

proc beginRecord*(w: var SszWriter, TT: type): auto  =
  type T = TT
  when isFixedSize(T):
    FixedSizedWriterCtx()
  else:
    const offset = when T is array|HashArray: len(T) * offsetSize
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
      writeFixedSized(ctx.fixedParts, toSszType(field))
    else:
      trs "WRITING OFFSET ", ctx.offset, " FOR ", fieldName
      writeOffset(ctx.fixedParts, ctx.offset)
      let initPos = w.stream.pos
      trs "WRITING VAR SIZE VALUE OF TYPE ", name(FieldType)
      when FieldType is BitList:
        trs "BIT SEQ ", bytes(field)
      writeVarSizeType(w, toSszType(field))
      ctx.offset += w.stream.pos - initPos

template endRecord*(w: var SszWriter, ctx: var auto) =
  when ctx is VarSizedWriterCtx:
    finalize ctx.fixedParts

proc writeSeq[T](w: var SszWriter, value: seq[T])
                {.raises: [Defect, IOError].} =
  # Please note that `writeSeq` exists in order to reduce the code bloat
  # produced from generic instantiations of the unique `List[N, T]` types.
  when isFixedSize(T):
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
      let initPos = w.stream.pos
      w.writeVarSizeType toSszType(elem)
      offset += w.stream.pos - initPos
    finalize cursor
    trs "DONE"

proc writeVarSizeType(w: var SszWriter, value: auto) {.raises: [Defect, IOError].} =
  trs "STARTING VAR SIZE TYPE"

  when value is HashArray|HashList:
    writeVarSizeType(w, value.data)
  elif value is SingleMemberUnion:
    if value.selector != 0'u8:
      raise newException(MalformedSszError, "SingleMemberUnion selector must be 0")
    w.writeValue 0'u8
    w.writeValue value.value
  elif value is List:
    # We reduce code bloat by forwarding all `List` types to a general `seq[T]` proc.
    writeSeq(w, asSeq value)
  elif value is BitList:
    # ATTENTION! We can reuse `writeSeq` only as long as our BitList type is implemented
    # to internally match the binary representation of SSZ BitLists in memory.
    writeSeq(w, bytes value)
  elif value is object|tuple|array:
    trs "WRITING OBJECT OR ARRAY"
    var ctx = beginRecord(w, type value)
    enumerateSubFields(value, field):
      writeField w, ctx, astToStr(field), field
    endRecord w, ctx
  else:
    unsupported type(value)

proc writeValue*(w: var SszWriter, x: auto) {.gcsafe, raises: [Defect, IOError].} =
  mixin toSszType
  type T = type toSszType(x)

  when isFixedSize(T):
    w.stream.writeFixedSized toSszType(x)
  else:
    w.writeVarSizeType toSszType(x)

func sszSize*(value: auto): int {.gcsafe, raises: [Defect].}

func sszSizeForVarSizeList[T](value: openArray[T]): int =
  result = len(value) * offsetSize
  for elem in value:
    result += sszSize(toSszType elem)

func sszSize*(value: auto): int {.gcsafe, raises: [Defect].} =
  mixin toSszType
  type T = type toSszType(value)

  when isFixedSize(T):
    anonConst fixedPortionSize(T)

  elif T is array|List|HashList|HashArray:
    type E = ElemType(T)
    when isFixedSize(E):
      len(value) * anonConst(fixedPortionSize(E))
    elif T is HashArray:
      sszSizeForVarSizeList(value.data)
    elif T is array:
      sszSizeForVarSizeList(value)
    else:
      sszSizeForVarSizeList(asSeq value)

  elif T is BitList:
    return len(bytes(value))

  elif T is SingleMemberUnion:
    sszSize(toSszType value.value) + 1

  elif T is object|tuple:
    result = anonConst fixedPortionSize(T)
    enumInstanceSerializedFields(value, _{.used.}, field):
      type FieldType = type toSszType(field)
      when not isFixedSize(FieldType):
        result += sszSize(toSszType field)

  else:
    unsupported T

proc writeValue*[T](w: var SszWriter, x: SizePrefixed[T]) {.raises: [Defect, IOError].} =
  var cursor = w.stream.delayVarSizeWrite(Leb128.maxLen(uint64))
  let initPos = w.stream.pos
  w.writeValue T(x)
  let length = toBytes(uint64(w.stream.pos - initPos), Leb128)
  cursor.finalWrite length.toOpenArray()

proc readValue*(r: var SszReader, val: var auto) {.
    raises: [Defect, MalformedSszError, SszSizeMismatchError, IOError].} =
  mixin readSszBytes
  type T = type val
  when isFixedSize(T):
    const minimalSize = fixedPortionSize(T)
    if r.stream.readable(minimalSize):
      readSszBytes(r.stream.read(minimalSize), val)
    else:
      raise newException(MalformedSszError, "SSZ input of insufficient size")
  else:
    # TODO(zah) Read the fixed portion first and precisely measure the
    # size of the dynamic portion to consume the right number of bytes.
    readSszBytes(r.stream.read(r.stream.len.get), val)

proc readSszBytes*[T](data: openArray[byte], val: var T) {.
    raises: [Defect, MalformedSszError, SszSizeMismatchError].} =
  # Overload `readSszBytes` to perform custom operations on T after
  # deserialization
  mixin readSszValue
  readSszValue(data, val)
