# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# SSZ Serialization (simple serialize)
# See https://github.com/ethereum/beacon_chain/issues/100
# and https://github.com/ethereum/beacon_chain/tree/master/ssz

import ./datatypes, eth_common, endians, typetraits

# ################### Helper functions ###################################
func `+`[T](p: ptr T, offset: int): ptr T {.inline.}=
  ## Pointer arithmetic: Addition
  const size = sizeof T
  cast[ptr T](cast[ByteAddress](p) +% offset * size)

func checkSize[T: not seq](x: T, pos, len: int) {.inline.}=
  # This assumes that T is packed
  doAssert pos + T.sizeof < len, "Deserialization overflow"

func checkSize[T](x: seq[T], pos, len: int) {.inline.}=
  # seq length is stored in an uint32 (4 bytes) for SSZ
  doAssert pos + 4 + x.len * T.sizeof < len, "Deserialization overflow"

template deserInt(x: var SomeInteger or byte, data: ptr byte, pos: var int) =
  when x.sizeof == 8:
    bigEndian64(x.addr, data + pos)
    inc pos, 8
  elif x.sizeof == 4:
    bigEndian32(x.addr, data + pos)
    inc pos, 4
  elif x.sizeof == 2:
    bigEndian16(x.addr, data + pos)
    inc pos, 2
  else:
    x = cast[ptr type x](data + pos)[]
    inc pos

func deserSeq[T](dest: var seq[T], len: int, src: ptr byte, pos: var int) =
  dest = newSeqUninitialized[T](len)
  for val in dest.mitems:
    val.deserInt(src, pos)

func serInt[T: SomeInteger or byte](dest: var seq[byte], src: T, buffer: var array[sizeof(T), byte]) {.inline.}=
  when T.sizeof == 8:
    bigEndian64(buffer.addr, src.unsafeAddr)
  elif T.sizeof == 4:
    bigEndian32(buffer.addr, src.unsafeAddr)
  elif T.sizeof == 2:
    bigEndian16(buffer.addr, src.unsafeAddr)
  else:
    dest.add byte(src)
    return
  dest.add buffer

func serInt[T: SomeInteger or byte](dest: var seq[byte], src: T) {.inline.}=
  var buffer: array[T.sizeof, byte]
  dest.serInt(src, buffer)

func serSeq[T: SomeInteger or byte](dest: var seq[byte], src: seq[T]) =
  dest.serInt src.len.uint32
  var buffer: array[T.sizeof, byte]
  for val in src:
    dest.serInt(val, buffer)

# ################### Core functions ###################################
func deserialize(data: ptr byte, pos: var int, len: int, typ: typedesc[object]): typ =
  for field in result.fields:
    checkSize field, pos, len
    when field is EthAddress:
      copyMem(field.addr, data + pos, 20)
      inc pos, 20
    elif field is MDigest:
      const size = field.bits div 8
      copyMem(field.addr, data + pos, size)
      inc pos, size
    elif field is (SomeInteger or byte):
      field.deserInt(data, pos)
    elif field is seq[SomeInteger or byte]:
      var length: int32
      bigEndian32(length.addr, data + pos)
      inc pos, 4
      deserSeq(field, length, data, pos)
    else: # TODO: deserializing subtypes (?, depends on final spec)
      {.fatal: "Unsupported type deserialization: " & $typ.name.}

func deserialize*(
      data: seq[byte or uint8] or openarray[byte or uint8] or string,
      typ: typedesc[object]): typ {.inline.}=
  var pos = 0
  deserialize((ptr byte)(data[0].unsafeAddr), pos, data.len, typ)

func serialize*[T](value: T): seq[byte] =
  for field in value.fields:
    when field is EthAddress:
      result.add field
    elif field is MDigest:
      result.add field.data
    elif field is (SomeInteger or byte):
      result.serInt field
    elif field is seq[SomeInteger or byte]:
      result.serSeq field
    else: # TODO: Serializing subtypes (?, depends on final spec)
      {.fatal: "Unsupported type serialization: " & $typ.name.}
