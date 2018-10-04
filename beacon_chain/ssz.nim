# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# SSZ Serialization (simple serialize)
# See https://github.com/ethereum/beacon_chain/issues/100
# and https://github.com/ethereum/beacon_chain/tree/master/ssz

import ./datatypes, eth_common, endians, typetraits, options

# ################### Helper functions ###################################
func `+`[T](p: ptr T, offset: int): ptr T {.inline.}=
  ## Pointer arithmetic: Addition
  const size = sizeof T
  cast[ptr T](cast[ByteAddress](p) +% offset * size)

func eat(x: var auto, data: ptr byte, pos: var int, len: int): bool =
  if pos + x.sizeof > len: return
  copyMem(x.addr, data + pos, x.sizeof)
  inc pos, x.sizeof
  return true

func eatInt[T: SomeInteger or byte](x: var T, data: ptr byte, pos: var int, len: int):
    bool =
  if pos + x.sizeof > len: return

  when x.sizeof == 8:
    bigEndian64(x.addr, data + pos)
  elif x.sizeof == 4:
    bigEndian32(x.addr, data + pos)
  elif x.sizeof == 2:
    bigEndian16(x.addr, data + pos)
  elif x.sizeof == 1:
    x = cast[ptr type x](data + pos)[]
  else:
    {.fatal: "Unsupported type deserialization: " & $(type(x)).name.}

  inc pos, x.sizeof
  return true

func eatSeq[T: SomeInteger or byte](x: var seq[T], data: ptr byte, pos: var int,
    len: int): bool =
  var items: int32
  if not eatInt(items, data, pos, len): return
  if pos + T.sizeof * items > len: return

  x = newSeqUninitialized[T](items)
  for val in x.mitems:
    discard eatInt(val, data, pos, len) # Bounds-checked above
  return true

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

func serInt[T: SomeInteger or byte](dest: var seq[byte], src: T) {.inline.} =
  var buffer: array[T.sizeof, byte]
  dest.serInt(src, buffer)

func serSeq[T: SomeInteger or byte](dest: var seq[byte], src: seq[T]) =
  dest.serInt src.len.uint32
  var buffer: array[T.sizeof, byte]
  for val in src:
    dest.serInt(val, buffer)

# ################### Core functions ###################################
func deserialize(data: ptr byte, pos: var int, len: int, typ: typedesc[object]):
    auto =
  var t: typ

  for field in t.fields:
    when field is EthAddress | MDigest:
      if not eat(field, data, pos, len): return
    elif field is (SomeInteger or byte):
      if not eatInt(field, data, pos, len): return
    elif field is seq[SomeInteger or byte]:
      if not eatSeq(field, data, pos, len): return
    else: # TODO: deserializing subtypes (?, depends on final spec)
      {.fatal: "Unsupported type deserialization: " & $typ.name.}
  return some(t)

func deserialize*(
      data: seq[byte or uint8] or openarray[byte or uint8] or string,
      typ: typedesc[object]): auto {.inline.} =
  # XXX: returns Option[typ]: https://github.com/nim-lang/Nim/issues/9195
  var pos = 0
  return deserialize((ptr byte)(data[0].unsafeAddr), pos, data.len, typ)

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
