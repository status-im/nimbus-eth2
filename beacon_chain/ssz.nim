# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# SSZ Serialization (simple serialize)
# See https://github.com/ethereum/beacon_chain/issues/100
# and https://github.com/ethereum/beacon_chain/tree/master/ssz

import
  endians, typetraits, options, algorithm,
  eth_common, nimcrypto/blake2,
  ./spec/[crypto, datatypes, digest]

from milagro_crypto import getRaw

# ################### Helper functions ###################################

func len(x: Uint24): int = 3

func toBytesSSZ(x: SomeInteger): array[sizeof(x), byte] =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **big endian**.

  when x.sizeof == 8: bigEndian64(result.addr, x.unsafeAddr)
  elif x.sizeof == 4: bigEndian32(result.addr, x.unsafeAddr)
  elif x.sizeof == 2: bigEndian16(result.addr, x.unsafeAddr)
  elif x.sizeof == 1: copyMem(result.addr, x.unsafeAddr, sizeof(result))
  else: {.fatal: "Unsupported type serialization: " & $(type(x)).name.}

func toBytesSSZ(x: Uint24): array[3, byte] =
  ## Integers are all encoded as bigendian and not padded
  let v = x.uint32
  result[2] = byte(v and 0xff)
  result[1] = byte((v shr 8) and 0xff)
  result[0] = byte((v shr 16) and 0xff)

func toBytesSSZ(x: EthAddress): array[sizeof(x), byte] = x
func toBytesSSZ(x: Eth2Digest): array[32, byte] = x.data

func fromBytesSSZUnsafe(T: typedesc[SomeInteger], data: ptr byte): T =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **big endian**.
  ## TODO: Assumes data points to a sufficiently large buffer

  # TODO: any better way to get a suitably aligned buffer in nim???
  # see also: https://github.com/nim-lang/Nim/issues/9206
  var tmp: uint64
  var alignedBuf = cast[ptr byte](tmp.addr)
  copyMem(alignedBuf, data, result.sizeof)

  when result.sizeof == 8: bigEndian64(result.addr, alignedBuf)
  elif result.sizeof == 4: bigEndian32(result.addr, alignedBuf)
  elif result.sizeof == 2: bigEndian16(result.addr, alignedBuf)
  elif result.sizeof == 1: copyMem(result.addr, alignedBuf, sizeof(result))
  else: {.fatal: "Unsupported type deserialization: " & $(type(result)).name.}

func `+`[T](p: ptr T, offset: int): ptr T =
  ## Pointer arithmetic: Addition
  const size = sizeof T
  cast[ptr T](cast[ByteAddress](p) +% offset * size)

func eat(x: var auto, data: ptr byte, pos: var int, len: int): bool =
  if pos + x.sizeof > len: return
  copyMem(x.addr, data + pos, x.sizeof)
  inc pos, x.sizeof
  return true

func eatInt[T: SomeInteger](x: var T, data: ptr byte, pos: var int, len: int):
    bool =
  if pos + x.sizeof > len: return

  x = T.fromBytesSSZUnsafe(data + pos)

  inc pos, x.sizeof
  return true

func eatSeq[T: SomeInteger](x: var seq[T], data: ptr byte, pos: var int,
    len: int): bool =
  var items: int32
  if not eatInt(items, data, pos, len): return
  if pos + T.sizeof * items > len: return

  x = newSeqUninitialized[T](items)
  for val in x.mitems:
    discard eatInt(val, data, pos, len) # Bounds-checked above
  return true

func serInt(dest: var seq[byte], x: SomeInteger) =
  dest.add x.toBytesSSZ()

func serSeq(dest: var seq[byte], src: seq[SomeInteger]) =
  dest.serInt src.len.uint32
  for val in src:
    dest.add val.toBytesSSZ()

# ################### Core functions ###################################
func deserialize(data: ptr byte, pos: var int, len: int, typ: typedesc[object]):
    auto =
  var t: typ

  for field in t.fields:
    when field is EthAddress | Eth2Digest:
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
  # TODO: returns Option[typ]: https://github.com/nim-lang/Nim/issues/9195
  var pos = 0
  return deserialize((ptr byte)(data[0].unsafeAddr), pos, data.len, typ)

func serialize*[T](value: T): seq[byte] =
  for field in value.fields:
    when field is (EthAddress | Eth2Digest | SomeInteger):
      result.add field.toBytesSSZ()
    elif field is seq[SomeInteger or byte]:
      result.serSeq field
    else: # TODO: Serializing subtypes (?, depends on final spec)
      {.fatal: "Unsupported type serialization: " & $typ.name.}

# ################### Hashing ###################################

# Sample hash_tree_root implementation based on:
# https://github.com/ethereum/eth2.0-specs/blob/98312f40b5742de6aa73f24e6225ee68277c4614/specs/simple-serialize.md
# and
# https://github.com/ethereum/beacon_chain/pull/134
# Probably wrong - the spec is pretty bare-bones and no test vectors yet

const CHUNK_SIZE = 128

# ################### Hashing helpers ###################################

# TODO varargs openarray, anyone?
template withHash(body: untyped): array[32, byte] =
  let tmp = withEth2Hash: body
  toBytesSSZ tmp

func hash(a: openArray[byte]): array[32, byte] =
  withHash:
    h.update(a)

func hash(a, b: openArray[byte]): array[32, byte] =
  withHash:
    h.update(a)
    h.update(b)

# TODO: er, how is this _actually_ done?
# Mandatory bug: https://github.com/nim-lang/Nim/issues/9825
func empty(T: typedesc): T = discard
const emptyChunk = empty(array[CHUNK_SIZE, byte])

func merkleHash[T](lst: openArray[T]): array[32, byte]

# ################### Hashing interface ###################################

func hash_tree_root*(x: SomeInteger): array[sizeof(x), byte] =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **big endian**.
  toBytesSSZ(x)

func hash_tree_root*(x: Uint24): array[3, byte] =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **big endian**.
  toBytesSSZ(x)

func hash_tree_root*(x: EthAddress): array[sizeof(x), byte] =
  ## Addresses copied as-is
  toBytesSSZ(x)

func hash_tree_root*(x: Eth2Digest): array[32, byte] =
  ## Hash32 copied as-is
  toBytesSSZ(x)

func hash_tree_root*(x: openArray[byte]): array[32, byte] =
  ## Blobs are hashed
  hash(x)

func hash_tree_root*[T: not enum](x: T): array[32, byte] =
  when T is seq or T is array:
    ## Sequences are tree-hashed
    merkleHash(x)
  else:
    ## Containers have their fields recursively hashed, concatenated and hashed
    # TODO could probaby compile-time-macro-sort fields...
    # TODO or.. https://github.com/ethereum/eth2.0-specs/issues/275
    var fields: seq[tuple[name: string, value: seq[byte]]]
    for name, field in x.fieldPairs:
      fields.add (name, @(hash_tree_root(field)))

    withHash:
      for name, value in fields.sortedByIt(it.name):
        h.update hash_tree_root(value.value)

# #################################
# hash_tree_root not part of official spec
func hash_tree_root*(x: enum): array[32, byte] =
  ## TODO - Warning ⚠️: not part of the spec
  ## as of https://github.com/ethereum/beacon_chain/pull/133/files
  ## This is a "stub" needed for BeaconBlock hashing
  static: assert x.sizeof == 1 # Check that the enum fits in 1 byte
  withHash:
    h.update [uint8 x]

func hash_tree_root*(x: ValidatorPubKey): array[32, byte] =
  ## TODO - Warning ⚠️: not part of the spec
  ## as of https://github.com/ethereum/beacon_chain/pull/133/files
  ## This is a "stub" needed for BeaconBlock hashing
  x.getRaw().hash()

func hash_tree_root*(x: ValidatorSig): array[32, byte] =
  ## TODO - Warning ⚠️: not part of the spec
  ## as of https://github.com/ethereum/beacon_chain/pull/133/files
  ## This is a "stub" needed for BeaconBlock hashing
  x.getRaw().hash()

# ################### Tree hash ###################################

func merkleHash[T](lst: openArray[T]): array[32, byte] =
  ## Merkle tree hash of a list of homogenous, non-empty items

  # TODO: the heap allocations here can be avoided by computing the merkle tree
  #      recursively, but for now keep things simple and aligned with upstream

  # Store length of list (to compensate for non-bijectiveness of padding)
  var dataLen: array[32, byte]
  var lstLen = uint64(len(lst))
  bigEndian64(dataLen[32-8].addr, lstLen.addr)

  # Divide into chunks
  var chunkz: seq[seq[byte]]

  if len(lst) == 0:
    chunkz.add @emptyChunk
  elif sizeof(hash_tree_root(lst[0])) < CHUNK_SIZE:
    # See how many items fit in a chunk
    let itemsPerChunk = CHUNK_SIZE div sizeof(hash_tree_root(lst[0]))

    chunkz.setLen((len(lst) + itemsPerChunk - 1) div itemsPerChunk)

    # Build a list of chunks based on the number of items in the chunk
    for i in 0..<chunkz.len:
      for j in 0..<itemsPerChunk:
        if i == chunkz.len - 1:
          let idx = i * itemsPerChunk + j
          if idx >= lst.len: break # Last chunk may be partial!
        chunkz[i].add hash_tree_root(lst[i * itemsPerChunk + j])
  else:
    # Leave large items alone
    chunkz.setLen(len(lst))
    for i in 0..<len(lst):
      chunkz[i].add hash_tree_root(lst[i])

  while chunkz.len() > 1:
    if chunkz.len() mod 2 == 1:
      chunkz.add @emptyChunk
    for i in 0..<(chunkz.len div 2):
      # As tradition dictates - one feature, at least one nim bug:
      # https://github.com/nim-lang/Nim/issues/9684
      let tmp = @(hash(chunkz[i * 2], chunkz[i * 2 + 1]))
      chunkz[i] = tmp

    chunkz.setLen(chunkz.len div 2)

  if chunkz.len == 0:
    const empty32 = empty(array[32, byte])
    result = hash(empty32, dataLen)
    return

  result = hash(chunkz[0], dataLen)
