# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# SSZ Serialization (simple serialize)
# See https://github.com/ethereum/eth2.0-specs/blob/master/specs/simple-serialize.md

import
  endians, typetraits, options, algorithm,
  eth_common, nimcrypto/blake2, milagro_crypto,
  ./spec/[crypto, datatypes, digest]

from milagro_crypto import getRaw

# ################### Helper functions ###################################

# toBytesSSZ convert simple fixed-length types to their SSZ wire representation
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

# TODO these two are still being debated:
# https://github.com/ethereum/eth2.0-specs/issues/308#issuecomment-447026815
func toBytesSSZ(x: ValidatorPubKey|ValidatorSig): auto = x.getRaw()

type TrivialTypes =
  # Types that serialize down to a fixed-length array - basically, all those
  # for which toBytesSSZ is defined!
  # TODO think about this for a bit - depends where the serialization of
  #      validator keys ends up going..
  SomeInteger | Uint24 | EthAddress | Eth2Digest | ValidatorPubKey |
  ValidatorSig

func sszLen(v: TrivialTypes): int =
  toBytesSSZ(v).len

func sszLen(v: object | tuple): int =
  result = 4 # Length
  for field in v.fields:
    result += sszLen(type field)

func sszLen(v: seq | array): int =
  result = 4 # Length
  for i in v:
    result += sszLen(i)

# fromBytesSSZUnsafe copy wire representation to a Nim variable, assuming
# there's enough data in the buffer
func fromBytesSSZUnsafe(T: typedesc[SomeInteger], data: pointer): T =
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

func fromBytesSSZUnsafe(T: typedesc[Uint24], data: pointer): T =
  ## Integers are all encoded as bigendian and not padded
  var tmp: uint32
  let p = cast[ptr UncheckedArray[byte]](data)
  tmp = tmp or uint32(p[2])
  tmp = tmp or uint32(p[1]) shl 8
  tmp = tmp or uint32(p[0]) shl 16
  result = tmp.Uint24

func fromBytesSSZUnsafe(T: typedesc[EthAddress], data: pointer): T =
  copyMem(result.addr, data, sizeof(result))

func fromBytesSSZUnsafe(T: typedesc[Eth2Digest], data: pointer): T =
  copyMem(result.data.addr, data, sizeof(result.data))

proc deserialize[T: TrivialTypes](
    dest: var T, offset: var int, data: openArray[byte]): bool =
  # TODO proc because milagro is problematic
  if offset + sszLen(dest) > data.len():
    false
  else:
    when T is (ValidatorPubKey|ValidatorSig):
      if T.fromRaw(data[offset..data.len-1], dest):
        offset += sszLen(dest)
        true
      else:
        false
    else:
      dest = fromBytesSSZUnsafe(T, data[offset].unsafeAddr)
      offset += sszLen(dest)
      true

func deserialize[T: enum](dest: var T, offset: var int, data: openArray[byte]): bool =
  # TODO er, verify the size here, probably an uint64 but...
  var tmp: uint64
  if not deserialize(tmp, offset, data):
    false
  else:
    dest = cast[T](tmp)
    true

proc deserialize[T: not (enum|TrivialTypes)](
    dest: var T, offset: var int, data: openArray[byte]): bool =
  # Length is a prefix, so we'll put a dummy value there and fill it after
  # serializing
  var totalLen: uint32
  if not deserialize(totalLen, offset, data): return false

  if offset + totalLen.int > data.len(): return false

  let itemEnd = offset + totalLen.int
  when T is seq:
    # Items are of homogenous type, but not necessarily homogenous length
    while offset < itemEnd:
      dest.setLen dest.len + 1
      if not deserialize(dest[^1], offset, data): return false
  elif T is array:
    var i = 0
    while offset < itemEnd:
      if not deserialize(dest[i], offset, data): return false
      i += 1
      if i > dest.len: return false
  else:
    for field in dest.fields:
      if not deserialize(field, offset, data):  return false
    if offset != itemEnd: return false

  true

func serialize(dest: var seq[byte], src: TrivialTypes) =
  dest.add src.toBytesSSZ()

func serialize(dest: var seq[byte], x: enum) =
  # TODO er, verify the size here, probably an uint64 but...
  serialize dest, uint64(x)

func serialize[T: not enum](dest: var seq[byte], src: T) =
  # Length is a prefix, so we'll put a dummy value there and fill it after
  # serializing

  let lenPos = dest.len()
  dest.add toBytesSSZ(0'u32)

  when T is seq|array:
    # If you get an error here that looks like:
    # type mismatch: got <type range 0..8191(uint64)>
    # you just used an unsigned int for an array index thinking you'd get
    # away with it (surprise, surprise: you can't, uints are crippled!)
    # https://github.com/nim-lang/Nim/issues/9984
    for val in src:
      serialize dest, val
  else:
    # TODO to sort, or not to sort, that is the question:
    # TODO or.. https://github.com/ethereum/eth2.0-specs/issues/275
    when defined(debugFieldSizes) and T is (BeaconState | BeaconBlock):
      # for research/serialized_sizes, remove when appropriate
      for name, field in src.fieldPairs:
        let start = dest.len()
        serialize dest, field
        let sz = dest.len() - start
        debugEcho(name, ": ", sz)
    else:
      for field in src.fields:
        serialize dest, field

  # Write size (we only know it once we've serialized the object!)
  var objLen = dest.len() - lenPos - 4
  bigEndian32(dest[lenPos].addr, objLen.addr)

# ################### Core functions ###################################

proc deserialize*(data: openArray[byte],
                  typ: typedesc): auto {.inline.} =
  # TODO: returns Option[typ]: https://github.com/nim-lang/Nim/issues/9195
  var ret: typ
  var offset: int
  if not deserialize(ret, offset, data): none(typ)
  else: some(ret)

func serialize*[T](value: T): seq[byte] =
  # TODO Fields should be sorted, but...
  serialize(result, value)

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
        h.update value.value

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
