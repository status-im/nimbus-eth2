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
  faststreams/input_stream, serialization, eth/common, nimcrypto/keccak,
  ./spec/[crypto, datatypes, digest]

# ################### Helper functions ###################################

export
  serialization

type
  SszReader* = object
    stream: ByteStreamVar

  SszWriter* = object
    stream: OutputStreamVar

  SszError* = object of SerializationError
  CorruptedDataError* = object of SszError

  RecordWritingMemo = object
    initialStreamPos: int
    sizePrefixCursor: DelayedWriteCursor

serializationFormat SSZ,
                    Reader = SszReader,
                    Writer = SszWriter,
                    PreferedOutput = seq[byte]

proc init*(T: type SszReader, stream: ByteStreamVar): T =
  result.stream = stream

# toBytesSSZ convert simple fixed-length types to their SSZ wire representation
func toBytesSSZ(x: SomeInteger): array[sizeof(x), byte] =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **little endian**.

  when x.sizeof == 8: littleEndian64(result.addr, x.unsafeAddr)
  elif x.sizeof == 4: littleEndian32(result.addr, x.unsafeAddr)
  elif x.sizeof == 2: littleEndian16(result.addr, x.unsafeAddr)
  elif x.sizeof == 1: copyMem(result.addr, x.unsafeAddr, sizeof(result))
  else: {.fatal: "Unsupported type serialization: " & $(type(x)).name.}

func toBytesSSZ(x: ValidatorIndex): array[3, byte] =
  ## Integers are all encoded as little endian and not padded
  let v = x.uint32
  result[0] = byte(v and 0xff)
  result[1] = byte((v shr 8) and 0xff)
  result[2] = byte((v shr 16) and 0xff)

func toBytesSSZ(x: bool): array[1, byte] =
  [if x: 1'u8 else: 0'u8]

func toBytesSSZ(x: EthAddress): array[sizeof(x), byte] = x
func toBytesSSZ(x: Eth2Digest): array[32, byte] = x.data

# TODO these two are still being debated:
# https://github.com/ethereum/eth2.0-specs/issues/308#issuecomment-447026815
func toBytesSSZ(x: ValidatorPubKey|ValidatorSig): auto = x.getBytes()

type
  TrivialType =
    # Types that serialize down to a fixed-length array - most importantly,
    # these values don't carry a length prefix in the final encoding. toBytesSSZ
    # provides the actual nim-type-to-bytes conversion.
    # TODO think about this for a bit - depends where the serialization of
    #      validator keys ends up going..
    # TODO can't put ranges like ValidatorIndex in here:
    #      https://github.com/nim-lang/Nim/issues/10027
    SomeInteger | EthAddress | Eth2Digest | ValidatorPubKey | ValidatorSig |
      bool

func sszLen(v: TrivialType): int = toBytesSSZ(v).len
func sszLen(v: ValidatorIndex): int = toBytesSSZ(v).len

func sszLen(v: object | tuple): int =
  result = 4 # Length
  for field in v.fields:
    result += sszLen(type field)

func sszLen(v: seq | array): int =
  result = 4 # Length
  for i in v:
    result += sszLen(i)

# fromBytesSSZ copies the wire representation to a Nim variable,
# assuming there's enough data in the buffer
func fromBytesSSZ(T: type SomeInteger, data: openarray[byte]): T =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **little endian**.
  ## TODO: Assumes data points to a sufficiently large buffer
  doAssert data.len == sizeof(result)
  # TODO: any better way to get a suitably aligned buffer in nim???
  # see also: https://github.com/nim-lang/Nim/issues/9206
  var tmp: uint64
  var alignedBuf = cast[ptr byte](tmp.addr)
  copyMem(alignedBuf, unsafeAddr data[0], result.sizeof)

  when result.sizeof == 8: littleEndian64(result.addr, alignedBuf)
  elif result.sizeof == 4: littleEndian32(result.addr, alignedBuf)
  elif result.sizeof == 2: littleEndian16(result.addr, alignedBuf)
  elif result.sizeof == 1: copyMem(result.addr, alignedBuf, sizeof(result))
  else: {.fatal: "Unsupported type deserialization: " & $(type(result)).name.}

func fromBytesSSZ(T: type bool, data: openarray[byte]): T =
  # TODO: spec doesn't say what to do if the value is >1 - we'll use the C
  #       definition for now, but maybe this should be a parse error instead?
  fromBytesSSZ(uint8, data) != 0

func fromBytesSSZ(T: type ValidatorIndex, data: openarray[byte]): T =
  ## Integers are all encoded as littleendian and not padded
  doAssert data.len == 3
  var tmp: uint32
  tmp = tmp or uint32(data[0])
  tmp = tmp or uint32(data[1]) shl 8
  tmp = tmp or uint32(data[2]) shl 16
  result = tmp.ValidatorIndex

func fromBytesSSZ(T: type EthAddress, data: openarray[byte]): T =
  doAssert data.len == sizeof(result)
  copyMem(result.addr, unsafeAddr data[0], sizeof(result))

func fromBytesSSZ(T: type Eth2Digest, data: openarray[byte]): T =
  doAssert data.len == sizeof(result.data)
  copyMem(result.data.addr, unsafeAddr data[0], sizeof(result.data))

proc init*(T: type SszWriter, stream: OutputStreamVar): T =
  result.stream = stream

proc writeValue*(w: var SszWriter, obj: auto)

# This is an alternative lower-level API useful for RPC
# frameworks that can simulate the serialization of an
# object without constructing an actual instance:
proc beginRecord*(w: var SszWriter, T: type): RecordWritingMemo =
  result.initialStreamPos = w.stream.pos
  result.sizePrefixCursor = w.stream.delayFixedSizeWrite sizeof(uint32)

template writeField*(w: var SszWriter, name: string, value: auto) =
  w.writeValue(value)

proc endRecord*(w: var SszWriter, memo: RecordWritingMemo) =
  let finalSize = uint32(w.stream.pos - memo.initialStreamPos - 4)
  memo.sizePrefixCursor.endWrite(finalSize.toBytesSSZ)

func toSSZType(x: auto): auto =
  when x is Slot:
    x.uint64
  else:
    x

proc writeValue*(w: var SszWriter, obj: auto) =
  # We are not using overloads here, because this leads to
  # slightly better error messages when the user provides
  # additional overloads for `writeValue`.
  mixin writeValue

  when obj is ValidatorIndex|TrivialType:
    w.stream.append obj.toBytesSSZ
  elif obj is enum:
    w.stream.append uint64(obj).toBytesSSZ
  else:
    let memo = w.beginRecord(obj.type)
    when obj is seq|array|openarray:
      # If you get an error here that looks like:
      # type mismatch: got <type range 0..8191(uint64)>
      # you just used an unsigned int for an array index thinking you'd get
      # away with it (surprise, surprise: you can't, uints are crippled!)
      # https://github.com/nim-lang/Nim/issues/9984
      for elem in obj:
        w.writeValue elem
    else:
      obj.serializeFields(fieldName, field):
        # for research/serialized_sizes, remove when appropriate
        when defined(debugFieldSizes) and obj is (BeaconState|BeaconBlock):
          let start = w.stream.pos
          w.writeValue field.toSSZType
          debugEcho fieldName, ": ", w.stream.pos - start
        else:
          w.writeValue field.toSSZType
    w.endRecord(memo)

proc readValue*(r: var SszReader, result: var auto) =
  # We are not using overloads here, because this leads to
  # slightly better error messages when the user provides
  # additional overloads for `readValue`.
  type T = result.type
  mixin readValue

  template checkEof(n: int) =
    if not r.stream[].ensureBytes(n):
      raise newException(UnexpectedEofError, "SSZ has insufficient number of bytes")

  when result is ValidatorIndex|TrivialType:
    let bytesToRead = result.sszLen;
    checkEof bytesToRead

    when result is ValidatorPubKey|ValidatorSig:
      if not result.init(r.stream.readBytes(bytesToRead)):
        raise newException(CorruptedDataError, "Failed to load a BLS key or signature")
    else:
      result = T.fromBytesSSZ(r.stream.readBytes(bytesToRead))

  elif result is enum:
    # TODO what to do with out-of-range values?? rejecting means breaking
    #      forwards compatibility..
    result = cast[T](r.readValue(uint64))

  elif result is string:
    {.error: "The SSZ format doesn't support the string type yet".}
  else:
    let totalLen = int r.readValue(uint32)
    checkEof totalLen

    let endPos = r.stream[].pos + totalLen
    when T is seq:
      type ElemType = type(result[0])
      # Items are of homogenous type, but not necessarily homogenous length,
      # cannot pre-allocate item list generically
      while r.stream[].pos < endPos:
        result.add r.readValue(ElemType)

    elif T is array:
      type ElemType = type(result[0])
      var i = 0
      while r.stream[].pos < endPos:
        if i > result.len:
          raise newException(CorruptedDataError, "SSZ includes unexpected bytes past the end of an array")
        result[i] = r.readValue(ElemType)
        i += 1

    else:
      result.deserializeFields(fieldName, field):
        when field is Slot:
          field = r.readValue(uint64).Slot
        else:
          field = r.readValue(field.type)

    if r.stream[].pos != endPos:
      raise newException(CorruptedDataError, "SSZ includes unexpected bytes past the end of the deserialized object")

# ################### Hashing ###################################

# Sample hash_tree_root implementation based on:
# https://github.com/ethereum/eth2.0-specs/blob/a9328157a87451ee4f372df272ece158b386ec41/specs/simple-serialize.md
# TODO Probably wrong - the spec is pretty bare-bones and no test vectors yet

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
func empty(T: type): T = discard
const emptyChunk = empty(array[CHUNK_SIZE, byte])

func merkleHash[T](lst: openArray[T]): array[32, byte]

# ################### Hashing interface ###################################

func hash_tree_root*(x: SomeInteger | bool): array[sizeof(x), byte] =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **little endian**.
  toBytesSSZ(x)

func hash_tree_root*(x: ValidatorIndex): array[3, byte] =
  ## Convert directly to bytes the size of the int. (e.g. ``uint16 = 2 bytes``)
  ## All integers are serialized as **little endian**.
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

func hash_tree_root*[T: seq|array](x: T): array[32, byte] =
  ## Sequences are tree-hashed
  merkleHash(x)

func hash_tree_root*[T: object|tuple](x: T): array[32, byte] =
  ## Containers have their fields recursively hashed, concatenated and hashed
  withHash:
    for field in x.fields:
      h.update hash_tree_root(field.toSSZType)

# https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/simple-serialize.md#signed-roots
func signed_root*[T: object](x: T, field_name: string): array[32, byte] =
  # TODO write tests for this (check vs hash_tree_root)

  var found_field_name = false

  withHash:
    for name, field in x.fieldPairs:
      if name == field_name:
        found_field_name = true
        break
      h.update hash_tree_root(field.toSSZType)

    doAssert found_field_name

# #################################
# hash_tree_root not part of official spec
func hash_tree_root*(x: enum): array[8, byte] =
  ## TODO - Warning ⚠️: not part of the spec
  ## as of https://github.com/ethereum/beacon_chain/pull/133/files
  ## This is a "stub" needed for BeaconBlock hashing
  static: assert x.sizeof == 1 # Check that the enum fits in 1 byte
  # TODO We've put enums where the spec uses `uint64` - maybe we should not be
  # using enums?
  hash_tree_root(uint64(x))

func hash_tree_root*(x: ValidatorPubKey): array[32, byte] =
  ## TODO - Warning ⚠️: not part of the spec
  ## as of https://github.com/ethereum/beacon_chain/pull/133/files
  ## This is a "stub" needed for BeaconBlock hashing
  x.getBytes().hash()

func hash_tree_root*(x: ValidatorSig): array[32, byte] =
  ## TODO - Warning ⚠️: not part of the spec
  ## as of https://github.com/ethereum/beacon_chain/pull/133/files
  ## This is a "stub" needed for BeaconBlock hashing
  x.getBytes().hash()

func hash_tree_root_final*(x: object|tuple): Eth2Digest =
  # TODO suggested for spec:
  # https://github.com/ethereum/eth2.0-specs/issues/276
  # only for objects now, else the padding would have to be implemented - not
  # needed yet..
  Eth2Digest(data: hash_tree_root(x))

# ################### Tree hash ###################################

func merkleHash[T](lst: openArray[T]): array[32, byte] =
  ## Merkle tree hash of a list of homogenous, non-empty items

  # TODO: the heap allocations here can be avoided by computing the merkle tree
  #      recursively, but for now keep things simple and aligned with upstream

  # Store length of list (to compensate for non-bijectiveness of padding)
  var dataLen: array[32, byte]
  var lstLen = uint64(len(lst))
  littleEndian64(dataLen[32-8].addr, lstLen.addr)

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

  hash(chunkz[0], dataLen)
