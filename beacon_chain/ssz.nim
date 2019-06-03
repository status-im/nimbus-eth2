# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# SSZ Serialization (simple serialize)
# See https://github.com/ethereum/eth2.0-specs/blob/master/specs/simple-serialize.md

import
  endians, typetraits, options, algorithm, math,
  faststreams/input_stream, serialization, eth/common, nimcrypto/sha2,
  ./spec/[bitfield, crypto, datatypes, digest]

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

func toSSZType(x: Slot|Epoch): auto = x.uint64
func toSSZType(x: auto): auto = x

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
  BasicType =
    # Types that serialize down to a fixed-length array - most importantly,
    # these values don't carry a length prefix in the final encoding. toBytesSSZ
    # provides the actual nim-type-to-bytes conversion.
    # TODO think about this for a bit - depends where the serialization of
    #      validator keys ends up going..
    # TODO can't put ranges like ValidatorIndex in here:
    #      https://github.com/nim-lang/Nim/issues/10027
    SomeInteger | EthAddress | Eth2Digest | ValidatorPubKey | ValidatorSig |
      bool | Slot | Epoch

func sszLen(v: BasicType): int = toBytesSSZ(v.toSSZType()).len
func sszLen(v: ValidatorIndex): int = toBytesSSZ(v).len

func sszLen(v: object | tuple): int =
  result = 4 # Length
  for field in v.fields:
    result += sszLen(type field)

func sszLen(v: seq | array): int =
  result = 4 # Length
  for i in v:
    result += sszLen(i)

func sszLen(v: BitField): int =
  sszLen(v.bits)

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

proc writeValue*(w: var SszWriter, obj: auto) =
  # We are not using overloads here, because this leads to
  # slightly better error messages when the user provides
  # additional overloads for `writeValue`.
  mixin writeValue

  when obj is ValidatorIndex|BasicType:
    w.stream.append obj.toSSZType().toBytesSSZ
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
    elif obj is BitField:
      for elem in obj.bits:
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

  when result is ValidatorIndex|BasicType:
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

    elif T is BitField:
      type ElemType = type(result.bits[0])
      while r.stream[].pos < endPos:
        result.bits.add r.readValue(ElemType)

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
        # TODO This hardcoding's ugly; generalize & abstract.
        when field is Slot:
          field = r.readValue(uint64).Slot
        elif field is Epoch:
          field = r.readValue(uint64).Epoch
        else:
          field = r.readValue(field.type)

    if r.stream[].pos != endPos:
      raise newException(CorruptedDataError, "SSZ includes unexpected bytes past the end of the deserialized object")

# ################### Hashing ###################################

# Sample hash_tree_root implementation based on:
# https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/simple-serialize.md
# https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/test_libs/pyspec/eth2spec/utils/minimal_ssz.py
# TODO Probably wrong - the spec is pretty bare-bones and no test vectors yet

const
  BYTES_PER_CHUNK = 32

# ################### Hashing helpers ###################################

# TODO varargs openarray, anyone?
template withHash(body: untyped): array[32, byte] =
  let tmp = withEth2Hash: body
  toBytesSSZ tmp

func hash(a, b: openArray[byte]): array[32, byte] =
  withHash:
    h.update(a)
    h.update(b)

type
  Chunk = array[BYTES_PER_CHUNK, byte]

# TODO: er, how is this _actually_ done?
# Mandatory bug: https://github.com/nim-lang/Nim/issues/9825
func empty(T: type): T = discard
const emptyChunk = empty(Chunk)

func mix_in_length(root: Chunk, length: int): Chunk =
  var dataLen: array[32, byte]
  var lstLen = uint64(length)
  littleEndian64(dataLen[32-8].addr, lstLen.addr)

  hash(root, dataLen)

template padEmptyChunks(chunks: int) =
  for i in chunks..<nextPowerOfTwo(chunks):
    yield emptyChunk

iterator packAndPad(values: seq|array): Chunk =
  ## Produce a stream of chunks that are packed and padded such that they number
  ## a power of two

  when sizeof(values[0].toSSZType().toBytesSSZ()) == sizeof(Chunk):
    # When chunks and value lengths coincide, do the simple thing
    for v in values:
      yield v.toSSZType().toBytesSSZ()
    padEmptyChunks(values.len)

  else:
    var
      chunks: int
      tmp: Chunk
      tmpPos: int # how many bytes of tmp we've filled with ssz values

    for v in values:
      var
        vssz = toBytesSSZ(v.toSSZType)
        vPos = 0 # how many bytes of vssz that we've consumed

      while vPos < vssz.len:
        # there are still bytes of vssz left to consume - looping happens when
        # vssz.len > sizeof(Chunk)

        let left = min(tmp.len - tmpPos, vssz.len - vPos)
        copyMem(addr tmp[tmpPos], addr vssz[vPos], left)
        vPos += left
        tmpPos += left

        if tmpPos == tmp.len:
          # When vssz.len < sizeof(Chunk), multiple values will fit in a chunk
          yield tmp
          tmpPos = 0
          chunks += 1

    if tmpPos > 0:
      # If vssz.len is not a multiple of Chunk, we might need to pad the last
      # chunk with zeroes and return it
      for i in tmpPos..<tmp.len:
        tmp[i] = 0'u8
      yield tmp
      tmpPos = 0
      chunks += 1

    padEmptyChunks(chunks)

iterator hash_tree_collection(value: array|seq): Chunk =
  mixin hash_tree_root
  var chunks = 0
  for v in value:
    yield hash_tree_root(v).data
    chunks += 1
  padEmptyChunks(chunks)

iterator hash_tree_fields(value: object): Chunk =
  mixin hash_tree_root
  var chunks = 0
  for v in value.fields:
    yield hash_tree_root(v).data
    chunks += 1
  padEmptyChunks(chunks)

template merkleize(chunker: untyped): Chunk =
  var
    # a depth of 32 here should give us capability to handle 2^32 chunks,
    # more than enough
    # TODO replace with SmallVector-like thing..
    stack: array[32, tuple[height: int, chunk: Chunk]]
    stackPos = 0

  for chunk in chunker:
    # Leaves start at height 0 - every time they move up, height is increased
    # allowing us to detect two chunks at the same height ready for
    # consolidation
    # See also: http://szydlo.com/logspacetime03.pdf
    stack[stackPos] = (0, chunk)
    inc stackPos

    # Consolidate items of the same height - this keeps stack size at log N
    while stackPos > 1 and stack[stackPos - 1].height == stack[stackPos - 2].height:
      # As tradition dictates - one feature, at least one nim bug:
      # https://github.com/nim-lang/Nim/issues/9684
      let tmp = hash(stack[stackPos - 2].chunk, stack[stackPos - 1].chunk)
      stack[stackPos - 2].height += 1
      stack[stackPos - 2].chunk = tmp
      stackPos -= 1

  doAssert stackPos == 1,
    "With power-of-two leaves, we should end up with a single root"

  stack[0].chunk

template elementType[T, N](_: type array[N, T]): typedesc = T
template elementType[T](_: type seq[T]): typedesc = T

func hash_tree_root*[T](value: T): Eth2Digest =
  # Merkle tree
  Eth2Digest(data:
    when T is BasicType:
      merkleize(packAndPad([value]))
    elif T is array|seq:
      when T.elementType() is BasicType:
        mix_in_length(merkleize(packAndPad(value)), len(value))
      else:
        mix_in_length(merkleize(hash_tree_collection(value)), len(value))
    elif T is object:
      merkleize(hash_tree_fields(value))
    else:
      static: doAssert false, "Unexpected type: " & T.name
  )

iterator hash_tree_most(v: object): Chunk =
  const numFields = (proc(): int =
    var o: type(v)
    var i = 0
    for _, _ in o.fieldPairs: inc i
    i)()

  var i = 0
  for name, field in v.fieldPairs:
    if i == numFields - 1:
      break
    inc i
    yield hash_tree_root(field).data

# https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/simple-serialize.md#signed-roots
func signing_root*[T: object](x: T): Eth2Digest =
  # TODO write tests for this (check vs hash_tree_root)

  let root = merkleize(hash_tree_most(x))

  Eth2Digest(data: root)
