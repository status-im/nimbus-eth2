# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This module contains the parts necessary to create a merkle hash from the core
# SSZ types outlined in the spec:
# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/ssz/simple-serialize.md#merkleization

{.push raises: [Defect].}

import
  stew/[bitops2, endians2, ptrops],
  stew/ranges/ptr_arith,
  serialization/testing/tracing,
  ../spec/digest,
  ./bitseqs, ./spec_types, ./types

export
  spec_types, types

when hasSerializationTracing:
  import stew/byteutils, typetraits

const
  zero64 = default array[64, byte]
  bitsPerChunk = bytesPerChunk * 8

type
  SszChunksMerkleizer = object
    combinedChunks: ptr UncheckedArray[Eth2Digest]
    totalChunks: uint64
    topIndex: int

func digest(a, b: openArray[byte]): Eth2Digest =
  result = withEth2Hash:
    trs "DIGESTING ARRAYS ", toHex(a), " ", toHex(b)
    trs toHex(a)
    trs toHex(b)

    h.update a
    h.update b
  trs "HASH RESULT ", result

func digest(a, b, c: openArray[byte]): Eth2Digest =
  result = withEth2Hash:
    trs "DIGESTING ARRAYS ", toHex(a), " ", toHex(b), " ", toHex(c)

    h.update a
    h.update b
    h.update c
  trs "HASH RESULT ", result

func mergeBranches(existing: Eth2Digest, newData: openarray[byte]): Eth2Digest =
  trs "MERGING BRANCHES OPEN ARRAY"

  let paddingBytes = bytesPerChunk - newData.len
  digest(existing.data, newData, zero64.toOpenArray(0, paddingBytes - 1))

template mergeBranches(existing: Eth2Digest, newData: array[32, byte]): Eth2Digest =
  trs "MERGING BRANCHES ARRAY"
  digest(existing.data, newData)

template mergeBranches(a, b: Eth2Digest): Eth2Digest =
  trs "MERGING BRANCHES DIGEST"
  digest(a.data, b.data)

func computeZeroHashes: array[sizeof(Limit) * 8, Eth2Digest] =
  result[0] = Eth2Digest()
  for i in 1 .. result.high:
    result[i] = mergeBranches(result[i - 1], result[i - 1])

const zeroHashes = computeZeroHashes()

func addChunk(merkleizer: var SszChunksMerkleizer, data: openarray[byte]) =
  doAssert data.len > 0 and data.len <= bytesPerChunk

  if not getBitLE(merkleizer.totalChunks, 0):
    let paddingBytes = bytesPerChunk - data.len

    merkleizer.combinedChunks[0].data[0..<data.len] = data
    merkleizer.combinedChunks[0].data[data.len..<bytesPerChunk] =
      zero64[0..<paddingBytes]

    trs "WROTE BASE CHUNK ",
      toHex(merkleizer.combinedChunks[0].data), " ", data.len
  else:
    var hash = mergeBranches(merkleizer.combinedChunks[0], data)

    for i in 1 .. merkleizer.topIndex:
      trs "ITERATING"
      if getBitLE(merkleizer.totalChunks, i):
        trs "CALLING MERGE BRANCHES"
        hash = mergeBranches(merkleizer.combinedChunks[i], hash)
      else:
        trs "WRITING FRESH CHUNK AT ", i, " = ", hash
        merkleizer.combinedChunks[i] = hash
        break

  inc merkleizer.totalChunks

template createMerkleizer(totalElements: static Limit): SszChunksMerkleizer =
  trs "CREATING A MERKLEIZER FOR ", totalElements

  const treeHeight = bitWidth nextPow2(uint64 totalElements)
  var combinedChunks {.noInit.}: array[treeHeight, Eth2Digest]

  SszChunksMerkleizer(
    combinedChunks: cast[ptr UncheckedArray[Eth2Digest]](addr combinedChunks),
    topIndex: treeHeight - 1,
    totalChunks: 0)

func getFinalHash(merkleizer: var SszChunksMerkleizer): Eth2Digest =
  if merkleizer.totalChunks == 0:
    return zeroHashes[merkleizer.topIndex]

  let
    bottomHashIdx = firstOne(merkleizer.totalChunks) - 1
    submittedChunksHeight = bitWidth(merkleizer.totalChunks - 1)
    topHashIdx = merkleizer.topIndex

  trs "BOTTOM HASH ", bottomHashIdx
  trs "SUBMITTED HEIGHT ", submittedChunksHeight
  trs "TOP HASH IDX ", topHashIdx

  if bottomHashIdx != submittedChunksHeight:
    # Our tree is not finished. We must complete the work in progress
    # branches and then extend the tree to the right height.
    result = mergeBranches(merkleizer.combinedChunks[bottomHashIdx],
                           zeroHashes[bottomHashIdx])

    for i in bottomHashIdx + 1 ..< topHashIdx:
      if getBitLE(merkleizer.totalChunks, i):
        result = mergeBranches(merkleizer.combinedChunks[i], result)
        trs "COMBINED"
      else:
        result = mergeBranches(result, zeroHashes[i])
        trs "COMBINED WITH ZERO"

  elif bottomHashIdx == topHashIdx:
    # We have a perfect tree (chunks == 2**n) at just the right height!
    result = merkleizer.combinedChunks[bottomHashIdx]
  else:
    # We have a perfect tree of user chunks, but we have more work to
    # do - we must extend it to reach the desired height
    result = mergeBranches(merkleizer.combinedChunks[bottomHashIdx],
                           zeroHashes[bottomHashIdx])

    for i in bottomHashIdx + 1 ..< topHashIdx:
      result = mergeBranches(result, zeroHashes[i])

func mixInLength(root: Eth2Digest, length: int): Eth2Digest =
  var dataLen: array[32, byte]
  dataLen[0..<8] = uint64(length).toBytesLE()
  mergeBranches(root, dataLen)

func hash_tree_root*(x: auto): Eth2Digest {.gcsafe, raises: [Defect].}

template merkleizeFields(totalElements: static Limit, body: untyped): Eth2Digest =
  var merkleizer {.inject.} = createMerkleizer(totalElements)

  template addField(field) =
    let hash = hash_tree_root(field)
    trs "MERKLEIZING FIELD ", astToStr(field), " = ", hash
    addChunk(merkleizer, hash.data)
    trs "CHUNK ADDED"

  body

  getFinalHash(merkleizer)

template writeBytesLE(chunk: var array[bytesPerChunk, byte], atParam: int,
                      val: SomeUnsignedInt) =
  let at = atParam
  chunk[at ..< at + sizeof(val)] = toBytesLE(val)

func chunkedHashTreeRootForBasicTypes[T](merkleizer: var SszChunksMerkleizer,
                                         arr: openarray[T]): Eth2Digest =
  static:
    doAssert T is BasicType

  if arr.len == 0:
    return getFinalHash(merkleizer)

  when T is byte:
    var
      remainingBytes = arr.len
      pos = cast[ptr byte](unsafeAddr arr[0])

    while remainingBytes >= bytesPerChunk:
      merkleizer.addChunk(makeOpenArray(pos, bytesPerChunk))
      pos = offset(pos, bytesPerChunk)
      remainingBytes -= bytesPerChunk

    if remainingBytes > 0:
      merkleizer.addChunk(makeOpenArray(pos, remainingBytes))

  elif T is bool or cpuEndian == littleEndian:
    let
      baseAddr = cast[ptr byte](unsafeAddr arr[0])
      len = arr.len * sizeof(T)
    return chunkedHashTreeRootForBasicTypes(merkleizer, makeOpenArray(baseAddr, len))

  else:
    static:
      doAssert T is UintN
      doAssert bytesPerChunk mod sizeof(Т) == 0

    const valuesPerChunk = bytesPerChunk div sizeof(Т)

    var writtenValues = 0

    var chunk: array[bytesPerChunk, byte]
    while writtenValues < arr.len - valuesPerChunk:
      for i in 0 ..< valuesPerChunk:
        chunk.writeBytesLE(i * sizeof(T), arr[writtenValues + i])
      merkleizer.addChunk chunk
      inc writtenValues, valuesPerChunk

    let remainingValues = arr.len - writtenValues
    if remainingValues > 0:
      var lastChunk: array[bytesPerChunk, byte]
      for i in 0 ..< remainingValues:
        chunk.writeBytesLE(i * sizeof(T), arr[writtenValues + i])
      merkleizer.addChunk lastChunk

  getFinalHash(merkleizer)

func bitListHashTreeRoot(merkleizer: var SszChunksMerkleizer, x: BitSeq): Eth2Digest =
  # TODO: Switch to a simpler BitList representation and
  #       replace this with `chunkedHashTreeRoot`
  trs "CHUNKIFYING BIT SEQ WITH TOP INDEX ", merkleizer.topIndex

  var
    totalBytes = bytes(x).len
    lastCorrectedByte = bytes(x)[^1]

  if lastCorrectedByte == byte(1):
    if totalBytes == 1:
      # This is an empty bit list.
      # It should be hashed as a tree containing all zeros:
      return mergeBranches(zeroHashes[merkleizer.topIndex],
                           zeroHashes[0]) # this is the mixed length

    totalBytes -= 1
    lastCorrectedByte = bytes(x)[^2]
  else:
    let markerPos = log2trunc(lastCorrectedByte)
    lastCorrectedByte.clearBit(markerPos)

  var
    bytesInLastChunk = totalBytes mod bytesPerChunk
    fullChunks = totalBytes div bytesPerChunk

  if bytesInLastChunk == 0:
    fullChunks -= 1
    bytesInLastChunk = 32

  for i in 0 ..< fullChunks:
    let
      chunkStartPos = i * bytesPerChunk
      chunkEndPos = chunkStartPos + bytesPerChunk - 1

    merkleizer.addChunk bytes(x).toOpenArray(chunkStartPos, chunkEndPos)

  var
    lastChunk: array[bytesPerChunk, byte]
    chunkStartPos = fullChunks * bytesPerChunk

  for i in 0 .. bytesInLastChunk - 2:
    lastChunk[i] = bytes(x)[chunkStartPos + i]

  lastChunk[bytesInLastChunk - 1] = lastCorrectedByte

  merkleizer.addChunk lastChunk.toOpenArray(0, bytesInLastChunk - 1)
  let contentsHash = merkleizer.getFinalHash
  mixInLength contentsHash, x.len

func maxChunksCount(T: type, maxLen: int64): int64 =
  when T is BitList|BitArray:
    (maxLen + bitsPerChunk - 1) div bitsPerChunk
  elif T is array|List:
    maxChunkIdx(ElemType(T), maxLen)
  else:
    unsupported T # This should never happen

func hashTreeRootAux[T](x: T): Eth2Digest =
  when T is bool|char:
    result.data[0] = byte(x)
  elif T is SomeUnsignedInt:
    when cpuEndian == bigEndian:
      result.data[0..<sizeof(x)] = toBytesLE(x)
    else:
      copyMem(addr result.data[0], unsafeAddr x, sizeof x)
  elif (when T is array: ElemType(T) is BasicType else: false):
    type E = ElemType(T)
    when sizeof(T) <= sizeof(result.data):
      when E is byte|bool or cpuEndian == littleEndian:
        copyMem(addr result.data[0], unsafeAddr x, sizeof x)
      else:
        var pos = 0
        for e in x:
          writeBytesLE(result.data, pos, e)
          pos += sizeof(E)
    else:
      trs "FIXED TYPE; USE CHUNK STREAM"
      var markleizer = createMerkleizer(maxChunksCount(T, x.len))
      chunkedHashTreeRootForBasicTypes(markleizer, x)
  elif T is BitArray:
    hashTreeRootAux(x.bytes)
  elif T is array|object|tuple:
    trs "MERKLEIZING FIELDS"
    const totalFields = when T is array: len(x)
                        else: totalSerializedFields(T)
    merkleizeFields(totalFields):
      x.enumerateSubFields(f):
        addField f
  #elif isCaseObject(T):
  #  # TODO implement this
  else:
    unsupported T

func hashTreeRootList(x: List|BitList): Eth2Digest =
  const maxLen = static(x.maxLen)
  type T = type(x)
  const limit = maxChunksCount(T, maxLen)
  var merkleizer = createMerkleizer(limit)

  when x is BitList:
    merkleizer.bitListHashTreeRoot(BitSeq x)
  else:
    type E = ElemType(T)
    let contentsHash = when E is BasicType:
      chunkedHashTreeRootForBasicTypes(merkleizer, asSeq x)
    else:
      for elem in x:
        let elemHash = hash_tree_root(elem)
        merkleizer.addChunk(elemHash.data)
      merkleizer.getFinalHash()
    mixInLength(contentsHash, x.len)

func mergedDataHash(x: HashList|HashArray, chunkIdx: int64): Eth2Digest =
  # The merged hash of the data at `chunkIdx` and `chunkIdx + 1`
  trs "DATA HASH ", chunkIdx, " ", x.data.len

  when x.T is BasicType:
    when cpuEndian == bigEndian:
      unsupported type x # No bigendian support here!

    let
      bytes = cast[ptr UncheckedArray[byte]](unsafeAddr x.data[0])
      byteIdx = chunkIdx * bytesPerChunk
      byteLen = x.data.len * sizeof(x.T)

    if byteIdx >= byteLen:
      zeroHashes[1]
    else:
      let
        nbytes = min(byteLen - byteIdx, 64)
        padding = 64 - nbytes

      digest(
        toOpenArray(bytes, int(byteIdx), int(byteIdx + nbytes - 1)),
        toOpenArray(zero64, 0, int(padding - 1)))
  else:
    if chunkIdx + 1 > x.data.len():
      zeroHashes[x.maxDepth]
    elif chunkIdx + 1 == x.data.len():
      mergeBranches(
        hash_tree_root(x.data[chunkIdx]),
        Eth2Digest())
    else:
      mergeBranches(
        hash_tree_root(x.data[chunkIdx]),
        hash_tree_root(x.data[chunkIdx + 1]))

template mergedHash(x: HashList|HashArray, vIdxParam: int64): Eth2Digest =
  # The merged hash of the data at `vIdx` and `vIdx + 1`
  let vIdx = vIdxParam
  if vIdx >= x.maxChunks:
    let dataIdx = vIdx - x.maxChunks
    mergedDataHash(x, dataIdx)
  else:
    mergeBranches(
      hashTreeRootCached(x, vIdx),
      hashTreeRootCached(x, vIdx + 1))

func hashTreeRootCached*(x: HashList, vIdx: int64): Eth2Digest =
  doAssert vIdx >= 1, "Only valid for flat merkle tree indices"

  let
    layer = layer(vIdx)
    idxInLayer = vIdx - (1'i64 shl layer)
    layerIdx = idxInlayer + x.indices[layer]

  trs "GETTING ", vIdx, " ", layerIdx, " ", layer, " ", x.indices.len

  doAssert layer < x.maxDepth
  if layerIdx >= x.indices[layer + 1]:
    trs "ZERO ", x.indices[layer], " ", x.indices[layer + 1]
    zeroHashes[x.maxDepth - layer]
  else:
    if not isCached(x.hashes[layerIdx]):
      # TODO oops. so much for maintaining non-mutability.
      let px = unsafeAddr x

      trs "REFRESHING ", vIdx, " ", layerIdx, " ", layer

      px[].hashes[layerIdx] = mergedHash(x, vIdx * 2)
    else:
      trs "CACHED ", layerIdx

    x.hashes[layerIdx]

func hashTreeRootCached*(x: HashArray, vIdx: int): Eth2Digest =
  doAssert vIdx >= 1, "Only valid for flat merkle tree indices"

  if not isCached(x.hashes[vIdx]):
    # TODO oops. so much for maintaining non-mutability.
    let px = unsafeAddr x

    px[].hashes[vIdx] = mergedHash(x, vIdx * 2)

  return x.hashes[vIdx]

func hashTreeRootCached*(x: HashArray): Eth2Digest =
  hashTreeRootCached(x, 1) # Array does not use idx 0

func hashTreeRootCached*(x: HashList): Eth2Digest =
  if x.data.len == 0:
    mergeBranches(
      zeroHashes[x.maxDepth],
      zeroHashes[0]) # mixInLength with 0!
  else:
    if not isCached(x.hashes[0]):
      # TODO oops. so much for maintaining non-mutability.
      let px = unsafeAddr x
      px[].hashes[0] = mixInLength(hashTreeRootCached(x, 1), x.data.len)

    x.hashes[0]

func hash_tree_root*(x: auto): Eth2Digest {.raises: [Defect].} =
  trs "STARTING HASH TREE ROOT FOR TYPE ", name(type(x))
  mixin toSszType

  result =
    when x is HashArray|HashList:
      hashTreeRootCached(x)
    elif x is List|BitList:
      hashTreeRootList(x)
    else:
      hashTreeRootAux toSszType(x)

  trs "HASH TREE ROOT FOR ", name(type x), " = ", "0x", $result

iterator hash_tree_roots_prefix*[T](lst: openarray[T], limit: static Limit): Eth2Digest =
  # This is a particular type's instantiation of a general fold, reduce,
  # accumulation, prefix sums, etc family of operations. As long as that
  # Eth1 deposit case is the only notable example -- the usual uses of a
  # list involve, at some point, tree-hashing it -- finalized hashes are
  # the only abstraction that escapes from this module this way.
  var merkleizer = createMerkleizer(limit)
  for i, elem in lst:
    merkleizer.addChunk(hash_tree_root(elem).data)
    yield mixInLength(merkleizer.getFinalHash(), i + 1)
