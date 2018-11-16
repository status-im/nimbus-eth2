import
  nimcrypto, eth_common, endians, sequtils, algorithm, ./datatypes,
  milagro_crypto

# Sample hashSSZ implementation based on:
# https://github.com/ethereum/eth2.0-specs/pull/120
# and
# https://github.com/ethereum/beacon_chain/blob/e32464d9c1c82a2b46f2eb83c383654ea1d1ebe6/hash_ssz.py
# Probably wrong - the spec is pretty bare-bones and no test vectors yet

const CHUNK_SIZE = 128

template withHash(body: untyped): untyped =
  ## Spec defines hash as BLAKE2b-512(x)[0:32]
  ## This little helper will init the hash function and return the sliced
  ## hash:
  ## let hashOfData = withHash: h.update(data)
  var h  {.inject.}: blake2_512
  h.init()
  body
  var res: array[32, byte]
  var tmp = h.finish().data
  copyMem(res.addr, tmp.addr, 32)
  res

# XXX varargs openarray, anyone?
func hash(a: openArray[byte]): array[32, byte] =
  withHash:
    h.update(a)

func hash(a, b: openArray[byte]): array[32, byte] =
  withHash:
    h.update(a)
    h.update(b)

func nextPowerOf2(v: uint32): uint32 =
  result = v - 1
  result = result or (result shr 1)
  result = result or (result shr 2)
  result = result or (result shr 4)
  result = result or (result shr 8)
  result = result or (result shr 16)
  inc result

func roundUpTo(v, to: int): int =
  ## Round up `v` to an even boundary of `to`
  ((v + to - 1) div to) * to

func listToGlob[T](lst: seq[T]): seq[byte]

# XXX: er, how is this _actually_ done?
func empty(T: typedesc): T = discard
const emptyChunk = @(empty(array[CHUNK_SIZE, byte]))

func merkleHash[T](lst: seq[T]): array[32, byte] =
  ## Merkle tree hash of a list of items flattening list with some padding,
  ## then dividing the list into CHUNK_SIZE sized chunks

  # Turn list into padded data
  # XXX: the heap allocations here can be avoided by computing the merkle tree
  #      recursively, but for now keep things simple and aligned with upstream
  var data = listToGlob(lst)

  # Store length of list (to compensate for non-bijectiveness of padding)
  var dataLen: array[32, byte]
  var lstLen = uint64(len(lst))
  bigEndian64(dataLen[32-8].addr, lstLen.addr)

  # Divide into chunks
  var chunkz: seq[seq[byte]]
  for i in countup(0, data.len - 1, CHUNK_SIZE):
    chunkz.add data[i..<i + CHUNK_SIZE]

  while chunkz.len() > 1:
    if chunkz.len() mod 2 == 1:
      chunkz.add emptyChunk
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

func hashSSZ*(x: SomeInteger): array[sizeof(x), byte] =
  ## Integers area all encoded as bigendian and not padded
  var v: array[x.sizeof, byte]
  copyMem(v.addr, x.unsafeAddr, x.sizeof)

  when x.sizeof == 8: bigEndian64(result.addr, v.addr)
  elif x.sizeof == 4: bigEndian32(result.addr, v.addr)
  elif x.sizeof == 2: bigEndian16(result.addr, v.addr)
  elif x.sizeof == 1: result = v
  else: {.fatal: "boink: " & $x.sizeof .}

func hashSSZ*(x: Uint24): array[3, byte] =
  var tmp = hashSSZ(x.uint32) # XXX broken endian!
  copyMem(result.addr, tmp.addr, 3)

func hashSSZ*(x: EthAddress): array[sizeof(x), byte] = x
func hashSSZ*(x: MDigest[32*8]): array[32, byte] = x.data
func hashSSZ*(x: openArray[byte]): array[32, byte] = hash(x)

func hashSSZ*(x: ValidatorRecord): array[32, byte] =
  # XXX hash_ssz.py code contains special cases for some types, why?
  withHash:
    # tmp.add(x.pubkey) # XXX our code vs spec!
    h.update hashSSZ(x.withdrawal_shard)
    h.update hashSSZ(x.withdrawal_address)
    h.update hashSSZ(x.randao_commitment)
    h.update hashSSZ(x.balance.data.lo) # XXX our code vs spec!
    h.update hashSSZ(x.start_dynasty)
    h.update hashSSZ(x.end_dynasty)

func hashSSZ*(x: ShardAndCommittee): array[32, byte] =
  return withHash:
    h.update hashSSZ(x.shard_id)
    h.update merkleHash(x.committee)

func hashSSZ*[T](x: T): array[32, byte] =
  when T is seq:
    return merkleHash(x)
  else:
    # XXX could probaby compile-time-macro-sort fields...
    var fields: seq[tuple[name: string, value: seq[byte]]]
    for name, field in x.fieldPairs:
      fields.add (name, hashSSZ(field))

    return withHash:
      for name, value in fields.sortedByIt(it.name):
        h.update hashSSZ(value.value)

func listToGlob[T](lst: seq[T]): seq[byte] =
  ## Concatenate a list of homogeneous objects into data and pad it
  for x in lst:
    let
      y = hashSSZ(x)
      paddedLen = nextPowerOf2(len(y).uint32).int
    result.add(y)
    if paddedLen != len(y):
      result.setLen(result.len.roundUpTo(paddedLen))

  # Pad to chunksize
  result.setLen(result.len().roundUpTo(CHUNK_SIZE))
