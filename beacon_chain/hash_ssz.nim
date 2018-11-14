import
  nimcrypto, eth_common, endians, sequtils, algorithm, ./datatypes,
  milagro_crypto

# Sample hashSSZ implementation based on:
# https://github.com/ethereum/eth2.0-specs/pull/120
# and
# https://github.com/ethereum/beacon_chain/blob/e32464d9c1c82a2b46f2eb83c383654ea1d1ebe6/hash_ssz.py
# Probably wrong - the spec is pretty bare-bones and no test vectors yet

const CHUNK_SIZE = 128

# XXX varargs openarray, anyone?
func hash(a: openArray[byte]): array[32, byte] =
  var h: blake2_512
  h.init()
  h.update(a)
  var tmp = h.finish().data
  copyMem(result.addr, tmp.addr, 32)

func hash(a, b: openArray[byte]): array[32, byte] =
  var h: blake2_512
  h.init()
  h.update(a)
  h.update(b)
  var tmp = h.finish().data
  copyMem(result.addr, tmp.addr, 32)

func nextPowerOf2(v: uint32): uint32 =
  result = v - 1
  result = result or (result shr 1)
  result = result or (result shr 2)
  result = result or (result shr 4)
  result = result or (result shr 8)
  result = result or (result shr 16)
  inc result

func roundUpTo(v, to: int): int =
  ## Round up to an even boundary of `to`
  ((v + to - 1) div to) * to

# Concatenate a list of homogeneous objects into data and pad it
proc listToGlob(lst: seq[seq[byte]]): seq[byte] =
  for x in lst:
    var y = x
    y.setLen(nextPowerOf2(len(x).uint32))
    result.add(y)

  # Pad to chunksize
  result.setLen(result.len().roundUpTo(CHUNK_SIZE))

# XXX: er, how is this _actually_ done?
func empty(T: typedesc): T = discard
const emptyChunk = @(empty(array[CHUNK_SIZE, byte]))

proc merkleHash(lst: seq[seq[byte]]): array[32, byte] =
  ## Merkle tree hash of a list of items
  # XXX: seq-of-seq looks weird...

  # Turn list into padded data
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
    # XXX What now? not in spec, shouldn't happen in the real world.. for now,
    #     just do a dummy
    result = hash(dataLen)
    return

  result = hash(chunkz[0], dataLen)


proc hashSSZ*(x: SomeInteger): seq[byte] =
  var v: array[x.sizeof, byte]
  copyMem(v.addr, x.unsafeAddr, x.sizeof)

  var res: array[x.sizeof, byte]
  when x.sizeof == 8: bigEndian64(res.addr, v.addr)
  elif x.sizeof == 4: bigEndian32(res.addr, v.addr)
  elif x.sizeof == 2: bigEndian16(res.addr, v.addr)
  elif x.sizeof == 1: res = v
  else: {.fatal: "boink: " & $x.sizeof .}
  result = @res

proc hashSSZ*(x: Uint24): seq[byte] =
  # XXX broken!
  @(hashSSZ(x.uint32)[0..2])

proc hashSSZ*(x: EthAddress): seq[byte] = @x
proc hashSSZ*(x: MDigest[32*8]): seq[byte] = @(x.data)
proc hashSSZ*(x: openArray[byte]): seq[byte] = @(hash(x))

proc hashSSZ*(x: ValidatorRecord): seq[byte] =
  # for whatever reason, hash_ssz.py code contains special cases for some types..
  var tmp: seq[byte]
  # tmp.add(x.pubkey) # XXX our code vs spec!
  tmp.add hashSSZ(x.withdrawal_shard)
  tmp.add hashSSZ(x.withdrawal_address)
  tmp.add hashSSZ(x.randao_commitment)
  tmp.add hashSSZ(x.balance.data.lo) # XXX our code vs spec!
  tmp.add hashSSZ(x.start_dynasty)
  tmp.add hashSSZ(x.end_dynasty)
  result = @(hash(tmp))

proc hashSSZ*(x: ShardAndCommittee): seq[byte] =
  var tmp: seq[byte]
  var committee: seq[seq[byte]]
  for v in x.committee: committee.add hashSSZ(v)

  tmp.add hashSSZ(x.shard_id)
  tmp.add merkleHash(committee)
  return @(hash(tmp))

proc hashSSZ*[T](x: T): seq[byte] =
  when T is seq:
    var tmp: seq[seq[byte]]
    for v in x:
      tmp.add hashSSZ(v)
    result = merkleHash(tmp)
  else:
    # XXX: could probaby compile-time-macro-sort fields...
    var fields: seq[tuple[name: string, value: seq[byte]]]
    for name, field in x.fieldPairs:
      fields.add (name, hashSSZ(field))

    var tmp: seq[byte]
    for name, value in fields.sortedByIt(it.name):
      tmp.add hashSSZ(value.value)
    result = @(hash(tmp))
