import
  ./bench_common,
  milagro_crypto,
  nimcrypto, endians, sequtils, times, strformat,
  random

func attestation_signed_data(
    fork_version: int,
    slot: int64,
    shard_id: int16,
    parent_hashes: seq[array[32, byte]],
    shard_block_hash: array[32, byte],
    justified_slot: int64
  ): MDigest[256]=

  var ctx: blake2_512
  ctx.init()

  var be_slot: array[8, byte]
  bigEndian64(be_slot[0].addr, slot.unsafeAddr)
  ctx.update be_slot

  let size_p_hashes = uint parent_hashes.len * sizeof(array[32, byte])
  ctx.update(cast[ptr byte](parent_hashes[0].unsafeAddr), size_p_hashes)

  var be_shard_id: array[2, byte]
  bigEndian16(be_shard_id.addr, shard_id.unsafeAddr)
  ctx.update be_shard_id

  ctx.update shard_block_hash

  var be_justified_slot: array[8, byte]
  bigEndian64(be_justified_slot[0].addr, justified_slot.unsafeAddr)
  ctx.update be_justified_slot

  result.data[0 ..< 32] = ctx.finish().data.toOpenArray(0, 31)
  ctx.clear()

proc randBytes32(): array[32, byte] =
  for b in result.mitems:
    b = byte rand(0..255)

proc main() =

  warmup()
  randomize(42) # Random seed for reproducibility

  #####################
  # Randomize block and attestation parameters
  # so that compiler does not optimize them away
  let
    num_validators = rand(128 .. 1024)
    num_parent_hashes = rand(2 .. 16)
    justified_slot = rand(4096)
    slot = rand(4096 .. 4096 + 256) # 256 slots = 1.1 hour
    shard_id = rand(high(int16))
    parent_hashes = newSeqWith(num_parent_hashes, randBytes32())
    shard_block_hash = randBytes32()

  echo "\n#### Block parameters"
  echo &"Number of validators:          {num_validators:>64}"
  echo &"Number of block parent hashes: {num_parent_hashes:>64}"
  echo &"Slot:                          {slot:>64}"
  echo &"Shard_id:                      {shard_id:>64}"
  echo &"Parent_hash[0]:                {parent_hashes[0].toHex:>64}"
  echo &"Shard_block_hash:              {shard_block_hash.toHex:>64}"
  echo &"justified_slot:                {justified_slot:>64}"

  #####################
  var start = cpuTime()
  let secret_public_keypairs = newSeqWith(num_validators, newKeyPair())
  var stop = cpuTime()

  echo &"\n{num_validators} key pairs generated in {stop - start :>4.3f} ms"


when isMainModule:
  main()


