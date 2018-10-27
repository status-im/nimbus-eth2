import
  ./bench_common,
  ../src/scheme1,
  nimcrypto, endians

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
