import
  ./bench_common,
  blscurve,
  nimcrypto, endians, sequtils, times, strformat,
  random

func attestation_signed_data(
    fork_version: int,
    slot: int64,
    shard_id: int16,
    parent_hashes: seq[array[32, byte]],
    shard_block_root: array[32, byte],
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

  ctx.update shard_block_root

  var be_justified_slot: array[8, byte]
  bigEndian64(be_justified_slot[0].addr, justified_slot.unsafeAddr)
  ctx.update be_justified_slot

  result.data[0 ..< 32] = ctx.finish().data.toOpenArray(0, 31)
  ctx.clear()

proc randBytes32(): array[32, byte] =
  for b in result.mitems:
    b = byte rand(0..255)

proc main(nb_samples: Natural) =
  warmup()
  randomize(42) # Random seed for reproducibility

  #####################
  # Randomize block and attestation parameters
  # so that compiler does not optimize them away
  let
    fork_version = rand(1 .. 10)
    num_validators = rand(128 .. 1024)
    num_parent_hashes = rand(2 .. 16)
    justified_slot = rand(4096)
    slot = rand(4096 .. 4096 + 256) # 256 slots = 1.1 hour
    shard_id = int16 rand(high(int16))
    parent_hashes = newSeqWith(num_parent_hashes, randBytes32())
    shard_block_root = randBytes32()

  echo '\n'
  echo "######################"
  echo "#"
  echo "# Benchmark parameters"
  echo "#"
  echo "######################"
  echo '\n'
  echo &"Number of validators:          {num_validators:>64}"
  echo &"Number of block parent hashes: {num_parent_hashes:>64}"
  echo &"Fork version:                  {fork_version:>64}"
  echo &"Slot:                          {slot:>64}"
  echo &"Shard_id:                      {shard_id:>64}"
  echo &"Parent_hash[0]:                {parent_hashes[0].toHex:>64}"
  echo &"shard_block_root:              {shard_block_root.toHex:>64}"
  echo &"justified_slot:                {justified_slot:>64}"

  echo '\n'
  echo "######################"
  echo "#"
  echo "# Benchmark prologue"
  echo "#"
  echo "######################"
  echo '\n'

  var start = cpuTime()
  let secret_public_keypairs = newSeqWith(num_validators, KeyPair.random())
  var stop = cpuTime()
  echo "#### Message crypto keys, signatures and proofs of possession"
  echo '\n'
  echo &"{num_validators} secret and public keys pairs generated in {stop - start :>4.3f} s"
  echo &"Throughput: {num_validators.float / (stop - start) :>4.3f} kps/s (key pairs/second)"

  start = cpuTime()
  let proof_of_possessions = secret_public_keypairs.mapIt(it.generatePoP())
  stop = cpuTime()
  echo '\n'
  echo &"{num_validators} proof of possessions in {stop - start :>4.3f} s"
  echo &"Throughput: {num_validators.float / (stop - start) :>4.3f} pops/s (proofs-of-possession/second)"

  start = cpuTime()
  let msg = attestation_signed_data(
                fork_version,
                slot,
                shard_id,
                parent_hashes,
                shard_block_root,
                justified_slot
              )
  stop = cpuTime()
  echo &"Message generated in {(stop - start) * 1_000 :>4.3f} ms"

  echo '\n'
  var pubkeys: seq[VerKey]
  var signatures: seq[Signature]
  let domain = 0'u64
  start = cpuTime()
  for kp in secret_public_keypairs:
    pubkeys.add kp.verkey
    signatures.add kp.sigkey.sign(domain, msg.data) # toOpenArray?
  stop = cpuTime()
  echo &"{num_validators} public key and message signature pairs generated in {stop - start :>4.3f} s"
  echo &"Throughput: {num_validators.float / (stop - start) :>4.3f} kps/s (keysig pairs/second)"
  echo '\n'
  echo "Note: message is re-hashed through Blake2B-384."
  echo "      Eth2.0 spec mentions hashing with Blake2b-512 and slicing the first 256-bit."
  echo "      However message signing is unspecified, and Milagro BLS12-381 requires a 384-bit input."

  echo '\n'
  echo "######################"
  echo "#"
  echo "# Benchmark main body"
  echo "#"
  echo "######################"
  echo '\n'

  echo &"#### Benchmark: {num_validators} proofs-of-possessions verification"
  var pop_valid: bool
  bench &"Benchmarking {num_validators} proofs-of-possessions verification", pop_valid:
    for i in 0 ..< proof_of_possessions.len:
      pop_valid = pop_valid and proof_of_possessions[i].verifyPoP(pubkeys[i])

  # TODO: update with IETF API (Eth2 v0.11.1)
  # func fastAggregateVerify*[T: byte|char](
  #       publicKeys: openarray[PublicKey],
  #       message: openarray[T],
  #       signature: Signature   # Aggregated signature
  #     ): bool

  # var agg_pubkey: VerKey
  # bench &"Benchmarking {num_validators} public keys aggregation", agg_pubkey:
  #   agg_pubkey = combine(pubkeys)

  # var agg_sig: Signature
  # bench &"Benchmarking {num_validators} signatures aggregation", agg_sig:
  #   agg_sig = combine(signatures)

  # var msg_verif: bool
  # bench "Benchmarking message verification", msg_verif:
  #   let domain = 0'u64
  #   msg_verif = agg_sig.verify(msg.data, domain, agg_pubkey)

  #####################
  #
  # Benchmark epilogue
  #
  #####################
  discard

when isMainModule:
  main(100)
