import ./digest
import ./forks
import ./helpers
export helpers

const
  SEED_SIZE = sizeof(Eth2Digest)
  ROUND_SIZE = 1
  POSITION_WINDOW_SIZE = 4
  PIVOT_VIEW_SIZE = SEED_SIZE + ROUND_SIZE
  TOTAL_SIZE = PIVOT_VIEW_SIZE + POSITION_WINDOW_SIZE

func shuffle_list*(input: var seq[ValidatorIndex], seed: Eth2Digest) =
  let list_size = input.lenu64

  if list_size <= 1: return

  var buf {.noinit.}: array[TOTAL_SIZE, byte]

  buf[0..<32] = seed.data

  for r in 0'u8..<SHUFFLE_ROUND_COUNT.uint8:
    buf[SEED_SIZE] = (SHUFFLE_ROUND_COUNT.uint8 - r - 1)

    let
      pivotDigest = eth2digest(buf.toOpenArray(0, PIVOT_VIEW_SIZE - 1))
      pivot = bytes_to_uint64(pivotDigest.data.toOpenArray(0, 7)) mod list_size


    buf[33..<37] = uint_to_bytes(uint32(pivot shr 8))

    var
      mirror = (pivot + 1) shr 1
      source = eth2digest(buf)
      byteV = source.data[(pivot and 0xff) shr 3]
      i = 0'u64
      j = pivot

    template shuffle =
      while i < mirror:
        # The pair is i,j. With j being the bigger of the two, hence the "position" identifier of the pair.
        # Every 256th bit (aligned to j).
        if (j and 0xff) == 0xff:
          # just overwrite the last part of the buffer, reuse the start (seed, round)
          buf[33..<37] = uint_to_bytes(uint32(j shr 8))
          source = eth2digest(buf)

        # Same trick with byte retrieval. Only every 8th.
        if (j and 0x07) == 0x7:
          byteV = source.data[(j and 0xff'u64) shr 3]

        let
          bitV = (byteV shr (j and 0x7)) and 0x1

        if bitV == 1:
          swap(input[i], input[j])

        i.inc
        j.dec

    shuffle

    mirror = (pivot + list_size + 1) shr 1
    let lend = list_size - 1
    buf[33..<37] = uint_to_bytes(uint32(lend shr 8))

    source = eth2digest(buf)
    byteV = source.data[(lend and 0xff) shr 3]
    i = pivot + 1'u64
    j = lend

    shuffle

func get_shuffled_active_validator_indices*(
    state: ForkyBeaconState, epoch: Epoch,
    mix: Eth2Digest): seq[ValidatorIndex] =
  var active_validator_indices = get_active_validator_indices(state, epoch)
  let seed = get_seed(state, epoch, DOMAIN_BEACON_ATTESTER, mix)
  shuffle_list(active_validator_indices, seed)
  active_validator_indices

func get_shuffled_active_validator_indices*(
    state: ForkyBeaconState, epoch: Epoch): seq[ValidatorIndex] =
  var active_validator_indices = get_active_validator_indices(state, epoch)
  let seed = get_seed(state, epoch, DOMAIN_BEACON_ATTESTER)
  shuffle_list(active_validator_indices, seed)
  active_validator_indices

func get_shuffled_active_validator_indices*(
    cache: var StateCache, state: ForkyBeaconState, epoch: Epoch):
    var seq[ValidatorIndex] =
  cache.shuffled_active_validator_indices.withValue(epoch, validator_indices) do:
    return validator_indices[]
  do:
    let indices = get_shuffled_active_validator_indices(state, epoch)
    return cache.shuffled_active_validator_indices.mgetOrPut(epoch, indices)

func get_shuffled_active_validator_indices*(
    cache: var StateCache, state: ForkedHashedBeaconState, epoch: Epoch):
    seq[ValidatorIndex] =
  withState(state):
    cache.get_shuffled_active_validator_indices(forkyState.data, epoch)

template compute_shuffled_index_aux(
    index: uint64, index_count: uint64, seed: Eth2Digest, iter: untyped):
    uint64 =
  doAssert index < index_count

  var
    source_buffer {.noinit.}: array[(32+1+4), byte]
    cur_idx_permuted = index

  source_buffer[0..31] = seed.data

  for current_round in iter:
    source_buffer[32] = current_round

    let
      # If using multiple indices, can amortize this
      pivot =
        bytes_to_uint64(eth2digest(source_buffer.toOpenArray(0, 32)).data.toOpenArray(0, 7)) mod
          index_count

      flip = ((index_count + pivot) - cur_idx_permuted) mod index_count
      position = max(cur_idx_permuted, flip)
    source_buffer[33..36] = uint_to_bytes(uint32(position shr 8))
    let
      source = eth2digest(source_buffer).data
      byte_value = source[(position mod 256) shr 3]
      bit = (byte_value shr (position mod 8)) mod 2

    cur_idx_permuted = if bit != 0: flip else: cur_idx_permuted

  cur_idx_permuted

func compute_shuffled_index*(
    index: uint64, index_count: uint64, seed: Eth2Digest): uint64 =
  compute_shuffled_index_aux(index, index_count, seed) do:
    0'u8 ..< SHUFFLE_ROUND_COUNT.uint8

template compute_proposer_index(state: ForkyBeaconState,
    indices: openArray[ValidatorIndex], seed: Eth2Digest,
    unshuffleTransform: untyped): Opt[ValidatorIndex] =
  const MAX_RANDOM_BYTE = 255

  if len(indices) == 0:
    Opt.none(ValidatorIndex)
  else:
    let seq_len {.inject.} = indices.lenu64

    var
      i = 0'u64
      buffer: array[32+8, byte]
      res: Opt[ValidatorIndex]
    buffer[0..31] = seed.data
    while true:
      buffer[32..39] = uint_to_bytes(i div 32)
      let
        shuffled_index {.inject.} =
          compute_shuffled_index(i mod seq_len, seq_len, seed)
        candidate_index = indices[unshuffleTransform]
        random_byte = (eth2digest(buffer).data)[i mod 32]
        effective_balance = state.validators[candidate_index].effective_balance
      if effective_balance * MAX_RANDOM_BYTE >=
          MAX_EFFECTIVE_BALANCE * random_byte:
        res = Opt.some(candidate_index)
        break
      i += 1

    doAssert res.isSome
    res

func compute_proposer_index(state: ForkyBeaconState,
    indices: openArray[ValidatorIndex], seed: Eth2Digest):
    Opt[ValidatorIndex] =
  compute_proposer_index(state, indices, seed, shuffled_index)

func get_beacon_proposer_index*(
    state: ForkyBeaconState, cache: var StateCache, slot: Slot):
    Opt[ValidatorIndex] =
  let epoch = get_current_epoch(state)

  if slot.epoch() != epoch:
    return Opt.none(ValidatorIndex)

  cache.beacon_proposer_indices.withValue(slot, proposer) do:
    return proposer[]
  do:

    var buffer: array[32 + 8, byte]
    buffer[0..31] = get_seed(state, epoch, DOMAIN_BEACON_PROPOSER).data

    let indices = get_active_validator_indices(state, epoch)
    var res: Opt[ValidatorIndex]

    for epoch_slot in epoch.slots():
      buffer[32..39] = uint_to_bytes(epoch_slot.asUInt64)
      let seed = eth2digest(buffer)
      let pi = compute_proposer_index(state, indices, seed)
      if epoch_slot == slot:
        res = pi
      cache.beacon_proposer_indices[epoch_slot] = pi

    return res

func get_beacon_proposer_index*(state: ForkyBeaconState, cache: var StateCache):
    Opt[ValidatorIndex] =
  get_beacon_proposer_index(state, cache, state.slot)

func get_beacon_proposer_index*(state: ForkedHashedBeaconState,
                                cache: var StateCache, slot: Slot):
                                Opt[ValidatorIndex] =
  withState(state):
    get_beacon_proposer_index(forkyState.data, cache, slot)
