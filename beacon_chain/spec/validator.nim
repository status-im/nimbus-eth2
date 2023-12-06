# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

{.push raises: [].}

import ./helpers
export helpers

const
  SEED_SIZE = sizeof(Eth2Digest)
  ROUND_SIZE = 1
  POSITION_WINDOW_SIZE = 4
  PIVOT_VIEW_SIZE = SEED_SIZE + ROUND_SIZE
  TOTAL_SIZE = PIVOT_VIEW_SIZE + POSITION_WINDOW_SIZE

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_shuffled_index
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_committee
# Port of https://github.com/protolambda/zrnt/blob/v0.14.0/eth2/beacon/shuffle.go
func shuffle_list*(input: var seq[ValidatorIndex], seed: Eth2Digest) =
  let list_size = input.lenu64

  if list_size <= 1: return

  var buf {.noinit.}: array[TOTAL_SIZE, byte]

  # Seed is always the first 32 bytes of the hash input, we never have to change
  # this part of the buffer.
  buf[0..<32] = seed.data

  # The original code includes a direction flag, but only the reverse direction
  # is used in eth2, so we simplify it here
  for r in 0'u8..<SHUFFLE_ROUND_COUNT.uint8:
    # spec: pivot = bytes_to_int(hash(seed + int_to_bytes1(round))[0:8]) % list_size
    # This is the "int_to_bytes1(round)", appended to the seed.
    buf[SEED_SIZE] = (SHUFFLE_ROUND_COUNT.uint8 - r - 1)

    # Seed is already in place, now just hash the correct part of the buffer,
    # and take a uint64 from it, and modulo it to get a pivot within range.
    let
      pivotDigest = eth2digest(buf.toOpenArray(0, PIVOT_VIEW_SIZE - 1))
      pivot = bytes_to_uint64(pivotDigest.data.toOpenArray(0, 7)) mod list_size

    # Split up the for-loop in two:
    #  1. Handle the part from 0 (incl) to pivot (incl). This is mirrored around
    #     (pivot / 2)
    #  2. Handle the part from pivot (excl) to N (excl). This is mirrored around
    #     ((pivot / 2) + (size/2))
    # The pivot defines a split in the array, with each of the splits mirroring
    # their data within the split.
    # Print out some example even/odd sized index lists, with some even/odd pivots,
    # and you can deduce how the mirroring works exactly.
    # Note that the mirror is strict enough to not consider swapping the index
    # @mirror with itself.
    # Since we are iterating through the "positions" in order, we can just
    # repeat the hash every 256th position.
    # No need to pre-compute every possible hash for efficiency like in the
    # example code.
    # We only need it consecutively (we are going through each in reverse order
    # however, but same thing)

    # spec: source = hash(seed + int_to_bytes1(round) + int_to_bytes4(position // 256))
    # - seed is still in 0:32 (excl., 32 bytes)
    # - round number is still in 32
    # - mix in the position for randomness, except the last byte of it,
    #     which will be used later to select a bit from the resulting hash.
    # We start from the pivot position, and work back to the mirror position
    # (of the part left to the pivot).
    # This makes us process each pear exactly once (instead of unnecessarily
    # twice, like in the spec)
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

    # Now repeat, but for the part after the pivot.
    mirror = (pivot + list_size + 1) shr 1
    let lend = list_size - 1
    # Again, seed and round input is in place, just update the position.
    # We start at the end, and work back to the mirror point.
    # This makes us process each pear exactly once (instead of unnecessarily twice, like in the spec)
    buf[33..<37] = uint_to_bytes(uint32(lend shr 8))

    source = eth2digest(buf)
    byteV = source.data[(lend and 0xff) shr 3]
    i = pivot + 1'u64
    j = lend

    shuffle

func get_shuffled_active_validator_indices*(
    state: ForkyBeaconState, epoch: Epoch,
    mix: Eth2Digest): seq[ValidatorIndex] =
  # Non-spec function, to cache a data structure from which one can cheaply
  # compute both get_active_validator_indexes() and get_beacon_committee().
  var active_validator_indices = get_active_validator_indices(state, epoch)
  let seed = get_seed(state, epoch, DOMAIN_BEACON_ATTESTER, mix)
  shuffle_list(active_validator_indices, seed)
  active_validator_indices

func get_shuffled_active_validator_indices*(
    state: ForkyBeaconState, epoch: Epoch): seq[ValidatorIndex] =
  # Non-spec function, to cache a data structure from which one can cheaply
  # compute both get_active_validator_indexes() and get_beacon_committee().
  var active_validator_indices = get_active_validator_indices(state, epoch)
  let seed = get_seed(state, epoch, DOMAIN_BEACON_ATTESTER)
  shuffle_list(active_validator_indices, seed)
  active_validator_indices

func get_shuffled_active_validator_indices*(
    cache: var StateCache, state: ForkyBeaconState, epoch: Epoch):
    var seq[ValidatorIndex] =
  # `cache` comes first because of nim's borrowing rules for the `var` return -
  # the `var` returns avoids copying the validator set.
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_active_validator_indices
func count_active_validators*(state: ForkyBeaconState,
                              epoch: Epoch,
                              cache: var StateCache): uint64 =
  cache.get_shuffled_active_validator_indices(state, epoch).lenu64

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_committee_count_per_slot
func get_committee_count_per_slot*(num_active_validators: uint64): uint64 =
  clamp(
    num_active_validators div SLOTS_PER_EPOCH div TARGET_COMMITTEE_SIZE,
    1'u64, MAX_COMMITTEES_PER_SLOT)

func get_committee_count_per_slot*(state: ForkyBeaconState,
                                   epoch: Epoch,
                                   cache: var StateCache): uint64 =
  ## Return the number of committees at ``slot``.
  let
    active_validator_count = count_active_validators(state, epoch, cache)
  get_committee_count_per_slot(active_validator_count)

func get_committee_count_per_slot*(state: ForkedHashedBeaconState,
                                   epoch: Epoch,
                                   cache: var StateCache): uint64 =
  withState(state):
    get_committee_count_per_slot(forkyState.data, epoch, cache)

iterator get_committee_indices*(committee_count_per_slot: uint64): CommitteeIndex =
  for idx in 0'u64..<min(committee_count_per_slot, MAX_COMMITTEES_PER_SLOT):
    let committee_index = CommitteeIndex.init(idx).expect("value clamped")
    yield committee_index

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_committee
func compute_committee_slice*(
    active_validators, index, count: uint64): Slice[int] =
  doAssert active_validators <= ValidatorIndex.high.uint64

  if index < count:
    let
      start = (active_validators * index) div count
      endIdx = (active_validators * (index + 1)) div count

    start.int..(endIdx.int - 1)
  else:
    0 .. -1

iterator compute_committee*(shuffled_indices: seq[ValidatorIndex],
    index: uint64, count: uint64): (int, ValidatorIndex) =
  let
    slice = compute_committee_slice(shuffled_indices.lenu64, index, count)
  var idx = 0
  for i in slice:
    yield (idx, shuffled_indices[i])
    idx += 1

func compute_committee*(shuffled_indices: seq[ValidatorIndex],
    index: uint64, count: uint64): seq[ValidatorIndex] =
  ## Return the committee corresponding to ``indices``, ``seed``, ``index``,
  ## and committee ``count``.
  ## In this version, we pass in the shuffled indices meaning we no longer need
  ## the seed.
  let
    slice = compute_committee_slice(shuffled_indices.lenu64, index, count)

  # In spec, this calls get_shuffled_index() every time, but that's wasteful
  # Here, get_beacon_committee() gets the shuffled version.
  shuffled_indices[slice]

func compute_committee_len*(
    active_validators, index, count: uint64): uint64 =
  ## Return the committee corresponding to ``indices``, ``seed``, ``index``,
  ## and committee ``count``.

  let
    slice = compute_committee_slice(active_validators, index, count)

  (slice.b - slice.a + 1).uint64

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_beacon_committee
iterator get_beacon_committee*(
    state: ForkyBeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): (int, ValidatorIndex) =
  ## Return the beacon committee at ``slot`` for ``index``.
  let
    epoch = epoch(slot)
    committees_per_slot = get_committee_count_per_slot(state, epoch, cache)
  for index_in_committee, idx in compute_committee(
    cache.get_shuffled_active_validator_indices(state, epoch),
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  ): yield (index_in_committee, idx)

func get_beacon_committee*(
    state: ForkyBeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): seq[ValidatorIndex] =
  ## Return the beacon committee at ``slot`` for ``index``.
  let
    epoch = epoch(slot)
    committees_per_slot = get_committee_count_per_slot(state, epoch, cache)
  compute_committee(
    cache.get_shuffled_active_validator_indices(state, epoch),
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

func get_beacon_committee*(
    state: ForkedHashedBeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): seq[ValidatorIndex] =
  # This one is used by tests/, ncli/, and a couple of places in RPC
  # TODO use the iterator version alone, to remove the risk of using
  # diverging get_beacon_committee() in tests and beacon_chain/ by a
  # wrapper approach (e.g., toSeq). This is a perf tradeoff for test
  # correctness/consistency.
  withState(state):
    get_beacon_committee(forkyState.data, slot, index, cache)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee_len*(
    state: ForkyBeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): uint64 =
  ## Return the number of members in the beacon committee at ``slot``
  ## for ``index``.
  let
    epoch = epoch(slot)
    committees_per_slot = get_committee_count_per_slot(state, epoch, cache)

  compute_committee_len(
    count_active_validators(state, epoch, cache),
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

func get_beacon_committee_len*(
    state: ForkedHashedBeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): uint64 =
  # This one is used by tests
  withState(state):
    get_beacon_committee_len(forkyState.data, slot, index, cache)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_shuffled_index
template compute_shuffled_index_aux(
    index: uint64, index_count: uint64, seed: Eth2Digest, iter: untyped):
    uint64 =
  ## Return the shuffled index corresponding to ``seed`` (and ``index_count``).
  doAssert index < index_count

  var
    source_buffer {.noinit.}: array[(32+1+4), byte]
    cur_idx_permuted = index

  source_buffer[0..31] = seed.data

  # Swap or not (https://link.springer.com/content/pdf/10.1007%2F978-3-642-32009-5_1.pdf)
  # See the 'generalized domain' algorithm on page 3
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
  ## Return the shuffled index corresponding to ``seed`` (and ``index_count``).
  compute_shuffled_index_aux(index, index_count, seed) do:
    0'u8 ..< SHUFFLE_ROUND_COUNT.uint8

func compute_inverted_shuffled_index*(
    index: uint64, index_count: uint64, seed: Eth2Digest): uint64 =
  ## Return the inverse of the shuffled index corresponding to ``seed`` (and
  ## ``index_count``).
  compute_shuffled_index_aux(index, index_count, seed) do:
    countdown(SHUFFLE_ROUND_COUNT.uint8 - 1, 0'u8, 1)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_proposer_index
template compute_proposer_index(state: ForkyBeaconState,
    indices: openArray[ValidatorIndex], seed: Eth2Digest,
    unshuffleTransform: untyped): Opt[ValidatorIndex] =
  ## Return from ``indices`` a random index sampled by effective balance.
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
  ## Return from ``indices`` a random index sampled by effective balance.
  compute_proposer_index(state, indices, seed, shuffled_index)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(
    state: ForkyBeaconState, cache: var StateCache, slot: Slot):
    Opt[ValidatorIndex] =
  let epoch = get_current_epoch(state)

  if slot.epoch() != epoch:
    # compute_proposer_index depends on `effective_balance`, therefore the
    # beacon proposer index can only be computed for the "current" epoch:
    # https://github.com/ethereum/consensus-specs/pull/772#issuecomment-475574357
    return Opt.none(ValidatorIndex)

  cache.beacon_proposer_indices.withValue(slot, proposer) do:
    return proposer[]
  do:
    ## Return the beacon proposer index at the current slot.

    var buffer: array[32 + 8, byte]
    buffer[0..31] = get_seed(state, epoch, DOMAIN_BEACON_PROPOSER).data

    # There's exactly one beacon proposer per slot - the same validator may
    # however propose several times in the same epoch (however unlikely)
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_indices*(
    state: ForkyBeaconState, shuffled_indices: openArray[ValidatorIndex], epoch: Epoch):
    seq[Opt[ValidatorIndex]] =
  ## Return the beacon proposer indices at the current epoch, using shuffled
  ## rather than sorted active validator indices.
  var
    buffer {.noinit.}: array[32 + 8, byte]
    res: seq[Opt[ValidatorIndex]]

  buffer[0..31] = get_seed(state, epoch, DOMAIN_BEACON_PROPOSER).data
  let epoch_shuffle_seed = get_seed(state, epoch, DOMAIN_BEACON_ATTESTER)

  for epoch_slot in epoch.slots():
    buffer[32..39] = uint_to_bytes(epoch_slot.asUInt64)
    res.add (
      compute_proposer_index(state, shuffled_indices, eth2digest(buffer)) do:
        compute_inverted_shuffled_index(
          shuffled_index, seq_len, epoch_shuffle_seed))

  res

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: ForkyBeaconState, cache: var StateCache):
    Opt[ValidatorIndex] =
  ## Return the beacon proposer index at the current slot.
  get_beacon_proposer_index(state, cache, state.slot)

func get_beacon_proposer_index*(state: ForkedHashedBeaconState,
                                cache: var StateCache, slot: Slot):
                                Opt[ValidatorIndex] =
  withState(state):
    get_beacon_proposer_index(forkyState.data, cache, slot)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#aggregation-selection
func is_aggregator*(committee_len: uint64, slot_signature: ValidatorSig): bool =
  let modulo = max(1'u64, committee_len div TARGET_AGGREGATORS_PER_COMMITTEE)
  bytes_to_uint64(eth2digest(
    slot_signature.toRaw()).data.toOpenArray(0, 7)) mod modulo == 0

# https://github.com/ethereum/builder-specs/pull/47
func livenessFailsafeInEffect*(
    block_roots: array[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest],
    slot: Slot): bool =
  const
    MAX_MISSING_CONTIGUOUS = 3
    MAX_MISSING_WINDOW = 5

  static: doAssert MAX_MISSING_WINDOW > MAX_MISSING_CONTIGUOUS
  if slot <= MAX_MISSING_CONTIGUOUS:
    # Cannot ever trigger and allows a bit of safe arithmetic. Furthermore
    # there's notionally always a genesis block, which pushes the earliest
    # possible failure out an additional slot.
    return false

  # Using this slightly convoluted construction to handle wraparound better;
  # baseIndex + faultInspectionWindow can overflow array but only exactly by
  # the required amount. Furthermore, go back one more slot to address using
  # that it looks ahead rather than looks back and whether a block's missing
  # requires seeing the previous block_root.
  let
    faultInspectionWindow = min(distinctBase(slot) - 1, SLOTS_PER_EPOCH)
    baseIndex = (slot + SLOTS_PER_HISTORICAL_ROOT - faultInspectionWindow) mod
      SLOTS_PER_HISTORICAL_ROOT
    endIndex = baseIndex + faultInspectionWindow - 1

  doAssert endIndex mod SLOTS_PER_HISTORICAL_ROOT ==
    (slot - 1) mod SLOTS_PER_HISTORICAL_ROOT

  var
    totalMissing = 0
    streakLen = 0
    maxStreakLen = 0

  for i in baseIndex .. endIndex:
    # This look-forward means checking slot i for being missing uses i - 1
    if  block_roots[(i mod SLOTS_PER_HISTORICAL_ROOT).int] ==
        block_roots[((i + 1) mod SLOTS_PER_HISTORICAL_ROOT).int]:
      totalMissing += 1
      if totalMissing > MAX_MISSING_WINDOW:
        return true

      streakLen += 1
      if streakLen > maxStreakLen:
        maxStreakLen = streakLen
        if maxStreakLen > MAX_MISSING_CONTIGUOUS:
          return true
    else:
      streakLen = 0

  false

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#attestation-subnet-subscription
func compute_subscribed_subnet(node_id: UInt256, epoch: Epoch, index: uint64):
    SubnetId =
  # Ensure neither `truncate` loses information
  static:
    doAssert EPOCHS_PER_SUBNET_SUBSCRIPTION <= high(uint64)
    doAssert sizeof(UInt256) * 8 == NODE_ID_BITS
    doAssert ATTESTATION_SUBNET_PREFIX_BITS < sizeof(SubnetId) * 8

  let
    node_id_prefix = truncate(
      node_id shr (
        NODE_ID_BITS - static(ATTESTATION_SUBNET_PREFIX_BITS.int)), uint64)
    node_offset = truncate(
      node_id mod static(EPOCHS_PER_SUBNET_SUBSCRIPTION.u256), uint64)
    permutation_seed = eth2digest(uint_to_bytes(
      uint64((epoch + node_offset) div EPOCHS_PER_SUBNET_SUBSCRIPTION)))
    permutated_prefix = compute_shuffled_index(
      node_id_prefix,
      1 shl ATTESTATION_SUBNET_PREFIX_BITS,
      permutation_seed,
    )
  SubnetId((permutated_prefix + index) mod ATTESTATION_SUBNET_COUNT)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.4/specs/phase0/p2p-interface.md#attestation-subnet-subscription
iterator compute_subscribed_subnets*(node_id: UInt256, epoch: Epoch): SubnetId =
  for index in 0'u64 ..< SUBNETS_PER_NODE:
    yield compute_subscribed_subnet(node_id, epoch, index)
