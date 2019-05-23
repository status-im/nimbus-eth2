# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

import
  options, nimcrypto, sequtils, math, chronicles,
  eth/common,
  ../ssz, ../beacon_node_types,
  ./crypto, ./datatypes, ./digest, ./helpers

# TODO: Proceed to renaming and signature changes
# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#get_shuffled_index
# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#compute_committee
func get_shuffled_seq*(seed: Eth2Digest,
                       list_size: uint64,
                       ): seq[ValidatorIndex] =
  ## Via https://github.com/protolambda/eth2-shuffle/blob/master/shuffle.go
  ## Shuffles ``validators`` into crosslink committees seeded by ``seed`` and
  ## ``slot``.
  ## Returns a list of ``SLOTS_PER_EPOCH * committees_per_slot`` committees
  ## where each committee is itself a list of validator indices.
  ##
  ## Invert the inner/outer loops from the spec, essentially. Most useful
  ## hash result re-use occurs within a round.

  # Empty size -> empty list.
  if list_size == 0:
    return

  var
    # Share these buffers.
    # TODO: Redo to follow spec.
    #       We can have an "Impl" private version that takes buffer as parameters
    #       so that we avoid alloc on repeated calls from compute_committee
    pivot_buffer: array[(32+1), byte]
    source_buffer: array[(32+1+4), byte]
    shuffled_active_validator_indices = mapIt(
      0 ..< list_size.int, it.ValidatorIndex)
    sources = repeat(Eth2Digest(), (list_size div 256) + 1)

  ## The pivot's a function of seed and round only.
  ## This doesn't change across rounds.
  pivot_buffer[0..31] = seed.data
  source_buffer[0..31] = seed.data

  for round in 0 ..< SHUFFLE_ROUND_COUNT:
    let round_bytes1 = int_to_bytes1(round)[0]
    pivot_buffer[32] = round_bytes1
    source_buffer[32] = round_bytes1

    # Only one pivot per round.
    let pivot = bytes_to_int(eth2hash(pivot_buffer).data.toOpenArray(0, 7)) mod list_size

    ## Only need to run, per round, position div 256 hashes, so precalculate
    ## them. This consumes memory, but for low-memory devices, it's possible
    ## to mitigate by some light LRU caching and similar.
    for reduced_position in 0 ..< sources.len:
      source_buffer[33..36] = int_to_bytes4(reduced_position.uint64)
      sources[reduced_position] = eth2hash(source_buffer)

    ## Iterate over all the indices. This was in get_permuted_index, but large
    ## efficiency gains exist in caching and re-using data.
    for index in 0 ..< list_size.int:
      let
        cur_idx_permuted = shuffled_active_validator_indices[index]
        flip = ((list_size + pivot) - cur_idx_permuted.uint64) mod list_size
        position = max(cur_idx_permuted, flip.int)

      let
        source = sources[position div 256].data
        byte_value = source[(position mod 256) div 8]
        bit = (byte_value shr (position mod 8)) mod 2

      if bit != 0:
        shuffled_active_validator_indices[index] = flip.ValidatorIndex

  result = shuffled_active_validator_indices

func get_shuffled_index(index: ValidatorIndex, index_count: uint64, seed: Eth2Digest): uint64 =
  ## Return the shuffled validator index corresponding to ``seed`` (and
  ## ``index_count``).
  ## https://github.com/status-im/nim-beacon-chain/blob/f77016af6818ad2c853f6c9e2751b17548e0222e/beacon_chain/spec/validator.nim#L15

  doAssert index.uint64 < index_count
  doAssert index_count <= 2'u64^40

  result = index
  var pivot_buffer: array[(32+1), byte]
  var source_buffer: array[(32+1+4), byte]

  # Swap or not (https://link.springer.com/content/pdf/10.1007%2F978-3-642-32009-5_1.pdf)
  # See the 'generalized domain' algorithm on page 3
  for round in 0 ..< SHUFFLE_ROUND_COUNT:
    pivot_buffer[0..31] = seed.data
    let round_bytes1 = int_to_bytes1(round)[0]
    pivot_buffer[32] = round_bytes1

    let
      pivot = bytes_to_int(eth2hash(pivot_buffer).data[0..7]) mod index_count
      flip = (pivot - index) mod index_count
      position = max(index.uint64, flip)

    ## Tradeoff between slicing (if reusing one larger buffer) and additional
    ## copies here of seed and `int_to_bytes1(round)`.
    source_buffer[0..31] = seed.data
    source_buffer[32] = round_bytes1
    source_buffer[33..36] = int_to_bytes4(position div 256)

    let
      source = eth2hash(source_buffer).data
      byte_value = source[(position mod 256) div 8]
      bit = (byte_value shr (position mod 8)) mod 2

    if bit != 0:
      result = flip

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#get_shuffling
func get_shuffling*(seed: Eth2Digest,
                    validators: openArray[Validator],
                    epoch: Epoch,
                    ): seq[seq[ValidatorIndex]] =
  ## This function is factored to facilitate testing with
  ## https://github.com/ethereum/eth2.0-test-generators/tree/master/permutated_index
  ## test vectors, which the split of get_shuffling obfuscates.

  let
    active_validator_indices = get_active_validator_indices(validators, epoch)
    list_size = active_validator_indices.len.uint64
    committees_per_epoch = get_epoch_committee_count(
      validators, epoch).int
    shuffled_seq = get_shuffled_seq(seed, list_size)

  # Split the shuffled list into committees_per_epoch pieces
  result = split(shuffled_seq, committees_per_epoch)
  doAssert result.len() == committees_per_epoch # what split should do..

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#get_previous_epoch
func get_previous_epoch*(state: BeaconState): Epoch =
  ## Return the previous epoch of the given ``state``.
  # Note: This is allowed to underflow internally (this is why GENESIS_EPOCH != 0)
  #       however when interfacing with peers for example for attestations
  #       this should not underflow.
  # TODO or not - it causes issues: https://github.com/ethereum/eth2.0-specs/issues/849

  let epoch = get_current_epoch(state)
  max(GENESIS_EPOCH, epoch - 1) # TODO max here to work around the above issue


# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#get_crosslink_committees_at_slot
func get_crosslink_committees_at_slot*(state: BeaconState, slot: Slot|uint64,
                                       registry_change: bool = false):
    seq[CrosslinkCommittee] =
  ## Returns the list of ``(committee, shard)`` tuples for the ``slot``.
  ##
  ## Note: There are two possible shufflings for crosslink committees for a
  ## ``slot`` in the next epoch -- with and without a `registry_change`

  let
    epoch = slot_to_epoch(slot) # TODO, enforce slot to be a Slot
    current_epoch = get_current_epoch(state)
    previous_epoch = get_previous_epoch(state)
    next_epoch = current_epoch + 1

  doAssert previous_epoch <= epoch,
    "Previous epoch: " & $humaneEpochNum(previous_epoch) &
    ", epoch: " & $humaneEpochNum(epoch) &
    " (slot: " & $humaneSlotNum(slot.Slot) & ")" &
    ", Next epoch: " & $humaneEpochNum(next_epoch)

  doAssert epoch <= next_epoch,
    "Previous epoch: " & $humaneEpochNum(previous_epoch) &
    ", epoch: " & $humaneEpochNum(epoch) &
    " (slot: " & $humaneSlotNum(slot.Slot) & ")" &
    ", Next epoch: " & $humaneEpochNum(next_epoch)

  template get_epoch_specific_params(): auto =
    if epoch == current_epoch:
      let
        committees_per_epoch = get_epoch_committee_count(state, current_epoch)
        seed = state.current_shuffling_seed
        shuffling_epoch = state.current_shuffling_epoch
        shuffling_start_shard = state.current_shuffling_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)
    elif epoch == previous_epoch:
      let
        committees_per_epoch = get_epoch_committee_count(state, previous_epoch)
        seed = state.previous_shuffling_seed
        shuffling_epoch = state.previous_shuffling_epoch
        shuffling_start_shard = state.previous_shuffling_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)
    else:
      doAssert epoch == next_epoch

      let
        shuffling_epoch = next_epoch

        epochs_since_last_registry_update =
          current_epoch - state.validator_registry_update_epoch
        condition = epochs_since_last_registry_update > 1'u64 and
                    is_power_of_2(epochs_since_last_registry_update)
        use_next = registry_change or condition
        committees_per_epoch =
          if use_next:
            get_epoch_committee_count(state, next_epoch)
          else:
            get_epoch_committee_count(state, current_epoch)
        seed =
          if use_next:
            generate_seed(state, next_epoch)
          else:
            state.current_shuffling_seed
        shuffling_epoch =
          if use_next: next_epoch else: state.current_shuffling_epoch
        shuffling_start_shard =
          if registry_change:
            (state.current_shuffling_start_shard +
             get_epoch_committee_count(state, current_epoch)) mod SHARD_COUNT
          else:
            state.current_shuffling_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)

  let (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard) =
    get_epoch_specific_params()

  let
    shuffling = get_shuffling(seed, state.validator_registry, shuffling_epoch)
    offset = slot mod SLOTS_PER_EPOCH
    committees_per_slot = committees_per_epoch div SLOTS_PER_EPOCH
    slot_start_shard = (shuffling_start_shard + committees_per_slot * offset) mod SHARD_COUNT

  for i in 0 ..< committees_per_slot.int:
    result.add (
     shuffling[(committees_per_slot * offset + i.uint64).int],
     (slot_start_shard + i.uint64) mod SHARD_COUNT
    )

iterator get_crosslink_committees_at_slot_cached*(
  state: BeaconState, slot: Slot|uint64,
  registry_change: bool = false, cache: var StateCache):
    CrosslinkCommittee =
  let key = (slot.uint64, registry_change)
  if key in cache.crosslink_committee_cache:
    for v in cache.crosslink_committee_cache[key]: yield v
  #debugEcho "get_crosslink_committees_at_slot_cached: MISS"
  let result = get_crosslink_committees_at_slot(state, slot, registry_change)
  cache.crosslink_committee_cache[key] = result
  for v in result: yield v

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#get_shard_delta
func get_shard_delta(state: BeaconState, epoch: Epoch): uint64 =
  ## Return the number of shards to increment ``state.latest_start_shard``
  ## during ``epoch``.
  min(get_epoch_committee_count(state, epoch),
    (SHARD_COUNT - SHARD_COUNT div SLOTS_PER_EPOCH).uint64)

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#get_epoch_start_shard
func get_epoch_start_shard(state: BeaconState, epoch: Epoch): Shard =
  doAssert epoch <= get_current_epoch(state) + 1
  var
    check_epoch = get_current_epoch(state) + 1
    shard =
      (state.latest_start_shard +
       get_shard_delta(state, get_current_epoch(state))) mod SHARD_COUNT
  while check_epoch > epoch:
    check_epoch -= 1
    shard = (shard + SHARD_COUNT - get_shard_delta(state, check_epoch)) mod
      SHARD_COUNT
  return shard

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#compute_committee
func compute_committee(indices: seq[ValidatorIndex], seed: Eth2Digest,
    index: uint64, count: uint64): seq[ValidatorIndex] =
  let
    start = (len(indices).uint64 * index) div count
    endIdx = (len(indices).uint64 * (index + 1)) div count
  debugEcho "from ", start.int, " to ", (endIdx.int-1), " with count ", count, " and index ", index
  doAssert endIdx.int - start.int > 0
  mapIt(
    start.int .. (endIdx.int-1),
    indices[
      get_shuffled_index(it.ValidatorIndex, len(indices).uint64, seed).int])

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#get_crosslink_committee
func get_crosslink_committee(state: BeaconState, epoch: Epoch, shard: Shard):
    seq[ValidatorIndex] =
  compute_committee(
    get_active_validator_indices(state, epoch),
    generate_seed(state, epoch),
    (shard + SHARD_COUNT - get_epoch_start_shard(state, epoch)) mod SHARD_COUNT,
    get_epoch_committee_count(state, epoch),
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: BeaconState): ValidatorIndex =
  # Return the current beacon proposer index.
  const
    MAX_RANDOM_BYTE = 255

  let
    epoch = get_current_epoch(state)
    committees_per_slot =
      get_epoch_committee_count(state, epoch) div SLOTS_PER_EPOCH
    offset = committees_per_slot * (state.slot mod SLOTS_PER_EPOCH)
    shard = (get_epoch_start_shard(state, epoch) + offset) mod SHARD_COUNT
    first_committee = get_crosslink_committee(state, epoch, shard)
    seed = generate_seed(state, epoch)

  var
    i = 0
    buffer: array[(32+8), byte]
  buffer[0..31] = seed.data
  while true:
    buffer[32..39] = int_to_bytes8(i.uint64 div 32)
    let
      candidate_index = first_committee[((epoch + i.uint64) mod
        len(first_committee).uint64).int]
      random_byte = (eth2hash(buffer).data)[i mod 32]
      effective_balance =
        state.validator_registry[candidate_index].effective_balance
    if effective_balance * MAX_RANDOM_BYTE >= MAX_EFFECTIVE_BALANCE * random_byte:
      return candidate_index
    i += 1
