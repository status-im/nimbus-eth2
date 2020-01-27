# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

import
  options, nimcrypto, sequtils, math, tables,
  ./datatypes, ./digest, ./helpers

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#compute_shuffled_index
# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#compute_committee
func get_shuffled_seq*(seed: Eth2Digest,
                      list_size: uint64,
                      ): seq[ValidatorIndex] =
  ## Via https://github.com/protolambda/eth2-shuffle/blob/master/shuffle.go
  ## Shuffles ``validators`` into beacon committees, seeded by ``seed`` and
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
        position = max(cur_idx_permuted.int, flip.int)

      let
        source = sources[position div 256].data
        byte_value = source[(position mod 256) div 8]
        bit = (byte_value shr (position mod 8)) mod 2

      if bit != 0:
        shuffled_active_validator_indices[index] = flip.ValidatorIndex

  result = shuffled_active_validator_indices

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(state: BeaconState): Epoch =
  # Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  let current_epoch = get_current_epoch(state)
  if current_epoch == GENESIS_EPOCH:
    current_epoch
  else:
    current_epoch - 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#compute_committee
func compute_committee(indices: seq[ValidatorIndex], seed: Eth2Digest,
    index: uint64, count: uint64, stateCache: var StateCache): seq[ValidatorIndex] =
  ## Return the committee corresponding to ``indices``, ``seed``, ``index``,
  ## and committee ``count``.

  let
    start = (len(indices).uint64 * index) div count
    endIdx = (len(indices).uint64 * (index + 1)) div count
    key = (indices.len, seed)

  if key notin stateCache.beacon_committee_cache:
    stateCache.beacon_committee_cache[key] =
      get_shuffled_seq(seed, len(indices).uint64)

  # These assertions from compute_shuffled_index(...)
  let index_count = indices.len().uint64
  doAssert endIdx <= index_count
  doAssert index_count <= 2'u64^40

  # In spec, this calls get_shuffled_index() every time, but that's wasteful
  mapIt(
    start.int .. (endIdx.int-1),
    indices[stateCache.beacon_committee_cache[key][it]])

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee*(state: BeaconState, slot: Slot, index: uint64, cache: var StateCache): seq[ValidatorIndex] =
  # Return the beacon committee at ``slot`` for ``index``.
  let
    epoch = compute_epoch_at_slot(slot)

  ## This is a somewhat more fragile, but high-ROI, caching setup --
  ## get_active_validator_indices() is slow to run in a loop and only
  ## changes once per epoch.
  if epoch notin cache.active_validator_indices_cache:
    cache.active_validator_indices_cache[epoch] =
      get_active_validator_indices(state, epoch)

  # Constant throughout an epoch
  if epoch notin cache.committee_count_cache:
    cache.committee_count_cache[epoch] =
      get_committee_count_at_slot(state, slot)

  compute_committee(
    cache.active_validator_indices_cache[epoch],
    get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
    (slot mod SLOTS_PER_EPOCH) * cache.committee_count_cache[epoch] + index,
    cache.committee_count_cache[epoch] * SLOTS_PER_EPOCH,
    cache
  )

# Not from spec
func get_empty_per_epoch_cache*(): StateCache =
  result.beacon_committee_cache =
    initTable[tuple[a: int, b: Eth2Digest], seq[ValidatorIndex]]()
  result.active_validator_indices_cache =
    initTable[Epoch, seq[ValidatorIndex]]()
  result.committee_count_cache = initTable[Epoch, uint64]()

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#compute_proposer_index
func compute_proposer_index(state: BeaconState, indices: seq[ValidatorIndex],
    seed: Eth2Digest, stateCache: var StateCache): Option[ValidatorIndex] =
  # Return from ``indices`` a random index sampled by effective balance.
  const MAX_RANDOM_BYTE = 255

  if len(indices) == 0:
    return none(ValidatorIndex)

  # TODO fixme; should only be run once per slot and cached
  # There's exactly one beacon proposer per slot.
  let
    seq_len = indices.len.uint64
    shuffled_seq = get_shuffled_seq(seed, seq_len)

  doAssert seq_len == shuffled_seq.len.uint64

  var
    i = 0
    buffer: array[32+8, byte]
  buffer[0..31] = seed.data
  while true:
    buffer[32..39] = int_to_bytes8(i.uint64 div 32)
    let
      candidate_index = shuffled_seq[(i.uint64 mod seq_len).int]
      random_byte = (eth2hash(buffer).data)[i mod 32]
      effective_balance =
        state.validators[candidate_index].effective_balance
    if effective_balance * MAX_RANDOM_BYTE >=
        MAX_EFFECTIVE_BALANCE * random_byte:
      return some(candidate_index)
    i += 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: BeaconState, stateCache: var StateCache):
    Option[ValidatorIndex] =
  # Return the beacon proposer index at the current slot.
  let epoch = get_current_epoch(state)

  var buffer: array[32 + 8, byte]
  buffer[0..31] = get_seed(state, epoch, DOMAIN_BEACON_PROPOSER).data
  buffer[32..39] = int_to_bytes8(state.slot.uint64)

  let
    seed = eth2hash(buffer)
    indices = get_active_validator_indices(state, epoch)

  compute_proposer_index(state, indices, seed, stateCache)
