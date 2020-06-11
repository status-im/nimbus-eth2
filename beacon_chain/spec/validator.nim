# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

{.push raises: [Defect].}

import
  algorithm, options, sequtils, math, tables,
  ./datatypes, ./digest, ./helpers

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#compute_shuffled_index
# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#compute_committee
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

func get_shuffled_active_validator_indices*(state: BeaconState, epoch: Epoch):
    seq[ValidatorIndex] =
  # Non-spec function, to cache a data structure from which one can cheaply
  # compute both get_active_validator_indexes() and get_beacon_committee().
  let active_validator_indices = get_active_validator_indices(state, epoch)
  mapIt(
    get_shuffled_seq(
      get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
      active_validator_indices.len.uint64),
    active_validator_indices[it])

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(state: BeaconState): Epoch =
  # Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  let current_epoch = get_current_epoch(state)
  if current_epoch == GENESIS_EPOCH:
    current_epoch
  else:
    current_epoch - 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#compute_committee
func compute_committee(indices: seq[ValidatorIndex], seed: Eth2Digest,
    index: uint64, count: uint64): seq[ValidatorIndex] =
  ## Return the committee corresponding to ``indices``, ``seed``, ``index``,
  ## and committee ``count``.

  # indices only used here for its length, or for the shuffled version,
  # so unlike spec, pass the shuffled version in directly.
  let
    start = (len(indices).uint64 * index) div count
    endIdx = (len(indices).uint64 * (index + 1)) div count

  # These assertions from compute_shuffled_index(...)
  let index_count = indices.len().uint64
  doAssert endIdx <= index_count
  doAssert index_count <= 2'u64^40

  # In spec, this calls get_shuffled_index() every time, but that's wasteful
  # Here, get_beacon_committee() gets the shuffled version.
  try:
    indices[start.int .. (endIdx.int-1)]
  except KeyError:
    raiseAssert("Cached entries are added before use")

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee*(
    state: BeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): seq[ValidatorIndex] =
  # Return the beacon committee at ``slot`` for ``index``.
  let
    epoch = compute_epoch_at_slot(slot)

  # This is a somewhat more fragile, but high-ROI, caching setup --
  # get_active_validator_indices() is slow to run in a loop and only
  # changes once per epoch. It is not, in the general case, possible
  # to precompute these arbitrarily far out so still need to pick up
  # missing cases here.
  if epoch notin cache.shuffled_active_validator_indices:
    cache.shuffled_active_validator_indices[epoch] =
      get_shuffled_active_validator_indices(state, epoch)

  # Constant throughout an epoch
  if epoch notin cache.committee_count_cache:
    cache.committee_count_cache[epoch] =
      get_committee_count_at_slot(state, slot)

  try:
    compute_committee(
      cache.shuffled_active_validator_indices[epoch],
      get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
      (slot mod SLOTS_PER_EPOCH) * cache.committee_count_cache[epoch] +
        index.uint64,
      cache.committee_count_cache[epoch] * SLOTS_PER_EPOCH
    )
  except KeyError:
    raiseAssert "values are added to cache before using them"

# Not from spec
func get_empty_per_epoch_cache*(): StateCache =
  result.shuffled_active_validator_indices =
    initTable[Epoch, seq[ValidatorIndex]]()
  result.committee_count_cache = initTable[Epoch, uint64]()

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#compute_proposer_index
func compute_proposer_index(state: BeaconState, indices: seq[ValidatorIndex],
    seed: Eth2Digest): Option[ValidatorIndex] =
  # Return from ``indices`` a random index sampled by effective balance.
  const MAX_RANDOM_BYTE = 255

  if len(indices) == 0:
    return none(ValidatorIndex)

  let
    seq_len = indices.len.uint64
    shuffled_seq = mapIt(get_shuffled_seq(seed, seq_len), indices[it])

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

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: BeaconState, cache: var StateCache, slot: Slot):
    Option[ValidatorIndex] =
  try:
    if slot in cache.beacon_proposer_indices:
      return cache.beacon_proposer_indices[slot]
  except KeyError:
    raiseAssert("Cached entries are added before use")

  # Return the beacon proposer index at the current slot.
  let epoch = get_current_epoch(state)

  var buffer: array[32 + 8, byte]
  buffer[0..31] = get_seed(state, epoch, DOMAIN_BEACON_PROPOSER).data
  buffer[32..39] = int_to_bytes8(slot.uint64)

  # TODO fixme; should only be run once per slot and cached
  # There's exactly one beacon proposer per slot.
  if epoch notin cache.shuffled_active_validator_indices:
    cache.shuffled_active_validator_indices[epoch] =
      get_shuffled_active_validator_indices(state, epoch)

  try:
    let
      seed = eth2hash(buffer)
      indices =
        sorted(cache.shuffled_active_validator_indices[epoch], system.cmp)

    cache.beacon_proposer_indices[slot] =
      compute_proposer_index(state, indices, seed)
    cache.beacon_proposer_indices[slot]
  except KeyError:
    raiseAssert("Cached entries are added before use")

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: BeaconState, cache: var StateCache):
    Option[ValidatorIndex] =
  get_beacon_proposer_index(state, cache, state.slot)

# Not from spec
# TODO: cache the results from this and reuse in subsequent calls to get_beacon_proposer_index
func get_beacon_proposer_indexes_for_epoch*(state: BeaconState, epoch: Epoch,
    stateCache: var StateCache): seq[tuple[s: Slot, i: ValidatorIndex]] =
  for i in 0 ..< SLOTS_PER_EPOCH:
    let currSlot = (compute_start_slot_at_epoch(epoch).int + i).Slot
    let idx = get_beacon_proposer_index(state, stateCache, currSlot)
    if idx.isSome:
      result.add (currSlot, idx.get)

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/validator.md#validator-assignments
func get_committee_assignment*(
    state: BeaconState, epoch: Epoch, validator_index: ValidatorIndex):
    Option[tuple[a: seq[ValidatorIndex], b: CommitteeIndex, c: Slot]] {.used.} =
  # Return the committee assignment in the ``epoch`` for ``validator_index``.
  # ``assignment`` returned is a tuple of the following form:
  #     * ``assignment[0]`` is the list of validators in the committee
  #     * ``assignment[1]`` is the index to which the committee is assigned
  #     * ``assignment[2]`` is the slot at which the committee is assigned
  # Return None if no assignment.
  let next_epoch = get_current_epoch(state) + 1
  doAssert epoch <= next_epoch

  var cache = get_empty_per_epoch_cache()

  let start_slot = compute_start_slot_at_epoch(epoch)
  for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:
    for index in 0 ..< get_committee_count_at_slot(state, slot):
      let idx = index.CommitteeIndex
      let committee =
        get_beacon_committee(state, slot, idx, cache)
      if validator_index in committee:
        return some((committee, idx, slot))
  none(tuple[a: seq[ValidatorIndex], b: CommitteeIndex, c: Slot])

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/validator.md#validator-assignments
func is_proposer(
    state: BeaconState, validator_index: ValidatorIndex): bool {.used.} =
  var cache = get_empty_per_epoch_cache()
  let proposer_index = get_beacon_proposer_index(state, cache)
  proposer_index.isSome and proposer_index.get == validator_index

