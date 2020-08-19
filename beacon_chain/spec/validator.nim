# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

{.push raises: [Defect].}

import
  options, sequtils, math, tables,
  ./datatypes, ./digest, ./helpers

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#compute_shuffled_index
# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#compute_committee
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

  static: doAssert SHUFFLE_ROUND_COUNT < uint8.high
  for round in 0'u8 ..< SHUFFLE_ROUND_COUNT.uint8:
    pivot_buffer[32] = round
    source_buffer[32] = round

    # Only one pivot per round.
    let pivot =
      bytes_to_uint64(eth2digest(pivot_buffer).data.toOpenArray(0, 7)) mod
        list_size

    ## Only need to run, per round, position div 256 hashes, so precalculate
    ## them. This consumes memory, but for low-memory devices, it's possible
    ## to mitigate by some light LRU caching and similar.
    for reduced_position in 0 ..< sources.len:
      source_buffer[33..36] = uint_to_bytes4(reduced_position.uint64)
      sources[reduced_position] = eth2digest(source_buffer)

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

  shuffled_active_validator_indices

func get_shuffled_active_validator_indices*(state: BeaconState, epoch: Epoch):
    seq[ValidatorIndex] =
  # Non-spec function, to cache a data structure from which one can cheaply
  # compute both get_active_validator_indexes() and get_beacon_committee().
  let active_validator_indices = get_active_validator_indices(state, epoch)
  mapIt(
    get_shuffled_seq(
      get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
      active_validator_indices.lenu64),
    active_validator_indices[it])

func get_shuffled_active_validator_indices*(
    cache: var StateCache, state: BeaconState, epoch: Epoch):
    var seq[ValidatorIndex] =
  # `cache` comes first because of nim's borrowing rules for the `var` return -
  # the `var` returns avoids copying the validator set.
  cache.shuffled_active_validator_indices.withValue(epoch, validator_indices) do:
    return validator_indices[]
  do:
    let indices = get_shuffled_active_validator_indices(state, epoch)
    return cache.shuffled_active_validator_indices.mgetOrPut(epoch, indices)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_active_validator_indices
func count_active_validators*(state: BeaconState,
                              epoch: Epoch,
                              cache: var StateCache): uint64 =
  cache.get_shuffled_active_validator_indices(state, epoch).lenu64

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_committee_count_per_slot
func get_committee_count_per_slot*(num_active_validators: uint64): uint64 =
  clamp(
    num_active_validators div SLOTS_PER_EPOCH div TARGET_COMMITTEE_SIZE,
    1'u64, MAX_COMMITTEES_PER_SLOT)

func get_committee_count_per_slot*(state: BeaconState,
                                   epoch: Epoch,
                                   cache: var StateCache): uint64 =
  # Return the number of committees at ``slot``.

  # TODO this is mostly used in for loops which have indexes which then need to
  # be converted to CommitteeIndex types for get_beacon_committee(...); replace
  # with better and more type-safe use pattern, probably beginning with using a
  # CommitteeIndex return type here.
  let
    active_validator_count = count_active_validators(state, epoch, cache)
  result = get_committee_count_per_slot(active_validator_count)

  # Otherwise, get_beacon_committee(...) cannot access some committees.
  doAssert (SLOTS_PER_EPOCH * MAX_COMMITTEES_PER_SLOT) >= uint64(result)

func get_committee_count_per_slot*(state: BeaconState,
                                   slot: Slot,
                                   cache: var StateCache): uint64 =
  get_committee_count_per_slot(state, slot.compute_epoch_at_slot, cache)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(current_epoch: Epoch): Epoch =
  # Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  if current_epoch == GENESIS_EPOCH:
    current_epoch
  else:
    current_epoch - 1

func get_previous_epoch*(state: BeaconState): Epoch =
  # Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  get_previous_epoch(get_current_epoch(state))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#compute_committee
func compute_committee*(shuffled_indices: seq[ValidatorIndex],
    index: uint64, count: uint64): seq[ValidatorIndex] =
  ## Return the committee corresponding to ``indices``, ``seed``, ``index``,
  ## and committee ``count``.
  ## In this version, we pass in the shuffled indices meaning we no longer need
  ## the seed.

  let
    active_validators = shuffled_indices.len.uint64
    start = (active_validators * index) div count
    endIdx = (active_validators * (index + 1)) div count

  # These assertions from compute_shuffled_index(...)
  doAssert endIdx <= active_validators
  doAssert active_validators <= 2'u64^40

  # In spec, this calls get_shuffled_index() every time, but that's wasteful
  # Here, get_beacon_committee() gets the shuffled version.
  shuffled_indices[start.int .. (endIdx.int-1)]

func compute_committee_len*(active_validators: uint64,
    index: uint64, count: uint64): uint64 =
  ## Return the committee corresponding to ``indices``, ``seed``, ``index``,
  ## and committee ``count``.

  # indices only used here for its length, or for the shuffled version,
  # so unlike spec, pass the shuffled version in directly.
  let
    start = (active_validators * index) div count
    endIdx = (active_validators * (index + 1)) div count

  # These assertions from compute_shuffled_index(...)
  doAssert endIdx <= active_validators
  doAssert active_validators <= 2'u64^40

  # In spec, this calls get_shuffled_index() every time, but that's wasteful
  # Here, get_beacon_committee() gets the shuffled version.
  endIdx - start

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee*(
    state: BeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): seq[ValidatorIndex] =
  # Return the beacon committee at ``slot`` for ``index``.
  let
    epoch = compute_epoch_at_slot(slot)
    committees_per_slot = get_committee_count_per_slot(state, epoch, cache)
  compute_committee(
    cache.get_shuffled_active_validator_indices(state, epoch),
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee_len*(
    state: BeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): uint64 =
  # Return the number of members in the beacon committee at ``slot`` for ``index``.
  let
    epoch = compute_epoch_at_slot(slot)
    committees_per_slot = get_committee_count_per_slot(state, epoch, cache)

  compute_committee_len(
    count_active_validators(state, epoch, cache),
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#compute_shuffled_index
func compute_shuffled_index(
    index: uint64, index_count: uint64, seed: Eth2Digest): uint64 =
  # Return the shuffled index corresponding to ``seed`` (and ``index_count``).
  doAssert index < index_count

  var
    pivot_buffer: array[(32+1), byte]
    source_buffer: array[(32+1+4), byte]
    cur_idx_permuted = index

  pivot_buffer[0..31] = seed.data
  source_buffer[0..31] = seed.data

  # Swap or not (https://link.springer.com/content/pdf/10.1007%2F978-3-642-32009-5_1.pdf)
  # See the 'generalized domain' algorithm on page 3
  for current_round in 0'u8 ..< SHUFFLE_ROUND_COUNT.uint8:
    pivot_buffer[32] = current_round
    source_buffer[32] = current_round

    let
      # If using multiple indices, can amortize this
      pivot =
        bytes_to_uint64(eth2digest(pivot_buffer).data.toOpenArray(0, 7)) mod
          index_count

      flip = ((index_count + pivot) - cur_idx_permuted) mod index_count
      position = max(cur_idx_permuted.int, flip.int)
    source_buffer[33..36] = uint_to_bytes4((position div 256).uint64)
    let
      source = eth2digest(source_buffer).data
      byte_value = source[(position mod 256) div 8]
      bit = (byte_value shr (position mod 8)) mod 2

    cur_idx_permuted = if bit != 0: flip else: cur_idx_permuted

  cur_idx_permuted

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#compute_proposer_index
func compute_proposer_index(state: BeaconState, indices: seq[ValidatorIndex],
    seed: Eth2Digest): Option[ValidatorIndex] =
  # Return from ``indices`` a random index sampled by effective balance.
  const MAX_RANDOM_BYTE = 255

  if len(indices) == 0:
    return none(ValidatorIndex)

  let seq_len = indices.lenu64

  var
    i = 0'u64
    buffer: array[32+8, byte]
  buffer[0..31] = seed.data
  while true:
    buffer[32..39] = uint_to_bytes8(i div 32)
    let
      candidate_index =
        indices[compute_shuffled_index(i mod seq_len, seq_len, seed)]
      random_byte = (eth2digest(buffer).data)[i mod 32]
      effective_balance = state.validators[candidate_index].effective_balance
    if effective_balance * MAX_RANDOM_BYTE >=
        MAX_EFFECTIVE_BALANCE * random_byte:
      return some(candidate_index)
    i += 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: BeaconState, cache: var StateCache, slot: Slot):
    Option[ValidatorIndex] =
  cache.beacon_proposer_indices.withValue(slot, proposer) do:
    return proposer[]
  do:

    # Return the beacon proposer index at the current slot.
    let epoch = get_current_epoch(state)

    var buffer: array[32 + 8, byte]
    buffer[0..31] = get_seed(state, epoch, DOMAIN_BEACON_PROPOSER).data

    # There's exactly one beacon proposer per slot.

    let
      # active validator indices are kept in cache but sorting them takes
      # quite a while
      indices = get_active_validator_indices(state, epoch)
      start = slot.epoch().compute_start_slot_at_epoch()

    var res: Option[ValidatorIndex]
    for i in 0..<SLOTS_PER_EPOCH:
      buffer[32..39] = uint_to_bytes8((start + i).uint64)
      let seed = eth2digest(buffer)
      let pi = compute_proposer_index(state, indices, seed)
      if start + i == slot:
        res = pi
      cache.beacon_proposer_indices[start + i] = pi

    return res

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: BeaconState, cache: var StateCache):
    Option[ValidatorIndex] =
  get_beacon_proposer_index(state, cache, state.slot)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#validator-assignments
func get_committee_assignment*(
    state: BeaconState, epoch: Epoch,
    validator_index: ValidatorIndex):
    Option[tuple[a: seq[ValidatorIndex], b: CommitteeIndex, c: Slot]] =
  # Return the committee assignment in the ``epoch`` for ``validator_index``.
  # ``assignment`` returned is a tuple of the following form:
  #     * ``assignment[0]`` is the list of validators in the committee
  #     * ``assignment[1]`` is the index to which the committee is assigned
  #     * ``assignment[2]`` is the slot at which the committee is assigned
  # Return None if no assignment.
  let next_epoch = get_current_epoch(state) + 1
  doAssert epoch <= next_epoch

  var cache = StateCache()

  let
    start_slot = compute_start_slot_at_epoch(epoch)
    committee_count_per_slot =
      get_committee_count_per_slot(state, epoch, cache)
  for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:
    for index in 0'u64 ..< committee_count_per_slot:
      let idx = index.CommitteeIndex
      let committee = get_beacon_committee(state, slot, idx, cache)
      if validator_index in committee:
        return some((committee, idx, slot))
  none(tuple[a: seq[ValidatorIndex], b: CommitteeIndex, c: Slot])
