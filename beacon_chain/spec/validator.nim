# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

{.push raises: [Defect].}

import
  algorithm, options, sequtils, math, tables, sets,
  ./datatypes, ./digest, ./helpers, ./network

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#compute_shuffled_index
# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#compute_committee
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

  for round in 0 ..< SHUFFLE_ROUND_COUNT.int:
    let round_bytes1 = int_to_bytes1(round)[0]
    pivot_buffer[32] = round_bytes1
    source_buffer[32] = round_bytes1

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
    state: BeaconState, epoch: Epoch, cache: var StateCache):
    seq[ValidatorIndex] =
  try:
    cache.shuffled_active_validator_indices[epoch]
  except KeyError:
    let validator_indices = get_shuffled_active_validator_indices(state, epoch)
    cache.shuffled_active_validator_indices[epoch] = validator_indices
    validator_indices

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(current_epoch: Epoch): Epoch =
  # Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  if current_epoch == GENESIS_EPOCH:
    current_epoch
  else:
    current_epoch - 1

func get_previous_epoch*(state: BeaconState): Epoch =
  # Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  get_previous_epoch(get_current_epoch(state))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#compute_committee
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#get_beacon_committee
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

  try:
    let committees_per_slot = get_committee_count_per_slot(
      cache.shuffled_active_validator_indices[epoch].lenu64)
    compute_committee(
      cache.shuffled_active_validator_indices[epoch],
      get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
      (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
        index.uint64,
      committees_per_slot * SLOTS_PER_EPOCH
    )
  except KeyError:
    raiseAssert "values are added to cache before using them"

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#compute_shuffled_index
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
  for current_round in 0 ..< SHUFFLE_ROUND_COUNT.int:
    let round_bytes1 = int_to_bytes1(current_round)[0]
    pivot_buffer[32] = round_bytes1
    source_buffer[32] = round_bytes1

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

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#compute_proposer_index
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#get_beacon_proposer_index
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
  buffer[32..39] = uint_to_bytes8(slot.uint64)

  # TODO fixme; should only be run once per slot and cached
  # There's exactly one beacon proposer per slot.
  if epoch notin cache.shuffled_active_validator_indices:
    cache.shuffled_active_validator_indices[epoch] =
      get_shuffled_active_validator_indices(state, epoch)

  try:
    let
      seed = eth2digest(buffer)
      indices =
        sorted(cache.shuffled_active_validator_indices[epoch], system.cmp)

    cache.beacon_proposer_indices[slot] =
      compute_proposer_index(state, indices, seed)
    cache.beacon_proposer_indices[slot]
  except KeyError:
    raiseAssert("Cached entries are added before use")

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: BeaconState, cache: var StateCache):
    Option[ValidatorIndex] =
  get_beacon_proposer_index(state, cache, state.slot)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#validator-assignments
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

func get_committee_assignments*(
    state: BeaconState, epoch: Epoch,
    validator_indices: HashSet[ValidatorIndex]):
    seq[tuple[subnetIndex: uint64, slot: Slot]] =
  let next_epoch = get_current_epoch(state) + 1
  doAssert epoch <= next_epoch

  var cache = StateCache()
  let start_slot = compute_start_slot_at_epoch(epoch)

  let committees_per_slot =
    get_committee_count_per_slot(state, epoch, cache)

  for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:
    for index in 0'u64 ..< committees_per_slot:
      let idx = index.CommitteeIndex
      if not disjoint(validator_indices,
          get_beacon_committee(state, slot, idx, cache).toHashSet):
        result.add(
          (compute_subnet_for_attestation(committees_per_slot, slot, idx),
            slot))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#validator-assignments
func is_proposer(
    state: BeaconState, validator_index: ValidatorIndex): bool {.used.} =
  var cache = StateCache()
  let proposer_index = get_beacon_proposer_index(state, cache)
  proposer_index.isSome and proposer_index.get == validator_index

