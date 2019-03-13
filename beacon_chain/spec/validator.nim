# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

import
  options, nimcrypto, sequtils, math,
  eth/common,
  ../ssz,
  ./crypto, ./datatypes, ./digest, ./helpers

# https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/core/0_beacon-chain.md#get_shuffling
# https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/core/0_beacon-chain.md#get_permuted_index
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
  var
    # Share these buffers.
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
    let pivot = bytes_to_int(eth2hash(pivot_buffer).data[0..7]) mod list_size

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

# https://github.com/ethereum/eth2.0-specs/blob/v0.4.0/specs/core/0_beacon-chain.md#get_shuffling
func get_shuffling*(seed: Eth2Digest,
                    validators: openArray[Validator],
                    epoch: Epoch,
                    shuffling_cache: ShufflingCache
                    ): seq[seq[ValidatorIndex]] =
  ## This function is factored to facilitate testing with
  ## https://github.com/ethereum/eth2.0-test-generators/tree/master/permutated_index
  ## test vectors, which the split of get_shuffling obfuscates.
  ## TODO fix bad list size but keep consistent with cached values,
  ## once epoch processing reordering comes around
  let list_size = validators.len.uint64

  let
    active_validator_indices = get_active_validator_indices(validators, epoch)
    committees_per_epoch = get_epoch_committee_count(
      len(active_validator_indices)).int
    # Both mapIt-type-conversions are an SSZ artifact. TODO remove.
    shuffled_seq =
      if shuffling_cache.seeds[0] == seed and
         shuffling_cache.list_sizes[0] == list_size:
        mapIt(shuffling_cache.shuffling_0, it.ValidatorIndex)
      elif shuffling_cache.seeds[1] == seed and
           shuffling_cache.list_sizes[1] == list_size:
        mapIt(shuffling_cache.shuffling_1, it.ValidatorIndex)
      else:
        get_shuffled_seq(seed, list_size)

  # Split the shuffled list into committees_per_epoch pieces
  result = split(shuffled_seq, committees_per_epoch)
  doAssert result.len() == committees_per_epoch # what split should do..

# https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/core/0_beacon-chain.md#get_previous_epoch_committee_count
func get_previous_epoch_committee_count(state: BeaconState): uint64 =
  ## Return the number of committees in the previous epoch of the given
  ## ``state``.
  let previous_active_validators = get_active_validator_indices(
    state.validator_registry,
    state.previous_shuffling_epoch,
  )
  get_epoch_committee_count(len(previous_active_validators))

# https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/core/0_beacon-chain.md#get_next_epoch_committee_count
func get_next_epoch_committee_count(state: BeaconState): uint64 =
  ## Return the number of committees in the next epoch of the given ``state``.
  let next_active_validators = get_active_validator_indices(
    state.validator_registry,
    get_current_epoch(state) + 1,
  )
  get_epoch_committee_count(len(next_active_validators))

# https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/core/0_beacon-chain.md#get_previous_epoch
func get_previous_epoch*(state: BeaconState): Epoch =
  ## Return the previous epoch of the given ``state``.
  max(get_current_epoch(state) - 1, GENESIS_EPOCH)

# https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/core/0_beacon-chain.md#get_crosslink_committees_at_slot
func get_crosslink_committees_at_slot*(state: BeaconState, slot: Slot|uint64,
                                       registry_change: bool = false):
    seq[CrosslinkCommittee] =
  ## Returns the list of ``(committee, shard)`` tuples for the ``slot``.
  ##
  ## Note: There are two possible shufflings for crosslink committees for a
  ## ``slot`` in the next epoch -- with and without a `registry_change`

  let
    # TODO: the + 1 here works around a bug, remove when upgrading to
    #       some more recent version:
    # https://github.com/ethereum/eth2.0-specs/pull/732
    # It's not 100% clear to me regarding 0.4.0; waiting until 0.5.0 to remove
    # TODO recheck
    epoch = slot_to_epoch(slot + 1)
    current_epoch = get_current_epoch(state)
    previous_epoch = get_previous_epoch(state)
    next_epoch = current_epoch + 1

  doAssert previous_epoch <= epoch,
    "Previous epoch: " & $humaneEpochNum(previous_epoch) &
    ", epoch: " & $humaneEpochNum(epoch) &
    ", Next epoch: " & $humaneEpochNum(next_epoch)

  doAssert epoch <= next_epoch,
    "Previous epoch: " & $humaneEpochNum(previous_epoch) &
    ", epoch: " & $humaneEpochNum(epoch) &
    ", Next epoch: " & $humaneEpochNum(next_epoch)

  template get_epoch_specific_params(): auto =
    if epoch == current_epoch:
      let
        committees_per_epoch = get_current_epoch_committee_count(state)
        seed = state.current_shuffling_seed
        shuffling_epoch = state.current_shuffling_epoch
        shuffling_start_shard = state.current_shuffling_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)
    elif epoch == previous_epoch:
      let
        committees_per_epoch = get_previous_epoch_committee_count(state)
        seed = state.previous_shuffling_seed
        shuffling_epoch = state.previous_shuffling_epoch
        shuffling_start_shard = state.previous_shuffling_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)
    else:
      doAssert epoch == next_epoch

      let
        current_committees_per_epoch = get_current_epoch_committee_count(state)
        committees_per_epoch = get_next_epoch_committee_count(state)
        shuffling_epoch = next_epoch

        epochs_since_last_registry_update = current_epoch - state.validator_registry_update_epoch
        condition = epochs_since_last_registry_update > 1'u64 and
                    is_power_of_2(epochs_since_last_registry_update)
        seed = if registry_change or condition:
                 generate_seed(state, next_epoch)
               else:
                 state.current_shuffling_seed
        shuffling_start_shard =
          if registry_change:
            (state.current_shuffling_start_shard +
             current_committees_per_epoch) mod SHARD_COUNT
          else:
            state.current_shuffling_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)

  let (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard) =
    get_epoch_specific_params()

  let
    shuffling = get_shuffling(
      seed,
      state.validator_registry,
      shuffling_epoch,

      # Not in spec
      state.shuffling_cache
    )
    offset = slot mod SLOTS_PER_EPOCH
    committees_per_slot = committees_per_epoch div SLOTS_PER_EPOCH
    slot_start_shard = (shuffling_start_shard + committees_per_slot * offset) mod SHARD_COUNT

  for i in 0 ..< committees_per_slot.int:
    result.add (
     shuffling[(committees_per_slot * offset + i.uint64).int],
     (slot_start_shard + i.uint64) mod SHARD_COUNT
    )

# https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/core/0_beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: BeaconState, slot: Slot): ValidatorIndex =
  ## From Casper RPJ mini-spec:
  ## When slot i begins, validator Vidx is expected
  ## to create ("propose") a block, which contains a pointer to some parent block
  ## that they perceive as the "head of the chain",
  ## and includes all of the **attestations** that they know about
  ## that have not yet been included into that chain.
  ##
  ## idx in Vidx == p(i mod N), pi being a random permutation of validators indices (i.e. a committee)
  ## Returns the beacon proposer index for the ``slot``.
  # TODO this index is invalid outside of the block state transition function
  #      because presently, `state.slot += 1` happens before this function
  #      is called - see also testutil.getNextBeaconProposerIndex
  # TODO is the above still true? the shuffling has changed since it was written
  let (first_committee, _) = get_crosslink_committees_at_slot(state, slot)[0]
  let idx = int(slot mod uint64(first_committee.len))
  first_committee[idx]
