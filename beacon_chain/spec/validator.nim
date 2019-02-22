# Copyright (c) 2018 Status Research & Development GmbH
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

# TODO remove once there are test vectors to check with directly
# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_permuted_index
func get_permuted_index_spec(index: uint64, list_size: uint64, seed: Eth2Digest): uint64 =
  ## Return `p(index)` in a pseudorandom permutation `p` of `0...list_size-1`
  ## with ``seed`` as entropy.
  ##
  ## Utilizes 'swap or not' shuffling found in
  ## https://link.springer.com/content/pdf/10.1007%2F978-3-642-32009-5_1.pdf
  ## See the 'generalized domain' algorithm on page 3.
  result = index
  var pivot_buffer: array[(32+1), byte]
  var source_buffer: array[(32+1+4), byte]

  for round in 0 ..< SHUFFLE_ROUND_COUNT:
    pivot_buffer[0..31] = seed.data
    let round_bytes1 = int_to_bytes1(round)[0]
    pivot_buffer[32] = round_bytes1

    let
      pivot = bytes_to_int(eth2hash(pivot_buffer).data[0..7]) mod list_size
      flip = (pivot - index) mod list_size
      position = max(index, flip)

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

# TODO remove once there are test vectors to check with directly
# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_shuffling
func get_shuffling_spec*(seed: Eth2Digest, validators: openArray[Validator],
                         epoch: Epoch): seq[seq[ValidatorIndex]] =
  ## Shuffles ``validators`` into crosslink committees seeded by ``seed`` and
  ## ``slot``.
  ## Returns a list of ``SLOTS_PER_EPOCH * committees_per_slot`` committees where
  ## each committee is itself a list of validator indices.

  let
    active_validator_indices = get_active_validator_indices(validators, epoch)

    committees_per_epoch = get_epoch_committee_count(
      len(active_validator_indices)).int

    shuffled_active_validator_indices = mapIt(
      active_validator_indices,
      active_validator_indices[get_permuted_index_spec(
        it, len(active_validator_indices).uint64, seed).int])

  # Split the shuffled list into committees_per_epoch pieces
  result = split(shuffled_active_validator_indices, committees_per_epoch)
  assert result.len() == committees_per_epoch # what split should do..

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_permuted_index
func get_permuted_index(index: uint64, list_size: uint64, seed: Eth2Digest,
                        pivots: seq[uint64]): uint64 =
  ## Via https://github.com/protolambda/eth2-shuffle/blob/master/shuffle.go
  ## Return `p(index)` in a pseudorandom permutation `p` of `0...list_size-1`
  ## with ``seed`` as entropy.
  ##
  ## Utilizes 'swap or not' shuffling found in
  ## https://link.springer.com/content/pdf/10.1007%2F978-3-642-32009-5_1.pdf
  ## See the 'generalized domain' algorithm on page 3.
  result = index
  var source_buffer: array[(32+1+4), byte]

  doAssert len(pivots) == SHUFFLE_ROUND_COUNT

  for round in 0 ..< SHUFFLE_ROUND_COUNT:
    let
      pivot = pivots[round]
      flip = (pivot - index) mod list_size
      position = max(index, flip)
      round_bytes1 = int_to_bytes1(round)[0]

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

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_shuffling
func get_shuffling*(seed: Eth2Digest,
                    validators: openArray[Validator],
                    epoch: Epoch
                    ): seq[seq[ValidatorIndex]] =
  ## Via https://github.com/protolambda/eth2-shuffle/blob/master/shuffle.go
  ## Shuffles ``validators`` into crosslink committees seeded by ``seed`` and
  ## ``slot``.
  ## Returns a list of ``SLOTS_PER_EPOCH * committees_per_slot`` committees where
  ## each committee is itself a list of validator indices.

  ## The pivot's a function of seed and round only, so precalculate all
  ## SHUFFLE_ROUND_COUNT pivots, using one buffer.
  let
    active_validator_indices = get_active_validator_indices(validators, epoch)
    list_size = active_validator_indices.len.uint64
  var
    pivot_buffer: array[(32+1), byte]

    # Allow Nim stdlib to preallocate the correct seq size.
    pivots = repeat(0'u64, SHUFFLE_ROUND_COUNT)

  # This doesn't change across rounds.
  pivot_buffer[0..31] = seed.data

  for round in 0 ..< SHUFFLE_ROUND_COUNT:
    let round_bytes1 = int_to_bytes1(round)[0]
    pivot_buffer[32] = round_bytes1
    let pivot = bytes_to_int(eth2hash(pivot_buffer).data[0..7]) mod list_size
    pivots[round] = pivot

  let
    committees_per_epoch = get_epoch_committee_count(
      len(active_validator_indices)).int

    shuffled_active_validator_indices = mapIt(
      active_validator_indices,
      active_validator_indices[get_permuted_index(
        it, len(active_validator_indices).uint64, seed, pivots).int])

  # Split the shuffled list into committees_per_epoch pieces
  result = split(shuffled_active_validator_indices, committees_per_epoch)
  assert result.len() == committees_per_epoch # what split should do..

func get_new_validator_registry_delta_chain_tip*(
    current_validator_registry_delta_chain_tip: Eth2Digest,
    index: ValidatorIndex,
    pubkey: ValidatorPubKey,
    slot: uint64,
    flag: ValidatorSetDeltaFlags): Eth2Digest =
  ## Compute the next hash in the validator registry delta hash chain.

  hash_tree_root_final(ValidatorRegistryDeltaBlock(
    latest_registry_delta_root: current_validator_registry_delta_chain_tip,
    validator_index: index,
    pubkey: pubkey,
    slot: slot,
    flag: flag
  ))

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_previous_epoch_committee_count
func get_previous_epoch_committee_count(state: BeaconState): uint64 =
  # Return the number of committees in the previous epoch of the given ``state``.
  let previous_active_validators = get_active_validator_indices(
    state.validator_registry,
    state.previous_shuffling_epoch,
  )
  get_epoch_committee_count(len(previous_active_validators))

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_next_epoch_committee_count
func get_next_epoch_committee_count(state: BeaconState): uint64 =
  ## Return the number of committees in the next epoch of the given ``state``.
  let next_active_validators = get_active_validator_indices(
    state.validator_registry,
    get_current_epoch(state) + 1,
  )
  get_epoch_committee_count(len(next_active_validators))

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_previous_epoch
func get_previous_epoch(state: BeaconState): Epoch =
  ## Return the previous epoch of the given ``state``.
  ## If the current epoch is  ``GENESIS_EPOCH``, return ``GENESIS_EPOCH``.
  let current_epoch = get_current_epoch(state)
  if current_epoch == GENESIS_EPOCH:
    GENESIS_EPOCH
  else:
    current_epoch - 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_crosslink_committees_at_slot
func get_crosslink_committees_at_slot*(state: BeaconState, slot: Slot,
                                       registry_change: bool = false):
    seq[CrosslinkCommittee] =
  ## Returns the list of ``(committee, shard)`` tuples for the ``slot``.
  ##
  ## Note: There are two possible shufflings for crosslink committees for a
  ## ``slot`` in the next epoch -- with and without a `registry_change`

  let
    epoch = slot_to_epoch(slot)
    current_epoch = get_current_epoch(state)
    previous_epoch = get_previous_epoch(state)
    next_epoch = current_epoch + 1

  assert previous_epoch <= epoch,
    "Previous epoch: " & $humaneEpochNum(previous_epoch) &
    ", epoch: " & $humaneEpochNum(epoch) &
    ", Next epoch: " & $humaneEpochNum(next_epoch)

  assert epoch <= next_epoch,
    "Previous epoch: " & $humaneEpochNum(previous_epoch) &
    ", epoch: " & $humaneEpochNum(epoch) &
    ", Next epoch: " & $humaneEpochNum(next_epoch)
  # TODO - Hack: used to be "epoch < next_epoch" (exlusive interval)
  # until https://github.com/status-im/nim-beacon-chain/issues/97

  template get_epoch_specific_params(): auto =
    if epoch < current_epoch:
      let
        ## TODO this might be pointless copying; RVO exists, but not sure if
        ## Nim optimizes out both copies per. Could directly construct tuple
        ## but this hews closer to spec helper code.
        committees_per_epoch = get_previous_epoch_committee_count(state)
        seed = state.previous_shuffling_seed
        shuffling_epoch = state.previous_shuffling_epoch
        shuffling_start_shard = state.previous_shuffling_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)
    elif epoch == current_epoch:
      let
        committees_per_epoch = get_current_epoch_committee_count(state)
        seed = state.current_shuffling_seed
        shuffling_epoch = state.current_shuffling_epoch
        shuffling_start_shard = state.current_shuffling_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)
    else:
      assert epoch == next_epoch

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
    )
    offset = slot mod SLOTS_PER_EPOCH
    committees_per_slot = committees_per_epoch div SLOTS_PER_EPOCH
    slot_start_shard = (shuffling_start_shard + committees_per_slot * offset) mod SHARD_COUNT

  for i in 0 ..< committees_per_slot.int:
    result.add (
     shuffling[(committees_per_slot * offset + i.uint64).int],
     (slot_start_shard + i.uint64) mod SHARD_COUNT
    )

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#get_beacon_proposer_index
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
  let (first_committee, _) = get_crosslink_committees_at_slot(state, slot)[0]
  let idx = int(slot mod uint64(first_committee.len))
  first_committee[idx]
