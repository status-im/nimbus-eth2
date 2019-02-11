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

func xorSeed(seed: Eth2Digest, x: uint64): Eth2Digest =
  ## Integers are all encoded as bigendian
  ## Helper for get_shuffling in lieu of generally better bitwise handling
  ## xor least significant/highest-index 8 bytes in place (after copy)
  result = seed
  for i in 0 ..< 8:
    result.data[31 - i] = result.data[31 - i] xor byte((x shr i*8) and 0xff)

# https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#get_shuffling
func get_shuffling*(seed: Eth2Digest,
                    validators: openArray[Validator],
                    epoch: EpochNumber
                    ): seq[seq[ValidatorIndex]] =
  ## Shuffles ``validators`` into crosslink committees seeded by ``seed`` and ``slot``.
  ## Returns a list of ``EPOCH_LENGTH * committees_per_slot`` committees where each
  ## committee is itself a list of validator indices.
  ## Implementation should do the following: http://vitalik.ca/files/ShuffleAndAssign.png

  let
    active_validator_indices = get_active_validator_indices(validators, epoch)

    committees_per_epoch = get_epoch_committee_count(len(active_validator_indices)).int

    # Shuffle
    shuffled_active_validator_indices = shuffle(
      active_validator_indices,
      xorSeed(seed, epoch))

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

# https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#get_previous_epoch_committee_count
func get_previous_epoch_committee_count(state: BeaconState): uint64 =
  let previous_active_validators = get_active_validator_indices(
    state.validator_registry,
    state.previous_calculation_epoch,
  )
  get_epoch_committee_count(len(previous_active_validators))

# https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#get_next_epoch_committee_count
func get_next_epoch_committee_count(state: BeaconState): uint64 =
  let next_active_validators = get_active_validator_indices(
    state.validator_registry,
    get_current_epoch(state) + 1,
  )
  get_epoch_committee_count(len(next_active_validators))

# https://github.com/ethereum/eth2.0-specs/blob/v0.2.0/specs/core/0_beacon-chain.md#get_previous_epoch
func get_previous_epoch(state: BeaconState): EpochNumber =
  ## Return the previous epoch of the given ``state``.
  ## If the current epoch is  ``GENESIS_EPOCH``, return ``GENESIS_EPOCH``.
  let current_epoch = get_current_epoch(state)
  if current_epoch == GENESIS_EPOCH:
    GENESIS_EPOCH
  else:
    current_epoch - 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#get_crosslink_committees_at_slot
func get_crosslink_committees_at_slot*(state: BeaconState, slot: uint64,
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

  assert previous_epoch <= epoch
  assert epoch <= next_epoch
  # TODO - Hack: used to be "epoch < next_epoch"
  # until https://github.com/status-im/nim-beacon-chain/issues/97

  template get_epoch_specific_params(): auto =
    if epoch < current_epoch:
      let
        committees_per_epoch = get_previous_epoch_committee_count(state)
        seed = state.previous_epoch_seed
        shuffling_epoch = state.previous_calculation_epoch
        shuffling_start_shard = state.previous_epoch_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)
    elif epoch == current_epoch:
      let
        committees_per_epoch = get_current_epoch_committee_count(state)
        seed = state.current_epoch_seed
        shuffling_epoch = state.current_calculation_epoch
        shuffling_start_shard = state.current_epoch_start_shard
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
                 state.current_epoch_seed
        shuffling_start_shard =
          if registry_change:
            (state.current_epoch_start_shard +
             current_committees_per_epoch) mod SHARD_COUNT
          else:
            state.current_epoch_start_shard
      (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard)

  let (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard) =
    get_epoch_specific_params()

  let
    shuffling = get_shuffling(
      seed,
      state.validator_registry,
      shuffling_epoch,
    )
    offset = slot mod EPOCH_LENGTH
    committees_per_slot = committees_per_epoch div EPOCH_LENGTH
    slot_start_shard = (shuffling_start_shard + committees_per_slot * offset) mod SHARD_COUNT

  for i in 0 ..< committees_per_slot.int:
    result.add (
     shuffling[(committees_per_slot * offset + i.uint64).int],
     (slot_start_shard + i.uint64) mod SHARD_COUNT
    )

# https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#get_beacon_proposer_index
func get_beacon_proposer_index*(state: BeaconState, slot: uint64): ValidatorIndex =
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
