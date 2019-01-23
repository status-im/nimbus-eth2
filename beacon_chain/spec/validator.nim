# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

import
  options, nimcrypto, sequtils, math,
  eth_common,
  ../ssz,
  ./crypto, ./datatypes, ./digest, ./helpers

func min_empty_validator_index*(
    validators: seq[Validator],
    validator_balances: seq[uint64],
    current_slot: uint64): Option[int] =
  for i, v in validators:
    if validator_balances[i] == 0 and
        v.latest_status_change_slot +
          ZERO_BALANCE_VALIDATOR_TTL.uint64 <= current_slot:
      return some(i)

func xorSeed(seed: Eth2Digest, x: uint64): Eth2Digest =
  ## Integers are all encoded as bigendian
  ## Helper for get_shuffling in lieu of generally better bitwise handling
  ## xor least significant/highest-index 8 bytes in place (after copy)
  result = seed
  for i in 0 ..< 8:
    result.data[31 - i] = result.data[31 - i] xor byte((x shr i*8) and 0xff)

func get_shuffling*(seed: Eth2Digest,
                    validators: openArray[Validator],
                    slot_nonaligned: uint64
                    ): seq[seq[Uint24]] =
  ## Shuffles ``validators`` into crosslink committees seeded by ``seed`` and ``slot``.
  ## Returns a list of ``EPOCH_LENGTH * committees_per_slot`` committees where each
  ## committee is itself a list of validator indices.
  ## Implementation should do the following: http://vitalik.ca/files/ShuffleAndAssign.png

  let
    slot = slot_nonaligned - slot_nonaligned mod EPOCH_LENGTH

    active_validator_indices = get_active_validator_indices(validators, slot)

    committees_per_slot = get_committee_count_per_slot(len(active_validator_indices)).int

    # Shuffle
    shuffled_active_validator_indices = shuffle(
      active_validator_indices,
      xorSeed(seed, slot))

  # Split the shuffled list into epoch_length * committees_per_slot pieces
  result = split(shuffled_active_validator_indices, committees_per_slot * EPOCH_LENGTH)
  assert result.len() == committees_per_slot * EPOCH_LENGTH # what split should do..

func get_new_validator_registry_delta_chain_tip*(
    current_validator_registry_delta_chain_tip: Eth2Digest,
    index: Uint24,
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

func get_previous_epoch_committee_count_per_slot(state: BeaconState): uint64 =
  let previous_active_validators = get_active_validator_indices(
    state.validator_registry,
    state.previous_epoch_calculation_slot
  )
  return get_committee_count_per_slot(len(previous_active_validators))

func get_current_epoch_committee_count_per_slot(state: BeaconState): uint64 =
  let previous_active_validators = get_active_validator_indices(
    state.validator_registry,
    state.current_epoch_calculation_slot
  )
  return get_committee_count_per_slot(len(previous_active_validators))

func get_crosslink_committees_at_slot*(state: BeaconState, slot: uint64) : seq[tuple[a: seq[Uint24], b: uint64]] =
  ## Returns the list of ``(committee, shard)`` tuples for the ``slot``.

  let state_epoch_slot = state.slot - (state.slot mod EPOCH_LENGTH)
  assert state_epoch_slot <= slot + EPOCH_LENGTH
  assert slot < state_epoch_slot + EPOCH_LENGTH
  let offset = slot mod EPOCH_LENGTH

  if slot < state_epoch_slot:
    let
      committees_per_slot = get_previous_epoch_committee_count_per_slot(state)
      shuffling = get_shuffling(
        state.previous_epoch_randao_mix,
        state.validator_registry,
        state.previous_epoch_calculation_slot
      )
      slot_start_shard = (state.previous_epoch_start_shard + committees_per_slot * offset) mod SHARD_COUNT

    ## This duplication is ugly, but keeping for sake of closeness with spec code structure
    ## There are better approaches in general.
    for i in 0 ..< committees_per_slot.int:
      result.add (
       shuffling[(committees_per_slot * offset + i.uint64).int],
       (slot_start_shard + i.uint64) mod SHARD_COUNT
      )
  else:
    let
      committees_per_slot = get_current_epoch_committee_count_per_slot(state)
      shuffling = get_shuffling(
        state.current_epoch_randao_mix,
        state.validator_registry,
        state.current_epoch_calculation_slot
      )
      slot_start_shard = (state.current_epoch_start_shard + committees_per_slot * offset) mod SHARD_COUNT

    for i in 0 ..< committees_per_slot.int:
      result.add (
       shuffling[(committees_per_slot * offset + i.uint64).int],
       (slot_start_shard + i.uint64) mod SHARD_COUNT
      )
