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

# TODO remove this once get_shuffling works
func get_shuffling_prev*(seed: Eth2Digest,
                    validators: openArray[Validator],
                    crosslinking_start_shard: uint64, # TODO remove
                    slot_nonaligned: uint64
                    ): array[EPOCH_LENGTH, seq[ShardCommittee]] =
  ## Split up validators into groups at the start of every epoch,
  ## determining at what height they can make attestations and what shard they are making crosslinks for
  ## Implementation should do the following: http://vitalik.ca/files/ShuffleAndAssign.png

  let
    slot = slot_nonaligned - slot_nonaligned mod EPOCH_LENGTH
    active_validator_indices = get_active_validator_indices(validators, slot)
    committees_per_slot = clamp(
      len(active_validator_indices) div EPOCH_LENGTH div TARGET_COMMITTEE_SIZE,
      1, SHARD_COUNT div EPOCH_LENGTH).uint64
    # Shuffle with seed
    shuffled_active_validator_indices = shuffle(active_validator_indices, seed)
    # Split the shuffled list into cycle_length pieces
    validators_per_slot = split(shuffled_active_validator_indices, EPOCH_LENGTH)

  assert validators_per_slot.len() == EPOCH_LENGTH # what split should do..

  for slot, slot_indices in validators_per_slot:
    let
      shard_indices = split(slot_indices, committees_per_slot)
      shard_id_start =
        crosslinking_start_shard + slot.uint64 * committees_per_slot

    var committees = newSeq[ShardCommittee](shard_indices.len)
    for shard_position, indices in shard_indices:
      committees[shard_position].shard =
        shard_id_start + shard_position.uint64 mod SHARD_COUNT.uint64
      committees[shard_position].committee = indices
      committees[shard_position].total_validator_count =
        len(active_validator_indices).uint64

    result[slot] = committees

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
