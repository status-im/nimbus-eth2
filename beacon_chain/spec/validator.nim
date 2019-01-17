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

func get_active_validator_indices*(validators: openArray[Validator]): seq[Uint24] =
  ## Select the active validators
  for idx, val in validators:
    if is_active_validator(val):
      result.add idx.Uint24

func get_shuffling*(seed: Eth2Digest,
                    validators: openArray[Validator],
                    crosslinking_start_shard: uint64
                    ): array[EPOCH_LENGTH, seq[ShardCommittee]] =
  ## Split up validators into groups at the start of every epoch,
  ## determining at what height they can make attestations and what shard they are making crosslinks for
  ## Implementation should do the following: http://vitalik.ca/files/ShuffleAndAssign.png

  let
    active_validator_indices = get_active_validator_indices(validators)
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
