# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helpers and functions pertaining to managing the validator set

import
  options,
  eth_common, nimcrypto/blake2,
  ./datatypes, ./private/helpers

func min_empty_validator(validators: seq[ValidatorRecord], current_slot: uint64): Option[int] =
  for i, v in validators:
      if v.status == WITHDRAWN and v.exit_slot + DELETION_PERIOD.uint64 <= current_slot:
          return some(i)

func add_validator*(validators: var seq[ValidatorRecord],
                    pubkey: BLSPublicKey,
                    proof_of_possession: seq[byte],
                    withdrawal_shard: uint16,
                    withdrawal_address: EthAddress,
                    randao_commitment: Blake2_256_Digest,
                    status: ValidatorStatusCodes,
                    current_slot: uint64
                    ): int =
  # Check that validator really did register
  # let signed_message = as_bytes32(pubkey) + as_bytes2(withdrawal_shard) + withdrawal_address + randao_commitment
  # assert BLSVerify(pub=pubkey,
  #                  msg=hash(signed_message),
  #                  sig=proof_of_possession)

  # Pubkey uniqueness
  # assert pubkey not in [v.pubkey for v in validators]
  let
    rec = ValidatorRecord(
      pubkey: pubkey,
      withdrawal_shard: withdrawal_shard,
      withdrawal_address: withdrawal_address,
      randao_commitment: randao_commitment,
      randao_last_change: current_slot,
      balance: DEPOSIT_SIZE * GWEI_PER_ETH,
      status: status,
      exit_slot: 0,
      exit_seq: 0
    )

  let index = min_empty_validator(validators, current_slot)
  if index.isNone:
      validators.add(rec)
      return len(validators) - 1
  else:
      validators[index.get()] = rec
      return index.get()

func get_active_validator_indices(validators: openArray[ValidatorRecord]): seq[Uint24] =
  ## Select the active validators
  result = @[]
  for idx, val in validators:
    if val.status == ACTIVE:
      result.add idx.Uint24

func get_new_shuffling*(seed: Blake2_256_Digest,
                        validators: openArray[ValidatorRecord],
                        crosslinking_start_shard: int
                        ): array[CYCLE_LENGTH, seq[ShardAndCommittee]] =
  ## Split up validators into groups at the start of every epoch,
  ## determining at what height they can make attestations and what shard they are making crosslinks for
  ## Implementation should do the following: http://vitalik.ca/files/ShuffleAndAssign.png

  let
    active_validators = get_active_validator_indices(validators)
    committees_per_slot = clamp(
      len(active_validators) div CYCLE_LENGTH div TARGET_COMMITTEE_SIZE,
      1, SHARD_COUNT div CYCLE_LENGTH)
    # Shuffle with seed
    shuffled_active_validator_indices = shuffle(active_validators, seed)
    # Split the shuffled list into cycle_length pieces
    validators_per_slot = split(shuffled_active_validator_indices, CYCLE_LENGTH)

  assert validators_per_slot.len() == CYCLE_LENGTH # what split should do..

  for slot, slot_indices in validators_per_slot:
    let
      shard_indices = split(slot_indices, committees_per_slot)
      shard_id_start = crosslinking_start_shard + slot * committees_per_slot

    var committees = newSeq[ShardAndCommittee](shard_indices.len)
    for shard_position, indices in shard_indices:
      committees[shard_position].shard_id = (shard_id_start + shard_position).uint16 mod SHARD_COUNT
      committees[shard_position].committee = indices

    result[slot] = committees
