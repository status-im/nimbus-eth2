# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helper functions
import ../datatypes, sequtils, nimcrypto, math

func get_active_validator_indices(validators: seq[ValidatorRecord]): seq[Uint24] =
  ## Select the active validators
  result = @[]
  for idx, val in validators:
    if val.status == ACTIVE:
      result.add idx.Uint24

func shuffle(values: seq[Uint24], seed: Blake2_256_Digest): seq[Uint24] {.noInit.}=
  ## Returns the shuffled ``values`` with seed as entropy.
  ## TODO: this calls out for tests, but I odn't particularly trust spec
  ## right now.

  let values_count = values.len

  # Entropy is consumed from the seed in 3-byte (24 bit) chunks
  const rand_bytes = 3
  let rand_max = 2^(rand_bytes * 8) - 1

  # The range of the RNG places an upper-bound on the size of the list that
  # may be shuffled. It is a logic error to supply an oversized list.
  assert values_count < rand_max

  deepCopy(result, values)
  var source = seed

  var i = 0
  while i < values.len - 1:
    # Re-hash the `source` to obtain a new pattern of bytes
    source = blake2_256.digest source.data
    # Iterate through the `source` bytes in 3-byte chunks
    for pos in countup(0, 29, 3):
      let remaining = values_count - i
      if remaining == 1:
        break

      # Read 3-bytes of `source` as a 24-bit big-endian integer.
      let sample_from_source = source.data[pos].Uint24 shl 16 or source.data[pos+1].Uint24 shl 8 or source.data[pos+2].Uint24

      # Sample values greater than or equal to `sample_max` will cause
      # modulo bias when mapped into the `remaining` range.
      let sample_max = rand_max - rand_max mod remaining

      # Perform a swap if the consumed entropy will not cause modulo bias.
      if sample_from_source < sample_max:
        let replacement_position = sample_from_source mod remaining + i
        swap result[i], result[replacement_position]
        inc i

func split[T](lst: seq[T], N: Positive): seq[seq[T]] =
  # TODO: implement as an iterator
  result = newSeq[seq[T]](N)
  for i in 0 ..< N:
    result[i] = lst[lst.len * i div N ..< lst.len * (i+1) div N] # TODO: avoid alloc via toOpenArray

func get_new_shuffling*(seed: Blake2_256_Digest, validators: seq[ValidatorRecord],
    dynasty: int64, crosslinking_start_shard: int16): seq[seq[ShardAndCommittee]] {.noInit.} =
  ## Split up validators into groups at the start of every epoch,
  ## determining at what height they can make attestations and what shard they are making crosslinks for
  ## Implementation should do the following: http://vitalik.ca/files/ShuffleAndAssign.png

  let avs = get_active_validator_indices(validators)
  var committees_per_slot, slots_per_committee: uint16

  if avs.len >= CYCLE_LENGTH * MIN_COMMITTEE_SIZE:
    committees_per_slot = uint16 avs.len div CYCLE_LENGTH div (MIN_COMMITTEE_SIZE * 2) + 1
    slots_per_committee = 1
  else:
    committees_per_slot = 1
    slots_per_committee = 1
    while avs.len.uint16 * slots_per_committee < CYCLE_LENGTH * MIN_COMMITTEE_SIZE and
        slots_per_committee < CYCLE_LENGTH:
      slots_per_committee *= 2

  result = @[]
  for slot, slot_indices in shuffle(avs, seed).split(CYCLE_LENGTH):
    let shard_indices = slot_indices.split(committees_per_slot)
    let shard_id_start = crosslinking_start_shard.uint16 +
                            slot.uint16 * committees_per_slot div slots_per_committee

    var committees = newSeq[ShardAndCommittee](shard_indices.len)
    for j, indices in shard_indices:
      committees[j].shard_id = (shard_id_start + j.uint16) mod SHARD_COUNT
      committees[j].committee = indices

    result.add committees

func mod_get[T](arr: openarray[T], pos: Natural): T =
  arr[pos mod arr.len]

func get_shard_and_committees_idx*(state: BeaconState, slot: uint64): int =
  # This replaces `get_shards_and_committees_for_slot` from the spec
  # since in Nim, it's not currently efficient to create read-only
  # accessors to expensive-to-copy members (such as sequences).
  let earliest_slot_in_array = state.last_state_recalculation_slot - CYCLE_LENGTH
  doAssert earliest_slot_in_array <= slot and
           slot < earliest_slot_in_array + CYCLE_LENGTH * 2
  return int(slot - earliest_slot_in_array)

func get_beacon_proposer_idx*(state: BeaconState, slot: int): int =
  # This replaces `get_beacon_proposer` from the spec since in Nim,
  # it's not currently efficient to create read-only accessors to
  # expensive-to-copy members (such as ValidatorRecord).
  let idx = get_shard_and_committees_idx(state, slot)
  return state.shard_and_committee_for_slots[idx][0].committee.mod_get(slot)

func get_block_hash*(state: BeaconState, current_block: BeaconBlock, slot: int): Blake2_256_Digest =
  let earliest_slot_in_array = current_block.slot.int - state.recent_block_hashes.len
  assert earliest_slot_in_array <= slot
  assert slot < current_block.slot.int

  return state.recent_block_hashes[slot - earliest_slot_in_array]

func get_new_recent_block_hashes*(
  old_block_hashes: seq[Blake2_256_Digest],
  parent_slot, current_slot: int64,
  parent_hash: Blake2_256_Digest
  ): seq[Blake2_256_Digest] =

  # Should throw for `current_slot - CYCLE_LENGTH * 2 - 1` according to spec comment
  let d = current_slot - parent_slot
  result = old_block_hashes[d .. ^1]
  for _ in 0 ..< min(d, old_block_hashes.len):
    result.add parent_hash

