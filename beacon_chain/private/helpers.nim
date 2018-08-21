# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helper functions
import ../datatypes, sequtils, nimcrypto, math

func get_active_validator_indices(validators: seq[ValidatorRecord], dynasty: int64): seq[Uint24] =
  ## Select the active validators
  result = @[]
  for idx, val in validators:
    if  val.start_dynasty <= dynasty and
        dynasty < val.end_dynasty:
      result.add idx.Uint24

func shuffle(validators: seq[Uint24], seed: Blake2_256_Digest): seq[Uint24] {.noInit.}=
  ## Pseudorandomly shuffles the validator set based on some seed

  const UpperBound = 2^24 # 16777216
  assert validators.len <= UpperBound

  deepCopy(result, validators)
  var source = seed

  var i = 0
  while i < validators.len:
    source = blake2_256.digest source.data
    for pos in countup(0, 29, 3):
      let remaining = validators.len - i
      if remaining == 0:
        break

      let m = source.data[pos].Uint24 shl 16 or source.data[pos+1].Uint24 shl 8 or source.data[pos+2].Uint24
      let rand_max = Uint24 UpperBound - UpperBound mod remaining

      if m < randMax:
        let replacementPos = m mod remaining + i
        swap result[i], result[replacementPos]
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

  let avs = get_active_validator_indices(validators, dynasty)
  var committees_per_slot, slots_per_committee: int16

  if avs.len >= CYCLE_LENGTH * MIN_COMMITTEE_SIZE:
    committees_per_slot = int16 avs.len div CYCLE_LENGTH div (MIN_COMMITTEE_SIZE * 2) + 1
    slots_per_committee = 1
  else:
    committees_per_slot = 1
    slots_per_committee = 1
    while avs.len * slots_per_committee < CYCLE_LENGTH * MIN_COMMITTEE_SIZE and
        slots_per_committee < CYCLE_LENGTH:
      slots_per_committee *= 2

  result = @[]
  for slot, height_indices in shuffle(avs, seed).split(CYCLE_LENGTH):
    let shard_indices = height_indices.split(committees_per_slot)

    var committees = newSeq[ShardAndCommittee](shard_indices.len)
    for j, indices in shard_indices:
      committees[j].shard_id = crosslinking_start_shard +
                                slot.int16 * committees_per_slot div slots_per_committee + j.int16
      committees[j].committee = indices

    result.add committees

func get_indices_for_slot*(crystallized_state: CrystallizedState,
        slot: int64): seq[ShardAndCommittee] {.noInit.}=
  # TODO: Spec why is active_state an argument?

  let ifh_start = crystallized_state.last_state_recalc - CYCLE_LENGTH
  assert ifh_start <= slot
  assert slot < ifh_start + CYCLE_LENGTH * 2

  result = crystallized_state.indices_for_slots[int slot - ifh_start]
  # TODO, slot is an int64 will be an issue on int32 arch.
  #       Clarify with EF if light clients will need the beacon chain

func get_block_hash*(active_state: ActiveState,
        beacon_block: BeaconBlock, slot: int64): Blake2_256_Digest =

  let sback = beacon_block.slot_number - CYCLE_LENGTH * 2
  assert sback <= slot
  assert slot < sback + CYCLE_LENGTH * 2

  result = active_state.recent_block_hashes[int slot - sback]

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

