# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ./datatypes, ./digest, ./helpers, ./validator

func mod_get[T](arr: openarray[T], pos: Natural): T =
  arr[pos mod arr.len]

func get_shard_and_committees_idx*(state: BeaconState, slot: int): int =
  # This replaces `get_shards_and_committees_for_slot` from the spec
  # since in Nim, it's not currently efficient to create read-only
  # accessors to expensive-to-copy members (such as sequences).
  let earliest_slot_in_array = state.last_state_recalculation_slot.int - CYCLE_LENGTH
  doAssert earliest_slot_in_array <= slot and
           slot < earliest_slot_in_array + CYCLE_LENGTH * 2
  return int(slot - earliest_slot_in_array)

proc get_shards_and_committees_for_slot*(state: BeaconState, slot: int): seq[ShardAndCommittee] =
  return state.shard_and_committee_for_slots[state.get_shard_and_committees_idx(slot)]

func get_beacon_proposer_idx*(state: BeaconState, slot: int): int =
  ## From Casper RPJ mini-spec:
  ## When slot i begins, validator Vidx is expected
  ## to create ("propose") a block, which contains a pointer to some parent block
  ## that they perceive as the "head of the chain",
  ## and includes all of the **attestations** that they know about
  ## that have not yet been included into that chain.
  ##
  ## idx in Vidx == p(i mod N), pi being a random permutation of validators indices (i.e. a committee)

  # This replaces `get_beacon_proposer` from the spec since in Nim,
  # it's not currently efficient to create read-only accessors to
  # expensive-to-copy members (such as ValidatorRecord).

  let idx = get_shard_and_committees_idx(state, slot)
  return state.shard_and_committee_for_slots[idx][0].committee.mod_get(slot)

func get_block_hash*(state: BeaconState,
                     current_block: BeaconBlock,
                     slot: int): Eth2Digest =
  let earliest_slot_in_array = current_block.slot.int - state.recent_block_hashes.len
  assert earliest_slot_in_array <= slot
  assert slot < current_block.slot.int

  return state.recent_block_hashes[slot - earliest_slot_in_array]

