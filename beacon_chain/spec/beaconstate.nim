# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ./datatypes, ./digest, ./helpers, ./validator

func get_shards_and_committees_for_slot*(state: BeaconState,
                                         slot: uint64
                                         ): seq[ShardAndCommittee] =
  let earliest_slot_in_array = state.last_state_recalculation_slot - CYCLE_LENGTH
  assert earliest_slot_in_array <= slot
  assert slot < earliest_slot_in_array + CYCLE_LENGTH * 2

  return state.shard_and_committee_for_slots[int slot - earliest_slot_in_array]
  # TODO, slot is a uint64; will be an issue on int32 arch.
  #       Clarify with EF if light clients will need the beacon chain

func get_block_hash*(state: BeaconState, current_block: BeaconBlock, slot: int): Eth2Digest =
  let earliest_slot_in_array = current_block.slot.int - state.recent_block_hashes.len
  assert earliest_slot_in_array <= slot
  assert slot < current_block.slot.int

  return state.recent_block_hashes[slot - earliest_slot_in_array]

func get_beacon_proposer*(state: BeaconState, slot: uint64): ValidatorRecord =
  ## From Casper RPJ mini-spec:
  ## When slot i begins, validator Vidx is expected
  ## to create ("propose") a block, which contains a pointer to some parent block
  ## that they perceive as the "head of the chain",
  ## and includes all of the **attestations** that they know about
  ## that have not yet been included into that chain.
  ##
  ## idx in Vidx == p(i mod N), pi being a random permutation of validators indices (i.e. a committee)
  let
    first_committee = get_shards_and_committees_for_slot(state, slot)[0].committee
    index = first_committee[(slot mod len(first_committee).uint64).int]
  state.validators[index]
