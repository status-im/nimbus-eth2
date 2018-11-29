# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  math, sequtils,
  ../extras,
  ./datatypes, ./digest, ./helpers, ./validator

func mod_get[T](arr: openarray[T], pos: Natural): T =
  arr[pos mod arr.len]

func on_startup*(initial_validator_entries: openArray[InitialValidator],
                 genesis_time: int,
                 processed_pow_receipt_root: Eth2Digest): BeaconState =
  ## BeaconState constructor
  ##
  ## Before the beacon chain starts, validators will register in the Eth1 chain
  ## and deposit ETH. When enough many validators have registered, a
  ## `ChainStart` log will be emitted and the beacon chain can start beaconing.
  ##
  ## Because the state root hash is part of the genesis block, the beacon state
  ## must be calculated before creating the genesis block.
  #
  # Induct validators
  # Not in spec: the system doesn't work unless there are at least CYCLE_LENGTH
  # validators - there needs to be at least one member in each committee -
  # good to know for testing, though arguably the system is not that useful at
  # at that point :)
  assert initial_validator_entries.len >= CYCLE_LENGTH

  var validators: seq[ValidatorRecord]

  for v in initial_validator_entries:
    validators = get_new_validators(
        validators,
        ForkData(
                pre_fork_version: INITIAL_FORK_VERSION,
                post_fork_version: INITIAL_FORK_VERSION,
                fork_slot_number: 0xffffffffffffffff'u64
            ),
        v.pubkey,
        v.deposit_size,
        v.proof_of_possession,
        v.withdrawal_credentials,
        v.randao_commitment,
        ACTIVE,
        0
      ).validators
  # Setup state
  let
    x = get_new_shuffling(Eth2Digest(), validators, 0)

  # x + x in spec, but more ugly
  var tmp: array[2 * CYCLE_LENGTH, seq[ShardAndCommittee]]
  for i, n in x:
    tmp[i] = n
    tmp[CYCLE_LENGTH + i] = n

  # The spec says to use validators, but it's actually indices..
  let validator_indices = get_active_validator_indices(validators)

  BeaconState(
      validators: validators,
      shard_and_committee_for_slots: tmp,
      persistent_committees: split(
        shuffle(validator_indices, Eth2Digest()), SHARD_COUNT),
      fork_data: ForkData(
        pre_fork_version: INITIAL_FORK_VERSION,
        post_fork_version: INITIAL_FORK_VERSION
      )
  )

func get_shards_and_committees_index*(state: BeaconState, slot: uint64): uint64 =
  # TODO spec unsigned-unsafe here
  let earliest_slot_in_array =
    if state.last_state_recalculation_slot > CYCLE_LENGTH.uint64:
      state.last_state_recalculation_slot - CYCLE_LENGTH
    else:
      0

  doAssert earliest_slot_in_array <= slot and
           slot < earliest_slot_in_array + CYCLE_LENGTH * 2
  slot - earliest_slot_in_array

proc get_shards_and_committees_for_slot*(
    state: BeaconState, slot: uint64): seq[ShardAndCommittee] =
  let index = state.get_shards_and_committees_index(slot)
  state.shard_and_committee_for_slots[index]

func get_beacon_proposer_index*(state: BeaconState, slot: uint64): uint64 =
  ## From Casper RPJ mini-spec:
  ## When slot i begins, validator Vidx is expected
  ## to create ("propose") a block, which contains a pointer to some parent block
  ## that they perceive as the "head of the chain",
  ## and includes all of the **attestations** that they know about
  ## that have not yet been included into that chain.
  ##
  ## idx in Vidx == p(i mod N), pi being a random permutation of validators indices (i.e. a committee)

  let idx = get_shards_and_committees_index(state, slot)
  state.shard_and_committee_for_slots[idx][0].committee.mod_get(slot)

func get_block_hash*(state: BeaconState,
                     current_block: BeaconBlock,
                     slot: int): Eth2Digest =
  let earliest_slot_in_array =
    current_block.slot.int - state.recent_block_hashes.len
  assert earliest_slot_in_array <= slot
  assert slot < current_block.slot.int

  state.recent_block_hashes[slot - earliest_slot_in_array]

func append_to_recent_block_hashes*(old_block_hashes: seq[Eth2Digest],
                                    parent_slot, current_slot: uint64,
                                    parent_hash: Eth2Digest): seq[Eth2Digest] =
  let d = current_slot - parent_slot
  result = old_block_hashes
  result.add repeat(parent_hash, d)

proc get_attestation_participants*(state: BeaconState,
                                   attestation_data: AttestationSignedData,
                                   attester_bitfield: seq[byte]): seq[int] =
  ## Attestation participants in the attestation data are called out in a
  ## bit field that corresponds to the committee of the shard at the time - this
  ## function converts it to list of indices in to BeaconState.validators
  ## Returns empty list if the shard is not found
  # TODO Linear search through shard list? borderline ok, it's a small list
  # TODO bitfield type needed, once bit order settles down
  # TODO iterator candidate
  let
    sncs_for_slot = get_shards_and_committees_for_slot(
      state, attestation_data.slot)

  for snc in sncs_for_slot:
    if snc.shard != attestation_data.shard:
      continue

    # TODO investigate functional library / approach to help avoid loop bugs
    assert len(attester_bitfield) == ceil_div8(len(snc.committee))
    for i, vindex in snc.committee:
      let
        bit = (attester_bitfield[i div 8] shr (7 - (i mod 8))) mod 2
      if bit == 1:
          result.add(vindex)
    return # found the shard, we're done
