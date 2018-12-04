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

func on_startup*(initial_validator_entries: openArray[InitialValidator],
                 genesis_time: uint64,
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
  # Not in spec: the system doesn't work unless there are at least EPOCH_LENGTH
  # validators - there needs to be at least one member in each committee -
  # good to know for testing, though arguably the system is not that useful at
  # at that point :)
  assert initial_validator_entries.len >= EPOCH_LENGTH

  var validators: seq[ValidatorRecord]

  for v in initial_validator_entries:
    validators = get_new_validators(
        validators,
        ForkData(
                pre_fork_version: INITIAL_FORK_VERSION,
                post_fork_version: INITIAL_FORK_VERSION,
                fork_slot: INITIAL_SLOT_NUMBER
            ),
        v.pubkey,
        v.deposit_size,
        v.proof_of_possession,
        v.withdrawal_credentials,
        v.randao_commitment,
        ACTIVE,
        INITIAL_SLOT_NUMBER
      ).validators
  # Setup state
  let
    initial_shuffling = get_new_shuffling(Eth2Digest(), validators, 0)

  # initial_shuffling + initial_shuffling in spec, but more ugly
  var shard_and_committee_for_slots: array[2 * EPOCH_LENGTH, seq[ShardAndCommittee]]
  for i, n in initial_shuffling:
    shard_and_committee_for_slots[i] = n
    shard_and_committee_for_slots[EPOCH_LENGTH + i] = n

  # TODO validators vs indices
  let active_validator_indices = get_active_validator_indices(validators)

  let persistent_committees = split(shuffle(
    active_validator_indices, ZERO_HASH), SHARD_COUNT)

  BeaconState(
    validator_registry: validators,
    validator_registry_latest_change_slot: INITIAL_SLOT_NUMBER,
    validator_registry_exit_count: 0,
    validator_registry_delta_chain_tip: ZERO_HASH,

    # Randomness and committees
    randao_mix: ZERO_HASH,
    next_seed: ZERO_HASH,
    shard_and_committee_for_slots: shard_and_committee_for_slots,
    persistent_committees: persistent_committees,

    # Finality
    previous_justified_slot: INITIAL_SLOT_NUMBER,
    justified_slot: INITIAL_SLOT_NUMBER,
    finalized_slot: INITIAL_SLOT_NUMBER,

    # Recent state
    latest_state_recalculation_slot: INITIAL_SLOT_NUMBER,
    latest_block_hashes: repeat(ZERO_HASH, EPOCH_LENGTH * 2),

     # PoW receipt root
    processed_pow_receipt_root: processed_pow_receipt_root,
    # Misc
    genesis_time: genesis_time,
    fork_data: ForkData(
        pre_fork_version: INITIAL_FORK_VERSION,
        post_fork_version: INITIAL_FORK_VERSION,
        fork_slot: INITIAL_SLOT_NUMBER,
    ),
  )

func get_block_hash*(state: BeaconState,
                     current_block: BeaconBlock,
                     slot: uint64): Eth2Digest =
  let earliest_slot_in_array =
    current_block.slot.int - state.latest_block_hashes.len
  assert earliest_slot_in_array <= slot.int
  assert slot < current_block.slot

  state.latest_block_hashes[slot.int - earliest_slot_in_array]

func append_to_recent_block_hashes*(old_block_hashes: seq[Eth2Digest],
                                    parent_slot, current_slot: uint64,
                                    parent_hash: Eth2Digest): seq[Eth2Digest] =
  let d = current_slot - parent_slot
  result = old_block_hashes
  result.add repeat(parent_hash, d)

func get_attestation_participants*(state: BeaconState,
                                   attestation_data: AttestationData,
                                   participation_bitfield: seq[byte]): seq[Uint24] =
  ## Attestation participants in the attestation data are called out in a
  ## bit field that corresponds to the committee of the shard at the time - this
  ## function converts it to list of indices in to BeaconState.validators
  ## Returns empty list if the shard is not found
  # TODO Linear search through shard list? borderline ok, it's a small list
  # TODO bitfield type needed, once bit order settles down
  # TODO iterator candidate
  let
    sncs_for_slot = get_shard_and_committees_for_slot(
      state, attestation_data.slot)

  for snc in sncs_for_slot:
    if snc.shard != attestation_data.shard:
      continue

    # TODO investigate functional library / approach to help avoid loop bugs
    assert len(participation_bitfield) == ceil_div8(len(snc.committee))
    for i, vindex in snc.committee:
      let
        bit = (participation_bitfield[i div 8] shr (7 - (i mod 8))) mod 2
      if bit == 1:
          result.add(vindex)
    return # found the shard, we're done

func change_validators*(state: var BeaconState,
                        current_slot: uint64) =
  ## Change validator registry.

  let res = get_changed_validators(
    state.validator_registry,
    state.latest_penalized_exit_balances,
    state.validator_registry_delta_chain_tip,
    current_slot
  )
  state.validator_registry = res.validators
  state.latest_penalized_exit_balances = res.latest_penalized_exit_balances
