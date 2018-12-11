# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  math, sequtils,
  ../extras, ../ssz,
  ./crypto, ./datatypes, ./digest, ./helpers, ./validator

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
  var shard_committees_at_slots: array[2 * EPOCH_LENGTH, seq[ShardCommittee]]
  for i, n in initial_shuffling:
    shard_committees_at_slots[i] = n
    shard_committees_at_slots[EPOCH_LENGTH + i] = n

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
    shard_committees_at_slots: shard_committees_at_slots,
    persistent_committees: persistent_committees,

    # Finality
    previous_justified_slot: INITIAL_SLOT_NUMBER,
    justified_slot: INITIAL_SLOT_NUMBER,
    finalized_slot: INITIAL_SLOT_NUMBER,

    # Recent state
    latest_state_recalculation_slot: INITIAL_SLOT_NUMBER,
    latest_block_roots: repeat(ZERO_HASH, EPOCH_LENGTH * 2),

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

func get_block_root*(state: BeaconState,
                     slot: uint64): Eth2Digest =
  let earliest_slot_in_array =
    state.slot - len(state.latest_block_roots).uint64
  assert earliest_slot_in_array <= slot
  assert slot < state.slot
  state.latest_block_roots[(slot - earliest_slot_in_array).int]

func append_to_recent_block_roots*(old_block_roots: seq[Eth2Digest],
                                    parent_slot, current_slot: uint64,
                                    parent_hash: Eth2Digest): seq[Eth2Digest] =
  let d = current_slot - parent_slot
  result = old_block_roots
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

func process_ejections*(state: var BeaconState) =
  ## Iterate through the validator registry
  ## and eject active validators with balance below ``EJECTION_BALANCE``.

  for i, v in state.validator_registry.mpairs():
    if is_active_validator(v) and v.balance < EJECTION_BALANCE:
      exit_validator(i.Uint24, state, EXITED_WITHOUT_PENALTY)

func update_validator_registry*(state: var BeaconState) =
  # Update validator registry.
  # Note that this function mutates ``state``.

  (state.validator_registry,
    state.latest_penalized_exit_balances,
    state.validator_registry_delta_chain_tip) =
      get_updated_validator_registry(
        state.validator_registry,
        state.latest_penalized_exit_balances,
        state.validator_registry_delta_chain_tip,
        state.slot
      )

func checkAttestation*(state: BeaconState, attestation: Attestation): bool =
  ## Check that an attestation follows the rules of being included in the state
  ## at the current slot.
  ##
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#attestations-1

  if attestation.data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot:
    return

  if attestation.data.slot + EPOCH_LENGTH >= state.slot:
    return

  let expected_justified_slot =
    if attestation.data.slot >= state.slot - (state.slot mod EPOCH_LENGTH):
      state.justified_slot
    else:
      state.previous_justified_slot

  if attestation.data.justified_slot != expected_justified_slot:
    return

  let expected_justified_block_root =
    get_block_root(state, attestation.data.justified_slot)
  if attestation.data.justified_block_root != expected_justified_block_root:
    return

  if state.latest_crosslinks[attestation.data.shard].shard_block_root notin [
      attestation.data.latest_crosslink_root,
      attestation.data.shard_block_root]:
    return

  let
    participants = get_attestation_participants(
      state, attestation.data, attestation.participation_bitfield)
    group_public_key = BLSAddPubkeys(mapIt(
      participants, state.validator_registry[it].pubkey))

  # Verify that aggregate_signature verifies using the group pubkey.
  let msg = hash_tree_root(attestation.data)

  if not BLSVerify(
        group_public_key, @msg & @[0'u8], attestation.aggregate_signature,
        get_domain(state.fork_data, attestation.data.slot, DOMAIN_ATTESTATION)
      ):
    return

  # To be removed in Phase1:
  if attestation.data.shard_block_root != ZERO_HASH:
    return

  true
