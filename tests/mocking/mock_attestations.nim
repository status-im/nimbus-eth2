# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking attestations
# ---------------------------------------------------------------

import
  # Standard library
  sets,
  # 0.19.6 shims
  # Specs
  ../../beacon_chain/spec/[datatypes, beaconstate, helpers, validator, crypto],
  # Internals
  ../../beacon_chain/[ssz, extras, state_transition],
  # Mocking procs
  ./mock_blocks,
  ./mock_validator_keys

proc mockAttestationData(
       state: BeaconState,
       slot: Slot,
       shard: Shard): AttestationData =
  doAssert state.slot >= slot

  if slot == state.slot:
    result.beacon_block_root = mockBlockForNextSlot(state).parent_root
  else:
    result.beacon_block_root = get_block_root_at_slot(state, slot)

  let current_epoch_start_slot = state.get_current_epoch().compute_start_slot_at_epoch()
  let epoch_boundary_root = block:
    if slot < current_epoch_start_slot:
      get_block_root(state, get_previous_epoch(state))
    elif slot == current_epoch_start_slot:
      result.beacon_block_root
    else:
      get_block_root(state, get_current_epoch(state))

  if slot < current_epoch_start_slot:
    result.source = state.previous_justified_checkpoint
  else:
    result.source = state.current_justified_checkpoint

  let target_epoch = compute_epoch_at_slot(slot)
  let parent_crosslink = block:
    if target_epoch == get_current_epoch(state):
      state.current_crosslinks[shard]
    else:
      state.previous_crosslinks[shard]

  result.target = Checkpoint(
    epoch: target_epoch, root: epoch_boundary_root
  )
  result.crosslink = Crosslink(
    shard: shard,
    start_epoch: parent_crosslink.end_epoch,
    end_epoch: min(target_epoch, parent_crosslink.end_epoch + MAX_EPOCHS_PER_CROSSLINK),
    parent_root: hash_tree_root(parent_crosslink)
  )

proc get_attestation_signature(
       state: BeaconState,
       attestation_data: AttestationData,
       privkey: ValidatorPrivKey
      ): ValidatorSig =

  let msg = AttestationDataAndCustodyBit(
    data: attestation_data,
    custody_bit: false
  ).hash_tree_root()

  return bls_sign(
    key = privkey,
    msg = msg.data,
    domain = get_domain(
      state = state,
      domain_type = DOMAIN_BEACON_ATTESTER,
      message_epoch = attestation_data.target.epoch
    )
  )

proc signMockAttestation*(state: BeaconState, attestation: var Attestation) =
  var cache = get_empty_per_epoch_cache()
  let participants = get_attesting_indices(
    state,
    attestation.data,
    attestation.aggregation_bits,
    cache
  )

  var first_iter = true # Can't do while loop on hashset
  for validator_index in participants:
    let sig = get_attestation_signature(
      state, attestation.data, MockPrivKeys[validator_index]
    )
    if first_iter:
      attestation.signature = sig
      first_iter = false
    else:
      combine(attestation.signature, sig)

proc mockAttestationImpl(
       state: BeaconState,
       slot: Slot,
       flags: UpdateFlags): Attestation =

  var cache = get_empty_per_epoch_cache()

  let
    epoch = compute_epoch_at_slot(slot)
    epoch_start_shard = get_start_shard(state, epoch)
    committees_per_slot = get_committee_count(state, epoch) div SLOTS_PER_EPOCH
    shard = (
      epoch_start_shard +
      committees_per_slot * (slot mod SLOTS_PER_EPOCH)
    ) mod SHARD_COUNT

    crosslink_committee = get_crosslink_committee(
      state,
      result.data.target.epoch,
      result.data.crosslink.shard,
      cache
    )
    committee_size = crosslink_committee.len

  result.data = mockAttestationData(state, slot, shard)
  result.aggregation_bits = init(CommitteeValidatorsBits, committee_size)
  result.custody_bits = init(CommitteeValidatorsBits, committee_size)

  # fillAggregateAttestation
  for i in 0 ..< crosslink_committee.len:
    result.aggregation_bits[i] = true

  if skipValidation notin flags:
    signMockAttestation(state, result)

proc mockAttestation*(
       state: BeaconState,
       flags: UpdateFlags = {}): Attestation {.inline.}=
  mockAttestationImpl(state, state.slot, flags)

proc mockAttestation*(
       state: BeaconState,
       slot: Slot,
       flags: UpdateFlags = {}): Attestation {.inline.}=
  mockAttestationImpl(state, slot, flags)

proc fillAggregateAttestation*(state: BeaconState, attestation: var Attestation) =
  var cache = get_empty_per_epoch_cache()
  let crosslink_committee = get_crosslink_committee(
    state,
    attestation.data.target.epoch,
    attestation.data.crosslink.shard,
    cache
  )
  for i in 0 ..< crosslink_committee.len:
    attestation.aggregation_bits[i] = true

proc add*(state: var BeaconState, attestation: Attestation, slot: Slot) =
  var blck = mockBlockForNextSlot(state)
  blck.slot = slot
  blck.body.attestations.add attestation
  process_slots(state, slot)
  signMockBlock(state, blck)

  # TODO: we can skip just VerifyStateRoot
  doAssert state_transition(state, blck, flags = {skipValidation})
