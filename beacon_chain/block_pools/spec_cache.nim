# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[algorithm, sequtils, sets],
  ../spec/[
    beaconstate, crypto, datatypes, digest, helpers, presets, signatures,
    validator],
  ../extras,
  ./block_pools_types, ./chain_dag

# Spec functions implemented based on cached values instead of the full state
func count_active_validators*(epochInfo: EpochRef): uint64 =
  epochInfo.shuffled_active_validator_indices.lenu64

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_committee_count_per_slot
func get_committee_count_per_slot*(epochInfo: EpochRef): uint64 =
  get_committee_count_per_slot(count_active_validators(epochInfo))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee*(
    epochRef: EpochRef, slot: Slot, index: CommitteeIndex): seq[ValidatorIndex] =
  # Return the beacon committee at ``slot`` for ``index``.
  let
    committees_per_slot = get_committee_count_per_slot(epochRef)
  compute_committee(
    epochRef.shuffled_active_validator_indices,
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_attesting_indices
func get_attesting_indices*(epochRef: EpochRef,
                            data: AttestationData,
                            bits: CommitteeValidatorsBits):
                            HashSet[ValidatorIndex] =
  get_attesting_indices(
    bits,
    get_beacon_committee(epochRef, data.slot, data.index.CommitteeIndex))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_indexed_attestation
func get_indexed_attestation*(epochRef: EpochRef, attestation: Attestation): IndexedAttestation =
  # Return the indexed attestation corresponding to ``attestation``.
  let
    attesting_indices =
      get_attesting_indices(
        epochRef, attestation.data, attestation.aggregation_bits)

  IndexedAttestation(
    attesting_indices:
      List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE].init(
        sorted(mapIt(attesting_indices, it.uint64), system.cmp)),
    data: attestation.data,
    signature: attestation.signature
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee_len*(
    epochRef: EpochRef, slot: Slot, index: CommitteeIndex): uint64 =
  # Return the number of members in the beacon committee at ``slot`` for ``index``.
  let
    committees_per_slot = get_committee_count_per_slot(epochRef)

  compute_committee_len(
    count_active_validators(epochRef),
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#aggregation-selection
func is_aggregator*(epochRef: EpochRef, slot: Slot, index: CommitteeIndex,
    slot_signature: ValidatorSig): bool =
  let
    committee_len = get_beacon_committee_len(epochRef, slot, index)
    modulo = max(1'u64, committee_len div TARGET_AGGREGATORS_PER_COMMITTEE)
  bytes_to_uint64(eth2digest(
    slot_signature.toRaw()).data.toOpenArray(0, 7)) mod modulo == 0

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
proc is_valid_indexed_attestation*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    epochRef: EpochRef, indexed_attestation: SomeIndexedAttestation,
    flags: UpdateFlags): Result[void, cstring] =
  # Check if ``indexed_attestation`` is not empty, has sorted and unique
  # indices and has a valid aggregate signature.

  template is_sorted_and_unique(s: untyped): bool =
    var res = true
    for i in 1 ..< s.len:
      if s[i - 1].uint64 >= s[i].uint64:
        res = false
        break
    res

  if len(indexed_attestation.attesting_indices) == 0:
    return err("indexed_attestation: no attesting indices")

  # Not from spec, but this function gets used in front-line roles, not just
  # behind firewall.
  let num_validators = epochRef.validator_keys.lenu64
  if anyIt(indexed_attestation.attesting_indices, it >= num_validators):
    return err("indexed attestation: not all indices valid validators")

  if not is_sorted_and_unique(indexed_attestation.attesting_indices):
    return err("indexed attestation: indices not sorted and unique")

  # Verify aggregate signature
  if skipBLSValidation notin flags:
     # TODO: fuse loops with blsFastAggregateVerify
    let pubkeys = mapIt(
      indexed_attestation.attesting_indices, epochRef.validator_keys[it])
    if not verify_attestation_signature(
        fork, genesis_validators_root, indexed_attestation.data,
        pubkeys, indexed_attestation.signature):
      return err("indexed attestation: signature verification failure")

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
proc is_valid_indexed_attestation*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    epochRef: EpochRef, attesting_indices: HashSet[ValidatorIndex],
    attestation: SomeAttestation, flags: UpdateFlags): Result[void, cstring] =
  # This is a variation on `is_valid_indexed_attestation` that works directly
  # with an attestation instead of first constructing an `IndexedAttestation`
  # and then validating it - for the purpose of validating the signature, the
  # order doesn't matter and we can proceed straight to validating the
  # signature instead
  if attesting_indices.len == 0:
    return err("indexed_attestation: no attesting indices")

  # Verify aggregate signature
  if skipBLSValidation notin flags:
     # TODO: fuse loops with blsFastAggregateVerify
    let pubkeys = mapIt(
      attesting_indices, epochRef.validator_keys[it])
    if not verify_attestation_signature(
        fork, genesis_validators_root, attestation.data,
        pubkeys, attestation.signature):
      return err("indexed attestation: signature verification failure")

  ok()

func makeAttestationData*(
    epochRef: EpochRef, bs: BlockSlot,
    committee_index: uint64): AttestationData =
  ## Create an attestation / vote for the block `bs` using the
  ## data in `epochRef` to fill in the rest of the fields.
  ## `epochRef` is the epoch information corresponding to the `bs` advanced to
  ## the slot we're attesting to.

  let
    slot = bs.slot
    current_epoch = slot.compute_epoch_at_slot()
    epoch_boundary_slot = compute_start_slot_at_epoch(current_epoch)
    epoch_boundary_block = bs.blck.atSlot(epoch_boundary_slot)

  doAssert current_epoch == epochRef.epoch

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#attestation-data
  AttestationData(
    slot: slot,
    index: committee_index,
    beacon_block_root: bs.blck.root,
    source: epochRef.current_justified_checkpoint,
    target: Checkpoint(
      epoch: current_epoch,
      root: epoch_boundary_block.blck.root
    )
  )
