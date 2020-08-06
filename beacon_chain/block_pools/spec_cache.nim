# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[algorithm, sequtils, sets],
  chronicles,
  ../spec/[
    beaconstate, crypto, datatypes, digest, helpers, presets, signatures,
    validator],
  ../extras,
  ./block_pools_types

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
    epoch = compute_epoch_at_slot(slot)
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
  bytes_to_uint64(eth2digest(slot_signature.toRaw()).data[0..7]) mod modulo == 0

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
proc is_valid_indexed_attestation*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    epochRef: EpochRef, indexed_attestation: SomeIndexedAttestation,
    flags: UpdateFlags): bool =
  # Check if ``indexed_attestation`` is not empty, has sorted and unique
  # indices and has a valid aggregate signature.

  template is_sorted_and_unique(s: untyped): bool =
    for i in 1 ..< s.len:
      if s[i - 1].uint64 >= s[i].uint64:
        return false

    true

  # Not from spec, but this function gets used in front-line roles, not just
  # behind firewall.
  let num_validators = epochRef.validator_keys.lenu64
  if anyIt(indexed_attestation.attesting_indices, it >= num_validators):
    trace "indexed attestation: not all indices valid validators"
    return false

  # Verify indices are sorted and unique
  let indices = indexed_attestation.attesting_indices.asSeq
  if len(indices) == 0 or not is_sorted_and_unique(indices):
    trace "indexed attestation: indices not sorted and unique"
    return false

  # Verify aggregate signature
  if skipBLSValidation notin flags:
     # TODO: fuse loops with blsFastAggregateVerify
    let pubkeys = mapIt(indices, epochRef.validator_keys[it])
    if not verify_attestation_signature(
        fork, genesis_validators_root, indexed_attestation.data,
        pubkeys, indexed_attestation.signature):
      trace "indexed attestation: signature verification failure"
      return false

  true
