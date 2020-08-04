# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[algorithm, sequtils, sets],
  ../spec/[beaconstate, datatypes, presets, validator],
  block_pools_types

# Spec functions implemented based on cached values instead of the full state
func count_active_validators*(epochInfo: EpochRef): uint64 =
  epochInfo.shuffled_active_validator_indices.lenu64

func get_committee_count_per_slot*(epochInfo: EpochRef): uint64 =
  get_committee_count_per_slot(count_active_validators(epochInfo))

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
