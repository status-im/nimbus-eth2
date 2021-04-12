# beacon_chain
# Copyright (c) 2019-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/options,
  ../spec/[datatypes, digest, crypto, helpers],
  ../consensus_object_pools/[spec_cache, attestation_pool]

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/validator.md#aggregation-selection
func is_aggregator*(committee_len: uint64, slot_signature: ValidatorSig): bool =
  let
    modulo = max(1'u64, committee_len div TARGET_AGGREGATORS_PER_COMMITTEE)
  bytes_to_uint64(eth2digest(
    slot_signature.toRaw()).data.toOpenArray(0, 7)) mod modulo == 0

func is_aggregator*(epochRef: EpochRef, slot: Slot, index: CommitteeIndex,
    slot_signature: ValidatorSig): bool =
  let
    committee_len = get_beacon_committee_len(epochRef, slot, index)
  return is_aggregator(committee_len, slot_signature)

proc aggregate_attestations*(
    pool: var AttestationPool, epochRef: EpochRef, slot: Slot, index: CommitteeIndex,
    validatorIndex: ValidatorIndex, slot_signature: ValidatorSig): Option[AggregateAndProof] =
  doAssert validatorIndex in get_beacon_committee(epochRef, slot, index)
  doAssert index.uint64 < get_committee_count_per_slot(epochRef)

  # TODO for testing purposes, refactor this into the condition check
  # and just calculation
  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/validator.md#aggregation-selection
  if not is_aggregator(epochRef, slot, index, slot_signature):
    return none(AggregateAndProof)

  let maybe_slot_attestation = getAggregatedAttestation(pool, slot, index)
  if maybe_slot_attestation.isNone:
    return none(AggregateAndProof)

  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/validator.md#construct-aggregate
  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/validator.md#aggregateandproof
  some(AggregateAndProof(
    aggregator_index: validatorIndex.uint64,
    aggregate: maybe_slot_attestation.get,
    selection_proof: slot_signature))
