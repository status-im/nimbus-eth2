# beacon_chain
# Copyright (c) 2019-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  options,
  ./spec/[beaconstate, datatypes, crypto, digest, helpers, validator,
    state_transition_block],
  ./attestation_pool, ./beacon_node_types

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#aggregation-selection
func is_aggregator(state: BeaconState, slot: Slot, index: CommitteeIndex,
    slot_signature: ValidatorSig): bool =
  var cache = get_empty_per_epoch_cache()

  let
    committee = get_beacon_committee(state, slot, index, cache)
    modulo = max(1, len(committee) div TARGET_AGGREGATORS_PER_COMMITTEE).uint64
  bytes_to_int(eth2hash(slot_signature.toRaw()).data[0..7]) mod modulo == 0

proc aggregate_attestations*(
    pool: AttestationPool, state: BeaconState, index: CommitteeIndex,
    privkey: ValidatorPrivKey, trailing_distance: uint64): Option[AggregateAndProof] =
  doAssert state.slot >= trailing_distance

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#configuration
  doAssert trailing_distance <= ATTESTATION_PROPAGATION_SLOT_RANGE

  let
    slot = state.slot - trailing_distance
    slot_signature = get_slot_signature(
      state.fork, state.genesis_validators_root, slot, privkey)

  doAssert slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= state.slot
  doAssert state.slot >= slot

  # TODO performance issue for future, via get_active_validator_indices(...)
  doAssert index.uint64 < get_committee_count_at_slot(state, slot)

  # TODO for testing purposes, refactor this into the condition check
  # and just calculation
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#aggregation-selection
  if not is_aggregator(state, slot, index, slot_signature):
    return none(AggregateAndProof)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#attestation-data
  # describes how to construct an attestation, which applies for makeAttestationData(...)
  # TODO this won't actually match anything
  let attestation_data = AttestationData(
    slot: slot,
    index: index.uint64,
    beacon_block_root: get_block_root_at_slot(state, slot))

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#construct-aggregate
  # TODO once EV goes in w/ refactoring of getAttestationsForBlock, pull out the getSlot version and use
  # it. This is incorrect.
  for attestation in getAttestationsForBlock(pool, state):
    # getAttestationsForBlock(...) already aggregates
    if attestation.data == attestation_data:
      # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#aggregateandproof
      return some(AggregateAndProof(
        aggregator_index: index.uint64,
        aggregate: attestation,
        selection_proof: slot_signature))

  none(AggregateAndProof)
