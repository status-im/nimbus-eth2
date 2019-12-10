# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mostly TODOs at this point, but basically, called every 1/3 + expected
# network + attestation pool lag to collect attestations, if one wants a
# maximally updated pool (but could also just only aggregate to previous
# slots, safer probably), check for some fixed slot offset to past for a
# locally attached validator (externally-to-this-module supplied), run a
# set of supplied algorithms (already implemented) to check if that is a
# matching pair. Aggregation itself's already implemented in attestation
# pool, so this is mostly (a) selection of when to aggregate, (b) change
# of validation, (c) and specific sending deadlines with slots.
#
# The other part is arguably part of attestation pool -- the validation's
# something that should be happing on receipt, not aggregation per se. In
# that part, check that messages conform -- so, check for each type
# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/networking/p2p-interface.md#topics-and-messages
# specifies. So by the time this calls attestation pool, all validation's
# already done.
#
# Finally, some of the filtering's libp2p stuff. Consistency checks between
# topic/message types and GOSSIP_MAX_SIZE.

import
  options,
  ./spec/[datatypes, crypto, digest, helpers, validator],
  ./attestation_pool, ./beacon_node_types, ./ssz

# TODO gossipsub validation lives somewhere, maybe here
# TODO add tests, especially for validation
# https://github.com/status-im/nim-beacon-chain/issues/122#issuecomment-562479965
# it's conceptually separate, sort of, but depends on beaconstate, so isn't a
# pure libp2p thing.

const
  # https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/networking/p2p-interface.md#configuration
  ATTESTATION_PROPAGATION_SLOT_RANGE* = 32
  GOSSIP_MAX_SIZE = 1048576

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregation-selection
func get_slot_signature(state: BeaconState, slot: Slot, privkey: ValidatorPrivKey):
    ValidatorSig =
  let domain =
    get_domain(state, DOMAIN_BEACON_ATTESTER, compute_epoch_at_slot(slot))
  bls_sign(privkey, hash_tree_root(slot).data, domain)

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregation-selection
func is_aggregator(state: BeaconState, slot: Slot, index: uint64,
    slot_signature: ValidatorSig): bool =
  # TODO index is a CommitteeIndex, aka uint64
  var cache = get_empty_per_epoch_cache()

  let
    committee = get_beacon_committee(state, slot, index, cache)
    modulo = max(1, len(committee) div TARGET_AGGREGATORS_PER_COMMITTEE).uint64
  bytes_to_int(eth2hash(slot_signature.getBytes).data[0..7]) mod modulo == 0

proc aggregate_attestations*(
    pool: AttestationPool, state: BeaconState, index: uint64,
    privkey: ValidatorPrivKey): Option[AggregateAndProof] =
  # TODO alias CommitteeIndex to actual type then convert various uint64's here

  let
    slot = state.slot - 2
    slot_signature = get_slot_signature(state, slot, privkey)

  if slot < 0:
    return none(AggregateAndProof)
  doAssert slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= state.slot
  doAssert state.slot >= slot

  # https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregation-selection
  if not is_aggregator(state, slot, index, slot_signature):
    return none(AggregateAndProof)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#construct-aggregate
  let attestations = getAttestationsForBlock(pool, state, slot)

  var correct_attestation_data: AttestationData

  for attestation in attestations:
    if attestation.data == correct_attestation_data:
      return some(AggregateAndProof(
        aggregator_index: index,
        aggregate: attestation,
        selection_proof: slot_signature))

  none(AggregateAndProof)
  # SECONDS_PER_SLOT / 3 in: initial aggregation TODO adjust this elsewhere
  # SECONDS_PER_SLOT * 2 / 3
