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
  options, sequtils,
  ./spec/[datatypes, crypto, digest, helpers, validator],
  ./attestation_pool, ./beacon_node_types, ./ssz

# TODO add tests
# TODO gossipsub validation lives somewhere, maybe here
# https://github.com/status-im/nim-beacon-chain/issues/122#issuecomment-562479965
# it's conceptually separate, sort of, but depends on beaconstate, so isn't a
# pure libp2p thing.

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregation-selection
func get_slot_signature(state: BeaconState, slot: Slot, privkey: ValidatorPrivKey):
    ValidatorSig =
  # TODO privkey is int in spec, but bls_sign wants a ValidatorPrivKey
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregate-signature-1
func get_aggregate_signature(attestations: openarray[Attestation]): ValidatorSig =
  let signatures = mapIt(attestations, it.signature)
  bls_aggregate_signatures(signatures)

func should_aggregate(
    state: BeaconState, index: uint64, privkey: ValidatorPrivKey): bool =
  # https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregation-selection
  # A validator is selected to aggregate based upon the return value of
  # is_aggregator().
  #const use_offset = ATTESTATION_PROPAGATION_SLOT_RANGE - 3
  #TODO implement this constant
  # just pick some fixed time offset in past after which we should have gotten
  # all attestations -- in principle, if we trust that we get attestations the
  # slot get sent within SECONDS_PER_SLOT / 3, can use current slot, but seems
  # risky. initally aim for one or two slots back to try to be currentand keep
  # away from anything too near edge of ATTESTATION_PROPAGATION_SLOT_RANGE.
  #
  # static:
  #  doAssert use_offset > 0
  let slot = state.slot - 2
  if slot < 0:
    return
  # TODO aggregate_and_proof.aggregate.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate_and_proof.aggregate.data.slot
  doAssert slot < state.slot
  is_aggregator(state, slot, index, get_slot_signature(state, slot, privkey))

proc aggregate_attestations*(
    pool: AttestationPool, state: BeaconState, index: uint64,
    privkey: ValidatorPrivKey): Option[Attestation] =
  # Keep this code opt-in with clean entry point; if there's a part that
  # mutates state, split that off and keep this separate.
  # TODO alias CommitteeIndex to actual type then convert various uint64's here
  # TODO return Option[AggregateAndProof]

  # If the validator is selected to aggregate (`is_aggregator()`), they
  # construct an aggregate attestation
  let slot = state.slot - 2
  # TODO as before, check sanity here against (1) constant ATTESTATION_PROPAGATION_SLOT_RANGE
  # and (2) genesis slot
  if not should_aggregate(state, index, privkey):
    return none(Attestation)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#construct-aggregate
  # Collect attestations seen via gossip during the slot that have an
  # equivalent attestation_data to that constructed by the validator,
  # and create an aggregate_attestation: Attestation with the following fields.
  # TODO set slot here and tell should_aggregate
  let attestations = getAttestationsForBlock(pool, state, slot)
  # TODO it's a greedy set packing algorithm to avoid overlap
  # make sure this works here or change it (both places maybe?)
  # TODO scan for matching attestationdata; already aggregated
  # SECONDS_PER_SLOT / 3 in: initial aggregation TODO adjust this elsewhere
  # SECONDS_PER_SLOT * 2 / 3

  # TODO obviously wrong, but define check against attestation_data first
  # also, this should be AggregateAndProof apparently, indeed.
  let aggregate_attestation = attestations[0]
  some(aggregate_attestation)
