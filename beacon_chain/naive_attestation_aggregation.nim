# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, sequtils,
  ./spec/[datatypes, crypto, digest, helpers, validator],
  ./ssz

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
  let slot = state.slot - 1 # TODO this isn't correct

  # the "Construct aggregate" section seems to suggest it's from a previous
  # slot.
  doAssert slot < state.slot
  is_aggregator(state, slot, index, get_slot_signature(state, slot, privkey))

func aggregate_attestations_naively*(
    state: BeaconState, index: uint64, privkey: ValidatorPrivKey):
    Option[Attestation] =
  # Keep this code opt-in with clean entry point; if there's a part that
  # mutates state, split that off and keep this separate.
  # TODO alias CommitteeIndex to actual type then convert various uint64's here
  # to it

  # If the validator is selected to aggregate (`is_aggregator()`), they
  # construct an aggregate attestation
  if not should_aggregate(state, index, privkey):
    return none(Attestation)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#construct-aggregate
  # Collect attestations seen via gossip during the slot that have an
  # equivalent attestation_data to that constructed by the validator,
  # and create an aggregate_attestation: Attestation with the following fields.
  var aggregate_attestation = Attestation(
  )

  # https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregate-signature-1
  # Set aggregate_attestation.signature = aggregate_signature where
  # aggregate_signature is obtained from get_aggregate_signature(...).
  aggregate_attestation.signature = get_aggregate_signature([])

  some(aggregate_attestation)
