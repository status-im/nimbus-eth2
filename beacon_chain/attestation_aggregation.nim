# beacon_chain
# Copyright (c) 2019-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Have an an aggregated aggregation ready for broadcast at
# SECONDS_PER_SLOT * 2 / 3, i.e. 2/3 through relevant slot
# intervals.
#
# The other part is arguably part of attestation pool -- the validation's
# something that should be happing on receipt, not aggregation per se. In
# that part, check that messages conform -- so, check for each type
# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/p2p-interface.md#topics-and-messages
# specifies. So by the time this calls attestation pool, all validation's
# already done.
#
# Finally, some of the filtering's libp2p stuff. Consistency checks between
# topic/message types and GOSSIP_MAX_SIZE -- mostly doesn't belong here, so
# while TODO, isn't TODO for this module.

import
  options,
  ./spec/[beaconstate, datatypes, crypto, digest, helpers, validator],
  ./attestation_pool, ./beacon_node_types, ./ssz

# TODO gossipsub validation lives somewhere, maybe here
# TODO add tests, especially for validation
# https://github.com/status-im/nim-beacon-chain/issues/122#issuecomment-562479965

const
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/p2p-interface.md#configuration
  ATTESTATION_PROPAGATION_SLOT_RANGE = 32

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/validator/0_beacon-chain-validator.md#aggregation-selection
func get_slot_signature(state: BeaconState, slot: Slot, privkey: ValidatorPrivKey):
    ValidatorSig =
  let domain =
    get_domain(state, DOMAIN_BEACON_ATTESTER, compute_epoch_at_slot(slot))
  bls_sign(privkey, hash_tree_root(slot).data, domain)

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/validator/0_beacon-chain-validator.md#aggregation-selection
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

  # https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/validator/0_beacon-chain-validator.md#aggregation-selection
  if not is_aggregator(state, slot, index, slot_signature):
    return none(AggregateAndProof)

  let attestation_data =
    makeAttestationData(state, slot, index, get_block_root_at_slot(state, slot))

  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.0/specs/phase0/validator.md#construct-aggregate
  for attestation in getAttestationsForBlock(pool, state, slot):
    if attestation.data == attestation_data:
      # https://github.com/ethereum/eth2.0-specs/blob/v0.10.0/specs/phase0/validator.md#aggregateandproof
      return some(AggregateAndProof(
        aggregator_index: index,
        aggregate: attestation,
        selection_proof: slot_signature))

  # TODO in catch-up mode, we could get here, so probably shouldn't assert
  doAssert false
  none(AggregateAndProof)
