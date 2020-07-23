# beacon_chain
# Copyright (c) 2019-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  options, chronicles,
  ./spec/[
    beaconstate, datatypes, crypto, digest, helpers, network, validator,
    signatures],
  ./block_pool, ./block_pools/candidate_chains, ./attestation_pool,
  ./beacon_node_types, ./ssz

logScope:
  topics = "att_aggr"

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#aggregation-selection
func is_aggregator(state: BeaconState, slot: Slot, index: CommitteeIndex,
    slot_signature: ValidatorSig, cache: var StateCache): bool =
  let
    committee = get_beacon_committee(state, slot, index, cache)
    modulo = max(1'u64, len(committee).uint64 div TARGET_AGGREGATORS_PER_COMMITTEE)
  bytes_to_int(eth2digest(slot_signature.toRaw()).data[0..7]) mod modulo == 0

proc aggregate_attestations*(
    pool: AttestationPool, state: BeaconState, index: CommitteeIndex,
    privkey: ValidatorPrivKey, trailing_distance: uint64): Option[AggregateAndProof] =
  doAssert state.slot >= trailing_distance

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/p2p-interface.md#configuration
  doAssert trailing_distance <= ATTESTATION_PROPAGATION_SLOT_RANGE

  let
    slot = state.slot - trailing_distance
    slot_signature = get_slot_signature(
      state.fork, state.genesis_validators_root, slot, privkey)

  doAssert slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= state.slot
  doAssert state.slot >= slot

  var cache = StateCache()
  # TODO performance issue for future, via get_active_validator_indices(...)
  doAssert index.uint64 < get_committee_count_at_slot(state, slot, cache)

  # TODO for testing purposes, refactor this into the condition check
  # and just calculation
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#aggregation-selection
  if not is_aggregator(state, slot, index, slot_signature, cache):
    return none(AggregateAndProof)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#attestation-data
  # describes how to construct an attestation, which applies for makeAttestationData(...)
  # TODO this won't actually match anything
  let attestation_data = AttestationData(
    slot: slot,
    index: index.uint64,
    beacon_block_root: get_block_root_at_slot(state, slot))

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#construct-aggregate
  # TODO once EV goes in w/ refactoring of getAttestationsForBlock, pull out the getSlot version and use
  # it. This is incorrect.
  for attestation in getAttestationsForBlock(pool, state):
    # getAttestationsForBlock(...) already aggregates
    if attestation.data == attestation_data:
      # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#aggregateandproof
      return some(AggregateAndProof(
        aggregator_index: index.uint64,
        aggregate: attestation,
        selection_proof: slot_signature))

  none(AggregateAndProof)

proc isValidAttestationSlot(
    pool: AttestationPool, attestationSlot: Slot, attestationBlck: BlockRef): bool =
  # If we allow voting for very old blocks, the state transaction below will go
  # nuts and keep processing empty slots
  logScope:
    attestationSlot
    attestationBlck = shortLog(attestationBlck)

  if not (attestationBlck.slot > pool.blockPool.finalizedHead.slot):
    debug "voting for already-finalized block"
    return false

  # we'll also cap it at 4 epochs which is somewhat arbitrary, but puts an
  # upper bound on the processing done to validate the attestation
  # TODO revisit with less arbitrary approach
  if not (attestationSlot >= attestationBlck.slot):
    debug "voting for block that didn't exist at the time"
    return false

  if not ((attestationSlot - attestationBlck.slot) <= uint64(4 * SLOTS_PER_EPOCH)):
    debug "voting for very old block"
    return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#attestation-subnets
proc isValidAttestation*(
    pool: var AttestationPool, attestation: Attestation, current_slot: Slot,
    topicCommitteeIndex: uint64): bool =
  logScope:
    topics = "att_aggr valid_att"
    received_attestation = shortLog(attestation)

  if not (attestation.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >=
      current_slot and current_slot >= attestation.data.slot):
    debug "attestation.data.slot not within ATTESTATION_PROPAGATION_SLOT_RANGE"
    return false

  # The attestation is unaggregated -- that is, it has exactly one
  # participating validator (len([bit for bit in attestation.aggregation_bits
  # if bit == 0b1]) == 1).
  # TODO a cleverer algorithm, along the lines of countOnes() in nim-stew
  # But that belongs in nim-stew, since it'd break abstraction layers, to
  # use details of its representation from nim-beacon-chain.
  var onesCount = 0
  for aggregation_bit in attestation.aggregation_bits:
    if not aggregation_bit:
      continue
    onesCount += 1
    if onesCount > 1:
      debug "attestation has too many aggregation bits"
      return false
  if onesCount != 1:
    debug "attestation has too few aggregation bits"
    return false

  # The attestation is the first valid attestation received for the
  # participating validator for the slot, attestation.data.slot.
  let maybeAttestationsSeen = getAttestationsForSlot(pool, attestation.data.slot)
  if maybeAttestationsSeen.isSome:
    for attestationEntry in maybeAttestationsSeen.get.attestations:
      if attestation.data != attestationEntry.data:
        continue
      # Attestations might be aggregated eagerly or lazily; allow for both.
      for validation in attestationEntry.validations:
        if attestation.aggregation_bits.isSubsetOf(validation.aggregation_bits):
          debug "attestation already exists at slot",
            attestation_pool_validation = validation.aggregation_bits
          return false

  # The block being voted for (attestation.data.beacon_block_root) passes
  # validation.
  # We rely on the block pool to have been validated, so check for the
  # existence of the block in the pool.
  # TODO: consider a "slush pool" of attestations whose blocks have not yet
  # propagated - i.e. imagine that attestations are smaller than blocks and
  # therefore propagate faster, thus reordering their arrival in some nodes
  let attestationBlck = pool.blockPool.getRef(attestation.data.beacon_block_root)
  if attestationBlck.isNil:
    debug "block doesn't exist in block pool"
    pool.blockPool.addMissing(attestation.data.beacon_block_root)
    return false

  if not isValidAttestationSlot(pool, attestation.data.slot, attestationBlck):
    # Not in spec - check that rewinding to the state is sane
    return false

  pool.blockPool.withState(
      pool.blockPool.tmpState,
      BlockSlot(blck: attestationBlck, slot: attestation.data.slot)):
    # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/p2p-interface.md#attestation-subnets
    # [REJECT] The attestation is for the correct subnet (i.e.
    # compute_subnet_for_attestation(state, attestation) == subnet_id).
    let
      epochInfo = blck.getEpochInfo(state)
      requiredSubnetIndex =
        compute_subnet_for_attestation(
          get_committee_count_at_slot(epochInfo),
          attestation.data.slot, attestation.data.index.CommitteeIndex)

    if requiredSubnetIndex != topicCommitteeIndex:
      debug "isValidAttestation: attestation's committee index not for the correct subnet",
        topicCommitteeIndex = topicCommitteeIndex,
        attestation_data_index = attestation.data.index,
        requiredSubnetIndex = requiredSubnetIndex
      return false

    # The signature of attestation is valid.
    var cache = getEpochCache(blck, state)
    if not is_valid_indexed_attestation(
        state, get_indexed_attestation(state, attestation, cache), {}):
      debug "signature verification failed"
      return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/p2p-interface.md#global-topics
proc isValidAggregatedAttestation*(
    pool: var AttestationPool,
    signedAggregateAndProof: SignedAggregateAndProof,
    current_slot: Slot): bool =
  let
    aggregate_and_proof = signedAggregateAndProof.message
    aggregate = aggregate_and_proof.aggregate

  # There's some overlap between this and isValidAttestation(), but unclear if
  # saving a few lines of code would balance well with losing straightforward,
  # spec-based synchronization.
  #
  # [IGNORE] aggregate.data.slot is within the last
  # ATTESTATION_PROPAGATION_SLOT_RANGE slots (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. aggregate.data.slot +
  # ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate.data.slot
  if not (aggregate.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >=
      current_slot and current_slot >= aggregate.data.slot):
    debug "isValidAggregatedAttestation: aggregation.data.slot not within ATTESTATION_PROPAGATION_SLOT_RANGE"
    return false

  # [IGNORE] The valid aggregate attestation defined by
  # hash_tree_root(aggregate) has not already been seen (via aggregate gossip,
  # within a verified block, or through the creation of an equivalent aggregate
  # locally).
  #
  # This is [IGNORE] and already checked by attestation pool when aggregate is
  # added.

  # [IGNORE] The aggregate is the first valid aggregate received for the
  # aggregator with index aggregate_and_proof.aggregator_index for the epoch
  # aggregate.data.target.epoch.
  #
  # This is [IGNORE] and already effectively checked by attestation pool upon
  # attempting to resolve attestations.

  # [REJECT] The block being voted for (aggregate.data.beacon_block_root)
  # passes validation.
  let attestationBlck = pool.blockPool.getRef(aggregate.data.beacon_block_root)
  if attestationBlck.isNil:
    debug "isValidAggregatedAttestation: block doesn't exist in block pool"
    pool.blockPool.addMissing(aggregate.data.beacon_block_root)
    return false

  # [REJECT] The attestation has participants -- that is,
  # len(get_attesting_indices(state, aggregate.data, aggregate.aggregation_bits)) >= 1.
  #
  # get_attesting_indices() is:
  # committee = get_beacon_committee(state, data.slot, data.index)
  # return set(index for i, index in enumerate(committee) if bits[i])
  #
  # the attestation doesn't have participants is iff either:
  # (1) the aggregation bits are all 0; or
  # (2) the non-zero aggregation bits don't overlap with extant committee
  #     members, i.e. they counts don't match.
  # But (2) would reflect an invalid aggregation in other ways, so reject it
  # either way.
  if isZeros(aggregate.aggregation_bits):
    debug "isValidAggregatedAttestation: attestation has no or invalid aggregation bits"
    return false

  if not isValidAttestationSlot(pool, aggregate.data.slot, attestationBlck):
    # Not in spec - check that rewinding to the state is sane
    return false

  # [REJECT] aggregate_and_proof.selection_proof selects the validator as an
  # aggregator for the slot -- i.e. is_aggregator(state, aggregate.data.slot,
  # aggregate.data.index, aggregate_and_proof.selection_proof) returns True.
  # TODO use withEpochState when it works more reliably
  pool.blockPool.withState(
      pool.blockPool.tmpState,
      BlockSlot(blck: attestationBlck, slot: aggregate.data.slot)):
    var cache = getEpochCache(blck, state)
    if not is_aggregator(
        state, aggregate.data.slot, aggregate.data.index.CommitteeIndex,
        aggregate_and_proof.selection_proof, cache):
      debug "isValidAggregatedAttestation: incorrect aggregator"
      return false

    # [REJECT] The aggregator's validator index is within the committee -- i.e.
    # aggregate_and_proof.aggregator_index in get_beacon_committee(state,
    # aggregate.data.slot, aggregate.data.index).
    if aggregate_and_proof.aggregator_index.ValidatorIndex notin
        get_beacon_committee(
          state, aggregate.data.slot, aggregate.data.index.CommitteeIndex, cache):
      debug "isValidAggregatedAttestation: aggregator's validator index not in committee"
      return false

    # [REJECT] The aggregate_and_proof.selection_proof is a valid signature of the
    # aggregate.data.slot by the validator with index
    # aggregate_and_proof.aggregator_index.
    # get_slot_signature(state, aggregate.data.slot, privkey)
    if aggregate_and_proof.aggregator_index >= state.validators.len.uint64:
      debug "isValidAggregatedAttestation: invalid aggregator_index"
      return false

    if not verify_slot_signature(
        state.fork, state.genesis_validators_root, aggregate.data.slot,
        state.validators[aggregate_and_proof.aggregator_index].pubkey,
        aggregate_and_proof.selection_proof):
      debug "isValidAggregatedAttestation: selection_proof signature verification failed"
      return false

    # [REJECT] The aggregator signature, signed_aggregate_and_proof.signature, is valid.
    if not verify_aggregate_and_proof_signature(
        state.fork, state.genesis_validators_root, aggregate_and_proof,
        state.validators[aggregate_and_proof.aggregator_index].pubkey,
        signed_aggregate_and_proof.signature):
      debug "isValidAggregatedAttestation: signed_aggregate_and_proof signature verification failed"
      return false

    # [REJECT] The signature of aggregate is valid.
    if not is_valid_indexed_attestation(
        state, get_indexed_attestation(state, aggregate, cache), {}):
      debug "isValidAggregatedAttestation: aggregate signature verification failed"
      return false

  debug "isValidAggregatedAttestation: succeeded"
  true
