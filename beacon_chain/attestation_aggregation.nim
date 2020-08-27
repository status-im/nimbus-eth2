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
  ./block_pools/[spec_cache, chain_dag, quarantine, spec_cache],
  ./attestation_pool, ./beacon_node_types, ./ssz, ./time

logScope:
  topics = "att_aggr"

const
  MAXIMUM_GOSSIP_CLOCK_DISPARITY = 500.millis

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#aggregation-selection
func is_aggregator(state: BeaconState, slot: Slot, index: CommitteeIndex,
    slot_signature: ValidatorSig, cache: var StateCache): bool =
  let
    committee_len = get_beacon_committee_len(state, slot, index, cache)
    modulo = max(1'u64, committee_len div TARGET_AGGREGATORS_PER_COMMITTEE)
  bytes_to_uint64(eth2digest(
    slot_signature.toRaw()).data.toOpenArray(0, 7)) mod modulo == 0

proc aggregate_attestations*(
    pool: AttestationPool, state: BeaconState, index: CommitteeIndex,
    validatorIndex: ValidatorIndex, privkey: ValidatorPrivKey,
    cache: var StateCache):
    Option[AggregateAndProof] =
  let
    slot = state.slot
    slot_signature = get_slot_signature(
      state.fork, state.genesis_validators_root, slot, privkey)

  doAssert validatorIndex in get_beacon_committee(state, slot, index, cache)
  doAssert index.uint64 < get_committee_count_per_slot(state, slot.epoch, cache)

  # TODO for testing purposes, refactor this into the condition check
  # and just calculation
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#aggregation-selection
  if not is_aggregator(state, slot, index, slot_signature, cache):
    return none(AggregateAndProof)

  let maybe_slot_attestation = getAggregatedAttestation(pool, slot, index)
  if maybe_slot_attestation.isNone:
    return none(AggregateAndProof)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#construct-aggregate
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#aggregateandproof
  some(AggregateAndProof(
    aggregator_index: validatorIndex.uint64,
    aggregate: maybe_slot_attestation.get,
    selection_proof: slot_signature))

func check_attestation_block_slot(
    pool: AttestationPool, attestationSlot: Slot, attestationBlck: BlockRef): Result[void, cstring] =
  # If we allow voting for very old blocks, the state transaction below will go
  # nuts and keep processing empty slots
  if not (attestationBlck.slot > pool.chainDag.finalizedHead.slot):
    return err("Voting for already-finalized block")

  # we'll also cap it at 4 epochs which is somewhat arbitrary, but puts an
  # upper bound on the processing done to validate the attestation
  # TODO revisit with less arbitrary approach
  if not (attestationSlot >= attestationBlck.slot):
    return err("Voting for block that didn't exist at the time")

  if not ((attestationSlot - attestationBlck.slot) <= uint64(4 * SLOTS_PER_EPOCH)):
    return err("Voting for very old block")

  ok()

func check_propagation_slot_range(
    data: AttestationData, wallTime: BeaconTime): Result[void, cstring] =
  let
    futureSlot = (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot()

  if not futureSlot.afterGenesis or data.slot > futureSlot.slot:
    return err("Attestation slot in the future")

  let
    pastSlot = (wallTime - MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot()

  if pastSlot.afterGenesis and
      data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE < pastSlot.slot:
    return err("Attestation slot in the past")

  ok()

func check_attestation_beacon_block(
    pool: var AttestationPool, attestation: Attestation): Result[void, cstring] =
  # The block being voted for (attestation.data.beacon_block_root) passes
  # validation.
  # We rely on the chain DAG to have been validated, so check for the existence
  # of the block in the pool.
  let attestationBlck = pool.chainDag.getRef(attestation.data.beacon_block_root)
  if attestationBlck.isNil:
    pool.quarantine.addMissing(attestation.data.beacon_block_root)
    return err("Attestation block unknown")

  # Not in spec - check that rewinding to the state is sane
  ? check_attestation_block_slot(pool, attestation.data.slot, attestationBlck)

  ok()

func check_aggregation_count(
    attestation: Attestation, singular: bool): Result[void, cstring] =
  var onesCount = 0
  # TODO a cleverer algorithm, along the lines of countOnes() in nim-stew
  # But that belongs in nim-stew, since it'd break abstraction layers, to
  # use details of its representation from nim-beacon-chain.

  for aggregation_bit in attestation.aggregation_bits:
    if not aggregation_bit:
      continue
    onesCount += 1
    if singular: # More than one ok
      if onesCount > 1:
        return err("Attestation has too many aggregation bits")
    else:
      break # Found the one we needed

  if onesCount < 1:
    return err("Attestation has too few aggregation bits")

  ok()

func check_attestation_subnet(
    epochRef: EpochRef, attestation: Attestation,
    topicCommitteeIndex: uint64): Result[void, cstring] =
  let
    expectedSubnet =
      compute_subnet_for_attestation(
        get_committee_count_per_slot(epochRef),
        attestation.data.slot, attestation.data.index.CommitteeIndex)

  if expectedSubnet != topicCommitteeIndex:
    return err("Attestation's committee index not for the correct subnet")

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id
proc validateAttestation*(
    pool: var AttestationPool,
    attestation: Attestation, wallTime: BeaconTime,
    topicCommitteeIndex: uint64): Result[HashSet[ValidatorIndex], cstring] =
  ? check_attestation_slot_target(attestation.data) # Not in spec - ignore

  # attestation.data.slot is within the last ATTESTATION_PROPAGATION_SLOT_RANGE
  # slots (within a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e.
  # attestation.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot
  # >= attestation.data.slot (a client MAY queue future attestations for\
  # processing at the appropriate slot).
  ? check_propagation_slot_range(attestation.data, wallTime) # [IGNORE]

  # The attestation is unaggregated -- that is, it has exactly one
  # participating validator (len([bit for bit in attestation.aggregation_bits
  # if bit == 0b1]) == 1).
  ? check_aggregation_count(attestation, singular = true) # [REJECT]

  # The block being voted for (attestation.data.beacon_block_root) has been seen
  # (via both gossip and non-gossip sources) (a client MAY queue aggregates for
  # processing once block is retrieved).
  # The block being voted for (attestation.data.beacon_block_root) passes
  # validation.
  ? check_attestation_beacon_block(pool, attestation) # [IGNORE/REJECT]

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
          return err("Attestation already exists at slot") # [IGNORE]

  let tgtBlck = pool.chainDag.getRef(attestation.data.target.root)
  if tgtBlck.isNil:
    pool.quarantine.addMissing(attestation.data.target.root)
    return err("Attestation target block unknown")

  # The following rule follows implicitly from that we clear out any
  # unviable blocks from the chain dag:
  #
  # The current finalized_checkpoint is an ancestor of the block defined by
  # attestation.data.beacon_block_root -- i.e. get_ancestor(store,
  # attestation.data.beacon_block_root,
  # compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
  # store.finalized_checkpoint.root

  let epochRef = pool.chainDag.getEpochRef(
    tgtBlck, attestation.data.target.epoch)

  # [REJECT] The attestation is for the correct subnet -- i.e.
  # compute_subnet_for_attestation(committees_per_slot,
  # attestation.data.slot, attestation.data.index) == subnet_id, where
  # committees_per_slot = get_committee_count_per_slot(state,
  # attestation.data.target.epoch), which may be pre-computed along with the
  # committee information for the signature check.
  ? check_attestation_subnet(epochRef, attestation, topicCommitteeIndex)

  let
    fork = pool.chainDag.headState.data.data.fork
    genesis_validators_root =
      pool.chainDag.headState.data.data.genesis_validators_root
    attesting_indices = get_attesting_indices(
      epochRef, attestation.data, attestation.aggregation_bits)

    # The signature of attestation is valid.
  ? is_valid_indexed_attestation(
      fork, genesis_validators_root, epochRef, attesting_indices, attestation, {})

  ok(attesting_indices)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
proc validateAggregate*(
    pool: var AttestationPool,
    signedAggregateAndProof: SignedAggregateAndProof,
    wallTime: BeaconTime): Result[HashSet[ValidatorIndex], cstring] =
  let
    aggregate_and_proof = signedAggregateAndProof.message
    aggregate = aggregate_and_proof.aggregate

  ? check_attestation_slot_target(aggregate.data) # Not in spec - ignore

  # [IGNORE] aggregate.data.slot is within the last
  # ATTESTATION_PROPAGATION_SLOT_RANGE slots (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. aggregate.data.slot +
  # ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate.data.slot
  ? check_propagation_slot_range(aggregate.data, wallTime) # [IGNORE]

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
  ? check_aggregation_count(aggregate, singular = false)

  # [REJECT] The block being voted for (aggregate.data.beacon_block_root)
  # passes validation.
  ? check_attestation_beacon_block(pool, aggregate)

  # [REJECT] aggregate_and_proof.selection_proof selects the validator as an
  # aggregator for the slot -- i.e. is_aggregator(state, aggregate.data.slot,
  # aggregate.data.index, aggregate_and_proof.selection_proof) returns True.
  let tgtBlck = pool.chainDag.getRef(aggregate.data.target.root)
  if tgtBlck.isNil:
    pool.quarantine.addMissing(aggregate.data.target.root)
    return err("Aggregate target block unknown")

  let epochRef = pool.chainDag.getEpochRef(tgtBlck, aggregate.data.target.epoch)

  if not is_aggregator(
      epochRef, aggregate.data.slot, aggregate.data.index.CommitteeIndex,
      aggregate_and_proof.selection_proof):
    return err("Incorrect aggregator")

  # [REJECT] The aggregator's validator index is within the committee -- i.e.
  # aggregate_and_proof.aggregator_index in get_beacon_committee(state,
  # aggregate.data.slot, aggregate.data.index).
  if aggregate_and_proof.aggregator_index.ValidatorIndex notin
      get_beacon_committee(
        epochRef, aggregate.data.slot, aggregate.data.index.CommitteeIndex):
    return err("Aggregator's validator index not in committee")

  # [REJECT] The aggregate_and_proof.selection_proof is a valid signature of the
  # aggregate.data.slot by the validator with index
  # aggregate_and_proof.aggregator_index.
  # get_slot_signature(state, aggregate.data.slot, privkey)
  if aggregate_and_proof.aggregator_index >= epochRef.validator_keys.lenu64:
    return err("Invalid aggregator_index")

  let
    fork = pool.chainDag.headState.data.data.fork
    genesis_validators_root =
      pool.chainDag.headState.data.data.genesis_validators_root
  if not verify_slot_signature(
      fork, genesis_validators_root, aggregate.data.slot,
      epochRef.validator_keys[aggregate_and_proof.aggregator_index],
      aggregate_and_proof.selection_proof):
    return err("Selection_proof signature verification failed")

  # [REJECT] The aggregator signature, signed_aggregate_and_proof.signature, is valid.
  if not verify_aggregate_and_proof_signature(
      fork, genesis_validators_root, aggregate_and_proof,
      epochRef.validator_keys[aggregate_and_proof.aggregator_index],
      signed_aggregate_and_proof.signature):
    return err("signed_aggregate_and_proof signature verification failed")

  let attesting_indices = get_attesting_indices(
    epochRef, aggregate.data, aggregate.aggregation_bits)

  # [REJECT] The signature of aggregate is valid.
  ? is_valid_indexed_attestation(
      fork, genesis_validators_root, epochRef, attesting_indices, aggregate, {})

  # The following rule follows implicitly from that we clear out any
  # unviable blocks from the chain dag:
  #
  # The current finalized_checkpoint is an ancestor of the block defined by
  # aggregate.data.beacon_block_root -- i.e. get_ancestor(store,
  # aggregate.data.beacon_block_root,
  # compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
  # store.finalized_checkpoint.root

  ok(attesting_indices)
