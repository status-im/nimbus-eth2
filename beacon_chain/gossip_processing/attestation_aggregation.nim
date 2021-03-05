# beacon_chain
# Copyright (c) 2019-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[options, sequtils],
  chronos, chronicles,
  ../spec/[
    beaconstate, datatypes, crypto, digest, helpers, network, signatures],
  ../consensus_object_pools/[
    spec_cache, blockchain_dag, block_quarantine, spec_cache,
    attestation_pool
  ],
  ".."/[beacon_node_types, ssz, beacon_clock]

logScope:
  topics = "att_aggr"

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/validator.md#aggregation-selection
func is_aggregator*(committee_len: uint64, slot_signature: ValidatorSig): bool =
  let
    modulo = max(1'u64, committee_len div TARGET_AGGREGATORS_PER_COMMITTEE)
  bytes_to_uint64(eth2digest(
    slot_signature.toRaw()).data.toOpenArray(0, 7)) mod modulo == 0

func is_aggregator(epochRef: EpochRef, slot: Slot, index: CommitteeIndex,
    slot_signature: ValidatorSig): bool =
  let
    committee_len = get_beacon_committee_len(epochRef, slot, index)
  return is_aggregator(committee_len, slot_signature)

proc aggregate_attestations*(
    pool: AttestationPool, epochRef: EpochRef, slot: Slot, index: CommitteeIndex,
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

func check_attestation_block(
    pool: AttestationPool, attestationSlot: Slot, blck: BlockRef):
    Result[void, (ValidationResult, cstring)] =
  # The voted-for block must be a descendant of the finalized block, thus it
  # must at least  as new than the finalized checkpoint - in theory it could be
  # equal, but then we're voting for an already-finalized block which is pretty
  # useless - other blocks that are not rooted in the finalized chain will be
  # pruned by the chain dag, and thus we can no longer get a BlockRef for them
  if not (blck.slot > pool.chainDag.finalizedHead.slot):
    return err((ValidationResult.Ignore, cstring(
      "Voting for already-finalized block")))

  # The attestation shouldn't be voting for a block that didn't exist at the
  # time - not in spec, but hard to reason about
  if not (attestationSlot >= blck.slot):
    return err((ValidationResult.Ignore, cstring(
      "Voting for block that didn't exist at the time")))

  # We'll also cap it at 4 epochs which is somewhat arbitrary, but puts an
  # upper bound on the processing done to validate the attestation
  # TODO revisit with less arbitrary approach
  if not ((attestationSlot - blck.slot) <= uint64(4 * SLOTS_PER_EPOCH)):
    return err((ValidationResult.Ignore, cstring("Voting for very old block")))

  ok()

func check_propagation_slot_range(
    data: AttestationData, wallTime: BeaconTime):
    Result[void, (ValidationResult, cstring)] =
  let
    futureSlot = (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot()

  if not futureSlot.afterGenesis or data.slot > futureSlot.slot:
    return err((ValidationResult.Ignore, cstring(
      "Attestation slot in the future")))

  let
    pastSlot = (wallTime - MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot()

  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#configuration
  # The spec value of ATTESTATION_PROPAGATION_SLOT_RANGE is 32, but it can
  # retransmit attestations on the cusp of being out of spec, and which by
  # the time they reach their destination might be out of spec.
  const ATTESTATION_PROPAGATION_SLOT_RANGE = 28

  if pastSlot.afterGenesis and
      data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE < pastSlot.slot:
    return err((ValidationResult.Ignore, cstring(
      "Attestation slot in the past")))

  ok()

func check_beacon_and_target_block(
    pool: var AttestationPool, data: AttestationData):
    Result[BlockRef, (ValidationResult, cstring)] =
  # The block being voted for (data.beacon_block_root) passes validation - by
  # extension, the target block must at that point also pass validation.
  # The target block is returned.
  # We rely on the chain DAG to have been validated, so check for the existence
  # of the block in the pool.
  let blck = pool.chainDag.getRef(data.beacon_block_root)
  if blck.isNil:
    pool.quarantine.addMissing(data.beacon_block_root)
    return err((ValidationResult.Ignore, cstring("Attestation block unknown")))

  # Not in spec - check that rewinding to the state is sane
  ? check_attestation_block(pool, data.slot, blck)

  # [REJECT] The attestation's target block is an ancestor of the block named
  # in the LMD vote -- i.e. get_ancestor(store,
  # attestation.data.beacon_block_root,
  # compute_start_slot_at_epoch(attestation.data.target.epoch)) ==
  # attestation.data.target.root
  let
    target = get_ancestor(
      blck, compute_start_slot_at_epoch(data.target.epoch), SLOTS_PER_EPOCH.int)

  if not (target.root == data.target.root):
    return err((ValidationResult.Reject, cstring(
      "attestation's target block not an ancestor of LMD vote block")))

  ok(target)

func check_aggregation_count(
    attestation: Attestation, singular: bool):
    Result[void, (ValidationResult, cstring)] =
  var onesCount = 0
  # TODO a cleverer algorithm, along the lines of countOnes() in nim-stew
  # But that belongs in nim-stew, since it'd break abstraction layers, to
  # use details of its representation from nimbus-eth2.

  for aggregation_bit in attestation.aggregation_bits:
    if not aggregation_bit:
      continue
    onesCount += 1
    if singular: # More than one ok
      if onesCount > 1:
        return err((ValidationResult.Reject, cstring(
          "Attestation has too many aggregation bits")))
    else:
      break # Found the one we needed

  if onesCount < 1:
    return err((ValidationResult.Reject, cstring(
      "Attestation has too few aggregation bits")))

  ok()

func check_attestation_subnet(
    epochRef: EpochRef, attestation: Attestation,
    topicCommitteeIndex: uint64): Result[void, (ValidationResult, cstring)] =
  let
    expectedSubnet =
      compute_subnet_for_attestation(
        get_committee_count_per_slot(epochRef),
        attestation.data.slot, attestation.data.index.CommitteeIndex)

  if expectedSubnet != topicCommitteeIndex:
    return err((ValidationResult.Reject, cstring(
      "Attestation's committee index not for the correct subnet")))

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id
proc validateAttestation*(
    pool: var AttestationPool,
    attestation: Attestation, wallTime: BeaconTime,
    topicCommitteeIndex: uint64, checksExpensive: bool):
    Result[seq[ValidatorIndex], (ValidationResult, cstring)] =
  # Some of the checks below have been reordered compared to the spec, to
  # perform the cheap checks first - in particular, we want to avoid loading
  # an `EpochRef` and checking signatures. This reordering might lead to
  # different IGNORE/REJECT results in turn affecting gossip scores.

  # [REJECT] The attestation's epoch matches its target -- i.e.
  # attestation.data.target.epoch ==
  # compute_epoch_at_slot(attestation.data.slot)
  block:
    let v = check_attestation_slot_target(attestation.data)
    if v.isErr():
      return err((ValidationResult.Reject, v.error))

  # attestation.data.slot is within the last ATTESTATION_PROPAGATION_SLOT_RANGE
  # slots (within a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e.
  # attestation.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot
  # >= attestation.data.slot (a client MAY queue future attestations for
  # processing at the appropriate slot).
  ? check_propagation_slot_range(attestation.data, wallTime) # [IGNORE]

  # The attestation is unaggregated -- that is, it has exactly one
  # participating validator (len([bit for bit in attestation.aggregation_bits
  # if bit == 0b1]) == 1).
  ? check_aggregation_count(attestation, singular = true) # [REJECT]

  # The block being voted for (attestation.data.beacon_block_root) has been seen
  # (via both gossip and non-gossip sources) (a client MAY queue attestations for
  # processing once block is retrieved).
  # The block being voted for (attestation.data.beacon_block_root) passes
  # validation.
  # [IGNORE] if block is unseen so far and enqueue it in missing blocks
  let target = ? check_beacon_and_target_block(pool, attestation.data) # [IGNORE/REJECT]

  # The following rule follows implicitly from that we clear out any
  # unviable blocks from the chain dag:
  #
  # The current finalized_checkpoint is an ancestor of the block defined by
  # attestation.data.beacon_block_root -- i.e. get_ancestor(store,
  # attestation.data.beacon_block_root,
  # compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
  # store.finalized_checkpoint.root
  let
    epochRef = pool.chainDag.getEpochRef(target, attestation.data.target.epoch)

  # [REJECT] The committee index is within the expected range -- i.e.
  # data.index < get_committee_count_per_slot(state, data.target.epoch).
  if not (attestation.data.index < get_committee_count_per_slot(epochRef)):
    return err((ValidationResult.Reject, cstring(
      "validateAttestation: committee index not within expected range")))

  # [REJECT] The attestation is for the correct subnet -- i.e.
  # compute_subnet_for_attestation(committees_per_slot,
  # attestation.data.slot, attestation.data.index) == subnet_id, where
  # committees_per_slot = get_committee_count_per_slot(state,
  # attestation.data.target.epoch), which may be pre-computed along with the
  # committee information for the signature check.
  ? check_attestation_subnet(epochRef, attestation, topicCommitteeIndex)

  # [REJECT] The number of aggregation bits matches the committee size -- i.e.
  # len(attestation.aggregation_bits) == len(get_beacon_committee(state,
  # data.slot, data.index)).
  #
  # This uses the same epochRef as data.target.epoch, because the attestation's
  # epoch matches its target and attestation.data.target.root is an ancestor of
  # attestation.data.beacon_block_root.
  if not (attestation.aggregation_bits.lenu64 == get_beacon_committee_len(
      epochRef, attestation.data.slot, attestation.data.index.CommitteeIndex)):
    return err((ValidationResult.Reject, cstring(
      "validateAttestation: number of aggregation bits and committee size mismatch")))

  let
    fork = pool.chainDag.headState.data.data.fork
    genesis_validators_root =
      pool.chainDag.headState.data.data.genesis_validators_root
    attesting_indices = get_attesting_indices(
      epochRef, attestation.data, attestation.aggregation_bits)

  # The number of aggregation bits matches the committee size, which ensures
  # this condition holds.
  doAssert attesting_indices.len == 1, "Per bits check above"
  let validator_index = toSeq(attesting_indices)[0]

  # There has been no other valid attestation seen on an attestation subnet
  # that has an identical `attestation.data.target.epoch` and participating
  # validator index.
  # Slightly modified to allow only newer attestations than were previously
  # seen (no point in propagating older votes)
  if (pool.nextAttestationEpoch.lenu64 > validator_index.uint64) and
      pool.nextAttestationEpoch[validator_index].subnet >
        attestation.data.target.epoch:
    return err((ValidationResult.Ignore, cstring(
      "Validator has already voted in epoch")))

  if not checksExpensive:
    return ok(attesting_indices)

  # The signature of attestation is valid.
  block:
    let v = is_valid_indexed_attestation(
        fork, genesis_validators_root, epochRef, attesting_indices,
        attestation, {})
    if v.isErr():
      return err((ValidationResult.Reject, v.error))

  # Only valid attestations go in the list, which keeps validator_index
  # in range
  if not (pool.nextAttestationEpoch.lenu64 > validator_index.uint64):
    pool.nextAttestationEpoch.setLen(validator_index.int + 1)
  pool.nextAttestationEpoch[validator_index].subnet =
    attestation.data.target.epoch + 1

  ok(attesting_indices)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
proc validateAggregate*(
    pool: var AttestationPool,
    signedAggregateAndProof: SignedAggregateAndProof, wallTime: BeaconTime):
    Result[seq[ValidatorIndex], (ValidationResult, cstring)] =
  # Some of the checks below have been reordered compared to the spec, to
  # perform the cheap checks first - in particular, we want to avoid loading
  # an `EpochRef` and checking signatures. This reordering might lead to
  # different IGNORE/REJECT results in turn affecting gossip scores.

  template aggregate_and_proof: untyped = signedAggregateAndProof.message
  template aggregate: untyped = aggregate_and_proof.aggregate

  # [REJECT] The aggregate attestation's epoch matches its target -- i.e.
  # `aggregate.data.target.epoch == compute_epoch_at_slot(aggregate.data.slot)`
  block:
    let v = check_attestation_slot_target(aggregate.data)
    if v.isErr():
      return err((ValidationResult.Reject, v.error))

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
  # Slightly modified to allow only newer attestations than were previously
  # seen (no point in propagating older votes)
  if (pool.nextAttestationEpoch.lenu64 >
        aggregate_and_proof.aggregator_index) and
      pool.nextAttestationEpoch[
          aggregate_and_proof.aggregator_index].aggregate >
        aggregate.data.target.epoch:
    return err((ValidationResult.Ignore, cstring(
      "Validator has already aggregated in epoch")))

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
  # [IGNORE] if block is unseen so far and enqueue it in missing blocks
  let target = ? check_beacon_and_target_block(pool, aggregate.data)

  # [REJECT] aggregate_and_proof.selection_proof selects the validator as an
  # aggregator for the slot -- i.e. is_aggregator(state, aggregate.data.slot,
  # aggregate.data.index, aggregate_and_proof.selection_proof) returns True.
  let
    epochRef = pool.chainDag.getEpochRef(target, aggregate.data.target.epoch)

  if not is_aggregator(
      epochRef, aggregate.data.slot, aggregate.data.index.CommitteeIndex,
      aggregate_and_proof.selection_proof):
    return err((ValidationResult.Reject, cstring("Incorrect aggregator")))

  # [REJECT] The aggregator's validator index is within the committee -- i.e.
  # aggregate_and_proof.aggregator_index in get_beacon_committee(state,
  # aggregate.data.slot, aggregate.data.index).
  if aggregate_and_proof.aggregator_index.ValidatorIndex notin
      get_beacon_committee(
        epochRef, aggregate.data.slot, aggregate.data.index.CommitteeIndex):
    return err((ValidationResult.Reject, cstring(
      "Aggregator's validator index not in committee")))

  # [REJECT] The aggregate_and_proof.selection_proof is a valid signature of the
  # aggregate.data.slot by the validator with index
  # aggregate_and_proof.aggregator_index.
  # get_slot_signature(state, aggregate.data.slot, privkey)
  if aggregate_and_proof.aggregator_index >= epochRef.validator_keys.lenu64:
    return err((ValidationResult.Reject, cstring("Invalid aggregator_index")))

  let
    fork = pool.chainDag.headState.data.data.fork
    genesis_validators_root =
      pool.chainDag.headState.data.data.genesis_validators_root
  if not verify_slot_signature(
      fork, genesis_validators_root, aggregate.data.slot,
      epochRef.validator_keys[aggregate_and_proof.aggregator_index],
      aggregate_and_proof.selection_proof):
    return err((ValidationResult.Reject, cstring(
      "Selection_proof signature verification failed")))

  # [REJECT] The aggregator signature, signed_aggregate_and_proof.signature, is valid.
  if not verify_aggregate_and_proof_signature(
      fork, genesis_validators_root, aggregate_and_proof,
      epochRef.validator_keys[aggregate_and_proof.aggregator_index],
      signed_aggregate_and_proof.signature):
    return err((ValidationResult.Reject, cstring(
      "signed_aggregate_and_proof signature verification failed")))

  let attesting_indices = get_attesting_indices(
    epochRef, aggregate.data, aggregate.aggregation_bits)

  # [REJECT] The signature of aggregate is valid.
  block:
    let v = is_valid_indexed_attestation(
        fork, genesis_validators_root, epochRef, attesting_indices,
        aggregate, {})
    if v.isErr():
      return err((ValidationResult.Reject, v.error))

  # The following rule follows implicitly from that we clear out any
  # unviable blocks from the chain dag:
  #
  # The current finalized_checkpoint is an ancestor of the block defined by
  # aggregate.data.beacon_block_root -- i.e. get_ancestor(store,
  # aggregate.data.beacon_block_root,
  # compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
  # store.finalized_checkpoint.root

  # Only valid aggregates go in the list
  if pool.nextAttestationEpoch.lenu64 <= aggregate_and_proof.aggregator_index:
    pool.nextAttestationEpoch.setLen(
      aggregate_and_proof.aggregator_index.int + 1)
  pool.nextAttestationEpoch[aggregate_and_proof.aggregator_index].aggregate =
    aggregate.data.target.epoch + 1

  ok(attesting_indices)
