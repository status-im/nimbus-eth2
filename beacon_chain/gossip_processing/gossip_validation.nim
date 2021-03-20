# beacon_chain
# Copyright (c) 2019-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/[sequtils, intsets, deques],
  # Status
  chronicles, chronos,
  stew/results,
  # Internals
  ../spec/[
    beaconstate, state_transition_block,
    datatypes, crypto, digest, helpers, network, signatures],
  ../consensus_object_pools/[
    spec_cache, blockchain_dag, block_quarantine, spec_cache,
    attestation_pool, exit_pool
  ],
  ".."/[beacon_node_types, ssz, beacon_clock],
  ../validators/attestation_aggregation,
  ../extras,
  ./batch_validation

logScope:
  topics = "gossip_checks"

# Internal checks
# ----------------------------------------------------------------

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

# Gossip Validation
# ----------------------------------------------------------------

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id
proc validateAttestation*(
    pool: var AttestationPool,
    batchCrypto: ref BatchCrypto,
    attestation: Attestation,
    wallTime: BeaconTime,
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
    # First pass - without cryptography
    let v = is_valid_indexed_attestation(
        fork, genesis_validators_root, epochRef, attesting_indices,
        attestation,
        {skipBLSValidation})
    if v.isErr():
      return err((ValidationResult.Reject, v.error))

    # Buffer crypto checks
    let deferredCrypto = batchCrypto
                  .scheduleAttestationCheck(
                    fork, genesis_validators_root, epochRef,
                    attestation
                  )
    if deferredCrypto.isNone():
      return err((ValidationResult.Reject,
                  cstring("validateAttestation: crypto sanity checks failure")))

    # Await the crypto check
    let cryptoChecked = try:
      waitFor deferredCrypto.get()
    except Exception as e:
      # TODO
      # https://github.com/nim-lang/Nim/issues/10288 - sigh
      raiseAssert e.msg

    if cryptoChecked.isErr():
      return err((ValidationResult.Reject, cryptoChecked.error))

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
    batchCrypto: ref BatchCrypto,
    signedAggregateAndProof: SignedAggregateAndProof,
    wallTime: BeaconTime):
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

  block:
    # 1. [REJECT] The aggregate_and_proof.selection_proof is a valid signature of the
    #    aggregate.data.slot by the validator with index
    #    aggregate_and_proof.aggregator_index.
    #    get_slot_signature(state, aggregate.data.slot, privkey)
    # 2. [REJECT] The aggregator signature, signed_aggregate_and_proof.signature, is valid.
    # 3. [REJECT] The signature of aggregate is valid.
    if aggregate_and_proof.aggregator_index >= epochRef.validator_keys.lenu64:
      return err((ValidationResult.Reject, cstring("Invalid aggregator_index")))

    let
      fork = pool.chainDag.headState.data.data.fork
      genesis_validators_root =
        pool.chainDag.headState.data.data.genesis_validators_root

    let deferredCrypto = batchCrypto
                  .scheduleAggregateChecks(
                    fork, genesis_validators_root, epochRef,
                    signed_aggregate_and_proof
                  )
    if deferredCrypto.isNone():
      return err((ValidationResult.Reject,
                  cstring("validateAttestation: crypto sanity checks failure")))

    # [REJECT] aggregate_and_proof.selection_proof
    let slotChecked = try:
      waitFor deferredCrypto.get().slotCheck
    except Exception as e:
      # TODO
      # https://github.com/nim-lang/Nim/issues/10288 - sigh
      raiseAssert e.msg

    if slotChecked.isErr():
      return err((ValidationResult.Reject, cstring(
        "Selection_proof signature verification failed")))

    # [REJECT] The aggregator signature, signed_aggregate_and_proof.signature, is valid.
    let aggregatorChecked = try:
      waitFor deferredCrypto.get().aggregatorCheck
    except Exception as e:
      # TODO
      # https://github.com/nim-lang/Nim/issues/10288 - sigh
      raiseAssert e.msg

    if aggregatorChecked.isErr():
      return err((ValidationResult.Reject, cstring(
        "signed_aggregate_and_proof aggregator signature verification failed")))

    # [REJECT] The aggregator signature, signed_aggregate_and_proof.signature, is valid.
    let aggregateChecked = try:
      waitFor deferredCrypto.get().aggregateCheck
    except Exception as e:
      # TODO
      # https://github.com/nim-lang/Nim/issues/10288 - sigh
      raiseAssert e.msg

    if aggregateChecked.isErr():
      return err((ValidationResult.Reject, cstring(
        "signed_aggregate_and_proof aggregate attester signatures verification failed")))

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

  let attesting_indices = get_attesting_indices(
    epochRef, aggregate.data, aggregate.aggregation_bits)

  ok(attesting_indices)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_block
proc isValidBeaconBlock*(
       dag: ChainDAGRef, quarantine: var QuarantineRef,
       signed_beacon_block: SignedBeaconBlock, wallTime: BeaconTime,
       flags: UpdateFlags):
       Result[void, (ValidationResult, BlockError)] =
  logScope:
    received_block = shortLog(signed_beacon_block.message)
    blockRoot = shortLog(signed_beacon_block.root)

  # In general, checks are ordered from cheap to expensive. Especially, crypto
  # verification could be quite a bit more expensive than the rest. This is an
  # externally easy-to-invoke function by tossing network packets at the node.

  # [IGNORE] The block is not from a future slot (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that
  # signed_beacon_block.message.slot <= current_slot (a client MAY queue future
  # blocks for processing at the appropriate slot).
  if not (signed_beacon_block.message.slot <=
      (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero):
    debug "block is from a future slot",
      wallSlot = wallTime.toSlot()
    return err((ValidationResult.Ignore, Invalid))

  # [IGNORE] The block is from a slot greater than the latest finalized slot --
  # i.e. validate that signed_beacon_block.message.slot >
  # compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
  if not (signed_beacon_block.message.slot > dag.finalizedHead.slot):
    debug "block is not from a slot greater than the latest finalized slot"
    return err((ValidationResult.Ignore, Invalid))

  # [IGNORE] The block is the first block with valid signature received for the
  # proposer for the slot, signed_beacon_block.message.slot.
  #
  # While this condition is similar to the proposer slashing condition at
  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/validator.md#proposer-slashing
  # it's not identical, and this check does not address slashing:
  #
  # (1) The beacon blocks must be conflicting, i.e. different, for the same
  #     slot and proposer. This check also catches identical blocks.
  #
  # (2) By this point in the function, it's not been checked whether they're
  #     signed yet. As in general, expensive checks should be deferred, this
  #     would add complexity not directly relevant this function.
  #
  # (3) As evidenced by point (1), the similarity in the validation condition
  #     and slashing condition, while not coincidental, aren't similar enough
  #     to combine, as one or the other might drift.
  #
  # (4) Furthermore, this function, as much as possible, simply returns a yes
  #     or no answer, without modifying other state for p2p network interface
  #     validation. Complicating this interface, for the sake of sharing only
  #     couple lines of code, wouldn't be worthwhile.
  #
  # TODO might check unresolved/orphaned blocks too, and this might not see all
  # blocks at a given slot (though, in theory, those get checked elsewhere), or
  # adding metrics that count how often these conditions occur.
  let
    slotBlockRef = getBlockBySlot(dag, signed_beacon_block.message.slot)

  if not slotBlockRef.isNil:
    let blck = dag.get(slotBlockRef).data
    if blck.message.proposer_index ==
          signed_beacon_block.message.proposer_index and
        blck.message.slot == signed_beacon_block.message.slot and
        blck.signature.toRaw() != signed_beacon_block.signature.toRaw():
      notice "block isn't first block with valid signature received for the proposer",
        blckRef = slotBlockRef,
        existing_block = shortLog(blck.message)
      return err((ValidationResult.Ignore, Invalid))

  # [IGNORE] The block's parent (defined by block.parent_root) has been seen
  # (via both gossip and non-gossip sources) (a client MAY queue blocks for
  # processing once the parent block is retrieved).
  #
  # And implicitly:
  # [REJECT] The block's parent (defined by block.parent_root) passes validation.
  let parent_ref = dag.getRef(signed_beacon_block.message.parent_root)
  if parent_ref.isNil:
    # Pending dag gets checked via `ChainDAGRef.add(...)` later, and relevant
    # checks are performed there. In usual paths beacon_node adds blocks via
    # ChainDAGRef.add(...) directly, with no additional validity checks.
    debug "parent unknown, putting block in quarantine",
      current_slot = wallTime.toSlot()
    if not quarantine.add(dag, signed_beacon_block):
      debug "Block quarantine full"
    return err((ValidationResult.Ignore, MissingParent))

  # [REJECT] The current finalized_checkpoint is an ancestor of block -- i.e.
  # get_ancestor(store, block.parent_root,
  # compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
  # store.finalized_checkpoint.root
  let
    finalized_checkpoint = dag.headState.data.data.finalized_checkpoint
    ancestor = get_ancestor(
      parent_ref, compute_start_slot_at_epoch(finalized_checkpoint.epoch))

  if ancestor.isNil:
    debug "couldn't find ancestor block"
    return err((ValidationResult.Ignore, Invalid)) # might not've received block

  if not (finalized_checkpoint.root in [ancestor.root, Eth2Digest()]):
    debug "block not descendent of finalized block"
    return err((ValidationResult.Reject, Invalid))

  # [REJECT] The block is proposed by the expected proposer_index for the
  # block's slot in the context of the current shuffling (defined by
  # parent_root/slot). If the proposer_index cannot immediately be verified
  # against the expected shuffling, the block MAY be queued for later
  # processing while proposers for the block's branch are calculated -- in such
  # a case do not REJECT, instead IGNORE this message.
  let
    proposer = getProposer(dag, parent_ref, signed_beacon_block.message.slot)

  if proposer.isNone:
    warn "cannot compute proposer for message"
    return err((ValidationResult.Ignore, Invalid)) # internal issue

  if proposer.get()[0] !=
      ValidatorIndex(signed_beacon_block.message.proposer_index):
    notice "block had unexpected proposer",
      expected_proposer = proposer.get()[0]
    return err((ValidationResult.Reject, Invalid))

  # [REJECT] The proposer signature, signed_beacon_block.signature, is valid
  # with respect to the proposer_index pubkey.
  if not verify_block_signature(
      dag.headState.data.data.fork,
      dag.headState.data.data.genesis_validators_root,
      signed_beacon_block.message.slot,
      signed_beacon_block.message,
      proposer.get()[1],
      signed_beacon_block.signature):
    debug "block failed signature verification",
      signature = shortLog(signed_beacon_block.signature)

    return err((ValidationResult.Reject, Invalid))

  ok()


# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#attester_slashing
proc validateAttesterSlashing*(
    pool: var ExitPool, attester_slashing: AttesterSlashing):
    Result[bool, (ValidationResult, cstring)] =
  # [IGNORE] At least one index in the intersection of the attesting indices of
  # each attestation has not yet been seen in any prior attester_slashing (i.e.
  # attester_slashed_indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices),
  # verify if any(attester_slashed_indices.difference(prior_seen_attester_slashed_indices))).
  # TODO sequtils2 should be able to make this more reasonable, from asSeq on
  # down, and can sort and just find intersection that way
  let
    attestation_1_indices =
      attester_slashing.attestation_1.attesting_indices.asSeq
    attestation_2_indices =
      attester_slashing.attestation_2.attesting_indices.asSeq
    attester_slashed_indices =
      toIntSet(attestation_1_indices) * toIntSet(attestation_2_indices)

  if not disjoint(
      attester_slashed_indices, pool.prior_seen_attester_slashed_indices):
    return err((ValidationResult.Ignore, cstring(
      "validateAttesterSlashing: attester-slashed index already attester-slashed")))

  # [REJECT] All of the conditions within process_attester_slashing pass
  # validation.
  let attester_slashing_validity =
    check_attester_slashing(
      pool.chainDag.headState.data.data, attester_slashing, {})
  if attester_slashing_validity.isErr:
    return err((ValidationResult.Reject, attester_slashing_validity.error))

  pool.prior_seen_attester_slashed_indices.incl attester_slashed_indices
  pool.attester_slashings.addExitMessage(
    attester_slashing, ATTESTER_SLASHINGS_BOUND)

  ok(true)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#proposer_slashing
proc validateProposerSlashing*(
    pool: var ExitPool, proposer_slashing: ProposerSlashing):
    Result[bool, (ValidationResult, cstring)] =
  # Not from spec; the rest of NBC wouldn't have correctly processed it either.
  if proposer_slashing.signed_header_1.message.proposer_index > high(int).uint64:
    return err((ValidationResult.Ignore, cstring(
      "validateProposerSlashing: proposer-slashed index too high")))

  # [IGNORE] The proposer slashing is the first valid proposer slashing
  # received for the proposer with index
  # proposer_slashing.signed_header_1.message.proposer_index.
  if proposer_slashing.signed_header_1.message.proposer_index.int in
      pool.prior_seen_proposer_slashed_indices:
    return err((ValidationResult.Ignore, cstring(
      "validateProposerSlashing: proposer-slashed index already proposer-slashed")))

  # [REJECT] All of the conditions within process_proposer_slashing pass validation.
  let proposer_slashing_validity =
    check_proposer_slashing(
      pool.chainDag.headState.data.data, proposer_slashing, {})
  if proposer_slashing_validity.isErr:
    return err((ValidationResult.Reject, proposer_slashing_validity.error))

  pool.prior_seen_proposer_slashed_indices.incl(
    proposer_slashing.signed_header_1.message.proposer_index.int)
  pool.proposer_slashings.addExitMessage(
    proposer_slashing, PROPOSER_SLASHINGS_BOUND)

  ok(true)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#voluntary_exit
proc validateVoluntaryExit*(
    pool: var ExitPool, signed_voluntary_exit: SignedVoluntaryExit):
    Result[void, (ValidationResult, cstring)] =
  # [IGNORE] The voluntary exit is the first valid voluntary exit received for
  # the validator with index signed_voluntary_exit.message.validator_index.
  if signed_voluntary_exit.message.validator_index >=
      pool.chainDag.headState.data.data.validators.lenu64:
    return err((ValidationResult.Ignore, cstring(
      "validateVoluntaryExit: validator index too high")))

  # Since pool.chainDag.headState.data.data.validators is a seq, this means
  # signed_voluntary_exit.message.validator_index.int is already valid, but
  # check explicitly if one changes that data structure.
  if signed_voluntary_exit.message.validator_index.int in
      pool.prior_seen_voluntary_exit_indices:
    return err((ValidationResult.Ignore, cstring(
      "validateVoluntaryExit: validator index already voluntarily exited")))

  # [REJECT] All of the conditions within process_voluntary_exit pass
  # validation.
  let voluntary_exit_validity =
    check_voluntary_exit(
      pool.chainDag.headState.data.data, signed_voluntary_exit, {})
  if voluntary_exit_validity.isErr:
    return err((ValidationResult.Reject, voluntary_exit_validity.error))

  pool.prior_seen_voluntary_exit_indices.incl(
    signed_voluntary_exit.message.validator_index.int)
  pool.voluntary_exits.addExitMessage(
    signed_voluntary_exit, VOLUNTARY_EXITS_BOUND)

  ok()
