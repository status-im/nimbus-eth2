# beacon_chain
# Copyright (c) 2019-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Status
  chronicles, chronos, metrics,
  stew/results,
  # Internals
  ../spec/datatypes/[phase0, altair],
  ../spec/[
    beaconstate, state_transition_block, forks, helpers, network, signatures],
  ../consensus_object_pools/[
    attestation_pool, blockchain_dag, block_quarantine, exit_pool, spec_cache,
    sync_committee_msg_pool],
  ".."/[beacon_clock],
  ./batch_validation

from libp2p/protocols/pubsub/pubsub import ValidationResult

export results, ValidationResult

logScope:
  topics = "gossip_checks"

declareCounter beacon_attestations_dropped_queue_full,
  "Number of attestations dropped because queue is full"

declareCounter beacon_aggregates_dropped_queue_full,
  "Number of aggregates dropped because queue is full"

# This result is a little messy in that it returns Result.ok for
# ValidationResult.Accept and an err for the others - this helps transport
# an error message to callers but could arguably be done in an cleaner way.
type
  ValidationError* = (ValidationResult, cstring)

template errIgnore*(msg: cstring): untyped =
  err((ValidationResult.Ignore, cstring msg))
template errReject*(msg: cstring): untyped =
  err((ValidationResult.Reject, cstring msg))

# Internal checks
# ----------------------------------------------------------------

func check_attestation_block(
    pool: AttestationPool, attestationSlot: Slot, blck: BlockRef):
    Result[void, ValidationError] =
  # The voted-for block must be a descendant of the finalized block, thus it
  # must at least  as new than the finalized checkpoint - in theory it could be
  # equal, but then we're voting for an already-finalized block which is pretty
  # useless - other blocks that are not rooted in the finalized chain will be
  # pruned by the chain dag, and thus we can no longer get a BlockRef for them
  if not (blck.slot > pool.dag.finalizedHead.slot):
    return errIgnore("Voting for already-finalized block")

  # The attestation shouldn't be voting for a block that didn't exist at the
  # time - not in spec, but hard to reason about
  if not (attestationSlot >= blck.slot):
    return errIgnore("Voting for block that didn't exist at the time")

  # We'll also cap it at 4 epochs which is somewhat arbitrary, but puts an
  # upper bound on the processing done to validate the attestation
  # TODO revisit with less arbitrary approach
  if not ((attestationSlot - blck.slot) <= uint64(4 * SLOTS_PER_EPOCH)):
    return errIgnore("Voting for very old block")

  ok()

func check_propagation_slot_range(
    msgSlot: Slot, wallTime: BeaconTime): Result[void, ValidationError] =
  let
    futureSlot = (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot()

  if not futureSlot.afterGenesis or msgSlot > futureSlot.slot:
    return errIgnore("Attestation slot in the future")

  let
    pastSlot = (wallTime - MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot()

  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#configuration
  # The spec value of ATTESTATION_PROPAGATION_SLOT_RANGE is 32, but it can
  # retransmit attestations on the cusp of being out of spec, and which by
  # the time they reach their destination might be out of spec.
  const ATTESTATION_PROPAGATION_SLOT_RANGE = 28

  if pastSlot.afterGenesis and
      msgSlot + ATTESTATION_PROPAGATION_SLOT_RANGE < pastSlot.slot:
    return errIgnore("Attestation slot in the past")

  ok()

func check_beacon_and_target_block(
    pool: var AttestationPool, data: AttestationData):
    Result[BlockRef, ValidationError] =
  # The block being voted for (data.beacon_block_root) passes validation - by
  # extension, the target block must at that point also pass validation.
  # The target block is returned.
  # We rely on the chain DAG to have been validated, so check for the existence
  # of the block in the pool.
  let blck = pool.dag.getRef(data.beacon_block_root)
  if blck.isNil:
    pool.quarantine.addMissing(data.beacon_block_root)
    return errIgnore("Attestation block unknown")

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
    return errIgnore(
      "Attestation's target block not an ancestor of LMD vote block")

  ok(target)

func check_aggregation_count(
    attestation: Attestation, singular: bool): Result[void, ValidationError] =

  let ones = attestation.aggregation_bits.countOnes()
  if singular and ones != 1:
    return errReject("Attestation must have a single attestation bit set")
  elif not singular and ones < 1:
    return errReject("Attestation must have at least one attestation bit set")

  ok()

func check_attestation_subnet(
    epochRef: EpochRef, attestation: Attestation,
    subnet_id: SubnetId): Result[void, ValidationError] =
  let
    expectedSubnet =
      compute_subnet_for_attestation(
        get_committee_count_per_slot(epochRef),
        attestation.data.slot, attestation.data.index.CommitteeIndex)

  if expectedSubnet != subnet_id:
    return errReject("Attestation not on the correct subnet")

  ok()

# Gossip Validation
# ----------------------------------------------------------------

template checkedReject(msg: cstring): untyped =
  if verifyFinalization in pool.dag.updateFlags:
    # This doesn't depend on the wall clock or the exact state of the DAG; it's
    # an internal consistency/correctness check only, and effectively never has
    # false positives. These don't, for example, arise from timeouts.
    raiseAssert $msg
  errReject(msg)

template checkedReject(error: ValidationError): untyped =
  doAssert error[0] == ValidationResult.Reject
  if verifyFinalization in pool.dag.updateFlags:
    # This doesn't depend on the wall clock or the exact state of the DAG; it's
    # an internal consistency/correctness check only, and effectively never has
    # false positives. These don't, for example, arise from timeouts.
    raiseAssert $error[1]
  err(error)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_block
proc validateBeaconBlock*(
    dag: ChainDAGRef, quarantine: QuarantineRef,
    signed_beacon_block: phase0.SignedBeaconBlock | altair.SignedBeaconBlock,
    wallTime: BeaconTime, flags: UpdateFlags): Result[void, ValidationError] =
  # In general, checks are ordered from cheap to expensive. Especially, crypto
  # verification could be quite a bit more expensive than the rest. This is an
  # externally easy-to-invoke function by tossing network packets at the node.

  # [IGNORE] The block is not from a future slot (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that
  # signed_beacon_block.message.slot <= current_slot (a client MAY queue future
  # blocks for processing at the appropriate slot).
  if not (signed_beacon_block.message.slot <=
      (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero):
    return errIgnore("BeaconBlock: slot too high")

  # [IGNORE] The block is from a slot greater than the latest finalized slot --
  # i.e. validate that signed_beacon_block.message.slot >
  # compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
  if not (signed_beacon_block.message.slot > dag.finalizedHead.slot):
    return errIgnore("BeaconBlock: slot already finalized")

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
  if signed_beacon_block.root in dag:
    # The gossip algorithm itself already does one round of hashing to find
    # already-seen data, but it is fairly aggressive about forgetting about
    # what it has seen already
    # "[IGNORE] The block is the first block ..."
    return errIgnore("BeaconBlock: already seen")

  let
    slotBlockRef = getBlockBySlot(dag, signed_beacon_block.message.slot)

  if not slotBlockRef.isNil:
    let blck = dag.get(slotBlockRef).data
    if getForkedBlockField(blck, proposer_index) ==
          signed_beacon_block.message.proposer_index and
        getForkedBlockField(blck, slot) == signed_beacon_block.message.slot and
        blck.signature.toRaw() != signed_beacon_block.signature.toRaw():
      return errIgnore("BeaconBlock: already proposed in the same slot")

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
    if not quarantine.add(dag, signed_beacon_block):
      debug "Block quarantine full"
    return errIgnore("BeaconBlock: Parent not found")

  # [REJECT] The current finalized_checkpoint is an ancestor of block -- i.e.
  # get_ancestor(store, block.parent_root,
  # compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
  # store.finalized_checkpoint.root
  let
    finalized_checkpoint = getStateField(
      dag.headState.data, finalized_checkpoint)
    ancestor = get_ancestor(
      parent_ref, compute_start_slot_at_epoch(finalized_checkpoint.epoch))

  if ancestor.isNil:
    # This shouldn't happen: we should always be able to trace the parent back
    # to the finalized checkpoint (else it wouldn't be in the DAG)
    return errIgnore("BeaconBlock: Can't find ancestor")

  if not (finalized_checkpoint.root in [ancestor.root, Eth2Digest()]):
    return errReject("BeaconBlock: Finalized checkpoint not an ancestor")

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
    return errIgnore("BeaconBlock: Cannot compute proposer") # internal issue

  if uint64(proposer.get()) != signed_beacon_block.message.proposer_index:
    return errReject("BeaconBlock: Unexpected proposer proposer")

  # [REJECT] The proposer signature, signed_beacon_block.signature, is valid
  # with respect to the proposer_index pubkey.
  if not verify_block_signature(
      dag.forkAtEpoch(signed_beacon_block.message.slot.epoch),
      getStateField(dag.headState.data, genesis_validators_root),
      signed_beacon_block.message.slot,
      signed_beacon_block.root,
      dag.validatorKey(proposer.get()).get(),
      signed_beacon_block.signature):
    return errReject("Invalid proposer signature")

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id
proc validateAttestation*(
    pool: ref AttestationPool,
    batchCrypto: ref BatchCrypto,
    attestation: Attestation,
    wallTime: BeaconTime,
    subnet_id: SubnetId, checkSignature: bool):
    Future[Result[
      tuple[attesting_index: ValidatorIndex, sig: CookedSig],
      ValidationError]] {.async.} =
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
      return errReject(v.error())

  # attestation.data.slot is within the last ATTESTATION_PROPAGATION_SLOT_RANGE
  # slots (within a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e.
  # attestation.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot
  # >= attestation.data.slot (a client MAY queue future attestations for
  # processing at the appropriate slot).
  block:
    let v = check_propagation_slot_range(attestation.data.slot, wallTime) # [IGNORE]
    if v.isErr():
      return err(v.error())

  # The attestation is unaggregated -- that is, it has exactly one
  # participating validator (len([bit for bit in attestation.aggregation_bits
  # if bit == 0b1]) == 1).
  block:
    let v = check_aggregation_count(attestation, singular = true) # [REJECT]
    if v.isErr():
      return checkedReject(v.error)

  # The block being voted for (attestation.data.beacon_block_root) has been seen
  # (via both gossip and non-gossip sources) (a client MAY queue attestations for
  # processing once block is retrieved).
  # The block being voted for (attestation.data.beacon_block_root) passes
  # validation.
  # [IGNORE] if block is unseen so far and enqueue it in missing blocks
  let target = block:
    let v = check_beacon_and_target_block(pool[], attestation.data) # [IGNORE/REJECT]
    if v.isErr():
      return err(v.error)
    v.get()

  # The following rule follows implicitly from that we clear out any
  # unviable blocks from the chain dag:
  #
  # The current finalized_checkpoint is an ancestor of the block defined by
  # attestation.data.beacon_block_root -- i.e. get_ancestor(store,
  # attestation.data.beacon_block_root,
  # compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
  # store.finalized_checkpoint.root
  let
    epochRef = pool.dag.getEpochRef(target, attestation.data.target.epoch)

  # [REJECT] The committee index is within the expected range -- i.e.
  # data.index < get_committee_count_per_slot(state, data.target.epoch).
  if not (attestation.data.index < get_committee_count_per_slot(epochRef)):
    return checkedReject("Attestation: committee index not within expected range")

  # [REJECT] The attestation is for the correct subnet -- i.e.
  # compute_subnet_for_attestation(committees_per_slot,
  # attestation.data.slot, attestation.data.index) == subnet_id, where
  # committees_per_slot = get_committee_count_per_slot(state,
  # attestation.data.target.epoch), which may be pre-computed along with the
  # committee information for the signature check.
  block:
    let v = check_attestation_subnet(epochRef, attestation, subnet_id) # [REJECT]
    if v.isErr():
      return err(v.error)

  # [REJECT] The number of aggregation bits matches the committee size -- i.e.
  # len(attestation.aggregation_bits) == len(get_beacon_committee(state,
  # data.slot, data.index)).
  #
  # This uses the same epochRef as data.target.epoch, because the attestation's
  # epoch matches its target and attestation.data.target.root is an ancestor of
  # attestation.data.beacon_block_root.
  if not (attestation.aggregation_bits.lenu64 == get_beacon_committee_len(
      epochRef, attestation.data.slot, attestation.data.index.CommitteeIndex)):
    return checkedReject(
      "Attestation: number of aggregation bits and committee size mismatch")

  let
    fork = pool.dag.forkAtEpoch(attestation.data.slot.epoch)
    genesis_validators_root =
      getStateField(pool.dag.headState.data, genesis_validators_root)
    attesting_index = get_attesting_indices_one(
      epochRef, attestation.data, attestation.aggregation_bits)

  # The number of aggregation bits matches the committee size, which ensures
  # this condition holds.
  doAssert attesting_index.isSome(), "We've checked bits length and one count already"
  let validator_index = attesting_index.get()

  # There has been no other valid attestation seen on an attestation subnet
  # that has an identical `attestation.data.target.epoch` and participating
  # validator index.
  # Slightly modified to allow only newer attestations than were previously
  # seen (no point in propagating older votes)
  if (pool.nextAttestationEpoch.lenu64 > validator_index.uint64) and
      pool.nextAttestationEpoch[validator_index].subnet >
        attestation.data.target.epoch:
    return errIgnore("Attestation: Validator has already voted in epoch")

  block:
    # First pass - without cryptography
    let v = is_valid_indexed_attestation(
        fork, genesis_validators_root, epochRef, attestation,
        {skipBLSValidation})
    if v.isErr():
      return checkedReject(v.error)

  let sig =
    if checkSignature:
      # Attestation signatures are batch-verified
      let deferredCrypto = batchCrypto
                            .scheduleAttestationCheck(
                              fork, genesis_validators_root, epochRef,
                              attestation
                            )
      if deferredCrypto.isErr():
        return checkedReject(deferredCrypto.error)

      # Await the crypto check
      let
        (cryptoFut, sig) = deferredCrypto.get()

      var x = (await cryptoFut)
      case x
      of BatchResult.Invalid:
        return checkedReject("Attestation: invalid signature")
      of BatchResult.Timeout:
        beacon_attestations_dropped_queue_full.inc()
        return errIgnore("Attestation: timeout checking signature")
      of BatchResult.Valid:
        sig # keep going only in this case
    else:
      let sig = attestation.signature.load()
      if not sig.isSome():
        return checkedReject("Attestation: unable to load signature")
      sig.get()

  # Only valid attestations go in the list, which keeps validator_index
  # in range
  if not (pool.nextAttestationEpoch.lenu64 > validator_index.uint64):
    pool.nextAttestationEpoch.setLen(validator_index.int + 1)
  pool.nextAttestationEpoch[validator_index].subnet =
    attestation.data.target.epoch + 1

  return ok((validator_index, sig))

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
proc validateAggregate*(
    pool: ref AttestationPool,
    batchCrypto: ref BatchCrypto,
    signedAggregateAndProof: SignedAggregateAndProof,
    wallTime: BeaconTime):
    Future[Result[
      tuple[attestingIndices: seq[ValidatorIndex], sig: CookedSig],
      ValidationError]] {.async.} =
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
      return checkedReject(v.error)

  # [IGNORE] aggregate.data.slot is within the last
  # ATTESTATION_PROPAGATION_SLOT_RANGE slots (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. aggregate.data.slot +
  # ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate.data.slot
  block:
    let v = check_propagation_slot_range(aggregate.data.slot, wallTime) # [IGNORE]
    if v.isErr():
      return err(v.error())

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
    return errIgnore("Aggregate: validator has already aggregated in epoch")

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
  block:
    let v = check_aggregation_count(aggregate, singular = false) # [REJECT]
    if v.isErr():
      return err(v.error)

  # [REJECT] The block being voted for (aggregate.data.beacon_block_root)
  # passes validation.
  # [IGNORE] if block is unseen so far and enqueue it in missing blocks
  let target = block:
    let v = check_beacon_and_target_block(pool[], aggregate.data) # [IGNORE/REJECT]
    if v.isErr():
      return err(v.error)
    v.get()

  # [REJECT] aggregate_and_proof.selection_proof selects the validator as an
  # aggregator for the slot -- i.e. is_aggregator(state, aggregate.data.slot,
  # aggregate.data.index, aggregate_and_proof.selection_proof) returns True.
  let
    epochRef = pool.dag.getEpochRef(target, aggregate.data.target.epoch)

  # [REJECT] The committee index is within the expected range -- i.e.
  # data.index < get_committee_count_per_slot(state, data.target.epoch).
  if not (aggregate.data.index < get_committee_count_per_slot(epochRef)):
    return checkedReject("Aggregate: committee index not within expected range")

  if not is_aggregator(
      epochRef, aggregate.data.slot, aggregate.data.index.CommitteeIndex,
      aggregate_and_proof.selection_proof):
    return checkedReject("Aggregate: incorrect aggregator")

  # [REJECT] The aggregator's validator index is within the committee -- i.e.
  # aggregate_and_proof.aggregator_index in get_beacon_committee(state,
  # aggregate.data.slot, aggregate.data.index).
  if aggregate_and_proof.aggregator_index.ValidatorIndex notin
      get_beacon_committee(
        epochRef, aggregate.data.slot, aggregate.data.index.CommitteeIndex):
    return checkedReject("Aggregate: aggregator's validator index not in committee")

  # 1. [REJECT] The aggregate_and_proof.selection_proof is a valid signature of the
  #    aggregate.data.slot by the validator with index
  #    aggregate_and_proof.aggregator_index.
  #    get_slot_signature(state, aggregate.data.slot, privkey)
  # 2. [REJECT] The aggregator signature, signed_aggregate_and_proof.signature, is valid.
  # 3. [REJECT] The signature of aggregate is valid.

  let
    fork = pool.dag.forkAtEpoch(aggregate.data.slot.epoch)
    genesis_validators_root =
      getStateField(pool.dag.headState.data, genesis_validators_root)

  let deferredCrypto = batchCrypto
                .scheduleAggregateChecks(
                  fork, genesis_validators_root, epochRef,
                  signed_aggregate_and_proof
                )
  if deferredCrypto.isErr():
    return checkedReject(deferredCrypto.error)

  let
    (cryptoFuts, sig) = deferredCrypto.get()

  block:
    # [REJECT] aggregate_and_proof.selection_proof
    var x = await cryptoFuts.slotCheck
    case x
    of BatchResult.Invalid:
      return checkedReject("Aggregate: invalid slot signature")
    of BatchResult.Timeout:
      beacon_aggregates_dropped_queue_full.inc()
      return errIgnore("Aggregate: timeout checking slot signature")
    of BatchResult.Valid:
      discard

  block:
    # [REJECT] The aggregator signature, signed_aggregate_and_proof.signature, is valid.
    var x = await cryptoFuts.aggregatorCheck
    case x
    of BatchResult.Invalid:
      return checkedReject("Aggregate: invalid aggregator signature")
    of BatchResult.Timeout:
      beacon_aggregates_dropped_queue_full.inc()
      return errIgnore("Aggregate: timeout checking aggregator signature")
    of BatchResult.Valid:
      discard

  block:
    # [REJECT] The aggregator signature, signed_aggregate_and_proof.signature, is valid.
    var x = await cryptoFuts.aggregateCheck
    case x
    of BatchResult.Invalid:
      return checkedReject("Aggregate: invalid aggregate signature")
    of BatchResult.Timeout:
      beacon_aggregates_dropped_queue_full.inc()
      return errIgnore("Aggregate: timeout checking aggregate signature")
    of BatchResult.Valid:
      discard

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

  return ok((attesting_indices, sig))

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#attester_slashing
proc validateAttesterSlashing*(
    pool: ExitPool, attester_slashing: AttesterSlashing):
    Result[void, ValidationError] =
  # [IGNORE] At least one index in the intersection of the attesting indices of
  # each attestation has not yet been seen in any prior attester_slashing (i.e.
  # attester_slashed_indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices),
  # verify if any(attester_slashed_indices.difference(prior_seen_attester_slashed_indices))).
  # TODO sequtils2 should be able to make this more reasonable, from asSeq on
  # down, and can sort and just find intersection that way
  if pool.isSeen(attester_slashing):
    return errIgnore(
      "AttesterSlashing: attester-slashed index already attester-slashed")

  # [REJECT] All of the conditions within process_attester_slashing pass
  # validation.
  let attester_slashing_validity =
    check_attester_slashing(pool.dag.headState.data, attester_slashing, {})
  if attester_slashing_validity.isErr:
    return err((ValidationResult.Reject, attester_slashing_validity.error))

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#proposer_slashing
proc validateProposerSlashing*(
    pool: ExitPool, proposer_slashing: ProposerSlashing):
    Result[void, ValidationError] =
  # Not from spec; the rest of NBC wouldn't have correctly processed it either.
  if proposer_slashing.signed_header_1.message.proposer_index > high(int).uint64:
    return errIgnore("ProposerSlashing: proposer-slashed index too high")

  # [IGNORE] The proposer slashing is the first valid proposer slashing
  # received for the proposer with index
  # proposer_slashing.signed_header_1.message.proposer_index.
  if pool.isSeen(proposer_slashing):
    return errIgnore(
      "ProposerSlashing: proposer-slashed index already proposer-slashed")

  # [REJECT] All of the conditions within process_proposer_slashing pass validation.
  let proposer_slashing_validity =
    check_proposer_slashing(pool.dag.headState.data, proposer_slashing, {})
  if proposer_slashing_validity.isErr:
    return err((ValidationResult.Reject, proposer_slashing_validity.error))

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#voluntary_exit
proc validateVoluntaryExit*(
    pool: ExitPool, signed_voluntary_exit: SignedVoluntaryExit):
    Result[void, ValidationError] =
  # [IGNORE] The voluntary exit is the first valid voluntary exit received for
  # the validator with index signed_voluntary_exit.message.validator_index.
  if signed_voluntary_exit.message.validator_index >=
      getStateField(pool.dag.headState.data, validators).lenu64:
    return errIgnore("VoluntaryExit: validator index too high")

  # Given that getStateField(pool.dag.headState, validators) is a seq,
  # signed_voluntary_exit.message.validator_index.int is already valid, but
  # check explicitly if one changes that data structure.
  if pool.isSeen(signed_voluntary_exit):
    return errIgnore("VoluntaryExit: validator index already voluntarily exited")

  # [REJECT] All of the conditions within process_voluntary_exit pass
  # validation.
  let voluntary_exit_validity =
    check_voluntary_exit(
      pool.dag.cfg, pool.dag.headState.data, signed_voluntary_exit, {})
  if voluntary_exit_validity.isErr:
    return err((ValidationResult.Reject, voluntary_exit_validity.error))

  # Send notification about new voluntary exit via callback
  if not(isNil(pool.onVoluntaryExitReceived)):
    pool.onVoluntaryExitReceived(signed_voluntary_exit)

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.8/specs/altair/p2p-interface.md#sync_committee_subnet_id
proc validateSyncCommitteeMessage*(
    dag: ChainDAGRef,
    syncCommitteeMsgPool: SyncCommitteeMsgPool,
    msg: SyncCommitteeMessage,
    subcommitteeIdx: SyncSubcommitteeIndex,
    wallTime: BeaconTime,
    checkSignature: bool):
    Result[(seq[uint64], CookedSig), ValidationError] =
  block:
    # [IGNORE] The signature's slot is for the current slot
    # (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance)
    # i.e. sync_committee_message.slot == current_slot.
    ? check_propagation_slot_range(msg.slot, wallTime)

  # [REJECT] The subnet_id is valid for the given validator
  # i.e. subnet_id in compute_subnets_for_sync_committee(state, sync_committee_message.validator_index).
  # Note this validation implies the validator is part of the broader
  # current sync committee along with the correct subcommittee.
  # This check also ensures that the validator index is in range
  let positionsInSubcommittee = dag.getSubcommitteePositions(
    msg.slot + 1, subcommitteeIdx, msg.validator_index)

  if positionsInSubcommittee.len == 0:
    return errReject(
      "SyncCommitteeMessage: originator not part of sync committee")

  block:
    # [IGNORE] There has been no other valid sync committee signature for the
    # declared slot for the validator referenced by sync_committee_message.validator_index
    # (this requires maintaining a cache of size SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT
    # for each subnet that can be flushed after each slot).
    #
    # Note this validation is per topic so that for a given slot, multiple
    # messages could be forwarded with the same validator_index as long as
    # the subnet_ids are distinct.
    if syncCommitteeMsgPool.isSeen(msg, subcommitteeIdx):
      return errIgnore("SyncCommitteeMessage: duplicate message")

  # [REJECT] The signature is valid for the message beacon_block_root for the
  # validator referenced by validator_index.
  let
    epoch = msg.slot.epoch
    fork = dag.forkAtEpoch(epoch)
    genesisValidatorsRoot = dag.genesisValidatorsRoot
    senderPubKey = dag.validatorKey(msg.validator_index)

  if senderPubKey.isNone():
    return errReject("SyncCommitteeMessage: invalid validator index")

  var cookedSignature = msg.signature.load
  if cookedSignature.isNone:
    return errReject("SyncCommitteeMessage: signature fails to load")

  if checkSignature and
      not verify_sync_committee_message_signature(epoch,
                                                  msg.beacon_block_root,
                                                  fork, genesisValidatorsRoot,
                                                  senderPubKey.get(),
                                                  cookedSignature.get):
    return errReject("SyncCommitteeMessage: signature fails to verify")

  ok((positionsInSubcommittee, cookedSignature.get()))

# https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.8/specs/altair/p2p-interface.md#sync_committee_contribution_and_proof
proc validateSignedContributionAndProof*(
    dag: ChainDAGRef,
    syncCommitteeMsgPool: var SyncCommitteeMsgPool,
    msg: SignedContributionAndProof,
    wallTime: BeaconTime,
    checkSignature: bool):
    Result[CookedSig, ValidationError] =

  # [IGNORE] The contribution's slot is for the current slot
  # (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance)
  # i.e. contribution.slot == current_slot.
  ? check_propagation_slot_range(msg.message.contribution.slot, wallTime)
  let
    aggregatorPubKey = dag.validatorKey(msg.message.aggregator_index)
  if aggregatorPubKey.isNone():
    return errReject("SignedContributionAndProof: invalid aggregator index")

  # [REJECT] The subcommittee index is in the allowed range
  # i.e. contribution.subcommittee_index < SYNC_COMMITTEE_SUBNET_COUNT.
  let committeeIdx = msg.message.contribution.subcommittee_index.validateSyncCommitteeIndexOr:
    return errReject("SignedContributionAndProof: subcommittee index too high")

  # [REJECT] contribution_and_proof.selection_proof selects the validator as an aggregator for the slot
  # i.e. is_sync_committee_aggregator(contribution_and_proof.selection_proof) returns True.
  if not is_sync_committee_aggregator(msg.message.selection_proof):
    return errReject("SignedContributionAndProof: invalid selection_proof")

  block:
    # [IGNORE] The sync committee contribution is the first valid contribution
    # received for the aggregator with index contribution_and_proof.aggregator_index
    # for the slot contribution.slot and subcommittee index contribution.subcommittee_index
    # (this requires maintaining a cache of size SYNC_COMMITTEE_SIZE for this
    #  topic that can be flushed after each slot).
    if syncCommitteeMsgPool.isSeen(msg.message):
      return errIgnore("SignedContributionAndProof: duplicate contribution")

  # [REJECT] The aggregator's validator index is in the declared subcommittee
  # of the current sync committee.
  # i.e. state.validators[contribution_and_proof.aggregator_index].pubkey in
  #      get_sync_subcommittee_pubkeys(state, contribution.subcommittee_index).
  let
    epoch = msg.message.contribution.slot.epoch
    fork = dag.forkAtEpoch(epoch)
    genesisValidatorsRoot = dag.genesisValidatorsRoot

  # [REJECT] The aggregator signature, signed_contribution_and_proof.signature, is valid
  if not verify_signed_contribution_and_proof_signature(msg, fork,
                                                        genesisValidatorsRoot,
                                                        aggregatorPubKey.get()):
    return errReject(
      "SignedContributionAndProof: aggregator signature fails to verify")

  # [REJECT] The contribution_and_proof.selection_proof is a valid signature of the
  # SyncAggregatorSelectionData derived from the contribution by the validator with
  # index contribution_and_proof.aggregator_index.
  if not verify_selection_proof_signature(msg.message, fork,
                                          genesisValidatorsRoot,
                                          aggregatorPubKey.get()):
    return errReject(
      "SignedContributionAndProof: selection proof signature fails to verify")

  # [REJECT] The aggregate signature is valid for the message beacon_block_root
  # and aggregate pubkey derived from the participation info in aggregation_bits
  # for the subcommittee specified by the contribution.subcommittee_index.
  var
    committeeAggKey {.noInit.}: AggregatePublicKey
    initialized = false
    syncCommitteeSlot = msg.message.contribution.slot + 1

  for validatorPubKey in dag.syncCommitteeParticipants(
      syncCommitteeSlot,
      committeeIdx,
      msg.message.contribution.aggregation_bits):
    let validatorPubKey = validatorPubKey.loadWithCache.get
    if not initialized:
      initialized = true
      committeeAggKey.init(validatorPubKey)
    else:
      committeeAggKey.aggregate(validatorPubKey)

  if not initialized:
    # [REJECT] The contribution has participants
    # that is, any(contribution.aggregation_bits).
    return errReject("SignedContributionAndProof: aggregation bits empty")

  let cookedSignature = msg.message.contribution.signature.load
  if cookedSignature.isNone:
    return errReject(
      "SignedContributionAndProof: aggregate signature fails to load")

  if checkSignature and
      not verify_sync_committee_message_signature(
        epoch, msg.message.contribution.beacon_block_root, fork,
        genesisValidatorsRoot, committeeAggKey.finish, cookedSignature.get):
    debug "failing_sync_contribution",
      blk = msg.message.contribution.beacon_block_root,
      slot = syncCommitteeSlot,
      subnet = committeeIdx,
      participants = $(msg.message.contribution.aggregation_bits)

    return errReject(
      "SignedContributionAndProof: aggregate signature fails to verify")

  ok(cookedSignature.get)
