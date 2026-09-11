# beacon_chain
# Copyright (c) 2019-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Status
  chronicles, chronos, metrics,
  results,
  kzg4844/[kzg, kzg_abi],
  # Internals
  ../spec/[
    beaconstate, state_transition_block, forks, helpers, inclusion_list,
    network, signatures, peerdas_helpers],
  ../consensus_object_pools/[
    attestation_pool, blockchain_dag, block_clearance, block_quarantine,
    column_quarantine, envelope_quarantine, execution_payload_pool,
    inclusion_list_pool, light_client_pool, payload_attestation_pool,
    spec_cache, sync_committee_msg_pool, validator_change_pool],
  ../beacon_clock,
  ./batch_validation

from libp2p/protocols/pubsub/errors import ValidationResult
from ../consensus_object_pools/common_tools import
  is_gas_limit_target_compatible

export results, ValidationResult

logScope:
  topics = "gossip_checks"

declareCounter beacon_attestations_dropped_queue_full,
  "Number of attestations dropped because queue is full"

declareCounter beacon_aggregates_dropped_queue_full,
  "Number of aggregates dropped because queue is full"

declareCounter beacon_sync_messages_dropped_queue_full,
  "Number of sync committee messages dropped because queue is full"

declareCounter beacon_contributions_dropped_queue_full,
  "Number of sync committee contributions dropped because queue is full"

declareCounter beacon_data_column_sidecars_dropped_queue_full,
  "Number of data column sidecars dropped because queue is full"

# This result is a little messy in that it returns Result.ok for
# ValidationResult.Accept and an err for the others - this helps transport
# an error message to callers but could arguably be done in an cleaner way.
type
  ValidationError* = (ValidationResult, cstring)

  SeenProposerPreferences* =
    array[MIN_SEED_LOOKAHEAD + 2,
      array[SLOTS_PER_EPOCH, Table[Eth2Digest, ProposerPreferences]]]

template errIgnore*(msg: cstring): untyped =
  err((ValidationResult.Ignore, msg))
template errReject*(msg: cstring): untyped =
  err((ValidationResult.Reject, msg))

template addMissingValid(
    quarantine: var Quarantine, root: Eth2Digest, prefix: static string
): untyped =
  # Add the given root that is required to be valid, returning a reject if it
  # turns out it is not
  let missing = quarantine.addMissing(root)
  if missing.isOk:
    errIgnore(cstring(prefix & " not found"))
  else:
    case missing.error
    of UnviableKind.UnviableFork:
      errIgnore(cstring(prefix & " from unviable fork"))
    of UnviableKind.Invalid:
      errReject(cstring(prefix & " invalid"))

template addMissingValid(
    quarantine: var Quarantine, root, descendant: Eth2Digest, prefix: static string
): untyped =
  # Add the given root that is required to be valid, returning a reject if it
  # turns out it is not - descendant inherits the viability of the parent
  let missing = quarantine.addMissing(root)
  if missing.isOk:
    errIgnore(cstring(prefix & " not found"))
  else:
    # The descendant is unviable the same way as the parent!
    discard quarantine.addUnviable(descendant, missing.error)
    case missing.error
    of UnviableKind.UnviableFork:
      errIgnore(cstring(prefix & " from unviable fork"))
    of UnviableKind.Invalid:
      errReject(cstring(prefix & " invalid"))

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
    timeParams: TimeParams,
    msgSlot: Slot,
    wallTime: BeaconTime): Result[void, ValidationError] =
  let futureSlot =
    (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot(timeParams)
  if not futureSlot.afterGenesis or msgSlot > futureSlot.slot:
    return errIgnore("Attestation slot in the future")

  let pastSlot =
    (wallTime - MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot(timeParams)
  if not pastSlot.afterGenesis:
    return ok()

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/deneb/p2p-interface.md#beacon_attestation_subnet_id
  # "[IGNORE] the epoch of attestation.data.slot is either the current or
  # previous epoch (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e.
  # compute_epoch_at_slot(attestation.data.slot) in
  # (get_previous_epoch(state), get_current_epoch(state))"
  #
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/deneb/p2p-interface.md#beacon_aggregate_and_proof
  # "[IGNORE] the epoch of aggregate.data.slot is either the current or
  # previous epoch (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e.
  # compute_epoch_at_slot(aggregate.data.slot) in
  # (get_previous_epoch(state), get_current_epoch(state))"
  if msgSlot.epoch < pastSlot.slot.epoch.get_previous_epoch:
    return errIgnore("Attestation slot in the past")

  ok()

func check_slot_exact(
    timeParams: TimeParams,
    msgSlot: Slot,
    wallTime: BeaconTime): Result[Slot, ValidationError] =
  let futureSlot =
    (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot(timeParams)
  if not futureSlot.afterGenesis or msgSlot > futureSlot.slot:
    return errIgnore("Sync committee slot in the future")

  if (msgSlot + 1).start_beacon_time(timeParams) +
      MAXIMUM_GOSSIP_CLOCK_DISPARITY < wallTime:
    return errIgnore("Sync committee slot in the past")

  ok(msgSlot)

proc check_beacon_and_target_block(
    pool: var AttestationPool, data: AttestationData):
    Result[BlockSlot, ValidationError] =
  # The block being voted for (data.beacon_block_root) passes validation - by
  # extension, the target block must at that point also pass validation.
  # The target block is returned.
  # We rely on the chain DAG to have been validated, so check for the existence
  # of the block in the pool.
  let blck = pool.dag.getBlockRef(data.beacon_block_root).valueOr:
    return pool.quarantine[].addMissingValid(
      data.beacon_block_root, "AttestationData: block"
    )

  # Not in spec - check that rewinding to the state is sane
  ? check_attestation_block(pool, data.slot, blck)

  # [REJECT] The attestation's target block is an ancestor of the block named
  # in the LMD vote -- i.e.
  # get_checkpoint_block(store, attestation.data.beacon_block_root,
  # attestation.data.target.epoch) == attestation.data.target.root
  # the sanity of target.epoch has been checked by check_attestation_slot_target
  let target = blck.atCheckpoint(data.target).valueOr:
    return errReject("Attestation target is not ancestor of LMD vote block")

  ok(target)

func check_aggregation_count(
    attestation: electra.Attestation | gloas.Attestation,
    singular: bool): Result[void, ValidationError] =
  block:
    let ones = attestation.committee_bits.countOnes()
    if singular and ones != 1:
      return errReject("Attestation must have a single committee bit set")
    elif not singular and ones < 1:
      return errReject("Attestation must have at least one committee bit set")

  block:
    let ones = attestation.aggregation_bits.countOnes()
    if singular and ones != 1:
      return errReject("Attestation must have a single attestation bit set")
    elif not singular and ones < 1:
      return errReject("Attestation must have at least one attestation bit set")

  ok()

func check_attestation_subnet(
    shufflingRef: ShufflingRef, slot: Slot, committee_index: CommitteeIndex,
    subnet_id: SubnetId): Result[void, ValidationError] =
  let
    expectedSubnet = compute_subnet_for_attestation(
      get_committee_count_per_slot(shufflingRef), slot, committee_index)

  if expectedSubnet != subnet_id:
    return errReject("Attestation not on the correct subnet")

  ok()

func check_data_column_sidecar_inclusion_proof(
    data_column_sidecar: ref fulu.DataColumnSidecar):
    Result[void, ValidationError] =
  let res = data_column_sidecar[].verify_data_column_sidecar_inclusion_proof()
  if res.isErr:
    return errReject(res.error)

  ok()

# Gossip Validation
# ----------------------------------------------------------------

# Generally, the following rules apply for gossip validation:
#
# [REJECT]
# This doesn't depend on the wall clock or the exact state of the DAG; it's
# an internal consistency/correctness check only, and effectively never has
# false positives. These don't, for example, arise from timeouts.
#
# [IGNORE]
# This may be intermittent, depend on timing or the current state of the DAG.

template checkedReject(
    msg: cstring, strictVerification: bool): untyped =
  if strictVerification:
    raiseAssert $msg
  errReject(msg)

template checkedReject(
    error: ValidationError, strictVerification: bool): untyped =
  doAssert error[0] == ValidationResult.Reject
  if strictVerification:
    raiseAssert $error[1]
  err(error)

template checkedResult*(
    error: ValidationError, strictVerification: bool): untyped =
  if error[0] == ValidationResult.Reject and strictVerification:
    raiseAssert $error[1]
  err(error)

# ChainDAGRef
template checkedReject(
    dag: ChainDAGRef, msg: cstring): untyped =
  checkedReject(msg, strictVerification in dag.updateFlags)

template checkedReject(
    dag: ChainDAGRef, error: ValidationError): untyped =
  checkedReject(error, strictVerification in dag.updateFlags)

template checkedResult(
    dag: ChainDAGRef, error: ValidationError): untyped =
  checkedResult(error, strictVerification in dag.updateFlags)

# AttestationPool
template checkedReject(
    pool: ref AttestationPool, msg: cstring): untyped =
  pool[].dag.checkedReject(msg)

template checkedReject(
    pool: ref AttestationPool, error: ValidationError): untyped =
  pool[].dag.checkedReject(error)

template checkedResult(
    pool: ref AttestationPool, error: ValidationError): untyped =
  pool[].dag.checkedResult(error)

# ValidatorChangePool
template checkedReject(
    pool: ValidatorChangePool, msg: cstring): untyped =
  pool.dag.checkedReject(msg)

# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/p2p-interface.md#beacon_block
template validateBeaconBlockBellatrix(
    _: phase0.SignedBeaconBlock | altair.SignedBeaconBlock |
       gloas.SignedBeaconBlock | heze.SignedBeaconBlock,
    _: BlockRef): untyped =
  discard

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/bellatrix/p2p-interface.md#beacon_block
template validateBeaconBlockBellatrix(
    signed_beacon_block:
      bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock |
      deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
      fulu.SignedBeaconBlock,
    parent: BlockRef): untyped =
  # If the execution is enabled for the block -- i.e.
  # is_execution_enabled(state, block.body) then validate the following:
  #
  # `is_execution_enabled(state, block.body)` is
  # `is_merge_transition_block(state, block.body) or is_merge_transition_complete(state)` is
  # `(not is_merge_transition_complete(state) and block.body.execution_payload != ExecutionPayload()) or is_merge_transition_complete(state)` is
  # `is_merge_transition_complete(state) or block.body.execution_payload != ExecutionPayload()` is
  # `is_merge_transition_complete(state) or is_execution_block(block)`
  #
  # `is_merge_transition_complete(state)` tests for
  # `state.latest_execution_payload_header != ExecutionPayloadHeader()`, while
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/bellatrix/beacon-chain.md#block-processing
  # shows that `state.latest_execution_payload_header` being default or not is
  # exactly equivalent to whether that block's execution payload is default or
  # not, so test cached block information rather than reconstructing a state.
  let isExecutionEnabled =
    if signed_beacon_block.message.is_execution_block:
      true
    else:
      # If we don't know whether the parent block had execution enabled,
      # assume it didn't. This way, we don't reject here if the timestamp
      # is invalid, and let state transition check the timestamp.
      # This is an edge case, and may be hit in a pathological scenario with
      # checkpoint sync, because the checkpoint block may be unavailable
      # and it could already be the parent of the new block before backfill.
      not dag.loadExecutionBlockHash(parent).get(ZERO_HASH).isZero
  if isExecutionEnabled:
    # [REJECT] The block's execution payload timestamp is correct with respect
    # to the slot -- i.e. execution_payload.timestamp ==
    # compute_timestamp_at_slot(state, block.slot).
    let timestampAtSlot =
      withState(dag.headState):
        dag.timeParams.compute_timestamp_at_slot(
          forkyState.data, signed_beacon_block.message.slot)
    if not (signed_beacon_block.message.body.execution_payload.timestamp ==
        timestampAtSlot):
      discard quarantine[].addUnviable(signed_beacon_block.root, UnviableKind.Invalid)
      return dag.checkedReject(
        "BeaconBlock: mismatched execution payload timestamp")

  # The condition:
  # [REJECT] The block's parent (defined by `block.parent_root`) passes all
  # validation (excluding execution node verification of the
  # `block.body.execution_payload`).
  # cannot occur here, because Nimbus's optimistic sync waits for either
  # `ACCEPTED` or `SYNCING` from the EL to get this far.

# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/p2p-interface.md#beacon_block
template validateBeaconBlockDeneb(
    _: ChainDAGRef,
    _:
      phase0.SignedBeaconBlock | altair.SignedBeaconBlock |
      bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock |
      gloas.SignedBeaconBlock | heze.SignedBeaconBlock,
    _: BeaconTime): untyped =
  discard

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/deneb/p2p-interface.md#beacon_block
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/electra/p2p-interface.md#beacon_block
template validateBeaconBlockDeneb(
    dag: ChainDAGRef,
    signed_beacon_block:
      deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
      fulu.SignedBeaconBlock,
    wallTime: BeaconTime): untyped =
  # [REJECT] The length of KZG commitments is less than or equal to the
  # limitation defined in Consensus Layer -- i.e. validate that
  # len(body.signed_beacon_block.message.blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK
  let blob_params =
    dag.cfg.get_blob_parameters(signed_beacon_block.message.slot.epoch())
  if not (lenu64(signed_beacon_block.message.body.blob_kzg_commitments) <=
      blob_params.MAX_BLOBS_PER_BLOCK):
    return dag.checkedReject("validateBeaconBlockDeneb: too many blob commitments")

template validateBeaconBlockGloas(
    _: ChainDAGRef,
    _: ref Quarantine,
    _: ref EnvelopeQuarantine,
    _:
      phase0.SignedBeaconBlock | altair.SignedBeaconBlock |
      bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock |
      deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
      fulu.SignedBeaconBlock | heze.SignedBeaconBlock): untyped =
  debugHezeComment "this effectively disables gossip validation for Heze blocks currently"
  discard

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/p2p-interface.md#beacon_block
template validateBeaconBlockGloas(
    dag: ChainDAGRef,
    quarantine: ref Quarantine,
    envelopeQuarantine: ref EnvelopeQuarantine,
    signed_beacon_block: gloas.SignedBeaconBlock): untyped =
  template blck: untyped = signed_beacon_block.message
  template bid: untyped = blck.body.signed_execution_payload_bid.message

  let executionParent = block:
    let parentRef = dag.getBlockRef(bid.parent_block_root).valueOr:
      return errIgnore("validateBeaconBlockGloas: parent not yet seen")
    dag.executionParent(parentRef, bid.parent_block_hash).valueOr:
      return errIgnore("validateBeaconBlockGloas: invalid execution parent")

  # - [IGNORE] The block's parent execution payload (defined by
  #   bid.parent_block_hash) has been seen (via gossip or non-gossip sources)
  #   (a client MAY queue blocks for processing once the parent payload is
  #   retrieved).
  #
  # If execution_payload verification of block's execution payload parent by an
  # execution node is complete:
  #
  # - [REJECT] The block's execution payload parent (defined by
  #   bid.parent_block_hash) passes all validation.
  if executionParent.slot.epoch() >= dag.cfg.GLOAS_FORK_EPOCH:
    # The executionParent exists in DAG, so we should check unviable envelope
    # and the database for the validation rules.
    if executionParent.root in envelopeQuarantine.unviable:
      return dag.checkedReject("validateBeaconBlockGloas: unviable execution parent")
    # The genesis block would not have an envelope. Otherwise, we should have
    # the envelope for the execution parent.
    elif executionParent.slot != GENESIS_SLOT and
        not dag.db.containsExecutionPayloadEnvelope(executionParent.root):
      envelopeQuarantine[].addMissing(executionParent.root)
      discard quarantine[].addOrphan(dag.finalizedHead.slot, signed_beacon_block)
      return errIgnore("validateBeaconBlockGloas: parent payload not yet seen")
  else:
    # The executionParent is found from DAG, which is a validated pre-Gloas
    # block. It could also be pre-merge or optimistic block. In either case,
    # they shouldn't be rejected.
    discard

  # [REJECT] The bid's parent (defined by `bid.parent_block_root`) equals the
  # block's parent (defined by `block.parent_root`).
  if not (bid.parent_block_root == blck.parent_root):
    return dag.checkedReject("validateBeaconBlockGloas: parent block mismatch")

  # [REJECT] The length of KZG commitments is less than or equal to the
  # limitation defined in the consensus layer -- i.e. validate that
  # `len(bid.blob_kzg_commitments) <= max_blobs_per_block`.
  if not (bid.blob_kzg_commitments.lenu64 <=
      dag.cfg.get_blob_parameters(blck.slot.epoch).MAX_BLOBS_PER_BLOCK):
    return dag.checkedReject("validateBeaconBlockGloas: too many blob commitments")

  # [REJECT] The counts of `block.body.parent_execution_requests` are within
  # their respective limits.
  template parent_execution_requests: untyped =
    blck.body.parent_execution_requests
  if parent_execution_requests.withdrawals.lenu64 >
      MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many withdrawal requests")
  if parent_execution_requests.consolidations.lenu64 >
      MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many consolidation requests")
  if parent_execution_requests.builder_deposits.lenu64 >
      MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many builder deposit requests")
  if parent_execution_requests.builder_exits.lenu64 >
      MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many builder exit requests")

  # [REJECT] The counts of the block body operations are within their
  # respective limits.
  if blck.body.proposer_slashings.lenu64 > MAX_PROPOSER_SLASHINGS:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many proposer slashings")
  if blck.body.attester_slashings.lenu64 > MAX_ATTESTER_SLASHINGS_ELECTRA:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many attester slashings")
  if blck.body.attestations.lenu64 > MAX_ATTESTATIONS_ELECTRA:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many attestations")
  if blck.body.deposits.lenu64 != 0:
    return dag.checkedReject(
      "validateBeaconBlockGloas: deposits must be empty")
  if blck.body.voluntary_exits.lenu64 > MAX_VOLUNTARY_EXITS:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many voluntary exits")
  if blck.body.bls_to_execution_changes.lenu64 > MAX_BLS_TO_EXECUTION_CHANGES:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many BLS to execution changes")
  if blck.body.payload_attestations.lenu64 > MAX_PAYLOAD_ATTESTATIONS:
    return dag.checkedReject(
      "validateBeaconBlockGloas: too many payload attestations")

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/fulu/p2p-interface.md#data_column_sidecar_subnet_id
proc validateDataColumnSidecar*(
    dag: ChainDAGRef,
    batchCrypto: ref BatchCrypto,
    quarantine: ref Quarantine,
    fuluColumnQuarantine: ref FuluColumnQuarantine,
    data_column_sidecar: ref fulu.DataColumnSidecar,
    wallTime: BeaconTime, subnet_id: uint64
): Future[Result[void, ValidationError]] {.async: (raises: [CancelledError]).} =

  # If the header is invalid, so is the block that shares its block_root ->
  # we can mark those blocks invalid without further processing
  template block_header: untyped = data_column_sidecar[].signed_block_header.message
  # [REJECT] The sidecar is valid as verified by verify_data_column_sidecar(sidecar)
  block:
    let v = verify_data_column_sidecar(dag.cfg, data_column_sidecar[])
    if v.isErr:
      return dag.checkedReject(v.error)

  # [REJECT] The sidecar is for the correct subnet
  # -- i.e. `compute_subnet_for_data_column_sidecar(blob_sidecar.index) == subnet_id`.
  if not (compute_subnet_for_data_column_sidecar(data_column_sidecar[].index) == subnet_id):
    return dag.checkedReject("DataColumnSidecar: The sidecar is not for the correct subnet")

  # [IGNORE] The sidecar is not from a future slot
  # (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance) -- i.e. validate that
  # `block_header.slot <= current_slot`(a client MAY queue future sidecars for
  # processing at the appropriate slot).
  if not (block_header.slot <=
      (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero(dag.timeParams)):
    return errIgnore("DataColumnSidecar: slot too high")

  # [IGNORE] The sidecar is from a slot greater than the latest
  # finalized slot -- i.e. validate that `block_header.slot >
  # compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)`
  if not (block_header.slot > dag.finalizedHead.slot):
    return errIgnore("DataColumnSidecar: slot already finalized")

  # [IGNORE] The sidecar is the first sidecar for the tuple
  # (block_header.slot, block_header.proposer_index, data_column_sidecar.index)
  # with valid header signature, sidecar inclusion proof, and kzg proof.
  let block_root = hash_tree_root(block_header)
  if fuluColumnQuarantine[].hasSidecar(
      block_root, block_header.slot, block_header.proposer_index,
      data_column_sidecar[].index):
    return errIgnore("DataColumnSidecar: already have valid data column from same proposer")

  # [REJECT] The sidecar's `kzg_commitments` inclusion proof is valid as verified by
  # `verify_data_column_sidecar_inclusion_proof(sidecar)`.
  block:
    let v = check_data_column_sidecar_inclusion_proof(data_column_sidecar)
    if v.isErr:
      return dag.checkedReject(v.error)

  # [IGNORE] The sidecar's block's parent (defined by
  # `block_header.parent_root`) has been seen (via both gossip and
  # non-gossip sources) (a client MAY queue sidecars for processing
  # once the parent block is retrieved).
  #
  # [REJECT] The sidecar's block's parent (defined by
  # `block_header.parent_root`) passes validation.
  let parent = dag.getBlockRef(block_header.parent_root).valueOr:
    return quarantine[].addMissingValid(
      block_header.parent_root, block_root, "DataColumnSidecar: parent"
    )

  # [REJECT] The sidecar is from a higher slot than the sidecar's
  # block's parent (defined by `block_header.parent_root`).
  if not (block_header.slot > parent.bid.slot):
    discard quarantine[].addUnviable(block_root, UnviableKind.Invalid)
    return dag.checkedReject("DataColumnSidecar: slot lower than parents'")

  # [REJECT] The current finalized_checkpoint is an ancestor of the sidecar's
  # block -- i.e. `get_checkpoint_block(store, block_header.parent_root,
  # store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root`.
  let
    finalized_checkpoint = dag.headState.finalized_checkpoint
    ancestor = get_ancestor(parent, finalized_checkpoint.epoch.start_slot)

  if ancestor.isNil:
    # This shouldn't happen: we should always be able to trace the parent back
    # to the finalized checkpoint (else it wouldn't be in the DAG)
    return errIgnore("DataColumnSidecar: Can't find ancestor")

  if not (
      finalized_checkpoint.root == ancestor.root or
      finalized_checkpoint.root.isZero):
    discard quarantine[].addUnviable(block_root, UnviableKind.Invalid)
    return dag.checkedReject(
      "DataColumnSidecar: Finalized checkpoint not an ancestor")

  # [REJECT] The sidecar is proposed by the expected `proposer_index`
  # for the block's slot in the context of the current shuffling
  # (defined by `block_header.parent_root`/`block_header.slot`).
  # If the proposer_index cannot immediately be verified against the expected
  # shuffling, the sidecar MAY be queued for later processing while proposers
  # for the block's branch are calculated -- in such a case do not
  # REJECT, instead IGNORE this message.
  # [REJECT] The proposer signature of `data_column_sidecar.signed_block_header`,
  # is valid with respect to the `block_header.proposer_index` pubkey.

  dag.verifyBlockProposer(
    parent, block_header.slot, block_header.proposer_index, block_root,
    data_column_sidecar[].signed_block_header.signature,
    quarantine.latest_sidecar_signatures
  ).isOkOr:
    if error.invalid:
      discard quarantine[].addUnviable(block_root, UnviableKind.Invalid)
    return dag.checkedReject(error.msg)

  # Cache the verified (block_root, signature) pair for future fast-path checks
  quarantine.latest_sidecar_signatures.put(
    (block_root, data_column_sidecar[].signed_block_header.signature), ())

  # [REJECT] The sidecar's column data is valid as
  # verified by `verify_data_column_kzg_proofs(sidecar)`
  case await batchCrypto.scheduleDataColumnSidecarCheck(data_column_sidecar)
  of BatchResult.Invalid:
    return dag.checkedReject("DataColumnSidecar: validation failed")
  of BatchResult.Timeout:
    beacon_data_column_sidecars_dropped_queue_full.inc()
    return errIgnore("DataColumnSidecar: timeout checking KZG proofs")
  of BatchResult.Valid:
    discard # keep going only in this case

  # The KZG proof check yielded - re-check that no other copy of this sidecar
  # was verified and stored in the meantime
  if fuluColumnQuarantine[].hasVerifiedSidecar(
      block_root, data_column_sidecar[].index):
    return errIgnore("DataColumnSidecar: already have valid data column")

  # Send notification about new data column sidecar via callback
  let onDataColumnSidecarCallback =
    fuluColumnQuarantine[].onDataColumnSidecarCallback()

  if not(isNil(onDataColumnSidecarCallback)):
    onDataColumnSidecarCallback DataColumnSidecarInfoObject(
      block_root: block_root,
      index: data_column_sidecar[].index,
      slot: data_column_sidecar[].signed_block_header.message.slot,
      kzg_commitments: data_column_sidecar[].kzg_commitments.asSeq)

  # Notify with the full sidecar so the EL (out of spec)
  # getBlobs service can derive header/commitments/inclusion proof when the
  # block has not yet been seen via gossip.
  let onFuluColumnAddedCallback =
    fuluColumnQuarantine[].onFuluDataColumnSidecarAddedCallback()
  if not(isNil(onFuluColumnAddedCallback)):
    onFuluColumnAddedCallback newClone(data_column_sidecar)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/p2p-interface.md#modified-data_column_sidecar_subnet_id
proc validateDataColumnSidecar*(
    dag: ChainDAGRef,
    batchCrypto: ref BatchCrypto,
    quarantine: ref Quarantine,
    gloasColumnQuarantine: ref GloasColumnQuarantine,
    executionPayloadBidPool: ref ExecutionPayloadBidPool,
    data_column_sidecar: ref gloas.DataColumnSidecar,
    wallTime: BeaconTime, subnet_id: uint64
): Future[Result[void, ValidationError]] {.async: (raises: [CancelledError]).} =

  template blockRoot(): auto = data_column_sidecar[].beacon_block_root

  if data_column_sidecar[].index >= NUMBER_OF_COLUMNS:
    return dag.checkedReject(
      "DataColumnSidecar: index exceeds the NUMBER_OF_COLUMNS")

  # [REJECT] The sidecar is for the correct subnet -- i.e.
  # `compute_subnet_for_data_column_sidecar(sidecar.index) == subnet_id`.
  #
  # Keep before block-seen [IGNORE] so the [REJECT] occurs properly
  if not (compute_subnet_for_data_column_sidecar(data_column_sidecar[].index) ==
      subnet_id):
    return dag.checkedReject("DataColumnSidecar: not for correct subnet")

  # [IGNORE] A valid block for the sidecar's `slot` has been seen (via gossip or
  # non-gossip sources). If not yet seen, a client SHOULD queue the sidecar for
  # deferred validation and possible processing once the block is received or
  # retrieved.
  let blck =
    block:
      let
        blckRef = dag.getBlockRef(blockRoot).valueOr:
          return errIgnore("DataColumnSidecar: block not yet seen")
        forkedBlock = dag.getForkedBlock(blckRef.bid).valueOr:
          info "block is missing, database corrupt?",
            root = shortLog(blockRoot)
          return errIgnore("DataColumnSidecar: block not yet seen")
      withBlck(forkedBlock):
        when consensusFork == ConsensusFork.Gloas:
          forkyBlck
        elif consensusFork == ConsensusFork.Heze:
          debugHezeComment "..."
          return errIgnore("DataColumnSidecar: block in incorrect fork")
        else:
          return errIgnore("DataColumnSidecar: block in incorrect fork")

  # [REJECT] The sidecar's `slot` matches the slot of the block with root
  # `beacon_block_root`.
  if not (blck.message.slot == data_column_sidecar[].slot and
      blck.root == data_column_sidecar[].beacon_block_root):
    return dag.checkedReject("DataColumnSidecar: slot mismatched")

  # [REJECT] The sidecar is valid as verified by
  # `verify_data_column_sidecar(sidecar, bid.blob_kzg_commitments)`.
  template bid(): auto = blck.message.body.signed_execution_payload_bid.message
  block:
    let v = verify_data_column_sidecar(
      dag.cfg, data_column_sidecar[], bid.blob_kzg_commitments)
    if v.isErr:
      return dag.checkedReject(v.error)

  # [REJECT] The sidecar's column data is valid as verified by
  # `verify_data_column_sidecar_kzg_proofs(sidecar, bid.blob_kzg_commitments)`.
  case await batchCrypto.scheduleDataColumnSidecarCheck(
      data_column_sidecar, bid.blob_kzg_commitments.asSeq)
  of BatchResult.Invalid:
    return dag.checkedReject("DataColumnSidecar: validation failed")
  of BatchResult.Timeout:
    beacon_data_column_sidecars_dropped_queue_full.inc()
    return errIgnore("DataColumnSidecar: timeout checking KZG proofs")
  of BatchResult.Valid:
    discard # keep going only in this case

  # [IGNORE] The sidecar is the first sidecar for the tuple
  # `(sidecar.beacon_block_root, sidecar.index)` with valid kzg proof.
  # An unverified sidecar at the same index (queued before its block was
  # seen) does not count: this one has a valid kzg proof and supersedes it.
  if gloasColumnQuarantine[].hasVerifiedSidecar(
      blockRoot, data_column_sidecar[].index):
    return errIgnore("DataColumnSidecar: already have valid data column")

  # Send notification about new data column sidecar via callback
  let onDataColumnSidecarCallback =
    gloasColumnQuarantine[].onDataColumnSidecarCallback()

  if not(isNil(onDataColumnSidecarCallback)):
    onDataColumnSidecarCallback DataColumnSidecarInfoObject(
      block_root: blockRoot,
      index: data_column_sidecar[].index,
      slot: data_column_sidecar[].slot,
      kzg_commitments: bid.blob_kzg_commitments)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/phase0/p2p-interface.md#beacon_block
# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/bellatrix/p2p-interface.md#beacon_block
# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/p2p-interface.md#beacon_block
proc validateBeaconBlock*(
    dag: ChainDAGRef, quarantine: ref Quarantine,
    envelopeQuarantine: ref EnvelopeQuarantine,
    signed_beacon_block: ForkySignedBeaconBlock,
    wallTime: BeaconTime, flags: UpdateFlags): Result[void, ValidationError] =
  # In general, checks are ordered from cheap to expensive. Especially, crypto
  # verification could be quite a bit more expensive than the rest. This is an
  # externally easy-to-invoke function by tossing network packets at the node.

  # [IGNORE] The block is not from a future slot (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that
  # signed_beacon_block.message.slot <= current_slot (a client MAY queue future
  # blocks for processing at the appropriate slot).
  if not (signed_beacon_block.message.slot <=
      (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero(dag.timeParams)):
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
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/phase0/validator.md#proposer-slashing
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
  if dag.containsForkBlock(signed_beacon_block.root):
    # The gossip algorithm itself already does one round of hashing to find
    # already-seen data, but it is fairly aggressive about forgetting about
    # what it has seen already
    # "[IGNORE] The block is the first block ..."
    return errIgnore("BeaconBlock: already seen")

  let
    slotBlock = getBlockIdAtSlot(dag, signed_beacon_block.message.slot)

  if slotBlock.isSome() and slotBlock.get().isProposed() and
      slotBlock.get().bid.slot == signed_beacon_block.message.slot:
    let curBlock = dag.getForkedBlock(slotBlock.get().bid)
    if curBlock.isOk():
      if curBlock[].proposer_index == signed_beacon_block.message.proposer_index and
          curBlock[].signature.toRaw() != signed_beacon_block.signature.toRaw():
        return errIgnore("BeaconBlock: already proposed in the same slot")

  # [IGNORE] The block's parent (defined by block.parent_root) has been seen
  # (via both gossip and non-gossip sources) (a client MAY queue blocks for
  # processing once the parent block is retrieved).
  #
  # [REJECT] The block's parent (defined by block.parent_root)
  # passes validation.
  let parent = dag.getBlockRef(signed_beacon_block.message.parent_root).valueOr:
    # When the parent is missing, we can't validate the block and instead queue
    # it for later processing
    quarantine[].addOrphan(dag.finalizedHead.slot, signed_beacon_block).isOkOr:
      # Queueing failed because the parent was unviable - this means this block
      # is unviable as well, for the same reason
      case error
      of UnviableKind.Invalid:
        when typeof(signed_beacon_block).kind <= ConsensusFork.Fulu:
          # These checks are removed in Gloas.
          if signed_beacon_block.message.is_execution_block:
            # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/p2p-interface.md#beacon_block
            #
            # Blocks with execution enabled will be permitted to propagate
            # regardless of the validity of the execution payload. This prevents
            # network segregation between optimistic and non-optimistic nodes.
            #
            # If execution_payload verification of block's parent by an execution
            # node is not complete:
            #
            # - [REJECT] The block's parent (defined by `block.parent_root`) passes
            #   all validation (excluding execution node verification of the
            #   `block.body.execution_payload`).
            #
            # otherwise:
            #
            # - [IGNORE] The block's parent (defined by `block.parent_root`) passes
            #   all validation (including execution node verification of the
            #   `block.body.execution_payload`).

            # Implementation restrictions:
            #
            # - We know that the parent was marked unviable, but don't know
            #   whether it was marked unviable due to consensus (REJECT) or
            #   execution (IGNORE) verification failure. We err on the IGNORE side.
            #   TODO track this as a separate UnviableKind
            return errIgnore("BeaconBlock: parent invalid")
          else:
            return errReject("BeaconBlock: parent invalid")
      of UnviableKind.UnviableFork:
        return errIgnore("BeaconBlock: parent from unviable fork")

    debug "Block quarantined",
      blockRoot = shortLog(signed_beacon_block.root),
      blck = shortLog(signed_beacon_block.message),
      signature = shortLog(signed_beacon_block.signature)

    return errIgnore("BeaconBlock: parent not found")

  # Continues block parent validity checking in optimistic case, where it does
  # appear as a `BlockRef` (and not handled above) but isn't usable for gossip
  # validation.
  validateBeaconBlockBellatrix(signed_beacon_block, parent)

  dag.validateBeaconBlockDeneb(signed_beacon_block, wallTime)

  dag.validateBeaconBlockGloas(
    quarantine, envelopeQuarantine, signed_beacon_block)

  # [REJECT] The block is from a higher slot than its parent.
  if not (signed_beacon_block.message.slot > parent.bid.slot):
    return dag.checkedReject(
      "BeaconBlock: block not from higher slot than its parent")

  # [REJECT] The current finalized_checkpoint is an ancestor of block -- i.e.
  # get_ancestor(store, block.parent_root,
  # compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
  # store.finalized_checkpoint.root
  let
    finalized_checkpoint = dag.headState.finalized_checkpoint
    ancestor = get_ancestor(parent, finalized_checkpoint.epoch.start_slot)

  if ancestor.isNil:
    # This shouldn't happen: we should always be able to trace the parent back
    # to the finalized checkpoint (else it wouldn't be in the DAG)
    return errIgnore("BeaconBlock: Can't find ancestor")

  if not (
      finalized_checkpoint.root == ancestor.root or
      finalized_checkpoint.root.isZero):
    discard quarantine[].addUnviable(signed_beacon_block.root, UnviableKind.Invalid)
    return dag.checkedReject(
      "BeaconBlock: Finalized checkpoint not an ancestor")

  # [REJECT] The block is proposed by the expected proposer_index for the
  # block's slot in the context of the current shuffling (defined by
  # parent_root/slot). If the proposer_index cannot immediately be verified
  # against the expected shuffling, the block MAY be queued for later
  # processing while proposers for the block's branch are calculated -- in such
  # a case do not REJECT, instead IGNORE this message.
  # [REJECT] The proposer signature, signed_beacon_block.signature, is valid
  # with respect to the proposer_index pubkey.
  dag.verifyBlockProposer(
    parent, signed_beacon_block.message.slot,
    signed_beacon_block.message.proposer_index, signed_beacon_block.root,
    signed_beacon_block.signature,
    quarantine.latest_sidecar_signatures
  ).isOkOr:
    if error.invalid:
      discard quarantine[].addUnviable(signed_beacon_block.root, UnviableKind.Invalid)
    return dag.checkedReject(error.msg)

  # Cache the verified (block_root, signature) pair for future fast-path checks
  quarantine.latest_sidecar_signatures.put(
    (signed_beacon_block.root, signed_beacon_block.signature), ())

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/p2p-interface.md#new-execution_payload
proc validateExecutionPayload*(
    dag: ChainDAGRef, quarantine: ref Quarantine,
    envelopeQuarantine: ref EnvelopeQuarantine,
    signed_execution_payload_envelope: SignedExecutionPayloadEnvelope,
    wallTime: BeaconTime): Result[void, ValidationError] =
  template envelope: untyped = signed_execution_payload_envelope.message

  # [IGNORE] The node has not seen another valid envelope for this block root
  # from this builder
  #
  # Validation of an envelope requires a valid block. There is a check to ensure
  # that the builder index are the same from the envelope and the bid from the
  # block. Meaning that checking builder index here would not be helpful due to
  # the check later.
  if dag.db.containsExecutionPayloadEnvelope(envelope.beacon_block_root):
    return errIgnore(
      "ExecutionPayload: already seen envelope for this block root from this builder")

  # [IGNORE] The envelope's block root has been seen (via gossip or non-gossip
  # sources) (MAY be queued until block is retrieved)
  # [REJECT] The envelope's block passes validation
  let blckRef = dag.getBlockRef(envelope.beacon_block_root).valueOr:
    if envelope.beacon_block_root in quarantine.unviable or
        quarantine[].checkOrphan(envelope.beacon_block_root):
      return dag.checkedReject(
        "ExecutionPayload: envelope's block failed validation")
    # No matching block can exist: blocks [IGNORE] future slots.
    if envelope.slot <=
        (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero(dag.timeParams):
      # TODO: when the envelope arrives before its block, we return IGNORE
      # which prevents it from being forwarded to peers. The envelope is
      # quarantined and processed locally once the block arrives, but never
      # re-gossiped to peers who may also be missing it.
      discard quarantine[].addMissing(envelope.beacon_block_root)
      envelopeQuarantine[].addOrphan(
        dag.finalizedHead.slot, signed_execution_payload_envelope)
    return errIgnore("ExecutionPayload: envelope's block has not been seen")

  # [IGNORE] The envelope is from a slot greater than or equal to the latest
  # finalized slot
  if not (envelope.slot >= dag.finalizedHead.slot):
    return errIgnore(
      "ExecutionPayload: envelope is from a slot before the latest finalized slot")

  let (blockSlot, proposerIndex, bid) =
    block:
      let forkedBlock = dag.getForkedBlock(blckRef.bid).valueOr:
        return dag.checkedReject(
          "ExecutionPayload: envelope's block failed validation")
      withBlck(forkedBlock):
        when consensusFork >= ConsensusFork.Gloas:
          template forkyBid: untyped =
            forkyBlck.message.body.signed_execution_payload_bid.message
          (forkyBlck.message.slot, forkyBlck.message.proposer_index,
           (builder_index: forkyBid.builder_index,
            block_hash: forkyBid.block_hash,
            execution_requests_root: forkyBid.execution_requests_root))
        else:
          return dag.checkedReject("ExecutionPayload: invalid fork")

  # [REJECT] The block's slot matches the payload's slot number
  if not (blockSlot == envelope.payload.slot_number):
    return dag.checkedReject(
      "ExecutionPayload: block's slot does not match payload's slot number")

  # [REJECT] The envelope is from the builder committed to by the bid
  if not (envelope.builder_index == bid.builder_index):
    return dag.checkedReject(
      "ExecutionPayload: envelope's builder index does not match the bid's builder index")

  # [REJECT] The payload's block hash matches the bid's block hash
  if not (envelope.payload.block_hash == bid.block_hash):
    return dag.checkedReject(
      "ExecutionPayload: payload's block hash does not match the bid's block hash")

  # [REJECT] The envelope's execution requests root matches the bid's execution
  # requests root
  if not (hash_tree_root(envelope.execution_requests) ==
      bid.execution_requests_root):
    return dag.checkedReject(
      "ExecutionPayload: envelope's execution requests root does not match the bid's")

  # [REJECT] The execution request counts are within their limits
  template reqs: untyped = envelope.execution_requests
  if reqs.deposits.lenu64 > MAX_DEPOSIT_REQUESTS_PER_PAYLOAD:
    return dag.checkedReject("ExecutionPayload: too many deposit requests")
  if reqs.withdrawals.lenu64 > MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD:
    return dag.checkedReject("ExecutionPayload: too many withdrawal requests")
  if reqs.consolidations.lenu64 > MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD:
    return dag.checkedReject(
      "ExecutionPayload: too many consolidation requests")
  if reqs.builder_deposits.lenu64 > MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD:
    return dag.checkedReject(
      "ExecutionPayload: too many builder deposit requests")
  if reqs.builder_exits.lenu64 > MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD:
    return dag.checkedReject("ExecutionPayload: too many builder exit requests")

  # [REJECT] The number of withdrawals is within the limit
  if envelope.payload.withdrawals.lenu64 > MAX_WITHDRAWALS_PER_PAYLOAD:
    return dag.checkedReject("ExecutionPayload: too many withdrawals")

  # [REJECT] The envelope signature is valid
  # TODO: headState may not match the envelope's fork during extended
  # non-finality.
  let builderKey =
    withState(dag.headState):
      when consensusFork >= ConsensusFork.Gloas:
        if bid.builder_index == BUILDER_INDEX_SELF_BUILD:
          forkyState.data.validators.item(proposerIndex).pubkey
        else:
          if bid.builder_index >= forkyState.data.builders.lenu64:
            return dag.checkedReject("ExecutionPayload: unknown builder")
          forkyState.data.builders.item(bid.builder_index).pubkey
      else:
        return dag.checkedReject("ExecutionPayload: invalid fork")
  if not verify_execution_payload_envelope_signature(
      dag.forkAtEpoch(envelope.slot.epoch),
      dag.genesis_validators_root,
      envelope.slot.epoch,
      signed_execution_payload_envelope.message,
      builderKey,
      signed_execution_payload_envelope.signature):
    return dag.checkedReject("ExecutionPayload: invalid envelope signature")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/electra/p2p-interface.md#beacon_attestation_subnet_id
proc validateAttestation*(
    pool: ref AttestationPool,
    batchCrypto: ref BatchCrypto,
    envelopeQuarantine: ref EnvelopeQuarantine,
    attestation: SingleAttestation,
    wallTime: BeaconTime,
    subnet_id: SubnetId,
    checkSignature: bool,
): Future[
    Result[
      tuple[
        attester_index: ValidatorIndex,
        beacon_committee_len, index_in_committee: int,
        sig: CookedSig,
      ],
      ValidationError,
    ]
] {.async: (raises: [CancelledError]).} =
  # Some of the checks below have been reordered compared to the spec, to
  # perform the cheap checks first - in particular, we want to avoid loading
  # an `EpochRef` and checking signatures. This reordering might lead to
  # different IGNORE/REJECT results in turn affecting gossip scores.

  # [REJECT] The attestation's epoch matches its target -- i.e.
  # attestation.data.target.epoch ==
  # compute_epoch_at_slot(attestation.data.slot)
  let
    slot = check_attestation_slot_target(attestation.data).valueOr:
      return pool.checkedReject(error)
    consensusFork = pool.dag.cfg.consensusForkAtEpoch(slot.epoch)

  # Sanity check - this check is implied by the new attestation type that
  # doesn't appear until Electra
  if consensusFork < ConsensusFork.Electra:
    return pool.checkedReject("SingleAttestation: pre-Electra fork")

  # [IGNORE]
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/deneb/p2p-interface.md#beacon_attestation_subnet_id
  # modifies this for Deneb and newer forks.
  ?pool.dag.timeParams.check_propagation_slot_range(slot, wallTime)

  # The block being voted for (attestation.data.beacon_block_root) has been seen
  # (via both gossip and non-gossip sources) (a client MAY queue attestations
  # for processing once block is retrieved).
  # [REJECT] The block being voted for (attestation.data.beacon_block_root)
  # passes validation.
  # [IGNORE] if block is unseen so far and enqueue it in missing blocks
  let target = check_beacon_and_target_block(pool[], attestation.data).valueOr:
    return pool.checkedResult(error) # [IGNORE/REJECT]

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/p2p-interface.md#beacon_attestation_subnet_id
  if consensusFork >= ConsensusFork.Gloas:
    # [REJECT] attestation.data.index < 2
    if not (attestation.data.index < 2):
      return pool.checkedReject("SingleAttestation: index must be < 2 in Gloas")

    # [REJECT] attestation.data.index == 0 if block.slot == attestation.data.slot
    if target.blck.bid.slot == attestation.data.slot:
      if not (attestation.data.index == 0):
        return pool.checkedReject(
          "SingleAttestation: same-slot attestation must have index 0"
        )
    # [REJECT] If attestation.data.index == 1 (payload present for a past block),
    # the execution payload for block passes validation.
    # [IGNORE] When attestation.data.index == 1 (payload present for a past block),
    # the execution payload for block has been seen
    if attestation.data.index == 1:
      template block_root: untyped = attestation.data.beacon_block_root
      if not pool.dag.db.containsExecutionPayloadEnvelope(block_root) and
          not envelopeQuarantine[].hasOrphan(block_root):
        return errIgnore(
          "SingleAttestation: execution payload not yet seen")
  else:
    # [REJECT] attestation.data.index == 0
    if not (attestation.data.index == 0):
      return pool.checkedReject("SingleAttestation: attestation.data.index != 0")

  let validator_index = ValidatorIndex.init(attestation.attester_index).valueOr:
    return errReject("SingleAttestation: attester index too high")

  # There has been no other valid attestation seen on an attestation subnet
  # that has an identical `attestation.data.target.epoch` and participating
  # validator index.
  # Slightly modified to allow only newer attestations than were previously
  # seen (no point in propagating older votes)
  if (pool.nextAttestationEpoch.lenu64 > validator_index.uint64) and
      pool.nextAttestationEpoch[validator_index].subnet >
        attestation.data.target.epoch:
    return errIgnore("SingleAttestation: Validator has already voted in epoch")

  # [REJECT] The signature of `attestation` is valid.
  # In the spec, is_valid_indexed_attestation is used to verify the signature -
  # here, we do a batch verification instead
  var sigchecked = false
  let sig = attestation.signature.load().valueOr:
    return pool.checkedReject("SingleAttestation: unable to load signature")

  template doSigCheck(): untyped =
    let
      fork = pool.dag.forkAtEpoch(attestation.data.slot.epoch)
      pubkey = pool.dag.validatorKey(validator_index).valueOr:
        # can't happen, in theory, because we checked the aggregator index above
        return errIgnore("SingleAttestation: cannot find validator pubkey")

    sigchecked = true
    if checkSignature:
      # Attestation signatures are batch-verified
      let x =
        await batchCrypto.scheduleAttestationCheck(fork, attestation.data, pubkey, sig)
      case x
      of BatchResult.Invalid:
        return pool.checkedReject("SingleAttestation: invalid signature")
      of BatchResult.Timeout:
        beacon_attestations_dropped_queue_full.inc()
        return errIgnore("SingleAttestation: timeout checking signature")
      of BatchResult.Valid:
        discard # keep going only in this case

  # The following rule follows implicitly from that we clear out any
  # unviable blocks from the chain dag:
  #
  # [IGNORE] The current finalized_checkpoint is an ancestor of the block
  # defined by attestation.data.beacon_block_root -- i.e.
  # get_checkpoint_block(store, attestation.data.beacon_block_root,
  # store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root
  let shufflingRef = pool.dag.findShufflingRef(target.blck.bid, target.slot.epoch).valueOr:
    # getShufflingRef might be slow here, so first try to eliminate by
    # signature check
    doSigCheck()
    pool.dag.getShufflingRef(target.blck, target.slot.epoch, false).valueOr:
      # Target is verified - shouldn't happen
      warn "No shuffling for SingleAttestation - report bug",
        attestation = shortLog(attestation), target = shortLog(target)
      return errIgnore("SingleAttestation: no shuffling")

  # [REJECT] The committee index is within the expected range -- i.e.
  # data.index < get_committee_count_per_slot(state, data.target.epoch).
  let committee_index = shufflingRef.get_committee_index(attestation.committee_index).valueOr:
    return
      pool.checkedReject("SingleAttestation: committee index not within expected range")

  # [REJECT] The attester is a member of the committee -- i.e.
  # attestation.attester_index in
  # get_beacon_committee(state, attestation.data.slot, index).
  let
    beacon_committee =
      get_beacon_committee(shufflingRef, attestation.data.slot, committee_index)
    index_in_committee = find(beacon_committee, validator_index)
  if index_in_committee < 0:
    return
      pool.checkedReject("SingleAttestation: attester index not in beacon committee")

  # [REJECT] The attestation is for the correct subnet -- i.e.
  # compute_subnet_for_attestation(committees_per_slot,
  # attestation.data.slot, attestation.data.index) == subnet_id, where
  # committees_per_slot = get_committee_count_per_slot(state,
  # attestation.data.target.epoch), which may be pre-computed along with the
  # committee information for the signature check.
  block:
    let v = check_attestation_subnet(
      shufflingRef, attestation.data.slot, committee_index, subnet_id
    )
    if v.isErr(): # [REJECT]
      return pool.checkedReject(v.error)

  # In the spec, is_valid_indexed_attestation is used to verify the signature -
  # here, we do a batch verification instead
  if not sigchecked:
    # findShufflingRef did find a cached ShufflingRef, which means the early
    # signature check was skipped, so do it now.
    doSigCheck()

  # Only valid attestations go in the list, which keeps validator_index
  # in range
  if not (pool.nextAttestationEpoch.lenu64 > validator_index.uint64):
    pool.nextAttestationEpoch.setLen(validator_index.int + 1)
  pool.nextAttestationEpoch[validator_index].subnet = attestation.data.target.epoch + 1

  ok((validator_index, beacon_committee.len, index_in_committee, sig))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/p2p-interface.md#beacon_aggregate_and_proof
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/electra/p2p-interface.md#beacon_aggregate_and_proof
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/p2p-interface.md#beacon_aggregate_and_proof
proc validateAggregate*(
    pool: ref AttestationPool,
    batchCrypto: ref BatchCrypto,
    envelopeQuarantine: ref EnvelopeQuarantine,
    signedAggregateAndProof:
      electra.SignedAggregateAndProof | gloas.SignedAggregateAndProof,
    wallTime: BeaconTime,
    checkSignature = true,
    checkCover = true,
): Future[
    Result[
      tuple[attesting_indices: seq[ValidatorIndex], sig: CookedSig], ValidationError
    ]
] {.async: (raises: [CancelledError]).} =
  # Some of the checks below have been reordered compared to the spec, to
  # perform the cheap checks first - in particular, we want to avoid loading
  # an `EpochRef` and checking signatures. This reordering might lead to
  # different IGNORE/REJECT results in turn affecting gossip scores.

  template aggregate_and_proof(): untyped =
    signedAggregateAndProof.message

  template aggregate(): untyped =
    aggregate_and_proof.aggregate

  # [REJECT] The aggregate attestation's epoch matches its target -- i.e.
  # `aggregate.data.target.epoch == compute_epoch_at_slot(aggregate.data.slot)`
  let
    slot = check_attestation_slot_target(aggregate.data).valueOr:
      return pool.checkedReject(error)
    consensusFork = pool.dag.cfg.consensusForkAtEpoch(slot.epoch)

  # Sanity check - this check is implied by the new attestation type that
  # doesn't appear until Electra
  if consensusFork < ConsensusFork.Electra:
    return pool.checkedReject("Aggregate: pre-Electra fork")

  # [IGNORE] aggregate.data.slot is within the last
  # ATTESTATION_PROPAGATION_SLOT_RANGE slots (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. aggregate.data.slot +
  # ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate.data.slot
  #
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/deneb/p2p-interface.md#beacon_aggregate_and_proof
  # modifies this for Deneb and newer forks.
  ?pool.dag.timeParams.check_propagation_slot_range(slot, wallTime)

  let aggregator_index = ValidatorIndex.init(aggregate_and_proof.aggregator_index).valueOr:
    return pool.checkedReject("Aggregate: invalid aggregator index")

  # [IGNORE] The aggregate is the first valid aggregate received for the
  # aggregator with index aggregate_and_proof.aggregator_index for the epoch
  # aggregate.data.target.epoch.
  # Slightly modified to allow only newer attestations than were previously
  # seen (no point in propagating older votes)
  if (pool.nextAttestationEpoch.lenu64 > aggregator_index.uint64) and
      pool.nextAttestationEpoch[aggregator_index].aggregate >
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
  check_aggregation_count(aggregate, singular = false).isOkOr:
    return pool.checkedReject(error) # [REJECT]

  # [REJECT] The block being voted for (aggregate.data.beacon_block_root)
  # passes validation.
  # [IGNORE] if block is unseen so far and enqueue it in missing blocks
  let target = check_beacon_and_target_block(pool[], aggregate.data).valueOr:
    return pool.checkedResult(error) # [IGNORE/REJECT]

  if consensusFork >= ConsensusFork.Gloas:
    # [REJECT] aggregate.data.index < 2
    if not (aggregate.data.index < 2):
      return pool.checkedReject("Aggregate: index must be < 2 in Gloas")

    # [REJECT] aggregate.data.index == 0 if block.slot == aggregate.data.slot
    if target.blck.bid.slot == aggregate.data.slot:
      if not (aggregate.data.index == 0):
        return pool.checkedReject("Aggregate: same-slot aggregate must have index 0")

    # [REJECT] If attestation.data.index == 1 (payload present for a past block),
    # the execution payload for block passes validation.
    # [IGNORE] When attestation.data.index == 1 (payload present for a past block),
    # the execution payload for block has been seen
    if aggregate.data.index == 1:
      template block_root: untyped = aggregate.data.beacon_block_root
      debugGloasComment("unviable envelope")
      if not pool.dag.db.containsExecutionPayloadEnvelope(block_root) and
          not envelopeQuarantine[].hasOrphan(block_root):
        return errIgnore(
          "Aggregate: execution payload not yet seen")
  else:
    # [REJECT] aggregate.data.index == 0
    if not (aggregate.data.index == 0):
      return pool.checkedReject("Aggregate: Electra aggregate.data.index != 0")

  let shufflingRef = pool.dag.getShufflingRef(target.blck, target.slot.epoch, false).valueOr:
    # Target is verified - shouldn't happen
    warn "No shuffling for attestation - report bug",
      aggregate = shortLog(aggregate), target = shortLog(target)
    return errIgnore("Aggregate: no shuffling")

  # [REJECT] The committee index is within the expected range -- i.e.
  # data.index < get_committee_count_per_slot(state, data.target.epoch).
  let committee_index = block:
    # [REJECT] len(committee_indices) == 1, where committee_indices =
    # get_committee_indices(aggregate)
    let agg_idx = get_committee_index_one(aggregate.committee_bits).valueOr:
      return pool.checkedReject("Aggregate: got multiple committee bits")
    shufflingRef.get_committee_index(agg_idx.uint64).valueOr:
      return pool.checkedReject("Aggregate: committee index not within expected range")

  if not (aggregate.aggregation_bits.lenu64 == get_beacon_committee_len(
      shufflingRef, slot, committee_index)):
    return pool.checkedReject(
      "Aggregate: number of aggregation bits and committee size mismatch"
    )

  # [IGNORE] A valid aggregate attestation defined by
  # `hash_tree_root(aggregate.data)` whose `aggregation_bits` is a non-strict
  # superset has _not_ already been seen.
  # https://github.com/ethereum/consensus-specs/pull/2847
  if checkCover and
      pool[].covers(
        aggregate.data, aggregate.aggregation_bits, committee_index
      ):
    return errIgnore("Aggregate: already covered")

  # [REJECT] aggregate_and_proof.selection_proof selects the validator as an
  # aggregator for the slot -- i.e. is_aggregator(state, aggregate.data.slot,
  # aggregate.data.index, aggregate_and_proof.selection_proof) returns True.
  if not is_aggregator(
    shufflingRef, slot, committee_index, aggregate_and_proof.selection_proof
  ):
    return pool.checkedReject("Aggregate: incorrect aggregator")

  # [REJECT] The aggregator's validator index is within the committee -- i.e.
  # aggregate_and_proof.aggregator_index in get_beacon_committee(state,
  # aggregate.data.slot, aggregate.data.index).

  if aggregator_index notin get_beacon_committee(shufflingRef, slot, committee_index):
    return
      pool.checkedReject("Aggregate: aggregator's validator index not in committee")

  # 1. [REJECT] The aggregate_and_proof.selection_proof is a valid signature
  #    of the aggregate.data.slot by the validator with index
  #    aggregate_and_proof.aggregator_index.
  #    get_slot_signature(state, aggregate.data.slot, privkey)
  # 2. [REJECT] The aggregator signature,
  #    signed_aggregate_and_proof.signature, is valid.
  # 3. [REJECT] The signature of aggregate is valid.

  let
    fork = pool.dag.forkAtEpoch(aggregate.data.slot.epoch)
    attesting_indices = shufflingRef.get_attesting_indices(
      slot, aggregate.committee_bits, aggregate.aggregation_bits
    )
    sig = aggregate.signature.load().valueOr:
      return pool.checkedReject("Aggregate: unable to load signature")

  if checkSignature:
    let (aggregatorFut, slotFut, aggregateFut) = batchCrypto.scheduleAggregateChecks(
      fork, signedAggregateAndProof, sig, pool.dag, attesting_indices
    ).valueOr:
      return pool.checkedReject(error)

    block:
      # [REJECT] The aggregator signature,
      # signed_aggregate_and_proof.signature, is valid.
      let x = await aggregatorFut
      case x
      of BatchResult.Invalid:
        return pool.checkedReject("Aggregate: invalid aggregator signature")
      of BatchResult.Timeout:
        beacon_aggregates_dropped_queue_full.inc()
        return errIgnore("Aggregate: timeout checking aggregator signature")
      of BatchResult.Valid:
        discard

    block:
      # [REJECT] aggregate_and_proof.selection_proof
      let x = await slotFut
      case x
      of BatchResult.Invalid:
        return pool.checkedReject("Aggregate: invalid slot signature")
      of BatchResult.Timeout:
        beacon_aggregates_dropped_queue_full.inc()
        return errIgnore("Aggregate: timeout checking slot signature")
      of BatchResult.Valid:
        discard

    block:
      # [REJECT] The aggregator signature,
      # signed_aggregate_and_proof.signature, is valid.
      let x = await aggregateFut
      case x
      of BatchResult.Invalid:
        return pool.checkedReject("Aggregate: invalid aggregate signature")
      of BatchResult.Timeout:
        beacon_aggregates_dropped_queue_full.inc()
        return errIgnore("Aggregate: timeout checking aggregate signature")
      of BatchResult.Valid:
        discard

  # The following rule follows implicitly from that we clear out any
  # unviable blocks from the chain dag:
  #
  # [IGNORE] The current finalized_checkpoint is an ancestor of the block
  # defined by aggregate.data.beacon_block_root -- i.e.
  # get_checkpoint_block(store, aggregate.data.beacon_block_root,
  # finalized_checkpoint.epoch) == store.finalized_checkpoint.root

  # Only valid aggregates go in the list
  if pool.nextAttestationEpoch.lenu64 <= aggregator_index.uint64:
    pool.nextAttestationEpoch.setLen(aggregator_index.int + 1)
  pool.nextAttestationEpoch[aggregator_index].aggregate =
    aggregate.data.target.epoch + 1

  return ok((attesting_indices, sig))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/capella/p2p-interface.md#new-bls_to_execution_change
proc validateBlsToExecutionChange*(
    pool: ValidatorChangePool, batchCrypto: ref BatchCrypto,
    signed_address_change: SignedBLSToExecutionChange,
    wallEpoch: Epoch): Future[Result[void, ValidationError]] {.async: (raises: [CancelledError]).} =
  # [IGNORE] The current epoch is at or after the Capella fork epoch
  if not (wallEpoch >= pool.dag.cfg.CAPELLA_FORK_EPOCH):
    return errIgnore("SignedBLSToExecutionChange: current epoch is pre-capella")

  # [IGNORE] This is the first valid bls_to_execution_change received for the validator
  if pool.isSeen(signed_address_change):
    return errIgnore(
      "SignedBLSToExecutionChange: already seen BLS to execution change for this validator")

  # [REJECT] The validator index is valid
  # [REJECT] The validator has BLS withdrawal credentials
  # [REJECT] The bls_to_execution_change is for the validator's withdrawal pubkey
  # [REJECT] The signature is valid
  withState(pool.dag.headState):
    when consensusFork < ConsensusFork.Capella:
      return errIgnore(
        "SignedBLSToExecutionChange: can't validate against pre-Capella state")
    else:
      let res = check_bls_to_execution_change(
        pool.dag.cfg.GENESIS_FORK_VERSION, forkyState.data, signed_address_change,
        {skipBlsValidation})
      if res.isErr:
        return pool.checkedReject(res.error)

      # BLS to execution change signatures are batch-verified
      let deferredCrypto = batchCrypto.scheduleBlsToExecutionChangeCheck(
        pool.dag.cfg.GENESIS_FORK_VERSION, signed_address_change)
      if deferredCrypto.isErr():
        return pool.checkedReject(deferredCrypto.error)

      let (cryptoFut, _) = deferredCrypto.get()
      case await cryptoFut
      of BatchResult.Invalid:
        return pool.checkedReject(
          "SignedBLSToExecutionChange: invalid BLS to execution change signature")
      of BatchResult.Timeout:
        return errIgnore(
          "SignedBLSToExecutionChange: timeout checking signature")
      of BatchResult.Valid:
        discard  # keep going only in this case

  # Send notification about new BLS to execution change via callback
  if not(isNil(pool.onBLSToExecutionChangeReceived)):
    pool.onBLSToExecutionChangeReceived(signed_address_change)

  return ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#attester_slashing
proc validateAttesterSlashing*(
    pool: ValidatorChangePool,
    attester_slashing: electra.AttesterSlashing | gloas.AttesterSlashing
): Result[void, ValidationError] =
  # [IGNORE] At least one index in the intersection has not yet been seen
  if pool.isSeen(attester_slashing):
    return errIgnore(
      "AttesterSlashing: all attester slashing indices already seen")

  # [REJECT] The attestation data is slashable (double vote or surround vote)
  # [REJECT] All validator indices in the first indexed attestation are valid
  # [REJECT] The first indexed attestation has valid properties
  # [REJECT] All validator indices in the second indexed attestation are valid
  # [REJECT] The second indexed attestation has valid properties
  # [REJECT] At least one validator in the intersection is slashable
  let attester_slashing_validity =
    check_attester_slashing(pool.dag.headState, attester_slashing, {})
  if attester_slashing_validity.isErr:
    return pool.checkedReject(attester_slashing_validity.error)

  # Send notification about new attester slashing via callback
  if not(isNil(pool.onAttesterSlashingReceived)):
    when typeof(attester_slashing) is gloas.AttesterSlashing:
      pool.onAttesterSlashingReceived(attester_slashing)
    else:
      pool.onAttesterSlashingReceived(
        upgrade_attester_slashing_to_gloas(attester_slashing))

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#proposer_slashing
proc validateProposerSlashing*(
    pool: ValidatorChangePool, proposer_slashing: ProposerSlashing):
    Result[void, ValidationError] =
  # Not from spec; the rest of NBC wouldn't have correctly processed it either.
  if proposer_slashing.signed_header_1.message.proposer_index > int.high.uint64:
    return errIgnore("ProposerSlashing: proposer-slashed index too high")

  # [IGNORE] The proposer slashing is the first valid proposer slashing received for this proposer
  if pool.isSeen(proposer_slashing):
    return errIgnore(
      "ProposerSlashing: already seen proposer slashing for this proposer")

  # [REJECT] The header slots match
  # [REJECT] The header proposer indices match
  # [REJECT] The headers are different
  # [REJECT] The proposer index is a valid validator index
  # [REJECT] The proposer is slashable
  # [REJECT] The signatures are valid
  let proposer_slashing_validity =
    check_proposer_slashing(pool.dag.headState, proposer_slashing, {})
  if proposer_slashing_validity.isErr:
    return pool.checkedReject(proposer_slashing_validity.error)

  # Send notification about new proposer slashing via callback
  if not(isNil(pool.onProposerSlashingReceived)):
    pool.onProposerSlashingReceived(proposer_slashing)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#voluntary_exit
proc validateVoluntaryExit*(
    pool: ValidatorChangePool, signed_voluntary_exit: SignedVoluntaryExit,
    wallTime: BeaconTime): Result[void, ValidationError] =
  template voluntary_exit: untyped = signed_voluntary_exit.message

  # [IGNORE] The voluntary exit is the first valid voluntary exit received for the validator
  if pool.isSeen(signed_voluntary_exit):
    return errIgnore(
      "VoluntaryExit: already seen voluntary exit for this validator")

  # [IGNORE] The voluntary exit epoch is not in the future
  block:
    let futureSlot =
      (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).toSlot(pool.dag.timeParams)
    if not futureSlot.afterGenesis or
        voluntary_exit.epoch > futureSlot.slot.epoch:
      return errIgnore("VoluntaryExit: voluntary exit epoch is in the future")

  # [REJECT] The validator index is valid
  if voluntary_exit.validator_index >= pool.dag.headState.validators.lenu64:
    return pool.checkedReject("VoluntaryExit: validator index out of range")

  withState(pool.dag.headState):
    let
      validator = addr forkyState.data.validators.item(
        voluntary_exit.validator_index)
      current_epoch = get_current_epoch(forkyState.data)

    # [IGNORE] The validator has not already initiated exit
    if validator[].exit_epoch != FAR_FUTURE_EPOCH:
      return errIgnore("VoluntaryExit: validator has already initiated exit")

    # [REJECT] The validator is active
    if not is_active_validator(validator[], current_epoch):
      return pool.checkedReject("VoluntaryExit: validator is not active")

    # [REJECT] The validator has been active long enough
    if current_epoch <
        validator[].activation_epoch + pool.dag.cfg.SHARD_COMMITTEE_PERIOD:
      return pool.checkedReject(
        "VoluntaryExit: validator has not been active long enough")

    # [REJECT] The signature is valid
    let voluntary_exit_fork = consensusFork.voluntary_exit_signature_fork(
      forkyState.data.fork, pool.dag.cfg.CAPELLA_FORK_VERSION)
    if not verify_voluntary_exit_signature(
        voluntary_exit_fork, forkyState.data.genesis_validators_root,
        voluntary_exit, validator[].pubkey, signed_voluntary_exit.signature):
      return pool.checkedReject(
        "VoluntaryExit: invalid voluntary exit signature")

  # Send notification about new voluntary exit via callback
  if not(isNil(pool.onVoluntaryExitReceived)):
    pool.onVoluntaryExitReceived(signed_voluntary_exit)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/altair/p2p-interface.md#new-sync_committee_subnet_id
proc validateSyncCommitteeMessage*(
    dag: ChainDAGRef,
    quarantine: ref Quarantine,
    batchCrypto: ref BatchCrypto,
    syncCommitteeMsgPool: ref SyncCommitteeMsgPool,
    msg: SyncCommitteeMessage,
    subcommitteeIdx: SyncSubcommitteeIndex,
    wallTime: BeaconTime,
    checkSignature: bool):
    Future[Result[
      (BlockId, CookedSig, seq[uint64]), ValidationError]] {.async: (raises: [CancelledError]).} =
  # [IGNORE] The message's slot is for the current slot
  dag.timeParams.check_slot_exact(msg.slot, wallTime).isOkOr:
    return err(error)

  # [REJECT] The validator index is valid
  # [REJECT] The subnet_id is valid for the given validator
  # (this implies the validator is part of the broader current sync committee
  # along with the correct subcommittee)
  let positionsInSubcommittee = dag.getSubcommitteePositions(
    msg.slot + 1, subcommitteeIdx, msg.validator_index)

  if positionsInSubcommittee.len == 0:
    return dag.checkedReject(
      "SyncCommitteeMessage: subnet_id is not valid for the validator")

  # [IGNORE] The block being signed (`sync_committee_message.beacon_block_root`)
  # has been seen (via both gossip and non-gossip sources) (a client MAY queue
  # sync committee messages for processing once block is received)
  # [REJECT] The block being signed (`sync_committee_message.beacon_block_root`)
  # passes validation.
  let
    blockRoot = msg.beacon_block_root
    blck = dag.getBlockRef(blockRoot).valueOr:
      return quarantine[].addMissingValid(blockRoot, "SyncCommitteeMessage: target")

  # [IGNORE] There has been no other valid sync committee message for the
  # declared slot for the validator referenced by
  # sync_committee_message.validator_index (this validation is per topic so
  # that for a given slot, multiple messages could be forwarded with the same
  # validator_index as long as the subnet_ids are distinct)
  if syncCommitteeMsgPool[].isSeen(msg, subcommitteeIdx, dag.head.bid):
    return errIgnore(
      "SyncCommitteeMessage: already seen message from this validator for this slot and subnet")

  # [REJECT] The signature is valid
  let
    senderPubKey = dag.validatorKey(msg.validator_index).valueOr:
      return dag.checkedReject(
        "SyncCommitteeMessage: validator index out of range")

  let sig =
    if checkSignature:
      # Attestation signatures are batch-verified
      let deferredCrypto = batchCrypto
                            .scheduleSyncCommitteeMessageCheck(
                              dag.forkAtEpoch(msg.slot.epoch),
                              msg.slot, msg.beacon_block_root,
                              senderPubKey, msg.signature)
      if deferredCrypto.isErr():
        return dag.checkedReject(deferredCrypto.error)

      # Await the crypto check
      let
        (cryptoFut, sig) = deferredCrypto.get()

      let x = (await cryptoFut)
      case x
      of BatchResult.Invalid:
        return dag.checkedReject(
          "SyncCommitteeMessage: invalid sync committee message signature")
      of BatchResult.Timeout:
        beacon_sync_messages_dropped_queue_full.inc()
        return errIgnore("SyncCommitteeMessage: timeout checking signature")
      of BatchResult.Valid:
        sig # keep going only in this case
    else:
      msg.signature.load().valueOr:
        return dag.checkedReject(
          "SyncCommitteeMessage: unable to load signature")

  ok((blck.bid, sig, positionsInSubcommittee))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/altair/p2p-interface.md#new-sync_committee_contribution_and_proof
proc validateContribution*(
    dag: ChainDAGRef,
    quarantine: ref Quarantine,
    batchCrypto: ref BatchCrypto,
    syncCommitteeMsgPool: ref SyncCommitteeMsgPool,
    msg: SignedContributionAndProof,
    wallTime: BeaconTime,
    checkSignature: bool
): Future[Result[
    (BlockId, CookedSig, seq[ValidatorIndex]), ValidationError]] {.async: (raises: [CancelledError]).} =
  # [IGNORE] The contribution's slot is for the current slot
  dag.timeParams.check_slot_exact(
      msg.message.contribution.slot, wallTime).isOkOr:
    return err(error)

  # [REJECT] The subcommittee index is in the allowed range
  let subcommitteeIdx = SyncSubcommitteeIndex.init(
      msg.message.contribution.subcommittee_index).valueOr:
    return dag.checkedReject("Contribution: subcommittee index out of range")

  # [REJECT] The contribution has participants
  if msg.message.contribution.aggregation_bits.isZeros:
    return dag.checkedReject("Contribution: contribution has no participants")

  # [REJECT] The selection_proof selects the validator as an aggregator for
  # the slot
  if not is_sync_committee_aggregator(msg.message.selection_proof):
    return dag.checkedReject(
      "Contribution: validator is not selected as aggregator")

  # [IGNORE] The sync committee contribution is the first valid contribution
  # received for the slot contribution.slot, aggregator with index
  # contribution_and_proof.aggregator_index, and subcommittee index
  # contribution.subcommittee_index
  if syncCommitteeMsgPool[].isSeen(msg.message):
    return errIgnore(
      "Contribution: already seen contribution from this aggregator")

  # [REJECT] The aggregator index is valid
  # [REJECT] The aggregator's validator index is in the declared subcommittee
  # of the current sync committee
  let
    aggregator_index =
      ValidatorIndex.init(msg.message.aggregator_index).valueOr:
        return dag.checkedReject("Contribution: aggregator index out of range")
    # TODO we take a copy of the participants to avoid the data going stale
    #      between validation and use - nonetheless, a design that avoids it and
    #      stays safe would be nice
    participants = dag.syncCommitteeParticipants(
      msg.message.contribution.slot + 1, subcommitteeIdx)
  if aggregator_index notin participants:
    return dag.checkedReject("Contribution: aggregator not in subcommittee")

  # [IGNORE] The block being signed
  # (`contribution_and_proof.contribution.beacon_block_root`) has been seen
  # (via both gossip and non-gossip sources) (a client MAY queue sync committee
  # contributions for processing once block is received)
  # [REJECT] The block being signed
  # (`contribution_and_proof.contribution.beacon_block_root`) passes validation.
  let
    blockRoot = msg.message.contribution.beacon_block_root
    blck = dag.getBlockRef(blockRoot).valueOr:
      return quarantine[].addMissingValid(blockRoot, "Contribution: target")

  # [IGNORE] A valid sync committee contribution with equal slot,
  # beacon_block_root and subcommittee_index whose aggregation_bits is
  # non-strict superset has not already been seen
  if syncCommitteeMsgPool[].covers(msg.message.contribution, blck.bid):
    return errIgnore("Contribution: already seen contribution for this data")

  let sig = if checkSignature:
    let deferredCrypto = batchCrypto.scheduleContributionChecks(
      dag.forkAtEpoch(msg.message.contribution.slot.epoch),
      msg, subcommitteeIdx, dag)
    if deferredCrypto.isErr():
      return dag.checkedReject(deferredCrypto.error)

    let
      (aggregatorFut, proofFut, contributionFut, sig) = deferredCrypto.get()

    block:
      # [REJECT] The aggregator signature,
      # signed_contribution_and_proof.signature, is valid
      let x = await aggregatorFut
      case x
      of BatchResult.Invalid:
        return dag.checkedReject(
          "Contribution: invalid aggregator signature")
      of BatchResult.Timeout:
        beacon_contributions_dropped_queue_full.inc()
        return errIgnore(
          "Contribution: timeout checking aggregator signature")
      of BatchResult.Valid:
        discard

    block:
      # [REJECT] The contribution_and_proof.selection_proof is a valid
      # signature of the SyncAggregatorSelectionData derived from the
      # contribution by the validator with index
      # contribution_and_proof.aggregator_index
      let x = await proofFut
      case x
      of BatchResult.Invalid:
        return dag.checkedReject(
          "Contribution: invalid selection proof signature")
      of BatchResult.Timeout:
        beacon_contributions_dropped_queue_full.inc()
        return errIgnore("Contribution: timeout checking proof")
      of BatchResult.Valid:
        discard

    block:
      # [REJECT] The aggregate signature is valid for the message
      # beacon_block_root and aggregate pubkey derived from the participation
      # info in aggregation_bits for the subcommittee specified by the
      # contribution.subcommittee_index
      let x = await contributionFut
      case x
      of BatchResult.Invalid:
        return dag.checkedReject("Contribution: invalid aggregate signature")
      of BatchResult.Timeout:
        beacon_contributions_dropped_queue_full.inc()
        return errIgnore(
          "Contribution: timeout checking contribution signature")
      of BatchResult.Valid:
        discard
    sig
  else:
    msg.message.contribution.signature.load().valueOr:
      return dag.checkedReject("Contribution: unable to load signature")

  ok((blck.bid, sig, participants))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#light_client_finality_update
proc validateLightClientFinalityUpdate*(
    pool: var LightClientPool, dag: ChainDAGRef,
    finality_update: ForkedLightClientFinalityUpdate,
    wallTime: BeaconTime): Result[void, ValidationError] =
  # [IGNORE] The `finalized_header.beacon.slot` is greater than that of all
  # previously forwarded `finality_update`s, or it matches the highest
  # previously forwarded slot and also has a `sync_aggregate` indicating
  # supermajority (> 2/3) sync committee participation while the previously
  # forwarded `finality_update` for that slot did not indicate supermajority
  let finalized_slot = withForkyFinalityUpdate(finality_update):
    when lcDataFork > LightClientDataFork.None:
      forkyFinalityUpdate.finalized_header.beacon.slot
    else:
      GENESIS_SLOT
  if finalized_slot < pool.latestForwardedFinalitySlot:
    return errIgnore("LightClientFinalityUpdate: slot already forwarded")
  let has_supermajority = withForkyFinalityUpdate(finality_update):
    when lcDataFork > LightClientDataFork.None:
      forkyFinalityUpdate.sync_aggregate.hasSupermajoritySyncParticipation
    else:
      false
  if finalized_slot == pool.latestForwardedFinalitySlot:
    if pool.latestForwardedFinalityHasSupermajority:
      return errIgnore("LightClientFinalityUpdate: already have supermajority")
    if not has_supermajority:
      return errIgnore("LightClientFinalityUpdate: no new supermajority")

  let
    signature_slot = withForkyFinalityUpdate(finality_update):
      when lcDataFork > LightClientDataFork.None:
        forkyFinalityUpdate.signature_slot
      else:
        GENESIS_SLOT
    currentTime = wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY
    forwardTime = signature_slot
      .light_client_finality_update_time(dag.timeParams)
  if currentTime < forwardTime:
    # [IGNORE] The `finality_update` is received after the block at
    # `signature_slot` was given enough time to propagate through the network.
    return errIgnore("LightClientFinalityUpdate: received too early")

  if not finality_update.matches(dag.lcDataStore.cache.latest):
    # [IGNORE] The received `finality_update` matches the locally computed one
    # exactly.
    return errIgnore("LightClientFinalityUpdate: not matching local")

  pool.latestForwardedFinalitySlot = finalized_slot
  pool.latestForwardedFinalityHasSupermajority = has_supermajority
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#light_client_optimistic_update
proc validateLightClientOptimisticUpdate*(
    pool: var LightClientPool, dag: ChainDAGRef,
    optimistic_update: ForkedLightClientOptimisticUpdate,
    wallTime: BeaconTime): Result[void, ValidationError] =
  let attested_slot = withForkyOptimisticUpdate(optimistic_update):
    when lcDataFork > LightClientDataFork.None:
      forkyOptimisticUpdate.attested_header.beacon.slot
    else:
      GENESIS_SLOT
  if attested_slot <= pool.latestForwardedOptimisticSlot:
    # [IGNORE] The `attested_header.beacon.slot` is greater than that of all
    # previously forwarded `optimistic_update`s
    return errIgnore("LightClientOptimisticUpdate: slot already forwarded")

  let
    signature_slot = withForkyOptimisticUpdate(optimistic_update):
      when lcDataFork > LightClientDataFork.None:
        forkyOptimisticUpdate.signature_slot
      else:
        GENESIS_SLOT
    currentTime = wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY
    forwardTime = signature_slot
      .light_client_optimistic_update_time(dag.timeParams)
  if currentTime < forwardTime:
    # [IGNORE] The `optimistic_update` is received after the block at
    # `signature_slot` was given enough time to propagate through the network.
    return errIgnore("LightClientOptimisticUpdate: received too early")

  if not optimistic_update.matches(dag.lcDataStore.cache.latest):
    # [IGNORE] The received `optimistic_update` matches the locally computed one
    # exactly.
    return errIgnore("LightClientOptimisticUpdate: not matching local")

  pool.latestForwardedOptimisticSlot = attested_slot
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.13/specs/gloas/p2p-interface.md#execution_payload_bid
proc validateExecutionPayloadBid*(
    dag: ChainDAGRef,
    forkChoice: var ForkChoice,
    executionPayloadBidPool: ref ExecutionPayloadBidPool,
    seenProposerPreferences: var SeenProposerPreferences,
    signed_execution_payload_bid: gloas.SignedExecutionPayloadBid,
    wallTime: BeaconTime): Result[PayloadAvailability, ValidationError] =
  template bid: untyped = signed_execution_payload_bid.message

  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      # [REJECT] bid.builder_index is a valid, active builder index
      if bid.builder_index >= forkyState.data.builders.lenu64:
        return dag.checkedReject("ExecutionPayloadBid: invalid builder index")

      if not is_active_builder(forkyState.data, bid.builder_index):
        return dag.checkedReject("ExecutionPayloadBid: builder not active")

      # [REJECT] The builder version is `PAYLOAD_BUILDER_VERSION`
      if not (forkyState.data.builders.item(bid.builder_index).version ==
          PAYLOAD_BUILDER_VERSION):
        return dag.checkedReject("ExecutionPayloadBid: builder version mismatch")

      # [REJECT] bid.execution_payment is zero
      if bid.execution_payment != 0.Gwei:
        return dag.checkedReject(
          "ExecutionPayloadBid: execution_payment is not zero")

      let parentBlck = dag.getBlockRef(bid.parent_block_root).valueOr:
        return errIgnore(
          "ExecutionPayloadBid: parent block root not found in fork choice")

      # [REJECT] The bid is for a higher slot than its parent block -- i.e.
      # validate that `bid.slot` is greater than the slot of the block with root
      # `bid.parent_block_root`.
      if not (bid.slot > parentBlck.slot):
        return errReject("ExecutionPayloadBid: slot not greater than parent's")

      # [REJECT] The bid's block hash is not equal to its parent block hash
      if bid.block_hash == bid.parent_block_hash:
        return dag.checkedReject(
          "ExecutionPayloadBid: block hash equals parent block hash")

      # [IGNORE] this bid is the highest value bid seen for the tuple
      # `(bid.slot, bid.parent_block_hash, bid.parent_block_root)`.
      let
        payloadAvailability =
          dag.payloadAvailability(parentBlck, bid.parent_block_hash).valueOr:
            return errIgnore("ExecutionPayloadBid: parent block hash unknown")
        highestBid = executionPayloadBidPool[].getHighestBidForSlotAndParent(
          bid.slot, bid.parent_block_root, payloadAvailability)

      # [IGNORE] this is the first signed bid seen with a valid signature from
      # the given builder for the tuple
      # `(bid.slot, bid.parent_block_hash, bid.parent_block_root)`
      if executionPayloadBidPool[].hasSeenBidFromBuilder(
          bid.slot, bid.builder_index, bid.parent_block_root,
          payloadAvailability):
        return errIgnore(
          "ExecutionPayloadBid: already seen bid from this builder for this " &
          "slot and parent")

      if highestBid.isSome() and highestBid.get().message.value > bid.value:
        return errIgnore(
          "ExecutionPayloadBid: not the highest value bid for this slot and parent")

      # [IGNORE] The bid is compatible with the current head branch, i.e.
      # `is_bid_compatible_with_head(store, bid)` returns `True`.
      if not forkChoice.is_bid_compatible_with_head(dag, bid):
        return errIgnore("ExecutionPayloadBid: incompatible with head branch")

      # [IGNORE] bid.value is less or equal than the builder's excess balance
      if not can_builder_cover_bid(
          forkyState.data, bid.builder_index.BuilderIndex, bid.value):
        return errIgnore(
          "ExecutionPayloadBid: insufficient builder balance")

      let bidDependentRoot = dag.get_dependent_root(parentBlck.bid, bid.slot)
      let
        seenBucket = uint64(bid.slot.epoch()) mod (MIN_SEED_LOOKAHEAD + 2)
        seenKey = uint64(bid.slot) mod SLOTS_PER_EPOCH
      var seenPref: ProposerPreferences
      seenProposerPreferences[seenBucket][seenKey].withValue(
          bidDependentRoot, pref):
        seenPref = pref[]
      do:
        return errIgnore("ExecutionPayloadBid: matching preferences not seen")

      # [IGNORE]
      # ... `is_gas_limit_target_compatible(parent_gas_limit, bid.gas_limit,
      # proposer_preferences.target_gas_limit)` is True, where
      # `parent_gas_limit` is the `gas_limit` of that execution payload.
      if not is_gas_limit_target_compatible(
          forkyState.data.latest_execution_payload_bid.gas_limit,
          bid.gas_limit, seenPref.target_gas_limit):
        return errIgnore("ExecutionPayloadBid: gas limit not target-compatible")

      # [IGNORE] bid.slot is the current slot or the next slot
      let currentSlot = wallTime.slotOrZero(dag.timeParams)
      if bid.slot != currentSlot and bid.slot != currentSlot + 1:
        return errIgnore("ExecutionPayloadBid: slot not current or next slot")

      # [REJECT] The length of KZG commitments is less than or equal to the
      # limitation defined in the consensus layer -- i.e. validate that
      # `len(bid.blob_kzg_commitments) <=
      # get_blob_parameters(compute_epoch_at_slot(bid.slot)).max_blobs_per_block`.
      if not (bid.blob_kzg_commitments.lenu64() <=
          dag.cfg.get_blob_parameters(bid.slot.epoch()).MAX_BLOBS_PER_BLOCK):
        return dag.checkedReject("ExecutionPayloadBid: invalid kzg commitments")

      # [IGNORE] `bid.fee_recipient` matches the `fee_recipient` from the
      # proposer's `SignedProposerPreferences` associated with `bid.slot`.
      if not (bid.fee_recipient == seenPref.fee_recipient):
        return errIgnore("ExecutionPayloadBid: fee recipient mismatch")

      # Extra check to prevent unincludable bids from purging legitimate ones
      # from the execution payload pool
      # https://github.com/ethereum/consensus-specs/pull/5360
      # [REJECT] bid.prev_randao is the correct RANDAO mix -- i.e.
      # validate that bid.prev_randao ==
      # get_randao_mix(parent_state, get_current_epoch(parent_state)).
      let expectedPrevRandao = executionPayloadBidPool[]
          .getPrevRandao(bid.slot, parentBlck.bid).valueOr:
        return errIgnore("ExecutionPayloadBid: unknown RANDAO mix")
      if not (bid.prev_randao == expectedPrevRandao):
        return errReject("ExecutionPayloadBid: incorrect RANDAO mix")

      # [REJECT] signed_execution_payload_bid.signature is valid with respect
      # to the bid.builder_index
      let builderPubkey =
        forkyState.data.builders.item(bid.builder_index).pubkey

      # Blocked on the bid type here being `heze.SignedExecutionPayloadBid`,
      # which is what carries `inclusion_list_bits`; the check itself is
      # `inclusionListPool[].isInclusionListBitsInclusive(bid.slot - 1, ...)`.
      debugHezeComment """
- _[IGNORE]_ `bid.inclusion_list_bits` is inclusive of the node's view of
inclusion lists for the slot preceding the bid's slot -- i.e.
`is_inclusion_list_bits_inclusive(get_inclusion_list_store(), state, Slot(bid.slot - 1), bid.inclusion_list_bits, only_timely=True)`
returns `True`, where `state` is the head state corresponding to processing
the block up to the current slot as determined by the fork choice.
"""

      if not verify_execution_payload_bid_signature(
          dag.forkAtEpoch(bid.slot.epoch),
          dag.genesis_validators_root,
          bid.slot.epoch,
          bid,
          builderPubkey,
          signed_execution_payload_bid.signature):
        return dag.checkedReject(
          "ExecutionPayloadBid: invalid signature")

      ok payloadAvailability
    else:
      dag.checkedReject(
        "ExecutionPayloadBid: only valid for Gloas fork or later")

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/p2p-interface.md#new-payload_attestation_message
proc validatePayloadAttestationMessage*(
    dag: ChainDAGRef,
    quarantine: ref Quarantine,
    payloadAttestationPool: ref PayloadAttestationPool,
    batchCrypto: ref BatchCrypto,
    payload_attestation_message: PayloadAttestationMessage,
    wallTime: BeaconTime,
    checkSignature: bool = true
): Future[Result[
     void, ValidationError]] {.async: (raises: [CancelledError]).} =
  template data: untyped = payload_attestation_message.data

  # [IGNORE] The payload attestation's slot is for the current slot
  dag.timeParams.check_slot_exact(data.slot, wallTime).isOkOr:
    return err(error)

  # [IGNORE] This is the first valid payload attestation from this validator
  # index
  if payloadAttestationPool[].isSeen(payload_attestation_message):
    return errIgnore("PayloadAttestationMessage: duplicate message from validator")

  # [IGNORE] The payload attestation's block has been seen (via gossip or
  # non-gossip sources) (MAY be queued until block is retrieved)
  # [REJECT] The payload attestation's block passes validation
  let attestedBlck = dag.getBlockRef(data.beacon_block_root).valueOr:
    return quarantine[].addMissingValid(
      data.beacon_block_root, "PayloadAttestationMessage: block")

  # [IGNORE] The payload attestation's block is at the assigned slot
  if attestedBlck.bid.slot != data.slot:
    return errIgnore("PayloadAttestationMessage: block slot mismatch")

  # [REJECT] The validator index is valid
  let vidx = ValidatorIndex.init(payload_attestation_message.validator_index).valueOr:
    return dag.checkedReject(
      "PayloadAttestationMessage: invalid validator index")

  # [REJECT] The validator is a member of the payload timeliness committee
  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      var present = false
      for idx in get_ptc(forkyState.data, data.slot):
        if idx == vidx:
          present = true
          break

      if not present:
        return dag.checkedReject(
          "PayloadAttestationMessage: validator not in ptc")
    else:
      return dag.checkedReject(
        "PayloadAttestationMessage: only valid for Gloas fork")

  # [REJECT] The signature is valid
  if checkSignature:
    let senderPubKey = dag.validatorKey(vidx).valueOr:
      return dag.checkedReject(
        "PayloadAttestationMessage: invalid validator index")

    let deferredCrypto = batchCrypto.schedulePayloadAttestationCheck(
      dag.forkAtEpoch(data.slot.epoch), dag.genesis_validators_root,
      payload_attestation_message, senderPubKey,
      payload_attestation_message.signature)
    if deferredCrypto.isErr():
      return dag.checkedReject(deferredCrypto.error)

    let (cryptoFut, _) = deferredCrypto.get()
    case await cryptoFut
    of BatchResult.Invalid:
      return dag.checkedReject(
        "PayloadAttestationMessage: invalid signature")
    of BatchResult.Timeout:
      return errIgnore(
        "PayloadAttestationMessage: timeout checking signature")
    of BatchResult.Valid:
      discard

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/p2p-interface.md#new-proposer_preferences
proc validateProposerPreferences*(
    dag: ChainDAGRef,
    seen: var SeenProposerPreferences,
    signed_preferences: SignedProposerPreferences,
    wallTime: BeaconTime): Result[void, ValidationError] =
  template preferences: untyped = signed_preferences.message

  let proposalEpoch = preferences.proposal_slot.epoch

  # [IGNORE] The proposal epoch is after the Gloas upgrade
  if proposalEpoch < dag.cfg.GLOAS_FORK_EPOCH:
    return errIgnore("ProposerPreferences: proposal epoch is pre-gloas")

  # [IGNORE] The proposal slot has not started yet
  if preferences.proposal_slot.start_beacon_time(dag.timeParams) +
      MAXIMUM_GOSSIP_CLOCK_DISPARITY < wallTime:
    return errIgnore("ProposerPreferences: proposal slot has already started")

  # [IGNORE] The proposer for the proposal slot is known
  let lookaheadEpoch =
    if proposalEpoch <= MIN_SEED_LOOKAHEAD: GENESIS_EPOCH
    else: proposalEpoch - MIN_SEED_LOOKAHEAD
  if wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY <
      lookaheadEpoch.start_slot.start_beacon_time(dag.timeParams):
    return errIgnore(
      "ProposerPreferences: proposer for the proposal slot is not yet known")

  # [IGNORE] These are the first valid preferences seen for this dependent root and slot
  let
    bucket = proposalEpoch.uint64 mod (MIN_SEED_LOOKAHEAD + 2)
    slotInEpoch = preferences.proposal_slot.uint64 mod SLOTS_PER_EPOCH
  if preferences.dependent_root in seen[bucket][slotInEpoch]:
    return errIgnore(
      "ProposerPreferences: already seen preferences for this dependent root and proposal slot")

  # [IGNORE] The dependent block has been seen (via gossip or non-gossip sources)
  # (MAY be queued until block is retrieved)
  # [IGNORE] The dependent block passes validation
  let dependentRef = dag.getBlockRef(preferences.dependent_root).valueOr:
    return errIgnore("ProposerPreferences: dependent block has not been seen")

<<<<<<< HEAD
  # [REJECT] The dependent block's slot is not after the shuffling dependent slot
  if dependentRef.slot > proposalEpoch.attester_dependent_slot:
    return dag.checkedReject(
      "ProposerPreferences: dependent block is after the shuffling dependent slot")
=======
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/p2p-interface.md#new-compute_shuffling_dependent_epoch
  let shufflingDependentEpoch =
    if proposalEpoch <= MIN_SEED_LOOKAHEAD: GENESIS_EPOCH
    else: proposalEpoch - MIN_SEED_LOOKAHEAD

  # [REJECT] The dependent block's slot is not after the shuffling dependent slot.
  if dependentRef.slot > proposer_dependent_slot(shufflingDependentEpoch):
    return dag.checkedReject(
      "ProposerPreferences: dependent_root after shuffling dependent slot")
>>>>>>> f5751db03 (ProposerPreferences: allow genesis dependent root)

  # [IGNORE] The dependent block is a possible dependent block for the lookahead epoch
  if not dag.is_valid_dependent_root(
<<<<<<< HEAD
      preferences.dependent_root, lookaheadEpoch):
    return errIgnore(
      "ProposerPreferences: dependent block is not a possible dependent block")
=======
      preferences.dependent_root, shufflingDependentEpoch):
    return errIgnore("ProposerPreferences: invalid dependent_root")
>>>>>>> f5751db03 (ProposerPreferences: allow genesis dependent root)

  # [REJECT] The validator is the proposer for the given slot in the proposer lookahead
  let proposer = dag.getProposer(
      dependentRef, preferences.proposal_slot).valueOr:
    return errIgnore("ProposerPreferences: unable to compute proposer")
  if proposer.uint64 != preferences.validator_index:
    return dag.checkedReject(
      "ProposerPreferences: validator is not the proposer for the given slot")

  # [REJECT] The signature is valid
  let pubkey = dag.validatorKey(preferences.validator_index).valueOr:
    return dag.checkedReject("ProposerPreferences: invalid validator index")
  if not verify_proposer_preferences_signature(
      dag.forkAtEpoch(proposalEpoch), dag.genesis_validators_root, preferences,
      pubkey, signed_preferences.signature):
    return dag.checkedReject(
      "ProposerPreferences: invalid proposer preferences signature")

  seen[bucket][slotInEpoch][preferences.dependent_root] = preferences
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.13/specs/heze/p2p-interface.md#new-inclusion_list
proc validateInclusionList*(
    dag: ChainDAGRef,
    inclusionListPool: ref InclusionListPool,
    batchCrypto: ref BatchCrypto,
    signed_inclusion_list: SignedInclusionList,
    wallTime: BeaconTime
): Future[Result[void, ValidationError]] {.async: (raises: [CancelledError]).} =
  template message: untyped = signed_inclusion_list.message

  # [REJECT] The size of `message.transactions` is within upperbound
  # `MAX_BYTES_PER_INCLUSION_LIST`.
  block:
    var total = 0'u64
    for transaction in message.transactions:
      total += transaction.lenu64
      if total > dag.cfg.MAX_BYTES_PER_INCLUSION_LIST:
        return dag.checkedReject(
          "InclusionList: transactions exceed MAX_BYTES_PER_INCLUSION_LIST")

  # [IGNORE] The slot `message.slot` is equal to the current slot (with a
  # `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance), i.e.
  # `message.slot == current_slot`.
  block:
    let v = dag.timeParams.check_slot_exact(message.slot, wallTime)
    if v.isErr():
      return err(v.error())

  if dag.cfg.consensusForkAtEpoch(message.slot.epoch) < ConsensusFork.Heze:
    return dag.checkedReject("InclusionList: only valid for Heze fork or later")

  # [IGNORE] The `message` is either the first or second valid message received
  # from the validator with index `message.validator_index`.
  #
  # Checked again when adding to the pool, since concurrent validations of
  # messages from the same validator may each pass this point.
  if inclusionListPool[].numSeen(message.slot, message.validator_index) >=
      MAX_INCLUSION_LISTS_PER_VALIDATOR:
    return errIgnore(
      "InclusionList: already seen two messages from this validator")

  # [REJECT] The message's validator index is in
  # `get_inclusion_list_committee(state, message.slot)`, where `state` is the
  # head state corresponding to processing the block up to the current slot as
  # determined by the fork choice.
  let shufflingRef = dag.getShufflingRef(
      dag.head, message.slot.epoch, false).valueOr:
    return errIgnore("InclusionList: no shuffling for slot")

  var
    committee: InclusionListCommittee
    isMember = false
  for i, validator_index in get_inclusion_list_committee(
      shufflingRef, message.slot):
    committee[i] = validator_index
    isMember = isMember or validator_index == message.validator_index

  if not isMember:
    return dag.checkedReject(
      "InclusionList: validator not in inclusion list committee")

  # [REJECT] The `message.inclusion_list_committee_root` is equal to
  # `hash_tree_root(get_inclusion_list_committee(state, message.slot))`.
  if message.inclusion_list_committee_root != hash_tree_root(committee):
    return dag.checkedReject(
      "InclusionList: inclusion_list_committee_root mismatch")

  # [REJECT] The signature of `signed_inclusion_list.signature` is valid with
  # respect to the validator's public key.
  let
    vidx = ValidatorIndex.init(message.validator_index).valueOr:
      return dag.checkedReject("InclusionList: invalid validator index")
    pubkey = dag.validatorKey(vidx).valueOr:
      return dag.checkedReject("InclusionList: invalid validator index")
    fork = dag.forkAtEpoch(message.slot.epoch)

  let deferredCrypto = batchCrypto.scheduleInclusionListCheck(
    fork, dag.genesis_validators_root, message, pubkey,
    signed_inclusion_list.signature)
  if deferredCrypto.isErr():
    return dag.checkedReject(deferredCrypto.error)

  let (cryptoFut, _) = deferredCrypto.get()
  case await cryptoFut
  of BatchResult.Invalid:
    return dag.checkedReject("InclusionList: invalid signature")
  of BatchResult.Timeout:
    return errIgnore("InclusionList: timeout checking signature")
  of BatchResult.Valid:
    discard

  ok()
