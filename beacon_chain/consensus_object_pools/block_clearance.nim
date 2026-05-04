# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles,
  results,
  ../spec/[
    beaconstate, forks, signatures, signatures_batch,
    state_transition, state_transition_epoch],
  "."/[block_pools_types, block_dag, blockchain_dag,
       blockchain_dag_light_client, block_quarantine]

export results, signatures_batch, block_dag, blockchain_dag

# Clearance
# ---------------------------------------------
#
# This module is in charge of making the
# "quarantined" network blocks
# pass the firewall and be stored in the chain DAG

logScope:
  topics = "clearance"

proc verifyBlockProposer*(
    dag: ChainDAGRef,
    parent: BlockRef,
    slot: Slot,
    proposer_index: uint64,
    blockRoot: Eth2Digest,
    signature: ValidatorSig,
    recentSignatures: RecentSidecarSignatureLru
): Result[void, tuple[msg: cstring, invalid: bool]] =
  ## Verify block proposer and signature, making sure to check that the proposer
  ## was indeed elected for the given slot and that the signature checks out.
  ##
  ## Because the signature only covers the block body (via its root), it's
  ## possible that the block itself is valid while the signature is not: in
  ## this case false is returned for "invalid".
  let proposer = dag.getProposer(parent, slot).valueOr:
    warn "cannot compute proposer for block", parent, slot, proposer_index, blockRoot
    return err(("verifyBlockProposer: cannot compute proposer", false)) # internal issue

  # `getProposer` returns a trusted proposer index, while `proposer_index` may
  # be invalid -> convert the former to the latter
  if distinctBase(proposer) != proposer_index:
    return err(("verifyBlockProposer: unexpected proposer", true))

  # Fast path: If this (block_root, signature) pair was recently verified, skip verification
  if (blockRoot, signature) in recentSignatures:
    return ok()

  let
    proposerKey = dag.validatorKey(proposer).expect("valid after getProposer")
    fork = dag.forkAtEpoch(slot.epoch)
  if not verify_block_signature(
    fork, dag.genesis_validators_root, slot, blockRoot, proposerKey, signature
  ):
    return err(("verifyBlockProposer: invalid signature", false))

  ok()

proc addResolvedHeadBlock(
       dag: ChainDAGRef,
       state: var ForkedHashedBeaconState,
       trustedBlock: ForkyTrustedSignedBeaconBlock,
       optimisticStatus: OptimisticStatus,
       parent: BlockRef, cache: var StateCache,
       onBlockAdded: OnBlockAdded,
       stateDataDur, sigVerifyDur, stateVerifyDur: Duration
     ): BlockRef =
  doAssert state.matches_block_slot(
    trustedBlock.root, trustedBlock.message.slot),
    "Given state must have the new block applied"
  const consensusFork = typeof(trustedBlock).kind

  let
    blockRoot = trustedBlock.root
    blockRef = BlockRef.init(blockRoot, optimisticStatus, trustedBlock.message)
    startTick = Moment.now()

  link(parent, blockRef)

  if optimisticStatus == OptimisticStatus.valid:
    # Since the new block has a valid payload, its ancestors also do but this
    # might be the first time we learn of it
    parent.markExecutionValid(true)

  dag.forkBlocks.incl(KeyedBlockRef.init(blockRef))

  # Resolved blocks should be stored in database
  dag.putBlock(trustedBlock)
  let putBlockTick = Moment.now()

  var foundHead: bool
  for head in dag.heads.mitems():
    if head.isAncestorOf(blockRef):
      head = blockRef
      foundHead = true
      break

  if not foundHead:
    dag.heads.add(blockRef)

  # Regardless of the chain we're on, the deposits come in the same order so
  # as soon as we import a block, we'll also update the shared public key
  # cache
  dag.updateValidatorKeys(state.validators)

  # Getting epochRef with the state will potentially create a new EpochRef
  let
    epochRef = dag.getEpochRef(state, cache)
    epochRefTick = Moment.now()

  debug "Block resolved",
    blockRoot = shortLog(blockRoot),
    blck = shortLog(trustedBlock.message),
    optimisticStatus, heads = dag.heads.len(),
    stateDataDur, sigVerifyDur, stateVerifyDur,
    putBlockDur = putBlockTick - startTick,
    epochRefDur = epochRefTick - putBlockTick

  # Update light client data
  dag.processNewBlockForLightClient(state, trustedBlock, parent.bid)

  # Pre-heat the shuffling cache with the shuffling caused by this block - this
  # is useful for attestation duty lookahead, REST API queries and attestation
  # validation of untaken forks (in case of instability / multiple heads)
  if dag.findShufflingRef(blockRef.bid, blockRef.slot.epoch + 1).isNone:
    dag.putShufflingRef(
      ShufflingRef.init(state, cache, blockRef.slot.epoch + 1))

  # Notify others of the new block before processing the quarantine, such that
  # notifications for parents happens before those of the children
  if onBlockAdded != nil:
    template forkyState: auto = state.forky(consensusFork)
    when consensusFork >= ConsensusFork.Altair:
      let (unrealized, balances) = forkyState.data.compute_unrealized_finality()
      dag.putParticipatingBalances CachedParticipatingBalances(
        bid: blockRef.bid, balances: balances)
    else:
      let unrealized = forkyState.data.compute_unrealized_finality(cache)
    onBlockAdded(blockRef, trustedBlock, forkyState.data, epochRef, unrealized)

  if not(isNil(dag.onBlockAdded)):
    dag.onBlockAdded(ForkedTrustedSignedBeaconBlock.init(trustedBlock))

  blockRef

proc checkStateTransition(
    dag: ChainDAGRef,
    signedBlock: ForkySigVerifiedSignedBeaconBlock,
    cache: var StateCache,
    updateFlags: UpdateFlags,
): Result[void, VerifierError] =
  ## Ensure block can be applied on a state
  func restore(v: var ForkedHashedBeaconState) =
    assign(dag.clearanceState, dag.headState)

  let res = state_transition_block(
      dag.cfg, dag.clearanceState, signedBlock,
      cache, updateFlags, restore)

  if res.isErr():
    info "Invalid block",
      blockRoot = shortLog(signedBlock.root),
      blck = shortLog(signedBlock.message),
      error = res.error()

    err(VerifierError.Invalid)
  else:
    ok()

proc checkHeadBlock*(
    dag: ChainDAGRef, signedBlock: ForkySignedBeaconBlock):
    Result[BlockRef, VerifierError] =
  ## Perform pre-addHeadBlock sanity checks returning the parent to use when
  ## calling `addHeadBlock`.
  ##
  ## This function must be called before `addHeadBlockWithParent`.
  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)
    signature = shortLog(signedBlock.signature)

  template blck(): untyped = signedBlock.message # shortcuts without copy
  template blockRoot(): untyped = signedBlock.root

  # If the block we get is older than what we finalized already, we drop it.
  # One way this can happen is that we start request a block and finalization
  # happens in the meantime - the block we requested will then be stale
  # by the time it gets here.
  if blck.slot <= dag.finalizedHead.slot:
    let existing = dag.getBlockIdAtSlot(blck.slot)
    # The exact slot match ensures we reject blocks that were orphaned in
    # the finalized chain
    if existing.isSome:
      if existing.get().bid.slot == blck.slot and
          existing.get().bid.root == blockRoot:
        debug "Duplicate block"
        return err(VerifierError.Duplicate)

    # Block is older than finalized, but different from the block in our
    # canonical history: it must be from an unviable branch
    debug "Block from unviable fork",
      existing = shortLog(existing.get()),
      finalizedHead = shortLog(dag.finalizedHead),
      tail = shortLog(dag.tail)

    return err(VerifierError.UnviableFork)

  # Check non-finalized blocks as well
  if dag.containsForkBlock(blockRoot):
    return err(VerifierError.Duplicate)

  let parent = dag.getBlockRef(blck.parent_root).valueOr:
    # There are two cases where the parent won't be found: we don't have it or
    # it has been finalized already, and as a result the branch the new block
    # is on is no longer a viable fork candidate - we can't tell which is which
    # at this stage, but we can check if we've seen the parent block previously
    # and thus prevent requests for it to be downloaded again.
    let parentId = dag.getBlockId(blck.parent_root)
    if parentId.isSome() and parentId.get.slot < dag.finalizedHead.slot:
      debug "Block unviable due to pre-finalized-checkpoint parent",
        parentId = parentId.get()
      return err(VerifierError.UnviableFork)

    debug "Block parent unknown or finalized already", parentId
    return err(VerifierError.MissingParent)

  if parent.slot >= blck.slot:
    # A block whose parent is newer than the block itself is clearly invalid -
    # discard it immediately
    debug "Block older than parent",
      parent = shortLog(parent)

    return err(VerifierError.Invalid)

  ok(parent)

proc addHeadBlockWithParent*(
    dag: ChainDAGRef, verifier: var BatchVerifier,
    signedBlock: ForkySignedBeaconBlock, parent: BlockRef,
    optimisticStatus: OptimisticStatus, onBlockAdded: OnBlockAdded
    ): Result[BlockRef, VerifierError] =
  ## Try adding a block to the chain, verifying first that it passes the state
  ## transition function and contains correct cryptographic signature.
  ##
  ## Cryptographic checks can be skipped by adding skipBlsValidation to
  ## dag.updateFlags.
  ##
  ## The parent should be obtained using `checkHeadBlock`.
  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)
    signature = shortLog(signedBlock.signature)

  block:
    # We re-check parent pre-conditions here to avoid the case where the parent
    # has become stale - it is possible that the dag has finalized the parent
    # by the time we get here which will cause us to return early.
    let checkedParent = ? checkHeadBlock(dag, signedBlock)
    if checkedParent != parent:
      # This should never happen: it would mean that the caller supplied a
      # different parent than the block points to!
      error "checkHeadBlock parent mismatch - this is a bug",
        parent = shortLog(parent), checkedParent = shortLog(checkedParent)
      return err(VerifierError.MissingParent)

  # The block is resolved, now it's time to validate it to ensure that the
  # blocks we add to the database are clean for the given state
  let startTick = Moment.now()

  # The clearance state works as the canonical
  # "let's make things permanent" point and saves things to the database -
  # storing things is slow, so we don't want to do so before there's a
  # reasonable chance that the information will become more permanently useful -
  # by the time a new block reaches this point, the parent block will already
  # have "established" itself in the network to some degree at least.
  var cache = StateCache()

  # We've verified that the slot of the new block is newer than that of the
  # parent, so we should now be able to create an appropriate clearance state
  # onto which we can apply the new block
  let
    clearanceBlock = BlockSlotId.init(parent.bid, signedBlock.message.slot)
    updateFlags =
      when typeof(signedBlock).kind >= ConsensusFork.Gloas:
        if isParentBlockFull(dag, signedBlock, parent):
          dag.updateFlags
        else:
          dag.updateFlags + {skipLastEnvelope}
      else:
        dag.updateFlags
  if not updateState(
      dag, dag.clearanceState, clearanceBlock, true, cache, updateFlags):
    # We should never end up here - the parent must be a block no older than and
    # rooted in the finalized checkpoint, hence we should always be able to
    # load its corresponding state
    error "Unable to load clearance state for parent block, database corrupt?",
      clearanceBlock = shortLog(clearanceBlock)
    return err(VerifierError.MissingParent)

  let stateDataTick = Moment.now()

  # First, batch-verify all signatures in block
  if skipBlsValidation notin dag.updateFlags:
    # TODO: remove skipBlsValidation
    var sigs: seq[SignatureSet]
    sigs.collectSignatureSets(
      signedBlock, dag.db.immutableValidators, dag.clearanceState,
      dag.cfg.GENESIS_FORK_VERSION, dag.cfg.CAPELLA_FORK_VERSION, cache,
    ).isOkOr:
      # A PublicKey or Signature isn't on the BLS12-381 curve
      info "Unable to load signature sets", err = error
      return err(VerifierError.Invalid)

    if not verifier.batchVerify(sigs):
      info "Block batch signature verification failed",
        signature = shortLog(signedBlock.signature)
      return err(VerifierError.Invalid)

  let sigVerifyTick = Moment.now()

  ? checkStateTransition(dag, signedBlock.asSigVerified(), cache,
                         dag.updateFlags)

  let stateVerifyTick = Moment.now()
  # Careful, clearanceState.data has been updated but not blck - we need to
  # create the BlockRef first!
  ok addResolvedHeadBlock(
    dag, dag.clearanceState,
    signedBlock.asTrusted(),
    optimisticStatus,
    parent, cache,
    onBlockAdded,
    stateDataDur = stateDataTick - startTick,
    sigVerifyDur = sigVerifyTick - stateDataTick,
    stateVerifyDur = stateVerifyTick - sigVerifyTick)

proc addBackfillBlock*(
    dag: ChainDAGRef,
    signedBlock: ForkySignedBeaconBlock | ForkySigVerifiedSignedBeaconBlock):
      Result[void, VerifierError] =
  ## When performing checkpoint sync, we need to backfill historical blocks
  ## in order to respond to GetBlocksByRange requests. Backfill blocks are
  ## added in backwards order, one by one, based on the `parent_root` of the
  ## earliest block we know about.
  ##
  ## Because only one history is relevant when backfilling, one doesn't have to
  ## consider forks or other finalization-related issues - a block is either
  ## valid and finalized, or not.
  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)
    signature = shortLog(signedBlock.signature)
    backfill = shortLog(dag.backfill)

  template blck(): untyped = signedBlock.message # shortcuts without copy
  template blockRoot(): untyped = signedBlock.root
  template checkSignature =
    # If the hash is correct, the block itself must be correct, but the root does
    # not cover the signature, which we check next
    when signedBlock.signature isnot TrustedSig:
      if blck.slot == GENESIS_SLOT:
        # The genesis block must have an empty signature (since there's no proposer)
        if signedBlock.signature != ValidatorSig():
          info "Invalid genesis block signature"
          return err(VerifierError.Invalid)
      else:
        let proposerKey = dag.validatorKey(blck.proposer_index).valueOr:
          # We've verified that the block root matches our expectations by following
          # the chain of parents all the way from checkpoint. If all those blocks
          # were valid, the proposer_index in this block must also be valid, and we
          # should have a key for it but we don't: this is either a bug on our from
          # which we cannot recover, or an invalid checkpoint state was given in which
          # case we're in trouble.
          fatal "Invalid proposer in backfill block - checkpoint state corrupt?",
            head = shortLog(dag.head), tail = shortLog(dag.tail)

          quit 1

        if not verify_block_signature(
            dag.forkAtEpoch(blck.slot.epoch),
            dag.headState.genesis_validators_root,
            blck.slot,
            signedBlock.root,
            proposerKey,
            signedBlock.signature):
          info "Block signature verification failed"
          return err(VerifierError.Invalid)

  let startTick = Moment.now()

  if blck.slot >= dag.backfill.slot:
    let existing = dag.getBlockIdAtSlot(blck.slot)
    if existing.isSome:
      if existing.get().bid.slot == blck.slot and
          existing.get().bid.root == blockRoot:
        let isDuplicate = dag.containsBlock(existing.get().bid)
        if isDuplicate:
          debug "Duplicate block"
        else:
          checkSignature()
          debug "Block backfilled (known BlockId)"
          dag.putBlock(signedBlock.asTrusted())

        if blockRoot == dag.backfill.parent_root:
          dag.backfill = blck.toBeaconBlockSummary()

        return
          if isDuplicate:
            err(VerifierError.Duplicate)
          else:
            ok()

      # Block is older than finalized, but different from the block in our
      # canonical history: it must be from an unviable branch
      debug "Block from unviable fork",
        existing = shortLog(existing.get()),
        finalizedHead = shortLog(dag.finalizedHead)

      return err(VerifierError.UnviableFork)

  if dag.frontfill.isSome():
    let frontfill = dag.frontfill.get()
    if blck.slot == frontfill.slot and
        dag.backfill.parent_root == frontfill.root:
      if blockRoot != frontfill.root:
        # We've matched the backfill blocks all the way back to frontfill via the
        # `parent_root` chain and ended up at a different block - one way this
        # can happen is when an invalid `--network` parameter is given during
        # startup (though in theory, we check that - maybe the database was
        # swapped or something?).
        fatal "Checkpoint given during initial startup inconsistent with genesis block - wrong network used when starting the node?",
          tail = shortLog(dag.tail), head = shortLog(dag.head)
        quit 1

      # Signal that we're done by resetting backfill
      reset(dag.backfill)
      dag.db.finalizedBlocks.insert(blck.slot, blockRoot)
      dag.updateFrontfillBlocks()

      notice "Received final block during backfill, backfill complete"

      # Backfill done - dag.backfill.slot now points to genesis block just like
      # it would if we loaded a fully synced database - returning duplicate
      # here is appropriate, though one could also call it ... ok?
      return err(VerifierError.Duplicate)

  if dag.backfill.parent_root != blockRoot:
    debug "Block does not match expected backfill root"
    return err(VerifierError.MissingParent) # MissingChild really, but ..

  if blck.slot < dag.horizon:
    # This can happen as the horizon keeps moving - we'll discard it as
    # duplicate since it would have duplicated an existing block had we been
    # interested
    debug "Block past horizon, dropping", horizon = dag.horizon
    return err(VerifierError.Duplicate)

  checkSignature()

  let sigVerifyTick = Moment.now

  dag.putBlock(signedBlock.asTrusted())
  dag.db.finalizedBlocks.insert(blck.slot, blockRoot)

  dag.backfill = blck.toBeaconBlockSummary()

  let putBlockTick = Moment.now
  debug "Block backfilled",
    sigVerifyDur = sigVerifyTick - startTick,
    putBlockDur = putBlockTick - sigVerifyTick

  ok()

proc addHeadExecutionPayload*(
    dag: ChainDAGRef,
    signedBlock: gloas.SignedBeaconBlock,
    signedEnvelope: gloas.SignedExecutionPayloadEnvelope,
): Result[BlockRef, VerifierError] =
  ## Try adding the execution payload envelope to the head block, which should
  ## usually be invoked after the call of addHeadBlockWithParent()
  ##
  ## First check that the block and envelope are matched with the DAG block.
  ## Then verify that it passes the state transition function.

  # Check if there is any valid envelope so that we can save some resources.
  if dag.db.containsExecutionPayloadEnvelope(signedBlock.root):
    return err(VerifierError.Duplicate)

  template envelopeBlockRoot(): auto = signedEnvelope.message.beacon_block_root
  template envelopeSlot(): auto = signedEnvelope.message.slot

  logScope:
    blockRoot = shortLog(envelopeBlockRoot)
    builderIdx = signedEnvelope.message.builder_index
    slot = envelopeSlot
    signature = shortLog(signedEnvelope.signature)

  const consensusFork = typeof(signedBlock).kind

  # Quick check between the received block and envelope.
  template bid(): auto =
    signedBlock.message.body.signed_execution_payload_bid.message
  if not (
    signedBlock.message.slot == envelopeSlot and
    signedBlock.root == envelopeBlockRoot and
    bid.builder_index == signedEnvelope.message.builder_index and
    bid.block_hash == signedEnvelope.message.payload.block_hash
  ):
    info "Envelope mismatches with this block"
    return err(VerifierError.Invalid)

  # Check if the block is valid and non-finalized.
  let blck = dag.getBlockRef(envelopeBlockRoot).valueOr:
    let blckId = dag.getBlockId(envelopeBlockRoot)
    if blckId.isSome() and blckId.get().slot < dag.finalizedHead.slot:
      return err(VerifierError.UnviableFork)
    return err(VerifierError.MissingParent)

  # Load state cache for updateState() and state transition.
  var cache: StateCache
  loadStateCache(dag, cache, blck.bid, blck.slot().epoch())

  # We need to move state back to the exact block time in order to validate the
  # envelope with state, as the block could be older than the head.
  let blckBsi = BlockSlotId.init(blck.bid, envelopeSlot)
  if not updateState(
      dag, dag.clearanceState, blckBsi, false, cache,
      dag.updateFlags + {skipLastEnvelope}):
    # If updateState() fails, it means there may be some missing blocks and
    # envelopes of its parents, or the database is corrupted.
    error "Unable to load clearance state for envelope, database corrupt?",
      clearanceBlock = shortLog(blckBsi)
    return err(VerifierError.MissingParent)

  # Validate the envelope with state. Slot and latest block root in state should
  # match with the envelope.
  if not (
      dag.clearanceState.slot() == envelopeSlot and
      dag.clearanceState.latest_block_root() == envelopeBlockRoot
  ):
    debug "Envelope is not for the current head"
    return err(VerifierError.Invalid)
  # With skipLastEnvelope flag and containsExecutionPayloadEnvelope() check
  # above, the envelope should have not been applied but double check.
  elif dag.clearanceState.forky(consensusFork).data.latest_block_hash ==
       signedEnvelope.message.payload.block_hash:
    debug "Envelope has been applied to the state"
    return err(VerifierError.Duplicate)

  # Verify with state transition function.
  verify_execution_payload_envelope(
      dag.timeParams,
      dag.forkAtEpoch(envelopeSlot.epoch),
      dag.clearanceState.forky(consensusFork),
      signedEnvelope,
      dag.genesis_validators_root).isOkOr:
    debug "Envelope verification failed", reason = error
    return err(VerifierError.Invalid)

  # Put the envelope into db and update optimistic status for the block.
  dag.db.putExecutionPayloadEnvelope(signedEnvelope)

  # https://github.com/ethereum/beacon-APIs/blob/v5.0.0-alpha.1/apis/eventstream/index.yaml
  # `execution_payload_available`: "The node has verified that the execution
  # payload and blobs for a block are available and ready for payload
  # attestation"; emit after envelope in database and REST-queryable.
  if not isNil(dag.onEnvelopeAvailable):
    dag.onEnvelopeAvailable(signedEnvelope)

  ok(blck)

proc addBackfillExecutionPayload*(
    dag: ChainDAGRef,
    signedEnvelope: gloas.SignedExecutionPayloadEnvelope,
): Result[void, VerifierError] =
  template blockRoot(): auto = signedEnvelope.message.beacon_block_root
  template envelope(): auto = signedEnvelope.message

  logScope:
    blockRoot = shortLog(blockRoot)
    slot = envelope.slot
    signature = shortLog(signedEnvelope.signature)
    backfill = shortLog(dag.backfill)

  let startTick = Moment.now()

  # When a valid block is backfilled, dag.backfill has already moved to next
  # parent. So we need to check with finalizedHead and database.
  if envelope.slot > dag.finalizedHead.slot:
    return err(VerifierError.Invalid)

  # Check root and slot of the block
  let bsi = dag.getBlockIdAtSlot(envelope.slot).valueOr:
    # This should not be happening as we backfill envelope after the block is
    # backfilled successfully.
    return err(VerifierError.Invalid)
  if blockRoot != bsi.bid.root:
    return err(VerifierError.Invalid)
  if dag.db.containsExecutionPayloadEnvelope(blockRoot):
    return err(VerifierError.Duplicate)

  let (builderIdx, bidBuilderIdx) = block:
    let forkedBlck = dag.getForkedBlock(bsi.bid).valueOr:
      # The block should exist as we have checked above. Database may be
      # corrupted.
      debug "Backfill envelope cannot find forked block, database corrupt?"
      return err(VerifierError.Invalid)
    withBlck(forkedBlck):
      when consensusFork >= ConsensusFork.Gloas:
        template bid(): auto =
          forkyBlck.message.body.signed_execution_payload_bid
        (forkyBlck.builder_index, bid.message.builder_index)
      else:
        return err(VerifierError.UnviableFork)

  # Check builder index is matched with the block
  if bidBuilderIdx != envelope.builder_index:
    return err(VerifierError.Invalid)

  # Verify signature
  let builderKey = dag.validatorKey(builderIdx).valueOr:
    fatal "Invalid builder in backfill envelope - checkpoint state corrupt?",
      head = shortLog(dag.head), tail = shortLog(dag.tail)
    quit 1
  if not verify_execution_payload_envelope_signature(
      dag.forkAtEpoch(envelope.slot.epoch),
      dag.genesis_validators_root,
      envelope.slot.epoch,
      envelope,
      builderKey,
      signedEnvelope.signature):
    return err(VerifierError.Invalid)
  let sigVerifyTick = Moment.now

  dag.db.putExecutionPayloadEnvelope(signedEnvelope)
  let putBlockTick = Moment.now

  debug "Envelope backfilled",
    sigVerifyDur = sigVerifyTick - startTick,
    putBlockDur = putBlockTick - sigVerifyTick

  ok()

proc verifyBlockSignatures*(
    verifier: var BatchVerifier,
    fork: Fork,
    genesis_validators_root: Eth2Digest,
    immutableValidators: openArray[ImmutableValidatorData2],
    blocks: openArray[ForkedSignedBeaconBlock]
): Result[void, string] =
  var sigs: seq[SignatureSet]

  ? sigs.collectProposerSignatureSet(
    blocks, immutableValidators, fork, genesis_validators_root)

  if not verifier.batchVerify(sigs):
    err("Block batch signature verification failed")
  else:
    ok()

proc addLightForwardBlock*(
    dag: ChainDAGRef,
    consensusFork: static ConsensusFork,
    bdata: BlockData,
    onStateUpdated: OnStateUpdated,
    onBlockAdded: OnBlockAdded,
): Result[void, VerifierError] =
  var cache = StateCache()
  template forkyBlck: untyped = bdata.blck.forky(consensusFork)
  let
    parent = checkHeadBlock(dag, forkyBlck).valueOr:
      if error == VerifierError.Duplicate:
        return ok()
      return err(error)
    startTick = Moment.now()
    clearanceBlock = BlockSlotId.init(parent.bid, forkyBlck.message.slot)
    updateFlags1 = dag.updateFlags
      # TODO (cheatfate): {skipLastStateRootCalculation} flag here could
      # improve performance by 100%, but this approach needs some
      # improvements, which is unclear.

  if not updateState(dag, dag.clearanceState, clearanceBlock, true, cache,
                      updateFlags1):
    error "Unable to load clearance state for parent block, " &
          "database corrupt?", clearanceBlock = shortLog(clearanceBlock)
    return err(VerifierError.MissingParent)

  let proposerVerifyTick = Moment.now()

  if not(isNil(onStateUpdated)):
    ? onStateUpdated(forkyBlck.message.slot)

  let
    stateDataTick = Moment.now()
    updateFlags2 =
      dag.updateFlags + {skipBlsValidation, skipStateRootValidation}

  ? checkStateTransition(dag, forkyBlck.asSigVerified(), cache, updateFlags2)

  let stateVerifyTick = Moment.now()

  if bdata.blob.isSome():
    for blob in bdata.blob.get():
      dag.db.putBlobSidecar(blob[])

  discard addResolvedHeadBlock(
    dag, dag.clearanceState,
    forkyBlck.asTrusted(),
    OptimisticStatus.notValidated,
    parent, cache,
    onBlockAdded,
    proposerVerifyTick - startTick,
    stateDataTick - proposerVerifyTick,
    stateVerifyTick - stateDataTick)

  ok()
