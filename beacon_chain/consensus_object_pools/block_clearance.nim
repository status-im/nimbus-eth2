# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles,
  stew/[assign2, results],
  ../spec/[
    beaconstate, forks, signatures, signatures_batch,
    state_transition, state_transition_epoch],
  "."/[block_dag, blockchain_dag, blockchain_dag_light_client]

from ../spec/datatypes/capella import asSigVerified, asTrusted, shortLog
from ../spec/datatypes/deneb import asSigVerified, asTrusted, shortLog

export results, signatures_batch, block_dag, blockchain_dag

# Clearance
# ---------------------------------------------
#
# This module is in charge of making the
# "quarantined" network blocks
# pass the firewall and be stored in the chain DAG

logScope:
  topics = "clearance"

proc addResolvedHeadBlock(
       dag: ChainDAGRef,
       state: var ForkedHashedBeaconState,
       trustedBlock: ForkyTrustedSignedBeaconBlock,
       executionValid: bool,
       parent: BlockRef, cache: var StateCache,
       onBlockAdded: OnForkyBlockAdded,
       stateDataDur, sigVerifyDur, stateVerifyDur: Duration
     ): BlockRef =
  doAssert state.matches_block_slot(
    trustedBlock.root, trustedBlock.message.slot),
    "Given state must have the new block applied"

  let
    blockRoot = trustedBlock.root
    blockRef = BlockRef.init(
      blockRoot, executionValid = executionValid, trustedBlock.message)
    startTick = Moment.now()

  link(parent, blockRef)

  if executionValid:
    dag.markBlockVerified(blockRef)

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
  dag.updateValidatorKeys(getStateField(state, validators).asSeq())

  # Getting epochRef with the state will potentially create a new EpochRef
  let
    epochRef = dag.getEpochRef(state, cache)
    epochRefTick = Moment.now()

  debug "Block resolved",
    blockRoot = shortLog(blockRoot),
    blck = shortLog(trustedBlock.message),
    executionValid, heads = dag.heads.len(),
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
    let unrealized = withState(state):
      when consensusFork >= ConsensusFork.Altair:
        forkyState.data.compute_unrealized_finality()
      else:
        forkyState.data.compute_unrealized_finality(cache)
    onBlockAdded(blockRef, trustedBlock, epochRef, unrealized)
  if not(isNil(dag.onBlockAdded)):
    dag.onBlockAdded(ForkedTrustedSignedBeaconBlock.init(trustedBlock))

  blockRef

proc checkStateTransition(
       dag: ChainDAGRef, signedBlock: ForkySigVerifiedSignedBeaconBlock,
       cache: var StateCache): Result[void, VerifierError] =
  ## Ensure block can be applied on a state
  func restore(v: var ForkedHashedBeaconState) =
    assign(dag.clearanceState, dag.headState)

  let res = state_transition_block(
      dag.cfg, dag.clearanceState, signedBlock,
      cache, dag.updateFlags, restore)

  if res.isErr():
    info "Invalid block",
      blockRoot = shortLog(signedBlock.root),
      blck = shortLog(signedBlock.message),
      error = res.error()

    err(VerifierError.Invalid)
  else:
    ok()

proc advanceClearanceState*(dag: ChainDAGRef) =
  # When the chain is synced, the most likely block to be produced is the block
  # right after head - we can exploit this assumption and advance the state
  # to that slot before the block arrives, thus allowing us to do the expensive
  # epoch transition ahead of time.
  # Notably, we use the clearance state here because that's where the block will
  # first be seen - later, this state will be copied to the head state!
  let advanced = withState(dag.clearanceState):
    forkyState.data.slot > forkyState.data.latest_block_header.slot
  if not advanced:
    let next = getStateField(dag.clearanceState, slot) + 1

    let startTick = Moment.now()
    var
      cache = StateCache()
      info = ForkedEpochInfo()

    dag.advanceSlots(dag.clearanceState, next, true, cache, info)

    debug "Prepared clearance state for next block",
      next, updateStateDur = Moment.now() - startTick

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
    executionValid: bool, onBlockAdded: OnForkyBlockAdded
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
  # parent, so we should now be able to create an approriate clearance state
  # onto which we can apply the new block
  let clearanceBlock = BlockSlotId.init(parent.bid, signedBlock.message.slot)
  if not updateState(
      dag, dag.clearanceState, clearanceBlock, true, cache):
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
    if (let e = sigs.collectSignatureSets(
        signedBlock, dag.db.immutableValidators,
        dag.clearanceState, dag.cfg.genesisFork(), dag.cfg.capellaFork(),
        cache); e.isErr()):
      # A PublicKey or Signature isn't on the BLS12-381 curve
      info "Unable to load signature sets",
        err = e.error()
      return err(VerifierError.Invalid)

    if not verifier.batchVerify(sigs):
      info "Block batch signature verification failed",
        signature = shortLog(signedBlock.signature)
      return err(VerifierError.Invalid)

  let sigVerifyTick = Moment.now()

  ? checkStateTransition(dag, signedBlock.asSigVerified(), cache)

  let stateVerifyTick = Moment.now()
  # Careful, clearanceState.data has been updated but not blck - we need to
  # create the BlockRef first!
  ok addResolvedHeadBlock(
    dag, dag.clearanceState,
    signedBlock.asTrusted(),
    executionValid,
    parent, cache,
    onBlockAdded,
    stateDataDur = stateDataTick - startTick,
    sigVerifyDur = sigVerifyTick - stateDataTick,
    stateVerifyDur = stateVerifyTick - sigVerifyTick)

proc addHeadBlock*(
    dag: ChainDAGRef, verifier: var BatchVerifier,
    signedBlock: ForkySignedBeaconBlock,
    executionValid: bool,
    onBlockAdded: OnForkyBlockAdded
    ): Result[BlockRef, VerifierError] =
  addHeadBlockWithParent(
    dag, verifier, signedBlock, ? dag.checkHeadBlock(signedBlock),
    executionValid, onBlockAdded)

proc addHeadBlock*(
    dag: ChainDAGRef, verifier: var BatchVerifier,
    signedBlock: ForkySignedBeaconBlock,
    onBlockAdded: OnForkyBlockAdded
    ): Result[BlockRef, VerifierError] =
  addHeadBlockWithParent(
    dag, verifier, signedBlock, ? dag.checkHeadBlock(signedBlock),
    executionValid = true, onBlockAdded)

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
    backfill = (dag.backfill.slot, shortLog(dag.backfill.parent_root))

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
        let proposerKey = dag.validatorKey(blck.proposer_index)
        if proposerKey.isNone():
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
            getStateField(dag.headState, genesis_validators_root),
            blck.slot,
            signedBlock.root,
            proposerKey.get(),
            signedBlock.signature):
          info "Block signature verification failed"
          return err(VerifierError.Invalid)

  let startTick = Moment.now()

  if blck.slot >= dag.backfill.slot:
    let existing = dag.getBlockIdAtSlot(blck.slot)
    if existing.isSome:
      if existing.get().bid.slot == blck.slot and
          existing.get().bid.root == blockRoot:

        # Special case: when starting with only a checkpoint state, we will not
        # have the head block data in the database
        if dag.getForkedBlock(existing.get().bid).isNone():
          checkSignature()

          debug "Block backfilled (checkpoint)"
          dag.putBlock(signedBlock.asTrusted())
          return ok()

        debug "Duplicate block"
        return err(VerifierError.Duplicate)

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
