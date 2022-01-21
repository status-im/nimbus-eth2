# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronicles,
  stew/[assign2, results],
  ../spec/[forks, signatures, signatures_batch, state_transition],
  "."/[block_dag, blockchain_dag]

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
       state: var StateData,
       trustedBlock: ForkyTrustedSignedBeaconBlock,
       parent: BlockRef, cache: var StateCache,
       onBlockAdded: OnPhase0BlockAdded | OnAltairBlockAdded | OnMergeBlockAdded,
       stateDataDur, sigVerifyDur, stateVerifyDur: Duration
     ): BlockRef =
  doAssert getStateField(state.data, slot) == trustedBlock.message.slot,
    "state must match block"
  doAssert state.blck.root == trustedBlock.message.parent_root,
    "the StateData passed into the addResolved function not yet updated!"

  let
    blockRoot = trustedBlock.root
    blockRef = BlockRef.init(blockRoot, trustedBlock.message)
    startTick = Moment.now()

  link(parent, blockRef)

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

  # Up to here, state.data was referring to the new state after the block had
  # been applied but the `blck` field was still set to the parent
  state.blck = blockRef

  # Regardless of the chain we're on, the deposits come in the same order so
  # as soon as we import a block, we'll also update the shared public key
  # cache

  dag.updateValidatorKeys(getStateField(state.data, validators).asSeq())

  # Getting epochRef with the state will potentially create a new EpochRef
  let
    epochRef = dag.getEpochRef(state, cache)
    epochRefTick = Moment.now()

  debug "Block resolved",
    blockRoot = shortLog(blockRoot),
    blck = shortLog(trustedBlock.message),
    heads = dag.heads.len(),
    stateDataDur, sigVerifyDur, stateVerifyDur,
    putBlockDur = putBlockTick - startTick,
    epochRefDur = epochRefTick - putBlockTick

  # Notify others of the new block before processing the quarantine, such that
  # notifications for parents happens before those of the children
  if onBlockAdded != nil:
    onBlockAdded(blockRef, trustedBlock, epochRef)
  if not(isNil(dag.onBlockAdded)):
    dag.onBlockAdded(ForkedTrustedSignedBeaconBlock.init(trustedBlock))

  blockRef

proc checkStateTransition(
       dag: ChainDAGRef, signedBlock: SomeForkySignedBeaconBlock,
       cache: var StateCache): Result[void, BlockError] =
  ## Ensure block can be applied on a state
  func restore(v: var ForkedHashedBeaconState) =
    # TODO address this ugly workaround - there should probably be a
    #      `state_transition` that takes a `StateData` instead and updates
    #      the block as well
    doAssert v.addr == addr dag.clearanceState.data
    assign(dag.clearanceState, dag.headState)

  let res = state_transition_block(
      dag.cfg, dag.clearanceState.data, signedBlock,
      cache, dag.updateFlags, restore)
  if res.isErr():
    info "Invalid block",
      blockRoot = shortLog(signedBlock.root),
      blck = shortLog(signedBlock.message),
      error = res.error()

    err(BlockError.Invalid)
  else:
    ok()

proc advanceClearanceState*(dag: ChainDAGRef) =
  # When the chain is synced, the most likely block to be produced is the block
  # right after head - we can exploit this assumption and advance the state
  # to that slot before the block arrives, thus allowing us to do the expensive
  # epoch transition ahead of time.
  # Notably, we use the clearance state here because that's where the block will
  # first be seen - later, this state will be copied to the head state!
  if dag.clearanceState.blck.slot == getStateField(dag.clearanceState.data, slot):
    let next =
      dag.clearanceState.blck.atSlot(dag.clearanceState.blck.slot + 1)

    let startTick = Moment.now()
    var cache = StateCache()
    if not updateStateData(dag, dag.clearanceState, next, true, cache):
      # The next head update will likely fail - something is very wrong here
      error "Cannot advance to next slot, database corrupt?",
        clearance = shortLog(dag.clearanceState.blck),
        next = shortLog(next)
    else:
      debug "Prepared clearance state for next block",
        next, updateStateDur = Moment.now() - startTick

proc addHeadBlock*(
    dag: ChainDAGRef, verifier: var BatchVerifier,
    signedBlock: ForkySignedBeaconBlock,
    onBlockAdded: OnPhase0BlockAdded | OnAltairBlockAdded | OnMergeBlockAdded
    ): Result[BlockRef, BlockError] =
  ## Try adding a block to the chain, verifying first that it passes the state
  ## transition function and contains correct cryptographic signature.
  ##
  ## Cryptographic checks can be skipped by adding skipBLSValidation to dag.updateFlags
  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)

  template blck(): untyped = signedBlock.message # shortcuts without copy
  template blockRoot(): untyped = signedBlock.root

  # If the block we get is older than what we finalized already, we drop it.
  # One way this can happen is that we start request a block and finalization
  # happens in the meantime - the block we requested will then be stale
  # by the time it gets here.
  if blck.slot <= dag.finalizedHead.slot:
    let previous = dag.getBlockIdAtSlot(blck.slot)
    if previous.isProposed() and blockRoot == previous.bid.root:
      # We should not call the block added callback for blocks that already
      # existed in the pool, as that may confuse consumers such as the fork
      # choice.
      debug "Duplicate block"
      return err(BlockError.Duplicate)

    # Block is older than finalized, but different from the block in our
    # canonical history: it must be from an unviable branch
    debug "Block from unviable fork",
      finalizedHead = shortLog(dag.finalizedHead),
      tail = shortLog(dag.tail)

    return err(BlockError.UnviableFork)

  # Check non-finalized blocks as well
  if dag.containsForkBlock(blockRoot):
    return err(BlockError.Duplicate)

  let parent = dag.getBlockRef(blck.parent_root).valueOr:
    # There are two cases where the parent won't be found: we don't have it or
    # it has been finalized already, and as a result the branch the new block
    # is on is no longer a viable fork candidate - we can't tell which is which
    # at this stage, but we can check if we've seen the parent block previously
    # and thus prevent requests for it to be downloaded again.
    if dag.db.containsBlock(blck.parent_root):
      debug "Block unviable due to pre-finalized-checkpoint parent"
      return err(BlockError.UnviableFork)

    debug "Block parent unknown or finalized already"
    return err(BlockError.MissingParent)

  if parent.slot >= signedBlock.message.slot:
    # A block whose parent is newer than the block itself is clearly invalid -
    # discard it immediately
    debug "Block with invalid parent",
      parentBlock = shortLog(parent)

    return err(BlockError.Invalid)

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
  if not updateStateData(
      dag, dag.clearanceState, parent.atSlot(signedBlock.message.slot), true,
      cache):
    # We should never end up here - the parent must be a block no older than and
    # rooted in the finalized checkpoint, hence we should always be able to
    # load its corresponding state
    error "Unable to load clearance state for parent block, database corrupt?",
      parent = shortLog(parent.atSlot(signedBlock.message.slot)),
      clearance = shortLog(dag.clearanceState.blck)
    return err(BlockError.MissingParent)

  let stateDataTick = Moment.now()

  # First, batch-verify all signatures in block
  if skipBLSValidation notin dag.updateFlags:
    # TODO: remove skipBLSValidation
    var sigs: seq[SignatureSet]
    if (let e = sigs.collectSignatureSets(
        signedBlock, dag.db.immutableValidators,
        dag.clearanceState.data, cache); e.isErr()):
      # A PublicKey or Signature isn't on the BLS12-381 curve
      info "Unable to load signature sets",
        err = e.error()

      return err(BlockError.Invalid)
    if not verifier.batchVerify(sigs):
      info "Block signature verification failed",
        signature = shortLog(signedBlock.signature)
      return err(BlockError.Invalid)

  let sigVerifyTick = Moment.now()

  ? checkStateTransition(dag, signedBlock.asSigVerified(), cache)

  let stateVerifyTick = Moment.now()
  # Careful, clearanceState.data has been updated but not blck - we need to
  # create the BlockRef first!
  ok addResolvedHeadBlock(
    dag, dag.clearanceState,
    signedBlock.asTrusted(),
    parent, cache,
    onBlockAdded,
    stateDataDur = stateDataTick - startTick,
    sigVerifyDur = sigVerifyTick - stateDataTick,
    stateVerifyDur = stateVerifyTick - sigVerifyTick)

proc addBackfillBlock*(
    dag: ChainDAGRef,
    signedBlock: ForkySignedBeaconBlock): Result[void, BlockError] =
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
    backfill = (dag.backfill.slot, shortLog(dag.backfill.parent_root))

  template blck(): untyped = signedBlock.message # shortcuts without copy
  template blockRoot(): untyped = signedBlock.root

  let startTick = Moment.now()

  if blck.slot >= dag.backfill.slot:
    let previous = dag.getBlockIdAtSlot(blck.slot)
    if previous.isProposed() and blockRoot == previous.bid.root:
      # We should not call the block added callback for blocks that already
      # existed in the pool, as that may confuse consumers such as the fork
      # choice. While the validation result won't be accessed, it's IGNORE,
      # according to the spec.
      return err(BlockError.Duplicate)

    # Block is older than finalized, but different from the block in our
    # canonical history: it must be from an unviable branch
    debug "Block from unviable fork",
      finalizedHead = shortLog(dag.finalizedHead),
      backfill = shortLog(dag.backfill)

    return err(BlockError.UnviableFork)

  if blck.slot == dag.genesis.slot and
      dag.backfill.parent_root == dag.genesis.root:
    if blockRoot != dag.genesis.root:
      # We've matched the backfill blocks all the way back to genesis via the
      # `parent_root` chain and ended up at a different genesis - one way this
      # can happen is when an invalid `--network` parameter is given during
      # startup (though in theory, we check that - maybe the database was
      # swapped or something?).
      fatal "Checkpoint given during initial startup inconsistent with genesis - wrong network used when starting the node?"
      quit 1

    dag.backfillBlocks[blck.slot.int] = blockRoot
    dag.backfill = blck.toBeaconBlockSummary()

    notice "Received matching genesis block during backfill, backfill complete"

    # Backfill done - dag.backfill.slot now points to genesis block just like
    # it would if we loaded a fully backfilled database - returning duplicate
    # here is appropriate, though one could also call it ... ok?
    return err(BlockError.Duplicate)

  if dag.backfill.parent_root != blockRoot:
    debug "Block does not match expected backfill root"
    return err(BlockError.MissingParent) # MissingChild really, but ..

  # If the hash is correct, the block itself must be correct, but the root does
  # not cover the signature, which we check next

  let proposerKey = dag.validatorKey(blck.proposer_index)
  if proposerKey.isNone():
    # This cannot happen, in theory, unless the checkpoint state is broken or
    # there is a bug in our validator key caching scheme - in order not to
    # send invalid attestations, we'll shut down defensively here - this might
    # need revisiting in the future.
    fatal "Invalid proposer in backfill block - checkpoint state corrupt?"
    quit 1

  if not verify_block_signature(
      dag.forkAtEpoch(blck.slot.epoch),
      getStateField(dag.headState.data, genesis_validators_root),
      blck.slot,
      signedBlock.root,
      proposerKey.get(),
      signedBlock.signature):
    info "Block signature verification failed",
      signature = shortLog(signedBlock.signature)
    return err(BlockError.Invalid)
  let sigVerifyTick = Moment.now

  dag.putBlock(signedBlock.asTrusted())

  # Invariants maintained on startup
  doAssert dag.backfillBlocks.lenu64 == dag.tail.slot.uint64
  doAssert dag.backfillBlocks.lenu64 > blck.slot.uint64

  dag.backfillBlocks[blck.slot.int] = blockRoot
  dag.backfill = blck.toBeaconBlockSummary()

  let putBlockTick = Moment.now
  debug "Block backfilled",
    sigVerifyDur = sigVerifyTick - startTick,
    putBlockDur = putBlocktick - sigVerifyTick

  ok()
