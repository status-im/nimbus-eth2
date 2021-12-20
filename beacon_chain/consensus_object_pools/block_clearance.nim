# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/tables,
  chronicles,
  stew/[assign2, results],
  eth/keys,
  ".."/[beacon_clock],
  ../spec/[
    eth2_merkleization, forks, helpers, signatures, signatures_batch,
    state_transition],
  ../spec/datatypes/[phase0, altair, merge],
  "."/[blockchain_dag]

export results, signatures_batch

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

  dag.blocks.incl(KeyedBlockRef.init(blockRef))

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

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
type SomeSignedBlock =
  phase0.SignedBeaconBlock | phase0.SigVerifiedSignedBeaconBlock |
  phase0.TrustedSignedBeaconBlock |
  altair.SignedBeaconBlock | altair.SigVerifiedSignedBeaconBlock |
  altair.TrustedSignedBeaconBlock |
  merge.SignedBeaconBlock | merge.SigVerifiedSignedBeaconBlock |
  merge.TrustedSignedBeaconBlock
proc checkStateTransition(
       dag: ChainDAGRef, signedBlock: SomeSignedBlock,
       cache: var StateCache): Result[void, BlockError] =
  ## Ensure block can be applied on a state
  func restore(v: var ForkedHashedBeaconState) =
    # TODO address this ugly workaround - there should probably be a
    #      `state_transition` that takes a `StateData` instead and updates
    #      the block as well
    doAssert v.addr == addr dag.clearanceState.data
    assign(dag.clearanceState, dag.headState)

  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)

  if not state_transition_block(
      dag.cfg, dag.clearanceState.data, signedBlock,
      cache, dag.updateFlags, restore):
    info "Invalid block"

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
    updateStateData(dag, dag.clearanceState, next, true, cache)

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

  if blockRoot in dag:
    debug "Block already exists"

    # We should not call the block added callback for blocks that already
    # existed in the pool, as that may confuse consumers such as the fork
    # choice. While the validation result won't be accessed, it's IGNORE,
    # according to the spec.
    return err(BlockError.Duplicate)

  # If the block we get is older than what we finalized already, we drop it.
  # One way this can happen is that we start request a block and finalization
  # happens in the meantime - the block we requested will then be stale
  # by the time it gets here.
  if blck.slot <= dag.finalizedHead.slot:
    debug "Old block, dropping",
      finalizedHead = shortLog(dag.finalizedHead),
      tail = shortLog(dag.tail)

    # Doesn't correspond to any specific validation condition, and still won't
    # be used, but certainly would be IGNORE.
    return err(BlockError.UnviableFork)

  let parent = dag.getRef(blck.parent_root)

  if parent == nil:
    debug "Block parent unknown"
    return err(BlockError.MissingParent)

  if parent.slot >= signedBlock.message.slot:
    # A block whose parent is newer than the block itself is clearly invalid -
    # discard it immediately
    debug "Block with invalid parent, dropping",
      parentBlock = shortLog(parent)

    return err(BlockError.Invalid)

  if (parent.slot < dag.finalizedHead.slot) or
      (parent.slot == dag.finalizedHead.slot and
        parent != dag.finalizedHead.blck):
    # We finalized a block that's newer than the parent of this block - this
    # block, although recent, is thus building on a history we're no longer
    # interested in pursuing. This can happen if a client produces a block
    # while syncing - ie it's own head block will be old, but it'll create
    # a block according to the wall clock, in its own little world - this is
    # correct - from their point of view, the head block they have is the
    # latest thing that happened on the chain and they're performing their
    # duty correctly.
    debug "Block from unviable fork",
      finalizedHead = shortLog(dag.finalizedHead),
      tail = shortLog(dag.tail)

    return err(BlockError.UnviableFork)

  # The block is resolved, now it's time to validate it to ensure that the
  # blocks we add to the database are clean for the given state
  let startTick = Moment.now()

  var cache = StateCache()
  updateStateData(
    dag, dag.clearanceState, parent.atSlot(signedBlock.message.slot), true, cache)
  let stateDataTick = Moment.now()

  # First, batch-verify all signatures in block
  if skipBLSValidation notin dag.updateFlags:
    # TODO: remove skipBLSValidation
    var sigs: seq[SignatureSet]
    if (let e = sigs.collectSignatureSets(
        signedBlock, dag.db.immutableValidators,
        dag.clearanceState.data, cache); e.isErr()):
      info "Unable to load signature sets",
        err = e.error()

      # A PublicKey or Signature isn't on the BLS12-381 curve
      return err(BlockError.Invalid)
    if not verifier.batchVerify(sigs):
      info "Block signature verification failed"
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

  if dag.backfill.slot <= signedBlock.message.slot or
      signedBlock.message.slot <= dag.genesis.slot:
    if blockRoot in dag:
      debug "Block already exists"
      return err(BlockError.Duplicate)

    # The block is newer than our backfill position but not in the dag - either
    # it sits somewhere between backfill and tail or it comes from an unviable
    # fork. We don't have an in-memory way of checking the former condition so
    # we return UnviableFork for that condition as well, even though `Duplicate`
    # would be more correct
    debug "Block unviable or duplicate"
    return err(BlockError.UnviableFork)

  if dag.backfill.parent_root != signedBlock.root:
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
    info "Block signature verification failed"
    return err(BlockError.Invalid)

  dag.putBlock(signedBlock.asTrusted())
  dag.backfill = blck.toBeaconBlockSummary()

  # Invariants maintained on startup
  doAssert dag.backfillBlocks.lenu64 == dag.tail.slot.uint64
  doAssert dag.backfillBlocks.lenu64 > blck.slot.uint64

  dag.backfillBlocks[blck.slot.int] = signedBlock.root

  debug "Block backfilled"

  ok()
