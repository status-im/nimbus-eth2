# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[options, sequtils, tables, sets],
  stew/[assign2, byteutils, results],
  metrics, snappy, chronicles,
  ../spec/[beaconstate, eth2_merkleization, eth2_ssz_serialization, helpers,
    state_transition, validator],
  ../spec/datatypes/[phase0, altair, merge],
  ".."/beacon_chain_db,
  "."/[block_pools_types, block_quarantine]

export
  eth2_merkleization, eth2_ssz_serialization,
  block_pools_types, results, beacon_chain_db

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#interop-metrics
declareGauge beacon_head_root, "Root of the head block of the beacon chain"
declareGauge beacon_head_slot, "Slot of the head block of the beacon chain"

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#interop-metrics
declareGauge beacon_finalized_epoch, "Current finalized epoch" # On epoch transition
declareGauge beacon_finalized_root, "Current finalized root" # On epoch transition
declareGauge beacon_current_justified_epoch, "Current justified epoch" # On epoch transition
declareGauge beacon_current_justified_root, "Current justified root" # On epoch transition
declareGauge beacon_previous_justified_epoch, "Current previously justified epoch" # On epoch transition
declareGauge beacon_previous_justified_root, "Current previously justified root" # On epoch transition

declareGauge beacon_reorgs_total_total, "Total occurrences of reorganizations of the chain" # On fork choice; backwards-compat name (used to be a counter)
declareGauge beacon_reorgs_total, "Total occurrences of reorganizations of the chain" # Interop copy
declareCounter beacon_state_data_cache_hits, "EpochRef hits"
declareCounter beacon_state_data_cache_misses, "EpochRef misses"
declareCounter beacon_state_rewinds, "State database rewinds"

declareGauge beacon_active_validators, "Number of validators in the active validator set"
declareGauge beacon_current_active_validators, "Number of validators in the active validator set" # Interop copy
declareGauge beacon_pending_deposits, "Number of pending deposits (state.eth1_data.deposit_count - state.eth1_deposit_index)" # On block
declareGauge beacon_processed_deposits_total, "Number of total deposits included on chain" # On block

logScope: topics = "chaindag"

proc putBlock*(
    dag: ChainDAGRef, signedBlock: ForkyTrustedSignedBeaconBlock) =
  dag.db.putBlock(signedBlock)

proc updateStateData*(
  dag: ChainDAGRef, state: var StateData, bs: BlockSlot, save: bool,
  cache: var StateCache) {.gcsafe.}

template withStateVars*(
    stateDataInternal: var StateData, body: untyped): untyped =
  ## Inject a few more descriptive names for the members of `stateData` -
  ## the stateData instance may get mutated through these names as well
  template stateData(): StateData {.inject, used.} = stateDataInternal
  template stateRoot(): Eth2Digest {.inject, used.} =
    getStateRoot(stateDataInternal.data)
  template blck(): BlockRef {.inject, used.} = stateDataInternal.blck
  template root(): Eth2Digest {.inject, used.} = stateDataInternal.data.root

  body

template withState*(
    dag: ChainDAGRef, stateData: var StateData, blockSlot: BlockSlot,
    body: untyped): untyped =
  ## Helper template that updates stateData to a particular BlockSlot - usage of
  ## stateData is unsafe outside of block.
  ## TODO async transformations will lead to a race where stateData gets updated
  ##      while waiting for future to complete - catch this here somehow?

  block:
    var cache {.inject.} = StateCache()
    updateStateData(dag, stateData, blockSlot, false, cache)

    withStateVars(stateData):
      body

func get_effective_balances(validators: openArray[Validator], epoch: Epoch):
    seq[Gwei] =
  ## Get the balances from a state as counted for fork choice
  result.newSeq(validators.len) # zero-init

  for i in 0 ..< result.len:
    # All non-active validators have a 0 balance
    let validator = unsafeAddr validators[i]
    if validator[].is_active_validator(epoch):
      result[i] = validator[].effective_balance

proc updateValidatorKeys*(dag: ChainDAGRef, validators: openArray[Validator]) =
  # Update validator key cache - must be called every time a valid block is
  # applied to the state - this is important to ensure that when we sync blocks
  # without storing a state (non-epoch blocks essentially), the deposits from
  # those blocks are persisted to the in-database cache of immutable validator
  # data (but no earlier than that the whole block as been validated)
  dag.db.updateImmutableValidators(validators)

func validatorKey*(
    dag: ChainDAGRef, index: ValidatorIndex or uint64): Option[CookedPubKey] =
  ## Returns the validator pubkey for the index, assuming it's been observed
  ## at any point in time - this function may return pubkeys for indicies that
  ## are not (yet) part of the head state (if the key has been observed on a
  ## non-head branch)!
  dag.db.immutableValidators.load(index)

func validatorKey*(
    epochRef: EpochRef, index: ValidatorIndex or uint64): Option[CookedPubKey] =
  ## Returns the validator pubkey for the index, assuming it's been observed
  ## at any point in time - this function may return pubkeys for indicies that
  ## are not (yet) part of the head state (if the key has been observed on a
  ## non-head branch)!
  validatorKey(epochRef.dag, index)

func init*(
    T: type EpochRef, dag: ChainDAGRef, state: StateData,
    cache: var StateCache): T =
  let
    epoch = state.data.get_current_epoch()
    epochRef = EpochRef(
      dag: dag, # This gives access to the validator pubkeys through an EpochRef
      key: state.blck.epochAncestor(epoch),
      eth1_data: getStateField(state.data, eth1_data),
      eth1_deposit_index: getStateField(state.data, eth1_deposit_index),
      current_justified_checkpoint:
        getStateField(state.data, current_justified_checkpoint),
      finalized_checkpoint: getStateField(state.data, finalized_checkpoint),
      shuffled_active_validator_indices:
        cache.get_shuffled_active_validator_indices(state.data, epoch),
      merge_transition_complete:
        case state.data.kind:
        of BeaconStateFork.Phase0: false
        of BeaconStateFork.Altair: false
        of BeaconStateFork.Merge:
          # https://github.com/ethereum/consensus-specs/blob/v1.1.6/specs/merge/beacon-chain.md#is_merge_transition_complete
          state.data.mergeData.data.latest_execution_payload_header !=
            ExecutionPayloadHeader()
    )
    epochStart = epoch.compute_start_slot_at_epoch()

  for i in 0'u64..<SLOTS_PER_EPOCH:
    epochRef.beacon_proposers[i] = get_beacon_proposer_index(
      state.data, cache, epochStart + i)

  # When fork choice runs, it will need the effective balance of the justified
  # checkpoint - we pre-load the balances here to avoid rewinding the justified
  # state later and compress them because not all checkpoints end up being used
  # for fork choice - specially during long periods of non-finalization
  proc snappyEncode(inp: openArray[byte]): seq[byte] =
    try:
      snappy.encode(inp)
    except CatchableError as err:
      raiseAssert err.msg

  epochRef.effective_balances_bytes =
    snappyEncode(SSZ.encode(
      List[Gwei, Limit VALIDATOR_REGISTRY_LIMIT](get_effective_balances(
        getStateField(state.data, validators).asSeq,
        epoch))))

  epochRef

func effective_balances*(epochRef: EpochRef): seq[Gwei] =
  try:
    SSZ.decode(snappy.decode(epochRef.effective_balances_bytes, uint32.high),
      List[Gwei, Limit VALIDATOR_REGISTRY_LIMIT]).toSeq()
  except CatchableError as exc:
    raiseAssert exc.msg

func getBlockBySlot*(dag: ChainDAGRef, slot: Slot): BlockSlot =
  ## Retrieve the canonical block at the given slot, or the last block that
  ## comes before - similar to atSlot, but without the linear scan - see
  ## getBlockSlotIdBySlot for a version that covers backfill blocks as well
  ## May return an empty BlockSlot (where blck is nil!)

  if slot == dag.genesis.slot:
    # There may be gaps in the
    return dag.genesis.atSlot(slot)

  if slot > dag.finalizedHead.slot:
    return dag.head.atSlot(slot) # Linear iteration is the fastest we have

  doAssert dag.finalizedHead.slot >= dag.tail.slot
  doAssert dag.tail.slot >= dag.backfill.slot
  doAssert dag.finalizedBlocks.len ==
    (dag.finalizedHead.slot - dag.tail.slot).int + 1, "see updateHead"

  if slot >= dag.tail.slot:
    var pos = int(slot - dag.tail.slot)

    while true:
      if dag.finalizedBlocks[pos] != nil:
        return dag.finalizedBlocks[pos].atSlot(slot)

      if pos == 0:
        break

      pos -= 1

  if dag.tail.slot == 0:
    raiseAssert "Genesis missing"

  BlockSlot() # nil blck!

func getBlockSlotIdBySlot*(dag: ChainDAGRef, slot: Slot): BlockSlotId =
  ## Retrieve the canonical block at the given slot, or the last block that
  ## comes before - similar to atSlot, but without the linear scan
  if slot == dag.genesis.slot:
    return dag.genesis.bid.atSlot(slot)

  if slot >= dag.tail.slot:
    return dag.getBlockBySlot(slot).toBlockSlotId()

  var pos = slot.int
  while pos >= dag.backfill.slot.int:
    if dag.backfillBlocks[pos] != Eth2Digest():
      return BlockId(root: dag.backfillBlocks[pos], slot: Slot(pos)).atSlot(slot)
    pos -= 1

  BlockSlotId() # not backfilled yet, and not genesis

func epochAncestor*(blck: BlockRef, epoch: Epoch): EpochKey =
  ## The state transition works by storing information from blocks in a
  ## "working" area until the epoch transition, then batching work collected
  ## during the epoch. Thus, last block in the ancestor epochs is the block
  ## that has an impact on epoch currently considered.
  ##
  ## This function returns an epoch key pointing to that epoch boundary, i.e. the
  ## boundary where the last block has been applied to the state and epoch
  ## processing has been done.
  var blck = blck
  while blck.slot.epoch >= epoch and not blck.parent.isNil:
    blck = blck.parent

  EpochKey(epoch: epoch, blck: blck)

func findEpochRef*(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch): EpochRef = # may return nil!
  if epoch < dag.tail.slot.epoch:
    # We can't compute EpochRef instances for states before the tail because
    # we do not have them!
    return

  let ancestor = epochAncestor(blck, epoch)
  doAssert ancestor.blck != nil
  for i in 0..<dag.epochRefs.len:
    if dag.epochRefs[i] != nil and dag.epochRefs[i].key == ancestor:
      return dag.epochRefs[i]

  return nil

func loadStateCache(
    dag: ChainDAGRef, cache: var StateCache, blck: BlockRef, epoch: Epoch) =
  # When creating a state cache, we want the current and the previous epoch
  # information to be preloaded as both of these are used in state transition
  # functions

  template load(e: Epoch) =
    if e notin cache.shuffled_active_validator_indices:
      let epochRef = dag.findEpochRef(blck, e)
      if epochRef != nil:
        cache.shuffled_active_validator_indices[epochRef.epoch] =
          epochRef.shuffled_active_validator_indices

        for i, idx in epochRef.beacon_proposers:
          cache.beacon_proposer_indices[
            epochRef.epoch.compute_start_slot_at_epoch + i] = idx

  load(epoch)

  if epoch > 0:
    load(epoch - 1)

func contains*(dag: ChainDAGRef, root: Eth2Digest): bool =
  KeyedBlockRef.asLookupKey(root) in dag.blocks

proc containsBlock(
    cfg: RuntimeConfig, db: BeaconChainDB, slot: Slot, root: Eth2Digest): bool =
  case cfg.blockForkAtEpoch(slot.epoch)
  of BeaconBlockFork.Phase0: db.containsBlockPhase0(root)
  of BeaconBlockFork.Altair: db.containsBlockAltair(root)
  of BeaconBlockFork.Merge: db.containsBlockMerge(root)

func isStateCheckpoint(bs: BlockSlot): bool =
  ## State checkpoints are the points in time for which we store full state
  ## snapshots, which later serve as rewind starting points when replaying state
  ## transitions from database, for example during reorgs.
  ##
  # As a policy, we only store epoch boundary states without the epoch block
  # (if it exists) applied - the rest can be reconstructed by loading an epoch
  # boundary state and applying the missing blocks.
  # We also avoid states that were produced with empty slots only - as such,
  # there is only a checkpoint for the first epoch after a block.

  # The tail block also counts as a state checkpoint!
  (bs.slot == bs.blck.slot and bs.blck.parent == nil) or
  (bs.slot.isEpoch and bs.slot.epoch == (bs.blck.slot.epoch + 1))

proc getStateData(
    db: BeaconChainDB, cfg: RuntimeConfig, state: var StateData, bs: BlockSlot,
    rollback: RollbackProc): bool =
  if not bs.isStateCheckpoint():
    return false

  let root = db.getStateRoot(bs.blck.root, bs.slot)
  if not root.isSome():
    return false

  let expectedFork = cfg.stateForkAtEpoch(bs.slot.epoch)
  if state.data.kind != expectedFork:
    state.data = (ref ForkedHashedBeaconState)(kind: expectedFork)[]

  case expectedFork
  of BeaconStateFork.Merge:
    if not db.getState(root.get(), state.data.mergeData.data, rollback):
      return false
  of BeaconStateFork.Altair:
    if not db.getState(root.get(), state.data.altairData.data, rollback):
      return false
  of BeaconStateFork.Phase0:
    if not db.getState(root.get(), state.data.phase0Data.data, rollback):
      return false

  state.blck = bs.blck
  setStateRoot(state.data, root.get())

  true

proc getForkedBlock(db: BeaconChainDB, root: Eth2Digest):
    Opt[ForkedTrustedSignedBeaconBlock] =
  # When we only have a digest, we don't know which fork it's from so we try
  # them one by one - this should be used sparingly
  if (let blck = db.getMergeBlock(root); blck.isSome()):
    ok(ForkedTrustedSignedBeaconBlock.init(blck.get()))
  elif (let blck = db.getAltairBlock(root); blck.isSome()):
    ok(ForkedTrustedSignedBeaconBlock.init(blck.get()))
  elif (let blck = db.getPhase0Block(root); blck.isSome()):
    ok(ForkedTrustedSignedBeaconBlock.init(blck.get()))
  else:
    err()

proc init*(T: type ChainDAGRef, cfg: RuntimeConfig, db: BeaconChainDB,
           updateFlags: UpdateFlags, onBlockCb: OnBlockCallback = nil,
           onHeadCb: OnHeadCallback = nil, onReorgCb: OnReorgCallback = nil,
           onFinCb: OnFinalizedCallback = nil): ChainDAGRef =
  # TODO we require that the db contains both a head and a tail block -
  #      asserting here doesn't seem like the right way to go about it however..

  let
    tailBlockRoot = db.getTailBlock()
    headBlockRoot = db.getHeadBlock()
    backfillBlockRoot = db.getBackfillBlock()

  doAssert tailBlockRoot.isSome(), "Missing tail block, database corrupt?"
  doAssert headBlockRoot.isSome(), "Missing head block, database corrupt?"

  let
    tailRoot = tailBlockRoot.get()
    tailBlock = db.getForkedBlock(tailRoot).get()
    tailRef = withBlck(tailBlock): BlockRef.init(tailRoot, blck.message)
    headRoot = headBlockRoot.get()

  let genesisRef = if tailBlock.slot == GENESIS_SLOT:
    tailRef
  else:
    let
      genesisBlockRoot = db.getGenesisBlock().expect(
        "preInit should have initialized the database with a genesis block root")
      genesisBlock = db.getForkedBlock(genesisBlockRoot).expect(
        "preInit should have initialized the database with a genesis block")
    withBlck(genesisBlock): BlockRef.init(genesisBlockRoot, blck.message)

  let backfill =
    if backfillBlockRoot.isSome():
      let backfillBlock = db.getForkedBlock(backfillBlockRoot.get()).expect(
        "backfill block must be present in database, database corrupt?")
      (getForkedBlockField(backfillBlock, slot),
        getForkedBlockField(backfillBlock, parentRoot))
    elif tailRef.slot > GENESIS_SLOT:
      (getForkedBlockField(tailBlock, slot),
        getForkedBlockField(tailBlock, parentRoot))
    else:
      (GENESIS_SLOT, Eth2Digest())

  var
    blocks: HashSet[KeyedBlockRef]
    headRef: BlockRef

  blocks.incl(KeyedBlockRef.init(tailRef))

  if genesisRef != tailRef:
    blocks.incl(KeyedBlockRef.init(genesisRef))

  var
    backfillBlocks = newSeq[Eth2Digest](tailRef.slot.int)
    curRef: BlockRef

  for blck in db.getAncestorSummaries(headRoot):
    if blck.summary.slot < tailRef.slot:
      backfillBlocks[blck.summary.slot.int] = blck.root
    elif blck.summary.slot == tailRef.slot:
      if curRef == nil:
        curRef = tailRef
        headRef = tailRef
      else:
        link(tailRef, curRef)
        curRef = curRef.parent
    else:
      if curRef == nil:
        # When the database has been written with a pre-fork version of the
        # software, it may happen that blocks produced using an "unforked"
        # chain get written to the database - we need to skip such blocks
        # when loading the database with a fork-compatible version
        if not containsBlock(cfg, db, blck.summary.slot, blck.root):
          continue

      let newRef = BlockRef.init(blck.root, blck.summary.slot)
      if curRef == nil:
        curRef = newRef
        headRef = newRef
      else:
        link(newRef, curRef)
        curRef = curRef.parent

      blocks.incl(KeyedBlockRef.init(curRef))
      trace "Populating block dag", key = curRef.root, val = curRef

  if curRef != tailRef:
    fatal "Head block does not lead to tail - database corrupt?",
      genesisRef, tailRef, headRef, curRef, tailRoot, headRoot,
      blocks = blocks.len()

    quit 1

  # Because of incorrect hardfork check, there might be no head block, in which
  # case it's equivalent to the tail block
  if headRef == nil:
    headRef = tailRef

  var
    cur = headRef.atSlot()
    tmpState = (ref StateData)()

  # Now that we have a head block, we need to find the most recent state that
  # we have saved in the database
  while cur.blck != nil and
      not getStateData(db, cfg, tmpState[], cur, noRollback):
    cur = cur.parentOrSlot()

  if tmpState.blck == nil:
    warn "No state found in head history, database corrupt?",
      genesisRef, tailRef, headRef, tailRoot, headRoot,
      blocks = blocks.len()
    # TODO Potentially we could recover from here instead of crashing - what
    #      would be a good recovery model?
    quit 1

  case tmpState.data.kind
  of BeaconStateFork.Phase0:
    if tmpState.data.phase0Data.data.fork != genesisFork(cfg):
      error "State from database does not match network, check --network parameter",
        genesisRef, tailRef, headRef, tailRoot, headRoot,
        blocks = blocks.len(),
        stateFork = tmpState.data.phase0Data.data.fork,
        configFork = genesisFork(cfg)
      quit 1
  of BeaconStateFork.Altair:
    if tmpState.data.altairData.data.fork != altairFork(cfg):
      error "State from database does not match network, check --network parameter",
        genesisRef, tailRef, headRef, tailRoot, headRoot,
        blocks = blocks.len(),
        stateFork = tmpState.data.altairData.data.fork,
        configFork = altairFork(cfg)
      quit 1
  of BeaconStateFork.Merge:
    if tmpState.data.mergeData.data.fork != mergeFork(cfg):
      error "State from database does not match network, check --network parameter",
        genesisRef, tailRef, headRef, tailRoot, headRoot,
        blocks = blocks.len(),
        stateFork = tmpState.data.mergeData.data.fork,
        configFork = mergeFork(cfg)
      quit 1

  let dag = ChainDAGRef(
    db: db,
    blocks: blocks,
    backfillBlocks: backfillBlocks,
    genesis: genesisRef,
    tail: tailRef,
    backfill: backfill,
    finalizedHead: tailRef.atSlot(),
    lastPrunePoint: tailRef.atSlot(),
    # Tail is implicitly finalized - we'll adjust it below when computing the
    # head state
    heads: @[headRef],
    headState: tmpState[],
    epochRefState: tmpState[],
    clearanceState: tmpState[],

    # The only allowed flag right now is verifyFinalization, as the others all
    # allow skipping some validation.
    updateFlags: {verifyFinalization} * updateFlags,
    cfg: cfg,

    forkDigests: newClone ForkDigests.init(
      cfg,
      getStateField(tmpState.data, genesis_validators_root)),

    onBlockAdded: onBlockCb,
    onHeadChanged: onHeadCb,
    onReorgHappened: onReorgCb,
    onFinHappened: onFinCb
  )

  let forkVersions =
    [cfg.GENESIS_FORK_VERSION, cfg.ALTAIR_FORK_VERSION, cfg.MERGE_FORK_VERSION,
     cfg.SHARDING_FORK_VERSION]
  for i in 0 ..< forkVersions.len:
    for j in i+1 ..< forkVersions.len:
      doAssert forkVersions[i] != forkVersions[j]
  doAssert cfg.ALTAIR_FORK_EPOCH <= cfg.MERGE_FORK_EPOCH
  doAssert cfg.MERGE_FORK_EPOCH <= cfg.SHARDING_FORK_EPOCH
  doAssert dag.updateFlags in [{}, {verifyFinalization}]

  var cache: StateCache
  dag.updateStateData(dag.headState, headRef.atSlot(), false, cache)

  # The tail block is "implicitly" finalized as it was given either as a
  # checkpoint block, or is the genesis, thus we use it as a lower bound when
  # computing the finalized head
  let
    finalized_checkpoint =
      getStateField(dag.headState.data, finalized_checkpoint)
    finalizedSlot = max(
      finalized_checkpoint.epoch.compute_start_slot_at_epoch(), tailRef.slot)

  dag.finalizedHead = headRef.atSlot(finalizedSlot)

  block:
    dag.finalizedBlocks.setLen((dag.finalizedHead.slot - dag.tail.slot).int + 1)

    var tmp = dag.finalizedHead.blck
    while not isNil(tmp):
      dag.finalizedBlocks[(tmp.slot - dag.tail.slot).int] = tmp
      tmp = tmp.parent

  dag.clearanceState = dag.headState

  # Pruning metadata
  dag.lastPrunePoint = dag.finalizedHead

  # Fill validator key cache in case we're loading an old database that doesn't
  # have a cache
  dag.updateValidatorKeys(getStateField(dag.headState.data, validators).asSeq())

  withState(dag.headState.data):
    when stateFork >= BeaconStateFork.Altair:
      dag.headSyncCommittees = state.data.get_sync_committee_cache(cache)

  info "Block dag initialized",
    head = shortLog(dag.head),
    finalizedHead = shortLog(dag.finalizedHead),
    tail = shortLog(dag.tail),
    totalBlocks = dag.blocks.len(),
    backfill = (dag.backfill.slot, shortLog(dag.backfill.root))

  dag

template genesisValidatorsRoot*(dag: ChainDAGRef): Eth2Digest =
  getStateField(dag.headState.data, genesis_validators_root)

func getEpochRef*(
    dag: ChainDAGRef, state: StateData, cache: var StateCache): EpochRef =
  let
    blck = state.blck
    epoch = state.data.get_current_epoch()

  var epochRef = dag.findEpochRef(blck, epoch)
  if epochRef == nil:
    epochRef = EpochRef.init(dag, state, cache)

    if epoch >= dag.finalizedHead.slot.epoch():
      # Only cache epoch information for unfinalized blocks - earlier states
      # are seldomly used (ie RPC), so no need to cache

      # Because we put a cap on the number of epochRefs we store, we want to
      # prune the least useful state - for now, we'll assume that to be the
      # oldest epochRef we know about.

      var
        oldest = 0
      for x in 0..<dag.epochRefs.len:
        let candidate = dag.epochRefs[x]
        if candidate == nil:
          oldest = x
          break
        if candidate.key.epoch < dag.epochRefs[oldest].epoch:
          oldest = x

      dag.epochRefs[oldest] = epochRef

  epochRef

proc getEpochRef*(dag: ChainDAGRef, blck: BlockRef, epoch: Epoch): EpochRef =
  let epochRef = dag.findEpochRef(blck, epoch)
  if epochRef != nil:
    beacon_state_data_cache_hits.inc
    return epochRef

  beacon_state_data_cache_misses.inc

  let
    ancestor = epochAncestor(blck, epoch)

  dag.withState(
      dag.epochRefState, ancestor.blck.atEpochStart(ancestor.epoch)):
    dag.getEpochRef(stateData, cache)

proc getFinalizedEpochRef*(dag: ChainDAGRef): EpochRef =
  dag.getEpochRef(dag.finalizedHead.blck, dag.finalizedHead.slot.epoch)

func stateCheckpoint*(bs: BlockSlot): BlockSlot =
  ## The first ancestor BlockSlot that is a state checkpoint
  var bs = bs
  while not isStateCheckPoint(bs):
    bs = bs.parentOrSlot
  bs

template forkAtEpoch*(dag: ChainDAGRef, epoch: Epoch): Fork =
  forkAtEpoch(dag.cfg, epoch)

proc forkDigestAtEpoch*(dag: ChainDAGRef, epoch: Epoch): ForkDigest =
  case dag.cfg.stateForkAtEpoch(epoch)
  of BeaconStateFork.Merge:  dag.forkDigests.merge
  of BeaconStateFork.Altair: dag.forkDigests.altair
  of BeaconStateFork.Phase0: dag.forkDigests.phase0

proc getState(dag: ChainDAGRef, state: var StateData, bs: BlockSlot): bool =
  ## Load a state from the database given a block and a slot - this will first
  ## lookup the state root in the state root table then load the corresponding
  ## state, if it exists
  if not bs.isStateCheckpoint():
    return false # Only state checkpoints are stored - no need to hit DB

  let stateRoot = dag.db.getStateRoot(bs.blck.root, bs.slot)
  if stateRoot.isNone(): return false

  let restoreAddr =
    # Any restore point will do as long as it's not the object being updated
    if unsafeAddr(state) == unsafeAddr(dag.headState):
      unsafeAddr dag.clearanceState
    else:
      unsafeAddr dag.headState

  let v = addr state.data
  func restore() =
    assign(v[], restoreAddr[].data)

  getStateData(dag.db, dag.cfg, state, bs, restore)

proc putState(dag: ChainDAGRef, state: StateData) =
  # Store a state and its root
  logScope:
    blck = shortLog(state.blck)
    stateSlot = shortLog(getStateField(state.data, slot))
    stateRoot = shortLog(getStateRoot(state.data))

  if not isStateCheckpoint(state.blck.atSlot(getStateField(state.data, slot))):
    return

  # Don't consider legacy tables here, they are slow to read so we'll want to
  # rewrite things in the new database anyway.
  if dag.db.containsState(getStateRoot(state.data), legacy = false):
    return

  let startTick = Moment.now()
  # Ideally we would save the state and the root lookup cache in a single
  # transaction to prevent database inconsistencies, but the state loading code
  # is resilient against one or the other going missing
  withState(state.data):
    dag.db.putStateRoot(state.latest_block_root(), state.data.slot, state.root)
    dag.db.putState(state.root, state.data)

  debug "Stored state", putStateDur = Moment.now() - startTick

func getRef*(dag: ChainDAGRef, root: Eth2Digest): BlockRef =
  ## Retrieve a resolved block reference, if available
  let key = KeyedBlockRef.asLookupKey(root)
  # HashSet lacks the api to do check-and-get in one lookup - `[]` will return
  # the copy of the instance in the set which has more fields than `root` set!
  if key in dag.blocks:
    try: dag.blocks[key].blockRef()
    except KeyError: raiseAssert "contains"
  else:
    nil

proc getBlockRange*(
    dag: ChainDAGRef, startSlot: Slot, skipStep: uint64,
    output: var openArray[BlockId]): Natural =
  ## This function populates an `output` buffer of blocks
  ## with a slots ranging from `startSlot` up to, but not including,
  ## `startSlot + skipStep * output.len`, skipping any slots that don't have
  ## a block.
  ##
  ## Blocks will be written to `output` from the end without gaps, even if
  ## a block is missing in a particular slot. The return value shows how
  ## many slots were missing blocks - to iterate over the result, start
  ## at this index.
  ##
  ## If there were no blocks in the range, `output.len` will be returned.
  let
    requestedCount = output.lenu64
    headSlot = dag.head.slot

  trace "getBlockRange entered",
    head = shortLog(dag.head.root), requestedCount, startSlot, skipStep, headSlot

  if startSlot < dag.backfill.slot:
    notice "Got request for pre-backfill slot",
      startSlot, backfillSlot = dag.backfill.slot
    return output.len

  if headSlot <= startSlot or requestedCount == 0:
    return output.len # Identical to returning an empty set of block as indicated above

  let
    runway = uint64(headSlot - startSlot)

    # This is the number of blocks that will follow the start block
    extraSlots = min(runway div skipStep, requestedCount - 1)

    # If `skipStep` is very large, `extraSlots` should be 0 from
    # the previous line, so `endSlot` will be equal to `startSlot`:
    endSlot = startSlot + extraSlots * skipStep

  var
    curSlot = endSlot
    o = output.len

  # Process all blocks that follow the start block (may be zero blocks)
  while curSlot > startSlot:
    let bs = dag.getBlockSlotIdBySlot(curSlot)
    if bs.isProposed():
      o -= 1
      output[o] = bs.bid
    curSlot -= skipStep

  # Handle start slot separately (to avoid underflow when computing curSlot)
  let bs = dag.getBlockSlotIdBySlot(startSlot)
  if bs.isProposed():
    o -= 1
    output[o] = bs.bid

  o # Return the index of the first non-nil item in the output

proc getForkedBlock*(dag: ChainDAGRef, id: BlockId): Opt[ForkedTrustedSignedBeaconBlock] =
  case dag.cfg.blockForkAtEpoch(id.slot.epoch)
  of BeaconBlockFork.Phase0:
    let data = dag.db.getPhase0Block(id.root)
    if data.isOk():
      return ok ForkedTrustedSignedBeaconBlock.init(data.get)
  of BeaconBlockFork.Altair:
    let data = dag.db.getAltairBlock(id.root)
    if data.isOk():
      return ok ForkedTrustedSignedBeaconBlock.init(data.get)
  of BeaconBlockFork.Merge:
    let data = dag.db.getMergeBlock(id.root)
    if data.isOk():
      return ok ForkedTrustedSignedBeaconBlock.init(data.get)

proc getForkedBlock*(dag: ChainDAGRef, blck: BlockRef): ForkedTrustedSignedBeaconBlock =
  let blck = dag.getForkedBlock(blck.bid)
  if blck.isSome():
    return blck.get()

proc get*(dag: ChainDAGRef, blck: BlockRef): BlockData =
  ## Retrieve the associated block body of a block reference
  doAssert (not blck.isNil), "Trying to get nil BlockRef"

  BlockData(data: dag.getForkedBlock(blck), refs: blck)

proc get*(dag: ChainDAGRef, root: Eth2Digest): Option[BlockData] =
  ## Retrieve a resolved block reference and its associated body, if available
  let refs = dag.getRef(root)

  if not refs.isNil:
    some(dag.get(refs))
  else:
    none(BlockData)

proc advanceSlots(
    dag: ChainDAGRef, state: var StateData, slot: Slot, save: bool,
    cache: var StateCache, info: var ForkedEpochInfo) =
  # Given a state, advance it zero or more slots by applying empty slot
  # processing - the state must be positions at a slot before or equal to the
  # target
  doAssert getStateField(state.data, slot) <= slot
  while getStateField(state.data, slot) < slot:
    loadStateCache(dag, cache, state.blck, getStateField(state.data, slot).epoch)

    doAssert process_slots(
        dag.cfg, state.data, getStateField(state.data, slot) + 1, cache, info,
        dag.updateFlags),
      "process_slots shouldn't fail when state slot is correct"
    if save:
      dag.putState(state)

proc applyBlock(
    dag: ChainDAGRef,
    state: var StateData, blck: BlockData, flags: UpdateFlags,
    cache: var StateCache, info: var ForkedEpochInfo): bool =
  # Apply a single block to the state - the state must be positioned at the
  # parent of the block with a slot lower than the one of the block being
  # applied
  doAssert state.blck == blck.refs.parent

  var statePtr = unsafeAddr state # safe because `restore` is locally scoped
  func restore(v: var ForkedHashedBeaconState) =
    doAssert (addr(statePtr.data) == addr v)
    assign(statePtr[], dag.headState)

  loadStateCache(dag, cache, state.blck, getStateField(state.data, slot).epoch)

  let ok = withBlck(blck.data):
    state_transition(
      dag.cfg, state.data, blck, cache, info,
      flags + dag.updateFlags + {slotProcessed}, restore)
  if ok:
    state.blck = blck.refs

  ok

proc updateStateData*(
    dag: ChainDAGRef, state: var StateData, bs: BlockSlot, save: bool,
    cache: var StateCache) =
  ## Rewind or advance state such that it matches the given block and slot -
  ## this may include replaying from an earlier snapshot if blck is on a
  ## different branch or has advanced to a higher slot number than slot
  ## If slot is higher than blck.slot, replay will fill in with empty/non-block
  ## slots, else it is ignored

  # First, see if we're already at the requested block. If we are, also check
  # that the state has not been advanced past the desired block - if it has,
  # an earlier state must be loaded since there's no way to undo the slot
  # transitions

  let startTick = Moment.now()

  var
    ancestors: seq[BlockRef]
    cur = bs
    found = false

  template exactMatch(state: StateData, bs: BlockSlot): bool =
    # The block is the same and we're at an early enough slot - the state can
    # be used to arrive at the desired blockslot
    state.blck == bs.blck and getStateField(state.data, slot) == bs.slot

  template canAdvance(state: StateData, bs: BlockSlot): bool =
    # The block is the same and we're at an early enough slot - the state can
    # be used to arrive at the desired blockslot
    state.blck == bs.blck and getStateField(state.data, slot) <= bs.slot

  # Fast path: check all caches for an exact match - this is faster than
  # advancing a state where there's epoch processing to do, by a wide margin -
  # it also avoids `hash_tree_root` for slot processing
  if exactMatch(state, cur):
    found = true
  elif exactMatch(dag.headState, cur):
    assign(state, dag.headState)
    found = true
  elif exactMatch(dag.clearanceState, cur):
    assign(state, dag.clearanceState)
    found = true
  elif exactMatch(dag.epochRefState, cur):
    assign(state, dag.epochRefState)
    found = true

  # First, run a quick check if we can simply apply a few blocks to an in-memory
  # state - any in-memory state will be faster than loading from database.
  # The limit here how many blocks we apply is somewhat arbitrary but two full
  # epochs (might be more slots if there are skips) seems like a good enough
  # first guess.
  # This happens in particular during startup where we replay blocks
  # sequentially to grab their votes.
  const RewindBlockThreshold = 64
  while not found and ancestors.len < RewindBlockThreshold:
    if canAdvance(state, cur):
      found = true
      break

    if canAdvance(dag.headState, cur):
      assign(state, dag.headState)
      found = true
      break

    if canAdvance(dag.clearanceState, cur):
      assign(state, dag.clearanceState)
      found = true
      break

    if canAdvance(dag.epochRefState, cur):
      assign(state, dag.epochRefState)
      found = true
      break

    if cur.slot == cur.blck.slot:
      # This is not an empty slot, so the block will need to be applied to
      # eventually reach bs
      ancestors.add(cur.blck)

    if cur.blck.parent == nil:
      break

    # Moving slot by slot helps find states that were advanced with empty slots
    cur = cur.parentOrSlot()

  if not found:
    debug "UpdateStateData cache miss",
      bs, stateBlock = state.blck, stateSlot = getStateField(state.data, slot)

    # Either the state is too new or was created by applying a different block.
    # We'll now resort to loading the state from the database then reapplying
    # blocks until we reach the desired point in time.

    cur = bs
    ancestors.setLen(0)

    # Look for a state in the database and load it - as long as it cannot be
    # found, keep track of the blocks that are needed to reach it from the
    # state that eventually will be found
    while not dag.getState(state, cur):
      # There's no state saved for this particular BlockSlot combination, keep
      # looking...
      if cur.slot == cur.blck.slot:
        # This is not an empty slot, so the block will need to be applied to
        # eventually reach bs
        ancestors.add(cur.blck)

      if cur.slot == dag.tail.slot:
        # If we've walked all the way to the tail and still not found a state,
        # there's no hope finding one - the database likely has become corrupt
        # and one will have to resync from start.
        fatal "Cannot find state to load, the database is likely corrupt",
          cur, bs, head = dag.head, tail = dag.tail
        quit 1

      # Move slot by slot to capture epoch boundary states
      cur = cur.parentOrSlot()

    beacon_state_rewinds.inc()

  # Starting state has been assigned, either from memory or database
  let
    assignTick = Moment.now()
    startSlot {.used.} = getStateField(state.data, slot) # used in logs below
    startRoot {.used.} = getStateRoot(state.data)
  var info: ForkedEpochInfo
  # Time to replay all the blocks between then and now
  for i in countdown(ancestors.len - 1, 0):
    # Because the ancestors are in the database, there's no need to persist them
    # again. Also, because we're applying blocks that were loaded from the
    # database, we can skip certain checks that have already been performed
    # before adding the block to the database.
    let ok =
      dag.applyBlock(state, dag.get(ancestors[i]), {}, cache, info)
    doAssert ok, "Blocks in database should never fail to apply.."

  # ...and make sure to process empty slots as requested
  dag.advanceSlots(state, bs.slot, save, cache, info)

  # ...and make sure to load the state cache, if it exists
  loadStateCache(dag, cache, state.blck, getStateField(state.data, slot).epoch)

  let
    assignDur = assignTick - startTick
    replayDur = Moment.now() - assignTick

  logScope:
    blocks = ancestors.len
    slots = getStateField(state.data, slot) - startSlot
    stateRoot = shortLog(getStateRoot(state.data))
    stateSlot = getStateField(state.data, slot)
    startRoot = shortLog(startRoot)
    startSlot
    blck = shortLog(bs)
    found
    assignDur
    replayDur

  if (assignDur + replayDur) >= 250.millis:
    # This might indicate there's a cache that's not in order or a disk that is
    # too slow - for now, it's here for investigative purposes and the cutoff
    # time might need tuning
    info "State replayed"
  elif ancestors.len > 0:
    debug "State replayed"
  else:
    trace "State advanced" # Normal case!

proc delState(dag: ChainDAGRef, bs: BlockSlot) =
  # Delete state state and mapping for a particular block+slot
  if not isStateCheckpoint(bs):
    return # We only ever save epoch states

  if (let root = dag.db.getStateRoot(bs.blck.root, bs.slot); root.isSome()):
    dag.db.delState(root.get())
    dag.db.delStateRoot(bs.blck.root, bs.slot)

proc pruneBlocksDAG(dag: ChainDAGRef) =
  ## This prunes the block DAG
  ## This does NOT prune the cached state checkpoints and EpochRef
  ## This must be done after a new finalization point is reached
  ## to invalidate pending blocks or attestations referring
  ## to a now invalid fork.
  ##
  ## This does NOT update the `dag.lastPrunePoint` field.
  ## as the caches and fork choice can be pruned at a later time.

  # Clean up block refs, walking block by block
  let startTick = Moment.now()

  # Finalization means that we choose a single chain as the canonical one -
  # it also means we're no longer interested in any branches from that chain
  # up to the finalization point
  let hlen = dag.heads.len
  for i in 0..<hlen:
    let n = hlen - i - 1
    let head = dag.heads[n]
    if dag.finalizedHead.blck.isAncestorOf(head):
      continue

    var cur = head.atSlot()
    while not cur.blck.isAncestorOf(dag.finalizedHead.blck):
      dag.delState(cur) # TODO: should we move that disk I/O to `onSlotEnd`

      if cur.blck.slot == cur.slot:
        dag.blocks.excl(KeyedBlockRef.init(cur.blck))
        dag.db.delBlock(cur.blck.root)

      if cur.blck.parent.isNil:
        break
      cur = cur.parentOrSlot

    dag.heads.del(n)

  debug "Pruned the blockchain DAG",
    currentCandidateHeads = dag.heads.len,
    prunedHeads = hlen - dag.heads.len,
    dagPruneDur = Moment.now() - startTick

iterator syncSubcommittee*(
    syncCommittee: openArray[ValidatorIndex],
    subcommitteeIdx: SyncSubcommitteeIndex): ValidatorIndex =
  var i = subcommitteeIdx.asInt * SYNC_SUBCOMMITTEE_SIZE
  let onePastEndIdx = min(syncCommittee.len, i + SYNC_SUBCOMMITTEE_SIZE)

  while i < onePastEndIdx:
    yield syncCommittee[i]
    inc i

iterator syncSubcommitteePairs*(
    syncCommittee: openArray[ValidatorIndex],
    subcommitteeIdx: SyncSubcommitteeIndex): tuple[validatorIdx: ValidatorIndex,
                                             subcommitteeIdx: int] =
  var i = subcommitteeIdx.asInt * SYNC_SUBCOMMITTEE_SIZE
  let onePastEndIdx = min(syncCommittee.len, i + SYNC_SUBCOMMITTEE_SIZE)

  while i < onePastEndIdx:
    yield (syncCommittee[i], i)
    inc i

func syncCommitteeParticipants*(dag: ChainDAGRef,
                                slot: Slot): seq[ValidatorIndex] =
  withState(dag.headState.data):
    when stateFork >= BeaconStateFork.Altair:
      let
        period = sync_committee_period(slot)
        curPeriod = sync_committee_period(state.data.slot)

      if period == curPeriod:
        @(dag.headSyncCommittees.current_sync_committee)
      elif period == curPeriod + 1:
        @(dag.headSyncCommittees.next_sync_committee)
      else: @[]
    else:
      @[]

func getSubcommitteePositionsAux(
    dag: ChainDAGRef,
    syncCommittee: openArray[ValidatorIndex],
    subcommitteeIdx: SyncSubcommitteeIndex,
    validatorIdx: uint64): seq[uint64] =
  var pos = 0'u64
  for valIdx in syncCommittee.syncSubcommittee(subcommitteeIdx):
    if validatorIdx == uint64(valIdx):
      result.add pos
    inc pos

func getSubcommitteePositions*(
    dag: ChainDAGRef,
    slot: Slot,
    subcommitteeIdx: SyncSubcommitteeIndex,
    validatorIdx: uint64): seq[uint64] =
  withState(dag.headState.data):
    when stateFork >= BeaconStateFork.Altair:
      let
        period = sync_committee_period(slot)
        curPeriod = sync_committee_period(state.data.slot)

      template search(syncCommittee: openArray[ValidatorIndex]): seq[uint64] =
        dag.getSubcommitteePositionsAux(
          syncCommittee, subcommitteeIdx, validatorIdx)

      if period == curPeriod:
        search(dag.headSyncCommittees.current_sync_committee)
      elif period == curPeriod + 1:
        search(dag.headSyncCommittees.next_sync_committee)
      else: @[]
    else:
      @[]

template syncCommitteeParticipants*(
    dag: ChainDAGRef,
    slot: Slot,
    subcommitteeIdx: SyncSubcommitteeIndex): seq[ValidatorIndex] =
  toSeq(syncSubcommittee(dag.syncCommitteeParticipants(slot), subcommitteeIdx))

iterator syncCommitteeParticipants*(
    dag: ChainDAGRef,
    slot: Slot,
    subcommitteeIdx: SyncSubcommitteeIndex,
    aggregationBits: SyncCommitteeAggregationBits): ValidatorIndex =
  for pos, valIdx in dag.syncCommitteeParticipants(slot, subcommitteeIdx):
    if pos < aggregationBits.bits and aggregationBits[pos]:
      yield valIdx

func needStateCachesAndForkChoicePruning*(dag: ChainDAGRef): bool =
  dag.lastPrunePoint != dag.finalizedHead

proc pruneStateCachesDAG*(dag: ChainDAGRef) =
  ## This prunes the cached state checkpoints and EpochRef
  ## This does NOT prune the state associated with invalidated blocks on a fork
  ## They are pruned via `pruneBlocksDAG`
  ##
  ## This updates the `dag.lastPrunePoint` variable
  doAssert dag.needStateCachesAndForkChoicePruning()

  let startTick = Moment.now()
  block: # Remove states, walking slot by slot
    # We remove all state checkpoints that come _before_ the current finalized
    # head, as we might frequently be asked to replay states from the
    # finalized checkpoint and onwards (for example when validating blocks and
    # attestations)
    var
      cur = dag.finalizedHead.stateCheckpoint.parentOrSlot
      prev = dag.lastPrunePoint.stateCheckpoint.parentOrSlot
    while cur.blck != nil and cur != prev:
      # TODO This is a quick fix to prune some states from the database, but
      # not all, pending a smarter storage - the downside of pruning these
      # states is that certain rewinds will take longer
      # After long periods of non-finalization, it can also take some time to
      # release all these states!
      if cur.slot.epoch mod 32 != 0 and cur.slot != dag.tail.slot:
        dag.delState(cur)
      cur = cur.parentOrSlot
  let statePruneTick = Moment.now()

  block: # Clean up old EpochRef instances
    # After finalization, we can clear up the epoch cache and save memory -
    # it will be recomputed if needed
    for i in 0..<dag.epochRefs.len:
      if dag.epochRefs[i] != nil and
          dag.epochRefs[i].epoch < dag.finalizedHead.slot.epoch:
        dag.epochRefs[i] = nil
  let epochRefPruneTick = Moment.now()

  dag.lastPrunePoint = dag.finalizedHead

  debug "Pruned the state checkpoints and DAG caches.",
    statePruneDur = statePruneTick - startTick,
    epochRefPruneDur = epochRefPruneTick - statePruneTick

proc updateHead*(
      dag: ChainDAGRef,
      newHead: BlockRef,
      quarantine: var Quarantine) =
  ## Update what we consider to be the current head, as given by the fork
  ## choice.
  ##
  ## The choice of head affects the choice of finalization point - the order
  ## of operations naturally becomes important here - after updating the head,
  ## blocks that were once considered potential candidates for a tree will
  ## now fall from grace, or no longer be considered resolved.
  doAssert not newHead.isNil()
  doAssert not newHead.parent.isNil() or newHead.slot <= dag.tail.slot
  logScope:
    newHead = shortLog(newHead)

  if dag.head == newHead:
    trace "No head block update"
    return

  let
    lastHead = dag.head
    lastHeadStateRoot = getStateRoot(dag.headState.data)

  # Start off by making sure we have the right state - updateStateData will try
  # to use existing in-memory states to make this smooth
  var cache: StateCache
  updateStateData(
    dag, dag.headState, newHead.atSlot(), false, cache)

  dag.db.putHeadBlock(newHead.root)

  withState(dag.headState.data):
    when stateFork >= BeaconStateFork.Altair:
      dag.headSyncCommittees = state.data.get_sync_committee_cache(cache)

  let
    finalized_checkpoint =
      getStateField(dag.headState.data, finalized_checkpoint)
    finalizedSlot = max(
      finalized_checkpoint.epoch.compute_start_slot_at_epoch(),
      dag.tail.slot)

    finalizedHead = newHead.atSlot(finalizedSlot)

  doAssert (not finalizedHead.blck.isNil),
    "Block graph should always lead to a finalized block"

  let (isAncestor, ancestorDepth) = lastHead.getDepth(newHead)
  if not(isAncestor):
    notice "Updated head block with chain reorg",
      lastHead = shortLog(lastHead),
      headParent = shortLog(newHead.parent),
      stateRoot = shortLog(getStateRoot(dag.headState.data)),
      headBlock = shortLog(dag.headState.blck),
      stateSlot = shortLog(getStateField(dag.headState.data, slot)),
      justified = shortLog(getStateField(
        dag.headState.data, current_justified_checkpoint)),
      finalized = shortLog(getStateField(
        dag.headState.data, finalized_checkpoint))

    if not(isNil(dag.onReorgHappened)):
      let data = ReorgInfoObject.init(dag.head.slot, uint64(ancestorDepth),
                                      lastHead.root, newHead.root,
                                      lastHeadStateRoot,
                                      getStateRoot(dag.headState.data))
      dag.onReorgHappened(data)

    # A reasonable criterion for "reorganizations of the chain"
    quarantine.clearQuarantine()
    beacon_reorgs_total_total.inc()
    beacon_reorgs_total.inc()
  else:
    debug "Updated head block",
      head = shortLog(dag.headState.blck),
      stateRoot = shortLog(getStateRoot(dag.headState.data)),
      justified = shortLog(getStateField(
        dag.headState.data, current_justified_checkpoint)),
      finalized = shortLog(getStateField(
        dag.headState.data, finalized_checkpoint))

    if not(isNil(dag.onHeadChanged)):
      let currentEpoch = epoch(newHead.slot)
      let
        currentDutyDepRoot =
          if currentEpoch > dag.tail.slot.epoch:
            dag.head.atSlot(
              compute_start_slot_at_epoch(currentEpoch) - 1).blck.root
          else:
            dag.tail.root
        previousDutyDepRoot =
          if currentEpoch > dag.tail.slot.epoch + 1:
            dag.head.atSlot(
              compute_start_slot_at_epoch(currentEpoch - 1) - 1).blck.root
          else:
            dag.tail.root
        epochTransition = (finalizedHead != dag.finalizedHead)
      let data = HeadChangeInfoObject.init(dag.head.slot, dag.head.root,
                                           getStateRoot(dag.headState.data),
                                           epochTransition, previousDutyDepRoot,
                                           currentDutyDepRoot)
      dag.onHeadChanged(data)

  # https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#additional-metrics
  # both non-negative, so difference can't overflow or underflow int64
  beacon_pending_deposits.set(
    getStateField(dag.headState.data, eth1_data).deposit_count.toGaugeValue -
    getStateField(dag.headState.data, eth1_deposit_index).toGaugeValue)
  beacon_processed_deposits_total.set(
    getStateField(dag.headState.data, eth1_deposit_index).toGaugeValue)

  beacon_head_root.set newHead.root.toGaugeValue
  beacon_head_slot.set newHead.slot.toGaugeValue

  if lastHead.slot.epoch != newHead.slot.epoch:
    # Epoch updated - in theory, these could happen when the wall clock
    # changes epoch, even if there is no new block / head, but we'll delay
    # updating them until a block confirms the change
    beacon_current_justified_epoch.set(
      getStateField(
        dag.headState.data, current_justified_checkpoint).epoch.toGaugeValue)
    beacon_current_justified_root.set(
      getStateField(
        dag.headState.data, current_justified_checkpoint).root.toGaugeValue)
    beacon_previous_justified_epoch.set(
      getStateField(
        dag.headState.data, previous_justified_checkpoint).epoch.toGaugeValue)
    beacon_previous_justified_root.set(
      getStateField(
        dag.headState.data, previous_justified_checkpoint).root.toGaugeValue)

    let
      epochRef = getEpochRef(dag, newHead, newHead.slot.epoch)
      number_of_active_validators = epochRef.shuffled_active_validator_indices.lenu64().toGaugeValue
    beacon_active_validators.set(number_of_active_validators)
    beacon_current_active_validators.set(number_of_active_validators)

  if finalizedHead != dag.finalizedHead:
    info "Reached new finalization checkpoint",
      head = shortLog(dag.headState.blck),
      stateRoot = shortLog(getStateRoot(dag.headState.data)),
      justified = shortLog(getStateField(
        dag.headState.data, current_justified_checkpoint)),
      finalized = shortLog(getStateField(
        dag.headState.data, finalized_checkpoint))

    block:
      # Update `dag.finalizedBlocks` with all newly finalized blocks (those
      # newer than the previous finalized head), then update `dag.finalizedHead`

      dag.finalizedBlocks.setLen(finalizedHead.slot - dag.tail.slot + 1)
      var tmp = finalizedHead.blck
      while not isNil(tmp) and tmp.slot >= dag.finalizedHead.slot:
        dag.finalizedBlocks[(tmp.slot - dag.tail.slot).int] = tmp
        tmp = tmp.parent

      dag.finalizedHead = finalizedHead

    beacon_finalized_epoch.set(getStateField(
      dag.headState.data, finalized_checkpoint).epoch.toGaugeValue)
    beacon_finalized_root.set(getStateField(
      dag.headState.data, finalized_checkpoint).root.toGaugeValue)

    # Pruning the block dag is required every time the finalized head changes
    # in order to clear out blocks that are no longer viable and should
    # therefore no longer be considered as part of the chain we're following
    dag.pruneBlocksDAG()

    # Send notification about new finalization point via callback.
    if not(isNil(dag.onFinHappened)):
      let stateRoot =
        if dag.finalizedHead.slot == dag.head.slot:
          getStateRoot(dag.headState.data)
        elif dag.finalizedHead.slot + SLOTS_PER_HISTORICAL_ROOT > dag.head.slot:
          getStateField(dag.headState.data, state_roots).data[
            int(dag.finalizedHead.slot mod SLOTS_PER_HISTORICAL_ROOT)]
        else:
          Eth2Digest() # The thing that finalized was >8192 blocks old?

      let data = FinalizationInfoObject.init(
        dag.finalizedHead.blck.root,
        stateRoot,
        dag.finalizedHead.slot.epoch)
      dag.onFinHappened(data)

proc isInitialized*(T: type ChainDAGRef, db: BeaconChainDB): bool =
  # Lightweight check to see if we have the minimal information needed to
  # load up a database - we don't check head here - if something is wrong with
  # head, it's likely an initialized, but corrupt database - init will detect
  # that
  let
    genesisBlockRoot = db.getGenesisBlock()
    tailBlockRoot = db.getTailBlock()

  if not (genesisBlockRoot.isSome() and tailBlockRoot.isSome()):
    return false

  let
    genesisBlock = db.getForkedBlock(genesisBlockRoot.get())
    tailBlock = db.getForkedBlock(tailBlockRoot.get())

  if not (genesisBlock.isSome() and tailBlock.isSome()):
    return false
  let
    genesisStateRoot = withBlck(genesisBlock.get()): blck.message.state_root
    tailStateRoot = withBlck(tailBlock.get()): blck.message.state_root

  if not (
      db.containsState(genesisStateRoot) and db.containsState(tailStateRoot)):
    return false

  true

proc preInit*(
    T: type ChainDAGRef, db: BeaconChainDB,
    genesisState, tailState: ForkedHashedBeaconState,
    tailBlock: ForkedTrustedSignedBeaconBlock) =
  # write a genesis state, the way the ChainDAGRef expects it to be stored in
  # database
  # TODO probably should just init a block pool with the freshly written
  #      state - but there's more refactoring needed to make it nice - doing
  #      a minimal patch for now..

  logScope:
    genesisStateRoot = getStateRoot(genesisState)
    genesisStateSlot = getStateField(genesisState, slot)
    tailStateRoot = getStateRoot(tailState)
    tailStateSlot = getStateField(tailState, slot)

  let genesisBlockRoot = withState(genesisState):
    if state.root != getStateRoot(tailState):
      # Different tail and genesis
      if state.data.slot >= getStateField(tailState, slot):
        fatal "Tail state must be newer or the same as genesis state"
        quit 1

      let tail_genesis_validators_root =
        getStateField(tailState, genesis_validators_root)
      if state.data.genesis_validators_root != tail_genesis_validators_root:
        fatal "Tail state doesn't match genesis validators root, it is likely from a different network!",
          genesis_validators_root = shortLog(state.data.genesis_validators_root),
          tail_genesis_validators_root = shortLog(tail_genesis_validators_root)
        quit 1

      let blck = get_initial_beacon_block(state)
      db.putGenesisBlock(blck.root)
      db.putBlock(blck)

      db.putStateRoot(state.latest_block_root(), state.data.slot, state.root)
      db.putState(state.root, state.data)
      blck.root
    else: # tail and genesis are the same
      withBlck(tailBlock):
        db.putGenesisBlock(blck.root)
        blck.root

  withState(tailState):
    withBlck(tailBlock):
      # When looking up the state root of the tail block, we don't use the
      # BlockSlot->state_root map, so the only way the init code can find the
      # state is through the state root in the block - this could be relaxed
      # down the line
      if blck.message.state_root != state.root:
        fatal "State must match the given block",
            tailBlck = shortLog(blck)

        quit 1

      db.putBlock(blck)
      db.putTailBlock(blck.root)
      db.putHeadBlock(blck.root)

      db.putStateRoot(state.latest_block_root(), state.data.slot, state.root)
      db.putState(state.root, state.data)

      notice "New database from snapshot",
        genesisBlockRoot = shortLog(genesisBlockRoot),
        genesisStateRoot = shortLog(getStateRoot(genesisState)),
        tailBlockRoot = shortLog(blck.root),
        tailStateRoot = shortLog(state.root),
        fork = state.data.fork,
        validators = state.data.validators.len()

proc getProposer*(
    dag: ChainDAGRef, head: BlockRef, slot: Slot): Option[ValidatorIndex] =
  let
    epochRef = dag.getEpochRef(head, slot.compute_epoch_at_slot())
    slotInEpoch = slot - slot.compute_epoch_at_slot().compute_start_slot_at_epoch()

  let proposer = epochRef.beacon_proposers[slotInEpoch]
  if proposer.isSome():
    if proposer.get().uint64 >= dag.db.immutableValidators.lenu64():
      # Sanity check - it should never happen that the key cache doesn't contain
      # a key for the selected proposer - that would mean that we somehow
      # created validators in the state without updating the cache!
      warn "Proposer key not found",
        keys = dag.db.immutableValidators.lenu64(), proposer = proposer.get()
      return none(ValidatorIndex)

  proposer

proc aggregateAll*(
  dag: ChainDAGRef,
  validator_indices: openArray[ValidatorIndex]): Result[CookedPubKey, cstring] =
  if validator_indices.len == 0:
    # Aggregation spec requires non-empty collection
    # - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04
    # Eth2 spec requires at least one attesting index in attestation
    # - https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
    return err("aggregate: no attesting keys")

  let
    firstKey = dag.validatorKey(validator_indices[0])

  if not firstKey.isSome():
    return err("aggregate: invalid validator index")

  var aggregateKey{.noInit.}: AggregatePublicKey

  aggregateKey.init(firstKey.get())

  for i in 1 ..< validator_indices.len:
    let key = dag.validatorKey(validator_indices[i])
    if not key.isSome():
      return err("aggregate: invalid validator index")
    aggregateKey.aggregate(key.get())

  ok(finish(aggregateKey))

proc aggregateAll*(
  dag: ChainDAGRef,
  validator_indices: openArray[ValidatorIndex|uint64],
  bits: BitSeq | BitArray): Result[CookedPubKey, cstring] =
  if validator_indices.len() != bits.len():
    return err("aggregateAll: mismatch in bits length")

  var
    aggregateKey{.noInit.}: AggregatePublicKey
    inited = false

  for i in 0..<bits.len():
    if bits[i]:
      let key = dag.validatorKey(validator_indices[i])
      if not key.isSome():
        return err("aggregate: invalid validator index")

      if inited:
        aggregateKey.aggregate(key.get)
      else:
        aggregateKey = AggregatePublicKey.init(key.get)
        inited = true

  if not inited:
    err("aggregate: no attesting keys")
  else:
    ok(finish(aggregateKey))
