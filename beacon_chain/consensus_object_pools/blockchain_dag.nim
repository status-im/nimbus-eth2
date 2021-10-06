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
  ../spec/[
    beaconstate, eth2_merkleization, eth2_ssz_serialization, forks, helpers,
    state_transition, validator],
  ../spec/datatypes/[phase0, altair, merge],
  ".."/beacon_chain_db,
  "."/[block_pools_types, block_quarantine, forkedbeaconstate_dbhelpers]

export block_pools_types, results

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
    dag: ChainDAGRef,
    signedBlock: phase0.TrustedSignedBeaconBlock | altair.TrustedSignedBeaconBlock |
                 merge.TrustedSignedBeaconBlock) =
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

  var cache {.inject.} = StateCache()
  updateStateData(dag, stateData, blockSlot, false, cache)

  withStateVars(stateData):
    body

func parent*(bs: BlockSlot): BlockSlot =
  ## Return a blockslot representing the previous slot, using the parent block
  ## if the current slot had a block
  if bs.slot == Slot(0):
    BlockSlot(blck: nil, slot: Slot(0))
  else:
    BlockSlot(
      blck: if bs.slot > bs.blck.slot: bs.blck else: bs.blck.parent,
      slot: bs.slot - 1
    )

func parentOrSlot*(bs: BlockSlot): BlockSlot =
  ## Return a blockslot representing the previous slot, using the parent block
  ## with the current slot if the current had a block
  if bs.blck.isNil():
    BlockSlot(blck: nil, slot: Slot(0))
  elif bs.slot == bs.blck.slot:
    BlockSlot(blck: bs.blck.parent, slot: bs.slot)
  else:
    BlockSlot(blck: bs.blck, slot: bs.slot - 1)

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
        cache.get_shuffled_active_validator_indices(state.data, epoch)
      )

  for i in 0'u64..<SLOTS_PER_EPOCH:
    epochRef.beacon_proposers[i] = get_beacon_proposer_index(
      state.data, cache, epoch.compute_start_slot_at_epoch() + i)

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
        get_current_epoch(state.data)))))

  epochRef

func effective_balances*(epochRef: EpochRef): seq[Gwei] =
  try:
    SSZ.decode(snappy.decode(epochRef.effective_balances_bytes, uint32.high),
      List[Gwei, Limit VALIDATOR_REGISTRY_LIMIT]).toSeq()
  except CatchableError as exc:
    raiseAssert exc.msg

func link*(parent, child: BlockRef) =
  doAssert (not (parent.root == Eth2Digest() or child.root == Eth2Digest())),
    "blocks missing root!"
  doAssert parent.root != child.root, "self-references not allowed"

  child.parent = parent

func getDepth*(a, b: BlockRef): tuple[ancestor: bool, depth: int] =
  var b = b
  var depth = 0
  const maxDepth = (100'i64 * 365 * 24 * 60 * 60 div SECONDS_PER_SLOT.int)
  while true:
    if a == b:
      return (true, depth)

    # for now, use an assert for block chain length since a chain this long
    # indicates a circular reference here..
    doAssert depth < maxDepth
    depth += 1

    if a.slot >= b.slot or b.parent.isNil:
      return (false, depth)

    doAssert b.slot > b.parent.slot
    b = b.parent

func isAncestorOf*(a, b: BlockRef): bool =
  let (isAncestor, _) = getDepth(a, b)
  isAncestor

func get_ancestor*(blck: BlockRef, slot: Slot,
    maxDepth = 100'i64 * 365 * 24 * 60 * 60 div SECONDS_PER_SLOT.int):
    BlockRef =
  ## https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/fork-choice.md#get_ancestor
  ## Return the most recent block as of the time at `slot` that not more recent
  ## than `blck` itself
  doAssert not blck.isNil

  var blck = blck

  var depth = 0

  while true:
    if blck.slot <= slot:
      return blck

    if blck.parent.isNil:
      return nil

    doAssert depth < maxDepth
    depth += 1

    blck = blck.parent

func atSlot*(blck: BlockRef, slot: Slot): BlockSlot =
  ## Return a BlockSlot at a given slot, with the block set to the closest block
  ## available. If slot comes from before the block, a suitable block ancestor
  ## will be used, else blck is returned as if all slots after it were empty.
  ## This helper is useful when imagining what the chain looked like at a
  ## particular moment in time, or when imagining what it will look like in the
  ## near future if nothing happens (such as when looking ahead for the next
  ## block proposal)
  BlockSlot(blck: blck.get_ancestor(slot), slot: slot)

func atEpochStart*(blck: BlockRef, epoch: Epoch): BlockSlot =
  ## Return the BlockSlot corresponding to the first slot in the given epoch
  atSlot(blck, epoch.compute_start_slot_at_epoch)

func epochAncestor*(blck: BlockRef, epoch: Epoch): EpochKey =
  ## The state transition works by storing information from blocks in a
  ## "working" area until the epoch transition, then batching work collected
  ## during the epoch. Thus, last block in the ancestor epochs is the block
  ## that has an impact on epoch currently considered.
  ##
  ## This function returns a BlockSlot pointing to that epoch boundary, ie the
  ## boundary where the last block has been applied to the state and epoch
  ## processing has been done.
  var blck = blck
  while blck.slot.epoch >= epoch and not blck.parent.isNil:
    blck = blck.parent

  EpochKey(epoch: epoch, blck: blck)

func findEpochRef*(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch): EpochRef = # may return nil!
  let ancestor = blck.epochAncestor(epoch)
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

func init(T: type BlockRef, root: Eth2Digest, slot: Slot): BlockRef =
  BlockRef(
    root: root,
    slot: slot
  )

func init*(T: type BlockRef, root: Eth2Digest, blck: SomeSomeBeaconBlock):
    BlockRef =
  BlockRef.init(root, blck.slot)

func contains*(dag: ChainDAGRef, root: Eth2Digest): bool =
  KeyedBlockRef.asLookupKey(root) in dag.blocks

proc containsBlock(
    cfg: RuntimeConfig, db: BeaconChainDB, blck: BlockRef): bool =
  case cfg.stateForkAtEpoch(blck.slot.epoch)
  of forkMerge:  db.containsBlockMerge(blck.root)
  of forkAltair: db.containsBlockAltair(blck.root)
  of forkPhase0: db.containsBlockPhase0(blck.root)

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

proc init*(T: type ChainDAGRef, cfg: RuntimeConfig, db: BeaconChainDB,
           updateFlags: UpdateFlags, onBlockCb: OnBlockCallback = nil,
           onHeadCb: OnHeadCallback = nil, onReorgCb: OnReorgCallback = nil,
           onFinCb: OnFinalizedCallback = nil): ChainDAGRef =
  # TODO we require that the db contains both a head and a tail block -
  #      asserting here doesn't seem like the right way to go about it however..

  let
    tailBlockRoot = db.getTailBlock()
    headBlockRoot = db.getHeadBlock()

  doAssert tailBlockRoot.isSome(), "Missing tail block, database corrupt?"
  doAssert headBlockRoot.isSome(), "Missing head block, database corrupt?"

  let
    tailRoot = tailBlockRoot.get()
    tailBlock = db.getBlock(tailRoot).get()
    tailRef = BlockRef.init(tailRoot, tailBlock.message)
    headRoot = headBlockRoot.get()

  let genesisRef = if tailBlock.message.slot == GENESIS_SLOT:
    tailRef
  else:
    let
      genesisBlockRoot = db.getGenesisBlockRoot().expect(
        "preInit should have initialized the database with a genesis block root")
      genesisBlock = db.getBlock(genesisBlockRoot).expect(
        "preInit should have initialized the database with a genesis block")
    BlockRef.init(genesisBlockRoot, genesisBlock.message)

  var
    blocks: HashSet[KeyedBlockRef]
    headRef: BlockRef

  blocks.incl(KeyedBlockRef.init(tailRef))

  if genesisRef != tailRef:
    blocks.incl(KeyedBlockRef.init(genesisRef))

  if headRoot != tailRoot:
    var curRef: BlockRef

    for blck in db.getAncestorSummaries(headRoot):
      if blck.root == tailRef.root:
        doAssert(not curRef.isNil)
        link(tailRef, curRef)
        curRef = curRef.parent
        break

      let newRef = BlockRef.init(blck.root, blck.summary.slot)
      if curRef == nil:
        curRef = newRef
      else:
        link(newRef, curRef)
        curRef = curRef.parent

      # Don't include blocks on incorrect hardforks
      if headRef == nil and cfg.containsBlock(db, newRef):
        headRef = newRef

      blocks.incl(KeyedBlockRef.init(curRef))
      trace "Populating block dag", key = curRef.root, val = curRef

    doAssert curRef == tailRef,
      "head block does not lead to tail, database corrupt?"
  else:
    headRef = tailRef

  # Because of incorrect hardfork check, there might be no head block, in which
  # case it's equivalent to the tail block
  if headRef == nil:
    headRef = tailRef

  var
    cur = headRef.atSlot(headRef.slot)
    tmpState = (ref StateData)()

  # Now that we have a head block, we need to find the most recent state that
  # we have saved in the database
  while cur.blck != nil:
    if cur.isStateCheckpoint():
      let root = db.getStateRoot(cur.blck.root, cur.slot)
      if root.isSome():
        if db.getState(root.get(), tmpState.data.hbsPhase0.data, noRollback):
          setStateRoot(tmpState.data, root.get())
          tmpState.blck = cur.blck

          break
    cur = cur.parentOrSlot()

  if tmpState.blck == nil:
    warn "No state found in head history, database corrupt?"
    # TODO Potentially we could recover from here instead of crashing - what
    #      would be a good recovery model?
    raiseAssert "No state found in head history, database corrupt?"

  case tmpState.data.beaconStateFork
  of forkPhase0:
    if tmpState.data.hbsPhase0.data.fork != genesisFork(cfg):
      error "State from database does not match network, check --network parameter",
        stateFork = tmpState.data.hbsPhase0.data.fork,
        configFork = genesisFork(cfg)
      quit 1
  of forkAltair:
    if tmpState.data.hbsAltair.data.fork != altairFork(cfg):
      error "State from database does not match network, check --network parameter",
        stateFork = tmpState.data.hbsAltair.data.fork,
        configFork = altairFork(cfg)
      quit 1
  of forkMerge:
    if tmpState.data.hbsMerge.data.fork != mergeFork(cfg):
      error "State from database does not match network, check --network parameter",
        stateFork = tmpState.data.hbsMerge.data.fork,
        configFork = mergeFork(cfg)
      quit 1

  let dag = ChainDAGRef(
    blocks: blocks,
    tail: tailRef,
    genesis: genesisRef,
    db: db,
    forkDigests: newClone ForkDigests.init(
      cfg,
      getStateField(tmpState.data, genesis_validators_root)),
    heads: @[headRef],
    headState: tmpState[],
    epochRefState: tmpState[],
    clearanceState: tmpState[],

    # The only allowed flag right now is verifyFinalization, as the others all
    # allow skipping some validation.
    updateFlags: {verifyFinalization} * updateFlags,
    cfg: cfg,

    onBlockAdded: onBlockCb,
    onHeadChanged: onHeadCb,
    onReorgHappened: onReorgCb,
    onFinHappened: onFinCb
  )

  doAssert cfg.GENESIS_FORK_VERSION != cfg.ALTAIR_FORK_VERSION
  when true:
    doAssert cfg.GENESIS_FORK_VERSION != cfg.MERGE_FORK_VERSION
    doAssert cfg.ALTAIR_FORK_VERSION != cfg.MERGE_FORK_VERSION
  doAssert cfg.ALTAIR_FORK_EPOCH <= cfg.MERGE_FORK_EPOCH
  doAssert dag.updateFlags in [{}, {verifyFinalization}]

  var cache: StateCache
  dag.updateStateData(dag.headState, headRef.atSlot(headRef.slot), false, cache)
  # We presently save states on the epoch boundary - it means that the latest
  # state we loaded might be older than head block - nonetheless, it will be
  # from the same epoch as the head, thus the finalized and justified slots are
  # the same - these only change on epoch boundaries.
  # When we start from a snapshot state, the `finalized_checkpoint` in the
  # snapshot will point to an even older state, but we trust the tail state
  # (the snapshot) to be finalized, hence the `max` expression below.
  let finalizedEpoch = max(getStateField(dag.headState.data, finalized_checkpoint).epoch,
                           tailRef.slot.epoch)
  dag.finalizedHead = headRef.atEpochStart(finalizedEpoch)

  dag.clearanceState = dag.headState

  # Pruning metadata
  dag.lastPrunePoint = dag.finalizedHead

  # Fill validator key cache in case we're loading an old database that doesn't
  # have a cache
  dag.updateValidatorKeys(getStateField(dag.headState.data, validators).asSeq())

  info "Block dag initialized",
    head = shortLog(headRef),
    finalizedHead = shortLog(dag.finalizedHead),
    tail = shortLog(tailRef),
    totalBlocks = blocks.len

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
    ancestor = blck.epochAncestor(epoch)

  dag.withState(
      dag.epochRefState, ancestor.blck.atEpochStart(ancestor.epoch)):
    dag.getEpochRef(stateData, cache)

proc getFinalizedEpochRef*(dag: ChainDAGRef): EpochRef =
  dag.getEpochRef(dag.finalizedHead.blck, dag.finalizedHead.slot.epoch)

proc getState(
    dag: ChainDAGRef, state: var StateData, stateRoot: Eth2Digest,
    blck: BlockRef): bool =
  let restoreAddr =
    # Any restore point will do as long as it's not the object being updated
    if unsafeAddr(state) == unsafeAddr(dag.headState):
      unsafeAddr dag.clearanceState
    else:
      unsafeAddr dag.headState

  let v = addr state.data

  func restore() =
    assign(v[], restoreAddr[].data)

  case dag.cfg.stateForkAtEpoch(blck.slot.epoch)
  of forkMerge:
    if state.data.beaconStateFork != forkMerge:
      state.data = (ref ForkedHashedBeaconState)(beaconStateFork: forkMerge)[]

    if not dag.db.getMergeState(stateRoot, state.data.hbsMerge.data, restore):
      return false
  of forkAltair:
    if state.data.beaconStateFork != forkAltair:
      state.data = (ref ForkedHashedBeaconState)(beaconStateFork: forkAltair)[]

    if not dag.db.getAltairState(stateRoot, state.data.hbsAltair.data, restore):
      return false
  of forkPhase0:
    if state.data.beaconStateFork != forkPhase0:
      state.data = (ref ForkedHashedBeaconState)(beaconStateFork: forkPhase0)[]

    if not dag.db.getState(stateRoot, state.data.hbsPhase0.data, restore):
      return false

  state.blck = blck
  setStateRoot(state.data, stateRoot)

  true

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
  of forkMerge:  dag.forkDigests.merge
  of forkAltair: dag.forkDigests.altair
  of forkPhase0: dag.forkDigests.phase0

proc getState(dag: ChainDAGRef, state: var StateData, bs: BlockSlot): bool =
  ## Load a state from the database given a block and a slot - this will first
  ## lookup the state root in the state root table then load the corresponding
  ## state, if it exists
  if not bs.isStateCheckpoint():
    return false # Only state checkpoints are stored - no need to hit DB

  if (let stateRoot = dag.db.getStateRoot(bs.blck.root, bs.slot);
      stateRoot.isSome()):
    return dag.getState(state, stateRoot.get(), bs.blck)

  false

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
  dag.db.putState(state.data)
  dag.db.putStateRoot(
    state.blck.root, getStateField(state.data, slot), getStateRoot(state.data))

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

func getBlockRange*(
    dag: ChainDAGRef, startSlot: Slot, skipStep: uint64,
    output: var openArray[BlockRef]): Natural =
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

  if startSlot < dag.tail.slot or headSlot <= startSlot or requestedCount == 0:
    return output.len # Identical to returning an empty set of block as indicated above

  let
    runway = uint64(headSlot - startSlot)

    # This is the number of blocks that will follow the start block
    extraBlocks = min(runway div skipStep, requestedCount - 1)

    # If `skipStep` is very large, `extraBlocks` should be 0 from
    # the previous line, so `endSlot` will be equal to `startSlot`:
    endSlot = startSlot + extraBlocks * skipStep

  var
    b = dag.head.atSlot(endSlot)
    o = output.len

  # Process all blocks that follow the start block (may be zero blocks)
  for i in 1..extraBlocks:
    if b.blck.slot == b.slot:
      dec o
      output[o] = b.blck
    for j in 1..skipStep:
      b = b.parent

  # We should now be at the start block.
  # Like any "block slot", it may be a missing/skipped block:
  if b.blck.slot == b.slot:
    dec o
    output[o] = b.blck

  o # Return the index of the first non-nil item in the output

func getBlockBySlot*(dag: ChainDAGRef, slot: Slot): BlockRef =
  ## Retrieves the first block in the current canonical chain
  ## with slot number less or equal to `slot`.
  dag.head.atSlot(slot).blck

proc getForkedBlock*(dag: ChainDAGRef, blck: BlockRef): ForkedTrustedSignedBeaconBlock =
  # TODO implement this properly
  let phase0Block = dag.db.getBlock(blck.root)
  if phase0Block.isOk:
    return ForkedTrustedSignedBeaconBlock.init(phase0Block.get)

  let altairBlock = dag.db.getAltairBlock(blck.root)
  if altairBlock.isOk:
    return ForkedTrustedSignedBeaconBlock.init(altairBlock.get)

  raiseAssert "BlockRef without backing data, database corrupt?"

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
    cache: var StateCache, rewards: var RewardInfo) =
  # Given a state, advance it zero or more slots by applying empty slot
  # processing - the state must be positions at a slot before or equal to the
  # target
  doAssert getStateField(state.data, slot) <= slot
  while getStateField(state.data, slot) < slot:
    loadStateCache(dag, cache, state.blck, getStateField(state.data, slot).epoch)

    doAssert process_slots(
        dag.cfg, state.data, getStateField(state.data, slot) + 1, cache, rewards,
        dag.updateFlags),
      "process_slots shouldn't fail when state slot is correct"
    if save:
      dag.putState(state)

proc applyBlock(
    dag: ChainDAGRef,
    state: var StateData, blck: BlockData, flags: UpdateFlags,
    cache: var StateCache, rewards: var RewardInfo): bool =
  # Apply a single block to the state - the state must be positioned at the
  # parent of the block with a slot lower than the one of the block being
  # applied
  doAssert state.blck == blck.refs.parent

  var statePtr = unsafeAddr state # safe because `restore` is locally scoped
  func restore(v: var ForkedHashedBeaconState) =
    doAssert (addr(statePtr.data) == addr v)
    # TODO the block_clearance version uses assign() here
    statePtr[] = dag.headState

  loadStateCache(dag, cache, state.blck, getStateField(state.data, slot).epoch)

  # TODO some abstractions
  let ok =
    case blck.data.kind:
    of BeaconBlockFork.Phase0:
      state_transition(
        dag.cfg, state.data, blck.data.phase0Block,
        cache, rewards, flags + dag.updateFlags + {slotProcessed}, restore)
    of BeaconBlockFork.Altair:
      state_transition(
        dag.cfg, state.data, blck.data.altairBlock,
        cache, rewards, flags + dag.updateFlags + {slotProcessed}, restore)
    of BeaconBlockFork.Merge:
      state_transition(
        dag.cfg, state.data, blck.data.mergeBlock,
        cache, rewards, flags + dag.updateFlags + {slotProcessed}, restore)
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
  var rewards: RewardInfo
  # Time to replay all the blocks between then and now
  for i in countdown(ancestors.len - 1, 0):
    # Because the ancestors are in the database, there's no need to persist them
    # again. Also, because we're applying blocks that were loaded from the
    # database, we can skip certain checks that have already been performed
    # before adding the block to the database.
    let ok =
      dag.applyBlock(state, dag.get(ancestors[i]), {}, cache, rewards)
    doAssert ok, "Blocks in database should never fail to apply.."

  # ...and make sure to process empty slots as requested
  dag.advanceSlots(state, bs.slot, save, cache, rewards)

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

    var cur = head.atSlot(head.slot)
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

func syncSubcommittee*(syncCommittee: openarray[ValidatorPubKey],
                       committeeIdx: SyncCommitteeIndex): seq[ValidatorPubKey] =
  ## TODO Return a view type
  ## Unfortunately, this doesn't work as a template right now.
  if syncCommittee.len == 0:
    return @[]

  let
    startIdx = committeeIdx.asInt * SYNC_SUBCOMMITTEE_SIZE
    onePastEndIdx = startIdx + SYNC_SUBCOMMITTEE_SIZE
  doAssert startIdx < syncCommittee.len

  @(toOpenArray(syncCommittee, startIdx, onePastEndIdx - 1))

func syncCommitteeParticipants*(dagParam: ChainDAGRef,
                                slotParam: Slot): seq[ValidatorPubKey] =
  # TODO:
  # Use view types in Nim 1.6
  # Right now, the compiler is not able to handle turning this into a
  # template and returning an openarray
  let
    dag = dagParam
    slot = slotParam

  if dag.headState.data.beaconStateFork == forkAltair:
    let
      headSlot = dag.headState.data.hbsAltair.data.slot
      headCommitteePeriod = syncCommitteePeriod(headSlot)
      periodStart = syncCommitteePeriodStartSlot(headCommitteePeriod)
      nextPeriodStart = periodStart + SLOTS_PER_SYNC_COMMITTEE_PERIOD

    if slot >= nextPeriodStart:
      @(dag.headState.data.hbsAltair.data.next_sync_committee.pubkeys.data)
    elif slot >= periodStart:
      @(dag.headState.data.hbsAltair.data.current_sync_committee.pubkeys.data)
    else:
      @[]
  else:
    @[]

func getSubcommitteePositionsAux(
    dag: ChainDAGRef,
    syncCommittee: openarray[ValidatorPubKey],
    committeeIdx: SyncCommitteeIndex,
    validatorIdx: uint64): seq[uint64] =
  # TODO Can we avoid the key conversions by getting a compressed key
  #      out of ImmutableValidatorData2? If we had this, we can define
  #      the function `dag.validatorKeyBytes` and use it here.
  let validatorKey = dag.validatorKey(validatorIdx)
  if validatorKey.isNone():
    return @[]
  let validatorPubKey = validatorKey.get().toPubKey

  for pos, key in syncCommittee.syncSubcommittee(committeeIdx):
    if validatorPubKey == key:
      result.add uint64(pos)

func getSubcommitteePositions*(dag: ChainDAGRef,
                               slot: Slot,
                               committeeIdx: SyncCommitteeIndex,
                               validatorIdx: uint64): seq[uint64] =
  if dag.headState.data.beaconStateFork == forkPhase0:
    return @[]

  let
    headSlot = dag.headState.data.hbsAltair.data.slot
    headCommitteePeriod = syncCommitteePeriod(headSlot)
    periodStart = syncCommitteePeriodStartSlot(headCommitteePeriod)
    nextPeriodStart = periodStart + SLOTS_PER_SYNC_COMMITTEE_PERIOD

  template search(syncCommittee: openarray[ValidatorPubKey]): seq[uint64] =
    dag.getSubcommitteePositionsAux(syncCommittee, committeeIdx, validatorIdx)

  if slot < periodStart:
    return @[]
  elif slot >= nextPeriodStart:
    return search(dag.headState.data.hbsAltair.data.next_sync_committee.pubkeys.data)
  else:
    return search(dag.headState.data.hbsAltair.data.current_sync_committee.pubkeys.data)

template syncCommitteeParticipants*(
    dag: ChainDAGRef,
    slot: Slot,
    committeeIdx: SyncCommitteeIndex): seq[ValidatorPubKey] =
  let
    startIdx = committeeIdx.asInt * SYNC_SUBCOMMITTEE_SIZE
    onePastEndIdx = startIdx + SYNC_SUBCOMMITTEE_SIZE
  # TODO Nim is not happy with returning an openarray here
  @(toOpenArray(dag.syncCommitteeParticipants(slot), startIdx, onePastEndIdx - 1))

iterator syncCommitteeParticipants*(
    dag: ChainDAGRef,
    slot: Slot,
    committeeIdx: SyncCommitteeIndex,
    aggregationBits: SyncCommitteeAggregationBits): ValidatorPubKey =
  for pos, valIdx in pairs(dag.syncCommitteeParticipants(slot, committeeIdx)):
    if aggregationBits[pos]:
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
      quarantine: QuarantineRef) =
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
    dag, dag.headState, newHead.atSlot(newHead.slot), false, cache)

  dag.db.putHeadBlock(newHead.root)

  let
    finalizedHead = newHead.atEpochStart(
      getStateField(dag.headState.data, finalized_checkpoint).epoch)

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
      stateRoot = shortLog(getStateRoot(dag.headState.data)),
      headBlock = shortLog(dag.headState.blck),
      stateSlot = shortLog(getStateField(dag.headState.data, slot)),
      justified = shortLog(getStateField(
        dag.headState.data, current_justified_checkpoint)),
      finalized = shortLog(getStateField(
        dag.headState.data, finalized_checkpoint))

    if not(isNil(dag.onHeadChanged)):
      let currentEpoch = epoch(newHead.slot)
      let
        currentDutyDepRoot =
          if currentEpoch > Epoch(0):
            dag.head.atSlot(
              compute_start_slot_at_epoch(currentEpoch) - 1).blck.root
          else:
            dag.genesis.root
        previousDutyDepRoot =
          if currentEpoch > Epoch(1):
            dag.head.atSlot(
              compute_start_slot_at_epoch(currentEpoch - 1) - 1).blck.root
          else:
            dag.genesis.root
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
    notice "Reached new finalization checkpoint",
      newFinalizedHead = shortLog(finalizedHead),
      oldFinalizedHead = shortLog(dag.finalizedHead)

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
      let epoch = getStateField(
        dag.headState.data, finalized_checkpoint).epoch
      let blckRoot = getStateField(
        dag.headState.data, finalized_checkpoint).root
      let data = FinalizationInfoObject.init(blckRoot,
                                             getStateRoot(dag.headState.data),
                                             epoch)
      dag.onFinHappened(data)

proc isInitialized*(T: type ChainDAGRef, db: BeaconChainDB): bool =
  let
    headBlockRoot = db.getHeadBlock()
    tailBlockRoot = db.getTailBlock()

  if not (headBlockRoot.isSome() and tailBlockRoot.isSome()):
    return false

  let
    headBlockPhase0 = db.getBlock(headBlockRoot.get())
    headBlockAltair = db.getAltairBlock(headBlockRoot.get())
    tailBlock = db.getBlock(tailBlockRoot.get())

  if not ((headBlockPhase0.isSome() or headBlockAltair.isSome()) and
          tailBlock.isSome()):
    return false

  if not db.containsState(tailBlock.get().message.state_root):
    return false

  true

proc preInit*(
    T: type ChainDAGRef, db: BeaconChainDB,
    genesisState, tailState: var phase0.BeaconState, tailBlock: phase0.TrustedSignedBeaconBlock) =
  # write a genesis state, the way the ChainDAGRef expects it to be stored in
  # database
  # TODO probably should just init a block pool with the freshly written
  #      state - but there's more refactoring needed to make it nice - doing
  #      a minimal patch for now..
  doAssert tailBlock.message.state_root == hash_tree_root(tailState)
  notice "New database from snapshot",
    blockRoot = shortLog(tailBlock.root),
    stateRoot = shortLog(tailBlock.message.state_root),
    fork = tailState.fork,
    validators = tailState.validators.len()

  db.putState(tailState)
  db.putBlock(tailBlock)
  db.putTailBlock(tailBlock.root)
  db.putHeadBlock(tailBlock.root)
  db.putStateRoot(tailBlock.root, tailState.slot, tailBlock.message.state_root)

  if tailState.slot == GENESIS_SLOT:
    db.putGenesisBlockRoot(tailBlock.root)
  else:
    doAssert genesisState.slot == GENESIS_SLOT
    db.putState(genesisState)
    let genesisBlock = get_initial_beacon_block(genesisState)
    db.putBlock(genesisBlock)
    db.putStateRoot(genesisBlock.root, GENESIS_SLOT, genesisBlock.message.state_root)
    db.putGenesisBlockRoot(genesisBlock.root)

func setTailState*(dag: ChainDAGRef,
                   checkpointState: phase0.BeaconState,
                   checkpointBlock: phase0.TrustedSignedBeaconBlock) =
  # TODO(zah)
  # Delete all records up to the tail node. If the tail node is not
  # in the database, init the dabase in a way similar to `preInit`.
  discard

proc getGenesisBlockData*(dag: ChainDAGRef): BlockData =
  dag.get(dag.genesis)

func getGenesisBlockSlot*(dag: ChainDAGRef): BlockSlot =
  BlockSlot(blck: dag.genesis, slot: GENESIS_SLOT)

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
