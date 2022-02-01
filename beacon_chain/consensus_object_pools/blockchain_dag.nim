# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
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
  ../spec/datatypes/[phase0, altair],
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

const
  # When finality happens, we prune historical states from the database except
  # for a snapshort every 32 epochs from which replays can happen - there's a
  # balance here between making long replays and saving on disk space
  EPOCHS_PER_STATE_SNAPSHOT = 32

proc putBlock*(
    dag: ChainDAGRef, signedBlock: ForkyTrustedSignedBeaconBlock) =
  dag.db.putBlock(signedBlock)

proc updateStateData*(
  dag: ChainDAGRef, state: var StateData, bs: BlockSlot, save: bool,
  cache: var StateCache): bool {.gcsafe.}

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

template withUpdatedState*(
    dag: ChainDAGRef, stateData: var StateData, blockSlot: BlockSlot,
    okBody: untyped, failureBody: untyped): untyped =
  ## Helper template that updates stateData to a particular BlockSlot - usage of
  ## stateData is unsafe outside of block, or across `await` boundaries

  block:
    var cache {.inject.} = StateCache()
    if updateStateData(dag, stateData, blockSlot, false, cache):
      withStateVars(stateData):
        okBody
    else:
      failureBody

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

proc updateFinalizedBlocks*(dag: ChainDAGRef) =
  template update(s: Slot) =
    if s < dag.tail.slot:
      if dag.backfillBlocks[s.int] != Eth2Digest():
        dag.db.finalizedBlocks.insert(s, dag.backfillBlocks[s.int])
    else:
      let dagIndex = int(s - dag.tail.slot)
      if not isNil(dag.finalizedBlocks[dagIndex]):
        dag.db.finalizedBlocks.insert(s, dag.finalizedBlocks[dagIndex].root)

  if not dag.db.db.readOnly: # TODO abstraction leak - where to put this?
    dag.db.withManyWrites:
      if dag.db.finalizedBlocks.low.isNone():
        for s in dag.backfill.slot .. dag.finalizedHead.slot:
          update(s)
      else:
        for s in dag.backfill.slot ..< dag.db.finalizedBlocks.low.get():
          update(s)
        for s in dag.db.finalizedBlocks.high.get() + 1 .. dag.finalizedHead.slot:
          update(s)

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
        of BeaconStateFork.Bellatrix:
          # https://github.com/ethereum/consensus-specs/blob/v1.1.7/specs/merge/beacon-chain.md#is_merge_transition_complete
          state.data.bellatrixData.data.latest_execution_payload_header !=
            ExecutionPayloadHeader()
    )
    epochStart = epoch.start_slot()

  doAssert epochRef.key.blck != nil, "epochAncestor should not fail for state block"

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

func getBlockRef*(dag: ChainDAGRef, root: Eth2Digest): Opt[BlockRef] =
  ## Retrieve a resolved block reference, if available - this function does
  ## not return historical finalized blocks, see `getBlockAtSlot` for a function
  ## that covers the entire known history
  let key = KeyedBlockRef.asLookupKey(root)
  # HashSet lacks the api to do check-and-get in one lookup - `[]` will return
  # the copy of the instance in the set which has more fields than `root` set!
  if key in dag.forkBlocks:
    try: ok(dag.forkBlocks[key].blockRef())
    except KeyError: raiseAssert "contains"
  else:
    err()

func getBlockAtSlot*(dag: ChainDAGRef, slot: Slot): BlockSlot =
  ## Retrieve the canonical block at the given slot, or the last block that
  ## comes before - similar to atSlot, but without the linear scan - see
  ## getBlockIdAtSlot for a version that covers backfill blocks as well
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

func getBlockIdAtSlot*(dag: ChainDAGRef, slot: Slot): BlockSlotId =
  ## Retrieve the canonical block at the given slot, or the last block that
  ## comes before - similar to atSlot, but without the linear scan
  if slot == dag.genesis.slot:
    return dag.genesis.bid.atSlot(slot)

  if slot >= dag.tail.slot:
    return dag.getBlockAtSlot(slot).toBlockSlotId()

  var pos = slot.int
  while pos >= dag.backfill.slot.int:
    if dag.backfillBlocks[pos] != Eth2Digest():
      return BlockId(root: dag.backfillBlocks[pos], slot: Slot(pos)).atSlot(slot)
    pos -= 1

  BlockSlotId() # not backfilled yet, and not genesis

func getBlockId*(dag: ChainDAGRef, root: Eth2Digest): Opt[BlockId] =
  let blck = ? dag.getBlockRef(root)
  ok(blck.bid)

func isCanonical*(dag: ChainDAGRef, bid: BlockId): bool =
  dag.getBlockIdAtSlot(bid.slot).bid == bid

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

  if blck.slot.epoch > epoch:
    EpochKey() # The searched-for epoch predates our tail block
  else:
    EpochKey(epoch: epoch, blck: blck)

func findEpochRef*(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch): Opt[EpochRef] =
  # Look for an existing EpochRef in the cache
  let ancestor = epochAncestor(blck, epoch)
  if isNil(ancestor.blck):
    # We can't compute EpochRef instances for states before the tail because
    # we do not have them!

    return err()

  for i in 0..<dag.epochRefs.len:
    if dag.epochRefs[i] != nil and dag.epochRefs[i].key == ancestor:
      return ok(dag.epochRefs[i])

  err()

func loadStateCache(
    dag: ChainDAGRef, cache: var StateCache, blck: BlockRef, epoch: Epoch) =
  # When creating a state cache, we want the current and the previous epoch
  # information to be preloaded as both of these are used in state transition
  # functions

  template load(e: Epoch) =
    block:
      let epoch = e
      if epoch notin cache.shuffled_active_validator_indices:
        let epochRef = dag.findEpochRef(blck, epoch)
        if epochRef.isSome():
          cache.shuffled_active_validator_indices[epoch] =
            epochRef[].shuffled_active_validator_indices
          let start_slot = epoch.start_slot()
          for i, idx in epochRef[].beacon_proposers:
            cache.beacon_proposer_indices[start_slot + i] = idx

  load(epoch)

  if epoch > 0:
    load(epoch - 1)

func containsForkBlock*(dag: ChainDAGRef, root: Eth2Digest): bool =
  ## Checks for blocks at the finalized checkpoint or newer
  KeyedBlockRef.asLookupKey(root) in dag.forkBlocks

proc containsBlock(
    cfg: RuntimeConfig, db: BeaconChainDB, slot: Slot, root: Eth2Digest): bool =
  case cfg.blockForkAtEpoch(slot.epoch)
  of BeaconBlockFork.Phase0:    db.containsBlockPhase0(root)
  of BeaconBlockFork.Altair:    db.containsBlockAltair(root)
  of BeaconBlockFork.Bellatrix: db.containsBlockMerge(root)

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
  (bs.slot.is_epoch and bs.slot.epoch == (bs.blck.slot.epoch + 1))

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
  of BeaconStateFork.Bellatrix:
    if not db.getState(root.get(), state.data.bellatrixData.data, rollback):
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

proc getForkedBlock*(db: BeaconChainDB, root: Eth2Digest):
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

proc getForkedBlock*(
    dag: ChainDAGRef, root: Eth2Digest): Opt[ForkedTrustedSignedBeaconBlock] =
  dag.db.getForkedBlock(root)

proc getForkedBlock*(
    dag: ChainDAGRef, id: BlockId): Opt[ForkedTrustedSignedBeaconBlock] =
  case dag.cfg.blockForkAtEpoch(id.slot.epoch)
  of BeaconBlockFork.Phase0:
    let data = dag.db.getPhase0Block(id.root)
    if data.isOk():
      return ok ForkedTrustedSignedBeaconBlock.init(data.get)
  of BeaconBlockFork.Altair:
    let data = dag.db.getAltairBlock(id.root)
    if data.isOk():
      return ok ForkedTrustedSignedBeaconBlock.init(data.get)
  of BeaconBlockFork.Bellatrix:
    let data = dag.db.getMergeBlock(id.root)
    if data.isOk():
      return ok ForkedTrustedSignedBeaconBlock.init(data.get)

proc getForkedBlock*(
    dag: ChainDAGRef, blck: BlockRef): ForkedTrustedSignedBeaconBlock =
  dag.getForkedBlock(blck.bid).expect(
    "BlockRef block should always load, database corrupt?")

proc updateBeaconMetrics(state: StateData, cache: var StateCache) =
  # https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#additional-metrics
  # both non-negative, so difference can't overflow or underflow int64

  beacon_head_root.set(state.blck.root.toGaugeValue)
  beacon_head_slot.set(state.blck.slot.toGaugeValue)

  withState(state.data):
    beacon_pending_deposits.set(
      (state.data.eth1_data.deposit_count -
        state.data.eth1_deposit_index).toGaugeValue)
    beacon_processed_deposits_total.set(
      state.data.eth1_deposit_index.toGaugeValue)

    beacon_current_justified_epoch.set(
      state.data.current_justified_checkpoint.epoch.toGaugeValue)
    beacon_current_justified_root.set(
      state.data.current_justified_checkpoint.root.toGaugeValue)
    beacon_previous_justified_epoch.set(
      state.data.previous_justified_checkpoint.epoch.toGaugeValue)
    beacon_previous_justified_root.set(
      state.data.previous_justified_checkpoint.root.toGaugeValue)
    beacon_finalized_epoch.set(
      state.data.finalized_checkpoint.epoch.toGaugeValue)
    beacon_finalized_root.set(
      state.data.finalized_checkpoint.root.toGaugeValue)

    let active_validators = count_active_validators(
      state.data, state.data.slot.epoch, cache).toGaugeValue
    beacon_active_validators.set(active_validators)
    beacon_current_active_validators.set(active_validators)

proc init*(T: type ChainDAGRef, cfg: RuntimeConfig, db: BeaconChainDB,
           validatorMonitor: ref ValidatorMonitor, updateFlags: UpdateFlags,
           onBlockCb: OnBlockCallback = nil, onHeadCb: OnHeadCallback = nil,
           onReorgCb: OnReorgCallback = nil,
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

  var
    backfillBlocks = newSeq[Eth2Digest](tailRef.slot.int)
    backfill = BeaconBlockSummary(slot: GENESIS_SLOT)
    midRef: BlockRef
    backRoot: Option[Eth2Digest]
    startTick = Moment.now()

  # Loads blocks in the forward direction - these may or may not be available
  # in the database
  for slot, root in db.finalizedBlocks:
    if slot < tailRef.slot:
      backfillBlocks[slot.int] = root
      if backRoot.isNone():
        backRoot = some(root)
    elif slot == tailRef.slot:
      midRef = tailRef
    elif slot > tailRef.slot:
      let next = BlockRef.init(root, slot)
      link(midRef, next)
      midRef = next

  let finalizedTick = Moment.now()

  var
    headRef: BlockRef
    curRef: BlockRef

  # Now load the part from head to finalized in the other direction - these
  # should meet at the midpoint if we loaded any finalized blocks
  for blck in db.getAncestorSummaries(headRoot):
    if midRef != nil and blck.summary.slot == midRef.slot:
      if midRef.root != blck.root:
        fatal "Finalized block table does not match ancestor summaries, database corrupt?",
          head = shortLog(headRoot), cur = shortLog(curRef),
          midref = shortLog(midRef), blck = shortLog(blck.root)

        quit 1

      if curRef == nil:
        # When starting from checkpoint, head == tail and there won't be any
        # blocks in between
        headRef = tailRef
      else:
        link(midRef, curRef)

       # The finalized blocks form a linear history by definition - we can skip
       # straight to the tail
      curRef = tailRef
      break

    if blck.summary.slot < tailRef.slot:
      backfillBlocks[blck.summary.slot.int] = blck.root
      if backRoot.isNone():
        backfill = blck.summary
    elif blck.summary.slot == tailRef.slot:
      if backRoot.isNone():
        backfill = blck.summary

      if curRef == nil:
        curRef = tailRef
        headRef = tailRef
      else:
        link(tailRef, curRef)
        curRef = curRef.parent
    else:
      let newRef = BlockRef.init(blck.root, blck.summary.slot)
      if curRef == nil:
        curRef = newRef
        headRef = newRef
      else:
        link(newRef, curRef)
        curRef = curRef.parent

      trace "Populating block dag", key = curRef.root, val = curRef

  if backRoot.isSome():
    backfill = db.getBeaconBlockSummary(backRoot.get()).expect(
      "Backfill block must have a summary")

  let summariesTick = Moment.now()

  if curRef != tailRef:
    fatal "Head block does not lead to tail - database corrupt?",
      genesisRef, tailRef, headRef, curRef, tailRoot, headRoot

    quit 1

  while not containsBlock(cfg, db, headRef.slot, headRef.root):
    # When the database has been written with a pre-fork version of the
    # software, it may happen that blocks produced using an "unforked"
    # chain get written to the database - we need to skip such blocks
    # when loading the database with a fork-compatible version
    if isNil(headRef.parent):
      fatal "Cannot find block for head root - database corrupt?",
        headRef = shortLog(headRef)

    headRef = headRef.parent

  # Because of incorrect hardfork check, there might be no head block, in which
  # case it's equivalent to the tail block
  if headRef == nil:
    headRef = tailRef

  let dag = ChainDAGRef(
    db: db,
    validatorMonitor: validatorMonitor,
    genesis: genesisRef,
    tail: tailRef,
    backfill: backfill,
    finalizedHead: tailRef.atSlot(),
    lastPrunePoint: tailRef.atSlot(),
    # Tail is implicitly finalized - we'll adjust it below when computing the
    # head state
    heads: @[headRef],

    # The only allowed flag right now is verifyFinalization, as the others all
    # allow skipping some validation.
    updateFlags: {verifyFinalization} * updateFlags,
    cfg: cfg,

    onBlockAdded: onBlockCb,
    onHeadChanged: onHeadCb,
    onReorgHappened: onReorgCb,
    onFinHappened: onFinCb
  )

  block: # Initialize dag states
    var
      cur = headRef.atSlot()

    # Now that we have a head block, we need to find the most recent state that
    # we have saved in the database
    while cur.blck != nil and
        not getStateData(db, cfg, dag.headState, cur, noRollback):
      cur = cur.parentOrSlot()

    if dag.headState.blck == nil:
      fatal "No state found in head history, database corrupt?",
        genesisRef, tailRef, headRef, tailRoot, headRoot
      # TODO Potentially we could recover from here instead of crashing - what
      #      would be a good recovery model?
      quit 1

    let
      configFork = case dag.headState.data.kind
        of BeaconStateFork.Phase0: genesisFork(cfg)
        of BeaconStateFork.Altair: altairFork(cfg)
        of BeaconStateFork.Bellatrix: bellatrixFork(cfg)
      statefork = getStateField(dag.headState.data, fork)

    if stateFork != configFork:
      error "State from database does not match network, check --network parameter",
        genesisRef, tailRef, headRef, tailRoot, headRoot, stateFork, configFork
      quit 1

  # db state is likely a epoch boundary state which is what we want for epochs
  assign(dag.epochRefState, dag.headState)

  dag.forkDigests = newClone ForkDigests.init(
    cfg,
    getStateField(dag.headState.data, genesis_validators_root))

  swap(dag.backfillBlocks, backfillBlocks) # avoid allocating a full copy

  let forkVersions =
    [cfg.GENESIS_FORK_VERSION, cfg.ALTAIR_FORK_VERSION,
     cfg.BELLATRIX_FORK_VERSION, cfg.SHARDING_FORK_VERSION]
  for i in 0 ..< forkVersions.len:
    for j in i+1 ..< forkVersions.len:
      doAssert forkVersions[i] != forkVersions[j]
  doAssert cfg.ALTAIR_FORK_EPOCH <= cfg.MERGE_FORK_EPOCH
  doAssert cfg.MERGE_FORK_EPOCH <= cfg.SHARDING_FORK_EPOCH
  doAssert dag.updateFlags in [{}, {verifyFinalization}]

  var cache: StateCache
  if not dag.updateStateData(dag.headState, headRef.atSlot(), false, cache):
    fatal "Unable to load head state, database corrupt?",
      head = shortLog(headRef)

    quit 1

  # Clearance most likely happens from head - assign it after rewinding head
  assign(dag.clearanceState, dag.headState)

  withState(dag.headState.data):
    dag.validatorMonitor[].registerState(state.data)

  updateBeaconMetrics(dag.headState, cache)

  # The tail block is "implicitly" finalized as it was given either as a
  # checkpoint block, or is the genesis, thus we use it as a lower bound when
  # computing the finalized head
  let
    finalized_checkpoint =
      getStateField(dag.headState.data, finalized_checkpoint)
    finalizedSlot = max(finalized_checkpoint.epoch.start_slot(), tailRef.slot)

  block: # Set up finalizedHead -> head
    var tmp = dag.head
    while tmp.slot > finalizedSlot:
      dag.forkBlocks.incl(KeyedBlockRef.init(tmp))
      tmp = tmp.parent

    dag.forkBlocks.incl(KeyedBlockRef.init(tmp))
    dag.finalizedHead = tmp.atSlot(finalizedSlot)

  block: # Set up tail -> finalizedHead
    dag.finalizedBlocks.setLen((dag.finalizedHead.slot - dag.tail.slot).int + 1)

    var tmp = dag.finalizedHead.blck
    while not isNil(tmp):
      dag.finalizedBlocks[(tmp.slot - dag.tail.slot).int] = tmp
      tmp = tmp.parent

  let stateTick = Moment.now()

  # Pruning metadata
  dag.lastPrunePoint = dag.finalizedHead

  # Fill validator key cache in case we're loading an old database that doesn't
  # have a cache
  dag.updateValidatorKeys(getStateField(dag.headState.data, validators).asSeq())
  dag.updateFinalizedBlocks()

  withState(dag.headState.data):
    when stateFork >= BeaconStateFork.Altair:
      dag.headSyncCommittees = state.data.get_sync_committee_cache(cache)

  info "Block DAG initialized",
    head = shortLog(dag.head),
    finalizedHead = shortLog(dag.finalizedHead),
    tail = shortLog(dag.tail),
    backfill = (dag.backfill.slot, shortLog(dag.backfill.parent_root)),
    finalizedDur = finalizedTick - startTick,
    summariesDur = summariesTick - finalizedTick,
    stateDur = stateTick - summariesTick,
    indexDur = Moment.now() - stateTick

  dag

template genesisValidatorsRoot*(dag: ChainDAGRef): Eth2Digest =
  getStateField(dag.headState.data, genesis_validators_root)

func getEpochRef*(
    dag: ChainDAGRef, state: StateData, cache: var StateCache): EpochRef =
  ## Get a cached `EpochRef` or construct one based on the given state - always
  ## returns an EpochRef instance
  let
    blck = state.blck
    epoch = state.data.get_current_epoch()

  var epochRef = dag.findEpochRef(blck, epoch)
  if epochRef.isErr:
    let res = EpochRef.init(dag, state, cache)

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

      dag.epochRefs[oldest] = res
    res
  else:
    epochRef.get()

proc getEpochRef*(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch,
    preFinalized: bool): Opt[EpochRef] =
  ## Return a cached EpochRef or construct one from the database, if possible -
  ## returns `none` on failure.
  ##
  ## When `preFinalized` is true, include epochs from before the finalized
  ## checkpoint in the search - this potentially can result in long processing
  ## times due to state replays.
  ##
  ## Requests for epochs >= dag.finalizedHead.slot.epoch always return an
  ## instance. One must be careful to avoid race conditions in `async` code
  ## where the finalized head might change during an `await`.
  ##
  ## Requests for epochs < dag.finalizedHead.slot.epoch may fail, either because
  ## the search was limited by the `preFinalized` flag or because state history
  ## has been pruned - none will be returned in this case.

  if not preFinalized and epoch < dag.finalizedHead.slot.epoch:
    return err()

  let epochRef = dag.findEpochRef(blck, epoch)
  if epochRef.isOk():
    beacon_state_data_cache_hits.inc
    return epochRef

  beacon_state_data_cache_misses.inc

  let
    ancestor = epochAncestor(blck, epoch)
  if isNil(ancestor.blck): # past the tail
    return err()

  dag.withUpdatedState(
      dag.epochRefState, ancestor.blck.atEpochStart(ancestor.epoch)) do:
    ok(dag.getEpochRef(stateData, cache))
  do:
    err()

proc getFinalizedEpochRef*(dag: ChainDAGRef): EpochRef =
  dag.getEpochRef(
    dag.finalizedHead.blck, dag.finalizedHead.slot.epoch, false).expect(
      "getEpochRef for finalized head should always succeed")

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
  of BeaconStateFork.Bellatrix: dag.forkDigests.bellatrix
  of BeaconStateFork.Altair:    dag.forkDigests.altair
  of BeaconStateFork.Phase0:    dag.forkDigests.phase0

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
    dag.db.putState(state)

  debug "Stored state", putStateDur = Moment.now() - startTick

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
    let bs = dag.getBlockIdAtSlot(curSlot)
    if bs.isProposed():
      o -= 1
      output[o] = bs.bid
    curSlot -= skipStep

  # Handle start slot separately (to avoid underflow when computing curSlot)
  let bs = dag.getBlockIdAtSlot(startSlot)
  if bs.isProposed():
    o -= 1
    output[o] = bs.bid

  o # Return the index of the first non-nil item in the output

proc advanceSlots(
    dag: ChainDAGRef, state: var StateData, slot: Slot, save: bool,
    cache: var StateCache, info: var ForkedEpochInfo) =
  # Given a state, advance it zero or more slots by applying empty slot
  # processing - the state must be positions at a slot before or equal to the
  # target
  doAssert getStateField(state.data, slot) <= slot

  while getStateField(state.data, slot) < slot:
    let preEpoch = getStateField(state.data, slot).epoch
    loadStateCache(dag, cache, state.blck, getStateField(state.data, slot).epoch)

    process_slots(
      dag.cfg, state.data, getStateField(state.data, slot) + 1, cache, info,
      dag.updateFlags).expect("process_slots shouldn't fail when state slot is correct")
    if save:
      dag.putState(state)

      # The reward information in the state transition is computed for epoch
      # transitions - when transitioning into epoch N, the activities in epoch
      # N-2 are translated into balance updates, and this is what we capture
      # in the monitor. This may be inaccurate during a deep reorg (>1 epoch)
      # which is an acceptable tradeoff for monitoring.
      withState(state.data):
        let postEpoch = state.data.slot.epoch
        if preEpoch != postEpoch:
          dag.validatorMonitor[].registerEpochInfo(postEpoch, info, state.data)

proc applyBlock(
    dag: ChainDAGRef,
    state: var StateData, blck: BlockRef, flags: UpdateFlags,
    cache: var StateCache, info: var ForkedEpochInfo) =
  # Apply a single block to the state - the state must be positioned at the
  # parent of the block with a slot lower than the one of the block being
  # applied
  doAssert state.blck == blck.parent

  loadStateCache(dag, cache, state.blck, getStateField(state.data, slot).epoch)

  case dag.cfg.blockForkAtEpoch(blck.slot.epoch)
  of BeaconBlockFork.Phase0:
    let data = dag.db.getPhase0Block(blck.root).expect("block loaded")
    state_transition(
      dag.cfg, state.data, data, cache, info,
      flags + dag.updateFlags + {slotProcessed}, noRollback).expect(
        "Blocks from database must not fail to apply")
  of BeaconBlockFork.Altair:
    let data = dag.db.getAltairBlock(blck.root).expect("block loaded")
    state_transition(
      dag.cfg, state.data, data, cache, info,
      flags + dag.updateFlags + {slotProcessed}, noRollback).expect(
        "Blocks from database must not fail to apply")
  of BeaconBlockFork.Bellatrix:
    let data = dag.db.getMergeBlock(blck.root).expect("block loaded")
    state_transition(
      dag.cfg, state.data, data, cache, info,
      flags + dag.updateFlags + {slotProcessed}, noRollback).expect(
        "Blocks from database must not fail to apply")

  state.blck = blck

proc updateStateData*(
    dag: ChainDAGRef, state: var StateData, bs: BlockSlot, save: bool,
    cache: var StateCache): bool =
  ## Rewind or advance state such that it matches the given block and slot -
  ## this may include replaying from an earlier snapshot if blck is on a
  ## different branch or has advanced to a higher slot number than slot
  ## If `bs.slot` is higher than `bs.blck.slot`, `updateStateData` will fill in
  ## with empty/non-block slots

  # First, see if we're already at the requested block. If we are, also check
  # that the state has not been advanced past the desired block - if it has,
  # an earlier state must be loaded since there's no way to undo the slot
  # transitions

  if isNil(bs.blck):
    info "Requesting state for unknown block, historical data not available?",
      head = shortLog(dag.head), tail = shortLog(dag.tail)

    return false

  let
    startTick = Moment.now()
    current {.used.} = state.blck.atSlot(getStateField(state.data, slot))

  var
    ancestors: seq[BlockRef]
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
  if exactMatch(state, bs):
    found = true
  elif not save:
    # When required to save states, we cannot rely on the caches because that
    # would skip the extra processing that save does - not all information that
    # goes into the database is cached
    if exactMatch(dag.headState, bs):
      assign(state, dag.headState)
      found = true
    elif exactMatch(dag.clearanceState, bs):
      assign(state, dag.clearanceState)
      found = true
    elif exactMatch(dag.epochRefState, bs):
      assign(state, dag.epochRefState)
      found = true

  const RewindBlockThreshold = 64

  if not found:
    # No exact match found - see if any in-memory state can be used as a base
    # onto which we can apply a few blocks - there's a tradeoff here between
    # loading the state from disk and performing the block applications
    var cur = bs
    while ancestors.len < RewindBlockThreshold:
      if isNil(cur.blck): # tail reached
        break

      if canAdvance(state, cur): # Typical case / fast path when there's no reorg
        found = true
        break

      if not save: # see above
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

      if cur.isProposed():
        # This is not an empty slot, so the block will need to be applied to
        # eventually reach bs
        ancestors.add(cur.blck)

      # Move slot by slot to capture epoch boundary states
      cur = cur.parentOrSlot()

  if not found:
    debug "UpdateStateData cache miss",
      current = shortLog(current), target = shortLog(bs)

    # Either the state is too new or was created by applying a different block.
    # We'll now resort to loading the state from the database then reapplying
    # blocks until we reach the desired point in time.

    var cur = bs
    ancestors.setLen(0)

    # Look for a state in the database and load it - as long as it cannot be
    # found, keep track of the blocks that are needed to reach it from the
    # state that eventually will be found.
    # If we hit the tail, it means that we've reached a point for which we can
    # no longer recreate history - this happens for example when starting from
    # a checkpoint block
    let startEpoch = bs.slot.epoch
    while not canAdvance(state, cur) and not dag.getState(state, cur):
      # There's no state saved for this particular BlockSlot combination, and
      # the state we have can't trivially be advanced (in case it was older than
      # RewindBlockThreshold), keep looking..
      if cur.isProposed():
        # This is not an empty slot, so the block will need to be applied to
        # eventually reach bs
        ancestors.add(cur.blck)

      if cur.slot == dag.tail.slot or
          (cur.slot.epoch + EPOCHS_PER_STATE_SNAPSHOT * 2 < startEpoch):
        # We've either walked two full state snapshot lengths or hit the tail
        # and still can't find a matching state: this can happen when
        # starting the node from an arbitrary finalized checkpoint and not
        # backfilling the states
        notice "Request for pruned historical state",
          request = shortLog(bs), tail = shortLog(dag.tail), cur = shortLog(cur)
        return false

      # Move slot by slot to capture epoch boundary states
      cur = cur.parentOrSlot()

    beacon_state_rewinds.inc()

  # Starting state has been assigned, either from memory or database
  let
    assignTick = Moment.now()
    ancestor {.used.} = state.blck.atSlot(getStateField(state.data, slot))
    ancestorRoot {.used.} = getStateRoot(state.data)

  var info: ForkedEpochInfo
  # Time to replay all the blocks between then and now
  for i in countdown(ancestors.len - 1, 0):
    # Because the ancestors are in the database, there's no need to persist them
    # again. Also, because we're applying blocks that were loaded from the
    # database, we can skip certain checks that have already been performed
    # before adding the block to the database.
    dag.applyBlock(state, ancestors[i], {}, cache, info)

  # ...and make sure to process empty slots as requested
  dag.advanceSlots(state, bs.slot, save, cache, info)

  # ...and make sure to load the state cache, if it exists
  loadStateCache(dag, cache, state.blck, getStateField(state.data, slot).epoch)

  let
    assignDur = assignTick - startTick
    replayDur = Moment.now() - assignTick

  # TODO https://github.com/status-im/nim-chronicles/issues/108
  if (assignDur + replayDur) >= 250.millis:
    # This might indicate there's a cache that's not in order or a disk that is
    # too slow - for now, it's here for investigative purposes and the cutoff
    # time might need tuning
    info "State replayed",
      blocks = ancestors.len,
      slots = getStateField(state.data, slot) - ancestor.slot,
      current = shortLog(current),
      ancestor = shortLog(ancestor),
      target = shortLog(bs),
      ancestorStateRoot = shortLog(ancestorRoot),
      targetStateRoot = shortLog(getStateRoot(state.data)),
      found,
      assignDur,
      replayDur

  elif ancestors.len > 0:
    debug "State replayed",
      blocks = ancestors.len,
      slots = getStateField(state.data, slot) - ancestor.slot,
      current = shortLog(current),
      ancestor = shortLog(ancestor),
      target = shortLog(bs),
      ancestorStateRoot = shortLog(ancestorRoot),
      targetStateRoot = shortLog(getStateRoot(state.data)),
      found,
      assignDur,
      replayDur
  else: # Normal case!
    trace "State advanced",
      blocks = ancestors.len,
      slots = getStateField(state.data, slot) - ancestor.slot,
      current = shortLog(current),
      ancestor = shortLog(ancestor),
      target = shortLog(bs),
      ancestorStateRoot = shortLog(ancestorRoot),
      targetStateRoot = shortLog(getStateRoot(state.data)),
      found,
      assignDur,
      replayDur

  true

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

      if cur.isProposed():
        dag.forkBlocks.excl(KeyedBlockRef.init(cur.blck))
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
      if cur.slot.epoch mod EPOCHS_PER_STATE_SNAPSHOT != 0 and
          cur.slot != dag.tail.slot:
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
  if not updateStateData(
      dag, dag.headState, newHead.atSlot(), false, cache):
    # Advancing the head state should never fail, given that the tail is
    # implicitly finalised, the head is an ancestor of the tail and we always
    # store the tail state in the database, as well as every epoch slot state in
    # between
    fatal "Unable to load head state during head update, database corrupt?",
      lastHead = shortLog(lastHead)
    quit 1

  dag.db.putHeadBlock(newHead.root)

  updateBeaconMetrics(dag.headState, cache)

  withState(dag.headState.data):
    when stateFork >= BeaconStateFork.Altair:
      dag.headSyncCommittees = state.data.get_sync_committee_cache(cache)

  let
    finalized_checkpoint =
      getStateField(dag.headState.data, finalized_checkpoint)
    finalizedSlot = max(finalized_checkpoint.epoch.start_slot(), dag.tail.slot)
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
    quarantine.clearAfterReorg()

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
      let
        currentEpoch = epoch(newHead.slot)
        depBlock = dag.head.dependentBlock(dag.tail, currentEpoch)
        prevDepBlock = dag.head.prevDependentBlock(dag.tail, currentEpoch)
        epochTransition = (finalizedHead != dag.finalizedHead)
      let data = HeadChangeInfoObject.init(dag.head.slot, dag.head.root,
                                           getStateRoot(dag.headState.data),
                                           epochTransition, depBlock.root,
                                           prevDepBlock.root)
      dag.onHeadChanged(data)

  withState(dag.headState.data):
    # Every time the head changes, the "canonical" view of balances and other
    # state-related metrics change - notify the validator monitor.
    # Doing this update during head update ensures there's a reasonable number
    # of such updates happening - at most once per valid block.
    dag.validatorMonitor[].registerState(state.data)

  if finalizedHead != dag.finalizedHead:
    debug "Reached new finalization checkpoint",
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
        if tmp != finalizedHead.blck:
          # The newly finalized block itself should remain in here so that fork
          # choice still can find it via root
          dag.forkBlocks.excl(KeyedBlockRef.init(tmp))

        tmp = tmp.parent

      dag.finalizedHead = finalizedHead

      dag.updateFinalizedBlocks()

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

proc isInitialized*(T: type ChainDAGRef, db: BeaconChainDB): Result[void, cstring] =
  # Lightweight check to see if we have the minimal information needed to
  # load up a database - we don't check head here - if something is wrong with
  # head, it's likely an initialized, but corrupt database - init will detect
  # that
  let
    genesisBlockRoot = db.getGenesisBlock()

  if not genesisBlockRoot.isSome():
    return err("Genesis block root missing")

  let
    genesisBlock = db.getForkedBlock(genesisBlockRoot.get())
  if not genesisBlock.isSome():
    return err("Genesis block missing")

  let
    genesisStateRoot = withBlck(genesisBlock.get()): blck.message.state_root

  if not db.containsState(genesisStateRoot):
    return err("Genesis state missing")

  let
    tailBlockRoot = db.getTailBlock()
  if not tailBlockRoot.isSome():
    return err("Tail block root missing")

  let
    tailBlock = db.getForkedBlock(tailBlockRoot.get())
  if not tailBlock.isSome():
    return err("Tail block missing")

  let
    tailStateRoot = withBlck(tailBlock.get()): blck.message.state_root

  if not db.containsState(tailStateRoot):
    return err("Tail state missing")

  ok()

proc preInit*(
    T: type ChainDAGRef, db: BeaconChainDB,
    genesisState, tailState: ForkedHashedBeaconState,
    tailBlock: ForkedTrustedSignedBeaconBlock) =
  # write a genesis state, the way the ChainDAGRef expects it to be stored in
  # database

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
      db.putBlock(blck)
      db.putState(state)

      db.putGenesisBlock(blck.root)

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
      db.putState(state)

      db.putTailBlock(blck.root)
      db.putHeadBlock(blck.root)

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
    epochRef = block:
      let tmp = dag.getEpochRef(head, slot.epoch(), false)
      if tmp.isErr():
        return none(ValidatorIndex)
      tmp.get()
    slotInEpoch = slot.since_epoch_start()

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
    # - https://github.com/ethereum/consensus-specs/blob/v1.1.9/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
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

proc getBlockSSZ*(dag: ChainDAGRef, id: BlockId, bytes: var seq[byte]): bool =
  # Load the SSZ-encoded data of a block into `bytes`, overwriting the existing
  # content
  # careful: there are two snappy encodings in use, with and without framing!
  # Returns true if the block is found, false if not
  case dag.cfg.blockForkAtEpoch(id.slot.epoch)
  of BeaconBlockFork.Phase0:
    dag.db.getPhase0BlockSSZ(id.root, bytes)
  of BeaconBlockFork.Altair:
    dag.db.getAltairBlockSSZ(id.root, bytes)
  of BeaconBlockFork.Bellatrix:
    dag.db.getMergeBlockSSZ(id.root, bytes)

func needsBackfill*(dag: ChainDAGRef): bool =
  dag.backfill.slot > dag.genesis.slot
