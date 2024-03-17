{.push raises: [].}

import
  std/[sequtils, tables, sets],
  stew/[arrayops, assign2, byteutils],
  results, snappy,
  ../spec/[beaconstate, eth2_merkleization, eth2_ssz_serialization, helpers,
    state_transition, validator],
  ../spec/forks,
  ../spec/datatypes/[phase0, altair, bellatrix, capella],
  ".."/[beacon_chain_db, beacon_clock],
  "."/block_pools_types

from ../spec/datatypes/deneb import shortLog

import chronicles

export
  eth2_merkleization, eth2_ssz_serialization,
  block_pools_types, results, beacon_chain_db

const
  EPOCHS_PER_STATE_SNAPSHOT = 32
    ## When finality happens, we prune historical states from the database except
    ## for a snapshot every 32 epochs from which replays can happen - there's a
    ## balance here between making long replays and saving on disk space
proc putBlock(
    dag: ChainDAGRef, signedBlock: ForkyTrustedSignedBeaconBlock) =
  dag.db.putBlock(signedBlock)

proc updateState(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bsi: BlockSlotId,
    save: bool, cache: var StateCache): bool {.gcsafe.}

func get_effective_balances(
    validators: openArray[Validator], epoch: Epoch): seq[Gwei] =
  result.newSeq(validators.len) # zero-init

  for i in 0 ..< result.len:
    # All non-active validators have a 0 balance
    let validator = unsafeAddr validators[i]
    if validator[].is_active_validator(epoch) and not validator[].slashed:
      result[i] = validator[].effective_balance

proc updateValidatorKeys(dag: ChainDAGRef, validators: openArray[Validator]) =
  dag.db.updateImmutableValidators(validators)

proc updateFinalizedBlocks(db: BeaconChainDB, newFinalized: openArray[BlockId]) =
  if db.db.readOnly: return # TODO abstraction leak - where to put this?

  db.withManyWrites:
    for bid in newFinalized:
      db.finalizedBlocks.insert(bid.slot, bid.root)

func validatorKey*(
    dag: ChainDAGRef, index: ValidatorIndex or uint64): Opt[CookedPubKey] =
  dag.db.immutableValidators.load(index)

template is_merge_transition_complete*(
    stateParam: ForkedHashedBeaconState): bool =
  withState(stateParam):
    when consensusFork >= ConsensusFork.Bellatrix:
      is_merge_transition_complete(forkyState.data)
    else:
      false

func getBlockRef*(dag: ChainDAGRef, root: Eth2Digest): Opt[BlockRef] =
  let key = KeyedBlockRef.asLookupKey(root)
  if key in dag.forkBlocks:
    try: ok(dag.forkBlocks[key].blockRef())
    except KeyError: raiseAssert "contains"
  else:
    err()

func getBlockIdAtSlot(
    state: ForkyHashedBeaconState, slot: Slot): Opt[BlockSlotId] =
  if slot > state.data.slot:
    return Opt.none(BlockSlotId)  # State does not know about requested slot
  if state.data.slot > slot + SLOTS_PER_HISTORICAL_ROOT:
    return Opt.none(BlockSlotId)  # Cache has expired

  var idx = slot mod SLOTS_PER_HISTORICAL_ROOT
  let root =
    if slot == state.data.slot:
      state.latest_block_root
    else:
      state.data.block_roots[idx]
  var bid = BlockId(slot: slot, root: root)

  let availableSlots =
    min(slot.uint64, slot + SLOTS_PER_HISTORICAL_ROOT - state.data.slot)
  for i in 0 ..< availableSlots:
    if idx == 0:
      idx = SLOTS_PER_HISTORICAL_ROOT
    dec idx
    if state.data.block_roots[idx] != root:
      return Opt.some BlockSlotId.init(bid, slot)
    dec bid.slot

  if bid.slot == GENESIS_SLOT:
    return Opt.some BlockSlotId.init(bid, slot)
  Opt.none(BlockSlotId)  # Unknown if there are more empty slots before

func getBlockIdAtSlot(dag: ChainDAGRef, slot: Slot): Opt[BlockSlotId] =
  if slot > dag.finalizedHead.slot:
    return dag.head.atSlot(slot).toBlockSlotId() # iterate to the given slot

  if dag.finalizedHead.blck == nil:
    # Not initialized yet (in init)
    return Opt.none(BlockSlotId)

  if slot >= dag.finalizedHead.blck.slot:
    # finalized head is still in memory
    return dag.finalizedHead.blck.atSlot(slot).toBlockSlotId()

  template tryWithState(state: ForkedHashedBeaconState) =
    block:
      withState(state):
        # State must be a descendent of the finalized chain to be viable
        let finBsi = forkyState.getBlockIdAtSlot(dag.finalizedHead.slot)
        if finBsi.isSome and  # DAG finalized bid slot wrong if CP not @ epoch
            finBsi.unsafeGet.bid.root == dag.finalizedHead.blck.bid.root:
          let bsi = forkyState.getBlockIdAtSlot(slot)
          if bsi.isSome:
            return bsi
  tryWithState dag.headState
  tryWithState dag.epochRefState
  tryWithState dag.clearanceState

  let finlow = dag.db.finalizedBlocks.low.expect("at least tailRef written")
  if slot >= finlow:
    var pos = slot
    while true:
      let root = dag.db.finalizedBlocks.get(pos)

      if root.isSome():
        return ok BlockSlotId.init(
          BlockId(root: root.get(), slot: pos), slot)

      doAssert pos > finlow, "We should have returned the finlow"

      pos = pos - 1

  if slot == GENESIS_SLOT and dag.genesis.isSome():
    return ok dag.genesis.get().atSlot()

  err() # not backfilled yet

proc containsBlock(
    cfg: RuntimeConfig, db: BeaconChainDB, slot: Slot, root: Eth2Digest): bool =
  db.containsBlock(root, cfg.consensusForkAtEpoch(slot.epoch))

proc containsBlock(dag: ChainDAGRef, bid: BlockId): bool =
  dag.cfg.containsBlock(dag.db, bid.slot, bid.root)

proc getForkedBlock(db: BeaconChainDB, root: Eth2Digest):
    Opt[ForkedTrustedSignedBeaconBlock] =
  static: doAssert high(ConsensusFork) == ConsensusFork.Electra
  if (let blck = db.getBlock(root, electra.TrustedSignedBeaconBlock);
      blck.isSome()):
    ok(ForkedTrustedSignedBeaconBlock.init(blck.get()))
  elif (let blck = db.getBlock(root, deneb.TrustedSignedBeaconBlock);
      blck.isSome()):
    ok(ForkedTrustedSignedBeaconBlock.init(blck.get()))
  elif (let blck = db.getBlock(root, capella.TrustedSignedBeaconBlock);
      blck.isSome()):
    ok(ForkedTrustedSignedBeaconBlock.init(blck.get()))
  elif (let blck = db.getBlock(root, bellatrix.TrustedSignedBeaconBlock);
      blck.isSome()):
    ok(ForkedTrustedSignedBeaconBlock.init(blck.get()))
  elif (let blck = db.getBlock(root, altair.TrustedSignedBeaconBlock);
      blck.isSome()):
    ok(ForkedTrustedSignedBeaconBlock.init(blck.get()))
  elif (let blck = db.getBlock(root, phase0.TrustedSignedBeaconBlock);
      blck.isSome()):
    ok(ForkedTrustedSignedBeaconBlock.init(blck.get()))
  else:
    err()

proc getBlock(
    dag: ChainDAGRef, bid: BlockId,
    T: type ForkyTrustedSignedBeaconBlock): Opt[T] =
  dag.db.getBlock(bid.root, T)

proc getForkedBlock(
    dag: ChainDAGRef, bid: BlockId): Opt[ForkedTrustedSignedBeaconBlock] =

  let fork = dag.cfg.consensusForkAtEpoch(bid.slot.epoch)
  result.ok(ForkedTrustedSignedBeaconBlock(kind: fork))
  withBlck(result.get()):
    type T = type(forkyBlck)
    forkyBlck = getBlock(dag, bid, T).valueOr:
      result.err()
      return

proc getBlockId(db: BeaconChainDB, root: Eth2Digest): Opt[BlockId] =
  block: # We might have a summary in the database
    let summary = db.getBeaconBlockSummary(root)
    if summary.isOk():
      return ok(BlockId(root: root, slot: summary.get().slot))

  block:
    # We might have a block without having written a summary - this can happen
    # if there was a crash between writing the block and writing the summary,
    # specially in databases written by older nimbus versions
    let forked = db.getForkedBlock(root)
    if forked.isSome():
      # Shouldn't happen too often but..
      let
        blck = forked.get()
        summary = withBlck(blck): forkyBlck.message.toBeaconBlockSummary()
      db.putBeaconBlockSummary(root, summary)
      return ok(BlockId(root: root, slot: summary.slot))

  err()

proc getBlockId(dag: ChainDAGRef, root: Eth2Digest): Opt[BlockId] =
  block: # If we have a BlockRef, this is the fastest way to get a block id
    let blck = dag.getBlockRef(root)
    if blck.isOk():
      return ok(blck.get().bid)

  dag.db.getBlockId(root)

proc getForkedBlock(
    dag: ChainDAGRef, root: Eth2Digest): Opt[ForkedTrustedSignedBeaconBlock] =
  let bid = dag.getBlockId(root)
  if bid.isSome():
    dag.getForkedBlock(bid.get())
  else:
    # In case we didn't have a summary - should be rare, but ..
    dag.db.getForkedBlock(root)

func parent(dag: ChainDAGRef, bid: BlockId): Opt[BlockId] =
  if bid.slot == 0:
    return err()

  if bid.slot > dag.finalizedHead.slot:
    # Make sure we follow the correct history as there may be forks
    let blck = ? dag.getBlockRef(bid.root)

    doAssert not isNil(blck.parent), "should reach finalized head"
    return ok blck.parent.bid

  let bids = ? dag.getBlockIdAtSlot(bid.slot - 1)
  ok(bids.bid)

func parentOrSlot(dag: ChainDAGRef, bsi: BlockSlotId): Opt[BlockSlotId] =
  if bsi.slot == 0:
    return err()

  if bsi.isProposed:
    let parent = ? dag.parent(bsi.bid)
    ok BlockSlotId.init(parent, bsi.slot)
  else:
    ok BlockSlotId.init(bsi.bid, bsi.slot - 1)

func atSlot(dag: ChainDAGRef, bid: BlockId, slot: Slot): Opt[BlockSlotId] =
  if bid.slot > dag.finalizedHead.slot:
    let blck = ? dag.getBlockRef(bid.root)

    if slot > dag.finalizedHead.slot:
      return blck.atSlot(slot).toBlockSlotId()
  else:
    # Check if the given `bid` is still part of history - it might hail from an
    # orphaned fork
    let existing = ? dag.getBlockIdAtSlot(bid.slot)
    if existing.bid != bid:
      return err() # Not part of known / relevant history

    if existing.slot == slot: # and bid.slot == slot
      return ok existing

  if bid.slot <= slot:
    ok BlockSlotId.init(bid, slot)
  else:
    dag.getBlockIdAtSlot(slot)

func nextTimestamp[I, T](cache: var LRUCache[I, T]): uint32 =
  if cache.timestamp == uint32.high:
    for i in 0 ..< I:
      template e: untyped = cache.entries[i]
      if e.lastUsed != 0:
        e.lastUsed = 1
    cache.timestamp = 1
  inc cache.timestamp
  cache.timestamp

template peekIt[I, T](cache: var LRUCache[I, T], predicate: untyped): Opt[T] =
  block:
    var res: Opt[T]
    for i in 0 ..< I:
      template e: untyped = cache.entries[i]
      template it: untyped {.inject, used.} = e.value
      if e.lastUsed != 0 and predicate:
        res.ok it
        break
    res

template findIt[I, T](cache: var LRUCache[I, T], predicate: untyped): Opt[T] =
  block:
    var res: Opt[T]
    for i in 0 ..< I:
      template e: untyped = cache.entries[i]
      template it: untyped {.inject, used.} = e.value
      if e.lastUsed != 0 and predicate:
        e.lastUsed = cache.nextTimestamp
        res.ok it
        break
    res

func put[I, T](cache: var LRUCache[I, T], value: T) =
  var lru = 0
  block:
    var min = uint32.high
    for i in 0 ..< I:
      template e: untyped = cache.entries[i]
      if e.lastUsed < min:
        min = e.lastUsed
        lru = i
        if min == 0:
          break

  template e: untyped = cache.entries[lru]
  e.value = value
  e.lastUsed = cache.nextTimestamp

func epochAncestor(dag: ChainDAGRef, bid: BlockId, epoch: Epoch):
    Opt[BlockSlotId] =
  if epoch < dag.tail.slot.epoch or bid.slot < dag.tail.slot:
    # Not enough information in database to meaningfully process pre-tail epochs
    return Opt.none BlockSlotId

  let
    dependentSlot =
      if epoch == dag.tail.slot.epoch:
        # Use the tail as "dependent block" - this may be the genesis block, or,
        dag.tail.slot
      else:
        epoch.start_slot() - 1
    bsi = ? dag.atSlot(bid, dependentSlot)
    epochSlot =
      if epoch == dag.tail.slot.epoch:
        dag.tail.slot
      else:
        epoch.start_slot()
  ok BlockSlotId(bid: bsi.bid, slot: epochSlot)

func epochKey(dag: ChainDAGRef, bid: BlockId, epoch: Epoch): Opt[EpochKey] =
  let bsi = dag.epochAncestor(bid, epoch).valueOr:
    return Opt.none(EpochKey)

  Opt.some(EpochKey(bid: bsi.bid, epoch: epoch))

func putShufflingRef(dag: ChainDAGRef, shufflingRef: ShufflingRef) =
  if shufflingRef.epoch < dag.finalizedHead.slot.epoch():
    # Only cache epoch information for unfinalized blocks - earlier states
    # are seldomly used (ie RPC), so no need to cache
    return

  dag.shufflingRefs.put shufflingRef

func findShufflingRef(
    dag: ChainDAGRef, bid: BlockId, epoch: Epoch): Opt[ShufflingRef] =
  let
    dependent_slot = epoch.attester_dependent_slot()
    dependent_bsi = ? dag.atSlot(bid, dependent_slot)

  let shufflingRef = dag.shufflingRefs.findIt(
    it.epoch == epoch and it.attester_dependent_root == dependent_bsi.bid.root)
  if shufflingRef.isOk:
    return shufflingRef

  let epochRef = dag.epochRefs.peekIt(
    it.shufflingRef.epoch == epoch and
    it.shufflingRef.attester_dependent_root == dependent_bsi.bid.root)
  if epochRef.isOk:
    dag.putShufflingRef(epochRef.get.shufflingRef)
    return ok epochRef.get.shufflingRef

  err()

func findEpochRef(
    dag: ChainDAGRef, bid: BlockId, epoch: Epoch): Opt[EpochRef] =
  let key = ? dag.epochKey(bid, epoch)

  dag.epochRefs.findIt(it.key == key)

func putEpochRef(dag: ChainDAGRef, epochRef: EpochRef) =
  if epochRef.epoch < dag.finalizedHead.slot.epoch():
    # Only cache epoch information for unfinalized blocks - earlier states
    # are seldomly used (ie RPC), so no need to cache
    return

  dag.epochRefs.put epochRef

func init(
    T: type ShufflingRef, state: ForkedHashedBeaconState,
    cache: var StateCache, epoch: Epoch): T =
  let attester_dependent_root =
    withState(state): forkyState.dependent_root(epoch.get_previous_epoch)

  ShufflingRef(
    epoch: epoch,
    attester_dependent_root: attester_dependent_root,
    shuffled_active_validator_indices:
      cache.get_shuffled_active_validator_indices(state, epoch),
  )

func init(
    T: type EpochRef, dag: ChainDAGRef, state: ForkedHashedBeaconState,
    cache: var StateCache): T =
  let
    epoch = state.get_current_epoch()
    proposer_dependent_root = withState(state):
      forkyState.proposer_dependent_root
    shufflingRef = dag.findShufflingRef(state.latest_block_id, epoch).valueOr:
      let tmp = ShufflingRef.init(state, cache, epoch)
      dag.putShufflingRef(tmp)
      tmp

    total_active_balance = withState(state):
      get_total_active_balance(forkyState.data, cache)
    epochRef = EpochRef(
      key: dag.epochKey(state.latest_block_id, epoch).expect(
        "Valid epoch ancestor when processing state"),

      eth1_data:
        getStateField(state, eth1_data),
      eth1_deposit_index:
        getStateField(state, eth1_deposit_index),

      checkpoints:
        FinalityCheckpoints(
          justified: getStateField(state, current_justified_checkpoint),
          finalized: getStateField(state, finalized_checkpoint)),

      # beacon_proposers: Separately filled below
      proposer_dependent_root: proposer_dependent_root,

      shufflingRef: shufflingRef,
      total_active_balance: total_active_balance
    )
    epochStart = epoch.start_slot()

  for i in 0'u64..<SLOTS_PER_EPOCH:
    epochRef.beacon_proposers[i] =
      get_beacon_proposer_index(state, cache, epochStart + i)

  func snappyEncode(inp: openArray[byte]): seq[byte] =
    try:
      snappy.encode(inp)
    except CatchableError as err:
      raiseAssert err.msg

  epochRef.effective_balances_bytes =
    snappyEncode(SSZ.encode(
      List[Gwei, Limit VALIDATOR_REGISTRY_LIMIT](
        get_effective_balances(getStateField(state, validators).asSeq, epoch))))

  epochRef

func loadStateCache(
    dag: ChainDAGRef, cache: var StateCache, bid: BlockId, epoch: Epoch) =

  template load(e: Epoch) =
    block:
      let epoch = e
      if epoch notin cache.shuffled_active_validator_indices:
        let shufflingRef = dag.findShufflingRef(bid, epoch)
        if shufflingRef.isSome():
          cache.shuffled_active_validator_indices[epoch] =
            shufflingRef[][].shuffled_active_validator_indices
        let epochRef = dag.findEpochRef(bid, epoch)
        if epochRef.isSome():
          let start_slot = epoch.start_slot()
          for i, idx in epochRef[][].beacon_proposers:
            cache.beacon_proposer_indices[start_slot + i] = idx
          cache.total_active_balance[epoch] = epochRef[][].total_active_balance

  load(epoch)

  if epoch > 0:
    load(epoch - 1)

func isStateCheckpoint(dag: ChainDAGRef, bsi: BlockSlotId): bool = false

proc getState(
    db: BeaconChainDB, cfg: RuntimeConfig, block_root: Eth2Digest, slot: Slot,
    state: var ForkedHashedBeaconState, rollback: RollbackProc): bool =
  let state_root = db.getStateRoot(block_root, slot).valueOr:
    return false

  db.getState(cfg.consensusForkAtEpoch(slot.epoch), state_root, state, rollback)

proc getState(
    db: BeaconChainDB, cfg: RuntimeConfig, block_root: Eth2Digest,
    slots: Slice[Slot], state: var ForkedHashedBeaconState,
    rollback: RollbackProc): bool =
  var slot = slots.b
  while slot >= slots.a:
    let state_root = db.getStateRoot(block_root, slot)
    if state_root.isSome() and
        db.getState(
          cfg.consensusForkAtEpoch(slot.epoch), state_root.get(), state,
          rollback):
      return true

    if slot == slots.a: # avoid underflow at genesis
      break
    slot -= 1
  false

proc getState(
    dag: ChainDAGRef, bsi: BlockSlotId, state: var ForkedHashedBeaconState): bool =
  if not dag.isStateCheckpoint(bsi):
    return false

  let rollbackAddr =
    # Any restore point will do as long as it's not the object being updated
    if unsafeAddr(state) == unsafeAddr(dag.headState):
      unsafeAddr dag.clearanceState
    else:
      unsafeAddr dag.headState

  let v = addr state
  func rollback() =
    assign(v[], rollbackAddr[])

  dag.db.getState(dag.cfg, bsi.bid.root, bsi.slot, state, rollback)

proc getStateByParent(
    dag: ChainDAGRef, bid: BlockId, state: var ForkedHashedBeaconState): bool =
  let slot = bid.slot

  let
    summary = dag.db.getBeaconBlockSummary(bid.root).valueOr:
      return false
    parentMinSlot =
      dag.db.getBeaconBlockSummary(summary.parent_root).
        map(proc(x: auto): auto = x.slot).valueOr:
      # in the cases that we don't have slot information, we'll search for the
      # state for a few back from the `bid` slot - if there are gaps of empty
      # slots larger than this, we will not be able to load the state using this
      # trick
      if slot.uint64 >= (EPOCHS_PER_STATE_SNAPSHOT * 2) * SLOTS_PER_EPOCH:
        slot - (EPOCHS_PER_STATE_SNAPSHOT * 2) * SLOTS_PER_EPOCH
      else:
        Slot(0)

  let rollbackAddr =
    # Any restore point will do as long as it's not the object being updated
    if unsafeAddr(state) == unsafeAddr(dag.headState):
      unsafeAddr dag.clearanceState
    else:
      unsafeAddr dag.headState

  let v = addr state
  func rollback() =
    assign(v[], rollbackAddr[])

  dag.db.getState(
    dag.cfg, summary.parent_root, parentMinSlot..slot, state, rollback)

proc getBlockIdAtSlot(
    dag: ChainDAGRef, state: ForkyHashedBeaconState, slot: Slot): Opt[BlockId] =
  if slot >= state.data.slot:
    Opt.some state.latest_block_id
  elif state.data.slot <= slot + SLOTS_PER_HISTORICAL_ROOT:
    dag.getBlockId(state.data.get_block_root_at_slot(slot))
  else:
    Opt.none(BlockId)

proc putState(dag: ChainDAGRef, state: ForkedHashedBeaconState, bid: BlockId) =
  let slot = getStateField(state, slot)
  if not dag.isStateCheckpoint(BlockSlotId.init(bid, slot)):
    return

  if dag.db.containsState(
      dag.cfg.consensusForkAtEpoch(slot.epoch), getStateRoot(state),
      legacy = false):
    return

  withState(state):
    dag.db.putState(forkyState)

proc advanceSlots*(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, slot: Slot, save: bool,
    cache: var StateCache, info: var ForkedEpochInfo) =
  doAssert getStateField(state, slot) <= slot

  let stateBid = state.latest_block_id
  while getStateField(state, slot) < slot:
    let
      preEpoch = getStateField(state, slot).epoch

    loadStateCache(dag, cache, stateBid, getStateField(state, slot).epoch)

    process_slots(
      dag.cfg, state, getStateField(state, slot) + 1, cache, info, {}).expect("process_slots shouldn't fail when state slot is correct")
    if save:
      dag.putState(state, stateBid)

      # The reward information in the state transition is computed for epoch
      # transitions - when transitioning into epoch N, the activities in epoch
      # N-2 are translated into balance updates, and this is what we capture
      # in the monitor. This may be inaccurate during a deep reorg (>1 epoch)
      # which is an acceptable tradeoff for monitoring.
      withState(state):
        let postEpoch = forkyState.data.slot.epoch
        if preEpoch != postEpoch and postEpoch >= 2:
          var proposers: array[SLOTS_PER_EPOCH, Opt[ValidatorIndex]]
          let epochRef = dag.findEpochRef(stateBid, postEpoch - 2)
          if epochRef.isSome():
            proposers = epochRef[][].beacon_proposers

proc applyBlock(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bid: BlockId,
    cache: var StateCache, info: var ForkedEpochInfo): Result[void, cstring] =

  loadStateCache(dag, cache, bid, getStateField(state, slot).epoch)

  case dag.cfg.consensusForkAtEpoch(bid.slot.epoch)
  of ConsensusFork.Phase0:
    let data = getBlock(dag, bid, phase0.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info, {slotProcessed}, noRollback)
  of ConsensusFork.Altair:
    let data = getBlock(dag, bid, altair.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info, {slotProcessed}, noRollback)
  of ConsensusFork.Bellatrix:
    let data = getBlock(dag, bid, bellatrix.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info, {slotProcessed}, noRollback)
  of ConsensusFork.Capella:
    let data = getBlock(dag, bid, capella.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info, {slotProcessed}, noRollback)
  of ConsensusFork.Deneb:
    let data = getBlock(dag, bid, deneb.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info, {slotProcessed}, noRollback)
  of ConsensusFork.Electra:
    let data = getBlock(dag, bid, electra.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info, {slotProcessed}, noRollback)

proc init*(T: type ChainDAGRef, cfg: RuntimeConfig, db: BeaconChainDB,
           updateFlags: UpdateFlags,
           eraPath = "."): ChainDAGRef =
  cfg.checkForkConsistency()

  doAssert updateFlags - {strictVerification} == {},
    "Other flags not supported in ChainDAG"


  let
    startTick = Moment.now()
    genesisRoot = db.getGenesisBlock()
    tailRoot = db.getTailBlock().expect(
      "preInit should have initialized the database with a tail block root")
    tail = db.getBlockId(tailRoot).expect(
      "tail block summary in database, database corrupt?")
    headRoot = db.getHeadBlock().expect("head root, database corrupt?")
    head = db.getBlockId(headRoot).expect("head block id, database corrupt?")

    # Have to be careful with this instance, it is not yet fully initialized so
    # as to avoid having to allocate a separate "init" state
    dag = ChainDAGRef(
      db: db,
      genesis: genesisRoot.map(
        proc(x: auto): auto = BlockId(root: x, slot: GENESIS_SLOT)),
      tail: tail,
      cfg: cfg,
    )
    loadTick = Moment.now()

  var
    headRef, curRef: BlockRef

    # When starting from a checkpoint with an empty block, we'll store the state
    # "ahead" of the head slot - this slot would be considered finalized
    slot = max(head.slot, (tail.slot.epoch + 1).start_slot)
    # To know the finalized checkpoint of the head, we need to recreate its
    # state - the tail is implicitly finalized, and if we have a finalized block
    # table, that provides another hint
    finalizedSlot = db.finalizedBlocks.high.get(tail.slot)
    cache: StateCache
    foundHeadState = false
    headBlocks: seq[BlockRef]

  for blck in db.getAncestorSummaries(head.root):
    # The execution block root gets filled in as needed. Nonfinalized Bellatrix
    # and later blocks are loaded as optimistic, which gets adjusted that first
    # `VALID` fcU from an EL plus markBlockVerified. Pre-merge blocks still get
    # marked as `VALID`.
    let newRef = BlockRef.init(
      blck.root, Opt.none Eth2Digest, executionValid = false,
      blck.summary.slot)
    if headRef == nil:
      headRef = newRef

    if curRef != nil:
      link(newRef, curRef)

    curRef = newRef

    dag.forkBlocks.incl(KeyedBlockRef.init(curRef))

    if not foundHeadState:
      foundHeadState = db.getState(
        cfg, blck.root, blck.summary.slot..slot, dag.headState, noRollback)
      slot = blck.summary.slot

      if not foundHeadState:
        # When the database has been written with a pre-fork version of the
        # software, it may happen that blocks produced using an "unforked"
        # chain get written to the database - we need to skip such blocks
        # when loading the database with a fork-compatible version
        if containsBlock(cfg, db, curRef.slot, curRef.root):
          headBlocks.add curRef
        else:
          if headBlocks.len > 0:
            quit 1
          # Without the block data we can't form a state for this root, so
          # we'll need to move the head back
          headRef = nil
          dag.forkBlocks.excl(KeyedBlockRef.init(curRef))

    if curRef.slot <= finalizedSlot:
      # Only non-finalized slots get a `BlockRef`
      break

  let summariesTick = Moment.now()

  if not foundHeadState:
    if not dag.getStateByParent(curRef.bid, dag.headState):
      quit 1

  block:
    # EpochRef needs an epoch boundary state
    assign(dag.epochRefState, dag.headState)

    var info: ForkedEpochInfo

    while headBlocks.len > 0:
      dag.applyBlock(
        dag.headState, headBlocks.pop().bid, cache,
        info).expect("head blocks should apply")

    dag.head = headRef
    dag.heads = @[headRef]

    assign(dag.clearanceState, dag.headState)

    if dag.headState.latest_block_root == tail.root:
      # In case we started from a checkpoint with an empty slot
      finalizedSlot = getStateField(dag.headState, slot)

    finalizedSlot =
      max(
        finalizedSlot,
        getStateField(dag.headState, finalized_checkpoint).epoch.start_slot)

  let
    configFork = case dag.headState.kind
      of ConsensusFork.Phase0:    genesisFork(cfg)
      of ConsensusFork.Altair:    altairFork(cfg)
      of ConsensusFork.Bellatrix: bellatrixFork(cfg)
      of ConsensusFork.Capella:   capellaFork(cfg)
      of ConsensusFork.Deneb:     denebFork(cfg)
      of ConsensusFork.Electra:   electraFork(cfg)
    stateFork = getStateField(dag.headState, fork)

  if stateFork.current_version != configFork.current_version:
    quit 1

  dag.finalizedHead = headRef.atSlot(finalizedSlot)
  doAssert dag.finalizedHead.blck != nil,
    "The finalized head should exist at the slot"

  block: # Top up finalized blocks
    if db.finalizedBlocks.high.isNone or
        db.finalizedBlocks.high.get() < dag.finalizedHead.blck.slot:
      var
        newFinalized: seq[BlockId]
        tmp = dag.finalizedHead.blck
      while tmp.parent != nil:
        newFinalized.add(tmp.bid)
        let p = tmp.parent
        tmp.parent = nil
        tmp = p

      for blck in db.getAncestorSummaries(tmp.root):
        if db.finalizedBlocks.high.isSome and
            blck.summary.slot <= db.finalizedBlocks.high.get:
          break

        newFinalized.add(BlockId(slot: blck.summary.slot, root: blck.root))

      db.updateFinalizedBlocks(newFinalized)

  doAssert dag.finalizedHead.blck.parent == nil,
    "The finalized head is the last BlockRef with a parent"

  block:
    let finalized = db.finalizedBlocks.get(db.finalizedBlocks.high.get()).expect(
      "tail at least")
    if finalized != dag.finalizedHead.blck.root:
      quit 1

  dag.forkDigests = newClone ForkDigests.init(
    cfg, getStateField(dag.headState, genesis_validators_root))

  dag.updateValidatorKeys(getStateField(dag.headState, validators).asSeq())

  dag

func getEpochRef(
    dag: ChainDAGRef, state: ForkedHashedBeaconState, cache: var StateCache): EpochRef =
  let
    bid = state.latest_block_id
    epoch = state.get_current_epoch()

  dag.findEpochRef(bid, epoch).valueOr:
    let res = EpochRef.init(dag, state, cache)
    dag.putEpochRef(res)
    res

proc getEpochRef(
    dag: ChainDAGRef, bid: BlockId, epoch: Epoch,
    preFinalized: bool): Result[EpochRef, cstring] =
  if not preFinalized and epoch < dag.finalizedHead.slot.epoch:
    return err("Requesting pre-finalized EpochRef")

  if bid.slot < dag.tail.slot or epoch < dag.tail.slot.epoch:
    return err("Requesting EpochRef for pruned state")

  let epochRef = dag.findEpochRef(bid, epoch)
  if epochRef.isOk():
    return ok epochRef.get()

  let
    ancestor = dag.epochAncestor(bid, epoch).valueOr:
      # If we got in here, the bid must be unknown or we would have gotten
      # _some_ ancestor (like the tail)
      return err("Requesting EpochRef for non-canonical block")

  var cache: StateCache
  if not updateState(dag, dag.epochRefState, ancestor, false, cache):
    return err("Could not load requested state")

  ok(dag.getEpochRef(dag.epochRefState, cache))

proc ancestorSlot(
    dag: ChainDAGRef, state: ForkyHashedBeaconState, bid: BlockId,
    lowSlot: Slot): Opt[Slot] =
  if state.data.slot < lowSlot or bid.slot < lowSlot:
    return Opt.none(Slot)

  var stateBid = ? dag.getBlockIdAtSlot(state, bid.slot)
  if stateBid.slot < lowSlot:
    return Opt.none(Slot)

  var blockBid = (? dag.atSlot(bid, stateBid.slot)).bid
  if blockBid.slot < lowSlot:
    return Opt.none(Slot)

  while stateBid != blockBid:
    if stateBid.slot >= blockBid.slot:
      stateBid = ? dag.getBlockIdAtSlot(
        state, min(blockBid.slot, stateBid.slot - 1))
      if stateBid.slot < lowSlot:
        return Opt.none(Slot)
    else:
      blockBid = ? dag.parent(blockBid)
      if blockBid.slot < lowSlot:
        return Opt.none(Slot)

  Opt.some stateBid.slot

proc computeRandaoMix(
    bdata: ForkedTrustedSignedBeaconBlock): Opt[Eth2Digest] =
  withBlck(bdata):
    when consensusFork >= ConsensusFork.Bellatrix:
      if forkyBlck.message.is_execution_block:
        var mix = eth2digest(forkyBlck.message.body.randao_reveal.toRaw())
        mix.data.mxor forkyBlck.message.body.execution_payload.prev_randao.data
        return ok mix
  Opt.none(Eth2Digest)

proc computeRandaoMix(
    dag: ChainDAGRef, state: ForkyHashedBeaconState, bid: BlockId,
    lowSlot: Slot): Opt[Eth2Digest] =
  let ancestorSlot = ? dag.ancestorSlot(state, bid, lowSlot)
  doAssert ancestorSlot <= state.data.slot
  doAssert ancestorSlot <= bid.slot

  let
    bdata = ? dag.getForkedBlock(bid)
    fullMix = computeRandaoMix(bdata)
  if fullMix.isSome:
    return fullMix

  var mix {.noinit.}: Eth2Digest
  proc mixToAncestor(highBid: BlockId): Opt[void] =
    ## Mix in/out RANDAO reveals back to `ancestorSlot`
    var bid = highBid
    while bid.slot > ancestorSlot:
      let bdata = ? dag.getForkedBlock(bid)
      withBlck(bdata):  # See `process_randao` / `process_randao_mixes_reset`
        mix.data.mxor eth2digest(
          forkyBlck.message.body.randao_reveal.toRaw()).data
      bid = ? dag.parent(bid)
    ok()

  if ancestorSlot < bid.slot:
    withBlck(bdata):
      mix = eth2digest(forkyBlck.message.body.randao_reveal.toRaw())
    ? mixToAncestor(? dag.parent(bid))
  else:
    mix.reset()

  let ancestorEpoch = ancestorSlot.epoch
  if ancestorEpoch + EPOCHS_PER_HISTORICAL_VECTOR <= state.data.slot.epoch:
    return Opt.none(Eth2Digest)
  let mixRoot = state.dependent_root(ancestorEpoch + 1)
  if mixRoot.isZero:
    return Opt.none(Eth2Digest)
  ? mixToAncestor(? dag.getBlockId(mixRoot))
  mix.data.mxor state.data.get_randao_mix(ancestorEpoch).data

  ok mix

proc updateState(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bsi: BlockSlotId,
    save: bool, cache: var StateCache): bool =


  let
    current {.used.} = withState(state):
      BlockSlotId.init(forkyState.latest_block_id, forkyState.data.slot)

  var
    ancestors: seq[BlockId]
    found = false

  template exactMatch(state: ForkedHashedBeaconState, bsi: BlockSlotId): bool =
    # The block is the same and we're at an early enough slot - the state can
    # be used to arrive at the desired blockslot
    state.matches_block_slot(bsi.bid.root, bsi.slot)

  template canAdvance(state: ForkedHashedBeaconState, bsi: BlockSlotId): bool =
    # The block is the same and we're at an early enough slot - the state can
    # be used to arrive at the desired blockslot
    state.can_advance_slots(bsi.bid.root, bsi.slot)

  if exactMatch(state, bsi):
    found = true
  elif not save:
    # When required to save states, we cannot rely on the caches because that
    # would skip the extra processing that save does - not all information that
    # goes into the database is cached
    if exactMatch(dag.headState, bsi):
      assign(state, dag.headState)
      found = true
    elif exactMatch(dag.clearanceState, bsi):
      assign(state, dag.clearanceState)
      found = true
    elif exactMatch(dag.epochRefState, bsi):
      assign(state, dag.epochRefState)
      found = true

  const RewindBlockThreshold = 64

  if not found:
    # No exact match found - see if any in-memory state can be used as a base
    # onto which we can apply a few blocks - there's a tradeoff here between
    # loading the state from disk and performing the block applications
    var cur = bsi
    while ancestors.len < RewindBlockThreshold:
      if isZero(cur.bid.root): # tail reached
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
        ancestors.add(cur.bid)

      # Move slot by slot to capture epoch boundary states
      cur = dag.parentOrSlot(cur).valueOr:
        break

  if not found:
    var cur = bsi
    ancestors.setLen(0)

    # Look for a state in the database and load it - as long as it cannot be
    # found, keep track of the blocks that are needed to reach it from the
    # state that eventually will be found.
    # If we hit the tail, it means that we've reached a point for which we can
    # no longer recreate history - this happens for example when starting from
    # a checkpoint block
    let startEpoch = bsi.slot.epoch
    while not canAdvance(state, cur) and
        not dag.db.getState(dag.cfg, cur.bid.root, cur.slot, state, noRollback):
      # There's no state saved for this particular BlockSlot combination, and
      # the state we have can't trivially be advanced (in case it was older than
      # RewindBlockThreshold), keep looking..
      if cur.isProposed():
        # This is not an empty slot, so the block will need to be applied to
        # eventually reach bs
        ancestors.add(cur.bid)

      if cur.slot == GENESIS_SLOT or
          (cur.slot.epoch +  uint64(EPOCHS_PER_STATE_SNAPSHOT) * 2 < startEpoch):
        return false

      # Move slot by slot to capture epoch boundary states
      cur = dag.parentOrSlot(cur).valueOr:
        if not dag.getStateByParent(cur.bid, state):
          return false
        break

  let
    ancestor {.used.} = withState(state):
      BlockSlotId.init(forkyState.latest_block_id, forkyState.data.slot)
    ancestorRoot {.used.} = getStateRoot(state)

  var info: ForkedEpochInfo
  for i in countdown(ancestors.len - 1, 0):
    # Because the ancestors are in the database, there's no need to persist them
    # again. Also, because we're applying blocks that were loaded from the
    # database, we can skip certain checks that have already been performed
    # before adding the block to the database.
    if (let res = dag.applyBlock(state, ancestors[i], cache, info); res.isErr):
      return false

  dag.advanceSlots(state, bsi.slot, save, cache, info)

  loadStateCache(dag, cache, bsi.bid, getStateField(state, slot).epoch)

  true

proc isInitialized*(T: type ChainDAGRef, db: BeaconChainDB): Result[void, cstring] =
  let
    tailBlockRoot = db.getTailBlock()
  if not tailBlockRoot.isSome():
    return err("Tail block root missing")

  let
    tailBlock = db.getBlockId(tailBlockRoot.get())
  if not tailBlock.isSome():
    return err("Tail block information missing")

  ok()

proc preInit*(
    T: type ChainDAGRef, db: BeaconChainDB, state: ForkedHashedBeaconState) =
  doAssert getStateField(state, slot).is_epoch,
    "Can only initialize database from epoch states"

  withState(state):
    db.putState(forkyState)

    if forkyState.data.slot == GENESIS_SLOT:
      let blck = get_initial_beacon_block(forkyState)
      db.putBlock(blck)
      db.putGenesisBlock(blck.root)
      db.putHeadBlock(blck.root)
      db.putTailBlock(blck.root)
    else:
      let blockRoot = forkyState.latest_block_root()
      # We write a summary but not the block contents - these will have to be
      # backfilled from the network
      db.putBeaconBlockSummary(blockRoot, BeaconBlockSummary(
        slot: forkyState.data.latest_block_header.slot,
        parent_root: forkyState.data.latest_block_header.parent_root
      ))
      db.putHeadBlock(blockRoot)
      db.putTailBlock(blockRoot)

      discard db.getGenesisBlock().isSome()

proc getProposer*(
    dag: ChainDAGRef, head: BlockRef, slot: Slot): Opt[ValidatorIndex] =
  let
    epochRef = dag.getEpochRef(head.bid, slot.epoch(), false).valueOr:
      return Opt.none(ValidatorIndex)

    slotInEpoch = slot.since_epoch_start()

  let proposer = epochRef.beacon_proposers[slotInEpoch]
  if proposer.isSome():
    if proposer.get().uint64 >= dag.db.immutableValidators.lenu64():
      return Opt.none(ValidatorIndex)

  proposer

proc getProposalState*(
    dag: ChainDAGRef, head: BlockRef, slot: Slot, cache: var StateCache):
    Result[ref ForkedHashedBeaconState, cstring] =

  let state = assignClone(dag.clearanceState)

  var
    info = ForkedEpochInfo()
  doAssert state[].can_advance_slots(head.root, slot)
  loadStateCache(dag, cache, head.bid, slot.epoch)

  if getStateField(state[], slot) < slot:
    process_slots(
      dag.cfg, state[], slot, cache, info,
      {skipLastStateRootCalculation}).expect("advancing 1 slot should not fail")

  ok state
