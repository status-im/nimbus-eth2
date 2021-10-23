# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[algorithm, options, sequtils, tables, sets],
  stew/[assign2, byteutils, results],
  metrics, snappy, chronicles,
  ../spec/[beaconstate, eth2_merkleization, eth2_ssz_serialization, helpers,
    state_transition, validator],
  ../spec/datatypes/[phase0, altair, bellatrix],
  ".."/[beacon_chain_db, era_db],
  "."/[block_pools_types, block_quarantine]

export
  eth2_merkleization, eth2_ssz_serialization,
  block_pools_types, results, beacon_chain_db

# https://github.com/ethereum/beacon-metrics/blob/master/metrics.md#interop-metrics
declareGauge beacon_head_root, "Root of the head block of the beacon chain"
declareGauge beacon_head_slot, "Slot of the head block of the beacon chain"

# https://github.com/ethereum/beacon-metrics/blob/master/metrics.md#interop-metrics
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

proc updateState*(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bsi: BlockSlotId,
    save: bool, cache: var StateCache): bool {.gcsafe.}

template withUpdatedState*(
    dag: ChainDAGRef, stateParam: var ForkedHashedBeaconState,
    bsiParam: BlockSlotId, okBody: untyped, failureBody: untyped): untyped =
  ## Helper template that updates stateData to a particular BlockSlot - usage of
  ## stateData is unsafe outside of block, or across `await` boundaries

  block:
    let bsi {.inject.} = bsiParam
    var cache {.inject.} = StateCache()
    if updateState(dag, stateParam, bsi, false, cache):
      template bid(): BlockId {.inject, used.} = bsi.bid
      template state(): ForkedHashedBeaconState {.inject, used.} = stateParam
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

proc updateFinalizedBlocks*(db: BeaconChainDB, newFinalized: openArray[BlockId]) =
  if db.db.readOnly: return # TODO abstraction leak - where to put this?

  db.withManyWrites:
    for bid in newFinalized:
      db.finalizedBlocks.insert(bid.slot, bid.root)

proc updateFrontfillBlocks*(dag: ChainDAGRef) =
  # When backfilling is done and manages to reach the frontfill point, we can
  # write the frontfill index knowing that the block information in the
  # era files match the chain
  if dag.db.db.readOnly: return # TODO abstraction leak - where to put this?

  if dag.frontfillBlocks.len == 0 or dag.backfill.slot > 0:
    return

  info "Writing frontfill index", slots = dag.frontfillBlocks.len

  dag.db.withManyWrites:
    let low = dag.db.finalizedBlocks.low.expect(
      "wrote at least tailRef during init")
    let blocks = min(low.int, dag.frontfillBlocks.len - 1)
    var parent: Eth2Digest
    for i in 0..blocks:
      let root = dag.frontfillBlocks[i]
      if not isZero(root):
        dag.db.finalizedBlocks.insert(Slot(i), root)
        dag.db.putBeaconBlockSummary(
          root, BeaconBlockSummary(slot: Slot(i), parent_root: parent))
        parent = root

    reset(dag.frontfillBlocks)

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

template is_merge_transition_complete(
    stateParam: ForkedHashedBeaconState): bool =
  withState(stateParam):
    when stateFork >= BeaconStateFork.Bellatrix:
      is_merge_transition_complete(state.data)
    else:
      false

func init*(
    T: type EpochRef, dag: ChainDAGRef, state: ForkedHashedBeaconState,
    cache: var StateCache): T =
  let
    epoch = state.get_current_epoch()
    proposer_dependent_root = withState(state): state.proposer_dependent_root
    attester_dependent_root = withState(state): state.attester_dependent_root
    epochRef = EpochRef(
      dag: dag, # This gives access to the validator pubkeys through an EpochRef
      key: dag.epochAncestor(state.latest_block_id, epoch),

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

      shuffled_active_validator_indices:
        cache.get_shuffled_active_validator_indices(state, epoch),
      attester_dependent_root: attester_dependent_root,

      merge_transition_complete: state.is_merge_transition_complete()
    )
    epochStart = epoch.start_slot()

  for i in 0'u64..<SLOTS_PER_EPOCH:
    epochRef.beacon_proposers[i] =
      get_beacon_proposer_index(state, cache, epochStart + i)

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
      List[Gwei, Limit VALIDATOR_REGISTRY_LIMIT](
        get_effective_balances(getStateField(state, validators).asSeq, epoch))))

  epochRef

func effective_balances*(epochRef: EpochRef): seq[Gwei] =
  try:
    SSZ.decode(snappy.decode(epochRef.effective_balances_bytes, uint32.high),
      List[Gwei, Limit VALIDATOR_REGISTRY_LIMIT]).toSeq()
  except CatchableError as exc:
    raiseAssert exc.msg

func getBlockRef*(dag: ChainDAGRef, root: Eth2Digest): Opt[BlockRef] =
  ## Retrieve a resolved block reference, if available - this function does
  ## not return historical finalized blocks, see `getBlockIdAtSlot` for a
  ## function that covers the entire known history
  let key = KeyedBlockRef.asLookupKey(root)
  # HashSet lacks the api to do check-and-get in one lookup - `[]` will return
  # the copy of the instance in the set which has more fields than `root` set!
  if key in dag.forkBlocks:
    try: ok(dag.forkBlocks[key].blockRef())
    except KeyError: raiseAssert "contains"
  else:
    err()

func getBlockIdAtSlot*(dag: ChainDAGRef, slot: Slot): Opt[BlockSlotId] =
  ## Retrieve the canonical block at the given slot, or the last block that
  ## comes before - similar to atSlot, but without the linear scan - may hit
  ## the database to look up early indices.
  if slot == dag.genesis.slot:
    return ok BlockSlotId.init(dag.genesis, slot)

  if slot > dag.finalizedHead.slot:
    return dag.head.atSlot(slot).toBlockSlotId() # iterate to the given slot

  if slot >= dag.finalizedHead.blck.slot:
    # finalized head is still in memory
    return dag.finalizedHead.blck.atSlot(slot).toBlockSlotId()

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

  err() # not backfilled yet, and not genesis

proc getBlockId*(dag: ChainDAGRef, root: Eth2Digest): Opt[BlockId] =
  ## Look up block id by root in history - useful for turning a root into a
  ## slot - may hit the database, may return blocks that have since become
  ## unviable - use `getBlockIdAtSlot` to check that the block is still viable
  ## if used in a sensitive context
  block: # If we have a BlockRef, this is the fastest way to get a block id
    let blck = dag.getBlockRef(root)
    if blck.isOk():
      return ok(blck.get().bid)

  block: # We might have a summary in the database
    let summary = dag.db.getBeaconBlockSummary(root)
    if summary.isOk():
      return ok(BlockId(root: root, slot: summary.get().slot))

  err()

func isCanonical*(dag: ChainDAGRef, bid: BlockId): bool =
  ## Return true iff the given `bid` is part of the history selected by `dag.head`
  let current = dag.getBlockIdAtSlot(bid.slot).valueOr:
    return false # We don't know, so ..
  return current.bid == bid

func parent*(dag: ChainDAGRef, bid: BlockId): Opt[BlockId] =
  if bid.slot == 0:
    return err()

  if bid.slot > dag.finalizedHead.slot:
    # Make sure we follow the correct history as there may be forks
    let blck = ? dag.getBlockRef(bid.root)

    doAssert not isNil(blck.parent), "should reach finalized head"
    return ok blck.parent.bid

  let bids = ? dag.getBlockIdAtSlot(bid.slot - 1)
  ok(bids.bid)

func parentOrSlot*(dag: ChainDAGRef, bsi: BlockSlotId): Opt[BlockSlotId] =
  if bsi.slot == 0:
    return err()

  if bsi.isProposed:
    let parent = ? dag.parent(bsi.bid)
    ok BlockSlotId.init(parent, bsi.slot)
  else:
    ok BlockSlotId.init(bsi.bid, bsi.slot - 1)

func atSlot*(dag: ChainDAGRef, bid: BlockId, slot: Slot): Opt[BlockSlotId] =
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

func epochAncestor*(dag: ChainDAGRef, bid: BlockId, epoch: Epoch): EpochKey =
  ## The state transition works by storing information from blocks in a
  ## "working" area until the epoch transition, then batching work collected
  ## during the epoch. Thus, last block in the ancestor epochs is the block
  ## that has an impact on epoch currently considered.
  ##
  ## This function returns an epoch key pointing to that epoch boundary, i.e. the
  ## boundary where the last block has been applied to the state and epoch
  ## processing has been done.
  if epoch < dag.tail.slot.epoch or bid.slot < dag.tail.slot:
    return EpochKey() # We can't load these states

  if epoch == dag.tail.slot.epoch:
    return EpochKey(bid: dag.tail, epoch: epoch)

  let bsi = dag.atSlot(bid, epoch.start_slot - 1).valueOr:
    # If we lack history for the given slot, we can use the given bid as epoch
    # ancestor
    return EpochKey(epoch: epoch, bid: bid)

  EpochKey(epoch: epoch, bid: bsi.bid)

func findEpochRef*(
    dag: ChainDAGRef, bid: BlockId, epoch: Epoch): Opt[EpochRef] =
  ## Look for an existing cached EpochRef, but unlike `getEpochRef`, don't
  ## try to create one by recreating the epoch state
  let ancestor = dag.epochAncestor(bid, epoch)

  for i in 0..<dag.epochRefs.len:
    if dag.epochRefs[i] != nil and dag.epochRefs[i].key == ancestor:
      return ok(dag.epochRefs[i])

  err()

func loadStateCache(
    dag: ChainDAGRef, cache: var StateCache, bid: BlockId, epoch: Epoch) =
  # When creating a state cache, we want the current and the previous epoch
  # information to be preloaded as both of these are used in state transition
  # functions

  template load(e: Epoch) =
    block:
      let epoch = e
      if epoch notin cache.shuffled_active_validator_indices:
        let epochRef = dag.findEpochRef(bid, epoch)
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
  db.containsBlock(root, cfg.blockForkAtEpoch(slot.epoch))

func isFinalizedStateSnapshot(slot: Slot): bool =
  slot.is_epoch and slot.epoch mod EPOCHS_PER_STATE_SNAPSHOT == 0

func isStateCheckpoint(dag: ChainDAGRef, bsi: BlockSlotId): bool =
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
  (bsi.isProposed and bsi.bid == dag.tail) or
  (bsi.slot.is_epoch and bsi.slot.epoch == (bsi.bid.slot.epoch + 1))

proc getState(
    db: BeaconChainDB, fork: BeaconStateFork, state_root: Eth2Digest,
    state: var ForkedHashedBeaconState, rollback: RollbackProc): bool =
  if state.kind != fork:
    # Avoid temporary (!)
    state = (ref ForkedHashedBeaconState)(kind: fork)[]

  withState(state):
    if not db.getState(state_root, state.data, rollback):
      return false

    state.root = state_root

  true

proc getState(
    db: BeaconChainDB, cfg: RuntimeConfig, block_root: Eth2Digest, slot: Slot,
    state: var ForkedHashedBeaconState, rollback: RollbackProc): bool =
  let state_root = db.getStateRoot(block_root, slot).valueOr:
    return false

  db.getState(cfg.stateForkAtEpoch(slot.epoch), state_root, state, rollback)

proc getState(
    dag: ChainDAGRef, bsi: BlockSlotId, state: var ForkedHashedBeaconState): bool =
  ## Load a state from the database given a block and a slot - this will first
  ## lookup the state root in the state root table then load the corresponding
  ## state, if it exists
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

proc getForkedBlock*(db: BeaconChainDB, root: Eth2Digest):
    Opt[ForkedTrustedSignedBeaconBlock] =
  # When we only have a digest, we don't know which fork it's from so we try
  # them one by one - this should be used sparingly
  if (let blck = db.getBlock(root, bellatrix.TrustedSignedBeaconBlock);
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

proc getBlock*(
    dag: ChainDAGRef, bid: BlockId,
    T: type ForkyTrustedSignedBeaconBlock): Opt[T] =
  dag.db.getBlock(bid.root, T) or
    getBlock(
      dag.era, getStateField(dag.headState, historical_roots).asSeq,
      bid.slot, Opt[Eth2Digest].ok(bid.root), T)

proc getBlockSSZ*(dag: ChainDAGRef, bid: BlockId, bytes: var seq[byte]): bool =
  # Load the SSZ-encoded data of a block into `bytes`, overwriting the existing
  # content
  let fork = dag.cfg.blockForkAtEpoch(bid.slot.epoch)
  dag.db.getBlockSSZ(bid.root, bytes, fork) or
    (bid.slot <= dag.finalizedHead.slot and
      getBlockSSZ(
        dag.era, getStateField(dag.headState, historical_roots).asSeq,
        bid.slot, bytes).isOk)

proc getBlockSZ*(dag: ChainDAGRef, bid: BlockId, bytes: var seq[byte]): bool =
  # Load the snappy-frame-compressed ("SZ") SSZ-encoded data of a block into
  # `bytes`, overwriting the existing content
  # careful: there are two snappy encodings in use, with and without framing!
  # Returns true if the block is found, false if not
  let fork = dag.cfg.blockForkAtEpoch(bid.slot.epoch)
  dag.db.getBlockSZ(bid.root, bytes, fork) or
    (bid.slot <= dag.finalizedHead.slot and
      getBlockSZ(
        dag.era, getStateField(dag.headState, historical_roots).asSeq,
        bid.slot, bytes).isOk)

proc getForkedBlock*(
    dag: ChainDAGRef, bid: BlockId): Opt[ForkedTrustedSignedBeaconBlock] =

  let fork = dag.cfg.blockForkAtEpoch(bid.slot.epoch)
  result.ok(ForkedTrustedSignedBeaconBlock(kind: fork))
  withBlck(result.get()):
    type T = type(blck)
    blck = getBlock(dag, bid, T).valueOr:
        getBlock(
            dag.era, getStateField(dag.headState, historical_roots).asSeq,
            bid.slot, Opt[Eth2Digest].ok(bid.root), T).valueOr:
          result.err()
          return

proc getForkedBlock*(
    dag: ChainDAGRef, root: Eth2Digest): Opt[ForkedTrustedSignedBeaconBlock] =
  let bid = dag.getBlockId(root)
  if bid.isSome():
    dag.getForkedBlock(bid.get())
  else:
    # In case we didn't have a summary - should be rare, but ..
    dag.db.getForkedBlock(root)

proc currentSyncCommitteeForPeriod*(
    dag: ChainDAGRef,
    tmpState: var ForkedHashedBeaconState,
    period: SyncCommitteePeriod): Opt[SyncCommittee] =
  ## Fetch a `SyncCommittee` for a given sync committee period.
  ## For non-finalized periods, follow the chain as selected by fork choice.
  let lowSlot = max(dag.tail.slot, dag.cfg.ALTAIR_FORK_EPOCH.start_slot)
  if period < lowSlot.sync_committee_period:
    return err()
  let
    periodStartSlot = period.start_slot
    syncCommitteeSlot = max(periodStartSlot, lowSlot)
    bsi = ? dag.getBlockIdAtSlot(syncCommitteeSlot)
  dag.withUpdatedState(tmpState, bsi) do:
    withState(state):
      when stateFork >= BeaconStateFork.Altair:
        ok state.data.current_sync_committee
      else: err()
  do: err()

func isNextSyncCommitteeFinalized*(
    dag: ChainDAGRef, period: SyncCommitteePeriod): bool =
  let finalizedSlot = dag.finalizedHead.slot
  if finalizedSlot < period.start_slot:
    false
  elif finalizedSlot < dag.cfg.ALTAIR_FORK_EPOCH.start_slot:
    false # Fork epoch not necessarily tied to sync committee period boundary
  else:
    true

func firstNonFinalizedPeriod*(dag: ChainDAGRef): SyncCommitteePeriod =
  if dag.finalizedHead.slot >= dag.cfg.ALTAIR_FORK_EPOCH.start_slot:
    dag.finalizedHead.slot.sync_committee_period + 1
  else:
    dag.cfg.ALTAIR_FORK_EPOCH.sync_committee_period

proc updateBeaconMetrics(
    state: ForkedHashedBeaconState, bid: BlockId, cache: var StateCache) =
  # https://github.com/ethereum/beacon-metrics/blob/master/metrics.md#additional-metrics
  # both non-negative, so difference can't overflow or underflow int64

  beacon_head_root.set(bid.root.toGaugeValue)
  beacon_head_slot.set(bid.slot.toGaugeValue)

  withState(state):
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

import blockchain_dag_light_client

export
  blockchain_dag_light_client.getLightClientBootstrap,
  blockchain_dag_light_client.getLightClientUpdateForPeriod,
  blockchain_dag_light_client.getLightClientFinalityUpdate,
  blockchain_dag_light_client.getLightClientOptimisticUpdate

proc getViableHead(cfg: RuntimeConfig, db: BeaconChainDB): Opt[BlockId] =
  # When the database has been written with a pre-fork version of the
  # software, it may happen that blocks produced using an "unforked"
  # chain get written to the database - we need to skip such blocks
  # when loading the database with a fork-compatible version
  let
    headRoot = ? db.getHeadBlock()

  for blck in db.getAncestorSummaries(headRoot):
    if containsBlock(cfg, db, blck.summary.slot, blck.root):
      return ok(BlockId(slot: blck.summary.slot, root: blck.root))

  err()

proc putState(dag: ChainDAGRef, state: ForkedHashedBeaconState, bid: BlockId) =
  # Store a state and its root
  logScope:
    blck = shortLog(bid)
    stateSlot = shortLog(getStateField(state, slot))
    stateRoot = shortLog(getStateRoot(state))

  if not dag.isStateCheckpoint(BlockSlotId.init(bid, getStateField(state, slot))):
    return

  # Don't consider legacy tables here, they are slow to read so we'll want to
  # rewrite things in the new table anyway.
  if dag.db.containsState(getStateRoot(state), legacy = false):
    return

  let startTick = Moment.now()
  # Ideally we would save the state and the root lookup cache in a single
  # transaction to prevent database inconsistencies, but the state loading code
  # is resilient against one or the other going missing
  withState(state):
    dag.db.putState(state)

  debug "Stored state", putStateDur = Moment.now() - startTick

proc advanceSlots*(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, slot: Slot, save: bool,
    cache: var StateCache, info: var ForkedEpochInfo) =
  # Given a state, advance it zero or more slots by applying empty slot
  # processing - the state must be positioned at or before `slot`
  doAssert getStateField(state, slot) <= slot

  let stateBid = state.latest_block_id
  while getStateField(state, slot) < slot:
    let
      preEpoch = getStateField(state, slot).epoch

    loadStateCache(dag, cache, stateBid, getStateField(state, slot).epoch)

    process_slots(
      dag.cfg, state, getStateField(state, slot) + 1, cache, info,
      dag.updateFlags).expect("process_slots shouldn't fail when state slot is correct")
    if save:
      dag.putState(state, stateBid)

      # The reward information in the state transition is computed for epoch
      # transitions - when transitioning into epoch N, the activities in epoch
      # N-2 are translated into balance updates, and this is what we capture
      # in the monitor. This may be inaccurate during a deep reorg (>1 epoch)
      # which is an acceptable tradeoff for monitoring.
      withState(state):
        let postEpoch = state.data.slot.epoch
        if preEpoch != postEpoch:
          dag.validatorMonitor[].registerEpochInfo(postEpoch, info, state.data)

proc applyBlock(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bid: BlockId,
    cache: var StateCache, info: var ForkedEpochInfo): Result[void, cstring] =

  loadStateCache(dag, cache, bid, getStateField(state, slot).epoch)

  case dag.cfg.blockForkAtEpoch(bid.slot.epoch)
  of BeaconBlockFork.Phase0:
    let data = getBlock(dag, bid, phase0.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info,
      dag.updateFlags + {slotProcessed}, noRollback)
  of BeaconBlockFork.Altair:
    let data = getBlock(dag, bid, altair.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info,
      dag.updateFlags + {slotProcessed}, noRollback)
  of BeaconBlockFork.Bellatrix:
    let data = getBlock(dag, bid, bellatrix.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info,
      dag.updateFlags + {slotProcessed}, noRollback)

proc init*(T: type ChainDAGRef, cfg: RuntimeConfig, db: BeaconChainDB,
           validatorMonitor: ref ValidatorMonitor, updateFlags: UpdateFlags,
           eraPath = ".",
           onBlockCb: OnBlockCallback = nil, onHeadCb: OnHeadCallback = nil,
           onReorgCb: OnReorgCallback = nil, onFinCb: OnFinalizedCallback = nil,
           vanityLogs = default(VanityLogs),
           lcDataConfig = default(LightClientDataConfig)): ChainDAGRef =
  cfg.checkForkConsistency()

  doAssert updateFlags - {strictVerification, enableTestFeatures} == {},
    "Other flags not supported in ChainDAG"

  # TODO we require that the db contains both a head and a tail block -
  #      asserting here doesn't seem like the right way to go about it however..

  # Tail is the first block for which we can construct a state - either
  # genesis or a checkpoint
  let
    startTick = Moment.now()
    genesisRoot = db.getGenesisBlock().expect(
      "preInit should have initialized the database with a genesis block root")
    tailRoot = db.getTailBlock().expect(
      "preInit should have initialized the database with a tail block root")
    tailBlock = db.getForkedBlock(tailRoot).expect(
      "Tail block in database, corrupt?")
    head = getViableHead(cfg, db).expect("Head root in database, corrupt?")

    # Have to be careful with this instance, it is not yet fully initialized so
    # as to avoid having to allocate a separate "init" state
    dag = ChainDAGRef(
      db: db,
      validatorMonitor: validatorMonitor,
      genesis: BlockId(root: genesisRoot, slot: GENESIS_SLOT),
      tail: tailBlock.toBlockId(),

      # The only allowed flag right now is strictVerification, as the others all
      # allow skipping some validation.
      updateFlags: {strictVerification, enableTestFeatures} * updateFlags,
      cfg: cfg,

      vanityLogs: vanityLogs,

      lcDataStore: initLightClientDataStore(
        lcDataConfig, cfg, db.getLightClientDataDB()),

      onBlockAdded: onBlockCb,
      onHeadChanged: onHeadCb,
      onReorgHappened: onReorgCb,
      onFinHappened: onFinCb
    )
    loadTick = Moment.now()

  var
    headRef, curRef: BlockRef
    slot = head.slot
    # To know the finalized checkpoint of the head, we need to recreate its
    # state - the tail is implicitly finalized, and if we have a finalized block
    # table, that provides another hint
    finalizedSlot = db.finalizedBlocks.high.get(dag.tail.slot)
    newFinalized: seq[BlockId]
    cache: StateCache
    foundHeadState = false
    headBlocks: seq[BlockRef]

  # Load head -> finalized, or all summaries in case the finalized block table
  # hasn't been written yet
  for blck in db.getAncestorSummaries(head.root):
    # The execution block root gets filled in as needed
    let newRef = BlockRef.init(blck.root, none Eth2Digest, blck.summary.slot)
    if headRef == nil:
      doAssert blck.root == head.root
      headRef = newRef

    if curRef != nil:
      link(newRef, curRef)

    curRef = newRef

    dag.forkBlocks.incl(KeyedBlockRef.init(curRef))

    if not foundHeadState:
      while slot >= blck.summary.slot:
        # Try loading state from database - we need the head state early on to
        # establish the (real) finalized checkpoint
        if db.getState(cfg, blck.root, slot, dag.headState, noRollback):
          # EpochRef needs an epoch boundary state
          assign(dag.epochRefState, dag.headState)

          var info: ForkedEpochInfo

          while headBlocks.len > 0:
            dag.applyBlock(
              dag.headState, headBlocks.pop().bid, cache,
              info).expect("head blocks should apply")

          dag.head = headRef

          assign(dag.clearanceState, dag.headState)

          finalizedSlot =
            max(finalizedSlot,
              getStateField(dag.headState, finalized_checkpoint).epoch.start_slot)
          foundHeadState = true
          break
        slot -= 1

      slot += 1

      if not foundHeadState:
        headBlocks.add curRef

    if curRef.slot <= finalizedSlot:
      # Only non-finalized slots get a `BlockRef`
      break

  let summariesTick = Moment.now()

  if not foundHeadState:
    fatal "Could not load head state, database corrupt? For Kiln testnet: database schema changed; need to resync from pre-Bellatrix database or genesis",
      head = shortLog(head), tail = shortLog(dag.tail),
      genesis = shortLog(dag.genesis)
    quit 1

  let
    configFork = case dag.headState.kind
      of BeaconStateFork.Phase0: genesisFork(cfg)
      of BeaconStateFork.Altair: altairFork(cfg)
      of BeaconStateFork.Bellatrix: bellatrixFork(cfg)
    stateFork = getStateField(dag.headState, fork)

  if stateFork != configFork:
    error "State from database does not match network, check --network parameter",
      genesis = dag.genesis, tail = dag.tail, headRef, stateFork, configFork
    quit 1

  # Need to load state to find genesis validators root, before loading era db
  dag.era = EraDB.new(
    cfg, eraPath, getStateField(dag.headState, genesis_validators_root))

  # We used an interim finalizedHead while loading the head state above - now
  # that we have loaded the dag up to the finalized slot, we can also set
  # finalizedHead to its real value
  dag.finalizedHead = headRef.atSlot(finalizedSlot)
  dag.lastPrunePoint = dag.finalizedHead.toBlockSlotId().expect("not nil")

  dag.heads = @[headRef]

  doAssert dag.finalizedHead.blck != nil,
    "The finalized head should exist at the slot"
  doAssert dag.finalizedHead.blck.parent == nil,
    "...but that's the last BlockRef with a parent"

  block: # Top up finalized blocks
    if db.finalizedBlocks.high.isNone or
        db.finalizedBlocks.high.get() < dag.finalizedHead.blck.slot:
      info "Loading finalized blocks",
        finHigh = db.finalizedBlocks.high,
          finalizedHead = shortLog(dag.finalizedHead)

      for blck in db.getAncestorSummaries(dag.finalizedHead.blck.root):
        if db.finalizedBlocks.high.isSome and
            blck.summary.slot <= db.finalizedBlocks.high.get:
          break

        # Versions prior to 1.7.0 did not store finalized blocks in the
        # database, and / or the application might have crashed between the head
        # and finalized blocks updates.
        newFinalized.add(BlockId(slot: blck.summary.slot, root: blck.root))

  let finalizedBlocksTick = Moment.now()
  db.updateFinalizedBlocks(newFinalized)

  block:
    let finalized = db.finalizedBlocks.get(db.finalizedBlocks.high.get()).expect(
      "tail at least")
    if finalized != dag.finalizedHead.blck.root:
      error "Head does not lead to finalized block, database corrupt?",
        head = shortLog(head), finalizedHead = shortLog(dag.finalizedHead),
        tail = shortLog(dag.tail), finalized = shortLog(finalized)
      quit 1

  dag.backfill = block:
    let backfillSlot = db.finalizedBlocks.low.expect("tail at least")
    if backfillSlot < dag.tail.slot:
      let backfillRoot = db.finalizedBlocks.get(backfillSlot).expect(
        "low to be loadable")

      db.getBeaconBlockSummary(backfillRoot).expect(
        "Backfill block must have a summary: " & $backfillRoot)
    else:
      withBlck(tailBlock): blck.message.toBeaconBlockSummary()

  dag.forkDigests = newClone ForkDigests.init(
    cfg, getStateField(dag.headState, genesis_validators_root))

  withState(dag.headState):
    dag.validatorMonitor[].registerState(state.data)

  updateBeaconMetrics(dag.headState, dag.head.bid, cache)

  let finalizedTick = Moment.now()

  if dag.backfill.slot > 0: # See if we can frontfill blocks from era files
    dag.frontfillBlocks = newSeqOfCap[Eth2Digest](dag.backfill.slot.int)

    let
      historical_roots = getStateField(dag.headState, historical_roots).asSeq()

    var
      blocks = 0
      parent: Eth2Digest

    # Here, we'll build up the slot->root mapping in memory for the range of
    # blocks from genesis to backfill, if possible.
    for summary in dag.era.getBlockIds(historical_roots, Slot(0)):
      if summary.slot >= dag.backfill.slot:
        # If we end up in here, we failed the root comparison just below in
        # an earlier iteration
        fatal "Era summaries don't lead up to backfill, database or era files corrupt?",
          slot = summary.slot
        quit 1

      # In BeaconState.block_roots, empty slots are filled with the root of
      # the previous block - in our data structure, we use a zero hash instead
      if summary.root != parent:
        dag.frontfillBlocks.setLen(summary.slot.int + 1)
        dag.frontfillBlocks[summary.slot.int] = summary.root

        if summary.root == dag.backfill.parent_root:
          # We've reached the backfill point, meaning blocks are available
          # in the sqlite database from here onwards - remember this point in
          # time so that we can write summaries to the database - it's a lot
          # faster to load from database than to iterate over era files with
          # the current naive era file reader.
          reset(dag.backfill)

          dag.updateFrontfillBlocks()

          break

        parent = summary.root

      blocks += 1

    if blocks > 0:
      info "Front-filled blocks from era files", blocks

  let frontfillTick = Moment.now()

  # Fill validator key cache in case we're loading an old database that doesn't
  # have a cache
  dag.updateValidatorKeys(getStateField(dag.headState, validators).asSeq())

  withState(dag.headState):
    when stateFork >= BeaconStateFork.Altair:
      dag.headSyncCommittees = state.data.get_sync_committee_cache(cache)

  info "Block DAG initialized",
    head = shortLog(dag.head),
    finalizedHead = shortLog(dag.finalizedHead),
    tail = shortLog(dag.tail),
    backfill = (dag.backfill.slot, shortLog(dag.backfill.parent_root)),

    loadDur = loadTick - startTick,
    summariesDur = summariesTick - loadTick,
    finalizedDur = finalizedTick - summariesTick,
    frontfillDur = frontfillTick - finalizedTick,
    keysDur = Moment.now() - frontfillTick

  dag.initLightClientDataCache()

  # If these aren't actually optimistic, the first fcU will resolve that
  withState(dag.headState):
    when stateFork >= BeaconStateFork.Bellatrix:
      template executionPayloadHeader(): auto =
        state().data.latest_execution_payload_header
      const emptyExecutionPayloadHeader =
        default(type(executionPayloadHeader))
      if executionPayloadHeader != emptyExecutionPayloadHeader:
        dag.optimisticRoots.incl dag.head.root
        dag.optimisticRoots.incl dag.finalizedHead.blck.root

  dag

template genesis_validators_root*(dag: ChainDAGRef): Eth2Digest =
  getStateField(dag.headState, genesis_validators_root)

proc genesisBlockRoot*(dag: ChainDAGRef): Eth2Digest =
  dag.db.getGenesisBlock().expect("DB must be initialized with genesis block")

func getEpochRef*(
    dag: ChainDAGRef, state: ForkedHashedBeaconState, cache: var StateCache): EpochRef =
  ## Get a cached `EpochRef` or construct one based on the given state - always
  ## returns an EpochRef instance
  let
    bid = state.latest_block_id
    epoch = state.get_current_epoch()

  var epochRef = dag.findEpochRef(bid, epoch)
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
    dag: ChainDAGRef, bid: BlockId, epoch: Epoch,
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
  ## has been pruned - `none` will be returned in this case.
  if not preFinalized and epoch < dag.finalizedHead.slot.epoch:
    return err()

  if bid.slot < dag.tail.slot or epoch < dag.tail.slot.epoch:
    return err()

  let epochRef = dag.findEpochRef(bid, epoch)
  if epochRef.isOk():
    beacon_state_data_cache_hits.inc
    return epochRef

  beacon_state_data_cache_misses.inc

  # TODO instead of using the epoch ancestor, we should really be looking
  #      for _any_ state in the desired epoch in the history of bid since the
  #      epoch values remain unchanged: currently `epochAncestor` itself
  #      contains a work-around for the tail state, but it would be better to
  #      turn that work-around into a more efficient loading solution here
  let
    ancestor = dag.epochAncestor(bid, epoch)

  var cache: StateCache
  if not updateState(
      dag, dag.epochRefState, ? dag.atSlot(ancestor.bid, epoch.start_slot),
      false, cache):
    return err()

  ok(dag.getEpochRef(dag.epochRefState, cache))

proc getEpochRef*(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch,
    preFinalized: bool): Opt[EpochRef] =
  dag.getEpochRef(blck.bid, epoch, preFinalized)

proc getFinalizedEpochRef*(dag: ChainDAGRef): EpochRef =
  dag.getEpochRef(
    dag.finalizedHead.blck, dag.finalizedHead.slot.epoch, false).expect(
      "getEpochRef for finalized head should always succeed")

func stateCheckpoint*(dag: ChainDAGRef, bsi: BlockSlotId): BlockSlotId =
  ## The first ancestor BlockSlot that is a state checkpoint
  var bsi = bsi
  while not dag.isStateCheckpoint(bsi):
    if bsi.isProposed:
      bsi.bid = dag.parent(bsi.bid).valueOr:
        break
    else:
      bsi.slot = bsi.slot - 1
  bsi

template forkAtEpoch*(dag: ChainDAGRef, epoch: Epoch): Fork =
  forkAtEpoch(dag.cfg, epoch)

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
    if bs.isSome and bs.get().isProposed():
      o -= 1
      output[o] = bs.get().bid
    curSlot -= skipStep

  # Handle start slot separately (to avoid underflow when computing curSlot)
  let bs = dag.getBlockIdAtSlot(startSlot)
  if bs.isSome and bs.get().isProposed():
    o -= 1
    output[o] = bs.get().bid

  o # Return the index of the first non-nil item in the output

proc updateState*(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bsi: BlockSlotId,
    save: bool, cache: var StateCache): bool =
  ## Rewind or advance state such that it matches the given block and slot -
  ## this may include replaying from an earlier snapshot if blck is on a
  ## different branch or has advanced to a higher slot number than slot
  ## If `bs.slot` is higher than `bs.blck.slot`, `updateState` will fill in
  ## with empty/non-block slots

  # First, see if we're already at the requested block. If we are, also check
  # that the state has not been advanced past the desired block - if it has,
  # an earlier state must be loaded since there's no way to undo the slot
  # transitions

  let
    startTick = Moment.now()
    current {.used.} = withState(state):
      BlockSlotId.init(state.latest_block_id, state.data.slot)

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

  # Fast path: check all caches for an exact match - this is faster than
  # advancing a state where there's epoch processing to do, by a wide margin -
  # it also avoids `hash_tree_root` for slot processing
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
      # TODO https://github.com/nim-lang/Nim/issues/19613
      cur = dag.parentOrSlot(cur).valueOr:
        break

  if not found:
    debug "UpdateStateData cache miss",
      current = shortLog(current), target = shortLog(bsi)

    # Either the state is too new or was created by applying a different block.
    # We'll now resort to loading the state from the database then reapplying
    # blocks until we reach the desired point in time.

    var cur = bsi
    ancestors.setLen(0)

    # Look for a state in the database and load it - as long as it cannot be
    # found, keep track of the blocks that are needed to reach it from the
    # state that eventually will be found.
    # If we hit the tail, it means that we've reached a point for which we can
    # no longer recreate history - this happens for example when starting from
    # a checkpoint block
    let startEpoch = bsi.slot.epoch
    while not canAdvance(state, cur) and not dag.db.getState(dag.cfg, cur.bid.root, cur.slot, state, noRollback):
      # There's no state saved for this particular BlockSlot combination, and
      # the state we have can't trivially be advanced (in case it was older than
      # RewindBlockThreshold), keep looking..
      if cur.isProposed():
        # This is not an empty slot, so the block will need to be applied to
        # eventually reach bs
        ancestors.add(cur.bid)

      if cur.slot == GENESIS_SLOT or
          (cur.slot.epoch +  uint64(EPOCHS_PER_STATE_SNAPSHOT) * 2 < startEpoch):
        # We've either walked two full state snapshot lengths or hit the tail
        # and still can't find a matching state: this can happen when
        # starting the node from an arbitrary finalized checkpoint and not
        # backfilling the states
        notice "Request for pruned historical state",
          request = shortLog(bsi), tail = shortLog(dag.tail),
          cur = shortLog(cur)
        return false

      # Move slot by slot to capture epoch boundary states
      # TODO https://github.com/nim-lang/Nim/issues/19613
      cur = dag.parentOrSlot(cur).valueOr:
        notice "Request for pruned historical state",
          request = shortLog(bsi), tail = shortLog(dag.tail),
          cur = shortLog(cur)
        return false

    beacon_state_rewinds.inc()

  # Starting state has been assigned, either from memory or database
  let
    assignTick = Moment.now()
    ancestor {.used.} = withState(state):
      BlockSlotId.init(state.latest_block_id, state.data.slot)
    ancestorRoot {.used.} = getStateRoot(state)

  var info: ForkedEpochInfo
  # Time to replay all the blocks between then and now
  for i in countdown(ancestors.len - 1, 0):
    # Because the ancestors are in the database, there's no need to persist them
    # again. Also, because we're applying blocks that were loaded from the
    # database, we can skip certain checks that have already been performed
    # before adding the block to the database.
    if dag.applyBlock(state, ancestors[i], cache, info).isErr:
      return false

  # ...and make sure to process empty slots as requested
  dag.advanceSlots(state, bsi.slot, save, cache, info)

  # ...and make sure to load the state cache, if it exists
  loadStateCache(dag, cache, bsi.bid, getStateField(state, slot).epoch)

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
      slots = getStateField(state, slot) - ancestor.slot,
      current = shortLog(current),
      ancestor = shortLog(ancestor),
      target = shortLog(bsi),
      ancestorStateRoot = shortLog(ancestorRoot),
      targetStateRoot = shortLog(getStateRoot(state)),
      found,
      assignDur,
      replayDur
  elif ancestors.len > 0:
    debug "State replayed",
      blocks = ancestors.len,
      slots = getStateField(state, slot) - ancestor.slot,
      current = shortLog(current),
      ancestor = shortLog(ancestor),
      target = shortLog(bsi),
      ancestorStateRoot = shortLog(ancestorRoot),
      targetStateRoot = shortLog(getStateRoot(state)),
      found,
      assignDur,
      replayDur
  else: # Normal case!
    trace "State advanced",
      blocks = ancestors.len,
      slots = getStateField(state, slot) - ancestor.slot,
      current = shortLog(current),
      ancestor = shortLog(ancestor),
      target = shortLog(bsi),
      ancestorStateRoot = shortLog(ancestorRoot),
      targetStateRoot = shortLog(getStateRoot(state)),
      found,
      assignDur,
      replayDur

  true

proc delState(dag: ChainDAGRef, bsi: BlockSlotId) =
  # Delete state state and mapping for a particular block+slot
  if not dag.isStateCheckpoint(bsi):
    return # We only ever save epoch states

  if (let root = dag.db.getStateRoot(bsi.bid.root, bsi.slot); root.isSome()):
    dag.db.delState(root.get())
    dag.db.delStateRoot(bsi.bid.root, bsi.slot)

proc pruneBlockSlot(dag: ChainDAGRef, bs: BlockSlot) =
  # TODO: should we move that disk I/O to `onSlotEnd`
  dag.delState(bs.toBlockSlotId().expect("not nil"))

  if bs.isProposed():
    # Update light client data
    dag.deleteLightClientData(bs.blck.bid)

    dag.optimisticRoots.excl bs.blck.root
    dag.forkBlocks.excl(KeyedBlockRef.init(bs.blck))
    dag.db.delBlock(bs.blck.root)

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
    # The block whose parent is nil is the `BlockRef` that's part of the
    # canonical chain but has now been finalized - in theory there could be
    # states at empty slot iff the fork had epoch-long gaps where the epoch
    # transition was not on the canonical chain - these will not properly get
    # cleaned up by the current logic - but they should also be rare
    # TODO clean up the above as well
    doAssert dag.finalizedHead.blck.parent == nil,
      "finalizedHead parent should have been pruned from memory already"

    while cur.blck.parent != nil:
      dag.pruneBlockSlot(cur)
      cur = cur.parentOrSlot

    dag.heads.del(n)

  debug "Pruned the blockchain DAG",
    currentCandidateHeads = dag.heads.len,
    prunedHeads = hlen - dag.heads.len,
    dagPruneDur = Moment.now() - startTick

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/sync/optimistic.md#helpers
template is_optimistic*(dag: ChainDAGRef, root: Eth2Digest): bool =
  root in dag.optimisticRoots

proc markBlockInvalid*(dag: ChainDAGRef, root: Eth2Digest) =
  let blck = dag.getBlockRef(root).valueOr:
    return
  logScope: blck = shortLog(blck)

  if not dag.is_optimistic(root):
    # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/sync/optimistic.md#transitioning-from-valid---invalidated-or-invalidated---valid
    # "It is outside of the scope of the specification since it's only possible
    # with a faulty EE. Such a scenario requires manual intervention."
    warn "markBlockInvalid: attempt to invalidate valid block"
    doAssert strictVerification notin dag.updateFlags
    return

  if root == dag.finalizedHead.blck.root:
    # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/sync/optimistic.md#re-orgs
    # "If the justified checkpoint transitions from `NOT_VALIDATED` ->
    # `INVALIDATED`, a consensus engine MAY choose to alert the user and force
    # the application to exit."
    #
    # But be slightly less aggressive, and only check finalized.
    warn "markBlockInvalid: finalized block invalidated"
    doAssert strictVerification notin dag.updateFlags
    return

  debug "markBlockInvalid"
  dag.pruneBlockSlot(blck.atSlot())

proc markBlockVerified*(
    dag: ChainDAGRef, quarantine: var Quarantine, root: Eth2Digest) =
  # Might be called when block was not optimistic to begin with, or had been
  # but already had been marked verified.
  if not dag.is_optimistic(root):
    return

  var cur = dag.getBlockRef(root).valueOr:
    return
  logScope: blck = shortLog(cur)

  debug "markBlockVerified"

  while true:
    if not dag.is_optimistic(cur.bid.root):
      return

    dag.optimisticRoots.excl cur.bid.root

    debug "markBlockVerified ancestor"

    if cur.parent.isNil:
      break

    cur = cur.parent

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
  withState(dag.headState):
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
  withState(dag.headState):
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
  dag.lastPrunePoint != dag.finalizedHead.toBlockSlotId().expect("not nil")

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
      finPoint = dag.finalizedHead.toBlockSlotId().expect("not nil")
      cur = dag.parentOrSlot(dag.stateCheckpoint(finPoint))
      prev = dag.parentOrSlot(dag.stateCheckpoint(dag.lastPrunePoint))

    while cur.isSome and prev.isSome and cur.get() != prev.get():
      if not isFinalizedStateSnapshot(cur.get().slot) and
          cur.get().slot != dag.tail.slot:
        dag.delState(cur.get())
      # TODO https://github.com/nim-lang/Nim/issues/19613
      let tmp = cur.get()
      cur = dag.parentOrSlot(tmp)

  let statePruneTick = Moment.now()

  block: # Clean up old EpochRef instances
    # After finalization, we can clear up the epoch cache and save memory -
    # it will be recomputed if needed
    for i in 0..<dag.epochRefs.len:
      if dag.epochRefs[i] != nil and
          dag.epochRefs[i].epoch < dag.finalizedHead.slot.epoch:
        dag.epochRefs[i] = nil
  let epochRefPruneTick = Moment.now()

  dag.lastPrunePoint = dag.finalizedHead.toBlockSlotId().expect("not nil")

  debug "Pruned the state checkpoints and DAG caches.",
    statePruneDur = statePruneTick - startTick,
    epochRefPruneDur = epochRefPruneTick - statePruneTick

proc loadExecutionBlockRoot*(dag: ChainDAGRef, blck: BlockRef): Eth2Digest =
  if dag.cfg.blockForkAtEpoch(blck.bid.slot.epoch) < BeaconBlockFork.Bellatrix:
    return ZERO_HASH

  if blck.executionBlockRoot.isSome:
    return blck.executionBlockRoot.get

  let blockData = dag.getForkedBlock(blck.bid).valueOr:
    blck.executionBlockRoot = some ZERO_HASH
    return ZERO_HASH

  let executionBlockRoot =
    withBlck(blockData):
      when stateFork >= BeaconStateFork.Bellatrix:
        blck.message.body.execution_payload.block_hash
      else:
        ZERO_HASH
  blck.executionBlockRoot = some executionBlockRoot

  executionBlockRoot

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

  let
    lastHead = dag.head

  logScope:
    newHead = shortLog(newHead)
    lastHead = shortLog(lastHead)

  if lastHead == newHead:
    trace "No head block update"
    return

  if newHead.parent.isNil:
    # The new head should always have the finalizedHead as ancestor - thus,
    # this should not happen except in a race condition where the selected
    # `BlockRef` had its parent set to nil as happens during finalization -
    # notably, resetting the head to be the finalizedHead is not allowed
    error "Cannot update head to block without parent"
    return

  let
    lastHeadStateRoot = getStateRoot(dag.headState)
    lastHeadMergeComplete = dag.headState.is_merge_transition_complete()

  # Start off by making sure we have the right state - updateState will try
  # to use existing in-memory states to make this smooth
  var cache: StateCache
  if not updateState(
      dag, dag.headState, newHead.bid.atSlot(), false, cache):
    # Advancing the head state should never fail, given that the tail is
    # implicitly finalised, the head is an ancestor of the tail and we always
    # store the tail state in the database, as well as every epoch slot state in
    # between
    fatal "Unable to load head state during head update, database corrupt?",
      lastHead = shortLog(lastHead)
    quit 1

  dag.head = newHead

  if  dag.headState.is_merge_transition_complete() and not
      lastHeadMergeComplete and
      dag.vanityLogs.onMergeTransitionBlock != nil:
    dag.vanityLogs.onMergeTransitionBlock()

  dag.db.putHeadBlock(newHead.root)

  updateBeaconMetrics(dag.headState, dag.head.bid, cache)

  withState(dag.headState):
    when stateFork >= BeaconStateFork.Altair:
      dag.headSyncCommittees = state.data.get_sync_committee_cache(cache)

  let
    finalized_checkpoint =
      getStateField(dag.headState, finalized_checkpoint)
    finalizedSlot =
      # finalized checkpoint may move back in the head state compared to what
      # we've seen in other forks - it does not move back in fork choice
      # however, so we'll use the last-known-finalized in that case
      max(finalized_checkpoint.epoch.start_slot(), dag.finalizedHead.slot)
    finalizedHead = newHead.atSlot(finalizedSlot)

  doAssert (not finalizedHead.blck.isNil),
    "Block graph should always lead to a finalized block"

  # Update light client data
  dag.processHeadChangeForLightClient()

  let (isAncestor, ancestorDepth) = lastHead.getDepth(newHead)
  if not(isAncestor):
    notice "Updated head block with chain reorg",
      headParent = shortLog(newHead.parent),
      stateRoot = shortLog(getStateRoot(dag.headState)),
      justified = shortLog(getStateField(
        dag.headState, current_justified_checkpoint)),
      finalized = shortLog(getStateField(dag.headState, finalized_checkpoint)),
      isOptHead = dag.is_optimistic(newHead.root)

    if not(isNil(dag.onReorgHappened)):
      let
        # TODO (cheatfate): Proper implementation required
        data = ReorgInfoObject.init(dag.head.slot, uint64(ancestorDepth),
                                    lastHead.root, newHead.root,
                                    lastHeadStateRoot,
                                    getStateRoot(dag.headState))
      dag.onReorgHappened(data)

    # A reasonable criterion for "reorganizations of the chain"
    quarantine.clearAfterReorg()

    beacon_reorgs_total_total.inc()
    beacon_reorgs_total.inc()
  else:
    debug "Updated head block",
      stateRoot = shortLog(getStateRoot(dag.headState)),
      justified = shortLog(getStateField(
        dag.headState, current_justified_checkpoint)),
      finalized = shortLog(getStateField(dag.headState, finalized_checkpoint)),
      isOptHead = dag.is_optimistic(newHead.root)

    if not(isNil(dag.onHeadChanged)):
      let
        currentEpoch = epoch(newHead.slot)
        depRoot = withState(dag.headState): state.proposer_dependent_root
        prevDepRoot = withState(dag.headState): state.attester_dependent_root
        epochTransition = (finalizedHead != dag.finalizedHead)
        # TODO (cheatfate): Proper implementation required
        data = HeadChangeInfoObject.init(dag.head.slot, dag.head.root,
                                         getStateRoot(dag.headState),
                                         epochTransition, depRoot,
                                         prevDepRoot)
      dag.onHeadChanged(data)

  withState(dag.headState):
    # Every time the head changes, the "canonical" view of balances and other
    # state-related metrics change - notify the validator monitor.
    # Doing this update during head update ensures there's a reasonable number
    # of such updates happening - at most once per valid block.
    dag.validatorMonitor[].registerState(state.data)

  if finalizedHead != dag.finalizedHead:
    debug "Reached new finalization checkpoint",
      stateRoot = shortLog(getStateRoot(dag.headState)),
      justified = shortLog(getStateField(
        dag.headState, current_justified_checkpoint)),
      finalized = shortLog(getStateField(dag.headState, finalized_checkpoint))
    let oldFinalizedHead = dag.finalizedHead

    block:
      # Update `dag.finalizedBlocks` with all newly finalized blocks (those
      # newer than the previous finalized head), then update `dag.finalizedHead`
      var newFinalized: seq[BlockId]
      var tmp = finalizedHead.blck
      while not isNil(tmp) and tmp.slot >= dag.finalizedHead.slot:
        newFinalized.add(tmp.bid)
        if tmp != finalizedHead.blck:
          # The newly finalized block itself should remain in here so that fork
          # choice still can find it via root
          dag.forkBlocks.excl(KeyedBlockRef.init(tmp))

        let p = tmp.parent
        tmp.parent = nil # Reset all parent links to release memory
        tmp = p

      dag.finalizedHead = finalizedHead

      dag.db.updateFinalizedBlocks(newFinalized)

    if  dag.loadExecutionBlockRoot(oldFinalizedHead.blck).isZero and
        not dag.loadExecutionBlockRoot(dag.finalizedHead.blck).isZero and
        dag.vanityLogs.onFinalizedMergeTransitionBlock != nil:
      dag.vanityLogs.onFinalizedMergeTransitionBlock()

    # Pruning the block dag is required every time the finalized head changes
    # in order to clear out blocks that are no longer viable and should
    # therefore no longer be considered as part of the chain we're following
    dag.pruneBlocksDAG()

    # Update light client data
    dag.processFinalizationForLightClient(oldFinalizedHead)

    # Send notification about new finalization point via callback.
    if not(isNil(dag.onFinHappened)):
      let stateRoot =
        if dag.finalizedHead.slot == dag.head.slot: getStateRoot(dag.headState)
        elif dag.finalizedHead.slot + SLOTS_PER_HISTORICAL_ROOT > dag.head.slot:
          getStateField(dag.headState, state_roots).data[
            int(dag.finalizedHead.slot mod SLOTS_PER_HISTORICAL_ROOT)]
        else:
          Eth2Digest() # The thing that finalized was >8192 blocks old?
      # TODO (cheatfate): Proper implementation required
      let data = FinalizationInfoObject.init(
        dag.finalizedHead.blck.root, stateRoot, dag.finalizedHead.slot.epoch)
      dag.onFinHappened(dag, data)

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
      let tmp = dag.getEpochRef(head.bid, slot.epoch(), false)
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
    # - https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
    return err("aggregate: no attesting keys")

  let
    firstKey = dag.validatorKey(validator_indices[0])

  if not firstKey.isSome():
    return err("aggregate: invalid validator index")

  var aggregateKey{.noinit.}: AggregatePublicKey

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
    aggregateKey{.noinit.}: AggregatePublicKey
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

func needsBackfill*(dag: ChainDAGRef): bool =
  dag.backfill.slot > dag.genesis.slot

proc rebuildIndex*(dag: ChainDAGRef) =
  ## After a checkpoint sync, we lack intermediate states to replay from - this
  ## function rebuilds them so that historical replay can take place again
  if dag.backfill.slot > 0:
    debug "Backfill not complete, cannot rebuild archive"
    return

  if dag.tail.slot == dag.genesis.slot:
    # The tail is the earliest slot for which we're supposed to have states -
    # if it's sufficiently recent, don't do anything
    debug "Archive does not need rebuilding"
    return

  # First, we check what states we already have in the database - that allows
  # resuming the operation at any time
  let
    roots = dag.db.loadStateRoots()

  var
    canonical = newSeq[Eth2Digest](
      (dag.finalizedHead.slot.epoch + EPOCHS_PER_STATE_SNAPSHOT - 1) div
      EPOCHS_PER_STATE_SNAPSHOT)
    # `junk` puts in place some infrastructure to prune unnecessary states - it
    # will be more useful in the future as a base for pruning
    junk: seq[((Slot, Eth2Digest), Eth2Digest)]

  for k, v in roots:
    if k[0] >= dag.finalizedHead.slot:
      continue # skip newer stuff

    if not isFinalizedStateSnapshot(k[0]):
      # `tail` will move at the end of the process, so we won't need any
      # intermediate states
      junk.add((k, v))

      continue # skip non-snapshot slots

    if k[0] > 0:
      let bs = dag.getBlockIdAtSlot(k[0] - 1)
      if bs.isNone or bs.get().bid.root != k[1]:
        # remove things that are no longer a canonical part of the chain or
        # cannot be reached via a block
        junk.add((k, v))
        continue

    if not dag.db.containsState(v):
      continue # If it's not in the database..

    canonical[k[0].epoch div EPOCHS_PER_STATE_SNAPSHOT] = v

  let
    state = (ref ForkedHashedBeaconState)()

  var
    cache: StateCache
    info: ForkedEpochInfo

  # `canonical` holds all slots at which a state is expected to appear, using a
  # zero root whenever a particular state is missing - this way, if there's
  # partial progress or gaps, they will be dealt with correctly
  for i, state_root in canonical.mpairs():
    if not state_root.isZero:
      continue

    doAssert i > 0, "Genesis should always be available"

    let
      startSlot = Epoch((i - 1) * EPOCHS_PER_STATE_SNAPSHOT).start_slot
      slot = Epoch(i * EPOCHS_PER_STATE_SNAPSHOT).start_slot

    info "Recreating state snapshot",
      slot, startStateRoot = canonical[i - 1],  startSlot

    if getStateRoot(state[]) != canonical[i - 1]:
      if not dag.db.getState(dag.cfg.stateForkAtEpoch(startSlot.epoch), canonical[i - 1], state[], noRollback):
        error "Can't load start state, database corrupt?",
          startStateRoot = shortLog(canonical[i - 1]), slot = startSlot
        return

    for slot in startSlot..<startSlot + (EPOCHS_PER_STATE_SNAPSHOT * SLOTS_PER_EPOCH):
      let bids = dag.getBlockIdAtSlot(slot).valueOr:
        warn "Block id missing, cannot continue - database corrupt?", slot
        return

      # The slot check is needed to avoid re-applying a block
      if bids.isProposed and getStateField(state[], latest_block_header).slot < bids.bid.slot:
        let res = dag.applyBlock(state[], bids.bid, cache, info)
        if res.isErr:
          error "Failed to apply block while ", bids, slot
          return

        if slot.is_epoch:
          cache.prune(slot.epoch)

    process_slots(
      dag.cfg, state[], slot, cache, info,
      dag.updateFlags).expect("process_slots shouldn't fail when state slot is correct")

    withState(state[]):
      dag.db.putState(state)
      dag.db.checkpoint()

      state_root = state.root

  # Now that we have states all the way to genesis, we can adjust the tail
  # and readjust the in-memory indices to what they would look like if we had
  # started with an earlier tail
  dag.db.putTailBlock(dag.genesis.root)

  dag.tail = dag.genesis

  if junk.len > 0:
    info "Dropping redundant states", states = junk.len

    for i in junk:
      dag.db.delState(i[1])
