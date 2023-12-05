# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[algorithm, sequtils, tables, sets],
  stew/[arrayops, assign2, byteutils, results],
  metrics, snappy, chronicles,
  ../spec/[beaconstate, eth2_merkleization, eth2_ssz_serialization, helpers,
    state_transition, validator],
  ../spec/forks,
  ../spec/datatypes/[phase0, altair, bellatrix, capella],
  ".."/[beacon_chain_db, era_db],
  "."/[block_pools_types, block_quarantine]

from ../spec/datatypes/deneb import shortLog

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
  EPOCHS_PER_STATE_SNAPSHOT* = 32
    ## When finality happens, we prune historical states from the database except
    ## for a snapshot every 32 epochs from which replays can happen - there's a
    ## balance here between making long replays and saving on disk space
  MAX_SLOTS_PER_PRUNE* = SLOTS_PER_EPOCH
    ## We prune the database incrementally so as not to introduce long
    ## processing breaks - this number is the maximum number of blocks we allow
    ## to be pruned every time the prune call is made (once per slot typically)
    ## unless head is moving faster (ie during sync)


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
      template updatedState(): ForkedHashedBeaconState {.inject, used.} = stateParam
      okBody
    else:
      failureBody

func get_effective_balances(
    validators: openArray[Validator], epoch: Epoch): seq[Gwei] =
  ## Get the balances from a state as counted for fork choice
  result.newSeq(validators.len) # zero-init

  for i in 0 ..< result.len:
    # All non-active validators have a 0 balance
    let validator = unsafeAddr validators[i]
    if validator[].is_active_validator(epoch) and not validator[].slashed:
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
    dag: ChainDAGRef, index: ValidatorIndex or uint64): Opt[CookedPubKey] =
  ## Returns the validator pubkey for the index, assuming it's been observed
  ## at any point in time - this function may return pubkeys for indicies that
  ## are not (yet) part of the head state (if the key has been observed on a
  ## non-head branch)!
  dag.db.immutableValidators.load(index)

template is_merge_transition_complete*(
    stateParam: ForkedHashedBeaconState): bool =
  withState(stateParam):
    when consensusFork >= ConsensusFork.Bellatrix:
      is_merge_transition_complete(forkyState.data)
    else:
      false

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
  if slot > dag.finalizedHead.slot:
    return dag.head.atSlot(slot).toBlockSlotId() # iterate to the given slot

  if dag.finalizedHead.blck == nil:
    # Not initialized yet (in init)
    return Opt.none(BlockSlotId)

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

  if slot == GENESIS_SLOT and dag.genesis.isSome():
    return ok dag.genesis.get().atSlot()

  err() # not backfilled yet

proc containsBlock(
    cfg: RuntimeConfig, db: BeaconChainDB, slot: Slot, root: Eth2Digest): bool =
  db.containsBlock(root, cfg.consensusForkAtEpoch(slot.epoch))

proc getForkedBlock*(db: BeaconChainDB, root: Eth2Digest):
    Opt[ForkedTrustedSignedBeaconBlock] =
  # When we only have a digest, we don't know which fork it's from so we try
  # them one by one - this should be used sparingly
  static: doAssert high(ConsensusFork) == ConsensusFork.Deneb
  if (let blck = db.getBlock(root, deneb.TrustedSignedBeaconBlock);
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

proc getBlock*(
    dag: ChainDAGRef, bid: BlockId,
    T: type ForkyTrustedSignedBeaconBlock): Opt[T] =
  dag.db.getBlock(bid.root, T) or
    getBlock(
      dag.era, getStateField(dag.headState, historical_roots).asSeq,
      dag.headState.historical_summaries().asSeq,
      bid.slot, Opt[Eth2Digest].ok(bid.root), T)

proc getBlockSSZ*(dag: ChainDAGRef, bid: BlockId, bytes: var seq[byte]): bool =
  # Load the SSZ-encoded data of a block into `bytes`, overwriting the existing
  # content
  let fork = dag.cfg.consensusForkAtEpoch(bid.slot.epoch)
  dag.db.getBlockSSZ(bid.root, bytes, fork) or
    (bid.slot <= dag.finalizedHead.slot and
      getBlockSSZ(
        dag.era, getStateField(dag.headState, historical_roots).asSeq,
        dag.headState.historical_summaries().asSeq,
        bid.slot, bytes).isOk() and bytes.len > 0)

proc getBlockSZ*(dag: ChainDAGRef, bid: BlockId, bytes: var seq[byte]): bool =
  # Load the snappy-frame-compressed ("SZ") SSZ-encoded data of a block into
  # `bytes`, overwriting the existing content
  # careful: there are two snappy encodings in use, with and without framing!
  # Returns true if the block is found, false if not
  let fork = dag.cfg.consensusForkAtEpoch(bid.slot.epoch)
  dag.db.getBlockSZ(bid.root, bytes, fork) or
    (bid.slot <= dag.finalizedHead.slot and
      getBlockSZ(
        dag.era, getStateField(dag.headState, historical_roots).asSeq,
        dag.headState.historical_summaries().asSeq,
        bid.slot, bytes).isOk and bytes.len > 0)

proc getForkedBlock*(
    dag: ChainDAGRef, bid: BlockId): Opt[ForkedTrustedSignedBeaconBlock] =

  let fork = dag.cfg.consensusForkAtEpoch(bid.slot.epoch)
  result.ok(ForkedTrustedSignedBeaconBlock(kind: fork))
  withBlck(result.get()):
    type T = type(forkyBlck)
    forkyBlck = getBlock(dag, bid, T).valueOr:
        getBlock(
            dag.era, getStateField(dag.headState, historical_roots).asSeq,
            dag.headState.historical_summaries().asSeq,
            bid.slot, Opt[Eth2Digest].ok(bid.root), T).valueOr:
          result.err()
          return

proc getBlockId*(db: BeaconChainDB, root: Eth2Digest): Opt[BlockId] =
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
      debug "Writing summary", blck = shortLog(blck)
      db.putBeaconBlockSummary(root, summary)
      return ok(BlockId(root: root, slot: summary.slot))

  err()

proc getBlockId*(dag: ChainDAGRef, root: Eth2Digest): Opt[BlockId] =
  ## Look up block id by root in history - useful for turning a root into a
  ## slot - may hit the database, may return blocks that have since become
  ## unviable - use `getBlockIdAtSlot` to check that the block is still viable
  ## if used in a sensitive context
  block: # If we have a BlockRef, this is the fastest way to get a block id
    let blck = dag.getBlockRef(root)
    if blck.isOk():
      return ok(blck.get().bid)

  dag.db.getBlockId(root)

proc getForkedBlock*(
    dag: ChainDAGRef, root: Eth2Digest): Opt[ForkedTrustedSignedBeaconBlock] =
  let bid = dag.getBlockId(root)
  if bid.isSome():
    dag.getForkedBlock(bid.get())
  else:
    # In case we didn't have a summary - should be rare, but ..
    dag.db.getForkedBlock(root)

func isCanonical*(dag: ChainDAGRef, bid: BlockId): bool =
  ## Returns `true` if the given `bid` is part of the history selected by
  ## `dag.head`.
  let current = dag.getBlockIdAtSlot(bid.slot).valueOr:
    return false # We don't know, so ..
  return current.bid == bid

func isFinalized*(dag: ChainDAGRef, bid: BlockId): bool =
  ## Returns `true` if the given `bid` is part of the finalized history
  ## selected by `dag.finalizedHead`.
  dag.isCanonical(bid) and (bid.slot <= dag.finalizedHead.slot)

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

template delIt[I, T](cache: var LRUCache[I, T], predicate: untyped) =
  block:
    for i in 0 ..< I:
      template e: untyped = cache.entries[i]
      template it: untyped {.inject, used.} = e.value
      if e.lastUsed != 0 and predicate:
        e.reset()

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
  ## The epoch ancestor is the last block that has an effect on the epoch-
  ## related state data, as updated in `process_epoch` - this block determines
  ## effective balances, validator addtions and removals etc and serves as a
  ## base for `EpochRef` construction.
  if epoch < dag.tail.slot.epoch or bid.slot < dag.tail.slot:
    # Not enough information in database to meaningfully process pre-tail epochs
    return Opt.none BlockSlotId

  let
    dependentSlot =
      if epoch == dag.tail.slot.epoch:
        # Use the tail as "dependent block" - this may be the genesis block, or,
        # in the case of checkpoint sync, the checkpoint block
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
  ## The state transition works by storing information from blocks in a
  ## "working" area until the epoch transition, then batching work collected
  ## during the epoch. Thus, last block in the ancestor epochs is the block
  ## that has an impact on epoch currently considered.
  ##
  ## This function returns an epoch key pointing to that epoch boundary, i.e. the
  ## boundary where the last block has been applied to the state and epoch
  ## processing has been done.
  let bsi = dag.epochAncestor(bid, epoch).valueOr:
    return Opt.none(EpochKey)

  Opt.some(EpochKey(bid: bsi.bid, epoch: epoch))

func putShufflingRef*(dag: ChainDAGRef, shufflingRef: ShufflingRef) =
  ## Store shuffling in the cache
  if shufflingRef.epoch < dag.finalizedHead.slot.epoch():
    # Only cache epoch information for unfinalized blocks - earlier states
    # are seldomly used (ie RPC), so no need to cache
    return

  dag.shufflingRefs.put shufflingRef

func findShufflingRef*(
    dag: ChainDAGRef, bid: BlockId, epoch: Epoch): Opt[ShufflingRef] =
  ## Lookup a shuffling in the cache, returning `none` if it's not present - see
  ## `getShufflingRef` for a version that creates a new instance if it's missing
  let
    dependent_slot = epoch.attester_dependent_slot()
    dependent_bsi = ? dag.atSlot(bid, dependent_slot)

  # Check `ShufflingRef` cache
  let shufflingRef = dag.shufflingRefs.findIt(
    it.epoch == epoch and it.attester_dependent_root == dependent_bsi.bid.root)
  if shufflingRef.isOk:
    return shufflingRef

  # Check `EpochRef` cache
  let epochRef = dag.epochRefs.peekIt(
    it.shufflingRef.epoch == epoch and
    it.shufflingRef.attester_dependent_root == dependent_bsi.bid.root)
  if epochRef.isOk:
    dag.putShufflingRef(epochRef.get.shufflingRef)
    return ok epochRef.get.shufflingRef

  err()

func findEpochRef*(
    dag: ChainDAGRef, bid: BlockId, epoch: Epoch): Opt[EpochRef] =
  ## Lookup an EpochRef in the cache, returning `none` if it's not present - see
  ## `getEpochRef` for a version that creates a new instance if it's missing
  let key = ? dag.epochKey(bid, epoch)

  dag.epochRefs.findIt(it.key == key)

func putEpochRef(dag: ChainDAGRef, epochRef: EpochRef) =
  if epochRef.epoch < dag.finalizedHead.slot.epoch():
    # Only cache epoch information for unfinalized blocks - earlier states
    # are seldomly used (ie RPC), so no need to cache
    return

  dag.epochRefs.put epochRef

func init*(
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

func init*(
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

  # When fork choice runs, it will need the effective balance of the justified
  # checkpoint - we pre-load the balances here to avoid rewinding the justified
  # state later and compress them because not all checkpoints end up being used
  # for fork choice - specially during long periods of non-finalization
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
  # When creating a state cache, we want the current and the previous epoch
  # information to be preloaded as both of these are used in state transition
  # functions

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

  if dag.head != nil: # nil during init.. sigh
    let period = dag.head.slot.sync_committee_period
    if period == epoch.sync_committee_period and
        period notin cache.sync_committees and
        period > dag.cfg.ALTAIR_FORK_EPOCH.sync_committee_period():
      # If the block we're aiming for shares ancestry with head, we can reuse
      # the cached head committee - this accounts for most "live" cases like
      # syncing and checking blocks since the committees rarely change
      let periodBsi = dag.atSlot(bid, period.start_slot)
      if periodBsi.isSome and periodBsi ==
          dag.atSlot(dag.head.bid, period.start_slot):
        # We often end up sharing sync committees with head during sync / gossip
        # validation / head updates
        cache.sync_committees[period] = dag.headSyncCommittees

func containsForkBlock*(dag: ChainDAGRef, root: Eth2Digest): bool =
  ## Checks for blocks at the finalized checkpoint or newer
  KeyedBlockRef.asLookupKey(root) in dag.forkBlocks

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
    db: BeaconChainDB, cfg: RuntimeConfig, block_root: Eth2Digest, slot: Slot,
    state: var ForkedHashedBeaconState, rollback: RollbackProc): bool =
  let state_root = db.getStateRoot(block_root, slot).valueOr:
    return false

  db.getState(cfg.consensusForkAtEpoch(slot.epoch), state_root, state, rollback)

proc containsState*(
    db: BeaconChainDB, cfg: RuntimeConfig, block_root: Eth2Digest,
    slots: Slice[Slot], legacy = true): bool =
  var slot = slots.b
  while slot >= slots.a:
    let state_root = db.getStateRoot(block_root, slot)
    if state_root.isSome() and
        db.containsState(
          cfg.consensusForkAtEpoch(slot.epoch), state_root.get(), legacy):
      return true

    if slot == slots.a: # avoid underflow at genesis
      break
    slot -= 1
  false

proc getState*(
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

proc getStateByParent(
    dag: ChainDAGRef, bid: BlockId, state: var ForkedHashedBeaconState): bool =
  ## Try to load the state referenced by the parent of the given `bid` - this
  ## state can be used to advance to the `bid` state itself.
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

proc getNearbyState(
    dag: ChainDAGRef, state: ref ForkedHashedBeaconState, bid: BlockId,
    lowSlot: Slot): Opt[void] =
  ## Load state from DB that is close to `bid` and has at least slot `lowSlot`.
  var
    e = bid.slot.epoch
    b = bid
  while true:
    let stateSlot = e.start_slot
    if stateSlot < lowSlot:
      return err()
    b = (? dag.atSlot(b, max(stateSlot, 1.Slot) - 1)).bid
    let bsi = BlockSlotId.init(b, stateSlot)
    if not dag.getState(bsi, state[]):
      if e == GENESIS_EPOCH:
        return err()
      dec e
      continue
    return ok()

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
    withState(updatedState):
      when consensusFork >= ConsensusFork.Altair:
        ok forkyState.data.current_sync_committee
      else: err()
  do: err()

proc getBlockIdAtSlot*(
    dag: ChainDAGRef, state: ForkyHashedBeaconState, slot: Slot): Opt[BlockId] =
  if slot >= state.data.slot:
    Opt.some state.latest_block_id
  elif state.data.slot <= slot + SLOTS_PER_HISTORICAL_ROOT:
    dag.getBlockId(state.data.get_block_root_at_slot(slot))
  else:
    Opt.none(BlockId)

proc updateBeaconMetrics(
    state: ForkedHashedBeaconState, bid: BlockId, cache: var StateCache) =
  # https://github.com/ethereum/beacon-metrics/blob/master/metrics.md#additional-metrics
  # both non-negative, so difference can't overflow or underflow int64

  beacon_head_root.set(bid.root.toGaugeValue)
  beacon_head_slot.set(bid.slot.toGaugeValue)

  withState(state):
    beacon_pending_deposits.set(
      (forkyState.data.eth1_data.deposit_count -
        forkyState.data.eth1_deposit_index).toGaugeValue)
    beacon_processed_deposits_total.set(
      forkyState.data.eth1_deposit_index.toGaugeValue)

    beacon_current_justified_epoch.set(
      forkyState.data.current_justified_checkpoint.epoch.toGaugeValue)
    beacon_current_justified_root.set(
      forkyState.data.current_justified_checkpoint.root.toGaugeValue)
    beacon_previous_justified_epoch.set(
      forkyState.data.previous_justified_checkpoint.epoch.toGaugeValue)
    beacon_previous_justified_root.set(
      forkyState.data.previous_justified_checkpoint.root.toGaugeValue)
    beacon_finalized_epoch.set(
      forkyState.data.finalized_checkpoint.epoch.toGaugeValue)
    beacon_finalized_root.set(
      forkyState.data.finalized_checkpoint.root.toGaugeValue)

    let active_validators = count_active_validators(
      forkyState.data, forkyState.data.slot.epoch, cache).toGaugeValue
    beacon_active_validators.set(active_validators)
    beacon_current_active_validators.set(active_validators)

import blockchain_dag_light_client

export
  blockchain_dag_light_client.getLightClientBootstrap,
  blockchain_dag_light_client.getLightClientUpdateForPeriod,
  blockchain_dag_light_client.getLightClientFinalityUpdate,
  blockchain_dag_light_client.getLightClientOptimisticUpdate

proc putState(dag: ChainDAGRef, state: ForkedHashedBeaconState, bid: BlockId) =
  # Store a state and its root
  let slot = getStateField(state, slot)
  logScope:
    blck = shortLog(bid)
    stateSlot = shortLog(slot)
    stateRoot = shortLog(getStateRoot(state))

  if not dag.isStateCheckpoint(BlockSlotId.init(bid, slot)):
    return

  # Don't consider legacy tables here, they are slow to read so we'll want to
  # rewrite things in the new table anyway.
  if dag.db.containsState(
      dag.cfg.consensusForkAtEpoch(slot.epoch), getStateRoot(state),
      legacy = false):
    return

  let startTick = Moment.now()
  # Ideally we would save the state and the root lookup cache in a single
  # transaction to prevent database inconsistencies, but the state loading code
  # is resilient against one or the other going missing
  withState(state):
    dag.db.putState(forkyState)

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
        let postEpoch = forkyState.data.slot.epoch
        if preEpoch != postEpoch:
          dag.validatorMonitor[].registerEpochInfo(
            postEpoch, info, forkyState.data)

proc applyBlock(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bid: BlockId,
    cache: var StateCache, info: var ForkedEpochInfo): Result[void, cstring] =

  loadStateCache(dag, cache, bid, getStateField(state, slot).epoch)

  case dag.cfg.consensusForkAtEpoch(bid.slot.epoch)
  of ConsensusFork.Phase0:
    let data = getBlock(dag, bid, phase0.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info,
      dag.updateFlags + {slotProcessed}, noRollback)
  of ConsensusFork.Altair:
    let data = getBlock(dag, bid, altair.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info,
      dag.updateFlags + {slotProcessed}, noRollback)
  of ConsensusFork.Bellatrix:
    let data = getBlock(dag, bid, bellatrix.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info,
      dag.updateFlags + {slotProcessed}, noRollback)
  of ConsensusFork.Capella:
    let data = getBlock(dag, bid, capella.TrustedSignedBeaconBlock).valueOr:
      return err("Block load failed")
    state_transition(
      dag.cfg, state, data, cache, info,
      dag.updateFlags + {slotProcessed}, noRollback)
  of ConsensusFork.Deneb:
    let data = getBlock(dag, bid, deneb.TrustedSignedBeaconBlock).valueOr:
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

  doAssert updateFlags - {strictVerification} == {},
    "Other flags not supported in ChainDAG"

  # TODO we require that the db contains both a head and a tail block -
  #      asserting here doesn't seem like the right way to go about it however..

  # Tail is the first block for which we can construct a state - either
  # genesis or a checkpoint
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
      validatorMonitor: validatorMonitor,
      genesis: genesisRoot.map(
        proc(x: auto): auto = BlockId(root: x, slot: GENESIS_SLOT)),
      tail: tail,

      # The only allowed flag right now is strictVerification, as the others all
      # allow skipping some validation.
      updateFlags: updateFlags * {strictVerification},
      cfg: cfg,

      vanityLogs: vanityLogs,

      lcDataStore: initLightClientDataStore(
        lcDataConfig, cfg, db.getLightClientDataDB()),

      onBlockAdded: onBlockCb,
      onHeadChanged: onHeadCb,
      onReorgHappened: onReorgCb,
      onFinHappened: onFinCb,
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

  # Load head -> finalized, or all summaries in case the finalized block table
  # hasn't been written yet
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
            fatal "Missing block needed to create head state, database corrupt?",
              curRef = shortLog(curRef)
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
      fatal "Could not load head state, database corrupt?",
        head = shortLog(head), tail = shortLog(dag.tail)
      quit 1

  withState(dag.headState):
    when consensusFork >= ConsensusFork.Altair:
      dag.headSyncCommittees = forkyState.data.get_sync_committee_cache(cache)

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
      of ConsensusFork.Phase0: genesisFork(cfg)
      of ConsensusFork.Altair: altairFork(cfg)
      of ConsensusFork.Bellatrix: bellatrixFork(cfg)
      of ConsensusFork.Capella: capellaFork(cfg)
      of ConsensusFork.Deneb:   denebFork(cfg)
    stateFork = getStateField(dag.headState, fork)

  # Here, we check only the `current_version` field because the spec
  # mandates that testnets starting directly from a particular fork
  # should have `previous_version` set to `current_version` while
  # this doesn't happen to be the case in network that go through
  # regular hard-fork upgrades. See for example:
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#testing
  if stateFork.current_version != configFork.current_version:
    error "State from database does not match network, check --network parameter",
      tail = dag.tail, headRef, stateFork, configFork
    quit 1

  # Need to load state to find genesis validators root, before loading era db
  dag.era = EraDB.new(
    cfg, eraPath, getStateField(dag.headState, genesis_validators_root))

  # We used an interim finalizedHead while loading the head state above - now
  # that we have loaded the dag up to the finalized slot, we can also set
  # finalizedHead to its real value
  dag.finalizedHead = headRef.atSlot(finalizedSlot)
  dag.lastPrunePoint = dag.finalizedHead.toBlockSlotId().expect("not nil")

  doAssert dag.finalizedHead.blck != nil,
    "The finalized head should exist at the slot"

  block: # Top up finalized blocks
    if db.finalizedBlocks.high.isNone or
        db.finalizedBlocks.high.get() < dag.finalizedHead.blck.slot:
      # Versions prior to 1.7.0 did not store finalized blocks in the
      # database, and / or the application might have crashed between the head
      # and finalized blocks updates.
      info "Loading finalized blocks",
        finHigh = db.finalizedBlocks.high,
        finalizedHead = shortLog(dag.finalizedHead)

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
      error "Head does not lead to finalized block, database corrupt?",
        head = shortLog(head), finalizedHead = shortLog(dag.finalizedHead),
        tail = shortLog(dag.tail), finalized = shortLog(finalized)
      quit 1

  dag.backfill = block:
    let backfillSlot = db.finalizedBlocks.low.expect("tail at least")
    if backfillSlot <= dag.horizon:
      # Backfill done, no need to load anything
      BeaconBlockSummary()
    elif backfillSlot < dag.tail.slot:
      let backfillRoot = db.finalizedBlocks.get(backfillSlot).expect(
        "low to be loadable")

      db.getBeaconBlockSummary(backfillRoot).expect(
        "Backfill block must have a summary: " & $backfillRoot)
    else:
      db.getBeaconBlockSummary(dag.tail.root).expect(
        "Tail block must have a summary: " & $dag.tail.root)

  dag.forkDigests = newClone ForkDigests.init(
    cfg, getStateField(dag.headState, genesis_validators_root))

  withState(dag.headState):
    dag.validatorMonitor[].registerState(forkyState.data)

  updateBeaconMetrics(dag.headState, dag.head.bid, cache)

  let finalizedTick = Moment.now()

  if dag.backfill.slot > 0: # See if we can frontfill blocks from era files
    dag.frontfillBlocks = newSeqOfCap[Eth2Digest](dag.backfill.slot.int)

    let
      historical_roots = getStateField(dag.headState, historical_roots).asSeq()
      historical_summaries = dag.headState.historical_summaries.asSeq()

    var
      blocks = 0

    # Here, we'll build up the slot->root mapping in memory for the range of
    # blocks from genesis to backfill, if possible.
    for bid in dag.era.getBlockIds(
        historical_roots, historical_summaries, Slot(0), Eth2Digest()):
      if bid.slot >= dag.backfill.slot:
        # If we end up in here, we failed the root comparison just below in
        # an earlier iteration
        fatal "Era summaries don't lead up to backfill, database or era files corrupt?",
          bid
        quit 1

      # In BeaconState.block_roots, empty slots are filled with the root of
      # the previous block - in our data structure, we use a zero hash instead
      dag.frontfillBlocks.setLen(bid.slot.int + 1)
      dag.frontfillBlocks[bid.slot.int] = bid.root

      if bid.root == dag.backfill.parent_root:
        # We've reached the backfill point, meaning blocks are available
        # in the sqlite database from here onwards - remember this point in
        # time so that we can write summaries to the database - it's a lot
        # faster to load from database than to iterate over era files with
        # the current naive era file reader.
        reset(dag.backfill)

        dag.updateFrontfillBlocks()

        break

      blocks += 1

    if blocks > 0:
      info "Front-filled blocks from era files", blocks

  let frontfillTick = Moment.now()

  # Fill validator key cache in case we're loading an old database that doesn't
  # have a cache
  dag.updateValidatorKeys(getStateField(dag.headState, validators).asSeq())

  # Initialize pruning such that when starting with a database that hasn't been
  # pruned, we work our way from the tail to the horizon in incremental steps
  dag.lastHistoryPruneHorizon = dag.horizon()
  dag.lastHistoryPruneBlockHorizon = block:
    let boundary = min(dag.tail.slot, dag.horizon())
    if boundary.epoch() >= EPOCHS_PER_STATE_SNAPSHOT:
      start_slot(boundary.epoch() - EPOCHS_PER_STATE_SNAPSHOT)
    else:
      Slot(0)

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

  dag.findEpochRef(bid, epoch).valueOr:
    let res = EpochRef.init(dag, state, cache)
    dag.putEpochRef(res)
    res

proc getEpochRef*(
    dag: ChainDAGRef, bid: BlockId, epoch: Epoch,
    preFinalized: bool): Result[EpochRef, cstring] =
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
    return err("Requesting pre-finalized EpochRef")

  if bid.slot < dag.tail.slot or epoch < dag.tail.slot.epoch:
    return err("Requesting EpochRef for pruned state")

  let epochRef = dag.findEpochRef(bid, epoch)
  if epochRef.isOk():
    beacon_state_data_cache_hits.inc
    return ok epochRef.get()

  beacon_state_data_cache_misses.inc

  let
    ancestor = dag.epochAncestor(bid, epoch).valueOr:
      # If we got in here, the bid must be unknown or we would have gotten
      # _some_ ancestor (like the tail)
      return err("Requesting EpochRef for non-canonical block")

  var cache: StateCache
  if not updateState(dag, dag.epochRefState, ancestor, false, cache):
    return err("Could not load requested state")

  ok(dag.getEpochRef(dag.epochRefState, cache))

proc getEpochRef*(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch,
    preFinalized: bool): Result[EpochRef, cstring] =
  dag.getEpochRef(blck.bid, epoch, preFinalized)

proc getFinalizedEpochRef*(dag: ChainDAGRef): EpochRef =
  dag.getEpochRef(
    dag.finalizedHead.blck, dag.finalizedHead.slot.epoch, false).expect(
      "getEpochRef for finalized head should always succeed")

proc ancestorSlot*(
    dag: ChainDAGRef, state: ForkyHashedBeaconState, bid: BlockId,
    lowSlot: Slot): Opt[Slot] =
  ## Return common ancestor slot of `bid` and `state`, if at least `lowSlot`.
  ## Return `none` if no common ancestor is found with slot >= `lowSlot`.
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
    dag: ChainDAGRef, bdata: ForkedTrustedSignedBeaconBlock): Opt[Eth2Digest] =
  ## Compute the requested RANDAO mix for `bdata` without `state`, if possible.
  withBlck(bdata):
    when consensusFork >= ConsensusFork.Bellatrix:
      if forkyBlck.message.is_execution_block:
        var mix = eth2digest(forkyBlck.message.body.randao_reveal.toRaw())
        mix.data.mxor forkyBlck.message.body.execution_payload.prev_randao.data
        return ok mix
  Opt.none(Eth2Digest)

proc computeRandaoMix*(
    dag: ChainDAGRef, state: ForkyHashedBeaconState, bid: BlockId,
    lowSlot: Slot): Opt[Eth2Digest] =
  ## Compute the requested RANDAO mix for `bid` based on `state`.
  ## Return `none` if `state` and `bid` do not share a common ancestor
  ## with slot >= `lowSlot`.
  let ancestorSlot = ? dag.ancestorSlot(state, bid, lowSlot)
  doAssert ancestorSlot <= state.data.slot
  doAssert ancestorSlot <= bid.slot

  # If `blck` is post merge, RANDAO information is immediately available
  let
    bdata = ? dag.getForkedBlock(bid)
    fullMix = dag.computeRandaoMix(bdata)
  if fullMix.isSome:
    return fullMix

  # RANDAO mix has to be recomputed from `bid` and `state`
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

  # Mix in RANDAO from `bid`
  if ancestorSlot < bid.slot:
    withBlck(bdata):
      mix = eth2digest(forkyBlck.message.body.randao_reveal.toRaw())
    ? mixToAncestor(? dag.parent(bid))
  else:
    mix.reset()

  # Mix in RANDAO from `state`
  let ancestorEpoch = ancestorSlot.epoch
  if ancestorEpoch + EPOCHS_PER_HISTORICAL_VECTOR <= state.data.slot.epoch:
    return Opt.none(Eth2Digest)
  let mixRoot = state.dependent_root(ancestorEpoch + 1)
  if mixRoot.isZero:
    return Opt.none(Eth2Digest)
  ? mixToAncestor(? dag.getBlockId(mixRoot))
  mix.data.mxor state.data.get_randao_mix(ancestorEpoch).data

  ok mix

proc computeRandaoMixFromMemory*(
    dag: ChainDAGRef, bid: BlockId, lowSlot: Slot): Opt[Eth2Digest] =
  ## Compute requested RANDAO mix for `bid` from available states (~5 ms).
  template tryWithState(state: ForkedHashedBeaconState) =
    block:
      withState(state):
        let mix = dag.computeRandaoMix(forkyState, bid, lowSlot)
        if mix.isSome:
          return mix
  tryWithState dag.headState
  tryWithState dag.epochRefState
  tryWithState dag.clearanceState

proc computeRandaoMixFromDatabase*(
    dag: ChainDAGRef, bid: BlockId, lowSlot: Slot): Opt[Eth2Digest] =
  ## Compute requested RANDAO mix for `bid` using closest DB state (~500 ms).
  let state = newClone(dag.headState)
  ? dag.getNearbyState(state, bid, lowSlot)
  withState(state[]):
    dag.computeRandaoMix(forkyState, bid, lowSlot)

proc computeRandaoMix(
    dag: ChainDAGRef, bid: BlockId, lowSlot: Slot): Opt[Eth2Digest] =
  # Try to compute from states available in memory
  let mix = dag.computeRandaoMixFromMemory(bid, lowSlot)
  if mix.isSome:
    return mix

  # Fall back to database
  dag.computeRandaoMixFromDatabase(bid, lowSlot)

proc computeRandaoMix*(dag: ChainDAGRef, bid: BlockId): Opt[Eth2Digest] =
  ## Compute requested RANDAO mix for `bid`.
  const maxSlotDistance = SLOTS_PER_HISTORICAL_ROOT
  let lowSlot = max(bid.slot, maxSlotDistance.Slot) - maxSlotDistance
  dag.computeRandaoMix(bid, lowSlot)

proc lowSlotForAttesterShuffling*(epoch: Epoch): Slot =
  ## Return minimum slot that a state must share ancestry with a block history
  ## so that RANDAO at `epoch.attester_dependent_slot` can be computed.

  # A state must be somewhat recent so that `get_active_validator_indices`
  # for the queried `epoch` cannot be affected by any such skipped processing.
  const numDelayEpochs = compute_activation_exit_epoch(GENESIS_EPOCH).uint64
  let lowEpoch = max(epoch, (numDelayEpochs - 1).Epoch) - (numDelayEpochs - 1)
  lowEpoch.start_slot

proc computeShufflingRef*(
    dag: ChainDAGRef, state: ForkyHashedBeaconState,
    blck: BlockRef, epoch: Epoch): Opt[ShufflingRef] =
  ## Compute `ShufflingRef` for `blck@epoch` based on `state`.
  ## If `state` has unviable `get_active_validator_indices`, return `none`.

  let
    dependentBid = (? dag.atSlot(blck.bid, epoch.attester_dependent_slot)).bid
    lowSlot = epoch.lowSlotForAttesterShuffling
    mix = ? dag.computeRandaoMix(state, dependentBid, lowSlot)

  return ok ShufflingRef(
    epoch: epoch,
    attester_dependent_root: dependentBid.root,
    shuffled_active_validator_indices:
      state.data.get_shuffled_active_validator_indices(epoch, mix))

proc computeShufflingRefFromMemory*(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch): Opt[ShufflingRef] =
  ## Compute `ShufflingRef` from available states (~5 ms).
  template tryWithState(state: ForkedHashedBeaconState) =
    block:
      withState(state):
        let shufflingRef = dag.computeShufflingRef(forkyState, blck, epoch)
        if shufflingRef.isOk:
          return shufflingRef
  tryWithState dag.headState
  tryWithState dag.epochRefState
  tryWithState dag.clearanceState

proc computeShufflingRefFromDatabase*(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch): Opt[ShufflingRef] =
  ## Compute `ShufflingRef` for `blck@epoch` using closest DB state (~500 ms).
  let state = newClone(dag.headState)
  ? dag.getNearbyState(state, blck.bid, epoch.lowSlotForAttesterShuffling)
  withState(state[]):
    dag.computeShufflingRef(forkyState, blck, epoch)

proc computeShufflingRef(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch): Opt[ShufflingRef] =
  # Try to compute from states available in memory
  let shufflingRef = dag.computeShufflingRefFromMemory(blck, epoch)
  if shufflingRef.isOk:
    return shufflingRef

  # Fall back to database
  dag.computeShufflingRefFromDatabase(blck, epoch)

proc getShufflingRef*(
    dag: ChainDAGRef, blck: BlockRef, epoch: Epoch,
    preFinalized: bool): Opt[ShufflingRef] =
  ## Return the shuffling in the given history and epoch - this potentially is
  ## faster than returning a full EpochRef because the shuffling is determined
  ## an epoch in advance and therefore is less sensitive to reorgs
  var shufflingRef = dag.findShufflingRef(blck.bid, epoch)
  if shufflingRef.isSome:
    return shufflingRef

  # Use existing states to quickly compute the shuffling
  shufflingRef = dag.computeShufflingRef(blck, epoch)
  if shufflingRef.isSome:
    dag.putShufflingRef(shufflingRef.get)
    return shufflingRef

  # Last resort, this can take several seconds as this may replay states
  # TODO here, we could check the existing cached states and see if any one
  # has the right dependent root - unlike EpochRef, we don't need an _exact_
  # epoch match
  let epochRef = dag.getEpochRef(blck, epoch, preFinalized).valueOr:
    return Opt.none ShufflingRef
  dag.putShufflingRef(epochRef.shufflingRef)
  Opt.some epochRef.shufflingRef

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
    if startSlot < dag.horizon:
      # We will not backfill these
      debug "Got request for pre-horizon slot",
        startSlot, backfillSlot = dag.backfill.slot
    else:
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
        # We've either walked two full state snapshot lengths or hit the tail
        # and still can't find a matching state: this can happen when
        # starting the node from an arbitrary finalized checkpoint and not
        # backfilling the states
        notice "Request for pruned historical state",
          request = shortLog(bsi), tail = shortLog(dag.tail),
          cur = shortLog(cur)
        return false

      # Move slot by slot to capture epoch boundary states
      cur = dag.parentOrSlot(cur).valueOr:
        if not dag.getStateByParent(cur.bid, state):
          notice "Request for pruned historical state",
            request = shortLog(bsi), tail = shortLog(dag.tail),
            cur = shortLog(cur)
          return false
        break

    beacon_state_rewinds.inc()

  # Starting state has been assigned, either from memory or database
  let
    assignTick = Moment.now()
    ancestor {.used.} = withState(state):
      BlockSlotId.init(forkyState.latest_block_id, forkyState.data.slot)
    ancestorRoot {.used.} = getStateRoot(state)

  var info: ForkedEpochInfo
  # Time to replay all the blocks between then and now
  for i in countdown(ancestors.len - 1, 0):
    # Because the ancestors are in the database, there's no need to persist them
    # again. Also, because we're applying blocks that were loaded from the
    # database, we can skip certain checks that have already been performed
    # before adding the block to the database.
    if (let res = dag.applyBlock(state, ancestors[i], cache, info); res.isErr):
      warn "Failed to apply block from database",
        blck = shortLog(ancestors[i]),
        state_bid = shortLog(state.latest_block_id),
        error = res.error()

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
  # Delete state and mapping for a particular block+slot
  if not dag.isStateCheckpoint(bsi):
    return # We only ever save epoch states

  if (let root = dag.db.getStateRoot(bsi.bid.root, bsi.slot); root.isSome()):
    dag.db.withManyWrites:
      dag.db.delStateRoot(bsi.bid.root, bsi.slot)
      dag.db.delState(
        dag.cfg.consensusForkAtEpoch(bsi.slot.epoch), root.get())

proc pruneBlockSlot(dag: ChainDAGRef, bs: BlockSlot) =
  # TODO: should we move that disk I/O to `onSlotEnd`
  dag.delState(bs.toBlockSlotId().expect("not nil"))

  if bs.isProposed():
    # Update light client data
    dag.deleteLightClientData(bs.blck.bid)

    bs.blck.executionValid = true
    dag.forkBlocks.excl(KeyedBlockRef.init(bs.blck))
    discard dag.db.delBlock(
      dag.cfg.consensusForkAtEpoch(bs.blck.slot.epoch), bs.blck.root)

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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/sync/optimistic.md#helpers
template is_optimistic*(dag: ChainDAGRef, bid: BlockId): bool =
  let blck =
    if bid.slot <= dag.finalizedHead.slot:
      dag.finalizedHead.blck
    else:
      dag.getBlockRef(bid.root).expect("Non-finalized block is known")
  not blck.executionValid

proc markBlockVerified*(dag: ChainDAGRef, blck: BlockRef) =
  var cur = blck

  while true:
    cur.executionValid = true

    debug "markBlockVerified", blck = shortLog(cur)

    if cur.parent.isNil:
      break

    cur = cur.parent

    # Always check at least as far back as the parent so that when a new block
    # is added with executionValid already set, it stil sets the ancestors, to
    # the next valid in the chain.
    if cur.executionValid:
      return

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
    when consensusFork >= ConsensusFork.Altair:
      let
        period = sync_committee_period(slot)
        curPeriod = sync_committee_period(forkyState.data.slot)

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
    when consensusFork >= ConsensusFork.Altair:
      let
        period = sync_committee_period(slot)
        curPeriod = sync_committee_period(forkyState.data.slot)

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
      let bs = cur.get()
      if not isFinalizedStateSnapshot(bs.slot) and
          bs.slot != dag.tail.slot:
        dag.delState(bs)
      let tmp = cur.get()
      cur = dag.parentOrSlot(tmp)

  let statePruneTick = Moment.now()

  block: # Clean up old EpochRef instances
    # After finalization, we can clear up the epoch cache and save memory -
    # it will be recomputed if needed
    dag.epochRefs.delIt(it.epoch < dag.finalizedHead.slot.epoch)
    dag.shufflingRefs.delIt(it.epoch < dag.finalizedHead.slot.epoch)

  let epochRefPruneTick = Moment.now()

  dag.lastPrunePoint = dag.finalizedHead.toBlockSlotId().expect("not nil")

  debug "Pruned the state checkpoints and DAG caches.",
    statePruneDur = statePruneTick - startTick,
    epochRefPruneDur = epochRefPruneTick - statePruneTick

func pruneStep(horizon, lastHorizon, lastBlockHorizon: Slot):
    tuple[stateHorizon, blockHorizon: Slot] =
  ## Compute a reasonable incremental pruning step considering the current
  ## horizon, how far the database has been pruned already and where we want the
  ## tail to be - the return value shows the first state and block that we
  ## should _keep_ (inclusive).

  const SLOTS_PER_STATE_SNAPSHOT =
    uint64(EPOCHS_PER_STATE_SNAPSHOT * SLOTS_PER_EPOCH)

  let
    blockHorizon = block:
      let
        # Keep up with horizon if it's moving fast, ie if we're syncing
        maxSlots = max(horizon - lastHorizon, MAX_SLOTS_PER_PRUNE)

        # Move the block horizon cap with a lag so that it moves slot-by-slot
        # instead of a big jump every time we prune a state - assuming we
        # prune every slot, this makes us prune one slot at a time instead of
        # a burst of prunes (as computed by maxSlots) around every snapshot
        # change followed by no pruning for the rest of the period
        maxBlockHorizon =
          if horizon + 1 >= SLOTS_PER_STATE_SNAPSHOT:
            horizon + 1 - SLOTS_PER_STATE_SNAPSHOT
          else:
            Slot(0)

      # `lastBlockHorizon` captures the case where we're incrementally
      # pruning a database that hasn't been pruned for a while: it's
      # initialized to a pre-tail value on startup and moves to approach
      # `maxBlockHorizon`.
      min(maxBlockHorizon, lastBlockHorizon + maxSlots)

    # Round up such that we remove state only once blocks have been removed
    stateHorizon =
      ((blockHorizon + SLOTS_PER_STATE_SNAPSHOT - 1) div
        SLOTS_PER_STATE_SNAPSHOT) * SLOTS_PER_STATE_SNAPSHOT

  (Slot(stateHorizon), blockHorizon)

proc pruneHistory*(dag: ChainDAGRef, startup = false) =
  ## Perform an incremental pruning step of the history
  if dag.db.db.readOnly:
    return

  let
    horizon = dag.horizon()
    (stateHorizon, blockHorizon) = pruneStep(
      horizon, dag.lastHistoryPruneHorizon, dag.lastHistoryPruneBlockHorizon)

  doAssert blockHorizon <= stateHorizon,
    "we must never prune blocks while leaving the state"

  debug "Pruning history",
    horizon, blockHorizon, stateHorizon,
    lastHorizon = dag.lastHistoryPruneHorizon,
    lastBlockHorizon = dag.lastHistoryPruneBlockHorizon,
    tail = dag.tail, head = dag.head

  dag.lastHistoryPruneHorizon = horizon
  dag.lastHistoryPruneBlockHorizon = blockHorizon

  dag.db.withManyWrites:
    if stateHorizon > dag.tail.slot:
      # First, we want to see if it's possible to prune any states - we store one
      # state every EPOCHS_PER_STATE_SNAPSHOT, so this happens infrequently.

      var
        cur = dag.getBlockIdAtSlot(stateHorizon)

      var first = true
      while cur.isSome():
        let bs = cur.get()
        # We don't delete legacy states because the legacy database is openend
        # in read-only and slow to delete from due to its sub-optimal structure
        if dag.db.containsState(
            dag.cfg, bs.bid.root, bs.slot..bs.slot, legacy = first):
          if first:
            # We leave the state on the prune horizon intact and update the tail
            # to point to this state, indicating the new point in time from
            # which we can load states in general.
            debug "Updating tail", bs
            dag.db.putTailBlock(bs.bid.root)
            dag.tail = bs.bid
            first = false
          else:
            debug "Pruning historical state", bs
            dag.delState(bs)
        elif not bs.isProposed:
          trace "Reached already-pruned slot, done pruning states", bs
          break

        if bs.isProposed:
          # We store states either at the same slot at the block (checkpoint) or
          # by advancing the slot to the nearest epoch start - check both when
          # pruning
          cur = dag.parentOrSlot(bs)
        elif bs.slot.epoch > EPOCHS_PER_STATE_SNAPSHOT:
          # Jump one snapshot interval at a time, but don't prune genesis
          cur = dag.getBlockIdAtSlot(start_slot(bs.slot.epoch() - EPOCHS_PER_STATE_SNAPSHOT))
        else:
          break

    # Prune blocks after sanity-checking that we don't prune post-tail blocks -
    # this could happen if a state is missing at the expected state horizon and
    # would indicate a partially inconsistent database since the base
    # invariant is that there exists a state at the snapshot slot - better not
    # further mess things up regardless
    if blockHorizon > GENESIS_SLOT and blockHorizon <= dag.tail.slot:
      var
        # Leave the horizon block itself
        cur = dag.getBlockIdAtSlot(blockHorizon - 1).map(proc(x: auto): auto = x.bid)

      while cur.isSome:
        let
          bid = cur.get()
          fork = dag.cfg.consensusForkAtEpoch(bid.slot.epoch)

        if bid.slot == GENESIS_SLOT:
          # Leave genesis block for nostalgia and the REST API
          break

        if not dag.db.delBlock(fork, bid.root):
          # Stop at the first gap - this is typically the pruning point of the
          # previous call to pruneHistory. An inconsistent DB might have more
          # blocks beyond that point but we have no efficient way of detecting
          # that.
          break

        cur = dag.parent(bid)

    # TODO There have been varied reports of startup pruning causing long
    #      startup times - an incremental approach would be needed here also
    if false and
        startup and
        dag.cfg.consensusForkAtEpoch(blockHorizon.epoch) > ConsensusFork.Phase0:
      # Once during start, we'll clear all "old fork" data - this ensures we get
      # rid of any leftover junk in the tables - we do so after linear pruning
      # so as to "mostly" clean up the phase0 tables as well (which cannot be
      # pruned easily by fork) - one fork at a time, so as not to take too long

      let stateFork = dag.cfg.consensusForkAtEpoch(dag.tail.slot.epoch)
      var clearedStates = false
      if stateFork > ConsensusFork.Phase0:
        for fork in ConsensusFork.Phase0..<stateFork:
          if dag.db.clearStates(fork):
            clearedStates = true
            break

      let blockFork = dag.cfg.consensusForkAtEpoch(blockHorizon.epoch)
      if not clearedStates and blockFork > ConsensusFork.Phase0:
        for fork in ConsensusFork.Phase0..<blockFork:
          if dag.db.clearBlocks(fork):
            break

proc loadExecutionBlockHash*(dag: ChainDAGRef, bid: BlockId): Eth2Digest =
  let blockData = dag.getForkedBlock(bid).valueOr:
    return ZERO_HASH

  withBlck(blockData):
    when consensusFork >= ConsensusFork.Bellatrix:
      forkyBlck.message.body.execution_payload.block_hash
    else:
      ZERO_HASH

proc loadExecutionBlockHash*(dag: ChainDAGRef, blck: BlockRef): Eth2Digest =
  if blck.executionBlockHash.isNone:
    blck.executionBlockHash = Opt.some dag.loadExecutionBlockHash(blck.bid)
  blck.executionBlockHash.unsafeGet

from std/packedsets import PackedSet, incl, items

func getValidatorChangeStatuses(
    state: ForkedHashedBeaconState, vis: openArray[ValidatorIndex]):
    PackedSet[ValidatorIndex] =
  var res: PackedSet[ValidatorIndex]
  withState(state):
    for vi in vis:
      if  forkyState.data.validators[vi].withdrawal_credentials.data[0] ==
          BLS_WITHDRAWAL_PREFIX:
        res.incl vi
  res

func checkBlsToExecutionChanges(
    state: ForkedHashedBeaconState, vis: PackedSet[ValidatorIndex]): bool =
  # Within each fork, BLS_WITHDRAWAL_PREFIX to ETH1_ADDRESS_WITHDRAWAL_PREFIX
  # and never ETH1_ADDRESS_WITHDRAWAL_PREFIX to BLS_WITHDRAWAL_PREFIX. Latter
  # can still happen via reorgs.
  # Cases:
  # 1) unchanged (BLS_WITHDRAWAL_PREFIX or ETH1_ADDRESS_WITHDRAWAL_PREFIX) from
  #    old to new head.
  # 2) ETH1_ADDRESS_WITHDRAWAL_PREFIX to BLS_WITHDRAWAL_PREFIX
  # 3) BLS_WITHDRAWAL_PREFIX to ETH1_ADDRESS_WITHDRAWAL_PREFIX
  #
  # Only report (3), i.e. whether there were validator indices with withdrawal
  # credentials previously using BLS_WITHDRAWAL_PREFIX now using, instead, the
  # ETH1_ADDRESS_WITHDRAWAL_PREFIX prefix indicating a BLS to execution change
  # went through.
  #
  # Since it tracks head, it's possible reorgs trigger reporting the same
  # validator indices multiple times; this is fine.
  withState(state):
    anyIt( vis, forkyState.data.validators[it].has_eth1_withdrawal_credential)

proc updateHead*(
    dag: ChainDAGRef, newHead: BlockRef, quarantine: var Quarantine,
    knownValidators: openArray[ValidatorIndex]) =
  ## Update what we consider to be the current head, as given by the fork
  ## choice.
  ##
  ## The choice of head affects the choice of finalization point - the order
  ## of operations naturally becomes important here - after updating the head,
  ## blocks that were once considered potential candidates for a tree will
  ## now fall from grace, or no longer be considered resolved.
  doAssert not newHead.isNil()

  # Could happen if enough blocks get invalidated and would corrupt database -
  # When finalized checkpoint is empty, the slot may also be smaller
  doAssert newHead.slot >= dag.finalizedHead.slot or
    newHead == dag.finalizedHead.blck

  let lastHead = dag.head

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
    lastHeadKind = dag.headState.kind
    lastKnownValidatorsChangeStatuses = getValidatorChangeStatuses(
      dag.headState, knownValidators)

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

  if dag.headState.kind > lastHeadKind:
    case dag.headState.kind
    of ConsensusFork.Phase0 .. ConsensusFork.Bellatrix:
      discard
    of ConsensusFork.Capella:
      if dag.vanityLogs.onUpgradeToCapella != nil:
        dag.vanityLogs.onUpgradeToCapella()
    of ConsensusFork.Deneb:
      if dag.vanityLogs.onUpgradeToDeneb != nil:
        dag.vanityLogs.onUpgradeToDeneb()

  if  dag.vanityLogs.onKnownBlsToExecutionChange != nil and
      checkBlsToExecutionChanges(
        dag.headState, lastKnownValidatorsChangeStatuses):
    dag.vanityLogs.onKnownBlsToExecutionChange()

  dag.db.putHeadBlock(newHead.root)

  updateBeaconMetrics(dag.headState, dag.head.bid, cache)

  withState(dag.headState):
    when consensusFork >= ConsensusFork.Altair:
      dag.headSyncCommittees = forkyState.data.get_sync_committee_cache(cache)

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
      isOptHead = not newHead.executionValid

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
      isOptHead = not newHead.executionValid

    if not(isNil(dag.onHeadChanged)):
      let
        depRoot = withState(dag.headState): forkyState.proposer_dependent_root
        prevDepRoot = withState(dag.headState):
          forkyState.attester_dependent_root
        epochTransition = (finalizedHead != dag.finalizedHead)
        # TODO (cheatfate): Proper implementation required
        data = HeadChangeInfoObject.init(dag.head.slot, dag.head.root,
                                         getStateRoot(dag.headState),
                                         epochTransition, prevDepRoot,
                                         depRoot)
      dag.onHeadChanged(data)

  withState(dag.headState):
    # Every time the head changes, the "canonical" view of balances and other
    # state-related metrics change - notify the validator monitor.
    # Doing this update during head update ensures there's a reasonable number
    # of such updates happening - at most once per valid block.
    dag.validatorMonitor[].registerState(forkyState.data)

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

    if  dag.loadExecutionBlockHash(oldFinalizedHead.blck).isZero and
        not dag.loadExecutionBlockHash(dag.finalizedHead.blck).isZero and
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
  ## Lightweight check to see if it is likely that the given database has been
  ## initialized
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
  ## Initialize a database using the given state, which potentially may be a
  ## non-genesis state.
  ##
  ## When used with a non-genesis state, the resulting database will not be
  ## compatible with pre-22.11 versions.
  logScope:
    stateRoot = $getStateRoot(state)
    stateSlot = getStateField(state, slot)

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

      notice "Database initialized from genesis",
        blockRoot = $blck.root
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

      if db.getGenesisBlock().isSome():
        notice "Checkpoint written to database", blockRoot = $blockRoot
      else:
        notice "Database initialized from checkpoint", blockRoot = $blockRoot

proc getProposer*(
    dag: ChainDAGRef, head: BlockRef, slot: Slot): Opt[ValidatorIndex] =
  let
    epochRef = dag.getEpochRef(head.bid, slot.epoch(), false).valueOr:
      notice "Cannot load EpochRef for given head", head, slot, error
      return Opt.none(ValidatorIndex)

    slotInEpoch = slot.since_epoch_start()

  let proposer = epochRef.beacon_proposers[slotInEpoch]
  if proposer.isSome():
    if proposer.get().uint64 >= dag.db.immutableValidators.lenu64():
      # Sanity check - it should never happen that the key cache doesn't contain
      # a key for the selected proposer - that would mean that we somehow
      # created validators in the state without updating the cache!
      warn "Proposer key not found",
        keys = dag.db.immutableValidators.lenu64(), proposer = proposer.get()
      return Opt.none(ValidatorIndex)

  proposer

proc getProposalState*(
    dag: ChainDAGRef, head: BlockRef, slot: Slot, cache: var StateCache):
    Result[ref ForkedHashedBeaconState, cstring] =
  ## Return a state suitable for making proposals for the given head and slot -
  ## in particular, the state can be discarded after use and does not have a
  ## state root set

  # Start with the clearance state, since this one typically has been advanced
  # and thus has a hot hash tree cache
  let state = newClone(dag.clearanceState)

  var
    info = ForkedEpochInfo()
  if not state[].can_advance_slots(head.root, slot):
    # The last state root will be computed as part of block production, so skip
    # it now
    if not dag.updateState(
        state[], head.atSlot(slot - 1).toBlockSlotId().expect("not nil"),
        false, cache):
      error "Cannot get proposal state - skipping block production, database corrupt?",
        head = shortLog(head),
        slot
      return err("Cannot create proposal state")
  else:
    loadStateCache(dag, cache, head.bid, slot.epoch)

  if getStateField(state[], slot) < slot:
    process_slots(
      dag.cfg, state[], slot, cache, info,
      {skipLastStateRootCalculation}).expect("advancing 1 slot should not fail")

  ok state

func aggregateAll*(
  dag: ChainDAGRef,
  validator_indices: openArray[ValidatorIndex]): Result[CookedPubKey, cstring] =
  if validator_indices.len == 0:
    # Aggregation spec requires non-empty collection
    # - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04
    # Consensus specs require at least one attesting index in attestation
    # - https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
    return err("aggregate: no attesting keys")

  let
    firstKey = dag.validatorKey(validator_indices[0]).valueOr:
      return err("aggregate: invalid validator index")

  var aggregateKey{.noinit.}: AggregatePublicKey

  aggregateKey.init(firstKey)

  for i in 1 ..< validator_indices.len:
    let key = dag.validatorKey(validator_indices[i]).valueOr:
      return err("aggregate: invalid validator index")
    aggregateKey.aggregate(key)

  ok(finish(aggregateKey))

func aggregateAll*(
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
      let key = dag.validatorKey(validator_indices[i]).valueOr:
        return err("aggregate: invalid validator index")

      if inited:
        aggregateKey.aggregate(key)
      else:
        aggregateKey = AggregatePublicKey.init(key)
        inited = true

  if not inited:
    err("aggregate: no attesting keys")
  else:
    ok(finish(aggregateKey))

func needsBackfill*(dag: ChainDAGRef): bool =
  dag.backfill.slot > dag.horizon

proc rebuildIndex*(dag: ChainDAGRef) =
  ## After a checkpoint sync, we lack intermediate states to replay from - this
  ## function rebuilds them so that historical replay can take place again
  ## TODO the pruning of junk states could be moved to a separate function that
  ##      runs either on startup
  # First, we check what states we already have in the database - that allows
  # resuming the operation at any time
  let
    roots = dag.db.loadStateRoots()
    historicalRoots = getStateField(dag.headState, historical_roots).asSeq()
    historicalSummaries = dag.headState.historical_summaries.asSeq()

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
    if k[0] < dag.backfill.slot:
      continue # skip stuff for which we have no blocks

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

    if not dag.db.containsState(dag.cfg.consensusForkAtEpoch(k[0].epoch), v):
      continue # If it's not in the database..

    canonical[k[0].epoch div EPOCHS_PER_STATE_SNAPSHOT] = v

  let
    state = (ref ForkedHashedBeaconState)()

  var
    cache: StateCache
    info: ForkedEpochInfo
    tailBid: Opt[BlockId]
    states: int

  # `canonical` holds all slots at which a state is expected to appear, using a
  # zero root whenever a particular state is missing - this way, if there's
  # partial progress or gaps, they will be dealt with correctly
  for i, state_root in canonical.mpairs():
    let
      slot = Epoch(i * EPOCHS_PER_STATE_SNAPSHOT).start_slot

    if slot < dag.backfill.slot:
      # TODO if we have era files, we could try to load blocks from them at
      #      this point
      # TODO if we don't do the above, we can of course compute the starting `i`
      continue

    if tailBid.isNone():
      if state_root.isZero:
        # If we can find an era file with this state, use it as an alternative
        # starting point - ignore failures for now
        if dag.era.getState(
            historicalRoots, historicalSummaries, slot, state[]).isOk():
          state_root = getStateRoot(state[])

          withState(state[]): dag.db.putState(forkyState)
          tailBid = Opt.some state[].latest_block_id()

      else:
        if not dag.db.getState(
            dag.cfg.consensusForkAtEpoch(slot.epoch), state_root, state[],
            noRollback):
          fatal "Cannot load state, database corrupt or created for a different network?",
            state_root, slot
          quit 1
        tailBid = Opt.some state[].latest_block_id()

      continue

    if i == 0 or canonical[i - 1].isZero:
      reset(tailBid) # No unbroken history!
      continue

    if not state_root.isZero:
      states += 1
      continue

    let
      startSlot = Epoch((i - 1) * EPOCHS_PER_STATE_SNAPSHOT).start_slot

    info "Recreating state snapshot",
      slot, startStateRoot = canonical[i - 1],  startSlot

    if getStateRoot(state[]) != canonical[i - 1]:
      if not dag.db.getState(
          dag.cfg.consensusForkAtEpoch(startSlot.epoch), canonical[i - 1],
          state[], noRollback):
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
          error "Failed to apply block while building index",
            state_bid = shortLog(state[].latest_block_id()),
            error = res.error()
          return

        if slot.is_epoch:
          cache.prune(slot.epoch)

    process_slots(
      dag.cfg, state[], slot, cache, info,
      dag.updateFlags).expect("process_slots shouldn't fail when state slot is correct")

    withState(state[]):
      dag.db.putState(forkyState)
      dag.db.checkpoint()

      state_root = forkyState.root

  # Now that we've found a starting point and topped up with "intermediate"
  # states, we can update the tail to start at the starting point of the
  # first loadable state

  if tailBid.isSome():
    dag.tail = tailBid.get()
    dag.db.putTailBlock(dag.tail.root)

  if junk.len > 0:
    info "Dropping redundant states", states, redundant = junk.len

    for i in junk:
      dag.db.delStateRoot(i[0][1], i[0][0])
      dag.db.delState(dag.cfg.consensusForkAtEpoch(i[0][0].epoch), i[1])
