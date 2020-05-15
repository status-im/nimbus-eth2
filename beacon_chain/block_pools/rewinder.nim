# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronicles, options, tables,
  metrics,
  ../ssz, ../beacon_chain_db, ../state_transition, ../extras,
  ../spec/[crypto, datatypes, digest, helpers, validator],

  block_pools_types, hot_db

declareCounter beacon_state_data_cache_hits, "rewinder.cachedStates hits"
declareCounter beacon_state_data_cache_misses, "rewinder.cachedStates misses"

logScope: topics = "rewinder"

proc updateStateData*(
  rewinder: Rewinder, state: var StateData, bs: BlockSlot) {.gcsafe.}

template withState*(
    rewinder: Rewinder, cache: var StateData, blockSlot: BlockSlot, body: untyped): untyped =
  ## Helper template that updates state to a particular BlockSlot - usage of
  ## cache is unsafe outside of block.
  ## TODO async transformations will lead to a race where cache gets updated
  ##      while waiting for future to complete - catch this here somehow?

  updateStateData(rewinder, cache, blockSlot)

  template hashedState(): HashedBeaconState {.inject, used.} = cache.data
  template state(): BeaconState {.inject, used.} = cache.data.data
  template blck(): BlockRef {.inject, used.} = cache.blck
  template root(): Eth2Digest {.inject, used.} = cache.data.root

  body

proc getMostRecentState*(db: BeaconChainDB, bs: BlockSlot): StateData =
  ## Find the most recent state starting from a (block, slot) pair
  var tmpState = default(StateData)
  var bs = bs

  # Now that we have a head block, we need to find the most recent state that
  # we have saved in the database
  while bs.blck != nil:
    let root = db.getStateRoot(bs.blck.root, bs.slot)
    if root.isSome():
      # TODO load StateData from BeaconChainDB
      # We save state root separately for empty slots which means we might
      # sometimes not find a state even though we saved its state root
      if db.getState(root.get(), tmpState.data.data, noRollback):
        tmpState.data.root = root.get()
        tmpState.blck = bs.blck

        break

    bs = bs.parent() # Iterate slot by slot in case there's a gap!

  if tmpState.blck == nil:
    warn "No state found in head history, database corrupt?"
    # TODO Potentially we could recover from here instead of crashing - what
    #      would be a good recovery model?
    raiseAssert "No state found in head history, database corrupt?"

  return tmpState

proc init*(T: type Rewinder,
           db: BeaconChainDB,
           headBlockSlot: BlockSlot,
           justifiedHead: BlockSlot,
           mostRecentState: StateData,
           updateFlags: UpdateFlags = {}): Rewinder =
  result = Rewinder(
    db: db,
    headState: mostRecentState,
    justifiedState: mostRecentState, # This is wrong but we'll update it below
    tmpState: mostRecentState,

    # The only allowed flag right now is verifyFinalization, as the others all
    # allow skipping some validation.
    updateFlags: {verifyFinalization} * updateFlags
  )

  doAssert result.updateFlags in [{}, {verifyFinalization}]

  result.updateStateData(result.justifiedState, justifiedHead)
  result.updateStateData(result.headState, headBlockSlot)

proc get*(rewinder: Rewinder, blck: BlockRef): BlockData =
  ## Retrieve the associated block body of a block reference
  # TODO: duplicated in hot_db
  doAssert (not blck.isNil), "Trying to get nil BlockRef"

  let data = rewinder.db.getBlock(blck.root)
  doAssert data.isSome, "BlockRef without backing data, database corrupt?"

  BlockData(data: data.get(), refs: blck)

proc getState(
    rewinder: Rewinder, db: BeaconChainDB, stateRoot: Eth2Digest, blck: BlockRef,
    output: var StateData): bool =
  let outputAddr = unsafeAddr output # local scope
  func restore(v: var BeaconState) =
    if outputAddr == (unsafeAddr rewinder.headState):
      # TODO seeing the headState in the restore shouldn't happen - we load
      #      head states only when updating the head position, and by that time
      #      the database will have gone through enough sanity checks that
      #      SSZ exceptions shouldn't happen, which is when restore happens.
      #      Nonetheless, this is an ugly workaround that needs to go away
      doAssert false, "Cannot alias headState"

    outputAddr[] = rewinder.headState

  if not db.getState(stateRoot, output.data.data, restore):
    return false

  output.blck = blck
  output.data.root = stateRoot

  true

func getStateCacheIndex(rewinder: Rewinder, blockRoot: Eth2Digest, slot: Slot): int =
  for i, cachedState in rewinder.cachedStates:
    let (cacheBlockRoot, cacheSlot, state) = cachedState
    if cacheBlockRoot == blockRoot and cacheSlot == slot:
      return i

  -1

proc putState*(rewinder: Rewinder, state: HashedBeaconState, blck: BlockRef) =
  # TODO we save state at every epoch start but never remove them - we also
  #      potentially save multiple states per slot if reorgs happen, meaning
  #      we could easily see a state explosion
  logScope: pcs = "save_state_at_epoch_start"

  var rootWritten = false
  if state.data.slot != blck.slot:
    # This is a state that was produced by a skip slot for which there is no
    # block - we'll save the state root in the database in case we need to
    # replay the skip
    rewinder.db.putStateRoot(blck.root, state.data.slot, state.root)
    rootWritten = true

  if state.data.slot.isEpoch:
    if not rewinder.db.containsState(state.root):
      info "Storing state",
        blck = shortLog(blck),
        stateSlot = shortLog(state.data.slot),
        stateRoot = shortLog(state.root),
        cat = "caching"
      rewinder.db.putState(state.root, state.data)
      if not rootWritten:
        rewinder.db.putStateRoot(blck.root, state.data.slot, state.root)

  # Need to be able to efficiently access states for both attestation
  # aggregation and to process block proposals going back to the last
  # finalized slot. Ideally to avoid potential combinatiorial forking
  # storage and/or memory constraints could CoW, up to and including,
  # in particular, hash_tree_root() which is expensive to do 30 times
  # since the previous epoch, to efficiently state_transition back to
  # desired slot. However, none of that's in place, so there are both
  # expensive, repeated BeaconState copies as well as computationally
  # time-consuming-near-end-of-epoch hash tree roots. The latter are,
  # effectively, naïvely O(n^2) in slot number otherwise, so when the
  # slots become in the mid-to-high-20s it's spending all its time in
  # pointlessly repeated calculations of prefix-state-transitions. An
  # intermediate time/memory workaround involves storing only mapping
  # between BlockRefs, or BlockSlots, and the BeaconState tree roots,
  # but that still involves tens of megabytes worth of copying, along
  # with the concomitant memory allocator and GC load. Instead, use a
  # more memory-intensive (but more conceptually straightforward, and
  # faster) strategy to just store, for the most recent slots.
  let stateCacheIndex = rewinder.getStateCacheIndex(blck.root, state.data.slot)
  if stateCacheIndex == -1:
    # Could use a deque or similar, but want simpler structure, and the data
    # items are small and few.
    const MAX_CACHE_SIZE = 32
    insert(rewinder.cachedStates, (blck.root, state.data.slot, newClone(state)))
    while rewinder.cachedStates.len > MAX_CACHE_SIZE:
      discard rewinder.cachedStates.pop()
    let cacheLen = rewinder.cachedStates.len
    trace "Rewinder.putState(): state cache updated", cacheLen
    doAssert cacheLen > 0 and cacheLen <= MAX_CACHE_SIZE


proc skipAndUpdateState(
    rewinder: Rewinder,
    state: var HashedBeaconState, blck: BlockRef, slot: Slot, save: bool) =
  while state.data.slot < slot:
    # Process slots one at a time in case afterUpdate needs to see empty states
    # TODO when replaying, we already do this query when loading the ancestors -
    #      save and reuse
    # TODO possibly we should keep this in memory for the hot blocks
    let nextStateRoot = rewinder.db.getStateRoot(blck.root, state.data.slot + 1)
    advance_slot(state, nextStateRoot, rewinder.updateFlags)

    if save:
      rewinder.putState(state, blck)

proc skipAndUpdateState(
    rewinder: Rewinder,
    state: var StateData, blck: BlockData, flags: UpdateFlags, save: bool): bool =

  rewinder.skipAndUpdateState(
    state.data, blck.refs, blck.data.message.slot - 1, save)

  var statePtr = unsafeAddr state # safe because `restore` is locally scoped
  func restore(v: var HashedBeaconState) =
    doAssert (addr(statePtr.data) == addr v)
    statePtr[] = rewinder.headState

  let ok = state_transition(
    state.data, blck.data, flags + rewinder.updateFlags, restore)
  if ok and save:
    rewinder.putState(state.data, blck.refs)

  ok

proc rewindState(rewinder: Rewinder, state: var StateData, bs: BlockSlot):
    seq[BlockData] =
  logScope: pcs = "replay_state"

  var ancestors = @[rewinder.get(bs.blck)]
  # Common case: the last block applied is the parent of the block to apply:
  if not bs.blck.parent.isNil and state.blck.root == bs.blck.parent.root and
      state.data.data.slot < bs.blck.slot:
    return ancestors

  # It appears that the parent root of the proposed new block is different from
  # what we expected. We will have to rewind the state to a point along the
  # chain of ancestors of the new block. We will do this by loading each
  # successive parent block and checking if we can find the corresponding state
  # in the database.
  var
    stateRoot = block:
      let tmp = rewinder.db.getStateRoot(bs.blck.root, bs.slot)
      if tmp.isSome() and rewinder.db.containsState(tmp.get()):
        tmp
      else:
        # State roots are sometimes kept in database even though state is not
        err(Opt[Eth2Digest])
    curBs = bs

  while stateRoot.isNone():
    let parBs = curBs.parent()
    if parBs.blck.isNil:
      break # Bug probably!

    if parBs.blck != curBs.blck:
      ancestors.add(rewinder.get(parBs.blck))

    # TODO investigate replacing with getStateCached, by refactoring whole
    # function. Empirically, this becomes pretty rare once good caches are
    # used in the front-end.
    let idx = rewinder.getStateCacheIndex(parBs.blck.root, parBs.slot)
    if idx >= 0:
      state.data = rewinder.cachedStates[idx].state[]
      let ancestor = ancestors.pop()
      state.blck = ancestor.refs

      beacon_state_data_cache_hits.inc()
      trace "Replaying state transitions via in-memory cache",
        stateSlot = shortLog(state.data.data.slot),
        ancestorStateRoot = shortLog(ancestor.data.message.state_root),
        ancestorStateSlot = shortLog(state.data.data.slot),
        slot = shortLog(bs.slot),
        blockRoot = shortLog(bs.blck.root),
        ancestors = ancestors.len,
        cat = "replay_state"

      return ancestors

    beacon_state_data_cache_misses.inc()
    if (let tmp = rewinder.db.getStateRoot(parBs.blck.root, parBs.slot); tmp.isSome()):
      if rewinder.db.containsState(tmp.get):
        stateRoot = tmp
        break

    curBs = parBs

  if stateRoot.isNone():
    # TODO this should only happen if the database is corrupt - we walked the
    #      list of parent blocks and couldn't find a corresponding state in the
    #      database, which should never happen (at least we should have the
    #      tail state in there!)
    error "Couldn't find ancestor state root!",
      blockRoot = shortLog(bs.blck.root),
      blockSlot = shortLog(bs.blck.slot),
      slot = shortLog(bs.slot),
      cat = "crash"
    doAssert false, "Oh noes, we passed big bang!"

  let
    ancestor = ancestors.pop()
    root = stateRoot.get()
    found = rewinder.getState(rewinder.db, root, ancestor.refs, state)

  if not found:
    # TODO this should only happen if the database is corrupt - we walked the
    #      list of parent blocks and couldn't find a corresponding state in the
    #      database, which should never happen (at least we should have the
    #      tail state in there!)
    error "Couldn't find ancestor state or block parent missing!",
      blockRoot = shortLog(bs.blck.root),
      blockSlot = shortLog(bs.blck.slot),
      slot = shortLog(bs.slot),
      cat = "crash"
    doAssert false, "Oh noes, we passed big bang!"

  trace "Replaying state transitions",
    stateSlot = shortLog(state.data.data.slot),
    ancestorStateRoot = shortLog(ancestor.data.message.state_root),
    ancestorStateSlot = shortLog(state.data.data.slot),
    slot = shortLog(bs.slot),
    blockRoot = shortLog(bs.blck.root),
    ancestors = ancestors.len,
    cat = "replay_state"

  ancestors

proc getStateDataCached(rewinder: Rewinder, state: var StateData, bs: BlockSlot): bool =
  # This pointedly does not run rewindState or state_transition, but otherwise
  # mostly matches updateStateData(...), because it's too expensive to run the
  # rewindState(...)/skipAndUpdateState(...)/state_transition(...) procs, when
  # each hash_tree_root(...) consumes a nontrivial fraction of a second.
  when false:
    # For debugging/development purposes to assess required lookback window for
    # any given use case.
    doAssert state.data.data.slot <= bs.slot + 4

  let idx = rewinder.getStateCacheIndex(bs.blck.root, bs.slot)
  if idx >= 0:
    state.data = rewinder.cachedStates[idx].state[]
    state.blck = bs.blck
    beacon_state_data_cache_hits.inc()
    return true

  # In-memory caches didn't hit. Try main blockpool database. This is slower
  # than the caches due to SSZ (de)serializing and disk I/O, so prefer them.
  beacon_state_data_cache_misses.inc()
  if (let tmp = rewinder.db.getStateRoot(bs.blck.root, bs.slot); tmp.isSome()):
    return rewinder.getState(rewinder.db, tmp.get(), bs.blck, state)

  false

proc updateStateData*(rewinder: Rewinder, state: var StateData, bs: BlockSlot) =
  ## Rewind or advance state such that it matches the given block and slot -
  ## this may include replaying from an earlier snapshot if blck is on a
  ## different branch or has advanced to a higher slot number than slot
  ## If slot is higher than blck.slot, replay will fill in with empty/non-block
  ## slots, else it is ignored

  # We need to check the slot because the state might have moved forwards
  # without blocks
  if state.blck.root == bs.blck.root and state.data.data.slot <= bs.slot:
    if state.data.data.slot != bs.slot:
      # Might be that we're moving to the same block but later slot
      rewinder.skipAndUpdateState(state.data, bs.blck, bs.slot, true)

    return # State already at the right spot

  if rewinder.getStateDataCached(state, bs):
    return

  let ancestors = rewindState(rewinder, state, bs)

  # If we come this far, we found the state root. The last block on the stack
  # is the one that produced this particular state, so we can pop it
  # TODO it might be possible to use the latest block hashes from the state to
  #      do this more efficiently.. whatever!

  # Time to replay all the blocks between then and now. We skip one because
  # it's the one that we found the state with, and it has already been
  # applied. Pathologically quadratic in slot number, naïvely.
  for i in countdown(ancestors.len - 1, 0):
    # Because the ancestors are in the database, there's no need to persist them
    # again. Also, because we're applying blocks that were loaded from the
    # database, we can skip certain checks that have already been performed
    # before adding the block to the database. In particular, this means that
    # no state root calculation will take place here, because we can load
    # the final state root from the block itself.
    let ok =
      rewinder.skipAndUpdateState(
        state, ancestors[i],
        {skipBlsValidation, skipMerkleValidation, skipStateRootValidation},
        false)
    doAssert ok, "Blocks in database should never fail to apply.."

  # We save states here - blocks were guaranteed to have passed through the save
  # function once at least, but not so for empty slots!
  rewinder.skipAndUpdateState(state.data, bs.blck, bs.slot, true)

  state.blck = bs.blck

proc loadTailState*(rewinder: Rewinder, hotDB: HotDB): StateData =
  ## Load the state associated with the current tail in the HotDB
  let stateRoot = rewinder.db.getBlock(hotDB.tail.root).get().message.state_root
  let found = rewinder.getState(rewinder.db, stateRoot, hotDB.tail, result)
  # TODO turn into regular error, this can happen
  doAssert found, "Failed to load tail state, database corrupt?"

proc delState(rewinder: Rewinder, bs: BlockSlot) =
  # Delete state state and mapping for a particular block+slot
  if (let root = rewinder.db.getStateRoot(bs.blck.root, bs.slot); root.isSome()):
    rewinder.db.delState(root.get())

proc getProposer*(rewinder: Rewinder, blockSlot: BlockSlot): Option[ValidatorPubKey] =
  let slot = blockSlot.slot
  rewinder.withState(rewinder.tmpState, blockSlot):
    var cache = get_empty_per_epoch_cache()

    # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#validator-assignments
    let proposerIdx = get_beacon_proposer_index(state, cache)
    if proposerIdx.isNone:
      warn "Missing proposer index",
        slot=slot,
        epoch=slot.compute_epoch_at_slot,
        num_validators=state.validators.len,
        active_validators=
          get_active_validator_indices(state, slot.compute_epoch_at_slot),
        balances=state.balances
      return

    return some(state.validators[proposerIdx.get()].pubkey)
