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
  block_pools_types

declareCounter beacon_reorgs_total, "Total occurrences of reorganizations of the chain" # On fork choice
declareCounter beacon_state_data_cache_hits, "hotDB.cachedStates hits"
declareCounter beacon_state_data_cache_misses, "hotDB.cachedStates misses"

logScope: topics = "hotdb"

proc putBlock*(hotDB: var HotDB, blockRoot: Eth2Digest, signedBlock: SignedBeaconBlock) {.inline.} =
  hotDB.db.putBlock(blockRoot, signedBlock)

proc updateStateData*(
  hotDB: HotDB, state: var StateData, bs: BlockSlot) {.gcsafe.}

template withState*(
    hotDB: HotDB, cache: var StateData, blockSlot: BlockSlot, body: untyped): untyped =
  ## Helper template that updates state to a particular BlockSlot - usage of
  ## cache is unsafe outside of block.
  ## TODO async transformations will lead to a race where cache gets updated
  ##      while waiting for future to complete - catch this here somehow?

  updateStateData(hotDB, cache, blockSlot)

  template hashedState(): HashedBeaconState {.inject, used.} = cache.data
  template state(): BeaconState {.inject, used.} = cache.data.data
  template blck(): BlockRef {.inject, used.} = cache.blck
  template root(): Eth2Digest {.inject, used.} = cache.data.root

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

func link*(parent, child: BlockRef) =
  doAssert (not (parent.root == Eth2Digest() or child.root == Eth2Digest())),
    "blocks missing root!"
  doAssert parent.root != child.root, "self-references not allowed"

  child.parent = parent
  parent.children.add(child)

func isAncestorOf*(a, b: BlockRef): bool =
  var b = b
  var depth = 0
  const maxDepth = (100'i64 * 365 * 24 * 60 * 60 div SECONDS_PER_SLOT.int)
  while true:
    if a == b: return true

    # for now, use an assert for block chain length since a chain this long
    # indicates a circular reference here..
    doAssert depth < maxDepth
    depth += 1

    if a.slot >= b.slot or b.parent.isNil:
      return false

    doAssert b.slot > b.parent.slot
    b = b.parent

func getAncestorAt*(blck: BlockRef, slot: Slot): BlockRef =
  ## Return the most recent block as of the time at `slot` that not more recent
  ## than `blck` itself

  var blck = blck

  var depth = 0
  const maxDepth = (100'i64 * 365 * 24 * 60 * 60 div SECONDS_PER_SLOT.int)

  while true:
    if blck.slot <= slot:
      return blck

    if blck.parent.isNil:
      return nil

    doAssert depth < maxDepth
    depth += 1

    blck = blck.parent

func get_ancestor*(blck: BlockRef, slot: Slot): BlockRef =
  ## https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/fork-choice.md#get_ancestor
  ## Return ancestor at slot, or nil if queried block is older
  var blck = blck

  var depth = 0
  const maxDepth = (100'i64 * 365 * 24 * 60 * 60 div SECONDS_PER_SLOT.int)

  while true:
    if blck.slot == slot:
      return blck

    if blck.slot < slot:
      return nil

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
  BlockSlot(blck: blck.getAncestorAt(slot), slot: slot)

func init*(T: type BlockRef, root: Eth2Digest, slot: Slot): BlockRef =
  BlockRef(
    root: root,
    slot: slot
  )

func init*(T: type BlockRef, root: Eth2Digest, blck: BeaconBlock): BlockRef =
  BlockRef.init(root, blck.slot)

proc init*(T: type HotDB, db: BeaconChainDB,
    updateFlags: UpdateFlags = {}): HotDB =
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

  var
    blocks = {tailRef.root: tailRef}.toTable()
    headRef: BlockRef

  if headRoot != tailRoot:
    var curRef: BlockRef

    for root, blck in db.getAncestors(headRoot):
      if root == tailRef.root:
        doAssert(not curRef.isNil)
        link(tailRef, curRef)
        curRef = curRef.parent
        break

      let newRef = BlockRef.init(root, blck.message)
      if curRef == nil:
        curRef = newRef
        headRef = newRef
      else:
        link(newRef, curRef)
        curRef = curRef.parent
      blocks[curRef.root] = curRef
      trace "Populating block hotDB", key = curRef.root, val = curRef

    doAssert curRef == tailRef,
      "head block does not lead to tail, database corrupt?"
  else:
    headRef = tailRef

  var
    bs = headRef.atSlot(headRef.slot)
    tmpState = (ref StateData)()

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

  # We presently save states on the epoch boundary - it means that the latest
  # state we loaded might be older than head block - nonetheless, it will be
  # from the same epoch as the head, thus the finalized and justified slots are
  # the same - these only change on epoch boundaries.
  let
    finalizedSlot =
       tmpState.data.data.finalized_checkpoint.epoch.compute_start_slot_at_epoch()
    finalizedHead = headRef.atSlot(finalizedSlot)
    justifiedSlot =
      tmpState.data.data.current_justified_checkpoint.epoch.compute_start_slot_at_epoch()
    justifiedHead = headRef.atSlot(justifiedSlot)
    head = Head(blck: headRef, justified: justifiedHead)

  doAssert justifiedHead.slot >= finalizedHead.slot,
    "justified head comes before finalized head - database corrupt?"

  let res = HotDB(
    blocks: blocks,
    tail: tailRef,
    head: head,
    finalizedHead: finalizedHead,
    db: db,
    heads: @[head],
    headState: tmpState[],
    justifiedState: tmpState[], # This is wrong but we'll update it below
    tmpState: tmpState[],

    # The only allowed flag right now is verifyFinalization, as the others all
    # allow skipping some validation.
    updateFlags: {verifyFinalization} * updateFlags
  )

  doAssert res.updateFlags in [{}, {verifyFinalization}]

  res.updateStateData(res.justifiedState, justifiedHead)
  res.updateStateData(res.headState, headRef.atSlot(headRef.slot))

  info "Block hotDB initialized",
    head = head.blck, justifiedHead, finalizedHead, tail = tailRef,
    totalBlocks = blocks.len

  res

proc getState(
    hotDB: HotDB, db: BeaconChainDB, stateRoot: Eth2Digest, blck: BlockRef,
    output: var StateData): bool =
  let outputAddr = unsafeAddr output # local scope
  func restore(v: var BeaconState) =
    if outputAddr == (unsafeAddr hotDB.headState):
      # TODO seeing the headState in the restore shouldn't happen - we load
      #      head states only when updating the head position, and by that time
      #      the database will have gone through enough sanity checks that
      #      SSZ exceptions shouldn't happen, which is when restore happens.
      #      Nonetheless, this is an ugly workaround that needs to go away
      doAssert false, "Cannot alias headState"

    outputAddr[] = hotDB.headState

  if not db.getState(stateRoot, output.data.data, restore):
    return false

  output.blck = blck
  output.data.root = stateRoot

  true

func getStateCacheIndex(hotDB: HotDB, blockRoot: Eth2Digest, slot: Slot): int =
  for i, cachedState in hotDB.cachedStates:
    let (cacheBlockRoot, cacheSlot, state) = cachedState
    if cacheBlockRoot == blockRoot and cacheSlot == slot:
      return i

  -1

proc putState*(hotDB: HotDB, state: HashedBeaconState, blck: BlockRef) =
  # TODO we save state at every epoch start but never remove them - we also
  #      potentially save multiple states per slot if reorgs happen, meaning
  #      we could easily see a state explosion
  logScope: pcs = "save_state_at_epoch_start"

  var rootWritten = false
  if state.data.slot != blck.slot:
    # This is a state that was produced by a skip slot for which there is no
    # block - we'll save the state root in the database in case we need to
    # replay the skip
    hotDB.db.putStateRoot(blck.root, state.data.slot, state.root)
    rootWritten = true

  if state.data.slot.isEpoch:
    if not hotDB.db.containsState(state.root):
      info "Storing state",
        blck = shortLog(blck),
        stateSlot = shortLog(state.data.slot),
        stateRoot = shortLog(state.root),
        cat = "caching"
      hotDB.db.putState(state.root, state.data)
      if not rootWritten:
        hotDB.db.putStateRoot(blck.root, state.data.slot, state.root)

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
  let stateCacheIndex = hotDB.getStateCacheIndex(blck.root, state.data.slot)
  if stateCacheIndex == -1:
    # Could use a deque or similar, but want simpler structure, and the data
    # items are small and few.
    const MAX_CACHE_SIZE = 32
    insert(hotDB.cachedStates, (blck.root, state.data.slot, newClone(state)))
    while hotDB.cachedStates.len > MAX_CACHE_SIZE:
      discard hotDB.cachedStates.pop()
    let cacheLen = hotDB.cachedStates.len
    trace "HotDB.putState(): state cache updated", cacheLen
    doAssert cacheLen > 0 and cacheLen <= MAX_CACHE_SIZE

func getRef*(hotDB: HotDB, root: Eth2Digest): BlockRef =
  ## Retrieve a resolved block reference, if available
  hotDB.blocks.getOrDefault(root, nil)

func getBlockRange*(
    hotDB: HotDB, startSlot: Slot, skipStep: Natural,
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
  let count = output.len
  trace "getBlockRange entered",
    head = shortLog(hotDB.head.blck.root), count, startSlot, skipStep

  let
    skipStep = max(1, skipStep) # Treat 0 step as 1
    endSlot = startSlot + uint64(count * skipStep)

  var
    b = hotDB.head.blck.atSlot(endSlot)
    o = count
  for i in 0..<count:
    for j in 0..<skipStep:
      b = b.parent
    if b.blck.slot == b.slot:
      dec o
      output[o] = b.blck

  # Make sure the given input is cleared, just in case
  for i in 0..<o:
    output[i] = nil

  o # Return the index of the first non-nil item in the output

func getBlockBySlot*(hotDB: HotDB, slot: Slot): BlockRef =
  ## Retrieves the first block in the current canonical chain
  ## with slot number less or equal to `slot`.
  hotDB.head.blck.atSlot(slot).blck

func getBlockByPreciseSlot*(hotDB: HotDB, slot: Slot): BlockRef =
  ## Retrieves a block from the canonical chain with a slot
  ## number equal to `slot`.
  let found = hotDB.getBlockBySlot(slot)
  if found.slot != slot: found else: nil

proc get*(hotDB: HotDB, blck: BlockRef): BlockData =
  ## Retrieve the associated block body of a block reference
  doAssert (not blck.isNil), "Trying to get nil BlockRef"

  let data = hotDB.db.getBlock(blck.root)
  doAssert data.isSome, "BlockRef without backing data, database corrupt?"

  BlockData(data: data.get(), refs: blck)

proc get*(hotDB: HotDB, root: Eth2Digest): Option[BlockData] =
  ## Retrieve a resolved block reference and its associated body, if available
  let refs = hotDB.getRef(root)

  if not refs.isNil:
    some(hotDB.get(refs))
  else:
    none(BlockData)

proc skipAndUpdateState(
    hotDB: HotDB,
    state: var HashedBeaconState, blck: BlockRef, slot: Slot, save: bool) =
  while state.data.slot < slot:
    # Process slots one at a time in case afterUpdate needs to see empty states
    # TODO when replaying, we already do this query when loading the ancestors -
    #      save and reuse
    # TODO possibly we should keep this in memory for the hot blocks
    let nextStateRoot = hotDB.db.getStateRoot(blck.root, state.data.slot + 1)
    advance_slot(state, nextStateRoot, hotDB.updateFlags)

    if save:
      hotDB.putState(state, blck)

proc skipAndUpdateState(
    hotDB: HotDB,
    state: var StateData, blck: BlockData, flags: UpdateFlags, save: bool): bool =

  hotDB.skipAndUpdateState(
    state.data, blck.refs, blck.data.message.slot - 1, save)

  var statePtr = unsafeAddr state # safe because `restore` is locally scoped
  func restore(v: var HashedBeaconState) =
    doAssert (addr(statePtr.data) == addr v)
    statePtr[] = hotDB.headState

  let ok = state_transition(
    state.data, blck.data, flags + hotDB.updateFlags, restore)
  if ok and save:
    hotDB.putState(state.data, blck.refs)

  ok

proc rewindState(hotDB: HotDB, state: var StateData, bs: BlockSlot):
    seq[BlockData] =
  logScope: pcs = "replay_state"

  var ancestors = @[hotDB.get(bs.blck)]
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
      let tmp = hotDB.db.getStateRoot(bs.blck.root, bs.slot)
      if tmp.isSome() and hotDB.db.containsState(tmp.get()):
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
      ancestors.add(hotDB.get(parBs.blck))

    # TODO investigate replacing with getStateCached, by refactoring whole
    # function. Empirically, this becomes pretty rare once good caches are
    # used in the front-end.
    let idx = hotDB.getStateCacheIndex(parBs.blck.root, parBs.slot)
    if idx >= 0:
      state.data = hotDB.cachedStates[idx].state[]
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
    if (let tmp = hotDB.db.getStateRoot(parBs.blck.root, parBs.slot); tmp.isSome()):
      if hotDB.db.containsState(tmp.get):
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
    found = hotDB.getState(hotDB.db, root, ancestor.refs, state)

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

proc getStateDataCached(hotDB: HotDB, state: var StateData, bs: BlockSlot): bool =
  # This pointedly does not run rewindState or state_transition, but otherwise
  # mostly matches updateStateData(...), because it's too expensive to run the
  # rewindState(...)/skipAndUpdateState(...)/state_transition(...) procs, when
  # each hash_tree_root(...) consumes a nontrivial fraction of a second.
  when false:
    # For debugging/development purposes to assess required lookback window for
    # any given use case.
    doAssert state.data.data.slot <= bs.slot + 4

  let idx = hotDB.getStateCacheIndex(bs.blck.root, bs.slot)
  if idx >= 0:
    state.data = hotDB.cachedStates[idx].state[]
    state.blck = bs.blck
    beacon_state_data_cache_hits.inc()
    return true

  # In-memory caches didn't hit. Try main blockpool database. This is slower
  # than the caches due to SSZ (de)serializing and disk I/O, so prefer them.
  beacon_state_data_cache_misses.inc()
  if (let tmp = hotDB.db.getStateRoot(bs.blck.root, bs.slot); tmp.isSome()):
    return hotDB.getState(hotDB.db, tmp.get(), bs.blck, state)

  false

proc updateStateData*(hotDB: HotDB, state: var StateData, bs: BlockSlot) =
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
      hotDB.skipAndUpdateState(state.data, bs.blck, bs.slot, true)

    return # State already at the right spot

  if hotDB.getStateDataCached(state, bs):
    return

  let ancestors = rewindState(hotDB, state, bs)

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
      hotDB.skipAndUpdateState(
        state, ancestors[i],
        {skipBlsValidation, skipMerkleValidation, skipStateRootValidation},
        false)
    doAssert ok, "Blocks in database should never fail to apply.."

  # We save states here - blocks were guaranteed to have passed through the save
  # function once at least, but not so for empty slots!
  hotDB.skipAndUpdateState(state.data, bs.blck, bs.slot, true)

  state.blck = bs.blck

proc loadTailState*(hotDB: HotDB): StateData =
  ## Load the state associated with the current tail in the hotDB
  let stateRoot = hotDB.db.getBlock(hotDB.tail.root).get().message.state_root
  let found = hotDB.getState(hotDB.db, stateRoot, hotDB.tail, result)
  # TODO turn into regular error, this can happen
  doAssert found, "Failed to load tail state, database corrupt?"

proc delState(hotDB: HotDB, bs: BlockSlot) =
  # Delete state state and mapping for a particular block+slot
  if (let root = hotDB.db.getStateRoot(bs.blck.root, bs.slot); root.isSome()):
    hotDB.db.delState(root.get())

proc updateHead*(hotDB: HotDB, newHead: BlockRef) =
  ## Update what we consider to be the current head, as given by the fork
  ## choice.
  ## The choice of head affects the choice of finalization point - the order
  ## of operations naturally becomes important here - after updating the head,
  ## blocks that were once considered potential candidates for a tree will
  ## now fall from grace, or no longer be considered resolved.
  doAssert newHead.parent != nil or newHead.slot == 0
  logScope: pcs = "fork_choice"

  if hotDB.head.blck == newHead:
    info "No head block update",
      head = shortLog(newHead),
      cat = "fork_choice"

    return

  let
    lastHead = hotDB.head
  hotDB.db.putHeadBlock(newHead.root)

  # Start off by making sure we have the right state
  updateStateData(
    hotDB, hotDB.headState, BlockSlot(blck: newHead, slot: newHead.slot))

  let
    justifiedSlot = hotDB.headState.data.data
                      .current_justified_checkpoint
                      .epoch
                      .compute_start_slot_at_epoch()
    justifiedBS = newHead.atSlot(justifiedSlot)

  hotDB.head = Head(blck: newHead, justified: justifiedBS)
  updateStateData(hotDB, hotDB.justifiedState, justifiedBS)

  # TODO isAncestorOf may be expensive - too expensive?
  if not lastHead.blck.isAncestorOf(newHead):
    info "Updated head block (new parent)",
      lastHead = shortLog(lastHead.blck),
      headParent = shortLog(newHead.parent),
      stateRoot = shortLog(hotDB.headState.data.root),
      headBlock = shortLog(hotDB.headState.blck),
      stateSlot = shortLog(hotDB.headState.data.data.slot),
      justifiedEpoch = shortLog(hotDB.headState.data.data.current_justified_checkpoint.epoch),
      finalizedEpoch = shortLog(hotDB.headState.data.data.finalized_checkpoint.epoch),
      cat = "fork_choice"

    # A reasonable criterion for "reorganizations of the chain"
    beacon_reorgs_total.inc()
  else:
    info "Updated head block",
      stateRoot = shortLog(hotDB.headState.data.root),
      headBlock = shortLog(hotDB.headState.blck),
      stateSlot = shortLog(hotDB.headState.data.data.slot),
      justifiedEpoch = shortLog(hotDB.headState.data.data.current_justified_checkpoint.epoch),
      finalizedEpoch = shortLog(hotDB.headState.data.data.finalized_checkpoint.epoch),
      cat = "fork_choice"

  let
    finalizedEpochStartSlot =
      hotDB.headState.data.data.finalized_checkpoint.epoch.
      compute_start_slot_at_epoch()
    # TODO there might not be a block at the epoch boundary - what then?
    finalizedHead = newHead.atSlot(finalizedEpochStartSlot)

  doAssert (not finalizedHead.blck.isNil),
    "Block graph should always lead to a finalized block"

  if finalizedHead != hotDB.finalizedHead:
    block: # Remove states, walking slot by slot
      discard
      # TODO this is very aggressive - in theory all our operations start at
      #      the finalized block so all states before that can be wiped..
      # TODO this is disabled for now because the logic for initializing the
      #      block hotDB and potentially a few other places depend on certain
      #      states (like the tail state) being present. It's also problematic
      #      because it is not clear what happens when tail and finalized states
      #      happen on an empty slot..
      # var cur = finalizedHead
      # while cur != hotDB.finalizedHead:
      #  cur = cur.parent
      #  hotDB.delState(cur)

    block: # Clean up block refs, walking block by block
      var cur = finalizedHead.blck
      while cur != hotDB.finalizedHead.blck:
        # Finalization means that we choose a single chain as the canonical one -
        # it also means we're no longer interested in any branches from that chain
        # up to the finalization point.
        # The new finalized head should not be cleaned! We start at its parent and
        # clean everything including the old finalized head.
        cur = cur.parent

        # TODO what about attestations? we need to drop those too, though they
        #      *should* be pretty harmless
        if cur.parent != nil: # This happens for the genesis / tail block
          for child in cur.parent.children:
            if child != cur:
              # TODO also remove states associated with the unviable forks!
              # TODO the easiest thing to do here would probably be to use
              #      hotDB.heads to find unviable heads, then walk those chains
              #      and remove everything.. currently, if there's a child with
              #      children of its own, those children will not be pruned
              #      correctly from the database
              hotDB.blocks.del(child.root)
              hotDB.db.delBlock(child.root)
          cur.parent.children = @[cur]

    hotDB.finalizedHead = finalizedHead

    let hlen = hotDB.heads.len
    for i in 0..<hlen:
      let n = hlen - i - 1
      if not hotDB.finalizedHead.blck.isAncestorOf(hotDB.heads[n].blck):
        # Any heads that are not derived from the newly finalized block are no
        # longer viable candidates for future head selection
        hotDB.heads.del(n)

    info "Finalized block",
      finalizedHead = shortLog(finalizedHead),
      head = shortLog(newHead),
      heads = hotDB.heads.len,
      cat = "fork_choice"

    # TODO prune everything before weak subjectivity period

func latestJustifiedBlock*(hotDB: HotDB): BlockSlot =
  ## Return the most recent block that is justified and at least as recent
  ## as the latest finalized block

  doAssert hotDB.heads.len > 0,
    "We should have at least the genesis block in heaads"
  doAssert (not hotDB.head.blck.isNil()),
    "Genesis block will be head, if nothing else"

  # Prefer stability: use justified block from current head to break ties!
  result = hotDB.head.justified
  for head in hotDB.heads[1 ..< ^0]:
    if head.justified.slot > result.slot:
      result = head.justified

proc isInitialized*(T: type HotDB, db: BeaconChainDB): bool =
  let
    headBlockRoot = db.getHeadBlock()
    tailBlockRoot = db.getTailBlock()

  if not (headBlockRoot.isSome() and tailBlockRoot.isSome()):
    return false

  let
    headBlock = db.getBlock(headBlockRoot.get())
    tailBlock = db.getBlock(tailBlockRoot.get())

  if not (headBlock.isSome() and tailBlock.isSome()):
    return false

  if not db.containsState(tailBlock.get().message.state_root):
    return false

  return true

proc preInit*(
    T: type HotDB, db: BeaconChainDB, state: BeaconState,
    signedBlock: SignedBeaconBlock) =
  # write a genesis state, the way the HotDB expects it to be stored in
  # database
  # TODO probably should just init a blockpool with the freshly written
  #      state - but there's more refactoring needed to make it nice - doing
  #      a minimal patch for now..
  let
    blockRoot = hash_tree_root(signedBlock.message)

  doAssert signedBlock.message.state_root == hash_tree_root(state)
  notice "New database from snapshot",
    blockRoot = shortLog(blockRoot),
    stateRoot = shortLog(signedBlock.message.state_root),
    fork = state.fork,
    validators = state.validators.len(),
    cat = "initialization"

  db.putState(state)
  db.putBlock(signedBlock)
  db.putTailBlock(blockRoot)
  db.putHeadBlock(blockRoot)
  db.putStateRoot(blockRoot, state.slot, signedBlock.message.state_root)

proc getProposer*(hotDB: HotDB, head: BlockRef, slot: Slot): Option[ValidatorPubKey] =
  hotDB.withState(hotDB.tmpState, head.atSlot(slot)):
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
