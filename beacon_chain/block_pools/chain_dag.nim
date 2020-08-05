# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard libraries
  chronicles, options, sequtils, tables, sets,
  # Status libraries
  metrics,
  # Internals
  ../ssz/merkleization, ../beacon_chain_db, ../extras,
  ../spec/[
    crypto, datatypes, digest, helpers, validator, state_transition,
    beaconstate],
  block_pools_types

export block_pools_types

declareCounter beacon_reorgs_total, "Total occurrences of reorganizations of the chain" # On fork choice
declareCounter beacon_state_data_cache_hits, "EpochRef hits"
declareCounter beacon_state_data_cache_misses, "EpochRef misses"

logScope: topics = "hotdb"

proc putBlock*(
    dag: var ChainDAGRef, signedBlock: SignedBeaconBlock) =
  dag.db.putBlock(signedBlock)

proc updateStateData*(
  dag: ChainDAGRef, state: var StateData, bs: BlockSlot) {.gcsafe.}

template withState*(
    dag: ChainDAGRef, cache: var StateData, blockSlot: BlockSlot, body: untyped): untyped =
  ## Helper template that updates state to a particular BlockSlot - usage of
  ## cache is unsafe outside of block.
  ## TODO async transformations will lead to a race where cache gets updated
  ##      while waiting for future to complete - catch this here somehow?

  updateStateData(dag, cache, blockSlot)

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

proc init*(T: type EpochRef, state: BeaconState, cache: var StateCache): T =
  let
    epoch = state.get_current_epoch()
    epochRef = EpochRef(
      epoch: epoch,
      current_justified_checkpoint: state.current_justified_checkpoint,
      finalized_checkpoint: state.finalized_checkpoint,
      shuffled_active_validator_indices:
        cache.get_shuffled_active_validator_indices(state, epoch))
  for i in 0'u64..<SLOTS_PER_EPOCH:
    let idx = get_beacon_proposer_index(
      state, cache, epoch.compute_start_slot_at_epoch() + i)
    if idx.isSome():
      epochRef.beacon_proposers[i] =
        some((idx.get(), state.validators[idx.get].pubkey))

  epochRef.validator_keys = mapIt(state.validators.toSeq, it.pubkey)
  epochRef

func link*(parent, child: BlockRef) =
  doAssert (not (parent.root == Eth2Digest() or child.root == Eth2Digest())),
    "blocks missing root!"
  doAssert parent.root != child.root, "self-references not allowed"

  child.parent = parent

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

func get_ancestor*(blck: BlockRef, slot: Slot): BlockRef =
  ## https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/fork-choice.md#get_ancestor
  ## Return the most recent block as of the time at `slot` that not more recent
  ## than `blck` itself
  doAssert not blck.isNil

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

func atEpochEnd*(blck: BlockRef, epoch: Epoch): BlockSlot =
  ## Return the BlockSlot corresponding to the last slot in the given epoch
  atSlot(blck, (epoch + 1).compute_start_slot_at_epoch - 1)

proc getEpochInfo*(blck: BlockRef, state: BeaconState, cache: var StateCache): EpochRef =
  # This is the only intended mechanism by which to get an EpochRef
  let
    state_epoch = state.get_current_epoch()
    matching_epochinfo = blck.epochsInfo.filterIt(it.epoch == state_epoch)

  if matching_epochinfo.len == 0:
    let epochInfo = EpochRef.init(state, cache)

    # Don't use BlockRef caching as far as the epoch where the active
    # validator indices can diverge.
    if (compute_activation_exit_epoch(blck.slot.compute_epoch_at_slot) >
        state_epoch):
      blck.epochsInfo.add(epochInfo)
    trace "chain_dag.getEpochInfo: back-filling parent.epochInfo",
      state_slot = state.slot
    epochInfo
  elif matching_epochinfo.len == 1:
    matching_epochinfo[0]
  else:
    raiseAssert "multiple EpochRefs per epoch per BlockRef invalid"

proc getEpochInfo*(blck: BlockRef, state: BeaconState): EpochRef =
  # This is the only intended mechanism by which to get an EpochRef
  var cache = StateCache()
  getEpochInfo(blck, state, cache)

proc getEpochCache*(blck: BlockRef, state: BeaconState): StateCache =
  var tmp = StateCache() # TODO Resolve circular init issue
  let epochInfo = getEpochInfo(blck, state, tmp)
  if epochInfo.epoch > 0:
    # When doing state transitioning, both the current and previous epochs are
    # useful from a cache perspective since attestations may come from either -
    # we'll use the last slot from the epoch because it is more likely to
    # be filled in already, compared to the first slot where the block might
    # be from the epoch before.
    let
      prevEpochBlck = blck.atEpochEnd(epochInfo.epoch - 1).blck

    for ei in prevEpochBlck.epochsInfo:
      if ei.epoch == epochInfo.epoch - 1:
        result.shuffled_active_validator_indices[ei.epoch] =
          ei.shuffled_active_validator_indices

  result.shuffled_active_validator_indices[state.get_current_epoch()] =
      epochInfo.shuffled_active_validator_indices
  for i, idx in epochInfo.beacon_proposers:
    result.beacon_proposer_indices[
      epochInfo.epoch.compute_start_slot_at_epoch + i] =
        if idx.isSome: some(idx.get()[0]) else: none(ValidatorIndex)

func init(T: type BlockRef, root: Eth2Digest, slot: Slot): BlockRef =
  BlockRef(
    root: root,
    slot: slot
  )

func init*(T: type BlockRef, root: Eth2Digest, blck: SomeBeaconBlock): BlockRef =
  BlockRef.init(root, blck.slot)

proc init*(T: type ChainDAGRef,
           preset: RuntimePreset,
           db: BeaconChainDB,
           updateFlags: UpdateFlags = {}): ChainDAGRef =
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

    for blck in db.getAncestors(headRoot):
      if blck.root == tailRef.root:
        doAssert(not curRef.isNil)
        link(tailRef, curRef)
        curRef = curRef.parent
        break

      let newRef = BlockRef.init(blck.root, blck.message)
      if curRef == nil:
        curRef = newRef
        headRef = newRef
      else:
        link(newRef, curRef)
        curRef = curRef.parent
      blocks[curRef.root] = curRef
      trace "Populating block dag", key = curRef.root, val = curRef

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
    finalizedHead = headRef.atEpochStart(
      tmpState.data.data.finalized_checkpoint.epoch)

  let res = ChainDAGRef(
    blocks: blocks,
    tail: tailRef,
    head: headRef,
    finalizedHead: finalizedHead,
    db: db,
    heads: @[headRef],
    headState: tmpState[],
    tmpState: tmpState[],
    clearanceState: tmpState[],
    balanceState: tmpState[],

    # The only allowed flag right now is verifyFinalization, as the others all
    # allow skipping some validation.
    updateFlags: {verifyFinalization} * updateFlags,
    runtimePreset: preset,
  )

  doAssert res.updateFlags in [{}, {verifyFinalization}]

  res.updateStateData(res.headState, headRef.atSlot(headRef.slot))
  res.clearanceState = res.headState
  res.balanceState = res.headState

  info "Block dag initialized",
    head = shortLog(headRef),
    finalizedHead = shortLog(finalizedHead),
    tail = shortLog(tailRef),
    totalBlocks = blocks.len

  res

proc getEpochRef*(dag: ChainDAGRef, blck: BlockRef, epoch: Epoch): EpochRef =
  var bs = blck.atEpochEnd(epoch)

  while true:
    # Any block from within the same epoch will carry the same epochinfo, so
    # we start at the most recent one
    for e in bs.blck.epochsInfo:
      if e.epoch == epoch:
        beacon_state_data_cache_hits.inc
        return e
    if bs.slot == epoch.compute_start_slot_at_epoch:
      break
    bs = bs.parent

  beacon_state_data_cache_misses.inc

  dag.withState(dag.tmpState, bs):
    var cache = StateCache()
    getEpochInfo(blck, state, cache)

proc getState(
    dag: ChainDAGRef, db: BeaconChainDB, stateRoot: Eth2Digest, blck: BlockRef,
    output: var StateData): bool =
  let outputAddr = unsafeAddr output # local scope
  func restore(v: var BeaconState) =
    if outputAddr == (unsafeAddr dag.headState):
      # TODO seeing the headState in the restore shouldn't happen - we load
      #      head states only when updating the head position, and by that time
      #      the database will have gone through enough sanity checks that
      #      SSZ exceptions shouldn't happen, which is when restore happens.
      #      Nonetheless, this is an ugly workaround that needs to go away
      doAssert false, "Cannot alias headState"

    assign(outputAddr[], dag.headState)

  if not db.getState(stateRoot, output.data.data, restore):
    return false

  output.blck = blck
  output.data.root = stateRoot

  true

proc putState*(dag: ChainDAGRef, state: HashedBeaconState, blck: BlockRef) =
  # TODO we save state at every epoch start but never remove them - we also
  #      potentially save multiple states per slot if reorgs happen, meaning
  #      we could easily see a state explosion
  logScope: pcs = "save_state_at_epoch_start"

  var rootWritten = false
  if state.data.slot != blck.slot:
    # This is a state that was produced by a skip slot for which there is no
    # block - we'll save the state root in the database in case we need to
    # replay the skip
    dag.db.putStateRoot(blck.root, state.data.slot, state.root)
    rootWritten = true

  if state.data.slot.isEpoch:
    if not dag.db.containsState(state.root):
      info "Storing state",
        blck = shortLog(blck),
        stateSlot = shortLog(state.data.slot),
        stateRoot = shortLog(state.root)

      dag.db.putState(state.root, state.data)
      if not rootWritten:
        dag.db.putStateRoot(blck.root, state.data.slot, state.root)

func getRef*(dag: ChainDAGRef, root: Eth2Digest): BlockRef =
  ## Retrieve a resolved block reference, if available
  dag.blocks.getOrDefault(root, nil)

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
  let requestedCount = output.lenu64
  trace "getBlockRange entered",
    head = shortLog(dag.head.root), requestedCount, startSlot, skipStep

  let
    headSlot = dag.head.slot
    runway = if headSlot > startSlot: uint64(headSlot - startSlot)
             else: return output.len # Identical to returning an empty set of block as indicated above
    skipStep = max(skipStep, 1) # Treat 0 step as 1
    count = min(1'u64 + (runway div skipStep), requestedCount)
    endSlot = startSlot + count * skipStep

  var
    b = dag.head.atSlot(endSlot)
    o = output.len
  for i in 0..<count:
    for j in 0..<skipStep:
      b = b.parent
    if b.blck.slot == b.slot:
      dec o
      output[o] = b.blck

  o # Return the index of the first non-nil item in the output

func getBlockBySlot*(dag: ChainDAGRef, slot: Slot): BlockRef =
  ## Retrieves the first block in the current canonical chain
  ## with slot number less or equal to `slot`.
  dag.head.atSlot(slot).blck

func getBlockByPreciseSlot*(dag: ChainDAGRef, slot: Slot): BlockRef =
  ## Retrieves a block from the canonical chain with a slot
  ## number equal to `slot`.
  let found = dag.getBlockBySlot(slot)
  if found.slot != slot: found else: nil

proc get*(dag: ChainDAGRef, blck: BlockRef): BlockData =
  ## Retrieve the associated block body of a block reference
  doAssert (not blck.isNil), "Trying to get nil BlockRef"

  let data = dag.db.getBlock(blck.root)
  doAssert data.isSome, "BlockRef without backing data, database corrupt?"

  BlockData(data: data.get(), refs: blck)

proc get*(dag: ChainDAGRef, root: Eth2Digest): Option[BlockData] =
  ## Retrieve a resolved block reference and its associated body, if available
  let refs = dag.getRef(root)

  if not refs.isNil:
    some(dag.get(refs))
  else:
    none(BlockData)

proc skipAndUpdateState(
    dag: ChainDAGRef,
    state: var HashedBeaconState, blck: BlockRef, slot: Slot, save: bool) =
  while state.data.slot < slot:
    # Process slots one at a time in case afterUpdate needs to see empty states
    var stateCache = getEpochCache(blck, state.data)
    advance_slot(state, dag.updateFlags, stateCache)

    if save:
      dag.putState(state, blck)

proc skipAndUpdateState(
    dag: ChainDAGRef,
    state: var StateData, blck: BlockData, flags: UpdateFlags, save: bool): bool =

  dag.skipAndUpdateState(
    state.data, blck.refs, blck.data.message.slot - 1, save)

  var statePtr = unsafeAddr state # safe because `restore` is locally scoped
  func restore(v: var HashedBeaconState) =
    doAssert (addr(statePtr.data) == addr v)
    statePtr[] = dag.headState

  var stateCache = getEpochCache(blck.refs, state.data.data)
  let ok = state_transition(
    dag.runtimePreset, state.data, blck.data,
    stateCache, flags + dag.updateFlags, restore)

  if ok and save:
    dag.putState(state.data, blck.refs)

  ok

proc rewindState(
    dag: ChainDAGRef, state: var StateData, bs: BlockSlot): seq[BlockRef] =
  logScope:
    blockSlot = shortLog(bs)
    pcs = "replay_state"

  var ancestors = @[bs.blck]
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
      let tmp = dag.db.getStateRoot(bs.blck.root, bs.slot)
      if tmp.isSome() and dag.db.containsState(tmp.get()):
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
      ancestors.add(parBs.blck)

    if (let tmp = dag.db.getStateRoot(parBs.blck.root, parBs.slot); tmp.isSome()):
      if dag.db.containsState(tmp.get):
        stateRoot = tmp
        break

    curBs = parBs

  if stateRoot.isNone():
    # TODO this should only happen if the database is corrupt - we walked the
    #      list of parent blocks and couldn't find a corresponding state in the
    #      database, which should never happen (at least we should have the
    #      tail state in there!)
    fatal "Couldn't find ancestor state root!"
    doAssert false, "Oh noes, we passed big bang!"

  let
    ancestor = ancestors.pop()
    root = stateRoot.get()
    found = dag.getState(dag.db, root, ancestor, state)

  if not found:
    # TODO this should only happen if the database is corrupt - we walked the
    #      list of parent blocks and couldn't find a corresponding state in the
    #      database, which should never happen (at least we should have the
    #      tail state in there!)
    fatal "Couldn't find ancestor state or block parent missing!"
    doAssert false, "Oh noes, we passed big bang!"

  trace "Replaying state transitions",
    stateSlot = shortLog(state.data.data.slot),
    ancestors = ancestors.len

  ancestors

proc getStateDataCached(
    dag: ChainDAGRef, state: var StateData, bs: BlockSlot): bool =
  # This pointedly does not run rewindState or state_transition, but otherwise
  # mostly matches updateStateData(...), because it's too expensive to run the
  # rewindState(...)/skipAndUpdateState(...)/state_transition(...) procs, when
  # each hash_tree_root(...) consumes a nontrivial fraction of a second.

  # In-memory caches didn't hit. Try main block pool database. This is slower
  # than the caches due to SSZ (de)serializing and disk I/O, so prefer them.
  if (let tmp = dag.db.getStateRoot(bs.blck.root, bs.slot); tmp.isSome()):
    return dag.getState(dag.db, tmp.get(), bs.blck, state)

  false

proc updateStateData*(
    dag: ChainDAGRef, state: var StateData, bs: BlockSlot) =
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
      dag.skipAndUpdateState(state.data, bs.blck, bs.slot, true)

    return # State already at the right spot

  if dag.getStateDataCached(state, bs):
    return

  let ancestors = rewindState(dag, state, bs)

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
      dag.skipAndUpdateState(state, dag.get(ancestors[i]), {}, false)
    doAssert ok, "Blocks in database should never fail to apply.."

  # We save states here - blocks were guaranteed to have passed through the save
  # function once at least, but not so for empty slots!
  dag.skipAndUpdateState(state.data, bs.blck, bs.slot, true)

  state.blck = bs.blck

proc loadTailState*(dag: ChainDAGRef): StateData =
  ## Load the state associated with the current tail in the dag
  let stateRoot = dag.db.getBlock(dag.tail.root).get().message.state_root
  let found = dag.getState(dag.db, stateRoot, dag.tail, result)
  # TODO turn into regular error, this can happen
  doAssert found, "Failed to load tail state, database corrupt?"

proc delState(dag: ChainDAGRef, bs: BlockSlot) =
  # Delete state state and mapping for a particular block+slot
  if (let root = dag.db.getStateRoot(bs.blck.root, bs.slot); root.isSome()):
    dag.db.delState(root.get())

proc updateHead*(dag: ChainDAGRef, newHead: BlockRef) =
  ## Update what we consider to be the current head, as given by the fork
  ## choice.
  ## The choice of head affects the choice of finalization point - the order
  ## of operations naturally becomes important here - after updating the head,
  ## blocks that were once considered potential candidates for a tree will
  ## now fall from grace, or no longer be considered resolved.
  doAssert newHead.parent != nil or newHead.slot == 0
  logScope:
    newHead = shortLog(newHead)
    pcs = "fork_choice"

  if dag.head == newHead:
    debug "No head block update"

    return

  let
    lastHead = dag.head
  dag.db.putHeadBlock(newHead.root)

  # Start off by making sure we have the right state - as a special case, we'll
  # check the last block that was cleared by clearance - it might be just the
  # thing we're looking for

  if dag.clearanceState.blck == newHead and
      dag.clearanceState.data.data.slot == newHead.slot:
    assign(dag.headState, dag.clearanceState)
  else:
    updateStateData(
      dag, dag.headState, newHead.atSlot(newHead.slot))

  dag.head = newHead

  if not lastHead.isAncestorOf(newHead):
    info "Updated head block with reorg",
      lastHead = shortLog(lastHead),
      headParent = shortLog(newHead.parent),
      stateRoot = shortLog(dag.headState.data.root),
      headBlock = shortLog(dag.headState.blck),
      stateSlot = shortLog(dag.headState.data.data.slot),
      justified = shortLog(dag.headState.data.data.current_justified_checkpoint),
      finalized = shortLog(dag.headState.data.data.finalized_checkpoint)

    # A reasonable criterion for "reorganizations of the chain"
    beacon_reorgs_total.inc()
  else:
    info "Updated head block",
      stateRoot = shortLog(dag.headState.data.root),
      headBlock = shortLog(dag.headState.blck),
      stateSlot = shortLog(dag.headState.data.data.slot),
      justified = shortLog(dag.headState.data.data.current_justified_checkpoint),
      finalized = shortLog(dag.headState.data.data.finalized_checkpoint)
  let
    finalizedHead = newHead.atEpochStart(
      dag.headState.data.data.finalized_checkpoint.epoch)

  doAssert (not finalizedHead.blck.isNil),
    "Block graph should always lead to a finalized block"

  if finalizedHead != dag.finalizedHead:
    block: # Remove states, walking slot by slot
      discard
      # TODO this is very aggressive - in theory all our operations start at
      #      the finalized block so all states before that can be wiped..
      # TODO this is disabled for now because the logic for initializing the
      #      block dag and potentially a few other places depend on certain
      #      states (like the tail state) being present. It's also problematic
      #      because it is not clear what happens when tail and finalized states
      #      happen on an empty slot..
      # var cur = finalizedHead
      # while cur != dag.finalizedHead:
      #  cur = cur.parent
      #  dag.delState(cur)

    block: # Clean up block refs, walking block by block
      # Finalization means that we choose a single chain as the canonical one -
      # it also means we're no longer interested in any branches from that chain
      # up to the finalization point
      let hlen = dag.heads.len
      for i in 0..<hlen:
        let n = hlen - i - 1
        let head = dag.heads[n]
        if finalizedHead.blck.isAncestorOf(head):
          continue

        var cur = head.atSlot(head.slot)
        while not cur.blck.isAncestorOf(finalizedHead.blck):
          # TODO there may be more empty states here: those that have a slot
          #      higher than head.slot and those near the branch point - one
          #      needs to be careful though because those close to the branch
          #      point should not necessarily be cleaned up
          dag.delState(cur)

          if cur.blck.slot == cur.slot:
            dag.blocks.del(cur.blck.root)
            dag.db.delBlock(cur.blck.root)

          if cur.blck.parent.isNil:
            break
          cur = cur.parent

        dag.heads.del(n)
    block: # Clean up old EpochRef instances
      # After finalization, we can clear up the epoch cache and save memory -
      # it will be recomputed if needed
      # TODO don't store recomputed pre-finalization epoch refs
      var tmp = finalizedHead.blck
      while tmp != dag.finalizedHead.blck:
        # leave the epoch cache in the last block of the epoch..
        tmp = tmp.parent
        tmp.epochsInfo = @[]

    dag.finalizedHead = finalizedHead

    info "Reached new finalization checkpoint",
      finalizedHead = shortLog(finalizedHead),
      heads = dag.heads.len

proc isInitialized*(T: type ChainDAGRef, db: BeaconChainDB): bool =
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

  true

proc preInit*(
    T: type ChainDAGRef, db: BeaconChainDB, state: BeaconState,
    signedBlock: SignedBeaconBlock) =
  # write a genesis state, the way the ChainDAGRef expects it to be stored in
  # database
  # TODO probably should just init a block pool with the freshly written
  #      state - but there's more refactoring needed to make it nice - doing
  #      a minimal patch for now..
  doAssert signedBlock.message.state_root == hash_tree_root(state)
  notice "New database from snapshot",
    blockRoot = shortLog(signedBlock.root),
    stateRoot = shortLog(signedBlock.message.state_root),
    fork = state.fork,
    validators = state.validators.len()

  db.putState(state)
  db.putBlock(signedBlock)
  db.putTailBlock(signedBlock.root)
  db.putHeadBlock(signedBlock.root)
  db.putStateRoot(signedBlock.root, state.slot, signedBlock.message.state_root)

proc getProposer*(
    dag: ChainDAGRef, head: BlockRef, slot: Slot):
    Option[(ValidatorIndex, ValidatorPubKey)] =
  let
    epochRef = dag.getEpochRef(head, slot.compute_epoch_at_slot())
    slotInEpoch = slot - slot.compute_epoch_at_slot().compute_start_slot_at_epoch()

  epochRef.beacon_proposers[slotInEpoch]
