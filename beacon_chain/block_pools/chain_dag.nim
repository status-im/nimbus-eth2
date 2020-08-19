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
declareCounter beacon_state_rewinds, "State database rewinds"

logScope: topics = "chaindag"

proc putBlock*(
    dag: var ChainDAGRef, signedBlock: SignedBeaconBlock) =
  dag.db.putBlock(signedBlock)

proc updateStateData*(
  dag: ChainDAGRef, state: var StateData, bs: BlockSlot,
  cache: var StateCache) {.gcsafe.}

template withState*(
    dag: ChainDAGRef, stateData: var StateData, blockSlot: BlockSlot,
    body: untyped): untyped =
  ## Helper template that updates stateData to a particular BlockSlot - usage of
  ## stateData is unsafe outside of block.
  ## TODO async transformations will lead to a race where stateData gets updated
  ##      while waiting for future to complete - catch this here somehow?

  var cache {.inject.} = blockSlot.blck.getStateCache(blockSlot.slot.epoch())
  updateStateData(dag, stateData, blockSlot, cache)

  template hashedState(): HashedBeaconState {.inject, used.} = stateData.data
  template state(): BeaconState {.inject, used.} = stateData.data.data
  template blck(): BlockRef {.inject, used.} = stateData.blck
  template root(): Eth2Digest {.inject, used.} = stateData.data.root

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

func get_effective_balances*(state: BeaconState): seq[Gwei] =
  ## Get the balances from a state as counted for fork choice
  result.newSeq(state.validators.len) # zero-init

  let epoch = state.get_current_epoch()

  for i in 0 ..< result.len:
    # All non-active validators have a 0 balance
    template validator: Validator = state.validators[i]
    if validator.is_active_validator(epoch):
      result[i] = validator.effective_balance

proc init*(
    T: type EpochRef, state: BeaconState, cache: var StateCache,
    prevEpoch: EpochRef): T =
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

  # Validator sets typically don't change between epochs - a more efficient
  # scheme could be devised where parts of the validator key set is reused
  # between epochs because in a single history, the validator set only
  # grows - this however is a trivially implementable compromise.

  # The validators root is cached in the state, so we can quickly compare
  # it to see if it remains unchanged - effective balances in the validator
  # information may however result in a different root, even if the public
  # keys are the same

  let validators_root = hash_tree_root(state.validators)

  template sameKeys(a: openArray[ValidatorPubKey], b: openArray[Validator]): bool =
    if a.len != b.len:
      false
    else:
      block:
        var ret = true
        for i, key in a:
          if key != b[i].pubkey:
            ret = false
            break
        ret

  if prevEpoch != nil and (
    prevEpoch.validator_key_store[0] == hash_tree_root(state.validators) or
      sameKeys(prevEpoch.validator_key_store[1][], state.validators.asSeq)):
    epochRef.validator_key_store =
      (validators_root, prevEpoch.validator_key_store[1])
  else:
    epochRef.validator_key_store = (
      hash_tree_root(state.validators),
      newClone(mapIt(state.validators.toSeq, it.pubkey)))

  # When fork choice runs, it will need the effective balance of the justified
  # epoch - we pre-load the balances here to avoid rewinding the justified
  # state later
  epochRef.effective_balances = get_effective_balances(state)

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

func epochAncestor*(blck: BlockRef, epoch: Epoch): BlockSlot =
  ## The state transition works by storing information from blocks in a
  ## "working" area until the epoch transition, then batching work collected
  ## during the epoch. Thus, last block in the ancestor epochs is the block
  ## that has an impact on epoch currently considered.
  ##
  ## This function returns a BlockSlot pointing to that epoch boundary, ie the
  ## boundary where the last block has been applied to the state and epoch
  ## processing has been done - we will store epoch caches in that particular
  ## block so that any block in the dag that needs it can find it easily. In
  ## particular, if empty slot processing is done, there may be multiple epoch
  ## caches found there.
  var blck = blck
  while blck.slot.epoch >= epoch and not blck.parent.isNil:
    blck = blck.parent

  blck.atEpochStart(epoch)

proc getStateCache*(blck: BlockRef, epoch: Epoch): StateCache =
  # When creating a state cache, we want the current and the previous epoch
  # information to be preloaded as both of these are used in state transition
  # functions

  var res = StateCache()
  template load(e: Epoch) =
    let ancestor = blck.epochAncestor(epoch)
    for epochRef in ancestor.blck.epochRefs:
      if epochRef.epoch == e:
        res.shuffled_active_validator_indices[epochRef.epoch] =
          epochRef.shuffled_active_validator_indices

        if epochRef.epoch == epoch:
          for i, idx in epochRef.beacon_proposers:
            res.beacon_proposer_indices[
              epoch.compute_start_slot_at_epoch + i] =
                if idx.isSome: some(idx.get()[0]) else: none(ValidatorIndex)

        break

  load(epoch)

  if epoch > 0:
    load(epoch - 1)

  res

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
    cur = headRef.atSlot(headRef.slot)
    tmpState = (ref StateData)()

  # Now that we have a head block, we need to find the most recent state that
  # we have saved in the database
  while cur.blck != nil:
    let root = db.getStateRoot(cur.blck.root, cur.slot)
    if root.isSome():
      # TODO load StateData from BeaconChainDB
      # We save state root separately for empty slots which means we might
      # sometimes not find a state even though we saved its state root
      if db.getState(root.get(), tmpState.data.data, noRollback):
        tmpState.data.root = root.get()
        tmpState.blck = cur.blck

        break

    if cur.blck.parent != nil and
        cur.blck.slot.epoch != epoch(cur.blck.parent.slot):
      # We store the state of the parent block with the epoch processing applied
      # in the database!
      cur = cur.blck.parent.atEpochStart(cur.blck.slot.epoch)
    else:
      # Moves back slot by slot, in case a state for an empty slot was saved
      cur = cur.parent

  if tmpState.blck == nil:
    warn "No state found in head history, database corrupt?"
    # TODO Potentially we could recover from here instead of crashing - what
    #      would be a good recovery model?
    raiseAssert "No state found in head history, database corrupt?"

  let res = ChainDAGRef(
    blocks: blocks,
    tail: tailRef,
    head: headRef,
    db: db,
    heads: @[headRef],
    headState: tmpState[],
    tmpState: tmpState[],
    clearanceState: tmpState[],

    # The only allowed flag right now is verifyFinalization, as the others all
    # allow skipping some validation.
    updateFlags: {verifyFinalization} * updateFlags,
    runtimePreset: preset,
  )

  doAssert res.updateFlags in [{}, {verifyFinalization}]

  var cache: StateCache
  res.updateStateData(res.headState, headRef.atSlot(headRef.slot), cache)
    # We presently save states on the epoch boundary - it means that the latest
  # state we loaded might be older than head block - nonetheless, it will be
  # from the same epoch as the head, thus the finalized and justified slots are
  # the same - these only change on epoch boundaries.
  res.finalizedHead = headRef.atEpochStart(
      res.headState.data.data.finalized_checkpoint.epoch)

  res.clearanceState = res.headState

  info "Block dag initialized",
    head = shortLog(headRef),
    finalizedHead = shortLog(res.finalizedHead),
    tail = shortLog(tailRef),
    totalBlocks = blocks.len

  res

proc findEpochRef*(blck: BlockRef, epoch: Epoch): EpochRef = # may return nil!
  let ancestor = blck.epochAncestor(epoch)
  for epochRef in ancestor.blck.epochRefs:
    if epochRef.epoch == epoch:
      return epochRef

proc getEpochRef*(dag: ChainDAGRef, blck: BlockRef, epoch: Epoch): EpochRef =
  let epochRef = blck.findEpochRef(epoch)
  if epochRef != nil:
      beacon_state_data_cache_hits.inc
      return epochRef

  beacon_state_data_cache_misses.inc

  let
    ancestor = blck.epochAncestor(epoch)

  dag.withState(dag.tmpState, ancestor):
    let
      prevEpochRef = blck.findEpochRef(epoch - 1)
      newEpochRef = EpochRef.init(state, cache, prevEpochRef)

    # TODO consider constraining the number of epochrefs per state
    ancestor.blck.epochRefs.add newEpochRef
    newEpochRef

proc getState(
    dag: ChainDAGRef, state: var StateData, stateRoot: Eth2Digest,
    blck: BlockRef): bool =
  let stateAddr = unsafeAddr state # local scope
  func restore(v: var BeaconState) =
    if stateAddr == (unsafeAddr dag.headState):
      # TODO seeing the headState in the restore shouldn't happen - we load
      #      head states only when updating the head position, and by that time
      #      the database will have gone through enough sanity checks that
      #      SSZ exceptions shouldn't happen, which is when restore happens.
      #      Nonetheless, this is an ugly workaround that needs to go away
      doAssert false, "Cannot alias headState"

    assign(stateAddr[], dag.headState)

  if not dag.db.getState(stateRoot, state.data.data, restore):
    return false

  state.blck = blck
  state.data.root = stateRoot

  true

proc getState(dag: ChainDAGRef, state: var StateData, bs: BlockSlot): bool =
  ## Load a state from the database given a block and a slot - this will first
  ## lookup the state root in the state root table then load the corresponding
  ## state, if it exists
  if not bs.slot.isEpoch:
    return false # We only ever save epoch states - no need to hit database

  # TODO earlier versions would store the epoch state with a the epoch block
  #      applied - we generally shouldn't hit the database for such states but
  #      will do so in a transitionary upgrade period!

  if (let stateRoot = dag.db.getStateRoot(bs.blck.root, bs.slot);
      stateRoot.isSome()):
    return dag.getState(state, stateRoot.get(), bs.blck)

  false

proc putState*(dag: ChainDAGRef, state: StateData) =
  # Store a state and its root
  # TODO we save state at every epoch start but never remove them - we also
  #      potentially save multiple states per slot if reorgs happen, meaning
  #      we could easily see a state explosion
  logScope: pcs = "save_state_at_epoch_start"

  # As a policy, we only store epoch boundary states without the epoch block
  # (if it exists) applied - the rest can be reconstructed by loading an epoch
  # boundary state and applying the missing blocks
  if not state.data.data.slot.isEpoch:
    trace "Not storing non-epoch state"
    return

  if state.data.data.slot <= state.blck.slot:
    trace "Not storing epoch state with block already applied"
    return

  if dag.db.containsState(state.data.root):
    return

  info "Storing state",
    blck = shortLog(state.blck),
    stateSlot = shortLog(state.data.data.slot),
    stateRoot = shortLog(state.data.root)

  # Ideally we would save the state and the root lookup cache in a single
  # transaction to prevent database inconsistencies, but the state loading code
  # is resilient against one or the other going missing
  dag.db.putState(state.data.root, state.data.data)
  dag.db.putStateRoot(state.blck.root, state.data.data.slot, state.data.root)

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

proc advanceSlots(
    dag: ChainDAGRef, state: var StateData, slot: Slot, save: bool) =
  # Given a state, advance it zero or more slots by applying empty slot
  # processing
  doAssert state.data.data.slot <= slot

  var cache = getStateCache(state.blck, state.data.data.slot.epoch)
  while state.data.data.slot < slot:
    # Process slots one at a time in case afterUpdate needs to see empty states
    advance_slot(state.data, dag.updateFlags, cache)

    if save:
      dag.putState(state)

proc applyBlock(
    dag: ChainDAGRef,
    state: var StateData, blck: BlockData, flags: UpdateFlags, save: bool): bool =
  # Apply a single block to the state - the state must be positioned at the
  # parent of the block with a slot lower than the one of the block being
  # applied
  doAssert state.blck == blck.refs.parent

  # `state_transition` can handle empty slots, but we want to potentially save
  # some of the empty slot states
  dag.advanceSlots(state, blck.data.message.slot, save)

  var statePtr = unsafeAddr state # safe because `restore` is locally scoped
  func restore(v: var HashedBeaconState) =
    doAssert (addr(statePtr.data) == addr v)
    statePtr[] = dag.headState

  var cache = getStateCache(state.blck, state.data.data.slot.epoch)
  let ok = state_transition(
    dag.runtimePreset, state.data, blck.data,
    cache, flags + dag.updateFlags + {slotProcessed}, restore)
  if ok:
    state.blck = blck.refs
    dag.putState(state)

  ok

proc updateStateData*(
    dag: ChainDAGRef, state: var StateData, bs: BlockSlot,
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
  if state.blck == bs.blck and state.data.data.slot <= bs.slot:
    # The block is the same and we're at an early enough slot - advance the
    # state with empty slot processing until the slot is correct
    dag.advanceSlots(state, bs.slot, true)

    return

  # Either the state is too new or was created by applying a different block.
  # We'll now resort to loading the state from the database then reapplying
  # blocks until we reach the desired point in time.

  var
    ancestors: seq[BlockRef]
    cur = bs
  # Look for a state in the database and load it - as long as it cannot be
  # found, keep track of the blocks that are needed to reach it from the
  # state that eventually will be found
  while not dag.getState(state, cur):
    # There's no state saved for this particular BlockSlot combination, keep
    # looking...
    if cur.blck.parent != nil and
        cur.blck.slot.epoch != epoch(cur.blck.parent.slot):
      # We store the state of the parent block with the epoch processing applied
      # in the database - we'll need to apply the block however!
      ancestors.add(cur.blck)
      cur = cur.blck.parent.atEpochStart(cur.blck.slot.epoch)
    else:
      if cur.slot == cur.blck.slot:
        # This is not an empty slot, so the block will need to be applied to
        # eventually reach bs
        ancestors.add(cur.blck)

      # Moves back slot by slot, in case a state for an empty slot was saved
      cur = cur.parent

  let
    startSlot = state.data.data.slot
    startRoot = state.data.root
  # Time to replay all the blocks between then and now
  for i in countdown(ancestors.len - 1, 0):
    # Because the ancestors are in the database, there's no need to persist them
    # again. Also, because we're applying blocks that were loaded from the
    # database, we can skip certain checks that have already been performed
    # before adding the block to the database.
    let ok =
      dag.applyBlock(state, dag.get(ancestors[i]), {}, false)
    doAssert ok, "Blocks in database should never fail to apply.."

  # We save states here - blocks were guaranteed to have passed through the save
  # function once at least, but not so for empty slots!
  dag.advanceSlots(state, bs.slot, true)

  beacon_state_rewinds.inc()

  debug "State reloaded from database",
    blocks = ancestors.len,
    slots = state.data.data.slot - startSlot,
    stateRoot = shortLog(state.data.root),
    stateSlot = state.data.data.slot,
    startRoot = shortLog(startRoot),
    startSlot,
    blck = shortLog(bs)

proc loadTailState*(dag: ChainDAGRef): StateData =
  ## Load the state associated with the current tail in the dag
  let stateRoot = dag.db.getBlock(dag.tail.root).get().message.state_root
  let found = dag.getState(result, stateRoot, dag.tail)
  # TODO turn into regular error, this can happen
  doAssert found, "Failed to load tail state, database corrupt?"

proc delState(dag: ChainDAGRef, bs: BlockSlot) =
  # Delete state state and mapping for a particular block+slot
  if not bs.slot.isEpoch:
    return # We only ever save epoch states
  if (let root = dag.db.getStateRoot(bs.blck.root, bs.slot); root.isSome()):
    dag.db.delState(root.get())
    dag.db.delStateRoot(bs.blck.root, bs.slot)

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
    var cache = getStateCache(newHead, newHead.slot.epoch())
    updateStateData(
      dag, dag.headState, newHead.atSlot(newHead.slot), cache)

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
        tmp.epochRefs = @[]

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
