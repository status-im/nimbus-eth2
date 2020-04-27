# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  bitops, chronicles, options, tables,
  stew/results, ssz, beacon_chain_db, state_transition, extras, eth/db/kvstore,
  beacon_node_types, metrics,
  spec/[crypto, datatypes, digest, helpers, validator]

declareCounter beacon_reorgs_total, "Total occurrences of reorganizations of the chain" # On fork choice

logScope: topics = "blkpool"

proc updateStateData*(
  pool: BlockPool, state: var StateData, bs: BlockSlot) {.gcsafe.}
proc add*(
    pool: var BlockPool, blockRoot: Eth2Digest,
    signedBlock: SignedBeaconBlock): BlockRef {.gcsafe.}

template withState*(
    pool: BlockPool, cache: var StateData, blockSlot: BlockSlot, body: untyped): untyped =
  ## Helper template that updates state to a particular BlockSlot - usage of
  ## cache is unsafe outside of block.
  ## TODO async transformations will lead to a race where cache gets updated
  ##      while waiting for future to complete - catch this here somehow?

  updateStateData(pool, cache, blockSlot)

  template hashedState(): HashedBeaconState {.inject, used.} = cache.data
  template state(): BeaconStateRef {.inject, used.} = cache.data.data
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

func link(parent, child: BlockRef) =
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

func findAncestorBySlot*(blck: BlockRef, slot: Slot): BlockSlot =
  ## Find the first ancestor that has a slot number less than or equal to `slot`
  doAssert(not blck.isNil)
  var ret = blck

  while ret.parent != nil and ret.slot > slot:
    ret = ret.parent

  BlockSlot(blck: ret, slot: slot)

proc init*(T: type BlockPool, db: BeaconChainDB): BlockPool =
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
    latestStateRoot = Option[tuple[stateRoot: Eth2Digest, blckRef: BlockRef]]()
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
      trace "Populating block pool", key = curRef.root, val = curRef

      if latestStateRoot.isNone() and db.containsState(blck.message.state_root):
        latestStateRoot = some((blck.message.state_root, curRef))

    doAssert curRef == tailRef,
      "head block does not lead to tail, database corrupt?"
  else:
    headRef = tailRef

  if latestStateRoot.isNone():
    doAssert db.containsState(tailBlock.message.state_root),
      "state data missing for tail block, database corrupt?"
    latestStateRoot = some((tailBlock.message.state_root, tailRef))

  # We're only saving epoch boundary states in the database right now, so when
  # we're loading the head block, the corresponding state does not necessarily
  # exist in the database - we'll load this latest state we know about and use
  # that as finalization point.
  let stateOpt = db.getState(latestStateRoot.get().stateRoot)
  doAssert stateOpt.isSome, "failed to obtain latest state. database corrupt?"
  let tmpState = stateOpt.get

  let
    finalizedSlot =
      tmpState.finalized_checkpoint.epoch.compute_start_slot_at_epoch()
    finalizedHead = headRef.findAncestorBySlot(finalizedSlot)
    justifiedSlot =
      tmpState.current_justified_checkpoint.epoch.compute_start_slot_at_epoch()
    justifiedHead = headRef.findAncestorBySlot(justifiedSlot)
    head = Head(blck: headRef, justified: justifiedHead)
    justifiedBlock = db.getBlock(justifiedHead.blck.root).get()
    justifiedStateRoot = justifiedBlock.message.state_root

  doAssert justifiedHead.slot >= finalizedHead.slot,
    "justified head comes before finalized head - database corrupt?"

  debug "Block pool initialized",
    head = head.blck, finalizedHead, tail = tailRef,
    totalBlocks = blocks.len

  let headState = StateData(
    data: HashedBeaconState(
      data: tmpState, root: latestStateRoot.get().stateRoot),
    blck: latestStateRoot.get().blckRef)

  let justifiedState = db.getState(justifiedStateRoot)
  doAssert justifiedState.isSome,
           "failed to obtain latest justified state. database corrupt?"

  # For the initialization of `tmpState` below.
  # Please note that it's initialized few lines below
  {.push warning[UnsafeDefault]: off.}
  let res = BlockPool(
    pending: initTable[Eth2Digest, SignedBeaconBlock](),
    missing: initTable[Eth2Digest, MissingBlock](),

    # Usually one of the other of these will get re-initialized if the pool's
    # initialized on an epoch boundary, but that is a reasonable readability,
    # simplicity, and non-special-casing tradeoff for the inefficiency.
    cachedStates: [
      init(BeaconChainDB, kvStore MemStoreRef.init()),
      init(BeaconChainDB, kvStore MemStoreRef.init())
    ],

    blocks: blocks,
    tail: tailRef,
    head: head,
    finalizedHead: finalizedHead,
    db: db,
    heads: @[head],
    headState: headState,
    justifiedState: StateData(
      data: HashedBeaconState(data: justifiedState.get, root: justifiedStateRoot),
      blck: justifiedHead.blck),
    tmpState: default(StateData)
  )
  {.pop.}

  res.updateStateData(res.headState, BlockSlot(blck: head.blck,
                                               slot: head.blck.slot))
  res.tmpState = clone(res.headState)
  res

proc addResolvedBlock(
    pool: var BlockPool, state: BeaconState, blockRoot: Eth2Digest,
    signedBlock: SignedBeaconBlock, parent: BlockRef): BlockRef =
  logScope: pcs = "block_resolution"
  doAssert state.slot == signedBlock.message.slot, "state must match block"

  let blockRef = BlockRef.init(blockRoot, signedBlock.message)
  link(parent, blockRef)

  pool.blocks[blockRoot] = blockRef
  trace "Populating block pool", key = blockRoot, val = blockRef

  # Resolved blocks should be stored in database
  pool.db.putBlock(blockRoot, signedBlock)

  # This block *might* have caused a justification - make sure we stow away
  # that information:
  let justifiedSlot =
    state.current_justified_checkpoint.epoch.compute_start_slot_at_epoch()

  var foundHead: Option[Head]
  for head in pool.heads.mitems():
    if head.blck.isAncestorOf(blockRef):
      if head.justified.slot != justifiedSlot:
        head.justified = blockRef.findAncestorBySlot(justifiedSlot)

      head.blck = blockRef

      foundHead = some(head)
      break

  if foundHead.isNone():
    foundHead = some(Head(
      blck: blockRef,
      justified: blockRef.findAncestorBySlot(justifiedSlot)))
    pool.heads.add(foundHead.get())

  info "Block resolved",
    blck = shortLog(signedBlock.message),
    blockRoot = shortLog(blockRoot),
    justifiedRoot = shortLog(foundHead.get().justified.blck.root),
    justifiedSlot = shortLog(foundHead.get().justified.slot),
    heads = pool.heads.len(),
    cat = "filtering"

  # Now that we have the new block, we should see if any of the previously
  # unresolved blocks magically become resolved
  # TODO there are more efficient ways of doing this that don't risk
  #      running out of stack etc
  # TODO This code is convoluted because when there are more than ~1.5k
  #      blocks being synced, there's a stack overflow as `add` gets called
  #      for the whole chain of blocks. Instead we use this ugly field in `pool`
  #      which could be avoided by refactoring the code
  if not pool.inAdd:
    pool.inAdd = true
    defer: pool.inAdd = false
    var keepGoing = true
    while keepGoing:
      let retries = pool.pending
      for k, v in retries:
        discard pool.add(k, v)
      # Keep going for as long as the pending pool is shrinking
      # TODO inefficient! so what?
      keepGoing = pool.pending.len < retries.len
  blockRef

proc putState(pool: BlockPool, state: HashedBeaconState, blck: BlockRef) =
  # TODO we save state at every epoch start but never remove them - we also
  #      potentially save multiple states per slot if reorgs happen, meaning
  #      we could easily see a state explosion
  logScope: pcs = "save_state_at_epoch_start"

  var currentCache =
    pool.cachedStates[state.data.slot.compute_epoch_at_slot.uint64 mod 2]
  if state.data.slot mod SLOTS_PER_EPOCH == 0:
    if not pool.db.containsState(state.root):
      info "Storing state",
        blockRoot = shortLog(blck.root),
        blockSlot = shortLog(blck.slot),
        stateSlot = shortLog(state.data.slot),
        stateRoot = shortLog(state.root),
        cat = "caching"
      pool.db.putState(state.root, state.data)
      # TODO this should be atomic with the above write..
      pool.db.putStateRoot(blck.root, state.data.slot, state.root)

      # Because state.data.slot mod SLOTS_PER_EPOCH == 0, wrap back to last
      # time this was the case i.e. last currentCache. The opposite parity,
      # by contrast, has just finished filling from the previous epoch. The
      # resulting lookback window is thus >= SLOTS_PER_EPOCH in size, while
      # bounded from above by 2*SLOTS_PER_EPOCH.
      currentCache = init(BeaconChainDB, kvStore MemStoreRef.init())
  else:
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
    # faster) strategy to just store, for the most recent slots. Keep a
    # block's StateData of odd-numbered epoch in bucket 1, whilst evens
    # land in bucket 0 (which is handed back to GC in if branch). There
    # still is a possibility of combinatorial explosion, but this only,
    # by a constant-factor, worsens things. TODO the actual solution's,
    # eventually, to switch to CoW and/or ref objects for state and the
    # hash_tree_root processing.
    if not currentCache.containsState(state.root):
      currentCache.putState(state.root, state.data)
      # TODO this should be atomic with the above write..
      currentCache.putStateRoot(blck.root, state.data.slot, state.root)

proc add*(
    pool: var BlockPool, blockRoot: Eth2Digest,
    signedBlock: SignedBeaconBlock): BlockRef {.gcsafe.} =
  ## return the block, if resolved...
  ## the state parameter may be updated to include the given block, if
  ## everything checks out
  # TODO reevaluate passing the state in like this
  let blck = signedBlock.message
  doAssert blockRoot == hash_tree_root(blck)

  logScope: pcs = "block_addition"

  # Already seen this block??
  pool.blocks.withValue(blockRoot, blockRef):
    debug "Block already exists",
      blck = shortLog(blck),
      blockRoot = shortLog(blockRoot),
      cat = "filtering"

    return blockRef[]

  pool.missing.del(blockRoot)

  # If the block we get is older than what we finalized already, we drop it.
  # One way this can happen is that we start resolving a block and finalization
  # happens in the meantime - the block we requested will then be stale
  # by the time it gets here.
  if blck.slot <= pool.finalizedHead.slot:
    debug "Old block, dropping",
      blck = shortLog(blck),
      tailSlot = shortLog(pool.tail.slot),
      blockRoot = shortLog(blockRoot),
      cat = "filtering"

    return

  let parent = pool.blocks.getOrDefault(blck.parent_root)

  if parent != nil:
    if parent.slot >= blck.slot:
      # TODO Malicious block? inform peer pool?
      notice "Invalid block slot",
        blck = shortLog(blck),
        blockRoot = shortLog(blockRoot),
        parentRoot = shortLog(parent.root),
        parentSlot = shortLog(parent.slot)

      return

    # The block might have been in either of pending or missing - we don't want
    # any more work done on its behalf
    pool.pending.del(blockRoot)

    # The block is resolved, now it's time to validate it to ensure that the
    # blocks we add to the database are clean for the given state

    # TODO if the block is from the future, we should not be resolving it (yet),
    #      but maybe we should use it as a hint that our clock is wrong?
    updateStateData(pool, pool.tmpState, BlockSlot(blck: parent, slot: blck.slot - 1))

    let
      poolPtr = unsafeAddr pool # safe because restore is short-lived
    proc restore(v: var HashedBeaconState) =
      # TODO address this ugly workaround - there should probably be a
      #      `state_transition` that takes a `StateData` instead and updates
      #      the block as well
      doAssert v.addr == addr poolPtr.tmpState.data
      poolPtr.tmpState = poolPtr.headState

    if not state_transition(pool.tmpState.data, signedBlock, {}, restore):
      # TODO find a better way to log all this block data
      notice "Invalid block",
        blck = shortLog(blck),
        blockRoot = shortLog(blockRoot),
        cat = "filtering"

      return
    # Careful, tmpState.data has been updated but not blck - we need to create
    # the BlockRef first!
    pool.tmpState.blck = pool.addResolvedBlock(
      pool.tmpState.data.data[], blockRoot, signedBlock, parent)
    pool.putState(pool.tmpState.data, pool.tmpState.blck)

    return pool.tmpState.blck

  # TODO already checked hash though? main reason to keep this is because
  # the pending pool calls this function back later in a loop, so as long
  # as pool.add(...) requires a SignedBeaconBlock, easier to keep them in
  # pending too.
  pool.pending[blockRoot] = signedBlock

  # TODO possibly, it makes sense to check the database - that would allow sync
  #      to simply fill up the database with random blocks the other clients
  #      think are useful - but, it would also risk filling the database with
  #      junk that's not part of the block graph

  if blck.parent_root in pool.missing or
      blck.parent_root in pool.pending:
    return

  # This is an unresolved block - put its parent on the missing list for now...
  # TODO if we receive spam blocks, one heurestic to implement might be to wait
  #      for a couple of attestations to appear before fetching parents - this
  #      would help prevent using up network resources for spam - this serves
  #      two purposes: one is that attestations are likely to appear for the
  #      block only if it's valid / not spam - the other is that malicious
  #      validators that are not proposers can sign invalid blocks and send
  #      them out without penalty - but signing invalid attestations carries
  #      a risk of being slashed, making attestations a more valuable spam
  #      filter.
  # TODO when we receive the block, we don't know how many others we're missing
  #      from that branch, so right now, we'll just do a blind guess
  let parentSlot = blck.slot - 1

  pool.missing[blck.parent_root] = MissingBlock(
    slots:
      # The block is at least two slots ahead - try to grab whole history
      if parentSlot > pool.head.blck.slot:
        parentSlot - pool.head.blck.slot
      else:
        # It's a sibling block from a branch that we're missing - fetch one
        # epoch at a time
        max(1.uint64, SLOTS_PER_EPOCH.uint64 -
          (parentSlot.uint64 mod SLOTS_PER_EPOCH.uint64))
  )

  debug "Unresolved block (parent missing)",
    blck = shortLog(blck),
    blockRoot = shortLog(blockRoot),
    pending = pool.pending.len,
    missing = pool.missing.len,
    cat = "filtering"

func getRef*(pool: BlockPool, root: Eth2Digest): BlockRef =
  ## Retrieve a resolved block reference, if available
  pool.blocks.getOrDefault(root, nil)

proc getBlockRange*(
    pool: BlockPool, startSlot: Slot, skipStep: Natural,
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
    head = shortLog(pool.head.blck.root), count, startSlot, skipStep

  let
    skipStep = max(1, skipStep) # Treat 0 step as 1
    endSlot = startSlot + uint64(count * skipStep)

  var
    b = pool.head.blck.atSlot(endSlot)
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

func getBlockBySlot*(pool: BlockPool, slot: Slot): BlockRef =
  ## Retrieves the first block in the current canonical chain
  ## with slot number less or equal to `slot`.
  pool.head.blck.findAncestorBySlot(slot).blck

func getBlockByPreciseSlot*(pool: BlockPool, slot: Slot): BlockRef =
  ## Retrieves a block from the canonical chain with a slot
  ## number equal to `slot`.
  let found = pool.getBlockBySlot(slot)
  if found.slot != slot: found else: nil

proc get*(pool: BlockPool, blck: BlockRef): BlockData =
  ## Retrieve the associated block body of a block reference
  doAssert (not blck.isNil), "Trying to get nil BlockRef"

  let data = pool.db.getBlock(blck.root)
  doAssert data.isSome, "BlockRef without backing data, database corrupt?"

  BlockData(data: data.get(), refs: blck)

proc get*(pool: BlockPool, root: Eth2Digest): Option[BlockData] =
  ## Retrieve a resolved block reference and its associated body, if available
  let refs = pool.getRef(root)

  if not refs.isNil:
    some(pool.get(refs))
  else:
    none(BlockData)

func getOrResolve*(pool: var BlockPool, root: Eth2Digest): BlockRef =
  ## Fetch a block ref, or nil if not found (will be added to list of
  ## blocks-to-resolve)
  result = pool.getRef(root)

  if result.isNil:
    pool.missing[root] = MissingBlock(slots: 1)

func checkMissing*(pool: var BlockPool): seq[FetchRecord] =
  ## Return a list of blocks that we should try to resolve from other client -
  ## to be called periodically but not too often (once per slot?)
  var done: seq[Eth2Digest]

  for k, v in pool.missing.mpairs():
    if v.tries > 8:
      done.add(k)
    else:
      inc v.tries

  for k in done:
    # TODO Need to potentially remove from pool.pending - this is currently a
    #      memory leak here!
    pool.missing.del(k)

  # simple (simplistic?) exponential backoff for retries..
  for k, v in pool.missing.pairs():
    if v.tries.popcount() == 1:
      result.add(FetchRecord(root: k, historySlots: v.slots))

proc skipAndUpdateState(
    pool: BlockPool,
    state: var HashedBeaconState, blck: BlockRef, slot: Slot) =
  while state.data.slot < slot:
    # Process slots one at a time in case afterUpdate needs to see empty states
    process_slots(state, state.data.slot + 1)
    pool.putState(state, blck)

proc skipAndUpdateState(
    pool: BlockPool,
    state: var StateData, blck: BlockData, flags: UpdateFlags): bool =

  pool.skipAndUpdateState(state.data, blck.refs, blck.data.message.slot - 1)

  var statePtr = unsafeAddr state # safe because `restore` is locally scoped
  proc restore(v: var HashedBeaconState) =
    doAssert (addr(statePtr.data) == addr v)
    statePtr[] = pool.headState

  let ok  = state_transition(state.data, blck.data, flags, restore)
  if ok:
    pool.putState(state.data, blck.refs)

  ok

proc rewindState(pool: BlockPool, state: var StateData, bs: BlockSlot):
    seq[BlockData] =
  logScope: pcs = "replay_state"

  var ancestors = @[pool.get(bs.blck)]
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
    stateRoot = pool.db.getStateRoot(bs.blck.root, bs.slot)
    curBs = bs

  # TODO this can happen when state root is saved but state is gone - this would
  #      indicate a corrupt database, but since we're not atomically
  #      writing and deleting state+root mappings in a single transaction, it's
  #      likely to happen and we guard against it here.
  if stateRoot.isSome() and not pool.db.containsState(stateRoot.get()):
    stateRoot.err()

  while stateRoot.isNone():
    let parBs = curBs.parent()
    if parBs.blck.isNil:
      break # Bug probably!

    if parBs.blck != curBs.blck:
      ancestors.add(pool.get(parBs.blck))

    for db in [pool.db, pool.cachedStates[0], pool.cachedStates[1]]:
      if (let tmp = db.getStateRoot(parBs.blck.root, parBs.slot); tmp.isSome()):
        if db.containsState(tmp.get):
          stateRoot = tmp
          break

    if stateRoot.isSome:
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
    ancestorState =
      if pool.db.containsState(root):
        pool.db.getState(root)
      elif pool.cachedStates[0].containsState(root):
        pool.cachedStates[0].getState(root)
      else:
        pool.cachedStates[1].getState(root)

  if ancestorState.isNone():
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
    ancestorStateSlot = shortLog(ancestorState.get().slot),
    slot = shortLog(bs.slot),
    blockRoot = shortLog(bs.blck.root),
    ancestors = ancestors.len,
    cat = "replay_state"

  state.data.data[] = ancestorState.get()[]
  state.data.root = stateRoot.get()
  state.blck = ancestor.refs

  ancestors

proc getStateDataCached(pool: BlockPool, state: var StateData, bs: BlockSlot): bool =
  # This pointedly does not run rewindState or state_transition, but otherwise
  # mostly matches updateStateData(...), because it's too expensive to run the
  # rewindState(...)/skipAndUpdateState(...)/state_transition(...) procs, when
  # each hash_tree_root(...) consumes a nontrivial fraction of a second.
  for db in [pool.db, pool.cachedStates[0], pool.cachedStates[1]]:
    if (let tmp = db.getStateRoot(bs.blck.root, bs.slot); tmp.isSome()):
      if not db.containsState(tmp.get):
        continue

      let
        root = tmp.get()
        ancestorState = db.getState(root)

      doAssert ancestorState.isSome()
      state.data.data = ancestorState.get()
      state.data.root = root
      state.blck = pool.get(bs.blck).refs
      return true

  false

proc updateStateData*(pool: BlockPool, state: var StateData, bs: BlockSlot) =
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
      pool.skipAndUpdateState(state.data, bs.blck, bs.slot)

    return # State already at the right spot

  if pool.getStateDataCached(state, bs):
    return

  let ancestors = rewindState(pool, state, bs)

  # If we come this far, we found the state root. The last block on the stack
  # is the one that produced this particular state, so we can pop it
  # TODO it might be possible to use the latest block hashes from the state to
  #      do this more efficiently.. whatever!

  # Time to replay all the blocks between then and now. We skip one because
  # it's the one that we found the state with, and it has already been
  # applied. Pathologically quadratic in slot number, naïvely.
  for i in countdown(ancestors.len - 1, 0):
    let ok =
      pool.skipAndUpdateState(
        state, ancestors[i],
        {skipBlsValidation, skipMerkleValidation, skipStateRootValidation})
    doAssert ok, "Blocks in database should never fail to apply.."

  pool.skipAndUpdateState(state.data, bs.blck, bs.slot)

  state.blck = bs.blck

proc loadTailState*(pool: BlockPool): StateData =
  ## Load the state associated with the current tail in the pool
  let stateRoot = pool.db.getBlock(pool.tail.root).get().message.state_root
  StateData(
    data: HashedBeaconState(
      data: pool.db.getState(stateRoot).get(),
      root: stateRoot),
    blck: pool.tail
  )

proc delState(pool: BlockPool, bs: BlockSlot) =
  # Delete state state and mapping for a particular block+slot
  if (let root = pool.db.getStateRoot(bs.blck.root, bs.slot); root.isSome()):
    pool.db.delState(root.get())
    pool.db.delStateRoot(bs.blck.root, bs.slot)

proc updateHead*(pool: BlockPool, newHead: BlockRef) =
  ## Update what we consider to be the current head, as given by the fork
  ## choice.
  ## The choice of head affects the choice of finalization point - the order
  ## of operations naturally becomes important here - after updating the head,
  ## blocks that were once considered potential candidates for a tree will
  ## now fall from grace, or no longer be considered resolved.
  doAssert newHead.parent != nil or newHead.slot == 0
  logScope: pcs = "fork_choice"

  if pool.head.blck == newHead:
    info "No head block update",
      headBlockRoot = shortLog(newHead.root),
      headBlockSlot = shortLog(newHead.slot),
      cat = "fork_choice"

    return

  let
    lastHead = pool.head
  pool.db.putHeadBlock(newHead.root)

  # Start off by making sure we have the right state
  updateStateData(
    pool, pool.headState, BlockSlot(blck: newHead, slot: newHead.slot))

  let
    justifiedSlot = pool.headState.data.data
                      .current_justified_checkpoint
                      .epoch
                      .compute_start_slot_at_epoch()
    justifiedBS = newHead.findAncestorBySlot(justifiedSlot)

  pool.head = Head(blck: newHead, justified: justifiedBS)
  updateStateData(pool, pool.justifiedState, justifiedBS)

  # TODO isAncestorOf may be expensive - too expensive?
  if not lastHead.blck.isAncestorOf(newHead):
    info "Updated head block (new parent)",
      lastHeadRoot = shortLog(lastHead.blck.root),
      parentRoot = shortLog(newHead.parent.root),
      stateRoot = shortLog(pool.headState.data.root),
      headBlockRoot = shortLog(pool.headState.blck.root),
      stateSlot = shortLog(pool.headState.data.data.slot),
      justifiedEpoch = shortLog(pool.headState.data.data.current_justified_checkpoint.epoch),
      finalizedEpoch = shortLog(pool.headState.data.data.finalized_checkpoint.epoch),
      cat = "fork_choice"

    # A reasonable criterion for "reorganizations of the chain"
    try:
      beacon_reorgs_total.inc()
    except Exception as e: # TODO https://github.com/status-im/nim-metrics/pull/22
      trace "Couldn't update metrics", msg = e.msg
  else:
    info "Updated head block",
      stateRoot = shortLog(pool.headState.data.root),
      headBlockRoot = shortLog(pool.headState.blck.root),
      stateSlot = shortLog(pool.headState.data.data.slot),
      justifiedEpoch = shortLog(pool.headState.data.data.current_justified_checkpoint.epoch),
      finalizedEpoch = shortLog(pool.headState.data.data.finalized_checkpoint.epoch),
      cat = "fork_choice"

  let
    finalizedEpochStartSlot =
      pool.headState.data.data.finalized_checkpoint.epoch.
      compute_start_slot_at_epoch()
    # TODO there might not be a block at the epoch boundary - what then?
    finalizedHead = newHead.findAncestorBySlot(finalizedEpochStartSlot)

  doAssert (not finalizedHead.blck.isNil),
    "Block graph should always lead to a finalized block"

  if finalizedHead != pool.finalizedHead:
    block: # Remove states, walking slot by slot
      discard
      # TODO this is very aggressive - in theory all our operations start at
      #      the finalized block so all states before that can be wiped..
      # TODO this is disabled for now because the logic for initializing the
      #      block pool and potentially a few other places depend on certain
      #      states (like the tail state) being present. It's also problematic
      #      because it is not clear what happens when tail and finalized states
      #      happen on an empty slot..
      # var cur = finalizedHead
      # while cur != pool.finalizedHead:
      #  cur = cur.parent
      #  pool.delState(cur)

    block: # Clean up block refs, walking block by block
      var cur = finalizedHead.blck
      while cur != pool.finalizedHead.blck:
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
              #      pool.heads to find unviable heads, then walk those chains
              #      and remove everything.. currently, if there's a child with
              #      children of its own, those children will not be pruned
              #      correctly from the database
              pool.blocks.del(child.root)
              pool.db.delBlock(child.root)
          cur.parent.children = @[cur]

    pool.finalizedHead = finalizedHead

    let hlen = pool.heads.len
    for i in 0..<hlen:
      let n = hlen - i - 1
      if not pool.finalizedHead.blck.isAncestorOf(pool.heads[n].blck):
        # Any heads that are not derived from the newly finalized block are no
        # longer viable candidates for future head selection
        pool.heads.del(n)

    info "Finalized block",
      finalizedBlockRoot = shortLog(finalizedHead.blck.root),
      finalizedBlockSlot = shortLog(finalizedHead.slot),
      headBlockRoot = shortLog(newHead.root),
      headBlockSlot = shortLog(newHead.slot),
      heads = pool.heads.len,
      cat = "fork_choice"

    # TODO prune everything before weak subjectivity period

func latestJustifiedBlock*(pool: BlockPool): BlockSlot =
  ## Return the most recent block that is justified and at least as recent
  ## as the latest finalized block

  doAssert pool.heads.len > 0,
    "We should have at least the genesis block in heaads"
  doAssert (not pool.head.blck.isNil()),
    "Genesis block will be head, if nothing else"

  # Prefer stability: use justified block from current head to break ties!
  result = pool.head.justified
  for head in pool.heads[1 ..< ^0]:
    if head.justified.slot > result.slot:
      result = head.justified

proc isInitialized*(T: type BlockPool, db: BeaconChainDB): bool =
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
    T: type BlockPool, db: BeaconChainDB, state: BeaconStateRef,
    signedBlock: SignedBeaconBlock) =
  # write a genesis state, the way the BlockPool expects it to be stored in
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

proc getProposer*(pool: BlockPool, head: BlockRef, slot: Slot): Option[ValidatorPubKey] =
  pool.withState(pool.tmpState, head.atSlot(slot)):
    var cache = get_empty_per_epoch_cache()

    # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#validator-assignments
    let proposerIdx = get_beacon_proposer_index(state[], cache)
    if proposerIdx.isNone:
      warn "Missing proposer index",
        slot=slot,
        epoch=slot.compute_epoch_at_slot,
        num_validators=state.validators.len,
        active_validators=
          get_active_validator_indices(state[], slot.compute_epoch_at_slot),
        balances=state.balances
      return

    return some(state.validators[proposerIdx.get()].pubkey)

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#global-topics
proc isValidBeaconBlock*(pool: var BlockPool,
    signed_beacon_block: SignedBeaconBlock, current_slot: Slot,
    flags: UpdateFlags): bool =
  # In general, checks are ordered from cheap to expensive. Especially, crypto
  # verification could be quite a bit more expensive than the rest. This is an
  # externally easy-to-invoke function by tossing network packets at the node.

  # The block is not from a future slot
  # TODO allow `MAXIMUM_GOSSIP_CLOCK_DISPARITY` leniency, especially towards
  # seemingly future slots.
  if not (signed_beacon_block.message.slot <= current_slot):
    debug "isValidBeaconBlock: block is from a future slot",
      signed_beacon_block_message_slot = signed_beacon_block.message.slot,
      current_slot = current_slot
    return false

  # The block is from a slot greater than the latest finalized slot (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that
  # signed_beacon_block.message.slot >
  # compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
  if not (signed_beacon_block.message.slot > pool.finalizedHead.slot):
    debug "isValidBeaconBlock: block is not from a slot greater than the latest finalized slot"
    return false

  # The block is the first block with valid signature received for the proposer
  # for the slot, signed_beacon_block.message.slot.
  #
  # While this condition is similar to the proposer slashing condition at
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#proposer-slashing
  # it's not identical, and this check does not address slashing:
  #
  # (1) The beacon blocks must be conflicting, i.e. different, for the same
  #     slot and proposer. This check also catches identical blocks.
  #
  # (2) By this point in the function, it's not been checked whether they're
  #     signed yet. As in general, expensive checks should be deferred, this
  #     would add complexity not directly relevant this function.
  #
  # (3) As evidenced by point (1), the similarity in the validation condition
  #     and slashing condition, while not coincidental, aren't similar enough
  #     to combine, as one or the other might drift.
  #
  # (4) Furthermore, this function, as much as possible, simply returns a yes
  #     or no answer, without modifying other state for p2p network interface
  #     validation. Complicating this interface, for the sake of sharing only
  #     couple lines of code, wouldn't be worthwhile.
  #
  # TODO might check unresolved/orphaned blocks too, and this might not see all
  # blocks at a given slot (though, in theory, those get checked elsewhere), or
  # adding metrics that count how often these conditions occur.
  let
    slotBlockRef = getBlockBySlot(pool, signed_beacon_block.message.slot)

  if not slotBlockRef.isNil:
    let blck = pool.get(slotBlockRef).data
    if blck.message.proposer_index ==
          signed_beacon_block.message.proposer_index and
        blck.message.slot == signed_beacon_block.message.slot and
        blck.signature.toRaw() != signed_beacon_block.signature.toRaw():
      debug "isValidBeaconBlock: block isn't first block with valid signature received for the proposer",
        signed_beacon_block_message_slot = signed_beacon_block.message.slot,
        blckRef = slotBlockRef,
        received_block = shortLog(signed_beacon_block.message),
        existing_block = shortLog(pool.get(slotBlockRef).data.message)
      return false

  # If this block doesn't have a parent we know about, we can't/don't really
  # trace it back to a known-good state/checkpoint to verify its prevenance;
  # while one could getOrResolve to queue up searching for missing parent it
  # might not be the best place. As much as feasible, this function aims for
  # answering yes/no, not queuing other action or otherwise altering state.
  let parent_ref = pool.getRef(signed_beacon_block.message.parent_root)
  if parent_ref.isNil:
    # This doesn't mean a block is forever invalid, only that we haven't seen
    # its ancestor blocks yet. While that means for now it should be blocked,
    # at least, from libp2p propagation, it shouldn't be ignored. TODO, if in
    # the future this block moves from pending to being resolved, consider if
    # it's worth broadcasting it then.

    # Pending pool gets checked via `BlockPool.add(...)` later, and relevant
    # checks are performed there. In usual paths beacon_node adds blocks via
    # BlockPool.add(...) directly, with no additional validity checks. TODO,
    # not specific to this, but by the pending pool keying on the htr of the
    # BeaconBlock, not SignedBeaconBlock, opens up certain spoofing attacks.
    pool.pending[hash_tree_root(signed_beacon_block.message)] =
      signed_beacon_block
    return false

  # The proposer signature, signed_beacon_block.signature, is valid with
  # respect to the proposer_index pubkey.
  let bs =
    BlockSlot(blck: parent_ref, slot: pool.get(parent_ref).data.message.slot)
  pool.withState(pool.tmpState, bs):
    let
      blockRoot = hash_tree_root(signed_beacon_block.message)
      domain = get_domain(pool.headState.data.data[], DOMAIN_BEACON_PROPOSER,
        compute_epoch_at_slot(signed_beacon_block.message.slot))
      signing_root = compute_signing_root(blockRoot, domain)
      proposer_index = signed_beacon_block.message.proposer_index

    if proposer_index >= pool.headState.data.data.validators.len.uint64:
      return false
    if not blsVerify(pool.headState.data.data.validators[proposer_index].pubkey,
        signing_root.data, signed_beacon_block.signature):
      debug "isValidBeaconBlock: block failed signature verification"
      return false

  true
