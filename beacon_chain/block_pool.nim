import
  bitops, chronicles, options, tables,
  ssz, beacon_chain_db, state_transition, extras,
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
  ## https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/fork-choice.md#get_ancestor
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

  # TODO can't do straight init because in mainnet config, there are too
  #      many live beaconstates on the stack...
  var tmpState = new Option[BeaconState]

  # We're only saving epoch boundary states in the database right now, so when
  # we're loading the head block, the corresponding state does not necessarily
  # exist in the database - we'll load this latest state we know about and use
  # that as finalization point.
  tmpState[] = db.getState(latestStateRoot.get().stateRoot)
  let
    finalizedSlot =
      tmpState[].get().finalized_checkpoint.epoch.compute_start_slot_at_epoch()
    finalizedHead = headRef.findAncestorBySlot(finalizedSlot)
    justifiedSlot =
      tmpState[].get().current_justified_checkpoint.epoch.compute_start_slot_at_epoch()
    justifiedHead = headRef.findAncestorBySlot(justifiedSlot)
    head = Head(blck: headRef, justified: justifiedHead)
    justifiedBlock = db.getBlock(justifiedHead.blck.root).get()
    justifiedStateRoot = justifiedBlock.message.state_root

  doAssert justifiedHead.slot >= finalizedHead.slot,
    "justified head comes before finalized head - database corrupt?"

  debug "Block pool initialized",
    head = head.blck, finalizedHead, tail = tailRef,
    totalBlocks = blocks.len

  let res = BlockPool(
    pending: initTable[Eth2Digest, SignedBeaconBlock](),
    missing: initTable[Eth2Digest, MissingBlock](),
    blocks: blocks,
    tail: tailRef,
    head: head,
    finalizedHead: finalizedHead,
    db: db,
    heads: @[head],
  )

  res.headState = StateData(
    data: HashedBeaconState(
      data: tmpState[].get(), root: latestStateRoot.get().stateRoot),
    blck: latestStateRoot.get().blckRef)

  res.updateStateData(res.headState, BlockSlot(blck: head.blck, slot: head.blck.slot))
  res.tmpState = res.headState

  tmpState[] = db.getState(justifiedStateRoot)
  res.justifiedState = StateData(
    data: HashedBeaconState(data: tmpState[].get(), root: justifiedStateRoot),
    blck: justifiedHead.blck)

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
  if blockRoot in pool.blocks:
    debug "Block already exists",
      blck = shortLog(blck),
      blockRoot = shortLog(blockRoot),
      cat = "filtering"

    return pool.blocks[blockRoot]

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

    if not state_transition(pool.tmpState.data, blck, {}):
      # TODO find a better way to log all this block data
      notice "Invalid block",
        blck = shortLog(blck),
        blockRoot = shortLog(blockRoot),
        cat = "filtering"

      return

    # Careful, tmpState.data has been updated but not blck - we need to create
    # the BlockRef first!
    pool.tmpState.blck = pool.addResolvedBlock(
      pool.tmpState.data.data, blockRoot, signedBlock, parent)

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

proc getBlockRange*(pool: BlockPool, headBlock: Eth2Digest,
                    startSlot: Slot, skipStep: Natural,
                    output: var openarray[BlockRef]): Natural =
  ## This function populates an `output` buffer of blocks
  ## with a range starting from `startSlot` and skipping
  ## every `skipTest` number of blocks.
  ##
  ## Please note that the function may not necessarily
  ## populate the entire buffer. The values will be written
  ## in a way such that the last block is placed at the end
  ## of the buffer while the first indices of the buffer
  ## may remain unwritten.
  ##
  ## The result value of the function will be the index of
  ## the first block in the resulting buffer. If no values
  ## were written to the buffer, the result will be equal to
  ## `buffer.len`. In other words, you can use the function
  ## like this:
  ##
  ## var buffer: array[N, BlockRef]
  ## let startPos = pool.getBlockRange(headBlock, startSlot, skipStep, buffer)
  ## for i in startPos ..< buffer.len:
  ##   echo buffer[i].slot
  ##
  result = output.len

  trace "getBlockRange entered", headBlock, startSlot, skipStep

  var b = pool.getRef(headBlock)
  if b == nil:
    trace "head block not found", headBlock
    return

  trace "head block found", headBlock = b

  if b.slot < startSlot:
    trace "head block is older than startSlot", headBlockSlot = b.slot, startSlot
    return

  template skip(n: int) =
    let targetSlot = b.slot - Slot(n)
    while b.slot > targetSlot:
      if b.parent == nil:
        trace "stopping at parentless block", slot = b.slot, root = b.root
        return
      trace "skipping block", nextBlock = b.parent
      b = b.parent

  # We must compute the last block that is eligible for inclusion
  # in the results. This will be a block with a slot number that's
  # aligned to the stride of the requested block range, so we first
  # compute the steps needed to get to an aligned position:
  var blocksToSkip = b.slot.int mod skipStep
  let alignedHeadSlot = b.slot.int - blocksToSkip

  # Then we see if this aligned position is within our wanted
  # range. If it's outside it, we must skip more blocks:
  let lastWantedSlot = startSlot.int + (output.len - 1) * skipStep
  if alignedHeadSlot > lastWantedSlot:
    blocksToSkip += (alignedHeadSlot - lastWantedSlot)

  # Finally, we skip the computed number of blocks
  trace "aligning head", blocksToSkip
  skip blocksToSkip

  # From here, we can just write out the requested block range:
  while b != nil and b.slot >= startSlot and result > 0:
    dec result
    output[result] = b
    trace "getBlockRange result", position = result, blockSlot = b.slot
    skip skipStep

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
    state: var HashedBeaconState, slot: Slot,
    afterUpdate: proc (state: HashedBeaconState)) =
  while state.data.slot < slot:
    # Process slots one at a time in case afterUpdate needs to see empty states
    process_slots(state, state.data.slot + 1)
    afterUpdate(state)

proc skipAndUpdateState(
    state: var HashedBeaconState, blck: BeaconBlock, flags: UpdateFlags,
    afterUpdate: proc (state: HashedBeaconState)): bool =

  skipAndUpdateState(state, blck.slot - 1, afterUpdate)

  let ok  = state_transition(state, blck, flags)

  afterUpdate(state)

  ok

proc maybePutState(pool: BlockPool, state: HashedBeaconState, blck: BlockRef) =
  # TODO we save state at every epoch start but never remove them - we also
  #      potentially save multiple states per slot if reorgs happen, meaning
  #      we could easily see a state explosion
  logScope: pcs = "save_state_at_epoch_start"

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
    stateRoot = none(type(stateRoot.get()))

  while stateRoot.isNone():
    let parBs = curBs.parent()
    if parBs.blck.isNil:
      break # Bug probably!

    if parBs.blck != curBs.blck:
      ancestors.add(pool.get(parBs.blck))

    if (let tmp = pool.db.getStateRoot(parBs.blck.root, parBs.slot); tmp.isSome()):
      if pool.db.containsState(tmp.get):
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
    ancestorState = pool.db.getState(stateRoot.get())

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

  state.data.data = ancestorState.get()
  state.data.root = stateRoot.get()
  state.blck = ancestor.refs

  ancestors

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
      skipAndUpdateState(state.data, bs.slot) do(state: HashedBeaconState):
        pool.maybePutState(state, bs.blck)

    return # State already at the right spot

  let ancestors = rewindState(pool, state, bs)

  # If we come this far, we found the state root. The last block on the stack
  # is the one that produced this particular state, so we can pop it
  # TODO it might be possible to use the latest block hashes from the state to
  #      do this more efficiently.. whatever!

  # Time to replay all the blocks between then and now. We skip one because
  # it's the one that we found the state with, and it has already been
  # applied
  for i in countdown(ancestors.len - 1, 0):
    let ok =
      skipAndUpdateState(state.data, ancestors[i].data.message, {skipValidation}) do(
        state: HashedBeaconState):
      pool.maybePutState(state, ancestors[i].refs)
    doAssert ok, "Blocks in database should never fail to apply.."

  skipAndUpdateState(state.data, bs.slot) do(state: HashedBeaconState):
    pool.maybePutState(state, bs.blck)

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
    beacon_reorgs_total.inc()
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
    T: type BlockPool, db: BeaconChainDB, state: BeaconState,
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
