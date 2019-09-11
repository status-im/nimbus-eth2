import
  bitops, chronicles, options, sequtils, tables,
  ssz, beacon_chain_db, state_transition, extras,
  beacon_node_types,
  spec/[crypto, datatypes, digest, helpers]

proc parent*(bs: BlockSlot): BlockSlot =
  BlockSlot(
    blck: if bs.slot > bs.blck.slot: bs.blck else: bs.blck.parent,
    slot: bs.slot - 1
  )

proc link(parent, child: BlockRef) =
  doAssert (not (parent.root == Eth2Digest() or child.root == Eth2Digest())),
    "blocks missing root!"
  doAssert parent.root != child.root, "self-references not allowed"

  child.parent = parent
  parent.children.add(child)

proc init*(T: type BlockRef, root: Eth2Digest, slot: Slot): BlockRef =
  BlockRef(
    root: root,
    slot: slot
  )

proc init*(T: type BlockRef, root: Eth2Digest, blck: BeaconBlock): BlockRef =
  BlockRef.init(root, blck.slot)

proc findAncestorBySlot*(blck: BlockRef, slot: Slot): BlockSlot =
  ## Find the first ancestor that has a slot number less than or equal to `slot`
  assert(not blck.isNil)
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
    tailRef = BlockRef.init(tailRoot, tailBlock)
    headRoot = headBlockRoot.get()

  var
    blocks = {tailRef.root: tailRef}.toTable()
    latestStateRoot = Option[Eth2Digest]()
    headStateBlock = tailRef
    headRef: BlockRef

  if headRoot != tailRoot:
    var curRef: BlockRef

    for root, blck in db.getAncestors(headRoot):
      if root == tailRef.root:
        doAssert(not curRef.isNil)
        link(tailRef, curRef)
        curRef = curRef.parent
        break

      let newRef = BlockRef.init(root, blck)
      if curRef == nil:
        curRef = newRef
        headRef = newRef
      else:
        link(newRef, curRef)
        curRef = curRef.parent
      blocks[curRef.root] = curRef

      if latestStateRoot.isNone() and db.containsState(blck.state_root):
        latestStateRoot = some(blck.state_root)

    doAssert curRef == tailRef,
      "head block does not lead to tail, database corrupt?"
  else:
    headRef = tailRef

  var blocksBySlot = initTable[uint64, seq[BlockRef]]()
  for _, b in tables.pairs(blocks):
    let slot = db.getBlock(b.root).get().slot
    blocksBySlot.mgetOrPut(slot.uint64, @[]).add(b)

  let
    # The head state is necessary to find out what we considered to be the
    # finalized epoch last time we saved something.
    headStateRoot =
      if latestStateRoot.isSome():
        latestStateRoot.get()
      else:
        db.getBlock(tailRef.root).get().state_root

    # TODO right now, because we save a state at every epoch, this *should*
    #      be the latest justified state or newer, meaning it's enough for
    #      establishing what we consider to be the finalized head. This logic
    #      will need revisiting however
    headState = db.getState(headStateRoot).get()
    finalizedHead =
      headRef.findAncestorBySlot(
        headState.finalized_checkpoint.epoch.compute_start_slot_of_epoch())
    justifiedSlot =
      headState.current_justified_checkpoint.epoch.compute_start_slot_of_epoch()
    justifiedHead = headRef.findAncestorBySlot(justifiedSlot)
    head = Head(blck: headRef, justified: justifiedHead)

  doAssert justifiedHead.slot >= finalizedHead.slot,
    "justified head comes before finalized head - database corrupt?"

  BlockPool(
    pending: initTable[Eth2Digest, BeaconBlock](),
    missing: initTable[Eth2Digest, MissingBlock](),
    blocks: blocks,
    blocksBySlot: blocksBySlot,
    tail: tailRef,
    head: head,
    finalizedHead: finalizedHead,
    db: db,
    heads: @[head]
  )

proc addSlotMapping(pool: BlockPool, slot: uint64, br: BlockRef) =
  proc addIfMissing(s: var seq[BlockRef], v: BlockRef) =
    if v notin s:
      s.add(v)
  pool.blocksBySlot.mgetOrPut(slot, @[]).addIfMissing(br)

proc updateStateData*(
  pool: BlockPool, state: var StateData, bs: BlockSlot) {.gcsafe.}

proc add*(
    pool: var BlockPool, state: var StateData, blockRoot: Eth2Digest,
    blck: BeaconBlock): BlockRef {.gcsafe.}

proc addResolvedBlock(
    pool: var BlockPool, state: var StateData, blockRoot: Eth2Digest,
    blck: BeaconBlock, parent: BlockRef): BlockRef =
  let blockRef = BlockRef.init(blockRoot, blck)
  link(parent, blockRef)

  pool.blocks[blockRoot] = blockRef

  pool.addSlotMapping(blck.slot.uint64, blockRef)

  # Resolved blocks should be stored in database
  pool.db.putBlock(blockRoot, blck)

  # TODO this is a bit ugly - we update state.data outside of this function then
  #      set the rest here - need a blockRef to update it. Clean this up -
  #      hopefully it won't be necessary by the time hash caching and the rest
  #      is done..
  doAssert state.data.data.slot == blockRef.slot
  state.blck = blockRef

  # This block *might* have caused a justification - make sure we stow away
  # that information:
  let justifiedSlot =
    state.data.data.current_justified_checkpoint.epoch.compute_start_slot_of_epoch()

  var foundHead: Option[Head]
  for head in pool.heads.mitems():
    if head.blck.root == blck.parent_root:
      if head.justified.slot != justifiedSlot:
        head.justified = blockRef.findAncestorBySlot(justifiedSlot)

      foundHead = some(head)
      break

  if foundHead.isNone():
    foundHead = some(Head(
      blck: blockRef,
      justified: blockRef.findAncestorBySlot(justifiedSlot)))
    pool.heads.add(foundHead.get())

  info "Block resolved",
    blck = shortLog(blck),
    blockRoot = shortLog(blockRoot),
    justifiedRoot = shortLog(foundHead.get().justified.blck.root),
    justifiedSlot = shortLog(foundHead.get().justified.slot)

  # Now that we have the new block, we should see if any of the previously
  # unresolved blocks magically become resolved
  # TODO there are more efficient ways of doing this that don't risk
  #      running out of stack etc
  let retries = pool.pending
  for k, v in retries:
    discard pool.add(state, k, v)

  blockRef

proc add*(
    pool: var BlockPool, state: var StateData, blockRoot: Eth2Digest,
    blck: BeaconBlock): BlockRef {.gcsafe.} =
  ## return the block, if resolved...
  ## the state parameter may be updated to include the given block, if
  ## everything checks out
  # TODO reevaluate passing the state in like this
  doAssert blockRoot == signing_root(blck)

  # Already seen this block??
  if blockRoot in pool.blocks:
    debug "[Block Pool] Block already exists",
      blck = shortLog(blck),
      blockRoot = shortLog(blockRoot),
      service = "block_pool",
      category = "filtering",
      process = "block_addition"

    return pool.blocks[blockRoot]

  pool.missing.del(blockRoot)

  # If the block we get is older than what we finalized already, we drop it.
  # One way this can happen is that we start resolving a block and finalization
  # happens in the meantime - the block we requested will then be stale
  # by the time it gets here.
  if blck.slot <= pool.finalizedHead.slot:
    debug "[Block pool] Old block, dropping",
      blck = shortLog(blck),
      tailSlot = shortLog(pool.tail.slot),
      blockRoot = shortLog(blockRoot),
      service = "block_pool",
      category = "filtering",
      process = "block_addition"

    return

  let parent = pool.blocks.getOrDefault(blck.parent_root)

  if parent != nil:
    # The block might have been in either of these - we don't want any more
    # work done on its behalf
    pool.pending.del(blockRoot)

    # The block is resolved, now it's time to validate it to ensure that the
    # blocks we add to the database are clean for the given state

    # TODO if the block is from the future, we should not be resolving it (yet),
    #      but maybe we should use it as a hint that our clock is wrong?
    updateStateData(pool, state, BlockSlot(blck: parent, slot: blck.slot - 1))

    if not state_transition(state.data, blck, {}):
      # TODO find a better way to log all this block data
      notice "[Block Pool] Invalid block",
        blck = shortLog(blck),
        blockRoot = shortLog(blockRoot),
        service = "block_pool",
        category = "filtering",
        process = "block_addition"

      return

    return pool.addResolvedBlock(state, blockRoot, blck, parent)

  pool.pending[blockRoot] = blck

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
  debug "[Block Pool] Unresolved block (parent missing)",
    blck = shortLog(blck),
    blockRoot = shortLog(blockRoot),
    service = "block_pool",
    category = "filtering",
    process = "block_addition"

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

proc getRef*(pool: BlockPool, root: Eth2Digest): BlockRef =
  ## Retrieve a resolved block reference, if available
  pool.blocks.getOrDefault(root)

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

  var b = pool.getRef(headBlock)
  if b == nil or b.slot < startSlot:
    return

  template skip(n: int) =
    for i in 0 ..< n:
      b = b.parent
      if b == nil: return

  # We must compute the last block that is eligible for inclusion
  # in the results. This will be a block with a slot number that's
  # aligned to the stride of the requested block range, so we first
  # compute the steps needed to get to an aligned position:
  var blocksToSkip = b.slot.int mod skipStep
  let alignedHeadSlot = b.slot.int - blocksToSkip

  # Then we see if this aligned position is within our wanted
  # range. If it's outside it, we must skip more blocks:
  let lastWantedSlot = startSlot.int + output.len * skipStep
  if alignedHeadSlot > lastWantedSlot:
    blocksToSkip += (alignedHeadSlot - lastWantedSlot)

  # Finally, we skip the computed number of blocks
  skip blocksToSkip

  # From here, we can just write out the requested block range:
  while b != nil and result > 0:
    dec result
    output[result] = b
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

proc getOrResolve*(pool: var BlockPool, root: Eth2Digest): BlockRef =
  ## Fetch a block ref, or nil if not found (will be added to list of
  ## blocks-to-resolve)
  result = pool.getRef(root)

  if result.isNil:
    pool.missing[root] = MissingBlock(slots: 1)

iterator blockRootsForSlot*(pool: BlockPool, slot: uint64|Slot): Eth2Digest =
  for br in pool.blocksBySlot.getOrDefault(slot.uint64, @[]):
    yield br.root

proc checkMissing*(pool: var BlockPool): seq[FetchRecord] =
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
    state: var HashedBeaconState, blck: BeaconBlock, flags: UpdateFlags,
    afterUpdate: proc (state: HashedBeaconState)): bool =

  process_slots(state, blck.slot - 1)
  afterUpdate(state)

  let ok  = state_transition(state, blck, flags)

  afterUpdate(state)

  ok

proc maybePutState(pool: BlockPool, state: HashedBeaconState, blck: BlockRef) =
  # TODO we save state at every epoch start but never remove them - we also
  #      potentially save multiple states per slot if reorgs happen, meaning
  #      we could easily see a state explosion
  # TODO this is out of sync with epoch def now, I think -- (slot + 1) mod foo.
  if state.data.slot mod SLOTS_PER_EPOCH == 0:
    if not pool.db.containsState(state.root):
      info "[Block Pool] Storing state",
        stateSlot = shortLog(state.data.slot),
        stateRoot = shortLog(state.root),
        service = "block_pool",
        category = "caching",
        process = "save_state_at_epoch_start"
      pool.db.putState(state.root, state.data)
      # TODO this should be atomic with the above write..
      pool.db.putStateRoot(blck.root, state.data.slot, state.root)

proc rewindState(pool: BlockPool, state: var StateData, bs: BlockSlot):
    seq[BlockData] =
  var ancestors = @[pool.get(bs.blck)]
  # Common case: the last block applied is the parent of the block to apply:
  if not bs.blck.parent.isNil and state.blck.root == bs.blck.parent.root and
      state.data.data.slot < bs.slot:
    return ancestors

  # It appears that the parent root of the proposed new block is different from
  # what we expected. We will have to rewind the state to a point along the
  # chain of ancestors of the new block. We will do this by loading each
  # successive parent block and checking if we can find the corresponding state
  # in the database.

  var
    stateRoot = pool.db.getStateRoot(bs.blck.root, bs.slot)
    curBs = bs
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
    error "[Block Pool] Couldn't find ancestor state root!",
      blockRoot = shortLog(bs.blck.root),
      service = "block_pool",
      category = "replay_state",
      process = "find_ancestor_state_root"
    doAssert false, "Oh noes, we passed big bang!"

  let
    ancestor = ancestors[^1]
    ancestorState = pool.db.getState(stateRoot.get())

  if ancestorState.isNone():
    # TODO this should only happen if the database is corrupt - we walked the
    #      list of parent blocks and couldn't find a corresponding state in the
    #      database, which should never happen (at least we should have the
    #      tail state in there!)
    error "Couldn't find ancestor state or block parent missing!",
      blockRoot = shortLog(bs.blck.root),
      service = "block_pool",
      category = "replay_state",
      process = "find_ancestor_state"
    doAssert false, "Oh noes, we passed big bang!"

  trace "[Block Pool] Replaying state transitions",
    stateSlot = shortLog(state.data.data.slot),
    ancestorStateRoot = shortLog(ancestor.data.state_root),
    ancestorStateSlot = shortLog(ancestorState.get().slot),
    slot = shortLog(bs.slot),
    blockRoot = shortLog(bs.blck.root),
    ancestors = ancestors.len,
    service = "block_pool",
    category = "replay_state",
    process = "replay_state"

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
      process_slots(state.data, bs.slot)
      pool.maybePutState(state.data, bs.blck)

    return # State already at the right spot

  let ancestors = rewindState(pool, state, bs)

  # If we come this far, we found the state root. The last block on the stack
  # is the one that produced this particular state, so we can pop it
  # TODO it might be possible to use the latest block hashes from the state to
  #      do this more efficiently.. whatever!

  # Time to replay all the blocks between then and now. We skip one because
  # it's the one that we found the state with, and it has already been
  # applied
  for i in countdown(ancestors.len - 2, 0):
    let ok =
      skipAndUpdateState(state.data, ancestors[i].data, {skipValidation}) do(
        state: HashedBeaconState):
      pool.maybePutState(state, ancestors[i].refs)
    doAssert ok, "Blocks in database should never fail to apply.."

  # TODO check if this triggers rest of state transition, or should
  process_slots(state.data, bs.slot)
  pool.maybePutState(state.data, bs.blck)

  state.blck = bs.blck

proc loadTailState*(pool: BlockPool): StateData =
  ## Load the state associated with the current tail in the pool
  let stateRoot = pool.db.getBlock(pool.tail.root).get().state_root
  StateData(
    data: HashedBeaconState(
      data: pool.db.getState(stateRoot).get(),
      root: stateRoot),
    blck: pool.tail
  )

func isAncestorOf*(a, b: BlockRef): bool =
  if a == b:
    true
  elif a.slot >= b.slot or b.parent.isNil:
    false
  else:
    a.isAncestorOf(b.parent)

proc updateHead*(pool: BlockPool, state: var StateData, blck: BlockRef) =
  ## Update what we consider to be the current head, as given by the fork
  ## choice.
  ## The choice of head affects the choice of finalization point - the order
  ## of operations naturally becomes important here - after updating the head,
  ## blocks that were once considered potential candidates for a tree will
  ## now fall from grace, or no longer be considered resolved.
  if pool.head.blck == blck:
    info "[Block Pool] Fork choice - No head update",
      headBlockRoot = shortLog(blck.root),
      headBlockSlot = shortLog(blck.slot),
      service = "block_pool",
      category = "fork_choice",
      process = "fork_choice"

    return

  let
    lastHead = pool.head
  pool.db.putHeadBlock(blck.root)

  # Start off by making sure we have the right state
  updateStateData(pool, state, BlockSlot(blck: blck, slot: blck.slot))
  let justifiedSlot = state.data.data
                           .current_justified_checkpoint
                           .epoch
                           .compute_start_slot_of_epoch()
  pool.head = Head(blck: blck, justified: blck.findAncestorBySlot(justifiedSlot))

  if lastHead.blck != blck.parent:
    info "[Block Pool] Fork choice - Updated head (new parent)",
      lastHeadRoot = shortLog(lastHead.blck.root),
      parentRoot = shortLog(blck.parent.root),
      stateRoot = shortLog(state.data.root),
      headBlockRoot = shortLog(state.blck.root),
      stateSlot = shortLog(state.data.data.slot),
      justifiedEpoch = shortLog(state.data.data.current_justified_checkpoint.epoch),
      finalizedEpoch = shortLog(state.data.data.finalized_checkpoint.epoch),
      service = "block_pool",
      category = "fork_choice",
      process = "fork_choice"
  else:
    info "[Block Pool] Fork choice - Updated head",
      stateRoot = shortLog(state.data.root),
      headBlockRoot = shortLog(state.blck.root),
      stateSlot = shortLog(state.data.data.slot),
      justifiedEpoch = shortLog(state.data.data.current_justified_checkpoint.epoch),
      finalizedEpoch = shortLog(state.data.data.finalized_checkpoint.epoch),
      service = "block_pool",
      category = "fork_choice",
      process = "fork_choice"

  let
    # TODO there might not be a block at the epoch boundary - what then?
    finalizedHead =
      blck.findAncestorBySlot(
        state.data.data.finalized_checkpoint.epoch.compute_start_slot_of_epoch())

  doAssert (not finalizedHead.blck.isNil),
    "Block graph should always lead to a finalized block"

  if finalizedHead != pool.finalizedHead:
    info "[Block Pool] Fork choice - Finalized block",
      finalizedBlockRoot = shortLog(finalizedHead.blck.root),
      finalizedBlockSlot = shortLog(finalizedHead.slot),
      headBlockRoot = shortLog(blck.root),
      headBlockSlot = shortLog(blck.slot),
      service = "block_pool",
      category = "fork_choice",
      process = "fork_choice"

    var cur = finalizedHead.blck
    while cur != pool.finalizedHead.blck:
      # Finalization means that we choose a single chain as the canonical one -
      # it also means we're no longer interested in any branches from that chain
      # up to the finalization point

      # TODO technically, if we remove from children the gc should free the block
      #      because it should become orphaned, via mark&sweep if nothing else,
      #      though this needs verification
      # TODO what about attestations? we need to drop those too, though they
      #      *should* be pretty harmless
      # TODO remove from database as well.. here, or using some GC-like setup
      #      that periodically cleans it up?
      for child in cur.parent.children:
        if child != cur:
          pool.blocks.del(child.root)
      cur.parent.children = @[cur]
      cur = cur.parent

    pool.finalizedHead = finalizedHead

    let hlen = pool.heads.len
    for i in 0..<hlen:
      let n = hlen - i - 1
      if pool.heads[n].blck.slot < pool.finalizedHead.blck.slot and
          not pool.heads[n].blck.isAncestorOf(pool.finalizedHead.blck):
        pool.heads.del(n)

proc latestJustifiedBlock*(pool: BlockPool): BlockSlot =
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

proc preInit*(
    T: type BlockPool, db: BeaconChainDB, state: BeaconState, blck: BeaconBlock) =
  # write a genesis state, the way the BlockPool expects it to be stored in
  # database
  # TODO probably should just init a blockpool with the freshly written
  #      state - but there's more refactoring needed to make it nice - doing
  #      a minimal patch for now..
  let
    blockRoot = signing_root(blck)

  notice "[Block Pool] New database from snapshot",
    blockRoot = shortLog(blockRoot),
    stateRoot = shortLog(blck.state_root),
    fork = state.fork,
    validators = state.validators.len(),
    service = "block_pool",
    category = "initialization",
    process = "initialization"

  db.putState(state)
  db.putBlock(blck)
  db.putTailBlock(blockRoot)
  db.putHeadBlock(blockRoot)
  db.putStateRoot(blockRoot, blck.slot, blck.state_root)
