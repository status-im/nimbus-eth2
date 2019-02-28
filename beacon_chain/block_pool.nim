import
  bitops, chronicles, options, sequtils, sets, tables,
  ssz, beacon_chain_db, state_transition, extras,
  spec/[crypto, datatypes, digest]

type
  BlockPool* = ref object
    ## Pool of blocks responsible for keeping a graph of resolved blocks as well
    ## as candidates that may yet become part of that graph.
    ## Currently, this type works as a facade to the BeaconChainDB, making
    ## assumptions about the block composition therein.
    ##
    ## The general idea here is that blocks known to us are divided into two
    ## camps - unresolved and resolved. When we start the chain, we have a
    ## genesis state that serves as the root of the graph we're interested in.
    ## Every block that belongs to that chain will have a path to that block -
    ## conversely, blocks that do not are not interesting to us.
    ##
    ## As the chain progresses, some states become finalized as part of the
    ## consensus process. One way to think of that is that the blocks that
    ## come before them are no longer relevant, and the finalized state
    ## is the new genesis from which we build. Thus, instead of tracing a path
    ## to genesis, we can trace a path to any finalized block that follows - we
    ## call the oldest such block a tail block.
    ##
    ## It's important to note that blocks may arrive in any order due to
    ## chainging network conditions - we counter this by buffering unresolved
    ## blocks for some time while trying to establish a path.
    ##
    ## Once a path is established, the block becomes resolved. We store the
    ## graph in memory, in the form of BlockRef objects. This is also when
    ## we forward the block for storage in the database
    ##
    ## TODO evaluate the split of responsibilities between the two
    ## TODO prune the graph as tail moves

    pending*: Table[Eth2Digest, BeaconBlock] ##\
    ## Blocks that have passed validation but that we lack a link back to tail
    ## for - when we receive a "missing link", we can use this data to build
    ## an entire branch

    unresolved*: Table[Eth2Digest, UnresolvedBlock] ##\
    ## Roots of blocks that we would like to have (either parent_root of
    ## unresolved blocks or block roots of attestations)

    blocks*: Table[Eth2Digest, BlockRef] ##\
    ## Tree of blocks pointing back to a finalized block on the chain we're
    ## interested in - we call that block the tail

    tail*: BlockData ##\
    ## The earliest finalized block we know about

    db*: BeaconChainDB

  UnresolvedBlock = object
    tries*: int

  BlockRef* = ref object {.acyclic.}
    ## Node in object graph guaranteed to lead back to tail block, and to have
    ## a corresponding entry in database.
    ## Block graph should form a tree - in particular, there are no cycles.

    root*: Eth2Digest ##\
    ## Root that can be used to retrieve block data from database

    parent*: BlockRef ##\
    ## Not nil, except for the tail

    children*: seq[BlockRef]

  BlockData* = object
    ## Body and graph in one

    data*: BeaconBlock
    refs*: BlockRef

  StateData* = object
    data*: BeaconState
    root*: Eth2Digest ##\
    ## Root of above data (cache)

    blck*: BlockRef ##\
    ## The block associated with the state found in data - in particular,
    ## blck.state_root == root

proc link(parent, child: BlockRef) =
  doAssert (not (parent.root == Eth2Digest() or child.root == Eth2Digest())),
    "blocks missing root!"
  doAssert parent.root != child.root, "self-references not allowed"

  child.parent = parent
  parent.children.add(child)

proc init*(T: type BlockPool, db: BeaconChainDB): BlockPool =
  # TODO we require that the db contains both a head and a tail block -
  #      asserting here doesn't seem like the right way to go about it however..
  # TODO head is updated outside of block pool but read here - ugly.

  let
    tail = db.getTailBlock()
    head = db.getHeadBlock()

  doAssert tail.isSome(), "Missing tail block, database corrupt?"
  doAssert head.isSome(), "Missing head block, database corrupt?"

  let
    headRoot = head.get()
    tailRoot = tail.get()
    tailRef = BlockRef(root: tailRoot)

  var blocks = {tailRef.root: tailRef}.toTable()

  if headRoot != tailRoot:
    var curRef: BlockRef

    for root, _ in db.getAncestors(headRoot):
      if root == tailRef.root:
        link(tailRef, curRef)
        curRef = curRef.parent
        break

      if curRef == nil:
        curRef = BlockRef(root: root)
      else:
        link(BlockRef(root: root), curRef)
        curRef = curRef.parent
      blocks[curRef.root] = curRef

    doAssert curRef == tailRef,
      "head block does not lead to tail, database corrupt?"

  BlockPool(
    pending: initTable[Eth2Digest, BeaconBlock](),
    unresolved: initTable[Eth2Digest, UnresolvedBlock](),
    blocks: blocks,
    tail: BlockData(
      data: db.getBlock(tailRef.root).get(),
      refs: tailRef,
    ),
    db: db
  )

proc add*(pool: var BlockPool, blockRoot: Eth2Digest, blck: BeaconBlock): bool =
  ## return false indicates that the block parent was missing and should be
  ## fetched
  ## TODO reevaluate this API - it's pretty ugly with the bool return
  doAssert blockRoot == hash_tree_root_final(blck)

  # Already seen this block??
  if blockRoot in pool.blocks:
    debug "Block already exists",
      slot = humaneSlotNum(blck.slot),
      stateRoot = shortLog(blck.state_root),
      parentRoot = shortLog(blck.parent_root),
      blockRoot = shortLog(blockRoot)

    return true

  # The tail block points to a cutoff time beyond which we don't store blocks -
  # if we receive a block with an earlier slot, there's no hope of ever
  # resolving it
  if blck.slot <= pool.tail.data.slot:
    debug "Old block, dropping",
      slot = humaneSlotNum(blck.slot),
      tailSlot = humaneSlotNum(pool.tail.data.slot),
      stateRoot = shortLog(blck.state_root),
      parentRoot = shortLog(blck.parent_root),
      blockRoot = shortLog(blockRoot)

    return true

  # TODO we should now validate the block to ensure that it's sane - but the
  #      only way to do that is to apply it to the state... for now, we assume
  #      all blocks are good!
  let parent = pool.blocks.getOrDefault(blck.parent_root)

  if parent != nil:
    # The block is resolved, nothing more to do!
    let blockRef = BlockRef(
      root: blockRoot
    )
    link(parent, blockRef)

    pool.blocks[blockRoot] = blockRef
    # The block might have been in either of these - we don't want any more
    # work done on its behalf
    pool.unresolved.del(blockRoot)
    pool.pending.del(blockRoot)

    # Resolved blocks should be stored in database
    pool.db.putBlock(blockRoot, blck)

    info "Block resolved",
      blockRoot = shortLog(blockRoot),
      slot = humaneSlotNum(blck.slot),
      stateRoot = shortLog(blck.state_root),
      parentRoot = shortLog(blck.parent_root),
      signature = shortLog(blck.signature),
      proposer_slashings = blck.body.proposer_slashings.len,
      attester_slashings = blck.body.attester_slashings.len,
      attestations = blck.body.attestations.len,
      deposits = blck.body.deposits.len,
      voluntary_exits = blck.body.voluntary_exits.len,
      transfers = blck.body.transfers.len

    # Now that we have the new block, we should see if any of the previously
    # unresolved blocks magically become resolved
    # TODO there are more efficient ways of doing this, that also don't risk
    #      running out of stack etc
    let retries = pool.pending
    for k, v in retries:
      discard pool.add(k, v)

    return true

  # TODO possibly, it makes sense to check the database - that would allow sync
  #      to simply fill up the database with random blocks the other clients
  #      think are useful - but, it would also risk filling the database with
  #      junk that's not part of the block graph

  if blck.parent_root in pool.unresolved:
    return true

  # This is an unresolved block - put it on the unresolved list for now...
  debug "Unresolved block",
    slot = humaneSlotNum(blck.slot),
    stateRoot = shortLog(blck.state_root),
    parentRoot = shortLog(blck.parent_root),
    blockRoot = shortLog(blockRoot)

  pool.unresolved[blck.parent_root] = UnresolvedBlock()
  pool.pending[blockRoot] = blck

  false

proc get*(pool: BlockPool, blck: BlockRef): BlockData =
  ## Retrieve the associated block body of a block reference
  doAssert (not blck.isNil), "Trying to get nil BlockRef"

  let data = pool.db.getBlock(blck.root)
  doAssert data.isSome, "BlockRef without backing data, database corrupt?"

  BlockData(data: data.get(), refs: blck)

proc get*(pool: BlockPool, root: Eth2Digest): Option[BlockData] =
  ## Retrieve a resolved block reference and its associated body, if available
  let refs = pool.blocks.getOrDefault(root)

  if not refs.isNil:
    some(pool.get(refs))
  else:
    none(BlockData)

proc getOrResolve*(pool: var BlockPool, root: Eth2Digest): BlockRef =
  ## Fetch a block ref, or nil if not found (will be added to list of
  ## blocks-to-resolve)
  result = pool.blocks.getOrDefault(root)

  if result.isNil:
    pool.unresolved[root] = UnresolvedBlock()

proc checkUnresolved*(pool: var BlockPool): seq[Eth2Digest] =
  ## Return a list of blocks that we should try to resolve from other client -
  ## to be called periodically but not too often (once per slot?)
  var done: seq[Eth2Digest]

  for k, v in pool.unresolved.mpairs():
    if v.tries > 8:
      done.add(k)
    else:
      inc v.tries

  for k in done:
    pool.unresolved.del(k)

  # simple (simplistic?) exponential backoff for retries..
  for k, v in pool.unresolved.pairs():
    if v.tries.popcount() == 1:
      result.add(k)

proc skipAndUpdateState(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  skipSlots(state, blck.parent_root, blck.slot - 1)
  updateState(state, blck.parent_root, some(blck), flags)

proc updateState*(
    pool: BlockPool, state: var StateData, blck: BlockRef) =
  if state.blck.root == blck.root:
    return # State already at the right spot

  # TODO this blockref should never be created, since we trace every blockref
  #      back to the tail block
  doAssert (not blck.parent.isNil), "trying to apply genesis block!"

  var ancestors = @[pool.get(blck)]

  # Common case: blck points to a block that is one step ahead of state
  if state.blck.root == blck.parent.root:
    let ok = skipAndUpdateState(state.data, ancestors[0].data, {skipValidation})
    doAssert ok, "Blocks in database should never fail to apply.."
    state.blck = blck
    state.root = ancestors[0].data.state_root

    return

  # It appears that the parent root of the proposed new block is different from
  # what we expected. We will have to rewind the state to a point along the
  # chain of ancestors of the new block. We will do this by loading each
  # successive parent block and checking if we can find the corresponding state
  # in the database.
  while not ancestors[^1].refs.parent.isNil:
    let parent = pool.get(ancestors[^1].refs.parent)
    ancestors.add parent

    if pool.db.containsState(parent.data.state_root): break

  let
    ancestor = ancestors[^1]
    ancestorState = pool.db.getState(ancestor.data.state_root)

  if ancestorState.isNone():
    # TODO this should only happen if the database is corrupt - we walked the
    #      list of parent blocks and couldn't find a corresponding state in the
    #      database, which should never happen (at least we should have the
    #      tail state in there!)
    error "Couldn't find ancestor state or block parent missing!",
      blockRoot = shortLog(blck.root)
    doAssert false, "Oh noes, we passed big bang!"

  notice "Replaying state transitions",
    stateSlot = humaneSlotNum(state.data.slot),
    prevStateSlot = humaneSlotNum(ancestorState.get().slot),
    ancestors = ancestors.len

  state.data = ancestorState.get()

  # If we come this far, we found the state root. The last block on the stack
  # is the one that produced this particular state, so we can pop it
  # TODO it might be possible to use the latest block hashes from the state to
  #      do this more efficiently.. whatever!

  # Time to replay all the blocks between then and now. We skip the one because
  # it's the one that we found the state with, and it has already been
  # applied
  for i in countdown(ancestors.len - 2, 0):
    let last = ancestors[i]

    skipSlots(state.data, last.data.parent_root, last.data.slot - 1)

    # TODO technically, we should be adding states to the database here because
    #      we're going down a different fork..
    let ok = updateState(
      state.data, last.data.parent_root, some(last.data), {skipValidation})

    doAssert(ok)

  state.blck = blck
  state.root = ancestors[0].data.state_root

proc loadTailState*(pool: BlockPool): StateData =
  ## Load the state associated with the current tail in the pool
  StateData(
    data: pool.db.getState(pool.tail.data.state_root).get(),
    root: pool.tail.data.state_root,
    blck: pool.tail.refs
  )
