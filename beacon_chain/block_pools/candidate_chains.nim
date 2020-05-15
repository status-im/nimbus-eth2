# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles, options, tables,
  metrics,
  ../ssz, ../beacon_chain_db,
  ../spec/[crypto, datatypes, digest],
  block_pools_types

{.push raises: [Defect].}
logScope: topics = "dag"

proc putBlock*(dag: var CandidateChains, blockRoot: Eth2Digest, signedBlock: SignedBeaconBlock) {.inline.} =
  dag.db.putBlock(blockRoot, signedBlock)

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

# CandidateChains init
# --------------------------------------------
#
# Interleaved with Rewinder at the moment
# 1. Get the Head, Tail and DAG
# 2. Find the most recent state from the DB
# 3. Compute the justified and finalized blocks from it

proc loadDAG*(db: BeaconChainDB): tuple[blocks: Table[Eth2Digest, BlockRef], headRef, tailRef: BlockRef] =
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
      trace "Populating block DAG", key = curRef.root, val = curRef

    doAssert curRef == tailRef,
      "head block does not lead to tail, database corrupt?"
  else:
    headRef = tailRef

  (blocks, headRef, tailRef)

proc init*(T: type CandidateChains, db: BeaconChainDB,
           blocks: Table[Eth2Digest, BlockRef],
           headRef, tailRef: BLockRef,
           justifiedHead: BlockSlot,
           finalizedHead: BlockSlot): CandidateChains =
  # We presently save states on the epoch boundary - it means that the latest
  # state we loaded might be older than head block - nonetheless, it will be
  # from the same epoch as the head, thus the finalized and justified slots are
  # the same - these only change on epoch boundaries.
  let head = Head(blck: headRef, justified: justifiedHead)

  let res = CandidateChains(
    blocks: blocks,
    tail: tailRef,
    head: head,
    finalizedHead: finalizedHead,
    db: db,
    heads: @[head]
  )

  info "CandidateChains initialized",
    head = head.blck, justifiedHead, finalizedHead, tail = tailRef,
    totalBlocks = blocks.len

  res

# --------------------------------------------

func getRef*(dag: CandidateChains, root: Eth2Digest): BlockRef =
  ## Retrieve a resolved block reference, if available
  dag.blocks.getOrDefault(root, nil)

func getBlockRange*(
    dag: CandidateChains, startSlot: Slot, skipStep: Natural,
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
    head = shortLog(dag.head.blck.root), count, startSlot, skipStep

  let
    skipStep = max(1, skipStep) # Treat 0 step as 1
    endSlot = startSlot + uint64(count * skipStep)

  var
    b = dag.head.blck.atSlot(endSlot)
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

func getBlockBySlot*(dag: CandidateChains, slot: Slot): BlockRef =
  ## Retrieves the first block in the current canonical chain
  ## with slot number less or equal to `slot`.
  dag.head.blck.atSlot(slot).blck

func getBlockByPreciseSlot*(dag: CandidateChains, slot: Slot): BlockRef =
  ## Retrieves a block from the canonical chain with a slot
  ## number equal to `slot`.
  let found = dag.getBlockBySlot(slot)
  if found.slot != slot: found else: nil

proc get*(dag: CandidateChains, blck: BlockRef): BlockData =
  ## Retrieve the associated block body of a block reference
  # TODO: Duplicated in Rewinder
  doAssert (not blck.isNil), "Trying to get nil BlockRef"

  let data = dag.db.getBlock(blck.root)
  doAssert data.isSome, "BlockRef without backing data, database corrupt?"

  BlockData(data: data.get(), refs: blck)

proc get*(dag: CandidateChains, root: Eth2Digest): Option[BlockData] =
  ## Retrieve a resolved block reference and its associated body, if available
  let refs = dag.getRef(root)

  if not refs.isNil:
    some(dag.get(refs))
  else:
    none(BlockData)

func latestJustifiedBlock*(dag: CandidateChains): BlockSlot =
  ## Return the most recent block that is justified and at least as recent
  ## as the latest finalized block

  doAssert dag.heads.len > 0,
    "We should have at least the genesis block in heaads"
  doAssert (not dag.head.blck.isNil()),
    "Genesis block will be head, if nothing else"

  # Prefer stability: use justified block from current head to break ties!
  result = dag.head.justified
  for head in dag.heads[1 ..< ^0]:
    if head.justified.slot > result.slot:
      result = head.justified

proc preInit*(
    T: type CandidateChains, db: BeaconChainDB, state: BeaconState,
    signedBlock: SignedBeaconBlock) =
  # write a genesis state, the way the CandidateChains expects it to be stored in
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

proc isInitialized*(T: type CandidateChains, db: BeaconChainDB): bool =
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

proc putHeadBlock*(dag: var CandidateChains, key: Eth2Digest) {.inline.}=
  dag.db.putHeadBlock(key)

proc delBlock*(dag: var CandidateChains, key: Eth2Digest) {.inline.}=
  dag.db.delBlock(key)
