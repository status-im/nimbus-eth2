# beacon_chain
# Copyright (c) 2019-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  std/[deques, math],
  chronicles,
  ../spec/forks,
  ../beacon_chain_db,
  ./block_pools_types

export forks, block_pools_types

logScope:
  topics = "clearance"

# Clearance (light client)
# ---------------------------------------------
#
# This module validates blocks obtained using the light client sync protocol.
# Those blocks are considered trusted by delegating the full verification to a
# supermajority (> 2/3) of the corresponding sync committee (512 members).
# The validated blocks are downloaded in backwards order into a `deque`.
#
# If the sync committee is trusted, expensive verification already done by the
# sync committee may be skipped:
# - BLS signatures (except the outer block signature not covered by `root`)
# - Verifying whether the state transition function applies
# - `ExecutionPayload` verification
# - `state_root` computation and verification

type LCBlocks* = object
  maxSlots: int # max cache.len
  cache: Deque[ref ForkedMsgTrustedSignedBeaconBlock] # by slots descending
  headSlot: Slot # matches cache[0].slot once block is downloaded
  backfill: BeaconBlockSummary # next expected block
  finalizedBid: BlockId

func initLCBlocks*(maxSlots: int): LCBlocks =
  LCBlocks(
    maxSlots: maxSlots,
    cache: initDeque[ref ForkedMsgTrustedSignedBeaconBlock](
      nextPowerOfTwo(maxSlots)),
    headSlot: FAR_FUTURE_SLOT)

func getHeadSlot*(lcBlocks: LCBlocks): Slot =
  lcBlocks.headSlot

func getFinalizedSlot*(lcBlocks: LCBlocks): Slot =
  lcBlocks.finalizedBid.slot

func getFrontfillSlot*(lcBlocks: LCBlocks): Slot =
  lcBlocks.headSlot + 1 - lcBlocks.cache.lenu64

func getBackfillSlot*(lcBlocks: LCBlocks): Slot =
  if lcBlocks.backfill.slot != FAR_FUTURE_SLOT:
    max(lcBlocks.backfill.slot, lcBlocks.getFrontfillSlot())
  else:
    lcBlocks.headSlot + 1

func getBackfillRoot*(lcBlocks: LCBlocks): Option[Eth2Digest] =
  if lcBlocks.headSlot == FAR_FUTURE_SLOT:
    none(Eth2Digest)
  elif lcBlocks.backfill.slot < lcBlocks.getFrontfillSlot():
    none(Eth2Digest)
  else:
    some lcBlocks.backfill.parent_root

func getCacheIndex(lcBlocks: LCBlocks, slot: Slot): uint64 =
  if slot < lcBlocks.headSlot and lcBlocks.headSlot != FAR_FUTURE_SLOT:
    lcBlocks.headSlot - slot
  else:
    0

func getBlockAtSlot*(
    lcBlocks: LCBlocks, slot: Slot): Opt[ForkedMsgTrustedSignedBeaconBlock] =
  if slot < lcBlocks.backfill.slot:
    return err()

  let index = lcBlocks.getCacheIndex(slot)
  if index >= lcBlocks.cache.lenu64:
    return err()
  let existing = lcBlocks.cache[index]
  if existing == nil:
    return err()
  return ok existing[]

func getLatestBlockThroughSlot*(
    lcBlocks: LCBlocks, maxSlot: Slot): Opt[ForkedMsgTrustedSignedBeaconBlock] =
  if maxSlot < lcBlocks.backfill.slot:
    return err()

  let startIndex = lcBlocks.getCacheIndex(maxSlot)
  for i in startIndex ..< lcBlocks.cache.lenu64:
    let blck = lcBlocks.cache[i]
    if blck != nil:
      return ok blck[]
  err()

proc processBlock(
    lcBlocks: var LCBlocks,
    signedBlock: ForkySignedBeaconBlock,
    isNewBlock = true): Result[void, BlockError] =
  logScope:
    headSlot = lcBlocks.headSlot
    backfill = (lcBlocks.backfill.slot, shortLog(lcBlocks.backfill.parent_root))
    blck = shortLog(signedBlock.toBlockId())

  let startTick = Moment.now()

  template blck(): untyped = signedBlock.message
  template blockRoot(): untyped = signedBlock.root

  if blck.slot > lcBlocks.headSlot:
    debug "LC block too new"
    return err(BlockError.Duplicate)

  # Handle head block
  if lcBlocks.backfill.slot == FAR_FUTURE_SLOT:
    if blck.slot < lcBlocks.headSlot:
      if isNewBlock:
        debug "Head LC block skipped"
      return err(BlockError.MissingParent)

    if blockRoot != lcBlocks.backfill.parent_root:
      if isNewBlock:
        debug "Head LC block from unviable fork"
      return err(BlockError.UnviableFork)

    const index = 0'u64 # Head block is always mapped to index 0 (never empty)
    if index >= lcBlocks.cache.lenu64:
      lcBlocks.backfill.slot = blck.slot
      debug "Final head LC block"
      return ok()

    lcBlocks.backfill = blck.toBeaconBlockSummary()
    let existing = lcBlocks.cache[index]
    if existing != nil:
      if blockRoot == existing[].root:
        if isNewBlock:
          debug "Head LC block already known"
        return ok()
      warn "Head LC block reorg", existing = existing[]
    lcBlocks.cache[index] =
      newClone ForkedMsgTrustedSignedBeaconBlock.init(
        signedBlock.asMsgTrusted())
    debug "Head LC block cached", cacheDur = Moment.now() - startTick
    return ok()

  # Handle duplicate block
  if blck.slot >= lcBlocks.getBackfillSlot():
    let index = lcBlocks.getCacheIndex(blck.slot)
    doAssert index < lcBlocks.cache.lenu64
    let existing = lcBlocks.cache[index]
    if existing == nil:
      debug "Duplicate LC block for empty slot"
      return err(BlockError.UnviableFork)

    doAssert blck.slot == existing[].slot
    if blockRoot != existing[].root:
      debug "Duplicate LC block from unviable fork"
      return err(BlockError.UnviableFork)

    debug "Duplicate LC block"
    return err(BlockError.Duplicate)

  # Handle new block
  if blck.slot > lcBlocks.backfill.slot:
    debug "LC block for empty slot"
    return err(BlockError.UnviableFork)

  if blockRoot != lcBlocks.backfill.parent_root:
    if blck.slot == lcBlocks.backfill.slot:
      debug "Final LC block from unviable fork"
      return err(BlockError.UnviableFork)
    if isNewBlock:
      debug "LC block does not match expected backfill root"
    return err(BlockError.MissingParent)

  if blck.slot == lcBlocks.backfill.slot:
    debug "Duplicate final LC block"
    return err(BlockError.Duplicate)

  let
    previousIndex = lcBlocks.getCacheIndex(lcBlocks.backfill.slot)
    index = lcBlocks.getCacheIndex(blck.slot)
  for i in previousIndex + 1 ..< min(index, lcBlocks.cache.lenu64):
    let existing = lcBlocks.cache[i]
    if existing != nil:
      warn "LC block reorg to empty", existing = existing[]
      lcBlocks.cache[i] = nil

  if index >= lcBlocks.cache.lenu64:
    lcBlocks.backfill.slot = blck.slot
    debug "Final LC block"
    return ok()

  lcBlocks.backfill = blck.toBeaconBlockSummary()
  let existing = lcBlocks.cache[index]
  if existing != nil:
    if blockRoot == existing[].root:
      if isNewBlock:
        debug "LC block already known"
      return ok()
    warn "LC block reorg", existing = existing[]
  lcBlocks.cache[index] =
    newClone ForkedMsgTrustedSignedBeaconBlock.init(
      signedBlock.asMsgTrusted())
  debug "LC block cached", cacheDur = Moment.now() - startTick
  ok()

proc setHeadBid*(lcBlocks: var LCBlocks, headBid: BlockId) =
  debug "New LC head block", headBid
  if lcBlocks.maxSlots == 0:
    discard

  elif lcBlocks.headSlot == FAR_FUTURE_SLOT or
      headBid.slot >= lcBlocks.headSlot + lcBlocks.maxSlots.uint64 or (
      lcBlocks.headSlot - lcBlocks.cache.lenu64 != FAR_FUTURE_SLOT and
      headBid.slot <= lcBlocks.headSlot - lcBlocks.cache.lenu64):
    lcBlocks.cache.clear()
    for i in 0 ..< min(headBid.slot + 1, lcBlocks.maxSlots.Slot).int:
      lcBlocks.cache.addLast(nil)

  elif headBid.slot > lcBlocks.headSlot:
    let numNewSlots = headBid.slot - lcBlocks.headSlot
    doAssert numNewSlots <= lcBlocks.maxSlots.uint64
    if numNewSlots > lcBlocks.maxSlots.uint64 - lcBlocks.cache.lenu64:
      lcBlocks.cache.shrink(
        fromLast = numNewSlots.int + lcBlocks.cache.len - lcBlocks.maxSlots)
    for i in 0 ..< numNewSlots:
      lcBlocks.cache.addFirst(nil)

  else:
    lcBlocks.cache.shrink(fromFirst = (lcBlocks.headSlot - headBid.slot).int)
    let startLen = lcBlocks.cache.len
    for i in startLen ..< min(headBid.slot + 1, lcBlocks.maxSlots.Slot).int:
      lcBlocks.cache.addLast(nil)

  lcBlocks.headSlot = headBid.slot
  lcBlocks.backfill.slot = FAR_FUTURE_SLOT
  lcBlocks.backfill.parent_root = headBid.root

  for i in 0 ..< lcBlocks.cache.len:
    let existing = lcBlocks.cache[i]
    if existing != nil:
      let res =
        withBlck(existing[]):
          lcBlocks.processBlock(blck.asSigned(), isNewBlock = false)
      if res.isErr:
        break

proc setFinalizedBid*(lcBlocks: var LCBlocks, finalizedBid: BlockId) =
  if finalizedBid.slot > lcBlocks.headSlot:
    lcBlocks.setHeadBid(finalizedBid)
  if finalizedBid != lcBlocks.finalizedBid:
    debug "New LC finalized block", finalizedBid
    lcBlocks.finalizedBid = finalizedBid

  if finalizedBid.slot <= lcBlocks.headSlot and
      finalizedBid.slot >= lcBlocks.getBackfillSlot:
    let index = lcBlocks.getCacheIndex(finalizedBid.slot)
    doAssert index < lcBlocks.cache.lenu64
    let existing = lcBlocks.cache[index]
    if existing == nil or finalizedBid.root != existing[].root:
      if existing != nil:
        error "Finalized LC block reorg", existing = existing[]
      else:
        error "Finalized LC block reorg"
      lcBlocks.cache.clear()
      lcBlocks.backfill.reset()
      lcBlocks.headSlot.reset()
      lcBlocks.setHeadBid(finalizedBid)

proc addBlock*(
    lcBlocks: var LCBlocks,
    signedBlock: ForkedSignedBeaconBlock): Result[void, BlockError] =
  let oldBackfillSlot = lcBlocks.getBackfillSlot()

  withBlck(signedBlock):
    ? lcBlocks.processBlock(blck)

  if oldBackfillSlot > lcBlocks.finalizedBid.slot and
      lcBlocks.getBackfillSlot() <= lcBlocks.finalizedBid.slot:
    if signedBlock.slot != lcBlocks.finalizedBid.slot or
        signedBlock.root != lcBlocks.finalizedBid.root:
      error "LC finalized block from unviable fork"
      lcBlocks.setFinalizedBid(lcBlocks.finalizedBid)
      return err(BlockError.UnviableFork)

  let slot = signedBlock.slot
  for i in lcBlocks.getCacheIndex(slot) + 1 ..< lcBlocks.cache.lenu64:
    let existing = lcBlocks.cache[i]
    if existing != nil:
      let res =
        withBlck(existing[]):
          lcBlocks.processBlock(blck.asSigned(), isNewBlock = false)
      if res.isErr:
        break

  ok()
