# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  chronicles,
  ../spec/forks,
  ../beacon_chain_db,
  ./block_pools_types

logScope:
  topics = "clearance"

# Clearance (light client)
# ---------------------------------------------
#
# This module validates blocks obtained using the light client sync protocol.
# Those blocks are considered trusted by delegating the full verification to a
# supermajority (> 2/3) of the corresponding sync committee (512 members).
#
# The validated blocks are downloaded in backwards order and cached in a `seq`
# before they are applied to the chain DAG in forward order, skipping expensive
# verification as that is trusted to be already done by the sync committee:
# - BLS signatures (except the outer block signature not covered by `root`)
# - Verifying whether the state transition function applies
# - `ExecutionPayload` verification
# - `state_root` verification

func getBlockIdAtSlot(
    trustedBlocks: seq[ForkedSignedBeaconBlock],
    slot: Slot): Opt[BlockSlotId] =
  ## Obtain the block id of a cached trusted block.
  ## `trustedBlocks` is ordered by slot descending.
  if trustedBlocks.len == 0:
    return err()
  if slot > trustedBlocks[0].slot or slot < trustedBlocks[^1].slot:
    return err()

  # If all slots from the given slot through the lowest known one are filled,
  # the slot index can be computed perfectly. Otherwise, the index will point
  # to a block with a higher slot number and some more scanning is needed.
  let
    numSlotsDiff = slot - trustedBlocks[^1].slot
    guessedIndex =
      if numSlotsDiff < trustedBlocks.lenu64:
        (trustedBlocks.lenu64 - 1) - numSlotsDiff
      else:
        0
  for i in guessedIndex ..< trustedBlocks.lenu64:
    if trustedBlocks[i].slot == slot:
      return ok BlockSlotId.init(
        BlockId(root: trustedBlocks[i].root, slot: slot), slot)
    if trustedBlocks[i].slot < slot:
      break
  return err()

proc cacheTrustedBlock*(
    trustedBlocks: var seq[ForkedSignedBeaconBlock],
    signedBlock: ForkySignedBeaconBlock,
    backfill: var BeaconBlockSummary): Result[void, BlockError] =
  ## Trusted blocks fill in future data not currently present in the DAG.
  ## They are added in backwards order, based on the previous `parent_root`.
  ##
  ## `backfill` must be initialized with `parent_root` being set to the root of
  ## the trusted header itself, instead of its `parent_root` member.
  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)
    signature = shortLog(signedBlock.signature)
    backfill = (backfill.slot, shortLog(backfill.parent_root))

  template blck(): untyped = signedBlock.message
  template blockRoot(): untyped = signedBlock.root

  let startTick = Moment.now()
  template acceptBlock() =
    # Because these blocks are based on future data, they may have been signed
    # by a proposer that the local DAG does not know about yet. Block signatures
    # need to be checked later, as the cached blocks are applied to the DAG.
    trustedBlocks.add(ForkedSignedBeaconBlock.init(signedBlock))
    backfill = blck.toBeaconBlockSummary()
    debug "Trusted block cached", cacheDur = Moment.now() - startTick

  # Handle initial block special case (different meaning of `backfill`)
  if trustedBlocks.len == 0:
    if blck.slot > backfill.slot:
      debug "Initial trusted block out of verifiable range"
      return err(BlockError.Duplicate)

    if blck.slot < backfill.slot:
      debug "Initial trusted block slot was skipped"
      return err(BlockError.MissingParent)

    if blockRoot != backfill.parent_root:
      debug "Initial trusted block from unviable fork"
      return err(BlockError.UnviableFork)

    acceptBlock()
    return ok()

  # Handle blocks in known history
  if blck.slot >= backfill.slot:
    if blck.slot > trustedBlocks[0].slot:
      debug "Trusted block out of verifiable range"
      return err(BlockError.Duplicate)

    let existing = trustedBlocks.getBlockIdAtSlot(blck.slot)
    if existing.isNone:
      debug "Trusted block for slot known to be empty"
      return err(BlockError.UnviableFork)

    if existing.get.bid.slot != blck.slot or existing.get.bid.root != blockRoot:
      debug "Trusted block from unviable fork",
        existing = shortLog(existing.get)
      return err(BlockError.UnviableFork)

    debug "Duplicate trusted block"
    return err(BlockError.Duplicate)

  # Handle new block
  if blockRoot != backfill.parent_root:
    debug "Trusted block does not match expected backfill root"
    return err(BlockError.MissingParent)

  acceptBlock()
  ok()
