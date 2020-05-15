# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  extras, beacon_chain_db,
  spec/[crypto, datatypes, digest, helpers]


import
  block_pools/[block_pools_types, clearance, candidate_chains, quarantine, rewinder, update_head]

# Block_Pools
# --------------------------------------------
#
# Compatibility shims to minimize PR breakage
# during block_pool refactor

type
  BlockPools* = object
    # TODO: Rename BlockPools
    quarantine: Quarantine
    dag: CandidateChains
    rewinder: Rewinder

  BlockPool* = BlockPools

{.push raises: [Defect], inline.}

# Quarantine dispatch
# --------------------------------------------

func checkMissing*(pool: var BlockPool): seq[FetchRecord] {.noInit.} =
  checkMissing(pool.quarantine)

# CandidateChains
# --------------------------------------------

template tail*(pool: BlockPool): BlockRef =
  pool.dag.tail

template heads*(pool: BlockPool): seq[Head] =
  pool.dag.heads

template head*(pool: BlockPool): Head =
  pool.dag.head

template finalizedHead*(pool: BlockPool): BlockSlot =
  pool.dag.finalizedHead

proc add*(pool: var BlockPool, blockRoot: Eth2Digest,
          signedBlock: SignedBeaconBlock): BlockRef {.gcsafe.} =
  add(pool.dag, pool.quarantine, pool.rewinder, blockRoot, signedBlock)

export parent        # func parent*(bs: BlockSlot): BlockSlot
export isAncestorOf  # func isAncestorOf*(a, b: BlockRef): bool
export getAncestorAt # func isAncestorOf*(a, b: BlockRef): bool
export get_ancestor  # func get_ancestor*(blck: BlockRef, slot: Slot): BlockRef
export atSlot        # func atSlot*(blck: BlockRef, slot: Slot): BlockSlot


proc init*(T: type BlockPools, db: BeaconChainDB,
    updateFlags: UpdateFlags = {}): BlockPools =

  let (blocks, headRef, tailRef) = db.loadDAG()
  let mostRecentState = db.getMostRecentState(headRef.atSlot(headRef.slot))

  let
    finalizedSlot =
        mostRecentState.data.data.finalized_checkpoint.epoch.compute_start_slot_at_epoch()
    finalizedHead = headRef.atSlot(finalizedSlot)
    justifiedSlot =
      mostRecentState.data.data.current_justified_checkpoint.epoch.compute_start_slot_at_epoch()
    justifiedHead = headRef.atSlot(justifiedSlot)

  doAssert justifiedHead.slot >= finalizedHead.slot,
    "justified head comes before finalized head - database corrupt?"

  result.dag = CandidateChains.init(db, blocks, headRef, tailRef, justifiedHead, finalizedHead)
  result.rewinder = Rewinder.init(
    db, headRef.atSlot(headRef.slot),
    justifiedHead, mostRecentState, updateFlags)

export init          # func init*(T: type BlockRef, root: Eth2Digest, blck: BeaconBlock): BlockRef

func getRef*(pool: BlockPool, root: Eth2Digest): BlockRef =
  ## Retrieve a resolved block reference, if available
  pool.dag.getRef(root)

func getBlockRange*(
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
  pool.dag.getBlockRange(startSlot, skipStep, output)

func getBlockBySlot*(pool: BlockPool, slot: Slot): BlockRef =
  ## Retrieves the first block in the current canonical chain
  ## with slot number less or equal to `slot`.
  pool.dag.getBlockBySlot(slot)

func getBlockByPreciseSlot*(pool: BlockPool, slot: Slot): BlockRef =
  ## Retrieves a block from the canonical chain with a slot
  ## number equal to `slot`.
  pool.dag.getBlockByPreciseSlot(slot)

proc get*(pool: BlockPool, blck: BlockRef): BlockData =
  ## Retrieve the associated block body of a block reference
  pool.dag.get(blck)

proc get*(pool: BlockPool, root: Eth2Digest): Option[BlockData] =
  ## Retrieve a resolved block reference and its associated body, if available
  pool.dag.get(root)

func getOrResolve*(pool: var BlockPool, root: Eth2Digest): BlockRef =
  ## Fetch a block ref, or nil if not found (will be added to list of
  ## blocks-to-resolve)
  getOrResolve(pool.dag, pool.quarantine, root)

proc updateHead*(pool: var BlockPool, newHead: BlockRef) =
  ## Update what we consider to be the current head, as given by the fork
  ## choice.
  ## The choice of head affects the choice of finalization point - the order
  ## of operations naturally becomes important here - after updating the head,
  ## blocks that were once considered potential candidates for a tree will
  ## now fall from grace, or no longer be considered resolved.
  updateHead(pool.dag, pool.rewinder, newHead)

proc latestJustifiedBlock*(pool: BlockPool): BlockSlot =
  ## Return the most recent block that is justified and at least as recent
  ## as the latest finalized block
  latestJustifiedBlock(pool.dag)

proc preInit*(
    T: type BlockPool, db: BeaconChainDB, state: BeaconState,
    signedBlock: SignedBeaconBlock) =
  preInit(CandidateChains, db, state, signedBlock)

proc isInitialized*(T: type BlockPool, db: BeaconChainDB): bool =
  isInitialized(CandidateChains, db)

# Rewinder / State transitions
# --------------------------------------------

template headState*(pool: BlockPool): StateData =
  pool.rewinder.headState

template tmpState*(pool: BlockPool): StateData =
  pool.rewinder.tmpState

template justifiedState*(pool: BlockPool): StateData =
  pool.rewinder.justifiedState

template withState*(
    pool: BlockPool, cache: var StateData, blockSlot: BlockSlot, body: untyped): untyped =
  ## Helper template that updates state to a particular BlockSlot - usage of
  ## cache is unsafe outside of block.
  ## TODO async transformations will lead to a race where cache gets updated
  ##      while waiting for future to complete - catch this here somehow?

  withState(pool.rewinder, cache, blockSlot, body)

proc updateStateData*(pool: BlockPool, state: var StateData, bs: BlockSlot) =
  ## Rewind or advance state such that it matches the given block and slot -
  ## this may include replaying from an earlier snapshot if blck is on a
  ## different branch or has advanced to a higher slot number than slot
  ## If slot is higher than blck.slot, replay will fill in with empty/non-block
  ## slots, else it is ignored
  updateStateData(pool.rewinder, state, bs)

proc loadTailState*(pool: BlockPool): StateData =
  loadTailState(pool.rewinder, pool.dag)

proc isValidBeaconBlock*(pool: var BlockPool,
                         signed_beacon_block: SignedBeaconBlock,
                         current_slot: Slot, flags: UpdateFlags): bool =
  isValidBeaconBlock(
    pool.dag, pool.quarantine, pool.rewinder,
    signed_beacon_block, current_slot, flags)

proc getProposer*(pool: BlockPool, head: BlockRef, slot: Slot): Option[ValidatorPubKey] =
  getProposer(pool.rewinder, head.atSlot(slot))
