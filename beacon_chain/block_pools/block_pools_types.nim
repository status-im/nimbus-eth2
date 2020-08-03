# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  deques, tables, hashes,
  # Status libraries
  stew/[endians2, byteutils], chronicles,
  # Internals
  ../spec/[datatypes, crypto, digest],
  ../beacon_chain_db, ../extras

# #############################################
#
#            Quarantine & DAG
#
# #############################################
#
# The Quarantine and DagChain data structures
# keep track respectively of unsafe blocks coming from the network
# and blocks that underwent verification and have a resolved path to
# the last finalized block known.

type
  BlockError* = enum
    MissingParent ##\
      ## We don't know the parent of this block so we can't tell if it's valid
      ## or not - it'll go into the quarantine and be reexamined when the parent
      ## appears or be discarded if finality obsoletes it

    Unviable ##\
      ## Block is from a different history / fork than the one we're interested
      ## in (based on our finalized checkpoint)

    Invalid ##\
      ## Block is broken / doesn't apply cleanly - whoever sent it is fishy (or
      ## we're buggy)
    Old
    Duplicate

  QuarantineRef* = ref object
    ## Keeps track of unsafe blocks coming from the network
    ## and that cannot be added to the chain
    ##
    ## This only stores valid blocks that cannot be linked to the
    ## ChainDAGRef DAG due to missing ancestor(s).
    ##
    ## Invalid blocks are dropped immediately.

    orphans*: Table[Eth2Digest, SignedBeaconBlock] ##\
    ## Blocks that have passed validation but that we lack a link back to tail
    ## for - when we receive a "missing link", we can use this data to build
    ## an entire branch

    missing*: Table[Eth2Digest, MissingBlock] ##\
    ## Roots of blocks that we would like to have (either parent_root of
    ## unresolved blocks or block roots of attestations)

    inAdd*: bool

  MissingBlock* = object
    tries*: int

  FetchRecord* = object
    root*: Eth2Digest

  ChainDAGRef* = ref object
    ## Pool of blocks responsible for keeping a DAG of resolved blocks.
    ##
    ## It is responsible for the following
    ##
    ## - Handle requests and updates to the "ColdDB" which
    ##   holds the canonical chain.
    ## - Maintain a direct acyclic graph (DAG) of
    ##   candidate chains from the last
    ##   finalized block.
    ##
    ## When a chain becomes finalized, it is saved in the ColdDB,
    ## the rejected candidates are discarded and this pool
    ## is pruned, only keeping the last finalized block.
    ##
    ## The last finalized block is called the tail block.

    # -----------------------------------
    # ColdDB - Canonical chain

    db*: BeaconChainDB ##\
      ## ColdDB - Stores the canonical chain

    # -----------------------------------
    # ChainDAGRef - DAG of candidate chains

    blocks*: Table[Eth2Digest, BlockRef] ##\
    ## Directed acyclic graph of blocks pointing back to a finalized block on the chain we're
    ## interested in - we call that block the tail

    tail*: BlockRef ##\
    ## The earliest finalized block we know about

    heads*: seq[BlockRef] ##\
    ## Candidate heads of candidate chains

    head*: BlockRef ##\
    ## The latest block we know about, that's been chosen as a head by the fork
    ## choice rule

    finalizedHead*: BlockSlot ##\
    ## The latest block that was finalized according to the block in head
    ## Ancestors of this block are guaranteed to have 1 child only.

    # -----------------------------------
    # Rewinder - Mutable state processing

    cachedStates*: seq[tuple[blockRoot: Eth2Digest, slot: Slot,
      state: ref HashedBeaconState]]

    headState*: StateData ##\
    ## State given by the head block; only update in `updateHead`, not anywhere
    ## else via `withState`

    tmpState*: StateData ## Scratchpad - may be any state

    clearanceState*: StateData ##\
      ## Cached state used during block clearance - should only be used in the
      ## clearance module to avoid the risk of modifying it in a callback

    balanceState*: StateData ##\
      ## Cached state for fork choice balance processing - should be replaced
      ## with a light-weight cache of balances only

    updateFlags*: UpdateFlags

    runtimePreset*: RuntimePreset

  EpochRef* = ref object
    epoch*: Epoch
    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint
    shuffled_active_validator_indices*: seq[ValidatorIndex]

  BlockRef* = ref object
    ## Node in object graph guaranteed to lead back to tail block, and to have
    ## a corresponding entry in database.
    ## Block graph should form a tree - in particular, there are no cycles.

    root*: Eth2Digest ##\
    ## Root that can be used to retrieve block data from database

    parent*: BlockRef ##\
    ## Not nil, except for the tail

    slot*: Slot # TODO could calculate this by walking to root, but..

    epochsInfo*: seq[EpochRef] ##\
    ## Cached information about the epochs starting at this block.
    ## Could be multiple, since blocks could skip slots, but usually, not many
    ## Even if competing forks happen later during this epoch, potential empty
    ## slots beforehand must all be from this fork. getEpochInfo() is the only
    ## supported way of accesssing these.

  BlockData* = object
    ## Body and graph in one

    data*: TrustedSignedBeaconBlock # We trust all blocks we have a ref for
    refs*: BlockRef

  StateData* = object
    data*: HashedBeaconState

    blck*: BlockRef ##\
    ## The block associated with the state found in data - normally
    ## `blck.state_root == data.root` but the state might have been advanced
    ## further with empty slots invalidating this condition.

  BlockSlot* = object
    ## Unique identifier for a particular fork and time in the block chain -
    ## normally, there's a block for every slot, but in the case a block is not
    ## produced, the chain progresses anyway, producing a new state for every
    ## slot.
    blck*: BlockRef
    slot*: Slot ##\
      ## Slot time for this BlockSlot which may differ from blck.slot when time
      ## has advanced without blocks

  OnBlockAdded* = proc(
    blckRef: BlockRef, blck: SignedBeaconBlock,
    state: HashedBeaconState) {.raises: [Defect], gcsafe.}

proc shortLog*(v: BlockSlot): string =
  if v.blck.slot == v.slot:
    v.blck.root.data[0..3].toHex() & ":" & $v.blck.slot
  else: # There was a gap - log it
    v.blck.root.data[0..3].toHex() & ":" & $v.blck.slot & "@" & $v.slot

proc shortLog*(v: BlockRef): string =
  if v == nil:
    "BlockRef(nil)"
  else:
    v.root.data[0..3].toHex() & ":" & $v.slot

chronicles.formatIt BlockSlot: shortLog(it)
chronicles.formatIt BlockRef: shortLog(it)

func hash*(blockRef: BlockRef): Hash =
  hash(blockRef.root)
