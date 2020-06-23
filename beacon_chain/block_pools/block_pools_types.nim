# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  deques, tables,
  stew/[endians2, byteutils], chronicles,
  ../spec/[datatypes, crypto, digest],
  ../beacon_chain_db, ../extras

# #############################################
#
#            Quarantine & DAG
#
# #############################################
#
# The Quarantine and DagChain data structures
# keeps track respectively of unsafe blocks coming from the network
# and blocks that underwent verification and have a resolved path to
# the last finalized block known.

type
  BlockError* = enum
    MissingParent
    Old
    Invalid
    Duplicate

  Quarantine* = object
    ## Keeps track of unsafe blocks coming from the network
    ## and that cannot be added to the chain
    ##
    ## This only stores valid blocks that cannot be linked to the BlockPool DAG
    ## due to missing ancestor(s).
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

  CandidateChains* = ref object
    ## Pool of blocks responsible for keeping a DAG of resolved blocks.
    ##
    ## The BlockPool is responsible for the following
    ##
    ## - Handle requests and updates to the "ColdDB" which
    ##   holds the canonical chain.
    ## - Maintain a direct acyclic graph (DAG) of
    ##   candidate chains from the last
    ##   finalized block.
    ##
    ## When a chain becomes finalized, it is saved in the ColdDB,
    ## the rejected candidates are discard and the BlockPool
    ## is CandidateChains is pruned, only keeping the last finalized block.
    ##
    ## The last finalized block is called the tail block.

    # -----------------------------------
    # ColdDB - Canonical chain

    db*: BeaconChainDB ##\
      ## ColdDB - Stores the canonical chain

    # -----------------------------------
    # CandidateChains - DAG of candidate chains

    blocks*: Table[Eth2Digest, BlockRef] ##\
    ## Directed acyclic graph of blocks pointing back to a finalized block on the chain we're
    ## interested in - we call that block the tail

    tail*: BlockRef ##\
    ## The earliest finalized block we know about

    heads*: seq[Head] ##\
    ## Candidate heads of candidate chains

    head*: Head ##\
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

    justifiedState*: StateData ## Latest justified state, as seen from the head

    tmpState*: StateData ## Scratchpad - may be any state

    updateFlags*: UpdateFlags

  EpochRef* = ref object
    shuffled_active_validator_indices*: seq[ValidatorIndex]
    epoch*: Epoch

  BlockRef* = ref object
    ## Node in object graph guaranteed to lead back to tail block, and to have
    ## a corresponding entry in database.
    ## Block graph should form a tree - in particular, there are no cycles.

    root*: Eth2Digest ##\
    ## Root that can be used to retrieve block data from database

    parent*: BlockRef ##\
    ## Not nil, except for the tail

    children*: seq[BlockRef]
    # TODO do we strictly need this?

    slot*: Slot # TODO could calculate this by walking to root, but..

    epochsInfo*: seq[EpochRef]
    ## Could be multiple, since blocks could skip slots, but usually, not many
    ## Even if competing forks happen later during this epoch, potential empty
    ## slots beforehand must all be from this fork. getEpochInfo() is the only
    ## supported way of accesssing these.

  BlockData* = object
    ## Body and graph in one

    data*: SignedBeaconBlock
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

  Head* = object
    blck*: BlockRef
    justified*: BlockSlot

proc shortLog*(v: BlockSlot): string =
  if v.blck.slot == v.slot:
    v.blck.root.data[0..3].toHex() & ":" & $v.blck.slot
  else: # There was a gap - log it
    v.blck.root.data[0..3].toHex() & ":" & $v.blck.slot & "@" & $v.slot

proc shortLog*(v: BlockRef): string =
  v.root.data[0..3].toHex() & ":" & $v.slot

chronicles.formatIt BlockSlot: shortLog(it)
chronicles.formatIt BlockRef: shortLog(it)
