# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/[strformat, sets, tables, hashes],
  # Status libraries
  stew/[endians2, byteutils], chronicles,
  eth/keys,
  # Internals
  ../spec/[datatypes, crypto, digest, signatures_batch],
  ../beacon_chain_db, ../extras

export sets, tables

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

    orphans*: Table[(Eth2Digest, ValidatorSig), SignedBeaconBlock] ##\
    ## Blocks that have passed validation but that we lack a link back to tail
    ## for - when we receive a "missing link", we can use this data to build
    ## an entire branch

    missing*: Table[Eth2Digest, MissingBlock] ##\
    ## Roots of blocks that we would like to have (either parent_root of
    ## unresolved blocks or block roots of attestations)

    sigVerifCache*: BatchedBLSVerifierCache ##\
    ## A cache for batch BLS signature verification contexts
    rng*: ref BrHmacDrbgContext  ##\
    ## A reference to the Nimbus application-wide RNG

    inAdd*: bool

  MissingBlock* = object
    tries*: int

  FetchRecord* = object
    root*: Eth2Digest

  KeyedBlockRef* = object
    # Special wrapper for BlockRef used in ChainDAG.blocks that allows lookup
    # by root without keeping a Table that keeps a separate copy of the digest
    # At the time of writing, a Table[Eth2Digest, BlockRef] adds about 100mb of
    # unnecessary overhead.
    data: BlockRef

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

    blocks*: HashSet[KeyedBlockRef] ##\
    ## Directed acyclic graph of blocks pointing back to a finalized block on the chain we're
    ## interested in - we call that block the tail

    genesis*: BlockRef ##\
    ## The genesis block of the network

    tail*: BlockRef ##\
    ## The earliest finalized block we know about

    heads*: seq[BlockRef] ##\
    ## Candidate heads of candidate chains

    finalizedHead*: BlockSlot ##\
    ## The latest block that was finalized according to the block in head
    ## Ancestors of this block are guaranteed to have 1 child only.

    # -----------------------------------
    # Pruning metadata

    lastPrunePoint*: BlockSlot ##\
    ## The last prune point
    ## We can prune up to finalizedHead

    # -----------------------------------
    # Rewinder - Mutable state processing

    headState*: StateData ##\
    ## State given by the head block - must only be updated in `updateHead` -
    ## always matches dag.head

    epochRefState*: StateData ##\
      ## State used to produce epochRef instances - must only be used in
      ## `getEpochRef`

    clearanceState*: StateData ##\
      ## Cached state used during block clearance - must only be used in
      ## clearance module

    updateFlags*: UpdateFlags

    runtimePreset*: RuntimePreset

    epochRefs*: array[32, (BlockRef, EpochRef)] ##\
      ## Cached information about a particular epoch ending with the given
      ## block - we limit the number of held EpochRefs to put a cap on
      ## memory usage

  EpochRef* = ref object
    epoch*: Epoch
    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint
    eth1_data*: Eth1Data
    eth1_deposit_index*: uint64
    beacon_proposers*: array[
      SLOTS_PER_EPOCH, Option[(ValidatorIndex, ValidatorPubKey)]]
    shuffled_active_validator_indices*: seq[ValidatorIndex]
    # This is an expensive cache that is sometimes shared among epochref
    # instances - in particular, validators keep their keys and locations in the
    # validator list in each particular history.
    validator_key_store*: (Eth2Digest, ref seq[ValidatorPubKey])

    # balances, as used in fork choice
    effective_balances_bytes*: seq[byte]

  BlockData* = object
    ## Body and graph in one

    data*: TrustedSignedBeaconBlock # We trust all blocks we have a ref for
    refs*: BlockRef

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
    blckRef: BlockRef, blck: TrustedSignedBeaconBlock,
    epochRef: EpochRef, state: HashedBeaconState) {.gcsafe, raises: [Defect].}

template validator_keys*(e: EpochRef): untyped = e.validator_key_store[1][]

template head*(v: ChainDagRef): BlockRef = v.headState.blck

func shortLog*(v: BlockSlot): string =
  try:
    if v.blck.isNil():
      &"nil:0@{v.slot}"
    elif v.blck.slot == v.slot:
      &"{v.blck.root.data.toOpenArray(0, 3).toHex()}:{v.blck.slot}"
    else: # There was a gap - log it
      &"{v.blck.root.data.toOpenArray(0, 3).toHex()}:{v.blck.slot}@{v.slot}"
  except ValueError as err:
    err.msg # Shouldn't happen - but also shouldn't crash!

func shortLog*(v: BlockRef): string =
  try:
    if v.isNil():
      "BlockRef(nil)"
    else:
      &"{v.root.data.toOpenArray(0, 3).toHex()}:{v.slot}"
  except ValueError as err:
    err.msg # Shouldn't happen - but also shouldn't crash!

func shortLog*(v: EpochRef): string =
  try:
    if v.isNil():
      "EpochRef(nil)"
    else:
      &"(epoch ref: {v.epoch})"
  except ValueError as err:
    err.msg # Shouldn't happen - but also shouldn't crash!

chronicles.formatIt BlockSlot: shortLog(it)
chronicles.formatIt BlockRef: shortLog(it)

func hash*(key: KeyedBlockRef): Hash =
  hash(key.data.root)

func `==`*(a, b: KeyedBlockRef): bool =
  a.data.root == b.data.root

func asLookupKey*(T: type KeyedBlockRef, root: Eth2Digest): KeyedBlockRef =
  # Create a special, temporary BlockRef instance that just has the key set
  KeyedBlockRef(data: BlockRef(root: root))

func init*(T: type KeyedBlockRef, blck: BlockRef): KeyedBlockRef =
  KeyedBlockRef(data: blck)

func blockRef*(key: KeyedBlockRef): BlockRef =
  key.data
