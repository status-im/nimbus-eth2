# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/[options, sets, tables, hashes],
  # Status libraries
  chronicles,
  # Internals
  ../spec/[signatures_batch, forks, helpers],
  ../spec/datatypes/[phase0, altair, bellatrix],
  ".."/beacon_chain_db,
  ../validators/validator_monitor,
  ./block_dag

export
  options, sets, tables, hashes, helpers, beacon_chain_db, block_dag,
  validator_monitor

# ChainDAG and types related to forming a DAG of blocks, keeping track of their
# relationships and allowing various forms of lookups

type
  BlockError* {.pure.} = enum
    Invalid
      ## Block is broken / doesn't apply cleanly - whoever sent it is fishy (or
      ## we're buggy)

    MissingParent
      ## We don't know the parent of this block so we can't tell if it's valid
      ## or not - it'll go into the quarantine and be reexamined when the parent
      ## appears or be discarded if finality obsoletes it

    UnviableFork
      ## Block is from a different history / fork than the one we're interested
      ## in (based on our finalized checkpoint)

    Duplicate
      ## We've seen this block already, can't add again

  OnBlockCallback* =
    proc(data: ForkedTrustedSignedBeaconBlock) {.gcsafe, raises: [Defect].}
  OnHeadCallback* =
    proc(data: HeadChangeInfoObject) {.gcsafe, raises: [Defect].}
  OnReorgCallback* =
    proc(data: ReorgInfoObject) {.gcsafe, raises: [Defect].}
  OnFinalizedCallback* =
    proc(data: FinalizationInfoObject) {.gcsafe, raises: [Defect].}

  FetchRecord* = object
    root*: Eth2Digest

  KeyedBlockRef* = object
    # Special wrapper for BlockRef used in ChainDAG.blocks that allows lookup
    # by root without keeping a Table that keeps a separate copy of the digest
    # At the time of writing, a Table[Eth2Digest, BlockRef] adds about 100mb of
    # unnecessary overhead.
    data*: BlockRef

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

    db*: BeaconChainDB
      ## ColdDB - Stores the canonical chain

    validatorMonitor*: ref ValidatorMonitor

    # -----------------------------------
    # ChainDAGRef - DAG of candidate chains

    forkBlocks*: HashSet[KeyedBlockRef]
      ## root -> BlockRef mapping of blocks still relevant to fork choice, ie
      ## those that have not yet been finalized - covers the slots
      ## `finalizedHead.slot..head.slot` (inclusive)

    finalizedBlocks*: seq[BlockRef]
      ## Slot -> BlockRef mapping for the canonical chain - use getBlockAtSlot
      ## to access, generally - covers the slots
      ## `tail.slot..finalizedHead.slot` (including the finalized head block) -
      ## indices are thus offset by tail.slot

    backfillBlocks*: seq[Eth2Digest]
    ## Slot -> Eth2Digest, covers genesis.slot..tail.slot - 1 (inclusive)

    genesis*: BlockRef
    ## The genesis block of the network

    tail*: BlockRef
    ## The earliest finalized block for which we have a corresponding state -
    ## when making a replay of chain history, this is as far back as we can
    ## go - the tail block is unique in that its parent is set to `nil`, even
    ## in the case where an earlier genesis block exists.

    backfill*: BeaconBlockSummary
    ## The backfill points to the oldest block that we have in the database -
    ## when backfilling, the first block to download is the parent of this block

    heads*: seq[BlockRef]
    ## Candidate heads of candidate chains

    finalizedHead*: BlockSlot
    ## The latest block that was finalized according to the block in head
    ## Ancestors of this block are guaranteed to have 1 child only.

    # -----------------------------------
    # Pruning metadata

    lastPrunePoint*: BlockSlot
    ## The last prune point
    ## We can prune up to finalizedHead

    # -----------------------------------
    # Rewinder - Mutable state processing

    headState*: StateData
    ## State given by the head block - must only be updated in `updateHead` -
    ## always matches dag.head

    epochRefState*: StateData
      ## State used to produce epochRef instances - must only be used in
      ## `getEpochRef`

    clearanceState*: StateData
      ## Cached state used during block clearance - must only be used in
      ## clearance module

    updateFlags*: UpdateFlags

    cfg*: RuntimeConfig

    epochRefs*: array[32, EpochRef]
      ## Cached information about a particular epoch ending with the given
      ## block - we limit the number of held EpochRefs to put a cap on
      ## memory usage

    forkDigests*: ref ForkDigests
      ## Cached copy of the fork digests associated with the current
      ## database. We use a ref type to facilitate sharing this small
      ## value with other components which don't have access to the
      ## full ChainDAG.

    onBlockAdded*: OnBlockCallback
      ## On block added callback
    onHeadChanged*: OnHeadCallback
      ## On head changed callback
    onReorgHappened*: OnReorgCallback
      ## On beacon chain reorganization
    onFinHappened*: OnFinalizedCallback
      ## On finalization callback

    headSyncCommittees*: SyncCommitteeCache
      ## A cache of the sync committees, as they appear in the head state -
      ## using the head state is slightly wrong - if a reorg deeper than
      ## EPOCHS_PER_SYNC_COMMITTEE_PERIOD is happening, some valid sync
      ## committee messages will be rejected

  EpochKey* = object
    ## The epoch key fully determines the shuffling for proposers and
    ## committees in a beacon state - the epoch level information in the state
    ## is derived from the last known block in the particular history _before_
    ## the beginning of that epoch, and then advanced with slot processing to
    ## the epoch start - we call this block the "epoch ancestor" in other parts
    ## of the code.
    epoch*: Epoch
    blck*: BlockRef

  EpochRef* = ref object
    dag*: ChainDAGRef
    key*: EpochKey
    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint
    eth1_data*: Eth1Data
    eth1_deposit_index*: uint64
    beacon_proposers*: array[SLOTS_PER_EPOCH, Option[ValidatorIndex]]
    shuffled_active_validator_indices*: seq[ValidatorIndex]

    # enables more efficient merge block validation
    merge_transition_complete*: bool

    # balances, as used in fork choice
    effective_balances_bytes*: seq[byte]

  StateData* = object
    data*: ForkedHashedBeaconState

    blck*: BlockRef
    ## The block associated with the state found in data

  OnPhase0BlockAdded* = proc(
    blckRef: BlockRef,
    blck: phase0.TrustedSignedBeaconBlock,
    epochRef: EpochRef) {.gcsafe, raises: [Defect].}

  OnAltairBlockAdded* = proc(
    blckRef: BlockRef,
    blck: altair.TrustedSignedBeaconBlock,
    epochRef: EpochRef) {.gcsafe, raises: [Defect].}

  OnMergeBlockAdded* = proc(
    blckRef: BlockRef,
    blck: bellatrix.TrustedSignedBeaconBlock,
    epochRef: EpochRef) {.gcsafe, raises: [Defect].}

  HeadChangeInfoObject* = object
    slot*: Slot
    block_root* {.serializedFieldName: "block".}: Eth2Digest
    state_root* {.serializedFieldName: "state".}: Eth2Digest
    epoch_transition*: bool
    previous_duty_dependent_root*: Eth2Digest
    current_duty_dependent_root*: Eth2Digest

  ReorgInfoObject* = object
    slot*: Slot
    depth*: uint64
    old_head_block*: Eth2Digest
    new_head_block*: Eth2Digest
    old_head_state*: Eth2Digest
    new_head_state*: Eth2Digest

  FinalizationInfoObject* = object
    block_root* {.serializedFieldName: "block".}: Eth2Digest
    state_root* {.serializedFieldName: "state".}: Eth2Digest
    epoch*: Epoch

template head*(dag: ChainDAGRef): BlockRef = dag.headState.blck

template epoch*(e: EpochRef): Epoch = e.key.epoch

func shortLog*(v: EpochKey): string =
  # epoch:root when logging epoch, root:slot when logging slot!
  $v.epoch & ":" & shortLog(v.blck)

func shortLog*(v: EpochRef): string =
  # epoch:root when logging epoch, root:slot when logging slot!
  if v.isNil():
    "0:nil"
  else:
    shortLog(v.key)

chronicles.formatIt EpochKey: shortLog(it)
chronicles.formatIt EpochRef: shortLog(it)

func hash*(key: KeyedBlockRef): Hash =
  hash(key.data.root)

func `==`*(a, b: KeyedBlockRef): bool =
  a.data.root == b.data.root

func asLookupKey*(T: type KeyedBlockRef, root: Eth2Digest): KeyedBlockRef =
  # Create a special, temporary BlockRef instance that just has the key set
  KeyedBlockRef(data: BlockRef(bid: BlockId(root: root)))

func init*(T: type KeyedBlockRef, blck: BlockRef): KeyedBlockRef =
  KeyedBlockRef(data: blck)

func blockRef*(key: KeyedBlockRef): BlockRef =
  key.data

func init*(t: typedesc[HeadChangeInfoObject], slot: Slot, blockRoot: Eth2Digest,
           stateRoot: Eth2Digest, epochTransition: bool,
           previousDutyDepRoot: Eth2Digest,
           currentDutyDepRoot: Eth2Digest): HeadChangeInfoObject =
  HeadChangeInfoObject(
    slot: slot,
    block_root: blockRoot,
    state_root: stateRoot,
    epoch_transition: epochTransition,
    previous_duty_dependent_root: previousDutyDepRoot,
    current_duty_dependent_root: currentDutyDepRoot
  )

func init*(t: typedesc[ReorgInfoObject], slot: Slot, depth: uint64,
           oldHeadBlockRoot: Eth2Digest, newHeadBlockRoot: Eth2Digest,
           oldHeadStateRoot: Eth2Digest,
           newHeadStateRoot: Eth2Digest): ReorgInfoObject =
  ReorgInfoObject(
    slot: slot,
    depth: depth,
    old_head_block: oldHeadBlockRoot,
    new_head_block: newHeadBlockRoot,
    old_head_state: oldHeadStateRoot,
    new_head_state: newHeadStateRoot
  )

func init*(t: typedesc[FinalizationInfoObject], blockRoot: Eth2Digest,
           stateRoot: Eth2Digest, epoch: Epoch): FinalizationInfoObject =
  FinalizationInfoObject(
    block_root: blockRoot,
    state_root: stateRoot,
    epoch: epoch
  )
