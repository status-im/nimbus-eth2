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
  ./block_dag, block_pools_types_light_client

export
  options, sets, tables, hashes, helpers, beacon_chain_db, block_dag,
  block_pools_types_light_client, validator_monitor

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
      ## Block is from a history / fork that does not include our most current
      ## finalized checkpoint

    Duplicate
      ## We've seen this block already, can't add again

  OnBlockCallback* =
    proc(data: ForkedTrustedSignedBeaconBlock) {.gcsafe, raises: [Defect].}
  OnHeadCallback* =
    proc(data: HeadChangeInfoObject) {.gcsafe, raises: [Defect].}
  OnReorgCallback* =
    proc(data: ReorgInfoObject) {.gcsafe, raises: [Defect].}
  OnFinalizedCallback* =
    proc(dag: ChainDAGRef, data: FinalizationInfoObject) {.gcsafe, raises: [Defect].}

  KeyedBlockRef* = object
    # Special wrapper for BlockRef used in ChainDAG.blocks that allows lookup
    # by root without keeping a Table that keeps a separate copy of the digest
    # At the time of writing, a Table[Eth2Digest, BlockRef] adds about 100mb of
    # unnecessary overhead.
    data*: BlockRef

  ChainDAGRef* = ref object
    ## ChainDAG validates, stores and serves chain history of valid blocks
    ## according to the beacon chain state transtion. From genesis to the
    ## finalization point, block history is linear - from there, it branches out
    ## into a dag with several heads, one of which is considered canonical.
    ##
    ## As new blocks are added, new segments of the chain may finalize,
    ## discarding now unviable candidate histories.
    ##
    ## In addition to storing blocks, the chaindag also is responsible for
    ## storing intermediate states in the database that are used to recreate
    ## chain history at any point in time through a rewinding process that loads
    ## a snapshots and applies blocks until the desired point in history is
    ## reached.
    ##
    ## Several indices are kept in memory to enable fast lookups - their shape
    ## and contents somewhat depend on how the chain was instantiated: sync
    ## from genesis or checkpoint, and therefore, what features we can offer in
    ## terms of historical replay.
    ##
    ## Beacuse the state transition is forwards-only, checkpoint sync generally
    ## allows replaying states from that point onwards - anything earlier
    ## would require a backfill of blocks and a subsequent replay from genesis.
    ##
    ## Era files contain state snapshots along the way, providing arbitrary
    ## starting points for replay and can be used to frontfill the archive -
    ## however, they are not used until the contents have been verified via
    ## parent_root ancestry.
    ##
    ## The chain and the various pointers and indices we keep can be seen in
    ## the following graph: depending on how the chain was instantiated, some
    ## pointers may overlap and some indices might be empty as a result.
    ##
    ##                                              / heads
    ##                                     /-------*     |
    ## *--------*---------*---------------*--------------*
    ## |        |         |               |              |
    ## genesis  backfill  tail            finalizedHead  head
    ##          |         |               |
    ##          archive   finalizedBlocks forkBlocks
    ##
    ## The archive is the the part of finalized history for which we no longer
    ## recreate states quickly because we don't have a reasonable state to
    ## start replay from - when starting from a checkpoint, this is the typical
    ## case - recreating history requires either replaying from genesis or
    ## providing an earlier checkpoint state.
    ##
    ## We do not keep an in-memory index for the archive - instead, lookups are
    ## made via `BeaconChainDB.finalizedBlocks` which covers the full range from
    ## `backfill` to `finalizedHead`.

    db*: BeaconChainDB
      ## Database of recent chain history as well as the state and metadata
      ## needed to pick up where we left off after a restart - in particular,
      ## the DAG and the canonical head are stored here, as well as several
      ## caches.

    validatorMonitor*: ref ValidatorMonitor

    forkBlocks*: HashSet[KeyedBlockRef]
      ## root -> BlockRef mapping of blocks relevant to fork choice, ie
      ## those that have not yet been finalized - covers the slots
      ## `finalizedHead.slot..head.slot` (inclusive) - dag.heads keeps track
      ## of each potential head block in this table.

    finalizedBlocks*: seq[BlockRef]
      ## Slot -> BlockRef mapping for the finalized portion of the canonical
      ## chain - use getBlockAtSlot to access
      ## Covers the slots `tail.slot..finalizedHead.slot` (including the
      ## finalized head block). Indices offset by `tail.slot`.

    genesis*: BlockRef
      ## The genesis block of the network

    tail*: BlockRef
      ## The earliest finalized block for which we have a corresponding state -
      ## when making a replay of chain history, this is as far back as we can
      ## go - the tail block is unique in that its parent is set to `nil`, even
      ## in the case where an earlier genesis block exists.

    backfill*: BeaconBlockSummary
      ## The backfill points to the oldest block with an unbroken ancestry from
      ## dag.tail - when backfilling, we'll move backwards in time starting
      ## with the parent of this block until we reach `genesis`.

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

    serveLightClientData*: bool
      ## Whether to make local light client data available or not

    importLightClientData*: ImportLightClientData
      ## Which classes of light client data to import

    epochRefs*: array[32, EpochRef]
      ## Cached information about a particular epoch ending with the given
      ## block - we limit the number of held EpochRefs to put a cap on
      ## memory usage

    forkDigests*: ref ForkDigests
      ## Cached copy of the fork digests associated with the current
      ## database. We use a ref type to facilitate sharing this small
      ## value with other components which don't have access to the
      ## full ChainDAG.

    # -----------------------------------
    # Data to enable light clients to stay in sync with the network

    lightClientCache*: LightClientCache

    # -----------------------------------
    # Callbacks

    onBlockAdded*: OnBlockCallback
      ## On block added callback
    onHeadChanged*: OnHeadCallback
      ## On head changed callback
    onReorgHappened*: OnReorgCallback
      ## On beacon chain reorganization
    onFinHappened*: OnFinalizedCallback
      ## On finalization callback
    onOptimisticLightClientUpdate*: OnOptimisticLightClientUpdateCallback
      ## On `OptimisticLightClientUpdate` updated callback

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

  # TODO when Nim 1.2 support is dropped, make these generic. 1.2 generates
  # invalid C code, which gcc refuses to compile. Example test case:
  # type
  #   OnBlockAdded[T] = proc(x: T)
  #   OnPhase0BlockAdded = OnBlockAdded[int]
  # proc f(x: OnPhase0BlockAdded) = discard
  # const nilCallback = OnPhase0BlockAdded(nil)
  # f(nilCallback)
  OnPhase0BlockAdded* = proc(
    blckRef: BlockRef,
    blck: phase0.TrustedSignedBeaconBlock,
    epochRef: EpochRef) {.gcsafe, raises: [Defect].}

  OnAltairBlockAdded* = proc(
    blckRef: BlockRef,
    blck: altair.TrustedSignedBeaconBlock,
    epochRef: EpochRef) {.gcsafe, raises: [Defect].}

  OnBellatrixBlockAdded* = proc(
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

template setFinalizationCb*(dag: ChainDAGRef, cb: OnFinalizedCallback) =
  dag.onFinHappened = cb

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
