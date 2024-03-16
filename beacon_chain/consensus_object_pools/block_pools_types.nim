import
  std/[sets, tables, hashes],
  ../spec/[forks, helpers],
  ../spec/datatypes/[phase0, altair, bellatrix],
  ".."/[beacon_chain_db],
  ./block_dag

from ../spec/datatypes/capella import TrustedSignedBeaconBlock
from ../spec/datatypes/deneb import TrustedSignedBeaconBlock

export
  sets, tables, hashes, helpers, beacon_chain_db, block_dag

type
  VerifierError* {.pure.} = enum
    Invalid
      ## Value is broken / doesn't apply cleanly - whoever sent it is fishy (or
      ## we're buggy)

    MissingParent
      ## We don't know the parent of this value so we can't tell if it's valid
      ## or not - it'll go into the quarantine and be reexamined when the parent
      ## appears or be discarded if finality obsoletes it

    UnviableFork
      ## Value is from a history / fork that does not include our most current
      ## finalized checkpoint

    Duplicate
      ## We've seen this value already, can't add again

  OnBlockCallback =
    proc(data: ForkedTrustedSignedBeaconBlock) {.gcsafe, raises: [].}
  OnHeadCallback =
    proc(data: HeadChangeInfoObject) {.gcsafe, raises: [].}
  OnReorgCallback =
    proc(data: ReorgInfoObject) {.gcsafe, raises: [].}
  OnFinalizedCallback =
    proc(dag: ChainDAGRef, data: FinalizationInfoObject) {.gcsafe, raises: [].}

  KeyedBlockRef* = object
    data: BlockRef

  LRUCache*[I: static[int], T] = object
    entries*: array[I, tuple[value: T, lastUsed: uint32]]
    timestamp*: uint32

  ChainDAGRef* = ref object

    db*: BeaconChainDB
      ## Database of recent chain history as well as the state and metadata
      ## needed to pick up where we left off after a restart - in particular,
      ## the DAG and the canonical head are stored here, as well as several
      ## caches.

    forkBlocks*: HashSet[KeyedBlockRef]
      ## root -> BlockRef mapping of blocks relevant to fork choice, ie
      ## those that have not yet been finalized - covers the slots
      ## `finalizedHead.slot..head.slot` (inclusive) - dag.heads keeps track
      ## of each potential head block in this table.

    genesis*: Opt[BlockId]
      ## The root of the genesis block, iff it is known (ie if the database was
      ## created with a genesis state available)

    tail*: BlockId
      ## The earliest block for which we can construct a state - we consider
      ## the tail implicitly finalized no matter what fork choice and state
      ## says - when starting from a trusted checkpoint, the tail is set to
      ## the checkpoint block.

    head*: BlockRef
      ## The most recently known head, as chosen by fork choice; might be
      ## optimistic

    backfill: BeaconBlockSummary
      ## The backfill points to the oldest block with an unbroken ancestry from
      ## dag.tail - when backfilling, we'll move backwards in time starting
      ## with the parent of this block until we reach `frontfill`.
      ##
      ## - `backfill.slot` points to the earliest block that has been synced,
      ##   or, if no blocks have been synced yet, to `checkpoint_state.slot + 1`
      ##   which is the earliest slot that may have `parent_root` as ancestor.
      ## - `backfill.parent_root` is the latest block that is not yet synced.
      ## - Once backfill completes, `backfill.slot` refers to `GENESIS_SLOT`.

    frontfillBlocks: seq[Eth2Digest]
      ## A temporary cache of blocks that we could load from era files, once
      ## backfilling reaches this point - empty when not backfilling.

    heads*: seq[BlockRef]
      ## Candidate heads of candidate chains

    finalizedHead*: BlockSlot
      ## The latest block that was finalized according to the block in head
      ## Ancestors of this block are guaranteed to have 1 child only.


    lastPrunePoint: BlockSlotId
      ## The last prune point
      ## We can prune up to finalizedHead

    lastHistoryPruneHorizon: Slot
      ## The horizon when we last pruned, for horizon diff computation

    lastHistoryPruneBlockHorizon: Slot
      ## Block pruning progress at the last call


    headState*: ForkedHashedBeaconState
      ## State given by the head block - must only be updated in `updateHead` -
      ## always matches dag.head

    epochRefState*: ForkedHashedBeaconState
      ## State used to produce epochRef instances - must only be used in
      ## `getEpochRef`

    clearanceState*: ForkedHashedBeaconState
      ## Cached state used during block clearance - must only be used in
      ## clearance module

    updateFlags: UpdateFlags

    cfg*: RuntimeConfig

    shufflingRefs*: LRUCache[16, ShufflingRef]

    epochRefs*: LRUCache[32, EpochRef]
      ## Cached information about a particular epoch ending with the given
      ## block - we limit the number of held EpochRefs to put a cap on
      ## memory usage

    forkDigests*: ref ForkDigests
      ## Cached copy of the fork digests associated with the current
      ## database. We use a ref type to facilitate sharing this small
      ## value with other components which don't have access to the
      ## full ChainDAG.

  EpochKey* = object
    epoch*: Epoch
    bid*: BlockId

  ShufflingRef* = ref object
    epoch*: Epoch
    attester_dependent_root*: Eth2Digest
      ## Root of the block that determined the shuffling - this is the last
      ## block that was applied in (epoch - 2).

    shuffled_active_validator_indices*: seq[ValidatorIndex]

  EpochRef* = ref object
    key*: EpochKey

    eth1_data*: Eth1Data
    eth1_deposit_index*: uint64

    checkpoints*: FinalityCheckpoints

    beacon_proposers*: array[SLOTS_PER_EPOCH, Opt[ValidatorIndex]]
    proposer_dependent_root*: Eth2Digest

    shufflingRef*: ShufflingRef

    total_active_balance*: Gwei

    effective_balances_bytes*: seq[byte]

  OnBlockAdded[T: ForkyTrustedSignedBeaconBlock] = proc(
    blckRef: BlockRef, blck: T, epochRef: EpochRef,
    unrealized: FinalityCheckpoints) {.gcsafe, raises: [].}
  OnPhase0BlockAdded = OnBlockAdded[phase0.TrustedSignedBeaconBlock]
  OnAltairBlockAdded = OnBlockAdded[altair.TrustedSignedBeaconBlock]
  OnBellatrixBlockAdded = OnBlockAdded[bellatrix.TrustedSignedBeaconBlock]
  OnCapellaBlockAdded = OnBlockAdded[capella.TrustedSignedBeaconBlock]
  OnDenebBlockAdded = OnBlockAdded[deneb.TrustedSignedBeaconBlock]
  OnElectraBlockAdded = OnBlockAdded[electra.TrustedSignedBeaconBlock]

  OnForkyBlockAdded =
    OnPhase0BlockAdded | OnAltairBlockAdded | OnBellatrixBlockAdded |
    OnCapellaBlockAdded | OnDenebBlockAdded | OnElectraBlockAdded

  HeadChangeInfoObject = object
    slot: Slot
    block_root {.serializedFieldName: "block".}: Eth2Digest
    state_root {.serializedFieldName: "state".}: Eth2Digest
    epoch_transition: bool
    previous_duty_dependent_root: Eth2Digest
    current_duty_dependent_root: Eth2Digest
    optimistic {.serializedFieldName: "execution_optimistic".}: Option[bool]

  ReorgInfoObject = object
    slot: Slot
    depth: uint64
    old_head_block: Eth2Digest
    new_head_block: Eth2Digest
    old_head_state: Eth2Digest
    new_head_state: Eth2Digest
    optimistic {.serializedFieldName: "execution_optimistic".}: Option[bool]

  FinalizationInfoObject = object
    block_root {.serializedFieldName: "block".}: Eth2Digest
    state_root {.serializedFieldName: "state".}: Eth2Digest
    epoch: Epoch
    optimistic {.serializedFieldName: "execution_optimistic".}: Option[bool]

  EventBeaconBlockObject = object
    slot: Slot
    block_root {.serializedFieldName: "block".}: Eth2Digest
    optimistic {.serializedFieldName: "execution_optimistic".}: Option[bool]

template OnBlockAddedCallback(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Electra:
    typedesc[OnElectraBlockAdded]
  elif kind == ConsensusFork.Deneb:
    typedesc[OnDenebBlockAdded]
  elif kind == ConsensusFork.Capella:
    typedesc[OnCapellaBlockAdded]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[OnBellatrixBlockAdded]
  elif kind == ConsensusFork.Altair:
    typedesc[OnAltairBlockAdded]
  elif kind == ConsensusFork.Phase0:
    typedesc[OnPhase0BlockAdded]
  else:
    static: raiseAssert "Unreachable"

func proposer_dependent_slot(epochRef: EpochRef): Slot =
  epochRef.key.epoch.proposer_dependent_slot()

func attester_dependent_slot(shufflingRef: ShufflingRef): Slot =
  shufflingRef.epoch.attester_dependent_slot()

template head(dag: ChainDAGRef): BlockRef = dag.headState.blck

template frontfill(dagParam: ChainDAGRef): Opt[BlockId] =
  let dag = dagParam
  if dag.frontfillBlocks.lenu64 > 0:
    Opt.some BlockId(
      slot: Slot(dag.frontfillBlocks.lenu64 - 1), root: dag.frontfillBlocks[^1])
  else:
    dag.genesis

func horizon(dag: ChainDAGRef): Slot =
  let minSlots = dag.cfg.MIN_EPOCHS_FOR_BLOCK_REQUESTS * SLOTS_PER_EPOCH
  if dag.head.slot > minSlots:
    min(dag.finalizedHead.slot, dag.head.slot - minSlots)
  else:
    GENESIS_SLOT

template epoch*(e: EpochRef): Epoch = e.key.epoch

func shortLog(v: EpochKey): string =
  $v.epoch & ":" & shortLog(v.bid)

template setFinalizationCb(dag: ChainDAGRef, cb: OnFinalizedCallback) =
  dag.onFinHappened = cb

template setBlockCb(dag: ChainDAGRef, cb: OnBlockCallback) =
  dag.onBlockAdded = cb

template setHeadCb(dag: ChainDAGRef, cb: OnHeadCallback) =
  dag.onHeadChanged = cb

template setReorgCb(dag: ChainDAGRef, cb: OnReorgCallback) =
  dag.onReorgHappened = cb

func shortLog(v: EpochRef): string =
  if v.isNil():
    "0:nil"
  else:
    shortLog(v.key)

func hash*(key: KeyedBlockRef): Hash =
  hash(key.data.root)

func `==`(a, b: KeyedBlockRef): bool =
  a.data.root == b.data.root

func asLookupKey*(T: type KeyedBlockRef, root: Eth2Digest): KeyedBlockRef =
  KeyedBlockRef(data: BlockRef(bid: BlockId(root: root)))

func init*(T: type KeyedBlockRef, blck: BlockRef): KeyedBlockRef =
  KeyedBlockRef(data: blck)

func blockRef*(key: KeyedBlockRef): BlockRef =
  key.data

func init(t: typedesc[HeadChangeInfoObject], slot: Slot, blockRoot: Eth2Digest,
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

func init(t: typedesc[ReorgInfoObject], slot: Slot, depth: uint64,
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

func init(t: typedesc[FinalizationInfoObject], blockRoot: Eth2Digest,
           stateRoot: Eth2Digest, epoch: Epoch): FinalizationInfoObject =
  FinalizationInfoObject(
    block_root: blockRoot,
    state_root: stateRoot,
    epoch: epoch
  )

func init(t: typedesc[EventBeaconBlockObject],
           v: ForkedTrustedSignedBeaconBlock,
           optimistic: Option[bool]): EventBeaconBlockObject =
  withBlck(v):
    EventBeaconBlockObject(
      slot: forkyBlck.message.slot,
      block_root: forkyBlck.root,
      optimistic: optimistic
    )
