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

    heads*: seq[BlockRef]
      ## Candidate heads of candidate chains

    finalizedHead*: BlockSlot
      ## The latest block that was finalized according to the block in head
      ## Ancestors of this block are guaranteed to have 1 child only.


    headState*: ForkedHashedBeaconState
      ## State given by the head block - must only be updated in `updateHead` -
      ## always matches dag.head

    epochRefState*: ForkedHashedBeaconState
      ## State used to produce epochRef instances - must only be used in
      ## `getEpochRef`

    clearanceState*: ForkedHashedBeaconState
      ## Cached state used during block clearance - must only be used in
      ## clearance module

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

template epoch*(e: EpochRef): Epoch = e.key.epoch

func hash*(key: KeyedBlockRef): Hash =
  hash(key.data.root)

func asLookupKey*(T: type KeyedBlockRef, root: Eth2Digest): KeyedBlockRef =
  KeyedBlockRef(data: BlockRef(bid: BlockId(root: root)))

func init*(T: type KeyedBlockRef, blck: BlockRef): KeyedBlockRef =
  KeyedBlockRef(data: blck)

func blockRef*(key: KeyedBlockRef): BlockRef =
  key.data
