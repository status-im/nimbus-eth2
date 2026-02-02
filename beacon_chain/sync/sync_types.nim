# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import results, chronos,
       ".."/spec/[forks_light_client, signatures_batch],
       ".."/consensus_object_pools/[block_pools_types, blockchain_dag,
                                    attestation_pool, blockchain_list,
                                    blob_quarantine, block_quarantine,
                                    consensus_manager],
       ".."/gossip_processing/block_processor,
       ".."/validators/validator_monitor,
       ".."/[beacon_clock, conf],
       ".."/networking/eth2_network,
       "."/[sync_manager, sync_dag, block_buffer]

export results, chronos, block_pools_types, conf, sync_dag

type
  BlockDataChunk* = ref object
    resfut*: Future[Result[void, string]].Raising([CancelledError])
    onStateUpdatedCb*: OnStateUpdated
    blocks*: seq[BlockData]

  SyncKind* {.pure.} = enum
    ForwardSync, TrustedNodeSync,
    UntrustedSyncInit,
    UntrustedSyncDownload,
    UntrustedSyncRebuild

  SyncOverseer* = object
    statusMsg*: Opt[string]
    consensusManager*: ref ConsensusManager
    validatorMonitor*: ref ValidatorMonitor
    config*: BeaconNodeConf
    getBeaconTimeFn*: GetBeaconTimeFn
    clist*: ChainListRef
    beaconClock*: BeaconClock
    eventQueue*: AsyncEventQueue[ForkedLightClientHeader]
    loopFuture*: Future[void].Raising([])
    forwardSync*: SyncManager[Peer, PeerId]
    backwardSync*: SyncManager[Peer, PeerId]
    untrustedSync*: SyncManager[Peer, PeerId]
    batchVerifier*: ref BatchVerifier
    pool*: PeerPool[Peer, PeerId]
    avgSpeedCounter*: int
    avgSpeed*: float
    blocksQueue*: AsyncQueue[BlockDataChunk]
    untrustedInProgress*: bool
    syncKind*: SyncKind

  ColumnsPeerState* = object
    usefulCount*: int
    uselessCount*: int
    distribution*: Table[ColumnIndex, int]

  SyncOverseer2* = object
    network*: Eth2Node
    consensusManager*: ref ConsensusManager
    config*: BeaconNodeConf
    getBeaconTimeFn*: GetBeaconTimeFn
    beaconClock*: BeaconClock
    loopFuture*: Future[void].Raising([])
    pool*: PeerPool[Peer, PeerId]
    blockProcessor*: ref BlockProcessor
    fblockBuffer*: BlocksRangeBuffer
    bblockBuffer*: BlocksRangeBuffer
    rblockBuffer*: BlocksRootBuffer
    blockQuarantine*: ref Quarantine
    blobQuarantine*: ref BlobQuarantine
    columnQuarantine*: ref ColumnQuarantine
    blockGossipBus*: AsyncEventQueue[EventBeaconBlockGossipPeerObject]
    blocksQueueBus*: AsyncEventQueue[EventBeaconBlockObject]
    blockFinalizationBus*: AsyncEventQueue[FinalizationInfoObject]
    missingRoots*: HashSet[Eth2Digest]
    avgSpeedCounter*: int
    avgSpeed*: float
    blocksChunkSize*: int
    sidecarsChunkSize*: int
    fqueue*: SyncQueue[Peer]
    fsqueue*: SyncQueue[Peer]
    bqueue*: SyncQueue[Peer]
    bsqueue*: SyncQueue[Peer]
    localPeerId*: PeerId
    lastSeenCheckpoint*: Opt[Checkpoint]
    lastSeenHead*: Opt[BlockId]
    statusMessages*: array[2, string]
    sdag*: SyncDag[Peer, PeerId]
    columnsState*: ColumnsPeerState

  SyncOverseerRef* = ref SyncOverseer

  SyncOverseerRef2* = ref SyncOverseer2

proc new*(
    t: typedesc[SyncOverseerRef],
    cm: ref ConsensusManager,
    vm: ref ValidatorMonitor,
    configuration: BeaconNodeConf,
    bt: GetBeaconTimeFn,
    clist: ChainListRef,
    clock: BeaconClock,
    eq: AsyncEventQueue[ForkedLightClientHeader],
    pool: PeerPool[Peer, PeerId],
    blockVerifier: BlockVerifier,
    forwardSync: SyncManager[Peer, PeerId],
    backwardSync: SyncManager[Peer, PeerId],
    untrustedSync: SyncManager[Peer, PeerId]
): SyncOverseerRef =
  SyncOverseerRef(
    consensusManager: cm,
    validatorMonitor: vm,
    config: configuration,
    getBeaconTimeFn: bt,
    clist: clist,
    beaconClock: clock,
    eventQueue: eq,
    pool: pool,
    blockVerifier: BlockVerifier,
    forwardSync: forwardSync,
    backwardSync: backwardSync,
    untrustedSync: untrustedSync,
    untrustedInProgress: false,
    blocksQueue: newAsyncQueue[BlockDataChunk]())

proc syncInProgress*(overseer: SyncOverseerRef): bool =
  overseer.forwardSync.inProgress or
  overseer.backwardSync.inProgress or
  overseer.untrustedSync.inProgress or
  overseer.untrustedInProgress

proc new*(
    t: typedesc[SyncOverseerRef2],
    net: Eth2Node,
    cm: ref ConsensusManager,
    configuration: BeaconNodeConf,
    bt: GetBeaconTimeFn,
    clock: BeaconClock,
    blockProcessor: ref BlockProcessor,
    blockQuarantine: ref Quarantine,
    blobQuarantine: ref BlobQuarantine,
    columnQuarantine: ref ColumnQuarantine,
    gossipQueue: AsyncEventQueue[EventBeaconBlockGossipPeerObject],
    blocksQueue: AsyncEventQueue[EventBeaconBlockObject],
    finalizationQueue: AsyncEventQueue[FinalizationInfoObject],
    blocksChunkSize = int(SLOTS_PER_EPOCH),
    sidecarsChunkSize = int(SLOTS_PER_EPOCH)
): SyncOverseerRef2 =
  SyncOverseerRef2(
    network: net,
    consensusManager: cm,
    config: configuration,
    getBeaconTimeFn: bt,
    beaconClock: clock,
    pool: net.peerPool,
    blockProcessor: blockProcessor,
    blobQuarantine: blobQuarantine,
    columnQuarantine: columnQuarantine,
    blockQuarantine: blockQuarantine,
    blockGossipBus: gossipQueue,
    blocksQueueBus: blocksQueue,
    blockFinalizationBus: finalizationQueue,
    blocksChunkSize: blocksChunkSize,
    sidecarsChunkSize: sidecarsChunkSize,
    localPeerId: net.peerId(),
    sdag: SyncDag.init(Peer, PeerId),
  )
