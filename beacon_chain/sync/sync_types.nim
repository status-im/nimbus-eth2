# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import results, chronos,
       ".."/spec/[forks_light_client, signatures_batch],
       ".."/consensus_object_pools/[block_pools_types, blockchain_dag,
                                    attestation_pool, blockchain_list,
                                    consensus_manager],
       ".."/validators/validator_monitor,
       ".."/[beacon_clock, conf],
       ".."/networking/eth2_network,
       "."/sync_manager

export results, chronos, block_pools_types, conf

type
  BlockDataChunk* = ref object
    resfut*: Future[Result[void, string]].Raising([CancelledError])
    onStateUpdatedCb*: OnStateUpdated
    blocks*: seq[BlockData]

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

  SyncOverseerRef* = ref SyncOverseer

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
    batchVerifier: ref BatchVerifier,
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
    batchVerifier: batchVerifier,
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
