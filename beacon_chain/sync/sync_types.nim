# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import results, chronos,
       ".."/spec/forks_light_client,
       ".."/consensus_object_pools/blockchain_dag,
       ".."/beacon_clock,
       ".."/networking/eth2_network,
       "."/sync_manager

export results, chronos

type
  SyncOverseer* = object
    statusMsg*: Opt[string]
    dag*: ChainDagRef
    clist*: ChainListRef
    beaconClock*: BeaconClock
    eventQueue*: AsyncEventQueue[ForkedLightClientHeader]
    loopFuture*: Future[void].Raising([])
    forwardSync*: SyncManager[Peer, PeerId]
    backwardSync*: SyncManager[Peer, PeerId]
    pool*: PeerPool[Peer, PeerId]

  SyncOverseerRef* = ref SyncOverseer

proc new*(
    t: typedesc[SyncOverseerRef],
    dag: ChainDagRef,
    clist: ChainListRef,
    clock: BeaconClock,
    eq: AsyncEventQueue[ForkedLightClientHeader],
    pool: PeerPool[Peer, PeerId],
    forwardSync: SyncManager[Peer, PeerId],
    backwardSync: SyncManager[Peer, PeerId]
): SyncOverseerRef =
  SyncOverseerRef(dag: dag, clist: clist, beaconClock: clock, eventQueue: eq,
                  forwardSync: forwardSync, backwardSync: backwardSync,
                  pool: pool)
