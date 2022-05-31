# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Everything needed to run a full Beacon Node

import
  std/osproc,

  # Nimble packages
  chronos, json_rpc/servers/httpserver, presto,

  # Local modules
  "."/[beacon_clock, beacon_chain_db, conf, light_client],
  ./gossip_processing/[eth2_processor, block_processor, consensus_manager],
  ./networking/eth2_network,
  ./eth1/eth1_monitor,
  ./consensus_object_pools/[
    blockchain_dag, block_quarantine, exit_pool, attestation_pool,
    sync_committee_msg_pool],
  ./spec/datatypes/base,
  ./sync/[sync_manager, request_manager],
  ./validators/[action_tracker, validator_monitor, validator_pool],
  ./rpc/state_ttl_cache

export
  osproc, chronos, httpserver, presto, action_tracker,
  beacon_clock, beacon_chain_db, conf, light_client,
  attestation_pool, sync_committee_msg_pool, validator_pool,
  eth2_network, eth1_monitor, request_manager, sync_manager,
  eth2_processor, blockchain_dag, block_quarantine, base, exit_pool,
  validator_monitor, consensus_manager

type
  RpcServer* = RpcHttpServer

  BeaconNode* = ref object
    nickname*: string
    graffitiBytes*: GraffitiBytes
    network*: Eth2Node
    netKeys*: NetKeyPair
    db*: BeaconChainDB
    config*: BeaconNodeConf
    attachedValidators*: ref ValidatorPool
    lightClient*: LightClient
    dag*: ChainDAGRef
    quarantine*: ref Quarantine
    attestationPool*: ref AttestationPool
    syncCommitteeMsgPool*: ref SyncCommitteeMsgPool
    lightClientPool*: ref LightClientPool
    exitPool*: ref ExitPool
    eth1Monitor*: Eth1Monitor
    restServer*: RestServerRef
    keymanagerServer*: RestServerRef
    keymanagerToken*: Option[string]
    eventBus*: AsyncEventBus
    vcProcess*: Process
    requestManager*: RequestManager
    syncManager*: SyncManager[Peer, PeerId]
    backfiller*: SyncManager[Peer, PeerId]
    genesisSnapshotContent*: string
    actionTracker*: ActionTracker
    processor*: ref Eth2Processor
    blockProcessor*: ref BlockProcessor
    consensusManager*: ref ConsensusManager
    attachedValidatorBalanceTotal*: uint64
    gossipState*: GossipState
    beaconClock*: BeaconClock
    restKeysCache*: Table[ValidatorPubKey, ValidatorIndex]
    validatorMonitor*: ref ValidatorMonitor
    stateTtlCache*: StateTtlCache

const
  MaxEmptySlotCount* = uint64(10*60) div SECONDS_PER_SLOT

# TODO stew/sequtils2
template findIt*(s: openArray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

proc currentSlot*(node: BeaconNode): Slot =
  node.beaconClock.now.slotOrZero
