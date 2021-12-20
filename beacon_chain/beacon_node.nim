# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
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
  "."/[beacon_clock, beacon_chain_db, conf],
  ./gossip_processing/[eth2_processor, block_processor, consensus_manager],
  ./networking/eth2_network,
  ./eth1/eth1_monitor,
  ./consensus_object_pools/[
    blockchain_dag, block_quarantine, exit_pool, attestation_pool,
    sync_committee_msg_pool],
  ./spec/datatypes/base,
  ./sync/[sync_manager, request_manager],
  ./validators/[action_tracker, validator_monitor, validator_pool]

export
  osproc, chronos, httpserver, presto, action_tracker, beacon_clock,
  beacon_chain_db, conf, attestation_pool, sync_committee_msg_pool,
  validator_pool, eth2_network, eth1_monitor, request_manager, sync_manager,
  eth2_processor, blockchain_dag, block_quarantine, base, exit_pool,
  validator_monitor

type
  RpcServer* = RpcHttpServer

  GossipState* = enum
    Disconnected
    ConnectedToPhase0
    InTransitionToAltair
    ConnectedToAltair

  BeaconNode* = ref object
    nickname*: string
    graffitiBytes*: GraffitiBytes
    network*: Eth2Node
    netKeys*: NetKeyPair
    db*: BeaconChainDB
    config*: BeaconNodeConf
    attachedValidators*: ref ValidatorPool
    dag*: ChainDAGRef
    quarantine*: ref Quarantine
    attestationPool*: ref AttestationPool
    syncCommitteeMsgPool*: ref SyncCommitteeMsgPool
    exitPool*: ref ExitPool
    eth1Monitor*: Eth1Monitor
    rpcServer*: RpcServer
    restServer*: RestServerRef
    eventBus*: AsyncEventBus
    vcProcess*: Process
    requestManager*: RequestManager
    syncManager*: SyncManager[Peer, PeerID]
    genesisSnapshotContent*: string
    actionTracker*: ActionTracker
    processor*: ref Eth2Processor
    blockProcessor*: ref BlockProcessor
    consensusManager*: ref ConsensusManager
    attachedValidatorBalanceTotal*: uint64
    gossipState*: GossipState
    beaconClock*: BeaconClock
    onAttestationSent*: OnAttestationCallback
    restKeysCache*: Table[ValidatorPubKey, ValidatorIndex]
    validatorMonitor*: ref ValidatorMonitor

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
