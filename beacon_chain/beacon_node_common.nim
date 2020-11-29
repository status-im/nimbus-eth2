# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Common routines for a BeaconNode and a BeaconValidator node

import
  std/osproc,

  # Nimble packages
  chronos, json_rpc/rpcserver,

  # Local modules
  ./conf, ./time, ./beacon_chain_db, ./attestation_pool, ./eth2_network,
  ./beacon_node_types, ./eth1_monitor, ./request_manager,
  ./sync_manager, ./eth2_processor,
  ./block_pools/[chain_dag, quarantine],
  ./spec/datatypes

export
  osproc, chronos, rpcserver, conf, time, beacon_chain_db,
  attestation_pool, eth2_network, beacon_node_types, eth1_monitor,
  request_manager, sync_manager, eth2_processor, chain_Dag, quarantine,
  datatypes

type
  RpcServer* = RpcHttpServer
  KeyPair* = eth2_network.KeyPair

  BeaconNode* = ref object
    nickname*: string
    graffitiBytes*: GraffitiBytes
    network*: Eth2Node
    netKeys*: KeyPair
    db*: BeaconChainDB
    config*: BeaconNodeConf
    attachedValidators*: ValidatorPool
    chainDag*: ChainDAGRef
    quarantine*: QuarantineRef
    attestationPool*: ref AttestationPool
    exitPool*: ref ExitPool
    eth1Monitor*: Eth1Monitor
    beaconClock*: BeaconClock
    rpcServer*: RpcServer
    vcProcess*: Process
    forkDigest*: ForkDigest
    requestManager*: RequestManager
    syncManager*: SyncManager[Peer, PeerID]
    topicBeaconBlocks*: string
    topicAggregateAndProofs*: string
    blockProcessingLoop*: Future[void]
    onSecondLoop*: Future[void]
    genesisSnapshotContent*: string
    attestationSubnets*: AttestationSubnets
    processor*: ref Eth2Processor
    attachedValidatorBalanceTotal*: uint64

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
