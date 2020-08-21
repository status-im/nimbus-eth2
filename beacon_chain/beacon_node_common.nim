# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Common routines for a BeaconNode and a BeaconValidator node

import
  # Standard library
  tables,

  # Nimble packages
  chronos, json_rpc/rpcserver, metrics,
  chronicles,

  # Local modules
  spec/[datatypes, crypto, digest],
  conf, time, beacon_chain_db,
  attestation_pool, eth2_network,
  block_pools/[chain_dag, quarantine],
  beacon_node_types, mainchain_monitor, request_manager,
  sync_manager,
  ./eth2_processor

# This removes an invalid Nim warning that the digest module is unused here
# It's currently used for `shortLog(head.blck.root)`
type Eth2Digest = digest.Eth2Digest

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
    mainchainMonitor*: MainchainMonitor
    beaconClock*: BeaconClock
    rpcServer*: RpcServer
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

const
  MaxEmptySlotCount* = uint64(10*60) div SECONDS_PER_SLOT

# Metrics
proc updateHead*(node: BeaconNode, wallSlot: Slot): Option[BlockRef] =
  node.processor[].updateHead(wallSlot)

template findIt*(s: openarray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res
