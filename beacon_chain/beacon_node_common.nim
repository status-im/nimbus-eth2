# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Common routines for a BeaconNode and a BeaconValidator node

import
  # Nimble packages
  chronos, json_rpc/rpcserver, metrics,

  # Local modules
  spec/[datatypes, crypto],
  conf, time, beacon_chain_db, validator_pool,
  attestation_pool, block_pool, eth2_network,
  beacon_node_types, mainchain_monitor,
  sync_protocol, request_manager

type
  BeaconNode* = ref object
    nickname*: string
    network*: Eth2Node
    netKeys*: KeyPair
    requestManager*: RequestManager
    db*: BeaconChainDB
    config*: BeaconNodeConf
    attachedValidators*: ValidatorPool
    blockPool*: BlockPool
    attestationPool*: AttestationPool
    mainchainMonitor*: MainchainMonitor
    beaconClock*: BeaconClock
    rpcServer*: RpcServer
    forkDigest*: ForkDigest
    topicBeaconBlocks*: string
    topicAggregateAndProofs*: string
    syncLoop*: Future[void]

const MaxEmptySlotCount* = uint64(10*60) div SECONDS_PER_SLOT

# Metrics
declareGauge beacon_head_root,
  "Root of the head block of the beacon chain"

proc updateHead*(node: BeaconNode): BlockRef =
  # Check pending attestations - maybe we found some blocks for them
  node.attestationPool.resolve()

  # Grab the new head according to our latest attestation data
  let newHead = node.attestationPool.selectHead()

  # Store the new head in the block pool - this may cause epochs to be
  # justified and finalized
  node.blockPool.updateHead(newHead)
  beacon_head_root.set newHead.root.toGaugeValue

  newHead
