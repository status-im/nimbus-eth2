# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Common routines for a BeaconNode and a BeaconValidator node

import
  # Standard library
  os, tables,

  # Nimble packages
  chronos, json_rpc/rpcserver, metrics,
  chronicles,

  # Local modules
  spec/[datatypes, crypto, digest, helpers],
  conf, time, beacon_chain_db, sszdump,
  ssz/merkleization,
  attestation_pool, block_pool, eth2_network,
  beacon_node_types, mainchain_monitor, request_manager,
  sync_manager

# This removes an invalid Nim warning that the digest module is unused here
# It's currently used for `shortLog(head.blck.root)`
type Eth2Digest = digest.Eth2Digest

type
  RpcServer* = RpcHttpServer

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
    syncManager*: SyncManager[Peer, PeerID]
    topicBeaconBlocks*: string
    topicAggregateAndProofs*: string
    forwardSyncLoop*: Future[void]
    onSecondLoop*: Future[void]

const
  MaxEmptySlotCount* = uint64(10*60) div SECONDS_PER_SLOT

# Metrics
declareGauge beacon_head_root,
  "Root of the head block of the beacon chain"

# Metrics for tracking attestation and beacon block loss
declareCounter beacon_blocks_received,
  "Number of beacon chain blocks received by this peer"

proc onAttestation*(node: BeaconNode, attestation: Attestation) =
  # We received an attestation from the network but don't know much about it
  # yet - in particular, we haven't verified that it belongs to particular chain
  # we're on, or that it follows the rules of the protocol
  logScope: pcs = "on_attestation"

  let
    wallSlot = node.beaconClock.now().toSlot()
    head = node.blockPool.head

  debug "Attestation received",
    attestation = shortLog(attestation),
    headRoot = shortLog(head.blck.root),
    headSlot = shortLog(head.blck.slot),
    wallSlot = shortLog(wallSlot.slot),
    cat = "consensus" # Tag "consensus|attestation"?

  if not wallSlot.afterGenesis or wallSlot.slot < head.blck.slot:
    warn "Received attestation before genesis or head - clock is wrong?",
      afterGenesis = wallSlot.afterGenesis,
      wallSlot = shortLog(wallSlot.slot),
      headSlot = shortLog(head.blck.slot),
      cat = "clock_drift" # Tag "attestation|clock_drift"?
    return

  if attestation.data.slot > head.blck.slot and
      (attestation.data.slot - head.blck.slot) > MaxEmptySlotCount:
    warn "Ignoring attestation, head block too old (out of sync?)",
      attestationSlot = attestation.data.slot, headSlot = head.blck.slot
    return

  node.attestationPool.add(attestation)

proc storeBlock*(
    node: BeaconNode, signedBlock: SignedBeaconBlock): Result[void, BlockError] =
  let blockRoot = hash_tree_root(signedBlock.message)
  debug "Block received",
    signedBlock = shortLog(signedBlock.message),
    blockRoot = shortLog(blockRoot),
    cat = "block_listener",
    pcs = "receive_block"

  if node.config.dumpEnabled:
    dump(node.config.dumpDir / "incoming", signedBlock, blockRoot)

  beacon_blocks_received.inc()
  let blck = node.blockPool.add(blockRoot, signedBlock)
  if blck.isErr:
    if blck.error == Invalid and node.config.dumpEnabled:
      let parent = node.blockPool.getRef(signedBlock.message.parent_root)
      if parent != nil:
        node.blockPool.withState(
          node.blockPool.tmpState, parent.atSlot(signedBlock.message.slot - 1)):
            dump(node.config.dumpDir / "invalid", hashedState, parent)
            dump(node.config.dumpDir / "invalid", signedBlock, blockRoot)

    return err(blck.error)

  # The block we received contains attestations, and we might not yet know about
  # all of them. Let's add them to the attestation pool - in case they block
  # is not yet resolved, neither will the attestations be!
  # But please note that we only care about recent attestations.
  # TODO shouldn't add attestations if the block turns out to be invalid..
  let currentSlot = node.beaconClock.now.toSlot
  if currentSlot.afterGenesis and
    signedBlock.message.slot.epoch + 1 >= currentSlot.slot.epoch:
    for attestation in signedBlock.message.body.attestations:
      node.onAttestation(attestation)
  ok()

proc onBeaconBlock*(node: BeaconNode, signedBlock: SignedBeaconBlock) =
  # We received a block but don't know much about it yet - in particular, we
  # don't know if it's part of the chain we're currently building.
  discard node.storeBlock(signedBlock)

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

template findIt*(s: openarray, predicate: untyped): int64 =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res
