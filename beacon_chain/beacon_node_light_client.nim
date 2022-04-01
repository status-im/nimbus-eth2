# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  "."/beacon_node,
  ./gossip_processing/light_client_processor,
  ./spec/datatypes/altair,
  ./sync/light_client_manager

logScope: topics = "beacnde"

proc getLocalWallPeriod(node: BeaconNode): SyncCommitteePeriod =
  node.beaconClock.now.slotOrZero.sync_committee_period

proc initLightClient*(
    node: BeaconNode,
    cfg: RuntimeConfig,
    rng: ref BrHmacDrbgContext,
    genesisValidatorsRoot: Eth2Digest,
    getBeaconTime: GetBeaconTimeFn) =
  template config(): auto = node.config

  let store = (ref Option[LightClientStore])()

  func getTrustedBlockRoot(): Option[Eth2Digest] =
    node.lightClient.trustedBlockRoot

  proc getLocalWallPeriod(): SyncCommitteePeriod =
    node.getLocalWallPeriod()

  func getFinalizedPeriod(): SyncCommitteePeriod =
    if store[].isSome:
      store[].get.finalized_header.slot.sync_committee_period
    else:
      GENESIS_SLOT.sync_committee_period

  func isLightClientStoreInitialized(): bool =
    store[].isSome

  func isNextSyncCommitteeKnown(): bool =
    if store[].isSome:
      not store[].get.next_sync_committee.isZeroMemory
    else:
      false

  let lightClientProcessor = LightClientProcessor.new(
    config.dumpEnabled, config.dumpDirInvalid, config.dumpDirIncoming,
    cfg, genesisValidatorsRoot, store, getBeaconTime, getTrustedBlockRoot)

  proc lightClientVerifier(obj: SomeLightClientObject):
      Future[Result[void, BlockError]] =
    let resfut = newFuture[Result[void, BlockError]]("lightClientVerifier")
    lightClientProcessor[].addObject(MsgSource.gossip, obj, resfut)
    resfut
  let
    bootstrapVerifier = proc(obj: altair.LightClientBootstrap):
        Future[Result[void, BlockError]] =
      lightClientVerifier(obj)
    updateVerifier = proc(obj: altair.LightClientUpdate):
        Future[Result[void, BlockError]] =
      lightClientVerifier(obj)
    optimisticUpdateVerifier = proc(obj: OptimisticLightClientUpdate):
        Future[Result[void, BlockError]] =
      lightClientVerifier(obj)

  node.lightClient.trustedBlockRoot = config.lightClientTrustedBlockRoot
  node.lightClient.store = store
  node.lightClient.processor = lightClientProcessor
  node.lightClient.manager = LightClientManager.init(
    node.network, rng,
    bootstrapVerifier, updateVerifier, optimisticUpdateVerifier,
    getTrustedBlockRoot, getLocalWallPeriod, getFinalizedPeriod,
    isLightClientStoreInitialized, isNextSyncCommitteeKnown)
  node.lightClient.gossipState = {}

proc startLightClient*(node: BeaconNode) =
  if node.lightClient.trustedBlockRoot.isNone:
    return

  notice "Starting light client",
    trusted_block_root = node.lightClient.trustedBlockRoot.get
  node.lightClient.manager.start()

proc installLightClientMessageValidators*(node: BeaconNode) =
  let forkDigests = node.dag.forkDigests
  for digest in [forkDigests.altair, forkDigests.bellatrix]:
    node.network.addValidator(
      getOptimisticLightClientUpdateTopic(digest),
      proc(msg: OptimisticLightClientUpdate): ValidationResult =
        template lc(): auto = node.lightClient
        if lc.manager.isGossipSupported(node.getLocalWallPeriod()):
          toValidationResult(
            lc.processor[].optimisticLightClientUpdateValidator(
              MsgSource.gossip, msg))
        else:
          ValidationResult.Ignore)

from
  libp2p/protocols/pubsub/gossipsub
import
  TopicParams, validateParameters, init

const lightClientTopicParams = TopicParams.init()
static: lightClientTopicParams.validateParameters().tryGet()

proc updateLightClientGossipStatus*(node: BeaconNode, slot: Slot) =
  let
    isBehind =
      if node.lightClient.manager.isGossipSupported(slot.sync_committee_period):
        false
      elif node.config.serveLightClientData:
        # While separate message validators can be installed for both
        # full node and light client (both are called unless one rejects msg),
        # only a single subscription can be installed per topic for now.
        # The full node subscription is also handled here, even though it
        # does not directly relate to the client side of the LC sync protocol
        let headDistance =
          if slot > node.dag.head.slot: (slot - node.dag.head.slot).uint64
          else: 0'u64
        headDistance > TOPIC_SUBSCRIBE_THRESHOLD_SLOTS + HYSTERESIS_BUFFER
      else:
        true # Force `targetGossipState` to `{}`
    targetGossipState =
      getTargetGossipState(
        slot.epoch,
        node.dag.cfg.ALTAIR_FORK_EPOCH,
        node.dag.cfg.BELLATRIX_FORK_EPOCH,
        isBehind)
  template currentGossipState(): auto = node.lightClient.gossipState
  if currentGossipState == targetGossipState:
    return

  if currentGossipState.card == 0 and targetGossipState.card > 0:
    debug "Enabling light client topic subscriptions",
      wallSlot = slot, targetGossipState
  elif currentGossipState.card > 0 and targetGossipState.card == 0:
    debug "Disabling light client topic subscriptions",
      wallSlot = slot
  else:
    # Individual forks added / removed
    discard

  let
    newGossipForks = targetGossipState - currentGossipState
    oldGossipForks = currentGossipState - targetGossipState

  for gossipFork in oldGossipForks:
    if gossipFork >= BeaconStateFork.Altair:
      let forkDigest = node.dag.forkDigest(gossipFork)
      node.network.unsubscribe(
        getOptimisticLightClientUpdateTopic(forkDigest))

  for gossipFork in newGossipForks:
    if gossipFork >= BeaconStateFork.Altair:
      let forkDigest = node.dag.forkDigest(gossipFork)
      node.network.subscribe(
        getOptimisticLightClientUpdateTopic(forkDigest),
        lightClientTopicParams)

  node.lightClient.gossipState = targetGossipState
