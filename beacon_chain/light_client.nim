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
  chronicles,
  eth/keys,
  ./gossip_processing/light_client_processor,
  ./networking/eth2_network,
  ./spec/datatypes/altair,
  ./spec/helpers,
  ./sync/light_client_manager,
  "."/[beacon_clock, conf_light_client]

export eth2_network, conf_light_client

logScope: topics = "lightcl"

type
  LightClientCallback* =
    proc(lightClient: LightClient) {.gcsafe, raises: [Defect].}

  LightClient* = ref object
    network: Eth2Node
    cfg: RuntimeConfig
    forkDigests: ref ForkDigests
    getBeaconTime: GetBeaconTimeFn
    store: ref Option[LightClientStore]
    processor: ref LightClientProcessor
    manager: LightClientManager
    gossipState: GossipState
    onFinalizedHeader*, onOptimisticHeader*: LightClientCallback
    trustedBlockRoot*: Option[Eth2Digest]

func finalizedHeader*(lightClient: LightClient): Opt[BeaconBlockHeader] =
  if lightClient.store[].isSome:
    ok lightClient.store[].get.finalized_header
  else:
    err()

func optimisticHeader*(lightClient: LightClient): Opt[BeaconBlockHeader] =
  if lightClient.store[].isSome:
    ok lightClient.store[].get.optimistic_header
  else:
    err()

proc createLightClient(
    network: Eth2Node,
    rng: ref BrHmacDrbgContext,
    dumpEnabled: bool,
    dumpDirInvalid, dumpDirIncoming: string,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest
): LightClient =
  let lightClient = LightClient(
    network: network,
    cfg: cfg,
    forkDigests: forkDigests,
    getBeaconTime: getBeaconTime,
    store: (ref Option[LightClientStore])())

  func getTrustedBlockRoot(): Option[Eth2Digest] =
    lightClient.trustedBlockRoot

  proc onStoreInitialized() =
    discard

  proc onFinalizedHeader() =
    if lightClient.onFinalizedHeader != nil:
      lightClient.onFinalizedHeader(lightClient)

  proc onOptimisticHeader() =
    if lightClient.onOptimisticHeader != nil:
      lightClient.onOptimisticHeader(lightClient)

  lightClient.processor = LightClientProcessor.new(
    dumpEnabled, dumpDirInvalid, dumpDirIncoming,
    cfg, genesis_validators_root,
    lightClient.store, getBeaconTime, getTrustedBlockRoot,
    onStoreInitialized, onFinalizedHeader, onOptimisticHeader)

  proc lightClientVerifier(obj: SomeLightClientObject):
      Future[Result[void, BlockError]] =
    let resfut = newFuture[Result[void, BlockError]]("lightClientVerifier")
    lightClient.processor[].addObject(MsgSource.gossip, obj, resfut)
    resfut
  proc bootstrapVerifier(obj: altair.LightClientBootstrap): auto =
    lightClientVerifier(obj)
  proc updateVerifier(obj: altair.LightClientUpdate): auto =
    lightClientVerifier(obj)
  proc finalityVerifier(obj: altair.LightClientFinalityUpdate): auto =
    lightClientVerifier(obj)
  proc optimisticVerifier(obj: altair.LightClientOptimisticUpdate): auto =
    lightClientVerifier(obj)

  func isLightClientStoreInitialized(): bool =
    lightClient.store[].isSome

  func isNextSyncCommitteeKnown(): bool =
    if lightClient.store[].isSome:
      lightClient.store[].get.is_next_sync_committee_known
    else:
      false

  func getFinalizedPeriod(): SyncCommitteePeriod =
    if lightClient.store[].isSome:
      lightClient.store[].get.finalized_header.slot.sync_committee_period
    else:
      GENESIS_SLOT.sync_committee_period

  func getOptimisticPeriod(): SyncCommitteePeriod =
    if lightClient.store[].isSome:
      lightClient.store[].get.optimistic_header.slot.sync_committee_period
    else:
      GENESIS_SLOT.sync_committee_period

  lightClient.manager = LightClientManager.init(
    lightClient.network, rng, getTrustedBlockRoot,
    bootstrapVerifier, updateVerifier, finalityVerifier, optimisticVerifier,
    isLightClientStoreInitialized, isNextSyncCommitteeKnown,
    getFinalizedPeriod, getOptimisticPeriod, getBeaconTime)

  lightClient.gossipState = {}

  lightClient

proc createLightClient*(
    network: Eth2Node,
    rng: ref BrHmacDrbgContext,
    config: BeaconNodeConf,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest
): LightClient =
  createLightClient(
    network, rng,
    config.dumpEnabled, config.dumpDirInvalid, config.dumpDirIncoming,
    cfg, forkDigests, getBeaconTime, genesis_validators_root)

proc createLightClient*(
    network: Eth2Node,
    rng: ref BrHmacDrbgContext,
    config: LightClientConf,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest
): LightClient =
  createLightClient(
    network, rng,
    dumpEnabled = false, dumpDirInvalid = ".", dumpDirIncoming = ".",
    cfg, forkDigests, getBeaconTime, genesis_validators_root)

proc installMessageValidators*(lightClient: LightClient) =
  template getLocalWallPeriod(): auto =
    lightClient.getBeaconTime().slotOrZero().sync_committee_period

  let forkDigests = lightClient.forkDigests
  for digest in [forkDigests.altair, forkDigests.bellatrix]:
    lightClient.network.addValidator(
      getLightClientFinalityUpdateTopic(digest),
      proc(msg: altair.LightClientFinalityUpdate): ValidationResult =
        let
          wallTime = lightClient.getBeaconTime()
          wallPeriod = wallTime.slotOrZero().sync_committee_period
        if lightClient.manager.isGossipSupported(getLocalWallPeriod()):
          toValidationResult(
            lightClient.processor[].lightClientFinalityUpdateValidator(
              MsgSource.gossip, msg))
        else:
          ValidationResult.Ignore)

    lightClient.network.addValidator(
      getLightClientOptimisticUpdateTopic(digest),
      proc(msg: altair.LightClientOptimisticUpdate): ValidationResult =
        let
          wallTime = lightClient.getBeaconTime()
          wallPeriod = wallTime.slotOrZero().sync_committee_period
        if lightClient.manager.isGossipSupported(getLocalWallPeriod()):
          toValidationResult(
            lightClient.processor[].lightClientOptimisticUpdateValidator(
              MsgSource.gossip, msg))
        else:
          ValidationResult.Ignore)

proc start*(lightClient: LightClient) =
  notice "Starting light client",
    trusted_block_root = lightClient.trustedBlockRoot
  lightClient.manager.start()

from
  libp2p/protocols/pubsub/gossipsub
import
  TopicParams, validateParameters, init

const lightClientTopicParams = TopicParams.init()
static: lightClientTopicParams.validateParameters().tryGet()

proc updateGossipStatus*(
    lightClient: LightClient, slot: Slot, dagIsBehind = default(Option[bool])) =
  let
    isBehind =
      if lightClient.manager.isGossipSupported(slot.sync_committee_period):
        false
      elif dagIsBehind.isSome:
        # While separate message validators can be installed for both
        # full node and light client (both are called unless one rejects msg),
        # only a single subscription can be installed per topic for now.
        # The full node subscription is also handled here, even though it
        # does not directly relate to the client side of the LC sync protocol
        dagIsBehind.get
      else:
        true # Force `targetGossipState` to `{}`
    targetGossipState =
      getTargetGossipState(
        slot.epoch,
        lightClient.cfg.ALTAIR_FORK_EPOCH,
        lightClient.cfg.BELLATRIX_FORK_EPOCH,
        isBehind)
  template currentGossipState(): auto = lightClient.gossipState
  if currentGossipState == targetGossipState:
    return

  if currentGossipState.card == 0 and targetGossipState.card > 0:
    debug "Enabling LC topic subscriptions",
      wallSlot = slot, targetGossipState
  elif currentGossipState.card > 0 and targetGossipState.card == 0:
    debug "Disabling LC topic subscriptions",
      wallSlot = slot
  else:
    # Individual forks added / removed
    discard

  let
    newGossipForks = targetGossipState - currentGossipState
    oldGossipForks = currentGossipState - targetGossipState

  for gossipFork in oldGossipForks:
    if gossipFork >= BeaconStateFork.Altair:
      let forkDigest = lightClient.forkDigests[].atStateFork(gossipFork)
      lightClient.network.unsubscribe(
        getLightClientFinalityUpdateTopic(forkDigest))

  for gossipFork in newGossipForks:
    if gossipFork >= BeaconStateFork.Altair:
      let forkDigest = lightClient.forkDigests[].atStateFork(gossipFork)
      lightClient.network.subscribe(
        getLightClientOptimisticUpdateTopic(forkDigest),
        lightClientTopicParams)

  lightClient.gossipState = targetGossipState
