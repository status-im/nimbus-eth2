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
    node.beaconClock.now.slotOrZero.sync_committee_period

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

proc startLightClient*(node: BeaconNode) =
  if node.lightClient.trustedBlockRoot.isNone:
    return

  notice "Starting light client",
    trusted_block_root = node.lightClient.trustedBlockRoot.get
  node.lightClient.manager.start()
