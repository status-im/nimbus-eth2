# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  chronicles,
  ./beacon_node

logScope: topics = "beacnde"

func shouldSyncOptimistically*(node: BeaconNode, wallSlot: Slot): bool =
  # Check whether light client is used
  let optimisticHeader = node.lightClient.optimisticHeader.valueOr:
    return false

  # Check whether light client is sufficiently ahead of DAG
  const minProgress = 8 * SLOTS_PER_EPOCH  # Set arbitrarily
  let dagSlot = getStateField(node.dag.headState, slot)
  if dagSlot + minProgress > optimisticHeader.slot:
    return false

  # Check whether light client has synced sufficiently close to wall slot
  const maxAge = 2 * SLOTS_PER_EPOCH
  if optimisticHeader.slot < max(wallSlot, maxAge.Slot) - maxAge:
    return false

  true

proc initLightClient*(
    node: BeaconNode,
    rng: ref HmacDrbgContext,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest) =
  template config(): auto = node.config

  # Creating a light client is not dependent on `lightClientEnable`
  # because the light client module also handles gossip subscriptions
  # for broadcasting light client data as a server.

  let
    optimisticHandler = proc(signedBlock: ForkedMsgTrustedSignedBeaconBlock):
        Future[void] {.async.} =
      debug "New LC optimistic block",
        opt = signedBlock.toBlockId(),
        dag = node.dag.head.bid,
        wallSlot = node.currentSlot
      return
    optimisticProcessor = initOptimisticProcessor(
      getBeaconTime, optimisticHandler)

    lightClient = createLightClient(
      node.network, rng, config, cfg, forkDigests, getBeaconTime,
      genesis_validators_root, LightClientFinalizationMode.Strict)

  if config.lightClientEnable:
    proc onFinalizedHeader(
        lightClient: LightClient, finalizedHeader: BeaconBlockHeader) =
      optimisticProcessor.setFinalizedHeader(finalizedHeader)

    proc onOptimisticHeader(
        lightClient: LightClient, optimisticHeader: BeaconBlockHeader) =
      optimisticProcessor.setOptimisticHeader(optimisticHeader)

    lightClient.onFinalizedHeader = onFinalizedHeader
    lightClient.onOptimisticHeader = onOptimisticHeader
    lightClient.trustedBlockRoot = config.lightClientTrustedBlockRoot

  elif config.lightClientTrustedBlockRoot.isSome:
    warn "Ignoring `lightClientTrustedBlockRoot`, light client not enabled",
      lightClientEnable = config.lightClientEnable,
      lightClientTrustedBlockRoot = config.lightClientTrustedBlockRoot

  node.optimisticProcessor = optimisticProcessor
  node.lightClient = lightClient

proc startLightClient*(node: BeaconNode) =
  if not node.config.lightClientEnable:
    return

  node.lightClient.start()

proc installLightClientMessageValidators*(node: BeaconNode) =
  let eth2Processor =
    if node.config.lightClientDataServe:
      # Process gossip using both full node and light client
      node.processor
    elif node.config.lightClientEnable:
      # Only process gossip using light client
      nil
    else:
      # Light client topics will never be subscribed to, no validators needed
      return

  node.lightClient.installMessageValidators(eth2Processor)

proc updateLightClientGossipStatus*(
    node: BeaconNode, slot: Slot, dagIsBehind: bool) =
  let isBehind =
    if node.config.lightClientDataServe:
      # Forward DAG's readiness to handle light client gossip
      dagIsBehind
    else:
      # Full node is not interested in gossip
      true

  node.lightClient.updateGossipStatus(slot, some isBehind)

proc updateLightClientFromDag*(node: BeaconNode) =
  if not node.config.lightClientEnable:
    return
  if node.config.lightClientTrustedBlockRoot.isSome:
    return

  let
    dagHead = node.dag.finalizedHead
    dagPeriod = dagHead.slot.sync_committee_period
  if dagHead.slot < node.dag.cfg.ALTAIR_FORK_EPOCH.start_slot:
    return

  let lcHeader = node.lightClient.finalizedHeader
  if lcHeader.isSome:
    if dagPeriod <= lcHeader.get.slot.sync_committee_period:
      return

  let
    bdata = node.dag.getForkedBlock(dagHead.blck.bid).valueOr:
      return
    header = bdata.toBeaconBlockHeader
    current_sync_committee = block:
      var tmpState = assignClone(node.dag.headState)
      node.dag.currentSyncCommitteeForPeriod(tmpState[], dagPeriod).valueOr:
        return
  node.lightClient.resetToFinalizedHeader(header, current_sync_committee)
