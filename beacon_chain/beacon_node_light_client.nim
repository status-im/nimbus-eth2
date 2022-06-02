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
  ./beacon_node

logScope: topics = "beacnde"

proc initLightClient*(
    node: BeaconNode,
    rng: ref BrHmacDrbgContext,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest) =
  template config(): auto = node.config

  let lightClient = createLightClient(
    node.network, rng, config, cfg,
    forkDigests, getBeaconTime, genesis_validators_root)

  if config.lightClientEnable.get:
    lightClient.trustedBlockRoot = config.lightClientTrustedBlockRoot

  elif config.lightClientTrustedBlockRoot.isSome:
    warn "Ignoring `lightClientTrustedBlockRoot`, light client not enabled",
      lightClientEnable = config.lightClientEnable.get,
      lightClientTrustedBlockRoot = config.lightClientTrustedBlockRoot

  node.lightClient = lightClient

proc startLightClient*(node: BeaconNode) =
  if not node.config.lightClientEnable.get:
    return

  node.lightClient.start()

proc installLightClientMessageValidators*(node: BeaconNode) =
  let eth2Processor =
    if node.config.serveLightClientData.get:
      # Process gossip using both full node and light client
      node.processor
    elif node.config.lightClientEnable.get:
      # Only process gossip using light client
      nil
    else:
      # Light client topics will never be subscribed to, no validators needed
      return

  node.lightClient.installMessageValidators(eth2Processor)

proc updateLightClientGossipStatus*(
    node: BeaconNode, slot: Slot, dagIsBehind: bool) =
  let isBehind =
    if node.config.serveLightClientData.get:
      # Forward DAG's readiness to handle light client gossip
      dagIsBehind
    else:
      # Full node is not interested in gossip
      true

  node.lightClient.updateGossipStatus(slot, some isBehind)

proc updateLightClientFromDag*(node: BeaconNode) =
  if not node.config.lightClientEnable.get:
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
