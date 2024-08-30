# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, web3/engine_api_types,
  ./beacon_node

logScope: topics = "beacnde"

func shouldSyncOptimistically*(node: BeaconNode, wallSlot: Slot): bool =
  let optimisticHeader = node.lightClient.optimisticHeader
  withForkyHeader(optimisticHeader):
    when lcDataFork > LightClientDataFork.None:
      shouldSyncOptimistically(
        optimisticSlot = forkyHeader.beacon.slot,
        dagSlot = getStateField(node.dag.headState, slot),
        wallSlot = wallSlot)
    else:
      false

proc initLightClient*(
    node: BeaconNode,
    rng: ref HmacDrbgContext,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest) =
  template config(): auto = node.config

  # Creating a light client is not dependent on `syncLightClient`
  # because the light client module also handles gossip subscriptions
  # for broadcasting light client data as a server.

  let
    optimisticHandler = proc(
        signedBlock: ForkedSignedBeaconBlock
    ): Future[void] {.async: (raises: [CancelledError]).} =
      withBlck(signedBlock):
        when consensusFork >= ConsensusFork.Bellatrix:
          if forkyBlck.message.is_execution_block:
            template payload(): auto = forkyBlck.message.body.execution_payload
            if not payload.block_hash.isZero:
              discard await node.elManager.newExecutionPayload(
                forkyBlck.message)
          else: discard
    optimisticProcessor = initOptimisticProcessor(
      getBeaconTime, optimisticHandler)

    shouldInhibitSync = func(): bool =
      if node.syncManager != nil:
        not node.syncManager.inProgress  # No LC sync needed if DAG is in sync
      else:
        false
    lightClient = createLightClient(
      node.network, rng, config, cfg, forkDigests, getBeaconTime,
      genesis_validators_root, LightClientFinalizationMode.Strict,
      shouldInhibitSync = shouldInhibitSync)

  if config.syncLightClient:
    proc onOptimisticHeader(
        lightClient: LightClient,
        optimisticHeader: ForkedLightClientHeader) =
      if node.optimisticFcuFut != nil:
        return
      withForkyHeader(optimisticHeader):
        when lcDataFork > LightClientDataFork.None:
          let bid = forkyHeader.beacon.toBlockId()
          logScope:
            opt = bid
            dag = node.dag.head.bid
            wallSlot = node.currentSlot
          when lcDataFork >= LightClientDataFork.Capella:
            let
              consensusFork = node.dag.cfg.consensusForkAtEpoch(bid.slot.epoch)
              blockHash = forkyHeader.execution.block_hash

            # Retain optimistic head for other `forkchoiceUpdated` callers.
            # May temporarily block `forkchoiceUpdated` calls, e.g., Geth:
            # - Refuses `newPayload`: "Ignoring payload while snap syncing"
            # - Refuses `fcU`: "Forkchoice requested unknown head"
            # Once DAG sync catches up or as new optimistic heads are fetched
            # the situation recovers
            debug "New LC optimistic header"
            node.consensusManager[].setOptimisticHead(bid, blockHash)
            if not node.consensusManager[]
                .shouldSyncOptimistically(node.currentSlot):
              return

            # engine_forkchoiceUpdated
            let beaconHead = node.attestationPool[].getBeaconHead(nil)
            withConsensusFork(consensusFork):
              when lcDataForkAtConsensusFork(consensusFork) == lcDataFork:
                node.optimisticFcuFut = node.elManager.forkchoiceUpdated(
                  headBlockHash = blockHash,
                  safeBlockHash = beaconHead.safeExecutionBlockHash,
                  finalizedBlockHash = beaconHead.finalizedExecutionBlockHash,
                  payloadAttributes = Opt.none consensusFork.PayloadAttributes)
                node.optimisticFcuFut.addCallback do (future: pointer):
                  node.optimisticFcuFut = nil
          else:
            # The execution block hash is only available from Capella onward
            info "Ignoring new LC optimistic header until Capella"

    lightClient.onOptimisticHeader = onOptimisticHeader
    lightClient.trustedBlockRoot = config.trustedBlockRoot

  elif config.trustedBlockRoot.isSome:
    warn "Ignoring `trustedBlockRoot`, light client not enabled",
      syncLightClient = config.syncLightClient,
      trustedBlockRoot = config.trustedBlockRoot

  node.optimisticProcessor = optimisticProcessor
  node.lightClient = lightClient

proc startLightClient*(node: BeaconNode) =
  if not node.config.syncLightClient:
    return

  node.lightClient.start()

proc stopLightClient*(node: BeaconNode) {.async: (raises: []).} =
  if not node.config.syncLightClient:
    return

  await node.lightClient.stop()

proc installLightClientMessageValidators*(node: BeaconNode) =
  let eth2Processor =
    if node.config.lightClientDataServe:
      # Process gossip using both full node and light client
      node.processor
    elif node.config.syncLightClient:
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
  if not node.config.syncLightClient:
    return
  if node.config.trustedBlockRoot.isSome:
    return

  let
    dagHead = node.dag.finalizedHead
    dagPeriod = dagHead.slot.sync_committee_period
  if dagHead.slot < node.dag.cfg.ALTAIR_FORK_EPOCH.start_slot:
    return

  let lcHeader = node.lightClient.finalizedHeader
  withForkyHeader(lcHeader):
    when lcDataFork > LightClientDataFork.None:
      if dagPeriod <= forkyHeader.beacon.slot.sync_committee_period:
        return

  let bdata = node.dag.getForkedBlock(dagHead.blck.bid).valueOr:
    return
  var header {.noinit.}: ForkedLightClientHeader
  withBlck(bdata):
    const lcDataFork = lcDataForkAtConsensusFork(consensusFork)
    when lcDataFork > LightClientDataFork.None:
      header = ForkedLightClientHeader.init(
        forkyBlck.toLightClientHeader(lcDataFork))
    else: raiseAssert "Unreachable"
  let current_sync_committee = block:
    let tmpState = assignClone(node.dag.headState)
    node.dag.currentSyncCommitteeForPeriod(tmpState[], dagPeriod).valueOr:
      return
  node.lightClient.resetToFinalizedHeader(header, current_sync_committee)
