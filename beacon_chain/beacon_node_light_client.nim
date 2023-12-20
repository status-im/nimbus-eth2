# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronicles, web3/engine_api_types, ./beacon_node

logScope:
  topics = "beacnde"

func shouldSyncOptimistically*(node: BeaconNode, wallSlot: Slot): bool =
  let optimisticHeader = node.lightClient.optimisticHeader
  withForkyHeader(optimisticHeader):
    when lcDataFork > LightClientDataFork.None:
      shouldSyncOptimistically(
        optimisticSlot = forkyHeader.beacon.slot,
        dagSlot = getStateField(node.dag.headState, slot),
        wallSlot = wallSlot,
      )
    else:
      false

proc initLightClient*(
    node: BeaconNode,
    rng: ref HmacDrbgContext,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest,
) =
  template config(): auto =
    node.config

  # Creating a light client is not dependent on `syncLightClient`
  # because the light client module also handles gossip subscriptions
  # for broadcasting light client data as a server.

  let
    optimisticHandler = proc(
        signedBlock: ForkedMsgTrustedSignedBeaconBlock
    ): Future[void] {.async.} =
      debug "New LC optimistic block",
        opt = signedBlock.toBlockId(),
        dag = node.dag.head.bid,
        wallSlot = node.currentSlot
      withBlck(signedBlock):
        when consensusFork >= ConsensusFork.Bellatrix:
          if forkyBlck.message.is_execution_block:
            template blckPayload(): auto =
              forkyBlck.message.body.execution_payload

            if not blckPayload.block_hash.isZero:
              # engine_newPayloadV1
              discard await node.elManager.newExecutionPayload(forkyBlck.message)

              # Retain optimistic head for other `forkchoiceUpdated` callers.
              # May temporarily block `forkchoiceUpdatedV1` calls, e.g., Geth:
              # - Refuses `newPayload`: "Ignoring payload while snap syncing"
              # - Refuses `fcU`: "Forkchoice requested unknown head"
              # Once DAG sync catches up or as new optimistic heads are fetched
              # the situation recovers
              node.consensusManager[].setOptimisticHead(
                forkyBlck.toBlockId(), blckPayload.block_hash
              )

              # engine_forkchoiceUpdatedV1 or engine_forkchoiceUpdatedV2,
              # depending on pre or post-Shapella
              let beaconHead = node.attestationPool[].getBeaconHead(nil)

              template callForkchoiceUpdated(attributes: untyped) =
                discard await node.elManager.forkchoiceUpdated(
                  headBlockHash = blckPayload.block_hash,
                  safeBlockHash = beaconHead.safeExecutionPayloadHash,
                  finalizedBlockHash = beaconHead.finalizedExecutionPayloadHash,
                  payloadAttributes = none attributes,
                )

              case node.dag.cfg.consensusForkAtEpoch(forkyBlck.message.slot.epoch)
              of ConsensusFork.Deneb:
                callForkchoiceUpdated(PayloadAttributesV3)
              of ConsensusFork.Capella:
                # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/shanghai.md#specification-1
                # Consensus layer client MUST call this method instead of
                # `engine_forkchoiceUpdatedV1` under any of the following
                # conditions:
                # `headBlockHash` references a block which `timestamp` is
                # greater or equal to the Shanghai timestamp
                callForkchoiceUpdated(PayloadAttributesV2)
              of ConsensusFork.Bellatrix:
                callForkchoiceUpdated(PayloadAttributesV1)
              of ConsensusFork.Phase0, ConsensusFork.Altair:
                discard
          else:
            discard

    optimisticProcessor = initOptimisticProcessor(getBeaconTime, optimisticHandler)

    lightClient = createLightClient(
      node.network, rng, config, cfg, forkDigests, getBeaconTime,
      genesis_validators_root, LightClientFinalizationMode.Strict,
    )

  if config.syncLightClient:
    proc onOptimisticHeader(
        lightClient: LightClient, optimisticHeader: ForkedLightClientHeader
    ) =
      withForkyHeader(optimisticHeader):
        when lcDataFork > LightClientDataFork.None:
          optimisticProcessor.setOptimisticHeader(forkyHeader.beacon)

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

proc updateLightClientGossipStatus*(node: BeaconNode, slot: Slot, dagIsBehind: bool) =
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
      header = ForkedLightClientHeader.init(forkyBlck.toLightClientHeader(lcDataFork))
    else:
      raiseAssert "Unreachable"
  let current_sync_committee = block:
    let tmpState = assignClone(node.dag.headState)
    node.dag.currentSyncCommitteeForPeriod(tmpState[], dagPeriod).valueOr:
      return
  node.lightClient.resetToFinalizedHeader(header, current_sync_committee)
