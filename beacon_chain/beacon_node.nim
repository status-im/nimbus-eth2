# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Everything needed to run a full Beacon Node

import
  std/[osproc, sets],

  # Nimble packages
  chronos, presto,
  metrics, metrics/chronos_httpserver,

  # Local modules
  ./[beacon_clock, beacon_chain_db, conf, light_client, version],
  ./gossip_processing/[
    eth2_processor, block_processor, block_processor_light_client],
  ./networking/eth2_network,
  ./el/[el_manager, el_getblobs_service],
  ./consensus_object_pools/[
    blockchain_dag, block_quarantine, column_quarantine, consensus_manager,
    attestation_pool, execution_payload_pool, payload_attestation_pool,
    sync_committee_msg_pool, validator_change_pool,
    blockchain_list],
  ./spec/datatypes/[base, altair],
  ./spec/eth2_apis/dynamic_fee_recipients,
  ./spec/signatures_batch,
  ./sync/[sync_manager, request_manager, sync_types, validator_custody],
  ./validators/[
    action_tracker, message_router, validator_monitor, validator_pool,
    keystore_management],
  ./rpc/state_ttl_cache

export
  osproc, chronos, presto, action_tracker,
  beacon_clock, beacon_chain_db, conf, light_client,
  attestation_pool, sync_committee_msg_pool, validator_change_pool,
  eth2_network, el_manager, request_manager, sync_manager, eth2_processor,
  block_processor_light_client, blockchain_dag, block_quarantine,
  base, message_router, validator_monitor, validator_pool,
  consensus_manager, dynamic_fee_recipients, sync_types

type
  EventBus* = object
    headQueue*: AsyncEventQueue[HeadChangeInfoObject]
    blocksQueue*: AsyncEventQueue[EventBeaconBlockObject]
    blockGossipQueue*: AsyncEventQueue[EventBeaconBlockGossipObject]
    blockGossipPeerQueue*: AsyncEventQueue[EventBeaconBlockGossipPeerObject]
    singleAttestQueue*: AsyncEventQueue[SingleAttestation]
    exitQueue*: AsyncEventQueue[SignedVoluntaryExit]
    blsToExecQueue*: AsyncEventQueue[SignedBLSToExecutionChange]
    propSlashQueue*: AsyncEventQueue[ProposerSlashing]
    attSlashQueue*: AsyncEventQueue[electra.AttesterSlashing]
    blobSidecarQueue*: AsyncEventQueue[BlobSidecarInfoObject]
    columnSidecarQueue*: AsyncEventQueue[DataColumnSidecarInfoObject]
    columnSidecarFullQueue*: AsyncEventQueue[ref fulu.DataColumnSidecar]
    finalQueue*: AsyncEventQueue[FinalizationInfoObject]
    fastConfirmationQueue*: AsyncEventQueue[FastConfirmationInfoObject]
    reorgQueue*: AsyncEventQueue[ReorgInfoObject]
    contribQueue*: AsyncEventQueue[SignedContributionAndProof]
    finUpdateQueue*: AsyncEventQueue[
      RestVersioned[ForkedLightClientFinalityUpdate]]
    optUpdateQueue*: AsyncEventQueue[
      RestVersioned[ForkedLightClientOptimisticUpdate]]
    optFinHeaderUpdateQueue*: AsyncEventQueue[ForkedLightClientHeader]
    execPayloadAddedQueue*: AsyncEventQueue[EventExecutionPayloadObject]
    execPayloadGossipAddedQueue*: AsyncEventQueue[EventExecutionPayloadGossipObject]
    execPayloadAvlQueue*: AsyncEventQueue[EventExecutionPayloadAvailableObject]
    execPayloadBidQueue*: AsyncEventQueue[gloas.SignedExecutionPayloadBid]
    payloadAttMsgQueue*: AsyncEventQueue[PayloadAttestationMessage]

  BeaconNode* = ref object
    nickname*: string
    network*: Eth2Node
    netKeys*: NetKeyPair
    db*: BeaconChainDB
    config*: BeaconNodeConf
    attachedValidators*: ref ValidatorPool
    lightBlockProcessor*: LightBlockProcessor
    lightClientFcuFut*: Future[(PayloadExecutionStatus, Opt[Hash32])]
      .Raising([CancelledError])
    lightClient*: LightClient
    dag*: ChainDAGRef
    list*: ChainListRef
    quarantine*: ref Quarantine
    dataColumnQuarantine*: ref ColumnQuarantine
    getBlobsService*: GetBlobsServiceRef
    attestationPool*: ref AttestationPool
    syncCommitteeMsgPool*: ref SyncCommitteeMsgPool
    lightClientPool*: ref LightClientPool
    validatorChangePool*: ref ValidatorChangePool
    executionPayloadBidPool*: ref ExecutionPayloadBidPool
    payloadAttestationPool*: ref PayloadAttestationPool
    elManager*: ELManager
    restServer*: RestServerRef
    keymanagerHost*: ref KeymanagerHost
    metricsServer*: Opt[MetricsHttpServerRef]
    keymanagerServer*: RestServerRef
    keystoreCache*: KeystoreCacheRef
    eventBus*: EventBus
    requestManager*: RequestManager
    validatorCustody*: ValidatorCustodyRef
    syncManager*: SyncManager[Peer, PeerId]
    backfiller*: SyncManager[Peer, PeerId]
    untrustedManager*: SyncManager[Peer, PeerId]
    syncOverseer*: SyncOverseerRef
    processor*: ref Eth2Processor
    batchVerifier*: ref BatchVerifier
    blockProcessor*: ref BlockProcessor
    consensusManager*: ref ConsensusManager
    attachedValidatorBalanceTotal*: Gwei
    gossipState*: GossipState
    blocksGossipState*: GossipState
    envelopeGossipState*: GossipState
    beaconClock*: BeaconClock
    restKeysCache*: Table[ValidatorPubKey, ValidatorIndex]
    validatorMonitor*: ref ValidatorMonitor
    stateTtlCache*: StateTtlCache
    router*: ref MessageRouter
    dynamicFeeRecipientsStore*: ref DynamicFeeRecipientsStore
    externalBuilderRegistrations*:
      Table[ValidatorPubKey, SignedValidatorRegistrationV1]
    dutyValidatorCount*: int
      ## Number of validators that we've checked for activation
    processingDelay*: Opt[Duration]
    lastValidAttestedBlock*: Opt[BlockSlot]
    lastColumnCustodyIndices*: seq[CustodyIndex]
    sentProposerPreferences*: array[2, HashSet[(uint64, Slot)]]
    shutdownEvent*: AsyncEvent

# TODO https://github.com/status-im/nim-stew/pull/258
template findIt*(s: openArray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

proc currentSlot*(node: BeaconNode): Slot =
  node.beaconClock.currentSlot

func hasRestAllowedOrigin*(node: BeaconNode): bool =
  node.config.restAllowedOrigin.isSome

func getPayloadBuilderAddress*(config: BeaconNodeConf): Opt[string] =
  if config.payloadBuilderEnable:
    Opt.some config.payloadBuilderUrl
  else:
    Opt.none(string)

proc getPayloadBuilderAddress*(
    node: BeaconNode, pubkey: ValidatorPubKey): Opt[string] =
  let defaultPayloadBuilderAddress = node.config.getPayloadBuilderAddress
  if node.keymanagerHost.isNil:
    defaultPayloadBuilderAddress
  else:
    node.keymanagerHost[].getBuilderConfig(pubkey).valueOr:
      defaultPayloadBuilderAddress

proc getPayloadBuilderClient*(
    node: BeaconNode, validator_index: uint64): RestResult[RestClientRef] =
  if not node.config.payloadBuilderEnable:
    return err "Payload builder globally disabled"

  let
    pubkey = withState(node.dag.headState):
      if validator_index >= forkyState.data.validators.lenu64:
        return err "Validator index too high"
      forkyState.data.validators.item(validator_index).pubkey
    payloadBuilderAddress = node.getPayloadBuilderAddress(pubkey)

  if payloadBuilderAddress.isNone:
    return err "Payload builder disabled"

  let
    flags = {RestClientFlag.CommaSeparatedArray,
             RestClientFlag.ResolveAlways}
    socketFlags = {SocketFlags.TcpNoDelay}

  RestClientRef.new(payloadBuilderAddress.get, flags = flags,
                    socketFlags = socketFlags,
                    userAgent = nimbusAgentStr)

func init*(T: type EventBus): T =
  T(
    headQueue:
      newAsyncEventQueue[HeadChangeInfoObject](),
    blocksQueue:
      newAsyncEventQueue[EventBeaconBlockObject](),
    blockGossipQueue:
      newAsyncEventQueue[EventBeaconBlockGossipObject](),
    blockGossipPeerQueue:
      newAsyncEventQueue[EventBeaconBlockGossipPeerObject](),
    singleAttestQueue:
      newAsyncEventQueue[SingleAttestation](),
    exitQueue:
      newAsyncEventQueue[SignedVoluntaryExit](),
    blsToExecQueue:
      newAsyncEventQueue[SignedBLSToExecutionChange](),
    propSlashQueue:
      newAsyncEventQueue[ProposerSlashing](),
    attSlashQueue:
      newAsyncEventQueue[electra.AttesterSlashing](),
    blobSidecarQueue:
      newAsyncEventQueue[BlobSidecarInfoObject](),
    columnSidecarQueue:
      newAsyncEventQueue[DataColumnSidecarInfoObject](),
    columnSidecarFullQueue:
      newAsyncEventQueue[ref fulu.DataColumnSidecar](),
    finalQueue:
      newAsyncEventQueue[FinalizationInfoObject](),
    fastConfirmationQueue:
      newAsyncEventQueue[FastConfirmationInfoObject](),
    reorgQueue:
      newAsyncEventQueue[ReorgInfoObject](),
    contribQueue:
      newAsyncEventQueue[SignedContributionAndProof](),
    finUpdateQueue:
      newAsyncEventQueue[RestVersioned[ForkedLightClientFinalityUpdate]](),
    optUpdateQueue:
      newAsyncEventQueue[RestVersioned[ForkedLightClientOptimisticUpdate]](),
    optFinHeaderUpdateQueue:
      newAsyncEventQueue[ForkedLightClientHeader](),
    execPayloadAddedQueue:
      newAsyncEventQueue[EventExecutionPayloadObject](),
    execPayloadGossipAddedQueue:
      newAsyncEventQueue[EventExecutionPayloadGossipObject](),
    execPayloadAvlQueue:
      newAsyncEventQueue[EventExecutionPayloadAvailableObject](),
    execPayloadBidQueue:
      newAsyncEventQueue[gloas.SignedExecutionPayloadBid](),
    payloadAttMsgQueue:
      newAsyncEventQueue[PayloadAttestationMessage](),
  )
