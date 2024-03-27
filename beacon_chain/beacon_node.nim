# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Everything needed to run a full Beacon Node

import
  std/osproc,

  # Nimble packages
  chronos, presto, bearssl/rand,

  # Local modules
  "."/[beacon_clock, beacon_chain_db, conf, light_client],
  ./gossip_processing/[eth2_processor, block_processor, optimistic_processor],
  ./networking/eth2_network,
  ./el/el_manager,
  ./consensus_object_pools/[
    blockchain_dag, blob_quarantine, block_quarantine, consensus_manager,
    attestation_pool, sync_committee_msg_pool, validator_change_pool],
  ./spec/datatypes/[base, altair],
  ./spec/eth2_apis/dynamic_fee_recipients,
  ./sync/[branch_discovery, sync_manager, request_manager],
  ./validators/[
    action_tracker, message_router, validator_monitor, validator_pool,
    keystore_management],
  ./rpc/state_ttl_cache

export
  osproc, chronos, presto, action_tracker,
  beacon_clock, beacon_chain_db, conf, light_client,
  attestation_pool, sync_committee_msg_pool, validator_change_pool,
  eth2_network, el_manager, branch_discovery, request_manager, sync_manager,
  eth2_processor, optimistic_processor, blockchain_dag, block_quarantine,
  base, message_router, validator_monitor, validator_pool,
  consensus_manager, dynamic_fee_recipients

type
  EventBus* = object
    headQueue*: AsyncEventQueue[HeadChangeInfoObject]
    blocksQueue*: AsyncEventQueue[EventBeaconBlockObject]
    attestQueue*: AsyncEventQueue[Attestation]
    exitQueue*: AsyncEventQueue[SignedVoluntaryExit]
    blsToExecQueue*: AsyncEventQueue[SignedBLSToExecutionChange]
    propSlashQueue*: AsyncEventQueue[ProposerSlashing]
    attSlashQueue*: AsyncEventQueue[AttesterSlashing]
    blobSidecarQueue*: AsyncEventQueue[BlobSidecarInfoObject]
    finalQueue*: AsyncEventQueue[FinalizationInfoObject]
    reorgQueue*: AsyncEventQueue[ReorgInfoObject]
    contribQueue*: AsyncEventQueue[SignedContributionAndProof]
    finUpdateQueue*: AsyncEventQueue[
      RestVersioned[ForkedLightClientFinalityUpdate]]
    optUpdateQueue*: AsyncEventQueue[
      RestVersioned[ForkedLightClientOptimisticUpdate]]

  BeaconNode* = ref object
    nickname*: string
    graffitiBytes*: GraffitiBytes
    network*: Eth2Node
    netKeys*: NetKeyPair
    db*: BeaconChainDB
    config*: BeaconNodeConf
    attachedValidators*: ref ValidatorPool
    optimisticProcessor*: OptimisticProcessor
    lightClient*: LightClient
    dag*: ChainDAGRef
    quarantine*: ref Quarantine
    blobQuarantine*: ref BlobQuarantine
    attestationPool*: ref AttestationPool
    syncCommitteeMsgPool*: ref SyncCommitteeMsgPool
    lightClientPool*: ref LightClientPool
    validatorChangePool*: ref ValidatorChangePool
    elManager*: ELManager
    restServer*: RestServerRef
    keymanagerHost*: ref KeymanagerHost
    keymanagerServer*: RestServerRef
    keystoreCache*: KeystoreCacheRef
    eventBus*: EventBus
    vcProcess*: Process
    requestManager*: RequestManager
    syncManager*: SyncManager[Peer, PeerId]
    backfiller*: SyncManager[Peer, PeerId]
    branchDiscovery*: ref BranchDiscovery[Peer, PeerId]
    genesisSnapshotContent*: string
    processor*: ref Eth2Processor
    blockProcessor*: ref BlockProcessor
    consensusManager*: ref ConsensusManager
    attachedValidatorBalanceTotal*: Gwei
    gossipState*: GossipState
    blocksGossipState*: GossipState
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

# TODO stew/sequtils2
template findIt*(s: openArray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

template rng*(node: BeaconNode): ref HmacDrbgContext =
  node.network.rng

proc currentSlot*(node: BeaconNode): Slot =
  node.beaconClock.now.slotOrZero

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
  let res = RestClientRef.new(payloadBuilderAddress.get)
  if res.isOk and res.get.isNil:
    err "Got nil payload builder REST client reference"
  else:
    res
