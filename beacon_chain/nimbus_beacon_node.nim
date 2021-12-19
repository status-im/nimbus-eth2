# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/[math, os, osproc, random, sequtils, strformat, strutils,
       tables, times, terminal],

  # Nimble packages
  stew/io2,
  spec/eth2_apis/eth2_rest_serialization,
  stew/[objects, byteutils, endians2, io2], stew/shims/macros,
  chronos, confutils, metrics, metrics/chronos_httpserver,
  chronicles, bearssl, blscurve, presto,
  json_serialization/std/[options, sets, net], serialization/errors,
  taskpools,

  eth/keys, eth/net/nat,
  eth/p2p/discoveryv5/[protocol, enr, random2],

  # Local modules
  "."/[
    beacon_clock, beacon_chain_db, beacon_node, beacon_node_status,
    conf, filepath, interop, nimbus_binary_common, statusbar,
    version],
  ./networking/[eth2_discovery, eth2_network, network_metadata],
  ./gossip_processing/[eth2_processor, block_processor, consensus_manager],
  ./validators/[
    validator_duties, validator_pool,
    slashing_protection, keystore_management],
  ./sync/[sync_protocol],
  ./rpc/[rest_api, rpc_api],
  ./spec/datatypes/[altair, merge, phase0],
  ./spec/eth2_apis/rpc_beacon_client,
  ./spec/[
    beaconstate, forks, helpers, network, weak_subjectivity, signatures,
    validator],
  ./consensus_object_pools/[
    blockchain_dag, block_quarantine, block_clearance, attestation_pool,
    sync_committee_msg_pool, exit_pool, spec_cache],
  ./eth1/eth1_monitor

from eth/common/eth_types import BlockHashOrNumber

when defined(posix):
  import system/ansi_c

from
  libp2p/protocols/pubsub/gossipsub
import
  TopicParams, validateParameters, init

type
  RpcServer* = RpcHttpServer

template init(T: type RpcHttpServer, ip: ValidIpAddress, port: Port): T =
  newRpcHttpServer([initTAddress(ip, port)])

template init(T: type RestServerRef, ip: ValidIpAddress, port: Port): T =
  let address = initTAddress(ip, port)
  let serverFlags = {HttpServerFlags.QueryCommaSeparatedArray,
                     HttpServerFlags.NotifyDisconnect}
  # We increase default timeout to help validator clients who poll our server
  # at least once per slot (12.seconds).
  let
    headersTimeout = seconds(2'i64 * int64(SECONDS_PER_SLOT))
    maxHeadersSize = 65536 # 64 kilobytes
    maxRequestBodySize = 16_777_216 # 16 megabytes
  let res = RestServerRef.new(getRouter(), address, serverFlags = serverFlags,
                              httpHeadersTimeout = headersTimeout,
                              maxHeadersSize = maxHeadersSize,
                              maxRequestBodySize = maxRequestBodySize)
  if res.isErr():
    notice "Rest server could not be started", address = $address,
           reason = res.error()
    nil
  else:
    notice "Starting REST HTTP server",
      url = "http://" & $ip & ":" & $port & "/"

    res.get()

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#interop-metrics
declareGauge beacon_slot, "Latest slot of the beacon chain state"
declareGauge beacon_current_epoch, "Current epoch"

# Finalization tracking
declareGauge finalization_delay,
  "Epoch delay between scheduled epoch and finalized epoch"

declareGauge ticks_delay,
  "How long does to take to run the onSecond loop"

declareGauge next_action_wait,
  "Seconds until the next attestation will be sent"

declareGauge versionGauge, "Nimbus version info (as metric labels)", ["version", "commit"], name = "version"
versionGauge.set(1, labelValues=[fullVersionStr, gitRevision])

declareGauge network_name, "network name", ["name"]

logScope: topics = "beacnde"

const SlashingDbName = "slashing_protection"
  # changing this requires physical file rename as well or history is lost.

func getBeaconTimeFn(clock: BeaconClock): GetBeaconTimeFn =
  return proc(): BeaconTime = clock.now()

proc init*(T: type BeaconNode,
           cfg: RuntimeConfig,
           rng: ref BrHmacDrbgContext,
           config: BeaconNodeConf,
           depositContractDeployedAt: BlockHashOrNumber,
           eth1Network: Option[Eth1Network],
           genesisStateContents: string,
           genesisDepositsSnapshotContents: string): BeaconNode {.
    raises: [Defect, CatchableError].} =

  var taskpool: TaskpoolPtr

  try:
    if config.numThreads < 0:
      fatal "The number of threads --numThreads cannot be negative."
      quit 1
    elif config.numThreads == 0:
      taskpool = TaskpoolPtr.new()
    else:
      taskpool = TaskpoolPtr.new(numThreads = config.numThreads)

    info "Threadpool started", numThreads = taskpool.numThreads
  except Exception as exc:
    raise newException(Defect, "Failure in taskpool initialization.")

  let
    eventBus = newAsyncEventBus()
    db = BeaconChainDB.new(config.databaseDir, inMemory = false)

  var
    genesisState, checkpointState: ref ForkedHashedBeaconState
    checkpointBlock: ForkedTrustedSignedBeaconBlock

  proc onAttestationReceived(data: Attestation) =
    eventBus.emit("attestation-received", data)
  proc onAttestationSent(data: Attestation) =
    eventBus.emit("attestation-sent", data)
  proc onVoluntaryExitAdded(data: SignedVoluntaryExit) =
    eventBus.emit("voluntary-exit", data)
  proc onBlockAdded(data: ForkedTrustedSignedBeaconBlock) =
    eventBus.emit("signed-beacon-block", data)
  proc onHeadChanged(data: HeadChangeInfoObject) =
    eventBus.emit("head-change", data)
  proc onChainReorg(data: ReorgInfoObject) =
    eventBus.emit("chain-reorg", data)
  proc onFinalization(data: FinalizationInfoObject) =
    eventBus.emit("finalization", data)
  proc onSyncContribution(data: SignedContributionAndProof) =
    eventBus.emit("sync-contribution-and-proof", data)

  if config.finalizedCheckpointState.isSome:
    let checkpointStatePath = config.finalizedCheckpointState.get.string
    checkpointState = try:
      newClone(readSszForkedHashedBeaconState(
        cfg, readAllBytes(checkpointStatePath).tryGet()))
    except SszError as err:
      fatal "Checkpoint state deserialization failed",
            err = formatMsg(err, checkpointStatePath)
      quit 1
    except CatchableError as err:
      fatal "Failed to read checkpoint state file", err = err.msg
      quit 1

    if config.finalizedCheckpointBlock.isNone:
      if getStateField(checkpointState[], slot) > 0:
        fatal "Specifying a non-genesis --finalized-checkpoint-state requires specifying --finalized-checkpoint-block as well"
        quit 1
    else:
      let checkpointBlockPath = config.finalizedCheckpointBlock.get.string
      try:
        # Checkpoint block might come from an earlier fork than the state with
        # the state having empty slots processed past the fork epoch.
        checkpointBlock = readSszForkedTrustedSignedBeaconBlock(
          cfg, readAllBytes(checkpointBlockPath).tryGet())
      except SszError as err:
        fatal "Invalid checkpoint block", err = err.formatMsg(checkpointBlockPath)
        quit 1
      except IOError as err:
        fatal "Failed to load the checkpoint block", err = err.msg
        quit 1
  elif config.finalizedCheckpointBlock.isSome:
    # TODO We can download the state from somewhere in the future relying
    #      on the trusted `state_root` appearing in the checkpoint block.
    fatal "--finalized-checkpoint-block cannot be specified without --finalized-checkpoint-state"
    quit 1

  var eth1Monitor: Eth1Monitor
  if not ChainDAGRef.isInitialized(db):
    var
      tailState: ref ForkedHashedBeaconState
      tailBlock: ForkedTrustedSignedBeaconBlock

    if genesisStateContents.len == 0 and checkpointState == nil:
      when hasGenesisDetection:
        if genesisDepositsSnapshotContents != nil:
          fatal "A deposits snapshot cannot be provided without also providing a matching beacon state snapshot"
          quit 1

        # This is a fresh start without a known genesis state
        # (most likely, it hasn't arrived yet). We'll try to
        # obtain a genesis through the Eth1 deposits monitor:
        if config.web3Urls.len == 0:
          fatal "Web3 URL not specified"
          quit 1

        # TODO Could move this to a separate "GenesisMonitor" process or task
        #      that would do only this - see Paul's proposal for this.
        let eth1MonitorRes = waitFor Eth1Monitor.init(
          cfg,
          db,
          config.web3Urls,
          depositContractDeployedAt,
          eth1Network,
          config.web3ForcePolling)

        if eth1MonitorRes.isErr:
          fatal "Failed to start Eth1 monitor",
                reason = eth1MonitorRes.error,
                web3Urls = config.web3Urls,
                depositContractDeployedAt
          quit 1
        else:
          eth1Monitor = eth1MonitorRes.get

        genesisState = waitFor eth1Monitor.waitGenesis()
        if bnStatus == BeaconNodeStatus.Stopping:
          return nil

        tailState = genesisState
        tailBlock = get_initial_beacon_block(genesisState[])

        notice "Eth2 genesis state detected",
          genesisTime = genesisState.genesisTime,
          eth1Block = genesisState.eth1_data.block_hash,
          totalDeposits = genesisState.eth1_data.deposit_count
      else:
        fatal "No database and no genesis snapshot found: supply a genesis.ssz " &
              "with the network configuration, or compile the beacon node with " &
              "the -d:has_genesis_detection option " &
              "in order to support monitoring for genesis events"
        quit 1

    elif genesisStateContents.len == 0:
      if getStateField(checkpointState[], slot) == GENESIS_SLOT:
        genesisState = checkpointState
        tailState = checkpointState
        tailBlock = get_initial_beacon_block(genesisState[])
      else:
        fatal "State checkpoints cannot be provided for a network without a known genesis state"
        quit 1
    else:
      try:
        genesisState = newClone(readSszForkedHashedBeaconState(
          cfg,
          genesisStateContents.toOpenArrayByte(0, genesisStateContents.high())))
      except CatchableError as err:
        raiseAssert "Invalid baked-in state: " & err.msg

      if not checkpointState.isNil:
        tailState = checkpointState
        tailBlock = checkpointBlock
      else:
        tailState = genesisState
        tailBlock = get_initial_beacon_block(genesisState[])

    try:
      ChainDAGRef.preInit(db, genesisState[], tailState[], tailBlock)
      doAssert ChainDAGRef.isInitialized(db), "preInit should have initialized db"
    except CatchableError as exc:
      error "Failed to initialize database", err = exc.msg
      quit 1
  else:
    if not checkpointState.isNil:
      fatal "A database already exists, cannot start from given checkpoint",
        dataDir = config.dataDir
      quit 1

  # Doesn't use std/random directly, but dependencies might
  randomize(rng[].rand(high(int)))

  info "Loading block dag from database", path = config.databaseDir

  let
    chainDagFlags = if config.verifyFinalization: {verifyFinalization}
                     else: {}
    dag = ChainDAGRef.init(cfg, db, chainDagFlags, onBlockAdded, onHeadChanged,
                           onChainReorg, onFinalization)
    quarantine = newClone(Quarantine.init())
    databaseGenesisValidatorsRoot =
      getStateField(dag.headState.data, genesis_validators_root)

  if genesisStateContents.len != 0:
    let
      networkGenesisValidatorsRoot =
        extractGenesisValidatorRootFromSnapshot(genesisStateContents)

    if networkGenesisValidatorsRoot != databaseGenesisValidatorsRoot:
      fatal "The specified --data-dir contains data for a different network",
            networkGenesisValidatorsRoot, databaseGenesisValidatorsRoot,
            dataDir = config.dataDir
      quit 1

  let beaconClock = BeaconClock.init(
    getStateField(dag.headState.data, genesis_time))

  if config.weakSubjectivityCheckpoint.isSome:
    let
      currentSlot = beaconClock.now.slotOrZero
      isCheckpointStale = not is_within_weak_subjectivity_period(
        cfg,
        currentSlot,
        dag.headState.data,
        config.weakSubjectivityCheckpoint.get)

    if isCheckpointStale:
      error "Weak subjectivity checkpoint is stale",
            currentSlot,
            checkpoint = config.weakSubjectivityCheckpoint.get,
            headStateSlot = getStateField(dag.headState.data, slot)
      quit 1

  if eth1Monitor.isNil and
     config.web3Urls.len > 0 and
     genesisDepositsSnapshotContents.len > 0:
    let genesisDepositsSnapshot = SSZ.decode(genesisDepositsSnapshotContents,
                                             DepositContractSnapshot)
    eth1Monitor = Eth1Monitor.init(
      cfg,
      db,
      config.web3Urls,
      genesisDepositsSnapshot,
      eth1Network,
      config.web3ForcePolling)

  let rpcServer = if config.rpcEnabled:
    RpcServer.init(config.rpcAddress, config.rpcPort)
  else:
    nil

  let restServer = if config.restEnabled:
    RestServerRef.init(config.restAddress, config.restPort)
  else:
    nil

  let
    netKeys = getPersistentNetKeys(rng[], config)
    nickname = if config.nodeName == "auto": shortForm(netKeys)
               else: config.nodeName
    getBeaconTime = beaconClock.getBeaconTimeFn()
    network = createEth2Node(
      rng, config, netKeys, cfg, dag.forkDigests, getBeaconTime,
      getStateField(dag.headState.data, genesis_validators_root))
    attestationPool = newClone(
      AttestationPool.init(dag, quarantine, onAttestationReceived)
    )
    syncCommitteeMsgPool = newClone(
      SyncCommitteeMsgPool.init(onSyncContribution)
    )
    exitPool = newClone(ExitPool.init(dag, onVoluntaryExitAdded))

  case config.slashingDbKind
  of SlashingDbKind.v2:
    discard
  of SlashingDbKind.v1:
    error "Slashing DB v1 is no longer supported for writing"
    quit 1
  of SlashingDbKind.both:
    warn "Slashing DB v1 deprecated, writing only v2"

  info "Loading slashing protection database (v2)",
    path = config.validatorsDir()

  func getLocalHeadSlot(): Slot =
    dag.head.slot

  proc getLocalWallSlot(): Slot =
    beaconClock.now.slotOrZero

  func getFirstSlotAtFinalizedEpoch(): Slot =
    dag.finalizedHead.slot

  func getBackfillSlot(): Slot =
    dag.backfill.slot

  let
    slashingProtectionDB =
      SlashingProtectionDB.init(
          getStateField(dag.headState.data, genesis_validators_root),
          config.validatorsDir(), SlashingDbName)
    validatorPool = newClone(ValidatorPool.init(slashingProtectionDB))

    consensusManager = ConsensusManager.new(
      dag, attestationPool, quarantine
    )
    blockProcessor = BlockProcessor.new(
      config.dumpEnabled, config.dumpDirInvalid, config.dumpDirIncoming,
      rng, taskpool, consensusManager, getBeaconTime)
    blockVerifier = proc(signedBlock: ForkedSignedBeaconBlock):
        Future[Result[void, BlockError]] =
      # The design with a callback for block verification is unusual compared
      # to the rest of the application, but fits with the general approach
      # taken in the sync/request managers - this is an architectural compromise
      # that should probably be reimagined more holistically in the future.
      let resfut = newFuture[Result[void, BlockError]]("blockVerifier")
      blockProcessor[].addBlock(signedBlock, resfut)
      resfut
    processor = Eth2Processor.new(
      config.doppelgangerDetection,
      blockProcessor, dag, attestationPool, exitPool, validatorPool,
      syncCommitteeMsgPool, quarantine, rng, getBeaconTime, taskpool)
    syncManager = newSyncManager[Peer, PeerID](
      network.peerPool, SyncQueueKind.Forward, getLocalHeadSlot, getLocalWallSlot,
      getFirstSlotAtFinalizedEpoch, getBackfillSlot, blockVerifier)

  var node = BeaconNode(
    nickname: nickname,
    graffitiBytes: if config.graffiti.isSome: config.graffiti.get.GraffitiBytes
                   else: defaultGraffitiBytes(),
    network: network,
    netKeys: netKeys,
    db: db,
    config: config,
    attachedValidators: validatorPool,
    dag: dag,
    quarantine: quarantine,
    attestationPool: attestationPool,
    syncCommitteeMsgPool: syncCommitteeMsgPool,
    exitPool: exitPool,
    eth1Monitor: eth1Monitor,
    rpcServer: rpcServer,
    restServer: restServer,
    eventBus: eventBus,
    requestManager: RequestManager.init(network, blockVerifier),
    syncManager: syncManager,
    actionTracker: ActionTracker.init(rng, config.subscribeAllSubnets),
    processor: processor,
    blockProcessor: blockProcessor,
    consensusManager: consensusManager,
    gossipState: GossipState.Disconnected,
    beaconClock: beaconClock,
    onAttestationSent: onAttestationSent,
  )

  debug "Loading validators", validatorsDir = config.validatorsDir()

  node.addValidators()

  block:
    # Add in-process validators to the list of "known" validators such that
    # we start with a reasonable ENR
    let wallSlot = node.beaconClock.now().slotOrZero()
    for validator in node.attachedValidators[].validators.values():
      if validator.index.isSome():
        node.actionTracker.knownValidators[validator.index.get()] = wallSlot

    let
      stabilitySubnets = node.actionTracker.stabilitySubnets(wallSlot)
    # Here, we also set the correct ENR should we be in all subnets mode!
    node.network.updateStabilitySubnetMetadata(stabilitySubnets)

  network.initBeaconSync(dag, getBeaconTime)

  node.updateValidatorMetrics()

  return node

func verifyFinalization(node: BeaconNode, slot: Slot) =
  # Epoch must be >= 4 to check finalization
  const SETTLING_TIME_OFFSET = 1'u64
  let epoch = slot.compute_epoch_at_slot()

  # Don't static-assert this -- if this isn't called, don't require it
  doAssert SLOTS_PER_EPOCH > SETTLING_TIME_OFFSET

  # Intentionally, loudly assert. Point is to fail visibly and unignorably
  # during testing.
  if epoch >= 4 and slot mod SLOTS_PER_EPOCH > SETTLING_TIME_OFFSET:
    let finalizedEpoch =
      node.dag.finalizedHead.slot.compute_epoch_at_slot()
    # Finalization rule 234, that has the most lag slots among the cases, sets
    # state.finalized_checkpoint = old_previous_justified_checkpoint.epoch + 3
    # and then state.slot gets incremented, to increase the maximum offset, if
    # finalization occurs every slot, to 4 slots vs scheduledSlot.
    doAssert finalizedEpoch + 4 >= epoch

func subnetLog(v: BitArray): string =
  $toSeq(v.oneIndices())

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/validator.md#phase-0-attestation-subnet-stability
proc updateAttestationSubnetHandlers(node: BeaconNode, slot: Slot) =
  if node.gossipState == GossipState.Disconnected:
    # When disconnected, updateGossipState is responsible for all things
    # subnets - in particular, it will remove subscriptions on the edge where
    # we enter the disconnected state.
    return

  let
    aggregateSubnets = node.actionTracker.aggregateSubnets(slot)
    stabilitySubnets = node.actionTracker.stabilitySubnets(slot)
    subnets = aggregateSubnets + stabilitySubnets

  node.network.updateStabilitySubnetMetadata(stabilitySubnets)

  # Now we know what we should be subscribed to - make it so
  let
    prevSubnets = node.actionTracker.subscribedSubnets
    unsubscribeSubnets = prevSubnets - subnets
    subscribeSubnets = subnets - prevSubnets

  # Remember what we subscribed to, so we can unsubscribe later
  node.actionTracker.subscribedSubnets = subnets

  case node.gossipState
  of GossipState.Disconnected:
    raiseAssert "Checked above"
  of GossipState.ConnectedToPhase0:
    node.network.unsubscribeAttestationSubnets(unsubscribeSubnets, node.dag.forkDigests.phase0)
    node.network.subscribeAttestationSubnets(subscribeSubnets, node.dag.forkDigests.phase0)
  of GossipState.InTransitionToAltair:
    node.network.unsubscribeAttestationSubnets(unsubscribeSubnets, node.dag.forkDigests.phase0)
    node.network.unsubscribeAttestationSubnets(unsubscribeSubnets, node.dag.forkDigests.altair)
    node.network.subscribeAttestationSubnets(subscribeSubnets, node.dag.forkDigests.phase0)
    node.network.subscribeAttestationSubnets(subscribeSubnets, node.dag.forkDigests.altair)
  of GossipState.ConnectedToAltair:
    node.network.unsubscribeAttestationSubnets(unsubscribeSubnets, node.dag.forkDigests.altair)
    node.network.subscribeAttestationSubnets(subscribeSubnets, node.dag.forkDigests.altair)

  debug "Attestation subnets",
    slot, epoch = slot.epoch, gossipState = node.gossipState,
    stabilitySubnets = subnetLog(stabilitySubnets),
    aggregateSubnets = subnetLog(aggregateSubnets),
    prevSubnets = subnetLog(prevSubnets),
    subscribeSubnets = subnetLog(subscribeSubnets),
    unsubscribeSubnets = subnetLog(unsubscribeSubnets)

# inspired by lighthouse research here
# https://gist.github.com/blacktemplar/5c1862cb3f0e32a1a7fb0b25e79e6e2c#file-generate-scoring-params-py
const
  blocksTopicParams = TopicParams(
    topicWeight: 0.5,
    timeInMeshWeight: 0.03333333333333333,
    timeInMeshQuantum: chronos.seconds(12),
    timeInMeshCap: 300,
    firstMessageDeliveriesWeight: 1.1471603557060206,
    firstMessageDeliveriesDecay: 0.9928302477768374,
    firstMessageDeliveriesCap: 34.86870846001471,
    meshMessageDeliveriesWeight: -458.31054878249114,
    meshMessageDeliveriesDecay: 0.9716279515771061,
    meshMessageDeliveriesThreshold: 0.6849191409056553,
    meshMessageDeliveriesCap: 2.054757422716966,
    meshMessageDeliveriesActivation: chronos.seconds(384),
    meshMessageDeliveriesWindow: chronos.seconds(2),
    meshFailurePenaltyWeight: -458.31054878249114 ,
    meshFailurePenaltyDecay: 0.9716279515771061,
    invalidMessageDeliveriesWeight: -214.99999999999994,
    invalidMessageDeliveriesDecay: 0.9971259067705325
  )
  aggregateTopicParams = TopicParams(
    topicWeight: 0.5,
    timeInMeshWeight: 0.03333333333333333,
    timeInMeshQuantum: chronos.seconds(12),
    timeInMeshCap: 300,
    firstMessageDeliveriesWeight: 0.10764904539552399,
    firstMessageDeliveriesDecay: 0.8659643233600653,
    firstMessageDeliveriesCap: 371.5778421725158,
    meshMessageDeliveriesWeight: -0.07538533073670682,
    meshMessageDeliveriesDecay: 0.930572040929699,
    meshMessageDeliveriesThreshold: 53.404248450179836,
    meshMessageDeliveriesCap: 213.61699380071934,
    meshMessageDeliveriesActivation: chronos.seconds(384),
    meshMessageDeliveriesWindow: chronos.seconds(2),
    meshFailurePenaltyWeight: -0.07538533073670682 ,
    meshFailurePenaltyDecay: 0.930572040929699,
    invalidMessageDeliveriesWeight: -214.99999999999994,
    invalidMessageDeliveriesDecay: 0.9971259067705325
  )
  basicParams = TopicParams.init()

static:
  # compile time validation
  blocksTopicParams.validateParameters().tryGet()
  aggregateTopicParams.validateParameters().tryGet()
  basicParams.validateParameters.tryGet()

proc addPhase0MessageHandlers(node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.network.subscribe(getBeaconBlocksTopic(forkDigest), blocksTopicParams, enableTopicMetrics = true)
  node.network.subscribe(getAttesterSlashingsTopic(forkDigest), basicParams)
  node.network.subscribe(getProposerSlashingsTopic(forkDigest), basicParams)
  node.network.subscribe(getVoluntaryExitsTopic(forkDigest), basicParams)
  node.network.subscribe(getAggregateAndProofsTopic(forkDigest), aggregateTopicParams, enableTopicMetrics = true)

  # updateAttestationSubnetHandlers subscribes attestation subnets

proc addPhase0MessageHandlers(node: BeaconNode, slot: Slot) =
  addPhase0MessageHandlers(node, node.dag.forkDigests.phase0, slot)

proc removePhase0MessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  node.network.unsubscribe(getBeaconBlocksTopic(forkDigest))
  node.network.unsubscribe(getVoluntaryExitsTopic(forkDigest))
  node.network.unsubscribe(getProposerSlashingsTopic(forkDigest))
  node.network.unsubscribe(getAttesterSlashingsTopic(forkDigest))
  node.network.unsubscribe(getAggregateAndProofsTopic(forkDigest))

  for subnet_id in 0'u64 ..< ATTESTATION_SUBNET_COUNT:
    node.network.unsubscribe(
      getAttestationTopic(forkDigest, SubnetId(subnet_id)))

  node.actionTracker.subscribedSubnets = default(AttnetBits)

proc removePhase0MessageHandlers(node: BeaconNode) =
  removePhase0MessageHandlers(node, node.dag.forkDigests.phase0)

proc addAltairMessageHandlers(node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.addPhase0MessageHandlers(forkDigest, slot)

  var syncnets: SyncnetBits

  # TODO: What are the best topic params for this?
  for committeeIdx in allSyncSubcommittees():
    closureScope:
      let idx = committeeIdx
      # TODO This should be done in dynamic way in trackSyncCommitteeTopics
      node.network.subscribe(getSyncCommitteeTopic(forkDigest, idx), basicParams)
      syncnets.setBit(idx.asInt)

  node.network.subscribe(
    getSyncCommitteeContributionAndProofTopic(forkDigest), basicParams)
  node.network.updateSyncnetsMetadata(syncnets)

proc addAltairMessageHandlers(node: BeaconNode, slot: Slot) =
  addAltairMessageHandlers(node, node.dag.forkDigests.altair, slot)

proc removeAltairMessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  node.removePhase0MessageHandlers(forkDigest)

  for committeeIdx in allSyncSubcommittees():
    closureScope:
      let idx = committeeIdx
      # TODO This should be done in dynamic way in trackSyncCommitteeTopics
      node.network.unsubscribe(getSyncCommitteeTopic(forkDigest, idx))

  node.network.unsubscribe(
    getSyncCommitteeContributionAndProofTopic(forkDigest))

proc removeAltairMessageHandlers(node: BeaconNode) =
  removeAltairMessageHandlers(node, node.dag.forkDigests.altair)

proc addMergeMessageHandlers(node: BeaconNode, slot: Slot) =
  addAltairMessageHandlers(node, node.dag.forkDigests.merge, slot)

proc removeMergeMessageHandlers(node: BeaconNode) =
  removeAltairMessageHandlers(node, node.dag.forkDigests.merge)

proc removeAllMessageHandlers(node: BeaconNode) =
  node.removePhase0MessageHandlers()
  node.removeAltairMessageHandlers()
  node.removeMergeMessageHandlers()

proc setupDoppelgangerDetection(node: BeaconNode, slot: Slot) =
  # When another client's already running, this is very likely to detect
  # potential duplicate validators, which can trigger slashing.
  #
  # Every missed attestation costs approximately 3*get_base_reward(), which
  # can be up to around 10,000 Wei. Thus, skipping attestations isn't cheap
  # and one should gauge the likelihood of this simultaneous launch to tune
  # the epoch delay to one's perceived risk.
  const duplicateValidatorEpochs = 2

  node.processor.doppelgangerDetection.broadcastStartEpoch =
    slot.epoch + duplicateValidatorEpochs
  debug "Setting up doppelganger protection",
    epoch = slot.epoch,
    broadcastStartEpoch =
      node.processor.doppelgangerDetection.broadcastStartEpoch

proc trackSyncCommitteeTopics*(node: BeaconNode) =
  # TODO
  discard

proc updateGossipStatus(node: BeaconNode, slot: Slot) {.async.} =
  ## Subscribe to subnets that we are providing stability for or aggregating
  ## and unsubscribe from the ones that are no longer relevant.

  # Let the tracker know what duties are approaching - this will tell us how
  # many stability subnets we need to be subscribed to and what subnets we'll
  # soon be aggregating - in addition to the in-beacon-node duties, there may
  # also be duties coming from the validator client, but we don't control when
  # these arrive
  await node.registerDuties(slot)

  # We start subscribing to gossip before we're fully synced - this allows time
  # to subscribe before the sync end game
  const
    TOPIC_SUBSCRIBE_THRESHOLD_SLOTS = 64
    HYSTERESIS_BUFFER = 16

  let
    head = node.dag.head
    headDistance =
      if slot > head.slot: (slot - head.slot).uint64
      else: 0'u64
    targetGossipState =
      if headDistance > TOPIC_SUBSCRIBE_THRESHOLD_SLOTS + HYSTERESIS_BUFFER:
        GossipState.Disconnected
      elif slot.epoch + 1 < node.dag.cfg.ALTAIR_FORK_EPOCH:
        GossipState.ConnectedToPhase0
      elif slot.epoch >= node.dag.cfg.ALTAIR_FORK_EPOCH:
        GossipState.ConnectedToAltair
      else:
        GossipState.InTransitionToAltair

  if node.gossipState == GossipState.Disconnected and
     targetGossipState != GossipState.Disconnected:
    # We are synced, so we will connect
    debug "Enabling topic subscriptions",
      wallSlot = slot,
      headSlot = head.slot,
      headDistance, targetGossipState

    node.setupDoppelgangerDetection(slot)

    # Specially when waiting for genesis, we'll already be synced on startup -
    # it might also happen on a sufficiently fast restart

    # We "know" the actions for the current and the next epoch
    if node.isSynced(head):
      node.actionTracker.updateActions(
        node.dag.getEpochRef(head, slot.epoch))
      node.actionTracker.updateActions(
        node.dag.getEpochRef(head, slot.epoch + 1))

  case targetGossipState
  of GossipState.Disconnected:
    case node.gossipState:
    of GossipState.Disconnected: discard
    else:
      debug "Disabling topic subscriptions",
        wallSlot = slot,
        headSlot = head.slot,
        headDistance
      node.removeAllMessageHandlers()
      node.gossipState = GossipState.Disconnected

  of GossipState.ConnectedToPhase0:
    case node.gossipState:
    of GossipState.ConnectedToPhase0: discard
    of GossipState.Disconnected:
      node.addPhase0MessageHandlers(slot)
    of GossipState.InTransitionToAltair:
      warn "Unexpected clock regression during altair transition"
      node.removeAltairMessageHandlers()
    of GossipState.ConnectedToAltair:
      warn "Unexpected clock regression during altair transition"
      node.removeAltairMessageHandlers()
      node.addPhase0MessageHandlers(slot)

  of GossipState.InTransitionToAltair:
    case node.gossipState:
    of GossipState.InTransitionToAltair: discard
    of GossipState.Disconnected:
      node.addPhase0MessageHandlers(slot)
      node.addAltairMessageHandlers(slot)
    of GossipState.ConnectedToPhase0:
      node.addAltairMessageHandlers(slot)
    of GossipState.ConnectedToAltair:
      warn "Unexpected clock regression during altair transition"
      node.addPhase0MessageHandlers(slot)

  of GossipState.ConnectedToAltair:
    case node.gossipState:
    of GossipState.ConnectedToAltair: discard
    of GossipState.Disconnected:
      node.addAltairMessageHandlers(slot)
    of GossipState.ConnectedToPhase0:
      node.removePhase0MessageHandlers()
      node.addAltairMessageHandlers(slot)
    of GossipState.InTransitionToAltair:
      node.removePhase0MessageHandlers()

  node.gossipState = targetGossipState
  node.updateAttestationSubnetHandlers(slot)

proc onSlotEnd(node: BeaconNode, slot: Slot) {.async.} =
  # Things we do when slot processing has ended and we're about to wait for the
  # next slot

  if node.dag.needStateCachesAndForkChoicePruning():
    if node.attachedValidators.validators.len > 0:
      node.attachedValidators
          .slashingProtection
          # pruning is only done if the DB is set to pruning mode.
          .pruneAfterFinalization(
            node.dag.finalizedHead.slot.compute_epoch_at_slot()
          )

  # Delay part of pruning until latency critical duties are done.
  # The other part of pruning, `pruneBlocksDAG`, is done eagerly.
  # ----
  # This is the last pruning to do as it clears the "needPruning" condition.
  node.consensusManager[].pruneStateCachesAndForkChoice()

  when declared(GC_fullCollect):
    # The slots in the beacon node work as frames in a game: we want to make
    # sure that we're ready for the next one and don't get stuck in lengthy
    # garbage collection tasks when time is of essence in the middle of a slot -
    # while this does not guarantee that we'll never collect during a slot, it
    # makes sure that all the scratch space we used during slot tasks (logging,
    # temporary buffers etc) gets recycled for the next slot that is likely to
    # need similar amounts of memory.
    GC_fullCollect()

  # Checkpoint the database to clear the WAL file and make sure changes in
  # the database are synced with the filesystem.
  node.db.checkpoint()

  node.syncCommitteeMsgPool[].pruneData(slot)

  # Update upcoming actions - we do this every slot in case a reorg happens
  if node.isSynced(node.dag.head) and
      node.actionTracker.lastCalculatedEpoch < slot.epoch + 1:
    # TODO this is costly because we compute an EpochRef that likely will never
    #      be used for anything else, due to the epoch ancestor being selected
    #      pessimistically with respect to the shuffling - this needs fixing
    #      at EpochRef level by not mixing balances and shufflings in the same
    #      place
    let epochRef = node.dag.getEpochRef(node.dag.head, slot.epoch + 1)
    node.actionTracker.updateActions(epochRef)

  let
    nextAttestationSlot = getNextValidatorAction(
      node.actionTracker.attestingSlots,
      node.actionTracker.lastCalculatedEpoch, slot)
    nextProposalSlot = getNextValidatorAction(
      node.actionTracker.proposingSlots,
      node.actionTracker.lastCalculatedEpoch, slot)
    nextActionWaitTime = saturate(fromNow(
      node.beaconClock, min(nextAttestationSlot, nextProposalSlot)))

  # -1 is a more useful output than 18446744073709551615 as an indicator of
  # no future attestation/proposal known.
  template displayInt64(x: Slot): int64 =
    if x == high(uint64).Slot:
      -1'i64
    else:
      toGaugeValue(x)

  info "Slot end",
    slot = shortLog(slot),
    nextActionWait =
      if nextAttestationSlot == FAR_FUTURE_SLOT:
        "n/a"
      else:
        shortLog(nextActionWaitTime),
    nextAttestationSlot = displayInt64(nextAttestationSlot),
    nextProposalSlot = displayInt64(nextProposalSlot),
    head = shortLog(node.dag.head)

  if nextAttestationSlot != FAR_FUTURE_SLOT:
    next_action_wait.set(nextActionWaitTime.toFloatSeconds)

  let epoch = slot.epoch
  if epoch + 1 >= node.network.forkId.next_fork_epoch:
    # Update 1 epoch early to block non-fork-ready peers
    node.network.updateForkId(epoch, node.dag.genesisValidatorsRoot)

  # When we're not behind schedule, we'll speculatively update the clearance
  # state in anticipation of receiving the next block - we do it after logging
  # slot end since the nextActionWaitTime can be short
  let
    advanceCutoff = node.beaconClock.fromNow(
      slot.toBeaconTime(chronos.seconds(int(SECONDS_PER_SLOT - 1))))
  if advanceCutoff.inFuture:
    # We wait until there's only a second left before the next slot begins, then
    # we advance the clearance state to the next slot - this gives us a high
    # probability of being prepared for the block that will arrive and the
    # epoch processing that follows
    await sleepAsync(advanceCutoff.offset)
    node.dag.advanceClearanceState()

  # Prepare action tracker for the next slot
  node.actionTracker.updateSlot(slot + 1)

  # The last thing we do is to perform the subscriptions and unsubscriptions for
  # the next slot, just before that slot starts - because of the advance cuttoff
  # above, this will be done just before the next slot starts
  await node.updateGossipStatus(slot + 1)

proc onSlotStart(
    node: BeaconNode, wallTime: BeaconTime, lastSlot: Slot) {.async.} =
  ## Called at the beginning of a slot - usually every slot, but sometimes might
  ## skip a few in case we're running late.
  ## wallTime: current system time - we will strive to perform all duties up
  ##           to this point in time
  ## lastSlot: the last slot that we successfully processed, so we know where to
  ##           start work from - there might be jumps if processing is delayed
  let
    # The slot we should be at, according to the clock
    wallSlot = wallTime.slotOrZero
    # If everything was working perfectly, the slot that we should be processing
    expectedSlot = lastSlot + 1
    finalizedEpoch =
      node.dag.finalizedHead.blck.slot.compute_epoch_at_slot()
    delay = wallTime - expectedSlot.toBeaconTime()

  info "Slot start",
    slot = shortLog(wallSlot),
    epoch = shortLog(wallSlot.epoch),
    sync =
      if node.syncManager.inProgress: node.syncManager.syncStatus
      else: "synced",
    peers = len(node.network.peerPool),
    head = shortLog(node.dag.head),
    finalized = shortLog(getStateField(
      node.dag.headState.data, finalized_checkpoint)),
    delay = shortLog(delay)

  # Check before any re-scheduling of onSlotStart()
  checkIfShouldStopAtEpoch(wallSlot, node.config.stopAtEpoch)

  beacon_slot.set wallSlot.toGaugeValue
  beacon_current_epoch.set wallSlot.epoch.toGaugeValue

  # both non-negative, so difference can't overflow or underflow int64
  finalization_delay.set(
    wallSlot.epoch.toGaugeValue - finalizedEpoch.toGaugeValue)

  if node.config.verifyFinalization:
    verifyFinalization(node, wallSlot)

  node.consensusManager[].updateHead(wallSlot)

  await node.handleValidatorDuties(lastSlot, wallSlot)

  if node.eth1Monitor != nil and (wallSlot mod SLOTS_PER_EPOCH) == 0:
    let finalizedEpochRef = node.dag.getFinalizedEpochRef()
    discard node.eth1Monitor.trackFinalizedState(
      finalizedEpochRef.eth1_data, finalizedEpochRef.eth1_deposit_index)

  await onSlotEnd(node, wallSlot)

proc handleMissingBlocks(node: BeaconNode) =
  let missingBlocks = node.quarantine[].checkMissing()
  if missingBlocks.len > 0:
    debug "Requesting detected missing blocks", blocks = shortLog(missingBlocks)
    node.requestManager.fetchAncestorBlocks(missingBlocks)

proc onSecond(node: BeaconNode) =
  ## This procedure will be called once per second.
  if not(node.syncManager.inProgress):
    node.handleMissingBlocks()

proc runOnSecondLoop(node: BeaconNode) {.async.} =
  let sleepTime = chronos.seconds(1)
  const nanosecondsIn1s = float(chronos.seconds(1).nanoseconds)
  while true:
    let start = chronos.now(chronos.Moment)
    await chronos.sleepAsync(sleepTime)
    let afterSleep = chronos.now(chronos.Moment)
    let sleepTime = afterSleep - start
    node.onSecond()
    let finished = chronos.now(chronos.Moment)
    let processingTime = finished - afterSleep
    ticks_delay.set(sleepTime.nanoseconds.float / nanosecondsIn1s)
    trace "onSecond task completed", sleepTime, processingTime

func connectedPeersCount(node: BeaconNode): int =
  len(node.network.peerPool)

proc installRpcHandlers(rpcServer: RpcServer, node: BeaconNode) {.
    raises: [Defect, CatchableError].} =
  rpcServer.installBeaconApiHandlers(node)
  rpcServer.installConfigApiHandlers(node)
  rpcServer.installDebugApiHandlers(node)
  rpcServer.installEventApiHandlers(node)
  rpcServer.installNimbusApiHandlers(node)
  rpcServer.installNodeApiHandlers(node)
  rpcServer.installValidatorApiHandlers(node)

proc installRestHandlers(restServer: RestServerRef, node: BeaconNode) =
  restServer.router.installBeaconApiHandlers(node)
  restServer.router.installConfigApiHandlers(node)
  restServer.router.installDebugApiHandlers(node)
  restServer.router.installEventApiHandlers(node)
  restServer.router.installNimbusApiHandlers(node)
  restServer.router.installNodeApiHandlers(node)
  restServer.router.installValidatorApiHandlers(node)
  if node.config.validatorApiEnabled:
    restServer.router.installValidatorManagementHandlers(node)

proc installMessageValidators(node: BeaconNode) =
  # https://github.com/ethereum/consensus-specs/blob/v1.1.6/specs/phase0/p2p-interface.md#attestations-and-aggregation
  # These validators stay around the whole time, regardless of which specific
  # subnets are subscribed to during any given epoch.
  func toValidationResult(res: ValidationRes): ValidationResult =
    if res.isOk(): ValidationResult.Accept else: res.error()[0]

  node.network.addValidator(
    getBeaconBlocksTopic(node.dag.forkDigests.phase0),
    proc (signedBlock: phase0.SignedBeaconBlock): ValidationResult =
      toValidationResult(node.processor[].blockValidator(signedBlock)))

  template installPhase0Validators(digest: auto) =
    for it in 0'u64 ..< ATTESTATION_SUBNET_COUNT.uint64:
      closureScope:
        let subnet_id = SubnetId(it)
        node.network.addAsyncValidator(
          getAttestationTopic(digest, subnet_id),
          # This proc needs to be within closureScope; don't lift out of loop.
          proc(attestation: Attestation): Future[ValidationResult] {.async.} =
            return toValidationResult(
              await node.processor.attestationValidator(attestation, subnet_id)))

    node.network.addAsyncValidator(
      getAggregateAndProofsTopic(digest),
      proc(signedAggregateAndProof: SignedAggregateAndProof):
          Future[ValidationResult] {.async.} =
        return toValidationResult(
          await node.processor.aggregateValidator(signedAggregateAndProof)))

    node.network.addValidator(
      getAttesterSlashingsTopic(digest),
      proc (attesterSlashing: AttesterSlashing): ValidationResult =
        toValidationResult(
          node.processor[].attesterSlashingValidator(attesterSlashing)))

    node.network.addValidator(
      getProposerSlashingsTopic(digest),
      proc (proposerSlashing: ProposerSlashing): ValidationResult =
        toValidationResult(
          node.processor[].proposerSlashingValidator(proposerSlashing)))

    node.network.addValidator(
      getVoluntaryExitsTopic(digest),
      proc (signedVoluntaryExit: SignedVoluntaryExit): ValidationResult =
        toValidationResult(
          node.processor[].voluntaryExitValidator(signedVoluntaryExit)))

  installPhase0Validators(node.dag.forkDigests.phase0)

  # Validators introduced in phase0 are also used in altair and merge, but with
  # different fork digest
  installPhase0Validators(node.dag.forkDigests.altair)
  installPhase0Validators(node.dag.forkDigests.merge)

  node.network.addValidator(
    getBeaconBlocksTopic(node.dag.forkDigests.altair),
    proc (signedBlock: altair.SignedBeaconBlock): ValidationResult =
      toValidationResult(node.processor[].blockValidator(signedBlock)))

  node.network.addValidator(
    getBeaconBlocksTopic(node.dag.forkDigests.merge),
    proc (signedBlock: merge.SignedBeaconBlock): ValidationResult =
      toValidationResult(node.processor[].blockValidator(signedBlock)))

  template installSyncCommitteeeValidators(digest: auto) =
    for committeeIdx in allSyncSubcommittees():
      closureScope:
        let idx = committeeIdx
        node.network.addAsyncValidator(
          getSyncCommitteeTopic(digest, idx),
          # This proc needs to be within closureScope; don't lift out of loop.
          proc(msg: SyncCommitteeMessage): Future[ValidationResult] {.async.} =
            return toValidationResult(
              await node.processor.syncCommitteeMessageValidator(msg, idx)))

    node.network.addAsyncValidator(
      getSyncCommitteeContributionAndProofTopic(digest),
      proc(msg: SignedContributionAndProof): Future[ValidationResult] {.async.} =
        return toValidationResult(
          await node.processor.contributionValidator(msg)))

  installSyncCommitteeeValidators(node.dag.forkDigests.altair)
  installSyncCommitteeeValidators(node.dag.forkDigests.merge)

proc stop*(node: BeaconNode) =
  bnStatus = BeaconNodeStatus.Stopping
  notice "Graceful shutdown"
  if not node.config.inProcessValidators:
    try:
      node.vcProcess.close()
    except Exception as exc:
      warn "Couldn't close vc process", msg = exc.msg
  try:
    waitFor node.network.stop()
  except CatchableError as exc:
    warn "Couldn't stop network", msg = exc.msg

  node.attachedValidators.slashingProtection.close()
  node.db.close()
  notice "Databases closed"

proc run*(node: BeaconNode) {.raises: [Defect, CatchableError].} =
  bnStatus = BeaconNodeStatus.Running

  if not(isNil(node.rpcServer)):
    node.rpcServer.installRpcHandlers(node)
    node.rpcServer.start()

  if not(isNil(node.restServer)):
    node.restServer.installRestHandlers(node)
    node.restServer.start()

  let
    wallTime = node.beaconClock.now()
    wallSlot = wallTime.slotOrZero()

  node.requestManager.start()
  node.syncManager.start()

  waitFor node.updateGossipStatus(wallSlot)

  asyncSpawn runSlotLoop(node, wallTime, onSlotStart)
  asyncSpawn runOnSecondLoop(node)
  asyncSpawn runQueueProcessingLoop(node.blockProcessor)

  ## Ctrl+C handling
  proc controlCHandler() {.noconv.} =
    when defined(windows):
      # workaround for https://github.com/nim-lang/Nim/issues/4057
      try:
        setupForeignThreadGc()
      except Exception as exc: raiseAssert exc.msg # shouldn't happen
    notice "Shutting down after having received SIGINT"
    bnStatus = BeaconNodeStatus.Stopping
  try:
    setControlCHook(controlCHandler)
  except Exception as exc: # TODO Exception
    warn "Cannot set ctrl-c handler", msg = exc.msg

  # equivalent SIGTERM handler
  when defined(posix):
    proc SIGTERMHandler(signal: cint) {.noconv.} =
      notice "Shutting down after having received SIGTERM"
      bnStatus = BeaconNodeStatus.Stopping
    c_signal(SIGTERM, SIGTERMHandler)

  # main event loop
  while bnStatus == BeaconNodeStatus.Running:
    poll() # if poll fails, the network is broken

  # time to say goodbye
  node.stop()

var gPidFile: string
proc createPidFile(filename: string) {.raises: [Defect, IOError].} =
  writeFile filename, $os.getCurrentProcessId()
  gPidFile = filename
  addQuitProc proc {.noconv.} = discard io2.removeFile(gPidFile)

proc initializeNetworking(node: BeaconNode) {.async.} =
  node.installMessageValidators()

  info "Listening to incoming network requests"
  await node.network.startListening()

  let addressFile = node.config.dataDir / "beacon_node.enr"
  writeFile(addressFile, node.network.announcedENR.toURI)

  await node.network.start()

proc start(node: BeaconNode) {.raises: [Defect, CatchableError].} =
  let
    head = node.dag.head
    finalizedHead = node.dag.finalizedHead
    genesisTime = node.beaconClock.fromNow(toBeaconTime(Slot 0))

  notice "Starting beacon node",
    version = fullVersionStr,
    enr = node.network.announcedENR.toURI,
    peerId = $node.network.switch.peerInfo.peerId,
    timeSinceFinalization =
      node.beaconClock.now() - finalizedHead.slot.toBeaconTime(),
    head = shortLog(head),
    justified = shortLog(getStateField(
      node.dag.headState.data, current_justified_checkpoint)),
    finalized = shortLog(getStateField(
      node.dag.headState.data, finalized_checkpoint)),
    finalizedHead = shortLog(finalizedHead),
    SLOTS_PER_EPOCH,
    SECONDS_PER_SLOT,
    SPEC_VERSION,
    dataDir = node.config.dataDir.string,
    validators = node.attachedValidators[].count

  if genesisTime.inFuture:
    notice "Waiting for genesis", genesisIn = genesisTime.offset

  waitFor node.initializeNetworking()

  if node.eth1Monitor != nil:
    node.eth1Monitor.start()
  else:
    notice "Running without execution chain monitor, block producation partially disabled"

  node.run()

func formatGwei(amount: uint64): string =
  # TODO This is implemented in a quite a silly way.
  # Better routines for formatting decimal numbers
  # should exists somewhere else.
  let
    eth = amount div 1000000000
    remainder = amount mod 1000000000

  result = $eth
  if remainder != 0:
    result.add '.'
    let remainderStr = $remainder
    for i in remainderStr.len ..< 9:
      result.add '0'
    result.add remainderStr
    while result[^1] == '0':
      result.setLen(result.len - 1)

proc initStatusBar(node: BeaconNode) {.raises: [Defect, ValueError].} =
  if not isatty(stdout): return
  if not node.config.statusBarEnabled: return

  try:
    enableTrueColors()
  except Exception as exc: # TODO Exception
    error "Couldn't enable colors", err = exc.msg

  proc dataResolver(expr: string): string {.raises: [Defect].} =
    template justified: untyped = node.dag.head.atEpochStart(
      getStateField(
        node.dag.headState.data, current_justified_checkpoint).epoch)
    # TODO:
    # We should introduce a general API for resolving dot expressions
    # such as `db.latest_block.slot` or `metrics.connected_peers`.
    # Such an API can be shared between the RPC back-end, CLI tools
    # such as ncli, a potential GraphQL back-end and so on.
    # The status bar feature would allow the user to specify an
    # arbitrary expression that is resolvable through this API.
    case expr.toLowerAscii
    of "connected_peers":
      $(node.connectedPeersCount)

    of "head_root":
      shortLog(node.dag.head.root)
    of "head_epoch":
      $(node.dag.head.slot.epoch)
    of "head_epoch_slot":
      $(node.dag.head.slot mod SLOTS_PER_EPOCH)
    of "head_slot":
      $(node.dag.head.slot)

    of "justifed_root":
      shortLog(justified.blck.root)
    of "justifed_epoch":
      $(justified.slot.epoch)
    of "justifed_epoch_slot":
      $(justified.slot mod SLOTS_PER_EPOCH)
    of "justifed_slot":
      $(justified.slot)

    of "finalized_root":
      shortLog(node.dag.finalizedHead.blck.root)
    of "finalized_epoch":
      $(node.dag.finalizedHead.slot.epoch)
    of "finalized_epoch_slot":
      $(node.dag.finalizedHead.slot mod SLOTS_PER_EPOCH)
    of "finalized_slot":
      $(node.dag.finalizedHead.slot)

    of "epoch":
      $node.currentSlot.epoch

    of "epoch_slot":
      $(node.currentSlot mod SLOTS_PER_EPOCH)

    of "slot":
      $node.currentSlot

    of "slots_per_epoch":
      $SLOTS_PER_EPOCH

    of "slot_trailing_digits":
      var slotStr = $node.currentSlot
      if slotStr.len > 3: slotStr = slotStr[^3..^1]
      slotStr

    of "attached_validators_balance":
      formatGwei(node.attachedValidatorBalanceTotal)

    of "sync_status":
      if isNil(node.syncManager):
        "pending"
      else:
        if node.syncManager.inProgress:
          node.syncManager.syncStatus
        else:
          "synced"
    else:
      # We ignore typos for now and just render the expression
      # as it was written. TODO: come up with a good way to show
      # an error message to the user.
      "$" & expr

  var statusBar = StatusBarView.init(
    node.config.statusBarContents,
    dataResolver)

  when compiles(defaultChroniclesStream.outputs[0].writer):
    let tmp = defaultChroniclesStream.outputs[0].writer

    defaultChroniclesStream.outputs[0].writer =
      proc (logLevel: LogLevel, msg: LogOutputStr) {.raises: [Defect].} =
        try:
          # p.hidePrompt
          erase statusBar
          # p.writeLine msg
          tmp(logLevel, msg)
          render statusBar
          # p.showPrompt
        except Exception as e: # render raises Exception
          logLoggingFailure(cstring(msg), e)

  proc statusBarUpdatesPollingLoop() {.async.} =
    try:
      while true:
        update statusBar
        erase statusBar
        render statusBar
        await sleepAsync(chronos.seconds(1))
    except CatchableError as exc:
      warn "Failed to update status bar, no further updates", err = exc.msg

  asyncSpawn statusBarUpdatesPollingLoop()

proc handleValidatorExitCommand(config: BeaconNodeConf) {.async.} =
  let port = try:
    let value = parseInt(config.rpcUrlForExit.port)
    if value < Port.low.int or value > Port.high.int:
      raise newException(ValueError,
        "The port number must be between " & $Port.low & " and " & $Port.high)
    Port value
  except CatchableError as err:
    fatal "Invalid port number", err = err.msg
    quit 1

  let rpcClient = newRpcHttpClient()

  try:
    await connect(rpcClient, config.rpcUrlForExit.hostname, port,
                  secure = config.rpcUrlForExit.scheme in ["https", "wss"])
  except CatchableError as err:
    fatal "Failed to connect to the beacon node RPC service", err = err.msg
    quit 1

  let (validator, validatorIdx, _, _) = try:
    await rpcClient.get_v1_beacon_states_stateId_validators_validatorId(
      "head", config.exitedValidator)
  except CatchableError as err:
    fatal "Failed to obtain information for validator", err = err.msg
    quit 1

  let exitAtEpoch = if config.exitAtEpoch.isSome:
    Epoch config.exitAtEpoch.get
  else:
    let headSlot = try:
      await rpcClient.getBeaconHead()
    except CatchableError as err:
      fatal "Failed to obtain the current head slot", err = err.msg
      quit 1
    headSlot.epoch

  let
    validatorsDir = config.validatorsDir
    validatorKeyAsStr = "0x" & $validator.pubkey
    keystoreDir = validatorsDir / validatorKeyAsStr

  if not dirExists(keystoreDir):
    echo "The validator keystores directory '" & config.validatorsDir.string &
         "' does not contain a keystore for the selected validator with public " &
         "key '" & validatorKeyAsStr & "'."
    quit 1

  let signingItem = loadKeystore(
    validatorsDir,
    config.secretsDir,
    validatorKeyAsStr,
    config.nonInteractive)

  if signingItem.isNone:
    fatal "Unable to continue without decrypted signing key"
    quit 1

  let fork = try:
    await rpcClient.get_v1_beacon_states_fork("head")
  except CatchableError as err:
    fatal "Failed to obtain the fork id of the head state", err = err.msg
    quit 1

  let genesisValidatorsRoot = try:
    (await rpcClient.get_v1_beacon_genesis()).genesis_validators_root
  except CatchableError as err:
    fatal "Failed to obtain the genesis validators root of the network",
           err = err.msg
    quit 1

  var signedExit = SignedVoluntaryExit(
    message: VoluntaryExit(
      epoch: exitAtEpoch,
      validator_index: validatorIdx))

  signedExit.signature =
    block:
      let key = signingItem.get().privateKey
      get_voluntary_exit_signature(fork, genesisValidatorsRoot,
                                   signedExit.message, key).toValidatorSig()

  template ask(prompt: string): string =
    try:
      stdout.write prompt, ": "
      stdin.readLine()
    except IOError:
      fatal "Failed to read user input from stdin"
      quit 1

  try:
    echoP "PLEASE BEWARE!"

    echoP "Publishing a voluntary exit is an irreversible operation! " &
          "You won't be able to restart again with the same validator."

    echoP "By requesting an exit now, you'll be exempt from penalties " &
          "stemming from not performing your validator duties, but you " &
          "won't be able to withdraw your deposited funds for the time " &
          "being. This means that your funds will be effectively frozen " &
          "until withdrawals are enabled in a future phase of Eth2."


    echoP "To understand more about the Eth2 roadmap, we recommend you " &
          "have a look at\n" &
          "https://ethereum.org/en/eth2/#roadmap"

    echoP "You must keep your validator running for at least 5 epochs " &
          "(32 minutes) after requesting a validator exit, as you will " &
          "still be required to perform validator duties until your exit " &
          "has been processed. The number of epochs could be significantly " &
          "higher depending on how many other validators are queued to exit."

    echoP "As such, we recommend you keep track of your validator's status " &
          "using an Eth2 block explorer before shutting down your beacon node."

    const
      confirmation = "I understand the implications of submitting a voluntary exit"

    while true:
      echoP "To proceed to submitting your voluntary exit, please type '" &
            confirmation & "' (without the quotes) in the prompt below and " &
            "press ENTER or type 'q' to quit."
      echo ""

      let choice = ask "Your choice"
      if choice == "q":
        quit 0
      elif choice == confirmation:
        let success = await rpcClient.post_v1_beacon_pool_voluntary_exits(signedExit)
        if success:
          echo "Successfully published voluntary exit for validator " &
                $validatorIdx & "(" & validatorKeyAsStr[0..9] & ")."
          quit 0
        else:
          echo "The voluntary exit was not submitted successfully. Please try again."
          quit 1
  except CatchableError as err:
    fatal "Failed to send the signed exit message to the beacon node RPC",
           err = err.msg
    quit 1

proc loadEth2Network(config: BeaconNodeConf): Eth2NetworkMetadata {.raises: [Defect, IOError].} =
  network_name.set(2, labelValues = [config.eth2Network.get(otherwise = "mainnet")])
  if config.eth2Network.isSome:
    getMetadataForNetwork(config.eth2Network.get)
  else:
    when const_preset == "mainnet":
      mainnetMetadata
    else:
      # Presumably other configurations can have other defaults, but for now
      # this simplifies the flow
      echo "Must specify network on non-mainnet node"
      quit 1

proc doRunBeaconNode(config: var BeaconNodeConf, rng: ref BrHmacDrbgContext) {.raises: [Defect, CatchableError].} =
  info "Launching beacon node",
      version = fullVersionStr,
      bls_backend = $BLS_BACKEND,
      cmdParams = commandLineParams(),
      config

  createPidFile(config.dataDir.string / "beacon_node.pid")

  config.createDumpDirs()

  if config.metricsEnabled:
    let metricsAddress = config.metricsAddress
    notice "Starting metrics HTTP server",
      url = "http://" & $metricsAddress & ":" & $config.metricsPort & "/metrics"
    try:
      startMetricsHttpServer($metricsAddress, config.metricsPort)
    except CatchableError as exc: raise exc
    except Exception as exc: raiseAssert exc.msg # TODO fix metrics

  # There are no managed event loops in here, to do a graceful shutdown, but
  # letting the default Ctrl+C handler exit is safe, since we only read from
  # the db.

  var metadata = config.loadEth2Network()

  # https://github.com/ethereum/consensus-specs/blob/v1.1.6/specs/merge/client-settings.md#override-terminal-total-difficulty
  if config.terminalTotalDifficultyOverride.isSome:
    metadata.cfg.TERMINAL_TOTAL_DIFFICULTY =
      config.terminalTotalDifficultyOverride.get.u256

  # Updating the config based on the metadata certainly is not beautiful but it
  # works
  for node in metadata.bootstrapNodes:
    config.bootstrapNodes.add node

  let node = BeaconNode.init(
    metadata.cfg,
    rng,
    config,
    metadata.depositContractDeployedAt,
    metadata.eth1Network,
    metadata.genesisData,
    metadata.genesisDepositsSnapshot)

  if bnStatus == BeaconNodeStatus.Stopping:
    return

  initStatusBar(node)

  if node.nickname != "":
    dynamicLogScope(node = node.nickname): node.start()
  else:
    node.start()

proc doCreateTestnet(config: BeaconNodeConf, rng: var BrHmacDrbgContext) {.raises: [Defect, CatchableError].} =
  let launchPadDeposits = try:
    Json.loadFile(config.testnetDepositsFile.string, seq[LaunchPadDeposit])
  except SerializationError as err:
    error "Invalid LaunchPad deposits file",
          err = formatMsg(err, config.testnetDepositsFile.string)
    quit 1

  var deposits: seq[DepositData]
  for i in 0 ..< launchPadDeposits.len:
    deposits.add(launchPadDeposits[i] as DepositData)

  let
    startTime = uint64(times.toUnix(times.getTime()) + config.genesisOffset)
    outGenesis = config.outputGenesis.string
    eth1Hash = if config.web3Urls.len == 0: eth1BlockHash
               else: (waitFor getEth1BlockHash(config.web3Urls[0], blockId("latest"))).asEth2Digest
    cfg = getRuntimeConfig(config.eth2Network)
  var
    initialState = newClone(initialize_beacon_state_from_eth1(
      cfg, eth1Hash, startTime, deposits, {skipBlsValidation}))

  # https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#create-genesis-state
  initialState.genesis_time = startTime

  doAssert initialState.validators.len > 0

  let outGenesisExt = splitFile(outGenesis).ext
  if cmpIgnoreCase(outGenesisExt, ".json") == 0:
    Json.saveFile(outGenesis, initialState, pretty = true)
    echo "Wrote ", outGenesis

  let outSszGenesis = outGenesis.changeFileExt "ssz"
  SSZ.saveFile(outSszGenesis, initialState[])
  echo "Wrote ", outSszGenesis

  let bootstrapFile = config.outputBootstrapFile.string
  if bootstrapFile.len > 0:
    let
      networkKeys = getPersistentNetKeys(rng, config)
      netMetadata = getPersistentNetMetadata(config)
      forkId = getENRForkID(
        cfg,
        initialState[].slot.epoch,
        initialState[].genesis_validators_root)
      bootstrapEnr = enr.Record.init(
        1, # sequence number
        networkKeys.seckey.asEthKey,
        some(config.bootstrapAddress),
        some(config.bootstrapPort),
        some(config.bootstrapPort),
        [
          toFieldPair(enrForkIdField, SSZ.encode(forkId)),
          toFieldPair(enrAttestationSubnetsField, SSZ.encode(netMetadata.attnets))
        ])

    writeFile(bootstrapFile, bootstrapEnr.tryGet().toURI)
    echo "Wrote ", bootstrapFile

proc findWalletWithoutErrors(config: BeaconNodeConf,
                             name: WalletName): Option[WalletPathPair] =
  let res = findWallet(config, name)
  if res.isErr:
    fatal "Failed to locate wallet", error = res.error
    quit 1
  res.get

proc doDeposits(config: BeaconNodeConf, rng: var BrHmacDrbgContext) {.
    raises: [Defect, CatchableError].} =
  case config.depositsCmd
  of DepositsCmd.createTestnetDeposits:
    if config.eth2Network.isNone:
      fatal "Please specify the intended testnet for the deposits"
      quit 1
    let metadata = config.loadEth2Network()
    var seed: KeySeed
    defer: burnMem(seed)
    var walletPath: WalletPathPair

    if config.existingWalletId.isSome:
      let
        id = config.existingWalletId.get
        found = findWalletWithoutErrors(config, id)

      if found.isSome:
        walletPath = found.get
      else:
        fatal "Unable to find wallet with the specified name/uuid", id
        quit 1

      var unlocked = unlockWalletInteractively(walletPath.wallet)
      if unlocked.isOk:
        swap(seed, unlocked.get)
      else:
        # The failure will be reported in `unlockWalletInteractively`.
        quit 1
    else:
      var walletRes = createWalletInteractively(rng, config)
      if walletRes.isErr:
        fatal "Unable to create wallet", err = walletRes.error
        quit 1
      else:
        swap(seed, walletRes.get.seed)
        walletPath = walletRes.get.walletPath

    let vres = secureCreatePath(config.outValidatorsDir)
    if vres.isErr():
      fatal "Could not create directory", path = config.outValidatorsDir
      quit QuitFailure

    let sres = secureCreatePath(config.outSecretsDir)
    if sres.isErr():
      fatal "Could not create directory", path = config.outSecretsDir
      quit QuitFailure

    let deposits = generateDeposits(
      metadata.cfg,
      rng,
      seed,
      walletPath.wallet.nextAccount,
      config.totalDeposits,
      config.outValidatorsDir,
      config.outSecretsDir)

    if deposits.isErr:
      fatal "Failed to generate deposits", err = deposits.error
      quit 1

    try:
      let depositDataPath = if config.outDepositsFile.isSome:
        config.outDepositsFile.get.string
      else:
        config.outValidatorsDir / "deposit_data-" & $epochTime() & ".json"

      let launchPadDeposits =
        mapIt(deposits.value, LaunchPadDeposit.init(metadata.cfg, it))

      Json.saveFile(depositDataPath, launchPadDeposits)
      echo "Deposit data written to \"", depositDataPath, "\""

      walletPath.wallet.nextAccount += deposits.value.len
      let status = saveWallet(walletPath)
      if status.isErr:
        fatal "Failed to update wallet file after generating deposits",
                wallet = walletPath.path,
                error = status.error
        quit 1
    except CatchableError as err:
      fatal "Failed to create launchpad deposit data file", err = err.msg
      quit 1
  #[
  of DepositsCmd.status:
    echo "The status command is not implemented yet"
    quit 1
  ]#

  of DepositsCmd.`import`:
    let validatorKeysDir = if config.importedDepositsDir.isSome:
      config.importedDepositsDir.get
    else:
      let cwd = os.getCurrentDir()
      if dirExists(cwd / "validator_keys"):
        InputDir(cwd / "validator_keys")
      else:
        echo "The default search path for validator keys is a sub-directory " &
              "named 'validator_keys' in the current working directory. Since " &
              "no such directory exists, please either provide the correct path" &
              "as an argument or copy the imported keys in the expected location."
        quit 1

    importKeystoresFromDir(
      rng,
      validatorKeysDir.string,
      config.validatorsDir, config.secretsDir)

  of DepositsCmd.exit:
    waitFor handleValidatorExitCommand(config)

proc doWallets(config: BeaconNodeConf, rng: var BrHmacDrbgContext) {.
    raises: [Defect, CatchableError].} =
  case config.walletsCmd:
  of WalletsCmd.create:
    if config.createdWalletNameFlag.isSome:
      let
        name = config.createdWalletNameFlag.get
        existingWallet = findWalletWithoutErrors(config, name)
      if existingWallet.isSome:
        echo "The Wallet '" & name.string & "' already exists."
        quit 1

    var walletRes = createWalletInteractively(rng, config)
    if walletRes.isErr:
      fatal "Unable to create wallet", err = walletRes.error
      quit 1
    burnMem(walletRes.get.seed)

  of WalletsCmd.list:
    for kind, walletFile in walkDir(config.walletsDir):
      if kind != pcFile: continue
      if checkSensitiveFilePermissions(walletFile):
        let walletRes = loadWallet(walletFile)
        if walletRes.isOk:
          echo walletRes.get.longName
        else:
          warn "Found corrupt wallet file",
                wallet = walletFile, error = walletRes.error
      else:
        warn "Found wallet file with insecure permissions",
              wallet = walletFile

  of WalletsCmd.restore:
    restoreWalletInteractively(rng, config)

proc doRecord(config: BeaconNodeConf, rng: var BrHmacDrbgContext) {.
    raises: [Defect, CatchableError].} =
  case config.recordCmd:
  of RecordCmd.create:
    let netKeys = getPersistentNetKeys(rng, config)

    var fieldPairs: seq[FieldPair]
    for field in config.fields:
      let fieldPair = field.split(":")
      if fieldPair.len > 1:
        fieldPairs.add(toFieldPair(fieldPair[0], hexToSeqByte(fieldPair[1])))
      else:
        fatal "Invalid field pair"
        quit QuitFailure

    let record = enr.Record.init(
      config.seqNumber,
      netKeys.seckey.asEthKey,
      some(config.ipExt),
      some(config.tcpPortExt),
      some(config.udpPortExt),
      fieldPairs).expect("Record within size limits")

    echo record.toURI()

  of RecordCmd.print:
    echo $config.recordPrint

proc doWeb3Cmd(config: BeaconNodeConf) {.raises: [Defect, CatchableError].} =
  case config.web3Cmd:
  of Web3Cmd.test:
    let metadata = config.loadEth2Network()
    waitFor testWeb3Provider(config.web3TestUrl,
                             metadata.cfg.DEPOSIT_CONTRACT_ADDRESS)

proc doSlashingExport(conf: BeaconNodeConf) {.raises: [IOError, Defect].}=
  let
    dir = conf.validatorsDir()
    filetrunc = SlashingDbName
  # TODO: Make it read-only https://github.com/status-im/nim-eth/issues/312
  let db = SlashingProtectionDB.loadUnchecked(dir, filetrunc, readOnly = false)

  let interchange = conf.exportedInterchangeFile.string
  db.exportSlashingInterchange(interchange, conf.exportedValidators)
  echo "Export finished: '", dir/filetrunc & ".sqlite3" , "' into '", interchange, "'"

proc doSlashingImport(conf: BeaconNodeConf) {.raises: [SerializationError, IOError, Defect].} =
  let
    dir = conf.validatorsDir()
    filetrunc = SlashingDbName
  # TODO: Make it read-only https://github.com/status-im/nim-eth/issues/312

  let interchange = conf.importedInterchangeFile.string

  var spdir: SPDIR
  try:
    spdir = JSON.loadFile(interchange, SPDIR)
  except SerializationError as err:
    writeStackTrace()
    stderr.write $JSON & " load issue for file \"", interchange, "\"\n"
    stderr.write err.formatMsg(interchange), "\n"
    quit 1

  # Open DB and handle migration from v1 to v2 if needed
  let db = SlashingProtectionDB.init(
    genesis_validators_root = Eth2Digest spdir.metadata.genesis_validators_root,
    basePath = dir,
    dbname = filetrunc,
    modes = {kCompleteArchive}
  )

  # Now import the slashing interchange file
  # Failures mode:
  # - siError can only happen with invalid genesis_validators_root which would be caught above
  # - siPartial can happen for invalid public keys, slashable blocks, slashable votes
  let status = db.inclSPDIR(spdir)
  doAssert status in {siSuccess, siPartial}

  echo "Import finished: '", interchange, "' into '", dir/filetrunc & ".sqlite3", "'"

proc doSlashingInterchange(conf: BeaconNodeConf) {.raises: [Defect, CatchableError].} =
  doAssert conf.cmd == slashingdb
  case conf.slashingdbCmd
  of SlashProtCmd.`export`:
    conf.doSlashingExport()
  of SlashProtCmd.`import`:
    conf.doSlashingImport()

{.pop.} # TODO moduletests exceptions
programMain:
  var
    config = makeBannerAndConfig(clientId, BeaconNodeConf)

  if not(checkAndCreateDataDir(string(config.dataDir))):
    # We are unable to access/create data folder or data folder's
    # permissions are insecure.
    quit QuitFailure

  setupLogging(config.logLevel, config.logStdout, config.logFile)

  ## This Ctrl+C handler exits the program in non-graceful way.
  ## It's responsible for handling Ctrl+C in sub-commands such
  ## as `wallets *` and `deposits *`. In a regular beacon node
  ## run, it will be overwritten later with a different handler
  ## performing a graceful exit.
  proc exitImmediatelyOnCtrlC() {.noconv.} =
    when defined(windows):
      # workaround for https://github.com/nim-lang/Nim/issues/4057
      setupForeignThreadGc()
    # in case a password prompt disabled echoing
    resetStdin()
    echo "" # If we interrupt during an interactive prompt, this
            # will move the cursor to the next line
    notice "Shutting down after having received SIGINT"
    quit 0
  setControlCHook(exitImmediatelyOnCtrlC)
  # equivalent SIGTERM handler
  when defined(posix):
    proc exitImmediatelyOnSIGTERM(signal: cint) {.noconv.} =
      notice "Shutting down after having received SIGTERM"
      quit 0
    c_signal(SIGTERM, exitImmediatelyOnSIGTERM)

  # Single RNG instance for the application - will be seeded on construction
  # and avoid using system resources (such as urandom) after that
  let rng = keys.newRng()

  case config.cmd
  of createTestnet: doCreateTestnet(config, rng[])
  of noCommand: doRunBeaconNode(config, rng)
  of deposits: doDeposits(config, rng[])
  of wallets: doWallets(config, rng[])
  of record: doRecord(config, rng[])
  of web3: doWeb3Cmd(config)
  of slashingdb: doSlashingInterchange(config)
