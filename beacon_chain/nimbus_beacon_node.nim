# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  std/[os, random, sequtils, terminal, times],
  chronos, chronicles, chronicles/chronos_tools,
  metrics, metrics/chronos_httpserver,
  stew/[byteutils, io2],
  eth/p2p/discoveryv5/[enr, random2],
  eth/keys,
  ./consensus_object_pools/vanity_logs/vanity_logs,
  ./networking/topic_params,
  ./rpc/[rest_api, state_ttl_cache],
  ./spec/datatypes/[altair, bellatrix, phase0],
  ./spec/[deposit_snapshots, engine_authentication, weak_subjectivity],
  ./validators/[keystore_management, validator_duties],
  "."/[
    beacon_node, beacon_node_light_client, deposits, interop,
    nimbus_binary_common, statusbar, trusted_node_sync, wallets]

when defined(posix):
  import system/ansi_c

from ./spec/datatypes/eip4844 import SignedBeaconBlock

from
  libp2p/protocols/pubsub/gossipsub
import
  TopicParams, validateParameters, init

when defined(windows):
  import winlean

  type
    LPCSTR* = cstring
    LPSTR* = cstring

    SERVICE_STATUS* {.final, pure.} = object
      dwServiceType*: DWORD
      dwCurrentState*: DWORD
      dwControlsAccepted*: DWORD
      dwWin32ExitCode*: DWORD
      dwServiceSpecificExitCode*: DWORD
      dwCheckPoint*: DWORD
      dwWaitHint*: DWORD

    SERVICE_STATUS_HANDLE* = DWORD
    LPSERVICE_STATUS* = ptr SERVICE_STATUS
    LPSERVICE_MAIN_FUNCTION* = proc (para1: DWORD, para2: LPSTR) {.stdcall.}

    SERVICE_TABLE_ENTRY* {.final, pure.} = object
      lpServiceName*: LPSTR
      lpServiceProc*: LPSERVICE_MAIN_FUNCTION

    LPSERVICE_TABLE_ENTRY* = ptr SERVICE_TABLE_ENTRY
    LPHANDLER_FUNCTION* = proc (para1: DWORD): WINBOOL{.stdcall.}

  const
    SERVICE_WIN32_OWN_PROCESS = 16
    SERVICE_RUNNING = 4
    SERVICE_STOPPED = 1
    SERVICE_START_PENDING = 2
    SERVICE_STOP_PENDING = 3
    SERVICE_CONTROL_STOP = 1
    SERVICE_CONTROL_PAUSE = 2
    SERVICE_CONTROL_CONTINUE = 3
    SERVICE_CONTROL_INTERROGATE = 4
    SERVICE_ACCEPT_STOP = 1
    NO_ERROR = 0
    SERVICE_NAME = LPCSTR "NIMBUS_BEACON_NODE"

  var
    gSvcStatusHandle: SERVICE_STATUS_HANDLE
    gSvcStatus: SERVICE_STATUS

  proc reportServiceStatus*(dwCurrentState, dwWin32ExitCode, dwWaitHint: DWORD) {.gcsafe.}

  proc StartServiceCtrlDispatcher*(lpServiceStartTable: LPSERVICE_TABLE_ENTRY): WINBOOL{.
      stdcall, dynlib: "advapi32", importc: "StartServiceCtrlDispatcherA".}

  proc SetServiceStatus*(hServiceStatus: SERVICE_STATUS_HANDLE,
                       lpServiceStatus: LPSERVICE_STATUS): WINBOOL{.stdcall,
    dynlib: "advapi32", importc: "SetServiceStatus".}

  proc RegisterServiceCtrlHandler*(lpServiceName: LPCSTR,
                                  lpHandlerProc: LPHANDLER_FUNCTION): SERVICE_STATUS_HANDLE{.
    stdcall, dynlib: "advapi32", importc: "RegisterServiceCtrlHandlerA".}

type
  RpcServer = RpcHttpServer

template init(T: type RpcHttpServer, ip: ValidIpAddress, port: Port): T =
  newRpcHttpServer([initTAddress(ip, port)])

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

logScope: topics = "beacnde"

func getVanityLogs(stdoutKind: StdoutLogKind): VanityLogs =
  case stdoutKind
  of StdoutLogKind.Auto: raiseAssert "inadmissable here"
  of StdoutLogKind.Colors:
    VanityLogs(
      onMergeTransitionBlock:          color🐼,
      onFinalizedMergeTransitionBlock: blink🐼,
      onUpgradeToCapella:              color🦉)
  of StdoutLogKind.NoColors:
    VanityLogs(
      onMergeTransitionBlock:          mono🐼,
      onFinalizedMergeTransitionBlock: mono🐼,
      onUpgradeToCapella:              mono🦉)
  of StdoutLogKind.Json, StdoutLogKind.None:
    VanityLogs(
      onMergeTransitionBlock:
        (proc() = notice "🐼 Proof of Stake Activated 🐼"),
      onFinalizedMergeTransitionBlock:
        (proc() = notice "🐼 Proof of Stake Finalized 🐼"),
      onUpgradeToCapella:
        (proc() = notice "🦉 Withdrowls now available 🦉"))

proc loadChainDag(
    config: BeaconNodeConf,
    cfg: RuntimeConfig,
    db: BeaconChainDB,
    eventBus: EventBus,
    validatorMonitor: ref ValidatorMonitor,
    networkGenesisValidatorsRoot: Opt[Eth2Digest],
    shouldEnableTestFeatures: bool): ChainDAGRef =
  info "Loading block DAG from database", path = config.databaseDir

  proc onLightClientFinalityUpdate(data: altair.LightClientFinalityUpdate) =
    eventBus.finUpdateQueue.emit(data)
  proc onLightClientOptimisticUpdate(data: altair.LightClientOptimisticUpdate) =
    eventBus.optUpdateQueue.emit(data)

  let
    extraFlags =
      if shouldEnableTestFeatures: {enableTestFeatures, lowParticipation}
      else: {enableTestFeatures}
    chainDagFlags =
      if config.strictVerification: {strictVerification}
      else: {}
    onLightClientFinalityUpdateCb =
      if config.lightClientDataServe: onLightClientFinalityUpdate
      else: nil
    onLightClientOptimisticUpdateCb =
      if config.lightClientDataServe: onLightClientOptimisticUpdate
      else: nil
    dag = ChainDAGRef.init(
      cfg, db, validatorMonitor, extraFlags + chainDagFlags, config.eraDir,
      vanityLogs = getVanityLogs(detectTTY(config.logStdout)),
      lcDataConfig = LightClientDataConfig(
        serve: config.lightClientDataServe,
        importMode: config.lightClientDataImportMode,
        maxPeriods: config.lightClientDataMaxPeriods,
        onLightClientFinalityUpdate: onLightClientFinalityUpdateCb,
        onLightClientOptimisticUpdate: onLightClientOptimisticUpdateCb))
    databaseGenesisValidatorsRoot =
      getStateField(dag.headState, genesis_validators_root)

  if networkGenesisValidatorsRoot.isSome:
    if networkGenesisValidatorsRoot.get != databaseGenesisValidatorsRoot:
      fatal "The specified --data-dir contains data for a different network",
            networkGenesisValidatorsRoot = networkGenesisValidatorsRoot.get,
            databaseGenesisValidatorsRoot,
            dataDir = config.dataDir
      quit 1

  dag

proc checkWeakSubjectivityCheckpoint(
    dag: ChainDAGRef,
    wsCheckpoint: Checkpoint,
    beaconClock: BeaconClock) =
  let
    currentSlot = beaconClock.now.slotOrZero
    isCheckpointStale = not is_within_weak_subjectivity_period(
      dag.cfg, currentSlot, dag.headState, wsCheckpoint)

  if isCheckpointStale:
    error "Weak subjectivity checkpoint is stale",
          currentSlot, checkpoint = wsCheckpoint,
          headStateSlot = getStateField(dag.headState, slot)
    quit 1

proc initFullNode(
    node: BeaconNode,
    rng: ref HmacDrbgContext,
    dag: ChainDAGRef,
    taskpool: TaskPoolPtr,
    getBeaconTime: GetBeaconTimeFn) =
  template config(): auto = node.config

  proc onAttestationReceived(data: Attestation) =
    node.eventBus.attestQueue.emit(data)
  proc onSyncContribution(data: SignedContributionAndProof) =
    node.eventBus.contribQueue.emit(data)
  proc onVoluntaryExitAdded(data: SignedVoluntaryExit) =
    node.eventBus.exitQueue.emit(data)
  proc onBlockAdded(data: ForkedTrustedSignedBeaconBlock) =
    let optimistic =
      if node.currentSlot().epoch() >= dag.cfg.BELLATRIX_FORK_EPOCH:
        some node.dag.is_optimistic(data.root)
      else:
        none[bool]()
    node.eventBus.blocksQueue.emit(
      EventBeaconBlockObject.init(data, optimistic))
  proc onHeadChanged(data: HeadChangeInfoObject) =
    let eventData =
      if node.currentSlot().epoch() >= dag.cfg.BELLATRIX_FORK_EPOCH:
        var res = data
        res.optimistic = some node.dag.is_optimistic(data.block_root)
        res
      else:
        data
    node.eventBus.headQueue.emit(eventData)
  proc onChainReorg(data: ReorgInfoObject) =
    let eventData =
      if node.currentSlot().epoch() >= dag.cfg.BELLATRIX_FORK_EPOCH:
        var res = data
        res.optimistic = some node.dag.is_optimistic(data.new_head_block)
        res
      else:
        data
    node.eventBus.reorgQueue.emit(eventData)
  proc makeOnFinalizationCb(
      # This `nimcall` functions helps for keeping track of what
      # needs to be captured by the onFinalization closure.
      eventBus: EventBus,
      eth1Monitor: Eth1Monitor): OnFinalizedCallback {.nimcall.} =
    static: doAssert (eth1Monitor is ref)
    return proc(dag: ChainDAGRef, data: FinalizationInfoObject) =
      if eth1Monitor != nil:
        let finalizedEpochRef = dag.getFinalizedEpochRef()
        discard trackFinalizedState(eth1Monitor,
                                    finalizedEpochRef.eth1_data,
                                    finalizedEpochRef.eth1_deposit_index)
      node.updateLightClientFromDag()
      let eventData =
        if node.currentSlot().epoch() >= dag.cfg.BELLATRIX_FORK_EPOCH:
          var res = data
          res.optimistic = some node.dag.is_optimistic(data.block_root)
          res
        else:
          data
      eventBus.finalQueue.emit(eventData)

  func getLocalHeadSlot(): Slot =
    dag.head.slot

  proc getLocalWallSlot(): Slot =
    node.beaconClock.now.slotOrZero

  func getFirstSlotAtFinalizedEpoch(): Slot =
    dag.finalizedHead.slot

  func getBackfillSlot(): Slot =
    dag.backfill.slot

  func getFrontfillSlot(): Slot =
    max(dag.frontfill.get(BlockId()).slot, dag.horizon)

  let
    quarantine = newClone(
      Quarantine.init())
    attestationPool = newClone(
      AttestationPool.init(dag, quarantine, onAttestationReceived))
    syncCommitteeMsgPool = newClone(
      SyncCommitteeMsgPool.init(rng, onSyncContribution))
    lightClientPool = newClone(
      LightClientPool())
    exitPool = newClone(
      ExitPool.init(dag, attestationPool, onVoluntaryExitAdded))
    consensusManager = ConsensusManager.new(
      dag, attestationPool, quarantine, node.eth1Monitor,
      ActionTracker.init(rng, config.subscribeAllSubnets),
      node.dynamicFeeRecipientsStore, config.validatorsDir,
      config.defaultFeeRecipient)
    blockProcessor = BlockProcessor.new(
      config.dumpEnabled, config.dumpDirInvalid, config.dumpDirIncoming,
      rng, taskpool, consensusManager, node.validatorMonitor, getBeaconTime,
      optimistic = config.optimistic)
    blockVerifier = proc(signedBlock: ForkedSignedBeaconBlock):
        Future[Result[void, VerifierError]] =
      # The design with a callback for block verification is unusual compared
      # to the rest of the application, but fits with the general approach
      # taken in the sync/request managers - this is an architectural compromise
      # that should probably be reimagined more holistically in the future.
      let resfut = newFuture[Result[void, VerifierError]]("blockVerifier")
      blockProcessor[].addBlock(MsgSource.gossip, signedBlock, resfut)
      resfut
    processor = Eth2Processor.new(
      config.doppelgangerDetection,
      blockProcessor, node.validatorMonitor, dag, attestationPool, exitPool,
      node.attachedValidators, syncCommitteeMsgPool, lightClientPool,
      quarantine, rng, getBeaconTime, taskpool)
    syncManager = newSyncManager[Peer, PeerId](
      node.network.peerPool, SyncQueueKind.Forward, getLocalHeadSlot,
      getLocalWallSlot, getFirstSlotAtFinalizedEpoch, getBackfillSlot,
      getFrontfillSlot, dag.tail.slot, blockVerifier)
    backfiller = newSyncManager[Peer, PeerId](
      node.network.peerPool, SyncQueueKind.Backward, getLocalHeadSlot,
      getLocalWallSlot, getFirstSlotAtFinalizedEpoch, getBackfillSlot,
      getFrontfillSlot, dag.backfill.slot, blockVerifier, maxHeadAge = 0)
    router = (ref MessageRouter)(
      processor: processor,
      network: node.network)

  if node.config.lightClientDataServe:
    proc scheduleSendingLightClientUpdates(slot: Slot) =
      if node.lightClientPool[].broadcastGossipFut != nil:
        return
      if slot <= node.lightClientPool[].latestBroadcastedSlot:
        return
      node.lightClientPool[].latestBroadcastedSlot = slot

      template fut(): auto = node.lightClientPool[].broadcastGossipFut
      fut = node.handleLightClientUpdates(slot)
      fut.addCallback do (p: pointer) {.gcsafe.}:
        fut = nil

    router.onSyncCommitteeMessage = scheduleSendingLightClientUpdates

  dag.setFinalizationCb makeOnFinalizationCb(node.eventBus, node.eth1Monitor)
  dag.setBlockCb(onBlockAdded)
  dag.setHeadCb(onHeadChanged)
  dag.setReorgCb(onChainReorg)

  node.dag = dag
  node.quarantine = quarantine
  node.attestationPool = attestationPool
  node.syncCommitteeMsgPool = syncCommitteeMsgPool
  node.lightClientPool = lightClientPool
  node.exitPool = exitPool
  node.processor = processor
  node.blockProcessor = blockProcessor
  node.consensusManager = consensusManager
  node.requestManager = RequestManager.init(node.network, blockVerifier)
  node.syncManager = syncManager
  node.backfiller = backfiller
  node.router = router

  node.addValidators()

  block:
    # Add in-process validators to the list of "known" validators such that
    # we start with a reasonable ENR
    let wallSlot = node.beaconClock.now().slotOrZero()
    for validator in node.attachedValidators[].validators.values():
      if config.validatorMonitorAuto:
        node.validatorMonitor[].addMonitor(validator.pubkey, validator.index)

      if validator.index.isSome():
        node.consensusManager[].actionTracker.knownValidators[
          validator.index.get()] = wallSlot
    let stabilitySubnets =
      node.consensusManager[].actionTracker.stabilitySubnets(wallSlot)
    # Here, we also set the correct ENR should we be in all subnets mode!
    node.network.updateStabilitySubnetMetadata(stabilitySubnets)

  node.network.initBeaconSync(dag, getBeaconTime)

  node.updateValidatorMetrics()

const SlashingDbName = "slashing_protection"
  # changing this requires physical file rename as well or history is lost.

proc init*(T: type BeaconNode,
           rng: ref HmacDrbgContext,
           config: BeaconNodeConf,
           metadata: Eth2NetworkMetadata): BeaconNode
          {.raises: [Defect, CatchableError].} =
  var taskpool: TaskPoolPtr

  template cfg: auto = metadata.cfg
  template eth1Network: auto = metadata.eth1Network

  try:
    if config.numThreads < 0:
      fatal "The number of threads --numThreads cannot be negative."
      quit 1
    elif config.numThreads == 0:
      taskpool = TaskPoolPtr.new(numThreads = min(countProcessors(), 16))
    else:
      taskpool = TaskPoolPtr.new(numThreads = config.numThreads)

    info "Threadpool started", numThreads = taskpool.numThreads
  except Exception as exc:
    raise newException(Defect, "Failure in taskpool initialization.")

  let
    eventBus = EventBus(
      blocksQueue: newAsyncEventQueue[EventBeaconBlockObject](),
      headQueue: newAsyncEventQueue[HeadChangeInfoObject](),
      reorgQueue: newAsyncEventQueue[ReorgInfoObject](),
      finUpdateQueue: newAsyncEventQueue[altair.LightClientFinalityUpdate](),
      optUpdateQueue: newAsyncEventQueue[altair.LightClientOptimisticUpdate](),
      attestQueue: newAsyncEventQueue[Attestation](),
      contribQueue: newAsyncEventQueue[SignedContributionAndProof](),
      exitQueue: newAsyncEventQueue[SignedVoluntaryExit](),
      finalQueue: newAsyncEventQueue[FinalizationInfoObject]()
    )
    db = BeaconChainDB.new(config.databaseDir, inMemory = false)

  if config.finalizedCheckpointBlock.isSome:
    warn "--finalized-checkpoint-block has been deprecated, ignoring"

  let checkpointState = if config.finalizedCheckpointState.isSome:
    let checkpointStatePath = config.finalizedCheckpointState.get.string
    let tmp = try:
      newClone(readSszForkedHashedBeaconState(
        cfg, readAllBytes(checkpointStatePath).tryGet()))
    except SszError as err:
      fatal "Checkpoint state deserialization failed",
            err = formatMsg(err, checkpointStatePath)
      quit 1
    except CatchableError as err:
      fatal "Failed to read checkpoint state file", err = err.msg
      quit 1

    if not getStateField(tmp[], slot).is_epoch:
      fatal "--finalized-checkpoint-state must point to a state for an epoch slot",
        slot = getStateField(tmp[], slot)
      quit 1
    tmp
  else:
    nil

  let optJwtSecret = rng[].loadJwtSecret(config, allowCreate = false)

  if config.web3Urls.len() == 0:
    notice "Running without execution client - validator features disabled (see https://nimbus.guide/eth1.html)"

  var eth1Monitor: Eth1Monitor

  let genesisState =
    if metadata.genesisData.len > 0:
      try:
        newClone readSszForkedHashedBeaconState(
          cfg,
          metadata.genesisData.toOpenArrayByte(0, metadata.genesisData.high))
      except CatchableError as err:
        raiseAssert "Invalid baked-in state: " & err.msg
    else:
      nil

  if not ChainDAGRef.isInitialized(db).isOk():
    if genesisState == nil and checkpointState == nil:
      when hasGenesisDetection:
        # This is a fresh start without a known genesis state
        # (most likely, it hasn't arrived yet). We'll try to
        # obtain a genesis through the Eth1 deposits monitor:
        if config.web3Urls.len == 0:
          fatal "Web3 URL not specified"
          quit 1

        # TODO Could move this to a separate "GenesisMonitor" process or task
        #      that would do only this - see Paul's proposal for this.
        let eth1Monitor = Eth1Monitor.init(
          cfg,
          metadata.depositContractBlock,
          metadata.depositContractBlockHash,
          db,
          nil,
          config.web3Urls,
          eth1Network,
          config.web3ForcePolling,
          optJwtSecret,
          ttdReached = false)

        eth1Monitor.loadPersistedDeposits()

        let phase0Genesis = waitFor eth1Monitor.waitGenesis()
        genesisState = (ref ForkedHashedBeaconState)(
          kind: BeaconStateFork.Phase0,
          phase0Data:
            (ref phase0.HashedBeaconState)(
              data: phase0Genesis[],
              root: hash_tree_root(phase0Genesis[]))[])

        if bnStatus == BeaconNodeStatus.Stopping:
          return nil

        notice "Eth2 genesis state detected",
          genesisTime = phase0Genesis.genesisTime,
          eth1Block = phase0Genesis.eth1_data.block_hash,
          totalDeposits = phase0Genesis.eth1_data.deposit_count
      else:
        fatal "No database and no genesis snapshot found: supply a genesis.ssz " &
              "with the network configuration, or compile the beacon node with " &
              "the -d:has_genesis_detection option " &
              "in order to support monitoring for genesis events"
        quit 1

    if not genesisState.isNil and not checkpointState.isNil:
      if getStateField(genesisState[], genesis_validators_root) !=
          getStateField(checkpointState[], genesis_validators_root):
        fatal "Checkpoint state does not match genesis - check the --network parameter",
          rootFromGenesis = getStateField(
            genesisState[], genesis_validators_root),
          rootFromCheckpoint = getStateField(
            checkpointState[], genesis_validators_root)
        quit 1

    try:
      # Always store genesis state if we have it - this allows reindexing and
      # answering genesis queries
      if not genesisState.isNil:
        ChainDAGRef.preInit(db, genesisState[])

      if not checkpointState.isNil:
        if genesisState.isNil or
            getStateField(checkpointState[], slot) != GENESIS_SLOT:
          ChainDAGRef.preInit(db, checkpointState[])

      doAssert ChainDAGRef.isInitialized(db).isOk(), "preInit should have initialized db"
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

  let
    validatorMonitor = newClone(ValidatorMonitor.init(
      config.validatorMonitorAuto, config.validatorMonitorTotals))

  for key in config.validatorMonitorPubkeys:
    validatorMonitor[].addMonitor(key, Opt.none(ValidatorIndex))

  let
    networkGenesisValidatorsRoot =
      if not genesisState.isNil:
        Opt.some(getStateField(genesisState[], genesis_validators_root))
      else:
        Opt.none(Eth2Digest)

    dag = loadChainDag(
      config, cfg, db, eventBus,
      validatorMonitor, networkGenesisValidatorsRoot,
      config.deploymentPhase <= DeploymentPhase.Testnet)
    genesisTime = getStateField(dag.headState, genesis_time)
    beaconClock = BeaconClock.init(genesisTime)
    getBeaconTime = beaconClock.getBeaconTimeFn()

  if config.weakSubjectivityCheckpoint.isSome:
    dag.checkWeakSubjectivityCheckpoint(
      config.weakSubjectivityCheckpoint.get, beaconClock)

  if eth1Monitor.isNil and config.web3Urls.len > 0:
    eth1Monitor = Eth1Monitor.init(
      cfg,
      metadata.depositContractBlock,
      metadata.depositContractBlockHash,
      db,
      getBeaconTime,
      config.web3Urls,
      eth1Network,
      config.web3ForcePolling,
      optJwtSecret,
      ttdReached = not dag.loadExecutionBlockRoot(dag.finalizedHead.blck).isZero)

  if config.rpcEnabled.isSome:
    warn "Nimbus's JSON-RPC server has been removed. This includes the --rpc, --rpc-port, and --rpc-address configuration options. https://nimbus.guide/rest-api.html shows how to enable and configure the REST Beacon API server which replaces it."

  let restServer = if config.restEnabled:
    RestServerRef.init(config.restAddress, config.restPort,
                       config.keymanagerAllowedOrigin,
                       validateBeaconApiQueries,
                       config)
  else:
    nil

  let
    netKeys = getPersistentNetKeys(rng[], config)
    nickname = if config.nodeName == "auto": shortForm(netKeys)
               else: config.nodeName
    network = createEth2Node(
      rng, config, netKeys, cfg, dag.forkDigests, getBeaconTime,
      getStateField(dag.headState, genesis_validators_root))

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

  proc getValidatorAndIdx(pubkey: ValidatorPubKey): Opt[ValidatorAndIndex] =
    withState(dag.headState):
      getValidator(forkyState().data.validators.asSeq(), pubkey)

  let
    slashingProtectionDB =
      SlashingProtectionDB.init(
          getStateField(dag.headState, genesis_validators_root),
          config.validatorsDir(), SlashingDbName)
    validatorPool = newClone(ValidatorPool.init(
      slashingProtectionDB, config.doppelgangerDetection))

    keymanagerInitResult = initKeymanagerServer(config, restServer)
    keymanagerHost = if keymanagerInitResult.server != nil:
      newClone KeymanagerHost.init(
        validatorPool,
        rng,
        keymanagerInitResult.token,
        config.validatorsDir,
        config.secretsDir,
        config.defaultFeeRecipient,
        getValidatorAndIdx,
        getBeaconTime)
    else: nil

    stateTtlCache =
      if config.restCacheSize > 0:
        StateTtlCache.init(
          cacheSize = config.restCacheSize,
          cacheTtl = chronos.seconds(config.restCacheTtl))
      else:
        nil

  let payloadBuilderRestClient =
    if config.payloadBuilderEnable:
      RestClientRef.new(config.payloadBuilderUrl).valueOr:
        warn "Payload builder REST client setup failed",
          payloadBuilderUrl = config.payloadBuilderUrl
        nil
    else:
      nil

  let node = BeaconNode(
    nickname: nickname,
    graffitiBytes: if config.graffiti.isSome: config.graffiti.get
                   else: defaultGraffitiBytes(),
    network: network,
    netKeys: netKeys,
    db: db,
    config: config,
    attachedValidators: validatorPool,
    eth1Monitor: eth1Monitor,
    payloadBuilderRestClient: payloadBuilderRestClient,
    restServer: restServer,
    keymanagerHost: keymanagerHost,
    keymanagerServer: keymanagerInitResult.server,
    eventBus: eventBus,
    gossipState: {},
    blocksGossipState: {},
    beaconClock: beaconClock,
    validatorMonitor: validatorMonitor,
    stateTtlCache: stateTtlCache,
    nextExchangeTransitionConfTime:
      # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.1/src/engine/specification.md#specification-3
      # Consensus Layer client software **SHOULD** poll this endpoint every
      # 60 seconds.
      # Delay first call by that time to allow for EL syncing to begin; it can
      # otherwise generate an EL warning by claiming a zero merge block.
      Moment.now + chronos.seconds(60),
    dynamicFeeRecipientsStore: newClone(DynamicFeeRecipientsStore.init()))

  node.initLightClient(
    rng, cfg, dag.forkDigests, getBeaconTime, dag.genesis_validators_root)
  node.initFullNode(
    rng, dag, taskpool, getBeaconTime)

  node.updateLightClientFromDag()

  node

func verifyFinalization(node: BeaconNode, slot: Slot) =
  # Epoch must be >= 4 to check finalization
  const SETTLING_TIME_OFFSET = 1'u64
  let epoch = slot.epoch()

  # Don't static-assert this -- if this isn't called, don't require it
  doAssert SLOTS_PER_EPOCH > SETTLING_TIME_OFFSET

  # Intentionally, loudly assert. Point is to fail visibly and unignorably
  # during testing.
  if epoch >= 4 and slot mod SLOTS_PER_EPOCH > SETTLING_TIME_OFFSET:
    let finalizedEpoch =
      node.dag.finalizedHead.slot.epoch()
    # Finalization rule 234, that has the most lag slots among the cases, sets
    # state.finalized_checkpoint = old_previous_justified_checkpoint.epoch + 3
    # and then state.slot gets incremented, to increase the maximum offset, if
    # finalization occurs every slot, to 4 slots vs scheduledSlot.
    doAssert finalizedEpoch + 4 >= epoch

func subnetLog(v: BitArray): string =
  $toSeq(v.oneIndices())

func forkDigests(node: BeaconNode): auto =
  let forkDigestsArray: array[BeaconStateFork, auto] = [
    node.dag.forkDigests.phase0,
    node.dag.forkDigests.altair,
    node.dag.forkDigests.bellatrix,
    node.dag.forkDigests.capella,
    node.dag.forkDigests.eip4844]
  forkDigestsArray

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.2/specs/phase0/validator.md#phase-0-attestation-subnet-stability
proc updateAttestationSubnetHandlers(node: BeaconNode, slot: Slot) =
  if node.gossipState.card == 0:
    # When disconnected, updateGossipState is responsible for all things
    # subnets - in particular, it will remove subscriptions on the edge where
    # we enter the disconnected state.
    return

  let
    aggregateSubnets =
      node.consensusManager[].actionTracker.aggregateSubnets(slot)
    stabilitySubnets =
      node.consensusManager[].actionTracker.stabilitySubnets(slot)
    subnets = aggregateSubnets + stabilitySubnets

  node.network.updateStabilitySubnetMetadata(stabilitySubnets)

  # Now we know what we should be subscribed to - make it so
  let
    prevSubnets = node.consensusManager[].actionTracker.subscribedSubnets
    unsubscribeSubnets = prevSubnets - subnets
    subscribeSubnets = subnets - prevSubnets

  # Remember what we subscribed to, so we can unsubscribe later
  node.consensusManager[].actionTracker.subscribedSubnets = subnets

  let forkDigests = node.forkDigests()

  for gossipFork in node.gossipState:
    let forkDigest = forkDigests[gossipFork]
    node.network.unsubscribeAttestationSubnets(unsubscribeSubnets, forkDigest)
    node.network.subscribeAttestationSubnets(subscribeSubnets, forkDigest)

  debug "Attestation subnets",
    slot, epoch = slot.epoch, gossipState = node.gossipState,
    stabilitySubnets = subnetLog(stabilitySubnets),
    aggregateSubnets = subnetLog(aggregateSubnets),
    prevSubnets = subnetLog(prevSubnets),
    subscribeSubnets = subnetLog(subscribeSubnets),
    unsubscribeSubnets = subnetLog(unsubscribeSubnets),
    gossipState = node.gossipState

proc updateBlocksGossipStatus*(
    node: BeaconNode, slot: Slot, dagIsBehind: bool) =
  template cfg(): auto = node.dag.cfg

  let
    isBehind =
      if node.shouldSyncOptimistically(slot):
        # If optimistic sync is active, always subscribe to blocks gossip
        false
      else:
        # Use DAG status to determine whether to subscribe for blocks gossip
        dagIsBehind

    targetGossipState = getTargetGossipState(
      slot.epoch, cfg.ALTAIR_FORK_EPOCH, cfg.BELLATRIX_FORK_EPOCH,
      cfg.CAPELLA_FORK_EPOCH, cfg.EIP4844_FORK_EPOCH, isBehind)

  template currentGossipState(): auto = node.blocksGossipState
  if currentGossipState == targetGossipState:
    return

  if currentGossipState.card == 0 and targetGossipState.card > 0:
    debug "Enabling blocks topic subscriptions",
      wallSlot = slot, targetGossipState
  elif currentGossipState.card > 0 and targetGossipState.card == 0:
    debug "Disabling blocks topic subscriptions",
      wallSlot = slot
  else:
    # Individual forks added / removed
    discard

  let
    newGossipForks = targetGossipState - currentGossipState
    oldGossipForks = currentGossipState - targetGossipState

  discard $eip4844ImplementationMissing & ": for EIP4844, https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.1/specs/eip4844/p2p-interface.md#beacon_block notes use beacon_block_and_blobs_sidecar rather than beacon_block"
  for gossipFork in oldGossipForks:
    let forkDigest = node.dag.forkDigests[].atStateFork(gossipFork)
    node.network.unsubscribe(getBeaconBlocksTopic(forkDigest))

  for gossipFork in newGossipForks:
    let forkDigest = node.dag.forkDigests[].atStateFork(gossipFork)
    node.network.subscribe(
      getBeaconBlocksTopic(forkDigest), blocksTopicParams,
      enableTopicMetrics = true)

  node.blocksGossipState = targetGossipState

proc addPhase0MessageHandlers(
    node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.network.subscribe(getAttesterSlashingsTopic(forkDigest), basicParams)
  node.network.subscribe(getProposerSlashingsTopic(forkDigest), basicParams)
  node.network.subscribe(getVoluntaryExitsTopic(forkDigest), basicParams)
  node.network.subscribe(
    getAggregateAndProofsTopic(forkDigest), aggregateTopicParams,
    enableTopicMetrics = true)

  # updateAttestationSubnetHandlers subscribes attestation subnets

proc removePhase0MessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  node.network.unsubscribe(getVoluntaryExitsTopic(forkDigest))
  node.network.unsubscribe(getProposerSlashingsTopic(forkDigest))
  node.network.unsubscribe(getAttesterSlashingsTopic(forkDigest))
  node.network.unsubscribe(getAggregateAndProofsTopic(forkDigest))

  for subnet_id in SubnetId:
    node.network.unsubscribe(getAttestationTopic(forkDigest, subnet_id))

  node.consensusManager[].actionTracker.subscribedSubnets = default(AttnetBits)

func hasSyncPubKey(node: BeaconNode, epoch: Epoch): auto =
  # Only used to determine which gossip topics to which to subscribe
  if node.config.subscribeAllSubnets:
    (func(pubkey: ValidatorPubKey): bool {.closure.} = true)
  else:
    (func(pubkey: ValidatorPubKey): bool =
      node.consensusManager[].actionTracker.hasSyncDuty(pubkey, epoch) or
         pubkey in node.attachedValidators[].validators)

func getCurrentSyncCommiteeSubnets(node: BeaconNode, epoch: Epoch): SyncnetBits =
  let syncCommittee = withState(node.dag.headState):
    when stateFork >= BeaconStateFork.Altair:
      forkyState.data.current_sync_committee
    else:
      return static(default(SyncnetBits))

  getSyncSubnets(node.hasSyncPubKey(epoch), syncCommittee)

func getNextSyncCommitteeSubnets(node: BeaconNode, epoch: Epoch): SyncnetBits =
  let syncCommittee = withState(node.dag.headState):
    when stateFork >= BeaconStateFork.Altair:
      forkyState.data.next_sync_committee
    else:
      return static(default(SyncnetBits))

  getSyncSubnets(
    node.hasSyncPubKey((epoch.sync_committee_period + 1).start_slot().epoch),
    syncCommittee)

func getSyncCommitteeSubnets(node: BeaconNode, epoch: Epoch): SyncnetBits =
  let
    subnets = node.getCurrentSyncCommiteeSubnets(epoch)
    epochsToSyncPeriod = nearSyncCommitteePeriod(epoch)

  # The end-slot tracker might call this when it's theoretically applicable,
  # but more than SYNC_COMMITTEE_SUBNET_COUNT epochs from when the next sync
  # committee period begins, in which case `epochsToNextSyncPeriod` is none.
  if  epochsToSyncPeriod.isNone or
      node.dag.cfg.stateForkAtEpoch(epoch + epochsToSyncPeriod.get) <
        BeaconStateFork.Altair:
    return subnets

  subnets + node.getNextSyncCommitteeSubnets(epoch)

proc addAltairMessageHandlers(
    node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.addPhase0MessageHandlers(forkDigest, slot)

  # If this comes online near sync committee period, it'll immediately get
  # replaced as usual by trackSyncCommitteeTopics, which runs at slot end.
  let syncnets = node.getSyncCommitteeSubnets(slot.epoch)

  for subcommitteeIdx in SyncSubcommitteeIndex:
    if syncnets[subcommitteeIdx]:
      node.network.subscribe(
        getSyncCommitteeTopic(forkDigest, subcommitteeIdx), basicParams)

  node.network.subscribe(
    getSyncCommitteeContributionAndProofTopic(forkDigest), basicParams)

  node.network.updateSyncnetsMetadata(syncnets)

proc addCapellaMessageHandlers(
    node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.addAltairMessageHandlers(forkDigest, slot)
  node.network.subscribe(getBlsToExecutionChangeTopic(forkDigest), basicParams)

proc removeAltairMessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  node.removePhase0MessageHandlers(forkDigest)

  for subcommitteeIdx in SyncSubcommitteeIndex:
    closureScope:
      let idx = subcommitteeIdx
      node.network.unsubscribe(getSyncCommitteeTopic(forkDigest, idx))

  node.network.unsubscribe(
    getSyncCommitteeContributionAndProofTopic(forkDigest))

proc removeCapellaMessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  node.removeAltairMessageHandlers(forkDigest)
  node.network.unsubscribe(getBlsToExecutionChangeTopic(forkDigest))

proc updateSyncCommitteeTopics(node: BeaconNode, slot: Slot) =
  template lastSyncUpdate: untyped =
    node.consensusManager[].actionTracker.lastSyncUpdate
  if lastSyncUpdate == Opt.some(slot.sync_committee_period()) and
      nearSyncCommitteePeriod(slot.epoch).isNone():
    # No need to update unless we're close to the next sync committee period or
    # new validators were registered with the action tracker
    # TODO we _could_ skip running this in some of the "near" slots, but..
    return

  lastSyncUpdate = Opt.some(slot.sync_committee_period())

  let syncnets = node.getSyncCommitteeSubnets(slot.epoch)

  debug "Updating sync committee subnets",
    syncnets,
    metadata_syncnets = node.network.metadata.syncnets,
    gossipState = node.gossipState

  # Assume that different gossip fork sync committee setups are in sync; this
  # only remains relevant, currently, for one gossip transition epoch, so the
  # consequences of this not being true aren't exceptionally dire, while this
  # allows for bookkeeping simplication.
  if syncnets == node.network.metadata.syncnets:
    return

  let
    newSyncnets =
      syncnets - node.network.metadata.syncnets
    oldSyncnets =
      node.network.metadata.syncnets - syncnets
    forkDigests = node.forkDigests()

  for subcommitteeIdx in SyncSubcommitteeIndex:
    doAssert not (newSyncnets[subcommitteeIdx] and
                  oldSyncnets[subcommitteeIdx])
    for gossipFork in node.gossipState:
      template topic(): auto =
        getSyncCommitteeTopic(forkDigests[gossipFork], subcommitteeIdx)
      if oldSyncnets[subcommitteeIdx]:
        node.network.unsubscribe(topic)
      elif newSyncnets[subcommitteeIdx]:
        node.network.subscribe(topic, basicParams)

  node.network.updateSyncnetsMetadata(syncnets)

proc updateDoppelganger(node: BeaconNode, epoch: Epoch) =
  if not node.processor[].doppelgangerDetectionEnabled:
    return

  # broadcastStartEpoch is set to FAR_FUTURE_EPOCH when we're not monitoring
  # gossip - it is only viable to assert liveness in epochs where gossip is
  # active
  if epoch > node.processor[].doppelgangerDetection.broadcastStartEpoch:
    for validator in node.attachedValidators[]:
      validator.updateDoppelganger(epoch - 1)

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
    isBehind =
      headDistance > TOPIC_SUBSCRIBE_THRESHOLD_SLOTS + HYSTERESIS_BUFFER
    targetGossipState =
      getTargetGossipState(
        slot.epoch,
        node.dag.cfg.ALTAIR_FORK_EPOCH,
        node.dag.cfg.BELLATRIX_FORK_EPOCH,
        node.dag.cfg.CAPELLA_FORK_EPOCH,
        node.dag.cfg.EIP4844_FORK_EPOCH,
        isBehind)

  doAssert targetGossipState.card <= 2

  let
    newGossipForks = targetGossipState - node.gossipState
    oldGossipForks = node.gossipState - targetGossipState

  doAssert newGossipForks.card <= 2
  doAssert oldGossipForks.card <= 2

  func maxGossipFork(gossipState: GossipState): int =
    var res = -1
    for gossipFork in gossipState:
      res = max(res, gossipFork.int)
    res

  if  maxGossipFork(targetGossipState) < maxGossipFork(node.gossipState) and
      targetGossipState != {}:
    warn "Unexpected clock regression during transition",
      targetGossipState,
      gossipState = node.gossipState

  if node.gossipState.card == 0 and targetGossipState.card > 0:
    # We are synced, so we will connect
    debug "Enabling topic subscriptions",
      wallSlot = slot,
      headSlot = head.slot,
      headDistance, targetGossipState

    node.processor[].setupDoppelgangerDetection(slot)

    # Specially when waiting for genesis, we'll already be synced on startup -
    # it might also happen on a sufficiently fast restart

    # We "know" the actions for the current and the next epoch
    withState(node.dag.headState):
      if node.consensusManager[].actionTracker.needsUpdate(
          forkyState, slot.epoch):
        let epochRef = node.dag.getEpochRef(head, slot.epoch, false).expect(
          "Getting head EpochRef should never fail")
        node.consensusManager[].actionTracker.updateActions(epochRef)

      if node.consensusManager[].actionTracker.needsUpdate(
          forkyState, slot.epoch + 1):
        let epochRef = node.dag.getEpochRef(head, slot.epoch + 1, false).expect(
          "Getting head EpochRef should never fail")
        node.consensusManager[].actionTracker.updateActions(epochRef)

  if node.gossipState.card > 0 and targetGossipState.card == 0:
    debug "Disabling topic subscriptions",
      wallSlot = slot,
      headSlot = head.slot,
      headDistance

    node.processor[].clearDoppelgangerProtection()

  let forkDigests = node.forkDigests()

  const removeMessageHandlers: array[BeaconStateFork, auto] = [
    removePhase0MessageHandlers,
    removeAltairMessageHandlers,
    removeAltairMessageHandlers,  # bellatrix (altair handlers, with different forkDigest)
    removeCapellaMessageHandlers,
    removeCapellaMessageHandlers  # eip4844 (capella handlers, different forkDigest)
  ]

  for gossipFork in oldGossipForks:
    removeMessageHandlers[gossipFork](node, forkDigests[gossipFork])

  const addMessageHandlers: array[BeaconStateFork, auto] = [
    addPhase0MessageHandlers,
    addAltairMessageHandlers,
    addAltairMessageHandlers,  # bellatrix (altair handlers, with different forkDigest)
    addCapellaMessageHandlers,
    addCapellaMessageHandlers  # eip4844 (capella handlers, different forkDigest)
  ]

  for gossipFork in newGossipForks:
    addMessageHandlers[gossipFork](node, forkDigests[gossipFork], slot)

  node.gossipState = targetGossipState
  node.updateDoppelganger(slot.epoch)
  node.updateAttestationSubnetHandlers(slot)
  node.updateBlocksGossipStatus(slot, isBehind)
  node.updateLightClientGossipStatus(slot, isBehind)

proc onSlotEnd(node: BeaconNode, slot: Slot) {.async.} =
  # Things we do when slot processing has ended and we're about to wait for the
  # next slot

  if node.dag.needStateCachesAndForkChoicePruning():
    if node.attachedValidators[].validators.len > 0:
      node.attachedValidators[]
          .slashingProtection
          # pruning is only done if the DB is set to pruning mode.
          .pruneAfterFinalization(
            node.dag.finalizedHead.slot.epoch()
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
    try:
      GC_fullCollect()
    except Defect as exc:
      raise exc # Reraise to maintain call stack
    except Exception as exc:
      # TODO upstream
      raiseAssert "Unexpected exception during GC collection"

  # Checkpoint the database to clear the WAL file and make sure changes in
  # the database are synced with the filesystem.
  node.db.checkpoint()

  node.syncCommitteeMsgPool[].pruneData(slot)
  if slot.is_epoch:
    node.dynamicFeeRecipientsStore[].pruneOldMappings(slot.epoch)

  # Update upcoming actions - we do this every slot in case a reorg happens
  let head = node.dag.head
  if node.isSynced(head) == SyncStatus.synced:
    withState(node.dag.headState):
      if node.consensusManager[].actionTracker.needsUpdate(
          forkyState, slot.epoch + 1):
        let epochRef = node.dag.getEpochRef(head, slot.epoch + 1, false).expect(
          "Getting head EpochRef should never fail")
        node.consensusManager[].actionTracker.updateActions(epochRef)

  let
    nextAttestationSlot =
      node.consensusManager[].actionTracker.getNextAttestationSlot(slot)
    nextProposalSlot =
      node.consensusManager[].actionTracker.getNextProposalSlot(slot)
    nextActionWaitTime = saturate(fromNow(
      node.beaconClock, min(nextAttestationSlot, nextProposalSlot)))

  # -1 is a more useful output than 18446744073709551615 as an indicator of
  # no future attestation/proposal known.
  template formatInt64(x: Slot): int64 =
    if x == high(uint64).Slot:
      -1'i64
    else:
      toGaugeValue(x)

  template formatSyncCommitteeStatus(): string =
    let slotsToNextSyncCommitteePeriod =
      SLOTS_PER_SYNC_COMMITTEE_PERIOD - since_sync_committee_period_start(slot)

    # int64 conversion is safe
    doAssert slotsToNextSyncCommitteePeriod <= SLOTS_PER_SYNC_COMMITTEE_PERIOD

    if not node.getCurrentSyncCommiteeSubnets(slot.epoch).isZeros:
      "current"
    elif not node.getNextSyncCommitteeSubnets(slot.epoch).isZeros:
      "in " & toTimeLeftString(
        SECONDS_PER_SLOT.int64.seconds * slotsToNextSyncCommitteePeriod.int64)
    else:
      "none"

  info "Slot end",
    slot = shortLog(slot),
    nextActionWait =
      if nextAttestationSlot == FAR_FUTURE_SLOT:
        "n/a"
      else:
        shortLog(nextActionWaitTime),
    nextAttestationSlot = formatInt64(nextAttestationSlot),
    nextProposalSlot = formatInt64(nextProposalSlot),
    syncCommitteeDuties = formatSyncCommitteeStatus(),
    head = shortLog(head)

  if nextAttestationSlot != FAR_FUTURE_SLOT:
    next_action_wait.set(nextActionWaitTime.toFloatSeconds)

  let epoch = slot.epoch
  if epoch + 1 >= node.network.forkId.next_fork_epoch:
    # Update 1 epoch early to block non-fork-ready peers
    node.network.updateForkId(epoch, node.dag.genesis_validators_root)

  # When we're not behind schedule, we'll speculatively update the clearance
  # state in anticipation of receiving the next block - we do it after logging
  # slot end since the nextActionWaitTime can be short
  let
    advanceCutoff = node.beaconClock.fromNow(
      slot.start_beacon_time() + chronos.seconds(int(SECONDS_PER_SLOT - 1)))
  if advanceCutoff.inFuture:
    # We wait until there's only a second left before the next slot begins, then
    # we advance the clearance state to the next slot - this gives us a high
    # probability of being prepared for the block that will arrive and the
    # epoch processing that follows
    await sleepAsync(advanceCutoff.offset)
    node.dag.advanceClearanceState()

  # Prepare action tracker for the next slot
  node.consensusManager[].actionTracker.updateSlot(slot + 1)

  # The last thing we do is to perform the subscriptions and unsubscriptions for
  # the next slot, just before that slot starts - because of the advance cuttoff
  # above, this will be done just before the next slot starts
  node.updateSyncCommitteeTopics(slot + 1)

  await node.updateGossipStatus(slot + 1)

func syncStatus(node: BeaconNode, wallSlot: Slot): string =
  let optimistic_head = node.dag.is_optimistic(node.dag.head.root)
  if node.syncManager.inProgress:
    let
      optimisticSuffix =
        if optimistic_head:
          "/opt"
        else:
          ""
      lightClientSuffix =
        if node.consensusManager[].shouldSyncOptimistically(wallSlot):
          " - lc: " & $shortLog(node.consensusManager[].optimisticHead)
        else:
          ""
    node.syncManager.syncStatus & optimisticSuffix & lightClientSuffix
  elif node.backfiller.inProgress:
    "backfill: " & node.backfiller.syncStatus
  elif optimistic_head:
    "synced/opt"
  else:
    "synced"

proc onSlotStart(node: BeaconNode, wallTime: BeaconTime,
                 lastSlot: Slot): Future[bool] {.async.} =
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
    finalizedEpoch = node.dag.finalizedHead.blck.slot.epoch()
    delay = wallTime - expectedSlot.start_beacon_time()

  info "Slot start",
    slot = shortLog(wallSlot),
    epoch = shortLog(wallSlot.epoch),
    sync = node.syncStatus(wallSlot),
    peers = len(node.network.peerPool),
    head = shortLog(node.dag.head),
    finalized = shortLog(getStateField(
      node.dag.headState, finalized_checkpoint)),
    delay = shortLog(delay)

  # Check before any re-scheduling of onSlotStart()
  if checkIfShouldStopAtEpoch(wallSlot, node.config.stopAtEpoch):
    quit(0)

  when defined(windows):
    if node.config.runAsService:
      reportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0)

  beacon_slot.set wallSlot.toGaugeValue
  beacon_current_epoch.set wallSlot.epoch.toGaugeValue

  # both non-negative, so difference can't overflow or underflow int64
  finalization_delay.set(
    wallSlot.epoch.toGaugeValue - finalizedEpoch.toGaugeValue)

  if node.config.strictVerification:
    verifyFinalization(node, wallSlot)

  node.consensusManager[].updateHead(wallSlot)

  await node.handleValidatorDuties(lastSlot, wallSlot)

  await onSlotEnd(node, wallSlot)

  # https://github.com/ethereum/builder-specs/blob/v0.2.0/specs/validator.md#registration-dissemination
  # This specification suggests validators re-submit to builder software every
  # `EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION` epochs.
  if  wallSlot.is_epoch and
      wallSlot.epoch mod EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION == 0:
    asyncSpawn node.registerValidators(wallSlot.epoch)

  return false

proc handleMissingBlocks(node: BeaconNode) =
  let missingBlocks = node.quarantine[].checkMissing()
  if missingBlocks.len > 0:
    debug "Requesting detected missing blocks", blocks = shortLog(missingBlocks)
    node.requestManager.fetchAncestorBlocks(missingBlocks)

proc onSecond(node: BeaconNode, time: Moment) =
  ## This procedure will be called once per second.
  if not(node.syncManager.inProgress):
    node.handleMissingBlocks()

  # Nim GC metrics (for the main thread)
  updateThreadMetrics()

  if time >= node.nextExchangeTransitionConfTime and not node.eth1Monitor.isNil:
    # The EL client SHOULD log a warning when not receiving an exchange message
    # at least once every 120 seconds. If we only attempt to exchange every 60
    # seconds, the warning would be triggered if a single message is missed.
    # To accommodate for that, exchange slightly more frequently.
    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.1/src/engine/specification.md#engine_exchangetransitionconfigurationv1
    node.nextExchangeTransitionConfTime = time + chronos.seconds(45)

    if node.currentSlot.epoch >= node.dag.cfg.BELLATRIX_FORK_EPOCH:
      traceAsyncErrors node.eth1Monitor.exchangeTransitionConfiguration()

  if node.config.stopAtSyncedEpoch != 0 and
      node.dag.head.slot.epoch >= node.config.stopAtSyncedEpoch:
    notice "Shutting down after having reached the target synced epoch"
    bnStatus = BeaconNodeStatus.Stopping

proc runOnSecondLoop(node: BeaconNode) {.async.} =
  const
    sleepTime = chronos.seconds(1)
    nanosecondsIn1s = float(sleepTime.nanoseconds)
  while true:
    let start = chronos.now(chronos.Moment)
    await chronos.sleepAsync(sleepTime)
    let afterSleep = chronos.now(chronos.Moment)
    let sleepTime = afterSleep - start
    node.onSecond(start)
    let finished = chronos.now(chronos.Moment)
    let processingTime = finished - afterSleep
    ticks_delay.set(sleepTime.nanoseconds.float / nanosecondsIn1s)
    trace "onSecond task completed", sleepTime, processingTime

func connectedPeersCount(node: BeaconNode): int =
  len(node.network.peerPool)

proc installRestHandlers(restServer: RestServerRef, node: BeaconNode) =
  restServer.router.installBeaconApiHandlers(node)
  restServer.router.installConfigApiHandlers(node)
  restServer.router.installDebugApiHandlers(node)
  restServer.router.installEventApiHandlers(node)
  restServer.router.installNimbusApiHandlers(node)
  restServer.router.installNodeApiHandlers(node)
  restServer.router.installValidatorApiHandlers(node)
  if node.dag.lcDataStore.serve:
    restServer.router.installLightClientApiHandlers(node)

from ./spec/datatypes/capella import SignedBeaconBlock

proc installMessageValidators(node: BeaconNode) =
  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.2/specs/phase0/p2p-interface.md#attestations-and-aggregation
  # These validators stay around the whole time, regardless of which specific
  # subnets are subscribed to during any given epoch.
  let forkDigests = node.dag.forkDigests

  template installBeaconBlocksValidator(digest: auto, phase: auto) =
    node.network.addValidator(
      getBeaconBlocksTopic(digest),
      proc (signedBlock: phase.SignedBeaconBlock): ValidationResult =
        if node.shouldSyncOptimistically(node.currentSlot):
          toValidationResult(
            node.optimisticProcessor.processSignedBeaconBlock(signedBlock))
        else:
          toValidationResult(node.processor[].processSignedBeaconBlock(
            MsgSource.gossip, signedBlock)))


  installBeaconBlocksValidator(forkDigests.phase0, phase0)
  installBeaconBlocksValidator(forkDigests.altair, altair)
  installBeaconBlocksValidator(forkDigests.bellatrix, bellatrix)
  installBeaconBlocksValidator(forkDigests.capella, capella)

  node.network.addValidator(
    getBeaconBlockAndBlobsSidecarTopic(forkDigests.eip4844),
    proc (signedBlock: eip4844.SignedBeaconBlockAndBlobsSidecar): ValidationResult =
      # todo: take into account node.shouldSyncOptimistically(node.currentSlot)
        toValidationResult(node.processor[].processSignedBeaconBlockAndBlobsSidecar(
          MsgSource.gossip, signedBlock)))

  template installPhase0Validators(digest: auto) =
    for it in SubnetId:
      closureScope:
        let subnet_id = it
        node.network.addAsyncValidator(
          getAttestationTopic(digest, subnet_id),
          # This proc needs to be within closureScope; don't lift out of loop.
          proc(attestation: Attestation): Future[ValidationResult] {.async.} =
            return toValidationResult(
              await node.processor.processAttestation(
                MsgSource.gossip, attestation, subnet_id)))

    node.network.addAsyncValidator(
      getAggregateAndProofsTopic(digest),
      proc(signedAggregateAndProof: SignedAggregateAndProof):
          Future[ValidationResult] {.async.} =
        return toValidationResult(
          await node.processor.processSignedAggregateAndProof(
            MsgSource.gossip, signedAggregateAndProof, false)))

    node.network.addValidator(
      getAttesterSlashingsTopic(digest),
      proc (attesterSlashing: AttesterSlashing): ValidationResult =
        toValidationResult(
          node.processor[].processAttesterSlashing(
            MsgSource.gossip, attesterSlashing)))

    node.network.addValidator(
      getProposerSlashingsTopic(digest),
      proc (proposerSlashing: ProposerSlashing): ValidationResult =
        toValidationResult(
          node.processor[].processProposerSlashing(
            MsgSource.gossip, proposerSlashing)))

    node.network.addValidator(
      getVoluntaryExitsTopic(digest),
      proc (signedVoluntaryExit: SignedVoluntaryExit): ValidationResult =
        toValidationResult(
          node.processor[].processSignedVoluntaryExit(
            MsgSource.gossip, signedVoluntaryExit)))

  installPhase0Validators(forkDigests.phase0)

  # Validators introduced in phase0 are also used in Altair and Bellatrix, but
  # with different fork digests
  installPhase0Validators(forkDigests.altair)
  installPhase0Validators(forkDigests.bellatrix)
  installPhase0Validators(forkDigests.capella)
  installPhase0Validators(forkDigests.eip4844)

  template installSyncCommitteeeValidators(digest: auto) =
    for subcommitteeIdx in SyncSubcommitteeIndex:
      closureScope:
        let idx = subcommitteeIdx
        node.network.addAsyncValidator(
          getSyncCommitteeTopic(digest, idx),
          # This proc needs to be within closureScope; don't lift out of loop.
          proc(msg: SyncCommitteeMessage): Future[ValidationResult] {.async.} =
            return toValidationResult(
              await node.processor.processSyncCommitteeMessage(
                MsgSource.gossip, msg, idx)))

    node.network.addAsyncValidator(
      getSyncCommitteeContributionAndProofTopic(digest),
      proc(msg: SignedContributionAndProof): Future[ValidationResult] {.async.} =
        return toValidationResult(
          await node.processor.processSignedContributionAndProof(
            MsgSource.gossip, msg)))

  installSyncCommitteeeValidators(forkDigests.altair)
  installSyncCommitteeeValidators(forkDigests.bellatrix)
  installSyncCommitteeeValidators(forkDigests.capella)
  installSyncCommitteeeValidators(forkDigests.eip4844)

  node.installLightClientMessageValidators()

proc stop(node: BeaconNode) =
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

  node.attachedValidators[].slashingProtection.close()
  node.attachedValidators[].close()
  node.db.close()
  notice "Databases closed"

proc startBackfillTask(node: BeaconNode) {.async.} =
  while node.dag.needsBackfill:
    if not node.syncManager.inProgress:
      # Only start the backfiller if it's needed _and_ head sync has completed -
      # if we lose sync after having synced head, we could stop the backfilller,
      # but this should be a fringe case - might as well keep the logic simple for
      # now
      node.backfiller.start()
      return

    await sleepAsync(chronos.seconds(2))

proc run(node: BeaconNode) {.raises: [Defect, CatchableError].} =
  bnStatus = BeaconNodeStatus.Running

  if not isNil(node.restServer):
    node.restServer.installRestHandlers(node)
    node.restServer.start()

  if not isNil(node.keymanagerServer):
    doAssert not isNil(node.keymanagerHost)
    node.keymanagerServer.router.installKeymanagerHandlers(node.keymanagerHost[])
    if node.keymanagerServer != node.restServer:
      node.keymanagerServer.start()

  let
    wallTime = node.beaconClock.now()
    wallSlot = wallTime.slotOrZero()

  node.startLightClient()
  node.requestManager.start()
  node.syncManager.start()

  if node.dag.needsBackfill(): asyncSpawn node.startBackfillTask()

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
    c_signal(ansi_c.SIGTERM, SIGTERMHandler)

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

proc start*(node: BeaconNode) {.raises: [Defect, CatchableError].} =
  let
    head = node.dag.head
    finalizedHead = node.dag.finalizedHead
    genesisTime = node.beaconClock.fromNow(start_beacon_time(Slot 0))

  notice "Starting beacon node",
    version = fullVersionStr,
    nimVersion = NimVersion,
    enr = node.network.announcedENR.toURI,
    peerId = $node.network.switch.peerInfo.peerId,
    timeSinceFinalization =
      node.beaconClock.now() - finalizedHead.slot.start_beacon_time(),
    head = shortLog(head),
    justified = shortLog(getStateField(
      node.dag.headState, current_justified_checkpoint)),
    finalized = shortLog(getStateField(
      node.dag.headState, finalized_checkpoint)),
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

when not defined(windows):
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
          node.dag.headState, current_justified_checkpoint).epoch)
      # TODO:
      # We should introduce a general API for resolving dot expressions
      # such as `db.latest_block.slot` or `metrics.connected_peers`.
      # Such an API can be shared between the RPC back-end, CLI tools
      # such as ncli, a potential GraphQL back-end and so on.
      # The status bar feature would allow the user to specify an
      # arbitrary expression that is resolvable through this API.
      case expr.toLowerAscii
      of "version":
        versionAsStr

      of "full_version":
        fullVersionStr

      of "connected_peers":
        $(node.connectedPeersCount)

      of "head_root":
        shortLog(node.dag.head.root)
      of "head_epoch":
        $(node.dag.head.slot.epoch)
      of "head_epoch_slot":
        $(node.dag.head.slot.since_epoch_start)
      of "head_slot":
        $(node.dag.head.slot)

      of "justifed_root":
        shortLog(justified.blck.root)
      of "justifed_epoch":
        $(justified.slot.epoch)
      of "justifed_epoch_slot":
        $(justified.slot.since_epoch_start)
      of "justifed_slot":
        $(justified.slot)

      of "finalized_root":
        shortLog(node.dag.finalizedHead.blck.root)
      of "finalized_epoch":
        $(node.dag.finalizedHead.slot.epoch)
      of "finalized_epoch_slot":
        $(node.dag.finalizedHead.slot.since_epoch_start)
      of "finalized_slot":
        $(node.dag.finalizedHead.slot)

      of "epoch":
        $node.currentSlot.epoch

      of "epoch_slot":
        $(node.currentSlot.since_epoch_start)

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
        node.syncStatus(node.currentSlot)
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

proc doRunBeaconNode(config: var BeaconNodeConf, rng: ref HmacDrbgContext) {.raises: [Defect, CatchableError].} =
  info "Launching beacon node",
      version = fullVersionStr,
      bls_backend = $BLS_BACKEND,
      cmdParams = commandLineParams(),
      config

  template ignoreDeprecatedOption(option: untyped): untyped =
    if config.option.isSome:
      warn "Config option is deprecated",
        option = config.option.get
  ignoreDeprecatedOption requireEngineAPI
  ignoreDeprecatedOption safeSlotsToImportOptimistically
  ignoreDeprecatedOption terminalTotalDifficultyOverride

  createPidFile(config.dataDir.string / "beacon_node.pid")

  config.createDumpDirs()

  if config.metricsEnabled:
    let metricsAddress = config.metricsAddress
    notice "Starting metrics HTTP server",
      url = "http://" & $metricsAddress & ":" & $config.metricsPort & "/metrics"
    try:
      startMetricsHttpServer($metricsAddress, config.metricsPort)
    except CatchableError as exc:
      raise exc
    except Exception as exc:
      raiseAssert exc.msg # TODO fix metrics

  # Nim GC metrics (for the main thread) will be collected in onSecond(), but
  # we disable piggy-backing on other metrics here.
  setSystemMetricsAutomaticUpdate(false)

  # There are no managed event loops in here, to do a graceful shutdown, but
  # letting the default Ctrl+C handler exit is safe, since we only read from
  # the db.
  let metadata = config.loadEth2Network()

  # Updating the config based on the metadata certainly is not beautiful but it
  # works
  for node in metadata.bootstrapNodes:
    config.bootstrapNodes.add node

  let node = BeaconNode.init(rng, config, metadata)

  if bnStatus == BeaconNodeStatus.Stopping:
    return

  when not defined(windows):
    # This status bar can lock a Windows terminal emulator, blocking the whole
    # event loop (seen on Windows 10, with a default MSYS2 terminal).
    initStatusBar(node)

  if node.nickname != "":
    dynamicLogScope(node = node.nickname): node.start()
  else:
    node.start()

proc doCreateTestnet*(config: BeaconNodeConf, rng: var HmacDrbgContext) {.raises: [Defect, CatchableError].} =
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
               else: (waitFor getEth1BlockHash(
                 config.web3Urls[0], blockId("latest"),
                 rng.loadJwtSecret(config, allowCreate = true))).asEth2Digest
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
    type MetaData = altair.MetaData
    let
      networkKeys = getPersistentNetKeys(rng, config)

      netMetadata = MetaData()
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

proc doRecord(config: BeaconNodeConf, rng: var HmacDrbgContext) {.
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

proc doWeb3Cmd(config: BeaconNodeConf, rng: var HmacDrbgContext)
    {.raises: [Defect, CatchableError].} =
  case config.web3Cmd:
  of Web3Cmd.test:
    let metadata = config.loadEth2Network()

    waitFor testWeb3Provider(config.web3TestUrl,
                             metadata.cfg.DEPOSIT_CONTRACT_ADDRESS,
                             rng.loadJwtSecret(config, allowCreate = true))

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
    spdir = Json.loadFile(interchange, SPDIR,
                          requireAllFields = true)
  except SerializationError as err:
    writeStackTrace()
    stderr.write $Json & " load issue for file \"", interchange, "\"\n"
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
  case conf.slashingdbCmd
  of SlashProtCmd.`export`:
    conf.doSlashingExport()
  of SlashProtCmd.`import`:
    conf.doSlashingImport()

proc handleStartUpCmd(config: var BeaconNodeConf) {.raises: [Defect, CatchableError].} =
  # Single RNG instance for the application - will be seeded on construction
  # and avoid using system resources (such as urandom) after that
  let rng = keys.newRng()

  case config.cmd
  of BNStartUpCmd.createTestnet: doCreateTestnet(config, rng[])
  of BNStartUpCmd.noCommand: doRunBeaconNode(config, rng)
  of BNStartUpCmd.deposits: doDeposits(config, rng[])
  of BNStartUpCmd.wallets: doWallets(config, rng[])
  of BNStartUpCmd.record: doRecord(config, rng[])
  of BNStartUpCmd.web3: doWeb3Cmd(config, rng[])
  of BNStartUpCmd.slashingdb: doSlashingInterchange(config)
  of BNStartUpCmd.trustedNodeSync:
    let
      network = loadEth2Network(config)
      cfg = network.cfg
      genesis =
        if network.genesisData.len > 0:
          newClone(readSszForkedHashedBeaconState(
            cfg,
            network.genesisData.toOpenArrayByte(0, network.genesisData.high())))
        else: nil

    if config.blockId.isSome():
      error "--blockId option has been removed - use --state-id instead!"
      quit 1

    waitFor doTrustedNodeSync(
      cfg,
      config.databaseDir,
      config.eraDir,
      config.trustedNodeUrl,
      config.stateId,
      config.backfillBlocks,
      config.reindex,
      config.downloadDepositSnapshot,
      genesis)

{.pop.} # TODO moduletests exceptions

when defined(windows):
  proc reportServiceStatus*(dwCurrentState, dwWin32ExitCode, dwWaitHint: DWORD) {.gcsafe.} =
    gSvcStatus.dwCurrentState = dwCurrentState
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode
    gSvcStatus.dwWaitHint = dwWaitHint
    if dwCurrentState == SERVICE_START_PENDING:
      gSvcStatus.dwControlsAccepted = 0
    else:
      gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP

    # TODO
    # We can use non-zero values for the `dwCheckPoint` parameter to report
    # progress during lengthy operations such as start-up and shut down.
    gSvcStatus.dwCheckPoint = 0

    # Report the status of the service to the SCM.
    let status = SetServiceStatus(gSvcStatusHandle, addr gSvcStatus)
    debug "Service status updated", status

  proc serviceControlHandler(dwCtrl: DWORD): WINBOOL {.stdcall.} =
    case dwCtrl
    of SERVICE_CONTROL_STOP:
      # We re reporting that we plan stop the service in 10 seconds
      reportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 10_000)
      bnStatus = BeaconNodeStatus.Stopping
    of SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_CONTINUE:
      warn "The Nimbus service cannot be paused and resimed"
    of SERVICE_CONTROL_INTERROGATE:
      # The default behavior is correct.
      # The service control manager will report our last status.
      discard
    else:
      debug "Service received an unexpected user-defined control message",
            msg = dwCtrl

  proc serviceMainFunction(dwArgc: DWORD, lpszArgv: LPSTR) {.stdcall.} =
    # The service is launched in a fresh thread created by Windows, so
    # we must initialize the Nim GC here
    setupForeignThreadGc()

    gSvcStatusHandle = RegisterServiceCtrlHandler(
      SERVICE_NAME,
      serviceControlHandler)

    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS
    gSvcStatus.dwServiceSpecificExitCode = 0
    reportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0)

    info "Service thread started"

    var config = makeBannerAndConfig(clientId, BeaconNodeConf)
    handleStartUpCmd(config)

    info "Service thread stopped"
    reportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0) # we have to report back when we stopped!

programMain:
  var config = makeBannerAndConfig(clientId, BeaconNodeConf)

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
    c_signal(ansi_c.SIGTERM, exitImmediatelyOnSIGTERM)

  when defined(windows):
    if config.runAsService:
      var dispatchTable = [
        SERVICE_TABLE_ENTRY(lpServiceName: SERVICE_NAME, lpServiceProc: serviceMainFunction),
        SERVICE_TABLE_ENTRY(lpServiceName: nil, lpServiceProc: nil) # last entry must be nil
      ]

      let status = StartServiceCtrlDispatcher(LPSERVICE_TABLE_ENTRY(addr dispatchTable[0]))
      if status == 0:
        fatal "Failed to start Windows service", errorCode = getLastError()
        quit 1
    else:
      handleStartUpCmd(config)
  else:
    handleStartUpCmd(config)
