# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[os, random, sequtils, terminal, times],
  chronos, chronicles, chronicles/chronos_tools,
  metrics, metrics/chronos_httpserver,
  stew/[byteutils, io2],
  eth/p2p/discoveryv5/[enr, random2],
  eth/keys,
  ./consensus_object_pools/vanity_logs/pandas,
  ./rpc/[rest_api, state_ttl_cache],
  ./spec/datatypes/[altair, bellatrix, phase0],
  ./spec/[engine_authentication, weak_subjectivity],
  ./validators/[keystore_management, validator_duties],
  "."/[
    beacon_node, beacon_node_light_client, deposits, interop,
    nimbus_binary_common, statusbar, trusted_node_sync, wallets]

when defined(posix):
  import system/ansi_c

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

template init(T: type RestServerRef,
              ip: ValidIpAddress, port: Port,
              allowedOrigin: Option[string],
              config: BeaconNodeConf): T =
  let address = initTAddress(ip, port)
  let serverFlags = {HttpServerFlags.QueryCommaSeparatedArray,
                     HttpServerFlags.NotifyDisconnect}
  let
    headersTimeout =
      if config.restRequestTimeout == 0:
        chronos.InfiniteDuration
      else:
        seconds(int64(config.restRequestTimeout))
    maxHeadersSize = config.restMaxRequestHeadersSize * 1024
    maxRequestBodySize = config.restMaxRequestBodySize * 1024
  let res = RestServerRef.new(getRouter(allowedOrigin),
                              address, serverFlags = serverFlags,
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

# https://github.com/ethereum/beacon-metrics/blob/master/metrics.md#interop-metrics
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

logScope: topics = "beacnde"

func getPandas(stdoutKind: StdoutLogKind): VanityLogs =
  case stdoutKind
  of StdoutLogKind.Auto: raiseAssert "inadmissable here"
  of StdoutLogKind.Colors:
    VanityLogs(
      onMergeTransitionBlock:          color🐼,
      onFinalizedMergeTransitionBlock: blink🐼)
  of StdoutLogKind.NoColors:
    VanityLogs(
      onMergeTransitionBlock:          mono🐼,
      onFinalizedMergeTransitionBlock: mono🐼)
  of StdoutLogKind.Json, StdoutLogKind.None:
    VanityLogs(
      onMergeTransitionBlock:          (proc() = notice "🐼 Proof of Stake Activated 🐼"),
      onFinalizedMergeTransitionBlock: (proc() = notice "🐼 Proof of Stake Finalized 🐼"))

proc loadChainDag(
    config: BeaconNodeConf,
    cfg: RuntimeConfig,
    db: BeaconChainDB,
    eventBus: EventBus,
    validatorMonitor: ref ValidatorMonitor,
    networkGenesisValidatorsRoot: Option[Eth2Digest],
    shouldEnableTestFeatures: bool): ChainDAGRef =
  info "Loading block DAG from database", path = config.databaseDir

  proc onLightClientFinalityUpdate(data: altair.LightClientFinalityUpdate) =
    eventBus.finUpdateQueue.emit(data)
  proc onLightClientOptimisticUpdate(data: altair.LightClientOptimisticUpdate) =
    eventBus.optUpdateQueue.emit(data)

  let
    extraFlags =
      if shouldEnableTestFeatures: {enableTestFeatures}
      else: {}
    chainDagFlags =
      if config.strictVerification: {strictVerification}
      else: {}
    onLightClientFinalityUpdateCb =
      if config.lightClientDataServe.get: onLightClientFinalityUpdate
      else: nil
    onLightClientOptimisticUpdateCb =
      if config.lightClientDataServe.get: onLightClientOptimisticUpdate
      else: nil
    dag = ChainDAGRef.init(
      cfg, db, validatorMonitor, extraFlags + chainDagFlags, config.eraDir,
      vanityLogs = getPandas(detectTTY(config.logStdout)),
      lcDataConfig = LightClientDataConfig(
        serve: config.lightClientDataServe.get,
        importMode: config.lightClientDataImportMode.get,
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
    dag.frontfill.slot

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
      dag, attestationPool, quarantine, node.eth1Monitor)
    blockProcessor = BlockProcessor.new(
      config.dumpEnabled, config.dumpDirInvalid, config.dumpDirIncoming,
      rng, taskpool, consensusManager, node.validatorMonitor, getBeaconTime,
      config.safeSlotsToImportOptimistically)
    blockVerifier = proc(signedBlock: ForkedSignedBeaconBlock):
        Future[Result[void, BlockError]] =
      # The design with a callback for block verification is unusual compared
      # to the rest of the application, but fits with the general approach
      # taken in the sync/request managers - this is an architectural compromise
      # that should probably be reimagined more holistically in the future.
      let resfut = newFuture[Result[void, BlockError]]("blockVerifier")
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
      network: node.network,
    )

  if node.config.lightClientDataServe.get:
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

  debug "Loading validators", validatorsDir = config.validatorsDir()

  node.addValidators()

  block:
    # Add in-process validators to the list of "known" validators such that
    # we start with a reasonable ENR
    let wallSlot = node.beaconClock.now().slotOrZero()
    for validator in node.attachedValidators[].validators.values():
      if config.validatorMonitorAuto:
        node.validatorMonitor[].addMonitor(validator.pubkey, validator.index)

      if validator.index.isSome():
        node.actionTracker.knownValidators[validator.index.get()] = wallSlot
    let
      stabilitySubnets = node.actionTracker.stabilitySubnets(wallSlot)
    # Here, we also set the correct ENR should we be in all subnets mode!
    node.network.updateStabilitySubnetMetadata(stabilitySubnets)

  node.network.initBeaconSync(dag, getBeaconTime)

  node.updateValidatorMetrics()

const SlashingDbName = "slashing_protection"
  # changing this requires physical file rename as well or history is lost.

proc init*(T: type BeaconNode,
           cfg: RuntimeConfig,
           rng: ref HmacDrbgContext,
           config: BeaconNodeConf,
           depositContractDeployedAt: BlockHashOrNumber,
           eth1Network: Option[Eth1Network],
           genesisStateContents: string,
           depositContractSnapshotContents: string): BeaconNode {.
    raises: [Defect, CatchableError].} =

  var taskpool: TaskPoolPtr

  let depositContractSnapshot = if depositContractSnapshotContents.len > 0:
    try:
      some SSZ.decode(depositContractSnapshotContents, DepositContractSnapshot)
    except CatchableError as err:
      fatal "Invalid deposit contract snapshot", err = err.msg
      quit 1
  else:
    none DepositContractSnapshot

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

  var
    genesisState, checkpointState: ref ForkedHashedBeaconState
    checkpointBlock: ForkedTrustedSignedBeaconBlock

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

    if not getStateField(checkpointState[], slot).is_epoch:
      fatal "--finalized-checkpoint-state must point to a state for an epoch slot",
        slot = getStateField(checkpointState[], slot)
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
        let tmp = readSszForkedSignedBeaconBlock(
          cfg, readAllBytes(checkpointBlockPath).tryGet())
        checkpointBlock = tmp.asTrusted()
      except SszError as err:
        fatal "Invalid checkpoint block", err = err.formatMsg(checkpointBlockPath)
        quit 1
      except IOError as err:
        fatal "Failed to load the checkpoint block", err = err.msg
        quit 1

      if not checkpointBlock.slot.is_epoch:
        fatal "--finalized-checkpoint-block must point to a block for an epoch slot",
          slot = checkpointBlock.slot
        quit 1

  elif config.finalizedCheckpointBlock.isSome:
    # TODO We can download the state from somewhere in the future relying
    #      on the trusted `state_root` appearing in the checkpoint block.
    fatal "--finalized-checkpoint-block cannot be specified without --finalized-checkpoint-state"
    quit 1

  let optJwtSecret = rng[].loadJwtSecret(config, allowCreate = false)

  template getDepositContractSnapshot: auto =
    if depositContractSnapshot.isSome:
      depositContractSnapshot
    elif not cfg.DEPOSIT_CONTRACT_ADDRESS.isZeroMemory:
      let snapshotRes = waitFor createInitialDepositSnapshot(
        cfg.DEPOSIT_CONTRACT_ADDRESS,
        depositContractDeployedAt,
        config.web3Urls[0],
        optJwtSecret)
      if snapshotRes.isErr:
        fatal "Failed to locate the deposit contract deployment block",
              depositContract = cfg.DEPOSIT_CONTRACT_ADDRESS,
              deploymentBlock = $depositContractDeployedAt,
              err = snapshotRes.error
        quit 1
      else:
        some snapshotRes.get
    else:
      none(DepositContractSnapshot)

  if config.web3Urls.len() == 0:
    if cfg.BELLATRIX_FORK_EPOCH == FAR_FUTURE_EPOCH:
      notice "Running without execution client - validator features partially disabled (see https://nimbus.guide/eth1.html)"
    else:
      notice "Running without execution client - validator features disabled (see https://nimbus.guide/eth1.html)"

  var eth1Monitor: Eth1Monitor
  if not ChainDAGRef.isInitialized(db).isOk():
    var
      tailState: ref ForkedHashedBeaconState
      tailBlock: ForkedTrustedSignedBeaconBlock

    if genesisStateContents.len == 0 and checkpointState == nil:
      when hasGenesisDetection:
        if depositContractSnapshotContents.len > 0:
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
        let eth1Monitor = Eth1Monitor.init(
          cfg,
          db,
          nil,
          config.web3Urls,
          getDepositContractSnapshot(),
          eth1Network,
          config.web3ForcePolling,
          optJwtSecret)

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

        tailState = genesisState
        tailBlock = get_initial_beacon_block(genesisState[])

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
    validatorMonitor[].addMonitor(key, none(ValidatorIndex))

  let
    networkGenesisValidatorsRoot: Option[Eth2Digest] =
      if genesisStateContents.len != 0:
        some(extractGenesisValidatorRootFromSnapshot(genesisStateContents))
      else:
        none(Eth2Digest)
    dag = loadChainDag(
      config, cfg, db, eventBus,
      validatorMonitor, networkGenesisValidatorsRoot,
      genesisStateContents.deploymentPhase <= DeploymentPhase.Devnet)
    genesisTime = getStateField(dag.headState, genesis_time)
    beaconClock = BeaconClock.init(genesisTime)
    getBeaconTime = beaconClock.getBeaconTimeFn()

  if config.weakSubjectivityCheckpoint.isSome:
    dag.checkWeakSubjectivityCheckpoint(
      config.weakSubjectivityCheckpoint.get, beaconClock)

  if eth1Monitor.isNil and config.web3Urls.len > 0:
    eth1Monitor = Eth1Monitor.init(
      cfg,
      db,
      getBeaconTime,
      config.web3Urls,
      getDepositContractSnapshot(),
      eth1Network,
      config.web3ForcePolling,
      optJwtSecret)

  if config.rpcEnabled:
    warn "Nimbus's JSON-RPC server has been removed. This includes the --rpc, --rpc-port, and --rpc-address configuration options. https://nimbus.guide/rest-api.html shows how to enable and configure the REST Beacon API server which replaces it."

  let restServer = if config.restEnabled:
    RestServerRef.init(
      config.restAddress,
      config.restPort,
      config.restAllowedOrigin,
      config)
  else:
    nil

  var keymanagerToken: Option[string]
  let keymanagerServer = if config.keymanagerEnabled:
    if config.keymanagerTokenFile.isNone:
      echo "To enable the Keymanager API, you must also specify " &
           "the --keymanager-token-file option."
      quit 1

    let
      tokenFilePath = config.keymanagerTokenFile.get.string
      tokenFileReadRes = readAllChars(tokenFilePath)

    if tokenFileReadRes.isErr:
      fatal "Failed to read the keymanager token file",
            error = $tokenFileReadRes.error
      quit 1

    keymanagerToken = some tokenFileReadRes.value.strip
    if keymanagerToken.get.len == 0:
      fatal "The keymanager token should not be empty", tokenFilePath
      quit 1

    if restServer != nil and
       config.restAddress == config.keymanagerAddress and
       config.restPort == config.keymanagerPort:
      if config.keymanagerAllowedOrigin.isSome and
         config.restAllowedOrigin != config.keymanagerAllowedOrigin:
        fatal "Please specify a separate port for the Keymanager API " &
              "if you want to restrict the origin in a different way " &
              "from the Beacon API"
        quit 1
      restServer
    else:
      RestServerRef.init(
        config.keymanagerAddress,
        config.keymanagerPort,
        config.keymanagerAllowedOrigin,
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

  let
    slashingProtectionDB =
      SlashingProtectionDB.init(
          getStateField(dag.headState, genesis_validators_root),
          config.validatorsDir(), SlashingDbName)
    validatorPool = newClone(ValidatorPool.init(slashingProtectionDB))

    stateTtlCache =
      if config.restCacheSize > 0:
        StateTtlCache.init(
          cacheSize = config.restCacheSize,
          cacheTtl = chronos.seconds(config.restCacheTtl))
      else:
        nil

    maxSecondsInMomentType = Moment.high.epochSeconds
    # If the Bellatrix epoch is above this value, the calculation
    # below will overflow. This happens in practice for networks
    # where the `BELLATRIX_FORK_EPOCH` is not yet specified.
    maxSupportedBellatrixEpoch = (maxSecondsInMomentType.uint64 - genesisTime) div
                                 (SLOTS_PER_EPOCH * SECONDS_PER_SLOT)
    bellatrixEpochTime = if cfg.BELLATRIX_FORK_EPOCH < maxSupportedBellatrixEpoch:
      int64(genesisTime + cfg.BELLATRIX_FORK_EPOCH * SLOTS_PER_EPOCH * SECONDS_PER_SLOT)
    else:
      maxSecondsInMomentType

    nextExchangeTransitionConfTime =
      max(Moment.init(bellatrixEpochTime, Second),
          Moment.now)

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
    restServer: restServer,
    keymanagerServer: keymanagerServer,
    keymanagerToken: keymanagerToken,
    eventBus: eventBus,
    actionTracker: ActionTracker.init(rng, config.subscribeAllSubnets),
    gossipState: {},
    beaconClock: beaconClock,
    validatorMonitor: validatorMonitor,
    stateTtlCache: stateTtlCache,
    nextExchangeTransitionConfTime: nextExchangeTransitionConfTime)

  node.initLightClient(
    rng, cfg, dag.forkDigests, getBeaconTime, dag.genesis_validators_root)
  node.initFullNode(
    rng, dag, taskpool, getBeaconTime)

  node.updateLightClientFromDag()

  node

func strictVerification(node: BeaconNode, slot: Slot) =
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
    node.dag.forkDigests.bellatrix]
  forkDigestsArray

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#phase-0-attestation-subnet-stability
proc updateAttestationSubnetHandlers(node: BeaconNode, slot: Slot) =
  if node.gossipState.card == 0:
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

proc addPhase0MessageHandlers(
    node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.network.subscribe(
    getBeaconBlocksTopic(forkDigest), blocksTopicParams,
    enableTopicMetrics = true)
  node.network.subscribe(getAttesterSlashingsTopic(forkDigest), basicParams)
  node.network.subscribe(getProposerSlashingsTopic(forkDigest), basicParams)
  node.network.subscribe(getVoluntaryExitsTopic(forkDigest), basicParams)
  node.network.subscribe(
    getAggregateAndProofsTopic(forkDigest), aggregateTopicParams,
    enableTopicMetrics = true)

  # updateAttestationSubnetHandlers subscribes attestation subnets

proc removePhase0MessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  node.network.unsubscribe(getBeaconBlocksTopic(forkDigest))
  node.network.unsubscribe(getVoluntaryExitsTopic(forkDigest))
  node.network.unsubscribe(getProposerSlashingsTopic(forkDigest))
  node.network.unsubscribe(getAttesterSlashingsTopic(forkDigest))
  node.network.unsubscribe(getAggregateAndProofsTopic(forkDigest))

  for subnet_id in SubnetId:
    node.network.unsubscribe(getAttestationTopic(forkDigest, subnet_id))

  node.actionTracker.subscribedSubnets = default(AttnetBits)

func hasSyncPubKey(node: BeaconNode, epoch: Epoch): auto =
  # Only used to determine which gossip topics to which to subscribe
  if node.config.subscribeAllSubnets:
    (func(pubkey: ValidatorPubKey): bool {.closure.} = true)
  else:
    (func(pubkey: ValidatorPubKey): bool =
       node.syncCommitteeMsgPool.syncCommitteeSubscriptions.getOrDefault(
           pubkey, GENESIS_EPOCH) >= epoch or
         pubkey in node.attachedValidators.validators)

func getCurrentSyncCommiteeSubnets(node: BeaconNode, slot: Slot): SyncnetBits =
  let syncCommittee = withState(node.dag.headState):
    when stateFork >= BeaconStateFork.Altair:
      state.data.current_sync_committee
    else:
      return static(default(SyncnetBits))

  getSyncSubnets(node.hasSyncPubKey(slot.epoch), syncCommittee)

proc addAltairMessageHandlers(node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.addPhase0MessageHandlers(forkDigest, slot)

  # If this comes online near sync committee period, it'll immediately get
  # replaced as usual by trackSyncCommitteeTopics, which runs at slot end.
  let currentSyncCommitteeSubnets = node.getCurrentSyncCommiteeSubnets(slot)

  for subcommitteeIdx in SyncSubcommitteeIndex:
    if currentSyncCommitteeSubnets[subcommitteeIdx]:
      node.network.subscribe(
        getSyncCommitteeTopic(forkDigest, subcommitteeIdx), basicParams)

  node.network.subscribe(
    getSyncCommitteeContributionAndProofTopic(forkDigest), basicParams)

  node.network.updateSyncnetsMetadata(currentSyncCommitteeSubnets)

proc removeAltairMessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  node.removePhase0MessageHandlers(forkDigest)

  for subcommitteeIdx in SyncSubcommitteeIndex:
    closureScope:
      let idx = subcommitteeIdx
      node.network.unsubscribe(getSyncCommitteeTopic(forkDigest, idx))

  node.network.unsubscribe(
    getSyncCommitteeContributionAndProofTopic(forkDigest))

proc trackCurrentSyncCommitteeTopics(node: BeaconNode, slot: Slot) =
  # Unlike trackNextSyncCommitteeTopics, just snap to the currently correct
  # set of subscriptions, and use current_sync_committee. Furthermore, this
  # is potentially useful at arbitrary times, so don't guard it by checking
  # for epoch alignment.
  let currentSyncCommitteeSubnets = node.getCurrentSyncCommiteeSubnets(slot)

  debug "trackCurrentSyncCommitteeTopics: aligning with sync committee subnets",
    currentSyncCommitteeSubnets,
    metadata_syncnets = node.network.metadata.syncnets,
    gossipState = node.gossipState

  # Assume that different gossip fork sync committee setups are in sync; this
  # only remains relevant, currently, for one gossip transition epoch, so the
  # consequences of this not being true aren't exceptionally dire, while this
  # allows for bookkeeping simplication.
  if currentSyncCommitteeSubnets == node.network.metadata.syncnets:
    return

  let
    newSyncSubnets =
      currentSyncCommitteeSubnets - node.network.metadata.syncnets
    oldSyncSubnets =
      node.network.metadata.syncnets - currentSyncCommitteeSubnets
    forkDigests = node.forkDigests()

  for subcommitteeIdx in SyncSubcommitteeIndex:
    doAssert not (newSyncSubnets[subcommitteeIdx] and
                  oldSyncSubnets[subcommitteeIdx])
    for gossipFork in node.gossipState:
      template topic(): auto =
        getSyncCommitteeTopic(forkDigests[gossipFork], subcommitteeIdx)
      if oldSyncSubnets[subcommitteeIdx]:
        node.network.unsubscribe(topic)
      elif newSyncSubnets[subcommitteeIdx]:
        node.network.subscribe(topic, basicParams)

  node.network.updateSyncnetsMetadata(currentSyncCommitteeSubnets)

func getNextSyncCommitteeSubnets(node: BeaconNode, epoch: Epoch): SyncnetBits =
  let epochsToSyncPeriod = nearSyncCommitteePeriod(epoch)

  # The end-slot tracker might call this when it's theoretically applicable,
  # but more than SYNC_COMMITTEE_SUBNET_COUNT epochs from when the next sync
  # committee period begins, in which case `epochsToNextSyncPeriod` is none.
  if  epochsToSyncPeriod.isNone or
      node.dag.cfg.stateForkAtEpoch(epoch + epochsToSyncPeriod.get) <
        BeaconStateFork.Altair:
    return static(default(SyncnetBits))

  let syncCommittee = withState(node.dag.headState):
    when stateFork >= BeaconStateFork.Altair:
      state.data.next_sync_committee
    else:
      return static(default(SyncnetBits))

  getSyncSubnets(
    node.hasSyncPubKey(epoch + epochsToSyncPeriod.get), syncCommittee)

proc trackNextSyncCommitteeTopics(node: BeaconNode, slot: Slot) =
  let
    epoch = slot.epoch
    epochsToSyncPeriod = nearSyncCommitteePeriod(epoch)

  if  epochsToSyncPeriod.isNone or
      node.dag.cfg.stateForkAtEpoch(epoch + epochsToSyncPeriod.get) <
        BeaconStateFork.Altair:
    return

  # No lookahead required
  if epochsToSyncPeriod.get == 0:
    node.trackCurrentSyncCommitteeTopics(slot)
    return

  let nextSyncCommitteeSubnets = node.getNextSyncCommitteeSubnets(epoch)

  let forkDigests = node.forkDigests()

  var newSubcommittees: SyncnetBits

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/validator.md#sync-committee-subnet-stability
  for subcommitteeIdx in SyncSubcommitteeIndex:
    if  (not node.network.metadata.syncnets[subcommitteeIdx]) and
        nextSyncCommitteeSubnets[subcommitteeIdx] and
        node.syncCommitteeMsgPool[].isEpochLeadTime(epochsToSyncPeriod.get):
      for gossipFork in node.gossipState:
        node.network.subscribe(getSyncCommitteeTopic(
          forkDigests[gossipFork], subcommitteeIdx), basicParams)
      newSubcommittees.setBit(distinctBase(subcommitteeIdx))

  debug "trackNextSyncCommitteeTopics: subscribing to sync committee subnets",
    metadata_syncnets = node.network.metadata.syncnets,
    nextSyncCommitteeSubnets,
    gossipState = node.gossipState,
    epochsToSyncPeriod = epochsToSyncPeriod.get,
    newSubcommittees

  node.network.updateSyncnetsMetadata(
    node.network.metadata.syncnets + newSubcommittees)

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
      if node.actionTracker.needsUpdate(state, slot.epoch):
        let epochRef = node.dag.getEpochRef(head, slot.epoch, false).expect(
          "Getting head EpochRef should never fail")
        node.actionTracker.updateActions(epochRef)

      if node.actionTracker.needsUpdate(state, slot.epoch + 1):
        let epochRef = node.dag.getEpochRef(head, slot.epoch + 1, false).expect(
          "Getting head EpochRef should never fail")
        node.actionTracker.updateActions(epochRef)

  if node.gossipState.card > 0 and targetGossipState.card == 0:
    debug "Disabling topic subscriptions",
      wallSlot = slot,
      headSlot = head.slot,
      headDistance

  let forkDigests = node.forkDigests()

  const removeMessageHandlers: array[BeaconStateFork, auto] = [
    removePhase0MessageHandlers,
    removeAltairMessageHandlers,
    removeAltairMessageHandlers  # with different forkDigest
  ]

  for gossipFork in oldGossipForks:
    removeMessageHandlers[gossipFork](node, forkDigests[gossipFork])

  const addMessageHandlers: array[BeaconStateFork, auto] = [
    addPhase0MessageHandlers,
    addAltairMessageHandlers,
    addAltairMessageHandlers  # with different forkDigest
  ]

  for gossipFork in newGossipForks:
    addMessageHandlers[gossipFork](node, forkDigests[gossipFork], slot)

  node.gossipState = targetGossipState
  node.updateAttestationSubnetHandlers(slot)
  node.updateLightClientGossipStatus(slot, isBehind)

proc onSlotEnd(node: BeaconNode, slot: Slot) {.async.} =
  # Things we do when slot processing has ended and we're about to wait for the
  # next slot

  if node.dag.needStateCachesAndForkChoicePruning():
    if node.attachedValidators.validators.len > 0:
      node.attachedValidators
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
    node.trackNextSyncCommitteeTopics(slot)

  # Update upcoming actions - we do this every slot in case a reorg happens
  let head = node.dag.head
  if node.isSynced(head):
    withState(node.dag.headState):
      if node.actionTracker.needsUpdate(state, slot.epoch + 1):
        let epochRef = node.dag.getEpochRef(head, slot.epoch + 1, false).expect(
          "Getting head EpochRef should never fail")
        node.actionTracker.updateActions(epochRef)

  let
    nextAttestationSlot = node.actionTracker.getNextAttestationSlot(slot)
    nextProposalSlot = node.actionTracker.getNextProposalSlot(slot)
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

    if not node.getCurrentSyncCommiteeSubnets(slot).isZeros:
      "current"
    # if 0 => fallback is getCurrentSyncCommitttee so avoid duplicate effort
    elif since_sync_committee_period_start(slot) > 0 and
         not node.getNextSyncCommitteeSubnets(slot.epoch).isZeros:
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
  node.actionTracker.updateSlot(slot + 1)

  # The last thing we do is to perform the subscriptions and unsubscriptions for
  # the next slot, just before that slot starts - because of the advance cuttoff
  # above, this will be done just before the next slot starts
  await node.updateGossipStatus(slot + 1)

func syncStatus(node: BeaconNode): string =
  if node.syncManager.inProgress:
    node.syncManager.syncStatus
  elif node.backfiller.inProgress:
    "backfill: " & node.backfiller.syncStatus
  elif node.dag.is_optimistic(node.dag.head.root):
    "opt synced"
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
    sync = node.syncStatus(),
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
    strictVerification(node, wallSlot)

  node.consensusManager[].updateHead(wallSlot)

  await node.handleValidatorDuties(lastSlot, wallSlot)

  await onSlotEnd(node, wallSlot)

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

  ## This procedure will be called once per minute.
  # https://github.com/ethereum/execution-apis/blob/v1.0.0-alpha.9/src/engine/specification.md#engine_exchangetransitionconfigurationv1
  if time > node.nextExchangeTransitionConfTime and not node.eth1Monitor.isNil:
    node.nextExchangeTransitionConfTime = time + chronos.minutes(1)
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

proc installMessageValidators(node: BeaconNode) =
  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/phase0/p2p-interface.md#attestations-and-aggregation
  # These validators stay around the whole time, regardless of which specific
  # subnets are subscribed to during any given epoch.
  let forkDigests = node.dag.forkDigests

  node.network.addValidator(
    getBeaconBlocksTopic(forkDigests.phase0),
    proc (signedBlock: phase0.SignedBeaconBlock): ValidationResult =
      toValidationResult(node.processor[].processSignedBeaconBlock(
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

  # Validators introduced in phase0 are also used in altair and merge, but with
  # different fork digest
  installPhase0Validators(forkDigests.altair)
  installPhase0Validators(forkDigests.bellatrix)

  node.network.addValidator(
    getBeaconBlocksTopic(forkDigests.altair),
    proc (signedBlock: altair.SignedBeaconBlock): ValidationResult =
      toValidationResult(node.processor[].processSignedBeaconBlock(
        MsgSource.gossip, signedBlock)))

  node.network.addValidator(
    getBeaconBlocksTopic(forkDigests.bellatrix),
    proc (signedBlock: bellatrix.SignedBeaconBlock): ValidationResult =
      toValidationResult(node.processor[].processSignedBeaconBlock(
        MsgSource.gossip, signedBlock)))

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

  node.attachedValidators.slashingProtection.close()
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

  if not(isNil(node.restServer)):
    node.restServer.installRestHandlers(node)
    node.restServer.start()

  if not(isNil(node.keymanagerServer)):
    node.keymanagerServer.router.installKeymanagerHandlers(node)
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
        node.syncStatus()
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

  var metadata = config.loadEth2Network()

  if config.terminalTotalDifficultyOverride.isSome:
    metadata.cfg.TERMINAL_TOTAL_DIFFICULTY =
      parse(config.terminalTotalDifficultyOverride.get, UInt256, 10)

  # Updating the config based on the metadata certainly is not beautiful but it
  # works
  for node in metadata.bootstrapNodes:
    config.bootstrapNodes.add node

  template applyConfigDefault(field: untyped): untyped =
    if config.`field`.isNone:
      if not metadata.configDefaults.`field`.isZeroMemory:
        info "Applying network config default",
          eth2Network = config.eth2Network,
          `field` = metadata.configDefaults.`field`
      config.`field` = some metadata.configDefaults.`field`

  applyConfigDefault(lightClientEnable)
  applyConfigDefault(lightClientDataServe)
  applyConfigDefault(lightClientDataImportMode)

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
    spdir = Json.loadFile(interchange, SPDIR)
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

    waitFor doTrustedNodeSync(
      cfg,
      config.databaseDir,
      config.trustedNodeUrl,
      config.blockId,
      config.backfillBlocks,
      config.reindex,
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
