# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  system/ansi_c,
  std/[os, random, terminal, times],
  chronos, chronicles,
  metrics, metrics/chronos_httpserver,
  stew/[byteutils, io2],
  kzg4844/kzg,
  eth/enr/enr,
  eth/p2p/discoveryv5/random2,
  ./consensus_object_pools/[
    blockchain_list, column_quarantine, envelope_quarantine,
    execution_payload_pool, partial_column_quarantine,
    payload_attestation_pool],
  ./consensus_object_pools/vanity_logs/vanity_logs,
  ./networking/[topic_params, network_metadata_downloads],
  ./rpc/[rest_api, state_ttl_cache],
  ./el/el_getblobs_service,
  ./spec/[
    engine_authentication, weak_subjectivity, peerdas_helpers, column_map],
  ./sync/[
    sync_protocol, light_client_protocol, sync_overseer, validator_custody],
  ./validators/[keystore_management, beacon_validators],
  ./[
    beacon_node, beacon_node_light_client, buildinfo, deposits, era_db,
    nimbus_binary_common, process_state, statusbar, trusted_node_sync, wallets]

from std/sequtils import filterIt, mapIt, toSeq
#from std/strutils import
from libp2p/protocols/pubsub/gossipsub import
  TopicParams, validateParameters, init
from ./spec/datatypes/deneb import SignedBeaconBlock

logScope: topics = "beacnde"

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

declareGauge next_proposal_wait,
  "Seconds until the next proposal will be sent, or Inf if not known"

declareGauge sync_committee_active,
  "1 if there are current sync committee duties, 0 otherwise"

declareCounter db_checkpoint_seconds,
  "Time spent checkpointing the database to clear the WAL file"

proc readState(
    cfg: RuntimeConfig, bytes: openArray[byte]
): Opt[ref ForkedHashedBeaconState] =
  try:
    ok newClone readSszForkedHashedBeaconState(cfg, bytes)
  except CatchableError as err:
    error "Failed to decode state, check that you're on the same `--network`!",
      size = bytes.len, digest = eth2digest(bytes), err = err.msg
    Opt.none(ref ForkedHashedBeaconState)

proc readFileState(
    cfg: RuntimeConfig, path: string): Opt[ref ForkedHashedBeaconState] =
  ## Read and decode a beacon state from a file path.
  ## Returns nil if file cannot be read, otherwise decodes the SSZ content.
  debug "Reading state", path
  var tmp: seq[byte]
  io2.readFile(path, tmp).isOkOr:
    error "Could not read state", path, err = error.ioErrorMsg
    return Opt.none(ref ForkedHashedBeaconState)

  readState(cfg, tmp)

proc readEraState(
    cfg: RuntimeConfig, file: EraPath): Opt[ref ForkedHashedBeaconState] =
  ## Extract and decode a beacon state from an era file - unlike the helpers in
  ## EraDB, this function does not validate that the era file corresponds to
  ## a particular history, as identified by summaries.
  ##
  ## If the Era file is corrup
  debug "Reading era state", file
  let ef = EraFile.open(file.path, file.era).valueOr:
    error "Could not open era file", file, error
    return Opt.none(ref ForkedHashedBeaconState)

  defer:
    ef.close()

  var tmp: seq[byte]

  ef.getStateSSZ(file.era.start_slot(), tmp).isOkOr:
    fatal "Could not read state, era file corrupt?", file, error
    return Opt.none(ref ForkedHashedBeaconState)

  readState(cfg, tmp)

proc fetchGenesisState(
    metadata: Eth2NetworkMetadata,
    eraDir: string,
    genesisState = none(InputFile),
    genesisStateUrl = none(Uri),
): Future[Opt[ref ForkedHashedBeaconState]] {.async: (raises: [CancelledError]).} =
  ## Load the genesis state from any of the given sources with a preference for
  ## local files (in the case that only an URL/digest pair is baked into the
  ## binary)
  ##
  ## Returns `none` if the era source is broken and `Opt.some nil` when no
  ## genesis state is available.

  if metadata.genesis.kind != BakedIn and genesisState.isSome:
    readFileState(metadata.cfg, genesisState.get().string)
  elif (let eraFile = EraFile.genesis(metadata.cfg, eraDir); eraFile.isSome):
    readEraState(metadata.cfg, eraFile[])
  elif metadata.hasGenesis:
    try:
      if metadata.genesis.kind == BakedInUrl:
        info "Downloading genesis state",
          sourceUrl = $genesisStateUrl.get(metadata.genesis.url)
      ok await metadata.fetchGenesisState(genesisStateUrl)
    except CancelledError as exc:
      raise exc
    except CatchableError as err:
      error "Failed to obtain genesis state",
        source = metadata.genesis.sourceDesc, err = err.msg
      Opt.none(ref ForkedHashedBeaconState)
  else:
    Opt.some default(ref ForkedHashedBeaconState)

proc fetchCheckpointState(
    metadata: Eth2NetworkMetadata, eraDir: string, file: Option[InputFile]
): Opt[ref ForkedHashedBeaconState] =
  ## Load a checkpoint state from file or era database.
  if file.isSome:
    readFileState(metadata.cfg, file.get().string)
  elif (let eraFile = EraFile.latest(metadata.cfg, eraDir); eraFile.isSome):
    readEraState(metadata.cfg, eraFile[])
  else:
    Opt.some default(ref ForkedHashedBeaconState)

proc setupDatabase(
    config: BeaconNodeConf, metadata: Eth2NetworkMetadata
): Future[Opt[BeaconChainDB]] {.async: (raises: [CancelledError]).} =
  # Open the database and initialize it with genesis/checkpoint if it wasn't
  # setup before - fails if the data sources we use are broken
  let db = BeaconChainDB.new(
    config.databaseDir, metadata.cfg, inMemory = false,
    lightClientDataImportBackfill = config.lightClientDataImportBackfill)

  if ChainDAGRef.isInitialized(db).isOk():
    if config.finalizedCheckpointState.isSome:
      error "A database already exists, cannot start from given checkpoint",
        dataDir = config.dataDir
      return Opt.none(BeaconChainDB)
    return ok db

  # We need at least one state to initialize the database - this can be the
  # genesis state which is a special case of a checkpoint state at slot 0.
  #
  # While a checkpoint state from any epoch slot is sufficient for launching
  # the client, we'll try to add the genesis state to the database as well.
  var
    checkpointState = ? fetchCheckpointState(
      metadata, config.eraDir, config.finalizedCheckpointState)
    genesisState =
      if not checkpointState.isNil and checkpointState[].slot == GENESIS_SLOT:
        checkpointState
      else:
        ?await fetchGenesisState(
          metadata, config.eraDir, config.genesisState, config.genesisStateUrl
        )

  if config.externalBeaconApiUrl.isSome():
    # When using an external beacon api, require that the checkpoint state is
    # verified with the light client by always using a verified sync target
    template isGenesisPostAltair: bool =
      metadata.cfg.ALTAIR_FORK_EPOCH == GENESIS_EPOCH
    let syncTarget =
      if config.trustedBlockRoot.isSome:
        Opt.some TrustedNodeSyncTarget.fromTrustedBlockRoot(
          config.trustedBlockRoot.get())
      elif config.trustedStateRoot.isSome:
        Opt.some TrustedNodeSyncTarget.fromStateId(
          config.trustedStateRoot.get().data.to0xHex())
      elif isGenesisPostAltair and not genesisState.isNil:
        # Sync can be bootstrapped from the genesis block root
        let genesisBlockRoot = get_initial_beacon_block(genesisState[]).root
        notice "Neither `--trusted-block-root` nor `--trusted-state-root` " &
          "provided with `--external-beacon-api-url`, " &
          "falling back to genesis block root",
          externalBeaconApiUrl = config.externalBeaconApiUrl.get,
          trustedBlockRoot = config.trustedBlockRoot,
          trustedStateRoot = config.trustedStateRoot,
          genesisBlockRoot = $genesisBlockRoot
        Opt.some TrustedNodeSyncTarget.fromTrustedBlockRoot(genesisBlockRoot)
      else:
        Opt.none TrustedNodeSyncTarget

    if syncTarget.isSome():
      let tmp = await metadata.cfg.fetchCheckpointState(
        config.externalBeaconApiUrl.get(), syncTarget[], genesisState)
      if checkpointState == nil:
        checkpointState = tmp
      elif tmp != nil:
        # Special case: we loaded a checkpoint state (for example from era
        # files) and then the remote beacon api gave us a newer one!
        if tmp[].slot > checkpointState[].slot:
          checkpointState = tmp
      else:
        discard  # Remain on state from era (if any)
    else:
      warn "Ignoring `--external-beacon-api-url`, neither " &
        "`--trusted-block-root` nor `--trusted-state-root` provided",
        externalBeaconApiUrl = config.externalBeaconApiUrl.get,
        trustedBlockRoot = config.trustedBlockRoot,
        trustedStateRoot = config.trustedStateRoot

  if genesisState.isNil and checkpointState.isNil:
    fatal "No database and no genesis snapshot found. " &
      "Please supply a genesis.ssz with the network configuration"
    return Opt.none(BeaconChainDB)

  if not genesisState.isNil and config.longRangeSync == LongRangeSyncMode.Light:
    let
      genesisTime = genesisState[].genesis_time
      beaconClock = BeaconClock.init(metadata.cfg.timeParams, genesisTime).valueOr:
        fatal "Invalid genesis time in genesis state", genesisTime
        return Opt.none(BeaconChainDB)
      currentSlot = beaconClock.currentSlot
      checkpoint = Checkpoint(
        epoch: genesisState[].slot.epoch(),
        root: genesisState[].latest_block_header.state_root,
      )

    if not is_within_weak_subjectivity_period(
      metadata.cfg, currentSlot, genesisState[], checkpoint
    ):
      # We do support any network which starts from Altair or later fork.
      if metadata.cfg.ALTAIR_FORK_EPOCH != GENESIS_EPOCH:
        fatal WeakSubjectivityLogMessage,
          current_slot = currentSlot, altair_fork_epoch = metadata.cfg.ALTAIR_FORK_EPOCH
        return Opt.none(BeaconChainDB)

  if not genesisState.isNil and not checkpointState.isNil:
    if genesisState[].genesis_validators_root != checkpointState[].genesis_validators_root:
      fatal "Checkpoint state does not match genesis - check the --network parameter",
        rootFromGenesis = genesisState[].genesis_validators_root,
        rootFromCheckpoint = checkpointState[].genesis_validators_root
      return Opt.none(BeaconChainDB)

  # Always store genesis state if we have it - this allows reindexing and
  # answering genesis queries
  if not genesisState.isNil:
    ChainDAGRef.preInit(db, genesisState[])

  if not checkpointState.isNil:
    if genesisState.isNil or checkpointState[].slot != genesisState[].slot:
      ChainDAGRef.preInit(db, checkpointState[])

  doAssert ChainDAGRef.isInitialized(db).isOk(), "preInit should have initialized db"

  ok db

proc doRunTrustedNodeSync(
    db: BeaconChainDB,
    metadata: Eth2NetworkMetadata,
    databaseDir: string,
    eraDir: string,
    restUrl: string,
    stateId: Option[string],
    trustedBlockRoot: Option[Eth2Digest],
    backfill: bool,
    reindex: bool,
    genesisState: ref ForkedHashedBeaconState,
) {.async: (raises: [CancelledError], raw: true).} =
  let syncTarget =
    if stateId.isSome:
      if trustedBlockRoot.isSome:
        warn "Ignoring `trustedBlockRoot`, `stateId` is set", stateId, trustedBlockRoot
      TrustedNodeSyncTarget.fromStateId(stateId.get)
    elif trustedBlockRoot.isSome:
      TrustedNodeSyncTarget.fromTrustedBlockRoot(trustedBlockRoot.get)
    else:
      TrustedNodeSyncTarget.fromStateId("finalized")

  db.doTrustedNodeSync(
    metadata.cfg, databaseDir, eraDir, restUrl, syncTarget, backfill, reindex,
    genesisState,
  )

func getVanityLogs(stdoutKind: StdoutLogKind): VanityLogs =
  case stdoutKind
  of StdoutLogKind.Auto: raiseAssert "inadmissable here"
  of StdoutLogKind.Colors:
    VanityLogs(
      onKnownBlsToExecutionChange:     capellaBlink,
      onUpgradeToElectra:              electraColor,
      onKnownCompoundingChange:        electraBlink,
      onUpgradeToFulu:                 fuluColor,
      onBlobParametersUpdate:          fuluColor)
  of StdoutLogKind.NoColors:
    VanityLogs(
      onKnownBlsToExecutionChange:     capellaMono,
      onUpgradeToElectra:              electraMono,
      onKnownCompoundingChange:        electraMono,
      onUpgradeToFulu:                 fuluMono,
      onBlobParametersUpdate:          fuluMono)
  of StdoutLogKind.Json, StdoutLogKind.None:
    VanityLogs(
      onKnownBlsToExecutionChange:
        (proc() = notice "🦉 BLS to execution changed 🦉"),
      onUpgradeToElectra:
        (proc() = notice "🦒 Compounding is available 🦒"),
      onKnownCompoundingChange:
        (proc() = notice "🦒 Compounding is activated 🦒"),
      onUpgradeToFulu:
        (proc() = notice "🐅 Blobs columnized 🐅"),
      onBlobParametersUpdate:
        (proc() = notice "🐅 Blob parameters updated 🐅"))

func getVanityMascot(consensusFork: ConsensusFork): string =
  debugGloasComment "don't know vanity mascot yet"
  case consensusFork
  of ConsensusFork.Heze:
    "?"
  of ConsensusFork.Gloas:
    "?"
  of ConsensusFork.Fulu:
    "🐅"
  of ConsensusFork.Electra:
    "🦒"
  of ConsensusFork.Deneb:
    "🐟"
  of ConsensusFork.Capella:
    "🦉"
  of ConsensusFork.Bellatrix:
    "🐼"
  of ConsensusFork.Altair:
    "✨"
  of ConsensusFork.Phase0:
    "🦏"

proc loadChainDag(
    config: BeaconNodeConf,
    cfg: RuntimeConfig,
    db: BeaconChainDB,
    eventBus: EventBus,
    validatorMonitor: ref ValidatorMonitor,
    networkGenesisValidatorsRoot: Opt[Eth2Digest]): ChainDAGRef =
  info "Loading block DAG from database", path = config.databaseDir

  var dag: ChainDAGRef
  proc onLightClientFinalityUpdate(data: ForkedLightClientFinalityUpdate) =
    if dag == nil: return
    withForkyFinalityUpdate(data):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyFinalityUpdate.contextEpoch
          contextFork = dag.cfg.consensusForkAtEpoch(contextEpoch)
          contextBytes = dag.forkDigestAtEpoch(contextEpoch)
        eventBus.finUpdateQueue.emit(
          RestVersioned[ForkedLightClientFinalityUpdate](
            data: data, jsonVersion: contextFork, sszContext: contextBytes))
  proc onLightClientOptimisticUpdate(data: ForkedLightClientOptimisticUpdate) =
    if dag == nil: return
    withForkyOptimisticUpdate(data):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyOptimisticUpdate.contextEpoch
          contextFork = dag.cfg.consensusForkAtEpoch(contextEpoch)
          contextBytes = dag.forkDigestAtEpoch(contextEpoch)
        eventBus.optUpdateQueue.emit(
          RestVersioned[ForkedLightClientOptimisticUpdate](
            data: data, jsonVersion: contextFork, sszContext: contextBytes))

  let
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
    cfg, db, validatorMonitor, chainDagFlags,
    config.eraDir, config.invalidBlockRoots,
    vanityLogs = getVanityLogs(detectTTY(config.logFormat)),
    lcDataConfig = LightClientDataConfig(
      serve: config.lightClientDataServe,
      importMode: config.lightClientDataImportMode,
      importBackfill: config.lightClientDataImportBackfill,
      maxPeriods: config.lightClientDataMaxPeriods,
      onLightClientFinalityUpdate: onLightClientFinalityUpdateCb,
      onLightClientOptimisticUpdate: onLightClientOptimisticUpdateCb))

  if networkGenesisValidatorsRoot.isSome:
    let databaseGenesisValidatorsRoot = dag.headState.genesis_validators_root
    if networkGenesisValidatorsRoot.get != databaseGenesisValidatorsRoot:
      fatal "The specified --data-dir contains data for a different network",
            networkGenesisValidatorsRoot = networkGenesisValidatorsRoot.get,
            databaseGenesisValidatorsRoot,
            dataDir = config.dataDir
      quit 1

  # The first pruning after restart may take a while..
  if config.historyMode == HistoryMode.Prune:
    dag.pruneHistory(true)

  dag

proc checkWeakSubjectivityCheckpoint(
    dag: ChainDAGRef,
    wsCheckpoint: Checkpoint,
    beaconClock: BeaconClock) =
  let
    currentSlot = beaconClock.currentSlot
    isCheckpointStale = not is_within_weak_subjectivity_period(
      dag.cfg, currentSlot, dag.headState, wsCheckpoint)

  if isCheckpointStale:
    error "Weak subjectivity checkpoint is stale",
          currentSlot, checkpoint = wsCheckpoint,
          headStateSlot = dag.headState.slot
    quit 1

from ./spec/state_transition_block import kzg_commitment_to_versioned_hash

func isSlotWithinWeakSubjectivityPeriod(dag: ChainDAGRef, slot: Slot): bool =
  let
    checkpoint = Checkpoint(
      epoch: dag.headState.slot.epoch(),
      root: dag.headState.latest_block_header.state_root)
  is_within_weak_subjectivity_period(dag.cfg, slot,
                                     dag.headState, checkpoint)

proc initFullNode(
    node: BeaconNode,
    rng: ref HmacDrbgContext,
    dag: ChainDAGRef,
    clist: ChainListRef,
    taskpool: Taskpool,
    getBeaconTime: GetBeaconTimeFn,
) {.async: (raises: [CancelledError]).} =
  template config(): auto = node.config

  proc onSingleAttestationReceived(data: SingleAttestation) =
    node.eventBus.singleAttestQueue.emit(data)
  proc onSyncContribution(data: SignedContributionAndProof) =
    node.eventBus.contribQueue.emit(data)
  proc onVoluntaryExitAdded(data: SignedVoluntaryExit) =
    node.eventBus.exitQueue.emit(data)
  proc onBLSToExecutionChangeAdded(data: SignedBLSToExecutionChange) =
    node.eventBus.blsToExecQueue.emit(data)
  proc onProposerSlashingAdded(data: ProposerSlashing) =
    node.eventBus.propSlashQueue.emit(data)
  proc onAttesterSlashingAdded(data: electra.AttesterSlashing) =
    node.eventBus.attSlashQueue.emit(data)
  proc onColumnSidecarAdded(data: DataColumnSidecarInfoObject) =
    node.eventBus.columnSidecarQueue.emit(data)
  proc onFuluColumnSidecarAdded(data: ref fulu.DataColumnSidecar) =
    node.eventBus.columnSidecarFullQueue.emit(data)
  proc onBlockAdded(data: ForkedTrustedSignedBeaconBlock) =
    let optimistic =
      if node.currentSlot().epoch() >= dag.cfg.BELLATRIX_FORK_EPOCH:
        Opt.some node.dag.is_optimistic(data.toBlockId())
      else:
        Opt.none(bool)
    node.eventBus.blocksQueue.emit(
      EventBeaconBlockObject.init(data, optimistic))
  proc onBlockGossipAdded(data: ForkedSignedBeaconBlock) =
    node.eventBus.blockGossipQueue.emit(
      EventBeaconBlockGossipObject.init(data))
  proc onHeadChanged(data: HeadChangeInfoObject) =
    let eventData =
      if node.currentSlot().epoch() >= dag.cfg.BELLATRIX_FORK_EPOCH:
        var res = data
        res.optimistic = Opt.some node.dag.is_optimistic(
          BlockId(slot: data.slot, root: data.block_root))
        res
      else:
        data
    node.eventBus.headQueue.emit(eventData)
  proc onChainReorg(data: ReorgInfoObject) =
    let eventData =
      if node.currentSlot().epoch() >= dag.cfg.BELLATRIX_FORK_EPOCH:
        var res = data
        res.optimistic = Opt.some node.dag.is_optimistic(
          BlockId(slot: data.slot, root: data.new_head_block))
        res
      else:
        data
    node.eventBus.reorgQueue.emit(eventData)
  proc onFastConfirmation(data: FastConfirmationInfoObject) =
    node.eventBus.fastConfirmationQueue.emit(data)
  proc onEnvelopeAdded(data: SignedExecutionPayloadEnvelope) =
    let optimistic = node.dag.is_optimistic(BlockId(
      root: data.message.beacon_block_root,
      slot: data.message.slot))
    node.eventBus.execPayloadAddedQueue.emit(
      EventExecutionPayloadObject.init(data, optimistic))
  proc onEnvelopeGossipAdded(data: SignedExecutionPayloadEnvelope) =
    node.eventBus.execPayloadGossipAddedQueue.emit(
      EventExecutionPayloadGossipObject.init(data))
  proc onEnvelopeAvailable(data: SignedExecutionPayloadEnvelope) =
    node.eventBus.execPayloadAvlQueue.emit(
      EventExecutionPayloadAvailableObject.init(data))
  proc makeOnFinalizationCb(
      # This `nimcall` functions helps for keeping track of what
      # needs to be captured by the onFinalization closure.
      eventBus: EventBus,
      elManager: ELManager): OnFinalizedCallback {.nimcall.} =
    static: doAssert (elManager is ref)
    return proc(dag: ChainDAGRef, data: FinalizationInfoObject) =
      node.updateLightClientFromDag()
      let eventData =
        if node.currentSlot().epoch() >= dag.cfg.BELLATRIX_FORK_EPOCH:
          var res = data
          # `slot` in this `BlockId` may be higher than block's actual slot,
          # this is alright for the purpose of calling `is_optimistic`.
          res.optimistic = Opt.some node.dag.is_optimistic(
            BlockId(slot: data.epoch.start_slot, root: data.block_root))
          res
        else:
          data
      eventBus.finalQueue.emit(eventData)

  func getLocalHeadSlot(): Slot =
    dag.head.slot

  proc getLocalWallSlot(): Slot =
    node.currentSlot

  func getFirstSlotAtFinalizedEpoch(): Slot =
    dag.finalizedHead.slot

  func getBackfillSlot(): Slot =
    if dag.backfill.parent_root != dag.tail.root:
      dag.backfill.slot
    else:
      dag.tail.slot

  func getUntrustedBackfillSlot(): Slot =
    if clist.tail.isSome():
      clist.tail.get().blck.slot
    else:
      dag.tail.slot

  func getFrontfillSlot(): Slot =
    max(dag.frontfill.get(BlockId()).slot, dag.horizon)

  proc isWithinWeakSubjectivityPeriod(): bool =
    isSlotWithinWeakSubjectivityPeriod(node.dag, node.currentSlot)

  proc forkAtEpoch(epoch: Epoch): ConsensusFork =
    consensusForkAtEpoch(dag.cfg, epoch)

  proc eventWaiter(): Future[void] {.async: (raises: [CancelledError]).} =
    await node.shutdownEvent.wait()
    ProcessState.scheduleStop("shutdownEvent")

  asyncSpawn eventWaiter()

  let
    quarantine = newClone(
      Quarantine.init(dag.cfg))
    envelopeQuarantine = newClone(EnvelopeQuarantine.init())
    attestationPool = newClone(AttestationPool.init(
      dag, quarantine, getBeaconTime(), onSingleAttestationReceived))
    syncCommitteeMsgPool = newClone(
      SyncCommitteeMsgPool.init(rng, dag.cfg, onSyncContribution))
    lightClientPool = newClone(
      LightClientPool())
    validatorChangePool = newClone(ValidatorChangePool.init(
      dag, attestationPool, onVoluntaryExitAdded, onBLSToExecutionChangeAdded,
      onProposerSlashingAdded, onAttesterSlashingAdded))
    executionPayloadBidPool = newClone(ExecutionPayloadBidPool.init(dag))
    payloadAttestationPool = newClone(PayloadAttestationPool.init(dag))
    validatorCustody = ValidatorCustodyRef.init(
      node.config, node.network, dag, node.attachedValidatorBalanceTotal)

  let
    fuluColumnQuarantine = newClone(FuluColumnQuarantine.init(
      dag.cfg, validatorCustody.getMap(), dag.db.getQuarantineDB(), 10,
      onColumnSidecarAdded, onFuluColumnSidecarAdded))
    gloasColumnQuarantine = newClone(GloasColumnQuarantine.init(
      dag.cfg, validatorCustody.getMap(), dag.db.getQuarantineDB(), 10,
      onColumnSidecarAdded))
    partialColumnQuarantine = newClone(FuluPartialColumnQuarantine.init())

  validatorCustody.setQuarantine(fuluColumnQuarantine)
  validatorCustody.setQuarantine(gloasColumnQuarantine)

  let
    consensusManager = ConsensusManager.new(
      dag, attestationPool, quarantine, node.elManager,
      ActionTracker.init(node.network.nodeId, config.subscribeAllSubnets),
      node.dynamicFeeRecipientsStore, config.validatorsDir,
      config.defaultFeeRecipient, config.suggestedGasLimit)
    batchVerifier = BatchVerifier.new(rng, taskpool)
    blockProcessor = BlockProcessor.new(
      config.dumpEnabled, config.dumpDirInvalid, config.dumpDirIncoming,
      batchVerifier, consensusManager, node.validatorMonitor,
      fuluColumnQuarantine, gloasColumnQuarantine,
      envelopeQuarantine, getBeaconTime, config.invalidBlockRoots)
    blockVerifier = proc(signedBlock: ForkedSignedBeaconBlock,
                         blobs: Opt[BlobSidecars], maybeFinalized: bool):
        Future[Result[void, VerifierError]] {.async: (raises: [CancelledError], raw: true).} =
      withBlck(signedBlock):
        when consensusFork in ConsensusFork.Fulu .. ConsensusFork.Heze:
          # TODO document why there are no columns here
          when consensusFork >= ConsensusFork.Gloas:
            # Disable sidecars processing at block time.
            const sidecarsOpt = noSidecars
          else:
            let sidecarsOpt = Opt.none(fulu.DataColumnSidecars)
        elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Electra:
          const sidecarsOpt = noSidecars
        else:
          {.error: "Unkown fork: " & $consensusFork.}

        blockProcessor.addBlock(
          MsgSource.gossip, forkyBlck, sidecarsOpt, maybeFinalized)

    untrustedBlockVerifier =
      proc(signedBlock: ForkedSignedBeaconBlock, blobs: Opt[BlobSidecars],
           maybeFinalized: bool): Future[Result[void, VerifierError]] {.
        async: (raises: [CancelledError], raw: true).} =
        clist.untrustedBackfillVerifier(signedBlock, blobs, maybeFinalized)
    rmanBlockVerifier = proc(signedBlock: ForkedSignedBeaconBlock,
                             maybeFinalized: bool):
        Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
      withBlck(signedBlock):
        when consensusFork >= ConsensusFork.Gloas:
          # Disable sidecars processing at block time.
          const sidecarsOpt = noSidecars
        elif consensusFork == ConsensusFork.Fulu:
          let sidecarsOpt =
            if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
              Opt.some(default(fulu.DataColumnSidecars))
            else:
              fuluColumnQuarantine[].popSidecars(forkyBlck.root)
          if sidecarsOpt.isNone():
            # We don't have all the columns for this block, so we have
            # to put it in columnless quarantine.
            return
              if not quarantine[].addSidecarless(dag.finalizedHead.slot, forkyBlck):
                err(VerifierError.UnviableFork)
              else:
                err(VerifierError.MissingParent)
        elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Electra:
          const sidecarsOpt = noSidecars
        else:
          {.error: "Unkown fork: " & $consensusFork.}

        await blockProcessor.addBlock(
          MsgSource.sync, forkyBlck, sidecarsOpt, maybeFinalized
        )
    rmanBlockLoader = proc(
        blockRoot: Eth2Digest): Opt[ForkedTrustedSignedBeaconBlock] =
      dag.getForkedBlock(blockRoot)
    rmanEnvelopeVerifier = proc(signedEnvelope: gloas.SignedExecutionPayloadEnvelope):
        Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
      ## Envelope verifier contains the same logic as block_processor
      ## enqueuePayload() except when the valid block or any sidecars is
      ## missing, we will return ok() as it is not any types of VerifierError.
      ## Therefore, the call is discarded silently.
      envelopeQuarantine[].addOrphan(dag.finalizedHead.slot, signedEnvelope)
      template blockRoot(): auto = signedEnvelope.message.beacon_block_root

      let
        blockRef = dag.getBlockRef(blockRoot).valueOr:
          # Return ok() as we may not have the block yet.
          return ok()
        blck =
          block:
            let forkedBlock = dag.getForkedBlock(blockRef.bid).valueOr:
              # We have checked that the block exists in the chain. There might be
              # issues in reading the database or data in the memory is broken.
              # Since no result is returned, we log for investigation.
              debug "Enqueue payload from envelope. Block is missing in DB",
                bid = shortLog(blockRef.bid)
              return err(VerifierError.Invalid)
            withBlck(forkedBlock):
              when consensusFork == ConsensusFork.Heze:
                debugHezeComment "..."
                return err(VerifierError.Duplicate)
              elif consensusFork == ConsensusFork.Gloas:
                forkyBlck.asSigned()
              else:
                # Incorrect fork which shouldn't be happening.
                debug "Enqueue payload from envelope. Block is in incorrect fork",
                  bid = shortLog(blockRef.bid)
                return err(VerifierError.UnviableFork)
        envelope = envelopeQuarantine[].popOrphan(blck).valueOr:
          # At this point, the signedEnvelope is from a different builder since
          # the block should be the source of truth. We should notify receiving
          # bad value from the peer.
          return err(VerifierError.Invalid)
        sidecarsOpt =
          block:
            template bid(): auto =
              blck.message.body.signed_execution_payload_bid
            let sidecarsOpt =
              if bid.message.blob_kzg_commitments.len() == 0:
                Opt.some(default(gloas.DataColumnSidecars))
              else:
                gloasColumnQuarantine[].popSidecars(blockRoot)
            if sidecarsOpt.isNone():
              # As sidecars are missing, put envelope back to quarantine.
              consensusManager.quarantine[].addSidecarless(blck)
              envelopeQuarantine[].addOrphan(dag.finalizedHead.slot, envelope)
              # Return ok() as columns may arrive late.
              return ok()
            sidecarsOpt
      await blockProcessor.addPayload(blck, envelope, sidecarsOpt)
    rmanEnvelopeLoader = proc(blockRoot: Eth2Digest):
        Opt[gloas.TrustedSignedExecutionPayloadEnvelope] =
      dag.db.getExecutionPayloadEnvelope(blockRoot)
    rmanDataColumnLoader = proc(
        columnId: DataColumnIdentifier): Opt[ref fulu.DataColumnSidecar] =
      var data_column_sidecar = fulu.DataColumnSidecar.new()
      if dag.db.getDataColumnSidecar(columnId.block_root, columnId.index, data_column_sidecar[]):
        Opt.some data_column_sidecar
      else:
        Opt.none(ref fulu.DataColumnSidecar)
    rmanGloasDataColumnLoader = proc(
        columnId: DataColumnIdentifier): Opt[ref gloas.DataColumnSidecar] =
      var data_column_sidecar = gloas.DataColumnSidecar.new()
      if dag.db.getDataColumnSidecar(
          columnId.block_root, columnId.index, data_column_sidecar[]):
        Opt.some data_column_sidecar
      else:
        Opt.none(ref gloas.DataColumnSidecar)

    processor = Eth2Processor.new(
      config.doppelgangerDetection,
      blockProcessor, node.validatorMonitor, dag, attestationPool,
      validatorChangePool, node.attachedValidators, syncCommitteeMsgPool,
      lightClientPool, executionPayloadBidPool, payloadAttestationPool,
      quarantine, fuluColumnQuarantine, gloasColumnQuarantine,
      envelopeQuarantine, rng, getBeaconTime, taskpool)
    syncManagerFlags =
      if node.config.longRangeSync != LongRangeSyncMode.Lenient:
        {SyncManagerFlag.NoGenesisSync}
      else:
        {}
    syncManager = newSyncManager[Peer, PeerId](
      node.network.peerPool,
      SyncQueueKind.Forward, getLocalHeadSlot,
      getLocalWallSlot, getFirstSlotAtFinalizedEpoch, getBackfillSlot,
      getFrontfillSlot, isWithinWeakSubjectivityPeriod,
      dag.tail.slot, blockVerifier, forkAtEpoch,
      shutdownEvent = node.shutdownEvent,
      flags = syncManagerFlags)
    backfiller = newSyncManager[Peer, PeerId](
      node.network.peerPool,
      SyncQueueKind.Backward, getLocalHeadSlot,
      getLocalWallSlot, getFirstSlotAtFinalizedEpoch, getBackfillSlot,
      getFrontfillSlot, isWithinWeakSubjectivityPeriod,
      dag.backfill.slot, blockVerifier, forkAtEpoch, maxHeadAge = 0,
      shutdownEvent = node.shutdownEvent,
      flags = syncManagerFlags)
    clistPivotSlot =
      if clist.tail.isSome():
        clist.tail.get().blck.slot()
      else:
        getLocalWallSlot()
    eaSlot = dag.head.slot
    untrustedManager = newSyncManager[Peer, PeerId](
      node.network.peerPool,
      SyncQueueKind.Backward, getLocalHeadSlot,
      getLocalWallSlot, getFirstSlotAtFinalizedEpoch, getUntrustedBackfillSlot,
      getFrontfillSlot, isWithinWeakSubjectivityPeriod,
      clistPivotSlot, untrustedBlockVerifier, forkAtEpoch, maxHeadAge = 0,
      shutdownEvent = node.shutdownEvent,
      flags = syncManagerFlags)
    router = (ref MessageRouter)(
      processor: processor,
      network: node.network)
    requestManager = RequestManager.init(
      node.network, validatorCustody,
      dag.cfg.DENEB_FORK_EPOCH, getBeaconTime,
      (proc(): bool = syncManager.inProgress),
      quarantine, envelopeQuarantine,
      fuluColumnQuarantine, gloasColumnQuarantine, rmanBlockVerifier,
      rmanBlockLoader, rmanEnvelopeVerifier, rmanEnvelopeLoader,
      rmanDataColumnLoader, rmanGloasDataColumnLoader)

  # As per EIP 7594, the BN is now categorised into a
  # `Fullnode` and a `Supernode`, the fullnodes custodies a
  # given set of data columns, and hence ONLY subcribes to those
  # data column subnet topics, however, the supernodes subscribe
  # to all of the topics. This in turn keeps our `data column quarantine`
  # really variable. Whenever the BN is a supernode, column quarantine
  # essentially means all the NUMBER_OF_COLUMNS, as per mentioned in the
  # spec. However, in terms of fullnode, quarantine is really dependent
  # on the randomly assigned columns, by `resolve_columns_from_custody_groups`.

  # Hence, in order to keep column quarantine accurate and error proof
  # the custody columns are computed once as the BN boots. Then the values
  # are used globally around the codebase.

  # `resolve_columns_from_custody_groups` is not a very expensive function,
  # but there are multiple instances of computing custody columns, especially
  # during peer selection, sync with columns, and so on. That is why,
  # the rationale of populating it at boot and using it gloabally.

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

  dag.setFinalizationCb makeOnFinalizationCb(node.eventBus, node.elManager)
  dag.setBlockCb(onBlockAdded)
  dag.setBlockGossipCb(onBlockGossipAdded)
  dag.setHeadCb(onHeadChanged)
  dag.setReorgCb(onChainReorg)
  dag.setFastConfirmationCb(onFastConfirmation)
  dag.setEnvelopeCb(onEnvelopeAdded)
  dag.setEnvelopeGossipCb(onEnvelopeGossipAdded)
  dag.setEnvelopeAvailableCb(onEnvelopeAvailable)

  node.dag = dag
  node.dag.eaSlot = eaSlot
  node.list = clist
  node.fuluColumnQuarantine = fuluColumnQuarantine
  node.quarantine = quarantine
  node.attestationPool = attestationPool
  node.syncCommitteeMsgPool = syncCommitteeMsgPool
  node.lightClientPool = lightClientPool
  node.validatorChangePool = validatorChangePool
  node.processor = processor
  node.executionPayloadBidPool = executionPayloadBidPool
  node.payloadAttestationPool = payloadAttestationPool
  node.batchVerifier = batchVerifier
  node.blockProcessor = blockProcessor
  node.consensusManager = consensusManager
  node.requestManager = requestManager
  node.validatorCustody = validatorCustody
  node.syncManager = syncManager
  node.backfiller = backfiller
  node.untrustedManager = untrustedManager
  node.syncOverseer = SyncOverseerRef.new(node.consensusManager,
                                          node.validatorMonitor,
                                          config,
                                          getBeaconTime,
                                          node.list,
                                          node.beaconClock,
                                          node.eventBus.optFinHeaderUpdateQueue,
                                          node.network.peerPool,
                                          node.batchVerifier,
                                          syncManager, backfiller,
                                          untrustedManager)
  node.getBlobsService = GetBlobsServiceRef.new(node.eventBus.blockGossipPeerQueue,
                                                node.eventBus.columnSidecarFullQueue,
                                                node.blockProcessor,
                                                node.fuluColumnQuarantine,
                                                gloasColumnQuarantine,
                                                partialColumnQuarantine,
                                                config.partialColumns,
                                                node.validatorCustody,
                                                node.network)
  node.router = router

  await node.addValidators()

  block:
    # Add in-process validators to the list of "known" validators such that
    # we start with a reasonable ENR
    let wallSlot = node.currentSlot
    for validator in node.attachedValidators[].validators.values():
      if config.validatorMonitorAuto:
        node.validatorMonitor[].addMonitor(validator.pubkey, validator.index)

      if validator.index.isSome():
        withState(dag.headState):
          let idx = validator.index.get()
          if distinctBase(idx) <= forkyState.data.validators.lenu64:
            template v: auto = forkyState.data.validators.item(idx)
            if  is_active_validator(v, wallSlot.epoch) or
                is_active_validator(v, wallSlot.epoch + 1):
              node.consensusManager[].actionTracker.knownValidators[idx] = wallSlot
            elif is_exited_validator(v, wallSlot.epoch):
              notice "Ignoring exited validator",
                index = idx,
                pubkey = shortLog(v.pubkey)
    let stabilitySubnets =
      node.consensusManager[].actionTracker.stabilitySubnets(wallSlot)
    # Here, we also set the correct ENR should we be in all subnets mode!
    node.network.updateStabilitySubnetMetadata(stabilitySubnets)

  node.network.registerProtocol(
    PeerSync, PeerSync.NetworkState.init(
      node.dag,
      node.beaconClock.getBeaconTimeFn(),
  ))

  node.network.registerProtocol(
    BeaconSync, BeaconSync.NetworkState.init(node.dag))

  if node.dag.lcDataStore.serve:
    node.network.registerProtocol(
      LightClientSync, LightClientSync.NetworkState.init(node.dag))

  node.updateValidatorMetrics()

const
  SlashingDbName = "slashing_protection"
  # changing this requires physical file rename as well or history is lost.

proc init*(
    T: type BeaconNode,
    rng: ref HmacDrbgContext,
    config: BeaconNodeConf,
    taskpool: Taskpool,
): Future[Opt[BeaconNode]] {.async: (raises: [CancelledError]).} =
  var config = config

  config.createDumpDirs()

  let metadata = config.loadEth2Network()

  # Updating the config based on the metadata certainly is not beautiful but it
  # works
  for node in metadata.bootstrapNodes:
    config.bootstrapNodes.add node
  if config.syncHorizon.isNone:
    config.syncHorizon = some(metadata.cfg.timeParams.defaultSyncHorizon)

  if ProcessState.stopIt(notice("Shutting down", reason = it)):
    return Opt.none(BeaconNode)

  if metadata.genesis.kind == BakedIn:
    if config.genesisState.isSome:
      warn "The --genesis-state option has no effect on networks with built-in genesis state"

    if config.genesisStateUrl.isSome:
      warn "The --genesis-state-url option has no effect on networks with built-in genesis state"

  let db = ?await setupDatabase(config, metadata)

  # Doesn't use std/random directly, but dependencies might
  randomize(rng[].rand(high(int)))

  # The validatorMonitorTotals flag has been deprecated and should eventually be
  # removed - until then, it's given priority if set so as not to needlessly
  # break existing setups
  let
    validatorMonitor = newClone(ValidatorMonitor.init(
      metadata.cfg,
      config.validatorMonitorAuto,
      config.validatorMonitorTotals.get(
        not config.validatorMonitorDetails)))

  for key in config.validatorMonitorPubkeys:
    validatorMonitor[].addMonitor(key, Opt.none(ValidatorIndex))

  let
    eventBus = EventBus.init()
    dag = loadChainDag(
      config, metadata.cfg, db, eventBus,
      validatorMonitor, metadata.bakedGenesisValidatorsRoot())
    genesisTime = dag.headState.genesis_time
    beaconClock = BeaconClock.init(metadata.cfg.timeParams, genesisTime).valueOr:
      fatal "Invalid genesis time in state", genesisTime
      return Opt.none(BeaconNode)

    getBeaconTime = beaconClock.getBeaconTimeFn()

  if config.reindexBN:
    dag.rebuildIndex(
      proc(): bool =
        ProcessState.stopping.isSome()
    )
  if ProcessState.stopIt(notice("Shutting down", reason = it)):
    return Opt.none(BeaconNode)

  let clist =
    block:
      let res = ChainListRef.init(config.databaseDir())

      debug "Backfill database has been loaded", path = config.databaseDir(),
            head = shortLog(res.head), tail = shortLog(res.tail)

      if res.handle.isSome() and res.tail().isSome():
        if not(isSlotWithinWeakSubjectivityPeriod(dag, res.tail.get().slot())):
          notice "Backfill database is outdated " &
                 "(outside of weak subjectivity period), reseting database",
                 path = config.databaseDir(),
                 tail = shortLog(res.tail)
          res.clear().isOkOr:
            fatal "Unable to reset backfill database",
                  path = config.databaseDir(), reason = error
            return Opt.none(BeaconNode)
      res

  info "Backfill database initialized", path = config.databaseDir(),
       head = shortLog(clist.head), tail = shortLog(clist.tail)

  if config.weakSubjectivityCheckpoint.isSome:
    dag.checkWeakSubjectivityCheckpoint(
      config.weakSubjectivityCheckpoint.get, beaconClock)

  if config.engineApiUrls.len == 0:
    notice "Running without execution client - validator features disabled (see https://nimbus.guide/eth1.html)"

  let elManager = ELManager.new(config.engineApiUrls, metadata.eth1Network)

  let restServer = if config.restEnabled:
    RestServerRef.init(config.restAddress, config.restPort,
                       config.restAllowedOrigin,
                       validateBeaconApiQueries,
                       nimbusAgentStr,
                       config)
  else:
    nil

  let
    netKeys = getPersistentNetKeys(rng[], config)
    nickname = if config.nodeName == "auto": shortForm(netKeys)
               else: config.nodeName
    network = createEth2Node(
      rng,
      config,
      netKeys,
      metadata.cfg,
      dag.forkDigests,
      getBeaconTime,
      dag.headState.genesis_validators_root,
    ).valueOr:
      error "Failed to initialize node", err = error
      return Opt.none(BeaconNode)

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

  func getValidatorAndIdx(pubkey: ValidatorPubKey): Opt[ValidatorAndIndex] =
    getValidator(dag.headState.validators, pubkey)

  func getCapellaForkVersion(): Opt[presets.Version] =
    Opt.some(metadata.cfg.CAPELLA_FORK_VERSION)

  func getDenebForkEpoch(): Opt[Epoch] =
    Opt.some(metadata.cfg.DENEB_FORK_EPOCH)

  func getForkForEpoch(epoch: Epoch): Opt[Fork] =
    Opt.some(dag.forkAtEpoch(epoch))

  func getGenesisRoot(): Eth2Digest =
    dag.headState.genesis_validators_root

  let
    keystoreCache = KeystoreCacheRef.init()
    slashingProtectionDB =
      SlashingProtectionDB.init(
          dag.headState.genesis_validators_root,
          config.validatorsDir(), SlashingDbName)
    validatorPool = newClone(ValidatorPool.init(
      slashingProtectionDB, config.doppelgangerDetection))

    keymanagerInitResult = initKeymanagerServer(config, restServer)
    keymanagerHost = if keymanagerInitResult.server != nil:
      newClone KeymanagerHost.init(
        validatorPool,
        keystoreCache,
        rng,
        metadata.cfg.timeParams,
        keymanagerInitResult.token,
        config.validatorsDir,
        config.secretsDir,
        config.defaultFeeRecipient,
        config.suggestedGasLimit,
        config.defaultGraffitiBytes,
        config.getPayloadBuilderAddress,
        getValidatorAndIdx,
        getBeaconTime,
        getCapellaForkVersion,
        getDenebForkEpoch,
        getForkForEpoch,
        getGenesisRoot)
    else: nil

    stateTtlCache =
      if config.restCacheSize > 0:
        StateTtlCache.init(
          cacheSize = config.restCacheSize,
          cacheTtl = chronos.seconds(config.restCacheTtl))
      else:
        nil

  if config.payloadBuilderEnable:
    info "Using external payload builder",
      payloadBuilderUrl = config.payloadBuilderUrl

  let node = BeaconNode(
    nickname: nickname,
    network: network,
    netKeys: netKeys,
    db: db,
    config: config,
    attachedValidators: validatorPool,
    elManager: elManager,
    restServer: restServer,
    keymanagerHost: keymanagerHost,
    keymanagerServer: keymanagerInitResult.server,
    keystoreCache: keystoreCache,
    eventBus: eventBus,
    beaconClock: beaconClock,
    validatorMonitor: validatorMonitor,
    stateTtlCache: stateTtlCache,
    shutdownEvent: newAsyncEvent(),
    dynamicFeeRecipientsStore: newClone(DynamicFeeRecipientsStore.init()))

  node.initLightClient(
    rng, metadata.cfg, dag.forkDigests,
    getBeaconTime, dag.genesis_validators_root)

  await node.initFullNode(rng, dag, clist, taskpool, getBeaconTime)

  node.updateLightClientFromDag()

  ok node

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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#attestation-subnet-subscription
proc updateAttestationSubnetHandlers(node: BeaconNode, slot: Slot) =
  if node.gossipState.card == 0:
    # When disconnected, updateBlocksGossipStatus is responsible for all things
    # subnets - in particular, it will remove subscriptions on the edge where
    # we enter the disconnected state.
    return

  let
    aggregateSubnets =
      node.consensusManager[].actionTracker.aggregateSubnets(slot)
    stabilitySubnets =
      node.consensusManager[].actionTracker.stabilitySubnets(slot)
    subnets = aggregateSubnets + stabilitySubnets
    validatorsCount = node.dag.headState.validators.lenu64

  node.network.updateStabilitySubnetMetadata(stabilitySubnets)

  # Now we know what we should be subscribed to - make it so
  let
    prevSubnets = node.consensusManager[].actionTracker.subscribedSubnets
    unsubscribeSubnets = prevSubnets - subnets
    subscribeSubnets = subnets - prevSubnets

  # Remember what we subscribed to, so we can unsubscribe later
  node.consensusManager[].actionTracker.subscribedSubnets = subnets

  for gossipEpoch in node.gossipState:
    let forkDigest = node.dag.forkDigests[].atEpoch(gossipEpoch, node.dag.cfg)
    node.network.unsubscribeAttestationSubnets(unsubscribeSubnets, forkDigest)
    node.network.subscribeAttestationSubnets(
      subscribeSubnets, forkDigest,
      getAttestationSubnetTopicParams(node.dag.timeParams, validatorsCount))

  debug "Attestation subnets",
    slot, epoch = slot.epoch, gossipState = node.gossipState,
    stabilitySubnets = subnetLog(stabilitySubnets),
    aggregateSubnets = subnetLog(aggregateSubnets),
    prevSubnets = subnetLog(prevSubnets),
    subscribeSubnets = subnetLog(subscribeSubnets),
    unsubscribeSubnets = subnetLog(unsubscribeSubnets),
    gossipState = node.gossipState

template updateNewPayloadGossipStatus(
    currentGossipState: var GossipState,
    name: static string,
    getTopic: proc (forkDigest: ForkDigest): string {.noSideEffect.},
    topicParams: TopicParams,
    enableTopicMetrics = false): untyped =
  template cfg(): auto = node.dag.cfg

  let
    isBehind =
      if node.shouldSyncViaLightClient(slot):
        # When syncing via light client, always subscribe
        false
      else:
        # Use DAG status to determine whether to subscribe to gossip
        dagIsBehind
    targetGossipState = getTargetGossipState(slot.epoch, cfg, isBehind)
  if currentGossipState == targetGossipState:
    return

  if currentGossipState.card == 0 and targetGossipState.card > 0:
    debug "Enabling " & name & " topic subscriptions",
      wallSlot = slot, targetGossipState
  elif currentGossipState.card > 0 and targetGossipState.card == 0:
    debug "Disabling " & name & " topic subscriptions",
      wallSlot = slot
  else:
    # Individual forks added / removed
    discard

  let
    newGossipEpochs = targetGossipState - currentGossipState
    oldGossipEpochs = currentGossipState - targetGossipState

  for gossipEpoch in oldGossipEpochs:
    let forkDigest = node.dag.forkDigests[].atEpoch(gossipEpoch, cfg)
    node.network.unsubscribe(getTopic(forkDigest))

  for gossipEpoch in newGossipEpochs:
    let forkDigest = node.dag.forkDigests[].atEpoch(gossipEpoch, cfg)
    node.network.subscribe(
      getTopic(forkDigest), topicParams, enableTopicMetrics)

  currentGossipState = targetGossipState

proc updateBlocksGossipStatus*(
    node: BeaconNode, slot: Slot, dagIsBehind: bool) =
  node.blocksGossipState.updateNewPayloadGossipStatus(
    "blocks", getBeaconBlocksTopic,
    getBlockTopicParams(node.dag.timeParams), enableTopicMetrics = true)

proc updateEnvelopeGossipStatus*(
    node: BeaconNode, slot: Slot, dagIsBehind: bool) =
  node.envelopeGossipState.updateNewPayloadGossipStatus(
    "envelope", getExecutionPayloadTopic, basicParams())

proc addPhase0MessageHandlers(
    node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  let validatorsCount = node.dag.headState.validators.lenu64
  node.network.subscribe(
    getAttesterSlashingsTopic(forkDigest),
    getAttesterSlashingTopicParams(node.dag.timeParams))
  node.network.subscribe(
    getProposerSlashingsTopic(forkDigest),
    getProposerSlashingTopicParams(node.dag.timeParams))
  node.network.subscribe(
    getVoluntaryExitsTopic(forkDigest),
    getVoluntaryExitTopicParams(node.dag.timeParams))
  node.network.subscribe(
    getAggregateAndProofsTopic(forkDigest),
    getAggregateProofTopicParams(node.dag.timeParams, validatorsCount),
    enableTopicMetrics = true)

  # updateAttestationSubnetHandlers subscribes attestation subnets

proc removePhase0MessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  node.network.unsubscribe(getVoluntaryExitsTopic(forkDigest))
  node.network.unsubscribe(getProposerSlashingsTopic(forkDigest))
  node.network.unsubscribe(getAttesterSlashingsTopic(forkDigest))
  node.network.unsubscribe(getAggregateAndProofsTopic(forkDigest))

  for subnet_id in SubnetId:
    node.network.unsubscribe(getAttestationTopic(forkDigest, subnet_id))

  node.consensusManager[].actionTracker.subscribedSubnets.reset()

func hasSyncPubKey(node: BeaconNode, epoch: Epoch): auto =
  # Only used to determine which gossip topics to which to subscribe
  if node.config.subscribeAllSubnets:
    (func(pubkey: ValidatorPubKey): bool {.closure.} = true)
  else:
    (func(pubkey: ValidatorPubKey): bool =
      node.consensusManager[].actionTracker.hasSyncDuty(pubkey, epoch) or
         pubkey in node.attachedValidators[].validators)

func getCurrentSyncCommiteeSubnets(
    node: BeaconNode, epoch: Epoch): SyncnetBits =
  let syncCommittee = withState(node.dag.headState):
    when consensusFork >= ConsensusFork.Altair:
      forkyState.data.current_sync_committee
    else:
      return static(default(SyncnetBits))

  getSyncSubnets(node.hasSyncPubKey(epoch), syncCommittee)

func getNextSyncCommitteeSubnets(
    node: BeaconNode, epoch: Epoch): SyncnetBits =
  let syncCommittee = withState(node.dag.headState):
    when consensusFork >= ConsensusFork.Altair:
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
      epoch + epochsToSyncPeriod.get < node.dag.cfg.ALTAIR_FORK_EPOCH:
    return subnets

  subnets + node.getNextSyncCommitteeSubnets(epoch)

proc updateDataColumnSidecarHandlers(node: BeaconNode, gossipEpoch: Epoch) =
  let forkDigest = node.dag.forkDigests[].atEpoch(gossipEpoch, node.dag.cfg)
  var custody: seq[CustodyIndex]

  for i in node.validatorCustody.custodyGroups():
    let topic = getDataColumnSidecarTopic(forkDigest, i)
    node.network.subscribe(topic, basicParams())
    custody.add(i)
  node.lastColumnCustodyIndices = custody

proc addAltairMessageHandlers(
    node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.addPhase0MessageHandlers(forkDigest, slot)

  # If this comes online near sync committee period, it'll immediately get
  # replaced as usual by trackSyncCommitteeTopics, which runs at slot end.
  let
    syncnets = node.getSyncCommitteeSubnets(slot.epoch)
    validatorsCount = node.dag.headState.validators.lenu64

  for subcommitteeIdx in SyncSubcommitteeIndex:
    if syncnets[subcommitteeIdx]:
      node.network.subscribe(
        getSyncCommitteeTopic(forkDigest, subcommitteeIdx),
        getSyncCommitteeSubnetTopicParams(node.dag.timeParams, validatorsCount))

  node.network.subscribe(
    getSyncCommitteeContributionAndProofTopic(forkDigest),
    getSyncContributionTopicParams(node.dag.timeParams))

  node.network.updateSyncnetsMetadata(syncnets)

proc addCapellaMessageHandlers(
    node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.addAltairMessageHandlers(forkDigest, slot)
  node.network.subscribe(
    getBlsToExecutionChangeTopic(forkDigest),
    getBlsToExecutionChangeTopicParams(node.dag.timeParams))

proc addGloasMessageHandlers(
    node: BeaconNode, forkDigest: ForkDigest, slot: Slot) =
  node.addCapellaMessageHandlers(forkDigest, slot)
  debugGloasComment "default gossipsub config"
  node.network.subscribe(
    getExecutionPayloadBidTopic(forkDigest), basicParams())
  node.network.subscribe(
    getPayloadAttestationMessageTopic(forkDigest), basicParams())
  node.network.subscribe(
    getProposerPreferencesTopic(forkDigest), basicParams())

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

proc removeFuluMessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  # Deliberately don't handle blobs, which Deneb and Electra contain, in lieu
  # of columns. Last common ancestor fork for gossip environment is Capellla.
  node.removeCapellaMessageHandlers(forkDigest)

  # Due to the dynamic column change, we need to unsubscribe from all the
  # subnets we subscribed to. Because getCustodyGroups() may return a different
  # set than the one we subscribed to previously.
  for i in node.lastColumnCustodyIndices:
    let topic = getDataColumnSidecarTopic(forkDigest, i)
    node.network.unsubscribe(topic)

proc removeGloasMessageHandlers(node: BeaconNode, forkDigest: ForkDigest) =
  node.removeFuluMessageHandlers(forkDigest)
  node.network.unsubscribe(getExecutionPayloadBidTopic(forkDigest))
  node.network.unsubscribe(getPayloadAttestationMessageTopic(forkDigest))
  node.network.unsubscribe(getProposerPreferencesTopic(forkDigest))

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
    validatorsCount = node.dag.headState.validators.lenu64

  for subcommitteeIdx in SyncSubcommitteeIndex:
    doAssert not (newSyncnets[subcommitteeIdx] and
                  oldSyncnets[subcommitteeIdx])
    for gossipEpoch in node.gossipState:
      template topic(): auto = getSyncCommitteeTopic(
        node.dag.forkDigests[].atEpoch(gossipEpoch, node.dag.cfg), subcommitteeIdx)
      if oldSyncnets[subcommitteeIdx]:
        node.network.unsubscribe(topic)
      elif newSyncnets[subcommitteeIdx]:
        node.network.subscribe(topic, getSyncCommitteeSubnetTopicParams(
          node.dag.timeParams, validatorsCount))

  node.network.updateSyncnetsMetadata(syncnets)

proc doppelgangerChecked(node: BeaconNode, epoch: Epoch) =
  if not node.processor[].doppelgangerDetectionEnabled:
    return

  # broadcastStartEpoch is set to FAR_FUTURE_EPOCH when we're not monitoring
  # gossip - it is only viable to assert liveness in epochs where gossip is
  # active
  if epoch > node.processor[].doppelgangerDetection.broadcastStartEpoch:
    for validator in node.attachedValidators[]:
      validator.doppelgangerChecked(epoch - 1)

proc maybeUpdateActionTrackerNextEpoch(
    node: BeaconNode, forkyState: ForkyHashedBeaconState, currentSlot: Slot) =
  let nextEpoch = currentSlot.epoch + 1
  if node.consensusManager[].actionTracker.needsUpdate(
      forkyState, nextEpoch):
    when typeof(forkyState).kind < ConsensusFork.Fulu:
      let epochRef =
        node.dag.getEpochRef(node.dag.head, nextEpoch, false).expect(
          "Getting head EpochRef should never fail")
      node.consensusManager[].actionTracker.updateActions(
        epochRef.shufflingRef, epochRef.beacon_proposers)
    else:
      let
        shufflingRef = node.dag.getShufflingRef(node.dag.head, nextEpoch, false).valueOr:
          return
        nextEpochProposers = get_beacon_proposer_indices(
          forkyState.data, shufflingRef.shuffled_active_validator_indices,
          nextEpoch)

      node.consensusManager[].actionTracker.updateActions(
        shufflingRef, nextEpochProposers)

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

  static: doAssert high(ConsensusFork) == ConsensusFork.Heze

  let
    head = node.dag.head
    headDistance =
      if slot > head.slot: (slot - head.slot).uint64
      else: 0'u64
    isBehind =
      headDistance > TOPIC_SUBSCRIBE_THRESHOLD_SLOTS + HYSTERESIS_BUFFER
    targetGossipState =
      getTargetGossipState(slot.epoch, node.dag.cfg, isBehind)

  doAssert targetGossipState.len <= 2

  let
    newGossipEpochs = targetGossipState - node.gossipState
    oldGossipEpochs = node.gossipState - targetGossipState

  doAssert newGossipEpochs.len <= 2
  doAssert oldGossipEpochs.len <= 2

  # TODO properly or reconsider, should become sort of trivial now
  func maxGossipEpoch(gossipState: GossipState): uint64 =
    var res = 0'u64
    for gossipEpoch in gossipState:
      res = max(res, distinctBase(gossipEpoch))
    res

  if  maxGossipEpoch(targetGossipState) < maxGossipEpoch(node.gossipState) and
      targetGossipState.len > 0:
    warn "Unexpected clock regression during transition",
      targetGossipState,
      gossipState = node.gossipState

  if node.gossipState.len == 0 and targetGossipState.len > 0:
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
        node.consensusManager[].actionTracker.updateActions(
          epochRef.shufflingRef, epochRef.beacon_proposers)

      node.maybeUpdateActionTrackerNextEpoch(forkyState, slot)

  if node.gossipState.len > 0 and targetGossipState.len == 0:
    debug "Disabling topic subscriptions",
      wallSlot = slot,
      headSlot = head.slot,
      headDistance

    node.processor[].clearDoppelgangerProtection()

  const removeMessageHandlers: array[ConsensusFork, auto] = [
    removePhase0MessageHandlers,
    removeAltairMessageHandlers,
    removeAltairMessageHandlers,  # bellatrix (altair handlers, different forkDigest)
    removeCapellaMessageHandlers,
    removeCapellaMessageHandlers,  # deneb (capella handlers, different forkDigest)
    removeCapellaMessageHandlers,  # electra (capella handlers, different forkDigest)
    removeFuluMessageHandlers,
    removeGloasMessageHandlers,
    removeGloasMessageHandlers  # heze (gloas handlers)
  ]

  for gossipEpoch in oldGossipEpochs:
    let gossipFork = node.dag.cfg.consensusForkAtEpoch(gossipEpoch)
    removeMessageHandlers[gossipFork](
      node, node.dag.forkDigests[].atEpoch(gossipEpoch, node.dag.cfg))

  const addMessageHandlers: array[ConsensusFork, auto] = [
    addPhase0MessageHandlers,
    addAltairMessageHandlers,
    addAltairMessageHandlers,  # bellatrix (altair handlers, different forkDigest)
    addCapellaMessageHandlers,
    addCapellaMessageHandlers,  # deneb (capella handlers, different forkDigest)
    addCapellaMessageHandlers,  # electra (capella handlers, different forkDigest)
    addCapellaMessageHandlers, # no blobs; updateDataColumnSidecarHandlers for rest
    addGloasMessageHandlers,
    addGloasMessageHandlers  # heze (gloas handlers)
  ]

  for gossipEpoch in newGossipEpochs:
    let gossipFork = node.dag.cfg.consensusForkAtEpoch(gossipEpoch)
    addMessageHandlers[gossipFork](
      node, node.dag.forkDigests[].atEpoch(gossipEpoch, node.dag.cfg), slot)

  node.gossipState = targetGossipState

  # Validator custody can change in the middle of a fork/BPO interval; need to
  # subscribe to potentially new column topics and unsubscribe from stale ones.
  # Do this after node.gossipState is updated to avoid adding immediately
  # unsubscribed subscriptions.
  for gossipEpoch in node.gossipState:
    if gossipEpoch >= node.dag.cfg.FULU_FORK_EPOCH:
      node.updateDataColumnSidecarHandlers(gossipEpoch)

  node.doppelgangerChecked(slot.epoch)
  node.updateAttestationSubnetHandlers(slot)
  node.updateBlocksGossipStatus(slot, isBehind)
  node.updateEnvelopeGossipStatus(slot, isBehind)
  node.updateLightClientGossipStatus(slot, isBehind)

proc pruneBlobs(node: BeaconNode, slot: Slot) =
  let blobPruneEpoch = (slot.epoch -
                        node.dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS - 1)
  if slot.is_epoch() and blobPruneEpoch >= node.dag.cfg.DENEB_FORK_EPOCH:
    var blocks: array[SLOTS_PER_EPOCH.int, BlockId]
    var count = 0
    let startIndex = node.dag.getBlockRange(
      blobPruneEpoch.start_slot, blocks.toOpenArray(0, SLOTS_PER_EPOCH - 1))
    for i in startIndex..<SLOTS_PER_EPOCH:
      let blck = node.dag.getForkedBlock(blocks[int(i)]).valueOr: continue
      withBlck(blck):
        debugGloasComment " "
        when typeof(forkyBlck).kind < ConsensusFork.Deneb or typeof(forkyBlck).kind in [ConsensusFork.Gloas, ConsensusFork.Heze]: continue
        else:
          for j in 0..len(forkyBlck.message.body.blob_kzg_commitments) - 1:
            if node.db.delBlobSidecar(blocks[int(i)].root, BlobIndex(j)):
              count = count + 1
    debug "pruned blobs", count, blobPruneEpoch

proc pruneDataColumns(node: BeaconNode, slot: Slot) =
  let dataColumnPruneEpoch = (slot.epoch -
                              node.dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS - 1)
  if slot.is_epoch() and dataColumnPruneEpoch >= node.dag.cfg.FULU_FORK_EPOCH:
    let consensusFork = node.dag.cfg.consensusForkAtEpoch(dataColumnPruneEpoch)
    var blocks: array[SLOTS_PER_EPOCH.int, BlockId]
    var count = 0
    let startIndex = node.dag.getBlockRange(dataColumnPruneEpoch.start_slot, blocks)
    for i in startIndex..<SLOTS_PER_EPOCH:
      # Iterate the full column space rather than just the local custody
      # set so late-arriving or reconstructed columns outside of this
      # node's custody groups are also cleaned up.
      count += node.db.delDataColumnSidecars(
        consensusFork, blocks[int(i)].root)
    debug "pruned data columns", count, dataColumnPruneEpoch

proc reconstructDataColumns(node: BeaconNode, slot: Slot) {.async: (raises: []).} =
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/fulu/das-core.md#reconstruction-and-cross-seeding
  # "If the node obtains 50%+ of all the columns, it SHOULD reconstruct the
  # full data matrix via the recover_matrix helper."
  if node.config.lightSupernode:
    return

  if node.fuluColumnQuarantine.custodyColumns.lenu64 <
      node.dag.cfg.NUMBER_OF_CUSTODY_GROUPS div 2:
    return

  # Currently, this logic is broken
  if not node.config.debugEnableReconstruction:
    return

  logScope:
    slot = slot

  let blck = node.dag.getForkedBlock(node.dag.head.bid).valueOr:
    warn "Failed to get the current slot head"
    return

  withBlck(blck):
    when consensusFork >= ConsensusFork.Fulu:
      var
        columns: seq[ref fulu.DataColumnSidecar]
        indices: HashSet[uint64]

      # Get columns from database
      for i in 0 ..< NUMBER_OF_COLUMNS.uint64:
        let colData = new fulu.DataColumnSidecar
        if node.dag.db.getDataColumnSidecar(forkyBlck.root, i, colData[]):
          columns.add(colData)
          indices.incl(i)
      trace "PeerDAS: Data columns before reconstruction", columns = indices.len

      # Make sure the node has obtained 50%+ of all the columns
      if columns.lenu64 < (NUMBER_OF_COLUMNS div 2):
        return
      # Ignore if the node has already obtained all the columns
      elif columns.lenu64 == NUMBER_OF_COLUMNS:
        trace "The node has already obtained all the columns"
        return

      let startTime = Moment.now()

      # Reconstruct columns
      let recovered = await(recover_cells_and_proofs_parallel(
        node.batchVerifier[].taskpool, columns)).valueOr:
          error "Data column reconstruction incomplete"
          return
      let rowCount = recovered.len
      var reconCounter = 0

      let recoveredTime = Moment.now()

      var reconstructed: seq[ref fulu.DataColumnSidecar]
      for i in 0 ..< NUMBER_OF_COLUMNS.uint64:
        if i in indices:
          continue
        var
          cells = newSeq[Cell](rowCount)
          proofs = newSeq[kzg.KzgProof](rowCount)
        for j in 0 ..< rowCount:
          cells[j] = recovered[j].cells[i]
          proofs[j] = recovered[j].proofs[i]
        reconstructed.add (ref fulu.DataColumnSidecar)(
          index: ColumnIndex(i),
          column: DataColumn.init(cells),
          kzg_commitments: columns[0][].kzg_commitments,
          kzg_proofs: deneb.KzgProofs.init(proofs),
          signed_block_header:
            forkyBlck.asSigned().toSignedBeaconBlockHeader(),
          kzg_commitments_inclusion_proof:
            columns[0][].kzg_commitments_inclusion_proof)  # TODO might already have
        inc reconCounter
      node.dag.db.putDataColumnSidecars(reconstructed)

      trace "Columns reconstructed",
        columns = reconCounter,
        recoveryTime = recoveredTime - startTime,
        reconstructionTime = Moment.now() - recoveredTime

proc onSlotEnd(node: BeaconNode, slot: Slot) {.async.} =
  # Things we do when slot processing has ended and we're about to wait for the
  # next slot

  let reconstructFut =
    if slot.epoch() >= node.dag.cfg.FULU_FORK_EPOCH:
      reconstructDataColumns(node, slot)
    else:
      nil

  # By waiting until close before slot end, ensure that preparation for next
  # slot does not interfere with propagation of messages and with VC duties.
  #
  # This must be before the advanceOffset/advanceCutoff.
  let
    endOffset = node.dag.timeParams.payloadAttestationSlotOffset + nanos((
      node.dag.timeParams.SLOT_DURATION.nanoseconds -
      node.dag.timeParams.payloadAttestationSlotOffset.nanoseconds) div 6)
    endCutoff = node.beaconClock.fromNow(
      slot.start_beacon_time(node.dag.timeParams) + endOffset)
  if endCutoff.inFuture:
    debug "Waiting for slot end", slot, endCutoff = shortLog(endCutoff.offset)
    await sleepAsync(endCutoff.offset)

  if not reconstructFut.isNil:
    await reconstructFut

  if node.dag.needStateCachesAndForkChoicePruning():
    if node.attachedValidators[].validators.len > 0:
      node.attachedValidators[]
          .slashingProtection
          # pruning is only done if the DB is set to pruning mode.
          .pruneAfterFinalization(
            node.dag.finalizedHead.slot.epoch()
          )
    node.processor.quarantine[].pruneAfterFinalization(
      node.dag.finalizedHead.slot.epoch(), node.dag.needsBackfill())

  # Delay part of pruning until latency critical duties are done.
  # The other part of pruning, `pruneBlocksDAG`, is done eagerly.
  # ----
  # This is the last pruning to do as it clears the "needPruning" condition.
  node.consensusManager[].pruneStateCachesAndForkChoice()

  if node.config.historyMode == HistoryMode.Prune:
    if not (slot + 1).is_epoch():
      # The epoch slot already is "heavy" due to the epoch processing, leave
      # the pruning for later
      node.dag.pruneHistory()
      node.pruneBlobs(slot)
      node.pruneDataColumns(slot)

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
  except Exception:
    # TODO upstream
    raiseAssert "Unexpected exception during GC collection"
  let gcCollectionTick = Moment.now()

  # Checkpoint the database to clear the WAL file and make sure changes in
  # the database are synced with the filesystem.
  node.db.checkpoint()
  let
    dbCheckpointTick = Moment.now()
    dbCheckpointDur = dbCheckpointTick - gcCollectionTick
  db_checkpoint_seconds.inc(dbCheckpointDur.toFloatSeconds)
  if dbCheckpointDur >= MinSignificantProcessingDuration:
    info "Database checkpointed", dur = dbCheckpointDur
  else:
    debug "Database checkpointed", dur = dbCheckpointDur

  node.syncCommitteeMsgPool[].pruneData(slot)
  if slot.is_epoch:
    node.dynamicFeeRecipientsStore[].pruneOldMappings(slot.epoch)

    if slot.epoch > 0:
      let justEnded = slot.epoch - Epoch(1)
      node.processor.seenProposerPreferences[justEnded.uint64 mod 2].reset()

  # Update upcoming actions - we do this every slot in case a reorg happens
  let head = node.dag.head
  if node.isSynced(head) and head.executionValid:
    withState(node.dag.headState):
      # maybeUpdateActionTrackerNextEpoch might not account for balance changes
      # from the process_rewards_and_penalties() epoch transition but only from
      # process_block() and other per-slot sources. This mainly matters insofar
      # as it might trigger process_effective_balance_updates() changes in that
      # same epoch transition, which function is therefore potentially blind to
      # but which might then affect beacon proposers.
      #
      # Because this runs every slot, it can account naturally for slashings,
      # which affect balances via slash_validator() when they happen, and any
      # missed sync committee participation via process_sync_aggregate(), but
      # attestation penalties for example, need, specific handling.
      # checked by maybeUpdateActionTrackerNextEpoch.
      node.maybeUpdateActionTrackerNextEpoch(forkyState, slot)

  let
    nextAttestationSlot =
      node.consensusManager[].actionTracker.getNextAttestationSlot(slot)
    nextProposalSlot =
      node.consensusManager[].actionTracker.getNextProposalSlot(slot)
    nextActionSlot = min(nextAttestationSlot, nextProposalSlot)
    nextActionWaitTime = saturate(fromNow(node.beaconClock, nextActionSlot))

  # -1 is a more useful output than 18446744073709551615 as an indicator of
  # no future attestation/proposal known.
  template formatInt64(x: Slot): int64 =
    if x == high(uint64).Slot:
      -1'i64
    else:
      toGaugeValue(x)

  let
    syncCommitteeSlot = slot + 1
    syncCommitteeEpoch = syncCommitteeSlot.epoch
    inCurrentSyncCommittee =
      not node.getCurrentSyncCommiteeSubnets(syncCommitteeEpoch).isZeros()

  template formatSyncCommitteeStatus(): string =
    if inCurrentSyncCommittee:
      "current"
    elif not node.getNextSyncCommitteeSubnets(syncCommitteeEpoch).isZeros():
      let slotsToNextSyncCommitteePeriod =
        SLOTS_PER_SYNC_COMMITTEE_PERIOD -
        since_sync_committee_period_start(syncCommitteeSlot)
      # int64 conversion is safe
      doAssert slotsToNextSyncCommitteePeriod <= SLOTS_PER_SYNC_COMMITTEE_PERIOD
      "in " & toTimeLeftString(
        node.dag.timeParams.SLOT_DURATION *
        slotsToNextSyncCommitteePeriod.int64)
    else:
      "none"

  info "Slot end",
    slot = shortLog(slot),
    nextActionWait =
      if nextActionSlot == FAR_FUTURE_SLOT:
        "n/a"
      else:
        shortLog(nextActionWaitTime),
    nextAttestationSlot = formatInt64(nextAttestationSlot),
    nextProposalSlot = formatInt64(nextProposalSlot),
    syncCommitteeDuties = formatSyncCommitteeStatus(),
    head = shortLog(head)

  if nextActionSlot != FAR_FUTURE_SLOT:
    next_action_wait.set(nextActionWaitTime.toFloatSeconds)

  next_proposal_wait.set(
    if nextProposalSlot != FAR_FUTURE_SLOT:
      saturate(fromNow(node.beaconClock, nextProposalSlot)).toFloatSeconds()
    else:
      Inf)

  sync_committee_active.set(if inCurrentSyncCommittee: 1 else: 0)

  let epoch = slot.epoch
  if epoch + 1 >= node.network.forkId.next_fork_epoch:
    # Update 1 epoch early to block non-fork-ready peers
    node.network.updateForkId(epoch, node.dag.genesis_validators_root)

  # When we're not behind schedule, we'll speculatively update the clearance
  # state in anticipation of receiving the next block - we do it after
  # logging slot end since the nextActionWaitTime can be short
  #
  # This must be after the endOffset/endCutoff.
  let
    advanceOffset = node.dag.timeParams.payloadAttestationSlotOffset + nanos((
      node.dag.timeParams.SLOT_DURATION.nanoseconds -
      node.dag.timeParams.payloadAttestationSlotOffset.nanoseconds) div 2)
    advanceCutoff = node.beaconClock.fromNow(
      slot.start_beacon_time(node.dag.timeParams) + advanceOffset)

  let proposalFcu =
    if advanceCutoff.inFuture:
      # Wait until half-way through the slot's idle tail, and then advance the
      # clearance state to the next slot - this gives us a high probability of
      # being prepared for the block that will arrive and the epoch processing
      # that follows
      await sleepAsync(advanceCutoff.offset)
      let
        nextSlot = slot + 1
        nextSlotCutoff = node.beaconClock.fromNow(
          nextSlot.start_beacon_time(node.dag.timeParams))
        head = node.dag.head # could be a new head compared to earlier

      if nextSlotCutoff.inFuture and node.isSynced(head) and head.executionValid:
        # If there is a proposal, we want to let the execution client know a bit
        # earlier - the risk is that fork choice changes again before the proposal
        # but this risk should be small - this function also prepares the
        # clearance state for the most likely block to be arriving next
        node.consensusManager.prepareNextSlot(
          nextSlot, sleepAsync(nextSlotCutoff.offset)
        )
      else:
        nil
    else:
      nil

  # Prepare action tracker for the next slot
  node.consensusManager[].actionTracker.updateSlot(slot + 1)

  # The last thing we do is to perform the subscriptions and unsubscriptions for
  # the next slot, just before that slot starts - because of the advance cuttoff
  # above, this will be done just before the next slot starts
  node.updateSyncCommitteeTopics(slot + 1)

  # TODO (cheatfate): This does not include VC provided validators balances.
  node.validatorCustody.updateValidatorCustody(
    slot, node.attachedValidatorBalanceTotal)

  # Update nfd field for BPOs
  node.network.updateNextForkDigest(
    node.dag.cfg.nextForkDigestAtEpoch(node.dag.forkDigests[], epoch))

  await node.updateGossipStatus(slot + 1)

  if proposalFcu != nil:
    await proposalFcu

func formatNextConsensusFork(
    node: BeaconNode, withVanityArt = false): Opt[string] =
  let consensusFork =
    node.dag.cfg.consensusForkAtEpoch(node.dag.head.slot.epoch)
  if consensusFork == ConsensusFork.high:
    return Opt.none(string)
  let
    nextConsensusFork = consensusFork.succ()
    nextForkEpoch = node.dag.cfg.consensusForkEpoch(nextConsensusFork)
  if nextForkEpoch == FAR_FUTURE_EPOCH:
    return Opt.none(string)
  Opt.some(
    (if withVanityArt: nextConsensusFork.getVanityMascot & " " else: "") &
    $nextConsensusFork & ":" & $nextForkEpoch)

proc syncStatus(node: BeaconNode, wallSlot: Slot): string =
  node.syncOverseer.syncStatusMessage()

when defined(windows):
  from winservice import establishWindowsService, reportServiceStatusSuccess

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
    wallSlot = wallTime.slotOrZero(node.dag.timeParams)
    # If everything was working perfectly, the slot that we should be processing
    expectedSlot = lastSlot + 1
    finalizedEpoch = node.dag.finalizedHead.blck.slot.epoch()
    delay = wallTime - expectedSlot.start_beacon_time(node.dag.timeParams)

  node.processingDelay = Opt.some(nanoseconds(delay.nanoseconds))

  block:
    logScope:
      slot = shortLog(wallSlot)
      epoch = shortLog(wallSlot.epoch)
      sync = node.syncStatus(wallSlot)
      peers = len(node.network.peerPool)
      head = shortLog(node.dag.head)
      finalized = shortLog(node.dag.headState.finalized_checkpoint)
      delay = shortLog(delay)
    let nextConsensusForkDescription = node.formatNextConsensusFork()
    if nextConsensusForkDescription.isNone:
      info "Slot start"
    else:
      info "Slot start", nextFork = nextConsensusForkDescription.get

  # Check before any re-scheduling of onSlotStart()
  if checkIfShouldStopAtEpoch(wallSlot, node.config.stopAtEpoch):
    quit(0)

  when defined(windows):
    if node.config.runAsService:
      reportServiceStatusSuccess()

  beacon_slot.set wallSlot.toGaugeValue
  beacon_current_epoch.set wallSlot.epoch.toGaugeValue

  # both non-negative, so difference can't overflow or underflow int64
  finalization_delay.set(
    wallSlot.epoch.toGaugeValue - finalizedEpoch.toGaugeValue)

  if node.config.strictVerification:
    verifyFinalization(node, wallSlot)

  node.consensusManager[].updateHead(wallSlot)

  await node.handleValidatorDuties(lastSlot, wallSlot)
  node.requestManager.upgradeLoops()
  await onSlotEnd(node, wallSlot)

  # https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/bellatrix/validator.md#registration-dissemination
  # This specification suggests validators re-submit to builder software every
  # `EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION` epochs.
  if  wallSlot.is_epoch and
      wallSlot.epoch mod EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION == 0:
    asyncSpawn node.registerValidators(wallSlot.epoch)

  return false

proc runSlotLoop(node: BeaconNode, startTime: BeaconTime) {.async.} =
  var
    curSlot = startTime.slotOrZero(node.dag.timeParams)
    nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
    timeToNextSlot = nextSlot.start_beacon_time(node.dag.timeParams) - startTime

  info "Scheduling first slot action",
    startTime = shortLog(startTime),
    nextSlot = shortLog(nextSlot),
    timeToNextSlot = shortLog(timeToNextSlot)

  while true:
    # Start by waiting for the time when the slot starts. Sleeping relinquishes
    # control to other tasks which may or may not finish within the allotted
    # time, so below, we need to be wary that the ship might have sailed
    # already.
    await sleepAsync(timeToNextSlot)

    let
      wallTime = node.beaconClock.now()
      wallSlot = wallTime.slotOrZero(node.dag.timeParams)  # Always >= GENESIS!

    if wallSlot < nextSlot:
      # While we were sleeping, the system clock changed and time moved
      # backwards!
      if wallSlot + 1 < nextSlot:
        # This is a critical condition where it's hard to reason about what
        # to do next - we'll call the attention of the user here by shutting
        # down.
        fatal "System time adjusted backwards significantly - clock may be inaccurate - shutting down",
          nextSlot = shortLog(nextSlot), wallSlot = shortLog(wallSlot)
        ProcessState.scheduleStop("clock skew")
        return

      # Time moved back by a single slot - this could be a minor adjustment,
      # for example when NTP does its thing after not working for a while
      warn "System time adjusted backwards, rescheduling slot actions",
        wallTime = shortLog(wallTime),
        nextSlot = shortLog(nextSlot),
        wallSlot = shortLog(wallSlot)

      # cur & next slot remain the same
      timeToNextSlot =
        nextSlot.start_beacon_time(node.dag.timeParams) - wallTime
      continue

    if wallSlot > nextSlot + SLOTS_PER_EPOCH:
      # Time moved forwards by more than an epoch - either the clock was reset
      # or we've been stuck in processing for a long time - either way, we will
      # skip ahead so that we only process the events of the last
      # SLOTS_PER_EPOCH slots
      warn "Time moved forwards by more than an epoch, skipping ahead",
        curSlot = shortLog(curSlot),
        nextSlot = shortLog(nextSlot),
        wallSlot = shortLog(wallSlot)

      curSlot = wallSlot - SLOTS_PER_EPOCH
    elif wallSlot > nextSlot:
      notice "Missed expected slot start, catching up",
        delay = shortLog(
          wallTime - nextSlot.start_beacon_time(node.dag.timeParams)),
        curSlot = shortLog(curSlot),
        nextSlot = shortLog(curSlot)

    let breakLoop = await onSlotStart(node, wallTime, curSlot)
    if breakLoop:
      break

    curSlot = wallSlot
    nextSlot = wallSlot + 1
    timeToNextSlot =
      nextSlot.start_beacon_time(node.dag.timeParams) - node.beaconClock.now()

proc onSecond(node: BeaconNode, time: Moment) =
  # Nim GC metrics (for the main thread)
  updateThreadMetrics()

  if node.config.stopAtSyncedEpoch != 0 and
      node.dag.head.slot.epoch >= node.config.stopAtSyncedEpoch:
    notice "Shutting down after having reached the target synced epoch"
    ProcessState.scheduleStop("stopAtSyncedEpoch")

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

    ticks_delay.set(sleepTime.nanoseconds.float / nanosecondsIn1s)
    trace "onSecond task completed",
      sleepTime, processingTime = chronos.now(chronos.Moment) - afterSleep

func connectedPeersCount(node: BeaconNode): int =
  len(node.network.peerPool)

proc installRestHandlers(restServer: RestServerRef, node: BeaconNode) =
  restServer.router.installBeaconApiHandlers(node)
  restServer.router.installBuilderApiHandlers()
  restServer.router.installConfigApiHandlers(node)
  restServer.router.installDebugApiHandlers(node)
  restServer.router.installEventApiHandlers(node)
  restServer.router.installNimbusApiHandlers(node)
  restServer.router.installNodeApiHandlers(node)
  restServer.router.installValidatorApiHandlers(node)
  restServer.router.installRewardsApiHandlers(node)
  if node.dag.lcDataStore.serve:
    restServer.router.installLightClientApiHandlers(node)

from ./spec/datatypes/capella import SignedBeaconBlock

proc installMessageValidators(node: BeaconNode) =
  # These validators stay around the whole time, regardless of which specific
  # subnets are subscribed to during any given epoch.
  let forkDigests = node.dag.forkDigests

  for fork in ConsensusFork:
    withConsensusFork(fork):
      # Post-Electra forks live entirely in `bpos`; pre-Fulu forks live in the
      # named ForkDigests fields.
      let digests =
        when consensusFork < ConsensusFork.Fulu:
          @[forkDigests[].atConsensusFork(consensusFork)]
        else:
          forkDigests[].bpos.filterIt(it[1] == consensusFork).mapIt(it[2])
      for digest in digests:
        let digest = digest # lent
        # beacon_block
        # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/p2p-interface.md#beacon_block
        # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/p2p-interface.md#beacon_block
        node.network.addValidator(
          getBeaconBlocksTopic(digest), proc (
            signedBlock: consensusFork.SignedBeaconBlock,
            src: PeerId,
          ): ValidationResult =
            if node.shouldSyncViaLightClient(node.currentSlot):
              toValidationResult(
                node.lightBlockProcessor.processSignedBeaconBlock(
                  signedBlock))
            else:
              let res =
                toValidationResult(
                  node.processor[].processSignedBeaconBlock(
                    MsgSource.gossip, signedBlock))
              if res == ValidationResult.Accept:
                node.eventBus.blockGossipPeerQueue.emit(
                  EventBeaconBlockGossipPeerObject.init(signedBlock, src))
              res)

        # execution_payload_bid
        # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.1/specs/gloas/p2p-interface.md#execution_payload_bid
        when consensusFork >= ConsensusFork.Gloas:
          node.network.addValidator(
            getExecutionPayloadBidTopic(digest), proc (
              signedBid: gloas.SignedExecutionPayloadBid,
              src: PeerId
            ): ValidationResult =
              toValidationResult(
                node.processor[].processExecutionPayloadBid(signedBid)))

        # execution_payload
        # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha-1/specs/gloas/p2p-interface.md#execution_payload
        when consensusFork >= ConsensusFork.Gloas:
          node.network.addValidator(
            getExecutionPayloadTopic(digest), proc (
              signedEnvelope: SignedExecutionPayloadEnvelope,
              src: PeerId,
            ): ValidationResult =
              if node.shouldSyncViaLightClient(node.currentSlot):
                toValidationResult(
                  node.lightBlockProcessor.processExecutionPayloadEnvelope(
                    signedEnvelope))
              else:
                toValidationResult(
                  node.processor[].processExecutionPayloadEnvelope(
                    MsgSource.gossip, signedEnvelope)))

        # payload_attestation_message
        # https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/p2p-interface.md#payload_attestation_message
        when consensusFork >= ConsensusFork.Gloas:
          node.network.addAsyncValidator(
            getPayloadAttestationMessageTopic(digest), proc (
              payloadAttestationMessage: PayloadAttestationMessage,
              src: PeerId
            ): Future[ValidationResult] {.
                 async: (raises: [CancelledError]).} =
              return toValidationResult(
                await node.processor.processPayloadAttestationMessage(
                  payloadAttestationMessage, checkSignature = true,
                  checkValidator = false)))

        # proposer_preferences
        # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/p2p-interface.md#proposer_preferences
        when consensusFork >= ConsensusFork.Gloas:
          node.network.addValidator(
            getProposerPreferencesTopic(digest), proc(
              signed_preferences: SignedProposerPreferences,
              src: PeerId
            ): ValidationResult =
              toValidationResult(
                node.processor.processProposerPreferences(
                  MsgSource.gossip, signed_preferences)))

        # beacon_attestation_{subnet_id}
        # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id
        # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/p2p-interface.md#beacon_attestation_subnet_id
        when consensusFork >= ConsensusFork.Electra:
          for it in SubnetId:
            closureScope:  # Needed for inner `proc`; don't lift it out of loop.
              let subnet_id = it
              node.network.addAsyncValidator(
                getAttestationTopic(digest, subnet_id), proc (
                  attestation: SingleAttestation, src: PeerId
                ): Future[ValidationResult] {.
                    async: (raises: [CancelledError]).} =
                  return toValidationResult(
                    await node.processor.processAttestation(
                      MsgSource.gossip, attestation, subnet_id,
                      checkSignature = true, checkValidator = false)))

        # beacon_aggregate_and_proof
        # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
        # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/p2p-interface.md#beacon_aggregate_and_proof
        when consensusFork >= ConsensusFork.Electra:
          node.network.addAsyncValidator(
            getAggregateAndProofsTopic(digest), proc (
              signedAggregateAndProof: electra.SignedAggregateAndProof,
              src: PeerId
            ): Future[ValidationResult] {.async: (raises: [CancelledError]).} =
              return toValidationResult(
                await node.processor.processSignedAggregateAndProof(
                  MsgSource.gossip, signedAggregateAndProof)))

        # attester_slashing
        # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/phase0/p2p-interface.md#attester_slashing
        # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/electra/p2p-interface.md#modifications-in-electra
        when consensusFork >= ConsensusFork.Electra:
          node.network.addValidator(
            getAttesterSlashingsTopic(digest), proc (
              attesterSlashing: electra.AttesterSlashing,
              src: PeerId
            ): ValidationResult =
              toValidationResult(
                node.processor[].processAttesterSlashing(
                  MsgSource.gossip, attesterSlashing)))

        # proposer_slashing
        # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/p2p-interface.md#proposer_slashing
        node.network.addValidator(
          getProposerSlashingsTopic(digest), proc (
            proposerSlashing: ProposerSlashing,
            src: PeerId
          ): ValidationResult =
            toValidationResult(
              node.processor[].processProposerSlashing(
                MsgSource.gossip, proposerSlashing)))

        # voluntary_exit
        # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/phase0/p2p-interface.md#voluntary_exit
        node.network.addValidator(
          getVoluntaryExitsTopic(digest), proc (
            signedVoluntaryExit: SignedVoluntaryExit,
            src: PeerId
          ): ValidationResult =
            toValidationResult(
              node.processor[].processSignedVoluntaryExit(
                MsgSource.gossip, signedVoluntaryExit)))

        when consensusFork >= ConsensusFork.Altair:
          # sync_committee_{subnet_id}
          # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/p2p-interface.md#sync_committee_subnet_id
          for subcommitteeIdx in SyncSubcommitteeIndex:
            closureScope:  # Needed for inner `proc`; don't lift it out of loop.
              let idx = subcommitteeIdx
              node.network.addAsyncValidator(
                getSyncCommitteeTopic(digest, idx), proc (
                  msg: SyncCommitteeMessage,
                  src: PeerId
                ): Future[ValidationResult] {.
                    async: (raises: [CancelledError]).} =
                  return toValidationResult(
                    await node.processor.processSyncCommitteeMessage(
                      MsgSource.gossip, msg, idx)))

          # sync_committee_contribution_and_proof
          # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/altair/p2p-interface.md#sync_committee_contribution_and_proof
          node.network.addAsyncValidator(
            getSyncCommitteeContributionAndProofTopic(digest), proc (
              msg: SignedContributionAndProof,
              src: PeerId
            ): Future[ValidationResult] {.async: (raises: [CancelledError]).} =
              return toValidationResult(
                await node.processor.processSignedContributionAndProof(
                  MsgSource.gossip, msg)))

        when consensusFork >= ConsensusFork.Capella:
          # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/capella/p2p-interface.md#bls_to_execution_change
          node.network.addAsyncValidator(
            getBlsToExecutionChangeTopic(digest), proc (
              msg: SignedBLSToExecutionChange,
              src: PeerId
            ): Future[ValidationResult] {.async: (raises: [CancelledError]).} =
              return toValidationResult(
                await node.processor.processBlsToExecutionChange(
                  MsgSource.gossip, msg)))

        # data_column_sidecar_{subnet_id}
        # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/fulu/p2p-interface.md#data_column_sidecar_subnet_id
        # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/gloas/p2p-interface.md#data_column_sidecar_subnet_id
        when consensusFork >= ConsensusFork.Gloas:
          for it in 0'u64..<node.dag.cfg.NUMBER_OF_CUSTODY_GROUPS:
            closureScope:
              let subnet_id = it
              node.network.addValidator(
                getDataColumnSidecarTopic(digest, subnet_id), proc (
                  dataColumnSidecar: gloas.DataColumnSidecar,
                  src: PeerId
                ): ValidationResult =
                  toValidationResult(
                    node.processor[].processDataColumnSidecar(
                      MsgSource.gossip, newClone(dataColumnSidecar),
                      subnet_id)))
        elif consensusFork == ConsensusFork.Fulu:
          for it in 0'u64..<node.dag.cfg.NUMBER_OF_CUSTODY_GROUPS:
            closureScope:
              let subnet_id = it
              node.network.addValidator(
                getDataColumnSidecarTopic(digest, subnet_id), proc (
                  dataColumnSidecar: fulu.DataColumnSidecar,
                  src: PeerId
                ): ValidationResult =
                  toValidationResult(
                    node.processor[].processDataColumnSidecar(
                      MsgSource.gossip, newClone(dataColumnSidecar),
                      subnet_id)))

  node.installLightClientMessageValidators()

proc stop(node: BeaconNode) =
  try:
    waitFor node.network.stop()
  except CatchableError as exc:
    warn "Couldn't stop network", msg = exc.msg

  waitFor node.metricsServer.stopMetricsServer()

  node.attachedValidators[].slashingProtection.close()
  node.attachedValidators[].close()
  node.db.close()
  notice "Databases closed"

proc initializeNetworking(node: BeaconNode) {.async.} =
  node.installMessageValidators()

  info "Listening to incoming network requests"
  await node.network.startListening()

  let addressFile = node.config.dataDir / "beacon_node.enr"
  writeFile(addressFile, node.network.announcedENR.toURI)

  await node.network.start()

type StopFuture = Future[void].Raising([CancelledError])

proc run*(node: BeaconNode, stopper: StopFuture) {.raises: [CatchableError].} =
  let
    head = node.dag.head
    finalizedHead = node.dag.finalizedHead
    genesisTime = node.beaconClock.fromNow(
      GENESIS_SLOT.start_beacon_time(node.dag.timeParams))

  notice "Starting beacon node",
    version = fullVersionStr,
    nimVersion = NimVersion,
    enr = node.network.announcedENR.toURI,
    peerId = $node.network.switch.peerInfo.peerId,
    timeSinceFinalization =
      node.beaconClock.now() -
      finalizedHead.slot.start_beacon_time(node.dag.timeParams),
    head = shortLog(head),
    justified = shortLog(node.dag.headState.current_justified_checkpoint),
    finalized = shortLog(node.dag.headState.finalized_checkpoint),
    finalizedHead = shortLog(finalizedHead),
    SLOTS_PER_EPOCH,
    SPEC_VERSION,
    dataDir = node.config.dataDir.string,
    validators = node.attachedValidators[].count

  if genesisTime.inFuture:
    notice "Waiting for genesis", genesisIn = genesisTime.offset

  waitFor node.initializeNetworking()

  node.elManager.start()

  ProcessState.notifyRunning()

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
    wallSlot = wallTime.slotOrZero(node.dag.timeParams)

  node.startLightClient()
  node.requestManager.start()
  node.syncOverseer.start()
  asyncSpawn node.getBlobsService.run()

  waitFor node.updateGossipStatus(wallSlot)

  for web3signerUrl in node.config.web3SignerUrls:
    # TODO
    # The current strategy polls all remote signers independently
    # from each other which may lead to some race conditions of
    # validators are migrated from one signer to another
    # (because the updates to our validator pool are not atomic).
    # Consider using different strategies that would detect such
    # race conditions.
    asyncSpawn node.pollForDynamicValidators(
      web3signerUrl, node.config.web3signerUpdateInterval)

  asyncSpawn runSlotLoop(node, wallTime)
  asyncSpawn runOnSecondLoop(node)
  asyncSpawn runKeystoreCachePruningLoop(node.keystoreCache)

  while true:
    if (let reason = ProcessState.stopping(); reason.isSome()):
      notice "Shutting down", reason = reason[]
      break
    if stopper != nil and stopper.finished():
      break

    chronos.poll()

  # time to say goodbye
  node.stop()

when not defined(windows):
  proc initStatusBar(node: BeaconNode) {.raises: [ValueError].} =
    if not isatty(stdout): return
    if not node.config.statusBarEnabled: return

    try:
      enableTrueColors()
    except Exception as exc: # TODO Exception
      error "Couldn't enable colors", err = exc.msg

    template safe: lent BlockId =
      node.attestationPool[].forkChoice.retrieve_fast_confirmed_bid()

    var stored_justified: Opt[BlockSlot]
    template justified: lent BlockSlot =
      if stored_justified.isNone:
        stored_justified.ok node.dag.head.atEpochStart(
          node.dag.headState.current_justified_checkpoint.epoch)
      stored_justified.unsafeGet

    proc dataResolver(expr: string): string {.raises: [].} =
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

      of "safe_root":
        shortLog(safe.root)
      of "safe_epoch":
        $(safe.slot.epoch)
      of "safe_epoch_slot":
        $(safe.slot.since_epoch_start)
      of "safe_slot":
        $(safe.slot)

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

      of "next_consensus_fork":
        let nextConsensusForkDescription =
          node.formatNextConsensusFork(withVanityArt = true)
        if nextConsensusForkDescription.isNone:
          ""
        else:
          " (scheduled " & nextConsensusForkDescription.get & ")"

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
        proc (logLevel: LogLevel, msg: LogOutputStr) {.raises: [].} =
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

proc doRunBeaconNode(
    config: var BeaconNodeConf, rng: ref HmacDrbgContext
) {.raises: [CatchableError].} =
  info "Launching beacon node",
    version = fullVersionStr,
    const_preset,
    cmdParams = commandLineParams(),
    config

  ProcessState.setupStopHandlers()

  createPidFile(config.dataDir.string / "beacon_node.pid")

  # Ensure that non-light peerdas supernode options are forcibly disabled
  # TODO when reconstruction works again, re-enable
  # this is required because the fall-through is that if one of these is
  # enabled, the (working) light supernode code won't run at all.
  if config.peerdasSupernode:
    # It's at least not worse than not doing this; a functioning (full)
    # supernode reconstructs and stores a superset of these columns
    config.lightSupernode = true
  config.peerdasSupernode = false

  if config.rpcEnabled.isSome:
    warn "Nimbus's JSON-RPC server has been removed. This includes the --rpc, --rpc-port, and --rpc-address configuration options. https://nimbus.guide/rest-api.html shows how to enable and configure the REST Beacon API server which replaces it."

  # Trusted setup is needed for Cancun+ blocks and is shared between threads,
  # so it needs to be initalized from the main thread before anything else tries
  # to use it
  if config.trustedSetupFile.isSome:
    kzg.loadTrustedSetup(config.trustedSetupFile.get(), 7).isOkOr:
      fatal "Cannot load KZG trusted setup from file", msg = error
      quit(QuitFailure)
  else:
    kzg.loadTrustedSetupFromString(kzg.trustedSetup, 7).isOkOr:
      fatal "Cannot load KZG trusted setup using default data", msg = error
      quit(QuitFailure)

  if ProcessState.stopIt(notice("Shutting down", reason = it)):
    return

  let
    taskpool = setupTaskpool(config.numThreads)
    node = waitFor(BeaconNode.init(rng, config, taskpool)).valueOr:
      return

  # Nim GC metrics (for the main thread) will be collected in onSecond(), but
  # we disable piggy-backing on other metrics here.
  setSystemMetricsAutomaticUpdate(false)

  node.metricsServer = waitFor(config.initMetricsServer()).valueOr:
    return

  when not defined(windows):
    # This status bar can lock a Windows terminal emulator, blocking the whole
    # event loop (seen on Windows 10, with a default MSYS2 terminal).
    initStatusBar(node)

  if node.nickname != "":
    dynamicLogScope(node = node.nickname):
      node.run(nil)
  else:
    node.run(nil)

proc doRecord(config: BeaconNodeConf, rng: var HmacDrbgContext) {.
    raises: [CatchableError].} =
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
      Opt.some(config.ipExt),
      if config.tcpExtEnabled: Opt.some(config.tcpPortExt) else: Opt.none(Port),
      Opt.some(config.udpPortExt),
      if config.quicExtEnabled: Opt.some(config.quicPortExt) else: Opt.none(Port),
      fieldPairs).expect("Record within size limits")

    echo record.toURI()

  of RecordCmd.print:
    echo $config.recordPrint

proc doWeb3Cmd(config: BeaconNodeConf, rng: var HmacDrbgContext)
    {.raises: [CatchableError].} =
  case config.web3Cmd:
  of Web3Cmd.test:
    waitFor testWeb3Provider(config.web3TestUrl,
                             rng.loadJwtSecret(config, allowCreate = true))

proc doSlashingExport(conf: BeaconNodeConf) {.raises: [IOError].}=
  let
    dir = conf.validatorsDir()
    filetrunc = SlashingDbName
  # TODO: Make it read-only https://github.com/status-im/nim-eth/issues/312
  let db = SlashingProtectionDB.loadUnchecked(dir, filetrunc, readOnly = false)

  let interchange = conf.exportedInterchangeFile.string
  db.exportSlashingInterchange(interchange, conf.exportedValidators)
  echo "Export finished: '", dir/filetrunc & ".sqlite3" , "' into '", interchange, "'"

proc doSlashingImport(conf: BeaconNodeConf) {.raises: [IOError].} =
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

proc doSlashingInterchange(conf: BeaconNodeConf) {.raises: [CatchableError].} =
  case conf.slashingdbCmd
  of SlashProtCmd.`export`:
    conf.doSlashingExport()
  of SlashProtCmd.`import`:
    conf.doSlashingImport()

proc handleStartUpCmd(config: var BeaconNodeConf) {.raises: [CatchableError].} =
  # Single RNG instance for the application - will be seeded on construction
  # and avoid using system resources (such as urandom) after that
  let rng = HmacDrbgContext.new()

  case config.cmd
  of BNStartUpCmd.beaconNode: doRunBeaconNode(config, rng)
  of BNStartUpCmd.deposits: doDeposits(config, rng[])
  of BNStartUpCmd.wallets: doWallets(config, rng[])
  of BNStartUpCmd.record: doRecord(config, rng[])
  of BNStartUpCmd.web3: doWeb3Cmd(config, rng[])
  of BNStartUpCmd.slashingdb: doSlashingInterchange(config)
  of BNStartUpCmd.trustedNodeSync:
    if config.blockId.isSome():
      error "--blockId option has been removed - use --state-id instead!"
      quit 1

    let
      metadata = loadEth2Network(config)
      db = BeaconChainDB.new(
        config.databaseDir, metadata.cfg, inMemory = false)
      genesisState = (waitFor fetchGenesisState(metadata, config.eraDir)).valueOr:
        quit 1
    waitFor db.doRunTrustedNodeSync(
      metadata,
      config.databaseDir,
      config.eraDir,
      config.trustedNodeUrl,
      config.stateId,
      config.lcTrustedBlockRoot,
      config.backfillBlocks,
      config.reindex,
      genesisState)
    db.close()

# noinline to keep it in stack traces
proc main*() {.noinline, raises: [CatchableError].} =
  const copyright =
    "Copyright (c) 2019-" & compileYear & " Status Research & Development GmbH"

  var config = BeaconNodeConf.loadWithBanners(
    clientId, copyright, [specBanner], setupLogger = true
  ).valueOr:
    writePanicLine error # Logging not yet set up
    quit QuitFailure

  setupFileLimits()

  if not (checkAndCreateDataDir(string(config.dataDir))):
    # We are unable to access/create data folder or data folder's
    # permissions are insecure.
    quit QuitFailure

  ## This Ctrl+C handler exits the program in non-graceful way.
  ## It's responsible for handling Ctrl+C in sub-commands such
  ## as `wallets *` and `deposits *`. In a regular beacon node
  ## run, it will be overwritten later with a different handler
  ## performing a graceful exit.
  proc exitImmediatelyOnCtrlC() {.noconv.} =
    # No allocations in signal handler
    cstdout.rawWrite("Shutting down after having received SIGINT / ctrl-c")
    quit QuitSuccess
  setControlCHook(exitImmediatelyOnCtrlC)

  # equivalent SIGTERM handler
  when declared(ansi_c.SIGTERM):
    proc exitImmediatelyOnSIGTERM(signal: cint) {.noconv.} =
      # No allocations in signal handler
      cstdout.rawWrite("Shutting down after having received SIGTERM")
      quit QuitSuccess
    c_signal(ansi_c.SIGTERM, exitImmediatelyOnSIGTERM)

  when defined(windows):
    if config.runAsService:
      proc exitService() =
        ProcessState.scheduleStop("exitService")
      establishWindowsService(clientId, copyright, [specBanner],
                              "nimbus_beacon_node", BeaconNodeConf,
                              handleStartUpCmd, exitService)
    else:
      handleStartUpCmd(config)
  else:
    handleStartUpCmd(config)

when isMainModule:
  main()
