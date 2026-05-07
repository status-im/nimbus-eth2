# beacon_chain
# Copyright (c) 2022-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/os,
  chronicles, chronos, metrics, stew/io2,
  eth/db/kvstore_sqlite3,
  ./el/el_manager,
  ./gossip_processing/block_processor_light_client,
  ./networking/[topic_params, network_metadata_downloads],
  ./spec/beaconstate,
  ./spec/datatypes/[phase0, altair, bellatrix, capella, deneb, gloas],
  ./[
    beacon_clock, buildinfo, filepath, light_client, light_client_db,
    nimbus_binary_common, process_state, version]

from ./consensus_object_pools/blockchain_dag import
  updateFinalizedBlockMetrics, updateHeadBlockMetrics
from ./gossip_processing/block_processor import newExecutionPayload
from ./gossip_processing/eth2_processor import toValidationResult

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#interop-metrics
declareGauge beacon_slot, "Latest slot of the beacon chain state"
declareGauge beacon_current_epoch, "Current epoch"

# noinline to keep it in stack traces
proc main() {.noinline, raises: [CatchableError].} =
  ProcessState.setupStopHandlers()
  const
    banner = "Nimbus light client " & fullVersionStr
    copyright =
      "Copyright (c) 2022-" & compileYear & " Status Research & Development GmbH"

  var config = LightClientConf.loadWithBanners(
    banner, copyright, [specBanner], setupLogger = true
  ).valueOr:
    writePanicLine error # Logging not yet set up
    quit QuitFailure

  notice "Launching light client",
    version = fullVersionStr, cmdParams = commandLineParams(), config

  let dbDir = config.databaseDir
  if (let res = secureCreatePath(dbDir); res.isErr):
    fatal "Failed to create create database directory",
      path = dbDir, err = ioErrorMsg(res.error)
    quit 1
  let backend = SqStoreRef.init(dbDir, "nlc").expect("Database OK")
  defer: backend.close()
  let db = backend.initLightClientDB(LightClientDBNames(
    legacyAltairHeaders: "altair_lc_headers",
    headers: "lc_headers",
    altairSyncCommittees: "altair_sync_committees")).expect("Database OK")
  defer: db.close()

  let metadata = loadEth2Network(config.eth2Network)
  for node in metadata.bootstrapNodes:
    config.bootstrapNodes.add node
  template cfg(): auto = metadata.cfg

  let
    genesisState = try: waitFor metadata.fetchGenesisState()
                   except CatchableError as err:
                     error "Failed to obtain genesis state",
                            source = metadata.genesis.sourceDesc,
                            err = err.msg
                     quit 1
    genesisTime = genesisState[].genesis_time
    beaconClock = BeaconClock.init(cfg.timeParams, genesisTime).valueOr:
      error "Invalid genesis time in state", genesisTime
      quit 1
    getBeaconTime = beaconClock.getBeaconTimeFn()

    genesis_validators_root = genesisState[].genesis_validators_root
    forkDigests = newClone ForkDigests.init(cfg, genesis_validators_root)

    genesisBlockRoot = get_initial_beacon_block(genesisState[]).root

    rng = HmacDrbgContext.new()
    netKeys = getRandomNetKeys(rng[])
    network = createEth2Node(
      rng, config, netKeys, cfg, forkDigests, getBeaconTime, genesis_validators_root
    ).valueOr:
      error "Failed to initialize node", err = error
      quit QuitFailure
    engineApiUrls = config.engineApiUrls
    elManager =
      if engineApiUrls.len > 0:
        ELManager.new(engineApiUrls, metadata.eth1Network)
      else:
        nil

    lightBlockHandler = proc(
        signedBlock: ForkedSignedBeaconBlock
    ): Future[void] {.async: (raises: [CancelledError]).} =
      withBlck(signedBlock):
        when consensusFork in ConsensusFork.Bellatrix ..< ConsensusFork.Gloas:
          if forkyBlck.message.is_execution_block:
            template payload(): auto = forkyBlck.message.body.execution_payload
            if elManager != nil and not payload.block_hash.isZero:
              discard await elManager.newExecutionPayload(forkyBlck.message)

    lightEnvelopeHandler = proc(
        signedEnvelope: gloas.SignedExecutionPayloadEnvelope
    ): Future[void] {.async: (raises: [CancelledError]).} =
      if elManager != nil and
          not signedEnvelope.message.payload.block_hash.isZero:
        discard await elManager.newExecutionPayload(signedEnvelope.message)

    lightBlockProcessor = initLightBlockProcessor(
      cfg.timeParams, getBeaconTime, lightBlockHandler, lightEnvelopeHandler)

    lightClient = createLightClient(
      network, rng, config, cfg, forkDigests, getBeaconTime,
      genesis_validators_root, LightClientFinalizationMode.Optimistic)

  # Nim GC metrics (for the main thread) will be collected in onSecond(), but
  # we disable piggy-backing on other metrics here.
  setSystemMetricsAutomaticUpdate(false)

  let metricsServer = waitFor(config.initMetricsServer()).valueOr:
    quit QuitFailure
  defer: waitFor metricsServer.stopMetricsServer()

  # Run `exchangeTransitionConfiguration` loop
  if elManager != nil:
    elManager.start()

  info "Listening to incoming network requests"
  network.registerProtocol(
    PeerSync, PeerSync.NetworkState.init(
      cfg, forkDigests, genesisBlockRoot, getBeaconTime))

  for consensusFork in ConsensusFork:
    for forkDigest in consensusFork.forkDigests(forkDigests[]):
      withConsensusFork(consensusFork):
        network.addValidator(
          getBeaconBlocksTopic(forkDigest), proc (
              signedBlock: consensusFork.SignedBeaconBlock,
              src: PeerId
          ): ValidationResult =
            toValidationResult(
              lightBlockProcessor.processSignedBeaconBlock(signedBlock)))

        when consensusFork >= ConsensusFork.Gloas:
          network.addValidator(
            getExecutionPayloadTopic(forkDigest), proc (
                signedEnvelope: gloas.SignedExecutionPayloadEnvelope,
                src: PeerId): ValidationResult =
              toValidationResult(
                lightBlockProcessor.processExecutionPayloadEnvelope(
                  signedEnvelope)))
  lightClient.installMessageValidators()
  waitFor network.startListening()
  waitFor network.start()

  func isSynced(lightClientSlot: Slot, wallSlot: Slot): bool =
    # Check whether light client has synced sufficiently close to wall slot
    const maxAge = 2 * SLOTS_PER_EPOCH
    lightClientSlot >= max(wallSlot, maxAge.Slot) - maxAge

  proc onFinalizedHeader(
      lightClient: LightClient, finalizedHeader: ForkedLightClientHeader) =
    withForkyHeader(finalizedHeader):
      when lcDataFork > LightClientDataFork.None:
        info "New LC finalized header",
          finalized_header = shortLog(forkyHeader)
        updateFinalizedBlockMetrics(forkyHeader.beacon.toBlockId())
        let
          period = forkyHeader.beacon.slot.sync_committee_period
          syncCommittee = lightClient.finalizedSyncCommittee.expect("Init OK")
        db.putSyncCommittee(period, syncCommittee)
        db.putLatestFinalizedHeader(finalizedHeader)

  var lightClientFcuFut: Future[(PayloadExecutionStatus, Opt[Hash32])]
    .Raising([CancelledError])
  proc onOptimisticHeader(
      lightClient: LightClient, optimisticHeader: ForkedLightClientHeader) =
    if lightClientFcuFut != nil:
      return
    withForkyHeader(optimisticHeader):
      when lcDataFork > LightClientDataFork.None:
        updateHeadBlockMetrics(forkyHeader.beacon.toBlockId())
        logScope: optimistic_header = shortLog(forkyHeader)
        when lcDataFork >= LightClientDataFork.Capella:
          let
            bid = forkyHeader.beacon.toBlockId()
            consensusFork = cfg.consensusForkAtEpoch(bid.slot.epoch)
            blockHash = forkyHeader.execution_block_hash

          info "New LC optimistic header"
          if elManager == nil or blockHash.isZero or
              not isSynced(bid.slot, beaconClock.currentSlot):
            return

          let finalizedBlockHash =
            if config.syncLightClientFinality:
              let finalizedHeader = lightClient.finalizedHeader
              withForkyHeader(finalizedHeader):
                when lcDataFork >= LightClientDataFork.Capella:
                  forkyHeader.execution_block_hash
                else:
                  ZERO_HASH
            else:
              ZERO_HASH

          withConsensusFork(consensusFork):
            when lcDataForkAtConsensusFork(consensusFork) == lcDataFork:
              debug "Sending forkchoiceUpdated",
                finalizedBlockHash = finalizedBlockHash

              let state = ForkchoiceStateV1.init(
                blockHash,
                finalizedBlockHash, # justified not available
                finalizedBlockHash
              )
              lightClientFcuFut = elManager.forkchoiceUpdated(
                state, payloadAttributes = Opt.none(consensusFork.PayloadAttributes)
              )
              lightClientFcuFut.addCallback do (future: pointer):
                lightClientFcuFut = nil
        else:
          info "Ignoring new LC optimistic header until Capella"

  lightClient.onFinalizedHeader = onFinalizedHeader
  lightClient.onOptimisticHeader = onOptimisticHeader
  lightClient.trustedBlockRoot = some config.trustedBlockRoot

  let latestHeader = db.getLatestFinalizedHeader()
  withForkyHeader(latestHeader):
    when lcDataFork > LightClientDataFork.None:
      let
        period = forkyHeader.beacon.slot.sync_committee_period
        syncCommittee = db.getSyncCommittee(period)
      if syncCommittee.isErr:
        error "LC store lacks sync committee", finalized_header = forkyHeader
      else:
        lightClient.resetToFinalizedHeader(latestHeader, syncCommittee.get)

  # Full blocks gossip is required to portably drive an EL client:
  # - EL clients may not sync when only driven with `forkChoiceUpdated`,
  #   e.g., Geth: "Forkchoice requested unknown head"
  # - `newPayload` requires the full `ExecutionPayload` (most of block content)
  # - `ExecutionPayload` block hash is not available in
  #   `altair.LightClientHeader`, so won't be exchanged via light client gossip
  #
  # Future `ethereum/consensus-specs` versions may remove need for full blocks.
  # Therefore, this current mechanism is to be seen as temporary; it is not
  # optimized for reducing code duplication, e.g., with `nimbus_beacon_node`.

  func isSynced(wallSlot: Slot): bool =
    let optimisticHeader = lightClient.optimisticHeader
    withForkyHeader(optimisticHeader):
      when lcDataFork > LightClientDataFork.None:
        isSynced(forkyHeader.beacon.slot, wallSlot)
      else:
        false

  func shouldSyncViaLightClient(wallSlot: Slot): bool =
    # Check whether an EL is connected
    if elManager == nil:
      return false

    isSynced(wallSlot)

  template updateNewPayloadGossipStatus(
      currentGossipState: var GossipState,
      name: static string,
      getTopic: proc (forkDigest: ForkDigest): string {.noSideEffect.},
      topicParams: TopicParams,
      enableTopicMetrics = false): untyped =
    let
      isBehind = not shouldSyncViaLightClient(slot)
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
      let forkDigest = forkDigests[].atEpoch(gossipEpoch, cfg)
      network.unsubscribe(getTopic(forkDigest))

    for gossipEpoch in newGossipEpochs:
      let forkDigest = forkDigests[].atEpoch(gossipEpoch, cfg)
      network.subscribe(getTopic(forkDigest), topicParams, enableTopicMetrics)

    currentGossipState = targetGossipState

  var blocksGossipState: GossipState
  proc updateBlocksGossipStatus(slot: Slot) =
    blocksGossipState.updateNewPayloadGossipStatus(
      "blocks", getBeaconBlocksTopic,
      getBlockTopicParams(cfg.timeParams), enableTopicMetrics = true)

  var envelopeGossipState: GossipState
  proc updateEnvelopeGossipStatus(slot: Slot) =
    envelopeGossipState.updateNewPayloadGossipStatus(
      "envelope", getExecutionPayloadTopic, basicParams())

  proc onSlot(wallTime: BeaconTime, lastSlot: Slot) =
    let
      wallSlot = wallTime.slotOrZero(cfg.timeParams)
      expectedSlot = lastSlot + 1
      delay = wallTime - expectedSlot.start_beacon_time(cfg.timeParams)

      finalizedHeader = lightClient.finalizedHeader
      optimisticHeader = lightClient.optimisticHeader

      finalizedBid = withForkyHeader(finalizedHeader):
        when lcDataFork > LightClientDataFork.None:
          forkyHeader.beacon.toBlockId()
        else:
          BlockId(root: genesisBlockRoot, slot: GENESIS_SLOT)
      optimisticBid = withForkyHeader(optimisticHeader):
        when lcDataFork > LightClientDataFork.None:
          forkyHeader.beacon.toBlockId()
        else:
          BlockId(root: genesisBlockRoot, slot: GENESIS_SLOT)

      syncStatus =
        if optimisticHeader.kind == LightClientDataFork.None:
          "bootstrapping(" & $config.trustedBlockRoot & ")"
        elif not isSynced(wallSlot):
          "syncing"
        else:
          "synced"

    info "Slot start",
      slot = shortLog(wallSlot),
      epoch = shortLog(wallSlot.epoch),
      sync = syncStatus,
      peers = len(network.peerPool),
      head = shortLog(optimisticBid),
      finalized = shortLog(finalizedBid),
      delay = shortLog(delay)

    beacon_slot.set wallSlot.toGaugeValue
    beacon_current_epoch.set wallSlot.epoch.toGaugeValue

  proc runOnSlotLoop() {.async.} =
    var
      curSlot = beaconClock.currentSlot
      nextSlot = curSlot + 1
      timeToNextSlot =
        nextSlot.start_beacon_time(cfg.timeParams) - beaconClock.now()
    while true:
      await sleepAsync(timeToNextSlot)

      let
        wallTime = beaconClock.now
        wallSlot = wallTime.slotOrZero(cfg.timeParams)

      onSlot(wallTime, curSlot)

      curSlot = wallSlot
      nextSlot = wallSlot + 1
      timeToNextSlot =
        nextSlot.start_beacon_time(cfg.timeParams) - beaconClock.now()

  proc onSecond(time: Moment) =
    # Nim GC metrics (for the main thread)
    updateThreadMetrics()

    let wallSlot = beaconClock.currentSlot
    if checkIfShouldStopAtEpoch(wallSlot, config.stopAtEpoch):
      quit(0)

    updateBlocksGossipStatus(wallSlot + 1)
    updateEnvelopeGossipStatus(wallSlot + 1)
    lightClient.updateGossipStatus(wallSlot + 1)

  proc runOnSecondLoop() {.async.} =
    let sleepTime = chronos.seconds(1)
    while true:
      let start = chronos.now(chronos.Moment)
      await chronos.sleepAsync(sleepTime)
      let afterSleep = chronos.now(chronos.Moment)
      let sleepTime = afterSleep - start
      onSecond(start)
      let finished = chronos.now(chronos.Moment)
      let processingTime = finished - afterSleep
      trace "onSecond task completed", sleepTime, processingTime

  onSecond(Moment.now())
  lightClient.start()

  asyncSpawn runOnSlotLoop()
  asyncSpawn runOnSecondLoop()

  while not ProcessState.stopIt(notice("Shutting down", reason = it)):
    poll()

when isMainModule:
  main()
