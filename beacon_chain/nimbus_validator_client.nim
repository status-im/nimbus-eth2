# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/io2, presto, metrics, metrics/chronos_httpserver,
  ./rpc/rest_key_management_api,
  ./validator_client/[
    common, fallback_service, duties_service, fork_service, block_service,
    doppelganger_service, attestation_service, sync_committee_service, presets]

const
  PREGENESIS_EPOCHS_COUNT = 1

declareGauge validator_client_node_counts,
  "Number of connected beacon nodes and their status",
  labels = ["status"]

proc initGenesis(vc: ValidatorClientRef): Future[RestGenesis] {.
     async: (raises: [CancelledError]).} =
  info "Initializing genesis", nodes_count = len(vc.beaconNodes)
  var nodes = vc.beaconNodes
  while true:
    var pendingRequests: seq[Future[RestResponse[GetGenesisResponse]]]
    let offlineNodes = vc.offlineNodes()
    if len(offlineNodes) == 0:
      let sleepDuration = 2.seconds
      info "Could not resolve beacon nodes, repeating",
           sleep_time = sleepDuration
      await sleepAsync(sleepDuration)
      for node in vc.nonameNodes():
        let status = checkName(node)
        node.updateStatus(status, ApiNodeFailure())
        if status == RestBeaconNodeStatus.Noname:
          warn "Cannot initialize beacon node", node = node, status = status
      continue

    for node in offlineNodes:
      debug "Requesting genesis information", node = node
      pendingRequests.add(node.client.getGenesis())

    try:
      await allFutures(pendingRequests)
    except CancelledError as exc:
      var pending: seq[Future[void]]
      debug "Genesis information request was interrupted"
      for future in pendingRequests:
        if not(future.finished()):
          pending.add(future.cancelAndWait())
      await allFutures(pending)
      raise exc

    let (errorNodes, genesisList) =
      block:
        var gres: seq[RestGenesis]
        var bres: seq[BeaconNodeServerRef]
        for i in 0 ..< len(pendingRequests):
          let fut = pendingRequests[i]
          if fut.completed():
            let resp = fut.value
            if resp.status == 200:
              debug "Received genesis information", endpoint = nodes[i],
                    genesis_time = resp.data.data.genesis_time,
                    genesis_fork_version = resp.data.data.genesis_fork_version,
                    genesis_root = resp.data.data.genesis_validators_root
              gres.add(resp.data.data)
            else:
              debug "Received unsuccessful response code", endpoint = nodes[i],
                    response_code = resp.status
              bres.add(nodes[i])
          elif fut.failed():
            let error = fut.error
            debug "Could not obtain genesis information from beacon node",
                  endpoint = nodes[i], error_name = error.name,
                  reason = error.msg
            bres.add(nodes[i])
          else:
            debug "Interrupted while requesting information from beacon node",
                  endpoint = nodes[i]
            bres.add(nodes[i])
        (bres, gres)

    if len(genesisList) == 0:
      let sleepDuration = 2.seconds
      info "Could not obtain network genesis information from nodes, repeating",
           sleep_time = sleepDuration
      await sleepAsync(sleepDuration)
      nodes = errorNodes
    else:
      # Boyer-Moore majority vote algorithm
      var melem: RestGenesis
      var counter = 0
      for item in genesisList:
        if counter == 0:
          melem = item
          inc(counter)
        else:
          if melem == item:
            inc(counter)
          else:
            dec(counter)
      return melem

proc addValidatorsFromWeb3Signer(
    vc: ValidatorClientRef,
    web3signerUrl: Web3SignerUrl
) {.async: (raises: [CancelledError]).} =
  let res = await queryValidatorsSource(web3signerUrl)
  if res.isOk():
    let dynamicKeystores = res.get()
    for keystore in dynamicKeystores:
      vc.addValidator(keystore)

proc initValidators(
    vc: ValidatorClientRef
): Future[bool] {.async: (raises: [CancelledError]).} =
  info "Loading validators", validatorsDir = vc.config.validatorsDir()
  for keystore in listLoadableKeystores(vc.config, vc.keystoreCache):
    vc.addValidator(keystore)

  let web3signerValidatorsFuts = mapIt(
    vc.config.web3SignerUrls,
    vc.addValidatorsFromWeb3Signer(it))

  # We use `allFutures` because all failures are already reported as
  # user-visible warnings in `queryValidatorsSource`.
  # We don't consider them fatal because the Web3Signer may be experiencing
  # a temporary hiccup that will be resolved later.
  await allFutures(web3signerValidatorsFuts)

  true

proc initClock(
    vc: ValidatorClientRef
): Future[BeaconClock] {.
   async: (raises: [CancelledError, ValidatorClientError]).} =
  # This procedure performs initialization of BeaconClock using current genesis
  # information. It also performs waiting for genesis.
  let
    res = BeaconClock.init(vc.beaconGenesis.genesis_time).valueOr:
      raise (ref ValidatorClientError)(
        msg: "Invalid genesis time: " & $vc.beaconGenesis.genesis_time)
    currentTime = res.now()
    currentSlot = currentTime.slotOrZero()
    currentEpoch = currentSlot.epoch()
    genesisTime = res.fromNow(Slot(0))

  if genesisTime.inFuture:
    info "Initializing beacon clock",
         genesis_time = vc.beaconGenesis.genesis_time,
         current_slot = "<n/a>", current_epoch = "<n/a>",
         time_to_genesis = genesisTime.offset
  else:
    info "Initializing beacon clock",
         genesis_time = vc.beaconGenesis.genesis_time,
         current_slot = currentSlot, current_epoch = currentEpoch
  res

proc initMetrics(
    vc: ValidatorClientRef
): Future[bool] {.async: (raises: [CancelledError]).} =
  if vc.config.metricsEnabled:
    let
      metricsAddress = vc.config.metricsAddress
      metricsPort = vc.config.metricsPort
      url = "http://" & $metricsAddress & ":" & $metricsPort & "/metrics"
    info "Starting metrics HTTP server", url = url
    let server =
      block:
        let res = MetricsHttpServerRef.new($metricsAddress, metricsPort)
        if res.isErr():
          error "Could not start metrics HTTP server", url = url,
                error_msg = res.error()
          return false
        res.get()
    vc.metricsServer = Opt.some(server)
    try:
      await server.start()
    except MetricsError as exc:
      error "Could not start metrics HTTP server", url = url,
            error_msg = exc.msg, error_name = exc.name
      return false
  true

proc shutdownMetrics(vc: ValidatorClientRef) {.async: (raises: []).} =
  if vc.config.metricsEnabled:
    if vc.metricsServer.isSome():
      info "Shutting down metrics HTTP server"
      await vc.metricsServer.get().close()

proc shutdownSlashingProtection(vc: ValidatorClientRef) =
  info "Closing slashing protection", path = vc.config.validatorsDir()
  vc.attachedValidators[].slashingProtection.close()

proc runVCSlotLoop(
    vc: ValidatorClientRef) {.async: (raises: [CancelledError]).} =
  var
    startTime = vc.beaconClock.now()
    curSlot = startTime.slotOrZero()
    nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
    timeToNextSlot = nextSlot.start_beacon_time() - startTime

  info "Scheduling first slot action",
       start_time = shortLog(startTime),
       current_slot = shortLog(curSlot),
       next_slot = shortLog(nextSlot),
       time_to_next_slot = shortLog(timeToNextSlot)

  var currentSlot = Opt.some(curSlot)

  while true:
    currentSlot = await vc.checkedWaitForNextSlot(currentSlot, ZeroTimeDiff,
                                                  true)
    if currentSlot.isNone():
      ## Fatal log line should be printed by checkedWaitForNextSlot().
      return

    let
      wallTime = vc.beaconClock.now()
      wallSlot = currentSlot.get()
      delay = wallTime - wallSlot.start_beacon_time()

    if checkIfShouldStopAtEpoch(wallSlot, vc.config.stopAtEpoch):
      return

    vc.processingDelay = Opt.some(nanoseconds(delay.nanoseconds))

    let
      counts = vc.getNodeCounts()
      # Good nodes are nodes which can be used for ALL the requests.
      goodNodes = counts.data[int(RestBeaconNodeStatus.Synced)]
      # Viable nodes are nodes which can be used only SOME of the requests.
      viableNodes = counts.data[int(RestBeaconNodeStatus.OptSynced)] +
                    counts.data[int(RestBeaconNodeStatus.NotSynced)] +
                    counts.data[int(RestBeaconNodeStatus.Compatible)]
      # Bad nodes are nodes which can't be used at all.
      badNodes = counts.data[int(RestBeaconNodeStatus.Offline)] +
                 counts.data[int(RestBeaconNodeStatus.Online)] +
                 counts.data[int(RestBeaconNodeStatus.Incompatible)]

    validator_client_node_counts.set(int64(goodNodes), ["good"])
    validator_client_node_counts.set(int64(viableNodes), ["viable"])
    validator_client_node_counts.set(int64(badNodes), ["bad"])

    if len(vc.beaconNodes) > 1:
      info "Slot start",
        slot = shortLog(wallSlot),
        epoch = shortLog(wallSlot.epoch()),
        attestationIn = vc.getDurationToNextAttestation(wallSlot),
        blockIn = vc.getDurationToNextBlock(wallSlot),
        validators = vc.attachedValidators[].count(),
        good_nodes = goodNodes, viable_nodes = viableNodes,
        bad_nodes = badNodes,
        delay = shortLog(delay)
    else:
      info "Slot start",
        slot = shortLog(wallSlot),
        epoch = shortLog(wallSlot.epoch()),
        attestationIn = vc.getDurationToNextAttestation(wallSlot),
        blockIn = vc.getDurationToNextBlock(wallSlot),
        validators = vc.attachedValidators[].count(),
        node_status = $vc.beaconNodes[0].status,
        delay = shortLog(delay)

proc new*(
    T: type ValidatorClientRef,
    config: ValidatorClientConf,
    rng: ref HmacDrbgContext
): ValidatorClientRef =
  let beaconNodes =
    block:
      var servers: seq[BeaconNodeServerRef]
      for index, url in config.beaconNodes.pairs():
        let res = BeaconNodeServerRef.init(url, index)
        if res.isErr():
          warn "Unable to initialize remote beacon node",
                url = $url, error = res.error()
        else:
          if res.get().status != RestBeaconNodeStatus.Noname:
            debug "Beacon node was initialized", node = res.get()
          servers.add(res.get())
      let missingRoles = getMissingRoles(servers)
      if len(missingRoles) != 0:
        if len(servers) == 0:
          fatal "Not enough beacon nodes available",
                nodes_count = len(servers)
          quit 1
        else:
          fatal "Beacon nodes do not cover all required roles",
                missing_roles = $missingRoles, nodes_count = len(servers)
          quit 1
      servers

  when declared(waitSignal):
    ValidatorClientRef(
      rng: rng,
      config: config,
      beaconNodes: beaconNodes,
      graffitiBytes: config.graffiti.get(defaultGraffitiBytes()),
      preGenesisEvent: newAsyncEvent(),
      genesisEvent: newAsyncEvent(),
      nodesAvailable: newAsyncEvent(),
      forksAvailable: newAsyncEvent(),
      doppelExit: newAsyncEvent(),
      indicesAvailable: newAsyncEvent(),
      dynamicFeeRecipientsStore: newClone(DynamicFeeRecipientsStore.init()),
      sigintHandleFut: waitSignal(SIGINT),
      sigtermHandleFut: waitSignal(SIGTERM),
      keystoreCache: KeystoreCacheRef.init()
    )
  else:
    ValidatorClientRef(
      rng: rng,
      config: config,
      beaconNodes: beaconNodes,
      graffitiBytes: config.graffiti.get(defaultGraffitiBytes()),
      preGenesisEvent: newAsyncEvent(),
      genesisEvent: newAsyncEvent(),
      nodesAvailable: newAsyncEvent(),
      forksAvailable: newAsyncEvent(),
      indicesAvailable: newAsyncEvent(),
      doppelExit: newAsyncEvent(),
      dynamicFeeRecipientsStore: newClone(DynamicFeeRecipientsStore.init()),
      sigintHandleFut: newFuture[void]("sigint_placeholder"),
      sigtermHandleFut: newFuture[void]("sigterm_placeholder"),
      keystoreCache: KeystoreCacheRef.init()
    )

proc asyncInit(vc: ValidatorClientRef): Future[ValidatorClientRef] {.
     async: (raises: [CancelledError, ValidatorClientError]).} =
  notice "Launching validator client", version = fullVersionStr,
                                       cmdParams = commandLineParams(),
                                       config = vc.config,
                                       beacon_nodes_count = len(vc.beaconNodes)

  for node in vc.beaconNodes:
    if node.status == RestBeaconNodeStatus.Offline:
      notice "Beacon node initialized", node = node
    else:
      notice "Cannot initialize beacon node", node = node, status = node.status

  vc.beaconGenesis = await vc.initGenesis()
  info "Genesis information", genesis_time = vc.beaconGenesis.genesis_time,
       genesis_fork_version = vc.beaconGenesis.genesis_fork_version,
       genesis_root = vc.beaconGenesis.genesis_validators_root

  vc.beaconClock = await vc.initClock()

  if not(await initMetrics(vc)):
    raise newException(ValidatorClientError,
                       "Could not initialize metrics server")

  info "Initializing slashing protection", path = vc.config.validatorsDir()

  let
    slashingProtectionDB =
      SlashingProtectionDB.init(
        vc.beaconGenesis.genesis_validators_root,
        vc.config.validatorsDir(), "slashing_protection")
    validatorPool = newClone(ValidatorPool.init(
      slashingProtectionDB, vc.config.doppelgangerDetection))

  vc.attachedValidators = validatorPool

  if not(await initValidators(vc)):
    await vc.shutdownMetrics()
    raise newException(ValidatorClientError,
                       "Could not initialize local validators")

  let
    keymanagerInitResult = initKeymanagerServer(vc.config, nil)

  func getCapellaForkVersion(): Opt[Version] =
    Opt.some(version(ConsensusFork.Capella))

  func getDenebForkEpoch(): Opt[Epoch] =
    vc.getForkEpoch(ConsensusFork.Deneb)

  proc getForkForEpoch(epoch: Epoch): Opt[Fork] =
    if len(vc.forks) > 0:
      Opt.some(vc.forkAtEpoch(epoch))
    else:
      Opt.none(Fork)

  proc getGenesisRoot(): Eth2Digest =
    vc.beaconGenesis.genesis_validators_root

  try:
    vc.fallbackService = await FallbackServiceRef.init(vc)
    vc.forkService = await ForkServiceRef.init(vc)
    vc.dutiesService = await DutiesServiceRef.init(vc)
    vc.doppelgangerService = await DoppelgangerServiceRef.init(vc)
    vc.attestationService = await AttestationServiceRef.init(vc)
    vc.blockService = await BlockServiceRef.init(vc)
    vc.syncCommitteeService = await SyncCommitteeServiceRef.init(vc)
    vc.keymanagerServer = keymanagerInitResult.server
    if not(isNil(vc.keymanagerServer)):
      vc.keymanagerHost = newClone KeymanagerHost.init(
        validatorPool,
        vc.keystoreCache,
        vc.rng,
        keymanagerInitResult.token,
        vc.config.validatorsDir,
        vc.config.secretsDir,
        vc.config.defaultFeeRecipient,
        vc.config.suggestedGasLimit,
        vc.config.defaultGraffitiBytes,
        Opt.none(string),
        nil,
        vc.beaconClock.getBeaconTimeFn,
        getCapellaForkVersion,
        getDenebForkEpoch,
        getForkForEpoch,
        getGenesisRoot
        )
  except CancelledError:
    debug "Initialization process interrupted"
    await vc.shutdownMetrics()
    vc.shutdownSlashingProtection()
    return

  return vc

proc runPreGenesisWaitingLoop(
    vc: ValidatorClientRef
) {.async: (raises: [CancelledError]).} =
  var breakLoop = false
  while not(breakLoop):
    let
      genesisTime = vc.beaconClock.fromNow(Slot(0))
      currentEpoch = vc.beaconClock.now().toSlot().slot.epoch()

    if not(genesisTime.inFuture) or currentEpoch < PREGENESIS_EPOCHS_COUNT:
      break

    notice "Waiting for genesis",
           genesis_time = vc.beaconGenesis.genesis_time,
           time_to_genesis = genesisTime.offset

    breakLoop =
      try:
        await sleepAsync(vc.beaconClock.durationToNextSlot())
        false
      except CancelledError as exc:
        debug "Pre-genesis waiting loop was interrupted"
        raise exc

  if not(breakLoop):
    vc.preGenesisEvent.fire()

proc runGenesisWaitingLoop(
    vc: ValidatorClientRef
) {.async: (raises: [CancelledError]).} =
  var breakLoop = false
  while not(breakLoop):
    let genesisTime = vc.beaconClock.fromNow(Slot(0))

    if not(genesisTime.inFuture):
      break

    notice "Waiting for genesis",
           genesis_time = vc.beaconGenesis.genesis_time,
           time_to_genesis = genesisTime.offset

    breakLoop =
      try:
        await sleepAsync(vc.beaconClock.durationToNextSlot())
        false
      except CancelledError as exc:
        debug "Genesis waiting loop was interrupted"
        raise exc

  if not(breakLoop):
    vc.genesisEvent.fire()

proc asyncRun*(
    vc: ValidatorClientRef
) {.async: (raises: [ValidatorClientError]).} =
  vc.fallbackService.start()
  vc.forkService.start()
  vc.dutiesService.start()
  vc.doppelgangerService.start()
  vc.attestationService.start()
  vc.blockService.start()
  vc.syncCommitteeService.start()

  if not(isNil(vc.keymanagerServer)):
    doAssert not(isNil(vc.keymanagerHost))
    vc.keymanagerServer.router.installKeymanagerHandlers(vc.keymanagerHost[])
    vc.keymanagerServer.start()

  let doppelEventFut = vc.doppelExit.wait()
  try:
    # Waiting for `GENESIS - PREGENESIS_EPOCHS_COUNT` loop.
    await vc.runPreGenesisWaitingLoop()
    # Waiting for `GENESIS` loop.
    await vc.runGenesisWaitingLoop()
    # Main processing loop.
    vc.runSlotLoopFut = vc.runVCSlotLoop()
    vc.runKeystoreCachePruningLoopFut =
      runKeystoreCachePruningLoop(vc.keystoreCache)
    discard await race(vc.runSlotLoopFut, doppelEventFut)
    if not(vc.runSlotLoopFut.finished()):
      notice "Received shutdown event, exiting"
  except CancelledError:
    debug "Main loop interrupted"

  await vc.shutdownMetrics()
  vc.shutdownSlashingProtection()

  if doppelEventFut.completed():
    # Critically, database has been shut down - the rest doesn't matter, we need
    # to stop as soon as possible
    quitDoppelganger()

  debug "Stopping main processing loop"
  var pending: seq[Future[void]]
  if not(isNil(vc.runSlotLoopFut)) and not(vc.runSlotLoopFut.finished()):
    pending.add(vc.runSlotLoopFut.cancelAndWait())
  if not(isNil(vc.runKeystoreCachePruningLoopFut)) and
     not(vc.runKeystoreCachePruningLoopFut.finished()):
    pending.add(vc.runKeystoreCachePruningLoopFut.cancelAndWait())
  if not(doppelEventFut.finished()):
    pending.add(doppelEventFut.cancelAndWait())
  debug "Stopping running services"
  pending.add(vc.fallbackService.stop())
  pending.add(vc.forkService.stop())
  pending.add(vc.dutiesService.stop())
  pending.add(vc.doppelgangerService.stop())
  pending.add(vc.attestationService.stop())
  pending.add(vc.blockService.stop())
  pending.add(vc.syncCommitteeService.stop())
  if not isNil(vc.keymanagerServer):
    pending.add(vc.keymanagerServer.stop())
  await noCancel allFutures(pending)

template runWithSignals(vc: ValidatorClientRef, body: untyped): bool =
  let future = body

  try:
    discard await race(future, vc.sigintHandleFut, vc.sigtermHandleFut)
  except CancelledError:
    discard

  if future.finished():
    if future.failed() or future.cancelled():
      let exc = future.error
      error "Validator client initialization failed", err_name = $exc.name,
            err_msg = $exc.msg
      var pending: seq[Future[void]]
      if not(vc.sigintHandleFut.finished()):
        pending.add(cancelAndWait(vc.sigintHandleFut))
      if not(vc.sigtermHandleFut.finished()):
        pending.add(cancelAndWait(vc.sigtermHandleFut))
      await noCancel allFutures(pending)
      false
    else:
      true
  else:
    let signal = if vc.sigintHandleFut.finished(): "SIGINT" else: "SIGTERM"
    info "Got interrupt, trying to shutdown gracefully", signal = signal
    var pending = @[cancelAndWait(future)]
    if not(vc.sigintHandleFut.finished()):
      pending.add(cancelAndWait(vc.sigintHandleFut))
    if not(vc.sigtermHandleFut.finished()):
      pending.add(cancelAndWait(vc.sigtermHandleFut))
    await noCancel allFutures(pending)
    false

proc runValidatorClient*(
    config: ValidatorClientConf,
    rng: ref HmacDrbgContext
) {.async: (raises: []).} =
  let vc = ValidatorClientRef.new(config, rng)
  if not vc.runWithSignals(asyncInit vc):
    return
  if not vc.runWithSignals(asyncRun vc):
    return

programMain:
  let
    config = makeBannerAndConfig("Nimbus validator client " & fullVersionStr,
                                 ValidatorClientConf)

    # Single RNG instance for the application - will be seeded on construction
    # and avoid using system resources (such as urandom) after that
    rng = HmacDrbgContext.new()

  setupFileLimits()
  setupLogging(config.logLevel, config.logStdout, config.logFile)
  waitFor runValidatorClient(config, rng)
