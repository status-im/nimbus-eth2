# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import validator_client/[common, fallback_service, duties_service,
                         attestation_service, fork_service, sync_committee_service]

proc initGenesis(vc: ValidatorClientRef): Future[RestGenesis] {.async.} =
  info "Initializing genesis", nodes_count = len(vc.beaconNodes)
  var nodes = vc.beaconNodes
  while true:
    var pending: seq[Future[RestResponse[GetGenesisResponse]]]
    for node in nodes:
      debug "Requesting genesis information", endpoint = node
      pending.add(node.client.getGenesis())

    try:
      await allFutures(pending)
    except CancelledError as exc:
      debug "Gensis information request was interrupted"
      raise exc

    let (errorNodes, genesisList) =
      block:
        var gres: seq[RestGenesis]
        var bres: seq[BeaconNodeServerRef]
        for i in 0 ..< len(pending):
          let fut = pending[i]
          if fut.done():
            let resp = fut.read()
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
            let error = fut.readError()
            debug "Could not obtain genesis information from beacon node",
                  endpoint = nodes[i], error_name = error.name,
                  error_msg = error.msg
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

proc initValidators(vc: ValidatorClientRef): Future[bool] {.async.} =
  info "Initializaing validators", path = vc.config.validatorsDir()
  var duplicates: seq[ValidatorPubKey]
  for keystore in listLoadableKeystores(vc.config):
    let pubkey = keystore.pubkey
    if pubkey in duplicates:
      error "Duplicate validator's key found", validator_pubkey = pubkey
      return false
    elif keystore.kind == KeystoreKind.Remote:
      info "Remote validator client was skipped", validator_pubkey = pubkey
      continue
    else:
      duplicates.add(pubkey)
      vc.attachedValidators.addLocalValidator(keystore)
  return true

proc initClock(vc: ValidatorClientRef): Future[BeaconClock] {.async.} =
  # This procedure performs initialization of BeaconClock using current genesis
  # information. It also performs waiting for genesis.
  let res = BeaconClock.init(vc.beaconGenesis.genesis_time)
  let currentSlot = res.now().slotOrZero()
  let currentEpoch = currentSlot.epoch()
  info "Initializing beacon clock",
       genesis_time = vc.beaconGenesis.genesis_time,
       current_slot = currentSlot, current_epoch = currentEpoch
  let genesisTime = res.fromNow(start_beacon_time(Slot(0)))
  if genesisTime.inFuture:
    notice "Waiting for genesis", genesisIn = genesisTime.offset
    await sleepAsync(genesisTime.offset)
  return res

proc onSlotStart(vc: ValidatorClientRef, wallTime: BeaconTime,
                 lastSlot: Slot): Future[bool] {.async.} =
  ## Called at the beginning of a slot - usually every slot, but sometimes might
  ## skip a few in case we're running late.
  ## wallTime: current system time - we will strive to perform all duties up
  ##           to this point in time
  ## lastSlot: the last slot that we successfully processed, so we know where to
  ##           start work from - there might be jumps if processing is delayed

  let
    # The slot we should be at, according to the clock
    beaconTime = wallTime
    wallSlot = wallTime.toSlot()

  let
    # If everything was working perfectly, the slot that we should be processing
    expectedSlot = lastSlot + 1
    delay = wallTime - expectedSlot.start_beacon_time()

  if checkIfShouldStopAtEpoch(wallSlot.slot, vc.config.stopAtEpoch):
    return true

  info "Slot start",
    slot = shortLog(wallSlot.slot),
    attestationIn = vc.getDurationToNextAttestation(wallSlot.slot),
    blockIn = vc.getDurationToNextBlock(wallSlot.slot),
    delay = shortLog(delay)

  return false

proc asyncInit(vc: ValidatorClientRef) {.async.} =
  vc.beaconGenesis = await vc.initGenesis()
  info "Genesis information", genesis_time = vc.beaconGenesis.genesis_time,
    genesis_fork_version = vc.beaconGenesis.genesis_fork_version,
    genesis_root = vc.beaconGenesis.genesis_validators_root

  vc.beaconClock = await vc.initClock()

  if not(await initValidators(vc)):
    fatal "Could not initialize local validators"

  info "Initializing slashing protection", path = vc.config.validatorsDir()
  vc.attachedValidators.slashingProtection =
    SlashingProtectionDB.init(
      vc.beaconGenesis.genesis_validators_root,
      vc.config.validatorsDir(), "slashing_protection"
    )

  try:
    vc.fallbackService = await FallbackServiceRef.init(vc)
    vc.forkService = await ForkServiceRef.init(vc)
    vc.dutiesService = await DutiesServiceRef.init(vc)
    vc.attestationService = await AttestationServiceRef.init(vc)
    vc.syncCommitteeService = await SyncCommitteeServiceRef.init(vc)
  except CancelledError:
    debug "Initialization process interrupted"
    info "Closing slashing protection", path = vc.config.validatorsDir()
    vc.attachedValidators.slashingProtection.close()

proc asyncRun(vc: ValidatorClientRef) {.async.} =
  vc.fallbackService.start()
  vc.forkService.start()
  vc.dutiesService.start()
  vc.attestationService.start()
  vc.syncCommitteeService.start()

  try:
    vc.runSlotLoopFut = runSlotLoop(vc, vc.beaconClock.now(), onSlotStart)
    await vc.runSlotLoopFut
  except CancelledError:
    debug "Main loop interrupted"
  except CatchableError as exc:
    debug "Main loop failed with an error", err_name = $exc.name,
          err_msg = $exc.msg

  info "Closing slashing protection", path = vc.config.validatorsDir()
  vc.attachedValidators.slashingProtection.close()
  debug "Stopping main processing loop"
  var pending: seq[Future[void]]
  if not(vc.runSlotLoopFut.finished()):
    pending.add(vc.runSlotLoopFut.cancelAndWait())
  if not(vc.sigintHandleFut.finished()):
    pending.add(vc.sigintHandleFut.cancelAndWait())
  if not(vc.sigtermHandleFut.finished()):
    pending.add(vc.sigtermHandleFut.cancelAndWait())
  debug "Stopping running services"
  pending.add(vc.fallbackService.stop())
  pending.add(vc.forkService.stop())
  pending.add(vc.dutiesService.stop())
  pending.add(vc.attestationService.stop())
  pending.add(vc.syncCommitteeService.stop())
  await allFutures(pending)
  info "Validator client stopped"

template runWithSignals(vc: ValidatorClientRef, body: untyped): bool =
  let future = body
  discard await race(future, vc.sigintHandleFut, vc.sigtermHandleFut)
  if future.finished():
    if future.failed() or future.cancelled():
      let exc = future.readError()
      debug "Validator client initialization failed", err_name = $exc.name,
            err_msg = $exc.msg
      var pending: seq[Future[void]]
      if not(vc.sigintHandleFut.finished()):
        pending.add(cancelAndWait(vc.sigintHandleFut))
      if not(vc.sigtermHandleFut.finished()):
        pending.add(cancelAndWait(vc.sigtermHandleFut))
      await allFutures(pending)
      false
    else:
      true
  else:
    let signal = if vc.sigintHandleFut.finished(): "SIGINT" else: "SIGTERM"
    error "Got interrupt, trying to shutdown gracefully", signal = signal
    var pending = @[cancelAndWait(future)]
    if not(vc.sigintHandleFut.finished()):
      pending.add(cancelAndWait(vc.sigintHandleFut))
    if not(vc.sigtermHandleFut.finished()):
      pending.add(cancelAndWait(vc.sigtermHandleFut))
    await allFutures(pending)
    false

proc asyncLoop*(vc: ValidatorClientRef) {.async.} =
  if not(vc.runWithSignals(asyncInit(vc))):
    return
  if not(vc.runWithSignals(asyncRun(vc))):
    return

programMain:
  let config = makeBannerAndConfig("Nimbus validator client " & fullVersionStr,
                                   ValidatorClientConf)

  setupLogging(config.logLevel, config.logStdout, config.logFile)

  let beaconNodes =
    block:
      var servers: seq[BeaconNodeServerRef]
      let flags = {RestClientFlag.CommaSeparatedArray}
      for url in config.beaconNodes:
        let res = RestClientRef.new(url, flags = flags)
        if res.isErr():
          warn "Unable to resolve remote beacon node server's hostname",
               url = url
        else:
          servers.add(BeaconNodeServerRef(client: res.get(), endpoint: url))
      servers

  if len(beaconNodes) == 0:
    # This should not happen, thanks to defaults in `conf.nim`
    fatal "Not enough beacon nodes in command line"
    quit 1

  notice "Launching validator client", version = fullVersionStr,
                                       cmdParams = commandLineParams(),
                                       config,
                                       beacon_nodes_count = len(beaconNodes)

  var vc =
    when declared(waitSignal):
      ValidatorClientRef(
        config: config,
        beaconNodes: beaconNodes,
        graffitiBytes: config.graffiti.get(defaultGraffitiBytes()),
        nodesAvailable: newAsyncEvent(),
        forksAvailable: newAsyncEvent(),
        sigintHandleFut: waitSignal(SIGINT),
        sigtermHandleFut: waitSignal(SIGTERM)
      )
    else:
      ValidatorClientRef(
        config: config,
        beaconNodes: beaconNodes,
        graffitiBytes: config.graffiti.get(defaultGraffitiBytes()),
        nodesAvailable: newAsyncEvent(),
        forksAvailable: newAsyncEvent(),
        sigintHandleFut: newFuture[void]("sigint_placeholder"),
        sigtermHandleFut: newFuture[void]("sigterm_placeholder")
      )

  waitFor asyncLoop(vc)
  info "Validator client stopped"
