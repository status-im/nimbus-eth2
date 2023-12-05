# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import common

const
  ServiceName = "fallback_service"

  FAIL_TIME_OFFSETS = [
    TimeOffset.init(-(MAXIMUM_GOSSIP_CLOCK_DISPARITY.nanoseconds)),
    TimeOffset.init(MAXIMUM_GOSSIP_CLOCK_DISPARITY.nanoseconds * 4)
  ]
  WARN_TIME_OFFSETS = [
    TimeOffset.init(-(MAXIMUM_GOSSIP_CLOCK_DISPARITY.nanoseconds div 2)),
    TimeOffset.init(MAXIMUM_GOSSIP_CLOCK_DISPARITY.nanoseconds * 2),
  ]
  NOTE_TIME_OFFSETS = [
    TimeOffset.init(-(MAXIMUM_GOSSIP_CLOCK_DISPARITY.nanoseconds div 4)),
    TimeOffset.init(MAXIMUM_GOSSIP_CLOCK_DISPARITY.nanoseconds),
  ]

declareGauge validator_client_time_offset,
  "Wall clock offset(s) between validator client and beacon node(s)",
  labels = ["node"]

logScope: service = ServiceName

proc nodesCount*(vc: ValidatorClientRef,
                 statuses: set[RestBeaconNodeStatus],
                 roles: set[BeaconNodeRole] = {}): int =
  if len(roles) == 0:
    vc.beaconNodes.countIt(it.status in statuses)
  else:
    vc.beaconNodes.countIt((it.roles * roles != {}) and (it.status in statuses))

proc filterNodes*(vc: ValidatorClientRef, statuses: set[RestBeaconNodeStatus],
                  roles: set[BeaconNodeRole] = {}): seq[BeaconNodeServerRef] =
  if len(roles) == 0:
    vc.beaconNodes.filterIt(it.status in statuses)
  else:
    vc.beaconNodes.filterIt((it.roles * roles != {}) and
                            (it.status in statuses))

proc nonameNodes*(vc: ValidatorClientRef): seq[BeaconNodeServerRef] =
  vc.beaconNodes.filterIt(it.status == RestBeaconNodeStatus.Noname)

proc offlineNodes*(vc: ValidatorClientRef): seq[BeaconNodeServerRef] =
  vc.beaconNodes.filterIt(it.status == RestBeaconNodeStatus.Offline)

proc otherNodes*(vc: ValidatorClientRef): seq[BeaconNodeServerRef] =
  vc.beaconNodes.filterIt(it.status != RestBeaconNodeStatus.Synced)

proc otherNodesCount*(vc: ValidatorClientRef): int =
  vc.beaconNodes.countIt(it.status != RestBeaconNodeStatus.Synced)

proc preGenesisNodes*(vc: ValidatorClientRef): seq[BeaconNodeServerRef] =
  vc.beaconNodes.filterIt(it.status notin {RestBeaconNodeStatus.Synced,
                                           RestBeaconNodeStatus.OptSynced})

proc waitNodes*(vc: ValidatorClientRef, timeoutFut: Future[void],
                statuses: set[RestBeaconNodeStatus],
                roles: set[BeaconNodeRole], waitChanges: bool) {.async.} =
  doAssert(not(isNil(vc.fallbackService)))
  var iterations = 0
  while true:
    if not(waitChanges) or (iterations != 0):
      if vc.nodesCount(statuses, roles) != 0:
        break

    if vc.fallbackService.changesEvent.isSet():
      vc.fallbackService.changesEvent.clear()

    if isNil(timeoutFut):
      await vc.fallbackService.changesEvent.wait()
    else:
      let breakLoop =
        block:
          let waitFut = vc.fallbackService.changesEvent.wait()
          try:
            discard await race(waitFut, timeoutFut)
          except CancelledError as exc:
            if not(waitFut.finished()):
              await waitFut.cancelAndWait()
            raise exc

          if not(waitFut.finished()):
            await waitFut.cancelAndWait()
            true
          else:
            false
      if breakLoop:
        break

    inc(iterations)

proc checkName*(
       node: BeaconNodeServerRef): RestBeaconNodeStatus {.raises: [].} =
  ## Could return only {Invalid, Noname, Offline}
  logScope: endpoint = node
  let client =
    block:
      let res = initClient(node.uri)
      if res.isErr():
        return
          case res.error
          of CriticalHttpAddressError:
            RestBeaconNodeStatus.Invalid
          of RecoverableHttpAddressError:
            RestBeaconNodeStatus.Noname
      res.get()

  node.client = client
  RestBeaconNodeStatus.Offline

proc checkCompatible(
       vc: ValidatorClientRef,
       node: BeaconNodeServerRef
     ): Future[RestBeaconNodeStatus] {.async.} =
  ## Could return only {Offline, Incompatible, Compatible}
  logScope: endpoint = node
  let info =
    try:
      debug "Requesting beacon node network configuration"
      let res = await node.client.getSpecVC()
      res.data.data
    except CancelledError as exc:
      debug "Configuration request was interrupted"
      raise exc
    except RestError as exc:
      if node.status != RestBeaconNodeStatus.Offline:
        debug "Unable to obtain beacon node's configuration",
              error_name = exc.name, error_message = exc.msg
      return RestBeaconNodeStatus.Offline
    except CatchableError as exc:
      if node.status != RestBeaconNodeStatus.Offline:
        error "Unexpected exception", error_name = exc.name,
              error_message = exc.msg
      return RestBeaconNodeStatus.Offline

  let genesis =
    try:
      debug "Requesting beacon node genesis information"
      let res = await node.client.getGenesis()
      res.data.data
    except CancelledError as exc:
      debug "Genesis request was interrupted"
      raise exc
    except RestError as exc:
      if node.status != RestBeaconNodeStatus.Offline:
        debug "Unable to obtain beacon node's genesis",
              error_name = exc.name, error_message = exc.msg
      return RestBeaconNodeStatus.Offline
    except CatchableError as exc:
      if node.status != RestBeaconNodeStatus.Offline:
        error "Unexpected exception", error_name = exc.name,
              error_message = exc.msg
      return RestBeaconNodeStatus.Offline

  let
    genesisFlag = (genesis != vc.beaconGenesis)
    configFlag = not(checkConfig(info))

  node.config = info
  node.genesis = Opt.some(genesis)

  return
    if configFlag or genesisFlag:
      if node.status != RestBeaconNodeStatus.Incompatible:
        warn "Beacon node has incompatible configuration",
              genesis_flag = genesisFlag, config_flag = configFlag
      RestBeaconNodeStatus.Incompatible
    else:
      let res = vc.updateRuntimeConfig(node, node.config)
      if res.isErr():
        warn "Beacon nodes report different configuration values",
             reason = res.error
        RestBeaconNodeStatus.Incompatible
      else:
        RestBeaconNodeStatus.Compatible

proc checkSync(
       vc: ValidatorClientRef,
       node: BeaconNodeServerRef
     ): Future[RestBeaconNodeStatus] {.async.} =
  ## Could return only {Offline, NotSynced, Synced, OptSynced}
  logScope: endpoint = node
  let syncInfo =
    try:
      debug "Requesting beacon node sync status"
      let res = await node.client.getSyncingStatus()
      res.data.data
    except CancelledError as exc:
      debug "Sync status request was interrupted"
      raise exc
    except RestError as exc:
      if node.status != RestBeaconNodeStatus.Offline:
        debug "Unable to obtain beacon node's sync status",
              error_name = exc.name, error_message = exc.msg
      return RestBeaconNodeStatus.Offline
    except CatchableError as exc:
      if node.status != RestBeaconNodeStatus.Offline:
        error "Unexpected exception", error_name = exc.name,
              error_message = exc.msg
      return RestBeaconNodeStatus.Offline
  node.syncInfo = Opt.some(syncInfo)
  let res =
    block:
      if not(syncInfo.is_syncing) or (syncInfo.sync_distance < SYNC_TOLERANCE):
        if not(syncInfo.is_optimistic.get(false)):
          RestBeaconNodeStatus.Synced
        else:
          RestBeaconNodeStatus.OptSynced
      else:
        RestBeaconNodeStatus.NotSynced
  return res

proc checkOnline(
       node: BeaconNodeServerRef
     ): Future[RestBeaconNodeStatus] {.async.} =
  ## Could return only {Offline, Online}.
  logScope: endpoint = node
  debug "Checking beacon node status"
  let agent =
    try:
      let res = await node.client.getNodeVersion()
      res.data.data
    except CancelledError as exc:
      debug "Status request was interrupted"
      raise exc
    except RestError as exc:
      debug "Unable to check beacon node's status",
            error_name = exc.name, error_message = exc.msg
      return RestBeaconNodeStatus.Offline
    except CatchableError as exc:
      error "Unexpected exception", error_name = exc.name,
            error_message = exc.msg
      return RestBeaconNodeStatus.Offline
  node.ident = Opt.some(agent.version)
  return RestBeaconNodeStatus.Online

func getReason(status: RestBeaconNodeStatus): string =
  case status
  of RestBeaconNodeStatus.Invalid:
    "Beacon node address invalid"
  of RestBeaconNodeStatus.Noname:
    "Beacon node address cannot be resolved"
  of RestBeaconNodeStatus.Offline:
    "Connection with node has been lost"
  of RestBeaconNodeStatus.Online:
    "Connection with node has been established"
  else:
    "Beacon node reports"

proc checkNode(vc: ValidatorClientRef,
               node: BeaconNodeServerRef): Future[bool] {.async.} =
  let nstatus = node.status
  debug "Checking beacon node", endpoint = node, status = node.status

  if nstatus in {RestBeaconNodeStatus.Noname}:
    let
      status = node.checkName()
      failure = ApiNodeFailure.init(ApiFailure.NoError, "checkName",
                                    node, status.getReason())
    node.updateStatus(status, failure)
    if status != RestBeaconNodeStatus.Offline:
      return nstatus != status

  if nstatus in {RestBeaconNodeStatus.Offline,
                 RestBeaconNodeStatus.UnexpectedCode,
                 RestBeaconNodeStatus.UnexpectedResponse,
                 RestBeaconNodeStatus.InternalError}:
    let
      status = await node.checkOnline()
      failure = ApiNodeFailure.init(ApiFailure.NoError, "checkOnline",
                                    node, status.getReason())
    node.updateStatus(status, failure)
    if status != RestBeaconNodeStatus.Online:
      return nstatus != status

  if nstatus in {RestBeaconNodeStatus.Offline,
                 RestBeaconNodeStatus.UnexpectedCode,
                 RestBeaconNodeStatus.UnexpectedResponse,
                 RestBeaconNodeStatus.InternalError,
                 RestBeaconNodeStatus.Online,
                 RestBeaconNodeStatus.Incompatible}:
    let
      status = await vc.checkCompatible(node)
      failure = ApiNodeFailure.init(ApiFailure.NoError, "checkCompatible",
                                    node, status.getReason())
    node.updateStatus(status, failure)
    if status != RestBeaconNodeStatus.Compatible:
      return nstatus != status

  if nstatus in {RestBeaconNodeStatus.Offline,
                 RestBeaconNodeStatus.UnexpectedCode,
                 RestBeaconNodeStatus.UnexpectedResponse,
                 RestBeaconNodeStatus.InternalError,
                 RestBeaconNodeStatus.Online,
                 RestBeaconNodeStatus.Incompatible,
                 RestBeaconNodeStatus.Compatible,
                 RestBeaconNodeStatus.OptSynced,
                 RestBeaconNodeStatus.NotSynced}:
    let
      status = await vc.checkSync(node)
      failure = ApiNodeFailure.init(ApiFailure.NoError, "checkSync",
                                    node, status.getReason())
    node.updateStatus(status, failure)
    return nstatus != status

proc checkNodes*(service: FallbackServiceRef): Future[bool] {.async.} =
  let
    vc = service.client
    nodesToCheck =
      if vc.genesisEvent.isSet():
        service.client.otherNodes()
      else:
        service.client.preGenesisNodes()
    pendingChecks = nodesToCheck.mapIt(service.client.checkNode(it))
  var res = false
  try:
    await allFutures(pendingChecks)
    for fut in pendingChecks:
      if fut.completed() and fut.read():
        res = true
  except CancelledError as exc:
    let pending = pendingChecks
      .filterIt(not(it.finished())).mapIt(it.cancelAndWait())
    await noCancel allFutures(pending)
    raise exc
  return res

proc checkOffsetStatus(node: BeaconNodeServerRef, offset: TimeOffset) =
  logScope:
    node = node

  node.timeOffset = Opt.some(offset)
  validator_client_time_offset.set(float64(offset.milliseconds()), @[$node])

  debug "Beacon node time offset", time_offset = offset

  let updateStatus =
    if (offset <= WARN_TIME_OFFSETS[0]) or (offset >= WARN_TIME_OFFSETS[1]):
      warn "Beacon node has significant time offset",
           time_offset = offset
      if (offset <= FAIL_TIME_OFFSETS[0]) or (offset >= FAIL_TIME_OFFSETS[1]):
        # Beacon node's clock is out of acceptable offsets, we marking this
        # beacon node and remote it from the list of working nodes.
        warn "Beacon node has enormous time offset",
             time_offset = offset
        let failure = ApiNodeFailure.init(ApiFailure.NoError,
          "checkTimeOffsetStatus()", node, 200,
          "Beacon node has enormous time offset")
        node.updateStatus(RestBeaconNodeStatus.BrokenClock, failure)
        false
      else:
        true
    elif (offset <= NOTE_TIME_OFFSETS[0]) or (offset >= NOTE_TIME_OFFSETS[1]):
      info "Beacon node has notable time offset",
           time_offset = offset
      true
    else:
      true

  if updateStatus:
    if node.status == RestBeaconNodeStatus.BrokenClock:
      # Beacon node's clock has been recovered to some acceptable offset, so we
      # could restore beacon node.
      let failure = ApiNodeFailure.init(ApiFailure.NoError,
          "checkTimeOffsetStatus()", node, 200,
          "Beacon node has acceptable time offset")
      node.updateStatus(RestBeaconNodeStatus.Offline, failure)

proc runTimeMonitor(service: FallbackServiceRef,
                    node: BeaconNodeServerRef) {.async.} =
  const NimbusExtensionsLog = "Beacon node do not support nimbus extensions"
  let
    vc = service.client
    roles = AllBeaconNodeRoles
    statuses = AllBeaconNodeStatuses - {RestBeaconNodeStatus.Offline}

  logScope:
    node = node

  if BeaconNodeRole.NoTimeCheck in node.roles:
    debug "Beacon node time offset checks disabled"
    return

  while true:
    while node.status notin statuses:
      await vc.waitNodes(nil, statuses, roles, true)

    if RestBeaconNodeFeature.NoNimbusExtensions in node.features:
      return

    let tres =
      try:
        let
          delay = vc.processingDelay.valueOr: ZeroDuration
          res = await node.client.getTimeOffset(delay)
        Opt.some(res)
      except RestResponseError as exc:
        case exc.status
        of 400:
          debug "Beacon node returns invalid response",
                status = $exc.status, reason = $exc.msg,
                error_message = $exc.message
        else:
          notice NimbusExtensionsLog, status = $exc.status,
                 reason = $exc.msg, error_message = $exc.message
          # Exiting loop
        node.features.incl(RestBeaconNodeFeature.NoNimbusExtensions)
        return
      except RestError as exc:
        debug "Unable to obtain beacon node's time offset", reason = $exc.msg
        notice NimbusExtensionsLog
        node.features.incl(RestBeaconNodeFeature.NoNimbusExtensions)
        return
      except CancelledError as exc:
        raise exc
      except CatchableError as exc:
        warn "An unexpected error occurred while asking for time offset",
             reason = $exc.msg, error = $exc.name
        notice NimbusExtensionsLog
        node.features.incl(RestBeaconNodeFeature.NoNimbusExtensions)
        return

    if tres.isSome():
      checkOffsetStatus(node, TimeOffset.init(tres.get()))
    else:
      debug "Beacon node's time offset was not updated"

    await service.waitForNextSlot()

proc processTimeMonitoring(service: FallbackServiceRef) {.async.} =
  let
    vc = service.client
    blockNodes = vc.filterNodes(
      ResolvedBeaconNodeStatuses, AllBeaconNodeRoles)

  var pendingChecks: seq[Future[void]]

  try:
    for node in blockNodes:
      pendingChecks.add(service.runTimeMonitor(node))
    await allFutures(pendingChecks)
  except CancelledError as exc:
    let pending = pendingChecks
      .filterIt(not(it.finished())).mapIt(it.cancelAndWait())
    await noCancel allFutures(pending)
    raise exc
  except CatchableError as exc:
    warn "An unexpected error occurred while running time monitoring",
         reason = $exc.msg, error = $exc.name
    return

proc mainLoop(service: FallbackServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  let timeMonitorFut = processTimeMonitoring(service)

  try:
    await vc.preGenesisEvent.wait()
  except CancelledError:
    debug "Service interrupted"
    if not(timeMonitorFut.finished()): await timeMonitorFut.cancelAndWait()
    return
  except CatchableError as exc:
    warn "Service crashed with unexpected error", err_name = exc.name,
         err_msg = exc.msg
    return

  while true:
    # This loop could look much more nicer/better, when
    # https://github.com/nim-lang/Nim/issues/19911 will be fixed, so it could
    # become safe to combine loops, breaks and exception handlers.
    let breakLoop =
      try:
        if await service.checkNodes(): service.changesEvent.fire()
        await sleepAsync(2.seconds)
        false
      except CancelledError:
        debug "Service interrupted"
        if not(timeMonitorFut.finished()): await timeMonitorFut.cancelAndWait()
        true
      except CatchableError as exc:
        error "Service crashed with unexpected error", err_name = exc.name,
              err_msg = exc.msg
        true

    if breakLoop:
      break

proc init*(t: typedesc[FallbackServiceRef],
           vc: ValidatorClientRef): Future[FallbackServiceRef] {.async.} =
  logScope: service = ServiceName
  var res = FallbackServiceRef(name: ServiceName, client: vc,
                               state: ServiceState.Initialized,
                               changesEvent: newAsyncEvent())
  debug "Initializing service"
  return res

proc start*(service: FallbackServiceRef) =
  service.lifeFut = mainLoop(service)
