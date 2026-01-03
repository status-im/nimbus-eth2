# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ./common

const
  ServiceName = "fallback_service"

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
                roles: set[BeaconNodeRole], waitChanges: bool) {.
     async: (raises: [CancelledError]).} =
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
     ): Future[RestBeaconNodeStatus] {.async: (raises: [CancelledError]).} =
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

  let
    genesisFlag = (genesis != vc.beaconGenesis)
    configFlag = not(checkConfig(info, vc.timeParams))

  node.config = info
  node.genesis = Opt.some(genesis)

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
     ): Future[RestBeaconNodeStatus] {.async: (raises: [CancelledError]).} =
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

  node.syncInfo = Opt.some(syncInfo)
  if not(syncInfo.is_syncing) or (syncInfo.sync_distance < SYNC_TOLERANCE):
    if not(syncInfo.is_optimistic.get(false)):
      RestBeaconNodeStatus.Synced
    else:
      RestBeaconNodeStatus.OptSynced
  else:
    RestBeaconNodeStatus.NotSynced

proc checkOnline(
       node: BeaconNodeServerRef
     ): Future[RestBeaconNodeStatus] {.async: (raises: [CancelledError]).} =
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

  node.ident = Opt.some(agent.version)
  RestBeaconNodeStatus.Online

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
               node: BeaconNodeServerRef): Future[bool] {.
     async: (raises: [CancelledError]).} =
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

proc checkNodes*(service: FallbackServiceRef): Future[bool] {.
     async: (raises: [CancelledError]).} =
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
      if fut.completed() and fut.value():
        res = true
  except CancelledError as exc:
    let pending = pendingChecks
      .filterIt(not(it.finished())).mapIt(it.cancelAndWait())
    await noCancel allFutures(pending)
    raise exc
  res

proc mainLoop(service: FallbackServiceRef) {.async: (raises: []).} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  try:
    await vc.preGenesisEvent.wait()
  except CancelledError:
    debug "Service interrupted"
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
        true

    if breakLoop:
      break

proc init*(
    t: typedesc[FallbackServiceRef],
    vc: ValidatorClientRef
): Future[FallbackServiceRef] {.async: (raises: []).} =
  logScope: service = ServiceName
  let res = FallbackServiceRef(name: ServiceName, client: vc,
                               state: ServiceState.Initialized,
                               changesEvent: newAsyncEvent())
  debug "Initializing service"
  res

proc start*(service: FallbackServiceRef) =
  service.lifeFut = mainLoop(service)
