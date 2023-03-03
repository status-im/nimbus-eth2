# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import common

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

proc otherNodes*(vc: ValidatorClientRef): seq[BeaconNodeServerRef] =
  vc.beaconNodes.filterIt(it.status != RestBeaconNodeStatus.Synced)

proc otherNodesCount*(vc: ValidatorClientRef): int =
  vc.beaconNodes.countIt(it.status != RestBeaconNodeStatus.Synced)

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

proc checkCompatible(
       vc: ValidatorClientRef,
       node: BeaconNodeServerRef
     ): Future[RestBeaconNodeStatus] {.async.} =
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

  node.config = some(info)
  node.genesis = some(genesis)
  let res =
    if configFlag or genesisFlag:
      if node.status != RestBeaconNodeStatus.Incompatible:
        warn "Beacon node has incompatible configuration",
              genesis_flag = genesisFlag, config_flag = configFlag
      RestBeaconNodeStatus.Incompatible
    else:
      RestBeaconNodeStatus.Compatible
  return res

proc checkSync(
       vc: ValidatorClientRef,
       node: BeaconNodeServerRef
     ): Future[RestBeaconNodeStatus] {.async.} =
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
  node.syncInfo = some(syncInfo)
  let res =
    block:
      let optimistic =
        if syncInfo.is_optimistic.isNone():
          "none"
        else:
          $syncInfo.is_optimistic.get()

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
  node.ident = some(agent.version)
  return RestBeaconNodeStatus.Online

proc checkNode(vc: ValidatorClientRef,
               node: BeaconNodeServerRef): Future[bool] {.async.} =
  let nstatus = node.status
  debug "Checking beacon node", endpoint = node, status = node.status

  if nstatus in {RestBeaconNodeStatus.Offline,
                 RestBeaconNodeStatus.Unexpected,
                 RestBeaconNodeStatus.InternalError}:
    let status = await node.checkOnline()
    node.updateStatus(status)
    if status != RestBeaconNodeStatus.Online:
      return nstatus != status

  if nstatus in {RestBeaconNodeStatus.Offline,
                 RestBeaconNodeStatus.Unexpected,
                 RestBeaconNodeStatus.InternalError,
                 RestBeaconNodeStatus.Online,
                 RestBeaconNodeStatus.Incompatible}:
    let status = await vc.checkCompatible(node)
    node.updateStatus(status)
    if status != RestBeaconNodeStatus.Compatible:
      return nstatus != status

  if nstatus in {RestBeaconNodeStatus.Offline,
                 RestBeaconNodeStatus.Unexpected,
                 RestBeaconNodeStatus.InternalError,
                 RestBeaconNodeStatus.Online,
                 RestBeaconNodeStatus.Incompatible,
                 RestBeaconNodeStatus.Compatible,
                 RestBeaconNodeStatus.OptSynced,
                 RestBeaconNodeStatus.NotSynced}:
    let status = await vc.checkSync(node)
    node.updateStatus(status)
    return nstatus != status

proc checkNodes*(service: FallbackServiceRef): Future[bool] {.async.} =
  let
    nodesToCheck = service.client.otherNodes()
    pendingChecks = nodesToCheck.mapIt(service.client.checkNode(it))
  var res = false
  try:
    await allFutures(pendingChecks)
    for fut in pendingChecks:
      if fut.completed() and fut.read():
        res = true
  except CancelledError as exc:
    var pending: seq[Future[void]]
    for future in pendingChecks:
      if not(future.finished()):
        pending.add(future.cancelAndWait())
    await allFutures(pending)
    raise exc
  return res

proc mainLoop(service: FallbackServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  while true:
    # This loop could look much more nicer/better, when
    # https://github.com/nim-lang/Nim/issues/19911 will be fixed, so it could
    # become safe to combine loops, breaks and exception handlers.
    let breakLoop =
      try:
        if await service.checkNodes(): service.changesEvent.fire()
        await sleepAsync(2.seconds)
        false
      except CancelledError as exc:
        debug "Service interrupted"
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
  # Perform initial nodes check.
  if await res.checkNodes(): res.changesEvent.fire()
  return res

proc start*(service: FallbackServiceRef) =
  service.lifeFut = mainLoop(service)
