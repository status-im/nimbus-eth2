# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import chronicles
import common, api
from fallback_service import waitNodes, filterNodes

const
  ServiceName = "monitor_service"
  WARNING_TIME_OFFSET = 2.seconds
  NOTICE_TIME_OFFSET = 1.seconds
  DEBUG_TIME_OFFSET = 500.milliseconds

logScope: service = ServiceName

proc pollForEvents(service: MonitorServiceRef, node: BeaconNodeServerRef,
                   response: RestHttpResponseRef): Future[bool] {.async.} =
  logScope:
      node = node

  let
    vc = service.client
    events =
      try:
        await response.getServerSentEvents()
      except RestError as exc:
        node.status = RestBeaconNodeStatus.Offline
        debug "Unable to receive server-sent event", reason = $exc.msg
        return false
      except CancelledError as exc:
        debug "Block monitoring loop has been interrupted"
        raise exc
      except CatchableError as exc:
        node.status = RestBeaconNodeStatus.Offline
        warn "Got an unexpected error, " &
             "while reading server-sent event stream", reason = $exc.msg
        return false

  for event in events:
    case event.name
    of "data":
      let blck = EventBeaconBlockObject.decodeString(event.data).valueOr:
        node.status = RestBeaconNodeStatus.Incompatible
        debug "Got invalid block event format", reason = error
        return
      vc.registerBlock(blck)
    of "event":
      if event.data != "block":
        node.status = RestBeaconNodeStatus.Incompatible
        debug "Got unexpected event name field", event_name = event.name,
              event_data = event.data
    else:
      node.status = RestBeaconNodeStatus.Incompatible
      debug "Got some unexpected event field", event_name = event.name

  return true

proc pollForBlockEvents(service: MonitorServiceRef,
                        node: BeaconNodeServerRef) {.async.} =
  let
    vc = service.client
    roles = {BeaconNodeRole.BlockProposalData}
    statuses = {RestBeaconNodeStatus.Synced}

  logScope:
    node = node

  while node.status notin statuses:
    await vc.waitNodes(nil, statuses, roles, false)

  let response =
    try:
      let res = await node.client.subscribeEventStream({EventTopic.Block})
      if res.status == 200:
        res
      else:
        node.status = RestBeaconNodeStatus.Incompatible
        let
          body = await res.getBodyBytes()
          plain = RestPlainResponse(status: res.status,
                                    contentType: res.contentType, data: body)
          reason = plain.getErrorMessage()
        info "Unable to to obtain events stream", code = res.status,
             reason = reason
        return
    except RestError as exc:
      node.status = RestBeaconNodeStatus.Offline
      debug "Unable to obtain events stream", reason = $exc.msg
      return
    except CancelledError as exc:
      debug "Block monitoring loop has been interrupted"
      raise exc
    except CatchableError as exc:
      node.status = RestBeaconNodeStatus.Offline
      warn "Got an unexpected error while trying to establish event stream",
           reason = $exc.msg
      return

  var breakLoop = false
  while not(breakLoop):
    breakLoop =
      try:
        let res = await service.pollForEvents(node, response)
        not(res)
      except CancelledError as exc:
        await response.closeWait()
        raise exc
      except CatchableError as exc:
        warn "Got an unexpected error while receiving block events",
             reason = $exc.msg
        true

  await response.closeWait()

proc blocksLoop(service: MonitorServiceRef,
                node: BeaconNodeServerRef) {.async.} =
  logScope:
    node = node

  debug "Block monitoring loop started"

  var breakLoop = false
  while not(breakLoop):
    breakLoop =
      try:
        await service.pollForBlockEvents(node)
        false
      except CancelledError:
        true
      except CatchableError as exc:
        warn "Got an unexpected error while polling for block events",
             reason = $exc.msg
        true

  debug "Block monitoring loop stopped"

proc blockMonitoringLoop(service: MonitorServiceRef) {.async.} =
  let
    vc = service.client
    blockNodes = vc.filterNodes(AllBeaconNodeStatuses,
                                {BeaconNodeRole.BlockProposalData})

  debug "Starting main block monitoring loop", nodes_count = len(blockNodes)

  var
    loops: seq[Future[void]]
    breakLoop = false

  try:
    for node in blockNodes:
      loops.add(service.blocksLoop(node))
  except CatchableError as exc:
    warn "An unexpected error occurred while starting block monitoring loop",
         reason = $exc.msg, error_name = $exc.name
    return

  while not(breakLoop):
    breakLoop =
      try:
        discard await race(loops.mapIt(FutureBase(it)))
        for index, future in loops.pairs():
          if future.finished():
            let reason =
              if future.done():
                "without error"
              elif future.failed():
                $future.readError().msg
              else:
                "interrupted"
            debug "Block monitoring loop unexpectedly finished, restarting",
                  reason = reason, node = blockNodes[index]
            loops[index] = service.blocksLoop(blockNodes[index])
            break
        false
      except CancelledError:
        debug "Main block monitoring loop was interrupted"
        var pending: seq[Future[void]]
        for future in loops:
          if not(future.finished()): pending.add(future.cancelAndWait())
        await allFutures(pending)
        true
      except CatchableError as exc:
        warn "An unexpected error occurred while running main block " &
             " monitoring loop", reason = $exc.msg, error_name = $exc.name
        true

proc pollForTime(service: MonitorServiceRef,
                 node: BeaconNodeServerRef) {.async.} =
  let
    vc = service.client
    roles = AllBeaconNodeRoles
    statuses = AllBeaconNodeStatuses - {RestBeaconNodeStatus.Offline}

  logScope:
    node = node

  while node.status notin statuses:
    await vc.waitNodes(nil, statuses, roles, false)

  let tres =
    try:
      let res = await node.client.getTimeOffset()
      Opt.some(res)
    except RestError as exc:
      debug "Unable to obtain remote beacon node time offset", reason = $exc.msg
      node.status = RestBeaconNodeStatus.Offline
      Opt.none(int64)
    except RestResponseError as exc:
      debug "Remote beacon node responds with invalid status",
            status = $exc.status, reason = $exc.msg, message = $exc.message
      node.status = RestBeaconNodeStatus.Incompatible
      Opt.none(int64)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      warn "An unexpected error occurred while asking remote beacon node for " &
           "time offset", reason = $exc.msg, error = $exc.name
      node.status = RestBeaconNodeStatus.Offline
      Opt.none(int64)

  if tres.isSome():
    let
      timeOffset = tres.get()
      timeDuration = nanoseconds(abs(tres.get()))
      soffset = if tres.get() < 0: "-" & $timeDuration else: $timeDuration
    debug "Remote beacon time offset received", offset = soffset
    if timeDuration >= WARNING_TIME_OFFSET:
      warn "Remote beacon node has significant time offset", offset = soffset
    elif timeDuration >= NOTICE_TIME_OFFSET:
      notice "Remote beacon node has big time offset", offset = soffset
    elif timeDuration >= DEBUG_TIME_OFFSET:
      debug "Remote beacon node has some time offset", offset = soffset

  await service.waitForNextEpoch(ZeroDuration)

proc timeLoop(service: MonitorServiceRef, node: BeaconNodeServerRef) {.async.} =
  logScope:
    node = node

  debug "Time monitoring loop started"

  var breakLoop = false
  while not(breakLoop):
    breakLoop =
      try:
        await pollForTime(service, node)
        false
      except CancelledError:
        true
      except CatchableError:
        true

  debug "Time monitoring loop stopped"

proc timeMonitoringLoop(service: MonitorServiceRef) {.async.} =
  let
    vc = service.client
    blockNodes = vc.filterNodes(AllBeaconNodeStatuses, AllBeaconNodeRoles)

  debug "Starting main time monitoring loop", nodes_count = len(blockNodes)

  var
    loops: seq[Future[void]]
    breakLoop = false

  try:
    for node in blockNodes:
      loops.add(service.timeLoop(node))
  except CatchableError as exc:
    warn "An unexpected error occurred while starting time monitoring loop",
         reason = $exc.msg, error_name = $exc.name
    return

  while not(breakLoop):
    breakLoop =
      try:
        discard await race(loops.mapIt(FutureBase(it)))
        for index, future in loops.pairs():
          if future.finished():
            let reason =
              if future.done():
                "without error"
              elif future.failed():
                $future.readError().msg
              else:
                "interrupted"
            debug "Block monitoring loop unexpectedly finished, restarting",
                  reason = reason, node = blockNodes[index]
            loops[index] = service.timeLoop(blockNodes[index])
            break
        false
      except CancelledError:
        debug "Main time monitoring loop was interrupted"
        var pending: seq[Future[void]]
        for future in loops:
          if not(future.finished()): pending.add(future.cancelAndWait())
        await allFutures(pending)
        true
      except CatchableError as exc:
        warn "An unexpected error occurred while running main time " &
             " monitoring loop",
             reason = $exc.msg, error_name = $exc.name
        true

proc mainLoop(service: MonitorServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  var breakLoop = false
  var blockMonitoringLoopFut: Future[void]
  var timeMonitoringLoopFut: Future[void]

  while not(breakLoop):
    breakLoop =
      try:
        blockMonitoringLoopFut = service.blockMonitoringLoop()
        timeMonitoringLoopFut = service.timeMonitoringLoop()
        await allFutures(blockMonitoringLoopFut, timeMonitoringLoopFut)
        false
      except CancelledError:
        debug "Service interrupted"
        var pending: seq[Future[void]]
        if not(blockMonitoringLoopFut.finished()):
          pending.add(blockMonitoringLoopFut.cancelAndWait())
        if not(timeMonitoringLoopFut.finished()):
          pending.add(timeMonitoringLoopFut.cancelAndWait())
        await allFutures(pending)
        true
      except CatchableError as exc:
        warn "Service crashed with unexpected error", err_name = exc.name,
             err_msg = exc.msg
        true

proc init*(t: type MonitorServiceRef,
           vc: ValidatorClientRef): Future[MonitorServiceRef] {.async.} =
  logScope: service = ServiceName
  let res = MonitorServiceRef(name: ServiceName,
                              client: vc, state: ServiceState.Initialized)
  debug "Initializing service"
  return res

proc start*(service: MonitorServiceRef) =
  service.lifeFut = mainLoop(service)
