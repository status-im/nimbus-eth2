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

logScope: service = ServiceName

proc blocksLoop(service: MonitorServiceRef,
                node: BeaconNodeServerRef) {.async.} =
  let
    vc = service.client
    roles = {BeaconNodeRole.BlockProposalData}
    statuses = {RestBeaconNodeStatus.Synced}

  logScope:
    node = node

  debug "Block monitoring loop started"

  while true:
    while node.status notin statuses:
      await vc.waitNodes(nil, statuses, roles, false)

    let respOpt =
      try:
        let res = await node.client.subscribeEventStream({EventTopic.Block})
        if res.status == 200:
          Opt.some(res)
        else:
          node.status = RestBeaconNodeStatus.Incompatible
          let
            body = await res.getBodyBytes()
            plain = RestPlainResponse(
              status: res.status,
              contentType: res.contentType,
              data: body)
            reason = plain.getErrorMessage()
          info "Unable to to obtain events stream", code = res.status,
                 reason = reason
          Opt.none(RestHttpResponseRef)
      except RestError as exc:
        node.status = RestBeaconNodeStatus.Offline
        info "Unable to obtain events stream", reason = $exc.msg
        Opt.none(RestHttpResponseRef)
      except CancelledError as exc:
        debug "Block monitoring loop has been interrupted"
        raise exc
      except CatchableError as exc:
        node.status = RestBeaconNodeStatus.Offline
        info "Got an unexpected error while trying to establish event stream",
              reason = $exc.msg
        Opt.none(RestHttpResponseRef)

    if respOpt.isNone():
      continue

    let response = respOpt.get()

    while true:
      let eventsOpt =
        try:
          let res = await response.getServerSentEvents()
          Opt.some(res)
        except RestError as exc:
          node.status = RestBeaconNodeStatus.Offline
          info "Unable to receive server-sent event", reason = $exc.msg
          Opt.none(seq[ServerSentEvent])
        except CancelledError as exc:
          debug "Block monitoring loop has been interrupted"
          raise exc
        except CatchableError as exc:
          node.status = RestBeaconNodeStatus.Offline
          info "Got an unexpected error, " &
                "while reading server-sent event stream", reason = $exc.msg
          Opt.none(seq[ServerSentEvent])

      if eventsOpt.isNone():
        break

      let events = eventsOpt.get()
      if len(events) == 0:
        break

      for event in events:
        case event.name
        of "data":
          let blck = EventBeaconBlockObject.decodeString(event.data).valueOr:
            node.status = RestBeaconNodeStatus.Incompatible
            debug "Got invalid block event format", reason = error
            continue
          vc.registerBlock(blck)
        of "event":
          if event.data != "block":
            node.status = RestBeaconNodeStatus.Incompatible
            debug "Got unexpected event name field", event_name = event.name,
                  event_data = event.data
        else:
          node.status = RestBeaconNodeStatus.Incompatible
          debug "Got some unexpected event field", event_name = event.name

    await response.closeWait()

  debug "Block monitoring loop exited"

proc blockMonitoringLoop(service: MonitorServiceRef) {.async.} =
  let
    vc = service.client
    blockNodes = vc.filterNodes(AllBeaconNodeStatuses,
                                {BeaconNodeRole.BlockProposalData})

  debug "Starting main block monitoring loop", nodes_count = len(blockNodes)

  var loops: seq[Future[void]]
  while true:
    for node in blockNodes:
      loops.add(service.blocksLoop(node))

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

    except CancelledError as exc:
      var pending: seq[Future[void]]
      for future in loops:
        if not(future.finished()): pending.add(future.cancelAndWait())
      await allFutures(pending)
      raise exc

proc mainLoop(service: MonitorServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  var breakLoop = false
  var blockMonitoringLoopFut: Future[void]

  while not(breakLoop):
    breakLoop =
      try:
        blockMonitoringLoopFut = service.blockMonitoringLoop()
        await allFutures(blockMonitoringLoopFut)
        false
      except CancelledError:
        debug "Service interrupted"
        var pending: seq[Future[void]]
        if not(blockMonitoringLoopFut.finished()):
          pending.add(blockMonitoringLoopFut.cancelAndWait())
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
