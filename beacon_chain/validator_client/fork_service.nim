# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/algorithm
import chronicles
import common, api

const
  ServiceName = "fork_service"

logScope: service = ServiceName

proc validateForkSchedule(forks: openArray[Fork]): bool {.raises: [Defect].} =
  # Check if `forks` list is linked list.
  var current_version = forks[0].current_version
  for index, item in forks:
    if index > 0:
      if item.previous_version != current_version:
        return false
    else:
      if item.previous_version != item.current_version:
        return false
    current_version = item.current_version
  true

proc sortForks(forks: openArray[Fork]): Result[seq[Fork], cstring] {.
     raises: [Defect].} =
  proc cmp(x, y: Fork): int {.closure.} =
    if uint64(x.epoch) == uint64(y.epoch): return 0
    if uint64(x.epoch) < uint64(y.epoch): return -1
    return 1

  if len(forks) == 0:
    return err("Empty fork schedule")

  let sortedForks = sorted(forks, cmp)
  if not(validateForkSchedule(sortedForks)):
    return err("Invalid fork schedule")
  ok(sortedForks)

proc pollForFork(vc: ValidatorClientRef) {.async.} =
  let sres = vc.getCurrentSlot()
  if sres.isSome():
    let
      currentSlot = sres.get()
      currentEpoch = currentSlot.epoch()

    let forks =
      try:
        await vc.getForkSchedule(ApiStrategyKind.Best)
      except ValidatorApiError as exc:
        error "Unable to retrieve fork schedule", reason = exc.msg
        return
      except CancelledError as exc:
        debug "Fork retrieval process was interrupted"
        raise exc
      except CatchableError as exc:
        error "Unexpected error occured while getting fork information",
              err_name = exc.name, err_msg = exc.msg
        return

    let sortedForks =
      block:
        let res = sortForks(forks)
        if res.isErr():
          error "Invalid fork schedule received", reason = res.error()
          return
        res.get()

    if (len(vc.forks) == 0) or (vc.forks != sortedForks):
      vc.forks = sortedForks
      notice "Fork schedule updated", fork_schedule = sortedForks
      vc.forksAvailable.fire()

proc waitForNextEpoch(service: ForkServiceRef) {.async.} =
  let vc = service.client
  let sleepTime = vc.beaconClock.durationToNextEpoch() + TIME_DELAY_FROM_SLOT
  debug "Sleeping until next epoch", sleep_time = sleepTime
  await sleepAsync(sleepTime)

proc mainLoop(service: ForkServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  while true:
    # This loop could look much more nicer/better, when
    # https://github.com/nim-lang/Nim/issues/19911 will be fixed, so it could
    # become safe to combine loops, breaks and exception handlers.
    let breakLoop =
      try:
        await vc.pollForFork()
        await service.waitForNextEpoch()
        false
      except CancelledError:
        debug "Service interrupted"
        true
      except CatchableError as exc:
        warn "Service crashed with unexpected error", err_name = exc.name,
             err_msg = exc.msg
        true

    if breakLoop:
      break

proc init*(t: typedesc[ForkServiceRef],
            vc: ValidatorClientRef): Future[ForkServiceRef] {.async.} =
  logScope: service = ServiceName
  let res = ForkServiceRef(name: ServiceName,
                           client: vc, state: ServiceState.Initialized)
  debug "Initializing service"
  await vc.pollForFork()
  return res

proc start*(service: ForkServiceRef) =
  service.lifeFut = mainLoop(service)
