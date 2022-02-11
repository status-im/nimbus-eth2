import std/algorithm
import chronicles
import common, api

logScope: service = "fork_service"

proc validateForkSchedule(forks: openarray[Fork]): bool {.raises: [Defect].} =
  # Check if `forks` list is linked list.
  var current_version = forks[0].current_version
  for index, item in forks.pairs():
    if index > 0:
      if item.previous_version != current_version:
        return false
    else:
      if item.previous_version != item.current_version:
        return false
    current_version = item.current_version
  true

proc sortForks(forks: openarray[Fork]): Result[seq[Fork], cstring] {.
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
        await vc.getForkSchedule()
      except ValidatorApiError as exc:
        error "Unable to retrieve fork schedule", reason = exc.msg
        return
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

    if vc.forks.isNone() or (vc.forks.get() != sortedForks):
      vc.forks = some(sortedForks)
      notice "Fork schedule updated", fork_schedule = sortedForks
      vc.forksAvailable.fire()

proc waitForNextEpoch(service: ForkServiceRef) {.async.} =
  let vc = service.client
  let sleepTime = vc.beaconClock.durationToNextEpoch() + TIME_DELAY_FROM_SLOT
  debug "Sleeping until next epoch", sleep_time = sleepTime
  await sleepAsync(sleepTime)

proc mainLoop(service: ForkServiceRef) {.async.} =
  service.state = ServiceState.Running
  let vc = service.client
  debug "Service started"
  try:
    while true:
      await vc.pollForFork()
      await service.waitForNextEpoch()
  except CatchableError as exc:
    warn "Service crashed with unexpected error", err_name = exc.name,
         err_msg = exc.msg

proc init*(t: typedesc[ForkServiceRef],
            vc: ValidatorClientRef): Future[ForkServiceRef] {.async.} =
  debug "Initializing service"
  var res = ForkServiceRef(client: vc, state: ServiceState.Initialized)
  await vc.pollForFork()
  return res

proc start*(service: ForkServiceRef) =
  service.lifeFut = mainLoop(service)
