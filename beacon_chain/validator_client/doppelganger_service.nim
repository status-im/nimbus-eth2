# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import chronicles
import common, api

const
  ServiceName = "doppelganger_service"

logScope: service = ServiceName

const
  DOPPELGANGER_EPOCHS_COUNT = 2

proc getCheckingList*(vc: ValidatorClientRef): seq[ValidatorIndex] =
  var res: seq[ValidatorIndex]
  for index, value in vc.doppelgangerDetection.validators.pairs():
    if value.status == DoppelgangerStatus.Checking:
      res.add(index)
  res

proc waitForNextEpoch(service: DoppelgangerServiceRef) {.async.} =
  let vc = service.client
  let sleepTime = vc.beaconClock.durationToNextEpoch() + TIME_DELAY_FROM_SLOT
  debug "Sleeping until next epoch", sleep_time = sleepTime
  await sleepAsync(sleepTime)

proc processActivities(service: DoppelgangerServiceRef, epoch: Epoch,
                       activities: GetValidatorsActivityResponse) =
  let vc = service.client
  if len(activities.data) == 0:
    debug "Unable to monitor validator's activity for epoch", epoch = epoch
    for index, value in vc.doppelgangerDetection.validators.mpairs():
      if value.status == DoppelgangerStatus.Checking:
        value.epochsCount = 0'u64
        value.lastAttempt = DoppelgangerAttempt.Failure
  else:
    for activity in activities.data:
      let vindex = activity.index
      vc.doppelgangerDetection.validators.withValue(vindex, value):
        if activity.active:
          if value.status == DoppelgangerStatus.Checking:
            value.epochsCount = 0'u64
            value.lastAttempt = DoppelgangerAttempt.SuccessTrue
            warn "Validator's activity has been seen",
                  validator_index = vindex, epoch = epoch
            vc.gracefulExit.fire()
            return
        else:
          if value.status == DoppelgangerStatus.Checking:
            value.lastAttempt = DoppelgangerAttempt.SuccessFalse
            if value.epochsCount == DOPPELGANGER_EPOCHS_COUNT:
              value.status = DoppelgangerStatus.Passed
              info "Validator successfully passed doppelganger detection",
                    validator_index = vindex
            else:
              inc(value.epochsCount)
              debug "Validator's activity was not seen",
                     validator_index = vindex, epoch = epoch,
                     epochs_count = value.epochsCount

proc mainLoop(service: DoppelgangerServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running

  if service.enabled:
    debug "Service started"
  else:
    debug "Service disabled because of configuration settings"
    return

  while true:
    let breakLoop =
      try:
        await service.waitForNextEpoch()
        let
          currentEpoch = vc.currentSlot().epoch()
          previousEpoch =
            if currentEpoch == Epoch(0):
              currentEpoch
            else:
              currentEpoch - 1'u64
          validators = vc.getCheckingList()
        if len(validators) > 0:
          let activities = await vc.getValidatorsActivity(previousEpoch,
                                                          validators)
          service.processActivities(previousEpoch, activities)
        else:
          debug "No validators found that require doppelganger protection"
          discard
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

proc init*(t: typedesc[DoppelgangerServiceRef],
           vc: ValidatorClientRef): Future[DoppelgangerServiceRef] {.async.} =
  logScope: service = ServiceName
  let res = DoppelgangerServiceRef(name: ServiceName,
                                   client: vc, state: ServiceState.Initialized,
                                   enabled: vc.config.doppelgangerDetection)
  debug "Initializing service"
  return res

proc start*(service: DoppelgangerServiceRef) =
  service.lifeFut = mainLoop(service)
