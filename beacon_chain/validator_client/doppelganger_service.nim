# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/algorithm
import chronicles
import common, api

logScope: service = "doppelganger_service"

proc init*(t: typedesc[DoppelgangerServiceRef],
           vc: ValidatorClientRef): Future[DoppelgangerServiceRef] {.async.} =
  debug "Initializing service"
  var res = DoppelgangerServiceRef(
    client: vc, state: ServiceState.Initialized,
    enabled: vc.config.doppelgangerDetection
  )
  return res

proc waitForNextEpoch(service: DoppelgangerServiceRef) {.async.} =
  let vc = service.client
  let sleepTime = vc.beaconClock.durationToNextEpoch() + TIME_DELAY_FROM_SLOT
  debug "Sleeping until next epoch", sleep_time = sleepTime
  await sleepAsync(sleepTime)

proc resyncDoppelgangerDetection(service: DoppelgangerServiceRef,
                                 epoch: Epoch) =
  let vc = service.client
  for validator in vc.attachedValidators.items():
    if validator.index.isSome():
      let
        index = validator.index.get()
        state = DoppelgangerState.init(epoch)
      discard vc.doppelgangerDetection.validators.hasKeyOrPut(index, state)

proc mainStep(service: DoppelgangerServiceRef): Future[bool] {.async.} =
  try:
    await service.waitForNextEpoch()
    let
      currentEpoch = vc.currentSlot().epoch()
      previousEpoch =
        if currentEpoch == Epoch(0):
          currentEpoch
        else:
          currentEpoch - 1'u64
      service.resyncDoppelgangerDetection(currentEpoch)
      let indexList = vc.doppelgangerDetection.validators.keys().toSeq()
    return true
  except CancelledError:
    debug "Service interrupted"
    return false
  except CatchableError as exc:
    warn "Service crashed with unexpected error", err_name = exc.name,
         err_msg = exc.msg
    return false

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
          indexList = vc.doppelgangerDetection.validators.keys().toSeq()
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

    let res = await mainStep(service)
    if not(res):
      break

  debug "Service stopped"

proc start*(service: DoppelgangerServiceRef) =
  service.lifeFut = mainLoop(service)
