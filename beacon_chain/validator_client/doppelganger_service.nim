# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronicles
import "."/[common, api]

const
  ServiceName = "doppelganger_service"

logScope: service = ServiceName

proc getCheckingList*(vc: ValidatorClientRef, epoch: Epoch): seq[ValidatorIndex] =
  var res: seq[ValidatorIndex]
  for validator in vc.attachedValidators[]:
    if validator.index.isSome and
        (validator.doppelCheck.isNone or validator.doppelCheck.get() < epoch):
      res.add validator.index.get()
  res

proc processActivities(service: DoppelgangerServiceRef, epoch: Epoch,
                       activities: GetValidatorsLivenessResponse) =
  let vc = service.client
  if len(activities.data) == 0:
    debug "Unable to monitor validator's activity for epoch", epoch = epoch
  else:
    for item in activities.data:
      let vindex = item.index
      for validator in vc.attachedValidators[]:
        if validator.index == Opt.some(vindex):
          validator.doppelgangerChecked(epoch)

          if item.is_live and validator.triggersDoppelganger(epoch):
            warn "Doppelganger detection triggered",
              validator = validatorLog(validator), epoch

            vc.doppelExit.fire()
            return

          break

proc mainLoop(service: DoppelgangerServiceRef) {.async: (raises: []).} =
  let vc = service.client
  service.state = ServiceState.Running

  if service.enabled:
    debug "Service started"
  else:
    debug "Service disabled because of configuration settings"
    return

  debug "Doppelganger detection loop is waiting for initialization"
  try:
    await allFutures(
      vc.preGenesisEvent.wait(),
      vc.genesisEvent.wait(),
      vc.indicesAvailable.wait()
    )
  except CancelledError:
    debug "Service interrupted"
    return

  # On (re)start, we skip the remainder of the epoch before we start monitoring
  # for doppelgangers so we don't trigger on the attestations we produced before
  # the epoch - there's no activity in the genesis slot, so if we start at or
  # before that, we can safely perform the check for epoch 0 and thus keep
  # validating in epoch 1
  if vc.beaconClock.now().slotOrZero() > GENESIS_SLOT:
    try:
      await service.waitForNextEpoch(TIME_DELAY_FROM_SLOT)
    except CancelledError:
      debug "Service interrupted"
      return

  while try:
    # Wait for the epoch to end - at the end (or really, the beginning of the
    # next one, we ask what happened
    await service.waitForNextEpoch(TIME_DELAY_FROM_SLOT)
    let
      currentEpoch = vc.currentSlot().epoch()
      previousEpoch =
        if currentEpoch == Epoch(0):
          currentEpoch
        else:
          currentEpoch - 1'u64
      validators = vc.getCheckingList(previousEpoch)
    if len(validators) > 0:
      let activities = await vc.getValidatorsLiveness(previousEpoch,
                                                      validators)
      service.processActivities(previousEpoch, activities)
    else:
      debug "No validators found that require doppelganger protection"
      discard
    true
  except CancelledError:
    debug "Service interrupted"
    false
  : discard

proc init*(
    t: type DoppelgangerServiceRef,
    vc: ValidatorClientRef
): Future[DoppelgangerServiceRef] {.async: (raises: []).} =
  logScope: service = ServiceName
  let res = DoppelgangerServiceRef(name: ServiceName,
                                   client: vc, state: ServiceState.Initialized,
                                   enabled: vc.config.doppelgangerDetection)
  debug "Initializing service"
  res

proc start*(service: DoppelgangerServiceRef) =
  service.lifeFut = mainLoop(service)
