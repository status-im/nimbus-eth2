# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/sets,
  chronicles,
  ./[common, api]

const ServiceName = "payload_attestation_service"

logScope: service = ServiceName

type
  PayloadAttestationItem = object
    validator_index: uint64
    validator: AttachedValidator

proc servePayloadAttestations(
    service: PayloadAttestationServiceRef,
    slot: Slot,
    duties: seq[RestPtcDuty]
) {.async: (raises: [CancelledError]).} =
  let
    vc = service.client
    fork = vc.forkAtEpoch(slot.epoch())
    consensusFork = vc.getConsensusFork(fork)

  logScope:
    slot = slot

  let data =
    try:
      await vc.producePayloadAttestationData(
        slot, vc.getMode()[FnKind.produceAttestationData])
    except ValidatorApiError as exc:
      warn "Unable to produce payload attestation data",
           duties_count = len(duties), reason = exc.getFailureReason()
      return
    except CancelledError as exc:
      debug "Payload attestation data production was interrupted"
      raise exc

  if data.slot != slot:
    warn "Inconsistent payload attestation data received",
         data_slot = data.slot
    return

  let items =
    block:
      var 
        res: seq[PayloadAttestationItem]
        seen: HashSet[uint64]
      for duty in duties:
        if seen.containsOrIncl(uint64(duty.validator_index)):
          continue
        let validator = vc.getValidatorForDuties(duty.pubkey, slot).valueOr:
          continue
        res.add(PayloadAttestationItem(
          validator_index: uint64(duty.validator_index),
          validator: validator))
      res

  if len(items) == 0:
    debug "No payload attestation duties for slot"
    return

  let messages =
    block:
      var res: seq[PayloadAttestationMessage]
      let pending =
        items.mapIt(
          getPayloadAttestationSignature(
            it.validator, fork, vc.beaconGenesis.genesis_validators_root,
            data))
      try:
        await allFutures(pending)

        for index, future in pending.pairs():
          let sres = future.value
          if sres.isErr():
            warn "Unable to sign payload attestation",
                 reason = sres.error(),
                 validator_index = items[index].validator_index
          else:
            res.add(PayloadAttestationMessage(
              validator_index: items[index].validator_index,
              data: data,
              signature: sres.get()))
        res
      except CancelledError as exc:
        debug "Payload attestation signature process was interrupted"
        await cancelAndWait(pending)
        raise exc

  if len(messages) == 0:
    return

  logScope:
    delay = vc.getDelay(slot.payload_attestation_deadline(vc.timeParams))

  debug "Sending payload attestations", count = len(messages)

  for item in items:
    item.validator.doppelgangerActivity(slot.epoch())

  let res =
    try:
      await vc.submitPoolPayloadAttestations(
        messages, consensusFork,
        vc.getMode()[FnKind.submitPoolAttestations])
    except ValidatorApiError as exc:
      warn "Unable to publish payload attestations",
            count = len(messages), reason = exc.getFailureReason()
      return
    except CancelledError as exc:
      debug "Payload attestation publishing was interrupted"
      raise exc

  if res:
    notice "Payload attestations published", count = len(messages)
  else:
    warn "Payload attestations were not accepted by beacon node"

proc spawnPayloadAttestationTasks(
    service: PayloadAttestationServiceRef,
    slot: Slot
) {.async: (raises: [CancelledError]).} =
  let
    vc = service.client
    duties = vc.getPtcDutiesForSlot(slot)

  if len(duties) == 0:
    return

  try:
    let timeout = vc.beaconClock.fromNow(slot + 1).durationOrZero()
    await service.servePayloadAttestations(slot, duties).wait(timeout)
  except AsyncTimeoutError:
    discard
  except CancelledError as exc:
    raise exc

proc mainLoop(service: PayloadAttestationServiceRef) {.async: (raises: []).} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  debug "Payload attestation loop is waiting for initialization"
  try:
    await allFutures(
      vc.preGenesisEvent.wait(),
      vc.genesisEvent.wait(),
      vc.indicesAvailable.wait(),
      vc.forksAvailable.wait()
    )
  except CancelledError:
    debug "Service interrupted"
    return

  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")

  var currentSlot: Opt[Slot]
  while true:
    try:
      let slot = await vc.checkedWaitForNextSlot(
        currentSlot, vc.timeParams.payloadAttestationSlotOffset, false)
      if slot.isNone():
        debug "System time adjusted backwards significantly, exiting"
        return

      currentSlot = slot
      if vc.isPastGloasFork(currentSlot.get().epoch()):
        await service.spawnPayloadAttestationTasks(currentSlot.get())
    except CancelledError:
      debug "Service interrupted"
      return

proc init*(
    t: typedesc[PayloadAttestationServiceRef],
    vc: ValidatorClientRef
): Future[PayloadAttestationServiceRef] {.async: (raises: []).} =
  logScope: service = ServiceName
  let res = PayloadAttestationServiceRef(name: ServiceName,
                                         client: vc,
                                         state: ServiceState.Initialized)
  debug "Initializing service"
  res

proc start*(service: PayloadAttestationServiceRef) =
  service.lifeFut = mainLoop(service)
