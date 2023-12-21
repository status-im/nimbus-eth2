# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/sets,
  chronicles,
  ../validators/[activity_metrics, validator_duties],
  "."/[common, api]

const
  ServiceName = "attestation_service"

logScope: service = ServiceName

type
  AggregateItem* = object
    aggregator_index: uint64
    selection_proof: ValidatorSig
    validator: AttachedValidator

proc serveAttestation(
    service: AttestationServiceRef, registered: RegisteredAttestation):
    Future[bool] {.async.} =
  let
    vc = service.client
    fork = vc.forkAtEpoch(registered.data.slot.epoch)
    validator = registered.validator

  logScope:
    validator = validatorLog(validator)

  let attestation = block:
    let signature =
      try:
        let res = await validator.getAttestationSignature(
          fork, vc.beaconGenesis.genesis_validators_root, registered.data)
        if res.isErr():
          warn "Unable to sign attestation", reason = res.error()
          return false
        res.get()
      except CancelledError as exc:
        debug "Attestation signature process was interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while signing attestation",
              err_name = exc.name, err_msg = exc.msg
        return false
    registered.toAttestation(signature)

  logScope:
    attestation = shortLog(attestation)
    delay = vc.getDelay(registered.data.slot.attestation_deadline())

  debug "Sending attestation"

  validator.doppelgangerActivity(attestation.data.slot.epoch)

  let res =
    try:
      await vc.submitPoolAttestations(@[attestation], ApiStrategyKind.First)
    except ValidatorApiError as exc:
      warn "Unable to publish attestation", reason = exc.getFailureReason()
      return false
    except CancelledError as exc:
      debug "Attestation publishing process was interrupted"
      raise exc
    except CatchableError as exc:
      error "Unexpected error occured while publishing attestation",
            err_name = exc.name, err_msg = exc.msg
      return false

  if res:
    let delay = vc.getDelay(attestation.data.slot.attestation_deadline())
    beacon_attestations_sent.inc()
    beacon_attestation_sent_delay.observe(delay.toFloatSeconds())
    notice "Attestation published"
  else:
    warn "Attestation was not accepted by beacon node"
  return res

proc serveAggregateAndProof*(service: AttestationServiceRef,
                             proof: AggregateAndProof,
                             validator: AttachedValidator): Future[bool] {.
     async.} =
  let
    vc = service.client
    genesisRoot = vc.beaconGenesis.genesis_validators_root
    slot = proof.aggregate.data.slot
    fork = vc.forkAtEpoch(slot.epoch)

  logScope:
    validator = validatorLog(validator)
    attestation = shortLog(proof.aggregate)

  debug "Signing aggregate", fork = fork

  let signature =
    try:
      let res =
        await validator.getAggregateAndProofSignature(fork, genesisRoot, proof)
      if res.isErr():
        warn "Unable to sign aggregate and proof using remote signer",
              reason = res.error()
        return false
      res.get()
    except CancelledError as exc:
      debug "Aggregated attestation signing process was interrupted"
      raise exc
    except CatchableError as exc:
      error "Unexpected error occured while signing aggregated attestation",
            err_name = exc.name, err_msg = exc.msg
      return false

  let signedProof = SignedAggregateAndProof(message: proof,
                                            signature: signature)
  logScope:
    delay = vc.getDelay(slot.aggregate_deadline())

  debug "Sending aggregated attestation", fork = fork

  validator.doppelgangerActivity(proof.aggregate.data.slot.epoch)

  let res =
    try:
      await vc.publishAggregateAndProofs(@[signedProof], ApiStrategyKind.First)
    except ValidatorApiError as exc:
      warn "Unable to publish aggregated attestation",
            reason = exc.getFailureReason()
      return false
    except CancelledError as exc:
      debug "Publish aggregate and proofs request was interrupted"
      raise exc
    except CatchableError as exc:
      error "Unexpected error occured while publishing aggregated attestation",
            err_name = exc.name, err_msg = exc.msg
      return false

  if res:
    beacon_aggregates_sent.inc()
    notice "Aggregated attestation published"
  else:
    warn "Aggregated attestation was not accepted by beacon node"
  return res

proc produceAndPublishAttestations*(service: AttestationServiceRef,
                                    slot: Slot, committee_index: CommitteeIndex,
                                    duties: seq[DutyAndProof]
                                   ): Future[AttestationData] {.
     async.} =
  doAssert(MAX_VALIDATORS_PER_COMMITTEE <= uint64(high(int)))
  let
    vc = service.client
    fork = vc.forkAtEpoch(slot.epoch)

  # This call could raise ValidatorApiError, but it is handled in
  # publishAttestationsAndAggregates().
  let data = await vc.produceAttestationData(slot, committee_index,
                                             ApiStrategyKind.Best)

  let registeredRes = vc.attachedValidators[].slashingProtection.withContext:
    var tmp: seq[RegisteredAttestation]
    for duty in duties:
      if (duty.data.slot != data.slot) or
          (uint64(duty.data.committee_index) != data.index):
        warn "Inconsistent validator duties during attestation signing",
              validator = shortLog(duty.data.pubkey),
              duty_slot = duty.data.slot,
              duty_index = duty.data.committee_index,
              attestation_slot = data.slot, attestation_index = data.index
        continue

      let validator = vc.getValidatorForDuties(
          duty.data.pubkey, duty.data.slot).valueOr:
        continue

      doAssert(validator.index.isSome())
      let validator_index = validator.index.get()

      logScope:
        validator = validatorLog(validator)

      # TODO: signing_root is recomputed in getAttestationSignature just after,
      # but not for locally attached validators.
      let
        signingRoot = compute_attestation_signing_root(
          fork, vc.beaconGenesis.genesis_validators_root, data)
        registered = registerAttestationInContext(
              validator_index, validator.pubkey, data.source.epoch,
              data.target.epoch, signingRoot)
      if registered.isErr():
        warn "Slashing protection activated for attestation",
            attestationData = shortLog(data),
            signingRoot = shortLog(signingRoot),
            badVoteDetails = $registered.error()
        continue

      tmp.add(RegisteredAttestation(
        validator: validator,
        index_in_committee: duty.data.validator_committee_index,
        committee_len: int duty.data.committee_length,
        data: data
      ))
    tmp

  if registeredRes.isErr():
    warn "Could not update slashing database, skipping attestation duties",
      error = registeredRes.error()
  else:
    let
      pendingAttestations = registeredRes[].mapIt(service.serveAttestation(it))
      statistics =
        block:
          var errored, succeed, failed = 0
          try:
            await allFutures(pendingAttestations)
          except CancelledError as exc:
            let pending = pendingAttestations
              .filterIt(not(it.finished())).mapIt(it.cancelAndWait())
            await noCancel allFutures(pending)
            raise exc

          for future in pendingAttestations:
            if future.completed():
              if future.read():
                inc(succeed)
              else:
                inc(failed)
            else:
              inc(errored)
          (succeed, errored, failed)

    let delay = vc.getDelay(slot.attestation_deadline())
    debug "Attestation statistics", total = len(pendingAttestations),
          succeed = statistics[0], failed_to_deliver = statistics[1],
          not_accepted = statistics[2], delay = delay, slot = slot,
          committee_index = committee_index, duties_count = len(duties)

  return data

proc produceAndPublishAggregates(service: AttestationServiceRef,
                                 adata: AttestationData,
                                 duties: seq[DutyAndProof]) {.async.} =
  let
    vc = service.client
    slot = adata.slot
    committeeIndex = adata.index
    attestationRoot = adata.hash_tree_root()

  let aggregateItems =
    block:
      var res: seq[AggregateItem]
      for duty in duties:
        let validator = vc.getValidatorForDuties(
            duty.data.pubkey, slot).valueOr:
          continue

        if (duty.data.slot != slot) or
            (duty.data.committee_index != committeeIndex):
          warn "Inconsistent validator duties during aggregate signing",
               duty_slot = duty.data.slot, slot = slot,
               duty_committee_index = duty.data.committee_index,
               committee_index = committeeIndex
          continue
        if duty.slotSig.isSome():
          let slotSignature = duty.slotSig.get()
          if is_aggregator(duty.data.committee_length, slotSignature):
            res.add(AggregateItem(
              aggregator_index: uint64(duty.data.validator_index),
              selection_proof: slotSignature,
              validator: validator
            ))
      res

  if len(aggregateItems) > 0:
    let aggAttestation =
      try:
        await vc.getAggregatedAttestation(slot, attestationRoot,
                                          ApiStrategyKind.Best)
      except ValidatorApiError as exc:
        warn "Unable to get aggregated attestation data", slot = slot,
             attestation_root = shortLog(attestationRoot),
             reason = exc.getFailureReason()
        return
      except CancelledError as exc:
        debug "Aggregated attestation request was interrupted"
        raise exc
      except CatchableError as exc:
        error "Unexpected error occured while getting aggregated attestation",
              slot = slot, attestation_root = shortLog(attestationRoot),
              err_name = exc.name, err_msg = exc.msg
        return

    let pendingAggregates =
      block:
        var res: seq[Future[bool]]
        for item in aggregateItems:
          let proof = AggregateAndProof(
            aggregator_index: item.aggregator_index,
            aggregate: aggAttestation,
            selection_proof: item.selection_proof
          )
          res.add(service.serveAggregateAndProof(proof, item.validator))
        res

    let statistics =
      block:
        var errored, succeed, failed = 0
        try:
          await allFutures(pendingAggregates)
        except CancelledError as exc:
          let pending = pendingAggregates
            .filterIt(not(it.finished())).mapIt(it.cancelAndWait())
          await noCancel allFutures(pending)
          raise exc

        for future in pendingAggregates:
          if future.completed():
            if future.read():
              inc(succeed)
            else:
              inc(failed)
          else:
            inc(errored)
        (succeed, errored, failed)

    let delay = vc.getDelay(slot.aggregate_deadline())
    debug "Aggregated attestation statistics", total = len(pendingAggregates),
          succeed = statistics[0], failed_to_deliver = statistics[1],
          not_accepted = statistics[2], delay = delay, slot = slot,
          committee_index = committeeIndex

  else:
    debug "No aggregate and proofs scheduled for slot", slot = slot,
           committee_index = committeeIndex

proc publishAttestationsAndAggregates(service: AttestationServiceRef,
                                      slot: Slot,
                                      committee_index: CommitteeIndex,
                                      duties: seq[DutyAndProof]) {.async.} =
  let vc = service.client

  block:
    let delay = vc.getDelay(slot.attestation_deadline())
    debug "Producing attestations", delay = delay, slot = slot,
                                    committee_index = committee_index,
                                    duties_count = len(duties)
  let ad =
    try:
      await service.produceAndPublishAttestations(slot, committee_index, duties)
    except ValidatorApiError as exc:
      warn "Unable to proceed attestations", slot = slot,
           committee_index = committee_index, duties_count = len(duties),
           reason = exc.getFailureReason()
      return
    except CancelledError as exc:
      debug "Publish attestation request was interrupted"
      raise exc
    except CatchableError as exc:
      error "Unexpected error while producing attestations", slot = slot,
            committee_index = committee_index, duties_count = len(duties),
            err_name = exc.name, err_msg = exc.msg
      return

  let aggregateTime =
    # chronos.Duration substraction could not return negative value, in such
    # case it will return `ZeroDuration`.
    vc.beaconClock.durationToNextSlot() - OneThirdDuration
  if aggregateTime != ZeroDuration:
    await sleepAsync(aggregateTime)

  block:
    let delay = vc.getDelay(slot.aggregate_deadline())
    debug "Producing aggregate and proofs", delay = delay
  await service.produceAndPublishAggregates(ad, duties)

proc spawnAttestationTasks(service: AttestationServiceRef,
                           slot: Slot) {.async.} =
  let vc = service.client
  let dutiesByCommittee =
    block:
      var res: Table[CommitteeIndex, seq[DutyAndProof]]
      let attesters = vc.getAttesterDutiesForSlot(slot)
      var default: seq[DutyAndProof]
      for item in attesters:
        res.mgetOrPut(item.data.committee_index, default).add(item)
      res

  # Waiting for blocks to be published before attesting.
  await vc.waitForBlock(slot, attestationSlotOffset)

  var tasks: seq[Future[void]]
  try:
    for index, duties in dutiesByCommittee:
      tasks.add(service.publishAttestationsAndAggregates(slot, index, duties))
    let timeout = vc.beaconClock.durationToNextSlot()
    await allFutures(tasks).wait(timeout)
  except AsyncTimeoutError:
    # Cancelling all the pending tasks.
    let pending = tasks.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
    await allFutures(pending)
  except CancelledError as exc:
    # Cancelling all the pending tasks.
    let pending = tasks.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
    await noCancel allFutures(pending)
    raise exc
  except CatchableError as exc:
    error "Unexpected error while processing attestation duties",
          error_name = exc.name, error_message = exc.msg

proc mainLoop(service: AttestationServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  debug "Attester loop is waiting for initialization"
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
  except CatchableError as exc:
    warn "Service crashed with unexpected error", err_name = exc.name,
         err_msg = exc.msg
    return

  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")

  var currentSlot: Opt[Slot]
  while true:
    # This loop could look much more nicer/better, when
    # https://github.com/nim-lang/Nim/issues/19911 will be fixed, so it could
    # become safe to combine loops, breaks and exception handlers.
    let breakLoop =
      try:
        let
          # We use zero offset here, because we do waiting in
          # waitForBlock(attestationSlotOffset).
          slot = await vc.checkedWaitForNextSlot(currentSlot,
                                                 ZeroTimeDiff, false)
        if slot.isNone():
          debug "System time adjusted backwards significantly, exiting"
          true
        else:
          currentSlot = slot
          await service.spawnAttestationTasks(currentSlot.get())
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

proc init*(t: typedesc[AttestationServiceRef],
           vc: ValidatorClientRef): Future[AttestationServiceRef] {.async.} =
  logScope: service = ServiceName
  let res = AttestationServiceRef(name: ServiceName,
                                  client: vc, state: ServiceState.Initialized)
  debug "Initializing service"
  return res

proc start*(service: AttestationServiceRef) =
  service.lifeFut = mainLoop(service)
