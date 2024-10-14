# beacon_chain
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

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
    committee_index: CommitteeIndex
    validator: AttachedValidator

func getAttesterDutiesByCommittee(
    duties: openArray[DutyAndProof]
): Table[CommitteeIndex, seq[DutyAndProof]] =
  var res: Table[CommitteeIndex, seq[DutyAndProof]]
  for item in duties:
    res.mgetOrPut(item.data.committee_index, default(seq[DutyAndProof])).
      add(item)
  res

proc serveAttestation(
    service: AttestationServiceRef,
    registered: RegisteredAttestation
): Future[bool] {.async: (raises: [CancelledError]).} =
  let
    vc = service.client
    fork = vc.forkAtEpoch(registered.data.slot.epoch)
    validator = registered.validator
    attestationSlot = registered.data.slot
    afterElectra = vc.isPastElectraFork(attestationSlot.epoch)

  logScope:
    validator = validatorLog(validator)

  let signature =
    try:
      let res =
        await validator.getAttestationSignature(
          fork, vc.beaconGenesis.genesis_validators_root, registered.data)
      if res.isErr():
        warn "Unable to sign attestation", reason = res.error()
        return false
      res.get()
    except CancelledError as exc:
      debug "Attestation signature process was interrupted"
      raise exc

  logScope:
    delay = vc.getDelay(attestationSlot.attestation_deadline())

  debug "Sending attestation"

  validator.doppelgangerActivity(attestationSlot.epoch)

  template submitAttestation(atst: untyped): untyped =
    logScope:
      attestation = shortLog(atst)
    try:
      when atst is electra.Attestation:
        await vc.submitPoolAttestationsV2(@[atst], ApiStrategyKind.First)
      else:
        await vc.submitPoolAttestations(@[atst], ApiStrategyKind.First)
    except ValidatorApiError as exc:
      warn "Unable to publish attestation", reason = exc.getFailureReason()
      return false
    except CancelledError as exc:
      debug "Attestation publishing process was interrupted"
      raise exc

  let res =
    if afterElectra:
      let attestation = registered.toElectraAttestation(signature)
      submitAttestation(attestation)
    else:
      let attestation = registered.toAttestation(signature)
      submitAttestation(attestation)

  if res:
    let delay = vc.getDelay(attestationSlot.attestation_deadline())
    beacon_attestations_sent.inc()
    beacon_attestation_sent_delay.observe(delay.toFloatSeconds())
    notice "Attestation published"
  else:
    warn "Attestation was not accepted by beacon node"

  res

proc serveAggregateAndProof*(
    service: AttestationServiceRef,
    proof: phase0.AggregateAndProof,
    validator: AttachedValidator
): Future[bool] {.async: (raises: [CancelledError]).} =
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

  let signedProof = phase0.SignedAggregateAndProof(
    message: proof, signature: signature)
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

  if res:
    beacon_aggregates_sent.inc()
    notice "Aggregated attestation published"
  else:
    warn "Aggregated attestation was not accepted by beacon node"
  return res

proc serveAggregateAndProofV2*(
    service: AttestationServiceRef,
    proof: ForkyAggregateAndProof,
    validator: AttachedValidator
): Future[bool] {.async: (raises: [CancelledError]).} =
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

  let signedProof =
    when proof is phase0.AggregateAndProof:
      phase0.SignedAggregateAndProof(
        message: proof, signature: signature)
    elif proof is electra.AggregateAndProof:
      electra.SignedAggregateAndProof(
        message: proof, signature: signature)
    else:
      static:
        raiseAssert "Unsupported SignedAggregateAndProof"

  logScope:
    delay = vc.getDelay(slot.aggregate_deadline())

  debug "Sending aggregated attestation", fork = fork

  validator.doppelgangerActivity(proof.aggregate.data.slot.epoch)

  let res =
    try:
      await vc.publishAggregateAndProofsV2(@[signedProof],
                                           ApiStrategyKind.First)
    except ValidatorApiError as exc:
      warn "Unable to publish aggregated attestation",
            reason = exc.getFailureReason()
      return false
    except CancelledError as exc:
      debug "Publish aggregate and proofs request was interrupted"
      raise exc

  if res:
    beacon_aggregates_sent.inc()
    notice "Aggregated attestation published"
  else:
    warn "Aggregated attestation was not accepted by beacon node"
  res

proc produceAndPublishAttestations*(
    service: AttestationServiceRef,
    slot: Slot,
    committee_index: CommitteeIndex,
    duties: seq[DutyAndProof]
): Future[AttestationData] {.
   async: (raises: [CancelledError, ValidatorApiError]).} =
  doAssert(MAX_VALIDATORS_PER_COMMITTEE <= uint64(high(int)))
  let
    vc = service.client
    fork = vc.forkAtEpoch(slot.epoch)

  let data = await vc.produceAttestationData(slot, committee_index,
                                             ApiStrategyKind.Best)

  let registeredRes = vc.attachedValidators[].slashingProtection.withContext:
    var tmp: seq[RegisteredAttestation]
    for duty in duties:
      if (duty.data.slot != data.slot) or
          (uint64(duty.data.committee_index) != data.index):
        warn "Inconsistent validator duties during attestation signing",
              pubkey = shortLog(duty.data.pubkey),
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
              if future.value:
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

  data

proc produceAndPublishAggregates(
    service: AttestationServiceRef,
    adata: AttestationData,
    duties: seq[DutyAndProof]
) {.async: (raises: [CancelledError]).} =
  let
    vc = service.client
    slot = adata.slot
    committeeIndex = adata.index
    attestationRoot = adata.hash_tree_root()
    afterElectra = vc.isPastElectraFork(slot.epoch())

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
              committee_index: CommitteeIndex(committeeIndex),
              selection_proof: slotSignature,
              validator: validator
            ))
      res

  if len(aggregateItems) > 0:
    let aggregates =
      block:
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

        if isLowestScoreAggregatedAttestation(aggAttestation):
          warn "Aggregated attestation with the root was not seen by the " &
               "beacon node",
               attestation_root = shortLog(attestationRoot)
          return

        var res: seq[Future[bool].Raising([CancelledError])]
        for item in aggregateItems:
          let proof = phase0.AggregateAndProof(
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
          await allFutures(aggregates)
        except CancelledError as exc:
          let pending = aggregates
            .filterIt(not(it.finished())).mapIt(it.cancelAndWait())
          await noCancel allFutures(pending)
          raise exc

        for future in aggregates:
          if future.completed():
            if future.value:
              inc(succeed)
            else:
              inc(failed)
          else:
            inc(errored)
        (succeed, errored, failed)

    let delay = vc.getDelay(slot.aggregate_deadline())
    debug "Aggregated attestation statistics", total = len(aggregates),
          succeed = statistics[0], failed_to_deliver = statistics[1],
          not_accepted = statistics[2], delay = delay, slot = slot,
          committee_index = committeeIndex

  else:
    debug "No aggregate and proofs scheduled for slot", slot = slot,
           committee_index = committeeIndex

proc publishAttestationsAndAggregates(
    service: AttestationServiceRef,
    slot: Slot,
    committee_index: CommitteeIndex,
    duties: seq[DutyAndProof]
) {.async: (raises: [CancelledError]).} =
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

proc produceAndPublishAttestationsV2*(
    service: AttestationServiceRef,
    slot: Slot,
    duties: seq[DutyAndProof]
): Future[AttestationData] {.
   async: (raises: [CancelledError, ValidatorApiError]).} =
  doAssert(MAX_VALIDATORS_PER_COMMITTEE <= uint64(high(int)))
  let
    vc = service.client
    fork = vc.forkAtEpoch(slot.epoch)
    data = await vc.produceAttestationData(slot, CommitteeIndex(0),
                                           ApiStrategyKind.Best)
    registeredRes =
      vc.attachedValidators[].slashingProtection.withContext:
        var tmp: seq[RegisteredAttestation]
        for duty in duties:
          if (duty.data.slot != data.slot):
            warn "Inconsistent validator duties during attestation signing",
                  pubkey = shortLog(duty.data.pubkey),
                  duty_slot = duty.data.slot,
                  duty_index = duty.data.committee_index,
                  attestation_slot = data.slot
            continue

          let validator =
            vc.getValidatorForDuties(duty.data.pubkey, duty.data.slot).valueOr:
              continue

          doAssert(validator.index.isSome())
          let validator_index = validator.index.get()

          logScope:
            validator = validatorLog(validator)

          # TODO: signing_root is recomputed in getAttestationSignature just
          # after, but not for locally attached validators.
          let
            signingRoot =
              compute_attestation_signing_root(
                fork, vc.beaconGenesis.genesis_validators_root, data)
            registered =
              registerAttestationInContext(
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
            committee_len: int(duty.data.committee_length),
            data: data
          ))
        tmp

  if registeredRes.isErr():
    warn "Could not update slashing database, skipping attestation duties",
         reason = registeredRes.error()
    return

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
            if future.value:
              inc(succeed)
            else:
              inc(failed)
          else:
            inc(errored)
        (succeed, errored, failed)

    delay = vc.getDelay(slot.attestation_deadline())

  debug "Attestation statistics", total = len(pendingAttestations),
        succeed = statistics[0], failed_to_deliver = statistics[1],
        not_accepted = statistics[2], delay = delay, slot = slot,
        duties_count = len(duties)
  data

proc produceAndPublishAggregatesV2(
    service: AttestationServiceRef,
    adata: AttestationData,
    duties: seq[DutyAndProof]
) {.async: (raises: [CancelledError]).} =
  let
    vc = service.client
    slot = adata.slot
    attestationRoot = adata.hash_tree_root()

  let aggregateItems =
    block:
      var res: seq[AggregateItem]
      for duty in duties:
        let validator =
          vc.getValidatorForDuties(duty.data.pubkey, slot).valueOr:
            continue

        if duty.data.slot != slot:
          warn "Inconsistent validator duties during aggregate signing",
               duty_slot = duty.data.slot, slot = slot,
               duty_committee_index = duty.data.committee_index
          continue
        if duty.slotSig.isSome():
          let slotSignature = duty.slotSig.get()
          if is_aggregator(duty.data.committee_length, slotSignature):
            res.add(AggregateItem(
              aggregator_index: uint64(duty.data.validator_index),
              committee_index: CommitteeIndex(duty.data.committee_index),
              selection_proof: slotSignature,
              validator: validator
            ))
      res

  if len(aggregateItems) == 0:
    debug "No aggregate and proofs scheduled for slot", slot = slot
    return

  # All duties should be sorted by `committee_index`.
  let committee_index = duties[0].data.committee_index

  let aggregates =
    block:
      let attestation =
        try:
          await vc.getAggregatedAttestationV2(slot, attestationRoot,
                                              committee_index,
                                              ApiStrategyKind.Best)
        except ValidatorApiError as exc:
          warn "Unable to get aggregated attestation data", slot = slot,
               attestation_root = shortLog(attestationRoot),
               reason = exc.getFailureReason()
          return
        except CancelledError as exc:
          debug "Aggregated attestation request was interrupted"
          raise exc

      if isLowestScoreAggregatedAttestation(attestation):
        warn "Aggregated attestation with the root was not seen by the " &
             "beacon node",
             attestation_root = shortLog(attestationRoot)
        return

      var res: seq[Future[bool].Raising([CancelledError])]
      for item in aggregateItems:
        withAttestation(attestation):
          when consensusFork > ConsensusFork.Deneb:
            let proof =
              electra.AggregateAndProof(
                aggregator_index: item.aggregator_index,
                aggregate: forkyAttestation,
                selection_proof: item.selection_proof
              )
            res.add(service.serveAggregateAndProofV2(proof, item.validator))
          else:
            let proof =
              phase0.AggregateAndProof(
                aggregator_index: item.aggregator_index,
                aggregate: forkyAttestation,
                selection_proof: item.selection_proof
              )
            res.add(service.serveAggregateAndProofV2(proof, item.validator))
      res

  let statistics =
    block:
      var errored, succeed, failed = 0
      try:
        await allFutures(aggregates)
      except CancelledError as exc:
        let pending = aggregates
          .filterIt(not(it.finished())).mapIt(it.cancelAndWait())
        await noCancel allFutures(pending)
        raise exc

      for future in aggregates:
        if future.completed():
          if future.value:
            inc(succeed)
          else:
            inc(failed)
        else:
          inc(errored)
      (succeed, errored, failed)

  let delay = vc.getDelay(slot.aggregate_deadline())
  debug "Aggregated attestation statistics", total = len(aggregates),
        succeed = statistics[0], failed_to_deliver = statistics[1],
        not_accepted = statistics[2], delay = delay, slot = slot,
        committee_index = committeeIndex

proc publishAttestationsAndAggregatesV2(
    service: AttestationServiceRef,
    slot: Slot,
    duties: seq[DutyAndProof]
) {.async: (raises: [CancelledError]).} =
  let
    vc = service.client

  block:
    let delay = vc.getDelay(slot.attestation_deadline())
    debug "Producing attestations", delay = delay, slot = slot,
                                    duties_count = len(duties)

  let ad =
    try:
      await service.produceAndPublishAttestationsV2(slot, duties)
    except ValidatorApiError as exc:
      warn "Unable to proceed attestations", slot = slot,
           duties_count = len(duties), reason = exc.getFailureReason()
      return
    except CancelledError as exc:
      debug "Publish attestation request was interrupted"
      raise exc

  let aggregateTime =
    # chronos.Duration substraction could not return negative value, in such
    # case it will return `ZeroDuration`.
    vc.beaconClock.durationToNextSlot() - OneThirdDuration
  if aggregateTime != ZeroDuration:
    await sleepAsync(aggregateTime)

  block:
    let
      delay = vc.getDelay(slot.aggregate_deadline())
      dutiesByCommittee = getAttesterDutiesByCommittee(duties)
    debug "Producing aggregate and proofs", delay = delay
    var tasks: seq[Future[void].Raising([CancelledError])]
    try:
      for index, cduties in dutiesByCommittee:
        tasks.add(service.produceAndPublishAggregatesV2(ad, cduties))
      await allFutures(tasks)
    except CancelledError as exc:
      # Cancelling all the pending tasks.
      let pending = tasks.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
      await noCancel allFutures(pending)
      raise exc

proc spawnAttestationTasks(
    service: AttestationServiceRef,
    slot: Slot
) {.async: (raises: [CancelledError]).} =
  let
    vc = service.client
    dutiesByCommittee =
      getAttesterDutiesByCommittee(vc.getAttesterDutiesForSlot(slot))

  # Waiting for blocks to be published before attesting.
  await vc.waitForBlock(slot, attestationSlotOffset)

  var tasks: seq[Future[void].Raising([CancelledError])]
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

proc spawnAttestationTasksV2(
    service: AttestationServiceRef,
    slot: Slot
) {.async: (raises: [CancelledError]).} =
  let
    vc = service.client
    duties = vc.getAttesterDutiesForSlot(slot)

  # Waiting for blocks to be published before attesting.
  await vc.waitForBlock(slot, attestationSlotOffset)

  try:
    let timeout = vc.beaconClock.durationToNextSlot()
    await service.publishAttestationsAndAggregatesV2(slot, duties).wait(timeout)
  except AsyncTimeoutError:
    discard
  except CancelledError as exc:
    # Cancelling all the pending tasks.
    raise exc

proc mainLoop(service: AttestationServiceRef) {.async: (raises: []).} =
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

  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")

  var currentSlot: Opt[Slot]
  while true:
    try:
      let
        # We use zero offset here, because we do waiting in
        # waitForBlock(attestationSlotOffset).
        slot = await vc.checkedWaitForNextSlot(currentSlot,
                                               ZeroTimeDiff, false)
      if slot.isNone():
        debug "System time adjusted backwards significantly, exiting"
        return

      currentSlot = slot
      if vc.isPastElectraFork(currentSlot.get().epoch()):
        await service.spawnAttestationTasksV2(currentSlot.get())
      else:
        await service.spawnAttestationTasks(currentSlot.get())
    except CancelledError:
      debug "Service interrupted"
      return

proc init*(
    t: typedesc[AttestationServiceRef],
    vc: ValidatorClientRef
): Future[AttestationServiceRef] {.async: (raises: []).} =
  logScope: service = ServiceName
  let res = AttestationServiceRef(name: ServiceName,
                                  client: vc, state: ServiceState.Initialized)
  debug "Initializing service"
  res

proc start*(service: AttestationServiceRef) =
  service.lifeFut = mainLoop(service)
