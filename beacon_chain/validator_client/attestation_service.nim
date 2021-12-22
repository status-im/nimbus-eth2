import std/[sets, sequtils]
import chronicles
import "."/[common, api, block_service]

logScope: service = "attestation_service"

type
  AggregateItem* = object
    aggregator_index: uint64
    selection_proof: ValidatorSig
    validator: AttachedValidator

proc serveAttestation(service: AttestationServiceRef, adata: AttestationData,
                      duty: DutyAndProof): Future[bool] {.async.} =
  let vc = service.client
  let validator =
    block:
      let res = vc.getValidator(duty.data.pubkey)
      if res.isNone():
        return false
      res.get()

  let fork = vc.fork.get()

  # TODO: signing_root is recomputed in signBlockProposal just after,
  # but not for locally attached validators.
  let signingRoot =
    compute_attestation_signing_root(
      fork, vc.beaconGenesis.genesis_validators_root, adata)
  let attestationRoot = adata.hash_tree_root()

  let vindex = validator.index.get()
  let notSlashable = vc.attachedValidators.slashingProtection
                       .registerAttestation(vindex, validator.pubkey,
                                            adata.source.epoch,
                                            adata.target.epoch, signingRoot)
  if notSlashable.isErr():
    warn "Slashing protection activated for attestation",
         slot = duty.data.slot,
         validator = shortLog(validator),
         validator_index = vindex, badVoteDetails = $notSlashable.error
    return false

  let attestation =
    block:
      let res = await validator.produceAndSignAttestation(adata,
        int(duty.data.committee_length),
        Natural(duty.data.validator_committee_index),
        fork, vc.beaconGenesis.genesis_validators_root)
      if res.isErr():
        error "Unable to sign attestation", validator = shortLog(validator),
              error_msg = res.error()
        return false
      res.get()

  debug "Sending attestation", attestation = shortLog(attestation),
        validator = shortLog(validator), validator_index = vindex,
        attestation_root = shortLog(attestationRoot),
        delay = vc.getDelay(attestationSlotOffset)

  let res =
    try:
      await vc.submitPoolAttestations(@[attestation])
    except ValidatorApiError:
      error "Unable to publish attestation",
            attestation = shortLog(attestation),
            validator = shortLog(validator),
            validator_index = vindex
      return false
    except CatchableError as exc:
      error "Unexpected error occured while publishing attestation",
            attestation = shortLog(attestation),
            validator = shortLog(validator),
            validator_index = vindex,
            err_name = exc.name, err_msg = exc.msg
      return false

  let delay = vc.getDelay(attestationSlotOffset)
  if res:
    notice "Attestation published", attestation = shortLog(attestation),
                                    validator = shortLog(validator),
                                    validator_index = vindex,
                                    delay = delay,
                                    attestation_root = attestationRoot
  else:
    warn "Attestation was not accepted by beacon node",
         attestation = shortLog(attestation),
         validator = shortLog(validator),
         validator_index = vindex, delay = delay
  return res

proc serveAggregateAndProof*(service: AttestationServiceRef,
                             proof: AggregateAndProof,
                             validator: AttachedValidator): Future[bool] {.
     async.} =
  let
    vc = service.client
    genesisRoot = vc.beaconGenesis.genesis_validators_root
    fork = vc.fork.get()

  let signature =
    block:
      let res = await signAggregateAndProof(validator, proof, fork,
                                            genesisRoot)
      if res.isErr():
        error "Unable to sign aggregate and proof using remote signer",
              validator = shortLog(validator),
              aggregationSlot = proof.aggregate.data.slot,
              error_msg = res.error()
        return false
      res.get()
  let signedProof = SignedAggregateAndProof(message: proof,
                                            signature: signature)

  let aggregationSlot = proof.aggregate.data.slot
  let vindex = validator.index.get()

  debug "Sending aggregated attestation",
        attestation = shortLog(signedProof.message.aggregate),
        validator = shortLog(validator), validator_index = vindex,
        aggregationSlot = aggregationSlot,
        delay = vc.getDelay(aggregateSlotOffset)

  let res =
    try:
      await vc.publishAggregateAndProofs(@[signedProof])
    except ValidatorApiError:
      error "Unable to publish aggregated attestation",
            attestation = shortLog(signedProof.message.aggregate),
            validator = shortLog(validator),
            aggregationSlot = aggregationSlot,
            validator_index = vindex
      return false
    except CatchableError as exc:
      error "Unexpected error occured while publishing aggregated attestation",
            attestation = shortLog(signedProof.message.aggregate),
            validator = shortLog(validator),
            aggregationSlot = aggregationSlot,
            validator_index = vindex,
            err_name = exc.name, err_msg = exc.msg
      return false

  if res:
    notice "Aggregated attestation published",
           attestation = shortLog(signedProof.message.aggregate),
           validator = shortLog(validator),
           aggregationSlot = aggregationSlot, validator_index = vindex
  else:
    warn "Aggregated attestation was not accepted by beacon node",
         attestation = shortLog(signedProof.message.aggregate),
         validator = shortLog(validator),
         aggregationSlot = aggregationSlot, validator_index = vindex
  return res

proc produceAndPublishAttestations*(service: AttestationServiceRef,
                                    slot: Slot, committee_index: CommitteeIndex,
                                    duties: seq[DutyAndProof]
                                   ): Future[AttestationData] {.
     async.} =
  doAssert(MAX_VALIDATORS_PER_COMMITTEE <= uint64(high(int)))
  let vc = service.client

  # This call could raise ValidatorApiError, but it is handled in
  # publishAttestationsAndAggregates().
  let ad = await vc.produceAttestationData(slot, committee_index)

  let pendingAttestations =
    block:
      var res: seq[Future[bool]]
      for duty in duties:
        debug "Serving attestation duty", duty = duty.data, epoch = slot.epoch()
        if (duty.data.slot != ad.slot) or
           (uint64(duty.data.committee_index) != ad.index):
          error "Inconsistent validator duties during attestation signing",
                validator = shortLog(duty.data.pubkey),
                duty_slot = duty.data.slot,
                duty_index = duty.data.committee_index,
                attestation_slot = ad.slot, attestation_index = ad.index
          continue
        res.add(service.serveAttestation(ad, duty))
      res

  let statistics =
    block:
      var errored, succeed, failed = 0
      try:
        await allFutures(pendingAttestations)
      except CancelledError:
        for fut in pendingAttestations:
          if not(fut.finished()):
            fut.cancel()
        await allFutures(pendingAttestations)

      for future in pendingAttestations:
        if future.done():
          if future.read():
            inc(succeed)
          else:
            inc(failed)
        else:
          inc(errored)
      (succeed, errored, failed)

  let delay = vc.getDelay(attestationSlotOffset)
  debug "Attestation statistics", total = len(pendingAttestations),
         succeed = statistics[0], failed_to_deliver = statistics[1],
         not_accepted = statistics[2], delay = delay, slot = slot,
         committee_index = committee_index, duties_count = len(duties)

  return ad

proc produceAndPublishAggregates(service: AttestationServiceRef,
                                 adata: AttestationData,
                                 duties: seq[DutyAndProof]) {.async.} =
  let
    vc = service.client
    slot = adata.slot
    committeeIndex = CommitteeIndex(adata.index)
    attestationRoot = adata.hash_tree_root()

  let aggregateItems =
    block:
      var res: seq[AggregateItem]
      for duty in duties:
        let validator = vc.attachedValidators.getValidator(duty.data.pubkey)
        if not(isNil(validator)):
          if (duty.data.slot != slot) or
             (duty.data.committee_index != committeeIndex):
            error "Inconsistent validator duties during aggregate signing",
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
        await vc.getAggregatedAttestation(slot, attestationRoot)
      except ValidatorApiError:
        error "Unable to get aggregated attestation data", slot = slot,
              attestation_root = shortLog(attestationRoot)
        return
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
        except CancelledError:
          for fut in pendingAggregates:
            if not(fut.finished()):
              fut.cancel()
          await allFutures(pendingAggregates)

        for future in pendingAggregates:
          if future.done():
            if future.read():
              inc(succeed)
            else:
              inc(failed)
          else:
            inc(errored)
        (succeed, errored, failed)

    let delay = vc.getDelay(aggregateSlotOffset)
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
  # Waiting for blocks to be published before attesting.
  let startTime = Moment.now()
  try:
    let timeout = attestationSlotOffset # 4.seconds in mainnet
    await vc.waitForBlockPublished(slot).wait(timeout)
    let dur = Moment.now() - startTime
    debug "Block proposal awaited", slot = slot, duration = dur
  except AsyncTimeoutError:
    let dur = Moment.now() - startTime
    debug "Block was not produced in time", slot = slot, duration = dur

  block:
    let delay = vc.getDelay(attestationSlotOffset)
    debug "Producing attestations", delay = delay, slot = slot,
                                    committee_index = committee_index,
                                    duties_count = len(duties)
  let ad =
    try:
      await service.produceAndPublishAttestations(slot, committee_index, duties)
    except ValidatorApiError:
      error "Unable to proceed attestations", slot = slot,
            committee_index = committee_index, duties_count = len(duties)
      return
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
    let delay = vc.getDelay(aggregateSlotOffset)
    debug "Producing aggregate and proofs", delay = delay
  await service.produceAndPublishAggregates(ad, duties)

proc spawnAttestationTasks(service: AttestationServiceRef,
                           slot: Slot) =
  let vc = service.client
  let dutiesByCommittee =
    block:
      var res: Table[CommitteeIndex, seq[DutyAndProof]]
      let attesters = vc.getAttesterDutiesForSlot(slot)
      var default: seq[DutyAndProof]
      for item in attesters:
        res.mgetOrPut(item.data.committee_index, default).add(item)
      res
  for index, duties in dutiesByCommittee.pairs():
    if len(duties) > 0:
      asyncSpawn service.publishAttestationsAndAggregates(slot, index, duties)

proc mainLoop(service: AttestationServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  try:
    while true:
      let sleepTime = vc.beaconClock.durationToNextSlot() +
                        attestationSlotOffset
      let sres = vc.getCurrentSlot()
      if sres.isSome():
        let currentSlot = sres.get()
        service.spawnAttestationTasks(currentSlot)
      await sleepAsync(sleepTime)
  except CatchableError as exc:
    warn "Service crashed with unexpected error", err_name = exc.name,
         err_msg = exc.msg

proc init*(t: typedesc[AttestationServiceRef],
           vc: ValidatorClientRef): Future[AttestationServiceRef] {.async.} =
  debug "Initializing service"
  var res = AttestationServiceRef(client: vc, state: ServiceState.Initialized)
  return res

proc start*(service: AttestationServiceRef) =
  service.lifeFut = mainLoop(service)
