# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

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
    consensusFork = vc.getConsensusFork(fork)
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
    delay = vc.getDelay(attestationSlot.attestation_deadline(
      vc.timeParams, consensusFork))

  debug "Sending attestation"

  validator.doppelgangerActivity(attestationSlot.epoch)

  template submitAttestation(atst: untyped): untyped =
    logScope:
      fork = consensusFork
      attestation = shortLog(atst)
    try:
      await vc.submitPoolAttestationsV2(
        @[atst], consensusFork,
        vc.getMode()[FnKind.submitPoolAttestations])
    except ValidatorApiError as exc:
      warn "Unable to publish attestation", reason = exc.getFailureReason()
      return false
    except CancelledError as exc:
      debug "Attestation publishing process was interrupted"
      raise exc

  let res =
    if afterElectra:
      let attestation = registered.toSingleAttestation(signature)
      submitAttestation(attestation)
    else:
      let attestation = registered.toAttestation(signature)
      submitAttestation(attestation)

  if res:
    let delay = vc.getDelay(attestationSlot.attestation_deadline(
      vc.timeParams, consensusFork))
    beacon_attestations_sent.inc()
    beacon_attestation_sent_delay.observe(delay.toFloatSeconds())
    notice "Attestation published"
  else:
    warn "Attestation was not accepted by beacon node"

  res

proc serveAttestations(
    service: AttestationServiceRef,
    slot: Slot,
    fork: Fork,
    registered: seq[RegisteredAttestation]
): Future[tuple[total, succeed, failed: int]] {.
  async: (raises: [CancelledError]).} =
  let
    vc = service.client
    consensusFork = vc.getConsensusFork(fork)

  let signed =
    block:
      var res: seq[electra.SingleAttestation]
      let pending =
        registered.mapIt(
          getAttestationSignature(
            it.validator, fork, vc.beaconGenesis.genesis_validators_root,
            it.data))
      try:
        await allFutures(pending)

        for index, future in pending.pairs():
          # We just created this future in previous step, and we are not
          # going to cancel it, so after allFutures() - all futures MUST be
          # finished.
          let sres = future.value
          if sres.isErr():
            warn "Unable to sign attestation",
              reason = sres.error(),
              validator = shortLog(registered[index].validator),
              attestation = shortLog(registered[index].data)
          else:
            res.add(registered[index].toSingleAttestation(sres.get()))

        res
      except CancelledError as exc:
        debug "Attestation signature process was interrupted"
        await cancelAndWait(pending)
        raise exc

  logScope:
    delay = vc.getDelay(slot.attestation_deadline(vc.timeParams, consensusFork))

  debug "Sending attestations", count = len(signed)

  for it in registered:
    doppelgangerActivity(it.validator, slot.epoch)

  logScope:
    fork = consensusFork

  let res =
    try:
      await vc.submitPoolAttestations2Ssz(
        signed, consensusFork, vc.getMode()[FnKind.submitPoolAttestations])
    except ValidatorApiError as exc:
      warn "Unable to publish attestations",
        reason = exc.getFailureReason()
      return (len(registered), 0, len(registered))
    except CancelledError as exc:
      debug "Attestation publishing process was interrupted"
      raise exc

  if res:
    (len(registered), len(signed), len(registered) - len(signed))
  else:
    (len(registered), 0, len(registered))

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
    consensusFork = vc.getConsensusFork(fork)

  logScope:
    validator = validatorLog(validator)
    attestation = shortLog(proof.aggregate)

  debug "Signing aggregate", fork = consensusFork

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
    delay = vc.getDelay(slot.aggregate_deadline(vc.timeParams, consensusFork))

  debug "Sending aggregated attestation", fork = consensusFork

  validator.doppelgangerActivity(proof.aggregate.data.slot.epoch)

  let res =
    try:
      await vc.publishAggregateAndProofsV2(
        @[signedProof], consensusFork,
        vc.getMode()[FnKind.publishAggregateAndProofs])
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
    data = await vc.produceAttestationData(
      slot,
      CommitteeIndex(0),
      vc.getMode()[FnKind.produceAttestationData])
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
            validator_index: validator_index,
            committee_index: duty.data.committee_index,
            index_in_committee: duty.data.validator_committee_index,
            committee_len: int(duty.data.committee_length),
            data: data
          ))
        tmp

  if registeredRes.isErr():
    warn "Could not update slashing database, skipping attestation duties",
         reason = registeredRes.error()
    return

  let statistics =
    if vc.config.batchAttestations:
      await service.serveAttestations(slot, fork, registeredRes[])
    else:
      let
        pending = registeredRes[].mapIt(service.serveAttestation(it))
        statistics =
          block:
            var succeed, failed, total = 0
            try:
              await allFutures(pending)
            except CancelledError as exc:
              await cancelAndWait(pending)
              raise exc

            for future in pending:
              if future.completed():
                if future.value:
                  inc(succeed)
                else:
                  inc(failed)
              else:
                inc(failed)
              inc(total)
            (total, succeed, failed)
      statistics

  let
    consensusFork = vc.getConsensusFork(fork)
    delay = vc.getDelay(slot.attestation_deadline(
      vc.timeParams, consensusFork))

  debug "Attestation statistics", total = statistics[0],
    succeed = statistics[1], failed = statistics[2],
    delay = delay, slot = slot, duties_count = len(duties)
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
              committee_index: duty.data.committee_index,
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
          await vc.getAggregatedAttestationV2(
            slot, attestationRoot,
            committee_index,
            vc.getMode()[FnKind.getAggregatedAttestation])
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

  let
    consensusFork = vc.getConsensusFork(vc.forkAtEpoch(slot.epoch))
    delay = vc.getDelay(
      slot.aggregate_deadline(vc.timeParams, consensusFork))
  debug "Aggregated attestation statistics", total = len(aggregates),
        succeed = statistics[0], failed_to_deliver = statistics[1],
        not_accepted = statistics[2], delay = delay, slot = slot,
        committee_index = committee_index

proc publishAttestationsAndAggregatesV2(
    service: AttestationServiceRef,
    slot: Slot,
    duties: seq[DutyAndProof]
) {.async: (raises: [CancelledError]).} =
  let
    vc = service.client

  block:
    let
      consensusFork = vc.getConsensusFork(vc.forkAtEpoch(slot.epoch))
      delay = vc.getDelay(slot.attestation_deadline(
        vc.timeParams, consensusFork))
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

  let
    consensusFork = vc.getConsensusFork(vc.forkAtEpoch(slot.epoch))
    aggregateTime = vc.beaconClock.fromNow(
      slot.aggregate_deadline(vc.timeParams, consensusFork))
  if aggregateTime.inFuture:
    await sleepAsync(aggregateTime.offset)

  block:
    let
      delay = vc.getDelay(
        slot.aggregate_deadline(vc.timeParams, consensusFork))
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

proc spawnAttestationTasksV2(
    service: AttestationServiceRef,
    slot: Slot
) {.async: (raises: [CancelledError]).} =
  let
    vc = service.client
    duties = vc.getAttesterDutiesForSlot(slot)

  # Waiting for blocks to be published before attesting.
  await vc.waitForBlock(slot, vc.timeParams.attestationSlotOffset)

  try:
    let timeout = vc.beaconClock.fromNow(slot + 1).durationOrZero()
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
        # waitForBlock(vc.timeParams.attestationSlotOffset).
        slot = await vc.checkedWaitForNextSlot(currentSlot,
                                               ZeroTimeDiff, false)
      if slot.isNone():
        debug "System time adjusted backwards significantly, exiting"
        return

      currentSlot = slot
      await service.spawnAttestationTasksV2(currentSlot.get())
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
