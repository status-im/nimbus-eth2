# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/sets,
  metrics, chronicles,
  ../spec/datatypes/[phase0, altair, bellatrix],
  ../spec/eth2_apis/rest_types,
  ../validators/activity_metrics,
  "."/[common, api, block_service]

const
  ServiceName = "sync_committee_service"

logScope: service = ServiceName

type
  ContributionItem* = object
    aggregator_index: uint64
    selection_proof: ValidatorSig
    validator: AttachedValidator
    subcommitteeIdx: SyncSubcommitteeIndex

proc serveSyncCommitteeMessage*(service: SyncCommitteeServiceRef,
                                slot: Slot, beaconBlockRoot: Eth2Digest,
                                duty: SyncCommitteeDuty): Future[bool] {.
     async.} =
  let
    vc = service.client
    fork = vc.forkAtEpoch(slot.epoch)
    genesisValidatorsRoot = vc.beaconGenesis.genesis_validators_root
    vindex = duty.validator_index
    subcommitteeIdx = getSubcommitteeIndex(
      duty.validator_sync_committee_index)
    validator = vc.getValidatorForDuties(
      duty.pubkey, slot, slashingSafe = true).valueOr: return false
    message =
      block:
        let res = await getSyncCommitteeMessage(validator, fork,
                                                genesisValidatorsRoot,
                                                slot, beaconBlockRoot)
        if res.isErr():
          warn "Unable to sign committee message using remote signer",
               validator = shortLog(validator), slot = slot,
               block_root = shortLog(beaconBlockRoot)
          return
        res.get()

  debug "Sending sync committee message", message = shortLog(message),
        validator = shortLog(validator), validator_index = vindex,
        delay = vc.getDelay(message.slot.sync_committee_message_deadline())

  let res =
    try:
      await vc.submitPoolSyncCommitteeSignature(message, ApiStrategyKind.First)
    except ValidatorApiError as exc:
      warn "Unable to publish sync committee message",
           message = shortLog(message),
           validator = shortLog(validator),
           validator_index = vindex,
           reason = exc.getFailureReason()
      return false
    except CancelledError:
      debug "Publish sync committee message request was interrupted"
      return false
    except CatchableError as exc:
      error "Unexpected error occurred while publishing sync committee message",
            message = shortLog(message),
            validator = shortLog(validator),
            validator_index = vindex,
            err_name = exc.name, err_msg = exc.msg
      return false

  let delay = vc.getDelay(message.slot.sync_committee_message_deadline())
  if res:
    beacon_sync_committee_messages_sent.inc()
    beacon_sync_committee_message_sent_delay.observe(delay.toFloatSeconds())
    notice "Sync committee message published",
           message = shortLog(message),
           validator = shortLog(validator),
           validator_index = vindex,
           delay = delay
  else:
    warn "Sync committee message was not accepted by beacon node",
         message = shortLog(message),
         validator = shortLog(validator),
         validator_index = vindex, delay = delay

  return res

proc produceAndPublishSyncCommitteeMessages(service: SyncCommitteeServiceRef,
                                            slot: Slot,
                                            beaconBlockRoot: Eth2Digest,
                                            duties: seq[SyncCommitteeDuty])
                                           {.async.} =
  let vc = service.client

  let pendingSyncCommitteeMessages =
    block:
      var res: seq[Future[bool]]
      for duty in duties:
        debug "Serving sync message duty", duty, epoch = slot.epoch()
        res.add(service.serveSyncCommitteeMessage(slot,
                                                  beaconBlockRoot,
                                                  duty))
      res

  let statistics =
    block:
      var errored, succeed, failed = 0
      try:
        await allFutures(pendingSyncCommitteeMessages)
      except CancelledError as exc:
        for fut in pendingSyncCommitteeMessages:
          if not(fut.finished()):
            fut.cancel()
        await allFutures(pendingSyncCommitteeMessages)
        raise exc

      for future in pendingSyncCommitteeMessages:
        if future.done():
          if future.read():
            inc(succeed)
          else:
            inc(failed)
        else:
          inc(errored)
      (succeed, errored, failed)

  let delay = vc.getDelay(slot.attestation_deadline())
  debug "Sync committee message statistics",
        total = len(pendingSyncCommitteeMessages),
        succeed = statistics[0], failed_to_deliver = statistics[1],
        not_accepted = statistics[2], delay = delay, slot = slot,
        duties_count = len(duties)

proc serveContributionAndProof*(service: SyncCommitteeServiceRef,
                                proof: ContributionAndProof,
                                validator: AttachedValidator): Future[bool] {.
     async.} =
  let
    vc = service.client
    slot = proof.contribution.slot
    validatorIdx = validator.index.get()
    genesisRoot = vc.beaconGenesis.genesis_validators_root
    fork = vc.forkAtEpoch(slot.epoch)

  let signature =
    block:
      let res = await validator.getContributionAndProofSignature(
        fork, genesisRoot, proof)
      if res.isErr():
        warn "Unable to sign sync committee contribution using remote signer",
             validator = shortLog(validator),
             contribution = shortLog(proof.contribution),
             error_msg = res.error()
        return false
      res.get()
  debug "Sending sync contribution",
        contribution = shortLog(proof.contribution),
        validator = shortLog(validator), validator_index = validatorIdx,
        delay = vc.getDelay(slot.sync_contribution_deadline())

  let restSignedProof = RestSignedContributionAndProof.init(
    proof, signature)

  let res =
    try:
      await vc.publishContributionAndProofs(@[restSignedProof],
                                            ApiStrategyKind.First)
    except ValidatorApiError as exc:
      warn "Unable to publish sync contribution",
           contribution = shortLog(proof.contribution),
           validator = shortLog(validator),
           validator_index = validatorIdx,
           err_msg = exc.msg,
           reason = exc.getFailureReason()
      false
    except CancelledError:
      debug "Publish sync contribution request was interrupted"
      return false
    except CatchableError as err:
      error "Unexpected error occurred while publishing sync contribution",
            contribution = shortLog(proof.contribution),
            validator = shortLog(validator),
            err_name = err.name, err_msg = err.msg
      false

  if res:
    beacon_sync_committee_contributions_sent.inc()
    notice "Sync contribution published",
           validator = shortLog(validator),
           validator_index = validatorIdx
  else:
    warn "Sync contribution was not accepted by beacon node",
         contribution = shortLog(proof.contribution),
         validator = shortLog(validator),
         validator_index = validatorIdx
  return res

proc produceAndPublishContributions(service: SyncCommitteeServiceRef,
                                    slot: Slot,
                                    beaconBlockRoot: Eth2Digest,
                                    duties: seq[SyncCommitteeDuty]) {.async.} =
  let
    vc = service.client
    epoch = slot.epoch
    fork = vc.forkAtEpoch(epoch)

  var slotSignatureReqs: seq[Future[SignatureResult]]
  var validators: seq[(AttachedValidator, SyncSubcommitteeIndex)]

  for duty in duties:
    let
      validator = vc.getValidatorForDuties(duty.pubkey, slot).valueOr:
        continue
      subCommitteeIdx =
        getSubcommitteeIndex(duty.validator_sync_committee_index)
      future = validator.getSyncCommitteeSelectionProof(
        fork,
        vc.beaconGenesis.genesis_validators_root,
        slot,
        subCommitteeIdx)

    slotSignatureReqs.add(future)
    validators.add((validator, subCommitteeIdx))

  try:
    await allFutures(slotSignatureReqs)
  except CancelledError as exc:
    var pendingCancel: seq[Future[void]]
    for future in slotSignatureReqs:
      if not(future.finished()):
        pendingCancel.add(future.cancelAndWait())
    await allFutures(pendingCancel)
    raise exc

  var
    contributionsFuts: array[SYNC_COMMITTEE_SUBNET_COUNT,
                             Future[SyncCommitteeContribution]]

  let validatorContributions = block:
    var res: seq[ContributionItem]
    for idx, fut in slotSignatureReqs:
      if fut.done:
        let
          sigRes = fut.read
          validator = validators[idx][0]
          subCommitteeIdx = validators[idx][1]
        if sigRes.isErr():
          warn "Unable to create slot signature using remote signer",
               validator = shortLog(validator),
               error_msg = sigRes.error()
        elif validator.index.isSome and
             is_sync_committee_aggregator(sigRes.get):
          res.add ContributionItem(
            aggregator_index: uint64(validator.index.get),
            selection_proof: sigRes.get,
            validator: validator,
            subcommitteeIdx: subCommitteeIdx)

          if isNil(contributionsFuts[subCommitteeIdx]):
            contributionsFuts[int subCommitteeIdx] =
              vc.produceSyncCommitteeContribution(
                slot,
                subCommitteeIdx,
                beaconBlockRoot,
                ApiStrategyKind.Best)
    res

  if len(validatorContributions) > 0:
    let pendingAggregates =
      block:
        var res: seq[Future[bool]]
        for item in validatorContributions:
          let aggContribution =
            try:
              await contributionsFuts[item.subcommitteeIdx]
            except ValidatorApiError as exc:
              warn "Unable to get sync message contribution data", slot = slot,
                   beaconBlockRoot = shortLog(beaconBlockRoot),
                   reason = exc.getFailureReason()
              return
            except CancelledError:
              debug "Request for sync message contribution was interrupted"
              return
            except CatchableError as exc:
              error "Unexpected error occurred while getting sync message "&
                    "contribution", slot = slot,
                    beaconBlockRoot = shortLog(beaconBlockRoot),
                    err_name = exc.name, err_msg = exc.msg
              return

          let proof = ContributionAndProof(
            aggregator_index: item.aggregator_index,
            contribution: aggContribution,
            selection_proof: item.selection_proof
          )
          res.add(service.serveContributionAndProof(proof, item.validator))
        res

    let statistics =
      block:
        var errored, succeed, failed = 0
        try:
          await allFutures(pendingAggregates)
        except CancelledError as err:
          for fut in pendingAggregates:
            if not(fut.finished()):
              fut.cancel()
          await allFutures(pendingAggregates)
          raise err

        for future in pendingAggregates:
          if future.done():
            if future.read():
              inc(succeed)
            else:
              inc(failed)
          else:
            inc(errored)
        (succeed, errored, failed)

    let delay = vc.getDelay(slot.aggregate_deadline())
    debug "Sync message contribution statistics",
          total = len(pendingAggregates),
          succeed = statistics[0], failed_to_deliver = statistics[1],
          not_accepted = statistics[2], delay = delay, slot = slot

  else:
    debug "No contribution and proofs scheduled for slot", slot = slot

proc publishSyncMessagesAndContributions(service: SyncCommitteeServiceRef,
                                         slot: Slot,
                                         duties: seq[SyncCommitteeDuty]) {.
     async.} =
  let vc = service.client

  await vc.waitForBlockPublished(slot, syncCommitteeMessageSlotOffset)

  block:
    let delay = vc.getDelay(slot.sync_committee_message_deadline())
    debug "Producing sync committee messages", delay = delay, slot = slot,
          duties_count = len(duties)

  let beaconBlockRoot =
    block:
      try:
        let res = await vc.getHeadBlockRoot(ApiStrategyKind.First)
        if res.execution_optimistic.isNone():
          ## The `execution_optimistic` is missing from the response, we assume
          ## that the BN is unaware optimistic sync, so we consider the BN
          ## to be synchronized with the network.
          ## TODO (cheatfate): This should be removed when VC will be able to
          ## handle getSpec() API call with fork constants.
          res.data.root
        else:
          if res.execution_optimistic.get():
            notice "Execution client not in sync; skipping validator duties " &
                   "for now", slot = slot
            return
          res.data.root
      except ValidatorApiError as exc:
        warn "Unable to retrieve head block's root to sign", reason = exc.msg,
             reason = exc.getFailureReason()
        return
      except CancelledError:
        debug "Block root request was interrupted"
        return
      except CatchableError as exc:
        error "Unexpected error while requesting sync message block root",
              err_name = exc.name, err_msg = exc.msg, slot = slot
        return

  try:
    await service.produceAndPublishSyncCommitteeMessages(slot,
                                                         beaconBlockRoot,
                                                         duties)
  except ValidatorApiError as exc:
    warn "Unable to proceed sync committee messages", slot = slot,
         duties_count = len(duties), reason = exc.getFailureReason()
    return
  except CancelledError:
    debug "Sync committee producing process was interrupted"
    return
  except CatchableError as exc:
    error "Unexpected error while producing sync committee messages",
          slot = slot,
          duties_count = len(duties),
          err_name = exc.name, err_msg = exc.msg
    return

  let contributionTime =
    # chronos.Duration subtraction cannot return a negative value; in such
    # case it will return `ZeroDuration`.
    vc.beaconClock.durationToNextSlot() - OneThirdDuration
  if contributionTime != ZeroDuration:
    await sleepAsync(contributionTime)

  block:
    let delay = vc.getDelay(slot.sync_contribution_deadline())
    debug "Producing contribution and proofs", delay = delay
  await service.produceAndPublishContributions(slot, beaconBlockRoot, duties)

proc spawnSyncCommitteeTasks(service: SyncCommitteeServiceRef, slot: Slot) =
  let
    vc = service.client
    duties = vc.getSyncCommitteeDutiesForSlot(slot + 1)

  asyncSpawn service.publishSyncMessagesAndContributions(slot, duties)

proc mainLoop(service: SyncCommitteeServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  debug "Sync committee duties loop waiting for fork schedule update"
  await vc.forksAvailable.wait()

  while true:
    # This loop could look much more nicer/better, when
    # https://github.com/nim-lang/Nim/issues/19911 will be fixed, so it could
    # become safe to combine loops, breaks and exception handlers.
    let breakLoop =
      try:
        let sleepTime =
          syncCommitteeMessageSlotOffset + vc.beaconClock.durationToNextSlot()

        let sres = vc.getCurrentSlot()
        if sres.isSome():
          let currentSlot = sres.get()
          service.spawnSyncCommitteeTasks(currentSlot)
        await sleepAsync(sleepTime)
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

proc init*(t: typedesc[SyncCommitteeServiceRef],
           vc: ValidatorClientRef): Future[SyncCommitteeServiceRef] {.async.} =
  logScope: service = ServiceName
  let res = SyncCommitteeServiceRef(name: ServiceName, client: vc,
                                    state: ServiceState.Initialized)
  debug "Initializing service"
  return res

proc start*(service: SyncCommitteeServiceRef) =
  service.lifeFut = mainLoop(service)
