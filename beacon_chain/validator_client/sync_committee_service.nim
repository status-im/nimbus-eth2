# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
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
  "."/[common, api, selection_proofs]

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
        let pending = pendingSyncCommitteeMessages
          .filterIt(not(it.finished())).mapIt(it.cancelAndWait())
        await noCancel allFutures(pending)
        raise exc

      for future in pendingSyncCommitteeMessages:
        if future.completed():
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
  let vc = service.client

  var (contributions, pendingFutures, contributionsMap) =
    block:
      var
        resItems: seq[ContributionItem]
        resFutures: seq[FutureBase]
        resMap: array[SYNC_COMMITTEE_SUBNET_COUNT,
                      Future[SyncCommitteeContribution]]
      for duty in duties:
        let validator = vc.getValidatorForDuties(duty.pubkey, slot).valueOr:
          continue
        if validator.index.isNone():
          continue
        for inindex in duty.validator_sync_committee_indices:
          let
            subCommitteeIdx = getSubcommitteeIndex(inindex)
            signature =
              vc.getSyncCommitteeSelectionProof(duty.pubkey,
                                                slot, inindex).valueOr:
                continue

          if is_sync_committee_aggregator(signature):
            resItems.add(ContributionItem(
              aggregator_index: uint64(validator.index.get()),
              selection_proof: signature,
              validator: validator,
              subcommitteeIdx: subCommitteeIdx
            ))
            if isNil(resMap[subCommitteeIdx]):
              let future =
                vc.produceSyncCommitteeContribution(
                  slot, subCommitteeIdx, beaconBlockRoot, ApiStrategyKind.Best)
              resMap[int(subCommitteeIdx)] = future
              resFutures.add(FutureBase(future))
      (resItems, resFutures, resMap)

  if len(contributions) > 0:
    let
      pendingAggregates =
        block:
          var res: seq[Future[bool]]
          while len(pendingFutures) > 0:
            try:
              discard await race(pendingFutures)
            except CancelledError as exc:
              let pending = pendingFutures
                .filterIt(not(it.finished())).mapIt(it.cancelAndWait())
              await noCancel allFutures(pending)
              raise exc

            var completed: seq[int]
            for contrib in contributions:
              let future = contributionsMap[contrib.subcommitteeIdx]
              doAssert(not(isNil(future)))
              let index = pendingFutures.find(FutureBase(future))
              if future.finished() and (index >= 0):
                if index notin completed: completed.add(index)
                let aggContribution =
                  try:
                    let res = future.read()
                    Opt.some(res)
                  except ValidatorApiError as exc:
                    warn "Unable to get sync message contribution data",
                         slot = slot,
                         beacon_block_root = shortLog(beaconBlockRoot),
                         reason = exc.getFailureReason()
                    Opt.none(SyncCommitteeContribution)
                  except CancelledError as exc:
                    debug "Request for sync message contribution was " &
                          "interrupted"
                    raise exc
                  except CatchableError as exc:
                    error "Unexpected error occurred while getting sync " &
                          "message contribution", slot = slot,
                      beacon_block_root = shortLog(beaconBlockRoot),
                      err_name = exc.name, err_msg = exc.msg
                    Opt.none(SyncCommitteeContribution)

                if aggContribution.isSome():
                  let proof = ContributionAndProof(
                    aggregator_index: contrib.aggregator_index,
                    contribution: aggContribution.get(),
                    selection_proof: contrib.selection_proof
                  )
                  res.add(
                    service.serveContributionAndProof(proof, contrib.validator))

            pendingFutures =
              block:
                var res: seq[FutureBase]
                for index, value in pendingFutures.pairs():
                  if index notin completed: res.add(value)
                res
          res
      statistics =
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
    debug "Sync message contribution statistics",
          total = len(contributions),
          succeed = statistics[0],
          failed_to_create = len(pendingAggregates) - len(contributions),
          failed_to_deliver = statistics[1],
          not_accepted = statistics[2],
          delay = delay, slot = slot

  else:
    debug "No contribution and proofs scheduled for the slot", slot = slot

proc publishSyncMessagesAndContributions(service: SyncCommitteeServiceRef,
                                         slot: Slot,
                                         duties: seq[SyncCommitteeDuty]) {.
     async.} =
  let vc = service.client

  await vc.waitForBlock(slot, syncCommitteeMessageSlotOffset)

  block:
    let delay = vc.getDelay(slot.sync_committee_message_deadline())
    debug "Producing sync committee messages", delay = delay, slot = slot,
          duties_count = len(duties)

  let beaconBlockRoot =
    block:
      try:
        let res = await vc.getHeadBlockRoot(ApiStrategyKind.Best)
        if res.execution_optimistic.isNone():
          ## The `execution_optimistic` is missing from the response, we assume
          ## that the BN is unaware optimistic sync, so we consider the BN
          ## to be synchronized with the network.
          ## TODO (cheatfate): This should be removed when VC will be able to
          ## handle getSpec() API call with fork constants.
          res.data.root
        else:
          if res.execution_optimistic.get():
            notice "Execution client not in sync", slot = slot
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

proc processSyncCommitteeTasks(service: SyncCommitteeServiceRef,
                               slot: Slot) {.async.} =
  let
    vc = service.client
    duties = vc.getSyncCommitteeDutiesForSlot(slot + 1)
    timeout = vc.beaconClock.durationToNextSlot()

  try:
    await service.publishSyncMessagesAndContributions(slot,
                                                      duties).wait(timeout)
  except AsyncTimeoutError:
    warn "Unable to publish sync committee messages and contributions in time",
         slot = slot, timeout = timeout
  except CancelledError as exc:
    debug "Sync committee publish task has been interrupted"
    raise exc
  except CatchableError as exc:
    error "Unexpected error encountered while processing sync committee tasks",
          error_name = exc.name, error_message = exc.msg

proc mainLoop(service: SyncCommitteeServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  debug "Sync committee processing loop is waiting for initialization"
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
          # waitForBlock(syncCommitteeMessageSlotOffset).
          slot = await vc.checkedWaitForNextSlot(currentSlot, ZeroTimeDiff,
                                                 false)
        if slot.isNone():
          debug "System time adjusted backwards significantly, exiting"
          true
        else:
          currentSlot = slot
          await service.processSyncCommitteeTasks(currentSlot.get())
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
