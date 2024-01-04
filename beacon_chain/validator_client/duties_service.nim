# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[sets, sequtils]
import chronicles, metrics
import common, api, block_service, selection_proofs

const
  ServiceName = "duties_service"
  SUBSCRIPTION_LOOKAHEAD_EPOCHS* = 4'u64
  AGGREGATION_PRE_COMPUTE_EPOCHS* = 1'u64

logScope: service = ServiceName

type
  DutiesServiceLoop* = enum
    AttesterLoop, ProposerLoop, IndicesLoop, SyncCommitteeLoop,
    ProposerPreparationLoop, ValidatorRegisterLoop, DynamicValidatorsLoop,
    SlashPruningLoop

chronicles.formatIt(DutiesServiceLoop):
  case it
  of AttesterLoop: "attester_loop"
  of ProposerLoop: "proposer_loop"
  of IndicesLoop: "index_loop"
  of SyncCommitteeLoop: "sync_committee_loop"
  of ProposerPreparationLoop: "proposer_prepare_loop"
  of ValidatorRegisterLoop: "validator_register_loop"
  of DynamicValidatorsLoop: "dynamic_validators_loop"
  of SlashPruningLoop: "slashing_pruning_loop"

proc checkDuty(duty: RestAttesterDuty): bool =
  (duty.committee_length <= MAX_VALIDATORS_PER_COMMITTEE) and
  (uint64(duty.committee_index) < MAX_COMMITTEES_PER_SLOT) and
  (uint64(duty.validator_committee_index) < duty.committee_length) and
  (uint64(duty.validator_index) <= VALIDATOR_REGISTRY_LIMIT)

proc checkSyncDuty(duty: RestSyncCommitteeDuty): bool =
  uint64(duty.validator_index) <= VALIDATOR_REGISTRY_LIMIT

proc pollForValidatorIndices*(service: DutiesServiceRef) {.async.} =
  let vc = service.client

  let validatorIdents =
    block:
      var res: seq[ValidatorIdent]
      for validator in vc.attachedValidators[].items():
        if validator.needsUpdate():
          res.add(ValidatorIdent.init(validator.pubkey))
      res

  let start = Moment.now()

  var validators: seq[RestValidator]

  for idents in chunks(validatorIdents, ClientMaximumValidatorIds):
    let res =
      try:
        await vc.getValidators(idents, ApiStrategyKind.First)
      except ValidatorApiError as exc:
        warn "Unable to get head state's validator information",
              reason = exc.getFailureReason()
        return
      except CancelledError as exc:
        debug "Validator's indices processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "Unexpected error occurred while getting validator information",
              err_name = exc.name, err_msg = exc.msg
        return
    for item in res:
      validators.add(item)

  var
    missing: seq[string]
    updated: seq[string]
    list: seq[AttachedValidator]

  for item in validators:
    let validator = vc.attachedValidators[].getValidator(item.validator.pubkey)
    if validator.isNone():
      missing.add(validatorLog(item.validator.pubkey, item.index))
    else:
      validator.get().updateValidator(Opt.some ValidatorAndIndex(
        index: item.index,
        validator: item.validator))
      updated.add(validatorLog(item.validator.pubkey, item.index))
      list.add(validator.get())

  if len(updated) > 0:
    info "Validator indices updated",
      pending = len(validatorIdents) - len(updated),
      missing = len(missing),
      updated = len(updated),
      elapsed_time = (Moment.now() - start)
    trace "Validator indices update dump", missing_validators = missing,
          updated_validators = updated
    vc.indicesAvailable.fire()

proc pollForAttesterDuties*(service: DutiesServiceRef,
                            epoch: Epoch): Future[int] {.async.} =
  var currentRoot: Opt[Eth2Digest]
  let
    vc = service.client
    indices = toSeq(vc.attachedValidators[].indices())
    relevantDuties =
      block:
        var duties: seq[RestAttesterDuty]
        block mainLoop:
          while true:
            block innerLoop:
              for chunk in indices.chunks(DutiesMaximumValidatorIds):
                let res =
                  try:
                    await vc.getAttesterDuties(epoch, chunk,
                                               ApiStrategyKind.First)
                  except ValidatorApiError as exc:
                    warn "Unable to get attester duties", epoch = epoch,
                         reason = exc.getFailureReason()
                    return 0
                  except CancelledError as exc:
                    debug "Attester duties processing was interrupted"
                    raise exc
                  except CatchableError as exc:
                    error "Unexpected error while getting attester duties",
                          epoch = epoch, err_name = exc.name, err_msg = exc.msg
                    return 0
                if currentRoot.isNone():
                  # First request
                  currentRoot = Opt.some(res.dependent_root)
                else:
                  if currentRoot.get() != res.dependent_root:
                    # `dependent_root` must be equal for all requests/response,
                    # if it got changed it means that some reorg was happened in
                    # beacon node and we should re-request all queries again.
                    duties.setLen(0)
                    currentRoot = Opt.none(Eth2Digest)
                    break innerLoop

                for duty in res.data:
                  if checkDuty(duty) and
                     (duty.pubkey in vc.attachedValidators[]):
                    duties.add(duty)
                break mainLoop
        duties

  template checkReorg(a, b: untyped): bool =
    not(a.dependentRoot == b.get())

  let addOrReplaceItems =
    block:
      var alreadyWarned = false
      var res: seq[tuple[epoch: Epoch, duty: RestAttesterDuty]]
      for duty in relevantDuties:
        var dutyFound = false
        vc.attesters.withValue(duty.pubkey, map):
          map[].duties.withValue(epoch, epochDuty):
            dutyFound = true
            if checkReorg(epochDuty[], currentRoot):
              if not(alreadyWarned):
                info "Attester duties re-organization",
                     prior_dependent_root = epochDuty[].dependentRoot,
                     dependent_root = currentRoot.get()
                alreadyWarned = true
              res.add((epoch, duty))
        if not(dutyFound):
          info "Received new attester duty", duty, epoch = epoch,
               dependent_root = currentRoot.get()
          res.add((epoch, duty))
      res

  for item in addOrReplaceItems:
    let dap = DutyAndProof.init(item.epoch, currentRoot.get(), item.duty,
                                Opt.none(ValidatorSig))
    vc.attesters.mgetOrPut(dap.data.pubkey,
                           default(EpochDuties)).duties[dap.epoch] = dap
  return len(addOrReplaceItems)

proc pruneSyncCommitteeDuties*(service: DutiesServiceRef, slot: Slot) =
  let vc = service.client
  if slot.is_sync_committee_period():
    var newSyncCommitteeDuties: SyncCommitteeDutiesMap
    let period = slot.sync_committee_period()
    for key, item in vc.syncCommitteeDuties:
      var currentPeriodDuties = SyncPeriodDuties()
      for periodKey, periodDuty in item.duties:
        if periodKey >= period:
          currentPeriodDuties.duties[periodKey] = periodDuty
      newSyncCommitteeDuties[key] = currentPeriodDuties
    vc.syncCommitteeDuties = newSyncCommitteeDuties

proc pruneSyncCommitteeSelectionProofs*(service: DutiesServiceRef, slot: Slot) =
  let
    vc = service.client
    slotEpoch = slot.epoch()
  var res: seq[Epoch]
  for epoch in vc.syncCommitteeProofs.keys():
    if epoch < slotEpoch: res.add(epoch)
  for epoch in res:
    vc.syncCommitteeProofs.del(epoch)

proc pollForSyncCommitteeDuties*(
       service: DutiesServiceRef,
       period: SyncCommitteePeriod
     ): Future[int] {.async.} =
  let
    vc = service.client
    indices = toSeq(vc.attachedValidators[].indices())
    epoch = max(period.start_epoch(), vc.runtimeConfig.altairEpoch.get())
    relevantDuties =
      block:
        var duties: seq[RestSyncCommitteeDuty]
        # We use `DutiesMaximumValidatorIds` here because validator ids are sent
        # in HTTP request body and NOT in HTTP request headers.
        for chunk in indices.chunks(DutiesMaximumValidatorIds):
          let res =
            try:
              await vc.getSyncCommitteeDuties(epoch, chunk,
                                              ApiStrategyKind.First)
            except ValidatorApiError as exc:
              warn "Unable to get sync committee duties",
                   period = period, epoch = epoch,
                   reason = exc.getFailureReason()
              return 0
            except CancelledError as exc:
              debug "Sync committee duties processing was interrupted",
                    period = period, epoch = epoch
              raise exc
            except CatchableError as exc:
              error "Unexpected error while getting sync committee duties",
                    period = period, epoch = epoch,
                    err_name = exc.name, err_msg = exc.msg
              return 0

          for duty in res.data:
            if checkSyncDuty(duty) and (duty.pubkey in vc.attachedValidators[]):
              duties.add(duty)

        duties

  template checkReorg(a, b: untyped): bool =
    not(compareUnsorted(a.validator_sync_committee_indices,
                        b.validator_sync_committee_indices))

  let addOrReplaceItems =
    block:
      var
        alreadyWarned = false
        res: seq[tuple[period: SyncCommitteePeriod,
                       duty: RestSyncCommitteeDuty]]
      for duty in relevantDuties:
        var dutyFound = false
        vc.syncCommitteeDuties.withValue(duty.pubkey, map):
          map[].duties.withValue(period, periodDuty):
            dutyFound = true
            if checkReorg(periodDuty[], duty):
              if not(alreadyWarned):
                info "Sync committee duties re-organization"
                alreadyWarned = true
              res.add((period, duty))
        if not(dutyFound):
          res.add((period, duty))
          info "Received new sync committee duty", duty, period
      res

  for item in addOrReplaceItems:
    vc.syncCommitteeDuties.mgetOrPut(item.duty.pubkey,
                           default(SyncPeriodDuties)).duties[item.period] =
                             item.duty
  len(addOrReplaceItems)

proc pruneAttesterDuties(service: DutiesServiceRef, epoch: Epoch) =
  let vc = service.client
  var attesters: AttesterMap
  for key, item in vc.attesters:
    var v = EpochDuties()
    for epochKey, epochDuty in item.duties:
      if (epochKey + HISTORICAL_DUTIES_EPOCHS) >= epoch:
        v.duties[epochKey] = epochDuty
      else:
        debug "Attester duties for the epoch has been pruned", validator = key,
              epoch = epochKey, loop = AttesterLoop
    attesters[key] = v
  vc.attesters = attesters

proc pollForAttesterDuties*(service: DutiesServiceRef) {.async.} =
  ## Query the beacon node for attestation duties for all known validators.
  ##
  ## This function will perform (in the following order):
  ##
  ## 1. Poll for current-epoch duties and update the local `attesters` map.
  ## 2. Poll for next-epoch duties and update the local `attesters` map.
  ## 3. Push out any attestation subnet subscriptions to the BN.
  let vc = service.client
  let
    currentSlot = vc.getCurrentSlot().get(Slot(0))
    currentEpoch = currentSlot.epoch()
    nextEpoch = currentEpoch + 1'u64

  if vc.attachedValidators[].count() != 0:
    var counts: array[2, tuple[epoch: Epoch, count: int]]
    counts[0] = (currentEpoch,
                 await service.pollForAttesterDuties(currentEpoch))
    counts[1] = (nextEpoch,
                 await service.pollForAttesterDuties(nextEpoch))

    if (counts[0].count == 0) and (counts[1].count == 0):
      debug "No new attester's duties received", slot = currentSlot

    block:
      let
        moment = Moment.now()
        sigres =
          await vc.fillAttestationSelectionProofs(currentSlot,
            currentSlot + Epoch(AGGREGATION_PRE_COMPUTE_EPOCHS))

      if vc.config.distributedEnabled:
        debug "Attestation selection proofs have been received",
              signatures_requested = sigres.signaturesRequested,
              signatures_received = sigres.signaturesReceived,
              selections_requested = sigres.selectionsRequested,
              selections_received = sigres.selectionsReceived,
              selections_processed = sigres.selectionsProcessed,
              total_elapsed_time = (Moment.now() - moment)
      else:
        debug "Attestation selection proofs have been received",
              signatures_requested = sigres.signaturesRequested,
              signatures_received = sigres.signaturesReceived,
              total_elapsed_time = (Moment.now() - moment)

    let subscriptions =
      block:
        var res: seq[RestCommitteeSubscription]
        for item in counts:
          if item.count > 0:
            for duty in vc.attesterDutiesForEpoch(item.epoch):
              if currentSlot + SUBSCRIPTION_BUFFER_SLOTS < duty.data.slot:
                let isAggregator =
                  if duty.slotSig.isSome():
                    is_aggregator(duty.data.committee_length,
                                  duty.slotSig.get())
                  else:
                    false
                let sub = RestCommitteeSubscription(
                  validator_index: duty.data.validator_index,
                  committee_index: duty.data.committee_index,
                  committees_at_slot: duty.data.committees_at_slot,
                  slot: duty.data.slot,
                  is_aggregator: isAggregator
                )
                res.add(sub)
        res

    if len(subscriptions) > 0:
      let res = await vc.prepareBeaconCommitteeSubnet(subscriptions)
      if res == 0:
        warn "Failed to subscribe validators to beacon committee subnets",
             slot = currentSlot, epoch = currentEpoch,
             subscriptions_count = len(subscriptions)

  service.pruneAttesterDuties(currentEpoch)

proc pollForSyncCommitteeDuties*(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  let
    currentSlot = vc.getCurrentSlot().get(Slot(0))
    currentEpoch = currentSlot.epoch()
    altairEpoch = vc.runtimeConfig.altairEpoch.valueOr:
      return

  if currentEpoch < altairEpoch:
    # We are not going to poll for sync committee duties until `altairEpoch`.
    return

  let
    currentPeriod = currentEpoch.sync_committee_period()
    nextPeriod = currentPeriod + 1

  if vc.attachedValidators[].count() != 0:
    var counts: array[2, tuple[period: SyncCommitteePeriod, count: int]]
    counts[0] = (currentPeriod,
                 await service.pollForSyncCommitteeDuties(currentPeriod))

    const
      numDelayEpochs = 4  # Chosen empirically
      numLookaheadEpochs =
        max(EPOCHS_PER_SYNC_COMMITTEE_PERIOD, numDelayEpochs) -
        numDelayEpochs + 1
    if (currentEpoch + numLookaheadEpochs) >= nextPeriod.start_epoch:
      counts[1] = (nextPeriod,
                   await service.pollForSyncCommitteeDuties(nextPeriod))
    else:
      # Skip fetching `nextPeriod` until sync committees are likely known,
      # as determined by `numDelayEpochs` from sync committee period start.
      counts[1] = (nextPeriod, 0)

    if (counts[0].count == 0) and (counts[1].count == 0):
      debug "No new sync committee duties received", slot = currentSlot

    block:
      let
        moment = Moment.now()
        sigres =
          await vc.fillSyncCommitteeSelectionProofs(currentSlot,
            currentSlot + Epoch(AGGREGATION_PRE_COMPUTE_EPOCHS))

      if vc.config.distributedEnabled:
        debug "Sync committee selection proofs have been received",
              signatures_requested = sigres.signaturesRequested,
              signatures_received = sigres.signaturesReceived,
              selections_requested = sigres.selectionsRequested,
              selections_received = sigres.selectionsReceived,
              selections_processed = sigres.selectionsProcessed,
              total_elapsed_time = (Moment.now() - moment)
      else:
        debug "Sync committee selection proofs have been received",
              signatures_requested = sigres.signaturesRequested,
              signatures_received = sigres.signaturesReceived,
              total_elapsed_time = (Moment.now() - moment)

    let
      periods =
        block:
          var res: seq[tuple[slot: Slot, period: SyncCommitteePeriod]]
          if service.syncSubscriptionEpoch.get(FAR_FUTURE_EPOCH) !=
             currentEpoch:
            res.add((currentSlot, currentPeriod))
          let
            lookaheadSlot = currentSlot +
                            SUBSCRIPTION_LOOKAHEAD_EPOCHS * SLOTS_PER_EPOCH
            lookaheadPeriod = lookaheadSlot.sync_committee_period()
          if lookaheadPeriod > currentPeriod:
            res.add((lookaheadSlot, lookaheadPeriod))
          res
      subscriptions =
        block:
          var res: seq[RestSyncCommitteeSubscription]
          for item in periods:
            let
              untilEpoch = start_epoch(item.period + 1)
              subscriptionsInfo =
                vc.syncMembersSubscriptionInfoForPeriod(item.period)
            for info in subscriptionsInfo:
              let sub = RestSyncCommitteeSubscription(
                validator_index: info.validator_index,
                sync_committee_indices:
                  info.validator_sync_committee_indices,
                until_epoch: untilEpoch
              )
              res.add(sub)
          res
    if len(subscriptions) > 0:
      let res = await vc.prepareSyncCommitteeSubnets(subscriptions)
      if res == 0:
        warn "Failed to subscribe validators to sync committee subnets",
             slot = currentSlot, epoch = currentPeriod, period = currentPeriod,
             periods = periods, subscriptions_count = len(subscriptions)
      else:
        service.syncSubscriptionEpoch = Opt.some(currentEpoch)

  service.pruneSyncCommitteeDuties(currentSlot)
  service.pruneSyncCommitteeSelectionProofs(currentSlot)

proc pruneBeaconProposers(service: DutiesServiceRef, epoch: Epoch) =
  let vc = service.client

  var proposers: ProposerMap
  for epochKey, data in vc.proposers:
    if (epochKey + HISTORICAL_DUTIES_EPOCHS) >= epoch:
      proposers[epochKey] = data
    else:
      debug "Proposer duty has been pruned", epoch = epochKey,
            loop = ProposerLoop
  vc.proposers = proposers

proc pollForBeaconProposers*(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  let
    currentSlot = vc.getCurrentSlot().get(Slot(0))
    currentEpoch = currentSlot.epoch()

  if vc.attachedValidators[].count() != 0:
    try:
      let res = await vc.getProposerDuties(currentEpoch,
                                           ApiStrategyKind.First)
      let
        dependentRoot = res.dependent_root
        duties = res.data
        relevantDuties = duties.filterIt(it.pubkey in vc.attachedValidators[])

      if len(relevantDuties) > 0:
        vc.addOrReplaceProposers(currentEpoch, dependentRoot, relevantDuties)
      else:
        debug "No relevant proposer duties received", slot = currentSlot,
              duties_count = len(duties)
    except ValidatorApiError as exc:
      notice "Unable to get proposer duties", slot = currentSlot,
             epoch = currentEpoch, reason = exc.getFailureReason()
    except CancelledError as exc:
      debug "Proposer duties processing was interrupted"
      raise exc
    except CatchableError as exc:
      debug "Unexpected error occured while getting proposer duties",
            slot = currentSlot, epoch = currentEpoch, err_name = exc.name,
            err_msg = exc.msg

    service.pruneBeaconProposers(currentEpoch)
    vc.pruneBlocksSeen(currentEpoch)

proc prepareBeaconProposers*(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  let
    currentSlot = vc.getCurrentSlot().get(Slot(0))
    currentEpoch = currentSlot.epoch()
    proposers = vc.prepareProposersList(currentEpoch)

  if len(proposers) > 0:
    let count =
      try:
        await prepareBeaconProposer(vc, proposers)
      except ValidatorApiError as exc:
        warn "Unable to prepare beacon proposers", slot = currentSlot,
              epoch = currentEpoch, err_name = exc.name,
              err_msg = exc.msg, reason = exc.getFailureReason()
        0
      except CancelledError as exc:
        debug "Beacon proposer preparation processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "Unexpected error occured while preparing beacon proposers",
              slot = currentSlot, epoch = currentEpoch, err_name = exc.name,
              err_msg = exc.msg
        0
    debug "Beacon proposers prepared",
          validators_count = vc.attachedValidators[].count(),
          proposers_count = len(proposers),
          prepared_count = count

proc registerValidators*(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  let
    currentSlot = vc.getCurrentSlot().get(Slot(0))
    genesisFork = vc.forks[0]
    registrations =
      try:
        await vc.prepareRegistrationList(getTime(), genesisFork)
      except CancelledError as exc:
        debug "Validator registration preparation was interrupted",
              slot = currentSlot, fork = genesisFork
        raise exc
      except CatchableError as exc:
        var default: seq[SignedValidatorRegistrationV1]
        error "Unexpected error occured while preparing validators " &
              "registration data", slot = currentSlot, fork = genesisFork,
              err_name = exc.name, err_msg = exc.msg
        default

    count =
      if len(registrations) > 0:
        try:
          await registerValidator(vc, registrations)
        except ValidatorApiError as exc:
          warn "Unable to register validators", slot = currentSlot,
                fork = genesisFork, err_name = exc.name,
                err_msg = exc.msg, reason = exc.getFailureReason()
          0
        except CancelledError as exc:
          debug "Validator registration was interrupted", slot = currentSlot,
                fork = genesisFork
          raise exc
        except CatchableError as exc:
          error "Unexpected error occured while registering validators",
                slot = currentSlot, fork = genesisFork, err_name = exc.name,
                err_msg = exc.msg
          0
      else:
        0

  if count > 0:
    debug "Validators registered", slot = currentSlot,
          beacon_nodes_count = count, registrations = len(registrations),
          validators_count = vc.attachedValidators[].count()

proc attesterDutiesLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  debug "Attester duties loop is waiting for initialization"
  await allFutures(
    vc.preGenesisEvent.wait(),
    vc.indicesAvailable.wait(),
    vc.forksAvailable.wait()
  )
  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")
  while true:
    await service.waitForNextSlot()
    # Cleaning up previous attestation duties task.
    if not(isNil(service.pollingAttesterDutiesTask)) and
       not(service.pollingAttesterDutiesTask.finished()):
      await cancelAndWait(service.pollingAttesterDutiesTask)
    # Spawning new attestation duties task.
    service.pollingAttesterDutiesTask = service.pollForAttesterDuties()

proc proposerDutiesLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  debug "Proposer duties loop is waiting for initialization"
  await allFutures(
    vc.preGenesisEvent.wait(),
    vc.indicesAvailable.wait(),
    vc.forksAvailable.wait()
  )
  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")
  while true:
    await service.pollForBeaconProposers()
    await service.waitForNextSlot()

proc validatorIndexLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  debug "Validator indices loop is waiting for initialization"
  await vc.preGenesisEvent.wait()
  while true:
    await service.pollForValidatorIndices()
    await service.waitForNextSlot()

proc dynamicValidatorsLoop*(service: DutiesServiceRef,
                            web3signerUrl: Web3SignerUrl,
                            intervalInSeconds: int) {.async.} =
  let vc = service.client
  doAssert(intervalInSeconds > 0)

  proc addValidatorProc(data: KeystoreData) =
    vc.addValidator(data)

  var
    timeout = seconds(intervalInSeconds)
    exitLoop = false

  while not(exitLoop):
    exitLoop =
      try:
        await sleepAsync(timeout)
        timeout =
          block:
            let res = await queryValidatorsSource(web3signerUrl)
            if res.isOk():
              let keystores = res.get()
              debug "Web3Signer has been polled for validators",
                    keystores_found = len(keystores),
                    web3signer_url = web3signerUrl.url
              vc.attachedValidators.updateDynamicValidators(web3signerUrl,
                                                            keystores,
                                                            addValidatorProc)
              seconds(intervalInSeconds)
            else:
              seconds(5)
        false
      except CancelledError:
        true

proc proposerPreparationsLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  debug "Beacon proposer preparation loop is waiting for initialization"
  await allFutures(
    vc.preGenesisEvent.wait(),
    vc.indicesAvailable.wait()
  )
  while true:
    await service.prepareBeaconProposers()
    await service.waitForNextSlot()

proc validatorRegisterLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  doAssert(vc.config.payloadBuilderEnable)
  debug "Validator registration loop is waiting for initialization"
  await allFutures(
    vc.preGenesisEvent.wait(),
    vc.indicesAvailable.wait(),
    vc.forksAvailable.wait()
  )
  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")
  while true:
    await service.registerValidators()
    await service.waitForNextSlot()

proc syncCommitteeDutiesLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  debug "Sync committee duties loop is waiting for initialization"
  await allFutures(
    vc.preGenesisEvent.wait(),
    vc.indicesAvailable.wait(),
    vc.forksAvailable.wait()
  )
  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")
  while true:
    await service.waitForNextSlot()
    if not(isNil(service.pollingSyncDutiesTask)) and
       not(service.pollingSyncDutiesTask.finished()):
      await cancelAndWait(service.pollingSyncDutiesTask)
    # Spawning new attestation duties task.
    service.pollingSyncDutiesTask = service.pollForSyncCommitteeDuties()

proc getNextEpochMiddleSlot(vc: ValidatorClientRef): Slot =
  let
    middleSlot = Slot(SLOTS_PER_EPOCH div 2)
    currentSlot = vc.beaconClock.now().slotOrZero()
    slotInEpoch = currentSlot.since_epoch_start()

  if slotInEpoch >= middleSlot:
    (currentSlot.epoch + 1'u64).start_slot() + uint64(middleSlot)
  else:
    currentSlot + (uint64(middleSlot) - uint64(slotInEpoch))

proc pruneSlashingDatabase(service: DutiesServiceRef) {.async.} =
  let
    vc = service.client
    currentSlot = vc.beaconClock.now().slotOrZero()
    startTime = Moment.now()
    blockHeader =
      try:
        await vc.getFinalizedBlockHeader()
      except CancelledError as exc:
        debug "Finalized block header request was interrupted",
              slot = currentSlot
        raise exc
      except CatchableError as exc:
        error "Unexpected error occured while requesting " &
              "finalized block header", slot = currentSlot,
              err_name = exc.name, err_msg = exc.msg
        Opt.none(GetBlockHeaderResponse)
    checkpointTime = Moment.now()
  if blockHeader.isSome():
    let epoch = blockHeader.get().data.header.message.slot.epoch
    vc.finalizedEpoch = Opt.some(epoch)
    if service.lastSlashingEpoch.get(FAR_FUTURE_EPOCH) != epoch:
      vc.attachedValidators[]
        .slashingProtection
        .pruneAfterFinalization(epoch)
      service.lastSlashingEpoch = Opt.some(epoch)
      let finishTime = Moment.now()
      debug "Slashing database has been pruned", slot = currentSlot,
        epoch = currentSlot.epoch(),
        finalized_epoch = epoch,
        elapsed_time = (finishTime - startTime),
        pruning_time = (finishTime - checkpointTime)

proc slashingDatabasePruningLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  debug "Slashing database pruning loop is waiting for initialization"
  await allFutures(
    vc.preGenesisEvent.wait(),
    vc.indicesAvailable.wait(),
    vc.forksAvailable.wait()
  )
  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")
  while true:
    let slot = await vc.checkedWaitForSlot(vc.getNextEpochMiddleSlot(),
                                           aggregateSlotOffset, false)
    if slot.isNone():
      continue

    if not(isNil(service.pruneSlashingDatabaseTask)) and
       not(service.pruneSlashingDatabaseTask.finished()):
      await cancelAndWait(service.pruneSlashingDatabaseTask)
    service.pruneSlashingDatabaseTask = service.pruneSlashingDatabase()

template checkAndRestart(serviceLoop: DutiesServiceLoop,
                         future: Future[void], body: untyped): untyped =
  if future.finished():
    if future.failed():
      let error = future.readError()
      debug "The loop ended unexpectedly with an error",
            error_name = error.name, error_msg = error.msg, loop = serviceLoop
    elif future.cancelled():
      debug "The loop was interrupted", loop = serviceLoop
    else:
      debug "The loop is finished unexpectedly without an error",
            loop = serviceLoop
    future = body

proc mainLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client

  service.state = ServiceState.Running
  debug "Service started"

  var
    attestFut = service.attesterDutiesLoop()
    proposeFut = service.proposerDutiesLoop()
    indicesFut = service.validatorIndexLoop()
    syncFut = service.syncCommitteeDutiesLoop()
    prepareFut = service.proposerPreparationsLoop()
    registerFut =
      if vc.config.payloadBuilderEnable:
        service.validatorRegisterLoop()
      else:
        nil
    dynamicFuts =
      if vc.config.web3signerUpdateInterval > 0:
        mapIt(vc.config.web3SignerUrls,
              service.dynamicValidatorsLoop(it, vc.config.web3signerUpdateInterval))
      else:
        debug "Dynamic validators update loop disabled"
        @[]
    slashPruningFut = service.slashingDatabasePruningLoop()
    web3SignerUrls = vc.config.web3SignerUrls

  while true:
    # This loop could look much more nicer/better, when
    # https://github.com/nim-lang/Nim/issues/19911 will be fixed, so it could
    # become safe to combine loops, breaks and exception handlers.
    let breakLoop =
      try:
        var futures = @[
          FutureBase(attestFut),
          FutureBase(proposeFut),
          FutureBase(indicesFut),
          FutureBase(syncFut),
          FutureBase(prepareFut),
          FutureBase(slashPruningFut)
        ]
        for fut in dynamicFuts:
          futures.add fut
        if not(isNil(registerFut)): futures.add(FutureBase(registerFut))
        discard await race(futures)
        checkAndRestart(AttesterLoop, attestFut, service.attesterDutiesLoop())
        checkAndRestart(ProposerLoop, proposeFut, service.proposerDutiesLoop())
        checkAndRestart(IndicesLoop, indicesFut, service.validatorIndexLoop())
        checkAndRestart(SyncCommitteeLoop, syncFut,
                        service.syncCommitteeDutiesLoop())
        checkAndRestart(ProposerPreparationLoop, prepareFut,
                        service.proposerPreparationsLoop())
        if not(isNil(registerFut)):
          checkAndRestart(ValidatorRegisterLoop, registerFut,
                          service.validatorRegisterLoop())
        for i in 0 ..< dynamicFuts.len:
          checkAndRestart(DynamicValidatorsLoop, dynamicFuts[i],
                          service.dynamicValidatorsLoop(
                            web3SignerUrls[i],
                            vc.config.web3signerUpdateInterval))
        checkAndRestart(SlashPruningLoop, slashPruningFut,
                        service.slashingDatabasePruningLoop())
        false
      except CancelledError:
        debug "Service interrupted"
        var pending: seq[Future[void]]
        if not(attestFut.finished()):
          pending.add(attestFut.cancelAndWait())
        if not(proposeFut.finished()):
          pending.add(proposeFut.cancelAndWait())
        if not(indicesFut.finished()):
          pending.add(indicesFut.cancelAndWait())
        if not(syncFut.finished()):
          pending.add(syncFut.cancelAndWait())
        if not(prepareFut.finished()):
          pending.add(prepareFut.cancelAndWait())
        if not(isNil(registerFut)) and not(registerFut.finished()):
          pending.add(registerFut.cancelAndWait())
        for dynamicFut in dynamicFuts:
          if not dynamicFut.finished():
            pending.add(dynamicFut.cancelAndWait())
        if not(isNil(service.pollingAttesterDutiesTask)) and
           not(service.pollingAttesterDutiesTask.finished()):
          pending.add(service.pollingAttesterDutiesTask.cancelAndWait())
        if not(isNil(service.pollingSyncDutiesTask)) and
           not(service.pollingSyncDutiesTask.finished()):
          pending.add(service.pollingSyncDutiesTask.cancelAndWait())
        if not(isNil(service.pruneSlashingDatabaseTask)) and
           not(service.pruneSlashingDatabaseTask.finished()):
          pending.add(service.pruneSlashingDatabaseTask.cancelAndWait())
        await allFutures(pending)
        true
      except CatchableError as exc:
        warn "Service crashed with unexpected error", err_name = exc.name,
             err_msg = exc.msg
        true

    if breakLoop:
      break

proc init*(t: typedesc[DutiesServiceRef],
           vc: ValidatorClientRef): Future[DutiesServiceRef] {.async.} =
  logScope: service = ServiceName
  let res = DutiesServiceRef(name: ServiceName,
                             client: vc, state: ServiceState.Initialized)
  debug "Initializing service"
  return res

proc start*(service: DutiesServiceRef) =
  service.lifeFut = mainLoop(service)
