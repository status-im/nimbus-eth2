# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[sets, sequtils]
import chronicles
import common, api, block_service

const
  ServiceName = "duties_service"
  SUBSCRIPTION_LOOKAHEAD_EPOCHS* = 4'u64

logScope: service = ServiceName

type
  DutiesServiceLoop* = enum
    AttesterLoop, ProposerLoop, IndicesLoop, SyncCommitteeLoop,
    ProposerPreparationLoop, ValidatorRegisterLoop

chronicles.formatIt(DutiesServiceLoop):
  case it
  of AttesterLoop: "attester_loop"
  of ProposerLoop: "proposer_loop"
  of IndicesLoop: "index_loop"
  of SyncCommitteeLoop: "sync_committee_loop"
  of ProposerPreparationLoop: "proposer_prepare_loop"
  of ValidatorRegisterLoop: "validator_register_loop"

proc checkDuty(duty: RestAttesterDuty): bool =
  (duty.committee_length <= MAX_VALIDATORS_PER_COMMITTEE) and
  (uint64(duty.committee_index) < MAX_COMMITTEES_PER_SLOT) and
  (uint64(duty.validator_committee_index) < duty.committee_length) and
  (uint64(duty.validator_index) <= VALIDATOR_REGISTRY_LIMIT)

proc checkSyncDuty(duty: RestSyncCommitteeDuty): bool =
  uint64(duty.validator_index) <= VALIDATOR_REGISTRY_LIMIT

proc pollForValidatorIndices*(vc: ValidatorClientRef) {.async.} =
  let validatorIdents =
    block:
      var res: seq[ValidatorIdent]
      for validator in vc.attachedValidators[].items():
        if validator.needsUpdate():
          res.add(ValidatorIdent.init(validator.pubkey))
      res

  var validators: seq[RestValidator]
  var offset = 0

  while offset < len(validatorIdents):
    let arraySize = min(ClientMaximumValidatorIds, len(validatorIdents))

    let idents =
      block:
        var res = newSeq[ValidatorIdent](arraySize)
        var k = 0
        for i in offset ..< arraySize:
          res[k] = validatorIdents[i]
          inc(k)
        res

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

    offset += arraySize

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
      updated = len(updated)
    trace "Validator indices update dump", missing_validators = missing,
          updated_validators = updated
    vc.indicesAvailable.fire()

proc pollForAttesterDuties*(vc: ValidatorClientRef,
                            epoch: Epoch): Future[int] {.async.} =
  let validatorIndices =
    block:
      var res: seq[ValidatorIndex]
      for index in vc.attachedValidators[].indices():
        res.add(index)
      res

  if validatorIndices.len == 0:
    return 0

  var duties: seq[RestAttesterDuty]
  var currentRoot: Option[Eth2Digest]

  var offset = 0
  while offset < len(validatorIndices):
    let arraySize = min(DutiesMaximumValidatorIds, len(validatorIndices))
    # We use `DutiesMaximumValidatorIds` here because validator ids are sent
    # in HTTP request body and NOT in HTTP request headers.
    let indices =
      block:
        var res = newSeq[ValidatorIndex](arraySize)
        var k = 0
        for i in offset ..< arraySize:
          res[k] = validatorIndices[i]
          inc(k)
        res

    let res =
      try:
        await vc.getAttesterDuties(epoch, indices, ApiStrategyKind.First)
      except ValidatorApiError as exc:
        warn "Unable to get attester duties", epoch = epoch,
             reason = exc.getFailureReason()
        return 0
      except CancelledError as exc:
        debug "Attester duties processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "Unexpected error occured while getting attester duties",
              epoch = epoch, err_name = exc.name, err_msg = exc.msg
        return 0

    if currentRoot.isNone():
      # First request
      currentRoot = some(res.dependent_root)
    else:
      if currentRoot.get() != res.dependent_root:
        # `dependent_root` must be equal for all requests/response, if it got
        # changed it means that some reorg was happened in beacon node and we
        # should re-request all queries again.
        offset = 0
        duties.setLen(0)
        currentRoot = none[Eth2Digest]()
        continue

    for item in res.data:
      duties.add(item)

    offset += arraySize

  let
    relevantDuties = duties.filterIt(
      checkDuty(it) and (it.pubkey in vc.attachedValidators[])
    )
    genesisRoot = vc.beaconGenesis.genesis_validators_root

  let addOrReplaceItems =
    block:
      var alreadyWarned = false
      var res: seq[tuple[epoch: Epoch, duty: RestAttesterDuty]]
      for duty in relevantDuties:
        let map = vc.attesters.getOrDefault(duty.pubkey)
        let epochDuty = map.duties.getOrDefault(epoch, DefaultDutyAndProof)
        if not(epochDuty.isDefault()):
          if epochDuty.dependentRoot != currentRoot.get():
            res.add((epoch, duty))
            if not(alreadyWarned):
              warn "Attester duties re-organization",
                   prior_dependent_root = epochDuty.dependentRoot,
                   dependent_root = currentRoot.get()
              alreadyWarned = true
        else:
          info "Received new attester duty", duty, epoch = epoch,
                                             dependent_root = currentRoot.get()
          res.add((epoch, duty))
      res

  if len(addOrReplaceItems) > 0:
    var pendingRequests: seq[Future[SignatureResult]]
    var validators: seq[AttachedValidator]
    for item in addOrReplaceItems:
      let validator =
          vc.attachedValidators[].getValidator(item.duty.pubkey).valueOr:
        continue
      let fork = vc.forkAtEpoch(item.duty.slot.epoch)
      let future = validator.getSlotSignature(
        fork, genesisRoot, item.duty.slot)
      pendingRequests.add(future)
      validators.add(validator)

    try:
      await allFutures(pendingRequests)
    except CancelledError as exc:
      var pendingCancel: seq[Future[void]]
      for future in pendingRequests:
        if not(future.finished()):
          pendingCancel.add(future.cancelAndWait())
      await allFutures(pendingCancel)
      raise exc

    for index, fut in pendingRequests:
      let item = addOrReplaceItems[index]
      let dap =
        if fut.done():
          let sigRes = fut.read()
          if sigRes.isErr():
            warn "Unable to create slot signature using remote signer",
                  validator = shortLog(validators[index]),
                  error_msg = sigRes.error()
            DutyAndProof.init(item.epoch, currentRoot.get(), item.duty,
                              none[ValidatorSig]())
          else:
            DutyAndProof.init(item.epoch, currentRoot.get(), item.duty,
                              some(sigRes.get()))
        else:
          DutyAndProof.init(item.epoch, currentRoot.get(), item.duty,
                            none[ValidatorSig]())

      var validatorDuties = vc.attesters.getOrDefault(item.duty.pubkey)
      validatorDuties.duties[item.epoch] = dap
      vc.attesters[item.duty.pubkey] = validatorDuties

  return len(addOrReplaceItems)

proc pruneSyncCommitteeDuties*(vc: ValidatorClientRef, slot: Slot) =
  if slot.is_sync_committee_period():
    var newSyncCommitteeDuties: SyncCommitteeDutiesMap
    let epoch = slot.epoch()
    for key, item in vc.syncCommitteeDuties:
      var currentPeriodDuties = EpochSyncDuties()
      for epochKey, epochDuty in item.duties:
        if epochKey >= epoch:
          currentPeriodDuties.duties[epochKey] = epochDuty
      newSyncCommitteeDuties[key] = currentPeriodDuties
    vc.syncCommitteeDuties = newSyncCommitteeDuties

proc pollForSyncCommitteeDuties*(vc: ValidatorClientRef,
                                 epoch: Epoch): Future[int] {.async.} =
  let validatorIndices = toSeq(vc.attachedValidators[].indices())
  var
    filteredDuties: seq[RestSyncCommitteeDuty]
    offset = 0
    remainingItems = len(validatorIndices)

  while offset < len(validatorIndices):
    let
      arraySize = min(DutiesMaximumValidatorIds, remainingItems)
      # We use `DutiesMaximumValidatorIds` here because validator ids are sent
      # in HTTP request body and NOT in HTTP request headers.
      indices = validatorIndices[offset ..< (offset + arraySize)]

      res =
        try:
          await vc.getSyncCommitteeDuties(epoch, indices, ApiStrategyKind.First)
        except ValidatorApiError as exc:
          warn "Unable to get sync committee duties", epoch = epoch,
               reason = exc.getFailureReason()
          return 0
        except CancelledError as exc:
          debug "Sync committee duties processing was interrupted"
          raise exc
        except CatchableError as exc:
          error "Unexpected error occurred while getting sync committee duties",
                epoch = epoch, err_name = exc.name, err_msg = exc.msg
          return 0

    for item in res.data:
      if checkSyncDuty(item) and (item.pubkey in vc.attachedValidators[]):
        filteredDuties.add(item)

    offset += arraySize
    remainingItems -= arraySize

  let
    relevantDuties =
      block:
        var res: seq[SyncCommitteeDuty]
        for duty in filteredDuties:
          for validatorSyncCommitteeIndex in
              duty.validator_sync_committee_indices:
            res.add(SyncCommitteeDuty(
              pubkey: duty.pubkey,
              validator_index: duty.validator_index,
              validator_sync_committee_index: validatorSyncCommitteeIndex))
        res

    fork = vc.forkAtEpoch(epoch)

  let addOrReplaceItems =
    block:
      var alreadyWarned = false
      var res: seq[tuple[epoch: Epoch, duty: SyncCommitteeDuty]]
      for duty in relevantDuties:
        var dutyFound = false

        vc.syncCommitteeDuties.withValue(duty.pubkey, map):
          map.duties.withValue(epoch, epochDuty):
            if epochDuty[] != duty:
              dutyFound = true

        if dutyFound and not alreadyWarned:
          info "Sync committee duties re-organization", duty, epoch
          alreadyWarned = true

        res.add((epoch, duty))
      res

  if len(addOrReplaceItems) > 0:
    for epoch, duty in items(addOrReplaceItems):
      var validatorDuties =
        vc.syncCommitteeDuties.getOrDefault(duty.pubkey)
      validatorDuties.duties[epoch] = duty
      vc.syncCommitteeDuties[duty.pubkey] = validatorDuties

  return len(addOrReplaceItems)

proc pruneAttesterDuties(vc: ValidatorClientRef, epoch: Epoch) =
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

proc pollForAttesterDuties*(vc: ValidatorClientRef) {.async.} =
  ## Query the beacon node for attestation duties for all known validators.
  ##
  ## This function will perform (in the following order):
  ##
  ## 1. Poll for current-epoch duties and update the local `attesters` map.
  ## 2. Poll for next-epoch duties and update the local `attesters` map.
  ## 3. Push out any attestation subnet subscriptions to the BN.
  let sres = vc.getCurrentSlot()
  if sres.isSome():
    let
      currentSlot = sres.get()
      currentEpoch = currentSlot.epoch()
      nextEpoch = currentEpoch + 1'u64

    if vc.attachedValidators[].count() != 0:
      var counts: array[2, tuple[epoch: Epoch, count: int]]
      counts[0] = (currentEpoch, await vc.pollForAttesterDuties(currentEpoch))
      counts[1] = (nextEpoch, await vc.pollForAttesterDuties(nextEpoch))

      if (counts[0].count == 0) and (counts[1].count == 0):
        debug "No new attester's duties received", slot = currentSlot

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

    vc.pruneAttesterDuties(currentEpoch)

proc pollForSyncCommitteeDuties* (vc: ValidatorClientRef) {.async.} =
  let sres = vc.getCurrentSlot()
  if sres.isSome():
    let
      currentSlot = sres.get()
      currentEpoch = currentSlot.epoch()

    if vc.attachedValidators[].count() != 0:
      let
        dutyPeriods =
          block:
            var res: seq[tuple[epoch: Epoch, period: SyncCommitteePeriod]]
            let
              currentPeriod = currentSlot.sync_committee_period()
              lookaheadSlot = currentSlot +
                              SUBSCRIPTION_LOOKAHEAD_EPOCHS * SLOTS_PER_EPOCH
              lookaheadPeriod = lookaheadSlot.sync_committee_period()
            res.add(
              (epoch: currentSlot.epoch(),
               period: currentPeriod)
            )
            if lookAheadPeriod > currentPeriod:
              res.add(
                (epoch: lookaheadPeriod.start_epoch(),
                 period: lookAheadPeriod)
              )
            res

        (counts, total) =
          block:
            var res: seq[tuple[epoch: Epoch, period: SyncCommitteePeriod,
                               count: int]]
            var total = 0
            if len(dutyPeriods) > 0:
              for (epoch, period) in dutyPeriods:
                let count = await vc.pollForSyncCommitteeDuties(epoch)
                res.add((epoch: epoch, period: period, count: count))
                total += count
            (res, total)

      if total == 0:
        debug "No new sync committee member's duties received",
              slot = currentSlot

      let subscriptions =
        block:
          var res: seq[RestSyncCommitteeSubscription]
          for item in counts:
            if item.count > 0:
              let untilEpoch = start_epoch(item.period + 1'u64)
              let subscriptionsInfo =
                vc.syncMembersSubscriptionInfoForEpoch(item.epoch)
              for subInfo in subscriptionsInfo:
                let sub = RestSyncCommitteeSubscription(
                  validator_index: subInfo.validator_index,
                  sync_committee_indices:
                    subInfo.validator_sync_committee_indices,
                  until_epoch: untilEpoch
                )
                res.add(sub)
          res

      if len(subscriptions) > 0:
        let res = await vc.prepareSyncCommitteeSubnets(subscriptions)
        if res != 0:
          warn "Failed to subscribe validators to sync committee subnets",
               slot = currentSlot, epoch = currentEpoch,
               subscriptions_count = len(subscriptions)

      vc.pruneSyncCommitteeDuties(currentSlot)

proc pruneBeaconProposers(vc: ValidatorClientRef, epoch: Epoch) =
  var proposers: ProposerMap
  for epochKey, data in vc.proposers:
    if (epochKey + HISTORICAL_DUTIES_EPOCHS) >= epoch:
      proposers[epochKey] = data
    else:
      debug "Proposer duty has been pruned", epoch = epochKey,
            loop = ProposerLoop
  vc.proposers = proposers

proc pollForBeaconProposers*(vc: ValidatorClientRef) {.async.} =
  let sres = vc.getCurrentSlot()
  if sres.isSome():
    let
      currentSlot = sres.get()
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
        warn "Unable to get proposer duties", slot = currentSlot,
             epoch = currentEpoch, reason = exc.getFailureReason()
      except CancelledError as exc:
        debug "Proposer duties processing was interrupted"
        raise exc
      except CatchableError as exc:
        debug "Unexpected error occured while getting proposer duties",
              slot = currentSlot, epoch = currentEpoch, err_name = exc.name,
              err_msg = exc.msg

    vc.pruneBeaconProposers(currentEpoch)

proc prepareBeaconProposers*(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  let sres = vc.getCurrentSlot()
  if sres.isSome():
    let
      currentSlot = sres.get()
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
  let sres = vc.getCurrentSlot()

  var default: seq[SignedValidatorRegistrationV1]
  if sres.isSome():
    let
      genesisFork = vc.forks[0]
      currentSlot = sres.get()
      registrations =
        try:
          await vc.prepareRegistrationList(getTime(), genesisFork)
        except CancelledError as exc:
          debug "Validator registration preparation was interrupted",
                slot = currentSlot, fork = genesisFork
          raise exc
        except CatchableError as exc:
          error "Unexpected error occured while preparing validators " &
                "registration data", slot = currentSlot, fork = genesisFork,
                err_name = exc.name, err_msg = exc.msg
          default

    let count =
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

proc waitForNextSlot(service: DutiesServiceRef,
                     serviceLoop: DutiesServiceLoop) {.async.} =
  let vc = service.client
  let sleepTime = vc.beaconClock.durationToNextSlot()
  await sleepAsync(sleepTime)

proc attesterDutiesLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client

  debug "Attester duties loop waiting for fork schedule update"
  await vc.forksAvailable.wait()
  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")
  while true:
    await vc.pollForAttesterDuties()
    await service.waitForNextSlot(AttesterLoop)

proc proposerDutiesLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client

  debug "Proposer duties loop waiting for fork schedule update"
  await vc.forksAvailable.wait()
  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")
  while true:
    await vc.pollForBeaconProposers()
    await service.waitForNextSlot(ProposerLoop)

proc validatorIndexLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  while true:
    await vc.pollForValidatorIndices()
    await service.waitForNextSlot(IndicesLoop)

proc proposerPreparationsLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client

  debug "Beacon proposer preparation loop waiting for validator indices update"
  await vc.indicesAvailable.wait()
  while true:
    await service.prepareBeaconProposers()
    await service.waitForNextSlot(ProposerPreparationLoop)

proc validatorRegisterLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  doAssert(vc.config.payloadBuilderEnable)

  debug "Validator registration loop is waiting for initialization"
  await allFutures(vc.indicesAvailable.wait(), vc.forksAvailable.wait())
  while true:
    await service.registerValidators()
    await service.waitForNextSlot(ValidatorRegisterLoop)

proc syncCommitteeDutiesLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client

  debug "Sync committee duties loop waiting for fork schedule update"
  await vc.forksAvailable.wait()
  doAssert(len(vc.forks) > 0, "Fork schedule must not be empty at this point")
  while true:
    await vc.pollForSyncCommitteeDuties()
    await service.waitForNextSlot(SyncCommitteeLoop)

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

  while true:
    # This loop could look much more nicer/better, when
    # https://github.com/nim-lang/Nim/issues/19911 will be fixed, so it could
    # become safe to combine loops, breaks and exception handlers.
    let breakLoop =
      try:
        var futures = @[FutureBase(attestFut), FutureBase(proposeFut),
                        FutureBase(indicesFut), FutureBase(syncFut),
                        FutureBase(prepareFut)]
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
  # We query for indices first, to avoid empty queries for duties.
  await vc.pollForValidatorIndices()
  return res

proc start*(service: DutiesServiceRef) =
  service.lifeFut = mainLoop(service)
