# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[sets, sequtils, algorithm]
import chronicles
import common, api, block_service

const
  ServiceName = "duties_service"
  SUBSCRIPTION_LOOKAHEAD_EPOCHS* = 4'u64
  SYNC_SIGNING_CHUNK_SIZE = 64
  ATTESTATION_SIGNING_CHUNK_SIZE = 64

logScope: service = ServiceName

type
  DutiesServiceLoop* = enum
    AttesterLoop, ProposerLoop, IndicesLoop, SyncCommitteeLoop,
    ProposerPreparationLoop, ValidatorRegisterLoop

  SyncIndexTable = Table[SyncSubcommitteeIndex, SlotProofsArray]

  SyncValidatorAndDuty = object
    validator: AttachedValidator
    duty: SyncDutyAndProof

  AttestationSlotRequest = object
    validator: AttachedValidator
    fork: Fork
    slot: Slot

  SyncSlotRequest = object
    validator: AttachedValidator
    slot: Slot
    fork: Fork
    validatorSyncCommitteeIndex: IndexInSyncCommittee
    validatorSubCommitteeIndex: SyncSubcommitteeIndex

chronicles.formatIt(DutiesServiceLoop):
  case it
  of AttesterLoop: "attester_loop"
  of ProposerLoop: "proposer_loop"
  of IndicesLoop: "index_loop"
  of SyncCommitteeLoop: "sync_committee_loop"
  of ProposerPreparationLoop: "proposer_prepare_loop"
  of ValidatorRegisterLoop: "validator_register_loop"

proc cmp(x, y: AttestationSlotRequest): int =
  if x.slot == y.slot: 0 elif x.slot < y.slot: -1 else: 1

proc cmp(x, y: SyncSlotRequest): int =
  if x.slot == y.slot: 0 elif x.slot < y.slot: -1 else: 1

iterator chunks*[T](data: openArray[T], maxCount: Positive): seq[T] =
  for i in countup(0, len(data) - 1, maxCount):
    yield @(data.toOpenArray(i, min(i + maxCount, len(data)) - 1))

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

proc fillAttestationSlotSignatures*(
       service: DutiesServiceRef,
       epochPeriods: seq[Epoch]
     ) {.async.} =
  let
    vc = service.client
    genesisRoot = vc.beaconGenesis.genesis_validators_root
    requests =
      block:
        var res: seq[AttestationSlotRequest]
        for epoch in epochPeriods:
          for duty in vc.attesterDutiesForEpoch(epoch):
            if duty.slotSig.isSome():
              continue
            let validator =
              vc.attachedValidators[].
                getValidator(duty.data.pubkey).valueOr:
              continue
            if validator.index.isNone():
              continue
            res.add(AttestationSlotRequest(
              validator: validator,
              slot: duty.data.slot,
              fork: vc.forkAtEpoch(duty.data.slot.epoch())
            ))
        # We make requests sorted by slot number.
        sorted(res, cmp, order = SortOrder.Ascending)

  # We creating signatures in chunks to make VC more responsive for big number
  # of validators. In this case tasks that run concurrently will be able to use
  # signatures for slots at the beginning of the epoch even before this
  # processing will be completed.
  for chunk in requests.chunks(ATTESTATION_SIGNING_CHUNK_SIZE):
    let pendingRequests = chunk.mapIt(
      getSlotSignature(it.validator, it.fork, genesisRoot, it.slot))

    try:
      await allFutures(pendingRequests)
    except CancelledError as exc:
      var pending: seq[Future[void]]
      for future in pendingRequests:
        if not(future.finished()): pending.add(future.cancelAndWait())
      await allFutures(pending)
      raise exc

    for index, fut in pendingRequests.pairs():
      let
        request = chunk[index]
        signature =
          if fut.done():
            let sres = fut.read()
            if sres.isErr():
              warn "Unable to create slot signature using remote signer",
                   reason = sres.error(), epoch = request.slot.epoch(),
                   slot = request.slot
              Opt.none(ValidatorSig)
            else:
              Opt.some(sres.get())
          else:
            Opt.none(ValidatorSig)

      vc.attesters.withValue(request.validator.pubkey, map):
        map[].duties.withValue(request.slot.epoch(), dap):
          dap[].slotSig = signature

  if vc.config.distributedEnabled:
    var indexToKey: Table[ValidatorIndex, Opt[ValidatorPubKey]]
    let selections =
      block:
        var sres: seq[RestBeaconCommitteeSelection]
        for epoch in epochPeriods:
          for duty in vc.attesterDutiesForEpoch(epoch):
            # We only use duties which has slot signature filled, because
            # middleware needs it to create aggregated signature.
            if duty.slotSig.isSome():
              let
                validator = vc.attachedValidators[].getValidator(
                              duty.data.pubkey).valueOr:
                  continue
                vindex = validator.index.valueOr:
                  continue
              indexToKey[vindex] = Opt.some(validator.pubkey)
              sres.add(RestBeaconCommitteeSelection(
                validator_index: RestValidatorIndex(vindex),
                slot: duty.data.slot,
                selection_proof: duty.slotSig.get()
              ))
        sres

    if len(selections) == 0: return

    let sresponse =
      try:
        # Query middleware for aggregated signatures.
        await vc.submitBeaconCommitteeSelections(selections,
                                                 ApiStrategyKind.Best)
      except ValidatorApiError as exc:
        warn "Unable to submit beacon committee selections",
             reason = exc.getFailureReason()
        return
      except CancelledError as exc:
        debug "Beacon committee selections processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "Unexpected error occured while trying to submit beacon " &
              "committee selections", reason = exc.msg, error = exc.name
        return

    for selection in sresponse.data:
      let
        vindex = selection.validator_index.toValidatorIndex().valueOr:
          warn "Invalid validator_index value encountered while processing " &
               "beacon committee selections",
               validator_index = uint64(selection.validator_index),
               reason = $error
          continue
        selectionProof = selection.selection_proof.load().valueOr:
          warn "Invalid signature encountered while processing " &
               "beacon committee selections",
               validator_index = vindex,
               slot = selection.slot,
               selection_proof = shortLog(selection.selection_proof)
          continue
        validator =
          block:
            # Selections operating using validator indices, so we should check
            # if we have such validator index in our validator's pool and it
            # still in place (not removed using keystore manager).
            let key = indexToKey.getOrDefault(vindex)
            if key.isNone():
              warn "Non-existing validator encountered while processing " &
                   "beacon committee selections",
                   validator_index = vindex,
                   slot = selection.slot,
                   selection_proof = shortLog(selection.selection_proof)
              continue
            vc.attachedValidators[].getValidator(key.get()).valueOr:
              continue

      vc.attesters.withValue(validator.pubkey, map):
        map[].duties.withValue(selection.slot.epoch(), dap):
          dap[].slotSig = Opt.some(selectionProof.toValidatorSig())

proc pollForAttesterDuties*(service: DutiesServiceRef,
                            epoch: Epoch): Future[int] {.async.} =
  let vc = service.client
  let validatorIndices = toSeq(vc.attachedValidators[].indices())

  if len(validatorIndices) == 0:
    return 0

  var duties: seq[RestAttesterDuty]
  var currentRoot: Opt[Eth2Digest]

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
      currentRoot = Opt.some(res.dependent_root)
    else:
      if currentRoot.get() != res.dependent_root:
        # `dependent_root` must be equal for all requests/response, if it got
        # changed it means that some reorg was happened in beacon node and we
        # should re-request all queries again.
        offset = 0
        duties.setLen(0)
        currentRoot = Opt.none(Eth2Digest)
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
        var dutyFound = false
        vc.attesters.withValue(duty.pubkey, map):
          map[].duties.withValue(epoch, epochDuty):
            dutyFound = true
            if epochDuty[].dependentRoot != currentRoot.get():
              res.add((epoch, duty))
              if not(alreadyWarned):
                info "Attester duties re-organization",
                     prior_dependent_root = epochDuty.dependentRoot,
                     dependent_root = currentRoot.get()
                alreadyWarned = true
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
    let epoch = slot.epoch()
    for key, item in vc.syncCommitteeDuties:
      var currentPeriodDuties = EpochSyncDuties()
      for epochKey, epochDuty in item.duties:
        if epochKey >= epoch:
          currentPeriodDuties.duties[epochKey] = epochDuty
      newSyncCommitteeDuties[key] = currentPeriodDuties
    vc.syncCommitteeDuties = newSyncCommitteeDuties

proc fillSyncSlotSignatures*(
       service: DutiesServiceRef,
       epochPeriods: seq[Epoch]
     ) {.async.} =
  let
    vc = service.client
    genesisRoot = vc.beaconGenesis.genesis_validators_root
    validatorDuties =
      block:
        var res: seq[SyncValidatorAndDuty]
        for epoch in epochPeriods:
          for duty in vc.syncDutiesForEpoch(epoch):
            if len(duty.slotSigs) == 0:
              let validator = vc.attachedValidators[].getValidator(
                duty.data.pubkey).valueOr:
                continue
              res.add(
                SyncValidatorAndDuty(
                  validator: validator,
                  duty: duty))
        res
    requests =
      block:
        var res: seq[SyncSlotRequest]
        for epoch in epochPeriods:
          let fork = vc.forkAtEpoch(epoch)
          for slot in epoch.slots():
            for item in validatorDuties:
              for syncCommitteeIndex in
                  item.duty.data.validator_sync_committee_indices:
                let subCommitteeIndex = getSubcommitteeIndex(syncCommitteeIndex)
                res.add(SyncSlotRequest(
                  validator: item.validator,
                  slot: slot,
                  fork: fork,
                  validatorSyncCommitteeIndex: syncCommitteeIndex,
                  validatorSubCommitteeIndex: subCommitteeIndex))
        res

  # We creating signatures in chunks to make VC more responsive for big number
  # of validators. In this case tasks that run concurrently will be able to use
  # signatures for slots at the beginning of the epoch even before this
  # processing will be completed.
  for chunk in requests.chunks(SYNC_SIGNING_CHUNK_SIZE):
    let pendingRequests = chunk.mapIt(
      getSyncCommitteeSelectionProof(
        it.validator, it.fork, genesisRoot, it.slot,
        it.validatorSubCommitteeIndex))

    try:
      await allFutures(pendingRequests)
    except CancelledError as exc:
      var pending: seq[Future[void]]
      for future in pendingRequests:
        if not(future.finished()): pending.add(future.cancelAndWait())
      await allFutures(pending)
      raise exc

    for index, fut in pendingRequests.pairs():
      let
        request = chunk[index]
        epoch = request.slot.epoch()
        slotIndex = request.slot - epoch.start_slot()
        signature =
          if fut.done():
            let sres = fut.read()
            if sres.isErr():
              warn "Unable to create slot proof using remote signer",
                   reason = sres.error(), epoch = epoch,
                   slot = request.slot, slot_index = slotIndex,
                   validator = shortLog(request.validator)
              Opt.none(ValidatorSig)
            else:
              Opt.some(sres.get())
          else:
            Opt.none(ValidatorSig)

      vc.syncCommitteeDuties.withValue(request.validator.pubkey, map):
        map[].duties.withValue(epoch, sdap):
          # We can't use `withValue` here, because `sdap` has an empty Table
          # after initialized.
          sdap[].slotSigs.mgetOrPut(
            request.validatorSubCommitteeIndex,
            default(SlotProofsArray)
          )[slotIndex] = signature

  if vc.config.distributedEnabled:
    var indexToKey: Table[ValidatorIndex, Opt[ValidatorPubKey]]

    let selections =
      block:
        var sres: seq[RestSyncCommitteeSelection]
        for epoch in epochPeriods:
          for duty in vc.syncDutiesForEpoch(epoch):
            let
              validator = vc.attachedValidators[].getValidator(
                              duty.data.pubkey).valueOr:
                continue
              vindex = validator.index.valueOr:
                continue
              startSlot = duty.epoch.start_slot()
            indexToKey[vindex] = Opt.some(validator.pubkey)
            for subCommitteeIndex, proofs in duty.slotSigs.pairs():
              for slotIndex, selection_proof in proofs.pairs():
                if selection_proof.isNone(): continue
                sres.add(RestSyncCommitteeSelection(
                  validator_index: RestValidatorIndex(vindex),
                  slot: startSlot + slotIndex,
                  subcommittee_index: uint64(subCommitteeIndex),
                  selection_proof: selection_proof.get()
                ))
        sres

    if len(selections) == 0: return

    let sresponse =
      try:
        # Query middleware for aggregated signatures.
        await vc.submitSyncCommitteeSelections(selections,
                                               ApiStrategyKind.Best)
      except ValidatorApiError as exc:
        warn "Unable to submit sync committee selections",
             reason = exc.getFailureReason()
        return
      except CancelledError as exc:
        debug "Beacon committee selections processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "Unexpected error occured while trying to submit sync " &
              "committee selections", reason = exc.msg, error = exc.name
        return

    for selection in sresponse.data:
      let
        vindex = selection.validator_index.toValidatorIndex().valueOr:
          warn "Invalid validator_index value encountered while processing " &
               "sync committee selections",
               validator_index = uint64(selection.validator_index),
               reason = $error
          continue
        selectionProof = selection.selection_proof.load().valueOr:
          warn "Invalid signature encountered while processing " &
               "sync committee selections",
               validator_index = vindex,
               slot = selection.slot,
               subcommittee_index = selection.subcommittee_index,
               selection_proof = shortLog(selection.selection_proof)
          continue
        epoch = selection.slot.epoch()
        slotIndex = selection.slot - epoch.start_slot()
          # Position in our slot_proofs array
        subCommitteeIndex = SyncSubcommitteeIndex(selection.subcommittee_index)
        validator =
          block:
            # Selections operating using validator indices, so we should check
            # if we have such validator index in our validator's pool and it
            # still in place (not removed using keystore manager).
            let key = indexToKey.getOrDefault(vindex)
            if key.isNone():
              warn "Non-existing validator encountered while processing " &
                   "sync committee selections",
                   validator_index = vindex,
                   slot = selection.slot,
                   subcommittee_index = selection.subcommittee_index,
                   selection_proof = shortLog(selection.selection_proof)
              continue
            vc.attachedValidators[].getValidator(key.get()).valueOr:
              continue

      vc.syncCommitteeDuties.withValue(validator.pubkey, map):
        map[].duties.withValue(epoch, sdap):
          sdap[].slotSigs.withValue(subCommitteeIndex, proofs):
            proofs[][slotIndex] = Opt.some(selectionProof.toValidatorSig())

proc pollForSyncCommitteeDuties*(service: DutiesServiceRef,
                                 epoch: Epoch): Future[int] {.async.} =
  let vc = service.client
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
    relevantSdaps = filteredDuties.mapIt(SyncDutyAndProof.init(epoch, it))
    fork = vc.forkAtEpoch(epoch)

    addOrReplaceItems =
      block:
        var
          alreadyWarned = false
          res: seq[tuple[epoch: Epoch, duty: SyncDutyAndProof]]
        for sdap in relevantSdaps:
          var dutyFound = false
          vc.syncCommitteeDuties.withValue(sdap.data.pubkey, map):
            map[].duties.withValue(epoch, epochDuty):
              dutyFound = true
              if epochDuty[] != sdap:
                res.add((epoch, sdap))
                if not(alreadyWarned):
                  info "Sync committee duties re-organization", sdap, epoch
                  alreadyWarned = true
          if not(dutyFound):
            let duty = sdap.data
            info "Received new sync committee duty", duty, epoch
            res.add((epoch, sdap))
        res

  if len(addOrReplaceItems) > 0:
    for epoch, sdap in items(addOrReplaceItems):
      vc.syncCommitteeDuties.mgetOrPut(sdap.data.pubkey,
        default(EpochSyncDuties)).duties[epoch] = sdap

  return len(addOrReplaceItems)

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
      let moment = Moment.now()
      await service.fillAttestationSlotSignatures(@[currentEpoch, nextEpoch])
      debug "Slot signatures has been obtained", time = (Moment.now() - moment)

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
          if lookaheadPeriod > currentPeriod:
            res.add(
              (epoch: lookaheadPeriod.start_epoch(),
               period: lookaheadPeriod)
            )
          res

      (counts, epochs, total) =
        block:
          var res: seq[tuple[epoch: Epoch, period: SyncCommitteePeriod,
                             count: int]]
          var periods: seq[Epoch]
          var total = 0
          if len(dutyPeriods) > 0:
            for (epoch, period) in dutyPeriods:
              let count = await service.pollForSyncCommitteeDuties(epoch)
              res.add((epoch: epoch, period: period, count: count))
              periods.add(epoch)
              total += count
          (res, periods, total)

    if total == 0:
      debug "No new sync committee member's duties received",
            slot = currentSlot

    block:
      let moment = Moment.now()
      await service.fillSyncSlotSignatures(epochs)
      debug "Sync selection proofs has been obtained",
             time = (Moment.now() - moment)

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
      if res == 0:
        warn "Failed to subscribe validators to sync committee subnets",
             slot = currentSlot, epoch = currentEpoch,
             subscriptions_count = len(subscriptions)

  service.pruneSyncCommitteeDuties(currentSlot)

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

proc waitForNextSlot(service: DutiesServiceRef,
                     serviceLoop: DutiesServiceLoop) {.async.} =
  let vc = service.client
  let sleepTime = vc.beaconClock.durationToNextSlot()
  await sleepAsync(sleepTime)

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
    await service.waitForNextSlot(AttesterLoop)
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
    await service.waitForNextSlot(ProposerLoop)

proc validatorIndexLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  debug "Validator indices loop is waiting for initialization"
  await vc.preGenesisEvent.wait()
  while true:
    await service.pollForValidatorIndices()
    await service.waitForNextSlot(IndicesLoop)

proc proposerPreparationsLoop(service: DutiesServiceRef) {.async.} =
  let vc = service.client
  debug "Beacon proposer preparation loop is waiting for initialization"
  await allFutures(
    vc.preGenesisEvent.wait(),
    vc.indicesAvailable.wait()
  )
  while true:
    await service.prepareBeaconProposers()
    await service.waitForNextSlot(ProposerPreparationLoop)

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
    await service.waitForNextSlot(ValidatorRegisterLoop)

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
    await service.waitForNextSlot(SyncCommitteeLoop)
    # Cleaning up previous attestation duties task.
    if not(isNil(service.pollingSyncDutiesTask)) and
       not(service.pollingSyncDutiesTask.finished()):
      await cancelAndWait(service.pollingSyncDutiesTask)
    # Spawning new attestation duties task.
    service.pollingSyncDutiesTask = service.pollForSyncCommitteeDuties()

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
        var futures = @[
          FutureBase(attestFut),
          FutureBase(proposeFut),
          FutureBase(indicesFut),
          FutureBase(syncFut),
          FutureBase(prepareFut)
        ]
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
        if not(isNil(service.pollingAttesterDutiesTask)) and
           not(service.pollingAttesterDutiesTask.finished()):
          pending.add(service.pollingAttesterDutiesTask.cancelAndWait())
        if not(isNil(service.pollingSyncDutiesTask)) and
           not(service.pollingSyncDutiesTask.finished()):
          pending.add(service.pollingSyncDutiesTask.cancelAndWait())
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
