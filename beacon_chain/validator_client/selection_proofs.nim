# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[algorithm, sequtils]
import chronicles, chronos, metrics
import common, api

{.push raises: [].}

declareGauge client_slot_signatures_time,
  "Time used to obtain slot signatures"

declareGauge client_sync_committee_selection_proof_time,
  "Time used to obtain sync committee selection proofs"

declareGauge client_obol_aggregated_slot_signatures_time,
  "Time used to obtain slot signatures"

declareGauge client_obol_aggregated_sync_committee_selection_proof_time,
  "Time used to obtain sync committee selection proofs"

type
  FillSignaturesResult* = object
    signaturesRequested*: int
    signaturesReceived*: int
    selectionsRequested*: int
    selectionsReceived*: int
    selectionsProcessed*: int

  AttestationSlotRequest = object
    validator: AttachedValidator
    fork: Fork
    slot: Slot
    proof: Opt[ValidatorSig]
    future: FutureBase

  SyncCommitteeSlotRequest* = object
    validator: AttachedValidator
    fork: Fork
    slot: Slot
    sync_committee_index: IndexInSyncCommittee
    sub_committee_index: SyncSubcommitteeIndex
    duty: SyncCommitteeDuty
    proof: Opt[ValidatorSig]
    future: FutureBase

template withTimeMetric(metricName, body: untyped): untyped =
  let momentTime = Moment.now()
  try:
    body
  finally:
    let elapsedTime = Moment.now() - momentTime
    metrics.set(metricName, elapsedTime.milliseconds())

proc cmp(x, y: AttestationSlotRequest|SyncCommitteeSlotRequest): int =
  cmp(x.slot, y.slot)

proc getAttesterDutiesRequests(
       vc: ValidatorClientRef,
       start, finish: Slot,
       genesisRoot: Eth2Digest
     ): seq[AttestationSlotRequest] =
  var res: seq[AttestationSlotRequest]
  for epoch in start.epoch() .. finish.epoch():
    for duty in vc.attesterDutiesForEpoch(epoch):
      if (duty.data.slot < start) or (duty.data.slot > finish):
        # Ignore all the slots which are not in range.
        continue
      if duty.slotSig.isSome():
        # Ignore all the duties which already has selection proof.
        continue
      let validator = vc.attachedValidators[].
        getValidator(duty.data.pubkey).valueOr:
          # Ignore all the validators which are not here anymore
          continue
      if validator.index.isNone():
        # Ignore all the validators which do not have index yet.
        continue

      let
        fork = vc.forkAtEpoch(duty.data.slot.epoch())
        future = getSlotSignature(validator, fork, genesisRoot, duty.data.slot)

      res.add(
        AttestationSlotRequest(validator: validator, slot: duty.data.slot,
                               fork: fork, future: FutureBase(future)))
  # We make requests sorted by slot number.
  sorted(res, cmp, order = SortOrder.Ascending)

proc fillAttestationSelectionProofs*(
       vc: ValidatorClientRef,
       start, finish: Slot
     ): Future[FillSignaturesResult] {.async.} =
  let genesisRoot = vc.beaconGenesis.genesis_validators_root
  var
    requests: seq[AttestationSlotRequest]
    sigres: FillSignaturesResult

  withTimeMetric(client_slot_signatures_time):
    requests = vc.getAttesterDutiesRequests(start, finish, genesisRoot)
    sigres.signaturesRequested = len(requests)
    var pendingRequests = requests.mapIt(it.future)

    while len(pendingRequests) > 0:
      try:
        discard await race(pendingRequests)
      except CancelledError as exc:
        var pending: seq[Future[void]]
        for future in pendingRequests:
          if not(future.finished()): pending.add(future.cancelAndWait())
        await noCancel allFutures(pending)
        raise exc

      pendingRequests =
        block:
          var res: seq[FutureBase]
          for mreq in requests.mitems():
            if isNil(mreq.future): continue
            if not(mreq.future.finished()):
              res.add(mreq.future)
            else:
              let signature =
                if mreq.future.completed():
                  let sres = Future[SignatureResult](mreq.future).read()
                  if sres.isErr():
                    warn "Unable to create slot signature using remote signer",
                         reason = sres.error(), epoch = mreq.slot.epoch(),
                         slot = mreq.slot
                    Opt.none(ValidatorSig)
                  else:
                    inc(sigres.signaturesReceived)
                    Opt.some(sres.get())
                else:
                  Opt.none(ValidatorSig)

              mreq.future = nil
              mreq.proof = signature

              if signature.isSome():
                vc.attesters.withValue(mreq.validator.pubkey, map):
                  map[].duties.withValue(mreq.slot.epoch(), dap):
                    dap[].slotSig = signature
          res

  if vc.config.distributedEnabled:
    withTimeMetric(client_obol_aggregated_slot_signatures_time):
      let (indexToKey, selections) =
        block:
          var
            res1: Table[ValidatorIndex, Opt[ValidatorPubKey]]
            res2: seq[RestBeaconCommitteeSelection]

          for mreq in requests.mitems():
            if mreq.proof.isSome():
              res1[mreq.validator.index.get()] = Opt.some(mreq.validator.pubkey)
              res2.add(RestBeaconCommitteeSelection(
                validator_index: RestValidatorIndex(mreq.validator.index.get()),
                slot: mreq.slot, selection_proof: mreq.proof.get()))
          (res1, res2)

      sigres.selectionsRequested = len(selections)

      if len(selections) == 0:
        return sigres

      let sresponse =
        try:
          # Query middleware for aggregated signatures.
          await vc.submitBeaconCommitteeSelections(selections,
                                                   ApiStrategyKind.Best)
        except ValidatorApiError as exc:
          warn "Unable to submit beacon committee selections",
               reason = exc.getFailureReason()
          return sigres
        except CancelledError as exc:
          debug "Beacon committee selections processing was interrupted"
          raise exc
        except CatchableError as exc:
          error "Unexpected error occured while trying to submit beacon " &
                "committee selections", reason = exc.msg, error = exc.name
          return sigres

      sigres.selectionsReceived = len(sresponse.data)

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
                 validator_index = vindex, slot = selection.slot,
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
                notice "Found missing validator while processing " &
                       "beacon committee selections", validator_index = vindex,
                       slot = selection.slot,
                       validator = shortLog(key.get()),
                       selection_proof = shortLog(selection.selection_proof)
                continue

        vc.attesters.withValue(validator.pubkey, map):
          map[].duties.withValue(selection.slot.epoch(), dap):
            dap[].slotSig = Opt.some(selectionProof.toValidatorSig())
            inc(sigres.selectionsProcessed)

  sigres

func getIndex*(proof: SyncCommitteeSelectionProof,
               inindex: IndexInSyncCommittee): Opt[int] =
  if len(proof) == 0:
    return Opt.none(int)
  for index, value in proof.pairs():
    if value.sync_committee_index == inindex:
      return Opt.some(index)
  Opt.none(int)

func hasSignature*(proof: SyncCommitteeSelectionProof,
                   inindex: IndexInSyncCommittee,
                   slot: Slot): bool =
  let index = proof.getIndex(inindex).valueOr: return false
  proof[index].signatures[int(slot.since_epoch_start())].isSome()

func getSignature*(proof: SyncCommitteeSelectionProof,
                   inindex: IndexInSyncCommittee,
                   slot: Slot): Opt[ValidatorSig] =
  let index = proof.getIndex(inindex).valueOr:
    return Opt.none(ValidatorSig)
  proof[index].signatures[int(slot.since_epoch_start())]

proc setSignature*(proof: var SyncCommitteeSelectionProof,
                   inindex: IndexInSyncCommittee, slot: Slot,
                   signature: Opt[ValidatorSig]) =
  let index = proof.getIndex(inindex).expect(
    "EpochSelectionProof should be present at this moment")
  proof[index].signatures[int(slot.since_epoch_start())] = signature

proc setSyncSelectionProof*(vc: ValidatorClientRef, pubkey: ValidatorPubKey,
                            inindex: IndexInSyncCommittee, slot: Slot,
                            duty: SyncCommitteeDuty,
                            signature: Opt[ValidatorSig]) =
  let
    proof =
      block:
        let length = len(duty.validator_sync_committee_indices)
        var res = newSeq[EpochSelectionProof](length)
        for i in 0 ..< length:
          res[i].sync_committee_index = duty.validator_sync_committee_indices[i]
        res

  vc.syncCommitteeProofs.
    mgetOrPut(slot.epoch(), default(SyncCommitteeProofs)).proofs.
    mgetOrPut(pubkey, proof).setSignature(inindex, slot, signature)

proc getSyncCommitteeSelectionProof*(
    vc: ValidatorClientRef,
    pubkey: ValidatorPubKey,
    epoch: Epoch
  ): Opt[SyncCommitteeSelectionProof] =
  vc.syncCommitteeProofs.withValue(epoch, epochProofs):
    epochProofs[].proofs.withValue(pubkey, validatorProofs):
      return Opt.some(validatorProofs[])
    do:
      return Opt.none(SyncCommitteeSelectionProof)
  do:
    return Opt.none(SyncCommitteeSelectionProof)

proc getSyncCommitteeSelectionProof*(
       vc: ValidatorClientRef,
       pubkey: ValidatorPubKey,
       slot: Slot,
       inindex: IndexInSyncCommittee
     ): Opt[ValidatorSig] =
  vc.syncCommitteeProofs.withValue(slot.epoch(), epochProofs):
    epochProofs[].proofs.withValue(pubkey, validatorProofs):
      let index = getIndex(validatorProofs[], inindex).valueOr:
        return Opt.none(ValidatorSig)
      return validatorProofs[][index].signatures[int(slot.since_epoch_start())]
    do:
      return Opt.none(ValidatorSig)
  do:
    return Opt.none(ValidatorSig)

proc getSyncCommitteeDutiesRequests*(
       vc: ValidatorClientRef,
       start, finish: Slot,
       genesisRoot: Eth2Digest
     ): seq[SyncCommitteeSlotRequest] =
  var res: seq[SyncCommitteeSlotRequest]
  for epoch in start.epoch() .. finish.epoch():
    let
      fork = vc.forkAtEpoch(epoch)
      period = epoch.sync_committee_period()

    for duty in vc.syncDutiesForPeriod(period):
      let validator = vc.attachedValidators[].getValidator(duty.pubkey).valueOr:
        # Ignore all the validators which are not here anymore
        continue
      if validator.index.isNone():
        # Ignore all the valididators which do not have index yet.
        continue

      let proof = vc.getSyncCommitteeSelectionProof(duty.pubkey, epoch).
                    get(default(SyncCommitteeSelectionProof))

      for inindex in duty.validator_sync_committee_indices:
        for slot in epoch.slots():
          if slot < start: continue
          if slot > finish: break
          if proof.hasSignature(inindex, slot): continue
          let
            future =
              getSyncCommitteeSelectionProof(validator, fork, genesisRoot, slot,
                                             getSubcommitteeIndex(inindex))
            req =
              SyncCommitteeSlotRequest(
                validator: validator,
                fork: fork,
                slot: slot,
                duty: duty,
                sync_committee_index: inindex,
                sub_committee_index: getSubcommitteeIndex(inindex),
                future: FutureBase(future))
          res.add(req)
  # We make requests sorted by slot number.
  sorted(res, cmp, order = SortOrder.Ascending)

proc getSyncRequest*(
       requests: var openArray[SyncCommitteeSlotRequest],
       validator: AttachedValidator,
       slot: Slot,
       subcommittee_index: uint64
     ): Opt[SyncCommitteeSlotRequest] =
  for mreq in requests.mitems():
    if mreq.validator.pubkey == validator.pubkey and
       mreq.slot == slot and
       mreq.sub_committee_index == subcommittee_index:
      return Opt.some(mreq)
  Opt.none(SyncCommitteeSlotRequest)

proc fillSyncCommitteeSelectionProofs*(
       vc: ValidatorClientRef,
       start, finish: Slot
     ): Future[FillSignaturesResult] {.async.} =
  let genesisRoot = vc.beaconGenesis.genesis_validators_root
  var
    requests: seq[SyncCommitteeSlotRequest]
    sigres: FillSignaturesResult

  withTimeMetric(client_sync_committee_selection_proof_time):
    requests = vc.getSyncCommitteeDutiesRequests(start, finish, genesisRoot)
    sigres.signaturesRequested = len(requests)
    var pendingRequests = requests.mapIt(it.future)

    while len(pendingRequests) > 0:
      try:
        discard await race(pendingRequests)
      except CancelledError as exc:
        var pending: seq[Future[void]]
        for future in pendingRequests:
          if not(future.finished()): pending.add(future.cancelAndWait())
        await noCancel allFutures(pending)
        raise exc

      pendingRequests =
        block:
          var res: seq[FutureBase]
          for mreq in requests.mitems():
            if isNil(mreq.future): continue
            if not(mreq.future.finished()):
              res.add(mreq.future)
            else:
              let signature =
                if mreq.future.completed():
                  let sres = Future[SignatureResult](mreq.future).read()
                  if sres.isErr():
                    warn "Unable to create slot signature using remote signer",
                         reason = sres.error(), epoch = mreq.slot.epoch(),
                         slot = mreq.slot
                    Opt.none(ValidatorSig)
                  else:
                    inc(sigres.signaturesReceived)
                    Opt.some(sres.get())
                else:
                  Opt.none(ValidatorSig)

              mreq.future = nil
              mreq.proof = signature

              if signature.isSome():
                vc.setSyncSelectionProof(mreq.validator.pubkey,
                                         mreq.sync_committee_index,
                                         mreq.slot, mreq.duty,
                                         signature)
          res

  if vc.config.distributedEnabled:
    withTimeMetric(client_obol_aggregated_sync_committee_selection_proof_time):
      let (indexToKey, selections) =
        block:
          var
            res1: Table[ValidatorIndex, Opt[ValidatorPubKey]]
            res2: seq[RestSyncCommitteeSelection]
          for mreq in requests.mitems():
            if mreq.proof.isSome():
              res1[mreq.validator.index.get()] = Opt.some(mreq.validator.pubkey)
              res2.add(RestSyncCommitteeSelection(
                validator_index: RestValidatorIndex(mreq.validator.index.get()),
                subcommittee_index: uint64(mreq.sub_committee_index),
                slot: mreq.slot, selection_proof: mreq.proof.get()))
          (res1, res2)

      sigres.selectionsRequested = len(selections)

      if len(selections) == 0:
        return sigres

      let sresponse =
        try:
          # Query middleware for aggregated signatures.
          await vc.submitSyncCommitteeSelections(selections,
                                                 ApiStrategyKind.Best)
        except ValidatorApiError as exc:
          warn "Unable to submit sync committee selections",
               reason = exc.getFailureReason()
          return sigres
        except CancelledError as exc:
          debug "Sync committee selections processing was interrupted"
          raise exc
        except CatchableError as exc:
          error "Unexpected error occured while trying to submit sync " &
                "committee selections", reason = exc.msg, error = exc.name
          return sigres

      sigres.selectionsReceived = len(sresponse.data)

      for selection in sresponse.data:
        let
          slot = selection.slot
          subcommittee_index = selection.subcommittee_index
          vindex = selection.validator_index.toValidatorIndex().valueOr:
            warn "Invalid validator_index value encountered while processing " &
                 "sync committee selections",
                 validator_index = uint64(selection.validator_index),
                 reason = $error
            continue
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
                     slot = slot,
                     selection_proof = shortLog(selection.selection_proof)
                continue
              vc.attachedValidators[].getValidator(key.get()).valueOr:
                notice "Found missing validator while processing " &
                       "sync committee selections", validator_index = vindex,
                       slot = slot,
                       validator = shortLog(key.get()),
                       selection_proof = shortLog(selection.selection_proof)
                continue
          request =
            block:
              let res = getSyncRequest(requests, validator, slot,
                                       subcommittee_index)
              if res.isNone():
                warn "Found sync committee selection proof which was not " &
                     "requested",
                     slot = slot, subcommittee_index = subcommittee_index,
                     validator = shortLog(validator),
                     selection_proof = shortLog(selection.selection_proof)
                continue
              res.get()

        vc.syncCommitteeProofs.withValue(slot.epoch(), epochProofs):
          epochProofs[].proofs.withValue(validator.pubkey, signatures):
            signatures[].setSignature(request.sync_committee_index,
                                      selection.slot,
                                      Opt.some(selection.selection_proof))
            inc(sigres.selectionsProcessed)
  sigres
