# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles,
  ".."/validators/activity_metrics,
  ".."/spec/forks,
  common, api

logScope: service = "block_service"

proc publishBlock(vc: ValidatorClientRef, currentSlot, slot: Slot,
                  validator: AttachedValidator) {.async.} =
  let
    genesisRoot = vc.beaconGenesis.genesis_validators_root
    graffiti =
      if vc.config.graffiti.isSome():
        vc.config.graffiti.get()
      else:
        defaultGraffitiBytes()
    fork = vc.forkAtEpoch(slot.epoch)
    vindex = validator.index.get()

  if not(vc.doppelgangerCheck(validator)):
    info "Block has not been produced (doppelganger check still active)",
         slot = slot, validator = shortLog(validator),
         validator_index = vindex
    return

  debug "Publishing block", validator = shortLog(validator),
                            delay = vc.getDelay(slot.block_deadline()),
                            wall_slot = currentSlot,
                            genesis_root = genesisRoot,
                            graffiti = graffiti, fork = fork, slot = slot,
                            wall_slot = currentSlot
  let randaoReveal =
    try:
      let res = await validator.getEpochSignature(fork, genesisRoot, slot.epoch)
      if res.isErr():
        error "Unable to generate randao reveal usint remote signer",
              validator = shortLog(validator), error_msg = res.error()
        return
      res.get()
    except CancelledError as exc:
      error "Randao reveal processing was interrupted"
      raise exc
    except CatchableError as exc:
      error "An unexpected error occurred while receiving randao data",
            err_name = exc.name, err_msg = exc.msg
      return

  let beaconBlock =
    try:
      await vc.produceBlockV2(slot, randaoReveal, graffiti,
                              ApiStrategyKind.Best)
    except ValidatorApiError:
      error "Unable to retrieve block data", slot = slot,
            wall_slot = currentSlot, validator = shortLog(validator)
      return
    except CancelledError as exc:
      error "Producing block processing was interrupted"
      raise exc
    except CatchableError as exc:
      error "An unexpected error occurred while getting block data",
            err_name = exc.name, err_msg = exc.msg
      return

  let blockRoot = withBlck(beaconBlock): hash_tree_root(blck)
  # TODO: signingRoot is recomputed in getBlockSignature just after
  let signingRoot = compute_block_signing_root(fork, genesisRoot, slot,
                                               blockRoot)
  let notSlashable = vc.attachedValidators[]
    .slashingProtection
    .registerBlock(vindex, validator.pubkey, slot, signingRoot)

  if notSlashable.isOk():
    let signature =
      try:
        let res = await validator.getBlockSignature(fork, genesisRoot,
                                                    slot, blockRoot,
                                                    beaconBlock)
        if res.isErr():
          error "Unable to sign block proposal using remote signer",
                validator = shortLog(validator), error_msg = res.error()
          return
        res.get()
      except CancelledError as exc:
        debug "Block signature processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while signing block",
            err_name = exc.name, err_msg = exc.msg
        return

    debug "Sending block",
      blockRoot = shortLog(blockRoot), blck = shortLog(beaconBlock),
      signature = shortLog(signature), validator = shortLog(validator)

    let res =
      try:
        let signedBlock = ForkedSignedBeaconBlock.init(beaconBlock, blockRoot,
                                                       signature)
        await vc.publishBlock(signedBlock, ApiStrategyKind.First)
      except ValidatorApiError:
        error "Unable to publish block",
              blockRoot = shortLog(blockRoot),
              blck = shortLog(beaconBlock),
              signature = shortLog(signature),
              validator = shortLog(validator),
              validator_index = validator.index.get(),
              wall_slot = currentSlot
        return
      except CancelledError as exc:
        debug "Publishing block processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while publishing block",
              err_name = exc.name, err_msg = exc.msg
        return
    if res:
      let delay = vc.getDelay(slot.block_deadline())
      beacon_blocks_sent.inc()
      beacon_blocks_sent_delay.observe(delay.toFloatSeconds())
      notice "Block published", blockRoot = shortLog(blockRoot),
             blck = shortLog(beaconBlock), signature = shortLog(signature),
             validator = shortLog(validator)
    else:
      warn "Block was not accepted by beacon node",
           blockRoot = shortLog(blockRoot),
           blck = shortLog(beaconBlock),
           signature = shortLog(signature),
           validator = shortLog(validator),
           wall_slot = currentSlot
  else:
    warn "Slashing protection activated for block proposal",
         blockRoot = shortLog(blockRoot), blck = shortLog(beaconBlock),
         signingRoot = shortLog(signingRoot),
         validator = shortLog(validator),
         wall_slot = currentSlot,
         existingProposal = notSlashable.error

proc proposeBlock(vc: ValidatorClientRef, slot: Slot,
                  proposerKey: ValidatorPubKey) {.async.} =
  let (inFuture, timeToSleep) = vc.beaconClock.fromNow(slot)
  try:
    if inFuture:
      debug "Proposing block", timeIn = timeToSleep,
                               validator = shortLog(proposerKey)
      await sleepAsync(timeToSleep)
    else:
      debug "Proposing block", timeIn = 0.seconds,
                               validator = shortLog(proposerKey)

    let sres = vc.getCurrentSlot()
    if sres.isSome():
      let
        currentSlot = sres.get()
        validator = vc.getValidator(proposerKey).valueOr: return
      await vc.publishBlock(currentSlot, slot, validator)
  except CancelledError as exc:
    debug "Block proposing was interrupted", slot = slot,
                                             validator = shortLog(proposerKey)
    raise exc

proc spawnProposalTask(vc: ValidatorClientRef,
                       duty: RestProposerDuty): ProposerTask =
  let future = proposeBlock(vc, duty.slot, duty.pubkey)
  ProposerTask(future: future, duty: duty)

proc contains(data: openArray[RestProposerDuty], task: ProposerTask): bool =
  for item in data:
    if (item.pubkey == task.duty.pubkey) and (item.slot == task.duty.slot):
      return true
  false

proc contains(data: openArray[ProposerTask], duty: RestProposerDuty): bool =
  for item in data:
    if (item.duty.pubkey == duty.pubkey) and (item.duty.slot == duty.slot):
      return true
  false

proc checkDuty(duty: RestProposerDuty, epoch: Epoch, slot: Slot): bool =
  let lastSlot = start_slot(epoch + 1'u64)
  if duty.slot >= slot:
    if duty.slot < lastSlot:
      true
    else:
      warn "Block proposal duty is in the far future, ignoring",
           duty_slot = duty.slot, validator = shortLog(duty.pubkey),
           wall_slot = slot, last_slot_in_epoch = (lastSlot - 1'u64)
      false
  else:
    warn "Block proposal duty is in the past, ignoring", duty_slot = duty.slot,
         validator = shortLog(duty.pubkey), wall_slot = slot
    false

proc addOrReplaceProposers*(vc: ValidatorClientRef, epoch: Epoch,
                            dependentRoot: Eth2Digest,
                            duties: openArray[RestProposerDuty]) =
  let default = ProposedData(epoch: Epoch(0xFFFF_FFFF_FFFF_FFFF'u64))
  let sres = vc.getCurrentSlot()
  if sres.isSome():
    let
      currentSlot = sres.get()
      epochDuties = vc.proposers.getOrDefault(epoch, default)
    if not(epochDuties.isDefault()):
      if epochDuties.dependentRoot != dependentRoot:
        warn "Proposer duties re-organization", duties_count = len(duties),
             wall_slot = currentSlot, epoch = epoch,
             prior_dependent_root = epochDuties.dependentRoot,
             dependent_root = dependentRoot, wall_slot = currentSlot
        let tasks =
          block:
            var res: seq[ProposerTask]
            var hashset = initHashSet[Slot]()

            for task in epochDuties.duties:
              if task notin duties:
                # Task is no more relevant, so cancel it.
                debug "Cancelling running proposal duty task",
                      slot = task.duty.slot,
                      validator = shortLog(task.duty.pubkey)
                task.future.cancel()
              else:
                # If task is already running for proper slot, we keep it alive.
                debug "Keep running previous proposal duty task",
                      slot = task.duty.slot,
                      validator = shortLog(task.duty.pubkey)
                res.add(task)

            for duty in duties:
              if duty notin res:
                debug "New proposal duty received", slot = duty.slot,
                      validator = shortLog(duty.pubkey)
                if checkDuty(duty, epoch, currentSlot):
                  let task = vc.spawnProposalTask(duty)
                  if duty.slot in hashset:
                    error "Multiple block proposers for this slot, " &
                          "producing blocks for all proposers", slot = duty.slot
                  else:
                    hashset.incl(duty.slot)
                  res.add(task)
            res
        vc.proposers[epoch] = ProposedData.init(epoch, dependentRoot, tasks)
    else:
      debug "New block proposal duties received",
            dependent_root = dependentRoot, duties_count = len(duties),
            wall_slot = currentSlot, epoch = epoch
      # Spawn new proposer tasks and modify proposers map.
      let tasks =
        block:
          var hashset = initHashSet[Slot]()
          var res: seq[ProposerTask]
          for duty in duties:
            debug "New proposal duty received", slot = duty.slot,
                  validator = shortLog(duty.pubkey)
            if checkDuty(duty, epoch, currentSlot):
              let task = vc.spawnProposalTask(duty)
              if duty.slot in hashset:
                error "Multiple block proposers for this slot, " &
                      "producing blocks for all proposers", slot = duty.slot
              else:
                hashset.incl(duty.slot)
              res.add(task)
          res
      vc.proposers[epoch] = ProposedData.init(epoch, dependentRoot, tasks)

proc waitForBlockPublished*(vc: ValidatorClientRef, slot: Slot) {.async.} =
  ## This procedure will wait for all the block proposal tasks to be finished at
  ## slot ``slot``
  let pendingTasks =
    block:
      var res: seq[Future[void]]
      let epochDuties = vc.proposers.getOrDefault(slot.epoch())
      for task in epochDuties.duties:
        if task.duty.slot == slot:
          if not(task.future.finished()):
            res.add(task.future)
      res
  if len(pendingTasks) > 0:
    try:
      await allFutures(pendingTasks)
    except CancelledError as exc:
      var pending: seq[Future[void]]
      for future in pendingTasks:
        if not(future.finished()):
          pending.add(future.cancelAndWait())
      await allFutures(pending)
      raise exc

