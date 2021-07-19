import common, api
import chronicles

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
    fork = vc.fork.get()

  debug "Publishing block", validator = shortLog(validator),
                            delay = vc.getDelay(ZeroDuration),
                            wall_slot = currentSlot,
                            genesis_root = genesisRoot,
                            graffiti = graffiti, fork = fork, slot = slot,
                            wall_slot = currentSlot
  try:
    let randaoReveal = await validator.genRandaoReveal(fork, genesisRoot, slot)
    let beaconBlock =
      try:
        await vc.produceBlock(slot, randaoReveal, graffiti)
      except ValidatorApiError:
        error "Unable to retrieve block data", slot = slot,
              wall_slot = currentSlot, validator = shortLog(validator)
        return
      except CatchableError as exc:
        error "An unexpected error occurred while getting block data",
              err_name = exc.name, err_msg = exc.msg
        return

    let blockRoot = hash_tree_root(beaconBlock)
    var signedBlock = SignedBeaconBlock(message: beaconBlock,
                                        root: hash_tree_root(beaconBlock))

    # TODO: signing_root is recomputed in signBlockProposal just after
    let signing_root = compute_block_root(fork, genesisRoot, slot,
                                          signedBlock.root)
    let notSlashable = vc.attachedValidators
      .slashingProtection
      .registerBlock(ValidatorIndex(signedBlock.message.proposer_index),
                     validator.pubKey, slot, signing_root)

    if notSlashable.isOk():
      let signature = await validator.signBlockProposal(fork, genesisRoot, slot,
                                                        blockRoot)
      let signedBlock = SignedBeaconBlock(message: beaconBlock, root: blockRoot,
                                          signature: signature)
      let res =
        try:
          await vc.publishBlock(signedBlock)
        except ValidatorApiError:
          error "Unable to publish block", blck = shortLog(signedBlock.message),
                blockRoot = shortLog(blockRoot),
                validator = shortLog(validator),
                validator_index = validator.index.get(),
                wall_slot = currentSlot
          return
        except CatchableError as exc:
          error "An unexpected error occurred while publishing block",
                err_name = exc.name, err_msg = exc.msg
          return
      if res:
        notice "Block published", blck = shortLog(signedBlock.message),
          blockRoot = shortLog(blockRoot), validator = shortLog(validator),
          validator_index = validator.index.get()
      else:
        warn "Block was not accepted by beacon node",
          blck = shortLog(signedBlock.message),
          blockRoot = shortLog(blockRoot),
          validator = shortLog(validator),
          validator_index = validator.index.get(),
          wall_slot = currentSlot
    else:
      warn "Slashing protection activated for block proposal",
           blck = shortLog(beaconBlock), blockRoot = shortLog(blockRoot),
           validator = shortLog(validator),
           validator_index = validator.index.get(),
           wall_slot = currentSlot,
           existingProposal = notSlashable.error
  except CatchableError as exc:
    error "Unexpected error happens while proposing block",
          error_name = exc.name, error_msg = exc.msg

proc proposeBlock(vc: ValidatorClientRef, slot: Slot,
                  proposerKey: ValidatorPubkey) {.async.} =
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
      let currentSlot = sres.get()
      let validator =
        block:
          let res = vc.getValidator(proposerKey)
          if res.isNone():
            return
          res.get()
      await vc.publishBlock(currentSlot, slot, validator)

  except CancelledError:
    debug "Proposing task was cancelled", slot = slot,
                                          validator = shortLog(proposerKey)

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
  let lastSlot = compute_start_slot_at_epoch(epoch + 1'u64)
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
    await allFutures(pendingTasks)
