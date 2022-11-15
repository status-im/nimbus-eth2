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

type
  SlashingForkedSignedBeaconBlock = object
    signing_root*: Eth2Digest
    data*: ForkedSignedBeaconBlock

  SlashingForkedSignedBlindedBeaconBlock = object
    signing_root*: Eth2Digest
    data*: ForkedSignedBlindedBeaconBlock

proc produceBlock(
       vc: ValidatorClientRef,
       genesis_root: Eth2Digest,
       fork: Fork,
       currentSlot, slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes,
       validator: AttachedValidator
     ): Future[Opt[SlashingForkedSignedBeaconBlock]] {.async.} =
  logScope:
    slot = slot
    wall_slot = currentSlot
    validator = shortLog(validator)
  let
    beaconBlock =
      try:
        await vc.produceBlockV2(slot, randao_reveal, graffiti,
                                ApiStrategyKind.Best)
      except ValidatorApiError:
        error "Unable to retrieve block data"
        return Opt.none(SlashingForkedSignedBeaconBlock)
      except CancelledError as exc:
        error "Block data processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while getting block data",
              error_name = exc.name, error_msg = exc.msg
        return Opt.none(SlashingForkedSignedBeaconBlock)
    blockRoot = withBlck(beaconBlock): hash_tree_root(blck)
    signingRoot = compute_block_signing_root(fork, genesis_root, slot,
                                             blockRoot)
    signature =
      try:
        let res = await validator.getBlockSignature(signingRoot, fork,
                                                    genesis_root, slot,
                                                    blockRoot,
                                                    beaconBlock)
        if res.isErr():
          error "Unable to sign block proposal using remote signer",
                error_msg = res.error()
          return Opt.none(SlashingForkedSignedBeaconBlock)
        res.get()
      except CancelledError as exc:
        debug "Block signature processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while signing block",
            error_name = exc.name, error_msg = exc.msg
        return Opt.none(SlashingForkedSignedBeaconBlock)
    signedBeaconBlock = SlashingForkedSignedBeaconBlock(
      data: ForkedSignedBeaconBlock.init(beaconBlock, blockRoot, signature),
      signing_root: signing_root
    )
  return Opt.some(signedBeaconBlock)

proc produceBlindedBlock(
       vc: ValidatorClientRef,
       genesis_root: Eth2Digest,
       fork: Fork,
       currentSlot, slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes,
       validator: AttachedValidator
     ): Future[Opt[SlashingForkedSignedBlindedBeaconBlock]] {.async.} =
  logScope:
    slot = slot
    wall_slot = currentSlot
    validator = shortLog(validator)
  let
    beaconBlock =
      try:
        await vc.produceBlindedBlock(slot, randao_reveal, graffiti,
                                     ApiStrategyKind.Best)
      except ValidatorApiError:
        error "Unable to retrieve blinded block data"
        return Opt.none(SlashingForkedSignedBlindedBeaconBlock)
      except CancelledError as exc:
        error "Blinded block data processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while getting blinded block data",
              error_name = exc.name, error_msg = exc.msg
        return Opt.none(SlashingForkedSignedBlindedBeaconBlock)
    blockRoot = withBlck(beaconBlock): hash_tree_root(blck)
    signingRoot = compute_block_signing_root(fork, genesis_root, slot,
                                             blockRoot)
    signature =
      try:
        let res = await validator.getBlockSignature(signingRoot, fork,
                                                    genesis_root, slot,
                                                    blockRoot,
                                                    beaconBlock)
        if res.isErr():
          error "Unable to sign blinded block proposal using remote signer",
                error_msg = res.error()
          return Opt.none(SlashingForkedSignedBlindedBeaconBlock)
        res.get()
      except CancelledError as exc:
        debug "Blinded block signature processing was interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while signing blinded block",
            error_name = exc.name, error_msg = exc.msg
        return Opt.none(SlashingForkedSignedBlindedBeaconBlock)
    signedBeaconBlock = SlashingForkedSignedBlindedBeaconBlock(
      data: ForkedSignedBlindedBeaconBlock.init(beaconBlock, blockRoot,
                                                signature),
      signing_root: signing_root
    )
  return Opt.some(signedBeaconBlock)

proc lazyWait[T](fut: Future[T]) {.async.} =
  try:
    discard await fut
  except CatchableError:
    discard

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

  logScope:
    validator = shortLog(validator)
    validator_index = vindex
    slot = slot

  if not(vc.doppelgangerCheck(validator)):
    info "Block has not been produced (doppelganger check still active)"
    return

  debug "Publishing block", delay = vc.getDelay(slot.block_deadline()),
                            genesis_root = genesisRoot,
                            graffiti = graffiti, fork = fork,
                            wall_slot = currentSlot
  let randaoReveal =
    try:
      let res = await validator.getEpochSignature(fork, genesisRoot, slot.epoch)
      if res.isErr():
        error "Unable to generate randao reveal usint remote signer",
              error_msg = res.error()
        return
      res.get()
    except CancelledError as exc:
      error "Randao reveal processing was interrupted"
      raise exc
    except CatchableError as exc:
      error "An unexpected error occurred while receiving randao data",
            error_name = exc.name, error_msg = exc.msg
      return

  var beaconBlocks =
    block:
      let blindedBlockFut =
        if vc.config.payloadBuilderEnable:
          vc.produceBlindedBlock(genesisRoot, fork, currentSlot, slot,
                                 randaoReveal, graffiti, validator)
        else:
          nil
      let normalBlockFut = vc.produceBlock(genesisRoot, fork, currentSlot, slot,
                                           randaoReveal, graffiti, validator)
      let blindedBlock =
        if isNil(blindedBlockFut):
          Opt.none(SlashingForkedSignedBlindedBeaconBlock)
        else:
          try:
            await blindedBlockFut
          except CancelledError as exc:
            if not(normalBlockFut.finished()):
              await normalBlockFut.cancelAndWait()
            raise exc
          except CatchableError as exc:
            # This should not be happened, because all the exceptions handled.
            Opt.none(SlashingForkedSignedBlindedBeaconBlock)

      let normalBlock =
        if blindedBlock.isNone():
          try:
            await normalBlockFut
          except CancelledError as exc:
            raise exc
          except CatchableError as exc:
            # This should not be happened, because all the exceptions handled.
            Opt.none(SlashingForkedSignedBeaconBlock)
        else:
          if not(normalBlockFut.finished()):
            asyncSpawn lazyWait(normalBlockFut)
          Opt.none(SlashingForkedSignedBeaconBlock)

      if blindedBlock.isNone() and normalBlock.isNone():
        return

      (blindedBlock: blindedBlock, normalBlock: normalBlock)

  let notSlashable =
    if beaconBlocks.blindedBlock.isSome():
      let signingRoot = beaconBlocks.blindedBlock.get().signing_root
      vc.attachedValidators[]
      .slashingProtection
      .registerBlock(vindex, validator.pubkey, slot, signingRoot)
    else:
      let signingRoot = beaconBlocks.normalBlock.get().signing_root
      vc.attachedValidators[]
      .slashingProtection
      .registerBlock(vindex, validator.pubkey, slot, signingRoot)

  if notSlashable.isOk():
    if beaconBlocks.blindedBlock.isSome():
      let slashyBlock = beaconBlocks.blindedBlock.get()
      logScope:
        signed_block = shortLog(slashyBlock.data)
        wall_slot = currentSlot

      let res =
        try:
          debug "Sending blinded block"
          await vc.publishBlindedBlock(slashyBlock.data, ApiStrategyKind.First)
        except ValidatorApiError:
          error "Unable to publish blinded block"
          return
        except CancelledError as exc:
          debug "Publishing block processing was interrupted"
          raise exc
        except CatchableError as exc:
          error "An unexpected error occurred while publishing block",
                error_name = exc.name, error_msg = exc.msg
          return

      if res:
        let delay = vc.getDelay(slot.block_deadline())
        beacon_blocks_sent.inc()
        beacon_blocks_sent_delay.observe(delay.toFloatSeconds())
        notice "Blinded block published"
      else:
        warn "Blinded block was not accepted by beacon node"
    else:
      let signedBlock = beaconBlocks.normalBlock.get().data
      logScope:
        signed_block = shortLog(signedBlock)
        wall_slot = currentSlot

      let res =
        try:
          debug "Sending block"
          await vc.publishBlock(signedBlock, ApiStrategyKind.First)
        except ValidatorApiError:
          error "Unable to publish block"
          return
        except CancelledError as exc:
          debug "Publishing block processing was interrupted"
          raise exc
        except CatchableError as exc:
          error "An unexpected error occurred while publishing block",
                error_name = exc.name, error_msg = exc.msg
          return

      if res:
        let delay = vc.getDelay(slot.block_deadline())
        beacon_blocks_sent.inc()
        beacon_blocks_sent_delay.observe(delay.toFloatSeconds())
        notice "Block published"
      else:
        warn "Block was not accepted by beacon node"
  else:
    if beaconBlocks.blindedBlock.isSome():
      let signedBlock = beaconBlocks.blindedBlock.get()
      warn "Slashing protection activated for block proposal",
           # blck = shortLog(signedBlock),
           # signingRoot = shortLog(signedBlock.signing_root),
           wall_slot = currentSlot,
           existingProposal = notSlashable.error()
    else:
      let signedBlock = beaconBlocks.normalBlock.get()
      warn "Slashing protection activated for block proposal",
           blck = shortLog(signedBlock.data),
           signingRoot = shortLog(signedBlock.signing_root),
           wall_slot = currentSlot,
           existingProposal = notSlashable.error()

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
