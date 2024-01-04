# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles,
  ".."/validators/activity_metrics,
  ".."/spec/forks,
  common, api, fallback_service

const
  ServiceName = "block_service"
  BlockPollInterval = attestationSlotOffset.nanoseconds div 4
  BlockPollOffset1 = TimeDiff(nanoseconds: BlockPollInterval)
  BlockPollOffset2 = TimeDiff(nanoseconds: BlockPollInterval * 2)
  BlockPollOffset3 = TimeDiff(nanoseconds: BlockPollInterval * 3)

logScope: service = ServiceName

type
  PreparedBeaconBlock = object
    blockRoot*: Eth2Digest
    data*: ForkedBeaconBlock
    kzgProofsOpt*: Opt[deneb.KzgProofs]
    blobsOpt*: Opt[deneb.Blobs]

  PreparedBlindedBeaconBlock = object
    blockRoot*: Eth2Digest
    data*: ForkedBlindedBeaconBlock

proc proposeBlock(vc: ValidatorClientRef, slot: Slot,
                  proposerKey: ValidatorPubKey) {.async.}

proc produceBlock(
       vc: ValidatorClientRef,
       currentSlot, slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes,
       validator: AttachedValidator
     ): Future[Opt[PreparedBeaconBlock]] {.async.} =
  logScope:
    slot = slot
    wall_slot = currentSlot
    validator = shortLog(validator)
  let
    produceBlockResponse =
      try:
        await vc.produceBlockV2(slot, randao_reveal, graffiti,
                                ApiStrategyKind.Best)
      except ValidatorApiError as exc:
        warn "Unable to retrieve block data", reason = exc.getFailureReason()
        return Opt.none(PreparedBeaconBlock)
      except CancelledError as exc:
        debug "Block data production has been interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while getting block data",
              error_name = exc.name, error_msg = exc.msg
        return Opt.none(PreparedBeaconBlock)
  case produceBlockResponse.kind
  of ConsensusFork.Phase0:
    let blck = produceBlockResponse.phase0Data
    return Opt.some(PreparedBeaconBlock(blockRoot: hash_tree_root(blck),
                                        data: ForkedBeaconBlock.init(blck),
                                        kzgProofsOpt: Opt.none(deneb.KzgProofs),
                                        blobsOpt: Opt.none(deneb.Blobs)))
  of ConsensusFork.Altair:
    let blck = produceBlockResponse.altairData
    return Opt.some(PreparedBeaconBlock(blockRoot: hash_tree_root(blck),
                                        data: ForkedBeaconBlock.init(blck),
                                        kzgProofsOpt: Opt.none(deneb.KzgProofs),
                                        blobsOpt: Opt.none(deneb.Blobs)))
  of ConsensusFork.Bellatrix:
    let blck = produceBlockResponse.bellatrixData
    return Opt.some(PreparedBeaconBlock(blockRoot: hash_tree_root(blck),
                                        data: ForkedBeaconBlock.init(blck),
                                        kzgProofsOpt: Opt.none(deneb.KzgProofs),
                                        blobsOpt: Opt.none(deneb.Blobs)))
  of ConsensusFork.Capella:
    let blck = produceBlockResponse.capellaData
    return Opt.some(PreparedBeaconBlock(blockRoot: hash_tree_root(blck),
                                        data: ForkedBeaconBlock.init(blck),
                                        kzgProofsOpt: Opt.none(deneb.KzgProofs),
                                        blobsOpt: Opt.none(deneb.Blobs)))
  of ConsensusFork.Deneb:
    let
      blck = produceBlockResponse.denebData.`block`
      kzgProofs = produceBlockResponse.denebData.kzg_proofs
      blobs = produceBlockResponse.denebData.blobs
    return Opt.some(PreparedBeaconBlock(blockRoot: hash_tree_root(blck),
                                        data: ForkedBeaconBlock.init(blck),
                                        kzgProofsOpt: Opt.some(kzgProofs),
                                        blobsOpt: Opt.some(blobs)))

proc produceBlindedBlock(
       vc: ValidatorClientRef,
       currentSlot, slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes,
       validator: AttachedValidator
     ): Future[Opt[PreparedBlindedBeaconBlock]] {.async.} =
  logScope:
    slot = slot
    wall_slot = currentSlot
    validator = shortLog(validator)
  let
    beaconBlock =
      try:
        await vc.produceBlindedBlock(slot, randao_reveal, graffiti,
                                     ApiStrategyKind.Best)
      except ValidatorApiError as exc:
        warn "Unable to retrieve blinded block data", error_msg = exc.msg,
             reason = exc.getFailureReason()
        return Opt.none(PreparedBlindedBeaconBlock)
      except CancelledError as exc:
        debug "Blinded block data production has been interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while getting blinded block data",
              error_name = exc.name, error_msg = exc.msg
        return Opt.none(PreparedBlindedBeaconBlock)
    blockRoot = withBlck(beaconBlock): hash_tree_root(forkyBlck)

  return Opt.some(
    PreparedBlindedBeaconBlock(blockRoot: blockRoot, data: beaconBlock))

proc lazyWait[T](fut: Future[T]) {.async.} =
  try:
    discard await fut
  except CatchableError:
    discard

proc prepareRandao(vc: ValidatorClientRef, slot: Slot,
                   proposerKey: ValidatorPubKey) {.async.} =
  if slot == GENESIS_SLOT:
    return

  let
    destSlot = slot - 1'u64
    destOffset = TimeDiff(nanoseconds: NANOSECONDS_PER_SLOT.int64 div 2)
    deadline = destSlot.start_beacon_time() + destOffset
    epoch = slot.epoch()
    # We going to wait to T - (T / 4 * 2), where T is proposer's
    # duty slot.
    currentSlot = (await vc.checkedWaitForSlot(destSlot, destOffset,
                   false)).valueOr:
      debug "Unable to perform RANDAO signature preparation because of " &
            "system time failure"
      return
    validator =
      vc.getValidatorForDuties(proposerKey, slot, true).valueOr: return

  if currentSlot <= destSlot:
    # We do not need result, because we want it to be cached.
    let
      start = Moment.now()
      genesisRoot = vc.beaconGenesis.genesis_validators_root
      fork = vc.forkAtEpoch(epoch)
      rsig = await validator.getEpochSignature(fork, genesisRoot, epoch)
      timeElapsed = Moment.now() - start
    if rsig.isErr():
      debug "Unable to prepare RANDAO signature", epoch = epoch,
            validator = shortLog(validator), elapsed_time = timeElapsed,
            current_slot = currentSlot, destination_slot = destSlot,
            delay = vc.getDelay(deadline)
    else:
      debug "RANDAO signature has been prepared", epoch = epoch,
            validator = shortLog(validator), elapsed_time = timeElapsed,
            current_slot = currentSlot, destination_slot = destSlot,
            delay = vc.getDelay(deadline)
  else:
    debug "RANDAO signature preparation timed out", epoch = epoch,
          validator = shortLog(validator),
          current_slot = currentSlot, destination_slot = destSlot,
          delay = vc.getDelay(deadline)

proc spawnProposalTask(vc: ValidatorClientRef,
                       duty: RestProposerDuty): ProposerTask =
  ProposerTask(
    randaoFut: prepareRandao(vc, duty.slot, duty.pubkey),
    proposeFut: proposeBlock(vc, duty.slot, duty.pubkey),
    duty: duty
  )

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
    wall_slot = currentSlot

  debug "Publishing block", delay = vc.getDelay(slot.block_deadline()),
                            genesis_root = genesisRoot,
                            graffiti = graffiti, fork = fork

  let
    randaoReveal =
      try:
        (await validator.getEpochSignature(fork, genesisRoot,
                                           slot.epoch())).valueOr:
          warn "Unable to generate RANDAO reveal using remote signer",
               reason = error
          return
      except CancelledError as exc:
        debug "RANDAO reveal production has been interrupted"
        raise exc
      except CatchableError as exc:
        error "An unexpected error occurred while receiving RANDAO data",
              error_name = exc.name, error_msg = exc.msg
        return

  var beaconBlocks =
    block:
      let blindedBlockFut =
        if vc.config.payloadBuilderEnable:
          vc.produceBlindedBlock(currentSlot, slot, randaoReveal, graffiti,
                                 validator)
        else:
          nil
      let normalBlockFut = vc.produceBlock(currentSlot, slot, randaoReveal,
                                           graffiti, validator)
      let blindedBlock =
        if isNil(blindedBlockFut):
          Opt.none(PreparedBlindedBeaconBlock)
        else:
          try:
            await blindedBlockFut
          except CancelledError as exc:
            if not(normalBlockFut.finished()):
              await normalBlockFut.cancelAndWait()
            raise exc
          except CatchableError:
            # This should not happen, because all the exceptions are handled.
            Opt.none(PreparedBlindedBeaconBlock)

      let normalBlock =
        if blindedBlock.isNone():
          try:
            await normalBlockFut
          except CancelledError as exc:
            raise exc
          except CatchableError:
            # This should not happen, because all the exceptions are handled.
            Opt.none(PreparedBeaconBlock)
        else:
          if not(normalBlockFut.finished()):
            asyncSpawn lazyWait(normalBlockFut)
          Opt.none(PreparedBeaconBlock)

      if blindedBlock.isNone() and normalBlock.isNone():
        return

      (blindedBlock: blindedBlock, normalBlock: normalBlock)

  if beaconBlocks.blindedBlock.isSome():
    let
      preparedBlock = beaconBlocks.blindedBlock.get()
      signingRoot = compute_block_signing_root(fork, genesisRoot, slot,
                                               preparedBlock.blockRoot)
      notSlashable = vc.attachedValidators[]
        .slashingProtection
        .registerBlock(vindex, validator.pubkey, slot, signingRoot)

    logScope:
      blck = shortLog(preparedBlock.data)
      block_root = shortLog(preparedBlock.blockRoot)
      signing_root = shortLog(signingRoot)

    if notSlashable.isOk():
      let
        signature =
          try:
            let res = await validator.getBlockSignature(fork, genesisRoot,
                                                        slot,
                                                        preparedBlock.blockRoot,
                                                        preparedBlock.data)
            if res.isErr():
              warn "Unable to sign blinded block proposal using remote signer",
                   reason = res.error()
              return
            res.get()
          except CancelledError as exc:
            debug "Blinded block signature process has been interrupted"
            raise exc
          except CatchableError as exc:
            error "An unexpected error occurred while signing blinded block",
                error_name = exc.name, error_msg = exc.msg
            return

      logScope:
        signature = shortLog(signature)

      let
        signedBlock = ForkedSignedBlindedBeaconBlock.init(preparedBlock.data,
                        preparedBlock.blockRoot, signature)
        res =
          try:
            debug "Sending blinded block"
            await vc.publishBlindedBlock(signedBlock, ApiStrategyKind.First)
          except ValidatorApiError as exc:
            warn "Unable to publish blinded block",
                 reason = exc.getFailureReason()
            return
          except CancelledError as exc:
            debug "Blinded block publication has been interrupted"
            raise exc
          except CatchableError as exc:
            error "An unexpected error occurred while publishing blinded block",
                  error_name = exc.name, error_msg = exc.msg
            return

      if res:
        let delay = vc.getDelay(slot.block_deadline())
        beacon_blocks_sent.inc()
        beacon_blocks_sent_delay.observe(delay.toFloatSeconds())
        notice "Blinded block published", delay = delay
      else:
        warn "Blinded block was not accepted by beacon node"
    else:
      warn "Slashing protection activated for blinded block proposal"
  else:
    let
      preparedBlock = beaconBlocks.normalBlock.get()
      signingRoot = compute_block_signing_root(fork, genesisRoot, slot,
                                               preparedBlock.blockRoot)
      notSlashable = vc.attachedValidators[]
        .slashingProtection
        .registerBlock(vindex, validator.pubkey, slot, signingRoot)

    logScope:
      blck = shortLog(preparedBlock.data)
      block_root = shortLog(preparedBlock.blockRoot)
      signing_root = shortLog(signingRoot)

    if notSlashable.isOk():
      let
        signature =
          try:
            let res = await validator.getBlockSignature(fork,
                                                        genesisRoot, slot,
                                                        preparedBlock.blockRoot,
                                                        preparedBlock.data)
            if res.isErr():
              warn "Unable to sign block proposal using remote signer",
                   reason = res.error()
              return
            res.get()
          except CancelledError as exc:
            debug "Block signature process has been interrupted"
            raise exc
          except CatchableError as exc:
            error "An unexpected error occurred while signing block",
                error_name = exc.name, error_msg = exc.msg
            return

        signedBlockContents =
          case preparedBlock.data.kind
          of ConsensusFork.Phase0:
            RestPublishedSignedBlockContents(kind: ConsensusFork.Phase0,
              phase0Data: phase0.SignedBeaconBlock(
                message: preparedBlock.data.phase0Data,
                root: preparedBlock.blockRoot,
                signature: signature))
          of ConsensusFork.Altair:
            RestPublishedSignedBlockContents(kind: ConsensusFork.Altair,
              altairData: altair.SignedBeaconBlock(
                message: preparedBlock.data.altairData,
                root: preparedBlock.blockRoot,
                signature: signature))
          of ConsensusFork.Bellatrix:
            RestPublishedSignedBlockContents(kind: ConsensusFork.Bellatrix,
              bellatrixData: bellatrix.SignedBeaconBlock(
                message: preparedBlock.data.bellatrixData,
                root: preparedBlock.blockRoot,
                signature: signature))
          of ConsensusFork.Capella:
            RestPublishedSignedBlockContents(kind: ConsensusFork.Capella,
              capellaData: capella.SignedBeaconBlock(
                message: preparedBlock.data.capellaData,
                root: preparedBlock.blockRoot,
                signature: signature))
          of ConsensusFork.Deneb:
            RestPublishedSignedBlockContents(kind: ConsensusFork.Deneb,
              denebData: DenebSignedBlockContents(
                signed_block: deneb.SignedBeaconBlock(
                  message: preparedBlock.data.denebData,
                  root: preparedBlock.blockRoot,
                  signature: signature),
                kzg_proofs: preparedBlock.kzgProofsOpt.get,
                blobs: preparedBlock.blobsOpt.get))

        res =
          try:
            debug "Sending block"
            await vc.publishBlock(signedBlockContents, ApiStrategyKind.First)
          except ValidatorApiError as exc:
            warn "Unable to publish block", reason = exc.getFailureReason()
            return
          except CancelledError as exc:
            debug "Block publication has been interrupted"
            raise exc
          except CatchableError as exc:
            error "An unexpected error occurred while publishing block",
                  error_name = exc.name, error_msg = exc.msg
            return

      if res:
        let delay = vc.getDelay(slot.block_deadline())
        beacon_blocks_sent.inc()
        beacon_blocks_sent_delay.observe(delay.toFloatSeconds())
        notice "Block published", delay = delay
      else:
        warn "Block was not accepted by beacon node"
    else:
      warn "Slashing protection activated for block proposal"

proc proposeBlock(vc: ValidatorClientRef, slot: Slot,
                  proposerKey: ValidatorPubKey) {.async.} =
  let
    currentSlot = (await vc.checkedWaitForSlot(slot, ZeroTimeDiff,
                                               false)).valueOr:
      error "Unable to perform block production because of system time"
      return

  if currentSlot > slot:
    warn "Skip block production for expired slot",
         current_slot = currentSlot, duties_slot = slot
    return

  let validator = vc.getValidatorForDuties(proposerKey, slot).valueOr: return

  try:
    await vc.publishBlock(currentSlot, slot, validator)
  except CancelledError as exc:
    debug "Block proposing process was interrupted",
          slot = slot, validator = shortLog(proposerKey)
    raise exc
  except CatchableError:
    error "Unexpected error encountered while proposing block",
          slot = slot, validator = shortLog(validator)

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
  let
    default = ProposedData(epoch: FAR_FUTURE_EPOCH)
    currentSlot = vc.getCurrentSlot().get(Slot(0))
    epochDuties = vc.proposers.getOrDefault(epoch, default)

  if not(epochDuties.isDefault()):
    if epochDuties.dependentRoot != dependentRoot:
      warn "Proposer duties re-organization", duties_count = len(duties),
           wall_slot = currentSlot, epoch = epoch,
           prior_dependent_root = epochDuties.dependentRoot,
           dependent_root = dependentRoot
      let tasks =
        block:
          var res: seq[ProposerTask]
          var hashset = initHashSet[Slot]()

          for task in epochDuties.duties:
            if task notin duties:
              # Task is no more relevant, so cancel it.
              debug "Cancelling running proposal duty tasks",
                    slot = task.duty.slot,
                    validator = shortLog(task.duty.pubkey)
              task.proposeFut.cancelSoon()
              task.randaoFut.cancelSoon()
            else:
              # If task is already running for proper slot, we keep it alive.
              debug "Keep running previous proposal duty tasks",
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

proc pollForEvents(service: BlockServiceRef, node: BeaconNodeServerRef,
                   response: RestHttpResponseRef) {.async.} =
  let vc = service.client

  logScope:
    node = node

  while true:
    let events =
      try:
        await response.getServerSentEvents()
      except RestError as exc:
        debug "Unable to receive server-sent event", reason = $exc.msg
        return
      except CancelledError as exc:
        raise exc
      except CatchableError as exc:
        warn "Got an unexpected error, " &
             "while reading server-sent event stream", reason = $exc.msg
        return

    for event in events:
      case event.name
      of "data":
        let blck = EventBeaconBlockObject.decodeString(event.data).valueOr:
          debug "Got invalid block event format", reason = error
          return
        vc.registerBlock(blck, node)
      of "event":
        if event.data != "block":
          debug "Got unexpected event name field", event_name = event.name,
                event_data = event.data
      else:
        debug "Got some unexpected event field", event_name = event.name

    if len(events) == 0:
      break

proc runBlockEventMonitor(service: BlockServiceRef,
                          node: BeaconNodeServerRef) {.async.} =
  let
    vc = service.client
    roles = {BeaconNodeRole.BlockProposalData}
    statuses = {RestBeaconNodeStatus.Synced}

  logScope:
    node = node

  while true:
    while node.status notin statuses:
      await vc.waitNodes(nil, statuses, roles, true)

    let response =
      block:
        var resp: HttpClientResponseRef
        try:
          resp = await node.client.subscribeEventStream({EventTopic.Block})
          if resp.status == 200:
            Opt.some(resp)
          else:
            let body = await resp.getBodyBytes()
            await resp.closeWait()
            let
              plain = RestPlainResponse(status: resp.status,
                        contentType: resp.contentType, data: body)
              reason = plain.getErrorMessage()
            debug "Unable to to obtain events stream", code = resp.status,
                  reason = reason
            Opt.none(HttpClientResponseRef)
        except RestError as exc:
          if not(isNil(resp)): await resp.closeWait()
          debug "Unable to obtain events stream", reason = $exc.msg
          Opt.none(HttpClientResponseRef)
        except CancelledError as exc:
          if not(isNil(resp)): await resp.closeWait()
          debug "Block monitoring loop has been interrupted"
          raise exc
        except CatchableError as exc:
          if not(isNil(resp)): await resp.closeWait()
          warn "Got an unexpected error while trying to establish event stream",
               reason = $exc.msg
          Opt.none(HttpClientResponseRef)

    if response.isSome():
      debug "Block monitoring connection has been established"
      try:
        await service.pollForEvents(node, response.get())
      except CancelledError as exc:
        raise exc
      except CatchableError as exc:
        warn "Got an unexpected error while receiving block events",
             reason = $exc.msg
      finally:
        debug "Block monitoring connection has been lost"
        await response.get().closeWait()

proc pollForBlockHeaders(service: BlockServiceRef, node: BeaconNodeServerRef,
                         slot: Slot, waitTime: Duration,
                         index: int): Future[bool] {.async.} =
  let vc = service.client

  logScope:
    node = node
    slot = slot
    wait_time = waitTime
    schedule_index = index

  trace "Polling for block header"

  let bres =
    try:
      await sleepAsync(waitTime)
      await node.client.getBlockHeader(BlockIdent.init(slot))
    except RestError as exc:
      debug "Unable to obtain block header",
            reason = $exc.msg, error = $exc.name
      return false
    except RestResponseError as exc:
      debug "Got an error while trying to obtain block header",
            reason = exc.message, status = exc.status
      return false
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      warn "Unexpected error encountered while receiving block header",
           reason = $exc.msg, error = $exc.name
      return false

  if bres.isNone():
    trace "Beacon node does not yet have block"
    return false

  let blockHeader = bres.get()

  let eventBlock = EventBeaconBlockObject(
    slot: blockHeader.data.header.message.slot,
    block_root: blockHeader.data.root,
    optimistic: blockHeader.execution_optimistic
  )
  vc.registerBlock(eventBlock, node)
  return true

proc runBlockPollMonitor(service: BlockServiceRef,
                         node: BeaconNodeServerRef) {.async.} =
  let
    vc = service.client
    roles = {BeaconNodeRole.BlockProposalData}
    statuses = {RestBeaconNodeStatus.Synced}

  logScope:
    node = node

  while true:
    let currentSlot =
      block:
        let res = await vc.checkedWaitForNextSlot(ZeroTimeDiff, false)
        if res.isNone(): continue
        res.geT()

    while node.status notin statuses:
      await vc.waitNodes(nil, statuses, roles, true)

    let
      currentTime = vc.beaconClock.now()
      afterSlot = currentTime.slotOrZero()

    if currentTime > afterSlot.attestation_deadline():
      # Attestation time already, lets wait for next slot.
      continue

    let
      pollTime1 = afterSlot.start_beacon_time() + BlockPollOffset1
      pollTime2 = afterSlot.start_beacon_time() + BlockPollOffset2
      pollTime3 = afterSlot.start_beacon_time() + BlockPollOffset3

    var pendingTasks =
      block:
        var res: seq[FutureBase]
        if currentTime <= pollTime1:
          let stime = nanoseconds((pollTime1 - currentTime).nanoseconds)
          res.add(FutureBase(
            service.pollForBlockHeaders(node, afterSlot, stime, 0)))
        if currentTime <= pollTime2:
          let stime = nanoseconds((pollTime2 - currentTime).nanoseconds)
          res.add(FutureBase(
            service.pollForBlockHeaders(node, afterSlot, stime, 1)))
        if currentTime <= pollTime3:
          let stime = nanoseconds((pollTime3 - currentTime).nanoseconds)
          res.add(FutureBase(
            service.pollForBlockHeaders(node, afterSlot, stime, 2)))
        res
    try:
      while true:
        let completedFuture = await race(pendingTasks)
        let blockReceived =
          block:
            var res = false
            for future in pendingTasks:
              if not(future.completed()): continue
              if not(cast[Future[bool]](future).read()): continue
              res = true
              break
            res
        if blockReceived:
          let pending =
            pendingTasks.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
          # We use `noCancel` here because its cleanup and we have `break`
          # after it.
          await noCancel allFutures(pending)
          break
        pendingTasks.keepItIf(it != completedFuture)
        if len(pendingTasks) == 0: break
    except CancelledError as exc:
      let pending =
        pendingTasks.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
      await noCancel allFutures(pending)
      raise exc
    except CatchableError as exc:
      warn "An unexpected error occurred while running block monitoring",
           reason = $exc.msg, error = $exc.name

proc runBlockMonitor(service: BlockServiceRef) {.async.} =
  let
    vc = service.client
    blockNodes = vc.filterNodes(ResolvedBeaconNodeStatuses,
                                {BeaconNodeRole.BlockProposalData})
  let pendingTasks =
    case vc.config.monitoringType
    of BlockMonitoringType.Disabled:
      debug "Block monitoring disabled"
      @[newFuture[void]("block.monitor.disabled")]
    of BlockMonitoringType.Poll:
      var res: seq[Future[void]]
      for node in blockNodes:
        res.add(service.runBlockPollMonitor(node))
      res
    of BlockMonitoringType.Event:
      var res: seq[Future[void]]
      for node in blockNodes:
        res.add(service.runBlockEventMonitor(node))
      res

  try:
    await allFutures(pendingTasks)
  except CancelledError as exc:
    let pending =
      pendingTasks.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
    await noCancel allFutures(pending)
    raise exc
  except CatchableError as exc:
    warn "An unexpected error occurred while running block monitoring",
         reason = $exc.msg, error = $exc.name
    return

proc mainLoop(service: BlockServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"
  let future = service.runBlockMonitor()
  try:
    # Future is not going to be completed, so the only way to exit, is to
    # cancel it.
    await future
  except CancelledError:
    debug "Service interrupted"
  except CatchableError as exc:
    error "Service crashed with unexpected error", err_name = exc.name,
          err_msg = exc.msg

  # We going to cleanup all the pending proposer tasks.
  var res: seq[FutureBase]
  for epoch, data in vc.proposers.pairs():
    for duty in data.duties.items():
      if not(duty.proposeFut.finished()):
        res.add(duty.proposeFut.cancelAndWait())
      if not(duty.randaoFut.finished()):
        res.add(duty.randaoFut.cancelAndWait())
  await noCancel allFutures(res)

proc init*(t: typedesc[BlockServiceRef],
           vc: ValidatorClientRef): Future[BlockServiceRef] {.async.} =
  logScope: service = ServiceName
  var res = BlockServiceRef(name: ServiceName, client: vc,
                            state: ServiceState.Initialized)
  debug "Initializing service"
  return res

proc start*(service: BlockServiceRef) =
  service.lifeFut = mainLoop(service)
