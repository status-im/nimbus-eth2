# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/sequtils,
  chronicles,
  metrics,
  ../spec/[network, peerdas_helpers],
  ../consensus_object_pools/spec_cache,
  ../gossip_processing/eth2_processor,
  ../networking/eth2_network,
  ./activity_metrics,
  ../spec/datatypes/deneb
export eth2_processor, eth2_network

logScope:
  topics = "message_router"

declareCounter beacon_voluntary_exits_sent,
  "Number of beacon voluntary sent by this node"

declareCounter beacon_attester_slashings_sent,
  "Number of beacon attester slashings sent by this node"

declareCounter beacon_proposer_slashings_sent,
  "Number of beacon proposer slashings sent by this node"

type
  MessageRouter* = object
    ## The message router is responsible for routing messages produced by
    ## attached validators or received via REST.
    ##
    ## Message routing does 3 things:
    ##
    ## * perform a "quick" sanity check of the message similar to gossip
    ##   processing - regardless where the message comes from, this check is
    ##   done so as to protect the internal state of the beacon node
    ## * broadcast the message to the network - in general, the aim is to start
    ##   the broadcasting as soon as possible without risking that the node
    ##   gets descored
    ## * update the internal state of the beacon node with the data in the
    ##   message - for example add a block to the dag or an attestation to the
    ##   attestation pool and fork choice - as a consequence, the message will
    ##   also be published to event subscribers
    ##
    ## Because the message router produces messages that will be gossiped, we
    ## run the messages through the same validation as incoming gossip messages.
    ##
    ## In most cases, processing of valid messages is identical to that done
    ## for gossip - blocks in particular however skip the queue.

    processor*: ref Eth2Processor
    network*: Eth2Node

    # TODO this belongs somewhere else, ie sync committee pool
    onSyncCommitteeMessage*: proc(slot: Slot) {.gcsafe, raises: [].}

  NoSidecarsAtFork* = typeof(())
  SomeSidecarsToRoute* =
    NoSidecarsAtFork |
    Opt[seq[BlobSidecar]] |
    Opt[seq[fulu.DataColumnSidecar]] |
    Opt[seq[gloas.DataColumnSidecar]]

  SomeOptSidecars =
    NoSidecars | Opt[BlobSidecars] | Opt[fulu.DataColumnSidecars] |
    Opt[gloas.DataColumnSidecars]

const noSidecarsAtFork* = default(NoSidecarsAtFork)

func isGoodForSending(validationResult: ValidationRes): bool =
  # When routing messages from REST, it's possible that these have already
  # been received via gossip (because they might have been sent to multiple
  # beacon nodes, as is the case with Vouch) - thus, we treat `IGNORE`
  # as success as far as further processing goes. `libp2p` however will not
  # re-broadcast the message as it already exists in its cache.
  validationResult.isOk() or
    validationResult.error[0] == ValidationResult.Ignore

template dag(router: MessageRouter): ChainDAGRef =
  router.processor[].dag
template quarantine(router: MessageRouter): ref Quarantine =
  router.processor[].quarantine
template blockProcessor(router: MessageRouter): ref BlockProcessor =
  router.processor[].blockProcessor
template getCurrentBeaconTime(router: MessageRouter): BeaconTime =
  router.processor[].getCurrentBeaconTime()

type RouteBlockResult = Result[Opt[BlockRef], string]

proc validateRouteBlock(
    router: ref MessageRouter,
    blck: ForkySignedBeaconBlock,
    checkValidator: bool
): Result[void,string] =

  let wallTime = router[].getCurrentBeaconTime()

  # proposer ownership checks
  let vindex = ValidatorIndex(blck.message.proposer_index)
  if checkValidator and (vindex in router.processor.validatorPool[]):
    warn "A validator client attempts to send a block from validator that is also managed by beacon node",
         validator_index = vindex
    return err("Block was not sent from validator that is also managed by the beacon node")

  # gossip validation
  let res = validateBeaconBlock(router[].dag, router[].quarantine, blck, wallTime, {})
  if not res.isGoodForSending():
    warn "Block failed validation",
      blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
      signature = shortLog(blck.signature), error = res.error()
    return err($(res.error()[1]))

  ok()

proc publishRouteBlock(
    router: ref MessageRouter,
    blck: ForkySignedBeaconBlock
): Future[void] {.async: (raises: [CancelledError]).} =
  let
    sendTime = router[].getCurrentBeaconTime()
    delay = sendTime - blck.message.slot.block_deadline(router[].dag.timeParams)
    res = await router[].network.broadcastBeaconBlock(blck)

  if res.isErr():
    notice "Block not sent",
      blockRoot = shortLog(blck.root),
      blck = shortLog(blck.message),
      signature = shortLog(blck.signature),
      error = res.error()
    return

  beacon_blocks_sent.inc()
  beacon_blocks_sent_delay.observe(delay.toFloatSeconds())

  notice "Block sent",
    blockRoot = shortLog(blck.root),
    blck = shortLog(blck.message),
    signature = shortLog(blck.signature),
    delay

proc publishSidecars(
    router: ref MessageRouter,
    blck: gloas.SignedBeaconBlock,
    sidecarsOpt: Opt[seq[gloas.DataColumnSidecar]]
): Future[Opt[gloas.DataColumnSidecars]] {.async: (raises: [CancelledError]).} =
  let cols = sidecarsOpt.get()
  var workers = newSeq[Future[SendResult]](len(cols))

  for i, dc in cols:
    let subnet = compute_subnet_for_data_column_sidecar(dc.index)
    workers[i] = router[].network.broadcastDataColumnSidecar(subnet, dc)

  let resAll = await allFinished(workers)

  for i in 0..<resAll.len:
    let r = resAll[i]
    doAssert r.finished()
    if r.failed():
      notice "Data column not sent",
        data_column = shortLog(cols[i]), error = r.error[]
    else:
      notice "Data column sent",
        data_column = shortLog(cols[i])

  # Custody filtering
  let metadata = router[].network.metadata.custody_group_count
  let allowed =
    router[].network.cfg.resolve_columns_from_custody_groups(
      router[].network.nodeId, metadata)

  var finalCols: gloas.DataColumnSidecars
  for dc in cols:
    if dc.index in allowed:
      finalCols.add newClone(dc)

  Opt.some(finalCols)

proc publishSidecars(
    router: ref MessageRouter,
    blck: fulu.SignedBeaconBlock,
    sidecarsOpt: Opt[seq[fulu.DataColumnSidecar]]
): Future[Opt[fulu.DataColumnSidecars]] {.async: (raises: [CancelledError]).} =
  let cols = sidecarsOpt.get()
  var workers = newSeq[Future[SendResult]](len(cols))

  for i, dc in cols:
    let subnet = compute_subnet_for_data_column_sidecar(dc.index)
    workers[i] = router[].network.broadcastDataColumnSidecar(subnet, dc)

  let resAll = await allFinished(workers)

  for i in 0..<resAll.len:
    let r = resAll[i]
    doAssert r.finished()
    if r.failed():
      notice "Data column not sent",
        data_column = shortLog(cols[i]), error = r.error[]
    else:
      notice "Data column sent",
        data_column = shortLog(cols[i])

  # Custody filtering
  let metadata = router[].network.metadata.custody_group_count
  let allowed =
    router[].network.cfg.resolve_columns_from_custody_groups(
      router[].network.nodeId, metadata)

  var finalCols: fulu.DataColumnSidecars
  for dc in cols:
    if dc.index in allowed:
      finalCols.add newClone(dc)

  Opt.some(finalCols)

proc publishSidecars*(
    router: ref MessageRouter,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock,
    sidecarsOpt: Opt[seq[BlobSidecar]]
): Future[Opt[BlobSidecars]] {.async: (raises: [CancelledError]).} =
  let blobs = sidecarsOpt.get()
  var workers = newSeq[Future[SendResult]](len(blobs))

  for i, blob in blobs:
    let subnet =
      router[].processor[].dag.cfg.compute_subnet_for_blob_sidecar(
        blck.message.slot, i.BlobIndex)
    workers[i] = router[].network.broadcastBlobSidecar(subnet, blob)

  let resAll = await allFinished(workers)

  for i in 0..<resAll.len:
    let r = resAll[i]
    doAssert r.finished()
    if r.failed():
      notice "Blob not sent",
        blob = shortLog(blobs[i]), error = r.error[]
    else:
      notice "Blob sent",
        blob = shortLog(blobs[i])

  # Convert to seq[ref BlobSidecar]
  var finalBlobs: BlobSidecars
  for blob in blobs:
    finalBlobs.add newClone(blob)

  Opt.some(finalBlobs)

proc addRoutedBlock(
    router: ref MessageRouter,
    blck: ForkySignedBeaconBlock,
    sidecarsOpt: SomeOptSidecars
): Future[RouteBlockResult] {.async: (raises: [CancelledError]).} =

  # The boolean we return tells the caller whether the block was integrated
  # into the chain
  let added =
    await router[].blockProcessor.addBlock(
      MsgSource.api, blck, sidecarsOpt)

  if added.isErr():
    return
      # If it's duplicate, there's an existing BlockRef to return. The block
      # shouldn't be finalized already because that requires a couple epochs
      # before occurring, so only check non-finalized resolved blockrefs.
      if added.error() != VerifierError.Duplicate:
        warn "Unable to add routed block to block pool",
          blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
          signature = shortLog(blck.signature), err = added.error()
        ok(Opt.none(BlockRef))
      else:
        let blockRef = router[].dag.getBlockRef(blck.root)
        if blockRef.isErr:
          warn "Unable to add routed duplicate block to block pool",
            blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
            signature = shortLog(blck.signature), err = added.error()
        ok(blockRef)

  let blockRef = router[].dag.getBlockRef(blck.root)
  if blockRef.isErr:
    warn "Block finalised while waiting for block processor",
      blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
      signature = shortLog(blck.signature)

  ok(blockRef)

proc routeSignedBeaconBlock*(
    router: ref MessageRouter,
    blck: ForkySignedBeaconBlock,
    someSidecarsOpt: SomeSidecarsToRoute,
    checkValidator: bool
): Future[RouteBlockResult] {.async: (raises: [CancelledError]).} =

  # 1. Validate
  ? router.validateRouteBlock(blck, checkValidator)

  # 2. Publish block
  await router.publishRouteBlock(blck)

  # 3. Publish sidecars
  when someSidecarsOpt is NoSidecarsAtFork:
    const finalSidecars = noSidecars
  else:
    let finalSidecars = await publishSidecars(router, blck, someSidecarsOpt)

  # 4. Add block to DAG
  return await router.addRoutedBlock(blck, finalSidecars)

proc routeAttestation*(
    router: ref MessageRouter,
    attestation: phase0.Attestation | SingleAttestation,
    subnet_id: SubnetId, checkSignature, checkValidator: bool):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  ## Process and broadcast attestation - processing will register the it with
  ## the attestation pool
  block:
    let
      wallTime = router[].processor.getCurrentBeaconTime()
      wallEpoch = wallTime.slotOrZero(router[].dag.timeParams).epoch
      currentFork = router[].dag.cfg.consensusForkAtEpoch(wallEpoch)
      res = await router[].processor.processAttestation(
        MsgSource.api, attestation, subnet_id,
        checkSignature = checkSignature, checkValidator = checkValidator,
        currentFork)

    if not res.isGoodForSending:
      warn "Attestation failed validation",
        attestation = shortLog(attestation), error = res.error()
      return err(res.error()[1])

  let
    sendTime = router[].processor.getCurrentBeaconTime()
    slot = attestation.data.slot
    delay = sendTime - slot.attestation_deadline(router[].dag.timeParams)
    res = await router[].network.broadcastAttestation(subnet_id, attestation)

  if res.isOk():
    beacon_attestations_sent.inc()
    beacon_attestation_sent_delay.observe(delay.toFloatSeconds())

    info "Attestation sent",
      attestation = shortLog(attestation), delay, subnet_id
  else: # "no broadcast" is not a fatal error
    notice "Attestation not sent",
      attestation = shortLog(attestation), error = res.error()

  return ok()

proc routeAttestation*(
    router: ref MessageRouter,
    attestation: phase0.Attestation | SingleAttestation,
    on_chain: static bool = false):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  # Compute subnet, then route attestation
  let
    target = router[].dag.getBlockRef(attestation.data.target.root).valueOr:
      notice "Attempt to send attestation for unknown target",
            attestation = shortLog(attestation)
      return err(
        "Attempt to send attestation for unknown target")

    shufflingRef = router[].dag.getShufflingRef(
        target, attestation.data.target.epoch, false).valueOr:
      warn "Cannot construct EpochRef for attestation, skipping send - report bug",
        target = shortLog(target),
        attestation = shortLog(attestation)
      return
    committee_index =
      shufflingRef.get_committee_index(attestation.committee_index(on_chain)).valueOr:
        notice "Invalid committee index in attestation",
          attestation = shortLog(attestation)
        return err("Invalid committee index in attestation")
    subnet_id = compute_subnet_for_attestation(
      get_committee_count_per_slot(shufflingRef), attestation.data.slot,
      committee_index)

  return await router.routeAttestation(
    attestation, subnet_id, checkSignature = true, checkValidator = true)

proc routeSignedAggregateAndProof*(
    router: ref MessageRouter,
    proof: phase0.SignedAggregateAndProof | electra.SignedAggregateAndProof,
    checkSignature = true):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  ## Validate and broadcast aggregate
  block:
    # Because the aggregate was (most likely) produced by this beacon node,
    # we already know all attestations in it - we skip the coverage check so
    # that all processing happens anyway
    let
      wallTime = router[].processor.getCurrentBeaconTime()
      wallEpoch = wallTime.slotOrZero(router[].dag.timeParams).epoch
      currentFork = router[].dag.cfg.consensusForkAtEpoch(wallEpoch)
      res = await router[].processor.processSignedAggregateAndProof(
        MsgSource.api, proof, checkSignature = checkSignature,
        checkCover = false, currentFork)
    if not res.isGoodForSending:
      warn "Aggregated attestation failed validation",
        attestation = shortLog(proof.message.aggregate),
        aggregator_index = proof.message.aggregator_index,
        signature = shortLog(proof.signature), error = res.error()
      return err(res.error()[1])

  let
    sendTime = router[].processor.getCurrentBeaconTime()
    slot = proof.message.aggregate.data.slot
    delay = sendTime - slot.aggregate_deadline(router[].dag.timeParams)
    res = await router[].network.broadcastAggregateAndProof(proof)

  if res.isOk():
    beacon_aggregates_sent.inc()

    info "Aggregated attestation sent",
      attestation = shortLog(proof.message.aggregate),
      aggregator_index = proof.message.aggregator_index,
      selection_proof = shortLog(proof.message.selection_proof),
      signature = shortLog(proof.signature), delay
  else: # "no broadcast" is not a fatal error
    notice "Aggregated attestation not sent",
      attestation = shortLog(proof.message.aggregate),
      aggregator_index = proof.message.aggregator_index,
      signature = shortLog(proof.signature), error = res.error()

  return ok()

proc routeSyncCommitteeMessage*(
    router: ref MessageRouter, msg: SyncCommitteeMessage,
    subcommitteeIdx: SyncSubcommitteeIndex,
    checkSignature: bool):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  block:
    let res = await router[].processor.processSyncCommitteeMessage(
      MsgSource.api, msg, subcommitteeIdx, checkSignature)

    if not res.isGoodForSending:
      warn "Sync committee message failed validation",
        message = shortLog(msg), error = res.error()
      return err(res.error()[1])

  let
    sendTime = router[].processor.getCurrentBeaconTime()
    delay = sendTime -
      msg.slot.sync_committee_message_deadline(router[].dag.timeParams)

    res = await router[].network.broadcastSyncCommitteeMessage(
      msg, subcommitteeIdx)

  if res.isOk():
    beacon_sync_committee_messages_sent.inc()
    beacon_sync_committee_message_sent_delay.observe(delay.toFloatSeconds())

    info "Sync committee message sent", message = shortLog(msg), delay
  else: # "no broadcast" is not a fatal error
    notice "Sync committee message not sent",
      message = shortLog(msg), error = res.error()

  if router[].onSyncCommitteeMessage != nil:
    router[].onSyncCommitteeMessage(msg.slot)

  return ok()

proc routeSyncCommitteeMessages*(
    router: ref MessageRouter, msgs: seq[SyncCommitteeMessage]):
    Future[seq[SendResult]] {.async: (raises: [CancelledError]).} =
  return withState(router[].dag.headState):
    when consensusFork >= ConsensusFork.Altair:
      var statuses = newSeq[Opt[SendResult]](len(msgs))

      let
        curPeriod = sync_committee_period(forkyState.data.slot)
        nextPeriod = curPeriod + 1

      let (keysCur, keysNxt) =
        block:
          var resCur: Table[uint64, int]
          var resNxt: Table[uint64, int]

          for index, msg in msgs:
            if msg.validator_index < lenu64(forkyState.data.validators):
              let msgPeriod = sync_committee_period(msg.slot + 1)
              if msgPeriod == curPeriod:
                resCur[msg.validator_index] = index
              elif msgPeriod == nextPeriod:
                resNxt[msg.validator_index] = index
              else:
                statuses[index] = Opt.some(
                  SendResult.err("Message's slot out of state's head range"))
            else:
              statuses[index] = Opt.some(
                SendResult.err("Incorrect validator's index"))
          if (len(resCur) == 0) and (len(resNxt) == 0):
            return statuses.mapIt(it.get())
          (resCur, resNxt)

      let (pending, indices) = block:
        var resFutures: seq[Future[SendResult]]
        var resIndices: seq[int]
        template headSyncCommittees(): auto = router[].dag.headSyncCommittees
        for subcommitteeIdx in SyncSubcommitteeIndex:
          for valKey in syncSubcommittee(
              headSyncCommittees.current_sync_committee, subcommitteeIdx):
            let index = keysCur.getOrDefault(uint64(valKey), -1)
            if index >= 0:
              resIndices.add(index)
              resFutures.add(router.routeSyncCommitteeMessage(
                msgs[index], subcommitteeIdx, true))
        for subcommitteeIdx in SyncSubcommitteeIndex:
          for valKey in syncSubcommittee(
              headSyncCommittees.next_sync_committee, subcommitteeIdx):
            let index = keysNxt.getOrDefault(uint64(valKey), -1)
            if index >= 0:
              resIndices.add(index)
              resFutures.add(router.routeSyncCommitteeMessage(
                msgs[index], subcommitteeIdx, true))
        (resFutures, resIndices)

      await allFutures(pending)

      for index, future in pending:
        if future.completed():
          let fres = future.value()
          if fres.isErr():
            statuses[indices[index]] = Opt.some(SendResult.err(fres.error()))
          else:
            statuses[indices[index]] = Opt.some(SendResult.ok())
        elif future.failed() or future.cancelled():
          let exc = future.error()
          debug "Unexpected failure while sending committee message",
            message = msgs[indices[index]], error = $exc.msg
          statuses[indices[index]] = Opt.some(SendResult.err(
            "Unexpected failure while sending committee message"))

      var res: seq[SendResult]
      for item in statuses:
        if item.isSome():
          res.add(item.get())
        else:
          res.add(SendResult.err("Message validator not in sync committee"))
      res
    else:
      var res: seq[SendResult]
      for _ in msgs:
        res.add(SendResult.err("Waiting for altair fork"))
      res

proc routeSignedContributionAndProof*(
    router: ref MessageRouter,
    msg: SignedContributionAndProof,
    checkSignature: bool):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  block:
    let res = await router[].processor.processSignedContributionAndProof(
      MsgSource.api, msg)
    if not res.isGoodForSending:
      warn "Contribution failed validation",
        contribution = shortLog(msg.message.contribution),
        aggregator_index = msg.message.aggregator_index,
        selection_proof = shortLog(msg.message.selection_proof),
        signature = shortLog(msg.signature), error = res.error()
      return err(res.error()[1])

  let
    sendTime = router[].processor.getCurrentBeaconTime()
    slot = msg.message.contribution.slot
    delay = sendTime - slot.sync_contribution_deadline(router[].dag.timeParams)

  let res = await router[].network.broadcastSignedContributionAndProof(msg)
  if res.isOk():
    beacon_sync_committee_contributions_sent.inc()
    info "Contribution sent",
      contribution = shortLog(msg.message.contribution),
      aggregator_index = msg.message.aggregator_index,
      selection_proof = shortLog(msg.message.selection_proof),
      signature = shortLog(msg.signature), delay
  else: # "no broadcast" is not a fatal error
    notice "Contribution not sent",
      contribution = shortLog(msg.message.contribution),
      aggregator_index = msg.message.aggregator_index,
      selection_proof = shortLog(msg.message.selection_proof),
      signature = shortLog(msg.signature), error = res.error()

  return ok()

proc routeSignedVoluntaryExit*(
    router: ref MessageRouter, exit: SignedVoluntaryExit):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  block:
    let res =
      router[].processor[].processSignedVoluntaryExit(MsgSource.api, exit)
    if not res.isGoodForSending:
      warn "Voluntary exit failed validation",
        exit = shortLog(exit), error = res.error()
      return err(res.error()[1])

  let res = await router[].network.broadcastVoluntaryExit(exit)
  if res.isOk():
    beacon_voluntary_exits_sent.inc()
    notice "Voluntary exit sent", exit = shortLog(exit)
  else: # "no broadcast" is not a fatal error
    notice "Voluntary exit not sent", exit = shortLog(exit), error = res.error()

  return ok()

proc routeAttesterSlashing*(
    router: ref MessageRouter,
    slashing: phase0.AttesterSlashing | electra.AttesterSlashing):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  block:
    let res =
      router[].processor[].processAttesterSlashing(MsgSource.api, slashing)
    if not res.isGoodForSending:
      warn "Attester slashing failed validation",
        slashing = shortLog(slashing), error = res.error()
      return err(res.error()[1])

  let res = await router[].network.broadcastAttesterSlashing(slashing)
  if res.isOk():
    beacon_attester_slashings_sent.inc()
    notice "Attester slashing sent", slashing = shortLog(slashing)
  else: # "no broadcast" is not a fatal error
    notice "Attester slashing not sent",
      slashing = shortLog(slashing), error = res.error()

  return ok()

proc routeProposerSlashing*(
    router: ref MessageRouter, slashing: ProposerSlashing):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  block:
    let res =
      router[].processor[].processProposerSlashing(MsgSource.api, slashing)
    if not res.isGoodForSending:
      warn "Proposer slashing request failed validation",
        slashing = shortLog(slashing), error = res.error()
      return err(res.error()[1])

  let res = await router[].network.broadcastProposerSlashing(slashing)
  if res.isOk():
    beacon_proposer_slashings_sent.inc()
    notice "Proposer slashing sent", slashing = shortLog(slashing)
  else: # "no broadcast" is not a fatal error
    notice "Proposer slashing not sent",
      slashing = shortLog(slashing), error = res.error()

  return ok()

proc routeBlsToExecutionChange*(
    router: ref MessageRouter,
    bls_to_execution_change: SignedBLSToExecutionChange):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  block:
    let res = await router.processor.processBlsToExecutionChange(
      MsgSource.api, bls_to_execution_change)
    if not res.isGoodForSending:
      warn "BLS to execution change request failed validation",
            change = shortLog(bls_to_execution_change),
            error = res.error()
      return err(res.error()[1])

  let wallEpoch =
    router[].getCurrentBeaconTime().slotOrZero(router[].dag.timeParams).epoch
  if wallEpoch < router[].dag.cfg.CAPELLA_FORK_EPOCH:
    # Broadcast hasn't failed, it just hasn't happened; desire seems to be to
    # allow queuing up BLS to execution changes.
    return ok()

  let res = await router[].network.broadcastBlsToExecutionChange(
    bls_to_execution_change)
  if res.isOk():
    notice "BLS to execution change sent",
      bls_to_execution_change = shortLog(bls_to_execution_change)
  else: # "no broadcast" is not a fatal error
    notice "BLS to execution change not sent",
      bls_to_execution_change = shortLog(bls_to_execution_change),
      error = res.error()

  return ok()

proc routePayloadAttestationMessage*(
    router: ref MessageRouter,
    message: PayloadAttestationMessage,
    checkSignature = true, checkValidator = true):
    Future[SendResult] {.async: (raises: [CancelledError]).} =
  block:
    let res = await router.processor.processPayloadAttestationMessage(
      MsgSource.api, message, checkSignature = checkSignature,
      checkValidator = checkValidator)

    if not res.isGoodForSending:
      warn "Payload attestation failed validation",
        message = shortLog(message), error = res.error()
      return err(res.error()[1])

  let
    sendTime = router[].processor.getCurrentBeaconTime()
    slot = message.data.slot
    delay = sendTime -
      slot.payload_attestation_deadline(router[].dag.timeParams)
    res = await router[].network.broadcastPayloadAttestationMessage(message)

  if res.isOk():
    info "Payload attestation sent",
      message = shortLog(message), delay
  else:
    notice "Payload attestation not sent",
      message = shortLog(message), error = res.error()

  return ok()

proc routeExecutionPayloadEnvelope*(
    router: ref MessageRouter,
    signedEnvelope: gloas.SignedExecutionPayloadEnvelope,
    checkValidator: bool
): Future[SendResult] {.async: (raises: [CancelledError]).} =
  block:
    let res = router[].processor[].processExecutionPayloadEnvelope(
      MsgSource.api, signedEnvelope)

    if not res.isGoodForSending:
      warn "Execution payload envelope failed validation",
        envelope = shortLog(signedEnvelope.message),
        error = res.error()
      return err(res.error()[1])

  let res =
    await router[].network.broadcastExecutionPayloadEnvelope(signedEnvelope)

  if res.isOk():
    info "Execution payload envelope sent",
      envelope = shortLog(signedEnvelope.message)
  else:
    notice "Execution payload envelope not sent",
      envelope = shortLog(signedEnvelope.message),
      error = res.error()

  return ok()
