# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/results,
  std/sequtils,
  chronicles,
  metrics,
  ../spec/network,
  ../consensus_object_pools/spec_cache,
  ../gossip_processing/eth2_processor,
  ../networking/eth2_network,
  ./activity_metrics,
  ../spec/datatypes/deneb
from  ../spec/state_transition_block import validate_blobs

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

type RouteBlockResult = Result[Opt[BlockRef], cstring]
proc routeSignedBeaconBlock*(
    router: ref MessageRouter, blck: ForkySignedBeaconBlock,
    blobsOpt: Opt[seq[BlobSidecar]]): Future[RouteBlockResult] {.async.} =
  ## Validate and broadcast beacon block, then add it to the block database
  ## Returns the new Head when block is added successfully to dag, none when
  ## block passes validation but is not added, and error otherwise
  let wallTime = router[].getCurrentBeaconTime()

  # Start with a quick gossip validation check such that broadcasting the
  # block doesn't get the node into trouble
  block:
    let res = validateBeaconBlock(
      router[].dag, router[].quarantine, blck, wallTime, {})

    if not res.isGoodForSending():
      warn "Block failed validation",
        blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
        signature = shortLog(blck.signature), error = res.error()
      return err(res.error()[1])

    when typeof(blck).kind >= ConsensusFork.Deneb:
      if blobsOpt.isSome:
        let blobs = blobsOpt.get()
        let kzgCommits = blck.message.body.blob_kzg_commitments.asSeq
        if blobs.len > 0 or kzgCommits.len > 0:
          let res = validate_blobs(kzgCommits, blobs.mapIt(it.blob),
                                   blobs.mapIt(it.kzg_proof))
          if res.isErr():
            warn "blobs failed validation",
              blockRoot = shortLog(blck.root),
              blobs = shortLog(blobs),
              blck = shortLog(blck.message),
              signature = shortLog(blck.signature),
              msg = res.error()
            return err(res.error())

  let
    sendTime = router[].getCurrentBeaconTime()
    delay = sendTime - blck.message.slot.block_deadline()
    # The block (and blobs, if present) passed basic gossip validation
    # - we can "safely" broadcast it now. In fact, per the spec, we
    # should broadcast it even if it later fails to apply to our
    # state.

  let res = await router[].network.broadcastBeaconBlock(blck)

  if res.isOk():
    beacon_blocks_sent.inc()
    beacon_blocks_sent_delay.observe(delay.toFloatSeconds())

    notice "Block sent",
      blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
      signature = shortLog(blck.signature), delay
  else: # "no broadcast" is not a fatal error
    notice "Block not sent",
      blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
      signature = shortLog(blck.signature), error = res.error()

  var blobRefs = Opt.none(BlobSidecars)
  if blobsOpt.isSome():
    let blobs = blobsOpt.get()
    var workers = newSeq[Future[SendResult]](blobs.len)
    for i in 0..<blobs.lenu64:
      let subnet_id = compute_subnet_for_blob_sidecar(i)
      workers[i] = router[].network.broadcastBlobSidecar(subnet_id, blobs[i])
    let allres = await allFinished(workers)
    for i in 0..<allres.len:
      let res = allres[i]
      doAssert res.finished()
      if res.failed():
        notice "Blob not sent",
          blob = shortLog(blobs[i]), error = res.error[]
      else:
        notice "Blob sent", blob = shortLog(blobs[i])
    blobRefs = Opt.some(blobs.mapIt(newClone(it)))

  let added = await router[].blockProcessor[].addBlock(
    MsgSource.api, ForkedSignedBeaconBlock.init(blck), blobRefs)

  # The boolean we return tells the caller whether the block was integrated
  # into the chain
  if added.isErr():
    return if added.error() != VerifierError.Duplicate:
      warn "Unable to add routed block to block pool",
        blockRoot = shortLog(blck.root), blck = shortLog(blck.message),
        signature = shortLog(blck.signature), err = added.error()
      ok(Opt.none(BlockRef))
    else:
      # If it's duplicate, there's an existing BlockRef to return. The block
      # shouldn't be finalized already because that requires a couple epochs
      # before occurring, so only check non-finalized resolved blockrefs.
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

proc routeAttestation*(
    router: ref MessageRouter, attestation: Attestation,
    subnet_id: SubnetId, checkSignature: bool): Future[SendResult] {.async.} =
  ## Process and broadcast attestation - processing will register the it with
  ## the attestation pool
  block:
    let res = await router[].processor.processAttestation(
      MsgSource.api, attestation, subnet_id, checkSignature)

    if not res.isGoodForSending:
      warn "Attestation failed validation",
        attestation = shortLog(attestation), error = res.error()
      return err(res.error()[1])

  let
    sendTime = router[].processor.getCurrentBeaconTime()
    delay = sendTime - attestation.data.slot.attestation_deadline()
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
    router: ref MessageRouter, attestation: Attestation):
    Future[SendResult] {.async.} =
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
      shufflingRef.get_committee_index(attestation.data.index).valueOr:
        notice "Invalid committee index in attestation",
          attestation = shortLog(attestation)
        return err("Invalid committee index in attestation")
    subnet_id = compute_subnet_for_attestation(
      get_committee_count_per_slot(shufflingRef), attestation.data.slot,
      committee_index)

  return await router.routeAttestation(
    attestation, subnet_id, checkSignature = true)

proc routeSignedAggregateAndProof*(
    router: ref MessageRouter, proof: SignedAggregateAndProof,
    checkSignature = true):
    Future[SendResult] {.async.} =
  ## Validate and broadcast aggregate
  block:
    # Because the aggregate was (most likely) produced by this beacon node,
    # we already know all attestations in it - we skip the coverage check so
    # that all processing happens anyway
    let res = await router[].processor.processSignedAggregateAndProof(
      MsgSource.api, proof, checkSignature = checkSignature,
      checkCover = false)
    if not res.isGoodForSending:
      warn "Aggregated attestation failed validation",
        attestation = shortLog(proof.message.aggregate),
        aggregator_index = proof.message.aggregator_index,
        signature = shortLog(proof.signature), error = res.error()
      return err(res.error()[1])

  let
    sendTime = router[].processor.getCurrentBeaconTime()
    delay = sendTime - proof.message.aggregate.data.slot.aggregate_deadline()
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
    checkSignature: bool): Future[SendResult] {.async.} =
  block:
    let res = await router[].processor.processSyncCommitteeMessage(
      MsgSource.api, msg, subcommitteeIdx, checkSignature)

    if not res.isGoodForSending:
      warn "Sync committee message failed validation",
        message = shortLog(msg), error = res.error()
      return err(res.error()[1])

  let
    sendTime = router[].processor.getCurrentBeaconTime()
    delay = sendTime - msg.slot.sync_committee_message_deadline()

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
    Future[seq[SendResult]] {.async.} =
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
          let fres = future.read()
          if fres.isErr():
            statuses[indices[index]] = Opt.some(SendResult.err(fres.error()))
          else:
            statuses[indices[index]] = Opt.some(SendResult.ok())
        elif future.failed() or future.cancelled():
          let exc = future.readError()
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
    checkSignature: bool): Future[SendResult] {.async.} =
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
    delay = sendTime - msg.message.contribution.slot.sync_contribution_deadline()

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
    Future[SendResult] {.async.} =
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
    router: ref MessageRouter, slashing: AttesterSlashing):
    Future[SendResult] {.async.} =
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
    Future[SendResult] {.async.} =
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
    Future[SendResult] {.async.} =
  block:
    let res = await router.processor.processBlsToExecutionChange(
      MsgSource.api, bls_to_execution_change)
    if not res.isGoodForSending:
      warn "BLS to execution change request failed validation",
            change = shortLog(bls_to_execution_change),
            error = res.error()
      return err(res.error()[1])

  if  router[].getCurrentBeaconTime().slotOrZero.epoch <
      router[].processor[].dag.cfg.CAPELLA_FORK_EPOCH:
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
