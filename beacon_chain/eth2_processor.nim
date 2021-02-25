# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[math, tables],
  stew/results,
  chronicles, chronos, metrics,
  ./spec/[crypto, datatypes, digest],
  ./block_pools/[clearance, chain_dag],
  ./attestation_aggregation, ./exit_pool, ./validator_pool,
  ./beacon_node_types, ./attestation_pool,
  ./time, ./conf, ./sszdump

# Metrics for tracking attestation and beacon block loss
declareCounter beacon_attestations_received,
  "Number of beacon chain attestations received by this peer"
declareCounter beacon_aggregates_received,
  "Number of beacon chain aggregate attestations received by this peer"
declareCounter beacon_blocks_received,
  "Number of beacon chain blocks received by this peer"
declareCounter beacon_attester_slashings_received,
  "Number of beacon chain attester slashings received by this peer"
declareCounter beacon_proposer_slashings_received,
  "Number of beacon chain proposer slashings received by this peer"
declareCounter beacon_voluntary_exits_received,
  "Number of beacon chain voluntary exits received by this peer"

declareCounter doppelganger_detection_activated,
  "Number of times doppelganger detection was activated"

const delayBuckets = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, Inf]

declareHistogram beacon_attestation_delay,
  "Time(s) between slot start and attestation reception", buckets = delayBuckets

declareHistogram beacon_aggregate_delay,
  "Time(s) between slot start and aggregate reception", buckets = delayBuckets

declareHistogram beacon_block_delay,
  "Time(s) between slot start and beacon block reception", buckets = delayBuckets

declareHistogram beacon_store_block_duration_seconds,
  "storeBlock() duration", buckets = [0.25, 0.5, 1, 2, 4, 8, Inf]

type
  GetWallTimeFn* = proc(): BeaconTime {.gcsafe, raises: [Defect].}

  SyncBlock* = object
    blk*: SignedBeaconBlock
    resfut*: Future[Result[void, BlockError]]

  BlockEntry* = object
    v*: SyncBlock

  AttestationEntry* = object
    v*: Attestation
    attesting_indices*: seq[ValidatorIndex]

  AggregateEntry* = AttestationEntry

  Eth2Processor* = object
    config*: BeaconNodeConf
    getWallTime*: GetWallTimeFn
    chainDag*: ChainDAGRef
    attestationPool*: ref AttestationPool
    exitPool: ref ExitPool
    validatorPool: ref ValidatorPool
    quarantine*: QuarantineRef
    expectedSlot: Slot
    expectedBlockReceived: Future[void]

    blocksQueue*: AsyncQueue[BlockEntry]
    attestationsQueue*: AsyncQueue[AttestationEntry]
    aggregatesQueue*: AsyncQueue[AggregateEntry]

    doppelgangerDetection*: DoppelgangerProtection

proc checkExpectedBlock(self: var Eth2Processor) =
  if self.expectedBlockReceived == nil:
    return

  if self.chainDag.head.slot < self.expectedSlot:
    return

  self.expectedBlockReceived.complete()
  self.expectedBlockReceived = nil # Don't keep completed futures around!

proc expectBlock*(self: var Eth2Processor, expectedSlot: Slot): Future[void] =
  ## Return a future that will complete when a head is selected whose slot is
  ## equal or greater than the given slot, or a new expectation is created
  if self.expectedBlockReceived != nil:
    # Reset the old future to not leave it hanging.. an alternative would be to
    # cancel it, but it doesn't make any practical difference for now
    self.expectedBlockReceived.complete()

  let fut = newFuture[void]("Eth2Processor.expectBlock")
  self.expectedSlot = expectedSlot
  self.expectedBlockReceived = fut

  # It might happen that by the time we're expecting a block, it might have
  # already been processed!
  self.checkExpectedBlock()

  return fut

proc updateHead*(self: var Eth2Processor, wallSlot: Slot) =
  ## Trigger fork choice and returns the new head block.
  ## Can return `nil`
  # Grab the new head according to our latest attestation data
  let newHead = self.attestationPool[].selectHead(wallSlot)
  if newHead.isNil():
    warn "Head selection failed, using previous head",
      head = shortLog(self.chainDag.head), wallSlot
    return

  # Store the new head in the chain DAG - this may cause epochs to be
  # justified and finalized
  let
    oldFinalized = self.chainDag.finalizedHead.blck

  self.chainDag.updateHead(newHead, self.quarantine)

  # Cleanup the fork choice v2 if we have a finalized head
  if oldFinalized != self.chainDag.finalizedHead.blck:
    self.attestationPool[].prune()

  self.checkExpectedBlock()

proc dumpBlock[T](
    self: Eth2Processor, signedBlock: SignedBeaconBlock,
    res: Result[T, (ValidationResult, BlockError)]) =
  if self.config.dumpEnabled and res.isErr:
    case res.error[1]
    of Invalid:
      dump(
        self.config.dumpDirInvalid, signedBlock)
    of MissingParent:
      dump(
        self.config.dumpDirIncoming, signedBlock)
    else:
      discard

proc done*(blk: SyncBlock) =
  ## Send signal to [Sync/Request]Manager that the block ``blk`` has passed
  ## verification successfully.
  if blk.resfut != nil:
    blk.resfut.complete(Result[void, BlockError].ok())

proc fail*(blk: SyncBlock, error: BlockError) =
  ## Send signal to [Sync/Request]Manager that the block ``blk`` has NOT passed
  ## verification with specific ``error``.
  if blk.resfut != nil:
    blk.resfut.complete(Result[void, BlockError].err(error))

proc complete*(blk: SyncBlock, res: Result[void, BlockError]) =
  ## Send signal to [Sync/Request]Manager about result ``res`` of block ``blk``
  ## verification.
  if blk.resfut != nil:
    blk.resfut.complete(res)

proc storeBlock(
    self: var Eth2Processor, signedBlock: SignedBeaconBlock,
    wallSlot: Slot): Result[void, BlockError] =
  let
    start = Moment.now()
    attestationPool = self.attestationPool

  let blck = self.chainDag.addRawBlock(self.quarantine, signedBlock) do (
      blckRef: BlockRef, trustedBlock: TrustedSignedBeaconBlock,
      epochRef: EpochRef, state: HashedBeaconState):
    # Callback add to fork choice if valid
    attestationPool[].addForkChoice(
      epochRef, blckRef, trustedBlock.message, wallSlot)

  self.dumpBlock(signedBlock, blck)

  # There can be a scenario where we receive a block we already received.
  # However this block was before the last finalized epoch and so its parent
  # was pruned from the ForkChoice.
  if blck.isErr:
    return err(blck.error[1])

  let duration = (Moment.now() - start).toFloatSeconds()
  beacon_store_block_duration_seconds.observe(duration)
  ok()

proc processAttestation(
    self: var Eth2Processor, entry: AttestationEntry) =
  logScope:
    signature = shortLog(entry.v.signature)

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing attestation before genesis, clock turned back?"
    quit 1

  trace "Processing attestation"
  self.attestationPool[].addAttestation(
    entry.v, entry.attesting_indices, wallSlot)

proc processAggregate(
    self: var Eth2Processor, entry: AggregateEntry) =
  logScope:
    signature = shortLog(entry.v.signature)

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing aggregate before genesis, clock turned back?"
    quit 1

  trace "Processing aggregate"
  self.attestationPool[].addAttestation(
    entry.v, entry.attesting_indices, wallSlot)

proc processBlock(self: var Eth2Processor, entry: BlockEntry) =
  logScope:
    blockRoot = shortLog(entry.v.blk.root)

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing block before genesis, clock turned back?"
    quit 1

  let
    start = now(chronos.Moment)
    res = self.storeBlock(entry.v.blk, wallSlot)
    storeDone = now(chronos.Moment)

  if res.isOk():
    # Eagerly update head in case the new block gets selected
    self.updateHead(wallSlot)

    let updateDone = now(chronos.Moment)
    let storeBlockDuration = storeDone - start
    let updateHeadDuration = updateDone - storeDone
    let overallDuration = updateDone - start
    let storeSpeed =
      block:
        let secs = float(chronos.seconds(1).nanoseconds)
        if not(overallDuration.isZero()):
          let v = secs / float(overallDuration.nanoseconds)
          round(v * 10_000) / 10_000
        else:
          0.0
    debug "Block processed",
      local_head_slot = self.chainDag.head.slot,
      store_speed = storeSpeed,
      block_slot = entry.v.blk.message.slot,
      store_block_duration = $storeBlockDuration,
      update_head_duration = $updateHeadDuration,
      overall_duration = $overallDuration

    if entry.v.resFut != nil:
      entry.v.resFut.complete(Result[void, BlockError].ok())
  elif res.error() in {BlockError.Duplicate, BlockError.Old}:
    # These are harmless / valid outcomes - for the purpose of scoring peers,
    # they are ok
    if entry.v.resFut != nil:
      entry.v.resFut.complete(Result[void, BlockError].ok())
  else:
    if entry.v.resFut != nil:
      entry.v.resFut.complete(Result[void, BlockError].err(res.error()))

{.pop.} # TODO AsyncQueue.addLast raises Exception in theory but not in practise

proc blockValidator*(
    self: var Eth2Processor,
    signedBlock: SignedBeaconBlock): ValidationResult =
  logScope:
    signedBlock = shortLog(signedBlock.message)
    blockRoot = shortLog(signedBlock.root)

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    return ValidationResult.Ignore  # not an issue with block, so don't penalize

  logScope: wallSlot

  let delay = wallTime - signedBlock.message.slot.toBeaconTime

  if signedBlock.root in self.chainDag.blocks:
    # The gossip algorithm itself already does one round of hashing to find
    # already-seen data, but it is fairly aggressive about forgetting about
    # what it has seen already
    debug "Dropping already-seen gossip block", delay
    return ValidationResult.Ignore  # "[IGNORE] The block is the first block ..."

  # Start of block processing - in reality, we have already gone through SSZ
  # decoding at this stage, which may be significant
  debug "Block received", delay

  let blck = self.chainDag.isValidBeaconBlock(
    self.quarantine, signedBlock, wallTime, {})

  self.dumpBlock(signedBlock, blck)

  if not blck.isOk:
    return blck.error[0]

  beacon_blocks_received.inc()
  beacon_block_delay.observe(delay.toFloatSeconds())

  # Block passed validation - enqueue it for processing. The block processing
  # queue is effectively unbounded as we use a freestanding task to enqueue
  # the block - this is done so that when blocks arrive concurrently with
  # sync, we don't lose the gossip blocks, but also don't block the gossip
  # propagation of seemingly good blocks
  trace "Block validated"
  asyncSpawn self.blocksQueue.addLast(
    BlockEntry(v: SyncBlock(blk: signedBlock)))

  ValidationResult.Accept

{.push raises: [Defect].}

proc checkForPotentialDoppelganger(
    self: var Eth2Processor, attestationData: AttestationData,
    attesterIndices: openArray[ValidatorIndex], wallSlot: Slot) =
  let epoch = wallSlot.epoch
  if epoch < self.doppelgangerDetection.broadcastStartEpoch:
    let tgtBlck = self.chainDag.getRef(attestationData.target.root)
    doAssert not tgtBlck.isNil  # because attestation is valid above

    let epochRef = self.chainDag.getEpochRef(
      tgtBlck, attestationData.target.epoch)
    for validatorIndex in attesterIndices:
      let validatorPubkey = epochRef.validator_keys[validatorIndex]
      if self.validatorPool[].getValidator(validatorPubkey) !=
          default(AttachedValidator):
        warn "Duplicate validator detected; would be slashed",
          validatorIndex,
          validatorPubkey
        doppelganger_detection_activated.inc()
        if self.config.doppelgangerDetection:
          warn "We believe you are currently running another instance of the same validator. We've disconnected you from the network as this presents a significant slashing risk. Possible next steps are (a) making sure you've disconnected your validator from your old machine before restarting the client; and (b) running the client again with the gossip-slashing-protection option disabled, only if you are absolutely sure this is the only instance of your validator running, and reporting the issue at https://github.com/status-im/nimbus-eth2/issues."
          quit QuitFailure

proc attestationValidator*(
    self: var Eth2Processor,
    attestation: Attestation,
    committeeIndex: uint64,
    checksExpensive: bool = true): ValidationResult =
  logScope:
    attestation = shortLog(attestation)
    committeeIndex

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    notice "Attestation before genesis"
    return ValidationResult.Ignore

  logScope: wallSlot

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - attestation.data.slot.toBeaconTime
  debug "Attestation received", delay
  let v = self.attestationPool[].validateAttestation(
      attestation, wallTime, committeeIndex, checksExpensive)
  if v.isErr():
    debug "Dropping attestation", err = v.error()
    return v.error[0]

  beacon_attestations_received.inc()
  beacon_attestation_delay.observe(delay.toFloatSeconds())

  self.checkForPotentialDoppelganger(attestation.data, v.value, wallSlot)

  while self.attestationsQueue.full():
    try:
      notice "Queue full, dropping attestation",
        dropped = shortLog(self.attestationsQueue[0].v)
      discard self.attestationsQueue.popFirstNoWait()
    except AsyncQueueEmptyError as exc:
      raiseAssert "If queue is full, we have at least one item! " & exc.msg

  trace "Attestation validated"
  try:
    self.attestationsQueue.addLastNoWait(
      AttestationEntry(v: attestation, attesting_indices: v.get()))
  except AsyncQueueFullError as exc:
    raiseAssert "We just checked that queue is not full! " & exc.msg

  ValidationResult.Accept

proc aggregateValidator*(
    self: var Eth2Processor,
    signedAggregateAndProof: SignedAggregateAndProof): ValidationResult =
  logScope:
    aggregate = shortLog(signedAggregateAndProof.message.aggregate)
    signature = shortLog(signedAggregateAndProof.signature)

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    notice "Aggregate before genesis"
    return ValidationResult.Ignore

  logScope: wallSlot

  # Potential under/overflows are fine; would just create odd logs
  let delay =
    wallTime - signedAggregateAndProof.message.aggregate.data.slot.toBeaconTime
  debug "Aggregate received", delay

  let v = self.attestationPool[].validateAggregate(
      signedAggregateAndProof, wallTime)
  if v.isErr:
    debug "Dropping aggregate",
      err = v.error,
      aggregator_index = signedAggregateAndProof.message.aggregator_index,
      selection_proof = signedAggregateAndProof.message.selection_proof,
      wallSlot
    return v.error[0]

  beacon_aggregates_received.inc()
  beacon_aggregate_delay.observe(delay.toFloatSeconds())

  self.checkForPotentialDoppelganger(
    signedAggregateAndProof.message.aggregate.data, v.value, wallSlot)

  while self.aggregatesQueue.full():
    try:
      notice "Queue full, dropping aggregate",
        dropped = shortLog(self.aggregatesQueue[0].v)
      discard self.aggregatesQueue.popFirstNoWait()
    except AsyncQueueEmptyError as exc:
      raiseAssert "We just checked that queue is not full! " & exc.msg

  trace "Aggregate validated",
    aggregator_index = signedAggregateAndProof.message.aggregator_index,
    selection_proof = signedAggregateAndProof.message.selection_proof,
    wallSlot

  try:
    self.aggregatesQueue.addLastNoWait(AggregateEntry(
      v: signedAggregateAndProof.message.aggregate,
      attesting_indices: v.get()))
  except AsyncQueueFullError as exc:
    raiseAssert "We just checked that queue is not full! " & exc.msg

  ValidationResult.Accept

proc attesterSlashingValidator*(
    self: var Eth2Processor, attesterSlashing: AttesterSlashing):
    ValidationResult =
  logScope:
    attesterSlashing = shortLog(attesterSlashing)

  let v = self.exitPool[].validateAttesterSlashing(attesterSlashing)
  if v.isErr:
    debug "Dropping attester slashing", err = v.error
    return v.error[0]

  beacon_attester_slashings_received.inc()

  ValidationResult.Accept

proc proposerSlashingValidator*(
    self: var Eth2Processor, proposerSlashing: ProposerSlashing):
    ValidationResult =
  logScope:
    proposerSlashing = shortLog(proposerSlashing)

  let v = self.exitPool[].validateProposerSlashing(proposerSlashing)
  if v.isErr:
    debug "Dropping proposer slashing", err = v.error
    return v.error[0]

  beacon_proposer_slashings_received.inc()

  ValidationResult.Accept

proc voluntaryExitValidator*(
    self: var Eth2Processor, signedVoluntaryExit: SignedVoluntaryExit):
    ValidationResult =
  logScope:
    signedVoluntaryExit = shortLog(signedVoluntaryExit)

  let v = self.exitPool[].validateVoluntaryExit(signedVoluntaryExit)
  if v.isErr:
    debug "Dropping voluntary exit", err = v.error
    return v.error[0]

  beacon_voluntary_exits_received.inc()

  ValidationResult.Accept

{.pop.} # TODO raises in chronos

proc runQueueProcessingLoop*(self: ref Eth2Processor) {.async.} =
  # Blocks in eth2 arrive on a schedule for every slot:
  #
  # * Block arrives at time 0
  # * Attestations arrives at time 4
  # * Aggregate arrives at time 8

  var
    blockFut = self[].blocksQueue.popFirst()
    aggregateFut = self[].aggregatesQueue.popFirst()
    attestationFut = self[].attestationsQueue.popFirst()

  while true:
    # Cooperative concurrency: one idle calculation step per loop - because
    # we run both networking and CPU-heavy things like block processing
    # on the same thread, we need to make sure that there is steady progress
    # on the networking side or we get long lockups that lead to timeouts.
    const
      # We cap waiting for an idle slot in case there's a lot of network traffic
      # taking up all CPU - we don't want to _completely_ stop processing blocks
      # in this case (attestations will get dropped) - doing so also allows us
      # to benefit from more batching / larger network reads when under load.
      idleTimeout = 10.milliseconds

      # Attestation processing is fairly quick and therefore done in batches to
      # avoid some of the `Future` overhead
      attestationBatch = 16

    discard await idleAsync().withTimeout(idleTimeout)

    # Avoid one more `await` when there's work to do
    if not (blockFut.finished or aggregateFut.finished or attestationFut.finished):
      trace "Waiting for processing work"
      await blockFut or aggregateFut or attestationFut

    # Only run one task per idle iteration, in priority order: blocks are needed
    # for all other processing - then come aggregates which are cheap to
    # process but might have a big impact on fork choice - last come
    # attestations which individually have the smallest effect on chain progress
    if blockFut.finished:
      self[].processBlock(blockFut.read())
      blockFut = self[].blocksQueue.popFirst()
    elif aggregateFut.finished:
      # aggregates will be dropped under heavy load on producer side
      self[].processAggregate(aggregateFut.read())
      for i in 0..<attestationBatch: # process a few at a time - this is fairly fast
        if self[].aggregatesQueue.empty():
          break
        self[].processAggregate(self[].aggregatesQueue.popFirstNoWait())

      aggregateFut = self[].aggregatesQueue.popFirst()
    elif attestationFut.finished:
      # attestations will be dropped under heavy load on producer side
      self[].processAttestation(attestationFut.read())

      for i in 0..<attestationBatch: # process a few at a time - this is fairly fast
        if self[].attestationsQueue.empty():
          break
        self[].processAttestation(self[].attestationsQueue.popFirstNoWait())

      attestationFut = self[].attestationsQueue.popFirst()

proc new*(T: type Eth2Processor,
          config: BeaconNodeConf,
          chainDag: ChainDAGRef,
          attestationPool: ref AttestationPool,
          exitPool: ref ExitPool,
          validatorPool: ref ValidatorPool,
          quarantine: QuarantineRef,
          getWallTime: GetWallTimeFn): ref Eth2Processor =
  (ref Eth2Processor)(
    config: config,
    getWallTime: getWallTime,
    chainDag: chainDag,
    attestationPool: attestationPool,
    exitPool: exitPool,
    validatorPool: validatorPool,
    quarantine: quarantine,
    blocksQueue: newAsyncQueue[BlockEntry](1),
    # limit to the max number of aggregates we expect to see in one slot
    aggregatesQueue: newAsyncQueue[AggregateEntry](
      (TARGET_AGGREGATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT).int),
    # This queue is a bit harder to bound reasonably - we want to get a good
    # spread of votes across committees - ideally at least TARGET_COMMITTEE_SIZE
    # per committee - assuming randomness in vote arrival, this limit should
    # cover that but of course, when votes arrive depends on a number of
    # factors that are not entire random
    attestationsQueue: newAsyncQueue[AttestationEntry](
      (TARGET_COMMITTEE_SIZE * MAX_COMMITTEES_PER_SLOT).int),
  )
