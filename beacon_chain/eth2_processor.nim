import
  std/[math, tables],
  stew/results,
  chronicles, chronicles/chronos_tools, chronos, metrics,
  ./spec/[crypto, datatypes, digest],
  ./block_pools/[clearance, chain_dag],
  ./attestation_aggregation, ./exit_pool,
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
    attesting_indices*: HashSet[ValidatorIndex]

  AggregateEntry* = AttestationEntry

  Eth2Processor* = object
    config*: BeaconNodeConf
    getWallTime*: GetWallTimeFn
    chainDag*: ChainDAGRef
    attestationPool*: ref AttestationPool
    exitPool: ref ExitPool
    quarantine*: QuarantineRef
    blockReceivedDuringSlot*: Future[void]

    blocksQueue*: AsyncQueue[BlockEntry]
    attestationsQueue*: AsyncQueue[AttestationEntry]
    aggregatesQueue*: AsyncQueue[AggregateEntry]

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
    oldHead = self.chainDag.head

  self.chainDag.updateHead(newHead, self.quarantine)

  # Cleanup the fork choice v2 if we have a finalized head
  if oldFinalized != self.chainDag.finalizedHead.blck:

    self.attestationPool[].prune()

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
      blckRef: BlockRef, signedBlock: SignedBeaconBlock,
      epochRef: EpochRef, state: HashedBeaconState):
    # Callback add to fork choice if valid
    attestationPool[].addForkChoice(
      epochRef, blckRef, signedBlock.message, wallSlot)

  # Trigger attestation sending
  if blck.isOk and not self.blockReceivedDuringSlot.finished:
    self.blockReceivedDuringSlot.complete()

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
  traceAsyncErrors self.blocksQueue.addLast(
    BlockEntry(v: SyncBlock(blk: signedBlock)))

  ValidationResult.Accept

proc attestationValidator*(
    self: var Eth2Processor,
    attestation: Attestation,
    committeeIndex: uint64): ValidationResult =
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
      attestation, wallTime, committeeIndex)
  if v.isErr():
    debug "Dropping attestation", err = v.error()
    return v.error[0]

  beacon_attestations_received.inc()
  beacon_attestation_delay.observe(delay.toFloatSeconds())

  while self.attestationsQueue.full():
    let dropped = self.attestationsQueue.popFirst()
    doAssert dropped.finished, "popFirst sanity"
    notice "Queue full, dropping attestation",
      dropped = shortLog(dropped.read().v)

  trace "Attestation validated"
  traceAsyncErrors self.attestationsQueue.addLast(
    AttestationEntry(v: attestation, attesting_indices: v.get()))

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
    debug "Dropping aggregate", err = v.error
    return v.error[0]

  beacon_aggregates_received.inc()
  beacon_aggregate_delay.observe(delay.toFloatSeconds())

  while self.aggregatesQueue.full():
    let dropped = self.aggregatesQueue.popFirst()
    doAssert dropped.finished, "popFirst sanity"
    notice "Queue full, dropping aggregate",
      dropped = shortLog(dropped.read().v)

  trace "Aggregate validated"
  traceAsyncErrors self.aggregatesQueue.addLast(AggregateEntry(
    v: signedAggregateAndProof.message.aggregate,
    attesting_indices: v.get()))

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
    trace "Waiting for processing work"
    await blockFut or aggregateFut or attestationFut

    while blockFut.finished:
      # TODO await here _hopefully_ yields to the event loop allowing another
      #      queue put to complete
      self[].processBlock(await blockFut)
      blockFut = self[].blocksQueue.popFirst()

    if aggregateFut.finished:
      self[].processAggregate(await aggregateFut)
      aggregateFut = self[].aggregatesQueue.popFirst()
      continue

    if attestationFut.finished:
      self[].processAttestation(await attestationFut)
      attestationFut = self[].attestationsQueue.popFirst()
      continue

proc new*(T: type Eth2Processor,
          config: BeaconNodeConf,
          chainDag: ChainDAGRef,
          attestationPool: ref AttestationPool,
          exitPool: ref ExitPool,
          quarantine: QuarantineRef,
          getWallTime: GetWallTimeFn): ref Eth2Processor =
  (ref Eth2Processor)(
    config: config,
    getWallTime: getWallTime,
    chainDag: chainDag,
    attestationPool: attestationPool,
    exitPool: exitPool,
    quarantine: quarantine,
    blockReceivedDuringSlot: newFuture[void](),
    blocksQueue: newAsyncQueue[BlockEntry](1),
    aggregatesQueue: newAsyncQueue[AggregateEntry](MAX_ATTESTATIONS.int),
    attestationsQueue: newAsyncQueue[AttestationEntry](TARGET_COMMITTEE_SIZE.int * 4),
  )
