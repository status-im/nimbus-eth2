import
  std/[math, tables],
  stew/results,
  chronicles, chronicles/chronos_tools, chronos, metrics,
  ./spec/[crypto, datatypes, digest],
  ./block_pools/[clearance, chain_dag],
  ./attestation_aggregation,
  ./beacon_node_types, ./attestation_pool,
  ./time, ./conf, ./sszdump

# Metrics for tracking attestation and beacon block loss
declareCounter beacon_attestations_received,
  "Number of beacon chain attestations received by this peer"
declareCounter beacon_aggregates_received,
  "Number of beacon chain aggregate attestations received by this peer"
declareCounter beacon_blocks_received,
  "Number of beacon chain blocks received by this peer"

const delayBuckets = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, Inf]

declareHistogram beacon_attestation_delay,
  "Time(s) between slot start and attestation reception", buckets = delayBuckets

declareHistogram beacon_aggregate_delay,
  "Time(s) between slot start and aggregate reception", buckets = delayBuckets

declareHistogram beacon_block_delay,
  "Time(s) between slot start and beacon block reception", buckets = delayBuckets

declareHistogram beacon_store_block_duration_seconds,
  "storeBlock() duration", buckets = [0.25, 0.5, 1, 2, 4, 8, Inf]

declareGauge beacon_head_root,
  "Root of the head block of the beacon chain"

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
    quarantine*: QuarantineRef

    blocksQueue*: AsyncQueue[BlockEntry]
    attestationsQueue*: AsyncQueue[AttestationEntry]
    aggregatesQueue*: AsyncQueue[AggregateEntry]

proc updateHead*(self: var Eth2Processor, wallSlot: Slot): BlockRef =
  ## Trigger fork choice and returns the new head block.
  ## Can return `nil`
  # Grab the new head according to our latest attestation data
  let newHead = self.attestationPool[].selectHead(wallSlot)
  if newHead.isNil():
    return nil

  # Store the new head in the chain DAG - this may cause epochs to be
  # justified and finalized
  let oldFinalized = self.chainDag.finalizedHead.blck

  self.chainDag.updateHead(newHead)
  beacon_head_root.set newHead.root.toGaugeValue

  # Cleanup the fork choice v2 if we have a finalized head
  if oldFinalized != self.chainDag.finalizedHead.blck:
    self.attestationPool[].prune()

  newHead

proc dumpBlock[T](
    self: Eth2Processor, signedBlock: SignedBeaconBlock,
    res: Result[T, BlockError]) =
  if self.config.dumpEnabled and res.isErr:
    case res.error
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

proc complete*(blk: SyncBlock, res: Result[void, BlockError]) {.inline.} =
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

  {.gcsafe.}: # TODO: fork choice and quarantine should sync via messages instead of callbacks
    let blck = self.chainDag.addRawBlock(self.quarantine, signedBlock) do (
        blckRef: BlockRef, signedBlock: SignedBeaconBlock,
        epochRef: EpochRef, state: HashedBeaconState):
      # Callback add to fork choice if valid
      attestationPool[].addForkChoice(
        epochRef, blckRef, signedBlock.message, wallSlot)

  self.dumpBlock(signedBlock, blck)

  # There can be a scenario where we receive a block we already received.
  # However this block was before the last finalized epoch and so its parent
  # was pruned from the ForkChoice.
  if blck.isErr:
    return err(blck.error)

  beacon_store_block_duration_seconds.observe((Moment.now() - start).milliseconds.float64 / 1000)
  return ok()

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
    discard self.updateHead(wallSlot)
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
    signedBlock: SignedBeaconBlock): bool =
  logScope:
    signedBlock = shortLog(signedBlock.message)
    blockRoot = shortLog(signedBlock.root)

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    return false

  logScope: wallSlot

  let delay = wallTime - signedBlock.message.slot.toBeaconTime

  if signedBlock.root in self.chainDag.blocks:
    # The gossip algorithm itself already does one round of hashing to find
    # already-seen data, but it is fairly aggressive about forgetting about
    # what it has seen already
    debug "Dropping already-seen gossip block", delay
    # TODO:
    # Potentially use a fast exit here. We only need to check that
    # the contents of the incoming message match our previously seen
    # version of the block. We don't need to use HTR for this - for
    # better efficiency we can use vanilla SHA256 or direct comparison
    # if we still have the previous block in memory.
    return false

  # Start of block processing - in reality, we have already gone through SSZ
  # decoding at this stage, which may be significant
  debug "Block received", delay

  let blck = self.chainDag.isValidBeaconBlock(
    self.quarantine, signedBlock, wallSlot, {})

  self.dumpBlock(signedBlock, blck)

  if not blck.isOk:
    return false

  beacon_blocks_received.inc()
  beacon_block_delay.observe(float(milliseconds(delay)) / 1000.0)

  # Block passed validation - enqueue it for processing. The block processing
  # queue is effectively unbounded as we use a freestanding task to enqueue
  # the block - this is done so that when blocks arrive concurrently with
  # sync, we don't lose the gossip blocks, but also don't block the gossip
  # propagation of seemingly good blocks
  trace "Block validated"
  traceAsyncErrors self.blocksQueue.addLast(
    BlockEntry(v: SyncBlock(blk: signedBlock)))

  true

proc attestationValidator*(
    self: var Eth2Processor,
    attestation: Attestation,
    committeeIndex: uint64): bool =
  logScope:
    attestation = shortLog(attestation)
    committeeIndex

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    notice "Attestation before genesis"
    return false

  logScope: wallSlot

  let delay = wallTime - attestation.data.slot.toBeaconTime
  debug "Attestation received", delay
  let v = self.attestationPool[].validateAttestation(
      attestation, wallTime, committeeIndex)
  if v.isErr():
    debug "Dropping attestation", err = v.error()
    return false

  beacon_attestations_received.inc()
  beacon_attestation_delay.observe(float(milliseconds(delay)) / 1000.0)

  while self.attestationsQueue.full():
    let dropped = self.attestationsQueue.popFirst()
    doAssert dropped.finished, "popFirst sanity"
    notice "Queue full, dropping attestation",
      dropped = shortLog(dropped.read().v)

  trace "Attestation validated"
  traceAsyncErrors self.attestationsQueue.addLast(
    AttestationEntry(v: attestation, attesting_indices: v.get()))

  true

proc aggregateValidator*(
  self: var Eth2Processor,
  signedAggregateAndProof: SignedAggregateAndProof): bool =
  logScope:
    aggregate = shortLog(signedAggregateAndProof.message.aggregate)
    signature = shortLog(signedAggregateAndProof.signature)

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    notice "Aggregate before genesis"
    return false

  logScope: wallSlot

  let delay =
    wallTime - signedAggregateAndProof.message.aggregate.data.slot.toBeaconTime
  debug "Aggregate received", delay

  let v = self.attestationPool[].validateAggregate(
      signedAggregateAndProof, wallTime)
  if v.isErr:
    debug "Dropping aggregate", err = v.error
    return false

  beacon_aggregates_received.inc()
  beacon_aggregate_delay.observe(float(milliseconds(delay)) / 1000.0)

  while self.aggregatesQueue.full():
    let dropped = self.aggregatesQueue.popFirst()
    doAssert dropped.finished, "popFirst sanity"
    notice "Queue full, dropping aggregate",
      dropped = shortLog(dropped.read().v)

  trace "Aggregate validated"
  traceAsyncErrors self.aggregatesQueue.addLast(AggregateEntry(
    v: signedAggregateAndProof.message.aggregate,
    attesting_indices: v.get()))

  true

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
          quarantine: QuarantineRef,
          getWallTime: GetWallTimeFn): ref Eth2Processor =
  (ref Eth2Processor)(
    config: config,
    getWallTime: getWallTime,
    chainDag: chainDag,
    attestationPool: attestationPool,
    quarantine: quarantine,
    blocksQueue: newAsyncQueue[BlockEntry](1),
    aggregatesQueue: newAsyncQueue[AggregateEntry](MAX_ATTESTATIONS.int),
    attestationsQueue: newAsyncQueue[AttestationEntry](TARGET_COMMITTEE_SIZE.int * 4),
  )
