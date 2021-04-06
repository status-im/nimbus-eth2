# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/math,
  stew/results,
  chronicles, chronos, metrics,
  ../spec/[crypto, datatypes, digest],
  ../consensus_object_pools/[block_clearance, blockchain_dag, attestation_pool],
  ./consensus_manager,
  ".."/[beacon_clock, beacon_node_types],
  ../ssz/sszdump

# Gossip Queue Manager
# ------------------------------------------------------------------------------
# The queue manager moves blocks from "Gossip validated" to "Consensus verified"

declareHistogram beacon_store_block_duration_seconds,
  "storeBlock() duration", buckets = [0.25, 0.5, 1, 2, 4, 8, Inf]

declareCounter beacon_attestations_dropped_queue_full,
  "Number of attestations dropped because queue is full"

declareCounter beacon_aggregates_dropped_queue_full,
  "Number of aggregates dropped because queue is full"

type
  SyncBlock* = object
    blk*: SignedBeaconBlock
    resfut*: Future[Result[void, BlockError]]

  BlockEntry* = object
    # Exported for "test_sync_manager"
    v*: SyncBlock

  AttestationEntry = object
    v: Attestation
    attesting_indices: seq[ValidatorIndex]

  AggregateEntry = AttestationEntry

  VerifQueueManager* = object
    ## This manages the queues of blocks and attestations.
    ## Blocks and attestations are enqueued in a gossip-validated state
    ##
    ## from:
    ## - Gossip (when synced)
    ## - SyncManager (during sync)
    ## - RequestManager (missing ancestor blocks)
    ##
    ## are then consensus-verified and added to:
    ## - the blockchain DAG
    ## - database
    ## - attestation pool
    ## - fork choice
    ##
    ## The queue manager doesn't manage exits (voluntary, attester slashing or proposer slashing)
    ## as don't need extra verification and can be added to the exit pool as soon as they are gossip-validated.

    # Config
    # ----------------------------------------------------------------
    dumpEnabled: bool
    dumpDirInvalid: string
    dumpDirIncoming: string

    # Clock
    # ----------------------------------------------------------------
    getWallTime: GetWallTimeFn

    # Producers
    # ----------------------------------------------------------------
    blocksQueue*: AsyncQueue[BlockEntry] # Exported for "test_sync_manager"
    # TODO:
    #   is there a point to separate
    #   attestations & aggregates here?
    attestationsQueue: AsyncQueue[AttestationEntry]
    attestationsDropped: int
    attestationsDropTime: tuple[afterGenesis: bool, slot: Slot]
    aggregatesQueue: AsyncQueue[AggregateEntry]
    aggregatesDropped: int
    aggregatesDropTime: tuple[afterGenesis: bool, slot: Slot]

    # Consumer
    # ----------------------------------------------------------------
    consensusManager: ref ConsensusManager
      ## Blockchain DAG, AttestationPool and Quarantine

{.push raises: [Defect].}

# Initialization
# ------------------------------------------------------------------------------

proc new*(T: type VerifQueueManager,
          dumpEnabled: bool,
          dumpDirInvalid, dumpDirIncoming: string,
          consensusManager: ref ConsensusManager,
          getWallTime: GetWallTimeFn): ref VerifQueueManager =
  (ref VerifQueueManager)(
    dumpEnabled: dumpEnabled,
    dumpDirInvalid: dumpDirInvalid,
    dumpDirIncoming: dumpDirIncoming,

    getWallTime: getWallTime,

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

    consensusManager: consensusManager,
    attestationsDropTime: getWallTime().toSlot(),
    aggregatesDropTime: getWallTime().toSlot(),
  )

# Sync callbacks
# ------------------------------------------------------------------------------

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

# Enqueue
# ------------------------------------------------------------------------------

proc addBlock*(self: var VerifQueueManager, syncBlock: SyncBlock) =
  ## Enqueue a Gossip-validated block for consensus verification
  # Backpressure:
  #   If no item can be enqueued because buffer is full,
  #   we suspend here.
  # Producers:
  # - Gossip (when synced)
  # - SyncManager (during sync)
  # - RequestManager (missing ancestor blocks)

  # addLast doesn't fail
  asyncSpawn(self.blocksQueue.addLast(BlockEntry(v: syncBlock)))

proc addAttestation*(self: var VerifQueueManager, att: Attestation, att_indices: seq[ValidatorIndex]) =
  ## Enqueue a Gossip-validated attestation for consensus verification
  # Backpressure:
  #   If buffer is full, the oldest attestation is dropped and the newest is enqueued
  # Producer:
  # - Gossip (when synced)
  while self.attestationsQueue.full():
    self.attestationsDropped += 1
    beacon_attestations_dropped_queue_full.inc()

    try:
      discard self.attestationsQueue.popFirstNoWait()
    except AsyncQueueEmptyError as exc:
      raiseAssert "If queue is full, we have at least one item! " & exc.msg

  if self.attestationsDropped > 0:
    let now = self.getWallTime().toSlot() # Print notice once per slot
    if now != self.attestationsDropTime:
      notice "Queue full, attestations dropped",
        count = self.attestationsDropped
      self.attestationsDropTime = now
      self.attestationsDropped = 0

  try:
    self.attestationsQueue.addLastNoWait(
      AttestationEntry(v: att, attesting_indices: att_indices))
  except AsyncQueueFullError as exc:
    raiseAssert "We just checked that queue is not full! " & exc.msg

proc addAggregate*(self: var VerifQueueManager, agg: SignedAggregateAndProof, att_indices: seq[ValidatorIndex]) =
  ## Enqueue a Gossip-validated aggregate attestation for consensus verification
  # Backpressure:
  #   If buffer is full, the oldest aggregate is dropped and the newest is enqueued
  # Producer:
  # - Gossip (when synced)

  while self.aggregatesQueue.full():
    self.aggregatesDropped += 1
    beacon_aggregates_dropped_queue_full.inc()

    try:
      discard self.aggregatesQueue.popFirstNoWait()
    except AsyncQueueEmptyError as exc:
      raiseAssert "We just checked that queue is not full! " & exc.msg

  if self.aggregatesDropped > 0:
    let now = self.getWallTime().toSlot() # Print notice once per slot
    if now != self.aggregatesDropTime:
      notice "Queue full, aggregates dropped",
        count = self.aggregatesDropped
      self.aggregatesDropTime = now
      self.aggregatesDropped = 0

  try:
    self.aggregatesQueue.addLastNoWait(AggregateEntry(
      v: agg.message.aggregate,
      attesting_indices: att_indices))
  except AsyncQueueFullError as exc:
    raiseAssert "We just checked that queue is not full! " & exc.msg

# Storage
# ------------------------------------------------------------------------------

proc dumpBlock*[T](
    self: VerifQueueManager, signedBlock: SignedBeaconBlock,
    res: Result[T, (ValidationResult, BlockError)]) =
  if self.dumpEnabled and res.isErr:
    case res.error[1]
    of Invalid:
      dump(
        self.dumpDirInvalid, signedBlock)
    of MissingParent:
      dump(
        self.dumpDirIncoming, signedBlock)
    else:
      discard

proc storeBlock(
    self: var VerifQueueManager, signedBlock: SignedBeaconBlock,
    wallSlot: Slot): Result[void, BlockError] =
  let
    start = Moment.now()
    attestationPool = self.consensusManager.attestationPool

  let blck = self.consensusManager.chainDag.addRawBlock(self.consensusManager.quarantine, signedBlock) do (
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

# Event Loop
# ------------------------------------------------------------------------------

proc processAttestation(
    self: var VerifQueueManager, entry: AttestationEntry) =
  logScope:
    signature = shortLog(entry.v.signature)

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing attestation before genesis, clock turned back?"
    quit 1

  trace "Processing attestation"
  self.consensusManager.attestationPool[].addAttestation(
    entry.v, entry.attesting_indices, wallSlot)

proc processAggregate(
    self: var VerifQueueManager, entry: AggregateEntry) =
  logScope:
    signature = shortLog(entry.v.signature)

  let
    wallTime = self.getWallTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing aggregate before genesis, clock turned back?"
    quit 1

  trace "Processing aggregate"
  self.consensusManager.attestationPool[].addAttestation(
    entry.v, entry.attesting_indices, wallSlot)

proc processBlock(self: var VerifQueueManager, entry: BlockEntry) =
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
    self.consensusManager[].updateHead(wallSlot)    # This also eagerly prunes the blocks DAG to prevent processing forks.
    # self.consensusManager.pruneStateCachesDAG() # Amortized pruning, we don't prune states & fork choice here but in `onSlotEnd`()

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
      local_head_slot = self.consensusManager.chainDag.head.slot,
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

proc runQueueProcessingLoop*(self: ref VerifQueueManager) {.async.} =
  # Blocks in eth2 arrive on a schedule for every slot:
  #
  # * Block arrives at time 0
  # * Attestations arrives at time 4
  # * Aggregate arrives at time 8

  var
    blockFut = self[].blocksQueue.popFirst()
    aggregateFut = self[].aggregatesQueue.popFirst()
    attestationFut = self[].attestationsQueue.popFirst()

  # TODO:
  #   revisit `idleTimeout`
  #   and especially `attestationBatch` in light of batch validation
  #   in particular we might want `attestationBatch` to drain both attestation & aggregates
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
