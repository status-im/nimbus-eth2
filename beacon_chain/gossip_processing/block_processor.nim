# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/math,
  stew/results,
  chronicles, chronos, metrics,
  eth/async_utils,
  web3/engine_api_types,
  ../spec/datatypes/[phase0, altair, bellatrix],
  ../spec/[forks, signatures_batch],
  ../consensus_object_pools/[
    attestation_pool, block_clearance, blockchain_dag, block_quarantine,
    spec_cache],
  ../eth1/eth1_monitor,
  ./consensus_manager,
  ../beacon_clock,
  ../sszdump

export sszdump, signatures_batch

# Block Processor
# ------------------------------------------------------------------------------
# The block processor moves blocks from "Incoming" to "Consensus verified"

declareHistogram beacon_store_block_duration_seconds,
  "storeBlock() duration", buckets = [0.25, 0.5, 1, 2, 4, 8, Inf]

type
  BlockEntry* = object
    blck*: ForkedSignedBeaconBlock
    resfut*: Future[Result[void, BlockError]]
    queueTick*: Moment # Moment when block was enqueued
    validationDur*: Duration # Time it took to perform gossip validation
    src*: MsgSource

  BlockProcessor* = object
    ## This manages the processing of blocks from different sources
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
    ## The processor will also reinsert blocks from the quarantine, should a
    ## parent be found.

    # Config
    # ----------------------------------------------------------------
    dumpEnabled: bool
    dumpDirInvalid: string
    dumpDirIncoming: string

    # Producers
    # ----------------------------------------------------------------
    blockQueue: AsyncQueue[BlockEntry]

    # Consumer
    # ----------------------------------------------------------------
    consensusManager: ref ConsensusManager
      ## Blockchain DAG, AttestationPool and Quarantine
      ## Blockchain DAG, AttestationPool, Quarantine, and Eth1Manager
    validatorMonitor: ref ValidatorMonitor
    getBeaconTime: GetBeaconTimeFn

    verifier: BatchVerifier

proc addBlock*(
    self: var BlockProcessor, src: MsgSource, blck: ForkedSignedBeaconBlock,
    resfut: Future[Result[void, BlockError]] = nil,
    validationDur = Duration())

# Initialization
# ------------------------------------------------------------------------------

proc new*(T: type BlockProcessor,
          dumpEnabled: bool,
          dumpDirInvalid, dumpDirIncoming: string,
          rng: ref BrHmacDrbgContext, taskpool: TaskPoolPtr,
          consensusManager: ref ConsensusManager,
          validatorMonitor: ref ValidatorMonitor,
          getBeaconTime: GetBeaconTimeFn): ref BlockProcessor =
  (ref BlockProcessor)(
    dumpEnabled: dumpEnabled,
    dumpDirInvalid: dumpDirInvalid,
    dumpDirIncoming: dumpDirIncoming,
    blockQueue: newAsyncQueue[BlockEntry](),
    consensusManager: consensusManager,
    validatorMonitor: validatorMonitor,
    getBeaconTime: getBeaconTime,
    verifier: BatchVerifier(rng: rng, taskpool: taskpool)
  )

# Sync callbacks
# ------------------------------------------------------------------------------

func hasBlocks*(self: BlockProcessor): bool =
  self.blockQueue.len() > 0

# Storage
# ------------------------------------------------------------------------------

proc dumpInvalidBlock*(
    self: BlockProcessor, signedBlock: ForkySignedBeaconBlock) =
  if self.dumpEnabled:
    dump(self.dumpDirInvalid, signedBlock)

proc dumpBlock[T](
    self: BlockProcessor,
    signedBlock: ForkySignedBeaconBlock,
    res: Result[T, BlockError]) =
  if self.dumpEnabled and res.isErr:
    case res.error
    of BlockError.Invalid:
      self.dumpInvalidBlock(signedBlock)
    of BlockError.MissingParent:
      dump(self.dumpDirIncoming, signedBlock)
    else:
      discard

proc storeBackfillBlock(
    self: var BlockProcessor,
    signedBlock: ForkySignedBeaconBlock): Result[void, BlockError] =

  # The block is certainly not missing any more
  self.consensusManager.quarantine[].missing.del(signedBlock.root)

  let res = self.consensusManager.dag.addBackfillBlock(signedBlock)

  if res.isErr():
    case res.error
    of BlockError.MissingParent:
      if signedBlock.message.parent_root in
          self.consensusManager.quarantine[].unviable:
        # DAG doesn't know about unviable ancestor blocks - we do! Translate
        # this to the appropriate error so that sync etc doesn't retry the block
        self.consensusManager.quarantine[].addUnviable(signedBlock.root)

        return err(BlockError.UnviableFork)
    of BlockError.UnviableFork:
      # Track unviables so that descendants can be discarded properly
      self.consensusManager.quarantine[].addUnviable(signedBlock.root)
    else: discard

  res

proc storeBlock*(
    self: var BlockProcessor,
    src: MsgSource, wallTime: BeaconTime,
    signedBlock: ForkySignedBeaconBlock, queueTick: Moment = Moment.now(),
    validationDur = Duration()): Result[BlockRef, BlockError] =
  ## storeBlock is the main entry point for unvalidated blocks - all untrusted
  ## blocks, regardless of origin, pass through here. When storing a block,
  ## we will add it to the dag and pass it to all block consumers that need
  ## to know about it, such as the fork choice and the monitoring
  let
    attestationPool = self.consensusManager.attestationPool
    startTick = Moment.now()
    wallSlot = wallTime.slotOrZero()
    vm = self.validatorMonitor
    dag = self.consensusManager.dag

  # The block is certainly not missing any more
  self.consensusManager.quarantine[].missing.del(signedBlock.root)

  # We'll also remove the block as an orphan: it's unlikely the parent is
  # missing if we get this far - should that be the case, the block will
  # be re-added later
  self.consensusManager.quarantine[].removeOrphan(signedBlock)

  type Trusted = typeof signedBlock.asTrusted()
  let blck = dag.addHeadBlock(self.verifier, signedBlock) do (
      blckRef: BlockRef, trustedBlock: Trusted, epochRef: EpochRef):
    # Callback add to fork choice if valid
    attestationPool[].addForkChoice(
      epochRef, blckRef, trustedBlock.message, wallTime)

    vm[].registerBeaconBlock(
      src, wallTime, trustedBlock.message)

    for attestation in trustedBlock.message.body.attestations:
      for validator_index in get_attesting_indices(
          epochRef, attestation.data.slot,
          CommitteeIndex.init(attestation.data.index).expect(
            "index has been checked"),
          attestation.aggregation_bits):
        vm[].registerAttestationInBlock(attestation.data, validator_index,
          trustedBlock.message.slot)

    withState(dag[].clearanceState):
      when stateFork >= BeaconStateFork.Altair and
          Trusted isnot phase0.TrustedSignedBeaconBlock: # altair+
        for i in trustedBlock.message.body.sync_aggregate.sync_committee_bits.oneIndices():
          vm[].registerSyncAggregateInBlock(
            trustedBlock.message.slot, trustedBlock.root,
            state.data.current_sync_committee.pubkeys.data[i])

  self.dumpBlock(signedBlock, blck)

  # There can be a scenario where we receive a block we already received.
  # However this block was before the last finalized epoch and so its parent
  # was pruned from the ForkChoice.
  if blck.isErr():
    case blck.error()
    of BlockError.MissingParent:
      if signedBlock.message.parent_root in
          self.consensusManager.quarantine[].unviable:
        # DAG doesn't know about unviable ancestor blocks - we do! Translate
        # this to the appropriate error so that sync etc doesn't retry the block
        self.consensusManager.quarantine[].addUnviable(signedBlock.root)

        return err(BlockError.UnviableFork)

      if not self.consensusManager.quarantine[].addOrphan(
          dag.finalizedHead.slot, ForkedSignedBeaconBlock.init(signedBlock)):
        debug "Block quarantine full",
          blockRoot = shortLog(signedBlock.root),
          blck = shortLog(signedBlock.message),
          signature = shortLog(signedBlock.signature)
    of BlockError.UnviableFork:
      # Track unviables so that descendants can be discarded properly
      self.consensusManager.quarantine[].addUnviable(signedBlock.root)
    else: discard

    return blck

  let storeBlockTick = Moment.now()

  # Eagerly update head: the incoming block "should" get selected
  self.consensusManager[].updateHead(wallTime.slotOrZero)

  let
    updateHeadTick = Moment.now()
    queueDur = startTick - queueTick
    storeBlockDur = storeBlockTick - startTick
    updateHeadDur = updateHeadTick - storeBlockTick

  beacon_store_block_duration_seconds.observe(storeBlockDur.toFloatSeconds())

  debug "Block processed",
    localHeadSlot = self.consensusManager.dag.head.slot,
    blockSlot = blck.get().slot,
    validationDur, queueDur, storeBlockDur, updateHeadDur

  for quarantined in self.consensusManager.quarantine[].pop(blck.get().root):
    # Process the blocks that had the newly accepted block as parent
    self.addBlock(MsgSource.gossip, quarantined)

  blck

# Enqueue
# ------------------------------------------------------------------------------

proc addBlock*(
    self: var BlockProcessor, src: MsgSource, blck: ForkedSignedBeaconBlock,
    resfut: Future[Result[void, BlockError]] = nil,
    validationDur = Duration()) =
  ## Enqueue a Gossip-validated block for consensus verification
  # Backpressure:
  #   There is no backpressure here - producers must wait for `resfut` to
  #   constrain their own processing
  # Producers:
  # - Gossip (when synced)
  # - SyncManager (during sync)
  # - RequestManager (missing ancestor blocks)

  withBlck(blck):
    if blck.message.slot <= self.consensusManager.dag.finalizedHead.slot:
      # let backfill blocks skip the queue - these are always "fast" to process
      # because there are no state rewinds to deal with
      let res = self.storeBackfillBlock(blck)

      if resfut != nil:
        resfut.complete(res)
      return

  try:
    self.blockQueue.addLastNoWait(BlockEntry(
      blck: blck,
      resfut: resfut, queueTick: Moment.now(),
      validationDur: validationDur,
      src: src))
  except AsyncQueueFullError:
    raiseAssert "unbounded queue"

# Event Loop
# ------------------------------------------------------------------------------

proc processBlock(self: var BlockProcessor, entry: BlockEntry) =
  logScope:
    blockRoot = shortLog(entry.blck.root)

  let
    wallTime = self.getBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing block before genesis, clock turned back?"
    quit 1

  let
     res = withBlck(entry.blck):
       self.storeBlock(entry.src, wallTime, blck, entry.queueTick, entry.validationDur)

  if entry.resfut != nil:
    entry.resfut.complete(
      if res.isOk(): Result[void, BlockError].ok()
      else: Result[void, BlockError].err(res.error()))

func `$`(h: BlockHash): string = $h.asEth2Digest

proc runForkchoiceUpdated(
    self: ref BlockProcessor, headBlockRoot, finalizedBlockRoot: Eth2Digest):
    Future[bool] {.async.} =
  # Allow finalizedBlockRoot to be 0 to avoid sync deadlocks.
  #
  # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md#pos-events
  # has "Before the first finalized block occurs in the system the finalized
  # block hash provided by this event is stubbed with
  # `0x0000000000000000000000000000000000000000000000000000000000000000`."
  # and
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/validator.md#executionpayload
  # notes "`finalized_block_hash` is the hash of the latest finalized execution
  # payload (`Hash32()` if none yet finalized)"
  doAssert not headBlockRoot.isZero

  try:
    # Minimize window for Eth1 monitor to shut down connection
    await self.consensusManager.eth1Monitor.ensureDataProvider()

    let fcuR = awaitWithTimeout(
      forkchoiceUpdated(
        self.consensusManager.eth1Monitor, headBlockRoot, finalizedBlockRoot),
      FORKCHOICEUPDATED_TIMEOUT):
        debug "runForkChoiceUpdated: forkchoiceUpdated timed out"
        default(ForkchoiceUpdatedResponse)

    debug "runForkChoiceUpdated: running forkchoiceUpdated",
      headBlockRoot,
      finalizedBlockRoot,
      payloadStatus = $fcuR.payloadStatus.status,
      latestValidHash = $fcuR.payloadStatus.latestValidHash,
      validationError = $fcuR.payloadStatus.validationError

    return fcuR.payloadStatus.status == PayloadExecutionStatus.valid
  except CatchableError as err:
    debug "runForkChoiceUpdated: forkchoiceUpdated failed",
      err = err.msg
    return false

proc newExecutionPayload*(
    eth1Monitor: Eth1Monitor, executionPayload: bellatrix.ExecutionPayload):
    Future[PayloadExecutionStatus] {.async.} =
  debug "newPayload: inserting block into execution engine",
    parentHash = executionPayload.parent_hash,
    blockHash = executionPayload.block_hash,
    stateRoot = shortLog(executionPayload.state_root),
    receiptsRoot = shortLog(executionPayload.receipts_root),
    prevRandao = shortLog(executionPayload.prev_randao),
    blockNumber = executionPayload.block_number,
    gasLimit = executionPayload.gas_limit,
    gasUsed = executionPayload.gas_used,
    timestamp = executionPayload.timestamp,
    extraDataLen = executionPayload.extra_data.len,
    blockHash = executionPayload.block_hash,
    baseFeePerGas = executionPayload.base_fee_per_gas,
    numTransactions = executionPayload.transactions.len

  if eth1Monitor.isNil:
    info "newPayload: attempting to process execution payload without an Eth1Monitor. Ensure --web3-url setting is correct."
    return PayloadExecutionStatus.syncing

  try:
    let
      payloadResponse =
        awaitWithTimeout(
            eth1Monitor.newPayload(
              executionPayload.asEngineExecutionPayload),
            NEWPAYLOAD_TIMEOUT):
          info "newPayload: newPayload timed out"
          PayloadStatusV1(status: PayloadExecutionStatus.syncing)
      payloadStatus = payloadResponse.status

    return payloadStatus
  except CatchableError as err:
    debug "newPayload failed", msg = err.msg
    return PayloadExecutionStatus.syncing

proc runQueueProcessingLoop*(self: ref BlockProcessor) {.async.} =
  # Don't want to vacillate between "optimistic" sync and non-optimistic
  # sync heads. Relies on runQueueProcessingLoop() being the only place,
  # in Nimbus, which does this.
  var
    optForkchoiceHeadSlot = GENESIS_SLOT # safe default
    optForkchoiceHeadRoot: Eth2Digest
    optForkchoiceFinalizedRoot: Eth2Digest

    # don't keep fcUing same fcU to Geth; might be restarting sync each time
    lastFcHead: Eth2Digest

  while true:
    # Cooperative concurrency: one block per loop iteration - because
    # we run both networking and CPU-heavy things like block processing
    # on the same thread, we need to make sure that there is steady progress
    # on the networking side or we get long lockups that lead to timeouts.
    const
      # We cap waiting for an idle slot in case there's a lot of network traffic
      # taking up all CPU - we don't want to _completely_ stop processing blocks
      # in this case - doing so also allows us to benefit from more batching /
      # larger network reads when under load.
      idleTimeout = 10.milliseconds

    discard await idleAsync().withTimeout(idleTimeout)

    let
      blck = await self[].blockQueue.popFirst()
      hasExecutionPayload = blck.blck.kind >= BeaconBlockFork.Bellatrix
      isExecutionBlock =
        hasExecutionPayload and
          blck.blck.bellatrixData.message.body.is_execution_block
      executionPayloadStatus =
        if isExecutionBlock:
          # Eth1 syncing is asynchronous from this

          # TODO self.consensusManager.eth1Monitor.terminalBlockHash.isSome
          # should gate this when it works more reliably
          when true:
            try:
              # Minimize window for Eth1 monitor to shut down connection
              await self.consensusManager.eth1Monitor.ensureDataProvider()

              await newExecutionPayload(
                self.consensusManager.eth1Monitor,
                blck.blck.bellatrixData.message.body.execution_payload)
            except CatchableError as err:
              debug "runQueueProcessingLoop: newPayload failed",
                err = err.msg
              PayloadExecutionStatus.syncing
          else:
            debug "runQueueProcessingLoop: got execution payload before TTD"
            PayloadExecutionStatus.syncing
        else:
          # Vacuously
          PayloadExecutionStatus.valid

    debug "FOO1",
      blckSrc = blck.src,
      isOpt = blck.src == MsgSource.optSync

    # optSync blocks should always be of Bellatrix or newer forks.
    doAssert blck.src != MsgSource.optSync or hasExecutionPayload

    if executionPayloadStatus in [
        PayloadExecutionStatus.invalid,
        PayloadExecutionStatus.invalid_block_hash]:
      debug "runQueueProcessingLoop: execution payload invalid",
        executionPayloadStatus
      # Every loop iteration ends with some version of blck.resfut.complete(),
      # including processBlock(), otherwise the sync manager stalls.
      if not blck.resfut.isNil:
        blck.resfut.complete(Result[void, BlockError].err(
          if blck.src != MsgSource.optSync:
            BlockError.Invalid
          else:
            BlockError.MissingParent))
      continue

    if isExecutionBlock:
      # The EL client doesn't know here whether the payload is valid, because,
      # for example, in Geth's case, its parent isn't known. When Geth logs an
      # "Ignoring payload with missing parent" message, this is the result. It
      # is distinct from the invalid cases above, and shouldn't cause the same
      # BlockError.Invalid error, because it doesn't badly on the peer sending
      # it, it's just not fully verifiable yet for this node. Furthermore, the
      # EL client can, e.g. via Geth, "rely on the beacon client to forcefully
      # update the head with a forkchoice update request". This can occur when
      # an EL client is substantially more synced than a CL client, and when a
      # CL client in that position attempts to serially sync it will encounter
      # potential for this message until it nearly catches up, unless using an
      # approach such as forkchoiceUpdated to trigger sync.
      #
      # Returning the MissingParent error causes the sync manager to loop in
      # place until the EL does resync/catch up, then the normal process can
      # resume where there's a hybrid serial and optimistic sync model.
      #
      # When this occurs within a couple of epochs of the Merge, before there
      # has been a chance to justify and finalize a post-merge block this can
      # cause a sync deadlock unless the EL can be convinced to sync back, or
      # the CL is rather more open-endedly optimistic (potentially for entire
      # weak subjectivity periods) than seems optimal.
      debug "runQueueProcessingLoop: execution payload accepted or syncing",
        executionPayloadStatus

      # Always do this. Geth will only initiate syncing or reorgs with this
      # combination of newPayload and forkchoiceUpdated. By design this must
      # be somewhat optimistic, at least by one slot, for Geth to process it
      # at all. This eventually converges to the same head as the DAG by the
      # time it's externally visible via validating activity.
      #
      # In particular, the constraints that hold here are that Geth expects a
      # sequence of
      # - newPayload(execution payload with block hash `h`) followed by
      # - forkchoiceUpdated(head = `h`)
      # This is intrinsically somewhat optimistic, because determining the 
      # validity of an execution payload requires the forkchoiceUpdated 
      # head to be set to a block hash of some execution payload with unknown
      # validity; otherwise it would not be necessary to ask the EL.
      #
      # The main reason this isn't done more adjacently in this code flow is to
      # catch outright invalid cases, where the EL can reject a payload, without
      # even running forkchoiceUpdated on it.
      static: doAssert high(BeaconStateFork) == BeaconStateFork.Bellatrix
      let
        curBh =
          blck.blck.bellatrixData.message.body.execution_payload.block_hash
        preferBlockExecutionPayloadHash =
          blck.blck.bellatrixData.message.slot + SLOTS_PER_EPOCH * 16 >=
            optForkchoiceHeadSlot
        usedBh =
          if preferBlockExecutionPayloadHash:
            blck.blck.bellatrixData.message.body.execution_payload.block_hash
          else:
            optForkchoiceHeadRoot

      if usedBh != lastFcHead:
        lastFcHead = usedBh

        if blck.src == MsgSource.optSync:
          optForkchoiceHeadSlot = blck.blck.bellatrixData.message.slot
          optForkchoiceHeadRoot =
            blck.blck.bellatrixData.message.body.execution_payload.block_hash

        if await self.runForkchoiceUpdated(
            usedBh,
            self.consensusManager.dag.finalizedHead.blck.executionBlockRoot):
          # Geth seldom seems to return VALID to newPayload alone, even when
          # it has all the relevant information.
          self[].processBlock(blck)
          continue

      if executionPayloadStatus != PayloadExecutionStatus.valid:
        if not blck.resfut.isNil:
          blck.resfut.complete(Result[void, BlockError].err(
            BlockError.MissingParent))

        continue

    # When newPayload, rather than forkchoiceUpdated, has returned valid.
    doAssert executionPayloadStatus == PayloadExecutionStatus.valid
    self[].processBlock(blck)
