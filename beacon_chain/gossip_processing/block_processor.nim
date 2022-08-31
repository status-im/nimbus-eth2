# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  stew/results,
  chronicles, chronos, metrics,
  ../spec/signatures_batch,
  ../sszdump

from ../consensus_object_pools/consensus_manager import
  ConsensusManager, checkNextProposer, optimisticExecutionPayloadHash,
  runForkchoiceUpdated, runForkchoiceUpdatedDiscardResult,
  runProposalForkchoiceUpdated, shouldSyncOptimistically, updateHead,
  updateHeadWithExecution
from ../beacon_clock import GetBeaconTimeFn, toFloatSeconds
from ../consensus_object_pools/block_dag import BlockRef, root, slot
from ../consensus_object_pools/block_pools_types import BlockError, EpochRef
from ../consensus_object_pools/block_quarantine import
  addOrphan, addUnviable, pop, removeOrphan
from ../validators/validator_monitor import
  MsgSource, ValidatorMonitor, registerAttestationInBlock, registerBeaconBlock,
  registerSyncAggregateInBlock

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
    safeSlotsToImportOptimistically: uint16

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
          rng: ref HmacDrbgContext, taskpool: TaskPoolPtr,
          consensusManager: ref ConsensusManager,
          validatorMonitor: ref ValidatorMonitor,
          getBeaconTime: GetBeaconTimeFn,
          safeSlotsToImportOptimistically: uint16): ref BlockProcessor =
  (ref BlockProcessor)(
    dumpEnabled: dumpEnabled,
    dumpDirInvalid: dumpDirInvalid,
    dumpDirIncoming: dumpDirIncoming,
    blockQueue: newAsyncQueue[BlockEntry](),
    consensusManager: consensusManager,
    validatorMonitor: validatorMonitor,
    getBeaconTime: getBeaconTime,
    safeSlotsToImportOptimistically: safeSlotsToImportOptimistically,
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

from ../consensus_object_pools/block_clearance import
  addBackfillBlock, addHeadBlock

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

from web3/engine_api_types import PayloadExecutionStatus, PayloadStatusV1
from ../eth1/eth1_monitor import
  Eth1Monitor, asEngineExecutionPayload, ensureDataProvider, newPayload

proc expectValidForkchoiceUpdated(
    eth1Monitor: Eth1Monitor,
    headBlockRoot, safeBlockRoot, finalizedBlockRoot: Eth2Digest
): Future[void] {.async.} =
  let payloadExecutionStatus =
    await eth1Monitor.runForkchoiceUpdated(
      headBlockRoot, safeBlockRoot, finalizedBlockRoot)
  if payloadExecutionStatus != PayloadExecutionStatus.valid:
    # Only called when expecting this to be valid because `newPayload` or some
    # previous `forkchoiceUpdated` had already marked it as valid.
    warn "expectValidForkchoiceUpdate: forkChoiceUpdated not `VALID`",
      payloadExecutionStatus, headBlockRoot, safeBlockRoot, finalizedBlockRoot

from ../consensus_object_pools/attestation_pool import
  addForkChoice, selectOptimisticHead, BeaconHead
from ../consensus_object_pools/blockchain_dag import
  is_optimistic, loadExecutionBlockRoot, markBlockVerified
from ../consensus_object_pools/block_dag import shortLog
from ../consensus_object_pools/spec_cache import get_attesting_indices
from ../spec/datatypes/phase0 import TrustedSignedBeaconBlock

proc storeBlock*(
    self: var BlockProcessor,
    src: MsgSource, wallTime: BeaconTime,
    signedBlock: ForkySignedBeaconBlock, payloadValid: bool,
    queueTick: Moment = Moment.now(),
    validationDur = Duration()): Result[BlockRef, BlockError] =
  ## storeBlock is the main entry point for unvalidated blocks - all untrusted
  ## blocks, regardless of origin, pass through here. When storing a block,
  ## we will add it to the dag and pass it to all block consumers that need
  ## to know about it, such as the fork choice and the monitoring
  let
    attestationPool = self.consensusManager.attestationPool
    startTick = Moment.now()
    vm = self.validatorMonitor
    dag = self.consensusManager.dag

  # The block is certainly not missing any more
  self.consensusManager.quarantine[].missing.del(signedBlock.root)

  # We'll also remove the block as an orphan: it's unlikely the parent is
  # missing if we get this far - should that be the case, the block will
  # be re-added later
  self.consensusManager.quarantine[].removeOrphan(signedBlock)

  type Trusted = typeof signedBlock.asTrusted()
  let blck = dag.addHeadBlock(self.verifier, signedBlock, payloadValid) do (
      blckRef: BlockRef, trustedBlock: Trusted,
      epochRef: EpochRef, unrealized: FinalityCheckpoints):
    # Callback add to fork choice if valid
    attestationPool[].addForkChoice(
      epochRef, blckRef, unrealized, trustedBlock.message, wallTime)

    vm[].registerBeaconBlock(
      src, wallTime, trustedBlock.message)

    for attestation in trustedBlock.message.body.attestations:
      for validator_index in dag.get_attesting_indices(attestation):
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

  # Eagerly update head: the incoming block "should" get selected.
  #
  # storeBlock gets called from validator_duties, which depends on its not
  # blocking progress any longer than necessary, and processBlock here, in
  # which case it's fine to await for a while on engine API results.
  #
  # Three general scenarios: (1) pre-merge; (2) merge, already `VALID` by way
  # of `newPayload`; (3) optimistically imported, need to call fcU before DAG
  # updateHead. Handle each with as little async latency as feasible.

  if payloadValid:
    self.consensusManager.dag.markBlockVerified(
      self.consensusManager.quarantine[], signedBlock.root)

  # Grab the new head according to our latest attestation data; determines how
  # async this needs to be.
  let
    wallSlot = wallTime.slotOrZero
    newHead = attestationPool[].selectOptimisticHead(
        wallSlot.start_beacon_time)

  if newHead.isOk:
    template eth1Monitor(): auto = self.consensusManager.eth1Monitor
    if self.consensusManager[].shouldSyncOptimistically(wallSlot):
      # Optimistic head is far in the future; report it as head block to EL.

      # Note that the specification allows an EL client to skip fcU processing
      # if an update to an ancestor is requested.
      # > Client software MAY skip an update of the forkchoice state and MUST
      #   NOT begin a payload build process if `forkchoiceState.headBlockHash`
      #   references an ancestor of the head of canonical chain.
      # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.1/src/engine/specification.md#engine_forkchoiceupdatedv1
      #
      # However, in practice, an EL client may not have completed importing all
      # block headers, so may be unaware of a block's ancestor status.
      # Therefore, hopping back and forth between the optimistic head and the
      # chain DAG head does not work well in practice, e.g., Geth:
      # - "Beacon chain gapped" from DAG head to optimistic head,
      # - followed by "Beacon chain reorged" from optimistic head back to DAG.
      self.consensusManager[].updateHead(newHead.get.blck)
      asyncSpawn eth1Monitor.runForkchoiceUpdatedDiscardResult(
        headBlockRoot = self.consensusManager[].optimisticExecutionPayloadHash,
        safeBlockRoot = newHead.get.safeExecutionPayloadHash,
        finalizedBlockRoot = newHead.get.finalizedExecutionPayloadHash)
    else:
      let headExecutionPayloadHash =
        self.consensusManager.dag.loadExecutionBlockRoot(newHead.get.blck)
      if headExecutionPayloadHash.isZero:
        # Blocks without execution payloads can't be optimistic.
        self.consensusManager[].updateHead(newHead.get.blck)
      elif not self.consensusManager.dag.is_optimistic newHead.get.blck.root:
        # Not `NOT_VALID`; either `VALID` or `INVALIDATED`, but latter wouldn't
        # be selected as head, so `VALID`. `forkchoiceUpdated` necessary for EL
        # client only.
        self.consensusManager[].updateHead(newHead.get.blck)

        if self.consensusManager.checkNextProposer().isNone:
          # No attached validator is next proposer, so use non-proposal fcU
          asyncSpawn eth1Monitor.expectValidForkchoiceUpdated(
            headBlockRoot = headExecutionPayloadHash,
            safeBlockRoot = newHead.get.safeExecutionPayloadHash,
            finalizedBlockRoot = newHead.get.finalizedExecutionPayloadHash)
        else:
          # Some attached validator is next proposer, so prepare payload
          asyncSpawn self.consensusManager.runProposalForkchoiceUpdated()
      else:
        asyncSpawn self.consensusManager.updateHeadWithExecution(newHead.get)
  else:
    warn "Head selection failed, using previous head",
      head = shortLog(self.consensusManager.dag.head), wallSlot

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

  return blck

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

proc processBlock(
    self: var BlockProcessor, entry: BlockEntry, payloadValid: bool) =
  logScope:
    blockRoot = shortLog(entry.blck.root)

  let
    wallTime = self.getBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing block before genesis, clock turned back?"
    quit 1

  let res = withBlck(entry.blck):
    self.storeBlock(
      entry.src, wallTime, blck, payloadValid, entry.queueTick,
      entry.validationDur)

  if entry.resfut != nil:
    entry.resfut.complete(
      if res.isOk(): Result[void, BlockError].ok()
      else: Result[void, BlockError].err(res.error()))

from eth/async_utils import awaitWithTimeout
from ../spec/datatypes/bellatrix import ExecutionPayload, SignedBeaconBlock

proc newExecutionPayload*(
    eth1Monitor: Eth1Monitor, executionPayload: bellatrix.ExecutionPayload):
    Future[Opt[PayloadExecutionStatus]] {.async.} =
  if eth1Monitor.isNil:
    warn "newPayload: attempting to process execution payload without Eth1Monitor. Ensure --web3-url setting is correct and JWT is configured."
    return Opt.none PayloadExecutionStatus

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
    baseFeePerGas = $executionPayload.base_fee_per_gas,
    numTransactions = executionPayload.transactions.len

  try:
    let
      payloadResponse =
        awaitWithTimeout(
            eth1Monitor.newPayload(
              executionPayload.asEngineExecutionPayload),
            NEWPAYLOAD_TIMEOUT):
          info "newPayload: newPayload timed out"
          return Opt.none PayloadExecutionStatus

          # Placeholder for type system
          PayloadStatusV1(status: PayloadExecutionStatus.syncing)

      payloadStatus = payloadResponse.status

    debug "newPayload: succeeded",
      parentHash = executionPayload.parent_hash,
      blockHash = executionPayload.block_hash,
      blockNumber = executionPayload.block_number,
      payloadStatus

    return Opt.some payloadStatus
  except CatchableError as err:
    error "newPayload failed", msg = err.msg
    return Opt.none PayloadExecutionStatus

from ../consensus_object_pools/blockchain_dag import
  getBlockRef, loadExecutionBlockRoot, markBlockInvalid

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/sync/optimistic.md#helpers
proc is_optimistic_candidate_block(
    self: BlockProcessor, blck: ForkedSignedBeaconBlock): bool =
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/sync/optimistic.md#when-to-optimistically-import-blocks
  # The current slot (as per the system clock) is at least
  # `SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY` ahead of the slot of the block being
  # imported.
  if  blck.slot + self.safeSlotsToImportOptimistically <=
      self.getBeaconTime().slotOrZero:
    return true

  # Once merge is finalized, always true; in principle, should be caught by
  # other checks, but sometimes blocks arrive out of order, triggering some
  # spurious false negatives because the parent-block-check does not find a
  # parent block. This can also occur under conditions where EL client RPCs
  # cause processing delays. Either way, bound this risk to post-merge head
  # and pre-merge finalization.
  if not self.consensusManager.dag.loadExecutionBlockRoot(
      self.consensusManager.dag.finalizedHead.blck).isZero:
    return true

  let
    parentRoot = withBlck(blck): blck.message.parent_root
    parentBlck = self.consensusManager.dag.getBlockRef(parentRoot).valueOr:
      return false

  # The parent of the block has execution enabled.
  not self.consensusManager.dag.loadExecutionBlockRoot(parentBlck).isZero

proc runQueueProcessingLoop*(self: ref BlockProcessor) {.async.} =
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
      hasExecutionPayload =
        withBlck(blck.blck): blck.message.is_execution_block
      executionPayloadStatus =
       if hasExecutionPayload:
         # Eth1 syncing is asynchronous from this
         # TODO self.consensusManager.eth1Monitor.terminalBlockHash.isSome
         # should gate this when it works more reliably
         # TODO detect have-TTD-but-not-is_execution_block case, and where
         # execution payload was non-zero when TTD detection more reliable
         when true:
           # When an execution engine returns an error or fails to respond to a
           # payload validity request for some block, a consensus engine:
           # - MUST NOT optimistically import the block.
           # - MUST NOT apply the block to the fork choice store.
           # - MAY queue the block for later processing.
           # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.3/sync/optimistic.md#execution-engine-errors
           template reEnqueueBlock: untyped =
             await sleepAsync(chronos.seconds(1))
             self[].addBlock(
               blck.src, blck.blck, blck.resfut, blck.validationDur)

           try:
             # Minimize window for Eth1 monitor to shut down connection
             await self.consensusManager.eth1Monitor.ensureDataProvider()

             let executionPayload =
               withBlck(blck.blck):
                 when stateFork >= BeaconStateFork.Bellatrix:
                   blck.message.body.execution_payload
                 else:
                   doAssert false
                   default(bellatrix.ExecutionPayload) # satisfy Nim

             let executionPayloadStatus = await newExecutionPayload(
               self.consensusManager.eth1Monitor, executionPayload)
             if executionPayloadStatus.isNone:
               reEnqueueBlock()
               continue

             executionPayloadStatus.get
           except CatchableError as err:
             error "runQueueProcessingLoop: newPayload failed", err = err.msg
             reEnqueueBlock()
             continue
         else:
           debug "runQueueProcessingLoop: got execution payload before TTD"
           PayloadExecutionStatus.syncing
       else:
         # Vacuously
         PayloadExecutionStatus.valid

    if executionPayloadStatus in static([
        PayloadExecutionStatus.invalid,
        PayloadExecutionStatus.invalid_block_hash]):
      debug "runQueueProcessingLoop: execution payload invalid",
        executionPayloadStatus,
        blck = shortLog(blck.blck)
      self.consensusManager.dag.markBlockInvalid(blck.blck.root)
      self.consensusManager.quarantine[].addUnviable(blck.blck.root)
      # Every loop iteration ends with some version of blck.resfut.complete(),
      # including processBlock(), otherwise the sync manager stalls.
      if not blck.resfut.isNil:
        blck.resfut.complete(Result[void, BlockError].err(BlockError.Invalid))
    else:
      if  executionPayloadStatus == PayloadExecutionStatus.valid or
          self[].is_optimistic_candidate_block(blck.blck):
        self[].processBlock(
          blck,
          payloadValid = executionPayloadStatus == PayloadExecutionStatus.valid)
      else:
        debug "runQueueProcessingLoop: block cannot be optimistically imported",
          blck = shortLog(blck.blck)
        if not blck.resfut.isNil:
          blck.resfut.complete(
            Result[void, BlockError].err(BlockError.MissingParent))
