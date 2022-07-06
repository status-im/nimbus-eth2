# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  stew/results,
  chronicles, chronos, metrics,
  ../spec/signatures_batch,
  ../sszdump

from ./consensus_manager import
  ConsensusManager, updateHead, updateHeadWithExecution
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

from chronicles/chronos_tools import traceAsyncErrors
from ../consensus_object_pools/attestation_pool import addForkChoice
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
  if not is_execution_block(signedBlock.message):
    self.consensusManager[].updateHead(wallTime.slotOrZero)
  else:
    # This primarily exists to ensure that by the time the DAG updateHead is
    # called valid blocks have already been registered as verified. The head
    # can lag a slot behind wall clock, complicating detecting synced status
    # for validating, otherwise.
    traceAsyncErrors self.consensusManager.updateHeadWithExecution(
      wallTime.slotOrZero)

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
from web3/engine_api_types import PayloadExecutionStatus, PayloadStatusV1
from ../eth1/eth1_monitor import
  Eth1Monitor, asEngineExecutionPayload, ensureDataProvider, newPayload
from ../spec/datatypes/bellatrix import ExecutionPayload, SignedBeaconBlock

proc newExecutionPayload*(
    eth1Monitor: Eth1Monitor, executionPayload: bellatrix.ExecutionPayload):
    Future[PayloadExecutionStatus] {.async.} =
  if eth1Monitor.isNil:
    warn "newPayload: attempting to process execution payload without an Eth1Monitor. Ensure --web3-url setting is correct."
    return PayloadExecutionStatus.syncing

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
          PayloadStatusV1(status: PayloadExecutionStatus.syncing)
      payloadStatus = payloadResponse.status

    debug "newPayload: succeeded",
      parentHash = executionPayload.parent_hash,
      blockHash = executionPayload.block_hash,
      blockNumber = executionPayload.block_number,
      payloadStatus

    return payloadStatus
  except CatchableError as err:
    debug "newPayload failed", msg = err.msg
    return PayloadExecutionStatus.syncing

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

             await newExecutionPayload(
               self.consensusManager.eth1Monitor, executionPayload)
           except CatchableError as err:
             info "runQueueProcessingLoop: newPayload failed",
               err = err.msg
             # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/sync/optimistic.md#execution-engine-errors
             if not blck.resfut.isNil:
               blck.resfut.complete(
                 Result[void, BlockError].err(BlockError.MissingParent))
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
          blck, executionPayloadStatus == PayloadExecutionStatus.valid)
      else:
        debug "runQueueProcessingLoop: block cannot be optimistically imported",
          blck = shortLog(blck.blck)
        if not blck.resfut.isNil:
          blck.resfut.complete(
            Result[void, BlockError].err(BlockError.MissingParent))
