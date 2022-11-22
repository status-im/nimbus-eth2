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
from ../consensus_object_pools/block_pools_types import
  EpochRef, VerifierError
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
    resfut*: Future[Result[void, VerifierError]]
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

    optimistic: bool
      ## Run block processor in optimistic mode allowing it to progress even
      ## though execution client is offline

  NewPayloadStatus {.pure.} = enum
    valid
    notValid
    invalid
    noResponse

  ProcessingStatus {.pure.} = enum
    completed
    notCompleted

proc addBlock*(
    self: var BlockProcessor, src: MsgSource, blck: ForkedSignedBeaconBlock,
    resfut: Future[Result[void, VerifierError]] = nil,
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
          optimistic: bool = false): ref BlockProcessor =
  (ref BlockProcessor)(
    dumpEnabled: dumpEnabled,
    dumpDirInvalid: dumpDirInvalid,
    dumpDirIncoming: dumpDirIncoming,
    blockQueue: newAsyncQueue[BlockEntry](),
    consensusManager: consensusManager,
    validatorMonitor: validatorMonitor,
    getBeaconTime: getBeaconTime,
    verifier: BatchVerifier(rng: rng, taskpool: taskpool),
    optimistic: optimistic
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
    res: Result[T, VerifierError]) =
  if self.dumpEnabled and res.isErr:
    case res.error
    of VerifierError.Invalid:
      self.dumpInvalidBlock(signedBlock)
    of VerifierError.MissingParent:
      dump(self.dumpDirIncoming, signedBlock)
    else:
      discard

from ../consensus_object_pools/block_clearance import
  addBackfillBlock, addHeadBlock

proc storeBackfillBlock(
    self: var BlockProcessor,
    signedBlock: ForkySignedBeaconBlock): Result[void, VerifierError] =

  # The block is certainly not missing any more
  self.consensusManager.quarantine[].missing.del(signedBlock.root)

  let res = self.consensusManager.dag.addBackfillBlock(signedBlock)

  if res.isErr():
    case res.error
    of VerifierError.MissingParent:
      if signedBlock.message.parent_root in
          self.consensusManager.quarantine[].unviable:
        # DAG doesn't know about unviable ancestor blocks - we do! Translate
        # this to the appropriate error so that sync etc doesn't retry the block
        self.consensusManager.quarantine[].addUnviable(signedBlock.root)

        return err(VerifierError.UnviableFork)
    of VerifierError.UnviableFork:
      # Track unviables so that descendants can be discarded properly
      self.consensusManager.quarantine[].addUnviable(signedBlock.root)
    else: discard

  res

from web3/engine_api_types import PayloadExecutionStatus, PayloadStatusV1
from ../eth1/eth1_monitor import
  Eth1Monitor, asEngineExecutionPayload, ensureDataProvider, newPayload

proc expectValidForkchoiceUpdated(
    eth1Monitor: Eth1Monitor,
    headBlockHash, safeBlockHash, finalizedBlockHash: Eth2Digest,
    receivedBlock: ForkySignedBeaconBlock): Future[void] {.async.} =
  let
    (payloadExecutionStatus, _) = await eth1Monitor.runForkchoiceUpdated(
      headBlockHash, safeBlockHash, finalizedBlockHash)
    receivedExecutionBlockHash =
      when typeof(receivedBlock).toFork >= BeaconBlockFork.Bellatrix:
        receivedBlock.message.body.execution_payload.block_hash
      else:
        # https://github.com/nim-lang/Nim/issues/19802
        (static(default(Eth2Digest)))

  # Only called when expecting this to be valid because `newPayload` or some
  # previous `forkchoiceUpdated` had already marked it as valid. However, if
  # it's not the block that was received, don't info/warn either way given a
  # relative lack of immediate evidence.
  if receivedExecutionBlockHash != headBlockHash:
    return

  case payloadExecutionStatus
  of PayloadExecutionStatus.valid:
    # situation nominal
    discard
  of PayloadExecutionStatus.accepted, PayloadExecutionStatus.syncing:
    info "execution payload forkChoiceUpdated status ACCEPTED/SYNCING, but was previously VALID",
      payloadExecutionStatus = $payloadExecutionStatus, headBlockHash,
      safeBlockHash, finalizedBlockHash,
      receivedBlock = shortLog(receivedBlock)
  of PayloadExecutionStatus.invalid, PayloadExecutionStatus.invalid_block_hash:
    warn "execution payload forkChoiceUpdated status INVALID, but was previously VALID",
      payloadExecutionStatus = $payloadExecutionStatus, headBlockHash,
      safeBlockHash, finalizedBlockHash,
      receivedBlock = shortLog(receivedBlock)

from ../consensus_object_pools/attestation_pool import
  addForkChoice, selectOptimisticHead, BeaconHead
from ../consensus_object_pools/blockchain_dag import
  is_optimistic, loadExecutionBlockRoot, markBlockVerified
from ../consensus_object_pools/block_dag import shortLog
from ../consensus_object_pools/spec_cache import get_attesting_indices
from ../spec/datatypes/phase0 import TrustedSignedBeaconBlock
from ../spec/datatypes/altair import SignedBeaconBlock
from ../spec/datatypes/bellatrix import SignedBeaconBlock

from eth/async_utils import awaitWithTimeout
from ../spec/datatypes/bellatrix import ExecutionPayload, SignedBeaconBlock
from ../spec/datatypes/capella import
  ExecutionPayload, SignedBeaconBlock, asTrusted, shortLog

proc newExecutionPayload*(
    eth1Monitor: Eth1Monitor,
    executionPayload: bellatrix.ExecutionPayload | capella.ExecutionPayload):
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

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.1/src/engine/specification.md#request
  const NEWPAYLOAD_TIMEOUT = 8.seconds

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
      payloadStatus = $payloadStatus

    return Opt.some payloadStatus
  except CatchableError as err:
    error "newPayload failed", msg = err.msg
    return Opt.none PayloadExecutionStatus

proc getExecutionValidity(
    eth1Monitor: Eth1Monitor,
    blck: phase0.SignedBeaconBlock | altair.SignedBeaconBlock):
    Future[NewPayloadStatus] {.async.} =
  return NewPayloadStatus.valid   # vacuously

proc getExecutionValidity(
    eth1Monitor: Eth1Monitor,
    blck: bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock):
    Future[NewPayloadStatus] {.async.} =
  # Eth1 syncing is asynchronous from this
  # TODO self.consensusManager.eth1Monitor.ttdReached
  # should gate this when it works more reliably
  # TODO detect have-TTD-but-not-is_execution_block case, and where
  # execution payload was non-zero when TTD detection more reliable

  if not blck.message.is_execution_block:
    return NewPayloadStatus.valid  # vacuously

  try:
    # Minimize window for Eth1 monitor to shut down connection
    await eth1Monitor.ensureDataProvider()

    let executionPayloadStatus = await newExecutionPayload(
      eth1Monitor, blck.message.body.execution_payload)
    if executionPayloadStatus.isNone:
      return NewPayloadStatus.noResponse

    case executionPayloadStatus.get
      of PayloadExecutionStatus.invalid, PayloadExecutionStatus.invalid_block_hash:
        debug "getExecutionValidity: execution payload invalid",
          executionPayloadStatus = $executionPayloadStatus.get,
          blck = shortLog(blck)
        return NewPayloadStatus.invalid
      of PayloadExecutionStatus.syncing, PayloadExecutionStatus.accepted:
        return NewPayloadStatus.notValid
      of PayloadExecutionStatus.valid:
        return NewPayloadStatus.valid
  except CatchableError as err:
    error "getExecutionValidity: newPayload failed", err = err.msg
    return NewPayloadStatus.noResponse

proc storeBlock*(
    self: ref BlockProcessor, src: MsgSource, wallTime: BeaconTime,
    signedBlock: ForkySignedBeaconBlock, queueTick: Moment = Moment.now(),
    validationDur = Duration()):
    Future[Result[BlockRef, (VerifierError, ProcessingStatus)]] {.async.} =
  ## storeBlock is the main entry point for unvalidated blocks - all untrusted
  ## blocks, regardless of origin, pass through here. When storing a block,
  ## we will add it to the dag and pass it to all block consumers that need
  ## to know about it, such as the fork choice and the monitoring
  let
    attestationPool = self.consensusManager.attestationPool
    startTick = Moment.now()
    vm = self.validatorMonitor
    dag = self.consensusManager.dag
    payloadStatus =
      await self.consensusManager.eth1Monitor.getExecutionValidity(signedBlock)
    payloadValid = payloadStatus == NewPayloadStatus.valid

  # The block is certainly not missing any more
  self.consensusManager.quarantine[].missing.del(signedBlock.root)

  if NewPayloadStatus.invalid == payloadStatus:
    self.consensusManager.quarantine[].addUnviable(signedBlock.root)
    return err((VerifierError.UnviableFork, ProcessingStatus.completed))

  if NewPayloadStatus.noResponse == payloadStatus and not self[].optimistic:
    # Disallow the `MissingParent` from leaking to the sync/request managers
    # as it will be descored. However sync and request managers interact via
    # `processBlock` (indirectly). `validator_duties` does call `storeBlock`
    # directly, so is exposed to this, but only cares about whether there is
    # an error or not.
    return err((
      VerifierError.MissingParent, ProcessingStatus.notCompleted))

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
            forkyState.data.current_sync_committee.pubkeys.data[i])

  self[].dumpBlock(signedBlock, blck)

  # There can be a scenario where we receive a block we already received.
  # However this block was before the last finalized epoch and so its parent
  # was pruned from the ForkChoice.
  if blck.isErr():
    case blck.error()
    of VerifierError.MissingParent:
      if signedBlock.message.parent_root in
          self.consensusManager.quarantine[].unviable:
        # DAG doesn't know about unviable ancestor blocks - we do! Translate
        # this to the appropriate error so that sync etc doesn't retry the block
        self.consensusManager.quarantine[].addUnviable(signedBlock.root)

        return err((VerifierError.UnviableFork, ProcessingStatus.completed))

      if not self.consensusManager.quarantine[].addOrphan(
          dag.finalizedHead.slot, ForkedSignedBeaconBlock.init(signedBlock)):
        debug "Block quarantine full",
          blockRoot = shortLog(signedBlock.root),
          blck = shortLog(signedBlock.message),
          signature = shortLog(signedBlock.signature)
    of VerifierError.UnviableFork:
      # Track unviables so that descendants can be discarded properly
      self.consensusManager.quarantine[].addUnviable(signedBlock.root)
    else: discard

    return err((blck.error, ProcessingStatus.completed))

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
        headBlockHash = self.consensusManager[].optimisticExecutionPayloadHash,
        safeBlockHash = newHead.get.safeExecutionPayloadHash,
        finalizedBlockHash = newHead.get.finalizedExecutionPayloadHash)
    else:
      let
        headExecutionPayloadHash =
          self.consensusManager.dag.loadExecutionBlockRoot(newHead.get.blck)
        wallSlot = self.getBeaconTime().slotOrZero
      if headExecutionPayloadHash.isZero:
        # Blocks without execution payloads can't be optimistic.
        self.consensusManager[].updateHead(newHead.get.blck)
      elif not self.consensusManager.dag.is_optimistic newHead.get.blck.root:
        # Not `NOT_VALID`; either `VALID` or `INVALIDATED`, but latter wouldn't
        # be selected as head, so `VALID`. `forkchoiceUpdated` necessary for EL
        # client only.
        self.consensusManager[].updateHead(newHead.get.blck)

        if self.consensusManager.checkNextProposer(wallSlot).isNone:
          # No attached validator is next proposer, so use non-proposal fcU
          asyncSpawn eth1Monitor.expectValidForkchoiceUpdated(
            headBlockHash = headExecutionPayloadHash,
            safeBlockHash = newHead.get.safeExecutionPayloadHash,
            finalizedBlockHash = newHead.get.finalizedExecutionPayloadHash,
            receivedBlock = signedBlock)
        else:
          # Some attached validator is next proposer, so prepare payload. As
          # updateHead() updated the DAG head, runProposalForkchoiceUpdated,
          # which needs the state corresponding to that head block, can run.
          asyncSpawn self.consensusManager.runProposalForkchoiceUpdated(
            wallSlot)
      else:
        asyncSpawn self.consensusManager.updateHeadWithExecution(
          newHead.get, self.getBeaconTime)
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
    self[].addBlock(MsgSource.gossip, quarantined)

  return Result[BlockRef, (VerifierError, ProcessingStatus)].ok blck.get

# Enqueue
# ------------------------------------------------------------------------------

proc addBlock*(
    self: var BlockProcessor, src: MsgSource, blck: ForkedSignedBeaconBlock,
    resfut: Future[Result[void, VerifierError]] = nil,
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
    self: ref BlockProcessor, entry: BlockEntry) {.async.} =
  logScope:
    blockRoot = shortLog(entry.blck.root)

  let
    wallTime = self.getBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing block before genesis, clock turned back?"
    quit 1

  let res = withBlck(entry.blck):
    await self.storeBlock(
      entry.src, wallTime, blck, entry.queueTick, entry.validationDur)

  if res.isErr and res.error[1] == ProcessingStatus.notCompleted:
    # When an execution engine returns an error or fails to respond to a
    # payload validity request for some block, a consensus engine:
    # - MUST NOT optimistically import the block.
    # - MUST NOT apply the block to the fork choice store.
    # - MAY queue the block for later processing.
    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/sync/optimistic.md#execution-engine-errors
    await sleepAsync(chronos.seconds(1))
    self[].addBlock(
      entry.src, entry.blck, entry.resfut, entry.validationDur)

    # To ensure backpressure on the sync manager, do not complete these futures.
    return

  if entry.resfut != nil:
    entry.resfut.complete(
      if res.isOk(): Result[void, VerifierError].ok()
      else: Result[void, VerifierError].err(res.error()[0]))

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

    await self.processBlock(await self[].blockQueue.popFirst())
