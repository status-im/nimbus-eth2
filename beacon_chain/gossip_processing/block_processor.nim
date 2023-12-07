# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/results,
  chronicles, chronos, metrics,
  ../spec/[signatures, signatures_batch],
  ../sszdump

from std/deques import Deque, addLast, contains, initDeque, items, len, shrink
from std/sequtils import mapIt
from ../consensus_object_pools/consensus_manager import
  ConsensusManager, checkNextProposer, optimisticExecutionPayloadHash,
  runProposalForkchoiceUpdated, shouldSyncOptimistically, updateHead,
  updateHeadWithExecution
from ../consensus_object_pools/blockchain_dag import
  getBlockRef, getProposer, forkAtEpoch, loadExecutionBlockHash,
  markBlockVerified, validatorKey
from ../beacon_clock import GetBeaconTimeFn, toFloatSeconds
from ../consensus_object_pools/block_dag import BlockRef, root, shortLog, slot
from ../consensus_object_pools/block_pools_types import
  EpochRef, VerifierError
from ../consensus_object_pools/block_quarantine import
  addBlobless, addOrphan, addUnviable, pop, removeOrphan
from ../consensus_object_pools/blob_quarantine import
  BlobQuarantine, hasBlobs, popBlobs
from ../validators/validator_monitor import
  MsgSource, ValidatorMonitor, registerAttestationInBlock, registerBeaconBlock,
  registerSyncAggregateInBlock
from ../beacon_chain_db import putBlobSidecar
from ../spec/state_transition_block import validate_blobs

export sszdump, signatures_batch

logScope: topics = "gossip_blocks"

# Block Processor
# ------------------------------------------------------------------------------
# The block processor moves blocks from "Incoming" to "Consensus verified"

declareHistogram beacon_store_block_duration_seconds,
  "storeBlock() duration", buckets = [0.25, 0.5, 1, 2, 4, 8, Inf]

const
  SLOTS_PER_PAYLOAD = SLOTS_PER_HISTORICAL_ROOT
    ## Number of slots we process between each execution payload execution, while
    ## syncing the finalized part of the chain
  PAYLOAD_PRE_WALL_SLOTS = SLOTS_PER_EPOCH * 2
    ## Number of slots from wall time that we start processing every payload

type
  BlobSidecars* = seq[ref BlobSidecar]
  BlockEntry = object
    blck*: ForkedSignedBeaconBlock
    blobs*: Opt[BlobSidecars]
    maybeFinalized*: bool
      ## The block source claims the block has been finalized already
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
      ## Blockchain DAG, AttestationPool, Quarantine, and ELManager
    validatorMonitor: ref ValidatorMonitor
    getBeaconTime: GetBeaconTimeFn

    blobQuarantine: ref BlobQuarantine
    verifier: BatchVerifier

    lastPayload: Slot
      ## The slot at which we sent a payload to the execution client the last
      ## time

  NewPayloadStatus {.pure.} = enum
    valid
    notValid
    invalid
    noResponse

  ProcessingStatus {.pure.} = enum
    completed
    notCompleted

# Initialization
# ------------------------------------------------------------------------------

proc new*(T: type BlockProcessor,
          dumpEnabled: bool,
          dumpDirInvalid, dumpDirIncoming: string,
          rng: ref HmacDrbgContext, taskpool: TaskPoolPtr,
          consensusManager: ref ConsensusManager,
          validatorMonitor: ref ValidatorMonitor,
          blobQuarantine: ref BlobQuarantine,
          getBeaconTime: GetBeaconTimeFn): ref BlockProcessor =
  (ref BlockProcessor)(
    dumpEnabled: dumpEnabled,
    dumpDirInvalid: dumpDirInvalid,
    dumpDirIncoming: dumpDirIncoming,
    blockQueue: newAsyncQueue[BlockEntry](),
    consensusManager: consensusManager,
    validatorMonitor: validatorMonitor,
    blobQuarantine: blobQuarantine,
    getBeaconTime: getBeaconTime,
    verifier: BatchVerifier.init(rng, taskpool)
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
  addBackfillBlock, addHeadBlockWithParent, checkHeadBlock

proc storeBackfillBlock(
    self: var BlockProcessor,
    signedBlock: ForkySignedBeaconBlock,
    blobsOpt: Opt[BlobSidecars]): Result[void, VerifierError] =

  # The block is certainly not missing any more
  self.consensusManager.quarantine[].missing.del(signedBlock.root)

  # Establish blob viability before calling addbackfillBlock to avoid
  # writing the block in case of blob error.
  var blobsOk = true
  when typeof(signedBlock).kind >= ConsensusFork.Deneb:
    if blobsOpt.isSome:
      let blobs = blobsOpt.get()
      let kzgCommits = signedBlock.message.body.blob_kzg_commitments.asSeq
      if blobs.len > 0 or kzgCommits.len > 0:
        let r = validate_blobs(kzgCommits, blobs.mapIt(it.blob),
                               blobs.mapIt(it.kzg_proof))
        if r.isErr():
          debug "backfill blob validation failed",
           blockRoot = shortLog(signedBlock.root),
           blobs = shortLog(blobs),
           blck = shortLog(signedBlock.message),
           signature = shortLog(signedBlock.signature),
           msg = r.error()
        blobsOk = r.isOk()

  if not blobsOk:
    return err(VerifierError.Invalid)

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
    return res

  # Only store blobs after successfully establishing block viability.
  let blobs = blobsOpt.valueOr: BlobSidecars @[]
  for b in blobs:
    self.consensusManager.dag.db.putBlobSidecar(b[])

  res

from web3/engine_api_types import
  PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3,
  PayloadExecutionStatus, PayloadStatusV1
from ../el/el_manager import
  ELManager, forkchoiceUpdated, hasConnection, hasProperlyConfiguredConnection,
  sendNewPayload

proc expectValidForkchoiceUpdated(
    elManager: ELManager, headBlockPayloadAttributesType: typedesc,
    headBlockHash, safeBlockHash, finalizedBlockHash: Eth2Digest,
    receivedBlock: ForkySignedBeaconBlock): Future[void] {.async.} =
  let
    (payloadExecutionStatus, _) = await elManager.forkchoiceUpdated(
      headBlockHash = headBlockHash,
      safeBlockHash = safeBlockHash,
      finalizedBlockHash = finalizedBlockHash,
      payloadAttributes = none headBlockPayloadAttributesType)
    receivedExecutionBlockHash =
      when typeof(receivedBlock).kind >= ConsensusFork.Bellatrix:
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
from ../consensus_object_pools/spec_cache import get_attesting_indices
from ../spec/datatypes/phase0 import TrustedSignedBeaconBlock
from ../spec/datatypes/altair import SignedBeaconBlock

from ../spec/datatypes/bellatrix import ExecutionPayload, SignedBeaconBlock
from ../spec/datatypes/capella import
  ExecutionPayload, SignedBeaconBlock, asTrusted, shortLog

# TODO investigate why this seems to allow compilation even though it doesn't
# directly address deneb.ExecutionPayload when complaint was that it didn't
# know about "deneb"
from ../spec/datatypes/deneb import SignedBeaconBlock, asTrusted, shortLog

proc newExecutionPayload*(
    elManager: ELManager, blck: SomeForkyBeaconBlock):
    Future[Opt[PayloadExecutionStatus]] {.async.} =

  template executionPayload: untyped = blck.body.execution_payload

  if not elManager.hasProperlyConfiguredConnection:
    if elManager.hasConnection:
      info "No execution client connected; cannot process block payloads",
        executionPayload = shortLog(executionPayload)
    else:
      debug "No execution client connected; cannot process block payloads",
        executionPayload = shortLog(executionPayload)
    return Opt.none PayloadExecutionStatus

  debug "newPayload: inserting block into execution engine",
    executionPayload = shortLog(executionPayload)

  try:
    let payloadStatus = await elManager.sendNewPayload(blck)

    debug "newPayload: succeeded",
      parentHash = executionPayload.parent_hash,
      blockHash = executionPayload.block_hash,
      blockNumber = executionPayload.block_number,
      payloadStatus = $payloadStatus

    return Opt.some payloadStatus
  except CatchableError as err:
    warn "newPayload failed - check execution client",
      msg = err.msg,
      parentHash = shortLog(executionPayload.parent_hash),
      blockHash = shortLog(executionPayload.block_hash),
      blockNumber = executionPayload.block_number
    return Opt.none PayloadExecutionStatus

proc getExecutionValidity(
    elManager: ELManager,
    blck: bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock |
          deneb.SignedBeaconBlock):
    Future[NewPayloadStatus] {.async.} =
  if not blck.message.is_execution_block:
    return NewPayloadStatus.valid  # vacuously

  try:
    let executionPayloadStatus = await elManager.newExecutionPayload(
      blck.message)
    if executionPayloadStatus.isNone:
      return NewPayloadStatus.noResponse

    case executionPayloadStatus.get
      of PayloadExecutionStatus.invalid, PayloadExecutionStatus.invalid_block_hash:
        # Blocks come either from gossip or request manager requests. In the
        # former case, they've passed libp2p gosisp validation which implies
        # correct signature for correct proposer,which makes spam expensive,
        # while for the latter, spam is limited by the request manager.
        info "execution payload invalid from EL client newPayload",
          executionPayloadStatus = $executionPayloadStatus.get,
          executionPayload = shortLog(blck.message.body.execution_payload),
          blck = shortLog(blck)
        return NewPayloadStatus.invalid
      of PayloadExecutionStatus.syncing, PayloadExecutionStatus.accepted:
        return NewPayloadStatus.notValid
      of PayloadExecutionStatus.valid:
        return NewPayloadStatus.valid
  except CatchableError as err:
    error "newPayload failed and leaked exception",
      err = err.msg,
      executionPayload = shortLog(blck.message.body.execution_payload),
      blck = shortLog(blck)
    return NewPayloadStatus.noResponse

proc checkBloblessSignature(self: BlockProcessor,
                            signed_beacon_block: deneb.SignedBeaconBlock):
                              Result[void, cstring] =
  let dag = self.consensusManager.dag
  let parent = dag.getBlockRef(signed_beacon_block.message.parent_root).valueOr:
    return err("checkBloblessSignature called with orphan block")
  let proposer = getProposer(
        dag, parent, signed_beacon_block.message.slot).valueOr:
    return err("checkBloblessSignature: Cannot compute proposer")
  if uint64(proposer) != signed_beacon_block.message.proposer_index:
    return err("checkBloblessSignature: Incorrect proposer")
  if not verify_block_signature(
      dag.forkAtEpoch(signed_beacon_block.message.slot.epoch),
      getStateField(dag.headState, genesis_validators_root),
      signed_beacon_block.message.slot,
      signed_beacon_block.root,
      dag.validatorKey(proposer).get(),
      signed_beacon_block.signature):
    return err("checkBloblessSignature: Invalid proposer signature")
  ok()

proc enqueueBlock*(
    self: var BlockProcessor, src: MsgSource, blck: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars],
    resfut: Future[Result[void, VerifierError]] = nil,
    maybeFinalized = false,
    validationDur = Duration()) =
  withBlck(blck):
    if forkyBlck.message.slot <= self.consensusManager.dag.finalizedHead.slot:
      # let backfill blocks skip the queue - these are always "fast" to process
      # because there are no state rewinds to deal with
      let res = self.storeBackfillBlock(forkyBlck, blobs)
      resfut.complete(res)
      return

  try:
    self.blockQueue.addLastNoWait(BlockEntry(
      blck: blck,
      blobs: blobs,
      maybeFinalized: maybeFinalized,
      resfut: resfut, queueTick: Moment.now(),
      validationDur: validationDur,
      src: src))
  except AsyncQueueFullError:
    raiseAssert "unbounded queue"

proc storeBlock(
    self: ref BlockProcessor, src: MsgSource, wallTime: BeaconTime,
    signedBlock: ForkySignedBeaconBlock,
    blobsOpt: Opt[BlobSidecars],
    maybeFinalized = false,
    queueTick: Moment = Moment.now(), validationDur = Duration()):
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
    wallSlot = wallTime.slotOrZero

  # If the block is missing its parent, it will be re-orphaned below
  self.consensusManager.quarantine[].removeOrphan(signedBlock)
  # The block is certainly not missing any more
  self.consensusManager.quarantine[].missing.del(signedBlock.root)

  if signedBlock.message.parent_root in
      self.consensusManager.quarantine[].unviable:
    # DAG doesn't know about unviable ancestor blocks - we do however!
    self.consensusManager.quarantine[].addUnviable(signedBlock.root)

    return err((VerifierError.UnviableFork, ProcessingStatus.completed))

  template handleVerifierError(errorParam: VerifierError): auto =
    let error = errorParam
    case error
    of VerifierError.MissingParent:
      if (let r = self.consensusManager.quarantine[].addOrphan(
          dag.finalizedHead.slot, ForkedSignedBeaconBlock.init(signedBlock));
              r.isErr()):
        debug "could not add orphan",
          blockRoot = shortLog(signedBlock.root),
          blck = shortLog(signedBlock.message),
          signature = shortLog(signedBlock.signature),
          err = r.error()
      else:
        debug "Block quarantined",
          blockRoot = shortLog(signedBlock.root),
          blck = shortLog(signedBlock.message),
          signature = shortLog(signedBlock.signature)

    of VerifierError.UnviableFork:
      # Track unviables so that descendants can be discarded promptly
      self.consensusManager.quarantine[].addUnviable(signedBlock.root)
    else:
      discard

    err((error, ProcessingStatus.completed))

  let
    # We have to be careful that there exists only one in-flight entry point
    # for adding blocks or the checks performed in `checkHeadBlock` might
    # be invalidated (ie a block could be added while we wait for EL response
    # here)
    parent = dag.checkHeadBlock(signedBlock)

  if parent.isErr():
    return handleVerifierError(parent.error())

  let
    payloadStatus =
      if maybeFinalized and
          (self.lastPayload + SLOTS_PER_PAYLOAD) > signedBlock.message.slot and
          (signedBlock.message.slot + PAYLOAD_PRE_WALL_SLOTS) < wallSlot and
          signedBlock.message.is_execution_block:
        # Skip payload validation when message source (reasonably) claims block
        # has been finalized - this speeds up forward sync - in the worst case
        # that the claim is false, we will correct every time we process a block
        # from an honest source (or when we're close to head).
        # Occasionally we also send a payload to the the EL so that it can
        # progress in its own sync.
        NewPayloadStatus.noResponse
      else:
        when typeof(signedBlock).kind >= ConsensusFork.Bellatrix:
          await self.consensusManager.elManager.getExecutionValidity(signedBlock)
        else:
          NewPayloadStatus.valid # vacuously
    payloadValid = payloadStatus == NewPayloadStatus.valid

  if NewPayloadStatus.invalid == payloadStatus:
    self.consensusManager.quarantine[].addUnviable(signedBlock.root)
    return err((VerifierError.UnviableFork, ProcessingStatus.completed))

  if NewPayloadStatus.noResponse == payloadStatus:
    # When the execution layer is not available to verify the payload, we do the
    # required check on the CL side instead and proceed as if the EL was syncing

    # TODO run https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/beacon-chain.md#blob-kzg-commitments
    # https://github.com/ethereum/execution-apis/blob/main/src/engine/experimental/blob-extension.md#specification
    # "This validation MUST be instantly run in all cases even during active sync process."
    #
    # Client software MUST validate `blockHash` value as being equivalent to
    # `Keccak256(RLP(ExecutionBlockHeader))`
    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/paris.md#specification
    when typeof(signedBlock).kind >= ConsensusFork.Bellatrix:
      template payload(): auto = signedBlock.message.body.execution_payload
      if  signedBlock.message.is_execution_block and
          payload.block_hash !=
            signedBlock.message.compute_execution_block_hash():
        debug "Execution block hash validation failed",
          execution_payload = shortLog(payload)
        self[].dumpInvalidBlock(signedBlock)
        doAssert strictVerification notin dag.updateFlags
        self.consensusManager.quarantine[].addUnviable(signedBlock.root)
        return err((VerifierError.Invalid, ProcessingStatus.completed))
    else:
      discard

  let newPayloadTick = Moment.now()

  # TODO with v1.4.0, not sure this is still relevant
  # Establish blob viability before calling addHeadBlock to avoid
  # writing the block in case of blob error.
  when typeof(signedBlock).kind >= ConsensusFork.Deneb:
    if blobsOpt.isSome:
      let blobs = blobsOpt.get()
      let kzgCommits = signedBlock.message.body.blob_kzg_commitments.asSeq
      if blobs.len > 0 or kzgCommits.len > 0:
        let r = validate_blobs(kzgCommits, blobs.mapIt(it.blob),
                               blobs.mapIt(it.kzg_proof))
        if r.isErr():
          debug "blob validation failed",
            blockRoot = shortLog(signedBlock.root),
            blobs = shortLog(blobs),
            blck = shortLog(signedBlock.message),
            signature = shortLog(signedBlock.signature),
            msg = r.error()
          return err((VerifierError.Invalid, ProcessingStatus.completed))

  type Trusted = typeof signedBlock.asTrusted()

  let
    blck = dag.addHeadBlockWithParent(
        self.verifier, signedBlock, parent.value(), payloadValid) do (
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
        when consensusFork >= ConsensusFork.Altair and
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
    return handleVerifierError(blck.error())

  # Even if the EL is not responding, we'll only try once every now and then
  # to give it a block - this avoids a pathological slowdown where a busy EL
  # times out on every block we give it because it's busy with the previous
  # one
  self[].lastPayload = signedBlock.message.slot

  # write blobs now that block has been written.
  let blobs = blobsOpt.valueOr: BlobSidecars @[]
  for b in blobs:
    self.consensusManager.dag.db.putBlobSidecar(b[])

  let addHeadBlockTick = Moment.now()

  # Eagerly update head: the incoming block "should" get selected.
  #
  # storeBlock gets called from validator_duties, which depends on its not
  # blocking progress any longer than necessary, and processBlock here, in
  # which case it's fine to await for a while on engine API results.
  #
  # Three general scenarios: (1) pre-merge; (2) merge, already `VALID` by way
  # of `newPayload`; (3) optimistically imported, need to call fcU before DAG
  # updateHead. Because in a non-finalizing network, completing sync isn't as
  # useful because regular reorgs likely still occur, and when finalizing the
  # EL is only called every SLOTS_PER_PAYLOAD slots regardless, await, rather
  # than asyncSpawn forkchoiceUpdated calls.
  #
  # This reduces in-flight fcU spam, which both reduces EL load and decreases
  # otherwise somewhat unpredictable CL head movement.

  # Grab the new head according to our latest attestation data; determines how
  # async this needs to be.
  let newHead = attestationPool[].selectOptimisticHead(
    wallSlot.start_beacon_time)

  if newHead.isOk:
    template elManager(): auto = self.consensusManager.elManager
    if self.consensusManager[].shouldSyncOptimistically(wallSlot):
      # Optimistic head is far in the future; report it as head block to EL.

      # Note that the specification allows an EL client to skip fcU processing
      # if an update to an ancestor is requested.
      # > Client software MAY skip an update of the forkchoice state and MUST
      #   NOT begin a payload build process if `forkchoiceState.headBlockHash`
      #   references an ancestor of the head of canonical chain.
      # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/paris.md#specification-1
      #
      # However, in practice, an EL client may not have completed importing all
      # block headers, so may be unaware of a block's ancestor status.
      # Therefore, hopping back and forth between the optimistic head and the
      # chain DAG head does not work well in practice, e.g., Geth:
      # - "Beacon chain gapped" from DAG head to optimistic head,
      # - followed by "Beacon chain reorged" from optimistic head back to DAG.
      self.consensusManager[].updateHead(newHead.get.blck)

      template callForkchoiceUpdated(attributes: untyped) =
        if  NewPayloadStatus.noResponse != payloadStatus and
            not self.consensusManager[].optimisticExecutionPayloadHash.isZero:
          discard await elManager.forkchoiceUpdated(
            headBlockHash =
              self.consensusManager[].optimisticExecutionPayloadHash,
            safeBlockHash = newHead.get.safeExecutionPayloadHash,
            finalizedBlockHash = newHead.get.finalizedExecutionPayloadHash,
            payloadAttributes = none attributes)

      let consensusFork = self.consensusManager.dag.cfg.consensusForkAtEpoch(
        newHead.get.blck.bid.slot.epoch)
      withConsensusFork(consensusFork):
        when consensusFork >= ConsensusFork.Bellatrix:
          callForkchoiceUpdated(consensusFork.PayloadAttributes)
    else:
      let
        headExecutionPayloadHash =
          dag.loadExecutionBlockHash(newHead.get.blck)
        wallSlot = self.getBeaconTime().slotOrZero
      if  headExecutionPayloadHash.isZero or
          NewPayloadStatus.noResponse == payloadStatus:
        # Blocks without execution payloads can't be optimistic, and don't try
        # to fcU to a block the EL hasn't seen
        self.consensusManager[].updateHead(newHead.get.blck)
      elif newHead.get.blck.executionValid:
        # `forkchoiceUpdated` necessary for EL client only.
        self.consensusManager[].updateHead(newHead.get.blck)

        template callExpectValidFCU(payloadAttributeType: untyped): auto =
          await elManager.expectValidForkchoiceUpdated(
            headBlockPayloadAttributesType = payloadAttributeType,
            headBlockHash = headExecutionPayloadHash,
            safeBlockHash = newHead.get.safeExecutionPayloadHash,
            finalizedBlockHash = newHead.get.finalizedExecutionPayloadHash,
            receivedBlock = signedBlock)

        template callForkChoiceUpdated: auto =
          case self.consensusManager.dag.cfg.consensusForkAtEpoch(
              newHead.get.blck.bid.slot.epoch)
          of ConsensusFork.Deneb:
            callExpectValidFCU(payloadAttributeType = PayloadAttributesV3)
          of ConsensusFork.Capella:
            callExpectValidFCU(payloadAttributeType = PayloadAttributesV2)
          of  ConsensusFork.Phase0, ConsensusFork.Altair,
              ConsensusFork.Bellatrix:
            callExpectValidFCU(payloadAttributeType = PayloadAttributesV1)

        if self.consensusManager.checkNextProposer(wallSlot).isNone:
          # No attached validator is next proposer, so use non-proposal fcU
          callForkChoiceUpdated()
        else:
          # Some attached validator is next proposer, so prepare payload. As
          # updateHead() updated the DAG head, runProposalForkchoiceUpdated,
          # which needs the state corresponding to that head block, can run.
          if (await self.consensusManager.runProposalForkchoiceUpdated(
              wallSlot)).isNone:
            callForkChoiceUpdated()
      else:
        await self.consensusManager.updateHeadWithExecution(
          newHead.get, self.getBeaconTime)
  else:
    warn "Head selection failed, using previous head",
      head = shortLog(dag.head), wallSlot

  let
    updateHeadTick = Moment.now()
    queueDur = startTick - queueTick
    newPayloadDur = newPayloadTick - startTick
    addHeadBlockDur = addHeadBlockTick - newPayloadTick
    updateHeadDur = updateHeadTick - addHeadBlockTick

    # "store block" is the full time it takes to process the block - in the log
    # we split this into execution and consensus timings
    storeBlockDur = newPayloadDur + addHeadBlockDur

  beacon_store_block_duration_seconds.observe(storeBlockDur.toFloatSeconds())

  debug "Block processed",
    head = shortLog(dag.head),
    blck = shortLog(blck.get()),
    validationDur, queueDur, newPayloadDur, addHeadBlockDur, updateHeadDur

  for quarantined in self.consensusManager.quarantine[].pop(blck.get().root):
    # Process the blocks that had the newly accepted block as parent
    debug "Block from quarantine",
      blockRoot = shortLog(signedBlock.root),
      quarantined = shortLog(quarantined.root)

    withBlck(quarantined):
      when typeof(forkyBlck).kind < ConsensusFork.Deneb:
        self[].enqueueBlock(
          MsgSource.gossip, quarantined, Opt.none(BlobSidecars))
      else:
        if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
          self[].enqueueBlock(
            MsgSource.gossip, quarantined, Opt.some(BlobSidecars @[]))
        else:
          if (let res = checkBloblessSignature(self[], forkyBlck); res.isErr):
            warn "Failed to verify signature of unorphaned blobless block",
             blck = shortLog(forkyBlck),
             error = res.error()
            continue
          if self.blobQuarantine[].hasBlobs(forkyBlck):
            let blobs = self.blobQuarantine[].popBlobs(
              forkyBlck.root, forkyBlck)
            self[].enqueueBlock(MsgSource.gossip, quarantined, Opt.some(blobs))
          else:
            if not self.consensusManager.quarantine[].addBlobless(
              dag.finalizedHead.slot, forkyBlck):
              notice "Block quarantine full (blobless)",
               blockRoot = shortLog(quarantined.root),
               signature = shortLog(quarantined.signature)

  ok blck.value()

# Enqueue
# ------------------------------------------------------------------------------

proc addBlock*(
    self: var BlockProcessor, src: MsgSource, blck: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars], maybeFinalized = false,
    validationDur = Duration()): Future[Result[void, VerifierError]] =
  ## Enqueue a Gossip-validated block for consensus verification
  # Backpressure:
  #   There is no backpressure here - producers must wait for `resfut` to
  #   constrain their own processing
  # Producers:
  # - Gossip (when synced)
  # - SyncManager (during sync)
  # - RequestManager (missing ancestor blocks)
  # - API
  let resfut = newFuture[Result[void, VerifierError]]("BlockProcessor.addBlock")
  enqueueBlock(self, src, blck, blobs, resfut, maybeFinalized, validationDur)
  resfut

# Event Loop
# ------------------------------------------------------------------------------

proc processBlock(
    self: ref BlockProcessor, entry: BlockEntry) {.async.} =
  logScope:
    blockRoot = shortLog(entry.blck.root)

  let
    wallTime = self.getBeaconTime()
    (afterGenesis, _) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing block before genesis, clock turned back?"
    quit 1

  let res = withBlck(entry.blck):
    await self.storeBlock(
      entry.src, wallTime, forkyBlck, entry.blobs, entry.maybeFinalized,
      entry.queueTick, entry.validationDur)

  if res.isErr and res.error[1] == ProcessingStatus.notCompleted:
    # When an execution engine returns an error or fails to respond to a
    # payload validity request for some block, a consensus engine:
    # - MUST NOT optimistically import the block.
    # - MUST NOT apply the block to the fork choice store.
    # - MAY queue the block for later processing.
    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/sync/optimistic.md#execution-engine-errors
    await sleepAsync(chronos.seconds(1))
    self[].enqueueBlock(
      entry.src, entry.blck, entry.blobs, entry.resfut, entry.maybeFinalized,
      entry.validationDur)
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
