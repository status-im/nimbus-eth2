# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles, chronos, metrics, minilru,
  ../spec/[forks, helpers_el, signatures, signatures_batch, column_map,
           peerdas_helpers],
  ../sszdump

from std/deques import Deque, addLast, contains, initDeque, items, len, shrink
from std/sequtils import anyIt, filterIt
from ../consensus_object_pools/consensus_manager import
  ConsensusManager, to, updateHead, updateExecutionHead
from ../consensus_object_pools/blockchain_dag import
  getBlockRef, getForkedBlock, getProposer, forkAtEpoch, loadExecutionBlockHash,
  markExecutionValid, validatorKey, is_optimistic
from ../beacon_clock import GetBeaconTimeFn, toFloatSeconds
from ../consensus_object_pools/block_dag import
  BlockRef, OptimisticStatus, executionValid, root, shortLog, slot
from ../consensus_object_pools/block_pools_types import
  ChainDAGRef, EpochRef, OnBlockAdded, VerifierError, timeParams
from ../consensus_object_pools/block_quarantine import
  addMissing, addSidecarless, addOrphan, addUnviable, clearProcessing, contains,
  get, pop, remove, startProcessing, clearProcessing, UnviableKind
from ../consensus_object_pools/column_quarantine import
  ColumnQuarantine, GloasColumnQuarantine, popSidecars, put, slot,
  popPendingVerify
from ../consensus_object_pools/envelope_quarantine import
  EnvelopeQuarantine, addMissing, addOrphan, addUnviable,
  delOrphan, popOrphan, remove
from ../validators/validator_monitor import
  MsgSource, ValidatorMonitor, registerAttestationInBlock, registerBeaconBlock,
  registerSyncAggregateInBlock
from ../beacon_chain_db import
  containsExecutionPayloadEnvelope, getDataColumnSidecar, putBlobSidecar,
  putDataColumnSidecars

export sszdump, signatures_batch

logScope: topics = "gossip_blocks"

# Block Processor
# ------------------------------------------------------------------------------
# The block processor moves blocks from "Incoming" to "Consensus verified"

declareHistogram beacon_store_block_duration_seconds,
  "storeBlock() duration", buckets = [0.25, 0.5, 1, 2, 4, 8, Inf]

declareHistogram beacon_block_data_availability_delay_seconds,
  "Time(s) between slot start and the block becoming data-available (resolved)",
  buckets = [0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 12.0, 16.0, Inf]

const
  SLOTS_PER_PAYLOAD = SLOTS_PER_HISTORICAL_ROOT
    ## Number of slots we process between each execution payload execution, while
    ## syncing the finalized part of the chain
  PAYLOAD_PRE_WALL_SLOTS = SLOTS_PER_EPOCH * 2
    ## Number of slots from wall time that we start processing every payload

type
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
    invalidBlockRoots: seq[Eth2Digest]

    # Producers
    # ----------------------------------------------------------------
    storeLock: AsyncLock
      ## storeLock ensures that storeBlock is only called by one async task at
      ## a time, queueing the others for processing in order
    pendingStores: int

    # Consumer
    # ----------------------------------------------------------------
    consensusManager*: ref ConsensusManager
      ## Blockchain DAG, AttestationPool, Quarantine, and ELManager
    validatorMonitor: ref ValidatorMonitor
    getBeaconTime: GetBeaconTimeFn

    # Quarantines
    # ----------------------------------------------------------------
    dataColumnQuarantine*: ref ColumnQuarantine
    gloasColumnQuarantine*: ref GloasColumnQuarantine
    envelopeQuarantine*: ref EnvelopeQuarantine

    verifier: BatchVerifier

    lastPayload: Slot
      ## The slot at which we sent a payload to the execution client the last
      ## time

    earlyExecValidity: ExecValidityLru
      ## newPayload started upon gossip validation, while waiting for Fulu
      ## column data availability

  ExecValidityLru =
    LruCache[Eth2Digest, Future[Opt[OptimisticStatus]].Raising([CancelledError])]

  NoSidecars* = typeof(())
  SomeOptSidecars =
    NoSidecars | Opt[BlobSidecars] | Opt[fulu.DataColumnSidecars] |
    Opt[gloas.DataColumnSidecars]

const noSidecars* = default(NoSidecars)

# Initialization
# ------------------------------------------------------------------------------

proc new*(T: type BlockProcessor,
          dumpEnabled: bool,
          dumpDirInvalid, dumpDirIncoming: string,
          batchVerifier: ref BatchVerifier,
          consensusManager: ref ConsensusManager,
          validatorMonitor: ref ValidatorMonitor,
          dataColumnQuarantine: ref ColumnQuarantine,
          gloasColumnQuarantine: ref GloasColumnQuarantine,
          envelopeQuarantine: ref EnvelopeQuarantine,
          getBeaconTime: GetBeaconTimeFn,
          invalidBlockRoots: seq[Eth2Digest] = @[]): ref BlockProcessor =
  if invalidBlockRoots.len > 0:
    warn "Config requests blocks to be treated as invalid",
      debugInvalidateBlockRoot = invalidBlockRoots

  (ref BlockProcessor)(
    dumpEnabled: dumpEnabled,
    dumpDirInvalid: dumpDirInvalid,
    dumpDirIncoming: dumpDirIncoming,
    invalidBlockRoots: invalidBlockRoots,
    storeLock: newAsyncLock(),
    consensusManager: consensusManager,
    validatorMonitor: validatorMonitor,
    dataColumnQuarantine: dataColumnQuarantine,
    gloasColumnQuarantine: gloasColumnQuarantine,
    envelopeQuarantine: envelopeQuarantine,
    getBeaconTime: getBeaconTime,
    verifier: batchVerifier[],
    earlyExecValidity: ExecValidityLru.init(8)
  )

# Sync callbacks
# ------------------------------------------------------------------------------

func hasBlocks*(self: BlockProcessor): bool =
  self.pendingStores > 0

func toVerifierError(v: UnviableKind): VerifierError =
  case v
  of UnviableKind.UnviableFork: VerifierError.UnviableFork
  of UnviableKind.Invalid: VerifierError.Invalid

# Storage
# ------------------------------------------------------------------------------

proc dumpInvalidBlock*(
    self: BlockProcessor, signedBlock: ForkySignedBeaconBlock) =
  if self.dumpEnabled:
    dump(self.dumpDirInvalid, signedBlock)

proc dumpBlock(
    self: BlockProcessor,
    signedBlock: ForkySignedBeaconBlock,
    res: Result[BlockRef, VerifierError]) =
  if self.dumpEnabled and res.isErr:
    case res.error
    of VerifierError.Invalid:
      self.dumpInvalidBlock(signedBlock)
    of VerifierError.MissingParent:
      dump(self.dumpDirIncoming, signedBlock)
    else:
      discard

from ../consensus_object_pools/block_clearance import
  addBackfillBlock, addBackfillExecutionPayload, addHeadBlockWithParent,
  addHeadExecutionPayload, checkHeadBlock, verifyBlockProposer

proc verifySidecars(
    signedBlock: gloas.SignedBeaconBlock,
    envelope: gloas.SignedExecutionPayloadEnvelope,
    sidecarsOpt: Opt[gloas.DataColumnSidecars],
): Result[void, VerifierError] =
  sidecarsOpt.isErrOr:
    template bid(): auto =
      signedBlock.message.body.signed_execution_payload_bid
    template kzgCommits: auto = bid.message.blob_kzg_commitments
    if value.len > 0 and kzgCommits.len > 0:
      verify_data_column_sidecar_kzg_proofs(value, kzgCommits).isOkOr:
        debug "data column validation failed",
          blockRoot = shortLog(signedBlock.root),
          blck = shortLog(signedBlock.message),
          signature = shortLog(signedBlock.signature),
          msg = error
        return err(VerifierError.Invalid)
  ok()

proc verifySidecars(
    signedBlock: fulu.SignedBeaconBlock,
    envelope: NoEnvelope,
    sidecarsOpt: Opt[fulu.DataColumnSidecars],
): Result[void, VerifierError] =
  sidecarsOpt.isErrOr:
    if value.len > 0 and signedBlock.message.body.blob_kzg_commitments.len > 0:
      verify_data_column_sidecar_kzg_proofs(value).isOkOr:
        debug "data column validation failed",
          blockRoot = shortLog(signedBlock.root),
          blck = shortLog(signedBlock.message),
          signature = shortLog(signedBlock.signature),
          msg = error
        return err(VerifierError.Invalid)
  ok()

proc storeSidecars(self: BlockProcessor, sidecarsOpt: Opt[BlobSidecars]) =
  if sidecarsOpt.isSome():
    for b in sidecarsOpt[]:
      self.consensusManager.dag.db.putBlobSidecar(b[])

proc storeSidecars(
    self: BlockProcessor,
    sidecarsOpt: Opt[fulu.DataColumnSidecars] | Opt[gloas.DataColumnSidecars]
) =
  if sidecarsOpt.isSome():
    self.consensusManager.dag.db.putDataColumnSidecars(sidecarsOpt[])

proc storeSidecars(self: BlockProcessor, sidecarsOpt: NoSidecars) =
  discard

proc enqueuePayload*(self: ref BlockProcessor, blck: gloas.SignedBeaconBlock)
proc enqueuePayload*(self: ref BlockProcessor, blck: heze.SignedBeaconBlock)

proc storeBackfillBlock(
    self: ref BlockProcessor,
    signedBlock: ForkySignedBeaconBlock,
    sidecarsOpt: SomeOptSidecars,
): Result[void, VerifierError] =
  let quarantine = self.consensusManager.quarantine
  # In case the block was added to any part of the quarantine..
  quarantine[].remove(signedBlock)

  const consensusFork = typeof(signedBlock).kind

  when consensusFork == ConsensusFork.Fulu:
    ?verifySidecars(signedBlock, noEnvelope, sidecarsOpt)

  let res = self.consensusManager.dag.addBackfillBlock(signedBlock)

  if res.isErr():
    case res.error
    of VerifierError.MissingParent:
      quarantine[].unviable.get(signedBlock.message.parent_root).isErrOr:
        # DAG doesn't know about unviable ancestor blocks - we do! Translate
        # this to the appropriate error so that sync etc doesn't retry the block
        return err(quarantine[].addUnviable(signedBlock.root, value).toVerifierError())

      # TODO Is the block always from an unviable fork? It didn't match the
      #      expected backfill block, so we could potentially mark it as
      #      UnviableFork here
      res
    of VerifierError.UnviableFork:
      # Track unviables so that descendants can be discarded properly
        err(
          quarantine[]
          .addUnviable(signedBlock.root, UnviableKind.UnviableFork)
          .toVerifierError()
        )
    of VerifierError.Invalid:
      # TODO track invalid blocks once we can differentiate between invalid
      #      proposer signature and other errors
      res
    of VerifierError.Duplicate:
      res
  else:
    when consensusFork <= ConsensusFork.Fulu:
      # Only store side cars after successfully establishing block viability.
      self[].storeSidecars(sidecarsOpt)

    res

from web3/engine_api_types import PayloadExecutionStatus
from ../el/el_manager import ELManager, DeadlineFuture, newPayload
from ../consensus_object_pools/attestation_pool import AttestationPool, addForkChoice
from ../consensus_object_pools/spec_cache import get_attesting_indices

proc newExecutionPayload*(
    elManager: ELManager,
    blck: SomeForkyBeaconBlock,
    envelope: NoEnvelope | gloas.ExecutionPayloadEnvelope,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadExecutionStatus]] {.async: (raises: [CancelledError]).} =
  template executionPayload: untyped =
    when typeof(blck).kind >= ConsensusFork.Gloas:
      envelope.payload
    else:
      blck.body.execution_payload

  debug "newPayload: inserting block into execution engine",
    executionPayload = shortLog(executionPayload)

  let payloadStatus = ?await elManager.newPayload(blck, envelope, deadline, retry)

  debug "newPayload: succeeded",
    parentHash = executionPayload.parent_hash,
    blockHash = executionPayload.block_hash,
    blockNumber = executionPayload.block_number,
    payloadStatus = payloadStatus

  Opt.some payloadStatus

proc newExecutionPayload*(
    elManager: ELManager,
    blck: SomeForkyBeaconBlock
): Future[Opt[PayloadExecutionStatus]] {.
  async: (raises: [CancelledError], raw: true).} =
  newExecutionPayload(
    elManager, blck, noEnvelope, sleepAsync(NEWPAYLOAD_TIMEOUT), true)

proc getExecutionValidity(
    elManager: ELManager,
    blck: bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock |
          deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock | gloas.SignedBeaconBlock,
    envelope: NoEnvelope | gloas.SignedExecutionPayloadEnvelope,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[OptimisticStatus]] {.async: (raises: [CancelledError]).} =
  if not blck.message.is_execution_block:
    return Opt.some(OptimisticStatus.valid) # vacuously

  const consensusFork = typeof(blck).kind
  template someEnvelope(): auto =
    when consensusFork >= ConsensusFork.Gloas:
      envelope.message
    else:
      envelope

  let status = (await elManager.newExecutionPayload(
      blck.message, someEnvelope, deadline, retry)).valueOr:
    return Opt.none(OptimisticStatus)

  let optimisticStatus = status.to(OptimisticStatus)

  if optimisticStatus == OptimisticStatus.invalidated:
    # Blocks come either from gossip or request manager requests. In the
    # former case, they've passed libp2p gossip validation which implies
    # correct signature for correct proposer,which makes spam expensive,
    # while for the latter, spam is limited by the request manager.
    template executionPayload(): auto =
      when consensusFork >= ConsensusFork.Gloas:
        envelope.message.payload
      else:
        blck.message.body.execution_payload
    info "execution payload invalid from EL client newPayload",
      executionPayloadStatus = status,
      executionPayload = shortLog(executionPayload),
      blck = shortLog(blck)

  Opt.some(optimisticStatus)

func nextSlotDeadline(wallTime: BeaconTime, dag: ChainDAGRef): Duration =
  ## Time from `wallTime` until ~1s before the next slot, for newPayload deadline
  let slotTime =
    (wallTime.slotOrZero(dag.timeParams) + 1).start_beacon_time(dag.timeParams) -
      chronos.seconds(1)
  if slotTime <= wallTime:
    chronos.seconds(0)
  else:
    chronos.nanoseconds((slotTime - wallTime).nanoseconds)

proc startExecutionValidity*(
    self: var BlockProcessor,
    signedBlock: fulu.SignedBeaconBlock, wallTime: BeaconTime) =
  if signedBlock.root in self.earlyExecValidity:
    return

  let dag = self.consensusManager.dag
  self.earlyExecValidity.put(
    signedBlock.root,
    self.consensusManager.elManager.getExecutionValidity(
      signedBlock, noEnvelope,
      deadline = sleepAsync(nextSlotDeadline(wallTime, dag)),
      retry = not dag.is_optimistic(dag.head.bid)))

proc addBlock*(
  self: ref BlockProcessor,
  src: MsgSource,
  blck: ForkySignedBeaconBlock,
  sidecarsOpt: SomeOptSidecars,
  maybeFinalized = false,
  validationDur = Duration(),
  fromGossip = false,
): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).}

proc enqueueBlock*(
    self: ref BlockProcessor,
    src: MsgSource,
    blck: ForkySignedBeaconBlock,
    sidecarsOpt: SomeOptSidecars,
    maybeFinalized = false,
    validationDur = Duration(),
) =
  if blck.message.slot <= self.consensusManager.dag.finalizedHead.slot:
    # let backfill blocks skip the queue - these are always "fast" to process
    # because there are no state rewinds to deal with
    discard self.storeBackfillBlock(blck, sidecarsOpt)
    return

  # `discard` here means that the `async` task will continue running even though
  # this function returns, similar to `asyncSpawn` (which we cannot use because
  # of the return type) - therefore, processing of the block cannot be cancelled
  # and its result is lost - this is fine however: callers of `enqueueBlock`
  # don't care. However, because this acts as an unbounded queue, they have to
  # be careful not to enqueue too many blocks or we'll run out of memory -
  # `addBlock` should be used where managing backpressure is appropriate.
  #
  # As such, `enqueueBlock` is the entry point for gossip processing; blocks
  # from sync/request managers reach `addBlock` directly.
  discard self.addBlock(
    src, blck, sidecarsOpt, maybeFinalized, validationDur,
    fromGossip = src == MsgSource.gossip)

proc enqueueQuarantine(self: ref BlockProcessor, parent: BlockRef) =
  ## Enqueue the blocks that are no longer orphans as a result of `parent` being
  ## added to the DAG
  let
    dag = self.consensusManager[].dag
    quarantine = self.consensusManager[].quarantine

  for quarantined in quarantine[].pop(parent.root):
    # Process the blocks that had the newly accepted block as parent
    debug "Block from quarantine", parent, quarantined = shortLog(quarantined.root)

    withBlck(quarantined):
      when consensusFork >= ConsensusFork.Gloas:
        const sidecarsOpt = noSidecars
      elif consensusFork == ConsensusFork.Fulu:
        let sidecarsOpt =
          if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
            Opt.some(default(fulu.DataColumnSidecars))
          else:
            self.dataColumnQuarantine[].popSidecars(forkyBlck.root)
      elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Electra:
        const sidecarsOpt = noSidecars
      else:
        {.error: "Unknown consensus fork " & $consensusFork.}

      when consensusFork == ConsensusFork.Fulu:
        if not sidecarsOpt.isSome():
          dag.verifyBlockProposer(
            parent, forkyBlck.message.slot, forkyBlck.message.proposer_index,
            forkyBlck.root, forkyBlck.signature,
            quarantine[].latest_sidecar_signatures
          ).isOkOr:
            warn "Failed to verify signature of unorphaned blobless block",
              blck = shortLog(forkyBlck), error = error.msg
            continue

          discard quarantine[].addSidecarless(dag.finalizedHead.slot, forkyBlck)
          continue

      self.enqueueBlock(MsgSource.gossip, forkyBlck, sidecarsOpt)

proc onBlockAdded*(
    dag: ChainDAGRef,
    consensusFork: static ConsensusFork,
    src: MsgSource,
    wallTime: BeaconTime,
    attestationPool: ref AttestationPool,
    validatorMonitor: ref ValidatorMonitor,
): OnBlockAdded[consensusFork] =
  # Actions to perform when a block is successfully added to the DAG, while
  # still having access to the clearance state data

  return proc(
      blckRef: BlockRef,
      blck: consensusFork.TrustedSignedBeaconBlock,
      state: consensusFork.BeaconState,
      epochRef: EpochRef,
      unrealized: FinalityCheckpoints,
  ) =
    attestationPool[].addForkChoice(
      epochRef, blckRef, unrealized, blck.message, wallTime
    )

    validatorMonitor[].registerBeaconBlock(src, wallTime, blck.message)

    for attestation in blck.message.body.attestations:
      for vidx in dag.get_attesting_indices(attestation):
        validatorMonitor[].registerAttestationInBlock(
          attestation.data, vidx, blck.message.slot
        )

    when consensusFork >= ConsensusFork.Altair:
      for i in blck.message.body.sync_aggregate.sync_committee_bits.oneIndices():
        validatorMonitor[].registerSyncAggregateInBlock(
          blck.message.slot, blck.root, state.current_sync_committee.pubkeys.data[i]
        )

proc verifyPayload(
    self: ref BlockProcessor,
    signedBlock: ForkySignedBeaconBlock,
    signedEnvelope: NoEnvelope | gloas.SignedExecutionPayloadEnvelope,
): Result[OptimisticStatus, VerifierError] =
  const consensusFork = typeof(signedBlock).kind
  # When the execution layer is not available to verify the payload, we do the
  # required checks on the CL instead and proceed as if the EL was syncing
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/bellatrix/beacon-chain.md#verify_and_notify_new_payload
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/deneb/beacon-chain.md#modified-verify_and_notify_new_payload
  when consensusFork >= ConsensusFork.Bellatrix:
    # Since Gloas, is_execution_block should always be true.
    if signedBlock.message.is_execution_block:
      template payload(): auto =
        when consensusFork >= ConsensusFork.Gloas:
          signedEnvelope.message.payload
        else:
          signedBlock.message.body.execution_payload

      template returnWithError(msg: string, extraMsg = ""): untyped =
        if extraMsg != "":
          debug msg, reason = extraMsg, executionPayload = shortLog(payload)
        else:
          debug msg, executionPayload = shortLog(payload)
        return err(VerifierError.Invalid)

      if payload.transactions.anyIt(it.len == 0):
        returnWithError "Execution block contains zero length transactions"

      template computedBlockHash(): auto =
        when consensusFork >= ConsensusFork.Gloas:
          signedBlock.message.compute_execution_block_hash(signedEnvelope.message)
        else:
          signedBlock.message.compute_execution_block_hash()
      if payload.block_hash != computedBlockHash:
        returnWithError "Execution block hash validation failed"

      # [New in Deneb:EIP4844]
      when consensusFork >= ConsensusFork.Deneb:
        let blobsRes =
          when consensusFork >= ConsensusFork.Gloas:
            signedBlock.message.is_valid_versioned_hashes(signedEnvelope.message)
          else:
            signedBlock.message.is_valid_versioned_hashes()
        if blobsRes.isErr:
          returnWithError "Blob versioned hashes invalid", blobsRes.error
      else:
        # If there are EIP-4844 (type 3) transactions in the payload with
        # versioned hashes, the transactions would be rejected by the EL
        # based on payload timestamp (only allowed post Deneb);
        # There are no `blob_kzg_commitments` before Deneb to compare against
        discard

      ok OptimisticStatus.notValidated
    else:
      ok OptimisticStatus.valid
  else:
    ok OptimisticStatus.valid

proc enqueueFromDb(self: ref BlockProcessor, root: Eth2Digest) =
  # TODO This logic can be removed if the database schema is extended
  # to store non-canonical heads on top of the canonical head and learns to keep
  # track of non-canonical forks - it was added during a time when there were
  # many forks and the client needed frequent restarting leading to a database
  # that contained semi-downloaded branches that couldn't be added via BlockRef.
  let
    dag = self.consensusManager.dag
    blck = dag.getForkedBlock(root).valueOr:
      return

  withBlck(blck):
    var sidecarsOk = true

    let sidecarsOpt =
      when consensusFork >= ConsensusFork.Gloas:
        noSidecars
      elif consensusFork == ConsensusFork.Fulu:
        var data_column_sidecars: fulu.DataColumnSidecars
        for i in self.dataColumnQuarantine[].custodyColumns:
          let data_column = fulu.DataColumnSidecar.new()
          if not dag.db.getDataColumnSidecar(root, i, data_column[]):
            sidecarsOk = false # Pruned, or inconsistent DB
            break
          data_column_sidecars.add data_column
        Opt.some data_column_sidecars
      else:
        noSidecars

    if sidecarsOk:
      debug "Loaded block from storage", root
      self.enqueueBlock(MsgSource.gossip, forkyBlck.asSigned(), sidecarsOpt)

proc storeBlock(
    self: ref BlockProcessor,
    src: MsgSource,
    wallTime: BeaconTime,
    signedBlock: ForkySignedBeaconBlock,
    sidecarsOpt: SomeOptSidecars,
    maybeFinalized: bool,
    queueTick: Moment,
    validationDur: Duration,
    fromGossip: bool,
): Future[Result[BlockRef, VerifierError]] {.async: (raises: [CancelledError]).} =
  ## storeBlock is the main entry point for unvalidated blocks - all untrusted
  ## blocks, regardless of origin, pass through here. When storing a block,
  ## we will add it to the dag and pass it to all block consumers that need
  ## to know about it, such as the fork choice and the monitoring.

  let
    ap = self.consensusManager.attestationPool
    startTick = Moment.now()
    vm = self.validatorMonitor
    dag = self.consensusManager.dag
    wallSlot = wallTime.slotOrZero(dag.timeParams)
    deadline = sleepAsync(nextSlotDeadline(wallTime, dag))

  if signedBlock.root in self.invalidBlockRoots:
    warn "Block root treated as invalid via config",
      blck = shortLog(signedBlock.message),
      blockRoot = shortLog(signedBlock.root)
    return err(VerifierError.Invalid)

  # We have to be careful that there exists only one in-flight entry point
  # for adding blocks or the checks performed in `checkHeadBlock` might
  # be invalidated (ie a block could be added while we wait for EL response
  # here)
  let parent = ?dag.checkHeadBlock(signedBlock)

  const consensusFork = typeof(signedBlock).kind
  let
    optimisticStatusRes =
      if maybeFinalized and
          (self.lastPayload + SLOTS_PER_PAYLOAD) > signedBlock.message.slot and
          (signedBlock.message.slot + PAYLOAD_PRE_WALL_SLOTS) < wallSlot and
          signedBlock.message.is_execution_block:
        # Skip payload validation when message source (reasonably) claims block
        # has been finalized - this speeds up forward sync - in the worst case
        # that the claim is false, we will correct every time we process a block
        # from an honest source (or when we're close to head).
        # Occasionally we also send a payload to the EL so that it can
        # progress in its own sync.
        Opt.none(OptimisticStatus)
      else:
        when consensusFork >= ConsensusFork.Gloas:
          # It is mainly for disabling the `updateExecutionHead` call. As we are
          # not sure if there is a valid envelope (execution payload), the
          # execution head should be updated after we get one and validate it.
          Opt.none(OptimisticStatus)
        elif consensusFork >= ConsensusFork.Bellatrix:
          func shouldRetry(): bool =
            not dag.is_optimistic(dag.head.bid)
          when consensusFork == ConsensusFork.Fulu:
            let cached = self.earlyExecValidity.pop(signedBlock.root)
            if cached.isSome:
              await cached.get()
            else:
              await self.consensusManager.elManager.getExecutionValidity(
                signedBlock, noEnvelope, deadline, shouldRetry())
          else:
            await self.consensusManager.elManager.getExecutionValidity(
              signedBlock, noEnvelope, deadline, shouldRetry())
        else:
          Opt.some(OptimisticStatus.valid) # vacuously

  let optimisticStatus =
    when consensusFork >= ConsensusFork.Gloas:
      # The execution payload validity is not known yet at block time as an
      # envelope will be processed after its valid block. So always return
      # `notValidated` and skip verifying payload.
      OptimisticStatus.notValidated
    else:
      ?(optimisticStatusRes or verifyPayload(self, signedBlock, noEnvelope))

  if OptimisticStatus.invalidated == optimisticStatus:
    return err(VerifierError.Invalid)

  let newPayloadTick = Moment.now()

  when consensusFork == ConsensusFork.Fulu:
    # Only request manager-sourced columns arrive unverified; getBlobsV2/V3/V4
    # and CL gossip are both either trusted or verified.
    let pendingVerify =
      self.dataColumnQuarantine[].popPendingVerify(signedBlock.root)
    if not pendingVerify.empty:
      sidecarsOpt.isErrOr:
        let toVerify = value.filterIt(it[].index in pendingVerify)
        if toVerify.len > 0:
          ?verifySidecars(signedBlock, noEnvelope, Opt.some(toVerify))
    debug "block_processor verifySidecars completed",
      verifySidecarsDur = Moment.now() - newPayloadTick,
      blck = shortLog(signedBlock.message),
      blockRoot = shortLog(signedBlock.root)

  let blck =
    ?dag.addHeadBlockWithParent(
      self.verifier,
      signedBlock,
      parent,
      optimisticStatus,
      onBlockAdded(dag, consensusFork, src, wallTime, ap, vm),
      fromGossip,
    )

  # The block has just been resolved (see the "Block resolved" log): all of its
  # data (incl. blobs / data columns) is available and it has been imported into
  # the dag. Measure how long after the slot start that happened - for live
  # gossip blocks this is the data-availability latency for the slot.
  if fromGossip:
    let daDelay = wallTime - signedBlock.message.slot.start_beacon_time(
      dag.timeParams)
    beacon_block_data_availability_delay_seconds.observe(daDelay.toFloatSeconds())

  # Even if the EL is not responding, we'll only try once every now and then
  # to give it a block - this avoids a pathological slowdown where a busy EL
  # times out on every block we give it because it's busy with the previous
  # one
  self[].lastPayload = signedBlock.message.slot

  # write blobs now that block has been written.
  when consensusFork in ConsensusFork.Deneb .. ConsensusFork.Fulu:
    self[].storeSidecars(sidecarsOpt)

  let addHeadBlockTick = Moment.now()

  # Update consensus head - in the happy case where we are in sync and the
  # execution client has validated the block, this will allow validators to
  # start attesting via the `checkExpectedBlock` mechanism - notably, this can
  # be done without waiting for `forkchoiceUpdated` as the execution client
  # already validated the payload.
  #
  # In the unhappy case, the head update kickstarts any pruning and cleanup work
  # which helps conserve resources, ie also a good thing to be doing just after
  # having added a block.
  let previousExecutionValid = dag.head.executionValid
  self.consensusManager[].updateHead(wallSlot)

  # After producing attestations, we might be asked to produce a block for the
  # next slot, for which there is a hard requirement on the execution client
  # fork choice being up to date - there's also a soft requirement that the
  # execution head follows the consensus head as closely as possible as this
  # keeps the execution client healthy and up to date with finality, so as soon
  # as we've updated the consensus head we'll do the same for execution.
  #
  # In the case that the execution client is not responding to payloads or
  # that we skipped sending the payload altogether per the above
  # `SLOTS_PER_PAYLOAD` logic, we will skip the execution client update.
  if optimisticStatusRes.isSome():
    # retry fcU until the deadline expires, in case the previous payload was
    # valid to increase chances of leaving this function with a still-valid head
    await self.consensusManager.updateExecutionHead(
      deadline, retry = previousExecutionValid, self.getBeaconTime)

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
    blck = shortLog(blck),
    validationDur, queueDur, newPayloadDur, addHeadBlockDur, updateHeadDur

  when consensusFork >= ConsensusFork.Gloas:
    # Enqueue payload here instead of `addBlock` for the consistency of payload
    # processing with backfilling.
    self.enqueuePayload(signedBlock)

  ok(blck)

proc addBlock*(
    self: ref BlockProcessor,
    src: MsgSource,
    blck: ForkySignedBeaconBlock,
    sidecarsOpt: SomeOptSidecars,
    maybeFinalized = false,
    validationDur = Duration(),
    fromGossip = false
): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
  ## Enqueue a Gossip-validated block for consensus verification - only one
  ## block at a time gets processed
  # Backpressure:
  #   Callers that don't await the returned future are responsible for implementing
  #   their own backpressure handling, limiting concurrent `addBlock` calls to
  #   reasonable amounts
  # Producers:
  # - Gossip (when synced)
  # - SyncManager (during sync)
  # - RequestManager (missing ancestor blocks)
  # - API
  let
    blockRoot = blck.root
    dag = self.consensusManager.dag
    quarantine = self.consensusManager.quarantine

  logScope:
    blockRoot = shortLog(blockRoot)

  if blck.message.slot <= dag.finalizedHead.slot:
    # let backfill blocks skip the queue - these are always "fast" to process
    # because there are no state rewinds to deal with
    return self.storeBackfillBlock(blck, sidecarsOpt)

  let
    queueTick = Moment.now()
    res =
      try:
        # If the lock is acquired already, the current block will be put on hold
        # meaning that we'll form an unbounded queue of blocks to be processed
        # waiting for the lock - this is similar to using an `AsyncQueue` but
        # without the copying and transition to/from `Forked`.
        # The lock is important to ensure that we don't process blocks
        # out-of-order which both would upset the `storeBlock` logic and cause
        # unnecessary quarantine traffic.
        self.pendingStores += 1
        await self.storeLock.acquire()

        try:
          # Since block processing is async, we want to make sure it doesn't get
          # (re)added there while we're busy - the start of processing also
          # removes the block from the various quarantines.
          # The processing status is cleared in the finally block below.
          quarantine[].startProcessing(blck)

          # Cooperative concurrency: one block per loop iteration - because
          # we run both networking and CPU-heavy things like block processing
          # on the same thread, we need to ensure that there is steady progress
          # on the networking side or we get long lockups that lead to timeouts.
          const
            # We cap waiting for an idle slot in case there's a lot of network
            # traffic taking up all CPU - we don't want to _completely_ stop
            # processing blocks in this case - doing so also allows us to
            # benefit from more batching / larger network reads when under load.
            idleTimeout = chronos.milliseconds(10)

          discard await idleAsync().withTimeout(idleTimeout)

          let wallTime = self.getBeaconTime()
          if not wallTime.afterGenesis:
            fatal "Processing block before genesis, clock turned back?"
            quit 1

          await self.storeBlock(
            src, wallTime, blck, sidecarsOpt, maybeFinalized,
            queueTick, validationDur, fromGossip)
        finally:
          quarantine[].clearProcessing()

          try:
            self.storeLock.release()
          except AsyncLockError:
            raiseAssert "release matched with acquire, shouldn't happen"
      finally:
        self.pendingStores -= 1

  self[].dumpBlock(blck, res)

  if res.isOk():
    # Once a block is successfully stored, enqueue the direct descendants
    self.enqueueQuarantine(res[])
    res.mapConvert(void)
  else:
    case res.error()
    of VerifierError.MissingParent:
      quarantine[].addOrphan(dag.finalizedHead.slot, blck).isOkOr:
        debug "Could not add orphan",
          blck = shortLog(blck), signature = shortLog(blck.signature), err = error
        return err(error.toVerifierError())

      # This indicates that no `BlockRef` is available for the `parent_root`.
      # However, the block may still be available in local storage. On startup,
      # only the canonical branch is imported into `blockchain_dag`, while
      # non-canonical branches are re-discovered with sync/request managers.
      # Data from non-canonical branches that has already been verified during
      # a previous run of the beacon node is already stored in the database but
      # only lacks a `BlockRef`. Loading the branch from the database saves a
      # lot of time, especially when a non-canonical branch has non-trivial
      # depth. Note that if it turns out that a non-canonical branch eventually
      # becomes canonical, it is vital to import it as quickly as possible.
      self.enqueueFromDb(blck.message.parent_root)

      when sidecarsOpt is Opt[fulu.DataColumnSidecars]:
        if sidecarsOpt.isSome:
          self.dataColumnQuarantine[].put(
            blockRoot, sidecarsOpt.get, verified = false)
      elif sidecarsOpt is Opt[gloas.DataColumnSidecars]:
        # In Gloas, block is enqueued with NoSidecar so we need not to care
        # about quarantine.
        discard
      elif sidecarsOpt is NoSidecars | Opt[BlobSidecars]:
        discard
      else:
        {.error: "Incorrect sidecar type".}

      debug "Block quarantined",
        blck = shortLog(blck), signature = shortLog(blck.signature)

      err(res.error())
    of VerifierError.UnviableFork:
      # Track unviables so that descendants can be discarded promptly
      err(
        self.consensusManager.quarantine[]
        .addUnviable(blockRoot, UnviableKind.UnviableFork)
        .toVerifierError()
      )
    of VerifierError.Invalid:
      # TODO track invalid blocks once we can differentiate between invalid
      #      proposer signature and other errors
      # TODO fix https://github.com/status-im/nimbus-eth2/issues/7583
      #      before marking as Invalid here to allow retrying with a fresh
      #      state
      # err(
      #   self.consensusManager.quarantine[]
      #   .addUnviable(blockRoot, UnviableKind.Invalid)
      #   .toVerifierError()
      # )
      err(res.error())
    of VerifierError.Duplicate:
      err(res.error())

proc storeBackfillPayload(
    self: var BlockProcessor,
    signedBlock: gloas.SignedBeaconBlock,
    signedEnvelope: gloas.SignedExecutionPayloadEnvelope,
    sidecarsOpt: Opt[gloas.DataColumnSidecars],
): Result[void, VerifierError] =
  self.envelopeQuarantine[].remove(signedEnvelope.message.beacon_block_root)

  ?verifySidecars(signedBlock, signedEnvelope, sidecarsOpt)
  ?self.consensusManager.dag.addBackfillExecutionPayload(signedEnvelope)

  self.storeSidecars(sidecarsOpt)
  ok()

proc storePayload(
    self: ref BlockProcessor,
    signedBlock: gloas.SignedBeaconBlock,
    signedEnvelope: gloas.SignedExecutionPayloadEnvelope,
    sidecarsOpt: Opt[gloas.DataColumnSidecars],
): Future[Result[BlockRef, VerifierError]] {.async: (raises: [CancelledError]).} =
  let
    dag = self.consensusManager.dag
    wallTime = self.getBeaconTime()
    wallSlot = wallTime.slotOrZero(dag.timeParams)
    deadline = sleepAsync(nextSlotDeadline(wallTime, dag))

  let
    optimisticStatusRes =
      block:
        debugGloasComment("handle (maybe)finalized slot")
        func shouldRetry(): bool =
          not dag.is_optimistic(dag.head.bid)
        await self.consensusManager.elManager.getExecutionValidity(
          signedBlock, signedEnvelope, deadline, shouldRetry())
    optimisticStatus =
      ?(optimisticStatusRes or verifyPayload(self, signedBlock, signedEnvelope))

  # optimisticStatus could be valid or notValidated at this point. We will
  # validate it by the clearance state transition.
  if OptimisticStatus.invalidated == optimisticStatus:
    return err(VerifierError.Invalid)

  ?verifySidecars(signedBlock, signedEnvelope, sidecarsOpt)

  # Try adding the envelope to clearance state.
  debugGloasComment("deadline")
  let blck = ?addHeadExecutionPayload(dag, signedBlock, signedEnvelope)

  # https://github.com/ethereum/beacon-APIs/blob/31f7d04f869d40a643b68ac22e10fb27644d20e7/apis/eventstream/index.yaml
  # execution_payload_available: The node has verified that the execution
  # payload and blobs for a block are available and ready for payload
  # attestation
  if not isNil(dag.onEnvelopeAvailable):
    dag.onEnvelopeAvailable(signedEnvelope)

  # The execution payload has added to the clearance state successfully, so try
  # adding to the current state.
  let previousExecutionValid = dag.head.executionValid

  debugGloasComment("deadline")
  debugGloasComment("should be decided by Fork Choice")
  # TODO To be removed - Temporary call without import.
  if blck.slot() >= dag.head.slot():
    blockchain_dag.updateHeadExecutionPayload(dag, blck, signedEnvelope)

  if optimisticStatusRes.isSome():
    await self.consensusManager.updateExecutionHead(
      deadline, retry = previousExecutionValid, self.getBeaconTime)

  debug "Envelope processed",
    head = shortLog(dag.head),
    blck = shortLog(blck),
    slot = signedBlock.message.slot

  # Store sidecars into db.
  self[].storeSidecars(sidecarsOpt)
  self.envelopeQuarantine[].remove(signedBlock.root)

  ok(blck)

proc addPayload*(
    self: ref BlockProcessor,
    signedBlock: gloas.SignedBeaconBlock,
    signedEnvelope: gloas.SignedExecutionPayloadEnvelope,
    sidecarsOpt: Opt[gloas.DataColumnSidecars],
): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
  if signedBlock.message.slot <= self.consensusManager.dag.finalizedHead.slot:
    return self[].storeBackfillPayload(signedBlock, signedEnvelope, sidecarsOpt)

  let res = await self.storePayload(signedBlock, signedEnvelope, sidecarsOpt)
  if res.isOk():
    # Once a block is successfully stored, enqueue the direct descendants
    self.enqueueQuarantine(res.get())
  else:
    case res.error()
    of VerifierError.MissingParent:
      # MissingParent is returned when block or parents cannot be found in the
      # DAG. This could happen if we process envelope before block, or there is
      # any missing parents. In either case, they should be caught when
      # processing block. So we only put the envelope into the quarantine for
      # the next try.
      self.envelopeQuarantine[].addOrphan(
        self.consensusManager.dag.finalizedHead.slot, signedEnvelope)
      if sidecarsOpt.isSome():
        self.gloasColumnQuarantine[].put(
          signedBlock.root, sidecarsOpt.get(), verified = false)
    of VerifierError.Invalid, VerifierError.UnviableFork:
      # The block is verified and has added to the DAG, but the envelope isn't
      # valid. It should be marked as invalid so that we can ignore it from
      # gossip or skip processing the same one.
      self.envelopeQuarantine[].addUnviable(signedBlock.root)
    of VerifierError.Duplicate:
      self.envelopeQuarantine[].remove(signedBlock.root)

  res.mapConvert(void)

proc addPayload*(
    self: ref BlockProcessor,
    signedBlock: heze.SignedBeaconBlock,
    signedEnvelope: gloas.SignedExecutionPayloadEnvelope,
    sidecarsOpt: Opt[gloas.DataColumnSidecars],
): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
  debugHezeComment "stub: heze addPayload not yet implemented"
  ok()

proc enqueuePayload*(self: ref BlockProcessor, blck: gloas.SignedBeaconBlock) =
  ## Enqueue payload processing by block that is a valid block.

  template bid(): auto = blck.message.body.signed_execution_payload_bid

  let
    envelope = self.envelopeQuarantine[].popOrphan(blck).valueOr:
      # We have not received the envelope yet so mark it as missing.
      self.envelopeQuarantine[].addMissing(blck.root)
      return
    sidecarsOpt =
      block:
        let sidecarsOpt =
          if bid.message.blob_kzg_commitments.len() == 0:
            Opt.some(default(gloas.DataColumnSidecars))
          else:
            self.gloasColumnQuarantine[].popSidecars(blck.root)
        if sidecarsOpt.isNone():
          # As sidecars are missing, put envelope back to quarantine.
          self.consensusManager.quarantine[].addSidecarless(blck)
          self.envelopeQuarantine[].addOrphan(
            self.consensusManager.dag.finalizedHead.slot, envelope)
          return
        sidecarsOpt

  discard self.addPayload(blck, envelope, sidecarsOpt)

proc enqueuePayload*(self: ref BlockProcessor, blck: heze.SignedBeaconBlock) =
  debugHezeComment "stub: heze enqueuePayload not yet implemented"

proc enqueuePayload*(self: ref BlockProcessor, blockRoot: Eth2Digest) =
  ## Enqueue payload processing by block root. If it is not a valid block, the
  ## enqueue request will be discarded silently.

  let
    dag = self.consensusManager.dag
    blockRef = dag.getBlockRef(blockRoot).valueOr:
      return
    blck =
      block:
        let forkedBlock = dag.getForkedBlock(blockRef.bid).valueOr:
          # We have checked that the block exists in the chain. There might be
          # issues in reading the database or data in the memory is broken.
          # Since no result is returned, we log for investigation.
          debug "Enqueue payload from envelope. Block is missing in DB",
            bid = shortLog(blockRef.bid)
          return
        withBlck(forkedBlock):
          debugHezeComment "..."
          when consensusFork == ConsensusFork.Gloas:
            forkyBlck.asSigned()
          else:
            # Incorrect fork which shouldn't be happening.
            debug "Enqueue payload from envelope. Block is in incorrect fork",
              bid = shortLog(blockRef.bid)
            return

  self.enqueuePayload(blck)
