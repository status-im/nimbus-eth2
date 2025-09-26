# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles, chronos, metrics,
  ../spec/[forks, helpers_el, signatures, signatures_batch, peerdas_helpers],
  ../sszdump

from std/deques import Deque, addLast, contains, initDeque, items, len, shrink
from std/sequtils import anyIt, mapIt
from ../consensus_object_pools/consensus_manager import
  ConsensusManager, to, updateHead, updateExecutionHead
from ../consensus_object_pools/blockchain_dag import
  getBlockRef, getForkedBlock, getProposer, forkAtEpoch, loadExecutionBlockHash,
  markExecutionValid, validatorKey, is_optimistic
from ../beacon_clock import GetBeaconTimeFn, toFloatSeconds
from ../consensus_object_pools/block_dag import
  BlockRef, OptimisticStatus, executionValid, root, shortLog, slot
from ../consensus_object_pools/block_pools_types import
  ChainDAGRef, EpochRef, OnBlockAdded, VerifierError
from ../consensus_object_pools/block_quarantine import
  addSidecarless, addOrphan, addUnviable, pop, removeOrphan, removeSidecarless
from ../consensus_object_pools/blob_quarantine import
  BlobQuarantine, ColumnQuarantine, popSidecars, put
from ../validators/validator_monitor import
  MsgSource, ValidatorMonitor, registerAttestationInBlock, registerBeaconBlock,
  registerSyncAggregateInBlock
from ../beacon_chain_db import getBlobSidecar, putBlobSidecar,
  getDataColumnSidecar, putDataColumnSidecar
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
  BlockEntry = object
    blck*: ForkedSignedBeaconBlock
    blobs*: Opt[BlobSidecars]
    columns*: Opt[DataColumnSidecars]
    maybeFinalized*: bool
      ## The block source claims the block has been finalized already
    resfut*: Future[Result[void, VerifierError]].Raising([CancelledError])
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
    invalidBlockRoots: seq[Eth2Digest]

    # Producers
    # ----------------------------------------------------------------
    blockQueue: AsyncQueue[BlockEntry]

    # Consumer
    # ----------------------------------------------------------------
    consensusManager*: ref ConsensusManager
      ## Blockchain DAG, AttestationPool and Quarantine
      ## Blockchain DAG, AttestationPool, Quarantine, and ELManager
    validatorMonitor: ref ValidatorMonitor
    getBeaconTime: GetBeaconTimeFn

    blobQuarantine: ref BlobQuarantine
    dataColumnQuarantine*: ref ColumnQuarantine
    verifier: BatchVerifier

    lastPayload: Slot
      ## The slot at which we sent a payload to the execution client the last
      ## time

  NoSidecars = typeof(())
  SomeOptSidecars = NoSidecars | Opt[BlobSidecars] | Opt[DatacolumnSidecars]

# Initialization
# ------------------------------------------------------------------------------

proc new*(T: type BlockProcessor,
          dumpEnabled: bool,
          dumpDirInvalid, dumpDirIncoming: string,
          batchVerifier: ref BatchVerifier,
          consensusManager: ref ConsensusManager,
          validatorMonitor: ref ValidatorMonitor,
          blobQuarantine: ref BlobQuarantine,
          dataColumnQuarantine: ref ColumnQuarantine,
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
    blockQueue: newAsyncQueue[BlockEntry](),
    consensusManager: consensusManager,
    validatorMonitor: validatorMonitor,
    blobQuarantine: blobQuarantine,
    dataColumnQuarantine: dataColumnQuarantine,
    getBeaconTime: getBeaconTime,
    verifier: batchVerifier[]
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

template selectSidecars(
    consensusFork: static ConsensusFork,
    blobsOpt: Opt[BlobSidecars],
    columnsOpt: Opt[DataColumnSidecars],
): untyped =
  # The when jungle here must be kept consistent with `verifySidecars`
  when consensusFork in ConsensusFork.Fulu .. ConsensusFork.Gloas:
    doAssert blobsOpt.isNone(), "No blobs in " & $consensusFork
    columnsOpt
  elif consensusFork in ConsensusFork.Deneb .. ConsensusFork.Electra:
    doAssert columnsOpt.isNone(), "No columns in " & $consensusFork
    blobsOpt
  elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Capella:
    doAssert blobsOpt.isNone and columnsOpt.isNone(),
      "No blobs/columns in " & $consensusFork
    default(NoSidecars)
  else:
    {.error: "Unkown fork " & $consensusFork.}

proc verifySidecars(
    signedBlock: ForkySignedBeaconBlock,
    sidecarsOpt: SomeOptSidecars,
): Result[void, VerifierError] =
  const consensusFork = typeof(signedBlock).kind

  when consensusFork == ConsensusFork.Gloas:
    # For Gloas, we still need to store the columns if they're provided
    # but skip validation since we don't have kzg_commitments in the block
    if sidecarsOpt.isSome:
      debugGloasComment "potentially validate against payload envelope"
      let columns = sidecarsOpt.get()
      discard
  elif consensusFork == ConsensusFork.Fulu:
    if sidecarsOpt.isSome:
      let columns = sidecarsOpt.get()
      let kzgCommits = signedBlock.message.body.blob_kzg_commitments.asSeq
      if columns.len > 0 and kzgCommits.len > 0:
        for i in 0 ..< columns.len:
          let r = verify_data_column_sidecar_kzg_proofs(columns[i][])
          if r.isErr():
            debug "data column validation failed",
              blockRoot = shortLog(signedBlock.root),
              column_sidecar = shortLog(columns[i][]),
              blck = shortLog(signedBlock.message),
              signature = shortLog(signedBlock.signature),
              msg = r.error()
            return err(VerifierError.Invalid)
  elif consensusFork in ConsensusFork.Deneb .. ConsensusFork.Electra:
    if sidecarsOpt.isSome:
      let blobs = sidecarsOpt.get()
      let kzgCommits = signedBlock.message.body.blob_kzg_commitments.asSeq
      if blobs.len > 0 or kzgCommits.len > 0:
        let r = validate_blobs(
          kzgCommits, blobs.mapIt(KzgBlob(bytes: it.blob)), blobs.mapIt(it.kzg_proof)
        )
        if r.isErr():
          debug "blob validation failed",
            blockRoot = shortLog(signedBlock.root),
            blobs = shortLog(blobs),
            blck = shortLog(signedBlock.message),
            kzgCommits = mapIt(kzgCommits, shortLog(it)),
            signature = shortLog(signedBlock.signature),
            msg = r.error()
          return err(VerifierError.Invalid)
  elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Capella:
    static: doAssert sidecarsOpt is NoSidecars
  else:
    {.error: "Unknown consensus fork " & $consensusFork.}

  ok()

proc storeSidecars(self: BlockProcessor, sidecarsOpt: Opt[BlobSidecars]) =
  if sidecarsOpt.isSome():
    debug "Inserting blobs into database", blobs = sidecarsOpt[].len
    for b in sidecarsOpt[]:
      self.consensusManager.dag.db.putBlobSidecar(b[])

proc storeSidecars(self: BlockProcessor, sidecarsOpt: Opt[DataColumnSidecars]) =
  if sidecarsOpt.isSome():
    debug "Inserting columns into database", columns = sidecarsOpt[].len
    for c in sidecarsOpt[]:
      self.consensusManager.dag.db.putDataColumnSidecar(c[])

proc storeSidecars(self: BlockProcessor, sidecarsOpt: NoSidecars) =
  discard

proc storeBackfillBlock(
    self: var BlockProcessor,
    signedBlock: ForkySignedBeaconBlock,
    sidecarsOpt: SomeOptSidecars,
): Result[void, VerifierError] =
  # The block is certainly not missing any more
  self.consensusManager.quarantine[].missing.del(signedBlock.root)

  ?verifySidecars(signedBlock, sidecarsOpt)

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

  # Only store side cars after successfully establishing block viability.
  self.storeSidecars(sidecarsOpt)

  res

from web3/engine_api_types import PayloadExecutionStatus
from ../el/el_manager import ELManager, DeadlineFuture, sendNewPayload
from ../consensus_object_pools/attestation_pool import AttestationPool, addForkChoice
from ../consensus_object_pools/spec_cache import get_attesting_indices

proc newExecutionPayload*(
    elManager: ELManager,
    blck: SomeForkyBeaconBlock,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadExecutionStatus]] {.async: (raises: [CancelledError]).} =
  template executionPayload: untyped = blck.body.execution_payload

  debug "newPayload: inserting block into execution engine",
    executionPayload = shortLog(executionPayload)

  let payloadStatus = ?await elManager.sendNewPayload(blck, deadline, retry)

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
    elManager, blck, sleepAsync(FORKCHOICEUPDATED_TIMEOUT), true)

proc getExecutionValidity(
    elManager: ELManager,
    blck: bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock |
          deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[OptimisticStatus]] {.async: (raises: [CancelledError]).} =
  if not blck.message.is_execution_block:
    return Opt.some(OptimisticStatus.valid) # vacuously

  let status = (await elManager.newExecutionPayload(blck.message, deadline, retry)).valueOr:
    return Opt.none(OptimisticStatus)

  let optimisticStatus = status.to(OptimisticStatus)

  if optimisticStatus == OptimisticStatus.invalidated:
    # Blocks come either from gossip or request manager requests. In the
    # former case, they've passed libp2p gossip validation which implies
    # correct signature for correct proposer,which makes spam expensive,
    # while for the latter, spam is limited by the request manager.
    info "execution payload invalid from EL client newPayload",
      executionPayloadStatus = status,
      executionPayload = shortLog(blck.message.body.execution_payload),
      blck = shortLog(blck)

  Opt.some(optimisticStatus)

proc checkBlobOrColumnlessSignature(
    self: BlockProcessor,
    signed_beacon_block: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
                         fulu.SignedBeaconBlock):
    Result[void, cstring] =
  let dag = self.consensusManager.dag
  let parent = dag.getBlockRef(signed_beacon_block.message.parent_root).valueOr:
    return err("checkBlobOrColumnlessSignature called with orphan block")
  let proposer = getProposer(
        dag, parent, signed_beacon_block.message.slot).valueOr:
    return err("checkBlobOrColumnlessSignature: Cannot compute proposer")
  if distinctBase(proposer) != signed_beacon_block.message.proposer_index:
    return err("checkBlobOrColumnlessSignature: Incorrect proposer")
  if not verify_block_signature(
      dag.forkAtEpoch(signed_beacon_block.message.slot.epoch),
      getStateField(dag.headState, genesis_validators_root),
      signed_beacon_block.message.slot,
      signed_beacon_block.root,
      dag.validatorKey(proposer).get(),
      signed_beacon_block.signature):
    return err("checkBlobOrColumnlessSignature: Invalid proposer signature")
  ok()

proc enqueueBlock*(
    self: var BlockProcessor, src: MsgSource, blck: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars], data_columns: Opt[DataColumnSidecars],
    resfut: Future[Result[void, VerifierError]].Raising([CancelledError]) = nil,
    maybeFinalized = false,
    validationDur = Duration()) =
  withBlck(blck):
    if forkyBlck.message.slot <= self.consensusManager.dag.finalizedHead.slot:
      # let backfill blocks skip the queue - these are always "fast" to process
      # because there are no state rewinds to deal with
      let sidecars = selectSidecars(consensusFork, blobs, data_columns)
      resfut.complete(self.storeBackfillBlock(forkyBlck, sidecars))
      return

  try:
    self.blockQueue.addLastNoWait(BlockEntry(
      blck: blck,
      blobs: blobs,
      columns: data_columns,
      maybeFinalized: maybeFinalized,
      resfut: resfut, queueTick: Moment.now(),
      validationDur: validationDur,
      src: src))
  except AsyncQueueFullError:
    raiseAssert "unbounded queue"

proc enqueueQuarantine(self: var BlockProcessor, root: Eth2Digest) =
  ## Enqueue blocks whose parent is `root` - ie when `root` has been added to
  ## the blockchain dag, its direct descendants are now candidates for
  ## processing
  for quarantined in self.consensusManager.quarantine[].pop(root):
    # Process the blocks that had the newly accepted block as parent
    debug "Block from quarantine",
      blockRoot = shortLog(root), quarantined = shortLog(quarantined.root)

    withBlck(quarantined):
      when consensusFork == ConsensusFork.Gloas:
        debugGloasComment ""
        self.enqueueBlock(
          MsgSource.gossip,
          quarantined,
          Opt.none(BlobSidecars),
          Opt.none(DataColumnSidecars),
        )
      elif consensusFork == ConsensusFork.Fulu:
        if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
          self.enqueueBlock(
            MsgSource.gossip,
            quarantined,
            Opt.some(BlobSidecars @[]),
            Opt.some(DataColumnSidecars @[]),
          )
        else:
          if (let res = checkBlobOrColumnlessSignature(self, forkyBlck); res.isErr):
            warn "Failed to verify signature of unorphaned blobless block",
              blck = shortLog(forkyBlck), error = res.error()
            continue
          let cres = self.dataColumnQuarantine[].popSidecars(forkyBlck.root, forkyBlck)
          if cres.isSome:
            self.enqueueBlock(
              MsgSource.gossip, quarantined, Opt.none(BlobSidecars), cres
            )
          else:
            discard self.consensusManager.quarantine[].addSidecarless(
              self.consensusManager[].dag.finalizedHead.slot, forkyBlck
            )
      elif consensusFork in ConsensusFork.Deneb .. ConsensusFork.Electra:
        if len(forkyBlck.message.body.blob_kzg_commitments) == 0:
          self.enqueueBlock(
            MsgSource.gossip,
            quarantined,
            Opt.some(BlobSidecars @[]),
            Opt.some(DataColumnSidecars @[]),
          )
        else:
          if (let res = checkBlobOrColumnlessSignature(self, forkyBlck); res.isErr):
            warn "Failed to verify signature of unorphaned columnless block",
              blck = shortLog(forkyBlck), error = res.error()
            continue
          let bres = self.blobQuarantine[].popSidecars(forkyBlck.root, forkyBlck)
          if bres.isSome():
            self.enqueueBlock(
              MsgSource.gossip, quarantined, bres, Opt.none(DataColumnSidecars)
            )
          else:
            self.consensusManager.quarantine[].addSidecarless(forkyBlck)
      elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Capella:
        self.enqueueBlock(
          MsgSource.gossip,
          quarantined,
          Opt.none(BlobSidecars),
          Opt.none(DataColumnSidecars),
        )
      else:
        {.error: "Unknown consensus fork " & $consensusFork.}

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
      for vidx in dag.get_attesting_indices(attestation, true):
        validatorMonitor[].registerAttestationInBlock(
          attestation.data, vidx, blck.message.slot
        )

    when consensusFork >= ConsensusFork.Altair:
      for i in blck.message.body.sync_aggregate.sync_committee_bits.oneIndices():
        validatorMonitor[].registerSyncAggregateInBlock(
          blck.message.slot, blck.root, state.current_sync_committee.pubkeys.data[i]
        )

proc verifyPayload(
    self: ref BlockProcessor, signedBlock: ForkySignedBeaconBlock
): Result[OptimisticStatus, VerifierError] =
  const consensusFork = typeof(signedBlock).kind
  # When the execution layer is not available to verify the payload, we do the
  # required checks on the CL instead and proceed as if the EL was syncing
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/bellatrix/beacon-chain.md#verify_and_notify_new_payload
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/specs/deneb/beacon-chain.md#modified-verify_and_notify_new_payload
  when consensusFork == ConsensusFork.Gloas:
    debugGloasComment "no exection payload field for gloas"
    ok OptimisticStatus.valid
  elif consensusFork >= ConsensusFork.Bellatrix:
    if signedBlock.message.is_execution_block:
      template payload(): auto =
        signedBlock.message.body.execution_payload

      template returnWithError(msg: string, extraMsg = ""): untyped =
        if extraMsg != "":
          debug msg, reason = extraMsg, executionPayload = shortLog(payload)
        else:
          debug msg, executionPayload = shortLog(payload)
        return err(VerifierError.Invalid)

      if payload.transactions.anyIt(it.len == 0):
        returnWithError "Execution block contains zero length transactions"

      if payload.block_hash != signedBlock.message.compute_execution_block_hash():
        returnWithError "Execution block hash validation failed"

      # [New in Deneb:EIP4844]
      when consensusFork >= ConsensusFork.Deneb:
        let blobsRes = signedBlock.message.is_valid_versioned_hashes
        if blobsRes.isErr:
          returnWithError "Blob versioned hashes invalid", blobsRes.error
      else:
        # If there are EIP-4844 (type 3) transactions in the payload with
        # versioned hashes, the transactions would be rejected by the EL
        # based on payload timestamp (only allowed post Deneb);
        # There are no `blob_kzg_commitments` before Deneb to compare against
        discard

      if signedBlock.root in self.invalidBlockRoots:
        returnWithError "Block root treated as invalid via config", $signedBlock.root

      ok OptimisticStatus.notValidated
    else:
      ok OptimisticStatus.valid
  else:
    ok OptimisticStatus.valid

proc storeBlock(
    self: ref BlockProcessor,
    src: MsgSource,
    wallTime: BeaconTime,
    signedBlock: ForkySignedBeaconBlock,
    sidecarsOpt: SomeOptSidecars,
    maybeFinalized: bool,
    queueTick: Moment,
    validationDur: Duration,
): Future[Result[BlockRef, VerifierError]] {.async: (raises: [CancelledError]).} =
  ## storeBlock is the main entry point for unvalidated blocks - all untrusted
  ## blocks, regardless of origin, pass through here. When storing a block,
  ## we will add it to the dag and pass it to all block consumers that need
  ## to know about it, such as the fork choice and the monitoring

  let
    ap = self.consensusManager.attestationPool
    startTick = Moment.now()
    vm = self.validatorMonitor
    dag = self.consensusManager.dag
    wallSlot = wallTime.slotOrZero
    deadlineTime =
      block:
        let slotTime = (wallSlot + 1).start_beacon_time() - 1.seconds
        if slotTime <= wallTime:
          0.seconds
        else:
          chronos.nanoseconds((slotTime - wallTime).nanoseconds)
    deadline = sleepAsync(deadlineTime)

  # If the block is missing its parent, it will be re-orphaned below
  self.consensusManager.quarantine[].removeOrphan(signedBlock)
  self.consensusManager.quarantine[].removeSidecarless(signedBlock)
  # The block is certainly not missing any more
  self.consensusManager.quarantine[].missing.del(signedBlock.root)

  if signedBlock.message.parent_root in
      self.consensusManager.quarantine[].unviable:
    # DAG doesn't know about unviable ancestor blocks - we do however!
    return err(VerifierError.UnviableFork)

  # We have to be careful that there exists only one in-flight entry point
  # for adding blocks or the checks performed in `checkHeadBlock` might
  # be invalidated (ie a block could be added while we wait for EL response
  # here)
  let parent = dag.checkHeadBlock(signedBlock).valueOr:
    # TODO This logic can be removed if the database schema is extended
    # to store non-canonical heads on top of the canonical head!
    # If that is done, the database no longer contains extra blocks
    # that have not yet been assigned a `BlockRef`
    if error == VerifierError.MissingParent:
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
      let
        parent_root = signedBlock.message.parent_root
        parentBlck = dag.getForkedBlock(parent_root)
      if parentBlck.isSome():
        var columnsOk = true
        let columns =
          withBlck(parentBlck.get()):
            when consensusFork >= ConsensusFork.Fulu:
              var data_column_sidecars: fulu.DataColumnSidecars
              for i in self.dataColumnQuarantine[].custodyColumns:
                let data_column = fulu.DataColumnSidecar.new()
                if not dag.db.getDataColumnSidecar(parent_root, i.ColumnIndex, data_column[]):
                  columnsOk = false
                  break
                data_column_sidecars.add data_column
              Opt.some data_column_sidecars
            else:
              Opt.none fulu.DataColumnSidecars

        var blobsOk = true
        let blobs =
          withBlck(parentBlck.get()):
            when consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
              var blob_sidecars: BlobSidecars
              for i in 0 ..< forkyBlck.message.body.blob_kzg_commitments.len:
                let blob = BlobSidecar.new()
                if not dag.db.getBlobSidecar(parent_root, i.BlobIndex, blob[]):
                  blobsOk = false  # Pruned, or inconsistent DB
                  break
                blob_sidecars.add blob
              Opt.some blob_sidecars
            else:
              Opt.none BlobSidecars
        # Blobs and columns can never co-exist in the same block
        # Block has neither blob sidecar nor data column sidecar
        if blobs.isNone and columns.isNone:
          debug "Loaded parent block from storage", parent_root
          self[].enqueueBlock(
            MsgSource.gossip, parentBlck.unsafeGet().asSigned(), Opt.none(BlobSidecars),
            Opt.none(DataColumnSidecars))
        # Block has blob sidecars associated and NO data column sidecars
        # as they cannot co-exist.
        if blobsOk and blobs.isSome:
          debug "Loaded parent block from storage", parent_root
          self[].enqueueBlock(
            MsgSource.gossip, parentBlck.unsafeGet().asSigned(), blobs,
            Opt.none(DataColumnSidecars))
        # Block has data column sidecars associated and NO blob sidecars
        # as they cannot co-exist.
        if columnsOk and columns.isSome:
          debug "Loaded parent block from storage", parent_root
          self[].enqueueBlock(
            MsgSource.gossip, parentBlck.unsafeGet().asSigned(), Opt.none(BlobSidecars),
            columns)

    return err(error)

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
        when consensusFork == ConsensusFork.Gloas:
          debugGloasComment "need getExecutionValidity on gloas blocks"
          Opt.some OptimisticStatus.valid
        elif consensusFork >= ConsensusFork.Bellatrix:
          func shouldRetry(): bool =
            not dag.is_optimistic(dag.head.bid)
          await self.consensusManager.elManager.getExecutionValidity(
            signedBlock, deadline, shouldRetry())
        else:
          Opt.some(OptimisticStatus.valid) # vacuously

  let optimisticStatus = ?(optimisticStatusRes or verifyPayload(self, signedBlock))

  if OptimisticStatus.invalidated == optimisticStatus:
    return err(VerifierError.Invalid)

  let newPayloadTick = Moment.now()

  ?verifySidecars(signedBlock, sidecarsOpt)

  let blck =
    ?dag.addHeadBlockWithParent(
      self.verifier,
      signedBlock,
      parent,
      optimisticStatus,
      onBlockAdded(dag, consensusFork, src, wallTime, ap, vm),
    )

  # Even if the EL is not responding, we'll only try once every now and then
  # to give it a block - this avoids a pathological slowdown where a busy EL
  # times out on every block we give it because it's busy with the previous
  # one
  self[].lastPayload = signedBlock.message.slot

  # write blobs now that block has been written.
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

  ok blck

# Enqueue
# ------------------------------------------------------------------------------

# Beacon block with no blobs and no data columns.
proc addBlock*(
    self: var BlockProcessor, src: MsgSource,
    blck: ForkedSignedBeaconBlock,
    maybeFinalized = false,
    validationDur = Duration()): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError], raw: true).} =
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
  enqueueBlock(self, src, blck, Opt.none(BlobSidecars), Opt.none(DataColumnSidecars),
    resfut, maybeFinalized, validationDur)
  resfut

# Post-Deneb and pre-Fulu block which MAY have blobs.
proc addBlock*(
    self: var BlockProcessor, src: MsgSource,
    blck: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars], maybeFinalized = false,
    validationDur = Duration()): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError], raw: true).} =
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
  enqueueBlock(self, src, blck, blobs, Opt.none(DataColumnSidecars),
    resfut, maybeFinalized, validationDur)
  resfut

# Post-Fulu block which MAY have data columns.
proc addBlock*(
    self: var BlockProcessor, src: MsgSource,
    blck: ForkedSignedBeaconBlock,
    data_columns: Opt[DataColumnSidecars], maybeFinalized = false,
    validationDur = Duration()): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError], raw: true).} =
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
  enqueueBlock(self, src, blck, Opt.none(BlobSidecars), data_columns,
    resfut, maybeFinalized, validationDur)
  resfut

# Event Loop
# ------------------------------------------------------------------------------

proc processBlock(
    self: ref BlockProcessor, entry: BlockEntry) {.async: (raises: [CancelledError]).} =
  logScope:
    blockRoot = shortLog(entry.blck.root)

  let
    wallTime = self.getBeaconTime()
    (afterGenesis, _) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing block before genesis, clock turned back?"
    quit 1

  let
    res = withBlck(entry.blck):
      let
        sidecars = selectSidecars(consensusFork, entry.blobs, entry.columns)
        res = await self.storeBlock(
          entry.src, wallTime, forkyBlck, sidecars,
          entry.maybeFinalized, entry.queueTick, entry.validationDur)

      self[].dumpBlock(forkyBlck, res)

      res
    root = entry.blck.root

  if res.isOk():
    # Once a block is successfully stored, enqueue the direct descendants
    self[].enqueueQuarantine(root)
  else:
    case res.error()
    of VerifierError.MissingParent:
      if (let r = self.consensusManager.quarantine[].addOrphan(
          self.consensusManager.dag.finalizedHead.slot, entry.blck);
              r.isErr()):
        debug "could not add orphan",
          blockRoot = shortLog(root),
          blck = shortLog(entry.blck),
          signature = shortLog(entry.blck.signature),
          err = r.error()
      else:
        if entry.blobs.isSome:
          self.blobQuarantine[].put(root, entry.blobs.get)
        if entry.columns.isSome:
          self.dataColumnQuarantine[].put(root, entry.columns.get)

        debug "Block quarantined",
          blockRoot = shortLog(root),
          blck = shortLog(entry.blck),
          signature = shortLog(entry.blck.signature)

    of VerifierError.UnviableFork:
      # Track unviables so that descendants can be discarded promptly
      # TODO Invalid and unviable should be treated separately, to correctly
      #      respond when a descendant of an invalid block is validated
      # TODO re-add VeriferError.Invalid handling
      self.consensusManager.quarantine[].addUnviable(root)
    else:
      discard

  if entry.resfut != nil:
    entry.resfut.complete(res.mapConvert(void))

proc runQueueProcessingLoop*(self: ref BlockProcessor) {.async: (raises: []).} =
  try:
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
  except CancelledError:
    debug "Shutting down queue processing loop"
