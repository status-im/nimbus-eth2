# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/tables,
  stew/results,
  chronicles, chronos, metrics, taskpools,
  ../networking/eth2_network,
  ../spec/[helpers, forks, eip7594_helpers],
  ../spec/datatypes/[altair, phase0, deneb, eip7594],
  ../consensus_object_pools/[
    blob_quarantine, block_clearance, block_quarantine, blockchain_dag,
    data_column_quarantine, attestation_pool, light_client_pool, 
    sync_committee_msg_pool, validator_change_pool],
  ../validators/validator_pool,
  ../beacon_clock,
  "."/[gossip_validation, block_processor, batch_validation],
  ../nimbus_binary_common

export
  results, taskpools, block_clearance, blockchain_dag, attestation_pool,
  light_client_pool, sync_committee_msg_pool, validator_change_pool,
  validator_pool, beacon_clock, gossip_validation, block_processor,
  batch_validation, block_quarantine

logScope: topics = "gossip_eth2"

# Metrics for tracking attestation and beacon block loss
declareCounter beacon_attestations_received,
  "Number of valid unaggregated attestations processed by this node"
declareCounter beacon_attestations_dropped,
  "Number of invalid unaggregated attestations dropped by this node", labels = ["reason"]
declareCounter beacon_aggregates_received,
  "Number of valid aggregated attestations processed by this node"
declareCounter beacon_aggregates_dropped,
  "Number of invalid aggregated attestations dropped by this node", labels = ["reason"]
declareCounter beacon_blocks_received,
  "Number of valid blocks processed by this node"
declareCounter beacon_blocks_dropped,
  "Number of invalid blocks dropped by this node", labels = ["reason"]
declareCounter blob_sidecars_received,
  "Number of valid blobs processed by this node"
declareCounter blob_sidecars_dropped,
  "Number of invalid blobs dropped by this node", labels = ["reason"]
declareCounter data_column_sidecars_received,
  "Number of valid data column sidecars processed by this node"
declareCounter data_column_sidecars_dropped,
  "Number of invalid data column sidecars dropped by this node", labels = ["reason"]
declareCounter beacon_attester_slashings_received,
  "Number of valid attester slashings processed by this node"
declareCounter beacon_attester_slashings_dropped,
  "Number of invalid attester slashings dropped by this node", labels = ["reason"]
declareCounter bls_to_execution_change_received,
  "Number of valid BLS to execution changes processed by this node"
declareCounter bls_to_execution_change_dropped,
  "Number of invalid BLS to execution changes dropped by this node", labels = ["reason"]
declareCounter beacon_proposer_slashings_received,
  "Number of valid proposer slashings processed by this node"
declareCounter beacon_proposer_slashings_dropped,
  "Number of invalid proposer slashings dropped by this node", labels = ["reason"]
declareCounter beacon_voluntary_exits_received,
  "Number of valid voluntary exits processed by this node"
declareCounter beacon_voluntary_exits_dropped,
  "Number of invalid voluntary exits dropped by this node", labels = ["reason"]
declareCounter beacon_sync_committee_messages_received,
  "Number of valid sync committee messages processed by this node"
declareCounter beacon_sync_committee_messages_dropped,
  "Number of invalid sync committee messages dropped by this node", labels = ["reason"]
declareCounter beacon_sync_committee_contributions_received,
  "Number of valid sync committee contributions processed by this node"
declareCounter beacon_sync_committee_contributions_dropped,
  "Number of invalid sync committee contributions dropped by this node", labels = ["reason"]
declareCounter beacon_light_client_finality_update_received,
  "Number of valid light client finality update processed by this node"
declareCounter beacon_light_client_finality_update_dropped,
  "Number of invalid light client finality update dropped by this node", labels = ["reason"]
declareCounter beacon_light_client_optimistic_update_received,
  "Number of valid light client optimistic update processed by this node"
declareCounter beacon_light_client_optimistic_update_dropped,
  "Number of invalid light client optimistic update dropped by this node", labels = ["reason"]

const delayBuckets = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, Inf]

declareHistogram beacon_attestation_delay,
  "Time(s) between slot start and attestation reception", buckets = delayBuckets

declareHistogram beacon_aggregate_delay,
  "Time(s) between slot start and aggregate reception", buckets = delayBuckets

declareHistogram beacon_block_delay,
  "Time(s) between slot start and beacon block reception", buckets = delayBuckets

declareHistogram blob_sidecar_delay,
  "Time(s) between slot start and blob sidecar reception", buckets = delayBuckets

declareHistogram data_column_sidecar_delay,
  "Time(s) between slot start and data column sidecar reception", buckets = delayBuckets

type
  DoppelgangerProtection = object
    broadcastStartEpoch*: Epoch  ##\
    ## Set anew, each time gossip is re-enabled after syncing completes, so
    ## might reset multiple times per instance. This allows some safe level
    ## of gossip interleaving between nodes so long as they don't gossip at
    ## the same time.

  Eth2Processor* = object
    ## The Eth2Processor is the entry point for untrusted message processing -
    ## when we receive messages from various sources, we pass them to the
    ## processor for validation and routing - the messages are generally
    ## validated, and if valid, passed on to the various pools, monitors and
    ## managers to update the state of the application.
    ##
    ## Block processing is special in that part of it is done in the
    ## `BlockProcessor` instead, via a special block processing queue.
    ##
    ## Each validating function generally will do a sanity check on the message
    ## whose purpose is to quickly filter out spam, then will (usually) delegate
    ## full validation to the proper manager - finally, metrics and monitoring
    ## are updated.
    doppelgangerDetectionEnabled*: bool

    # Local sources of truth for validation
    # ----------------------------------------------------------------
    dag*: ChainDAGRef
    attestationPool*: ref AttestationPool
    validatorPool: ref ValidatorPool
    syncCommitteeMsgPool: ref SyncCommitteeMsgPool
    lightClientPool: ref LightClientPool

    doppelgangerDetection*: DoppelgangerProtection

    # Gossip validated -> enqueue for further verification
    # ----------------------------------------------------------------
    blockProcessor*: ref BlockProcessor

    # Validator monitoring
    validatorMonitor: ref ValidatorMonitor

    # Validated with no further verification required
    # ----------------------------------------------------------------
    validatorChangePool: ref ValidatorChangePool

    # Almost validated, pending cryptographic signature check
    # ----------------------------------------------------------------
    batchCrypto*: ref BatchCrypto

    # Missing information
    # ----------------------------------------------------------------
    quarantine*: ref Quarantine

    blobQuarantine*: ref BlobQuarantine

    dataColumnQuarantine*: ref DataColumnQuarantine

    # Application-provided current time provider (to facilitate testing)
    getCurrentBeaconTime*: GetBeaconTimeFn

  ValidationRes* = Result[void, ValidationError]

func toValidationResult*(res: ValidationRes): ValidationResult =
  if res.isOk(): ValidationResult.Accept else: res.error()[0]

# Initialization
# ------------------------------------------------------------------------------

proc new*(T: type Eth2Processor,
          doppelgangerDetectionEnabled: bool,
          blockProcessor: ref BlockProcessor,
          validatorMonitor: ref ValidatorMonitor,
          dag: ChainDAGRef,
          attestationPool: ref AttestationPool,
          validatorChangePool: ref ValidatorChangePool,
          validatorPool: ref ValidatorPool,
          syncCommitteeMsgPool: ref SyncCommitteeMsgPool,
          lightClientPool: ref LightClientPool,
          quarantine: ref Quarantine,
          blobQuarantine: ref BlobQuarantine,
          dataColumnQuarantine: ref DataColumnQuarantine,
          rng: ref HmacDrbgContext,
          getBeaconTime: GetBeaconTimeFn,
          taskpool: TaskPoolPtr
         ): ref Eth2Processor =
  (ref Eth2Processor)(
    doppelgangerDetectionEnabled: doppelgangerDetectionEnabled,
    doppelgangerDetection: DoppelgangerProtection(
      broadcastStartEpoch: FAR_FUTURE_EPOCH),
    blockProcessor: blockProcessor,
    validatorMonitor: validatorMonitor,
    dag: dag,
    attestationPool: attestationPool,
    validatorChangePool: validatorChangePool,
    validatorPool: validatorPool,
    syncCommitteeMsgPool: syncCommitteeMsgPool,
    lightClientPool: lightClientPool,
    quarantine: quarantine,
    blobQuarantine: blobQuarantine,
    dataColumnQuarantine: dataColumnQuarantine,
    getCurrentBeaconTime: getBeaconTime,
    batchCrypto: BatchCrypto.new(
      rng = rng,
      # Only run eager attestation signature verification if we're not
      # processing blocks in order to give priority to block processing
      eager = proc(): bool = not blockProcessor[].hasBlocks(),
      genesis_validators_root = dag.genesis_validators_root, taskpool).expect(
        "working batcher")
  )

# Each validator logs, validates then passes valid data to its destination
# further down the line - in particular, validation should generally not have
# any side effects until the message is fully validated, or invalid messages
# could be used to push out valid messages.

proc processSignedBeaconBlock*(
    self: var Eth2Processor, src: MsgSource,
    signedBlock: ForkySignedBeaconBlock,
    maybeFinalized: bool = false): ValidationRes =
  let
    wallTime = self.getCurrentBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)
    signature = shortLog(signedBlock.signature)
    wallSlot

  if not afterGenesis:
    notice "Block before genesis"
    return errIgnore("Block before genesis")

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - signedBlock.message.slot.start_beacon_time

  # Start of block processing - in reality, we have already gone through SSZ
  # decoding at this stage, which may be significant
  debug "Block received", delay

  let v =
    self.dag.validateBeaconBlock(self.quarantine, signedBlock, wallTime, {})

  if v.isOk():
    # Block passed validation - enqueue it for processing. The block processing
    # queue is effectively unbounded as we use a freestanding task to enqueue
    # the block - this is done so that when blocks arrive concurrently with
    # sync, we don't lose the gossip blocks, but also don't block the gossip
    # propagation of seemingly good blocks
    trace "Block validated"

    # let blobs =
    #   when typeof(signedBlock).kind >= ConsensusFork.Deneb:
    #     if self.blobQuarantine[].hasBlobs(signedBlock):
    #       Opt.some(self.blobQuarantine[].popBlobs(signedBlock.root, signedBlock))
    #     else:
    #       discard self.quarantine[].addBlobless(self.dag.finalizedHead.slot,
    #                                             signedBlock)
    #       return v
    #   else:
    #     Opt.none(BlobSidecars)

    # self.blockProcessor[].enqueueBlock(
    #   src, ForkedSignedBeaconBlock.init(signedBlock),
    #   blobs,
    #   Opt.none(DataColumnSidecars),
    #   maybeFinalized = maybeFinalized,
    #   validationDur = nanoseconds(
    #     (self.getCurrentBeaconTime() - wallTime).nanoseconds))

    let data_columns =
      when typeof(signedBlock).kind >= ConsensusFork.Deneb:
        if self.dataColumnQuarantine[].hasDataColumns(signedBlock):
          Opt.some(self.dataColumnQuarantine[].popDataColumns(signedBlock.root, signedBlock))
        else:
          discard self.quarantine[].addColumnless(self.dag.finalizedHead.slot,
                                                  signedBlock)
          return v
      else:
        Opt.none(DataColumnSidecars)

    self.blockProcessor[].enqueueBlock(
      src, ForkedSignedBeaconBlock.init(signedBlock),
      Opt.none(BlobSidecars),
      data_columns,
      maybeFinalized = maybeFinalized,
      validationDur = nanoseconds(
        (self.getCurrentBeaconTime() - wallTime).nanoseconds))

    # Validator monitor registration for blocks is done by the processor
    beacon_blocks_received.inc()
    beacon_block_delay.observe(delay.toFloatSeconds())
  else:
    debug "Dropping block", error = v.error()

    self.blockProcessor[].dumpInvalidBlock(signedBlock)

    beacon_blocks_dropped.inc(1, [$v.error[0]])

  v

proc processBlobSidecar*(
    self: var Eth2Processor, src: MsgSource,
    blobSidecar: deneb.BlobSidecar, subnet_id: BlobId): ValidationRes =
  template block_header: untyped = blobSidecar.signed_block_header.message

  let
    wallTime = self.getCurrentBeaconTime()
    (_, wallSlot) = wallTime.toSlot()

  logScope:
    blob = shortLog(blobSidecar)
    wallSlot

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - block_header.slot.start_beacon_time
  debug "Blob received", delay

  let v =
    self.dag.validateBlobSidecar(self.quarantine, self.blobQuarantine,
                                 blobSidecar, wallTime, subnet_id)

  if v.isErr():
    debug "Dropping blob", error = v.error()
    blob_sidecars_dropped.inc(1, [$v.error[0]])
    return v

  debug "Blob validated, putting in blob quarantine"
  self.blobQuarantine[].put(newClone(blobSidecar))

  let block_root = hash_tree_root(block_header)
  if (let o = self.quarantine[].popBlobless(block_root); o.isSome):
    let blobless = o.unsafeGet()
    withBlck(blobless):
      when consensusFork >= ConsensusFork.Deneb:
        if self.blobQuarantine[].hasBlobs(forkyBlck):
          self.blockProcessor[].enqueueBlock(
            MsgSource.gossip, blobless,
            Opt.some(self.blobQuarantine[].popBlobs(block_root, forkyBlck)),
            Opt.none(DataColumnSidecars))
        else:
          discard self.quarantine[].addBlobless(
            self.dag.finalizedHead.slot, forkyBlck)
      else:
        raiseAssert "Could not have been added as blobless"

  blob_sidecars_received.inc()
  blob_sidecar_delay.observe(delay.toFloatSeconds())

  v

proc processDataColumnSidecar*(
    self: var Eth2Processor, src: MsgSource,
    dataColumnSidecar: DataColumnSidecar, subnet_id: uint64): ValidationRes =
  template block_header: untyped = dataColumnSidecar.signed_block_header.message

  let
    wallTime = self.getCurrentBeaconTime()
    (_, wallSlot) = wallTime.toSlot()

  logScope:
    dcs = shortLog(dataColumnSidecar)
    wallSlot

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - block_header.slot.start_beacon_time
  debug "Data column received", delay

  let v =
    self.dag.validateDataColumnSidecar(self.quarantine, self.dataColumnQuarantine,
                                 dataColumnSidecar, wallTime, subnet_id)

  if v.isErr():
    debug "Dropping data column", error = v.error()
    data_column_sidecars_dropped.inc(1, [$v.error[0]])
    return v

  debug "Data column validated, putting data column in quarantine"
  self.dataColumnQuarantine[].put(newClone(dataColumnSidecar))

  let block_root = hash_tree_root(block_header)
  if (let o = self.quarantine[].popColumnless(block_root); o.isSome):
    let columnless = o.unsafeGet()
    withBlck(columnless):
      when consensusFork >= ConsensusFork.Deneb:
        if self.dataColumnQuarantine[].hasDataColumns(forkyBlck):
          self.blockProcessor[].enqueueBlock(
            MsgSource.gossip, columnless,
            Opt.none(BlobSidecars),
            Opt.some(self.dataColumnQuarantine[].popDataColumns(block_root, forkyBlck)))
        else:
          discard self.quarantine[].addColumnless(
            self.dag.finalizedHead.slot, forkyBlck)
      else:
        raiseAssert "Could not have been added as columnless"

  data_column_sidecars_received.inc()
  data_column_sidecar_delay.observe(delay.toFloatSeconds())

  v

proc setupDoppelgangerDetection*(self: var Eth2Processor, slot: Slot) =
  # When another client's already running, this is very likely to detect
  # potential duplicate validators, which can trigger slashing.
  #
  # Every missed attestation costs approximately 3*get_base_reward(), which
  # can be up to around 10,000 Wei. Thus, skipping attestations isn't cheap
  # and one should gauge the likelihood of this simultaneous launch to tune
  # the epoch delay to one's perceived risk.

  # Round up to ensure that we cover the entire epoch - used by rest api also
  self.doppelgangerDetection.broadcastStartEpoch =
    (slot + SLOTS_PER_EPOCH - 1).epoch

  if self.doppelgangerDetectionEnabled:
    notice "Setting up doppelganger detection",
      epoch = slot.epoch,
      broadcast_epoch = self.doppelgangerDetection.broadcastStartEpoch

proc clearDoppelgangerProtection*(self: var Eth2Processor) =
  self.doppelgangerDetection.broadcastStartEpoch = FAR_FUTURE_EPOCH

proc checkForPotentialDoppelganger(
    self: var Eth2Processor, attestation: phase0.Attestation | electra.Attestation,
    attesterIndices: openArray[ValidatorIndex]) =
  # Only check for attestations after node launch. There might be one slot of
  # overlap in quick intra-slot restarts so trade off a few true negatives in
  # the service of avoiding more likely false positives.
  if not self.doppelgangerDetectionEnabled:
    return

  for validatorIndex in attesterIndices:
    let
      pubkey = self.dag.validatorKey(validatorIndex).get().toPubKey()

    if self.validatorPool[].triggersDoppelganger(
        pubkey, attestation.data.slot.epoch):
      warn "Doppelganger attestation",
        validator = shortLog(pubkey),
        validator_index = validatorIndex,
        attestation = shortLog(attestation)
      quitDoppelganger()

proc processDataColumnReconstruction*(
    self: ref Eth2Processor,
    node: Eth2Node,
    signed_block: deneb.SignedBeaconBlock |
    electra.SignedBeaconBlock):
    Future[ValidationRes] {.async: (raises: [CancelledError]).} =
  
  let
    dag = self.dag
    root = signed_block.root
    custodiedColumnIndices = get_custody_columns(
        node.nodeId,
        CUSTODY_REQUIREMENT)
  
  var
    data_column_sidecars: seq[DataColumnSidecar]
    columnsOk = true
    storedColumns: seq[ColumnIndex]
  
  # Loading the data columns from the database
  for custody_column in custodiedColumnIndices.get:
    let data_column = DataColumnSidecar.new()
    if not dag.db.getDataColumnSidecar(root, custody_column, data_column[]):
      columnsOk = false
      break
    data_column_sidecars.add data_column[]
    storedColumns.add data_column.index

    if columnsOk:
      debug "Loaded data column for reconstruction"

  # storedColumn number is less than the NUMBER_OF_COLUMNS
  # then reconstruction is not possible, and if all the data columns
  # are already stored then we do not need to reconstruct at all
  if storedColumns.len < NUMBER_OF_COLUMNS or storedColumns.len == NUMBER_OF_COLUMNS:
    return ok()
  else:
    return errIgnore ("DataColumnSidecar: Reconstruction error!")

  # Recover blobs from saved data column sidecars
  let recovered_blobs = recover_blobs(data_column_sidecars, storedColumns.len, signed_block)
  if not recovered_blobs.isOk:
    return errIgnore ("Error recovering blobs from data columns")

  # Reconstruct data column sidecars from recovered blobs
  let reconstructedDataColumns = get_data_column_sidecars(signed_block, recovered_blobs.get)

  for data_column in data_column_sidecars:
    if data_column.index notin custodiedColumnIndices.get:
      continue
    
    dag.db.putDataColumnSidecar(data_column)

  ok()

proc processAttestation*(
    self: ref Eth2Processor, src: MsgSource,
    attestation: phase0.Attestation | electra.Attestation, subnet_id: SubnetId,
    checkSignature: bool = true): Future[ValidationRes] {.async: (raises: [CancelledError]).} =
  var wallTime = self.getCurrentBeaconTime()
  let (afterGenesis, wallSlot) = wallTime.toSlot()

  logScope:
    attestation = shortLog(attestation)
    subnet_id
    wallSlot

  if not afterGenesis:
    notice "Attestation before genesis"
    return errIgnore("Attestation before genesis")

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - attestation.data.slot.attestation_deadline
  debug "Attestation received", delay

  # Now proceed to validation
  let v =
    await self.attestationPool.validateAttestation(
      self.batchCrypto, attestation, wallTime, subnet_id, checkSignature)
  return if v.isOk():
    # Due to async validation the wallTime here might have changed
    wallTime = self.getCurrentBeaconTime()

    let (attester_index, sig) = v.get()

    self[].checkForPotentialDoppelganger(attestation, [attester_index])

    trace "Attestation validated"
    self.attestationPool[].addAttestation(
      attestation, [attester_index], sig, wallTime)

    self.validatorMonitor[].registerAttestation(
      src, wallTime, attestation, attester_index)

    beacon_attestations_received.inc()
    beacon_attestation_delay.observe(delay.toFloatSeconds())

    ok()
  else:
    debug "Dropping attestation", reason = $v.error
    beacon_attestations_dropped.inc(1, [$v.error[0]])
    err(v.error())

proc processSignedAggregateAndProof*(
    self: ref Eth2Processor, src: MsgSource,
    signedAggregateAndProof: phase0.SignedAggregateAndProof | electra.SignedAggregateAndProof,
    checkSignature = true, checkCover = true): Future[ValidationRes] {.async: (raises: [CancelledError]).} =
  var wallTime = self.getCurrentBeaconTime()
  let (afterGenesis, wallSlot) = wallTime.toSlot()

  logScope:
    aggregate = shortLog(signedAggregateAndProof.message.aggregate)
    aggregator_index = signedAggregateAndProof.message.aggregator_index
    selection_proof = shortLog(signedAggregateAndProof.message.selection_proof)
    signature = shortLog(signedAggregateAndProof.signature)
    wallSlot

  if not afterGenesis:
    notice "Aggregate before genesis"
    return errIgnore("Aggregate before genesis")

  # Potential under/overflows are fine; would just create odd logs
  let
    slot = signedAggregateAndProof.message.aggregate.data.slot
    delay = wallTime - slot.aggregate_deadline
  debug "Aggregate received", delay

  let v =
    await self.attestationPool.validateAggregate(
      self.batchCrypto, signedAggregateAndProof, wallTime,
      checkSignature = checkSignature, checkCover = checkCover)

  return if v.isOk():
    # Due to async validation the wallTime here might have changed
    wallTime = self.getCurrentBeaconTime()

    let (attesting_indices, sig) = v.get()

    self[].checkForPotentialDoppelganger(
      signedAggregateAndProof.message.aggregate, attesting_indices)

    trace "Aggregate validated"

    self.attestationPool[].addAttestation(
      signedAggregateAndProof.message.aggregate, attesting_indices, sig,
      wallTime)

    self.validatorMonitor[].registerAggregate(
      src, wallTime, signedAggregateAndProof.message, attesting_indices)

    beacon_aggregates_received.inc()
    beacon_aggregate_delay.observe(delay.toFloatSeconds())

    ok()
  else:
    debug "Dropping aggregate", reason = $v.error
    beacon_aggregates_dropped.inc(1, [$v.error[0]])

    err(v.error())

proc processBlsToExecutionChange*(
    self: ref Eth2Processor, src: MsgSource,
    blsToExecutionChange: SignedBLSToExecutionChange):
    Future[ValidationRes] {.async: (raises: [CancelledError]).} =
  logScope:
    blsToExecutionChange = shortLog(blsToExecutionChange)

  debug "BLS to execution change received"

  let v = await self.validatorChangePool[].validateBlsToExecutionChange(
    self.batchCrypto, blsToExecutionChange,
    self.getCurrentBeaconTime().slotOrZero.epoch)

  if v.isOk():
    trace "BLS to execution change validated"
    # Prioritize API-provided messages
    self.validatorChangePool[].addMessage(
      blsToExecutionChange, src == MsgSource.api)
  else:
    debug "Dropping BLS to execution change", reason = $v.error
    beacon_attester_slashings_dropped.inc(1, [$v.error[0]])

  return v

proc processAttesterSlashing*(
    self: var Eth2Processor, src: MsgSource,
    attesterSlashing: phase0.AttesterSlashing): ValidationRes =
  logScope:
    attesterSlashing = shortLog(attesterSlashing)

  debug "Attester slashing received"

  let v = self.validatorChangePool[].validateAttesterSlashing(attesterSlashing)

  if v.isOk():
    trace "Attester slashing validated"

    self.validatorChangePool[].addMessage(attesterSlashing)

    self.validatorMonitor[].registerAttesterSlashing(src, attesterSlashing)

    beacon_attester_slashings_received.inc()
  else:
    debug "Dropping attester slashing", reason = $v.error
    beacon_attester_slashings_dropped.inc(1, [$v.error[0]])

  v

proc processProposerSlashing*(
    self: var Eth2Processor, src: MsgSource,
    proposerSlashing: ProposerSlashing): Result[void, ValidationError] =
  logScope:
    proposerSlashing = shortLog(proposerSlashing)

  debug "Proposer slashing received"

  let v = self.validatorChangePool[].validateProposerSlashing(proposerSlashing)
  if v.isOk():
    trace "Proposer slashing validated"

    self.validatorChangePool[].addMessage(proposerSlashing)

    self.validatorMonitor[].registerProposerSlashing(src, proposerSlashing)

    beacon_proposer_slashings_received.inc()
  else:
    debug "Dropping proposer slashing", reason = $v.error
    beacon_proposer_slashings_dropped.inc(1, [$v.error[0]])

  v

proc processSignedVoluntaryExit*(
    self: var Eth2Processor, src: MsgSource,
    signedVoluntaryExit: SignedVoluntaryExit): Result[void, ValidationError] =
  logScope:
    signedVoluntaryExit = shortLog(signedVoluntaryExit)

  debug "Voluntary exit received"

  let v = self.validatorChangePool[].validateVoluntaryExit(signedVoluntaryExit)
  if v.isOk():
    trace "Voluntary exit validated"

    self.validatorChangePool[].addMessage(signedVoluntaryExit)

    self.validatorMonitor[].registerVoluntaryExit(
      src, signedVoluntaryExit.message)

    beacon_voluntary_exits_received.inc()
  else:
    debug "Dropping voluntary exit", reason = $v.error
    beacon_voluntary_exits_dropped.inc(1, [$v.error[0]])

  v

proc processSyncCommitteeMessage*(
    self: ref Eth2Processor, src: MsgSource,
    syncCommitteeMsg: SyncCommitteeMessage,
    subcommitteeIdx: SyncSubcommitteeIndex,
    checkSignature: bool = true): Future[Result[void, ValidationError]] {.async: (raises: [CancelledError]).} =
  let
    wallTime = self.getCurrentBeaconTime()
    wallSlot = wallTime.slotOrZero()

  logScope:
    syncCommitteeMsg = shortLog(syncCommitteeMsg)
    subcommitteeIdx
    wallSlot

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - syncCommitteeMsg.slot.sync_committee_message_deadline
  debug "Sync committee message received", delay

  # Now proceed to validation
  let v = await validateSyncCommitteeMessage(
    self.dag, self.quarantine, self.batchCrypto, self.syncCommitteeMsgPool,
    syncCommitteeMsg, subcommitteeIdx, wallTime, checkSignature)
  return if v.isOk():
    trace "Sync committee message validated"
    let (bid, cookedSig, positions) = v.get()

    self.syncCommitteeMsgPool[].addSyncCommitteeMessage(
      syncCommitteeMsg.slot,
      bid,
      syncCommitteeMsg.validator_index,
      cookedSig,
      subcommitteeIdx,
      positions)

    self.validatorMonitor[].registerSyncCommitteeMessage(
      src, wallTime, syncCommitteeMsg)

    beacon_sync_committee_messages_received.inc()

    ok()
  else:
    debug "Dropping sync committee message", reason = $v.error
    beacon_sync_committee_messages_dropped.inc(1, [$v.error[0]])
    err(v.error())

proc processSignedContributionAndProof*(
    self: ref Eth2Processor, src: MsgSource,
    contributionAndProof: SignedContributionAndProof,
    checkSignature: bool = true): Future[Result[void, ValidationError]] {.async: (raises: [CancelledError]).} =
  let
    wallTime = self.getCurrentBeaconTime()
    wallSlot = wallTime.slotOrZero()

  logScope:
    contribution = shortLog(contributionAndProof.message.contribution)
    signature = shortLog(contributionAndProof.signature)
    aggregator_index = contributionAndProof.message.aggregator_index
    selection_proof = contributionAndProof.message.selection_proof
    wallSlot

  # Potential under/overflows are fine; would just create odd metrics and logs
  let
    slot = contributionAndProof.message.contribution.slot
    delay = wallTime - slot.sync_contribution_deadline
  debug "Contribution received", delay

  # Now proceed to validation
  let v = await validateContribution(
    self.dag, self.quarantine, self.batchCrypto, self.syncCommitteeMsgPool,
    contributionAndProof, wallTime, checkSignature)

  return if v.isOk():
    trace "Contribution validated"

    let (bid, sig, participants) = v.get

    self.syncCommitteeMsgPool[].addContribution(
      contributionAndProof, bid, sig)

    self.validatorMonitor[].registerSyncContribution(
      src, wallTime, contributionAndProof.message, participants)

    beacon_sync_committee_contributions_received.inc()

    ok()
  else:
    debug "Dropping contribution", reason = $v.error
    beacon_sync_committee_contributions_dropped.inc(1, [$v.error[0]])

    err(v.error())

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#process_light_client_finality_update
proc processLightClientFinalityUpdate*(
    self: var Eth2Processor, src: MsgSource,
    finality_update: ForkedLightClientFinalityUpdate
): Result[void, ValidationError] =
  let
    wallTime = self.getCurrentBeaconTime()
    v = validateLightClientFinalityUpdate(
      self.lightClientPool[], self.dag, finality_update, wallTime)

  if v.isOk():
    beacon_light_client_finality_update_received.inc()
  else:
    beacon_light_client_finality_update_dropped.inc(1, [$v.error[0]])
  v

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#process_light_client_optimistic_update
proc processLightClientOptimisticUpdate*(
    self: var Eth2Processor, src: MsgSource,
    optimistic_update: ForkedLightClientOptimisticUpdate
): Result[void, ValidationError] =
  let
    wallTime = self.getCurrentBeaconTime()
    v = validateLightClientOptimisticUpdate(
      self.lightClientPool[], self.dag, optimistic_update, wallTime)
  if v.isOk():
    beacon_light_client_optimistic_update_received.inc()
  else:
    beacon_light_client_optimistic_update_dropped.inc(1, [$v.error[0]])
  v