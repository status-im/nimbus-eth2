# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[tables],
  chronicles, chronos, metrics,
  taskpools,
  kzg4844/kzg,
  ssz_serialization/types,
  ../el/el_manager,
  ../spec/[helpers, forks],
  ../consensus_object_pools/[
    attestation_pool, blob_quarantine, block_clearance, block_quarantine,
    blockchain_dag, envelope_quarantine, execution_payload_pool,
    payload_attestation_pool, light_client_pool,
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
declareCounter execution_payload_envelopes_received,
  "Number of valid execution payload envelope processed by this node"
declareCounter execution_payload_envelopes_dropped,
  "Number of invalid execution payload envelope dropped by this node", labels = ["reason"]
declareCounter blob_sidecars_received,
  "Number of valid blobs processed by this node"
declareCounter blob_sidecars_dropped,
  "Number of invalid blobs dropped by this node", labels = ["reason"]
declareCounter data_column_sidecars_received,
  "Number of valid data columns processed by this node"
declareCounter data_column_sidecars_dropped,
  "Number of invalid data columns dropped by this node", labels = ["reason"]
declareCounter beacon_attester_slashings_received,
  "Number of valid attester slashings processed by this node"
declareCounter beacon_attester_slashings_dropped,
  "Number of invalid attester slashings dropped by this node", labels = ["reason"]
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

declareCounter beacon_execution_payload_bids_received,
  "Number of valid execution payload bids processed by this node"

declareCounter beacon_execution_payload_bids_dropped,
  "Number of invalid execution payload bids dropped by this node",
  labels = ["reason"]

const delayBuckets = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, Inf]

declareHistogram beacon_attestation_delay,
  "Time(s) between slot start and attestation reception", buckets = delayBuckets

declareHistogram beacon_aggregate_delay,
  "Time(s) between slot start and aggregate reception", buckets = delayBuckets

declareHistogram beacon_block_delay,
  "Time(s) between slot start and beacon block reception", buckets = delayBuckets

declareHistogram execution_payload_envelope_delay,
  "Time(s) between slot start and execution payload envelope reception", buckets = delayBuckets

declareHistogram blob_sidecar_delay,
  "Time(s) between slot start and blob sidecar reception", buckets = delayBuckets

declareHistogram data_column_sidecar_delay,
  "Time(s) betweeen slot start and data column sidecar reception",
  buckets = delayBuckets

declareHistogram data_column_sidecar_validation_duration,
  "Time(s) taken to validate a data column sidecar",
  buckets = [0.001, 0.005, 0.010, 0.015, 0.020, 0.030, 0.050, 0.100, 0.250, 0.500, 1.0, Inf]

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
    validatorPool*: ref ValidatorPool
    syncCommitteeMsgPool: ref SyncCommitteeMsgPool
    lightClientPool: ref LightClientPool
    executionPayloadBidPool*: ref ExecutionPayloadBidPool
    payloadAttestationPool*: ref PayloadAttestationPool

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
    dataColumnQuarantine*: ref ColumnQuarantine
    gloasColumnQuarantine*: ref GloasColumnQuarantine
    envelopeQuarantine*: ref EnvelopeQuarantine

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
          executionPayloadBidPool: ref ExecutionPayloadBidPool,
          payloadAttestationPool: ref PayloadAttestationPool,
          quarantine: ref Quarantine,
          blobQuarantine: ref BlobQuarantine,
          dataColumnQuarantine: ref ColumnQuarantine,
          gloasColumnQuarantine: ref GloasColumnQuarantine,
          envelopeQuarantine: ref EnvelopeQuarantine,
          rng: ref HmacDrbgContext,
          getBeaconTime: GetBeaconTimeFn,
          taskpool: Taskpool
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
    executionPayloadBidPool: executionPayloadBidPool,
    payloadAttestationPool: payloadAttestationPool,
    quarantine: quarantine,
    blobQuarantine: blobQuarantine,
    dataColumnQuarantine: dataColumnQuarantine,
    gloasColumnQuarantine: gloasColumnQuarantine,
    envelopeQuarantine: envelopeQuarantine,
    getCurrentBeaconTime: getBeaconTime,
    batchCrypto: BatchCrypto.new(
      rng, dag.cfg.timeParams,
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
  const consensusFork = typeof(signedBlock).kind

  let
    wallTime = self.getCurrentBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot(self.dag.timeParams)

  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)
    signature = shortLog(signedBlock.signature)
    wallSlot

  if not afterGenesis:
    notice "Block before genesis"
    return errIgnore("Block before genesis")

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime -
    signedBlock.message.slot.start_beacon_time(self.dag.timeParams)

  # Start of block processing - in reality, we have already gone through SSZ
  # decoding at this stage, which may be significant
  debug "Block received", delay

  self.dag.validateBeaconBlock(self.quarantine, signedBlock, wallTime, {}).isOkOr:
    debug "Dropping block", err = error

    self.blockProcessor[].dumpInvalidBlock(signedBlock)

    beacon_blocks_dropped.inc(1, [$error[0]])
    return err(error)

  # Block passed validation - enqueue it for processing. The block processing
  # queue is effectively unbounded as we use a freestanding task to enqueue
  # the block - this is done so that when blocks arrive concurrently with
  # sync, we don't lose the gossip blocks, but also don't block the gossip
  # propagation of seemingly good blocks
  trace "Block validated"

  if not (isNil(self.dag.onBlockGossipAdded)):
    self.dag.onBlockGossipAdded(ForkedSignedBeaconBlock.init(signedBlock))

  when consensusFork >= ConsensusFork.Gloas:
    # Disable processing sidecars at block time.
    const sidecarsOpt = noSidecars
  elif consensusFork == ConsensusFork.Fulu:
    let sidecarsOpt =
      if len(signedBlock.message.body.blob_kzg_commitments) == 0:
        Opt.some(default(fulu.DataColumnSidecars))
      else:
        self.dataColumnQuarantine[].popSidecars(signedBlock.root)
    if sidecarsOpt.isNone():
      discard self.quarantine[].addSidecarless(self.dag.finalizedHead.slot, signedBlock)
      return ok()
  elif consensusFork in ConsensusFork.Deneb .. ConsensusFork.Electra:
    let sidecarsOpt = self.blobQuarantine[].popSidecars(signedBlock.root, signedBlock)
    if sidecarsOpt.isNone():
      self.quarantine[].addSidecarless(signedBlock)
      return ok()
  elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Capella:
    const sidecarsOpt = noSidecars
  else:
    {.error: "Unknown fork " & $consensusFork.}

  let validationDur = nanoseconds((self.getCurrentBeaconTime() - wallTime).nanoseconds)
  self.blockProcessor.enqueueBlock(
    src, signedBlock, sidecarsOpt, maybeFinalized, validationDur
  )

  # Validator monitor registration for blocks is done by the processor
  beacon_blocks_received.inc()
  beacon_block_delay.observe(delay.toFloatSeconds())

  ok()

proc processExecutionPayloadEnvelope*(
    self: var Eth2Processor, src: MsgSource,
    signedEnvelope: SignedExecutionPayloadEnvelope): ValidationRes =
  let
    wallTime = self.getCurrentBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot(self.dag.timeParams)

  logScope:
    blockRoot = shortLog(signedEnvelope.message.beacon_block_root)
    envelope = shortLog(signedEnvelope.message)
    wallSlot

  if not afterGenesis:
    notice "Execution payload envelope before genesis"
    return errIgnore("Execution payload envelope before genesis")

  let delay = wallTime -
    signedEnvelope.message.slot.start_beacon_time(self.dag.timeParams)

  debug "Envelope received", delay

  self.dag.validateExecutionPayload(
      self.quarantine, self.envelopeQuarantine, signedEnvelope).isOkOr:
    debug "Dropping envelope", err = error
    execution_payload_envelopes_dropped.inc(1, [$error[0]])
    return err(error)

  trace "Envelope validated"
  self.envelopeQuarantine[].addOrphan(signedEnvelope)
  self.blockProcessor.enqueuePayload(signedEnvelope.message.beacon_block_root)

  execution_payload_envelopes_received.inc()
  execution_payload_envelope_delay.observe(delay.toFloatSeconds())

  ok()

proc processBlobSidecar*(
    self: var Eth2Processor, src: MsgSource,
    blobSidecar: deneb.BlobSidecar, subnet_id: BlobId): ValidationRes =
  template block_header: untyped = blobSidecar.signed_block_header.message

  let
    wallTime = self.getCurrentBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot(self.dag.timeParams)

  logScope:
    blob = shortLog(blobSidecar)
    wallSlot

  if not afterGenesis:
    notice "Blob before genesis"
    return errIgnore("Blob before genesis")

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime -
    block_header.slot.start_beacon_time(self.dag.timeParams)
  debug "Blob received", delay

  let v =
    self.dag.validateBlobSidecar(self.quarantine, self.blobQuarantine,
                                 blobSidecar, wallTime, subnet_id)

  if v.isErr():
    debug "Dropping blob", error = v.error()
    blob_sidecars_dropped.inc(1, [$v.error[0]])
    return v

  let block_root = hash_tree_root(block_header)
  debug "Blob validated, putting in blob quarantine"
  self.blobQuarantine[].put(block_root, newClone(blobSidecar))

  if (let o = self.quarantine[].popSidecarless(block_root); o.isSome):
    withBlck(o[]):
      when consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
        let bres = self.blobQuarantine[].popSidecars(block_root, forkyBlck)
        if bres.isSome():
          self.blockProcessor.enqueueBlock(MsgSource.gossip, forkyBlck, bres)
        else:
          self.quarantine[].addSidecarless(forkyBlck)
      else:
        raiseAssert "Wrong fork for blob: " & $consensusFork

  blob_sidecars_received.inc()
  blob_sidecar_delay.observe(delay.toFloatSeconds())

  v

proc processDataColumnSidecar*(
    self: var Eth2Processor, src: MsgSource,
    dataColumnSidecar: fulu.DataColumnSidecar,
    subnet_id: uint64): ValidationRes =
  template block_header: untyped = dataColumnSidecar.signed_block_header.message

  let
    wallTime = self.getCurrentBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot(self.dag.timeParams)

  logScope:
    dcs = shortLog(dataColumnSidecar)
    wallSlot

  if not afterGenesis:
    notice "Data column before genesis"
    return errIgnore("Data column before genesis")

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime -
    block_header.slot.start_beacon_time(self.dag.timeParams)
  debug "Data column received", delay

  let
    validationStart = Moment.now()
    v =
      self.dag.validateDataColumnSidecar(self.quarantine, self.dataColumnQuarantine,
                                         dataColumnSidecar, wallTime, subnet_id)

  data_column_sidecar_validation_duration.observe(
    (Moment.now() - validationStart).toFloatSeconds())

  if v.isErr():
    debug "Dropping data column", error = v.error()
    data_column_sidecars_dropped.inc(1, [$v.error[0]])
    return v

  let block_root = hash_tree_root(block_header)

  debug "Data column validated, putting data column in quarantine"
  self.dataColumnQuarantine[].put(block_root, newClone(dataColumnSidecar))

  if block_root in self.quarantine[].sidecarless:
    let cres = self.dataColumnQuarantine[].popSidecars(block_root)
    if cres.isSome():
      let blck = self.quarantine[].popSidecarless(block_root).expect("checked above")
      withBlck(blck):
        when (consensusFork >= ConsensusFork.Fulu) and
          (consensusFork < ConsensusFork.Gloas):
          self.blockProcessor.enqueueBlock(MsgSource.gossip, forkyBlck, cres)
        else:
          raiseAssert "Wrong fork for columns: " & $consensusFork

  data_column_sidecars_received.inc()
  data_column_sidecar_delay.observe(delay.toFloatSeconds())

  v

proc processDataColumnSidecar*(
    self: var Eth2Processor, src: MsgSource,
    dataColumnSidecar: gloas.DataColumnSidecar,
    subnet_id: uint64): ValidationRes =
  let
    wallTime = self.getCurrentBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot(self.dag.timeParams)

  logScope:
    dcs = shortLog(dataColumnSidecar)
    wallSlot

  if not afterGenesis:
    notice "Data column before genesis"
    return errIgnore("Data column before genesis")

  debug "Data column received (Gloas - quarantine not implemented)"

  let v = self.dag.validateDataColumnSidecar(
    self.quarantine, self.gloasColumnQuarantine, self.executionPayloadBidPool,
    dataColumnSidecar, wallTime, subnet_id)

  if v.isErr():
    debug "Dropping data column", error = v.error()
    data_column_sidecars_dropped.inc(1, [$v.error[0]])
    return v

  debug "Data column validated"
  self.gloasColumnQuarantine[].put(
    dataColumnSidecar.beacon_block_root, newClone(dataColumnSidecar))
  self.blockProcessor.enqueuePayload(dataColumnSidecar.beacon_block_root)

  data_column_sidecars_received.inc()
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

func clearDoppelgangerProtection*(self: var Eth2Processor) =
  self.doppelgangerDetection.broadcastStartEpoch = FAR_FUTURE_EPOCH

proc checkForPotentialDoppelganger(
    self: var Eth2Processor,
    attestation: phase0.Attestation | electra.Attestation | SingleAttestation,
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

proc processAttestation*(
    self: ref Eth2Processor,
    src: MsgSource,
    attestation: SingleAttestation,
    subnet_id: SubnetId,
    checkSignature, checkValidator: bool,
): Future[ValidationRes] {.async: (raises: [CancelledError]).} =
  var wallTime = self.getCurrentBeaconTime()
  let (afterGenesis, wallSlot) = wallTime.toSlot(self.dag.timeParams)

  logScope:
    attestation = shortLog(attestation)
    subnet_id
    wallSlot

  if not afterGenesis:
    notice "Attestation before genesis"
    return errIgnore("Attestation before genesis")

  # Potential under/overflows are fine; would just create odd metrics and logs
  let
    consensusFork =
      self.dag.cfg.consensusForkAtEpoch(attestation.data.slot.epoch)
    delay = wallTime - attestation.data.slot.attestation_deadline(
      self.dag.timeParams, consensusFork)
  debug "SingleAttestation received", delay

  let v = (
    await self.attestationPool.validateAttestation(
      self.batchCrypto, self.envelopeQuarantine, attestation,
      wallTime, subnet_id, checkSignature
    )
  ).valueOr:
    debug "Dropping attestation", reason = $error
    beacon_attestations_dropped.inc(1, [$error[0]])
    return err(error)

  # Due to async validation the wallTime here might have changed
  wallTime = self.getCurrentBeaconTime()

  if checkValidator and (v.attester_index in self.validatorPool[]):
    warn "A validator client has attempted to send an attestation from " &
      "validator that is also managed by the beacon node",
      validator_index = v.attester_index
    return errReject(
      "An attestation could not be sent from a validator that is " &
        "also managed by the beacon node"
    )

  self[].checkForPotentialDoppelganger(attestation, [v.attester_index])

  trace "SingleAttestation validated"
  let attesting_indices = [v.attester_index]
  self.attestationPool[].addAttestation(
    attestation, attesting_indices, v.beacon_committee_len, v.index_in_committee, v.sig,
    wallTime,
  )

  self.validatorMonitor[].registerAttestation(
    src, wallTime, attestation, v.attester_index
  )

  beacon_attestations_received.inc()
  beacon_attestation_delay.observe(delay.toFloatSeconds())

  ok()

proc processSignedAggregateAndProof*(
    self: ref Eth2Processor,
    src: MsgSource,
    signedAggregateAndProof: electra.SignedAggregateAndProof,
    checkSignature = true,
    checkCover = true,
): Future[ValidationRes] {.async: (raises: [CancelledError]).} =
  var wallTime = self.getCurrentBeaconTime()
  let (afterGenesis, wallSlot) = wallTime.toSlot(self.dag.timeParams)

  logScope:
    aggregator_index = signedAggregateAndProof.message.aggregator_index
    selection_proof = shortLog(signedAggregateAndProof.message.selection_proof)
    signature = shortLog(signedAggregateAndProof.signature)
    wallSlot

  if not afterGenesis:
    notice "Aggregate before genesis"
    return errIgnore("Aggregate before genesis")

  template aggregate(): untyped =
    signedAggregateAndProof.message.aggregate

  # Potential under/overflows are fine; would just create odd logs
  let
    slot = aggregate.data.slot
    consensusFork = self.dag.cfg.consensusForkAtEpoch(slot.epoch)
    delay = wallTime - slot.aggregate_deadline(self.dag.timeParams, consensusFork)

  debug "Aggregate received",
    delay, aggregate = shortLog(signedAggregateAndProof.message.aggregate)

  let v = (
    await self.attestationPool.validateAggregate(
      self.batchCrypto,
      self.envelopeQuarantine,
      signedAggregateAndProof,
      wallTime,
      checkSignature = checkSignature,
      checkCover = checkCover,
    )
  ).valueOr:
    debug "Dropping aggregate", reason = $error
    beacon_aggregates_dropped.inc(1, [$error[0]])

    return err(error)

  # Due to async validation the wallTime here might have changed
  wallTime = self.getCurrentBeaconTime()

  self[].checkForPotentialDoppelganger(aggregate, v.attesting_indices)

  trace "Aggregate validated"

  # -1 here is the notional index in committee for which the attestation pool
  # only requires external input regarding SingleAttestation messages.
  self.attestationPool[].addAttestation(
    aggregate, v.attesting_indices, aggregate.aggregation_bits.len, -1, v.sig, wallTime
  )

  self.validatorMonitor[].registerAggregate(
    src, wallTime, signedAggregateAndProof.message, v.attesting_indices
  )

  beacon_aggregates_received.inc()
  beacon_aggregate_delay.observe(delay.toFloatSeconds())

  ok()

proc processBlsToExecutionChange*(
    self: ref Eth2Processor, src: MsgSource,
    blsToExecutionChange: SignedBLSToExecutionChange):
    Future[ValidationRes] {.async: (raises: [CancelledError]).} =
  let
    wallTime = self.getCurrentBeaconTime()
    wallSlot = wallTime.slotOrZero(self.dag.timeParams)

  logScope:
    blsToExecutionChange = shortLog(blsToExecutionChange)
    wallSlot

  debug "BLS to execution change received"

  let v = await self.validatorChangePool[].validateBlsToExecutionChange(
    self.batchCrypto, blsToExecutionChange, wallSlot.epoch)

  if v.isOk():
    trace "BLS to execution change validated"
    # Prioritize API-provided messages
    self.validatorChangePool[].addMessage(
      blsToExecutionChange, src == MsgSource.api)
  else:
    debug "Dropping BLS to execution change", reason = $v.error
    beacon_attester_slashings_dropped.inc(1, [$v.error[0]])

  return v

proc checkKnownValidatorSlashing(
    self: var Eth2Processor,
    msg: ProposerSlashing | phase0.AttesterSlashing | electra.AttesterSlashing) =
  for idx in getValidatorIndices(msg):
    let i = ValidatorIndex.init(idx).valueOr:
      continue
    if self.blockProcessor[].consensusManager[].actionTracker.knownValidators.hasKey(i):
      quitSlashing()

proc processAttesterSlashing*(
    self: var Eth2Processor, src: MsgSource,
    attesterSlashing: electra.AttesterSlashing):
    ValidationRes =
  logScope:
    attesterSlashing = shortLog(attesterSlashing)

  debug "Attester slashing received"

  let v = self.validatorChangePool[].validateAttesterSlashing(attesterSlashing)

  if v.isOk():
    trace "Attester slashing validated"

    self.checkKnownValidatorSlashing(attesterSlashing)

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

    self.checkKnownValidatorSlashing(proposerSlashing)

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
    checkSignature: bool = true
): Future[Result[void, ValidationError]] {.async: (raises: [CancelledError]).} =
  let
    wallTime = self.getCurrentBeaconTime()
    wallSlot = wallTime.slotOrZero(self.dag.timeParams)
    consensusFork =
      self.dag.cfg.consensusForkAtEpoch(syncCommitteeMsg.slot.epoch)

  logScope:
    syncCommitteeMsg = shortLog(syncCommitteeMsg)
    subcommitteeIdx
    wallSlot

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime -
    syncCommitteeMsg.slot.sync_committee_message_deadline(
      self.dag.timeParams, consensusFork)
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
    checkSignature: bool = true
): Future[Result[void, ValidationError]] {.async: (raises: [CancelledError]).} =
  let
    wallTime = self.getCurrentBeaconTime()
    wallSlot = wallTime.slotOrZero(self.dag.timeParams)

  logScope:
    signature = shortLog(contributionAndProof.signature)
    aggregator_index = contributionAndProof.message.aggregator_index
    selection_proof = contributionAndProof.message.selection_proof
    wallSlot

  # Potential under/overflows are fine; would just create odd metrics and logs
  let
    slot = contributionAndProof.message.contribution.slot
    consensusFork = self.dag.cfg.consensusForkAtEpoch(slot.epoch)
    delay = wallTime - slot.sync_contribution_deadline(
      self.dag.timeParams, consensusFork)
  debug "Contribution received",
    delay, contribution = shortLog(contributionAndProof.message.contribution)

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
    self: var Eth2Processor, finality_update: ForkedLightClientFinalityUpdate
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
    self: var Eth2Processor,
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

proc processExecutionPayloadBid*(
    self: var Eth2Processor, signedBid: gloas.SignedExecutionPayloadBid
): ValidationRes =
  let wallTime = self.getCurrentBeaconTime()

  logScope:
    bidSlot = signedBid.message.slot
    builderIndex = signedBid.message.builder_index
    blockRoot = signedBid.message.parent_block_root

  let v = validateExecutionPayloadBid(
    self.dag, self.executionPayloadBidPool, signedBid, wallTime)
  if v.isOk():
    debug "Execution payload bid validated"
    self.executionPayloadBidPool[].addBid(signedBid, wallTime)
    beacon_execution_payload_bids_received.inc()
    ok()
  else:
    debug "Dropping execution payload bid", reason = $v.error
    beacon_execution_payload_bids_dropped.inc(1, [$v.error[0]])
    err(v.error())

proc processPayloadAttestationMessage*(
    self: ref Eth2Processor,
    payload_attestation_message: PayloadAttestationMessage,
    checkSignature, checkValidator: bool
): Future[ValidationRes] {.async: (raises: [CancelledError]).} =
  let
    wallTime = self.getCurrentBeaconTime()
    v = await validatePayloadAttestationMessage(
      self.dag, self.payloadAttestationPool, self.batchCrypto,
      payload_attestation_message, wallTime, checkSignature)

  if v.isErr():
    debug "Dropping payload attestation", reason = $v.error
    return err(v.error())

  discard self.payloadAttestationPool[].addPayloadAttestation(
    payload_attestation_message, wallTime)

  trace "Payload attestation validated"
  return ok()
