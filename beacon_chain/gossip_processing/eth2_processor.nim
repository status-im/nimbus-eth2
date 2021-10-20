# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/tables,
  stew/results,
  chronicles, chronos, metrics,
  ../spec/[helpers, forks],
  ../spec/datatypes/[altair, phase0],
  ../consensus_object_pools/[
    block_clearance, blockchain_dag, exit_pool, attestation_pool,
    sync_committee_msg_pool],
  ../validators/validator_pool,
  ../beacon_clock,
  "."/[gossip_validation, block_processor, batch_validation]


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

const delayBuckets = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, Inf]

declareHistogram beacon_attestation_delay,
  "Time(s) between slot start and attestation reception", buckets = delayBuckets

declareHistogram beacon_aggregate_delay,
  "Time(s) between slot start and aggregate reception", buckets = delayBuckets

declareHistogram beacon_block_delay,
  "Time(s) between slot start and beacon block reception", buckets = delayBuckets

type
  DoppelgangerProtection = object
    broadcastStartEpoch*: Epoch  ##\
    ## Set anew, each time gossip is re-enabled after syncing completes, so
    ## might reset multiple times per instance. This allows some safe level
    ## of gossip interleaving between nodes so long as they don't gossip at
    ## the same time.

    nodeLaunchSlot: Slot ##\
    ## Set once, at node launch. This functions as a basic protection against
    ## false positives from attestations persisting within the gossip network
    ## across quick restarts.

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
    doppelGangerDetectionEnabled*: bool

    # Local sources of truth for validation
    # ----------------------------------------------------------------
    dag*: ChainDAGRef
    attestationPool*: ref AttestationPool
    validatorPool: ref ValidatorPool
    syncCommitteeMsgPool: ref SyncCommitteeMsgPool

    doppelgangerDetection*: DoppelgangerProtection

    # Gossip validated -> enqueue for further verification
    # ----------------------------------------------------------------
    blockProcessor: ref BlockProcessor

    # Validated with no further verification required
    # ----------------------------------------------------------------
    exitPool: ref ExitPool

    # Almost validated, pending cryptographic signature check
    # ----------------------------------------------------------------
    batchCrypto*: ref BatchCrypto

    # Missing information
    # ----------------------------------------------------------------
    quarantine*: QuarantineRef

    # Application-provided current time provider (to facilitate testing)
    getCurrentBeaconTime*: GetBeaconTimeFn

# Initialization
# ------------------------------------------------------------------------------

proc new*(T: type Eth2Processor,
          doppelGangerDetectionEnabled: bool,
          blockProcessor: ref BlockProcessor,
          dag: ChainDAGRef,
          attestationPool: ref AttestationPool,
          exitPool: ref ExitPool,
          validatorPool: ref ValidatorPool,
          syncCommitteeMsgPool: ref SyncCommitteeMsgPool,
          quarantine: QuarantineRef,
          rng: ref BrHmacDrbgContext,
          getBeaconTime: GetBeaconTimeFn,
          taskpool: batch_validation.TaskPoolPtr
         ): ref Eth2Processor =
  (ref Eth2Processor)(
    doppelGangerDetectionEnabled: doppelGangerDetectionEnabled,
    doppelgangerDetection: DoppelgangerProtection(
      nodeLaunchSlot: getBeaconTime().slotOrZero),
    blockProcessor: blockProcessor,
    dag: dag,
    attestationPool: attestationPool,
    exitPool: exitPool,
    validatorPool: validatorPool,
    syncCommitteeMsgPool: syncCommitteeMsgPool,
    quarantine: quarantine,
    getCurrentBeaconTime: getBeaconTime,
    batchCrypto: BatchCrypto.new(
      rng = rng,
      # Only run eager attestation signature verification if we're not
      # processing blocks in order to give priority to block processing
      eager = proc(): bool = not blockProcessor[].hasBlocks(),
      taskpool)
  )

# Gossip Management
# -----------------------------------------------------------------------------------

proc blockValidator*(
    self: var Eth2Processor,
    signedBlock: phase0.SignedBeaconBlock | altair.SignedBeaconBlock): ValidationResult =
  logScope:
    signedBlock = shortLog(signedBlock.message)
    blockRoot = shortLog(signedBlock.root)

  let
    wallTime = self.getCurrentBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    return ValidationResult.Ignore  # not an issue with block, so don't penalize

  logScope: wallSlot

  let delay = wallTime - signedBlock.message.slot.toBeaconTime

  if signedBlock.root in self.dag:
    # The gossip algorithm itself already does one round of hashing to find
    # already-seen data, but it is fairly aggressive about forgetting about
    # what it has seen already
    debug "Dropping already-seen gossip block", delay
    return ValidationResult.Ignore  # "[IGNORE] The block is the first block ..."

  # Start of block processing - in reality, we have already gone through SSZ
  # decoding at this stage, which may be significant
  debug "Block received", delay

  let v = self.dag.isValidBeaconBlock(
    self.quarantine, signedBlock, wallTime, {})

  if v.isErr:
    self.blockProcessor[].dumpBlock(signedBlock, v)
    beacon_blocks_dropped.inc(1, [$v.error[0]])
    return v.error[0]

  # Block passed validation - enqueue it for processing. The block processing
  # queue is effectively unbounded as we use a freestanding task to enqueue
  # the block - this is done so that when blocks arrive concurrently with
  # sync, we don't lose the gossip blocks, but also don't block the gossip
  # propagation of seemingly good blocks
  trace "Block validated"

  self.blockProcessor[].addBlock(
    ForkedSignedBeaconBlock.init(signedBlock),
    validationDur = self.getCurrentBeaconTime() - wallTime)

  # Validator monitor registration for blocks is done by the processor
  beacon_blocks_received.inc()
  beacon_block_delay.observe(delay.toFloatSeconds())

  ValidationResult.Accept

proc checkForPotentialDoppelganger(
    self: var Eth2Processor, attestation: Attestation,
    attesterIndices: openArray[ValidatorIndex]) =
  # Only check for attestations after node launch. There might be one slot of
  # overlap in quick intra-slot restarts so trade off a few true negatives in
  # the service of avoiding more likely false positives.
  if attestation.data.slot <= self.doppelgangerDetection.nodeLaunchSlot + 1:
    return

  if attestation.data.slot.epoch <
      self.doppelgangerDetection.broadcastStartEpoch:
    let tgtBlck = self.dag.getRef(attestation.data.target.root)
    doAssert not tgtBlck.isNil  # because attestation is valid above

    let epochRef = self.dag.getEpochRef(
      tgtBlck, attestation.data.target.epoch)
    for validatorIndex in attesterIndices:
      let validatorPubkey = epochRef.validatorKey(validatorIndex).get().toPubKey()
      if  self.doppelgangerDetectionEnabled and
          self.validatorPool[].getValidator(validatorPubkey) !=
            default(AttachedValidator):
        warn "We believe you are currently running another instance of the same validator. We've disconnected you from the network as this presents a significant slashing risk. Possible next steps are (a) making sure you've disconnected your validator from your old machine before restarting the client; and (b) running the client again with the gossip-slashing-protection option disabled, only if you are absolutely sure this is the only instance of your validator running, and reporting the issue at https://github.com/status-im/nimbus-eth2/issues.",
          validatorIndex,
          validatorPubkey,
          attestation = shortLog(attestation)
        quit QuitFailure

proc attestationValidator*(
    self: ref Eth2Processor,
    attestation: Attestation,
    subnet_id: SubnetId,
    checkSignature: bool = true): Future[ValidationResult] {.async.} =
  logScope:
    attestation = shortLog(attestation)
    subnet_id

  let wallTime = self.getCurrentBeaconTime()
  var (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    notice "Attestation before genesis"
    return ValidationResult.Ignore

  logScope: wallSlot

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - attestation.data.slot.toBeaconTime
  debug "Attestation received", delay

  # Now proceed to validation
  let v = await self.attestationPool.validateAttestation(
      self.batchCrypto, attestation, wallTime, subnet_id, checkSignature)
  if v.isErr():
    debug "Dropping attestation", validationError = v.error
    beacon_attestations_dropped.inc(1, [$v.error[0]])
    return v.error[0]

  # Due to async validation the wallSlot here might have changed
  (afterGenesis, wallSlot) = self.getCurrentBeaconTime().toSlot()

  let (attester_index, sig) = v.get()

  self[].checkForPotentialDoppelganger(attestation, [attester_index])

  trace "Attestation validated"
  self.attestationPool[].addAttestation(
    attestation, [attester_index], sig, wallSlot)

  beacon_attestations_received.inc()
  beacon_attestation_delay.observe(delay.toFloatSeconds())

  return ValidationResult.Accept

proc aggregateValidator*(
    self: ref Eth2Processor,
    signedAggregateAndProof: SignedAggregateAndProof): Future[ValidationResult] {.async.} =
  logScope:
    aggregate = shortLog(signedAggregateAndProof.message.aggregate)
    signature = shortLog(signedAggregateAndProof.signature)

  let wallTime = self.getCurrentBeaconTime()
  var (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    notice "Aggregate before genesis"
    return ValidationResult.Ignore

  logScope: wallSlot

  # Potential under/overflows are fine; would just create odd logs
  let delay =
    wallTime - signedAggregateAndProof.message.aggregate.data.slot.toBeaconTime
  debug "Aggregate received", delay

  let v = await self.attestationPool.validateAggregate(
      self.batchCrypto,
      signedAggregateAndProof, wallTime)
  if v.isErr:
    debug "Dropping aggregate",
      validationError = v.error,
      aggregator_index = signedAggregateAndProof.message.aggregator_index,
      selection_proof = signedAggregateAndProof.message.selection_proof,
      wallSlot
    beacon_aggregates_dropped.inc(1, [$v.error[0]])
    return v.error[0]

  # Due to async validation the wallSlot here might have changed
  (afterGenesis, wallSlot) = self.getCurrentBeaconTime().toSlot()

  let (attesting_indices, sig) = v.get()

  self[].checkForPotentialDoppelganger(
    signedAggregateAndProof.message.aggregate, attesting_indices)

  trace "Aggregate validated",
    aggregator_index = signedAggregateAndProof.message.aggregator_index,
    selection_proof = signedAggregateAndProof.message.selection_proof

  self.attestationPool[].addAttestation(
    signedAggregateAndProof.message.aggregate, attesting_indices, sig, wallSlot)

  beacon_aggregates_received.inc()
  beacon_aggregate_delay.observe(delay.toFloatSeconds())

  return ValidationResult.Accept

proc attesterSlashingValidator*(
    self: var Eth2Processor, attesterSlashing: AttesterSlashing):
    ValidationResult =
  logScope:
    attesterSlashing = shortLog(attesterSlashing)

  let v = self.exitPool[].validateAttesterSlashing(attesterSlashing)
  if v.isErr:
    debug "Dropping attester slashing", validationError = v.error
    beacon_attester_slashings_dropped.inc(1, [$v.error[0]])
    return v.error[0]

  beacon_attester_slashings_received.inc()

  ValidationResult.Accept

proc proposerSlashingValidator*(
    self: var Eth2Processor, proposerSlashing: ProposerSlashing):
    ValidationResult =
  logScope:
    proposerSlashing = shortLog(proposerSlashing)

  let v = self.exitPool[].validateProposerSlashing(proposerSlashing)
  if v.isErr:
    debug "Dropping proposer slashing", validationError = v.error
    beacon_proposer_slashings_dropped.inc(1, [$v.error[0]])
    return v.error[0]

  beacon_proposer_slashings_received.inc()

  ValidationResult.Accept

proc voluntaryExitValidator*(
    self: var Eth2Processor, signedVoluntaryExit: SignedVoluntaryExit):
    ValidationResult =
  logScope:
    signedVoluntaryExit = shortLog(signedVoluntaryExit)

  let v = self.exitPool[].validateVoluntaryExit(signedVoluntaryExit)
  if v.isErr:
    debug "Dropping voluntary exit", validationError = v.error
    beacon_voluntary_exits_dropped.inc(1, [$v.error[0]])
    return v.error[0]

  beacon_voluntary_exits_received.inc()

  ValidationResult.Accept

proc syncCommitteeMsgValidator*(
    self: ref Eth2Processor,
    syncCommitteeMsg: SyncCommitteeMessage,
    committeeIdx: SyncSubcommitteeIndex,
    checkSignature: bool = true): ValidationResult =
  logScope:
    syncCommitteeMsg = shortLog(syncCommitteeMsg)
    committeeIdx

  let wallTime = self.getCurrentBeaconTime()

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - syncCommitteeMsg.slot.toBeaconTime
  debug "Sync committee message received", delay

  # Now proceed to validation
  let v = validateSyncCommitteeMessage(self.dag, self.syncCommitteeMsgPool,
                                       syncCommitteeMsg, committeeIdx, wallTime,
                                       checkSignature)
  if v.isErr:
    debug "Dropping sync committee message", validationError = v.error
    beacon_sync_committee_messages_dropped.inc(1, [$v.error[0]])
    return v.error[0]

  trace "Sync committee message validated"

  beacon_sync_committee_messages_received.inc()

  ValidationResult.Accept

proc syncCommitteeContributionValidator*(
    self: ref Eth2Processor,
    contributionAndProof: SignedContributionAndProof,
    checkSignature: bool = true): ValidationResult =
  logScope:
    contributionAndProof = shortLog(contributionAndProof.message.contribution)
    signature = shortLog(contributionAndProof.signature)
    aggregator_index = contributionAndProof.message.aggregator_index

  let wallTime = self.getCurrentBeaconTime()

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - contributionAndProof.message.contribution.slot.toBeaconTime
  debug "Contribution received", delay

  # Now proceed to validation
  let v = validateSignedContributionAndProof(self.dag, self.syncCommitteeMsgPool,
                                             contributionAndProof, wallTime,
                                             checkSignature)
  if v.isErr():
    let (_, wallSlot) = wallTime.toSlot()
    debug "Dropping contribution",
          validationError = v.error,
          selection_proof = contributionAndProof.message.selection_proof,
          wallSlot
    beacon_sync_committee_contributions_dropped.inc(1, [$v.error[0]])
    return v.error[0]

  beacon_sync_committee_contributions_received.inc()

  ValidationResult.Accept
