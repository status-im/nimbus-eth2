# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles, chronos,
  ../spec/datatypes/base,
  ../spec/beaconstate,
  ../consensus_object_pools/[blockchain_dag, block_quarantine, attestation_pool],
  ../el/el_manager,
  ../beacon_clock,
  ./common_tools

from ../spec/eth2_apis/dynamic_fee_recipients import
  DynamicFeeRecipientsStore, getDynamicFeeRecipient
from ../validators/action_tracker import ActionTracker, getNextProposalSlot

logScope: topics = "cman"

type
  ConsensusManager* = object
    expectedSlot: Slot
    expectedBlockReceived: Future[bool].Raising([CancelledError])

    # Validated & Verified
    # ----------------------------------------------------------------
    dag*: ChainDAGRef
    attestationPool*: ref AttestationPool

    # Missing info
    # ----------------------------------------------------------------
    quarantine*: ref Quarantine

    # Execution layer integration
    # ----------------------------------------------------------------
    elManager*: ELManager

    # Allow determination of whether there's an upcoming proposal
    # ----------------------------------------------------------------
    actionTracker*: ActionTracker

    # Allow determination of preferred fee recipient during proposals
    # ----------------------------------------------------------------
    dynamicFeeRecipientsStore: ref DynamicFeeRecipientsStore
    validatorsDir: string
    defaultFeeRecipient: Opt[Eth1Address]
    defaultGasLimit: uint64

    # Tracking last proposal forkchoiceUpdated payload information
    # ----------------------------------------------------------------
    optimisticHead: tuple[bid: BlockId, execution_block_hash: Eth2Digest]
    optimisticHeadStatus: OptimisticStatus
      ## forkchoiceUpdated response about the optimistic head

    forkchoiceInflight: bool
      ## True when there's an async `forkchoiceUpdated` in flight

# Initialization
# ------------------------------------------------------------------------------

func new*(T: type ConsensusManager,
          dag: ChainDAGRef,
          attestationPool: ref AttestationPool,
          quarantine: ref Quarantine,
          elManager: ELManager,
          actionTracker: ActionTracker,
          dynamicFeeRecipientsStore: ref DynamicFeeRecipientsStore,
          validatorsDir: string,
          defaultFeeRecipient: Opt[Eth1Address],
          defaultGasLimit: uint64
         ): ref ConsensusManager =
  (ref ConsensusManager)(
    dag: dag,
    attestationPool: attestationPool,
    quarantine: quarantine,
    elManager: elManager,
    actionTracker: actionTracker,
    dynamicFeeRecipientsStore: dynamicFeeRecipientsStore,
    validatorsDir: validatorsDir,
    defaultFeeRecipient: defaultFeeRecipient,
    defaultGasLimit: defaultGasLimit
  )

# Consensus Management
# -----------------------------------------------------------------------------------

func to*(v: PayloadExecutionStatus, T: type OptimisticStatus): T =
  case v
  of PayloadExecutionStatus.valid:
    OptimisticStatus.valid
  of PayloadExecutionStatus.syncing, PayloadExecutionStatus.accepted:
    OptimisticStatus.notValidated
  of invalid, invalid_block_hash:
    OptimisticStatus.invalidated

proc checkExpectedBlock(self: var ConsensusManager) =
  if self.expectedBlockReceived == nil:
    return

  if self.dag.head.slot < self.expectedSlot or not self.dag.head.executionValid:
    # Don't trigger `expectBlock` if the head is optimistic - this gives the
    # `forkchoiceUpdated` call time to maybe update the optimistic status before
    # it's time to validate
    return

  self.expectedBlockReceived.complete(true)
  self.expectedBlockReceived = nil # Don't keep completed futures around!

proc expectBlock*(self: var ConsensusManager, expectedSlot: Slot): Future[bool]
    {.async: (raises: [CancelledError], raw: true).} =
  ## Return a future that will complete when a head is selected whose slot is
  ## equal or greater than the given slot, or a new expectation is created
  if self.expectedBlockReceived != nil:
    # Reset the old future to not leave it hanging.. an alternative would be to
    # cancel it, but it doesn't make any practical difference for now
    self.expectedBlockReceived.complete(false)

  let fut = newFuture[bool]("ConsensusManager.expectBlock")
  self.expectedSlot = expectedSlot
  self.expectedBlockReceived = fut

  # It might happen that by the time we're expecting a block, it might have
  # already been processed!
  self.checkExpectedBlock()

  return fut

func shouldSyncOptimistically*(
    optimisticSlot, dagSlot, wallSlot: Slot): bool =
  ## Determine whether an optimistic execution block hash should be reported
  ## to the EL client instead of the current head as determined by fork choice.

  # Check whether optimistic head is sufficiently ahead of DAG
  const minProgress = 8 * SLOTS_PER_EPOCH  # Set arbitrarily
  if optimisticSlot < dagSlot or optimisticSlot - dagSlot < minProgress:
    return false

  # Check whether optimistic head has synced sufficiently close to wall slot
  const maxAge = 2 * SLOTS_PER_EPOCH  # Set arbitrarily
  if optimisticSlot < max(wallSlot, maxAge.Slot) - maxAge:
    return false

  true

func shouldSyncOptimistically*(self: ConsensusManager, wallSlot: Slot): bool =
  if self.optimisticHeadStatus == OptimisticStatus.invalidated or
      self.optimisticHead.execution_block_hash.isZero:
    return false

  shouldSyncOptimistically(
    optimisticSlot = self.optimisticHead.bid.slot,
    dagSlot = self.dag.headState.slot,
    wallSlot = wallSlot)

func optimisticHead*(self: ConsensusManager): BlockId =
  self.optimisticHead.bid

func optimisticExecutionBlockHash*(self: ConsensusManager): Eth2Digest =
  self.optimisticHead.execution_block_hash

proc setOptimisticHead*(
    self: var ConsensusManager,
    bid: BlockId, execution_block_hash: Eth2Digest) =
  if self.optimisticHeadStatus == OptimisticStatus.invalidated:
    # If the light client was wrong in the past, either the execution client or
    # the light client has been compromised and we shouldn't trust either until
    # a restart
    warn "Ignoring optimistic head update due to previous invalidity",
      bid, execution_block_hash
  else:
    let newHead = (bid: bid, execution_block_hash: execution_block_hash)
    if self.optimisticHead != newHead:
      self.optimisticHead = newHead
      self.optimisticHeadStatus = OptimisticStatus.notValidated

func getKnownValidatorsForBlsChangeTracking(
    self: ConsensusManager, newHead: BlockRef): seq[ValidatorIndex] =
  # Ensure that large nodes won't be overwhelmed by a nice-to-have, but
  # inessential cosmetic feature.
  const MAX_CHECKED_INDICES = 32

  var res = newSeqOfCap[ValidatorIndex](min(
    len(self.actionTracker.knownValidators), MAX_CHECKED_INDICES))
  for vi in self.actionTracker.knownValidators.keys():
    res.add vi
    if res.len >= MAX_CHECKED_INDICES:
      break
  res

proc updateHead(self: var ConsensusManager, newHead: BlockRef) =
  ## Trigger fork choice and update the DAG with the new head block
  ## This does not automatically prune the DAG after finalization
  ## `pruneFinalized` must be called for pruning.

  # Store the new head in the chain DAG - this may cause epochs to be
  # justified and finalized.
  # `willSelectNewHead` (part of `selectOptimisticHead`) required before this
  self.dag.updateHead(
    newHead, self.quarantine[],
    self.getKnownValidatorsForBlsChangeTracking(newHead))
  updateSafeBlockMetrics(
    self.attestationPool[].forkChoice.get_safe_beacon_block_id)
  self.checkExpectedBlock()

proc updateHead*(self: var ConsensusManager, wallSlot: Slot) =
  ## Trigger fork choice and update the DAG with the new head block
  ## This does not automatically prune the DAG after finalization
  ## `pruneFinalized` must be called for pruning.

  # Grab the new head according to our latest attestation data
  let
    wallTime = wallSlot.start_beacon_time(self.dag.timeParams)
    newHead = self.attestationPool[].selectOptimisticHead(wallTime).valueOr:
      warn "Head selection failed, using previous head",
        head = shortLog(self.dag.head), wallSlot
      return

  self.updateHead(newHead.blck)

func isSynced(dag: ChainDAGRef, wallSlot: Slot): bool =
  # This is a tweaked version of the beacon_validators isSynced. TODO, refactor
  # that one so this becomes the default version, with the same information to
  # work with. For the head slot, use the DAG head regardless of what head the
  # proposer forkchoiceUpdated is using, because by the beacon_validators might
  # be ready to actually propose, it's going to do so from the DAG head. Given
  # the defaultSyncHorizon, it will start triggering in time so that potential
  # discrepancies between the head here, and the head the DAG has (which might
  # not yet be updated) won't be visible.
  if dag.head.slot + dag.timeParams.defaultSyncHorizon < wallSlot:
    false
  else:
    dag.head.executionValid

proc checkNextProposer(
    dag: ChainDAGRef, actionTracker: ActionTracker,
    dynamicFeeRecipientsStore: ref DynamicFeeRecipientsStore,
    wallSlot: Slot):
    Opt[(ValidatorIndex, ValidatorPubKey)] =
  let nextWallSlot = wallSlot + 1

  # Avoid long rewinds during syncing, when it's not going to propose. Though
  # this is preparing for a proposal on `nextWallSlot`, it can't possibly yet
  # be on said slot, so still check just `wallSlot`.
  if not dag.isSynced(wallSlot):
    return Opt.none((ValidatorIndex, ValidatorPubKey))

  let proposer = ? dag.getProposer(dag.head, nextWallSlot)

  if  actionTracker.getNextProposalSlot(wallSlot) != nextWallSlot and
      dynamicFeeRecipientsStore[].getDynamicFeeRecipient(
        proposer, nextWallSlot.epoch).isNone:
    return Opt.none((ValidatorIndex, ValidatorPubKey))
  let proposerKey = dag.validatorKey(proposer).get().toPubKey
  Opt.some((proposer, proposerKey))

proc checkNextProposer*(self: ref ConsensusManager, wallSlot: Slot):
    Opt[(ValidatorIndex, ValidatorPubKey)] =
  self.dag.checkNextProposer(
    self.actionTracker, self.dynamicFeeRecipientsStore, wallSlot)

proc getFeeRecipient*(
    self: ConsensusManager, pubkey: ValidatorPubKey,
    validatorIdx: Opt[ValidatorIndex], epoch: Epoch): Eth1Address =

  let validator =
    if validatorIdx.isSome():
      withState(self.dag.headState):
        if validatorIdx.get < forkyState.data.validators.lenu64:
          Opt.some forkyState.data.validators.item(validatorIdx.get)
        else:
          Opt.none Validator
    else:
      Opt.none Validator

  getFeeRecipient(self.dynamicFeeRecipientsStore, pubkey, validatorIdx,
                  validator, self.defaultFeeRecipient, self.validatorsDir,
                  epoch)

proc getGasLimit*(self: ConsensusManager, pubkey: ValidatorPubKey): uint64 =
  getGasLimit(self.validatorsDir, self.defaultGasLimit, pubkey)

proc prepareNextSlot*(
    self: ref ConsensusManager, proposalSlot: Slot, deadline: DeadlineFuture
) {.async: (raises: [CancelledError]).} =
  ## Send a "warm-up" forkchoiceUpdated to the execution client, assuming that
  ## `clearanceState` has been updated to the expected epoch of the proposal -
  ## at the same time, ensure that the clearance state is ready for the next
  ## block

  # When the chain is synced, the most likely block to be produced is the block
  # right after head - we can exploit this assumption and advance the state
  # to that slot before the block arrives, thus allowing us to do the expensive
  # epoch transition ahead of time.
  # Notably, we use the clearance state here because that's what the clearance
  # function uses to validate the incoming block (or the one that's about to be
  # produced)
  let
    dag = self.dag
    head = dag.head
    nextBsi = BlockSlotId.init(head.bid, proposalSlot)
    startTick = Moment.now()

  var cache = StateCache()
  if not dag.updateState(dag.clearanceState, nextBsi, true, cache, dag.updateFlags):
    # This should never happen since we're basically advancing the slots of the
    # head state
    warn "Cannot prepare clearance state for next block - bug?"
    return

  debug "Prepared clearance state for next block",
    nextBsi, updateStateDur = Moment.now() - startTick

  if self.forkchoiceInflight:
    debug "Skipping proposal fcU, forkchoiceUpdated already in flight", proposalSlot
    return

  let
    preSlot = proposalSlot - 1
    (validatorIndex, nextProposer) = self.checkNextProposer(preSlot).valueOr:
      debug "Skipping proposal fcU, no proposers registered", head, proposalSlot
      return

  self.forkchoiceInflight = true
  defer:
    self.forkchoiceInflight = false

  # Approximately lines up with validator_duties version. Used optimistically/
  # opportunistically, so mismatches are fine if not too frequent.
  withState(dag.clearanceState):
    when consensusFork == ConsensusFork.Gloas:
      debugGloasComment "well, likely can't keep reusing V3 much longer"
    elif consensusFork in ConsensusFork.Electra .. ConsensusFork.Fulu:
      debug "Sending proposal fcU", proposalSlot, validatorIndex, nextProposer
      let
        timestamp = dag.timeParams
          .compute_timestamp_at_slot(forkyState.data, proposalSlot)
        # If the current head block still forms the basis of the eventual proposal
        # state, then its `get_randao_mix` will remain unchanged as well, as it is
        # constant until the next block.
        prevRandao = get_randao_mix(forkyState.data, get_current_epoch(forkyState.data))
        feeRecipient = self[].getFeeRecipient(
          nextProposer, Opt.some(validatorIndex), proposalSlot.epoch
        )
        beaconHead = self.attestationPool[].getBeaconHead(head)
        headBlockHash = dag.loadExecutionBlockHash(beaconHead.blck).valueOr:
          return

      if headBlockHash.isZero:
        return

      # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/cancun.md#payloadattributesv3
      let
        state = ForkchoiceStateV1.init(
          headBlockHash, beaconHead.safeExecutionBlockHash,
          beaconHead.finalizedExecutionBlockHash,
        )
        attributes = PayloadAttributesV3.init(
          timestamp,
          prevRandao,
          feeRecipient,
          get_expected_withdrawals(forkyState.data),
          beaconHead.blck.bid.root,
        )

        (status, _) = await self.elManager.forkchoiceUpdated(
          state, Opt.some(attributes), deadline, false
        )
      debug "Fork-choice updated for proposal", status, headBlockHash, attributes
    elif consensusFork in ConsensusFork.Phase0 .. ConsensusFork.Deneb:
      debug "Not producing blocks in pre-Electra fork"
    else:
      {.error: "Unknown consensus fork " & $consensusFork.}

proc forkchoiceUpdated*(
    self: ref ConsensusManager,
    slot: Slot,
    headBlockHash, safeBlockHash, finalizedBlockHash: Eth2Digest,
    deadline: DeadlineFuture,
    retry: bool,
): Future[PayloadExecutionStatus] {.async: (raises: [CancelledError]).} =
  ## Call non-proposer version of forkchoiceUpdated using the given slot to
  ## select the correct PayloadAttributes version

  withConsensusFork(self[].dag.cfg.consensusForkAtEpoch(slot.epoch)):
    when consensusFork >= ConsensusFork.Bellatrix:
      if headBlockHash.isZero:
        # Merge not yet activated
        PayloadExecutionStatus.valid
      else:
        let
          state =
            ForkchoiceStateV1.init(headBlockHash, safeBlockHash, finalizedBlockHash)
          (status, _) = await self.elManager.forkchoiceUpdated(
            state, Opt.none consensusFork.PayloadAttributes, deadline, retry
          )
        status
    else:
      PayloadExecutionStatus.valid

proc forkchoiceUpdated(
    self: ref ConsensusManager,
    head: BeaconHead,
    wallSlot: Slot,
    deadline: DeadlineFuture,
    retry: bool,
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Send forkchoiceUpdated to the client, return false iff the head was invalid
  ## and true otherwise

  if self[].shouldSyncOptimistically(wallSlot):
    # No point retrying for optimistic slots since there will be a new attempt
    # "soon"
    # However, we will make the call even if the optimistic head hasn't changed
    # since the last slot since the finalized / safe blocks might have changed
    let status = await self.forkchoiceUpdated(
      self.optimisticHead.bid.slot, self.optimisticHead.execution_block_hash,
      head.safeExecutionBlockHash, head.finalizedExecutionBlockHash, deadline, false,
    )

    self.optimisticHeadStatus = status.to(OptimisticStatus)

    case self.optimisticHeadStatus
    of OptimisticStatus.valid, OptimisticStatus.notValidated:
      true
    of OptimisticStatus.invalidated:
      warn "Light execution payload invalid - the execution client or the light client data is faulty",
        payloadExecutionStatus = status,
        optimisticBlockHash = self.optimisticHead.execution_block_hash
      false
  else:
    let
      headExecutionBlockHash = self.dag.loadExecutionBlockHash(head.blck).valueOr:
        # `BlockRef` are only created for blocks that have passed
        # execution block hash validation, either explicitly in
        # `block_processor.storeBlock`, or implicitly, e.g., through
        # checkpoint sync. With checkpoint sync, the checkpoint block
        # is initially not available, so if there is a reorg to it,
        # this may be triggered. Such a reorg could happen if the first
        # imported chain is completely invalid (after the checkpoint block)
        # and is subsequently pruned, in which case checkpoint block is head.
        # Because execution block hash validation has already passed,
        # we can treat this as `SYNCING`.
        warn "Failed to load head execution block hash", head = head.blck
        return true
      status = await self.forkchoiceUpdated(
        head.blck.slot, headExecutionBlockHash, head.safeExecutionBlockHash,
        head.finalizedExecutionBlockHash, deadline, retry,
      )

    case status.to(OptimisticStatus)
    of OptimisticStatus.valid:
      head.blck.markExecutionValid(true)
      true
    of OptimisticStatus.notValidated:
      if head.blck.optimisticStatus != OptimisticStatus.notValidated:
        info "Previously validated block not accepted as new head by execution client",
          blck = head.blck,
          prevStatus = head.blck.optimisticStatus,
          payloadExecutionStatus = status
      true
    of OptimisticStatus.invalidated:
      if head.blck.executionValid:
        # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/sync/optimistic.md#transitioning-from-valid---invalidated-or-invalidated---valid
        warn "Previously valid execution payload turned invalid during fork choice update - check execution client for faults and restart the beacon node",
          blck = head.blck,
          prevStatus = head.blck.optimisticStatus,
          payloadExecutionStatus = status

      head.blck.markExecutionValid(false)
      self.attestationPool[].forkChoice.mark_root_invalid(head.blck.root)
      # TODO differentiate invalid execution from invalid consensus
      discard self.quarantine[].addUnviable(head.blck.root, UnviableKind.Invalid)
      false

proc updateExecutionHead*(
    self: ref ConsensusManager,
    deadline: DeadlineFuture,
    retry: bool,
    getBeaconTimeFn: GetBeaconTimeFn,
) {.async: (raises: [CancelledError]).} =
  ## Update the execution client with consensus information from the latest
  ## head selection.
  ##
  ## In the case that we were optimistically synced and the execution client has
  ## determined that the payload was invalid, we will also attempt to update
  ## the consensus head towards a valid / nonValidated block by rerunning
  ## fork choice with the new information about invalid blocks in mind.

  if self.forkchoiceInflight:
    return

  self.forkchoiceInflight = true
  defer:
    self.forkchoiceInflight = false

  var
    attempts = 0
    wallTime = getBeaconTimeFn()
    head = self.attestationPool[].getBeaconHead(self.dag.head)

  while not (await self.forkchoiceUpdated(
      head, wallTime.slotOrZero(self.dag.timeParams), deadline, retry)):
    # Each failed call to forkchoiceUpdated that fails should reveal new
    # information about the suggested new head - a side effect of the failure is
    # that the block should be marked as invalid and removed from fork choice
    # consideration, meaning that a new fork choice should select either an
    # earlier block or a different fork (as attestations keep coming in).
    #
    # When light client data is available, we might also run into the case where
    # the optimistic head is broken - this is very bad and light client head
    # will simply be ignored until the next restart.

    if deadline.finished:
      # We will try again soon .. hopefully with a new head
      warn "Deadline expired while looking for valid payload", attempts, head
      break

    # Select new head for next attempt
    wallTime = getBeaconTimeFn()
    let nextHead = self.attestationPool[]
        .selectOptimisticHead(wallTime).valueOr:
      warn "Head selection failed after invalid block, using previous head",
        head, wallSlot = wallTime.slotOrZero(self.dag.timeParams)
      break

    warn "updateHeadWithExecution: attempting to recover from invalid payload",
      attempts, head, nextHead

    head = nextHead

    # Store the new head in the chain DAG - this may cause epochs to be
    # justified and finalized
    self[].updateHead(head.blck)

    attempts += 1

proc pruneStateCachesAndForkChoice*(self: var ConsensusManager) =
  ## Prune unneeded and invalidated data after finalization
  ## - the DAG state checkpoints
  ## - the DAG EpochRef
  ## - the attestation pool/fork choice

  # Cleanup DAG & fork choice if we have a finalized head
  if self.dag.needStateCachesAndForkChoicePruning():
    self.dag.pruneStateCachesDAG()
    self.attestationPool[].prune(self.dag)
