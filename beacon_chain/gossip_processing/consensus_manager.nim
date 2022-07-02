# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronicles, chronos,
  ../spec/datatypes/base,
  ../consensus_object_pools/[blockchain_dag, block_quarantine, attestation_pool],
  ../eth1/eth1_monitor

# TODO: Move to "consensus_object_pools" folder

type
  ConsensusManager* = object
    expectedSlot: Slot
    expectedBlockReceived: Future[bool]

    # Validated & Verified
    # ----------------------------------------------------------------
    dag*: ChainDAGRef
    attestationPool*: ref AttestationPool

    # Missing info
    # ----------------------------------------------------------------
    quarantine*: ref Quarantine

    # Execution layer integration
    # ----------------------------------------------------------------
    eth1Monitor*: Eth1Monitor

# Initialization
# ------------------------------------------------------------------------------

func new*(T: type ConsensusManager,
          dag: ChainDAGRef,
          attestationPool: ref AttestationPool,
          quarantine: ref Quarantine,
          eth1Monitor: Eth1Monitor
         ): ref ConsensusManager =
  (ref ConsensusManager)(
    dag: dag,
    attestationPool: attestationPool,
    quarantine: quarantine,
    eth1Monitor: eth1Monitor
  )

# Consensus Management
# -----------------------------------------------------------------------------------

proc checkExpectedBlock(self: var ConsensusManager) =
  if self.expectedBlockReceived == nil:
    return

  if self.dag.head.slot < self.expectedSlot:
    return

  self.expectedBlockReceived.complete(true)
  self.expectedBlockReceived = nil # Don't keep completed futures around!

proc expectBlock*(self: var ConsensusManager, expectedSlot: Slot): Future[bool] =
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

from eth/async_utils import awaitWithTimeout
from web3/engine_api_types import
  ForkchoiceUpdatedResponse, PayloadExecutionStatus, PayloadStatusV1

func `$`(h: BlockHash): string = $h.asEth2Digest

proc runForkchoiceUpdated(
    eth1Monitor: Eth1Monitor, headBlockRoot, finalizedBlockRoot: Eth2Digest):
    Future[PayloadExecutionStatus] {.async.} =
  # Allow finalizedBlockRoot to be 0 to avoid sync deadlocks.
  #
  # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md#pos-events
  # has "Before the first finalized block occurs in the system the finalized
  # block hash provided by this event is stubbed with
  # `0x0000000000000000000000000000000000000000000000000000000000000000`."
  # and
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/validator.md#executionpayload
  # notes "`finalized_block_hash` is the hash of the latest finalized execution
  # payload (`Hash32()` if none yet finalized)"
  doAssert not headBlockRoot.isZero

  try:
    # Minimize window for Eth1 monitor to shut down connection
    await eth1Monitor.ensureDataProvider()

    let fcuR = awaitWithTimeout(
      forkchoiceUpdated(
        eth1Monitor, headBlockRoot, finalizedBlockRoot),
      FORKCHOICEUPDATED_TIMEOUT):
        debug "runForkchoiceUpdated: forkchoiceUpdated timed out"
        ForkchoiceUpdatedResponse(
          payloadStatus: PayloadStatusV1(status: PayloadExecutionStatus.syncing))

    debug "runForkchoiceUpdated: ran forkchoiceUpdated",
      headBlockRoot,
      finalizedBlockRoot,
      payloadStatus = $fcuR.payloadStatus.status,
      latestValidHash = $fcuR.payloadStatus.latestValidHash,
      validationError = $fcuR.payloadStatus.validationError

    return fcuR.payloadStatus.status
  except CatchableError as err:
    debug "runForkchoiceUpdated: forkchoiceUpdated failed",
      err = err.msg
    return PayloadExecutionStatus.syncing

proc updateExecutionClientHead(self: ref ConsensusManager, newHead: BlockRef)
    {.async.} =
  if self.eth1Monitor.isNil:
    return

  # Can't use dag.head here because it hasn't been updated yet
  let
    consensusHeadRoot = newHead.root
    executionHeadRoot = self.dag.loadExecutionBlockRoot(newHead)

  if executionHeadRoot.isZero:
    # Can happen if an post-merge block has been received for processing, but
    # the fork choice head is still pre-merge.
    return

  let executionFinalizedRoot =
    self.dag.loadExecutionBlockRoot(self.dag.finalizedHead.blck)

  let payloadExecutionStatus = await self.eth1Monitor.runForkchoiceUpdated(
    executionHeadRoot, executionFinalizedRoot)

  case payloadExecutionStatus
  of PayloadExecutionStatus.valid:
    self.dag.markBlockVerified(self.quarantine[], consensusHeadRoot)
  of PayloadExecutionStatus.invalid, PayloadExecutionStatus.invalid_block_hash:
    self.dag.markBlockInvalid(consensusHeadRoot)
    self.quarantine[].addUnviable(consensusHeadRoot)
  of PayloadExecutionStatus.accepted, PayloadExecutionStatus.syncing:
    self.dag.optimisticRoots.incl consensusHeadRoot

template updateHeadWith(self: var ConsensusManager, wallSlot: Slot, body: untyped) =
  ## Trigger fork choice and update the DAG with the new head block
  ## This does not automatically prune the DAG after finalization
  ## `pruneFinalized` must be called for pruning.

  # Grab the new head according to our latest attestation data
  let newHead {.inject.} = self.attestationPool[].selectOptimisticHead(
      wallSlot.start_beacon_time).valueOr:
    warn "Head selection failed, using previous head",
      head = shortLog(self.dag.head), wallSlot
    return

  body

  # Store the new head in the chain DAG - this may cause epochs to be
  # justified and finalized
  self.dag.updateHead(newHead, self.quarantine[])

  self.checkExpectedBlock()

proc updateHead*(self: var ConsensusManager, wallSlot: Slot) =
  self.updateHeadWith(wallSlot):
    discard

proc updateHeadWithExecution*(
    self: ref ConsensusManager, wallSlot: Slot) {.async.} =
  self[].updateHeadWith(wallSlot):
    await self.updateExecutionClientHead(newHead)

proc pruneStateCachesAndForkChoice*(self: var ConsensusManager) =
  ## Prune unneeded and invalidated data after finalization
  ## - the DAG state checkpoints
  ## - the DAG EpochRef
  ## - the attestation pool/fork choice

  # Cleanup DAG & fork choice if we have a finalized head
  if self.dag.needStateCachesAndForkChoicePruning():
    self.dag.pruneStateCachesDAG()
    self.attestationPool[].prune()
