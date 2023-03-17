# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# This module is responsible for handling beacon node validators, ie those that
# that are running directly in the beacon node and not in a separate validator
# client process

import
  # Standard library
  std/[os, tables, sequtils],

  # Nimble packages
  stew/[assign2, byteutils],
  chronos, metrics,
  chronicles, chronicles/timings,
  json_serialization/std/[options, sets, net],
  eth/db/kvstore,
  eth/keys, eth/p2p/discoveryv5/[protocol, enr],
  web3/ethtypes,

  # Local modules
  ../spec/datatypes/[phase0, altair, bellatrix],
  ../spec/[
    eth2_merkleization, forks, helpers, network, signatures, state_transition,
    validator],
  ../consensus_object_pools/[
    spec_cache, blockchain_dag, block_clearance, attestation_pool, exit_pool,
    sync_committee_msg_pool, consensus_manager],
  ../eth1/eth1_monitor,
  ../networking/eth2_network,
  ../sszdump, ../sync/sync_manager,
  ../gossip_processing/block_processor,
  ".."/[conf, beacon_clock, beacon_node],
  "."/[slashing_protection, validator_pool, keystore_management],
  ".."/spec/mev/[rest_bellatrix_mev_calls, rest_capella_mev_calls]

from eth/async_utils import awaitWithTimeout

const
  delayBuckets = [-Inf, -4.0, -2.0, -1.0, -0.5, -0.1, -0.05,
                  0.05, 0.1, 0.5, 1.0, 2.0, 4.0, 8.0, Inf]

  BUILDER_STATUS_DELAY_TOLERANCE = 3.seconds
  BUILDER_VALIDATOR_REGISTRATION_DELAY_TOLERANCE = 6.seconds

# Metrics for tracking attestation and beacon block loss
declareCounter beacon_light_client_finality_updates_sent,
  "Number of LC finality updates sent by this peer"

declareCounter beacon_light_client_optimistic_updates_sent,
  "Number of LC optimistic updates sent by this peer"

declareCounter beacon_blocks_proposed,
  "Number of beacon chain blocks sent by this peer"

declareCounter beacon_block_production_errors,
  "Number of times we failed to produce a block"

declareCounter beacon_block_payload_errors,
  "Number of times execution client failed to produce block payload"

declareCounter beacon_blobs_sidecar_payload_errors,
  "Number of times execution client failed to produce blobs sidecar"

# Metrics for tracking external block builder usage
declareCounter beacon_block_builder_missed_with_fallback,
  "Number of beacon chain blocks where an attempt to use an external block builder failed with fallback"

declareCounter beacon_block_builder_missed_without_fallback,
  "Number of beacon chain blocks where an attempt to use an external block builder failed without possible fallback"

declareGauge(attached_validator_balance,
  "Validator balance at slot end of the first 64 validators, in Gwei",
  labels = ["pubkey"])

declarePublicGauge(attached_validator_balance_total,
  "Validator balance of all attached validators, in Gwei")

logScope: topics = "beacval"

type
  ForkedBlockResult* = Result[ForkedBeaconBlock, string]

  SyncStatus* {.pure.} = enum
    synced
    unsynced
    optimistic

proc getValidator*(validators: auto,
                   pubkey: ValidatorPubKey): Opt[ValidatorAndIndex] =
  let idx = validators.findIt(it.pubkey == pubkey)
  if idx == -1:
    # We allow adding a validator even if its key is not in the state registry:
    # it might be that the deposit for this validator has not yet been processed
    Opt.none ValidatorAndIndex
  else:
    Opt.some ValidatorAndIndex(index: ValidatorIndex(idx),
                               validator: validators[idx])

proc addValidators*(node: BeaconNode) =
  info "Loading validators", validatorsDir = node.config.validatorsDir(),
                keystore_cache_available = not(isNil(node.keystoreCache))
  let
    epoch = node.currentSlot().epoch
  for keystore in listLoadableKeystores(node.config, node.keystoreCache):
    let
      data = withState(node.dag.headState):
        getValidator(forkyState.data.validators.asSeq(), keystore.pubkey)
      index =
        if data.isSome():
          Opt.some(data.get().index)
        else:
          Opt.none(ValidatorIndex)
      feeRecipient = node.consensusManager[].getFeeRecipient(
        keystore.pubkey, index, epoch)
      gasLimit = node.consensusManager[].getGasLimit(keystore.pubkey)

      v = node.attachedValidators[].addValidator(keystore, feeRecipient, gasLimit)
    v.updateValidator(data)

proc getValidator*(node: BeaconNode, idx: ValidatorIndex): Opt[AttachedValidator] =
  let key = ? node.dag.validatorKey(idx)
  node.attachedValidators[].getValidator(key.toPubKey())

proc getValidatorForDuties*(
    node: BeaconNode, idx: ValidatorIndex, slot: Slot,
    slashingSafe = false): Opt[AttachedValidator] =
  let key = ? node.dag.validatorKey(idx)

  node.attachedValidators[].getValidatorForDuties(
    key.toPubKey(), slot, slashingSafe)

proc isSynced*(node: BeaconNode, head: BlockRef): SyncStatus =
  ## TODO This function is here as a placeholder for some better heurestics to
  ##      determine if we're in sync and should be producing blocks and
  ##      attestations. Generally, the problem is that slot time keeps advancing
  ##      even when there are no blocks being produced, so there's no way to
  ##      distinguish validators geniunely going missing from the node not being
  ##      well connected (during a network split or an internet outage for
  ##      example). It would generally be correct to simply keep running as if
  ##      we were the only legit node left alive, but then we run into issues:
  ##      with enough many empty slots, the validator pool is emptied leading
  ##      to empty committees and lots of empty slot processing that will be
  ##      thrown away as soon as we're synced again.

  let
    # The slot we should be at, according to the clock
    beaconTime = node.beaconClock.now()
    wallSlot = beaconTime.toSlot()

  # TODO if everyone follows this logic, the network will not recover from a
  #      halt: nobody will be producing blocks because everone expects someone
  #      else to do it
  if  wallSlot.afterGenesis and
      head.slot + node.config.syncHorizon < wallSlot.slot:
    SyncStatus.unsynced
  else:
    if node.dag.is_optimistic(head.root):
      SyncStatus.optimistic
    else:
      SyncStatus.synced

proc handleLightClientUpdates*(node: BeaconNode, slot: Slot) {.async.} =
  static: doAssert lightClientFinalityUpdateSlotOffset ==
    lightClientOptimisticUpdateSlotOffset
  let sendTime = node.beaconClock.fromNow(
    slot.light_client_finality_update_time())
  if sendTime.inFuture:
    debug "Waiting to send LC updates", slot, delay = shortLog(sendTime.offset)
    await sleepAsync(sendTime.offset)

  withForkyFinalityUpdate(node.dag.lcDataStore.cache.latest):
    when lcDataFork > LightClientDataFork.None:
      let signature_slot = forkyFinalityUpdate.signature_slot
      if slot != signature_slot:
        return

      let num_active_participants =
        forkyFinalityUpdate.sync_aggregate.num_active_participants
      if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
        return

      let finalized_slot = forkyFinalityUpdate.finalized_header.beacon.slot
      if finalized_slot > node.lightClientPool[].latestForwardedFinalitySlot:
        template msg(): auto = forkyFinalityUpdate
        let sendResult =
          await node.network.broadcastLightClientFinalityUpdate(msg)

        # Optimization for message with ephemeral validity, whether sent or not
        node.lightClientPool[].latestForwardedFinalitySlot = finalized_slot

        if sendResult.isOk:
          beacon_light_client_finality_updates_sent.inc()
          notice "LC finality update sent", message = shortLog(msg)
        else:
          warn "LC finality update failed to send",
            error = sendResult.error()

      let attested_slot = forkyFinalityUpdate.attested_header.beacon.slot
      if attested_slot > node.lightClientPool[].latestForwardedOptimisticSlot:
        let msg = forkyFinalityUpdate.toOptimistic
        let sendResult =
          await node.network.broadcastLightClientOptimisticUpdate(msg)

        # Optimization for message with ephemeral validity, whether sent or not
        node.lightClientPool[].latestForwardedOptimisticSlot = attested_slot

        if sendResult.isOk:
          beacon_light_client_optimistic_updates_sent.inc()
          notice "LC optimistic update sent", message = shortLog(msg)
        else:
          warn "LC optimistic update failed to send",
            error = sendResult.error()

proc createAndSendAttestation(node: BeaconNode,
                              fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              validator: AttachedValidator,
                              data: AttestationData,
                              committeeLen: int,
                              indexInCommittee: int,
                              subnet_id: SubnetId) {.async.} =
  try:
    let
      signature = block:
        let res = await validator.getAttestationSignature(
          fork, genesis_validators_root, data)
        if res.isErr():
          warn "Unable to sign attestation", validator = shortLog(validator),
                attestatingData = shortLog(data), error_msg = res.error()
          return
        res.get()
      attestation =
        Attestation.init(
          [uint64 indexInCommittee], committeeLen, data, signature).expect(
            "valid data")

    validator.doppelgangerActivity(attestation.data.slot.epoch)

    # Logged in the router
    let res = await node.router.routeAttestation(
      attestation, subnet_id, checkSignature = false)
    if not res.isOk():
      return

    if node.config.dumpEnabled:
      dump(node.config.dumpDirOutgoing, attestation.data, validator.pubkey)
  except CatchableError as exc:
    # An error could happen here when the signature task fails - we must
    # not leak the exception because this is an asyncSpawn task
    warn "Error sending attestation", err = exc.msg

proc getBlockProposalEth1Data*(node: BeaconNode,
                               state: ForkedHashedBeaconState):
                               BlockProposalEth1Data =
  let finalizedEpochRef = node.dag.getFinalizedEpochRef()
  result = node.elManager.getBlockProposalData(
    state, finalizedEpochRef.eth1_data,
    finalizedEpochRef.eth1_deposit_index)

proc getFeeRecipient(node: BeaconNode,
                     pubkey: ValidatorPubKey,
                     validatorIdx: ValidatorIndex,
                     epoch: Epoch): Eth1Address =
  node.consensusManager[].getFeeRecipient(pubkey, Opt.some(validatorIdx), epoch)

proc getGasLimit(node: BeaconNode,
                 pubkey: ValidatorPubKey): uint64 =
  node.consensusManager[].getGasLimit(pubkey)

from web3/engine_api_types import PayloadExecutionStatus
from ../spec/datatypes/capella import BeaconBlock, ExecutionPayload
from ../spec/datatypes/deneb import BeaconBlock, ExecutionPayload, shortLog
from ../spec/beaconstate import get_expected_withdrawals

proc getExecutionPayload(
    PayloadType: type ForkyExecutionPayloadForSigning,
    node: BeaconNode, proposalState: ref ForkedHashedBeaconState,
    epoch: Epoch, validator_index: ValidatorIndex): Future[Opt[PayloadType]] {.async.} =
  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/bellatrix/validator.md#executionpayload

  let feeRecipient = block:
    let pubkey = node.dag.validatorKey(validator_index)
    if pubkey.isNone():
      error "Cannot get proposer pubkey, bug?", validator_index
      default(Eth1Address)
    else:
      node.getFeeRecipient(pubkey.get().toPubKey(), validator_index, epoch)

  template empty_execution_payload(): auto =
    # Callers should already ensure these match, but type system doesn't
    # transmit this information through the Forked types, so this has to
    # be re-proven here.
    withState(proposalState[]):
      when consensusFork >= ConsensusFork.Capella:
        # As of Capella, because EL state root changes in way more difficult to
        # compute way from CL due to incorporation of withdrawals into EL state
        # cannot use fake-EL fallback. Unlike transactions, withdrawals are not
        # optional, so one cannot avoid this by not including any withdrawals.
        Opt.none PayloadType
      elif (consensusFork == ConsensusFork.Bellatrix and
            PayloadType is bellatrix.ExecutionPayloadForSigning):
        Opt.some build_empty_execution_payload(forkyState.data, feeRecipient)
      elif consensusFork == ConsensusFork.Bellatrix:
        raiseAssert "getExecutionPayload: mismatched proposalState and ExecutionPayload fork"
      else:
        # Vacuously -- these are pre-Bellatrix and not used.
        Opt.some default(PayloadType)

  try:
    let
      beaconHead = node.attestationPool[].getBeaconHead(node.dag.head)
      executionHead = withState(proposalState[]):
        when consensusFork >= ConsensusFork.Bellatrix:
          forkyState.data.latest_execution_payload_header.block_hash
        else:
          (static(default(Eth2Digest)))
      latestSafe = beaconHead.safeExecutionPayloadHash
      latestFinalized = beaconHead.finalizedExecutionPayloadHash
      timestamp = withState(proposalState[]):
        compute_timestamp_at_slot(forkyState.data, forkyState.data.slot)
      random = withState(proposalState[]):
        get_randao_mix(forkyState.data, get_current_epoch(forkyState.data))
      withdrawals = withState(proposalState[]):
        when consensusFork >= ConsensusFork.Capella:
          get_expected_withdrawals(forkyState.data)
        else:
          @[]
      payload = await node.elManager.getPayload(
        PayloadType, executionHead, latestSafe, latestFinalized,
        timestamp, random, feeRecipient, withdrawals)

    if payload.isNone:
      error "Failed to obtain execution payload from EL",
             executionHeadBlock = executionHead
      return Opt.none(PayloadType)

    return Opt.some payload.get
  except CatchableError as err:
    beacon_block_payload_errors.inc()
    error "Error creating non-empty execution payload; using empty execution payload",
      msg = err.msg
    return empty_execution_payload

proc makeBeaconBlockForHeadAndSlot*(
    PayloadType: type ForkyExecutionPayloadForSigning,
    node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot,

    # These parameters are for the builder API
    execution_payload: Opt[PayloadType],
    transactions_root: Opt[Eth2Digest],
    execution_payload_root: Opt[Eth2Digest],
    withdrawals_root: Opt[Eth2Digest]):
    Future[ForkedBlockResult] {.async.} =
  # Advance state to the slot that we're proposing for
  var cache = StateCache()

  let
    # The clearance state already typically sits at the right slot per
    # `advanceClearanceState`

    # TODO can use `valueOr:`/`return err($error)` if/when
    # https://github.com/status-im/nim-stew/issues/161 is addressed
    maybeState = node.dag.getProposalState(head, slot, cache)

  if maybeState.isErr:
    beacon_block_production_errors.inc()
    return err($maybeState.error)

  let
    state = maybeState.get
    payloadFut =
      if execution_payload.isSome:
        # Builder API

        # In Capella, only get withdrawals root from relay.
        # The execution payload will be small enough to be safe to copy because
        # it won't have transactions (it's blinded)
        var modified_execution_payload = execution_payload
        withState(state[]):
          when  consensusFork >= ConsensusFork.Capella and
                PayloadType.toFork >= ConsensusFork.Capella:
            let withdrawals = List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD](
              get_expected_withdrawals(forkyState.data))
            if  withdrawals_root.isNone or
                hash_tree_root(withdrawals) != withdrawals_root.get:
              # TODO: Why don't we fallback to the EL payload here?
              return err("Builder relay provided incorrect withdrawals root")
            # Otherwise, the state transition function notices that there are
            # too few withdrawals.
            assign(modified_execution_payload.get.executionPayload.withdrawals,
                   withdrawals)

        let fut = newFuture[Opt[PayloadType]]("given-payload")
        fut.complete(modified_execution_payload)
        fut
      elif slot.epoch < node.dag.cfg.BELLATRIX_FORK_EPOCH or
           not state[].is_merge_transition_complete:
        let fut = newFuture[Opt[PayloadType]]("empty-payload")
        fut.complete(Opt.some(default(PayloadType)))
        fut
      else:
        # Create execution payload while packing attestations
        getExecutionPayload(PayloadType, node, state, slot.epoch, validator_index)

    eth1Proposal = node.getBlockProposalEth1Data(state[])

  if eth1Proposal.hasMissingDeposits:
    beacon_block_production_errors.inc()
    warn "Eth1 deposits not available. Skipping block proposal", slot
    return err("Eth1 deposits not available")

  let
    attestations =
      node.attestationPool[].getAttestationsForBlock(state[], cache)
    exits = withState(state[]):
      node.validatorChangePool[].getBeaconBlockValidatorChanges(
        node.dag.cfg, forkyState.data)
    syncAggregate =
      if slot.epoch < node.dag.cfg.ALTAIR_FORK_EPOCH:
        SyncAggregate.init()
      else:
        node.syncCommitteeMsgPool[].produceSyncAggregate(head.root)
    payload = (await payloadFut).valueOr:
      beacon_block_production_errors.inc()
      warn "Unable to get execution payload. Skipping block proposal",
        slot, validator_index
      return err("Unable to get execution payload")

  return makeBeaconBlock(
      node.dag.cfg,
      state[],
      validator_index,
      randao_reveal,
      eth1Proposal.vote,
      graffiti,
      attestations,
      eth1Proposal.deposits,
      exits,
      syncAggregate,
      payload,
      noRollback, # Temporary state - no need for rollback
      cache,
      verificationFlags = {},
      transactions_root = transactions_root,
      execution_payload_root = execution_payload_root).mapErr do (error: cstring) -> string:
    # This is almost certainly a bug, but it's complex enough that there's a
    # small risk it might happen even when most proposals succeed - thus we
    # log instead of asserting
    beacon_block_production_errors.inc()
    error "Cannot create block for proposal",
      slot, head = shortLog(head), error
    $error

# workaround for https://github.com/nim-lang/Nim/issues/20900 to avoid default
# parameters
proc makeBeaconBlockForHeadAndSlot*(
    PayloadType: type ForkyExecutionPayloadForSigning, node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot):
    Future[ForkedBlockResult] {.async.} =
  return await makeBeaconBlockForHeadAndSlot(
    PayloadType, node, randao_reveal, validator_index, graffiti, head, slot,
    execution_payload = Opt.none(PayloadType),
    transactions_root = Opt.none(Eth2Digest),
    execution_payload_root = Opt.none(Eth2Digest),
    withdrawals_root = Opt.none(Eth2Digest))

proc getBlindedExecutionPayload[
    EPH: bellatrix.ExecutionPayloadHeader | capella.ExecutionPayloadHeader](
    node: BeaconNode, slot: Slot, executionBlockRoot: Eth2Digest,
    pubkey: ValidatorPubKey): Future[Result[EPH, string]] {.async.} =
  if node.payloadBuilderRestClient.isNil:
    return err "getBlindedExecutionPayload: nil REST client"

  when EPH is capella.ExecutionPayloadHeader:
    let blindedHeader = awaitWithTimeout(
      node.payloadBuilderRestClient.getHeaderCapella(
        slot, executionBlockRoot, pubkey),
      BUILDER_PROPOSAL_DELAY_TOLERANCE):
        return err "Timeout when obtaining Capella blinded header from builder"
  elif EPH is bellatrix.ExecutionPayloadHeader:
    let blindedHeader = awaitWithTimeout(
      node.payloadBuilderRestClient.getHeaderBellatrix(
        slot, executionBlockRoot, pubkey),
      BUILDER_PROPOSAL_DELAY_TOLERANCE):
        return err "Timeout when obtaining Bellatrix blinded header from builder"
  else:
    static: doAssert false

  const httpOk = 200
  if blindedHeader.status != httpOk:
    return err "getBlindedExecutionPayload: non-200 HTTP response"
  else:
    if not verify_builder_signature(
        node.dag.cfg.genesisFork, blindedHeader.data.data.message,
        blindedHeader.data.data.message.pubkey,
        blindedHeader.data.data.signature):
      return err "getBlindedExecutionPayload: signature verification failed"

    return ok blindedHeader.data.data.message.header

from ./message_router_mev import
  copyFields, getFieldNames, unblindAndRouteBlockMEV

func constructSignableBlindedBlock[T](
    blck: bellatrix.BeaconBlock | capella.BeaconBlock,
    executionPayloadHeader: bellatrix.ExecutionPayloadHeader |
                            capella.ExecutionPayloadHeader): T =
  const
    blckFields = getFieldNames(typeof(blck))
    blckBodyFields = getFieldNames(typeof(blck.body))

  var blindedBlock: T

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#block-proposal
  copyFields(blindedBlock.message, blck, blckFields)
  copyFields(blindedBlock.message.body, blck.body, blckBodyFields)
  assign(
    blindedBlock.message.body.execution_payload_header, executionPayloadHeader)

  blindedBlock

func constructPlainBlindedBlock[
    T: bellatrix_mev.BlindedBeaconBlock | capella_mev.BlindedBeaconBlock,
    EPH: bellatrix.ExecutionPayloadHeader | capella.ExecutionPayloadHeader](
    blck: ForkyBeaconBlock, executionPayloadHeader: EPH): T =
  const
    blckFields = getFieldNames(typeof(blck))
    blckBodyFields = getFieldNames(typeof(blck.body))

  var blindedBlock: T

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#block-proposal
  copyFields(blindedBlock, blck, blckFields)
  copyFields(blindedBlock.body, blck.body, blckBodyFields)
  assign(blindedBlock.body.execution_payload_header, executionPayloadHeader)

  blindedBlock

proc blindedBlockCheckSlashingAndSign[T](
    node: BeaconNode, slot: Slot, validator: AttachedValidator,
    validator_index: ValidatorIndex, nonsignedBlindedBlock: T):
    Future[Result[T, string]] {.async.} =
  # Check with slashing protection before submitBlindedBlock
  let
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root
    blockRoot = hash_tree_root(nonsignedBlindedBlock.message)
    signingRoot = compute_block_signing_root(
      fork, genesis_validators_root, slot, blockRoot)
    notSlashable = node.attachedValidators
      .slashingProtection
      .registerBlock(validator_index, validator.pubkey, slot, signingRoot)

  if notSlashable.isErr:
    warn "Slashing protection activated for MEV block",
      blockRoot = shortLog(blockRoot), blck = shortLog(nonsignedBlindedBlock),
      signingRoot = shortLog(signingRoot),
      validator = validator.pubkey,
      slot = slot,
      existingProposal = notSlashable.error
    return err("MEV proposal would be slashable: " & $notSlashable.error)

  var blindedBlock = nonsignedBlindedBlock
  blindedBlock.signature =
    block:
      let res = await validator.getBlockSignature(
        fork, genesis_validators_root, slot, blockRoot, blindedBlock.message)
      if res.isErr():
        return err("Unable to sign block: " & res.error())
      res.get()

  return ok blindedBlock

proc getBlindedBeaconBlock[
    T: bellatrix_mev.SignedBlindedBeaconBlock |
       capella_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, slot: Slot, validator: AttachedValidator,
    validator_index: ValidatorIndex, forkedBlock: ForkedBeaconBlock,
    executionPayloadHeader: bellatrix.ExecutionPayloadHeader |
                            capella.ExecutionPayloadHeader):
    Future[Result[T, string]] {.async.} =
  withBlck(forkedBlock):
    when consensusFork >= ConsensusFork.Deneb:
      debugRaiseAssert $denebImplementationMissing & ": getBlindedBeaconBlock"
      return err("getBlindedBeaconBlock: Deneb blinded block creation not implemented")
    elif consensusFork >= ConsensusFork.Bellatrix:
      when not (
          (T is bellatrix_mev.SignedBlindedBeaconBlock and
           consensusFork == ConsensusFork.Bellatrix) or
          (T is capella_mev.SignedBlindedBeaconBlock and
           consensusFork == ConsensusFork.Capella)):
        return err("getBlindedBeaconBlock: mismatched block/payload types")
      else:
        return await blindedBlockCheckSlashingAndSign(
          node, slot, validator, validator_index,
          constructSignableBlindedBlock[T](blck, executionPayloadHeader))
    else:
      return err("getBlindedBeaconBlock: attempt to construct pre-Bellatrix blinded block")

proc getBlindedBlockParts[EPH: ForkyExecutionPayloadHeader](
    node: BeaconNode, head: BlockRef, pubkey: ValidatorPubKey,
    slot: Slot, randao: ValidatorSig, validator_index: ValidatorIndex,
    graffiti: GraffitiBytes): Future[Result[(EPH, ForkedBeaconBlock), string]]
    {.async.} =
  let
    executionBlockRoot = node.dag.loadExecutionBlockRoot(head)
    executionPayloadHeader =
      try:
        awaitWithTimeout(
            getBlindedExecutionPayload[EPH](
              node, slot, executionBlockRoot, pubkey),
            BUILDER_PROPOSAL_DELAY_TOLERANCE):
          Result[EPH, string].err("getBlindedExecutionPayload timed out")
      except RestDecodingError as exc:
        Result[EPH, string].err(
          "getBlindedExecutionPayload REST decoding error")
      except CatchableError as exc:
        Result[EPH, string].err("getBlindedExecutionPayload error")

  if executionPayloadHeader.isErr:
    debug "getBlindedBlockParts: getBlindedExecutionPayload failed",
      error = executionPayloadHeader.error, slot, validator_index,
      head = shortLog(head)
    # Haven't committed to the MEV block, so allow EL fallback.
    return err(executionPayloadHeader.error)

  # When creating this block, need to ensure it uses the MEV-provided execution
  # payload, both to avoid repeated calls to network services and to ensure the
  # consistency of this block (e.g., its state root being correct). Since block
  # processing does not work directly using blinded blocks, fix up transactions
  # root after running the state transition function on an otherwise equivalent
  # non-blinded block without transactions.
  when EPH is bellatrix.ExecutionPayloadHeader:
    type PayloadType = bellatrix.ExecutionPayloadForSigning
    let withdrawals_root = Opt.none Eth2Digest
  elif EPH is capella.ExecutionPayloadHeader:
    type PayloadType = capella.ExecutionPayloadForSigning
    let withdrawals_root = Opt.some executionPayloadHeader.get.withdrawals_root
  elif EPH is deneb.ExecutionPayloadHeader:
    type PayloadType = deneb.ExecutionPayloadForSigning
    let withdrawals_root = Opt.some executionPayloadHeader.get.withdrawals_root
  else:
    static: doAssert false

  var shimExecutionPayload: PayloadType
  copyFields(
    shimExecutionPayload.executionPayload, executionPayloadHeader.get, getFieldNames(EPH))
  # In Capella and later, this doesn't have withdrawals, which each node knows
  # regardless of EL or builder API. makeBeaconBlockForHeadAndSlot fills it in
  # when it detects builder API usage.

  let newBlock = await makeBeaconBlockForHeadAndSlot(
    PayloadType, node, randao, validator_index, graffiti, head, slot,
    execution_payload = Opt.some shimExecutionPayload,
    transactions_root = Opt.some executionPayloadHeader.get.transactions_root,
    execution_payload_root =
      Opt.some hash_tree_root(executionPayloadHeader.get),
    withdrawals_root = withdrawals_root)

  if newBlock.isErr():
    # Haven't committed to the MEV block, so allow EL fallback.
    return err(newBlock.error)  # already logged elsewhere!

  let forkedBlck = newBlock.get()

  return ok((executionPayloadHeader.get, forkedBlck))

proc proposeBlockMEV[
    SBBB: bellatrix_mev.SignedBlindedBeaconBlock |
          capella_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, head: BlockRef, validator: AttachedValidator, slot: Slot,
    randao: ValidatorSig, validator_index: ValidatorIndex):
    Future[Opt[BlockRef]] {.async.} =
  when SBBB is bellatrix_mev.SignedBlindedBeaconBlock:
    type EPH = bellatrix.ExecutionPayloadHeader
  elif SBBB is capella_mev.SignedBlindedBeaconBlock:
    type EPH = capella.ExecutionPayloadHeader
  else:
    static: doAssert false

  let blindedBlockParts = await getBlindedBlockParts[EPH](
    node, head, validator.pubkey, slot, randao, validator_index,
    node.graffitiBytes)
  if blindedBlockParts.isErr:
    # Not signed yet, fine to try to fall back on EL
    beacon_block_builder_missed_with_fallback.inc()
    return Opt.none BlockRef

  # These, together, get combined into the blinded block for signing and
  # proposal through the relay network.
  let (executionPayloadHeader, forkedBlck) = blindedBlockParts.get

  # This is only substantively asynchronous with a remote key signer
  let blindedBlock = awaitWithTimeout(
      getBlindedBeaconBlock[SBBB](
        node, slot, validator, validator_index, forkedBlck,
        executionPayloadHeader),
      500.milliseconds):
    Result[SBBB, string].err("getBlindedBlock timed out")

  if blindedBlock.isErr:
    info "proposeBlockMEV: getBlindedBeaconBlock failed",
      slot, head = shortLog(head), validator_index, blindedBlock,
      error = blindedBlock.error
    return Opt.none BlockRef

  # Before unblindAndRouteBlockMEV, can fall back to EL; after, cannot
  let unblindedBlockRef = await node.unblindAndRouteBlockMEV(
      blindedBlock.get)
  return if unblindedBlockRef.isOk and unblindedBlockRef.get.isSome:
    beacon_blocks_proposed.inc()
    unblindedBlockRef.get
  else:
    # Signal to the caller that a signed, blinded beacon block was sent to the
    # builder API server, at which point no local EL fallback can occur. Using
    # non-`none` opt with the same head indicates this to proposeBlock(), with
    # any non-`none` return value indicating this in general.
    #
    # unblindedBlockRef.isOk and unblindedBlockRef.get.isNone indicates that
    # the block failed to validate and integrate into the DAG, which for the
    # purpose of this return value, is equivalent. It's used to drive Beacon
    # REST API output.
    let errMsg =
      if unblindedBlockRef.isErr:
        unblindedBlockRef.error
      else:
        "Unblinded block failed either to validate or integrate into validated store"
    warn "proposeBlockMEV: blinded block either not successfully unblinded or not successfully proposed",
      head = shortLog(head), slot, validator_index,
      validator = shortLog(validator),
      err = errMsg, blindedBlck = shortLog(blindedBlock.get)
    Opt.some head

proc makeBlindedBeaconBlockForHeadAndSlot*[
    BBB: bellatrix_mev.BlindedBeaconBlock | capella_mev.BlindedBeaconBlock](
    node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot): Future[Result[BBB, string]] {.async.} =
  ## Requests a beacon node to produce a valid blinded block, which can then be
  ## signed by a validator. A blinded block is a block with only a transactions
  ## root, rather than a full transactions list.
  when BBB is bellatrix_mev.BlindedBeaconBlock:
    type EPH = bellatrix.ExecutionPayloadHeader
  elif BBB is capella_mev.BlindedBeaconBlock:
    type EPH = capella.ExecutionPayloadHeader
  else:
    static: doAssert false

  let
    pubkey =
      # Relevant state for knowledge of validators
      withState(node.dag.headState):
        if distinctBase(validator_index) >= forkyState.data.validators.lenu64:
          debug "makeBlindedBeaconBlockForHeadAndSlot: invalid validator index",
            head = shortLog(head),
            validator_index,
            validators_len = forkyState.data.validators.len
          return err("Invalid validator index")

        forkyState.data.validators.item(validator_index).pubkey

    blindedBlockParts = await getBlindedBlockParts[EPH](
      node, head, pubkey, slot, randao_reveal, validator_index, graffiti)
  if blindedBlockParts.isErr:
    # Don't try EL fallback -- VC specifically requested a blinded block
    return err("Unable to create blinded block")

  let (executionPayloadHeader, forkedBlck) = blindedBlockParts.get
  withBlck(forkedBlck):
    when consensusFork >= ConsensusFork.Deneb:
      debugRaiseAssert $denebImplementationMissing & ": makeBlindedBeaconBlockForHeadAndSlot"
    elif consensusFork >= ConsensusFork.Bellatrix:
      when ((consensusFork == ConsensusFork.Bellatrix and
             EPH is bellatrix.ExecutionPayloadHeader) or
            (consensusFork == ConsensusFork.Capella and
             EPH is capella.ExecutionPayloadHeader)):
        return ok constructPlainBlindedBlock[BBB, EPH](
          blck, executionPayloadHeader)
      else:
        return err("makeBlindedBeaconBlockForHeadAndSlot: mismatched block/payload types")
    else:
      return err("Attempt to create pre-Bellatrix blinded block")

proc proposeBlock(node: BeaconNode,
                  validator: AttachedValidator,
                  validator_index: ValidatorIndex,
                  head: BlockRef,
                  slot: Slot): Future[BlockRef] {.async.} =
  if head.slot >= slot:
    # We should normally not have a head newer than the slot we're proposing for
    # but this can happen if block proposal is delayed
    warn "Skipping proposal, have newer head already",
      headSlot = shortLog(head.slot),
      headBlockRoot = shortLog(head.root),
      slot = shortLog(slot)
    return head

  let
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root
    randao =
      block:
        let res = await validator.getEpochSignature(
          fork, genesis_validators_root, slot.epoch)
        if res.isErr():
          warn "Unable to generate randao reveal",
               validator = shortLog(validator), error_msg = res.error()
          return head
        res.get()

  if node.config.payloadBuilderEnable:
    let newBlockMEV =
      if slot.epoch >= node.dag.cfg.DENEB_FORK_EPOCH:
        debugRaiseAssert $denebImplementationMissing & ": proposeBlock"
        await proposeBlockMEV[
            capella_mev.SignedBlindedBeaconBlock](
          node, head, validator, slot, randao, validator_index)
      elif slot.epoch >= node.dag.cfg.CAPELLA_FORK_EPOCH:
        await proposeBlockMEV[
            capella_mev.SignedBlindedBeaconBlock](
          node, head, validator, slot, randao, validator_index)
      else:
        await proposeBlockMEV[
            bellatrix_mev.SignedBlindedBeaconBlock](
          node, head, validator, slot, randao, validator_index)

    if newBlockMEV.isSome:
      # This might be equivalent to the `head` passed in, but it signals that
      # `submitBlindedBlock` ran, so don't do anything else. Otherwise, it is
      # fine to try again with the local EL.
      if newBlockMEV.get == head:
        # Returning same block as head indicates failure to generate new block
        beacon_block_builder_missed_without_fallback.inc()
      return newBlockMEV.get

  # TODO Compare the value of the MEV block and the execution block
  #      obtained from the EL below:

  let newBlock =
    if slot.epoch >= node.dag.cfg.DENEB_FORK_EPOCH:
      await makeBeaconBlockForHeadAndSlot(
        deneb.ExecutionPayloadForSigning,
        node, randao, validator_index, node.graffitiBytes, head, slot)
    elif slot.epoch >= node.dag.cfg.CAPELLA_FORK_EPOCH:
      await makeBeaconBlockForHeadAndSlot(
        capella.ExecutionPayloadForSigning,
        node, randao, validator_index, node.graffitiBytes, head, slot)
    else:
      await makeBeaconBlockForHeadAndSlot(
        bellatrix.ExecutionPayloadForSigning,
        node, randao, validator_index, node.graffitiBytes, head, slot)

  if newBlock.isErr():
    return head # already logged elsewhere!

  var forkedBlck = newBlock.get()

  withBlck(forkedBlck):
    var blobs_sidecar = deneb.BlobsSidecar(
      beacon_block_slot: slot,
    )
    when blck is deneb.BeaconBlock:
      # TODO: The blobs_sidecar variable is not currently used.
      #       It could be initialized in makeBeaconBlockForHeadAndSlot
      #       where the required information is available.
      # blobs_sidecar.blobs = forkedBlck.blobs
      # blobs_sidecar.kzg_aggregated_proof = kzg_aggregated_proof
      discard

    let
      blockRoot = hash_tree_root(blck)
      signingRoot = compute_block_signing_root(
        fork, genesis_validators_root, slot, blockRoot)

      notSlashable = node.attachedValidators
        .slashingProtection
        .registerBlock(validator_index, validator.pubkey, slot, signingRoot)

    blobs_sidecar.beacon_block_root = blockRoot
    if notSlashable.isErr:
      warn "Slashing protection activated for block proposal",
        blockRoot = shortLog(blockRoot), blck = shortLog(blck),
        signingRoot = shortLog(signingRoot),
        validator = validator.pubkey,
        slot = slot,
        existingProposal = notSlashable.error
      return head

    let
      signature =
        block:
          let res = await validator.getBlockSignature(
            fork, genesis_validators_root, slot, blockRoot, forkedBlck)
          if res.isErr():
            warn "Unable to sign block",
                 validator = shortLog(validator), error_msg = res.error()
            return head
          res.get()
      signedBlock =
        when blck is phase0.BeaconBlock:
          phase0.SignedBeaconBlock(
            message: blck, signature: signature, root: blockRoot)
        elif blck is altair.BeaconBlock:
          altair.SignedBeaconBlock(
            message: blck, signature: signature, root: blockRoot)
        elif blck is bellatrix.BeaconBlock:
          bellatrix.SignedBeaconBlock(
            message: blck, signature: signature, root: blockRoot)
        elif blck is capella.BeaconBlock:
          capella.SignedBeaconBlock(
            message: blck, signature: signature, root: blockRoot)
        elif blck is deneb.BeaconBlock:
          # TODO: also route blobs
          deneb.SignedBeaconBlock(message: blck, signature: signature, root: blockRoot)
       else:
          static: doAssert "Unknown SignedBeaconBlock type"
      newBlockRef =
        (await node.router.routeSignedBeaconBlock(signedBlock)).valueOr:
          return head # Errors logged in router

    if newBlockRef.isNone():
      return head # Validation errors logged in router

    notice "Block proposed",
      blockRoot = shortLog(blockRoot), blck = shortLog(blck),
      signature = shortLog(signature), validator = shortLog(validator)

    beacon_blocks_proposed.inc()

    return newBlockRef.get()

proc handleAttestations(node: BeaconNode, head: BlockRef, slot: Slot) =
  ## Perform all attestations that the validators attached to this node should
  ## perform during the given slot
  if slot + SLOTS_PER_EPOCH < head.slot:
    # The latest block we know about is a lot newer than the slot we're being
    # asked to attest to - this makes it unlikely that it will be included
    # at all.
    # TODO the oldest attestations allowed are those that are older than the
    #      finalized epoch.. also, it seems that posting very old attestations
    #      is risky from a slashing perspective. More work is needed here.
    warn "Skipping attestation, head is too recent",
      head = shortLog(head),
      slot = shortLog(slot)
    return

  if slot < node.dag.finalizedHead.slot:
    # During checkpoint sync, we implicitly finalize the given slot even if the
    # state transition does not yet consider it final - this is a sanity check
    # mostly to ensure the `atSlot` below works as expected
    warn "Skipping attestation - slot already finalized",
      head = shortLog(head),
      slot = shortLog(slot),
      finalized = shortLog(node.dag.finalizedHead)
    return

  let attestationHead = head.atSlot(slot)
  if head != attestationHead.blck:
    # In rare cases, such as when we're busy syncing or just slow, we'll be
    # attesting to a past state - we must then recreate the world as it looked
    # like back then
    notice "Attesting to a state in the past, falling behind?",
      attestationHead = shortLog(attestationHead),
      head = shortLog(head)

  trace "Checking attestations",
    attestationHead = shortLog(attestationHead),
    head = shortLog(head)

  # We need to run attestations exactly for the slot that we're attesting to.
  # In case blocks went missing, this means advancing past the latest block
  # using empty slots as fillers.
  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.4/specs/phase0/validator.md#validator-assignments
  let
    epochRef = node.dag.getEpochRef(
      attestationHead.blck, slot.epoch, false).valueOr:
        warn "Cannot construct EpochRef for attestation head, report bug",
          attestationHead = shortLog(attestationHead), slot, error
        return
    committees_per_slot = get_committee_count_per_slot(epochRef.shufflingRef)
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root

  for committee_index in get_committee_indices(committees_per_slot):
    let committee = get_beacon_committee(
      epochRef.shufflingRef, slot, committee_index)

    for index_in_committee, validator_index in committee:
      let validator = node.getValidatorForDuties(validator_index, slot).valueOr:
        continue

      let
        data = makeAttestationData(epochRef, attestationHead, committee_index)
        # TODO signing_root is recomputed in produceAndSignAttestation/signAttestation just after
        signingRoot = compute_attestation_signing_root(
          fork, genesis_validators_root, data)
        registered = node.attachedValidators
          .slashingProtection
          .registerAttestation(
            validator_index,
            validator.pubkey,
            data.source.epoch,
            data.target.epoch,
            signingRoot)
      if registered.isOk():
        let subnet_id = compute_subnet_for_attestation(
          committees_per_slot, data.slot, committee_index)
        asyncSpawn createAndSendAttestation(
          node, fork, genesis_validators_root, validator, data,
          committee.len(), index_in_committee, subnet_id)
      else:
        warn "Slashing protection activated for attestation",
          attestationData = shortLog(data),
          signingRoot = shortLog(signingRoot),
          validator_index,
          validator = shortLog(validator),
          badVoteDetails = $registered.error()

proc createAndSendSyncCommitteeMessage(node: BeaconNode,
                                       validator: AttachedValidator,
                                       slot: Slot,
                                       subcommitteeIdx: SyncSubcommitteeIndex,
                                       head: BlockRef) {.async.} =
  try:
    let
      fork = node.dag.forkAtEpoch(slot.epoch)
      genesis_validators_root = node.dag.genesis_validators_root
      msg =
        block:
          let res = await validator.getSyncCommitteeMessage(
            fork, genesis_validators_root, slot, head.root)
          if res.isErr():
            warn "Unable to sign committee message",
                  validator = shortLog(validator), slot = slot,
                  block_root = shortLog(head.root)
            return
          res.get()

    # Logged in the router
    let res = await node.router.routeSyncCommitteeMessage(
      msg, subcommitteeIdx, checkSignature = false)

    if not res.isOk():
      return

    if node.config.dumpEnabled:
      dump(node.config.dumpDirOutgoing, msg, validator.pubkey)
  except CatchableError as exc:
    # An error could happen here when the signature task fails - we must
    # not leak the exception because this is an asyncSpawn task
    notice "Error sending sync committee message", err = exc.msg

proc handleSyncCommitteeMessages(node: BeaconNode, head: BlockRef, slot: Slot) =
  # TODO Use a view type to avoid the copy
  let
    syncCommittee = node.dag.syncCommitteeParticipants(slot + 1)

  for subcommitteeIdx in SyncSubcommitteeIndex:
    for valIdx in syncSubcommittee(syncCommittee, subcommitteeIdx):
      let validator = node.getValidatorForDuties(
          valIdx, slot, slashingSafe = true).valueOr:
        continue
      asyncSpawn createAndSendSyncCommitteeMessage(node, validator, slot,
                                                   subcommitteeIdx, head)

proc signAndSendContribution(node: BeaconNode,
                             validator: AttachedValidator,
                             subcommitteeIdx: SyncSubcommitteeIndex,
                             head: BlockRef,
                             slot: Slot) {.async.} =
  try:
    let
      fork = node.dag.forkAtEpoch(slot.epoch)
      genesis_validators_root = node.dag.genesis_validators_root
      selectionProof = block:
        let res = await validator.getSyncCommitteeSelectionProof(
          fork, genesis_validators_root, slot, subcommitteeIdx)
        if res.isErr():
          warn "Unable to generate committee selection proof",
            validator = shortLog(validator), slot,
            subnet_id = subcommitteeIdx, error = res.error()
          return
        res.get()

    if not is_sync_committee_aggregator(selectionProof):
      return

    var
      msg = SignedContributionAndProof(
        message: ContributionAndProof(
          aggregator_index: uint64 validator.index.get,
          selection_proof: selectionProof))

    if not node.syncCommitteeMsgPool[].produceContribution(
        slot,
        head.root,
        subcommitteeIdx,
        msg.message.contribution):
      return

    msg.signature = block:
      let res = await validator.getContributionAndProofSignature(
        fork, genesis_validators_root, msg.message)

      if res.isErr():
        warn "Unable to sign sync committee contribution",
          validator = shortLog(validator), message = shortLog(msg.message),
          error_msg = res.error()
        return
      res.get()

    # Logged in the router
    discard await node.router.routeSignedContributionAndProof(msg, false)
  except CatchableError as exc:
    # An error could happen here when the signature task fails - we must
    # not leak the exception because this is an asyncSpawn task
    warn "Error sending sync committee contribution", err = exc.msg

proc handleSyncCommitteeContributions(
    node: BeaconNode, head: BlockRef, slot: Slot) {.async.} =
  let
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root
    syncCommittee = node.dag.syncCommitteeParticipants(slot + 1)

  for subcommitteeIdx in SyncSubCommitteeIndex:
    for valIdx in syncSubcommittee(syncCommittee, subcommitteeIdx):
      let validator = node.getValidatorForDuties(
          valIdx, slot, slashingSafe = true).valueOr:
        continue

      asyncSpawn signAndSendContribution(
        node, validator, subcommitteeIdx, head, slot)

proc handleProposal(node: BeaconNode, head: BlockRef, slot: Slot):
    Future[BlockRef] {.async.} =
  ## Perform the proposal for the given slot, iff we have a validator attached
  ## that is supposed to do so, given the shuffling at that slot for the given
  ## head - to compute the proposer, we need to advance a state to the given
  ## slot
  let
    proposer = node.dag.getProposer(head, slot).valueOr:
      return head
    proposerKey = node.dag.validatorKey(proposer).get().toPubKey
    validator = node.getValidatorForDuties(proposer, slot).valueOr:
      debug "Expecting block proposal", headRoot = shortLog(head.root),
                                        slot = shortLog(slot),
                                        proposer_index = proposer,
                                        proposer = shortLog(proposerKey)
      return head

  return await proposeBlock(node, validator, proposer, head, slot)

proc signAndSendAggregate(
    node: BeaconNode, validator: AttachedValidator, shufflingRef: ShufflingRef,
    slot: Slot, committee_index: CommitteeIndex) {.async.} =
  try:
    let
      fork = node.dag.forkAtEpoch(slot.epoch)
      genesis_validators_root = node.dag.genesis_validators_root
      validator_index = validator.index.get()
      selectionProof = block:
        let res = await validator.getSlotSignature(
          fork, genesis_validators_root, slot)
        if res.isErr():
          warn "Unable to create slot signature",
            validator = shortLog(validator),
            slot, error = res.error()
          return
        res.get()

    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.4/specs/phase0/validator.md#aggregation-selection
    if not is_aggregator(
        shufflingRef, slot, committee_index, selectionProof):
      return

    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.4/specs/phase0/validator.md#construct-aggregate
    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.4/specs/phase0/validator.md#aggregateandproof
    var
      msg = SignedAggregateAndProof(
        message: AggregateAndProof(
          aggregator_index: uint64 validator_index,
          selection_proof: selectionProof))

    msg.message.aggregate = node.attestationPool[].getAggregatedAttestation(
      slot, committee_index).valueOr:
        return

    msg.signature = block:
      let res = await validator.getAggregateAndProofSignature(
        fork, genesis_validators_root, msg.message)

      if res.isErr():
        warn "Unable to sign aggregate",
              validator = shortLog(validator), error_msg = res.error()
        return
      res.get()

    validator.doppelgangerActivity(msg.message.aggregate.data.slot.epoch)

    # Logged in the router
    discard await node.router.routeSignedAggregateAndProof(
      msg, checkSignature = false)
  except CatchableError as exc:
    # An error could happen here when the signature task fails - we must
    # not leak the exception because this is an asyncSpawn task
    warn "Error sending aggregate", err = exc.msg

proc sendAggregatedAttestations(
    node: BeaconNode, head: BlockRef, slot: Slot) {.async.} =
  # Aggregated attestations must be sent by members of the beacon committees for
  # the given slot, for which `is_aggregator` returns `true`.

  let
    shufflingRef = node.dag.getShufflingRef(head, slot.epoch, false).valueOr:
      warn "Cannot construct EpochRef for head, report bug",
        head = shortLog(head), slot
      return
    committees_per_slot = get_committee_count_per_slot(shufflingRef)

  for committee_index in get_committee_indices(committees_per_slot):
    for _, validator_index in
        get_beacon_committee(shufflingRef, slot, committee_index):
      let validator = node.getValidatorForDuties(validator_index, slot).valueOr:
        continue
      asyncSpawn signAndSendAggregate(node, validator, shufflingRef, slot,
                                      committee_index)

proc updateValidatorMetrics*(node: BeaconNode) =
  # Technically, this only needs to be done on epoch transitions and if there's
  # a reorg that spans an epoch transition, but it's easier to implement this
  # way for now.

  # We'll limit labelled metrics to the first 64, so that we don't overload
  # Prometheus.

  var total: Gwei
  var i = 0
  for _, v in node.attachedValidators[].validators:
    let balance =
      if v.index.isNone():
        0.Gwei
      elif v.index.get().uint64 >=
          getStateField(node.dag.headState, balances).lenu64:
        debug "Cannot get validator balance, index out of bounds",
          pubkey = shortLog(v.pubkey), index = v.index.get(),
          balances = getStateField(node.dag.headState, balances).len,
          stateRoot = getStateRoot(node.dag.headState)
        0.Gwei
      else:
        getStateField(node.dag.headState, balances).item(v.index.get())

    if i < 64:
      attached_validator_balance.set(
        balance.toGaugeValue, labelValues = [shortLog(v.pubkey)])

    inc i
    total += balance

  node.attachedValidatorBalanceTotal = total
  attached_validator_balance_total.set(total.toGaugeValue)

from std/times import epochTime

proc getValidatorRegistration(
    node: BeaconNode, validator: AttachedValidator, epoch: Epoch):
    Future[Result[SignedValidatorRegistrationV1, string]] {.async.} =
  let validatorIdx = validator.index.valueOr:
    # The validator index will be missing when the validator was not
    # activated for duties yet. We can safely skip the registration then.
    return

  let feeRecipient = node.getFeeRecipient(validator.pubkey, validatorIdx, epoch)
  let gasLimit = node.getGasLimit(validator.pubkey)
  var validatorRegistration = SignedValidatorRegistrationV1(
    message: ValidatorRegistrationV1(
      fee_recipient: ExecutionAddress(data: distinctBase(feeRecipient)),
      gas_limit: gasLimit,
      timestamp: epochTime().uint64,
      pubkey: validator.pubkey))

  let signature = await validator.getBuilderSignature(
    node.dag.cfg.genesisFork, validatorRegistration.message)

  debug "getValidatorRegistration: registering",
    validatorRegistration

  if signature.isErr:
    return err signature.error

  validatorRegistration.signature = signature.get

  return ok validatorRegistration

from std/sequtils import toSeq

proc registerValidators*(node: BeaconNode, epoch: Epoch) {.async.} =
  try:
    if  (not node.config.payloadBuilderEnable) or
        node.currentSlot.epoch < node.dag.cfg.BELLATRIX_FORK_EPOCH:
      return
    elif  node.config.payloadBuilderEnable and
          node.payloadBuilderRestClient.isNil:
      warn "registerValidators: node.config.payloadBuilderEnable and node.payloadBuilderRestClient.isNil"
      return

    const HttpOk = 200

    let restBuilderStatus = awaitWithTimeout(node.payloadBuilderRestClient.checkBuilderStatus(),
                                             BUILDER_STATUS_DELAY_TOLERANCE):
      debug "Timeout when obtaining builder status"
      return

    if restBuilderStatus.status != HttpOk:
      warn "registerValidators: specified builder or relay not available",
        builderUrl = node.config.payloadBuilderUrl,
        builderStatus = restBuilderStatus
      return

    # The async aspect of signing the registrations can cause the attached
    # validators to change during the loop.
    let attachedValidatorPubkeys =
      toSeq(node.attachedValidators[].validators.keys)

    const emptyNestedSeq = @[newSeq[SignedValidatorRegistrationV1](0)]
    # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#validator-registration
    # Seed with single empty inner list to avoid special cases
    var validatorRegistrations = emptyNestedSeq

    # Some relay networks disallow large request bodies, so split requests
    template addValidatorRegistration(
        validatorRegistration: SignedValidatorRegistrationV1) =
      const registrationValidatorChunkSize = 1000

      if validatorRegistrations[^1].len < registrationValidatorChunkSize:
        validatorRegistrations[^1].add validatorRegistration
      else:
        validatorRegistrations.add @[validatorRegistration]

    # First, check for VC-added keys; cheaper because provided pre-signed
    var nonExitedVcPubkeys: HashSet[ValidatorPubKey]
    if node.externalBuilderRegistrations.len > 0:
      withState(node.dag.headState):
        let currentEpoch = node.currentSlot().epoch
        for i in 0 ..< forkyState.data.validators.len:
          # https://github.com/ethereum/beacon-APIs/blob/v2.3.0/apis/validator/register_validator.yaml
          # "requests containing currently inactive or unknown validator
          # pubkeys will be accepted, as they may become active at a later
          # epoch" which means filtering is needed here, because including
          # any validators not pending or active may cause the request, as
          # a whole, to fail.
          let pubkey = forkyState.data.validators.item(i).pubkey
          if  pubkey in node.externalBuilderRegistrations and
              forkyState.data.validators.item(i).exit_epoch > currentEpoch:
            let signedValidatorRegistration =
              node.externalBuilderRegistrations[pubkey]
            nonExitedVcPubkeys.incl signedValidatorRegistration.message.pubkey
            addValidatorRegistration signedValidatorRegistration

    for key in attachedValidatorPubkeys:
      # Already included from VC
      if key in nonExitedVcPubkeys:
        warn "registerValidators: same validator registered by beacon node and validator client",
          pubkey = shortLog(key)
        continue

      # Time passed during awaits; REST keymanager API might have removed it
      if key notin node.attachedValidators[].validators:
        continue

      let validator = node.attachedValidators[].validators[key]

      if validator.index.isNone:
        continue

      # https://github.com/ethereum/builder-specs/blob/v0.3.0/apis/builder/validators.yaml
      # Builders should verify that `pubkey` corresponds to an active or
      # pending validator
      withState(node.dag.headState):
        if  distinctBase(validator.index.get) >=
            forkyState.data.validators.lenu64:
          continue

        if node.currentSlot().epoch >=
            forkyState.data.validators.item(validator.index.get).exit_epoch:
          continue

      if validator.externalBuilderRegistration.isSome:
        addValidatorRegistration validator.externalBuilderRegistration.get
      else:
        let validatorRegistration =
          await node.getValidatorRegistration(validator, epoch)
        if validatorRegistration.isErr:
          error "registerValidators: validatorRegistration failed",
                 validatorRegistration
          continue

        # Time passed during await; REST keymanager API might have removed it
        if key notin node.attachedValidators[].validators:
          continue

        node.attachedValidators[].validators[key].externalBuilderRegistration =
          Opt.some validatorRegistration.get
        addValidatorRegistration validatorRegistration.get

    if validatorRegistrations == emptyNestedSeq:
      return

    # TODO if there are too many chunks, could trigger DoS protections, so
    # might randomize order to accumulate cumulative coverage
    for chunkIdx in 0 ..< validatorRegistrations.len:
      let registerValidatorResult =
        awaitWithTimeout(
            node.payloadBuilderRestClient.registerValidator(
              validatorRegistrations[chunkIdx]),
            BUILDER_VALIDATOR_REGISTRATION_DELAY_TOLERANCE):
          error "Timeout when registering validator with builder"
          continue  # Try next batch regardless
      if HttpOk != registerValidatorResult.status:
        warn "registerValidators: Couldn't register validator with MEV builder",
          registerValidatorResult
  except CatchableError as exc:
    warn "registerValidators: exception",
      error = exc.msg

proc updateValidators(
    node: BeaconNode, validators: openArray[Validator]) =
  # Since validator indicies are stable, we only check the "updated" range -
  # checking all validators would significantly slow down this loop when there
  # are many inactive keys
  for i in node.dutyValidatorCount..validators.high:
    let
      v = node.attachedValidators[].getValidator(validators[i].pubkey).valueOr:
        continue
    v.index = Opt.some ValidatorIndex(i)

  node.dutyValidatorCount = validators.len

  for validator in node.attachedValidators[]:
    # Check if any validators have been activated
    if validator.needsUpdate and validator.index.isSome():
      # Activation epoch can change after index is assigned..
      let index = validator.index.get()
      if index < validators.lenu64:
        validator.updateValidator(
          Opt.some(ValidatorAndIndex(
            index: index, validator: validators[int index]
          )))

proc handleValidatorDuties*(node: BeaconNode, lastSlot, slot: Slot) {.async.} =
  ## Perform validator duties - create blocks, vote and aggregate existing votes
  if node.attachedValidators[].count == 0:
    # Nothing to do because we have no validator attached
    return

  # The dag head might be updated by sync while we're working due to the
  # await calls, thus we use a local variable to keep the logic straight here
  var head = node.dag.head
  case node.isSynced(head)
  of SyncStatus.unsynced:
    info "Beacon node not in sync; skipping validator duties for now",
      slot, headSlot = head.slot

    # Rewards will be growing though, as we sync..
    updateValidatorMetrics(node)

    return

  of SyncStatus.optimistic:
    info "Execution client not in sync; skipping validator duties for now",
      slot, headSlot = head.slot

    # Rewards will be growing though, as we sync..
    updateValidatorMetrics(node)

    return
  of SyncStatus.synced:
    discard # keep going

  withState(node.dag.headState):
    node.updateValidators(forkyState.data.validators.asSeq())

  var curSlot = lastSlot + 1

  # Start by checking if there's work we should have done in the past that we
  # can still meaningfully do
  while curSlot < slot:
    notice "Catching up on validator duties",
      curSlot = shortLog(curSlot),
      lastSlot = shortLog(lastSlot),
      slot = shortLog(slot)

    # For every slot we're catching up, we'll propose then send
    # attestations - head should normally be advancing along the same branch
    # in this case
    head = await handleProposal(node, head, curSlot)

    # For each slot we missed, we need to send out attestations - if we were
    # proposing during this time, we'll use the newly proposed head, else just
    # keep reusing the same - the attestation that goes out will actually
    # rewind the state to what it looked like at the time of that slot
    handleAttestations(node, head, curSlot)

    curSlot += 1

  let
    newHead = await handleProposal(node, head, slot)
    didSubmitBlock = (newHead != head)
  head = newHead

  let
    # The latest point in time when we'll be sending out attestations
    attestationCutoff = node.beaconClock.fromNow(slot.attestation_deadline())

  if attestationCutoff.inFuture:
    debug "Waiting to send attestations",
      head = shortLog(head),
      attestationCutoff = shortLog(attestationCutoff.offset)

    # Wait either for the block or the attestation cutoff time to arrive
    if await node.consensusManager[].expectBlock(slot)
        .withTimeout(attestationCutoff.offset):
      # The expected block arrived (or expectBlock was called again which
      # shouldn't happen as this is the only place we use it) - in our async
      # loop however, we might have been doing other processing that caused delays
      # here so we'll cap the waiting to the time when we would have sent out
      # attestations had the block not arrived.
      # An opposite case is that we received (or produced) a block that has
      # not yet reached our neighbours. To protect against our attestations
      # being dropped (because the others have not yet seen the block), we'll
      # impose a minimum delay of 2000ms. The delay is enforced only when we're
      # not hitting the "normal" cutoff time for sending out attestations.
      # An earlier delay of 250ms has proven to be not enough, increasing the
      # risk of losing attestations, and with growing block sizes, 1000ms
      # started to be risky as well.
      # Regardless, because we "just" received the block, we'll impose the
      # delay.

      # Take into consideration chains with a different slot time
      const afterBlockDelay = nanos(attestationSlotOffset.nanoseconds div 2)
      let
        afterBlockTime = node.beaconClock.now() + afterBlockDelay
        afterBlockCutoff = node.beaconClock.fromNow(
          min(afterBlockTime, slot.attestation_deadline() + afterBlockDelay))

      if afterBlockCutoff.inFuture:
        debug "Got block, waiting to send attestations",
          head = shortLog(head),
          afterBlockCutoff = shortLog(afterBlockCutoff.offset)

        await sleepAsync(afterBlockCutoff.offset)

    # Time passed - we might need to select a new head in that case
    node.consensusManager[].updateHead(slot)
    head = node.dag.head

  static: doAssert attestationSlotOffset == syncCommitteeMessageSlotOffset

  handleAttestations(node, head, slot)
  handleSyncCommitteeMessages(node, head, slot)

  updateValidatorMetrics(node) # the important stuff is done, update the vanity numbers

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.4/specs/phase0/validator.md#broadcast-aggregate
  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.4/specs/altair/validator.md#broadcast-sync-committee-contribution
  # Wait 2 / 3 of the slot time to allow messages to propagate, then collect
  # the result in aggregates
  static:
    doAssert aggregateSlotOffset == syncContributionSlotOffset, "Timing change?"
  let
    aggregateCutoff = node.beaconClock.fromNow(slot.aggregate_deadline())
  if aggregateCutoff.inFuture:
    debug "Waiting to send aggregate attestations",
      aggregateCutoff = shortLog(aggregateCutoff.offset)
    await sleepAsync(aggregateCutoff.offset)

  let sendAggregatedAttestationsFut =
    sendAggregatedAttestations(node, head, slot)

  let handleSyncCommitteeContributionsFut =
    handleSyncCommitteeContributions(node, head, slot)

  await handleSyncCommitteeContributionsFut
  await sendAggregatedAttestationsFut

proc registerDuties*(node: BeaconNode, wallSlot: Slot) {.async.} =
  ## Register upcoming duties of attached validators with the duty tracker

  if node.attachedValidators[].count() == 0 or
      node.isSynced(node.dag.head) != SyncStatus.synced:
    # Nothing to do because we have no validator attached
    return

  let
    genesis_validators_root = node.dag.genesis_validators_root
    head = node.dag.head

  # Getting the slot signature is expensive but cached - in "normal" cases we'll
  # be getting the duties one slot at a time
  for slot in wallSlot ..< wallSlot + SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS:
    let
      shufflingRef = node.dag.getShufflingRef(head, slot.epoch, false).valueOr:
        warn "Cannot construct EpochRef for duties - report bug",
          head = shortLog(head), slot
        return
    let
      fork = node.dag.forkAtEpoch(slot.epoch)
      committees_per_slot = get_committee_count_per_slot(shufflingRef)

    for committee_index in get_committee_indices(committees_per_slot):
      let committee = get_beacon_committee(shufflingRef, slot, committee_index)

      for index_in_committee, validator_index in committee:
        let
          validator = node.getValidator(validator_index).valueOr:
            continue

          subnet_id = compute_subnet_for_attestation(
            committees_per_slot, slot, committee_index)
          slotSigRes = await validator.getSlotSignature(
            fork, genesis_validators_root, slot)
        if slotSigRes.isErr():
          error "Unable to create slot signature",
                validator = shortLog(validator),
                error_msg = slotSigRes.error()
          continue
        let isAggregator = is_aggregator(committee.lenu64, slotSigRes.get())

        node.consensusManager[].actionTracker.registerDuty(
          slot, subnet_id, validator_index, isAggregator)
