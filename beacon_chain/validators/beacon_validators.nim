# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# This module is responsible for handling beacon node validators, ie those that
# that are running directly in the beacon node and not in a separate validator
# client process - we name these "beacon validators" while those running
# outside are "client validators".
# This module also contains implementation logic for the REST validator API.

import
  # Standard library
  std/[os, tables],

  # Nimble packages
  stew/[assign2, byteutils],
  chronos, metrics,
  chronicles, chronicles/timings,
  json_serialization/std/[options, sets, net],
  eth/db/kvstore,
  web3/primitives,
  kzg4844,

  # Local modules
  ../spec/datatypes/[phase0, altair, bellatrix],
  ../spec/[
    eth2_merkleization, forks, helpers, network, signatures, state_transition,
    validator],
  ../consensus_object_pools/[
    spec_cache, blockchain_dag, block_clearance, attestation_pool, exit_pool,
    sync_committee_msg_pool, consensus_manager],
  ../el/el_manager,
  ../networking/eth2_network,
  ../sszdump, ../sync/sync_manager,
  ../gossip_processing/block_processor,
  ".."/[conf, beacon_clock, beacon_node],
  "."/[
    keystore_management, slashing_protection, validator_duties, validator_pool],
  ".."/spec/mev/[rest_capella_mev_calls, rest_deneb_mev_calls]

from std/sequtils import mapIt
from eth/async_utils import awaitWithTimeout

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
  ForkedBlockResult =
    Result[tuple[blck: ForkedBeaconBlock,
                 blockValue: Wei,
                 blobsBundleOpt: Opt[BlobsBundle]], string]
  BlindedBlockResult[SBBB] =
    Result[tuple[blindedBlckPart: SBBB, blockValue: UInt256], string]
  BlockProposalBidFutures[SBBB] = object
    engineBidAvailable: bool
    engineBlockFut: Future[ForkedBlockResult]
    builderBidAvailable: bool
    payloadBuilderBidFut: Future[BlindedBlockResult[SBBB]]

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

proc addValidatorsFromWeb3Signer(node: BeaconNode, web3signerUrl: Web3SignerUrl, epoch: Epoch) {.async.} =
  let dynamicStores =
    try:
      let res = await queryValidatorsSource(web3signerUrl)
      if res.isErr():
        # Error is already reported via log warning.
        default(seq[KeystoreData])
      else:
        res.get()
    except CatchableError as exc:
      warn "Unexpected error happens while polling validator's source",
           error = $exc.name, reason = $exc.msg
      default(seq[KeystoreData])

  for keystore in dynamicStores:
    let
      data =
        withState(node.dag.headState):
          getValidator(forkyState.data.validators.asSeq(), keystore.pubkey)
      index =
        if data.isSome():
          Opt.some(data.get().index)
        else:
          Opt.none(ValidatorIndex)
      feeRecipient =
        node.consensusManager[].getFeeRecipient(keystore.pubkey, index, epoch)
      gasLimit = node.consensusManager[].getGasLimit(keystore.pubkey)
      v = node.attachedValidators[].addValidator(keystore, feeRecipient,
                                                 gasLimit)
    v.updateValidator(data)

proc addValidators*(node: BeaconNode) =
  info "Loading validators", validatorsDir = node.config.validatorsDir(),
                keystore_cache_available = not(isNil(node.keystoreCache))
  let epoch = node.currentSlot().epoch

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

      v = node.attachedValidators[].addValidator(keystore, feeRecipient,
                                                 gasLimit)
    v.updateValidator(data)

  try:
    # We use `allFutures` because all failures are already reported as
    # user-visible warnings in `queryValidatorsSource`.
    # We don't consider them fatal because the Web3Signer may be experiencing
    # a temporary hiccup that will be resolved later.
    waitFor allFutures(mapIt(node.config.web3SignerUrls,
                             node.addValidatorsFromWeb3Signer(it, epoch)))
  except CatchableError as err:
    # This should never happen because all errors are handled within
    # `addValidatorsFromWeb3Signer`. Furthermore, the code above is
    # using `allFutures` which is guaranteed to not raise exceptions.
    # Nevertheless, we need it to make the compiler's exception tracking happy.
    debug "Unexpected error while fetching the list of validators from a remote signer",
           err = err.msg

proc pollForDynamicValidators*(node: BeaconNode,
                               web3signerUrl: Web3SignerUrl,
                               intervalInSeconds: int) {.async.} =
  if intervalInSeconds == 0:
    return

  proc addValidatorProc(keystore: KeystoreData) =
    let
      epoch = node.currentSlot().epoch
      index = Opt.none(ValidatorIndex)
      feeRecipient =
        node.consensusManager[].getFeeRecipient(keystore.pubkey, index, epoch)
      gasLimit =
        node.consensusManager[].getGasLimit(keystore.pubkey)
    discard node.attachedValidators[].addValidator(keystore, feeRecipient,
                                                   gasLimit)

  var
    timeout = seconds(intervalInSeconds)
    exitLoop = false

  while not(exitLoop):
    exitLoop =
      try:
        await sleepAsync(timeout)
        timeout =
          block:
            let res = await queryValidatorsSource(web3signerUrl)
            if res.isOk():
              let keystores = res.get()
              debug "Validators source has been polled for validators",
                    keystores_found = len(keystores),
                    web3signer_url = web3signerUrl.url
              node.attachedValidators.updateDynamicValidators(web3signerUrl,
                                                              keystores,
                                                              addValidatorProc)
              seconds(intervalInSeconds)
            else:
              # In case of error we going to repeat our call with much smaller
              # interval.
              seconds(5)
        false
      except CancelledError:
        true

proc getValidator*(node: BeaconNode, idx: ValidatorIndex): Opt[AttachedValidator] =
  let key = ? node.dag.validatorKey(idx)
  node.attachedValidators[].getValidator(key.toPubKey())

proc getValidatorForDuties*(
    node: BeaconNode, idx: ValidatorIndex, slot: Slot,
    slashingSafe = false): Opt[AttachedValidator] =
  let key = ? node.dag.validatorKey(idx)

  node.attachedValidators[].getValidatorForDuties(
    key.toPubKey(), slot, slashingSafe)

proc isSynced*(node: BeaconNode, head: BlockRef): bool =
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
  not wallSlot.afterGenesis or
    head.slot + node.config.syncHorizon >= wallSlot.slot

proc handleLightClientUpdates*(node: BeaconNode, slot: Slot) {.async.} =
  template pool: untyped = node.lightClientPool[]

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

      let
        finalized_slot =
          forkyFinalityUpdate.finalized_header.beacon.slot
        has_supermajority =
          hasSupermajoritySyncParticipation(num_active_participants.uint64)
        newFinality =
          if finalized_slot > pool.latestForwardedFinalitySlot:
            true
          elif finalized_slot < pool.latestForwardedFinalitySlot:
            false
          elif pool.latestForwardedFinalityHasSupermajority:
            false
          else:
            has_supermajority
      if newFinality:
        template msg(): auto = forkyFinalityUpdate
        let sendResult =
          await node.network.broadcastLightClientFinalityUpdate(msg)

        # Optimization for message with ephemeral validity, whether sent or not
        pool.latestForwardedFinalitySlot = finalized_slot
        pool.latestForwardedFinalityHasSupermajority = has_supermajority

        if sendResult.isOk:
          beacon_light_client_finality_updates_sent.inc()
          notice "LC finality update sent", message = shortLog(msg)
        else:
          warn "LC finality update failed to send",
            error = sendResult.error()

      let attested_slot = forkyFinalityUpdate.attested_header.beacon.slot
      if attested_slot > pool.latestForwardedOptimisticSlot:
        let msg = forkyFinalityUpdate.toOptimistic
        let sendResult =
          await node.network.broadcastLightClientOptimisticUpdate(msg)

        # Optimization for message with ephemeral validity, whether sent or not
        pool.latestForwardedOptimisticSlot = attested_slot

        if sendResult.isOk:
          beacon_light_client_optimistic_updates_sent.inc()
          notice "LC optimistic update sent", message = shortLog(msg)
        else:
          warn "LC optimistic update failed to send",
            error = sendResult.error()

proc createAndSendAttestation(node: BeaconNode,
                              fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              registered: RegisteredAttestation,
                              subnet_id: SubnetId) {.async.} =
  try:
    let
      signature = block:
        let res = await registered.validator.getAttestationSignature(
          fork, genesis_validators_root, registered.data)
        if res.isErr():
          warn "Unable to sign attestation",
                validator = shortLog(registered.validator),
                attestationData = shortLog(registered.data),
                error_msg = res.error()
          return
        res.get()
      attestation = registered.toAttestation(signature)

    registered.validator.doppelgangerActivity(attestation.data.slot.epoch)

    # Logged in the router
    let res = await node.router.routeAttestation(
      attestation, subnet_id, checkSignature = false)
    if not res.isOk():
      return

    if node.config.dumpEnabled:
      dump(
        node.config.dumpDirOutgoing, attestation.data,
        registered.validator.pubkey)
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
  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/validator.md#executionpayload

  let feeRecipient = block:
    let pubkey = node.dag.validatorKey(validator_index)
    if pubkey.isNone():
      warn "Cannot get proposer pubkey, bug?", validator_index
      default(Eth1Address)
    else:
      node.getFeeRecipient(pubkey.get().toPubKey(), validator_index, epoch)

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

    info "Requesting engine payload",
      beaconHead = shortLog(beaconHead.blck),
      executionHead = shortLog(executionHead),
      validatorIndex = validator_index,
      feeRecipient = $feeRecipient

    let payload = (await node.elManager.getPayload(
        PayloadType, beaconHead.blck.bid.root, executionHead, latestSafe,
        latestFinalized, timestamp, random, feeRecipient, withdrawals)).valueOr:
      warn "Failed to obtain execution payload from EL",
             executionHeadBlock = executionHead
      return Opt.none(PayloadType)

    return Opt.some payload
  except CatchableError as exc:
    beacon_block_payload_errors.inc()
    warn "Error creating non-empty execution payload",
      msg = exc.msg
    return Opt.none PayloadType

proc makeBeaconBlockForHeadAndSlot*(
    PayloadType: type ForkyExecutionPayloadForSigning,
    node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot,

    # These parameters are for the builder API
    execution_payload: Opt[PayloadType],
    transactions_root: Opt[Eth2Digest],
    execution_payload_root: Opt[Eth2Digest],
    withdrawals_root: Opt[Eth2Digest],
    kzg_commitments: Opt[KzgCommitments]):
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
                PayloadType.kind >= ConsensusFork.Capella:
            let withdrawals = List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD](
              get_expected_withdrawals(forkyState.data))
            if  withdrawals_root.isNone or
                hash_tree_root(withdrawals) != withdrawals_root.get:
              # If engine API returned a block, will use that
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
    # TODO workaround for https://github.com/arnetheduck/nim-results/issues/34
    payloadRes = await payloadFut
    payload = payloadRes.valueOr:
      beacon_block_production_errors.inc()
      warn "Unable to get execution payload. Skipping block proposal",
        slot, validator_index
      return err("Unable to get execution payload")

  let blck = makeBeaconBlock(
      node.dag.cfg,
      state[],
      validator_index,
      randao_reveal,
      eth1Proposal.vote,
      graffiti,
      attestations,
      eth1Proposal.deposits,
      exits,
      node.syncCommitteeMsgPool[].produceSyncAggregate(head.bid, slot),
      payload,
      noRollback, # Temporary state - no need for rollback
      cache,
      verificationFlags = {},
      transactions_root = transactions_root,
      execution_payload_root = execution_payload_root,
      kzg_commitments = kzg_commitments).mapErr do (error: cstring) -> string:
    # This is almost certainly a bug, but it's complex enough that there's a
    # small risk it might happen even when most proposals succeed - thus we
    # log instead of asserting
    beacon_block_production_errors.inc()
    warn "Cannot create block for proposal",
      slot, head = shortLog(head), error
    $error

  var blobsBundleOpt = Opt.none(BlobsBundle)
  when payload is deneb.ExecutionPayloadForSigning:
    blobsBundleOpt = Opt.some(payload.blobsBundle)
  return if blck.isOk:
    ok((blck.get, payload.blockValue, blobsBundleOpt))
  else:
    err(blck.error)

proc makeBeaconBlockForHeadAndSlot*(
    PayloadType: type ForkyExecutionPayloadForSigning, node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot):
    Future[ForkedBlockResult] =
  return makeBeaconBlockForHeadAndSlot(
    PayloadType, node, randao_reveal, validator_index, graffiti, head, slot,
    execution_payload = Opt.none(PayloadType),
    transactions_root = Opt.none(Eth2Digest),
    execution_payload_root = Opt.none(Eth2Digest),
    withdrawals_root = Opt.none(Eth2Digest),
    kzg_commitments = Opt.none(KzgCommitments))

proc getBlindedExecutionPayload[
    EPH: capella.ExecutionPayloadHeader |
         deneb_mev.BlindedExecutionPayloadAndBlobsBundle](
    node: BeaconNode, payloadBuilderClient: RestClientRef, slot: Slot,
    executionBlockRoot: Eth2Digest, pubkey: ValidatorPubKey):
    Future[BlindedBlockResult[EPH]] {.async.} =
  # Not ideal to use `when` where instead of splitting into separate functions,
  # but Nim doesn't overload on generic EPH type parameter.
  when EPH is capella.ExecutionPayloadHeader:
    let blindedHeader = awaitWithTimeout(
      payloadBuilderClient.getHeaderCapella(slot, executionBlockRoot, pubkey),
      BUILDER_PROPOSAL_DELAY_TOLERANCE):
        return err "Timeout obtaining Capella blinded header from builder"
  elif EPH is deneb_mev.BlindedExecutionPayloadAndBlobsBundle:
    let blindedHeader = awaitWithTimeout(
      payloadBuilderClient.getHeaderDeneb(slot, executionBlockRoot, pubkey),
      BUILDER_PROPOSAL_DELAY_TOLERANCE):
        return err "Timeout obtaining Deneb blinded header and blob bundle from builder"
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

    when EPH is capella.ExecutionPayloadHeader:
      return ok((
        blindedBlckPart: blindedHeader.data.data.message.header,
        blockValue: blindedHeader.data.data.message.value))
    elif EPH is deneb_mev.BlindedExecutionPayloadAndBlobsBundle:
      template builderBid: untyped = blindedHeader.data.data.message
      return ok((
        blindedBlckPart: EPH(
          execution_payload_header: builderBid.header,
          blob_kzg_commitments: builderBid.blob_kzg_commitments),
        blockValue: builderBid.value))
    else:
      static: doAssert false

from ./message_router_mev import
  copyFields, getFieldNames, unblindAndRouteBlockMEV

func constructSignableBlindedBlock[T: capella_mev.SignedBlindedBeaconBlock](
    blck: capella.BeaconBlock,
    executionPayloadHeader: capella.ExecutionPayloadHeader): T =
  # Leaves signature field default, to be filled in by caller
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

proc constructSignableBlindedBlock[T: deneb_mev.SignedBlindedBeaconBlock](
    blck: deneb.BeaconBlock,
    blindedBundle: deneb_mev.BlindedExecutionPayloadAndBlobsBundle): T =
  # Leaves signature field default, to be filled in by caller
  const
    blckFields = getFieldNames(typeof(blck))
    blckBodyFields = getFieldNames(typeof(blck.body))

  var blindedBlock: T

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#block-proposal
  copyFields(blindedBlock.message, blck, blckFields)
  copyFields(blindedBlock.message.body, blck.body, blckBodyFields)
  assign(
    blindedBlock.message.body.execution_payload_header,
    blindedBundle.execution_payload_header)
  assign(
    blindedBlock.message.body.blob_kzg_commitments,
    blindedBundle.blob_kzg_commitments)

  blindedBlock

func constructPlainBlindedBlock[T: capella_mev.BlindedBeaconBlock](
    blck: ForkyBeaconBlock,
    executionPayloadHeader: capella.ExecutionPayloadHeader): T =
  # https://github.com/nim-lang/Nim/issues/23020 workaround
  static: doAssert T is capella_mev.BlindedBeaconBlock

  const
    blckFields = getFieldNames(typeof(blck))
    blckBodyFields = getFieldNames(typeof(blck.body))

  var blindedBlock: T

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#block-proposal
  copyFields(blindedBlock, blck, blckFields)
  copyFields(blindedBlock.body, blck.body, blckBodyFields)
  assign(blindedBlock.body.execution_payload_header, executionPayloadHeader)

  blindedBlock

func constructPlainBlindedBlock[T: deneb_mev.BlindedBeaconBlock](
    blck: ForkyBeaconBlock,
    blindedBundle: deneb_mev.BlindedExecutionPayloadAndBlobsBundle): T =
  # https://github.com/nim-lang/Nim/issues/23020 workaround
  static: doAssert T is deneb_mev.BlindedBeaconBlock

  const
    blckFields = getFieldNames(typeof(blck))
    blckBodyFields = getFieldNames(typeof(blck.body))

  var blindedBlock: T

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#block-proposal
  copyFields(blindedBlock, blck, blckFields)
  copyFields(blindedBlock.body, blck.body, blckBodyFields)
  assign(
    blindedBlock.body.execution_payload_header,
    blindedBundle.execution_payload_header)
  assign(
    blindedBlock.body.blob_kzg_commitments,
    blindedBundle.blob_kzg_commitments)

  blindedBlock

proc blindedBlockCheckSlashingAndSign[
    T:
      capella_mev.SignedBlindedBeaconBlock |
      deneb_mev.SignedBlindedBeaconBlock](
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
      signingRoot = shortLog(signingRoot), validator = validator.pubkey,
      slot = slot, existingProposal = notSlashable.error
    return err("MEV proposal would be slashable: " & $notSlashable.error)

  var blindedBlock = nonsignedBlindedBlock
  blindedBlock.signature = block:
    let res = await validator.getBlockSignature(
      fork, genesis_validators_root, slot, blockRoot, blindedBlock.message)
    if res.isErr():
      return err("Unable to sign block: " & res.error())
    res.get()

  return ok blindedBlock

proc getUnsignedBlindedBeaconBlock[
    T: capella_mev.SignedBlindedBeaconBlock |
       deneb_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, slot: Slot,
    validator_index: ValidatorIndex, forkedBlock: ForkedBeaconBlock,
    executionPayloadHeader: capella.ExecutionPayloadHeader |
                            deneb_mev.BlindedExecutionPayloadAndBlobsBundle):
    Result[T, string] =
  withBlck(forkedBlock):
    when consensusFork >= ConsensusFork.Capella:
      when not (
          (T is deneb_mev.SignedBlindedBeaconBlock and
           consensusFork == ConsensusFork.Deneb) or
          (T is capella_mev.SignedBlindedBeaconBlock and
           consensusFork == ConsensusFork.Capella)):
        return err("getUnsignedBlindedBeaconBlock: mismatched block/payload types")
      else:
        return ok constructSignableBlindedBlock[T](
          forkyBlck, executionPayloadHeader)
    else:
      return err("getUnsignedBlindedBeaconBlock: attempt to construct pre-Capella blinded block")

proc getBlindedBlockParts[
    EPH: capella.ExecutionPayloadHeader |
         deneb_mev.BlindedExecutionPayloadAndBlobsBundle](
    node: BeaconNode, payloadBuilderClient: RestClientRef, head: BlockRef,
    pubkey: ValidatorPubKey, slot: Slot, randao: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes):
    Future[Result[(EPH, UInt256, ForkedBeaconBlock), string]] {.async.} =
  let
    executionBlockRoot = node.dag.loadExecutionBlockHash(head)
    executionPayloadHeader =
      try:
        awaitWithTimeout(
            getBlindedExecutionPayload[EPH](
              node, payloadBuilderClient, slot, executionBlockRoot, pubkey),
            BUILDER_PROPOSAL_DELAY_TOLERANCE):
          BlindedBlockResult[EPH].err("getBlindedExecutionPayload timed out")
      except RestDecodingError as exc:
        BlindedBlockResult[EPH].err(
          "getBlindedExecutionPayload REST decoding error: " & exc.msg)
      except CatchableError as exc:
        BlindedBlockResult[EPH].err(
          "getBlindedExecutionPayload error: " & exc.msg)

  if executionPayloadHeader.isErr:
    warn "Could not obtain blinded execution payload header",
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
  #
  # This doesn't have withdrawals, which each node has regardless of engine or
  # builder API. makeBeaconBlockForHeadAndSlot fills it in later.
  when EPH is capella.ExecutionPayloadHeader:
    type PayloadType = capella.ExecutionPayloadForSigning
    template actualEPH: untyped = executionPayloadHeader.get.blindedBlckPart
    let withdrawals_root =
      Opt.some executionPayloadHeader.get.blindedBlckPart.withdrawals_root
    const kzg_commitments = Opt.none KzgCommitments

    var shimExecutionPayload: PayloadType
    copyFields(
      shimExecutionPayload.executionPayload,
      executionPayloadHeader.get.blindedBlckPart, getFieldNames(EPH))
  elif EPH is deneb_mev.BlindedExecutionPayloadAndBlobsBundle:
    type PayloadType = deneb.ExecutionPayloadForSigning
    template actualEPH: untyped =
      executionPayloadHeader.get.blindedBlckPart.execution_payload_header
    let
      withdrawals_root = Opt.some actualEPH.withdrawals_root
      kzg_commitments = Opt.some(
        executionPayloadHeader.get.blindedBlckPart.blob_kzg_commitments)

    var shimExecutionPayload: PayloadType
    type DenebEPH =
      deneb_mev.BlindedExecutionPayloadAndBlobsBundle.execution_payload_header
    copyFields(
      shimExecutionPayload.executionPayload, actualEPH, getFieldNames(DenebEPH))
  else:
    static: doAssert false

  let newBlock = await makeBeaconBlockForHeadAndSlot(
    PayloadType, node, randao, validator_index, graffiti, head, slot,
    execution_payload = Opt.some shimExecutionPayload,
    transactions_root = Opt.some actualEPH.transactions_root,
    execution_payload_root = Opt.some hash_tree_root(actualEPH),
    withdrawals_root = withdrawals_root,
    kzg_commitments = kzg_commitments)

  if newBlock.isErr():
    # Haven't committed to the MEV block, so allow EL fallback.
    return err(newBlock.error)  # already logged elsewhere!

  let forkedBlck = newBlock.get()

  return ok(
    (executionPayloadHeader.get.blindedBlckPart,
     executionPayloadHeader.get.blockValue,
     forkedBlck.blck))

proc getBuilderBid[
    SBBB: capella_mev.SignedBlindedBeaconBlock |
          deneb_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, payloadBuilderClient: RestClientRef, head: BlockRef,
    validator_pubkey: ValidatorPubKey, slot: Slot, randao: ValidatorSig,
    validator_index: ValidatorIndex):
    Future[BlindedBlockResult[SBBB]] {.async.} =
  ## Returns the unsigned blinded block obtained from the Builder API.
  ## Used by the BN's own validators, but not the REST server
  when SBBB is capella_mev.SignedBlindedBeaconBlock:
    type EPH = capella.ExecutionPayloadHeader
  elif SBBB is deneb_mev.SignedBlindedBeaconBlock:
    type EPH = deneb_mev.BlindedExecutionPayloadAndBlobsBundle
  else:
    static: doAssert false

  let blindedBlockParts = await getBlindedBlockParts[EPH](
    node, payloadBuilderClient, head, validator_pubkey, slot, randao,
    validator_index, node.graffitiBytes)
  if blindedBlockParts.isErr:
    # Not signed yet, fine to try to fall back on EL
    beacon_block_builder_missed_with_fallback.inc()
    return err blindedBlockParts.error()

  # These, together, get combined into the blinded block for signing and
  # proposal through the relay network.
  let (executionPayloadHeader, bidValue, forkedBlck) = blindedBlockParts.get

  let unsignedBlindedBlock = getUnsignedBlindedBeaconBlock[SBBB](
    node, slot, validator_index, forkedBlck, executionPayloadHeader)

  if unsignedBlindedBlock.isErr:
    return err unsignedBlindedBlock.error()

  return ok (unsignedBlindedBlock.get, bidValue)

proc proposeBlockMEV(
    node: BeaconNode, payloadBuilderClient: RestClientRef,
    blindedBlock: capella_mev.SignedBlindedBeaconBlock |
                  deneb_mev.SignedBlindedBeaconBlock):
    Future[Result[BlockRef, string]] {.async.} =
  let unblindedBlockRef = await node.unblindAndRouteBlockMEV(
    payloadBuilderClient, blindedBlock)
  return if unblindedBlockRef.isOk and unblindedBlockRef.get.isSome:
    beacon_blocks_proposed.inc()
    ok(unblindedBlockRef.get.get)
  else:
    # unblindedBlockRef.isOk and unblindedBlockRef.get.isNone indicates that
    # the block failed to validate and integrate into the DAG, which for the
    # purpose of this return value, is equivalent. It's used to drive Beacon
    # REST API output.
    #
    # https://collective.flashbots.net/t/post-mortem-april-3rd-2023-mev-boost-relay-incident-and-related-timing-issue/1540
    # has caused false positives, because
    # "A potential mitigation to this attack is to introduce a cutoff timing
    # into the proposer's slot whereafter this time (e.g. 3 seconds) the relay
    # will no longer return a block to the proposer. Relays began to roll out
    # this mitigation in the evening of April 3rd UTC time with a 2 second
    # cutoff, and notified other relays to do the same. After receiving
    # credible reports of honest validators missing their slots the suggested
    # timing cutoff was increased to 3 seconds."
    let errMsg =
      if unblindedBlockRef.isErr:
        unblindedBlockRef.error
      else:
        "Unblinded block not returned to proposer"
    err errMsg

func isEFMainnet(cfg: RuntimeConfig): bool =
  cfg.DEPOSIT_CHAIN_ID == 1 and cfg.DEPOSIT_NETWORK_ID == 1

proc makeBlindedBeaconBlockForHeadAndSlot*[BBB: ForkyBlindedBeaconBlock](
    node: BeaconNode, payloadBuilderClient: RestClientRef,
    randao_reveal: ValidatorSig, validator_index: ValidatorIndex,
    graffiti: GraffitiBytes, head: BlockRef, slot: Slot):
    Future[BlindedBlockResult[BBB]] {.async.} =
  ## Requests a beacon node to produce a valid blinded block, which can then be
  ## signed by a validator. A blinded block is a block with only a transactions
  ## root, rather than a full transactions list.
  ##
  ## This function is used by the validator client, but not the beacon node for
  ## its own validators.
  when BBB is deneb_mev.BlindedBeaconBlock:
    type EPH = deneb_mev.BlindedExecutionPayloadAndBlobsBundle
  elif BBB is capella_mev.BlindedBeaconBlock:
    type EPH = capella.ExecutionPayloadHeader
  else:
    static: doAssert false

  let
    pubkey =
      # Relevant state for knowledge of validators
      withState(node.dag.headState):
        if node.dag.cfg.isEFMainnet and livenessFailsafeInEffect(
            forkyState.data.block_roots.data, forkyState.data.slot):
          # It's head block's slot which matters here, not proposal slot
          return err("Builder API liveness failsafe in effect")

        if distinctBase(validator_index) >= forkyState.data.validators.lenu64:
          debug "makeBlindedBeaconBlockForHeadAndSlot: invalid validator index",
            head = shortLog(head),
            validator_index,
            validators_len = forkyState.data.validators.len
          return err("Invalid validator index")

        forkyState.data.validators.item(validator_index).pubkey

    blindedBlockParts = await getBlindedBlockParts[EPH](
      node, payloadBuilderClient, head, pubkey, slot, randao_reveal,
      validator_index, graffiti)
  if blindedBlockParts.isErr:
    # Don't try EL fallback -- VC specifically requested a blinded block
    return err("Unable to create blinded block")

  let (executionPayloadHeader, bidValue, forkedBlck) = blindedBlockParts.get
  withBlck(forkedBlck):
    when consensusFork >= ConsensusFork.Capella:
      when ((consensusFork == ConsensusFork.Deneb and
             EPH is deneb_mev.BlindedExecutionPayloadAndBlobsBundle) or
            (consensusFork == ConsensusFork.Capella and
             EPH is capella.ExecutionPayloadHeader)):
        return ok (constructPlainBlindedBlock[BBB](
          forkyBlck, executionPayloadHeader), bidValue)
      else:
        return err("makeBlindedBeaconBlockForHeadAndSlot: mismatched block/payload types")
    else:
      return err("Attempt to create pre-Capella blinded block")

proc collectBidFutures(
    SBBB: typedesc, EPS: typedesc, node: BeaconNode,
    payloadBuilderClient: RestClientRef, validator_pubkey: ValidatorPubKey,
    validator_index: ValidatorIndex, graffitiBytes: GraffitiBytes,
    head: BlockRef, slot: Slot,
    randao: ValidatorSig): Future[BlockProposalBidFutures[SBBB]] {.async.} =
  let usePayloadBuilder =
    if not payloadBuilderClient.isNil:
      withState(node.dag.headState):
        # Head slot, not proposal slot, matters here
        # TODO it might make some sense to allow use of builder API if local
        # EL fails -- i.e. it would change priorities, so any block from the
        # execution layer client would override builder API. But it seems an
        # odd requirement to produce no block at all in those conditions.
        (not node.dag.cfg.isEFMainnet) or (not livenessFailsafeInEffect(
          forkyState.data.block_roots.data, forkyState.data.slot))
    else:
      false

  let
    payloadBuilderBidFut =
      if usePayloadBuilder:
        when not (EPS is bellatrix.ExecutionPayloadForSigning):
          getBuilderBid[SBBB](node, payloadBuilderClient, head,
                              validator_pubkey, slot, randao, validator_index)
        else:
          let fut = newFuture[BlindedBlockResult[SBBB]]("builder-bid")
          fut.complete(BlindedBlockResult[SBBB].err(
            "Bellatrix Builder API unsupported"))
          fut
      else:
        let fut = newFuture[BlindedBlockResult[SBBB]]("builder-bid")
        fut.complete(BlindedBlockResult[SBBB].err(
          "either payload builder disabled or liveness failsafe active"))
        fut
    engineBlockFut = makeBeaconBlockForHeadAndSlot(
      EPS, node, randao, validator_index, graffitiBytes, head, slot)

  # getBuilderBid times out after BUILDER_PROPOSAL_DELAY_TOLERANCE, with 1 more
  # second for remote validators. makeBeaconBlockForHeadAndSlot times out after
  # 1 second.
  await allFutures(payloadBuilderBidFut, engineBlockFut)
  doAssert payloadBuilderBidFut.finished and engineBlockFut.finished

  let builderBidAvailable =
    if payloadBuilderBidFut.completed:
      if payloadBuilderBidFut.read().isOk:
        true
      elif usePayloadBuilder:
        info "Payload builder error",
          slot, head = shortLog(head), validator = shortLog(validator_pubkey),
          err = payloadBuilderBidFut.read().error()
        false
      else:
        # Effectively the same case, but without the log message
        false
    else:
      info "Payload builder bid future failed",
        slot, head = shortLog(head), validator = shortLog(validator_pubkey),
        err = payloadBuilderBidFut.error.msg
      false

  let engineBidAvailable =
    if engineBlockFut.completed:
      if engineBlockFut.read.isOk:
        true
      else:
        info "Engine block building error",
          slot, head = shortLog(head), validator = shortLog(validator_pubkey),
          err = engineBlockFut.read.error()
        false
    else:
      info "Engine block building failed",
        slot, head = shortLog(head), validator = shortLog(validator_pubkey),
        err = engineBlockFut.error.msg
      false

  return BlockProposalBidFutures[SBBB](
    engineBidAvailable: engineBidAvailable,
    engineBlockFut: engineBlockFut,
    builderBidAvailable: builderBidAvailable,
    payloadBuilderBidFut: payloadBuilderBidFut)

func builderBetterBid(
    localBlockValueBoost: uint8, builderValue: UInt256, engineValue: Wei): bool =
  # Scale down to ensure no overflows; if lower few bits would have been
  # otherwise decisive, was close enough not to matter. Calibrate to let
  # uint8-range percentages avoid overflowing.
  const scalingBits = 10
  static: doAssert 1 shl scalingBits >
    high(typeof(localBlockValueBoost)).uint16 + 100
  let
    scaledBuilderValue = (builderValue shr scalingBits) * 100
    scaledEngineValue = engineValue shr scalingBits
  scaledBuilderValue >
    scaledEngineValue * (localBlockValueBoost.uint16 + 100).u256

proc proposeBlockAux(
    SBBB: typedesc, EPS: typedesc, node: BeaconNode,
    validator: AttachedValidator, validator_index: ValidatorIndex,
    head: BlockRef, slot: Slot, randao: ValidatorSig, fork: Fork,
    genesis_validators_root: Eth2Digest,
    localBlockValueBoost: uint8): Future[BlockRef] {.async.} =
  var payloadBuilderClient: RestClientRef
  let payloadBuilderClientMaybe = node.getPayloadBuilderClient(
    validator_index.distinctBase)
  if payloadBuilderClientMaybe.isOk:
    payloadBuilderClient = payloadBuilderClientMaybe.get

  let collectedBids = await collectBidFutures(
    SBBB, EPS, node, payloadBuilderClient, validator.pubkey, validator_index,
    node.graffitiBytes, head, slot, randao)

  let useBuilderBlock =
    if collectedBids.builderBidAvailable:
      (not collectedBids.engineBidAvailable) or builderBetterBid(
        localBlockValueBoost,
        collectedBids.payloadBuilderBidFut.read.get().blockValue,
        collectedBids.engineBlockFut.read.get().blockValue)
    else:
      if not collectedBids.engineBidAvailable:
        return head   # errors logged in router
      false

  # There should always be an engine bid, and if payloadBuilderClient exists,
  # not getting a builder bid is also an error. Do not report lack of builder
  # when that's intentional. Replicate some of the nested if statements here,
  # because that avoids entangling logging with other functionality. The logs
  # here are inteded to clarify that, for example, when the builder API relay
  # URL is provided for this validator, it's reasonable for Nimbus not to use
  # it for every block.
  if collectedBids.engineBidAvailable:
    # Three cases: builder bid expected and absent, builder bid expected and
    # present, and builder bid not expected.
    if collectedBids.builderBidAvailable:
      info "Compared engine and builder block bids",
        localBlockValueBoost,
        useBuilderBlock,
        builderBlockValue =
          collectedBids.payloadBuilderBidFut.read.get().blockValue,
        engineBlockValue = collectedBids.engineBlockFut.read.get().blockValue
    elif payloadBuilderClient.isNil:
      discard  # builder API not configured for this block
    else:
      info "Did not receive expected builder bid; using engine block",
        engineBlockValue = collectedBids.engineBlockFut.read.get().blockValue
  else:
    # Similar three cases: builder bid expected and absent, builder bid
    # expected and present, and builder bid not expected. However, only
    # the second is worth logging, because the other two result in this
    # block being missed altogether, and with details logged elsewhere.
    if collectedBids.builderBidAvailable:
      info "Did not receive expected engine bid; using builder block",
        builderBlockValue =
          collectedBids.payloadBuilderBidFut.read.get().blockValue

  if useBuilderBlock:
    let
      blindedBlock = (await blindedBlockCheckSlashingAndSign(
        node, slot, validator, validator_index,
        collectedBids.payloadBuilderBidFut.read.get.blindedBlckPart)).valueOr:
          return head
      # Before proposeBlockMEV, can fall back to EL; after, cannot without
      # risking slashing.
      maybeUnblindedBlock = await proposeBlockMEV(
        node, payloadBuilderClient, blindedBlock)

    return maybeUnblindedBlock.valueOr:
      warn "Blinded block proposal incomplete",
        head = shortLog(head), slot, validator_index,
        validator = shortLog(validator),
        err = maybeUnblindedBlock.error,
        blindedBlck = shortLog(blindedBlock)
      beacon_block_builder_missed_without_fallback.inc()
      return head

  var forkedBlck = collectedBids.engineBlockFut.read.get().blck

  withBlck(forkedBlck):
    let
      blockRoot = hash_tree_root(forkyBlck)
      signingRoot = compute_block_signing_root(
        fork, genesis_validators_root, slot, blockRoot)

      notSlashable = node.attachedValidators
        .slashingProtection
        .registerBlock(validator_index, validator.pubkey, slot, signingRoot)

    if notSlashable.isErr:
      warn "Slashing protection activated for block proposal",
        blockRoot = shortLog(blockRoot), blck = shortLog(forkyBlck),
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
      signedBlock = consensusFork.SignedBeaconBlock(
        message: forkyBlck, signature: signature, root: blockRoot)
      blobsOpt =
        when consensusFork >= ConsensusFork.Deneb:
          template blobsBundle: untyped =
            collectedBids.engineBlockFut.read.get.blobsBundleOpt.get
          Opt.some(signedBlock.create_blob_sidecars(
            blobsBundle.proofs, blobsBundle.blobs))
        else:
          Opt.none(seq[BlobSidecar])
      newBlockRef = (
        await node.router.routeSignedBeaconBlock(signedBlock, blobsOpt)
      ).valueOr:
        return head # Errors logged in router

    if newBlockRef.isNone():
      return head # Validation errors logged in router

    notice "Block proposed",
      blockRoot = shortLog(blockRoot), blck = shortLog(forkyBlck),
      signature = shortLog(signature), validator = shortLog(validator)

    beacon_blocks_proposed.inc()

    return newBlockRef.get()

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
    randao = block:
      let res = await validator.getEpochSignature(
        fork, genesis_validators_root, slot.epoch)
      if res.isErr():
        warn "Unable to generate randao reveal",
             validator = shortLog(validator), error_msg = res.error()
        return head
      res.get()

  template proposeBlockContinuation(type1, type2: untyped): auto =
    await proposeBlockAux(
      type1, type2, node, validator, validator_index, head, slot, randao, fork,
        genesis_validators_root, node.config.localBlockValueBoost)

  return withConsensusFork(node.dag.cfg.consensusForkAtEpoch(slot.epoch)):
    when consensusFork >= ConsensusFork.Capella:
      proposeBlockContinuation(
        consensusFork.SignedBlindedBeaconBlock,
        consensusFork.ExecutionPayloadForSigning)
    else:
      # Bellatrix MEV is not supported; this signals that, because it triggers
      # intentional SignedBlindedBeaconBlock/ExecutionPayload mismatches.
      proposeBlockContinuation(
        capella_mev.SignedBlindedBeaconBlock,
        bellatrix.ExecutionPayloadForSigning)

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
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#validator-assignments
  let
    epochRef = node.dag.getEpochRef(
      attestationHead.blck, slot.epoch, false).valueOr:
        warn "Cannot construct EpochRef for attestation head, report bug",
          attestationHead = shortLog(attestationHead), slot, error
        return
    committees_per_slot = get_committee_count_per_slot(epochRef.shufflingRef)
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root
    registeredRes = node.attachedValidators.slashingProtection.withContext:
      var tmp: seq[(RegisteredAttestation, SubnetId)]

      for committee_index in get_committee_indices(committees_per_slot):
        let
          committee = get_beacon_committee(
            epochRef.shufflingRef, slot, committee_index)
          subnet_id = compute_subnet_for_attestation(
            committees_per_slot, slot, committee_index)

        for index_in_committee, validator_index in committee:
          let validator = node.getValidatorForDuties(validator_index, slot).valueOr:
            continue

          let
            data = makeAttestationData(epochRef, attestationHead, committee_index)
            # TODO signing_root is recomputed in produceAndSignAttestation/signAttestation just after
            signingRoot = compute_attestation_signing_root(
              fork, genesis_validators_root, data)
            registered = registerAttestationInContext(
              validator_index, validator.pubkey, data.source.epoch,
              data.target.epoch, signingRoot)
          if registered.isErr():
            warn "Slashing protection activated for attestation",
              attestationData = shortLog(data),
              signingRoot = shortLog(signingRoot),
              validator_index,
              validator = shortLog(validator),
              badVoteDetails = $registered.error()
            continue

          tmp.add((RegisteredAttestation(
            validator: validator,
            index_in_committee: uint64 index_in_committee,
            committee_len: committee.len(), data: data), subnet_id
          ))
      tmp

  if registeredRes.isErr():
    warn "Could not update slashing database, skipping attestation duties",
      error = registeredRes.error()
  else:
    for attestation in registeredRes[]:
      asyncSpawn createAndSendAttestation(
        node, fork, genesis_validators_root, attestation[0], attestation[1])

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
        head.bid,
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
  let syncCommittee = node.dag.syncCommitteeParticipants(slot + 1)

  for subcommitteeIdx in SyncSubcommitteeIndex:
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

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#aggregation-selection
    if not is_aggregator(
        shufflingRef, slot, committee_index, selectionProof):
      return

    # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#construct-aggregate
    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#aggregateandproof
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

proc registerValidatorsPerBuilder(
    node: BeaconNode, payloadBuilderAddress: string, epoch: Epoch,
    attachedValidatorPubkeys: seq[ValidatorPubKey]) {.async.} =
  const
    HttpOk = 200
    BUILDER_VALIDATOR_REGISTRATION_DELAY_TOLERANCE = 6.seconds

  try:
    let payloadBuilderClient =
        RestClientRef.new(payloadBuilderAddress).valueOr:
      debug "Unable to initialize payload builder client while registering validators",
        payloadBuilderAddress, epoch,
        err = error
      return

    if payloadBuilderClient.isNil:
      debug "registerValidatorsPerBuilder: got nil payload builder REST client reference",
        payloadBuilderAddress, epoch
      return

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
    # See issue #5599: currently VC have no way to provide BN with per-validator builders per the specs, so we have to
    #   resort to use the BN fallback default (--payload-builder-url value, obtained by calling getPayloadBuilderAddress)
    var nonExitedVcPubkeys: HashSet[ValidatorPubKey]
    if  node.externalBuilderRegistrations.len > 0 and
        payloadBuilderAddress == node.config.getPayloadBuilderAddress.value:
      withState(node.dag.headState):
        let currentEpoch = node.currentSlot().epoch
        for i in 0 ..< forkyState.data.validators.len:
          # https://github.com/ethereum/beacon-APIs/blob/v2.4.0/apis/validator/register_validator.yaml
          # "Note that only registrations for active or pending validators must
          # be sent to the builder network. Registrations for unknown or exited
          # validators must be filtered out and not sent to the builder
          # network."
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
            payloadBuilderClient.registerValidator(
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

proc registerValidators*(node: BeaconNode, epoch: Epoch) {.async.} =
  if not node.config.payloadBuilderEnable: return

  var builderKeys: Table[string, seq[ValidatorPubKey]]

  # Ensure VC validators are still registered if we have no attached validators
  let externalPayloadBuilderAddress = node.config.getPayloadBuilderAddress
  if externalPayloadBuilderAddress.isSome:
    builderKeys[externalPayloadBuilderAddress.value] = newSeq[ValidatorPubKey](0)

  for pubkey in node.attachedValidators[].validators.keys:
    let payloadBuilderAddress = node.getPayloadBuilderAddress(pubkey).valueOr:
      continue

    if payloadBuilderAddress in builderKeys:
      builderKeys[payloadBuilderAddress].add pubkey
    else:
      builderKeys[payloadBuilderAddress] = @[pubkey]

  for payloadBuilderAddress in builderKeys.keys:
    await node.registerValidatorsPerBuilder(
      payloadBuilderAddress, epoch, builderKeys[payloadBuilderAddress])

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
  if not node.isSynced(head):
    info "Beacon node not in sync; skipping validator duties for now",
      slot, headSlot = head.slot

    # Rewards will be growing though, as we sync..
    updateValidatorMetrics(node)

    return

  elif not head.executionValid:
    info "Execution client not in sync; skipping validator duties for now",
      slot, headSlot = head.slot

    # Rewards will be growing though, as we sync..
    updateValidatorMetrics(node)

    return
  else:
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

  let newHead = await handleProposal(node, head, slot)
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
      await waitAfterBlockCutoff(node.beaconClock, slot, Opt.some(head))

    # Time passed - we might need to select a new head in that case
    node.consensusManager[].updateHead(slot)
    head = node.dag.head

  static: doAssert attestationSlotOffset == syncCommitteeMessageSlotOffset

  handleAttestations(node, head, slot)
  handleSyncCommitteeMessages(node, head, slot)

  updateValidatorMetrics(node) # the important stuff is done, update the vanity numbers

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#broadcast-aggregate
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#broadcast-sync-committee-contribution
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
      not node.isSynced(node.dag.head) or not node.dag.head.executionValid:
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

proc makeMaybeBlindedBeaconBlockForHeadAndSlotImpl[ResultType](
    node: BeaconNode, consensusFork: static ConsensusFork,
    randao_reveal: ValidatorSig, graffiti: GraffitiBytes,
    head: BlockRef, slot: Slot): Future[ResultType] {.async.} =
  let
    proposer = node.dag.getProposer(head, slot).valueOr:
      return ResultType.err(
        "Unable to get proposer for specific head and slot")
    proposerKey = node.dag.validatorKey(proposer).get().toPubKey()

    payloadBuilderClient =
      node.getPayloadBuilderClient(proposer.distinctBase).valueOr:
        nil
    localBlockValueBoost = node.config.localBlockValueBoost

    collectedBids =
      await collectBidFutures(consensusFork.SignedBlindedBeaconBlock,
                              consensusFork.ExecutionPayloadForSigning,
                              node,
                              payloadBuilderClient, proposerKey,
                              proposer, graffiti, head, slot,
                              randao_reveal)
    useBuilderBlock =
      if collectedBids.builderBidAvailable:
        (not collectedBids.engineBidAvailable) or builderBetterBid(
          localBlockValueBoost,
          collectedBids.payloadBuilderBidFut.read.get().blockValue,
          collectedBids.engineBlockFut.read.get().blockValue)
      else:
        if not(collectedBids.engineBidAvailable):
          return ResultType.err("Engine bid is not available")
        false

    blockResult = block:
      if useBuilderBlock:
        let
          blindedResult = collectedBids.payloadBuilderBidFut.read()
          payloadValue = blindedResult.get().blockValue

        return ResultType.ok((
          blck: consensusFork.MaybeBlindedBeaconBlock(
            isBlinded: true,
            blindedData: blindedResult.get().blindedBlckPart.message),
          executionValue: Opt.some(payloadValue),
          consensusValue: Opt.none(UInt256)))

      collectedBids.engineBlockFut.read().get()

  doAssert blockResult.blck.kind == consensusFork
  template forkyBlck: untyped = blockResult.blck.forky(consensusFork)
  when consensusFork >= ConsensusFork.Deneb:
    let blobsBundle = blockResult.blobsBundleOpt.get()
    doAssert blobsBundle.commitments == forkyBlck.body.blob_kzg_commitments
    ResultType.ok((
      blck: consensusFork.MaybeBlindedBeaconBlock(
        isBlinded: false,
        data: deneb.BlockContents(
          `block`: forkyBlck,
          kzg_proofs: blobsBundle.proofs,
          blobs: blobsBundle.blobs)),
      executionValue: Opt.some(blockResult.blockValue),
      consensusValue: Opt.none(UInt256)))
  else:
    ResultType.ok((
      blck: consensusFork.MaybeBlindedBeaconBlock(
        isBlinded: false,
        data: forkyBlck),
      executionValue: Opt.some(blockResult.blockValue),
      consensusValue: Opt.none(UInt256)))

proc makeMaybeBlindedBeaconBlockForHeadAndSlot*(
    node: BeaconNode, consensusFork: static ConsensusFork,
    randao_reveal: ValidatorSig, graffiti: GraffitiBytes,
    head: BlockRef, slot: Slot): auto =
  type ResultType = Result[tuple[
    blck: consensusFork.MaybeBlindedBeaconBlock,
    executionValue: Opt[UInt256],
    consensusValue: Opt[UInt256]], string]

  makeMaybeBlindedBeaconBlockForHeadAndSlotImpl[ResultType](
    node, consensusFork, randao_reveal, graffiti, head, slot)
