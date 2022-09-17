# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

# This module is responsible for handling beacon node validators, ie those that
# that are running directly in the beacon node and not in a separate validator
# client process

import
  # Standard library
  std/[os, tables],

  # Nimble packages
  stew/[byteutils, objects],
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
  ".."/spec/mev/rest_bellatrix_mev_calls

from eth/async_utils import awaitWithTimeout

const
  delayBuckets = [-Inf, -4.0, -2.0, -1.0, -0.5, -0.1, -0.05,
                  0.05, 0.1, 0.5, 1.0, 2.0, 4.0, 8.0, Inf]

  BUILDER_BLOCK_SUBMISSION_DELAY_TOLERANCE = 4.seconds
  BUILDER_STATUS_DELAY_TOLERANCE = 3.seconds
  BUILDER_VALIDATOR_REGISTRATION_DELAY_TOLERANCE = 3.seconds

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

declareGauge(attached_validator_balance,
  "Validator balance at slot end of the first 64 validators, in Gwei",
  labels = ["pubkey"])

declarePublicGauge(attached_validator_balance_total,
  "Validator balance of all attached validators, in Gwei")

logScope: topics = "beacval"

type
  ForkedBlockResult* = Result[ForkedBeaconBlock, string]

proc findValidator*(validators: auto, pubkey: ValidatorPubKey): Opt[ValidatorIndex] =
  let idx = validators.findIt(it.pubkey == pubkey)
  if idx == -1:
    # We allow adding a validator even if its key is not in the state registry:
    # it might be that the deposit for this validator has not yet been processed
    notice "Validator deposit not yet processed, monitoring", pubkey
    Opt.none ValidatorIndex
  else:
    Opt.some idx.ValidatorIndex

# TODO: This should probably be moved to the validator_pool module
proc addRemoteValidator*(pool: var ValidatorPool,
                         keystore: KeystoreData,
                         index: Opt[ValidatorIndex],
                         feeRecipient: Eth1Address,
                         slot: Slot) =
  var clients: seq[(RestClientRef, RemoteSignerInfo)]
  let httpFlags =
    block:
      var res: set[HttpClientFlag]
      if RemoteKeystoreFlag.IgnoreSSLVerification in keystore.flags:
        res.incl({HttpClientFlag.NoVerifyHost,
                  HttpClientFlag.NoVerifyServerName})
      res
  let prestoFlags = {RestClientFlag.CommaSeparatedArray}
  for remote in keystore.remotes:
    let client = RestClientRef.new($remote.url, prestoFlags, httpFlags)
    if client.isErr():
      warn "Unable to resolve distributed signer address",
          remote_url = $remote.url, validator = $remote.pubkey
    clients.add((client.get(), remote))
  pool.addRemoteValidator(keystore, clients, index, feeRecipient, slot)

proc addValidators*(node: BeaconNode) =
  debug "Loading validators", validatorsDir = node.config.validatorsDir()
  let slot = node.currentSlot()
  for keystore in listLoadableKeystores(node.config):
    let
      index = withState(node.dag.headState):
        findValidator(forkyState.data.validators.asSeq(), keystore.pubkey)
      feeRecipient = node.consensusManager[].getFeeRecipient(
        keystore.pubkey, index, slot.epoch)

    case keystore.kind
    of KeystoreKind.Local:
      node.attachedValidators[].addLocalValidator(
        keystore, index, feeRecipient, slot)
    of KeystoreKind.Remote:
      node.attachedValidators[].addRemoteValidator(
        keystore, index, feeRecipient, slot)

proc getAttachedValidator(node: BeaconNode,
                          pubkey: ValidatorPubKey): AttachedValidator =
  node.attachedValidators[].getValidator(pubkey)

proc getAttachedValidator(node: BeaconNode,
                          state_validators: auto,
                          idx: ValidatorIndex): AttachedValidator =
  if uint64(idx) < state_validators.lenu64:
    let validator = node.getAttachedValidator(state_validators[idx].pubkey)
    if validator != nil and validator.index != some(idx):
      # Update index, in case the validator was activated!
      notice "Validator activated", pubkey = validator.pubkey, index = idx
      validator.index = Opt.some(idx)
    validator
  else:
    warn "Validator index out of bounds",
      idx, validators = state_validators.len
    nil

proc getAttachedValidator(node: BeaconNode,
                          idx: ValidatorIndex): AttachedValidator =
  let key = node.dag.validatorKey(idx)
  if key.isSome():
    let validator = node.getAttachedValidator(key.get().toPubKey())
    if validator != nil and validator.index != Opt.some(idx):
      # Update index, in case the validator was activated!
      notice "Validator activated", pubkey = validator.pubkey, index = idx
      validator.index = Opt.some(idx)
    validator
  else:
    warn "Validator key not found",
      idx, head = shortLog(node.dag.head)
    nil

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
  if  wallSlot.afterGenesis and
      head.slot + node.config.syncHorizon < wallSlot.slot:
    false
  else:
    not node.dag.is_optimistic(head.root)

proc handleLightClientUpdates*(node: BeaconNode, slot: Slot) {.async.} =
  static: doAssert lightClientFinalityUpdateSlotOffset ==
    lightClientOptimisticUpdateSlotOffset
  let sendTime = node.beaconClock.fromNow(
    slot.light_client_finality_update_time())
  if sendTime.inFuture:
    debug "Waiting to send LC updates", slot, delay = shortLog(sendTime.offset)
    await sleepAsync(sendTime.offset)

  template latest(): auto = node.dag.lcDataStore.cache.latest
  let signature_slot = latest.signature_slot
  if slot != signature_slot:
    return

  template sync_aggregate(): auto = latest.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64
  if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return

  let finalized_slot = latest.finalized_header.slot
  if finalized_slot > node.lightClientPool[].latestForwardedFinalitySlot:
    template msg(): auto = latest
    let sendResult = await node.network.broadcastLightClientFinalityUpdate(msg)

    # Optimization for message with ephemeral validity, whether sent or not
    node.lightClientPool[].latestForwardedFinalitySlot = finalized_slot

    if sendResult.isOk:
      beacon_light_client_finality_updates_sent.inc()
      notice "LC finality update sent", message = shortLog(msg)
    else:
      warn "LC finality update failed to send",
        error = sendResult.error()

  let attested_slot = latest.attested_header.slot
  if attested_slot > node.lightClientPool[].latestForwardedOptimisticSlot:
    let msg = latest.toOptimistic
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
                data = shortLog(data), error_msg = res.error()
          return
        res.get()
      attestation =
        Attestation.init(
          [uint64 indexInCommittee], committeeLen, data, signature).expect(
            "valid data")

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
  if node.eth1Monitor.isNil:
    var pendingDepositsCount =
      getStateField(state, eth1_data).deposit_count -
        getStateField(state, eth1_deposit_index)
    if pendingDepositsCount > 0:
      result.hasMissingDeposits = true
    else:
      result.vote = getStateField(state, eth1_data)
  else:
    let finalizedEpochRef = node.dag.getFinalizedEpochRef()
    result = node.eth1Monitor.getBlockProposalData(
      state, finalizedEpochRef.eth1_data,
      finalizedEpochRef.eth1_deposit_index)

from web3/engine_api import ForkchoiceUpdatedResponse

proc forkchoice_updated(
    head_block_hash: Eth2Digest, safe_block_hash: Eth2Digest,
    finalized_block_hash: Eth2Digest, timestamp: uint64, random: Eth2Digest,
    fee_recipient: ethtypes.Address, execution_engine: Eth1Monitor):
    Future[Option[bellatrix.PayloadID]] {.async.} =
  logScope:
    head_block_hash
    finalized_block_hash

  let
    forkchoiceResponse =
      try:
        awaitWithTimeout(
          execution_engine.forkchoiceUpdated(
            head_block_hash, safe_block_hash, finalized_block_hash,
            timestamp, random.data, fee_recipient),
          FORKCHOICEUPDATED_TIMEOUT):
            error "Engine API fork-choice update timed out"
            default(ForkchoiceUpdatedResponse)
      except CatchableError as err:
        error "Engine API fork-choice update failed", err = err.msg
        default(ForkchoiceUpdatedResponse)

    payloadId = forkchoiceResponse.payloadId

  return if payloadId.isSome:
    some(bellatrix.PayloadID(payloadId.get))
  else:
    none(bellatrix.PayloadID)

proc get_execution_payload(
    payload_id: Option[bellatrix.PayloadID], execution_engine: Eth1Monitor):
    Future[bellatrix.ExecutionPayload] {.async.} =
  return if payload_id.isNone():
    # Pre-merge, empty payload
    default(bellatrix.ExecutionPayload)
  else:
    asConsensusExecutionPayload(
      await execution_engine.getPayload(payload_id.get))

proc getFeeRecipient(node: BeaconNode,
                     pubkey: ValidatorPubKey,
                     validatorIdx: ValidatorIndex,
                     epoch: Epoch): Eth1Address =
  node.consensusManager[].getFeeRecipient(pubkey, Opt.some(validatorIdx), epoch)

from web3/engine_api_types import PayloadExecutionStatus

proc getExecutionPayload[T](
    node: BeaconNode, proposalState: ref ForkedHashedBeaconState,
    epoch: Epoch, validator_index: ValidatorIndex,
    pubkey: ValidatorPubKey): Future[Opt[T]] {.async.} =
  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/bellatrix/validator.md#executionpayload

  template empty_execution_payload(): auto =
    withState(proposalState[]):
      when stateFork >= BeaconStateFork.Bellatrix:
        build_empty_execution_payload(forkyState.data)
      else:
        default(T)

  if node.eth1Monitor.isNil:
    beacon_block_payload_errors.inc()
    warn "getExecutionPayload: eth1Monitor not initialized; using empty execution payload"
    return Opt.some empty_execution_payload

  try:
    # Minimize window for Eth1 monitor to shut down connection
    await node.consensusManager.eth1Monitor.ensureDataProvider()

    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.1/src/engine/specification.md#request-2
    const GETPAYLOAD_TIMEOUT = 1.seconds

    let
      terminalBlockHash =
        if node.eth1Monitor.terminalBlockHash.isSome:
          node.eth1Monitor.terminalBlockHash.get.asEth2Digest
        else:
          default(Eth2Digest)
      beaconHead = node.attestationPool[].getBeaconHead(node.dag.head)
      executionBlockRoot = node.dag.loadExecutionBlockRoot(beaconHead.blck)
      latestHead =
        if not executionBlockRoot.isZero:
          executionBlockRoot
        else:
          terminalBlockHash
      latestSafe = beaconHead.safeExecutionPayloadHash
      latestFinalized = beaconHead.finalizedExecutionPayloadHash
      feeRecipient = node.getFeeRecipient(pubkey, validator_index, epoch)
      lastFcU = node.consensusManager.forkchoiceUpdatedInfo
      timestamp = withState(proposalState[]):
        compute_timestamp_at_slot(forkyState.data, forkyState.data.slot)
      payload_id =
        if  lastFcU.isSome and
            lastFcU.get.headBlockRoot == latestHead and
            lastFcU.get.safeBlockRoot == latestSafe and
            lastFcU.get.finalizedBlockRoot == latestFinalized and
            lastFcU.get.timestamp == timestamp and
            lastFcU.get.feeRecipient == feeRecipient:
          some bellatrix.PayloadID(lastFcU.get.payloadId)
        else:
          debug "getExecutionPayload: didn't find payloadId, re-querying",
            latestHead, latestSafe, latestFinalized,
            timestamp,
            feeRecipient,
            cachedForkchoiceUpdateInformation = lastFcU

          let random = withState(proposalState[]):
            get_randao_mix(forkyState.data, get_current_epoch(forkyState.data))
          (await forkchoice_updated(
           latestHead, latestSafe, latestFinalized, timestamp, random,
           feeRecipient, node.consensusManager.eth1Monitor))
      payload = try:
          awaitWithTimeout(
            get_execution_payload(payload_id, node.consensusManager.eth1Monitor),
            GETPAYLOAD_TIMEOUT):
              beacon_block_payload_errors.inc()
              warn "Getting execution payload from Engine API timed out", payload_id
              empty_execution_payload
        except CatchableError as err:
          beacon_block_payload_errors.inc()
          warn "Getting execution payload from Engine API failed",
                payload_id, err = err.msg
          empty_execution_payload

      executionPayloadStatus =
        awaitWithTimeout(
          node.consensusManager.eth1Monitor.newExecutionPayload(payload),
          NEWPAYLOAD_TIMEOUT):
            info "getExecutionPayload: newPayload timed out"
            Opt.none PayloadExecutionStatus

    if executionPayloadStatus.isNone or executionPayloadStatus.get in [
        PayloadExecutionStatus.invalid,
        PayloadExecutionStatus.invalid_block_hash]:
      info "getExecutionPayload: newExecutionPayload invalid",
        executionPayloadStatus
      return Opt.none ExecutionPayload

    return Opt.some payload
  except CatchableError as err:
    beacon_block_payload_errors.inc()
    error "Error creating non-empty execution payload; using empty execution payload",
      msg = err.msg
    return Opt.some empty_execution_payload

proc makeBeaconBlockForHeadAndSlot*(
    node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot,
    execution_payload: Opt[ExecutionPayload] = Opt.none(ExecutionPayload),
    transactions_root: Opt[Eth2Digest] = Opt.none(Eth2Digest),
    execution_payload_root: Opt[Eth2Digest] = Opt.none(Eth2Digest)):
    Future[ForkedBlockResult] {.async.} =
  # Advance state to the slot that we're proposing for
  let
    proposalState = assignClone(node.dag.headState)

  # TODO fails at checkpoint synced head
  node.dag.withUpdatedState(
      proposalState[],
      head.atSlot(slot - 1).toBlockSlotId().expect("not nil")):
    # Advance to the given slot without calculating state root - we'll only
    # need a state root _with_ the block applied
    var info: ForkedEpochInfo

    process_slots(
      node.dag.cfg, state, slot, cache, info,
      {skipLastStateRootCalculation}).expect("advancing 1 slot should not fail")

    let
      eth1Proposal = node.getBlockProposalEth1Data(state)

    if eth1Proposal.hasMissingDeposits:
      beacon_block_production_errors.inc()
      warn "Eth1 deposits not available. Skipping block proposal", slot
      return ForkedBlockResult.err("Eth1 deposits not available")

    # Only current hardfork with execution payloads is Bellatrix
    static: doAssert high(BeaconStateFork) == BeaconStateFork.Bellatrix

    let
      exits = withState(state):
        node.exitPool[].getBeaconBlockExits(node.dag.cfg, forkyState.data)
      effectiveExecutionPayload =
        if executionPayload.isSome:
          executionPayload.get
        elif slot.epoch < node.dag.cfg.BELLATRIX_FORK_EPOCH or
             not (
               is_merge_transition_complete(proposalState[]) or
               ((not node.eth1Monitor.isNil) and
                node.eth1Monitor.terminalBlockHash.isSome)):
          # https://github.com/nim-lang/Nim/issues/19802
          (static(default(bellatrix.ExecutionPayload)))
        else:
          let
            pubkey = node.dag.validatorKey(validator_index)
            maybeExecutionPayload =
              (await getExecutionPayload[bellatrix.ExecutionPayload](
                node, proposalState, slot.epoch, validator_index,
                # TODO https://github.com/nim-lang/Nim/issues/19802
                if pubkey.isSome: pubkey.get.toPubKey else: default(ValidatorPubKey)))
          if maybeExecutionPayload.isNone:
            beacon_block_production_errors.inc()
            warn "Unable to get execution payload. Skipping block proposal",
              slot, validator_index
            return ForkedBlockResult.err("Unable to get execution payload")
          maybeExecutionPayload.get

    let res = makeBeaconBlock(
      node.dag.cfg,
      state,
      validator_index,
      randao_reveal,
      eth1Proposal.vote,
      graffiti,
      node.attestationPool[].getAttestationsForBlock(state, cache),
      eth1Proposal.deposits,
      exits,
      if slot.epoch < node.dag.cfg.ALTAIR_FORK_EPOCH:
        SyncAggregate.init()
      else:
        node.syncCommitteeMsgPool[].produceSyncAggregate(head.root),
      effectiveExecutionPayload,
      noRollback, # Temporary state - no need for rollback
      cache,
      transactions_root =
        if transactions_root.isSome:
          Opt.some transactions_root.get
        else:
          Opt.none(Eth2Digest),
      execution_payload_root =
        if execution_payload_root.isSome:
          Opt.some execution_payload_root.get
        else:
          Opt.none Eth2Digest)
    if res.isErr():
      # This is almost certainly a bug, but it's complex enough that there's a
      # small risk it might happen even when most proposals succeed - thus we
      # log instead of asserting
      beacon_block_production_errors.inc()
      error "Cannot create block for proposal",
        slot, head = shortLog(head), error = res.error()
      return err($res.error)
    return ok(res.get())
  do:
    beacon_block_production_errors.inc()
    error "Cannot get proposal state - skipping block production, database corrupt?",
      head = shortLog(head),
      slot
    return err("Cannot create proposal state")

proc getBlindedExecutionPayload(
    node: BeaconNode, slot: Slot, executionBlockRoot: Eth2Digest,
    pubkey: ValidatorPubKey):
    Future[Result[ExecutionPayloadHeader, cstring]] {.async.} =
  if node.payloadBuilderRestClient.isNil:
    return err "getBlindedBeaconBlock: nil REST client"

  let blindedHeader = awaitWithTimeout(
    node.payloadBuilderRestClient.getHeader(slot, executionBlockRoot, pubkey),
    BUILDER_PROPOSAL_DELAY_TOLERANCE):
      return err "Timeout when obtaining blinded header from builder"

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

import std/macros

func getFieldNames(x: typedesc[auto]): seq[string] {.compileTime.} =
  var res: seq[string]
  for name, _ in fieldPairs(default(x)):
    res.add name
  res

macro copyFields(
    dst: untyped, src: untyped, fieldNames: static[seq[string]]): untyped =
  result = newStmtList()
  for name in fieldNames:
    if name notin [
        # These fields are the ones which vary between the blinded and
        # unblinded objects, and can't simply be copied.
        "transactions_root", "execution_payload",
        "execution_payload_header", "body"]:
      # TODO use stew/assign2
      result.add newAssignment(
        newDotExpr(dst, ident(name)), newDotExpr(src, ident(name)))

proc getBlindedBeaconBlock[T](
    node: BeaconNode, slot: Slot, head: BlockRef, validator: AttachedValidator,
    validator_index: ValidatorIndex, forkedBlock: ForkedBeaconBlock,
    executionPayloadHeader: ExecutionPayloadHeader):
    Future[Result[T, string]] {.async.} =
  static: doAssert high(BeaconStateFork) == BeaconStateFork.Bellatrix
  const
    blckFields = getFieldNames(typeof(forkedBlock.bellatrixData))
    blckBodyFields = getFieldNames(typeof(forkedBlock.bellatrixData.body))

  # https://github.com/ethereum/builder-specs/blob/v0.2.0/specs/validator.md#block-proposal
  var blindedBlock: T

  copyFields(blindedBlock.message, forkedBlock.bellatrixData, blckFields)
  copyFields(
    blindedBlock.message.body, forkedBlock.bellatrixData.body, blckBodyFields)
  blindedBlock.message.body.execution_payload_header = executionPayloadHeader

  # Check with slashing protection before submitBlindedBlock
  let
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root
    blockRoot = hash_tree_root(blindedBlock.message)
    signing_root = compute_block_signing_root(
      fork, genesis_validators_root, slot, blockRoot)
    notSlashable = node.attachedValidators
      .slashingProtection
      .registerBlock(validator_index, validator.pubkey, slot, signing_root)

  if notSlashable.isErr:
    warn "Slashing protection activated for MEV block",
      validator = validator.pubkey,
      slot = slot,
      existingProposal = notSlashable.error
    return err("MEV proposal would be slashable: " & $notSlashable.error)

  blindedBlock.signature =
    block:
      let res = await validator.getBlockSignature(
        fork, genesis_validators_root, slot, blockRoot, blindedBlock.message)
      if res.isErr():
        return err("Unable to sign block: " & res.error())
      res.get()

  return ok blindedBlock

proc proposeBlockMEV(
    node: BeaconNode, head: BlockRef, validator: AttachedValidator, slot: Slot,
    randao: ValidatorSig, validator_index: ValidatorIndex):
    Future[Opt[BlockRef]] {.async.} =
  let
    executionBlockRoot = node.dag.loadExecutionBlockRoot(head)
    executionPayloadHeader = awaitWithTimeout(
        node.getBlindedExecutionPayload(
          slot, executionBlockRoot, validator.pubkey),
        BUILDER_PROPOSAL_DELAY_TOLERANCE):
      Result[ExecutionPayloadHeader, cstring].err(
        "getBlindedExecutionPayload timed out")

  if executionPayloadHeader.isErr:
    debug "proposeBlockMEV: getBlindedExecutionPayload failed",
      error = executionPayloadHeader.error
    # Haven't committed to the MEV block, so allow EL fallback.
    return Opt.none BlockRef

  # When creating this block, need to ensure it uses the MEV-provided execution
  # payload, both to avoid repeated calls to network services and to ensure the
  # consistency of this block (e.g., its state root being correct). Since block
  # processing does not work directly using blinded blocks, fix up transactions
  # root after running the state transition function on an otherwise equivalent
  # non-blinded block without transactions.
  var shimExecutionPayload: ExecutionPayload
  copyFields(
    shimExecutionPayload, executionPayloadHeader.get,
    getFieldNames(ExecutionPayloadHeader))

  let newBlock = await makeBeaconBlockForHeadAndSlot(
    node, randao, validator_index, node.graffitiBytes, head, slot,
    execution_payload = Opt.some shimExecutionPayload,
    transactions_root = Opt.some executionPayloadHeader.get.transactions_root,
    execution_payload_root =
      Opt.some hash_tree_root(executionPayloadHeader.get))

  if newBlock.isErr():
    # Haven't committed to the MEV block, so allow EL fallback.
    return Opt.none BlockRef # already logged elsewhere!

  let forkedBlck = newBlock.get()

  # This is only substantively asynchronous with a remote key signer
  let blindedBlock = awaitWithTimeout(
      getBlindedBeaconBlock[SignedBlindedBeaconBlock](
        node, slot, head, validator, validator_index, forkedBlck,
        executionPayloadHeader.get),
      500.milliseconds):
    Result[SignedBlindedBeaconBlock, string].err "getBlindedBlock timed out"

  if blindedBlock.isOk:
    # By time submitBlindedBlock is called, must already have done slashing
    # protection check
    let unblindedPayload =
      try:
        awaitWithTimeout(
          node.payloadBuilderRestClient.submitBlindedBlock(blindedBlock.get),
          BUILDER_BLOCK_SUBMISSION_DELAY_TOLERANCE):
            error "Submitting blinded block timed out",
                  blk = shortLog(blindedBlock.get)
            return Opt.some head
        # From here on, including error paths, disallow local EL production by
        # returning Opt.some, regardless of whether on head or newBlock.
      except RestDecodingError as exc:
        error "proposeBlockMEV: REST recoding error",
          slot, head = shortLog(head), validator_index, blindedBlock,
          error = exc.msg
        return Opt.some head
      except CatchableError as exc:
        error "proposeBlockMEV: exception in submitBlindedBlock",
          slot, head = shortLog(head), validator_index, blindedBlock,
          error = exc.msg
        return Opt.some head

    const httpOk = 200
    if unblindedPayload.status == httpOk:
      if  hash_tree_root(
            blindedBlock.get.message.body.execution_payload_header) !=
          hash_tree_root(unblindedPayload.data.data):
        debug "proposeBlockMEV: unblinded payload doesn't match blinded payload",
          blindedPayload =
            blindedBlock.get.message.body.execution_payload_header
      else:
        # Signature provided is consistent with unblinded execution payload,
        # so construct full beacon block
        # https://github.com/ethereum/builder-specs/blob/v0.2.0/specs/validator.md#block-proposal
        var signedBlock = bellatrix.SignedBeaconBlock(
          signature: blindedBlock.get.signature)
        copyFields(
          signedBlock.message, blindedBlock.get.message,
          getFieldNames(typeof(signedBlock.message)))
        copyFields(
          signedBlock.message.body, blindedBlock.get.message.body,
          getFieldNames(typeof(signedBlock.message.body)))
        signedBlock.message.body.execution_payload = unblindedPayload.data.data

        signedBlock.root = hash_tree_root(signedBlock.message)

        doAssert signedBlock.root == hash_tree_root(blindedBlock.get.message)

        debug "proposeBlockMEV: proposing unblinded block",
          blck = shortLog(signedBlock)

        let newBlockRef =
          (await node.router.routeSignedBeaconBlock(signedBlock)).valueOr:
            # submitBlindedBlock has run, so don't allow fallback to run
            return Opt.some head # Errors logged in router

        if newBlockRef.isNone():
          return Opt.some head # Validation errors logged in router

        notice "Block proposed (MEV)",
          blockRoot = shortLog(signedBlock.root), blck = shortLog(signedBlock),
          signature = shortLog(signedBlock.signature), validator = shortLog(validator)

        beacon_blocks_proposed.inc()

        return Opt.some newBlockRef.get()
    else:
      debug "proposeBlockMEV: submitBlindedBlock failed",
        slot, head = shortLog(head), validator_index, blindedBlock,
        payloadStatus = unblindedPayload.status

    # https://github.com/ethereum/builder-specs/blob/v0.2.0/specs/validator.md#proposer-slashing
    # This means if a validator publishes a signature for a
    # `BlindedBeaconBlock` (via a dissemination of a
    # `SignedBlindedBeaconBlock`) then the validator **MUST** not use the
    # local build process as a fallback, even in the event of some failure
    # with the external buildernetwork.
    return Opt.some head
  else:
    info "proposeBlockMEV: getBlindedBeaconBlock failed",
      slot, head = shortLog(head), validator_index, blindedBlock,
      error = blindedBlock.error
    return Opt.none BlockRef

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

  # https://github.com/ethereum/builder-specs/blob/v0.2.0/specs/validator.md#responsibilites-during-the-merge-transition
  # "Honest validators will not utilize the external builder network until
  # after the transition from the proof-of-work chain to the proof-of-stake
  # beacon chain has been finalized by the proof-of-stake validators."
  if  node.config.payloadBuilderEnable and
      not node.dag.loadExecutionBlockRoot(node.dag.finalizedHead.blck).isZero:
    let newBlockMEV = await node.proposeBlockMEV(
      head, validator, slot, randao, validator_index)

    if newBlockMEV.isSome:
      # This might be equivalent to the `head` passed in, but it signals that
      # `submitBlindedBlock` ran, so don't do anything else. Otherwise, it is
      # fine to try again with the local EL.
      return newBlockMEV.get

  let newBlock = await makeBeaconBlockForHeadAndSlot(
    node, randao, validator_index, node.graffitiBytes, head, slot)

  if newBlock.isErr():
    return head # already logged elsewhere!

  let forkedBlck = newBlock.get()

  withBlck(forkedBlck):
    let
      blockRoot = hash_tree_root(blck)
      signing_root = compute_block_signing_root(
        fork, genesis_validators_root, slot, blockRoot)

      notSlashable = node.attachedValidators
        .slashingProtection
        .registerBlock(validator_index, validator.pubkey, slot, signing_root)

    if notSlashable.isErr:
      warn "Slashing protection activated",
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
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#validator-assignments
  let
    epochRef = node.dag.getEpochRef(
      attestationHead.blck, slot.epoch, false).valueOr:
        warn "Cannot construct EpochRef for attestation head, report bug",
          attestationHead = shortLog(attestationHead), slot
        return
    committees_per_slot = get_committee_count_per_slot(epochRef.shufflingRef)
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root

  for committee_index in get_committee_indices(committees_per_slot):
    let committee = get_beacon_committee(
      epochRef.shufflingRef, slot, committee_index)

    for index_in_committee, validator_index in committee:
      let validator = node.getAttachedValidator(validator_index)
      if validator == nil:
        continue

      let
        data = makeAttestationData(epochRef, attestationHead, committee_index)
        # TODO signing_root is recomputed in produceAndSignAttestation/signAttestation just after
        signing_root = compute_attestation_signing_root(
          fork, genesis_validators_root, data)
        registered = node.attachedValidators
          .slashingProtection
          .registerAttestation(
            validator_index,
            validator.pubkey,
            data.source.epoch,
            data.target.epoch,
            signing_root)
      if registered.isOk():
        let subnet_id = compute_subnet_for_attestation(
          committees_per_slot, data.slot, committee_index)
        asyncSpawn createAndSendAttestation(
          node, fork, genesis_validators_root, validator, data,
          committee.len(), index_in_committee, subnet_id)
      else:
        warn "Slashing protection activated for attestation",
          validator = validator.pubkey,
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
      let validator = node.getAttachedValidator(valIdx)
      if isNil(validator) or validator.index.isNone():
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
      let validator = node.getAttachedValidator(valIdx)
      if validator == nil:
        continue

      asyncSpawn signAndSendContribution(
        node, validator, subcommitteeIdx, head, slot)

proc handleProposal(node: BeaconNode, head: BlockRef, slot: Slot):
    Future[BlockRef] {.async.} =
  ## Perform the proposal for the given slot, iff we have a validator attached
  ## that is supposed to do so, given the shuffling at that slot for the given
  ## head - to compute the proposer, we need to advance a state to the given
  ## slot
  let proposer = node.dag.getProposer(head, slot)
  if proposer.isNone():
    return head

  let
    proposerKey = node.dag.validatorKey(proposer.get).get().toPubKey
    validator = node.attachedValidators[].getValidator(proposerKey)

  return
    if validator == nil:
      debug "Expecting block proposal",
        headRoot = shortLog(head.root),
        slot = shortLog(slot),
        proposer_index = proposer.get(),
        proposer = shortLog(proposerKey)

      head
    else:
      await proposeBlock(node, validator, proposer.get(), head, slot)

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

    # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.3/specs/phase0/validator.md#aggregation-selection
    if not is_aggregator(
        shufflingRef, slot, committee_index, selectionProof):
      return

    # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#construct-aggregate
    # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#aggregateandproof
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
  # the given slot, for which `is_aggregator` returns `true.

  let
    shufflingRef = node.dag.getShufflingRef(head, slot.epoch, false).valueOr:
      warn "Cannot construct EpochRef for head, report bug",
        head = shortLog(head), slot
      return
    committees_per_slot = get_committee_count_per_slot(shufflingRef)

  for committee_index in get_committee_indices(committees_per_slot):
    for _, validator_index in
        get_beacon_committee(shufflingRef, slot, committee_index):
      let validator = node.getAttachedValidator(validator_index)
      if validator != nil:
        asyncSpawn signAndSendAggregate(
          node, validator, shufflingRef, slot, committee_index)

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
  # Stand-in, reasonable default
  const gasLimit = 30000000

  let validatorIdx = validator.index.valueOr:
    # The validator index will be missing when the validator was not
    # activated for duties yet. We can safely skip the registration then.
    return

  let feeRecipient = node.getFeeRecipient(validator.pubkey, validatorIdx, epoch)
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

proc registerValidators(node: BeaconNode, epoch: Epoch) {.async.} =
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

    # https://github.com/ethereum/builder-specs/blob/v0.2.0/specs/validator.md#validator-registration
    var validatorRegistrations: seq[SignedValidatorRegistrationV1]

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
            validatorRegistrations.add signedValidatorRegistration

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

      # https://ethereum.github.io/builder-specs/#/Builder/registerValidator
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
        validatorRegistrations.add validator.externalBuilderRegistration.get
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
        validatorRegistrations.add validatorRegistration.get

    let registerValidatorResult =
      awaitWithTimeout(node.payloadBuilderRestClient.registerValidator(validatorRegistrations),
                       BUILDER_VALIDATOR_REGISTRATION_DELAY_TOLERANCE):
        error "Timeout when registering validator with builder"
        return
    if HttpOk != registerValidatorResult.status:
      warn "registerValidators: Couldn't register validator with MEV builder",
        registerValidatorResult
  except CatchableError as exc:
    warn "registerValidators: exception",
      error = exc.msg

proc handleValidatorDuties*(node: BeaconNode, lastSlot, slot: Slot) {.async.} =
  ## Perform validator duties - create blocks, vote and aggregate existing votes
  if node.attachedValidators[].count == 0:
    # Nothing to do because we have no validator attached
    return

  # The dag head might be updated by sync while we're working due to the
  # await calls, thus we use a local variable to keep the logic straight here
  var head = node.dag.head
  if not node.isSynced(head):
    info "Syncing in progress; skipping validator duties for now",
      slot, headSlot = head.slot

    # Rewards will be growing though, as we sync..
    updateValidatorMetrics(node)

    return

  var curSlot = lastSlot + 1

  # If broadcastStartEpoch is 0, it hasn't had time to initialize yet, which
  # means that it'd be okay not to continue, but it won't gossip regardless.
  let doppelgangerDetection = node.processor[].doppelgangerDetection
  if curSlot.epoch < doppelgangerDetection.broadcastStartEpoch and
      doppelgangerDetection.nodeLaunchSlot > GENESIS_SLOT and
      node.config.doppelgangerDetection:
    let
      nextAttestationSlot =
        node.consensusManager[].actionTracker.getNextAttestationSlot(slot - 1)
      nextProposalSlot =
        node.consensusManager[].actionTracker.getNextProposalSlot(slot - 1)

    if slot in [nextAttestationSlot, nextProposalSlot]:
      notice "Doppelganger detection active - skipping validator duties while observing activity on the network",
        slot, epoch = slot.epoch,
        broadcastStartEpoch = doppelgangerDetection.broadcastStartEpoch

    return

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

  # https://github.com/ethereum/builder-specs/blob/v0.2.0/specs/validator.md#registration-dissemination
  # This specification suggests validators re-submit to builder software every
  # `EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION` epochs.
  if  slot.is_epoch and
      slot.epoch mod EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION == 0:
    asyncSpawn node.registerValidators(slot.epoch)

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

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#broadcast-aggregate
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.3/specs/altair/validator.md#broadcast-sync-committee-contribution
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
      not node.isSynced(node.dag.head):
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
        let validator = node.getAttachedValidator(validator_index)
        if validator != nil:
          let
            subnet_id = compute_subnet_for_attestation(
              committees_per_slot, slot, committee_index)
          let slotSigRes = await validator.getSlotSignature(
            fork, genesis_validators_root, slot)
          if slotSigRes.isErr():
            error "Unable to create slot signature",
                  validator = shortLog(validator),
                  error_msg = slotSigRes.error()
            continue
          let isAggregator = is_aggregator(committee.lenu64, slotSigRes.get())

          node.consensusManager[].actionTracker.registerDuty(
            slot, subnet_id, validator_index, isAggregator)
