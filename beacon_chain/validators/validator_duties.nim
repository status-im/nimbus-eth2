# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# This module is responsible for handling beacon node validators, ie those that
# that are running directly in the beacon node and not in a separate validator
# client process

# References to `vFuture` refer to the pre-release proposal of the libp2p based
# light client sync protocol. Conflicting release versions are not in use.
# https://github.com/ethereum/consensus-specs/pull/2802

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
    sync_committee_msg_pool],
  ../eth1/eth1_monitor,
  ../networking/eth2_network,
  ../sszdump, ../sync/sync_manager,
  ../gossip_processing/[block_processor, consensus_manager],
  ".."/[conf, beacon_clock, beacon_node],
  "."/[slashing_protection, validator_pool, keystore_management]

from eth/async_utils import awaitWithTimeout
from web3/engine_api import ForkchoiceUpdatedResponse
from web3/engine_api_types import PayloadExecutionStatus

# Metrics for tracking attestation and beacon block loss
const delayBuckets = [-Inf, -4.0, -2.0, -1.0, -0.5, -0.1, -0.05,
                      0.05, 0.1, 0.5, 1.0, 2.0, 4.0, 8.0, Inf]

declareCounter beacon_light_client_finality_updates_sent,
  "Number of LC finality updates sent by this peer"

declareCounter beacon_light_client_optimistic_updates_sent,
  "Number of LC optimistic updates sent by this peer"

declareCounter beacon_blocks_proposed,
  "Number of beacon chain blocks sent by this peer"

declareGauge(attached_validator_balance,
  "Validator balance at slot end of the first 64 validators, in Gwei",
  labels = ["pubkey"])

declarePublicGauge(attached_validator_balance_total,
  "Validator balance of all attached validators, in Gwei")

logScope: topics = "beacval"

type
  ForkedBlockResult* = Result[ForkedBeaconBlock, string]

proc findValidator(validators: auto, pubkey: ValidatorPubKey):
    Option[ValidatorIndex] =
  let idx = validators.findIt(it.pubkey == pubkey)
  if idx == -1:
    # We allow adding a validator even if its key is not in the state registry:
    # it might be that the deposit for this validator has not yet been processed
    notice "Validator deposit not yet processed, monitoring", pubkey
    none(ValidatorIndex)
  else:
    some(idx.ValidatorIndex)

proc addLocalValidator(node: BeaconNode, validators: auto,
                       item: KeystoreData) =
  let
    pubkey = item.pubkey
    index = findValidator(validators, pubkey)
  node.attachedValidators[].addLocalValidator(item, index)

proc addRemoteValidator(pool: var ValidatorPool, validators: auto,
                        item: KeystoreData) =
  var clients: seq[(RestClientRef, RemoteSignerInfo)]
  let httpFlags =
    block:
      var res: set[HttpClientFlag]
      if RemoteKeystoreFlag.IgnoreSSLVerification in item.flags:
        res.incl({HttpClientFlag.NoVerifyHost,
                  HttpClientFlag.NoVerifyServerName})
      res
  let prestoFlags = {RestClientFlag.CommaSeparatedArray}
  for remote in item.remotes:
    let client = RestClientRef.new($remote.url, prestoFlags, httpFlags)
    if client.isErr():
      warn "Unable to resolve distributed signer address",
          remote_url = $remote.url, validator = $remote.pubkey
    clients.add((client.get(), remote))
  let index = findValidator(validators, item.pubkey)
  pool.addRemoteValidator(item, clients, index)

proc addLocalValidators*(node: BeaconNode,
                         validators: openArray[KeystoreData]) =
  withState(node.dag.headState):
    for item in validators:
      node.addLocalValidator(state.data.validators.asSeq(), item)

proc addRemoteValidators*(node: BeaconNode,
                          validators: openArray[KeystoreData]) =
  withState(node.dag.headState):
    for item in validators:
      node.attachedValidators[].addRemoteValidator(
        state.data.validators.asSeq(), item)

proc addValidators*(node: BeaconNode) =
  let (localValidators, remoteValidators) =
    block:
      var local, remote, distributed: seq[KeystoreData]
      for keystore in listLoadableKeystores(node.config):
        case keystore.kind
        of KeystoreKind.Local:
          local.add(keystore)
        of KeystoreKind.Remote:
          remote.add(keystore)
      (local, remote)
  node.addLocalValidators(localValidators)
  node.addRemoteValidators(remoteValidators)

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
      validator.index  = some(idx)
    validator
  else:
    warn "Validator index out of bounds",
      idx, validators = state_validators.len
    nil

proc getAttachedValidator(node: BeaconNode,
                          epochRef: EpochRef,
                          idx: ValidatorIndex): AttachedValidator =
  let key = epochRef.validatorKey(idx)
  if key.isSome():
    let validator = node.getAttachedValidator(key.get().toPubKey())
    if validator != nil and validator.index != some(idx):
      # Update index, in case the validator was activated!
      notice "Validator activated", pubkey = validator.pubkey, index = idx
      validator.index = some(idx)
    validator
  else:
    warn "Validator key not found",
      idx, epoch = epochRef.epoch
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

proc forkchoice_updated(state: bellatrix.BeaconState,
                        head_block_hash: Eth2Digest,
                        finalized_block_hash: Eth2Digest,
                        fee_recipient: ethtypes.Address,
                        execution_engine: Eth1Monitor):
                        Future[Option[bellatrix.PayloadID]] {.async.} =
  let
    timestamp = compute_timestamp_at_slot(state, state.slot)
    random = get_randao_mix(state, get_current_epoch(state))
    forkchoiceResponse =
      awaitWithTimeout(
        execution_engine.forkchoiceUpdated(
          head_block_hash, finalized_block_hash, timestamp, random.data,
          fee_recipient),
        FORKCHOICEUPDATED_TIMEOUT):
          info "forkchoice_updated: forkchoiceUpdated timed out"
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

proc getSuggestedFeeRecipient(node: BeaconNode, pubkey: ValidatorPubKey):
    Eth1Address =
  template defaultSuggestedFeeRecipient(): Eth1Address =
    if node.config.suggestedFeeRecipient.isSome:
      node.config.suggestedFeeRecipient.get
    else:
      # https://github.com/nim-lang/Nim/issues/19802
      (static(default(Eth1Address)))

  const feeRecipientFilename = "suggested_fee_recipient.hex"
  let
    keyName = "0x" & pubkey.toHex()
    feeRecipientPath =
      node.config.validatorsDir() / keyName / feeRecipientFilename

  # In this particular case, an error might be by design. If the file exists,
  # but doesn't load or parse that's a more urgent matter to fix. Many people
  # people might prefer, however, not to override their default suggested fee
  # recipients per validator, so don't warn very loudly, if at all.
  if not fileExists(feeRecipientPath):
    debug "getSuggestedFeeRecipient: did not find fee recipient file; using default fee recipient",
      feeRecipientPath
    return defaultSuggestedFeeRecipient()

  try:
    # Avoid being overly flexible initially. Trailing whitespace is common
    # enough it probably should be allowed, but it is reasonable to simply
    # disallow the mostly-pointless flexibility of leading whitespace.
    Eth1Address.fromHex(strip(
      readFile(feeRecipientPath), leading = false, trailing = true))
  except CatchableError as exc:
    # Because the nonexistent validator case was already checked, any failure
    # at this point is serious enough to alert the user.
    warn "getSuggestedFeeRecipient: failed loading fee recipient file; falling back to default fee recipient",
      feeRecipientPath,
      err = exc.msg
    defaultSuggestedFeeRecipient()

proc getExecutionPayload(
    node: BeaconNode, proposalState: auto, pubkey: ValidatorPubKey):
    Future[ExecutionPayload] {.async.} =
  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/bellatrix/validator.md#executionpayload

  # Only current hardfork with execution payloads is Bellatrix
  static: doAssert high(BeaconStateFork) == BeaconStateFork.Bellatrix
  template empty_execution_payload(): auto =
    build_empty_execution_payload(proposalState.bellatrixData.data)

  if node.eth1Monitor.isNil:
    warn "getExecutionPayload: eth1Monitor not initialized; using empty execution payload"
    return empty_execution_payload

  try:
    # Minimize window for Eth1 monitor to shut down connection
    await node.consensusManager.eth1Monitor.ensureDataProvider()

    # https://github.com/ethereum/execution-apis/blob/v1.0.0-alpha.9/src/engine/specification.md#request-2
    const GETPAYLOAD_TIMEOUT = 1.seconds

    let
      terminalBlockHash =
        if node.eth1Monitor.terminalBlockHash.isSome:
          node.eth1Monitor.terminalBlockHash.get.asEth2Digest
        else:
          default(Eth2Digest)
      executionBlockRoot = node.dag.loadExecutionBlockRoot(node.dag.head)
      latestHead =
        if not executionBlockRoot.isZero:
          executionBlockRoot
        else:
          terminalBlockHash
      latestFinalized =
        node.dag.loadExecutionBlockRoot(node.dag.finalizedHead.blck)
      payload_id = (await forkchoice_updated(
        proposalState.bellatrixData.data, latestHead, latestFinalized,
        node.getSuggestedFeeRecipient(pubkey),
        node.consensusManager.eth1Monitor))
      payload = awaitWithTimeout(
        get_execution_payload(payload_id, node.consensusManager.eth1Monitor),
        GETPAYLOAD_TIMEOUT):
          info "getExecutionPayload: getPayload timed out; using empty execution payload"
          empty_execution_payload
      executionPayloadStatus =
        awaitWithTimeout(
          node.consensusManager.eth1Monitor.newExecutionPayload(payload),
          NEWPAYLOAD_TIMEOUT):
            info "getExecutionPayload: newPayload timed out"
            PayloadExecutionStatus.syncing

    if executionPayloadStatus != PayloadExecutionStatus.valid:
      info "getExecutionPayload: newExecutionPayload not valid; using empty execution payload",
        executionPayloadStatus
      return empty_execution_payload

    return payload
  except CatchableError as err:
    error "Error creating non-empty execution payload; using empty execution payload",
      msg = err.msg
    return empty_execution_payload

proc makeBeaconBlockForHeadAndSlot*(node: BeaconNode,
                                    randao_reveal: ValidatorSig,
                                    validator_index: ValidatorIndex,
                                    graffiti: GraffitiBytes,
                                    head: BlockRef, slot: Slot
                                   ): Future[ForkedBlockResult] {.async.} =
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
      warn "Eth1 deposits not available. Skipping block proposal", slot
      return ForkedBlockResult.err("Eth1 deposits not available")

    # Only current hardfork with execution payloads is Bellatrix
    static: doAssert high(BeaconStateFork) == BeaconStateFork.Bellatrix

    let exits = withState(state):
      node.exitPool[].getBeaconBlockExits(state.data)
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
      if  slot.epoch < node.dag.cfg.BELLATRIX_FORK_EPOCH or
          not (
            is_merge_transition_complete(proposalState.bellatrixData.data) or
            ((not node.eth1Monitor.isNil) and
             node.eth1Monitor.terminalBlockHash.isSome)):
        default(bellatrix.ExecutionPayload)
      else:
        let pubkey = node.dag.validatorKey(validator_index)
        (await getExecutionPayload(
          node, proposalState,
          # TODO https://github.com/nim-lang/Nim/issues/19802
          if pubkey.isSome: pubkey.get.toPubKey else: default(ValidatorPubKey))),
      noRollback, # Temporary state - no need for rollback
      cache)
    if res.isErr():
      # This is almost certainly a bug, but it's complex enough that there's a
      # small risk it might happen even when most proposals succeed - thus we
      # log instead of asserting
      error "Cannot create block for proposal",
        slot, head = shortLog(head), error = res.error()
      return err($res.error)
    return ok(res.get())
  do:
    error "Cannot get proposal state - skipping block production, database corrupt?",
      head = shortLog(head),
      slot

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

    newBlock = await makeBeaconBlockForHeadAndSlot(
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
    committees_per_slot = get_committee_count_per_slot(epochRef)
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root

  for committee_index in get_committee_indices(committees_per_slot):
    let committee = get_beacon_committee(epochRef, slot, committee_index)

    for index_in_committee, validator_index in committee:
      let validator = node.getAttachedValidator(epochRef, validator_index)
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
  var
    syncCommittee = node.dag.syncCommitteeParticipants(slot + 1)
    epochRef = node.dag.getEpochRef(head, slot.epoch, false).valueOr:
      warn "Cannot construct EpochRef for head, report bug",
        attestationHead = shortLog(head), slot
      return

  for subcommitteeIdx in SyncSubcommitteeIndex:
    for valIdx in syncSubcommittee(syncCommittee, subcommitteeIdx):
      let validator = node.getAttachedValidator(epochRef, valIdx)
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
    epochRef = node.dag.getEpochRef(head, slot.epoch, false).valueOr:
      warn "Cannot construct EpochRef for head, report bug",
        attestationHead = shortLog(head), slot
      return

  for subcommitteeIdx in SyncSubCommitteeIndex:
    for valIdx in syncSubcommittee(syncCommittee, subcommitteeIdx):
      let validator = node.getAttachedValidator(epochRef, valIdx)
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
    node: BeaconNode, validator: AttachedValidator, epochRef: EpochRef,
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

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#aggregation-selection
    if not is_aggregator(epochRef, slot, committee_index, selectionProof):
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
    epochRef = node.dag.getEpochRef(head, slot.epoch, false).valueOr:
      warn "Cannot construct EpochRef for head, report bug",
        head = shortLog(head), slot
      return
    committees_per_slot = get_committee_count_per_slot(epochRef)

  for committee_index in get_committee_indices(committees_per_slot):
    for _, validator_index in
        get_beacon_committee(epochRef, slot, committee_index):
      let validator = node.getAttachedValidator(epochRef, validator_index)
      if validator != nil:
        asyncSpawn signAndSendAggregate(
          node, validator, epochRef, slot, committee_index)

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
      nextAttestationSlot = node.actionTracker.getNextAttestationSlot(slot - 1)
      nextProposalSlot = node.actionTracker.getNextProposalSlot(slot - 1)

    if slot in [nextAttestationSlot, nextProposalSlot]:
      notice "Doppelganger detection active - skipping validator duties while observing activity on the network",
        slot, epoch = slot.epoch,
        broadcastStartEpoch = doppelgangerDetection.broadcastStartEpoch
    else:
      debug "Doppelganger detection active - skipping validator duties while observing activity on the network",
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
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/validator.md#broadcast-sync-committee-contribution
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
      epochRef = node.dag.getEpochRef(head, slot.epoch, false).valueOr:
        warn "Cannot construct EpochRef for duties - report bug",
          head = shortLog(head), slot
        return
    let
      fork = node.dag.forkAtEpoch(slot.epoch)
      committees_per_slot = get_committee_count_per_slot(epochRef)

    for committee_index in get_committee_indices(committees_per_slot):
      let committee = get_beacon_committee(epochRef, slot, committee_index)

      for index_in_committee, validator_index in committee:
        let validator = node.getAttachedValidator(epochRef, validator_index)
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

          node.actionTracker.registerDuty(
            slot, subnet_id, validator_index, isAggregator)
