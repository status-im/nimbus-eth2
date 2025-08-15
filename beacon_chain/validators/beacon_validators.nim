# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## This module is responsible for handling beacon node validators, ie those that
## that are running directly in the beacon node and not in a separate validator
## client process - we name these "beacon validators" while those running
## outside are "client validators".

import
  # Standard library
  std/[os, tables],

  # Nimble packages
  stew/byteutils,
  chronos,
  metrics,
  chronicles,
  json_serialization/std/[sets, net],
  web3/primitives,

  # Local modules
  ../spec/[
    eth2_merkleization, forks, helpers, network, signatures, state_transition,
    state_transition_block, validator,
  ],
  ../spec/mev/rest_mev_calls,
  ../consensus_object_pools/[
    spec_cache, blockchain_dag, attestation_pool, sync_committee_msg_pool,
    validator_change_pool, consensus_manager, common_tools,
  ],
  ../el/el_manager,
  ../networking/eth2_network,
  ../sszdump,
  ../[conf, beacon_clock, beacon_node],
  ./[
    block_payloads, keystore_management, slashing_protection, validator_duties,
    validator_pool,
  ]

from std/sequtils import mapIt
from eth/async_utils import awaitWithTimeout
from ./message_router_mev import unblindAndRouteBlockMEV

# Metrics for tracking attestation and beacon block loss
declareCounter beacon_light_client_finality_updates_sent,
  "Number of LC finality updates sent by this peer"

declareCounter beacon_light_client_optimistic_updates_sent,
  "Number of LC optimistic updates sent by this peer"

declareCounter beacon_blocks_proposed,
  "Number of beacon chain blocks sent by this peer"

declareCounter beacon_block_production_errors,
  "Number of times we failed to produce a block"

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

func getValidator*(validators: auto,
                   pubkey: ValidatorPubKey): Opt[ValidatorAndIndex] =
  let idx = validators.findIt(it.pubkey == pubkey)
  if idx == -1:
    # We allow adding a validator even if its key is not in the state registry:
    # it might be that the deposit for this validator has not yet been processed
    Opt.none ValidatorAndIndex
  else:
    Opt.some ValidatorAndIndex(index: ValidatorIndex(idx),
                               validator: validators[idx])

func blockConsensusValue(r: BlockRewards): UInt256 {.noinit.} =
  # Returns value of `block-consensus-value` in Wei units.
  u256(r.attestations + r.sync_aggregate +
    r.proposer_slashings + r.attester_slashings) * u256(1000000000)

proc getFeeRecipient(node: BeaconNode,
                     pubkey: ValidatorPubKey,
                     validatorIdx: Opt[ValidatorIndex],
                     epoch: Epoch): Eth1Address =
  node.consensusManager[].getFeeRecipient(pubkey, validatorIdx, epoch)

proc getGasLimit(node: BeaconNode,
                 pubkey: ValidatorPubKey): uint64 =
  node.consensusManager[].getGasLimit(pubkey)

proc addValidatorsFromWeb3Signer(
    node: BeaconNode, web3signerUrl: Web3SignerUrl, epoch: Epoch)
    {.async: (raises: [CancelledError]).} =
  let dynamicStores =
    # Error is already reported via log warning.
    (await queryValidatorsSource(web3signerUrl)).valueOr(
      default(seq[KeystoreData]))

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
      feeRecipient = node.getFeeRecipient(keystore.pubkey, index, epoch)
      gasLimit = node.getGasLimit(keystore.pubkey)
      v = node.attachedValidators[].addValidator(keystore, feeRecipient,
                                                 gasLimit)
    node.attachedValidators[].updateValidator(v, data)

proc addValidators*(node: BeaconNode) {.async: (raises: [CancelledError]).} =
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
      feeRecipient = node.getFeeRecipient(keystore.pubkey, index, epoch)
      gasLimit = node.getGasLimit(keystore.pubkey)

      v = node.attachedValidators[].addValidator(keystore, feeRecipient,
                                                 gasLimit)
    node.attachedValidators[].updateValidator(v, data)

  # We use `allFutures` because all failures are already reported as
  # user-visible warnings in `queryValidatorsSource`.
  # We don't consider them fatal because the Web3Signer may be experiencing
  # a temporary hiccup that will be resolved later.
  # TODO mapIt version fails at type deduction - figure out..
  var futs: seq[Future[void].Raising([CancelledError])]
  for it in node.config.web3SignerUrls:
    futs.add node.addValidatorsFromWeb3Signer(it, epoch)
  await allFutures(futs)

proc pollForDynamicValidators*(node: BeaconNode,
                               web3signerUrl: Web3SignerUrl,
                               intervalInSeconds: int)
                               {.async: (raises: [CancelledError]).} =
  if intervalInSeconds == 0:
    return

  proc addValidatorProc(keystore: KeystoreData) =
    let
      epoch = node.currentSlot().epoch
      index = Opt.none(ValidatorIndex)
      feeRecipient = node.getFeeRecipient(keystore.pubkey, index, epoch)
      gasLimit = node.getGasLimit(keystore.pubkey)
    discard node.attachedValidators[].addValidator(keystore, feeRecipient,
                                                   gasLimit)

  var
    timeout = seconds(intervalInSeconds)

  while true:
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

func getValidator*(node: BeaconNode, idx: ValidatorIndex): Opt[AttachedValidator] =
  let key = ? node.dag.validatorKey(idx)
  node.attachedValidators[].getValidator(key.toPubKey())

proc getValidatorForDuties*(
    node: BeaconNode, idx: ValidatorIndex, slot: Slot,
    slashingSafe = false): Opt[AttachedValidator] =
  let key = ? node.dag.validatorKey(idx)

  node.attachedValidators[].getValidatorForDuties(
    key.toPubKey(), slot, slashingSafe)

proc getGraffitiBytes*(
    node: BeaconNode, validator: AttachedValidator): GraffitiBytes =
  getGraffiti(node.config.validatorsDir, node.config.defaultGraffitiBytes(),
              validator.pubkey)

proc isSynced*(node: BeaconNode, head: BlockRef): bool =
  ## TODO This function is here as a placeholder for some better heurestics to
  ##      determine if we're in sync and should be producing blocks and
  ##      attestations. Generally, the problem is that slot time keeps advancing
  ##      even when there are no blocks being produced, so there's no way to
  ##      distinguish validators genuinely going missing from the node not being
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

proc handleLightClientUpdates*(node: BeaconNode, slot: Slot)
    {.async: (raises: [CancelledError]).} =
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
                              subnet_id: SubnetId)
                              {.async: (raises: [CancelledError]).} =
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
    epoch = registered.data.slot.epoch

  registered.validator.doppelgangerActivity(epoch)

  # Logged in the router
  if node.dag.cfg.consensusForkAtEpoch(epoch) >= ConsensusFork.Electra:
    discard await node.router.routeAttestation(
      registered.toSingleAttestation(signature), subnet_id,
      checkSignature = false, checkValidator = false)
  else:
    discard await node.router.routeAttestation(
      registered.toAttestation(signature), subnet_id,
      checkSignature = false, checkValidator = false)

proc registerBlock(
    node: BeaconNode,
    validator: AttachedValidator,
    validator_index: ValidatorIndex,
    blck: ForkyBeaconBlock | ForkyBlindedBeaconBlock,
): Result[Eth2Digest, string] =
  let
    fork = node.dag.forkAtEpoch(blck.slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root
    blockRoot = hash_tree_root(blck)
    signingRoot =
      compute_block_signing_root(fork, genesis_validators_root, blck.slot, blockRoot)

  node.attachedValidators[].slashingProtection.registerBlock(
    validator_index, validator.pubkey, blck.slot, signingRoot
  ).isOkOr:
    warn "Slashing protection activated for block proposal",
      blockRoot = shortLog(blockRoot),
      blck = shortLog(blck),
      signingRoot = shortLog(signingRoot),
      validator = validator.pubkey,
      slot = blck.slot,
      existingProposal = error
    return err("Proposal would be slashable: " & $error)
  ok blockRoot

proc getBlockSignature(
    node: BeaconNode,
    validator: AttachedValidator,
    blockRoot: Eth2Digest,
    blck: ForkyBeaconBlock | ForkyBlindedBeaconBlock,
): Future[Result[ValidatorSig, string]] {.async: (raises: [CancelledError]).} =
  # Check with slashing protection before submitBlindedBlock
  let
    fork = node.dag.forkAtEpoch(blck.slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root

    res =
      await validator.getBlockSignature(fork, genesis_validators_root, blockRoot, blck)

  if res.isErr:
    warn "Could not get block proposal signature",
      validator = shortLog(validator),
      blockRoot = shortLog(blockRoot),
      blck = shortLog(blck),
      err = res.error

  res

proc proposeBlockAux(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    validator: AttachedValidator,
    head: BlockRef,
    slot: Slot,
    randao_reveal: ValidatorSig,
): Future[BlockRef] {.async: (raises: [CancelledError]).} =
  var
    cache = new StateCache
    # TODO move the creation of this proposal state away from the hot path
    state = node.dag.getProposalState(head, slot, cache[]).valueOr:
      beacon_block_production_errors.inc()
      return head

  let
    graffiti = node.getGraffitiBytes(validator)
    validator_index = validator.index.expect("index set for proposer")

    enginePayload =
      when consensusFork >= ConsensusFork.Electra:
        # Fetch both builder and engine payloads then use the better one to
        # make a block
        let
          payloadBuilderClient =
            node.getPayloadBuilderClient(validator_index.distinctBase).valueOr(nil)

          bids = await node.collectBids(
            consensusFork, payloadBuilderClient, validator.pubkey, validator_index,
            head, slot, state,
          )

          localBlockValueBoost = node.config.localBlockValueBoost
          useBuilderPayload =
            bids.useBuilderPayload(BoostFactor.init(localBlockValueBoost))

        if payloadBuilderClient != nil:
          # Log payload selection only if the user enabled builder support
          info "Payload selected",
            slot,
            validator = shortLog(validator),
            localBlockValueBoost,
            useBuilderPayload,
            hasBuilderPayload = bids.builderBid.isSome(),
            hasEnginePayload = bids.engineBid.isSome()

        if useBuilderPayload:
          doAssert bids.builderBid.isSome(), "Checked in useBuilderPayload"
          let builderBlockRes = node.makeBuilderBlock(
            consensusFork,
            state[],
            cache[],
            validator_index,
            randao_reveal,
            graffiti,
            head,
            slot,
            bids.builderBid.value(),
          )

          if builderBlockRes.isOk:
            # Slashing database serves as the cutoff point for falling back to
            # engine blocks since failures from this point onwards should be
            # independent of the (type of) payload.
            template blck(): untyped =
              builderBlockRes.get().blck

            let
              blockRoot = node.registerBlock(validator, validator_index, blck).valueOr:
                beacon_block_builder_missed_without_fallback.inc()
                beacon_block_production_errors.inc()
                return head

              signature = (await node.getBlockSignature(validator, blockRoot, blck)).valueOr:
                beacon_block_builder_missed_without_fallback.inc()
                beacon_block_production_errors.inc()
                return head

              blindedBlock = consensusFork.SignedBlindedBeaconBlock(
                message: blck, signature: signature
              )

              unblindedBlockRef =
                await node.unblindAndRouteBlockMEV(payloadBuilderClient, blindedBlock)

            if unblindedBlockRef.isErr or unblindedBlockRef.get.isNone:
              # unblindedBlockRef.isErr or unblindedBlockRef.get.isNone indicates that
              # the block failed to validate or integrate into the DAG, which for the
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

              warn "Failed to unblind or route builder payload",
                validator = shortLog(validator),
                blck = shortLog(blindedBlock.message),
                err = errMsg

              # TODO Just because the relay didn't answer doesn't mean it was missed?
              beacon_block_builder_missed_without_fallback.inc()

              return head

            beacon_blocks_proposed.inc()
            return unblindedBlockRef.get.get

          if bids.engineBid.isNone() and state[].is_merge_transition_complete():
            # Cannot fall back to engine without a payload, post merge
            beacon_block_production_errors.inc()
            return head

          beacon_block_builder_missed_with_fallback.inc()

          notice "Failed to create builder-based block, trying engine payload",
            slot, error = builderBlockRes.error

          # makeBuilderBlock will invalidate the state - get a new one
          cache = new StateCache
          state = node.dag.getProposalState(head, slot, cache[]).valueOr:
            beacon_block_production_errors.inc()
            return head

        bids.engineBid
      else:
        type EPS = consensusFork.ExecutionPayloadForSigning
        await node.getExecutionPayload(
          EPS, head, state, validator_index, validator.pubkey
        )

    engineBlock = node.makeEngineBlock(
      consensusFork,
      state[],
      cache[],
      validator_index,
      randao_reveal,
      graffiti,
      head,
      slot,
      enginePayload,
    ).valueOr:
      beacon_block_production_errors.inc()
      return head

    blockRoot = node.registerBlock(validator, validator_index, engineBlock.blck).valueOr:
      beacon_block_production_errors.inc()
      return head

    signature = await(node.getBlockSignature(validator, blockRoot, engineBlock.blck)).valueOr:
      beacon_block_production_errors.inc()
      return head

    signedBlock = consensusFork.SignedBeaconBlock(
      message: engineBlock.blck, signature: signature, root: blockRoot
    )

    blobsOpt =
      when consensusFork >= ConsensusFork.Deneb:
        Opt.some(
          signedBlock.create_blob_sidecars(
            engineBlock.blobsBundle.proofs, engineBlock.blobsBundle.blobs
          )
        )
      else:
        Opt.none(seq[BlobSidecar])
    newBlockRef = await(
      node.router.routeSignedBeaconBlock(signedBlock, blobsOpt, checkValidator = false)
    ).valueOr:
      # TODO Is this an error?
      beacon_block_production_errors.inc()
      return head # Errors logged in router

  if newBlockRef.isNone():
    # TODO is this an error?
    beacon_block_production_errors.inc()
    return head # Validation errors logged in router

  notice "Block proposed",
    blockRoot = shortLog(blockRoot),
    blck = shortLog(signedBlock.message),
    signature = shortLog(signature),
    validator = shortLog(validator)

  beacon_blocks_proposed.inc()

  newBlockRef.get()

proc proposeBlock(
    node: BeaconNode, validator: AttachedValidator, head: BlockRef, slot: Slot
): Future[BlockRef] {.async: (raises: [CancelledError]).} =
  let
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root = node.dag.genesis_validators_root
    randao_reveal = (
      await validator.getEpochSignature(fork, genesis_validators_root, slot.epoch)
    ).valueOr:
      warn "Unable to generate randao reveal",
        validator = shortLog(validator), error_msg = error
      return head

  withConsensusFork(node.dag.cfg.consensusForkAtEpoch(slot.epoch)):
    when consensusFork >= ConsensusFork.Bellatrix:
      await node.proposeBlockAux(consensusFork, validator, head, slot, randao_reveal)
    else:
      warn "Block proposals for fork no longer supported", consensusFork
      head

proc sendAttestations(node: BeaconNode, head: BlockRef, slot: Slot) =
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
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/validator.md#validator-assignments
  let
    epochRef = node.dag.getEpochRef(
      attestationHead.blck, slot.epoch, false).valueOr:
        warn "Cannot construct EpochRef for attestation head, report bug",
          attestationHead = shortLog(attestationHead), slot, error
        return
    committees_per_slot = get_committee_count_per_slot(epochRef.shufflingRef)
    fork = node.dag.forkAtEpoch(slot.epoch)
    consensusFork = node.dag.cfg.consensusForkAtEpoch(slot.epoch)
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
          let
            validator = node.getValidatorForDuties(validator_index, slot).valueOr:
              continue
            data =
              if consensusFork >= ConsensusFork.Electra:
                makeAttestationData(epochRef, attestationHead, CommitteeIndex(0))
              else:
                makeAttestationData(epochRef, attestationHead, committee_index)
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
            validator: validator, validator_index: validator_index,
            committee_index: committee_index,
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
                                       head: BlockRef)
                                       {.async: (raises: [CancelledError]).} =
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

proc sendSyncCommitteeMessages(node: BeaconNode, head: BlockRef, slot: Slot) =
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
                             slot: Slot) {.async: (raises: [CancelledError]).} =
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

proc sendSyncCommitteeContributions(
    node: BeaconNode, head: BlockRef, slot: Slot) =
  let syncCommittee = node.dag.syncCommitteeParticipants(slot + 1)

  for subcommitteeIdx in SyncSubcommitteeIndex:
    for valIdx in syncSubcommittee(syncCommittee, subcommitteeIdx):
      let validator = node.getValidatorForDuties(
          valIdx, slot, slashingSafe = true).valueOr:
        continue

      asyncSpawn signAndSendContribution(
        node, validator, subcommitteeIdx, head, slot)

proc handleProposal(node: BeaconNode, head: BlockRef, slot: Slot):
    Future[BlockRef] {.async: (raises: [CancelledError]).} =
  ## Perform the proposal for the given slot, iff we have a validator attached
  ## that is supposed to do so, given the shuffling at that slot for the given
  ## head - to compute the proposer, we need to advance a state to the given
  ## slot
  if head.slot >= slot:
    # We should normally not have a head newer than the slot we're proposing for
    # but this can happen if block proposal is delayed
    warn "Skipping proposal, have newer head already",
      headSlot = shortLog(head.slot),
      headBlockRoot = shortLog(head.root),
      slot = shortLog(slot)
    return head

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

  await proposeBlock(node, validator, head, slot)

proc signAndSendAggregate(
    node: BeaconNode, validator: AttachedValidator, shufflingRef: ShufflingRef,
    slot: Slot, committee_index: CommitteeIndex) {.async: (raises: [CancelledError]).} =
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

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/validator.md#aggregation-selection
  if not is_aggregator(shufflingRef, slot, committee_index, selectionProof):
    return

  template signAndSendAggregatedAttestations() =
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

  if node.dag.cfg.consensusForkAtEpoch(slot.epoch) >= ConsensusFork.Electra:
    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/electra/validator.md#construct-aggregate
    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/electra/validator.md#aggregateandproof
    var msg = electra.SignedAggregateAndProof(
      message: electra.AggregateAndProof(
        aggregator_index: distinctBase validator_index,
        selection_proof: selectionProof))

    msg.message.aggregate = node.attestationPool[].getElectraAggregatedAttestation(
      slot, committee_index).valueOr:
        return

    signAndSendAggregatedAttestations()
  else:
    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/phase0/validator.md#construct-aggregate
    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/phase0/validator.md#aggregateandproof
    var msg = phase0.SignedAggregateAndProof(
      message: phase0.AggregateAndProof(
        aggregator_index: distinctBase validator_index,
        selection_proof: selectionProof))

    msg.message.aggregate = node.attestationPool[].getPhase0AggregatedAttestation(
      slot, committee_index).valueOr:
        return

    signAndSendAggregatedAttestations()

proc sendAggregatedAttestations(
    node: BeaconNode, head: BlockRef, slot: Slot) =
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
    Future[Result[SignedValidatorRegistrationV1, string]] {.async: (raises: [CancelledError]).} =
  if validator.index.isNone:
    # The validator index will be missing when the validator was not
    # activated for duties yet. We can safely skip the registration then.
    return

  let
    feeRecipient = node.getFeeRecipient(validator.pubkey, validator.index, epoch)
    gasLimit = node.getGasLimit(validator.pubkey)

  var validatorRegistration = SignedValidatorRegistrationV1(
    message: ValidatorRegistrationV1(
      fee_recipient: feeRecipient,
      gas_limit: gasLimit,
      timestamp: epochTime().uint64,
      pubkey: validator.pubkey,
    )
  )

  debug "getValidatorRegistration: registering", validatorRegistration

  validatorRegistration.signature =
    ?await validator.getBuilderSignature(
      node.dag.cfg.GENESIS_FORK_VERSION, validatorRegistration.message
    )

  ok validatorRegistration

proc registerValidatorsPerBuilder(
    node: BeaconNode, payloadBuilderAddress: string, epoch: Epoch,
    attachedValidatorPubkeys: seq[ValidatorPubKey]) {.async: (raises: [CancelledError]).} =
  const
    HttpOk = 200
    BUILDER_VALIDATOR_REGISTRATION_DELAY_TOLERANCE = 6.seconds

  let payloadBuilderClient =
    block:
      let
        flags = {RestClientFlag.CommaSeparatedArray,
                 RestClientFlag.ResolveAlways}
        socketFlags = {SocketFlags.TcpNoDelay}
      RestClientRef.new(payloadBuilderAddress, flags = flags,
                        socketFlags = socketFlags).valueOr:
        debug "Unable to initialize payload builder client while registering validators",
          payloadBuilderAddress, epoch, reason = error
        return

  if payloadBuilderClient.isNil:
    debug "registerValidatorsPerBuilder: got nil payload builder REST client reference",
      payloadBuilderAddress, epoch
    return

  const emptyNestedSeq = @[newSeq[SignedValidatorRegistrationV1](0)]
  # https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/bellatrix/validator.md#validator-registration
  # Seed with single empty inner list to avoid special cases
  var validatorRegistrations = emptyNestedSeq

  # Some relay networks disallow large request bodies, so split requests
  template addValidatorRegistration(
      validatorRegistration: SignedValidatorRegistrationV1) =
    const registrationValidatorChunkSize = 500

    if validatorRegistrations[^1].len < registrationValidatorChunkSize:
      validatorRegistrations[^1].add validatorRegistration
    else:
      validatorRegistrations.add @[validatorRegistration]

  # First, check for VC-added keys; cheaper because provided pre-signed
  # See issue #5599: currently VC have no way to provide BN with per-validator
  #   builders per the specs, so we have to resort to use the BN fallback
  #   default (--payload-builder-url value, obtained by calling
  #   getPayloadBuilderAddress)
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
        if forkyState.data.validators.item(i).exit_epoch > currentEpoch:
          let pubkey = forkyState.data.validators.item(i).pubkey
          node.externalBuilderRegistrations.withValue(
              pubkey, signedValidatorRegistration):
            nonExitedVcPubkeys.incl signedValidatorRegistration[].message.pubkey
            addValidatorRegistration signedValidatorRegistration[]

  for key in attachedValidatorPubkeys:
    # Already included from VC
    if key in nonExitedVcPubkeys:
      warn "registerValidators: same validator registered by beacon node and validator client",
        pubkey = shortLog(key)
      continue

    # Time passed during awaits; REST keymanager API might have removed it
    if key notin node.attachedValidators[].validators:
      continue

    let validator =
      try:
        node.attachedValidators[].validators[key]
      except KeyError:
        raiseAssert "just checked"

    if validator.index.isNone:
      continue

    # https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/bellatrix/builder.md#is_eligible_for_registration
    # Validators should be active or pending
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
      let validator = try:
        node.attachedValidators[].validators[key]
      except KeyError:
        raiseAssert "just checked"

      validator.externalBuilderRegistration = Opt.some validatorRegistration.get
      addValidatorRegistration validatorRegistration.get

  if validatorRegistrations == emptyNestedSeq:
    return

  # TODO if there are too many chunks, could trigger DoS protections, so
  # might randomize order to accumulate cumulative coverage
  for chunkIdx in 0 ..< validatorRegistrations.len:
    let registerValidatorResult =
      try:
        awaitWithTimeout(
            payloadBuilderClient.registerValidator(
              validatorRegistrations[chunkIdx]),
            BUILDER_VALIDATOR_REGISTRATION_DELAY_TOLERANCE):
          error "Timeout when registering validator with builder"
          continue  # Try next batch regardless
      except RestError as exc:
        warn "Error when registering validator(s) with builder", err = exc.msg
        continue

    if HttpOk != registerValidatorResult.status:
      warn "registerValidators: Couldn't register validator with MEV builder",
        registerValidatorResult

proc registerValidators*(node: BeaconNode, epoch: Epoch) {.async: (raises: [CancelledError]).} =
  if not node.config.payloadBuilderEnable: return

  var builderKeys: Table[string, seq[ValidatorPubKey]]

  # Ensure VC validators are still registered if we have no attached validators
  let externalPayloadBuilderAddress = node.config.getPayloadBuilderAddress
  if externalPayloadBuilderAddress.isSome:
    builderKeys[externalPayloadBuilderAddress.value] = newSeq[ValidatorPubKey](0)

  for pubkey in node.attachedValidators[].validators.keys:
    let payloadBuilderAddress = node.getPayloadBuilderAddress(pubkey).valueOr:
      continue

    builderKeys.mgetOrPut(
      payloadBuilderAddress, default(seq[ValidatorPubKey])).add pubkey

  for payloadBuilderAddress, keys in builderKeys:
    await node.registerValidatorsPerBuilder(payloadBuilderAddress, epoch, keys)

proc updateValidators(
    node: BeaconNode, validators: openArray[Validator]) =
  # Since validator indicies are stable, we only check the "updated" range -
  # checking all validators would significantly slow down this loop when there
  # are many inactive keys
  for i in node.dutyValidatorCount..validators.high:
    let
      v = node.attachedValidators[].getValidator(validators[i].pubkey).valueOr:
        continue
    node.attachedValidators[].setValidatorIndex(v, ValidatorIndex(i))

  node.dutyValidatorCount = validators.len

  for validator in node.attachedValidators[]:
    # Check if any validators have been activated
    if validator.needsUpdate and validator.index.isSome():
      # Activation epoch can change after index is assigned..
      let index = validator.index.get()
      if index < validators.lenu64:
        node.attachedValidators[].updateValidator(
          validator,
          Opt.some(ValidatorAndIndex(
            index: index, validator: validators[int index]
          ))
        )

proc handleFallbackAttestations(node: BeaconNode, lastSlot, slot: Slot) =
  # Neither block proposal nor sync committee duties can be done in this
  # situation.
  let attestationHead = node.lastValidAttestedBlock.valueOr:
    return

  if attestationHead.slot + SLOTS_PER_EPOCH < slot:
    return

  sendAttestations(node, attestationHead.blck, slot)

proc handleValidatorDuties*(node: BeaconNode, lastSlot, slot: Slot) {.async: (raises: [CancelledError]).} =
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

    handleFallbackAttestations(node, lastSlot, slot)

    # Rewards will be growing though, as we sync..
    updateValidatorMetrics(node)

    return
  else:
    discard # keep going

  node.lastValidAttestedBlock = Opt.some head.atSlot()

  withState(node.dag.headState):
    node.updateValidators(forkyState.data.validators.asSeq())

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

  sendAttestations(node, head, slot)
  sendSyncCommitteeMessages(node, head, slot)

  updateValidatorMetrics(node) # the important stuff is done, update the vanity numbers

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/phase0/validator.md#broadcast-aggregate
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/altair/validator.md#broadcast-sync-committee-contribution
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

  sendAggregatedAttestations(node, head, slot)
  sendSyncCommitteeContributions(node, head, slot)

proc registerDuties*(node: BeaconNode, wallSlot: Slot) {.async: (raises: [CancelledError]).} =
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

