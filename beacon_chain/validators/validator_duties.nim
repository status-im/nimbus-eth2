# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/[os, osproc, sequtils, streams, tables],

  # Nimble packages
  stew/[assign2, byteutils, objects],
  chronos, metrics,
  chronicles, chronicles/timings,
  json_serialization/std/[options, sets, net], serialization/errors,
  eth/db/kvstore,
  eth/keys, eth/p2p/discoveryv5/[protocol, enr],

  # Local modules
  ../spec/datatypes/[phase0, altair, merge],
  ../spec/[
    eth2_merkleization, forks, helpers, network, signatures, state_transition],
  ../consensus_object_pools/[
    spec_cache, blockchain_dag, block_clearance, attestation_pool, exit_pool,
    sync_committee_msg_pool],
  ../eth1/eth1_monitor,
  ../networking/eth2_network,
  ../sszdump, ../sync/sync_manager,
  ../gossip_processing/consensus_manager,
  ".."/[conf, beacon_clock, beacon_node_common, beacon_node_types, version],
  "."/[slashing_protection, validator_pool, keystore_management]

# Metrics for tracking attestation and beacon block loss
const delayBuckets = [-Inf, -4.0, -2.0, -1.0, -0.5, -0.1, -0.05,
                      0.05, 0.1, 0.5, 1.0, 2.0, 4.0, 8.0, Inf]

declareCounter beacon_attestations_sent,
  "Number of beacon chain attestations sent by this peer"

declareHistogram beacon_attestation_sent_delay,
  "Time(s) between slot start and attestation sent moment",
  buckets = delayBuckets

declareCounter beacon_sync_committee_messages_sent,
  "Number of sync committee messages sent by this peer"

declareCounter beacon_sync_committee_contributions_sent,
  "Number of sync committee contributions sent by this peer"

declareHistogram beacon_sync_committee_message_sent_delay,
  "Time(s) between slot start and sync committee message sent moment",
  buckets = delayBuckets

declareCounter beacon_blocks_proposed,
  "Number of beacon chain blocks sent by this peer"

declareGauge(attached_validator_balance,
  "Validator balance at slot end of the first 64 validators, in Gwei",
  labels = ["pubkey"])

declarePublicGauge(attached_validator_balance_total,
  "Validator balance of all attached validators, in Gwei")

logScope: topics = "beacval"

type
  SendResult* = Result[void, cstring]
  SendBlockResult* = Result[bool, cstring]
  ForkedBlockResult* = Result[ForkedBeaconBlock, string]

proc findValidator(validators: auto, pubKey: ValidatorPubKey):
    Option[ValidatorIndex] =
  let idx = validators.findIt(it.pubKey == pubKey)
  if idx == -1:
    # We allow adding a validator even if its key is not in the state registry:
    # it might be that the deposit for this validator has not yet been processed
    notice "Validator deposit not yet processed, monitoring", pubKey
    none(ValidatorIndex)
  else:
    some(idx.ValidatorIndex)

proc addLocalValidator(node: BeaconNode, item: ValidatorPrivateItem) =
  node.attachedValidators[].addLocalValidator(item)

proc addLocalValidators*(node: BeaconNode) =
  for validatorItem in node.config.validatorItems():
    node.addLocalValidator(validatorItem)

proc addRemoteValidators*(node: BeaconNode) {.raises: [Defect, OSError, IOError].} =
  # load all the validators from the child process - loop until `end`
  var line = newStringOfCap(120).TaintedString
  while line != "end" and running(node.vcProcess):
    if node.vcProcess.outputStream.readLine(line) and line != "end":
      let
        key = ValidatorPubKey.fromHex(line).get()
        index = findValidator(
          getStateField(node.dag.headState.data, validators).asSeq, key)
        pk = key.load()
      if pk.isSome():
        let v = AttachedValidator(pubKey: key,
                                  index: index,
                                  kind: ValidatorKind.Remote,
                                  connection: ValidatorConnection(
                                    inStream: node.vcProcess.inputStream,
                                    outStream: node.vcProcess.outputStream,
                                    pubKeyStr: $key))
        node.attachedValidators[].addRemoteValidator(key, v)
      else:
        warn "Could not load public key", line

proc getAttachedValidator*(node: BeaconNode,
                           pubkey: ValidatorPubKey): AttachedValidator =
  node.attachedValidators[].getValidator(pubkey)

proc getAttachedValidator*(node: BeaconNode,
                           state_validators: auto,
                           idx: ValidatorIndex): AttachedValidator =
  if idx < state_validators.len.ValidatorIndex:
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

proc getAttachedValidator*(node: BeaconNode,
                           epochRef: EpochRef,
                           idx: ValidatorIndex): AttachedValidator =
  let key = epochRef.validatorKey(idx)
  if key.isSome():
    let validator = node.getAttachedValidator(key.get().toPubKey())
    if validator != nil and validator.index != some(idx.ValidatorIndex):
      # Update index, in case the validator was activated!
      notice "Validator activated", pubkey = validator.pubkey, index = idx
      validator.index  = some(idx.ValidatorIndex)
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

  # TODO: MaxEmptySlotCount should likely involve the weak subjectivity period.

  # TODO if everyone follows this logic, the network will not recover from a
  #      halt: nobody will be producing blocks because everone expects someone
  #      else to do it
  if wallSlot.afterGenesis and head.slot + MaxEmptySlotCount < wallSlot.slot:
    false
  else:
    true

proc sendAttestation*(
    node: BeaconNode, attestation: Attestation,
    subnet_id: SubnetId, checkSignature: bool): Future[bool] {.async.} =
  # Validate attestation before sending it via gossip - validation will also
  # register the attestation with the attestation pool. Notably, although
  # libp2p calls the data handler for any subscription on the subnet
  # topic, it does not perform validation.
  let ok = await node.processor.attestationValidator(
    attestation, subnet_id, checkSignature)

  return case ok
    of ValidationResult.Accept:
      node.network.broadcastAttestation(subnet_id, attestation)
      beacon_attestations_sent.inc()
      if not(isNil(node.onAttestationSent)):
        node.onAttestationSent(attestation)
      true
    else:
      notice "Produced attestation failed validation",
        attestation = shortLog(attestation),
        result = $ok
      false

proc sendSyncCommitteeMessage*(
    node: BeaconNode, msg: SyncCommitteeMessage,
    committeeIdx: SyncCommitteeIndex,
    checkSignature: bool): Future[SendResult] {.async.} =
  # Validate sync committee message before sending it via gossip
  # validation will also register the message with the sync committee
  # message pool. Notably, although libp2p calls the data handler for
  # any subscription on the subnet topic, it does not perform validation.
  let res = node.processor.syncCommitteeMsgValidator(msg, committeeIdx,
                                                     checkSignature)
  return
    case res
    of ValidationResult.Accept:
      node.network.broadcastSyncCommitteeMessage(msg, committeeIdx)
      beacon_sync_committee_messages_sent.inc()
      SendResult.ok()
    else:
      notice "Sync committee message failed validation",
             msg, result = $res
      SendResult.err("Sync committee message failed validation")

proc sendSyncCommitteeMessages*(node: BeaconNode,
                                msgs: seq[SyncCommitteeMessage]
                               ): Future[seq[SendResult]] {.async.} =
  let validators = getStateField(node.dag.headState.data, validators)
  var statuses = newSeq[Option[SendResult]](len(msgs))

  let ranges =
    block:
      let
        headSlot = getStateField(node.dag.headState.data, slot)
        headCommitteePeriod = syncCommitteePeriod(headSlot)
        currentStart = syncCommitteePeriodStartSlot(headCommitteePeriod)
        currentFinish = currentStart + SLOTS_PER_SYNC_COMMITTEE_PERIOD
        nextStart = currentFinish
        nextFinish = nextStart + SLOTS_PER_SYNC_COMMITTEE_PERIOD
      (curStart: Slot(currentStart), curFinish: Slot(currentFinish),
        nxtStart: Slot(nextStart), nxtFinish: Slot(nextFinish))

  let (keysCur, keysNxt) =
    block:
      var resCur: Table[ValidatorPubKey, int]
      var resNxt: Table[ValidatorPubKey, int]
      for index, msg in msgs.pairs():
        if msg.validator_index < lenu64(validators):
          if (msg.slot >= ranges.curStart) and (msg.slot < ranges.curFinish):
            resCur[validators[msg.validator_index].pubkey] = index
          elif (msg.slot >= ranges.nxtStart) and (msg.slot < ranges.nxtFinish):
            resNxt[validators[msg.validator_index].pubkey] = index
          else:
            statuses[index] =
              some(SendResult.err("Message's slot out of state's head range"))
        else:
          statuses[index] = some(SendResult.err("Incorrect validator's index"))
      if (len(resCur) == 0) and (len(resNxt) == 0):
        return statuses.mapIt(it.get())
      (resCur, resNxt)

  let (pending, indices) =
    withState(node.dag.headState.data):
      when stateFork >= forkAltair:
        var resFutures: seq[Future[SendResult]]
        var resIndices: seq[int]
        for committeeIdx in allSyncCommittees():
          for valKey in syncSubcommittee(
              state.data.current_sync_committee.pubkeys.data, committeeIdx):
            let index = keysCur.getOrDefault(valKey, -1)
            if index >= 0:
              resIndices.add(index)
              resFutures.add(node.sendSyncCommitteeMessage(msgs[index],
                                                           committeeIdx, true))
        for committeeIdx in allSyncCommittees():
          for valKey in syncSubcommittee(
              state.data.next_sync_committee.pubkeys.data, committeeIdx):
            let index = keysNxt.getOrDefault(valKey, -1)
            if index >= 0:
              resIndices.add(index)
              resFutures.add(node.sendSyncCommitteeMessage(msgs[index],
                                                           committeeIdx, true))
        (resFutures, resIndices)
      else:
        raiseAssert "Sync committee not available in Phase0"

  await allFutures(pending)

  for index, future in pending.pairs():
    if future.done():
      let fres = future.read()
      if fres.isErr():
        statuses[indices[index]] = some(SendResult.err(fres.error()))
      else:
        statuses[indices[index]] = some(SendResult.ok())
    elif future.failed() or future.cancelled():
      let exc = future.readError()
      debug "Unexpected failure while sending committee message",
        message = msgs[indices[index]], error = $exc.msg
      statuses[indices[index]] = some(SendResult.err(
        "Unexpected failure while sending committee message"))

  let results =
    block:
      var res: seq[SendResult]
      for item in statuses:
        if item.isSome():
          res.add(item.get())
        else:
          res.add(SendResult.err("Message validator not in sync committee"))
      res
  return results

proc sendSyncCommitteeContribution*(
    node: BeaconNode,
    msg: SignedContributionAndProof,
    checkSignature: bool): Future[SendResult] {.async.} =
  let ok = node.processor.syncCommitteeContributionValidator(
    msg, checkSignature)

  return case ok
    of ValidationResult.Accept:
      node.network.broadcastSignedContributionAndProof(msg)
      beacon_sync_committee_contributions_sent.inc()
      SendResult.ok()
    else:
      notice "Sync committee contribution failed validation",
              msg, result = $ok
      SendResult.err("Sync committee contribution failed validation")

proc createAndSendAttestation(node: BeaconNode,
                              fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              validator: AttachedValidator,
                              attestationData: AttestationData,
                              committeeLen: int,
                              indexInCommittee: int,
                              subnet_id: SubnetId) {.async.} =
  try:
    var
      attestation = await validator.produceAndSignAttestation(
        attestationData, committeeLen, indexInCommittee, fork,
        genesis_validators_root)

    let ok = await node.sendAttestation(
      attestation, subnet_id, checkSignature = false)
    if not ok: # Logged in sendAttestation
      return

    if node.config.dumpEnabled:
      dump(node.config.dumpDirOutgoing, attestation.data,
           validator.pubKey)

    let wallTime = node.beaconClock.now()
    let deadline = attestationData.slot.toBeaconTime() +
                  seconds(int(SECONDS_PER_SLOT div 3))

    let (delayStr, delaySecs) =
      if wallTime < deadline:
        ("-" & $(deadline - wallTime), -toFloatSeconds(deadline - wallTime))
      else:
        ($(wallTime - deadline), toFloatSeconds(wallTime - deadline))

    notice "Attestation sent",
      attestation = shortLog(attestation), validator = shortLog(validator),
      delay = delayStr

    beacon_attestation_sent_delay.observe(delaySecs)
  except CatchableError as exc:
    # An error could happen here when the signature task fails - we must
    # not leak the exception because this is an asyncSpawn task
    notice "Error sending attestation", err = exc.msg

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

func get_pow_block(pow_chain: openArray[PowBlock], parent_hash: Eth2Digest):
    Opt[PoWBlock] =
  # Placeholder, pending performance importance. This whole thing is pretty
  # literal
  for pow_block in pow_chain:
    if parent_hash == pow_block.block_hash:
      return ok(pow_block)

  err()

# https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/merge/validator.md#executionpayload
func get_pow_block_at_terminal_total_difficulty(pow_chain: openArray[PowBlock]):
    Opt[PowBlock] =
  # `pow_chain` abstractly represents all blocks in the PoW chain

  const TERMINAL_TOTAL_DIFFICULTY = 0   # just first block

  for blck in pow_chain:
    # TODO oh, actually do need something like Uint256
    when false:
      let
        parent = get_pow_block(pow_chain, blck.parent_hash)
        block_reached_ttd = blck.total_difficulty >= TERMINAL_TOTAL_DIFFICULTY
        parent_reached_ttd = parent.total_difficulty >= TERMINAL_TOTAL_DIFFICULTY
      if block_reached_ttd and not parent_reached_ttd:
        return blck
    else:
      return ok(blck)

  err()

func get_terminal_pow_block(pow_chain: openArray[PowBlock]): Opt[PowBlock] =
  # supposedly part of mainnet config, maybe others
  const TERMINAL_BLOCK_HASH = Eth2Digest()

  if TERMINAL_BLOCK_HASH != Eth2Digest():
    # Terminal block hash override takes precedence over terminal total
    # difficulty
    let pow_block_overrides = filterIt(pow_chain, it.block_hash == TERMINAL_BLOCK_HASH)
    if pow_block_overrides.len == 0:
      return err()
    return ok(pow_block_overrides[0])

  get_pow_block_at_terminal_total_difficulty(pow_chain)

proc prepare_execution_payload(state: merge.BeaconState,
                               pow_chain: openArray[PowBlock],
                               fee_recipient: Address,
                               execution_engine: Web3DataProviderRef):
                               Future[Opt[PayloadId]] {.async.} =
  var parent_hash: Eth2Digest
  if not is_merge_complete(state):
    let terminal_pow_block = get_terminal_pow_block(pow_chain)
    if terminal_pow_block.isErr():
      # Pre-merge, no prepare payload call is needed
      return err()

    # Signify merge via producing on top of the terminal PoW block
    parent_hash = terminal_pow_block.get.block_hash
  else:
    # Post-merge, normal payload
    parent_hash = state.latest_execution_payload_header.block_hash

  let
    timestamp = compute_timestamp_at_slot(state, state.slot)
    random = get_randao_mix(state, get_current_epoch(state))
  return ok((await execution_engine.prepare_payload(
    parent_hash, timestamp, random.data, fee_recipient)).payloadId.PayloadId)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/merge/validator.md#executionpayload
proc get_execution_payload(
    payload_id: Opt[PayloadId], execution_engine: Web3DataProviderRef):
    Future[merge.ExecutionPayload] {.async.} =
  return if payload_id.isErr():
    # Pre-merge, empty payload
    default(merge.ExecutionPayload)
  else:
    let rpcExecutionPayload =
      await execution_engine.get_payload(payload_id.get.Quantity)
    merge.ExecutionPayload(
      parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
      coinbase: EthAddress(data: rpcExecutionPayload.coinbase.distinctBase),
      state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
      receipt_root: rpcExecutionPayload.receiptRoot.asEth2Digest,
      logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
      random: rpcExecutionPayload.random.asEth2Digest,
      block_number: rpcExecutionPayload.blockNumber.uint64,
      gas_limit: rpcExecutionPayload.gasLimit.uint64,
      gas_used: rpcExecutionPayload.gasUsed.uint64,
      timestamp: rpcExecutionPayload.timestamp.uint64,
      extra_data: List[byte, 32].init(rpcExecutionPayload.extraData.distinctBase),
      #base_fee_per_gas: rpcExecutionPayload.baseFeePerGas, TODO
      block_hash: rpcExecutionPayload.blockHash.asEth2Digest,

      # TODO
      # transactions: rpcExecutionPayload.transactions
    )

proc makeBeaconBlockForHeadAndSlot*(node: BeaconNode,
                                    randao_reveal: ValidatorSig,
                                    validator_index: ValidatorIndex,
                                    graffiti: GraffitiBytes,
                                    head: BlockRef, slot: Slot
                                   ): Future[ForkedBlockResult] {.async.} =
  # Advance state to the slot that we're proposing for

  let
    proposalState = assignClone(node.dag.headState)
    proposalStateAddr = unsafeAddr proposalState[]

  node.dag.withState(proposalState[], head.atSlot(slot)):
    let
      eth1Proposal = node.getBlockProposalEth1Data(stateData.data)
      poolPtr = unsafeAddr node.dag # safe because restore is short-lived

    if eth1Proposal.hasMissingDeposits:
      error "Eth1 deposits not available. Skipping block proposal", slot
      return ForkedBlockResult.err("Eth1 deposits not available")

    func restore(v: var ForkedHashedBeaconState) =
      # TODO address this ugly workaround - there should probably be a
      #      `state_transition` that takes a `StateData` instead and updates
      #      the block as well
      doAssert v.addr == addr proposalStateAddr.data
      assign(proposalStateAddr[], poolPtr.headState)

    return makeBeaconBlock(
      node.dag.cfg,
      stateData.data,
      validator_index,
      head.root,
      randao_reveal,
      eth1Proposal.vote,
      graffiti,
      node.attestationPool[].getAttestationsForBlock(stateData.data, cache),
      eth1Proposal.deposits,
      node.exitPool[].getProposerSlashingsForBlock(),
      node.exitPool[].getAttesterSlashingsForBlock(),
      node.exitPool[].getVoluntaryExitsForBlock(),
      if slot.epoch < node.dag.cfg.ALTAIR_FORK_EPOCH:
        SyncAggregate.init()
      else:
        node.sync_committee_msg_pool[].produceSyncAggregate(head.root),
      default(merge.ExecutionPayload),
      restore,
      cache)

proc proposeSignedBlock*(node: BeaconNode,
                         head: BlockRef,
                         validator: AttachedValidator,
                         newBlock: ForkedSignedBeaconBlock):
                         Future[BlockRef] {.async.} =
  let newBlockRef =
    case newBlock.kind:
    of BeaconBlockFork.Phase0:
      node.dag.addRawBlock(node.quarantine, newBlock.phase0Block) do (
          blckRef: BlockRef, trustedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if signed block valid (and becomes trusted)
        node.attestationPool[].addForkChoice(
          epochRef, blckRef, trustedBlock.message,
          node.beaconClock.now().slotOrZero())
    of BeaconBlockFork.Altair:
      node.dag.addRawBlock(node.quarantine, newBlock.altairBlock) do (
          blckRef: BlockRef, trustedBlock: altair.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if signed block valid (and becomes trusted)
        node.attestationPool[].addForkChoice(
          epochRef, blckRef, trustedBlock.message,
          node.beaconClock.now().slotOrZero())
    of BeaconBlockFork.Merge:
      node.dag.addRawBlock(node.quarantine, newBlock.mergeBlock) do (
          blckRef: BlockRef, trustedBlock: merge.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if signed block valid (and becomes trusted)
        node.attestationPool[].addForkChoice(
          epochRef, blckRef, trustedBlock.message,
          node.beaconClock.now().slotOrZero())

  if newBlockRef.isErr:
    withBlck(newBlock):
      warn "Unable to add proposed block to block pool",
            newBlock = blck.message, root = blck.root
    return head

  withBlck(newBlock):
    notice "Block proposed",
           blck = shortLog(blck.message), root = blck.root,
           validator = shortLog(validator)

    if node.config.dumpEnabled:
      dump(node.config.dumpDirOutgoing, blck)

  node.network.broadcastBeaconBlock(newBlock)

  beacon_blocks_proposed.inc()

  return newBlockRef[]

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
    genesis_validators_root =
      getStateField(node.dag.headState.data, genesis_validators_root)
    randao = await validator.genRandaoReveal(
      fork, genesis_validators_root, slot)
  var newBlock = await makeBeaconBlockForHeadAndSlot(
    node, randao, validator_index, node.graffitiBytes, head, slot)

  if newBlock.isErr():
    return head # already logged elsewhere!

  let blck = newBlock.get()

  # TODO abstract this, or move it into makeBeaconBlockForHeadAndSlot, and in
  # general this is far too much copy/paste
  let forked = case blck.kind:
  of BeaconBlockFork.Phase0:
    let root = hash_tree_root(blck.phase0Block)

    # TODO: recomputed in block proposal
    let signing_root = compute_block_root(
      fork, genesis_validators_root, slot, root)
    let notSlashable = node.attachedValidators
      .slashingProtection
      .registerBlock(validator_index, validator.pubkey, slot, signing_root)

    if notSlashable.isErr:
      warn "Slashing protection activated",
        validator = validator.pubkey,
        slot = slot,
        existingProposal = notSlashable.error
      return head

    let signature = await validator.signBlockProposal(
      fork, genesis_validators_root, slot, root)
    ForkedSignedBeaconBlock.init(
      phase0.SignedBeaconBlock(
        message: blck.phase0Block, root: root, signature: signature)
    )
  of BeaconBlockFork.Altair:
    let root = hash_tree_root(blck.altairBlock)

    # TODO: recomputed in block proposal
    let signing_root = compute_block_root(
      fork, genesis_validators_root, slot, root)
    let notSlashable = node.attachedValidators
      .slashingProtection
      .registerBlock(validator_index, validator.pubkey, slot, signing_root)

    if notSlashable.isErr:
      warn "Slashing protection activated",
        validator = validator.pubkey,
        slot = slot,
        existingProposal = notSlashable.error
      return head

    let signature = await validator.signBlockProposal(
      fork, genesis_validators_root, slot, root)

    ForkedSignedBeaconBlock.init(
      altair.SignedBeaconBlock(
        message: blck.altairBlock, root: root, signature: signature)
    )
  of BeaconBlockFork.Merge:
    let root = hash_tree_root(blck.mergeBlock)

    # TODO: recomputed in block proposal
    let signing_root = compute_block_root(
      fork, genesis_validators_root, slot, root)
    let notSlashable = node.attachedValidators
      .slashingProtection
      .registerBlock(validator_index, validator.pubkey, slot, signing_root)

    if notSlashable.isErr:
      warn "Slashing protection activated",
        validator = validator.pubkey,
        slot = slot,
        existingProposal = notSlashable.error
      return head

    let signature = await validator.signBlockProposal(
      fork, genesis_validators_root, slot, root)

    ForkedSignedBeaconBlock.init(
      merge.SignedBeaconBlock(
        message: blck.mergeBlock, root: root, signature: signature)
    )

  return await node.proposeSignedBlock(head, validator, forked)

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
      headSlot = shortLog(head.slot),
      slot = shortLog(slot)
    return

  let attestationHead = head.atSlot(slot)
  if head != attestationHead.blck:
    # In rare cases, such as when we're busy syncing or just slow, we'll be
    # attesting to a past state - we must then recreate the world as it looked
    # like back then
    notice "Attesting to a state in the past, falling behind?",
      headSlot = shortLog(head.slot),
      attestationHeadSlot = shortLog(attestationHead.slot),
      attestationSlot = shortLog(slot)

  trace "Checking attestations",
    attestationHeadRoot = shortLog(attestationHead.blck.root),
    attestationSlot = shortLog(slot)

  # We need to run attestations exactly for the slot that we're attesting to.
  # In case blocks went missing, this means advancing past the latest block
  # using empty slots as fillers.
  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/validator.md#validator-assignments
  let
    epochRef = node.dag.getEpochRef(
      attestationHead.blck, slot.compute_epoch_at_slot())
    committees_per_slot = get_committee_count_per_slot(epochRef)
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesis_validators_root =
      getStateField(node.dag.headState.data, genesis_validators_root)

  for committee_index in get_committee_indices(epochRef):
    let committee = get_beacon_committee(epochRef, slot, committee_index)

    for index_in_committee, validator_index in committee:
      let validator = node.getAttachedValidator(epochRef, validator_index)
      if validator == nil:
        continue

      let
        data = makeAttestationData(epochRef, attestationHead, committee_index)
        # TODO signing_root is recomputed in produceAndSignAttestation/signAttestation just after
        signing_root = compute_attestation_root(
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
          committees_per_slot, data.slot, data.index.CommitteeIndex)
        asyncSpawn createAndSendAttestation(
          node, fork, genesis_validators_root, validator, data,
          committee.len(), index_in_committee, subnet_id)
      else:
        warn "Slashing protection activated for attestation",
          validator = validator.pubkey,
          badVoteDetails = $registered.error()

proc createAndSendSyncCommitteeMessage(node: BeaconNode,
                                       slot: Slot,
                                       validator: AttachedValidator,
                                       committeeIdx: SyncCommitteeIndex,
                                       head: BlockRef) {.async.} =
  try:
    let
      fork = node.dag.forkAtEpoch(slot.epoch)
      genesisValidatorsRoot = node.dag.genesisValidatorsRoot
      msg = await signSyncCommitteeMessage(validator, slot, fork,
                                           genesisValidatorsRoot, head.root)

    let res = await node.sendSyncCommitteeMessage(
      msg, committeeIdx, checkSignature = false)
    if res.isErr():
      # Logged in sendSyncCommitteeMessage
      return

    if node.config.dumpEnabled:
      dump(node.config.dumpDirOutgoing, msg, validator.pubKey)

    let
      wallTime = node.beaconClock.now()
      deadline = msg.slot.toBeaconTime() +
                 seconds(int(SECONDS_PER_SLOT div 3))

    let (delayStr, delaySecs) =
      if wallTime < deadline:
        ("-" & $(deadline - wallTime), -toFloatSeconds(deadline - wallTime))
      else:
        ($(wallTime - deadline), toFloatSeconds(wallTime - deadline))

    notice "Sync committee message sent",
            message = shortLog(msg),
            validator = shortLog(validator),
            delay = delayStr

    beacon_sync_committee_message_sent_delay.observe(delaySecs)
  except CatchableError as exc:
    # An error could happen here when the signature task fails - we must
    # not leak the exception because this is an asyncSpawn task
    notice "Error sending sync committee message", err = exc.msg

proc handleSyncCommitteeMessages(node: BeaconNode, head: BlockRef, slot: Slot) =
  # TODO Use a view type to avoid the copy
  var syncCommittee = @(node.dag.syncCommitteeParticipants(slot + 1))

  for committeeIdx in allSyncCommittees():
    for valKey in syncSubcommittee(syncCommittee, committeeIdx):
      let validator = node.getAttachedValidator(valKey)
      if isNil(validator) or validator.index.isNone():
        continue
      asyncSpawn createAndSendSyncCommitteeMessage(node, slot, validator,
                                                   committeeIdx, head)

proc signAndSendContribution(node: BeaconNode,
                             validator: AttachedValidator,
                             contribution: SyncCommitteeContribution,
                             selectionProof: ValidatorSig) {.async.} =
  try:
    let msg = (ref SignedContributionAndProof)(
      message: ContributionAndProof(
        aggregator_index: uint64 validator.index.get,
        contribution: contribution,
        selection_proof: selectionProof))

    await validator.sign(msg,
                         node.dag.forkAtEpoch(contribution.slot.epoch),
                         node.dag.genesisValidatorsRoot)

    # Failures logged in sendSyncCommitteeContribution
    discard await node.sendSyncCommitteeContribution(msg[], false)
  except CatchableError as exc:
    # An error could happen here when the signature task fails - we must
    # not leak the exception because this is an asyncSpawn task
    notice "Error sending sync committee contribution", err = exc.msg

proc handleSyncCommitteeContributions(node: BeaconNode,
                                      head: BlockRef, slot: Slot) {.async.} =
  # TODO Use a view type to avoid the copy
  let
    fork = node.dag.forkAtEpoch(slot.epoch)
    genesisValidatorsRoot = node.dag.genesisValidatorsRoot
    syncCommittee = @(node.dag.syncCommitteeParticipants(slot + 1))

  type
    AggregatorCandidate = object
      validator: AttachedValidator
      committeeIdx: SyncCommitteeIndex

  var candidateAggregators: seq[AggregatorCandidate]
  var selectionProofs: seq[Future[ValidatorSig]]

  var time = timeIt:
    for committeeIdx in allSyncCommittees():
      # TODO Hoist outside of the loop with a view type
      #      to avoid the repeated offset calculations
      for valKey in syncSubcommittee(syncCommittee, committeeIdx):
        let validator = node.getAttachedValidator(valKey)
        if validator == nil:
          continue

        candidateAggregators.add AggregatorCandidate(
          validator: validator,
          committeeIdx: committeeIdx)

        selectionProofs.add validator.getSyncCommitteeSelectionProof(
          fork, genesisValidatorsRoot, slot, committeeIdx.asUInt64)

    await allFutures(selectionProofs)

  debug "Prepared contributions selection proofs",
        count = selectionProofs.len, time

  var contributionsSent = 0
  time = timeIt:
    for i in 0 ..< selectionProofs.len:
      if not selectionProofs[i].completed:
        continue

      let selectionProof = selectionProofs[i].read
      if not is_sync_committee_aggregator(selectionProof):
        continue

      var contribution: SyncCommitteeContribution
      let contributionWasProduced = node.syncCommitteeMsgPool[].produceContribution(
        slot, head.root, candidateAggregators[i].committeeIdx, contribution)

      if contributionWasProduced:
        asyncSpawn signAndSendContribution(
          node,
          candidateAggregators[i].validator,
          contribution,
          selectionProof)
        debug "Contribution sent", contribution = shortLog(contribution)
        inc contributionsSent
      else:
        debug "Failure to produce contribution",
              slot, head, subnet = candidateAggregators[i].committeeIdx

  if contributionsSent > 0:
    notice "Contributions sent", count = contributionsSent, time

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

  if validator != nil:
    return await proposeBlock(node, validator, proposer.get(), head, slot)

  debug "Expecting block proposal",
    headRoot = shortLog(head.root),
    slot = shortLog(slot),
    proposer_index = proposer.get(),
    proposer = shortLog(proposerKey)

  return head

proc makeAggregateAndProof*(
    pool: var AttestationPool, epochRef: EpochRef, slot: Slot, index: CommitteeIndex,
    validatorIndex: ValidatorIndex, slot_signature: ValidatorSig): Option[AggregateAndProof] =
  doAssert validatorIndex in get_beacon_committee(epochRef, slot, index)
  doAssert index.uint64 < get_committee_count_per_slot(epochRef)

  # TODO for testing purposes, refactor this into the condition check
  # and just calculation
  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/validator.md#aggregation-selection
  if not is_aggregator(epochRef, slot, index, slot_signature):
    return none(AggregateAndProof)

  let maybe_slot_attestation = getAggregatedAttestation(pool, slot, index)
  if maybe_slot_attestation.isNone:
    return none(AggregateAndProof)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/validator.md#construct-aggregate
  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/validator.md#aggregateandproof
  some(AggregateAndProof(
    aggregator_index: validatorIndex.uint64,
    aggregate: maybe_slot_attestation.get,
    selection_proof: slot_signature))

proc sendAggregatedAttestations(
    node: BeaconNode, aggregationHead: BlockRef, aggregationSlot: Slot) {.async.} =
  # The index is via a
  # locally attested validator. Unlike in handleAttestations(...) there's a
  # single one at most per slot (because that's how aggregation attestation
  # works), so the machinery that has to handle looping across, basically a
  # set of locally attached validators is in principle not necessary, but a
  # way to organize this. Then the private key for that validator should be
  # the corresponding one -- whatver they are, they match.

  let
    epochRef = node.dag.getEpochRef(aggregationHead, aggregationSlot.epoch)
    fork = node.dag.forkAtEpoch(aggregationSlot.epoch)
    genesis_validators_root =
      getStateField(node.dag.headState.data, genesis_validators_root)
    committees_per_slot = get_committee_count_per_slot(epochRef)

  var
    slotSigs: seq[Future[ValidatorSig]] = @[]
    slotSigsData: seq[tuple[committee_index: uint64,
                            validator_idx: ValidatorIndex,
                            v: AttachedValidator]] = @[]

  for committee_index in 0'u64..<committees_per_slot:
    let committee = get_beacon_committee(
      epochRef, aggregationSlot, committee_index.CommitteeIndex)

    for index_in_committee, validatorIdx in committee:
      let validator = node.getAttachedValidator(epochRef, validatorIdx)
      if validator != nil:
        # the validator index and private key pair.
        slotSigs.add getSlotSig(validator, fork,
          genesis_validators_root, aggregationSlot)
        slotSigsData.add (committee_index, validatorIdx, validator)

  await allFutures(slotSigs)

  for curr in zip(slotSigsData, slotSigs):
    let aggregateAndProof =
      makeAggregateAndProof(node.attestationPool[], epochRef, aggregationSlot,
                            curr[0].committee_index.CommitteeIndex,
                             curr[0].validator_idx,
                             curr[1].read)

    # Don't broadcast when, e.g., this node isn't aggregator
    if aggregateAndProof.isSome:
      let sig = await signAggregateAndProof(curr[0].v,
        aggregateAndProof.get, fork, genesis_validators_root)
      var signedAP = SignedAggregateAndProof(
        message: aggregateAndProof.get,
        signature: sig)
      node.network.broadcastAggregateAndProof(signedAP)
      notice "Aggregated attestation sent",
        attestation = shortLog(signedAP.message.aggregate),
        validator = shortLog(curr[0].v),
        signature = shortLog(signedAP.signature),
        aggregationSlot

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
          getStateField(node.dag.headState.data, balances).lenu64:
        debug "Cannot get validator balance, index out of bounds",
          pubkey = shortLog(v.pubkey), index = v.index.get(),
          balances = getStateField(node.dag.headState.data, balances).len,
          stateRoot = getStateRoot(node.dag.headState.data)
        0.Gwei
      else:
        getStateField(node.dag.headState.data, balances)[v.index.get()]

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
    notice "Syncing in progress; skipping validator duties for now",
      slot, headSlot = head.slot

    # Rewards will be growing though, as we sync..
    updateValidatorMetrics(node)

    return

  var curSlot = lastSlot + 1

  # If broadcastStartEpoch is 0, it hasn't had time to initialize yet, which
  # means that it'd be okay not to continue, but it won't gossip regardless.
  if  curSlot.epoch <
        node.processor[].doppelgangerDetection.broadcastStartEpoch and
      node.config.doppelgangerDetection:
    debug "Waiting to gossip out to detect potential duplicate validators",
      broadcastStartEpoch =
        node.processor[].doppelgangerDetection.broadcastStartEpoch
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

  head = await handleProposal(node, head, slot)

  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/validator.md#attesting
  # Milliseconds to wait from the start of the slot before sending out
  # attestations
  const attestationOffset = SECONDS_PER_SLOT.int64 * 1000 div 3

  let
    # The latest point in time when we'll be sending out attestations
    attestationCutoffTime = slot.toBeaconTime(millis(attestationOffset))
    attestationCutoff = node.beaconClock.fromNow(attestationCutoffTime)

  if attestationCutoff.inFuture:
    debug "Waiting to send attestations",
      head = shortLog(head),
      attestationCutoff = shortLog(attestationCutoff.offset)

    # Wait either for the block or the attestation cutoff time to arrive
    if await node.consensusManager[].expectBlock(slot).withTimeout(attestationCutoff.offset):
      # The expected block arrived (or expectBlock was called again which
      # shouldn't happen as this is the only place we use it) - in our async
      # loop however, we might have been doing other processing that caused delays
      # here so we'll cap the waiting to the time when we would have sent out
      # attestations had the block not arrived.
      # An opposite case is that we received (or produced) a block that has
      # not yet reached our neighbours. To protect against our attestations
      # being dropped (because the others have not yet seen the block), we'll
      # impose a minimum delay of 1000ms. The delay is enforced only when we're
      # not hitting the "normal" cutoff time for sending out attestations.
      # An earlier delay of 250ms has proven to be not enough, increasing the
      # risk of losing attestations.
      # Regardless, because we "just" received the block, we'll impose the
      # delay.

      const afterBlockDelay = 1000
      let
        afterBlockTime = node.beaconClock.now() + millis(afterBlockDelay)
        afterBlockCutoff = node.beaconClock.fromNow(
          min(afterBlockTime, attestationCutoffTime + millis(afterBlockDelay)))

      if afterBlockCutoff.inFuture:
        debug "Got block, waiting to send attestations",
          head = shortLog(head),
          afterBlockCutoff = shortLog(afterBlockCutoff.offset)

        await sleepAsync(afterBlockCutoff.offset)

    # Time passed - we might need to select a new head in that case
    node.consensusManager[].updateHead(slot)
    head = node.dag.head

  handleAttestations(node, head, slot)
  handleSyncCommitteeMessages(node, head, slot)

  updateValidatorMetrics(node) # the important stuff is done, update the vanity numbers

  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/validator.md#broadcast-aggregate
  # If the validator is selected to aggregate (is_aggregator), then they
  # broadcast their best aggregate as a SignedAggregateAndProof to the global
  # aggregate channel (beacon_aggregate_and_proof) two-thirds of the way
  # through the slot-that is, SECONDS_PER_SLOT * 2 / 3 seconds after the start
  # of slot.
  if slot > 2:
    let
      aggregateWaitTime = node.beaconClock.fromNow(
        slot.toBeaconTime(seconds(int64(SECONDS_PER_SLOT * 2) div 3)))
    if aggregateWaitTime.inFuture:
      debug "Waiting to send aggregate attestations",
        aggregateWaitTime = shortLog(aggregateWaitTime.offset)
      await sleepAsync(aggregateWaitTime.offset)

    let sendAggregatedAttestationsFut =
      sendAggregatedAttestations(node, head, slot)

    let handleSyncCommitteeContributionsFut =
      handleSyncCommitteeContributions(node, head, slot)

    await handleSyncCommitteeContributionsFut
    await sendAggregatedAttestationsFut

  if node.eth1Monitor != nil and (slot mod SLOTS_PER_EPOCH) == 0:
    let finalizedEpochRef = node.dag.getFinalizedEpochRef()
    discard node.eth1Monitor.trackFinalizedState(
      finalizedEpochRef.eth1_data, finalizedEpochRef.eth1_deposit_index)

proc sendAttestation*(node: BeaconNode,
                      attestation: Attestation): Future[SendResult] {.async.} =
  # REST/JSON-RPC API helper procedure.
  let attestationBlock =
    block:
      let res = node.dag.getRef(attestation.data.beacon_block_root)
      if isNil(res):
        debug "Attempt to send attestation without corresponding block",
              attestation = shortLog(attestation)
        return SendResult.err(
          "Attempt to send attestation without corresponding block")
      res
  let
    epochRef = node.dag.getEpochRef(
      attestationBlock, attestation.data.target.epoch)
    subnet_id = compute_subnet_for_attestation(
      get_committee_count_per_slot(epochRef), attestation.data.slot,
      attestation.data.index.CommitteeIndex)
    res = await node.sendAttestation(attestation, subnet_id,
                                     checkSignature = true)
  if not(res):
    return SendResult.err("Attestation failed validation")
  return SendResult.ok()

proc sendAggregateAndProof*(node: BeaconNode,
                          proof: SignedAggregateAndProof): Future[SendResult] {.
     async.} =
  # REST/JSON-RPC API helper procedure.
  let res = await node.processor.aggregateValidator(proof)
  case res
  of ValidationResult.Accept:
    node.network.broadcastAggregateAndProof(proof)
    return SendResult.ok()
  else:
    notice "Aggregate and proof failed validation",
           proof = shortLog(proof.message.aggregate), result = $res
    return SendResult.err("Aggregate and proof failed validation")

proc sendVoluntaryExit*(node: BeaconNode,
                        exit: SignedVoluntaryExit): SendResult =
  # REST/JSON-RPC API helper procedure.
  let res = node.processor[].voluntaryExitValidator(exit)
  case res
  of ValidationResult.Accept:
    node.network.broadcastVoluntaryExit(exit)
    ok()
  else:
    notice "Voluntary exit request failed validation",
           exit = shortLog(exit.message), result = $res
    err("Voluntary exit request failed validation")

proc sendAttesterSlashing*(node: BeaconNode,
                           slashing: AttesterSlashing): SendResult =
  # REST/JSON-RPC API helper procedure.
  let res = node.processor[].attesterSlashingValidator(slashing)
  case res
  of ValidationResult.Accept:
    node.network.broadcastAttesterSlashing(slashing)
    ok()
  else:
    notice "Attester slashing request failed validation",
           slashing = shortLog(slashing), result = $res
    err("Attester slashing request failed validation")

proc sendProposerSlashing*(node: BeaconNode,
                           slashing: ProposerSlashing): SendResult =
  # REST/JSON-RPC API helper procedure.
  let res = node.processor[].proposerSlashingValidator(slashing)
  case res
  of ValidationResult.Accept:
    node.network.broadcastProposerSlashing(slashing)
  else:
    notice "Proposer slashing request failed validation",
           slashing = shortLog(slashing), result = $res
    return SendResult.err("Proposer slashing request failed validation")

proc sendBeaconBlock*(node: BeaconNode, forked: ForkedSignedBeaconBlock
                     ): Future[SendBlockResult] {.async.} =
  # REST/JSON-RPC API helper procedure.
  let head = node.dag.head
  if not(node.isSynced(head)):
    return SendBlockResult.err("Beacon node is currently syncing")
  if head.slot >= forked.slot():
    node.network.broadcastBeaconBlock(forked)
    return SendBlockResult.ok(false)

  let res = await node.proposeSignedBlock(head, AttachedValidator(), forked)
  if res == head:
    # `res == head` means failure, in such case we need to broadcast block
    # manually because of the specification.
    node.network.broadcastBeaconBlock(forked)
    return SendBlockResult.ok(false)
  return SendBlockResult.ok(true)
