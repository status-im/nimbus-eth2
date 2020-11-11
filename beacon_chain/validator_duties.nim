# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[os, tables, sequtils, osproc, streams],

  # Nimble packages
  stew/[objects], stew/shims/macros,
  chronos, metrics, json_rpc/[rpcserver, jsonmarshal],
  chronicles,
  json_serialization/std/[options, sets, net], serialization/errors,
  eth/db/kvstore,
  eth/[keys, async_utils], eth/p2p/discoveryv5/[protocol, enr],

  # Local modules
  spec/[datatypes, digest, crypto, helpers, network, signatures],
  spec/state_transition,
  conf, time, validator_pool,
  attestation_pool, exit_pool, block_pools/[spec_cache, chain_dag, clearance],
  eth2_network, keystore_management, beacon_node_common, beacon_node_types,
  nimbus_binary_common, eth1_monitor, version, ssz/merkleization,
  attestation_aggregation, sync_manager, sszdump,
  validator_slashing_protection

# Metrics for tracking attestation and beacon block loss
const delayBuckets = [-Inf, -8.0, -4.0, -2.0, -1.0, -0.5, -0.1, -0.05,
                      0.05, 0.1, 0.5, 1.0, 2.0, 4.0, 8.0, Inf]

declareCounter beacon_attestations_sent,
  "Number of beacon chain attestations sent by this peer"
declareHistogram beacon_attestation_sent_delay,
  "Time(s) between slot start and attestation sent moment",
  buckets = delayBuckets
declareCounter beacon_blocks_proposed,
  "Number of beacon chain blocks sent by this peer"

logScope: topics = "beacval"

proc checkValidatorInRegistry(state: BeaconState,
                              pubKey: ValidatorPubKey) =
  let idx = state.validators.asSeq.findIt(it.pubKey == pubKey)
  if idx == -1:
    # We allow adding a validator even if its key is not in the state registry:
    # it might be that the deposit for this validator has not yet been processed
    warn "Validator not in registry (yet?)", pubKey

proc addLocalValidator*(node: BeaconNode,
                        state: BeaconState,
                        privKey: ValidatorPrivKey) =
  let pubKey = privKey.toPubKey()
  state.checkValidatorInRegistry(pubKey)
  node.attachedValidators.addLocalValidator(pubKey, privKey)

proc addLocalValidators*(node: BeaconNode) =
  for validatorKey in node.config.validatorKeys:
    node.addLocalValidator node.chainDag.headState.data.data, validatorKey
  notice "Local validators attached ", count = node.attachedValidators.count

proc addRemoteValidators*(node: BeaconNode) =
  # load all the validators from the child process - loop until `end`
  var line = newStringOfCap(120).TaintedString
  while line != "end" and running(node.vcProcess):
    if node.vcProcess.outputStream.readLine(line) and line != "end":
      let key = ValidatorPubKey.fromHex(line).get().initPubKey()
      node.chainDag.headState.data.data.checkValidatorInRegistry(key)

      let v = AttachedValidator(pubKey: key,
                                kind: ValidatorKind.remote,
                                connection: ValidatorConnection(
                                  inStream: node.vcProcess.inputStream,
                                  outStream: node.vcProcess.outputStream,
                                  pubKeyStr: $key))
      node.attachedValidators.addRemoteValidator(key, v)
  notice "Remote validators attached ", count = node.attachedValidators.count

proc getAttachedValidator*(node: BeaconNode,
                           pubkey: ValidatorPubKey): AttachedValidator =
  node.attachedValidators.getValidator(pubkey)

proc getAttachedValidator*(node: BeaconNode,
                           state: BeaconState,
                           idx: ValidatorIndex): AttachedValidator =
  if idx < state.validators.len.ValidatorIndex:
    node.getAttachedValidator(state.validators[idx].pubkey)
  else:
    warn "Validator index out of bounds",
      idx, stateSlot = state.slot, validators = state.validators.len
    nil

proc getAttachedValidator*(node: BeaconNode,
                           epochRef: EpochRef,
                           idx: ValidatorIndex): AttachedValidator =
  if idx < epochRef.validator_keys.len.ValidatorIndex:
    node.getAttachedValidator(epochRef.validator_keys[idx])
  else:
    warn "Validator index out of bounds",
      idx, epoch = epochRef.epoch, validators = epochRef.validator_keys.len
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
    node: BeaconNode, attestation: Attestation, num_active_validators: uint64) =
  node.network.broadcast(
    getAttestationTopic(node.forkDigest, attestation, num_active_validators),
    attestation)

  beacon_attestations_sent.inc()

proc sendAttestation*(node: BeaconNode, attestation: Attestation) =
  # For the validator API, which doesn't supply num_active_validators.
  let attestationBlck =
    node.chainDag.getRef(attestation.data.beacon_block_root)
  if attestationBlck.isNil:
    debug "Attempt to send attestation without corresponding block"
    return

  node.sendAttestation(
    attestation,
    count_active_validators(
      node.chainDag.getEpochRef(attestationBlck, attestation.data.target.epoch)))

proc createAndSendAttestation(node: BeaconNode,
                              fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              validator: AttachedValidator,
                              attestationData: AttestationData,
                              committeeLen: int,
                              indexInCommittee: int,
                              num_active_validators: uint64) {.async.} =
  var attestation = await validator.produceAndSignAttestation(
    attestationData, committeeLen, indexInCommittee, fork,
    genesis_validators_root)

  node.sendAttestation(attestation, num_active_validators)

  if node.config.dumpEnabled:
    dump(node.config.dumpDirOutgoing, attestation.data, validator.pubKey)

  let wallTime = node.beaconClock.now()
  let deadline = attestationData.slot.toBeaconTime() +
                 seconds(int(SECONDS_PER_SLOT div 3))

  let (delayStr, delayMillis) =
    if wallTime < deadline:
      ("-" & $(deadline - wallTime),
       -float(milliseconds(deadline - wallTime)) / 1000.0)
    else:
      ($(wallTime - deadline),
       float(milliseconds(wallTime - deadline)) / 1000.0)

  notice "Attestation sent", attestation = shortLog(attestation),
                             validator = shortLog(validator), delay = delayStr,
                             indexInCommittee = indexInCommittee

  beacon_attestation_sent_delay.observe(delayMillis)

proc makeBeaconBlockForHeadAndSlot*(node: BeaconNode,
                                    randao_reveal: ValidatorSig,
                                    validator_index: ValidatorIndex,
                                    graffiti: GraffitiBytes,
                                    head: BlockRef,
                                    slot: Slot): Option[BeaconBlock] =
  # Advance state to the slot that we're proposing for
  node.chainDag.withState(node.chainDag.tmpState, head.atSlot(slot)):
    let (eth1data, deposits) =
      if node.eth1Monitor.isNil:
        (state.eth1_data, newSeq[Deposit]())
      else:
        let finalizedEth1Data = node.chainDag.getFinalizedEpochRef().eth1_data
        node.eth1Monitor.getBlockProposalData(state, finalizedEth1Data)

    let
      poolPtr = unsafeAddr node.chainDag # safe because restore is short-lived

    func restore(v: var HashedBeaconState) =
      # TODO address this ugly workaround - there should probably be a
      #      `state_transition` that takes a `StateData` instead and updates
      #      the block as well
      doAssert v.addr == addr poolPtr.tmpState.data
      assign(poolPtr.tmpState, poolPtr.headState)

    makeBeaconBlock(
      node.config.runtimePreset,
      hashedState,
      validator_index,
      head.root,
      randao_reveal,
      eth1data,
      graffiti,
      node.attestationPool[].getAttestationsForBlock(state, cache),
      deposits,
      node.exitPool[].getProposerSlashingsForBlock(),
      node.exitPool[].getAttesterSlashingsForBlock(),
      node.exitPool[].getVoluntaryExitsForBlock(),
      restore,
      cache)

proc proposeSignedBlock*(node: BeaconNode,
                         head: BlockRef,
                         validator: AttachedValidator,
                         newBlock: SignedBeaconBlock): Future[BlockRef] {.async.} =

  let newBlockRef = node.chainDag.addRawBlock(node.quarantine,
                                                    newBlock) do (
      blckRef: BlockRef, signedBlock: SignedBeaconBlock,
      epochRef: EpochRef, state: HashedBeaconState):
    # Callback add to fork choice if valid
    node.attestationPool[].addForkChoice(
      epochRef, blckRef, signedBlock.message,
      node.beaconClock.now().slotOrZero())

  if newBlockRef.isErr:
    warn "Unable to add proposed block to block pool",
      newBlock = shortLog(newBlock.message),
      blockRoot = shortLog(newBlock.root)

    return head

  notice "Block proposed",
    blck = shortLog(newBlock.message),
    blockRoot = shortLog(newBlockRef[].root),
    validator = shortLog(validator)

  if node.config.dumpEnabled:
    dump(node.config.dumpDirOutgoing, newBlock)

  node.network.broadcast(node.topicBeaconBlocks, newBlock)

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

  let notSlashable = node.attachedValidators
                        .slashingProtection
                        .checkSlashableBlockProposal(validator.pubkey, slot)
  if notSlashable.isErr:
    warn "Slashing protection activated",
      validator = validator.pubkey,
      slot = slot,
      existingProposal = notSlashable.error
    return head

  let
    fork = node.chainDag.headState.data.data.fork
    genesis_validators_root =
      node.chainDag.headState.data.data.genesis_validators_root
  let
    randao = await validator.genRandaoReveal(
      fork, genesis_validators_root, slot)
    message = makeBeaconBlockForHeadAndSlot(
      node, randao, validator_index, node.graffitiBytes, head, slot)
  if not message.isSome():
    return head # already logged elsewhere!
  var
    newBlock = SignedBeaconBlock(
      message: message.get()
    )

  newBlock.root = hash_tree_root(newBlock.message)

  # TODO: recomputed in block proposal
  let signing_root = compute_block_root(
    fork, genesis_validators_root, slot, newBlock.root)
  node.attachedValidators
    .slashingProtection
    .registerBlock(validator.pubkey, slot, signing_root)

  newBlock.signature = await validator.signBlockProposal(
    fork, genesis_validators_root, slot, newBlock.root)

  return await node.proposeSignedBlock(head, validator, newBlock)

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

  # Collect data to send before node.stateCache grows stale
  var attestations: seq[tuple[
    data: AttestationData, committeeLen, indexInCommittee: int,
    validator: AttachedValidator]]

  # We need to run attestations exactly for the slot that we're attesting to.
  # In case blocks went missing, this means advancing past the latest block
  # using empty slots as fillers.
  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#validator-assignments
  let
    epochRef = node.chainDag.getEpochRef(
      attestationHead.blck, slot.compute_epoch_at_slot())
    committees_per_slot =
      get_committee_count_per_slot(epochRef)
    num_active_validators = count_active_validators(epochRef)
    fork = node.chainDag.headState.data.data.fork
    genesis_validators_root =
      node.chainDag.headState.data.data.genesis_validators_root

  for committee_index in 0'u64..<committees_per_slot:
    let committee = get_beacon_committee(
      epochRef, slot, committee_index.CommitteeIndex)

    for index_in_committee, validatorIdx in committee:
      let validator = node.getAttachedValidator(epochRef, validatorIdx)
      if validator != nil:
        let ad = makeAttestationData(
          epochRef, attestationHead, committee_index.CommitteeIndex)
        attestations.add((ad, committee.len, index_in_committee, validator))

  for a in attestations:
    let notSlashable = node.attachedValidators
                           .slashingProtection
                           .checkSlashableAttestation(
                             a.validator.pubkey,
                             a.data.source.epoch,
                             a.data.target.epoch)

    if notSlashable.isOk():
      # TODO signing_root is recomputed in produceAndSignAttestation/signAttestation just after
      let signing_root = compute_attestation_root(
            fork, genesis_validators_root, a.data)
      node.attachedValidators
          .slashingProtection
          .registerAttestation(
            a.validator.pubkey,
            a.data.source.epoch,
            a.data.target.epoch,
            signing_root
          )

      traceAsyncErrors createAndSendAttestation(
        node, fork, genesis_validators_root, a.validator, a.data,
        a.committeeLen, a.indexInCommittee, num_active_validators)
    else:
      warn "Slashing protection activated for attestation",
        validator = a.validator.pubkey,
        badVoteDetails = $notSlashable.error

proc handleProposal(node: BeaconNode, head: BlockRef, slot: Slot):
    Future[BlockRef] {.async.} =
  ## Perform the proposal for the given slot, iff we have a validator attached
  ## that is supposed to do so, given the shuffling in head

  # TODO here we advance the state to the new slot, but later we'll be
  #      proposing for it - basically, we're selecting proposer based on an
  #      empty slot

  let proposer = node.chainDag.getProposer(head, slot)
  if proposer.isNone():
    return head

  let validator =
    node.attachedValidators.getValidator(proposer.get()[1])

  if validator != nil:
    return await proposeBlock(node, validator, proposer.get()[0], head, slot)

  debug "Expecting block proposal",
    headRoot = shortLog(head.root),
    slot = shortLog(slot),
    proposer_index = proposer.get()[0],
    proposer = shortLog(proposer.get()[1].initPubKey())

  return head

proc broadcastAggregatedAttestations(
    node: BeaconNode, aggregationHead: BlockRef, aggregationSlot: Slot) {.async.} =
  # The index is via a
  # locally attested validator. Unlike in handleAttestations(...) there's a
  # single one at most per slot (because that's how aggregation attestation
  # works), so the machinery that has to handle looping across, basically a
  # set of locally attached validators is in principle not necessary, but a
  # way to organize this. Then the private key for that validator should be
  # the corresponding one -- whatver they are, they match.

  let
    bs = BlockSlot(blck: aggregationHead, slot: aggregationSlot)
    epochRef = node.chainDag.getEpochRef(aggregationHead, aggregationSlot.epoch)
    fork = node.chainDag.headState.data.data.fork
    genesis_validators_root =
      node.chainDag.headState.data.data.genesis_validators_root
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
      aggregate_attestations(node.attestationPool[], epochRef, aggregationSlot,
                             curr[0].committee_index.CommitteeIndex,
                             curr[0].validator_idx,
                             curr[1].read)

    # Don't broadcast when, e.g., this node isn't aggregator
    # TODO verify there is only one isSome() with test.
    if aggregateAndProof.isSome:
      let sig = await signAggregateAndProof(curr[0].v,
        aggregateAndProof.get, fork, genesis_validators_root)
      var signedAP = SignedAggregateAndProof(
        message: aggregateAndProof.get,
        signature: sig)
      node.network.broadcast(node.topicAggregateAndProofs, signedAP)
      notice "Aggregated attestation sent",
        attestation = shortLog(signedAP.message.aggregate),
        validator = shortLog(curr[0].v)

proc handleValidatorDuties*(node: BeaconNode, lastSlot, slot: Slot) {.async.} =
  ## Perform validator duties - create blocks, vote and aggregate existing votes
  if node.attachedValidators.count == 0:
    # Nothing to do because we have no validator attached
    return

  # The chainDag head might be updated by sync while we're working due to the
  # await calls, thus we use a local variable to keep the logic straight here
  var head = node.chainDag.head
  if not node.isSynced(head):
    notice "Syncing in progress; skipping validator duties for now",
      slot, headSlot = head.slot
    return

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

  head = await handleProposal(node, head, slot)

  # We've been doing lots of work up until now which took time. Normally, we
  # send out attestations at the slot thirds-point, so we go back to the clock
  # to see how much time we need to wait.
  # TODO the beacon clock might jump here also. It's probably easier to complete
  #      the work for the whole slot using a monotonic clock instead, then deal
  #      with any clock discrepancies once only, at the start of slot timer
  #      processing..

  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#attesting
  # A validator should create and broadcast the attestation to the associated
  # attestation subnet when either (a) the validator has received a valid
  # block from the expected block proposer for the assigned slot or
  # (b) one-third of the slot has transpired (`SECONDS_PER_SLOT / 3` seconds
  # after the start of slot) -- whichever comes first.
  template sleepToSlotOffsetWithHeadUpdate(extra: chronos.Duration, msg: static string) =
    if await node.beaconClock.sleepToSlotOffset(extra, slot, msg):
      # Time passed - we might need to select a new head in that case
      node.processor[].updateHead(slot)
      head = node.chainDag.head

  sleepToSlotOffsetWithHeadUpdate(
    seconds(int64(SECONDS_PER_SLOT)) div 3, "Waiting to send attestations")

  handleAttestations(node, head, slot)

  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#broadcast-aggregate
  # If the validator is selected to aggregate (is_aggregator), then they
  # broadcast their best aggregate as a SignedAggregateAndProof to the global
  # aggregate channel (beacon_aggregate_and_proof) two-thirds of the way
  # through the slot-that is, SECONDS_PER_SLOT * 2 / 3 seconds after the start
  # of slot.
  if slot > 2:
    sleepToSlotOffsetWithHeadUpdate(
      seconds(int64(SECONDS_PER_SLOT * 2) div 3),
      "Waiting to aggregate attestations")

    const TRAILING_DISTANCE = 1
    # https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/p2p-interface.md#configuration
    static:
      doAssert TRAILING_DISTANCE <= ATTESTATION_PROPAGATION_SLOT_RANGE

    let
      aggregationSlot = slot - TRAILING_DISTANCE
      aggregationHead = get_ancestor(head, aggregationSlot)

    await broadcastAggregatedAttestations(node, aggregationHead, aggregationSlot)
