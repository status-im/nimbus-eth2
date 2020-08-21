# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, tables, strutils,

  # Nimble packages
  stew/[objects], stew/shims/macros,
  chronos, metrics, json_rpc/[rpcserver, jsonmarshal],
  chronicles,
  json_serialization/std/[options, sets, net], serialization/errors,
  eth/db/kvstore,
  eth/[keys, async_utils], eth/p2p/discoveryv5/[protocol, enr],

  # Local modules
  spec/[datatypes, digest, crypto, helpers, validator, network],
  spec/state_transition,
  conf, time, validator_pool,
  attestation_pool, block_pools/[spec_cache, chain_dag, clearance],
  eth2_network, keystore_management, beacon_node_common, beacon_node_types,
  nimbus_binary_common, mainchain_monitor, version, ssz/merkleization, interop,
  attestation_aggregation, sync_manager, sszdump

# Metrics for tracking attestation and beacon block loss
declareCounter beacon_attestations_sent,
  "Number of beacon chain attestations sent by this peer"
declareCounter beacon_blocks_proposed,
  "Number of beacon chain blocks sent by this peer"

logScope: topics = "beacval"

proc saveValidatorKey*(keyName, key: string, conf: BeaconNodeConf) =
  let validatorsDir = conf.validatorsDir
  let outputFile = validatorsDir / keyName
  createDir validatorsDir
  writeFile(outputFile, key)
  info "Imported validator key", file = outputFile

proc addLocalValidator*(node: BeaconNode,
                        state: BeaconStateView,
                        privKey: ValidatorPrivKey) =
  let pubKey = privKey.toPubKey()

  let idx = state.validators.asSeq.findIt(it.pubKey == pubKey)
  if idx == -1:
    # We allow adding a validator even if its key is not in the state registry:
    # it might be that the deposit for this validator has not yet been processed
    warn "Validator not in registry (yet?)", pubKey

  node.attachedValidators.addLocalValidator(pubKey, privKey)

proc addLocalValidators*(node: BeaconNode) =
  for validatorKey in node.config.validatorKeys:
    node.addLocalValidator node.chainDag.headState.data.data, validatorKey

  info "Local validators attached ", count = node.attachedValidators.count

proc getAttachedValidator*(node: BeaconNode,
                           pubkey: ValidatorPubKey): AttachedValidator =
  node.attachedValidators.getValidator(pubkey)

proc getAttachedValidator*(node: BeaconNode,
                           state: BeaconStateView,
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

  # TODO if everyone follows this logic, the network will not recover from a
  #      halt: nobody will be producing blocks because everone expects someone
  #      else to do it
  if wallSlot.afterGenesis and head.slot + MaxEmptySlotCount < wallSlot.slot:
    false
  else:
    true

proc sendAttestation*(
  node: BeaconNode, attestation: Attestation, num_active_validators: uint64) =
  logScope: pcs = "send_attestation"

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
  logScope: pcs = "send_attestation"

  var attestation = await validator.produceAndSignAttestation(
    attestationData, committeeLen, indexInCommittee, fork,
    genesis_validators_root)

  node.sendAttestation(attestation, num_active_validators)

  if node.config.dumpEnabled:
    dump(node.config.dumpDirOutgoing, attestation.data, validator.pubKey)

  info "Attestation sent",
    attestation = shortLog(attestation),
    validator = shortLog(validator),
    indexInCommittee = indexInCommittee

type
  ValidatorInfoForMakeBeaconBlockKind* = enum
    viValidator
    viRandao_reveal
  ValidatorInfoForMakeBeaconBlock* = object
    case kind*: ValidatorInfoForMakeBeaconBlockKind
    of viValidator: validator*: AttachedValidator
    of viRandao_reveal: randao_reveal*: ValidatorSig

proc makeBeaconBlockForHeadAndSlot*(node: BeaconNode,
                                    val_info: ValidatorInfoForMakeBeaconBlock,
                                    validator_index: ValidatorIndex,
                                    graffiti: GraffitiBytes,
                                    head: BlockRef,
                                    slot: Slot):
    tuple[message: Option[BeaconBlock], fork: Fork, genesis_validators_root: Eth2Digest] =
  # Advance state to the slot that we're proposing for - this is the equivalent
  # of running `process_slots` up to the slot of the new block.
  node.chainDag.withState(
      node.chainDag.tmpState, head.atSlot(slot)):
    let (eth1data, deposits) =
      if node.mainchainMonitor.isNil:
        (get_eth1data_stub(state.eth1_deposit_index, slot.compute_epoch_at_slot()),
         newSeq[Deposit]())
      else:
        node.mainchainMonitor.getBlockProposalData(state)

    # TODO perhaps just making the enclosing function accept 2 different types at the
    # same time and doing some compile-time branching logic is cleaner (without the
    # need for the discriminated union)... but we need the `state` from `withState`
    # in order to get the fork/root for the specific head/slot for the randao_reveal
    # and it's causing problems when the function becomes a generic for 2 types...
    proc getRandaoReveal(val_info: ValidatorInfoForMakeBeaconBlock): ValidatorSig =
      if val_info.kind == viValidator:
        return val_info.validator.genRandaoReveal(state.fork, state.genesis_validators_root, slot)
      elif val_info.kind == viRandao_reveal:
        return val_info.randao_reveal

    let
      poolPtr = unsafeAddr node.chainDag # safe because restore is short-lived

    func restore(v: var HashedBeaconState) =
      # TODO address this ugly workaround - there should probably be a
      #      `state_transition` that takes a `StateData` instead and updates
      #      the block as well
      doAssert v.addr == addr poolPtr.tmpState.data
      assign(poolPtr.tmpState, poolPtr.headState)

    let message = makeBeaconBlock(
      node.config.runtimePreset,
      hashedState,
      validator_index,
      head.root,
      getRandaoReveal(val_info),
      eth1data,
      graffiti,
      node.attestationPool[].getAttestationsForBlock(state),
      deposits,
      restore,
      cache)

    if message.isSome():
      # TODO this restore is needed because otherwise tmpState will be internally
      #      inconsistent - it's blck will not be pointing to the block that
      #      created this state - we have to reset it here before `await` to avoid
      #      races.
      restore(poolPtr.tmpState.data)

    return (message, state.fork, state.genesis_validators_root)

proc proposeSignedBlock*(node: BeaconNode,
                         head: BlockRef,
                         validator: AttachedValidator,
                         newBlock: SignedBeaconBlock): Future[BlockRef] {.async.} =

  {.gcsafe.}: # TODO: fork choice and quarantine should sync via messages instead of callbacks
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

  info "Block proposed",
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
  logScope: pcs = "block_proposal"

  if head.slot >= slot:
    # We should normally not have a head newer than the slot we're proposing for
    # but this can happen if block proposal is delayed
    warn "Skipping proposal, have newer head already",
      headSlot = shortLog(head.slot),
      headBlockRoot = shortLog(head.root),
      slot = shortLog(slot)
    return head

  let valInfo = ValidatorInfoForMakeBeaconBlock(kind: viValidator, validator: validator)
  let beaconBlockTuple = makeBeaconBlockForHeadAndSlot(node, valInfo, validator_index, node.graffitiBytes, head, slot)
  if not beaconBlockTuple.message.isSome():
    return head # already logged elsewhere!
  var
    newBlock = SignedBeaconBlock(
      message: beaconBlockTuple.message.get()
    )

  newBlock.root = hash_tree_root(newBlock.message)
  newBlock.signature = await validator.signBlockProposal(
    beaconBlockTuple.fork, beaconBlockTuple.genesis_validators_root, slot, newBlock.root)

  return await node.proposeSignedBlock(head, validator, newBlock)

proc handleAttestations(node: BeaconNode, head: BlockRef, slot: Slot) =
  ## Perform all attestations that the validators attached to this node should
  ## perform during the given slot
  logScope: pcs = "handleAttestations"

  if slot + SLOTS_PER_EPOCH < head.slot:
    # The latest block we know about is a lot newer than the slot we're being
    # asked to attest to - this makes it unlikely that it will be included
    # at all.
    # TODO the oldest attestations allowed are those that are older than the
    #      finalized epoch.. also, it seems that posting very old attestations
    #      is risky from a slashing perspective. More work is needed here.
    notice "Skipping attestation, head is too recent",
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
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#validator-assignments
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
        let ad = makeAttestationData(epochRef, attestationHead, committee_index)
        attestations.add((ad, committee.len, index_in_committee, validator))

  for a in attestations:
    traceAsyncErrors createAndSendAttestation(
      node, fork, genesis_validators_root, a.validator, a.data,
      a.committeeLen, a.indexInCommittee, num_active_validators)

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
    proposer = shortLog(proposer.get()[1].initPubKey()),
    pcs = "wait_for_proposal"

  return head

proc broadcastAggregatedAttestations(
    node: BeaconNode, aggregationHead: BlockRef, aggregationSlot: Slot) =
  # The index is via a
  # locally attested validator. Unlike in handleAttestations(...) there's a
  # single one at most per slot (because that's how aggregation attestation
  # works), so the machinery that has to handle looping across, basically a
  # set of locally attached validators is in principle not necessary, but a
  # way to organize this. Then the private key for that validator should be
  # the corresponding one -- whatver they are, they match.

  let bs = BlockSlot(blck: aggregationHead, slot: aggregationSlot)
  node.chainDag.withState(node.chainDag.tmpState, bs):
    let
      committees_per_slot =
        get_committee_count_per_slot(state, aggregationSlot.epoch, cache)
    for committee_index in 0'u64..<committees_per_slot:
      let committee = get_beacon_committee(
        state, aggregationSlot, committee_index.CommitteeIndex, cache)

      for index_in_committee, validatorIdx in committee:
        let validator = node.getAttachedValidator(state, validatorIdx)
        if validator != nil:
          # This is slightly strange/inverted control flow, since really it's
          # going to happen once per slot, but this is the best way to get at
          # the validator index and private key pair. TODO verify it only has
          # one isSome() with test.
          let aggregateAndProof =
            aggregate_attestations(node.attestationPool[], state,
              committee_index.CommitteeIndex,
              # TODO https://github.com/status-im/nim-beacon-chain/issues/545
              # this assumes in-process private keys
              validatorIdx,
              validator.privKey,
              cache)

          # Don't broadcast when, e.g., this node isn't aggregator
          if aggregateAndProof.isSome:
            var signedAP = SignedAggregateAndProof(
              message: aggregateAndProof.get,
              # TODO Make the signing async here
              signature: validator.signAggregateAndProof(
                aggregateAndProof.get, state.fork,
                state.genesis_validators_root))

            node.network.broadcast(node.topicAggregateAndProofs, signedAP)
            info "Aggregated attestation sent",
              attestation = shortLog(signedAP.message.aggregate),
              validator = shortLog(validator)

proc handleValidatorDuties*(
    node: BeaconNode, lastSlot, slot: Slot) {.async.} =
  ## Perform validator duties - create blocks, vote and aggregate existing votes
  var head = node.updateHead(slot)
  if node.attachedValidators.count == 0:
    # Nothing to do because we have no validator attached
    return

  if not node.isSynced(head):
    notice "Node out of sync, skipping validator duties",
      slot, headSlot = head.slot
    return

  var curSlot = lastSlot + 1

  # Start by checking if there's work we should have done in the past that we
  # can still meaningfully do
  while curSlot < slot:
    # TODO maybe even collect all work synchronously to avoid unnecessary
    #      state rewinds while waiting for async operations like validator
    #      signature..
    notice "Catching up",
      curSlot = shortLog(curSlot),
      lastSlot = shortLog(lastSlot),
      slot = shortLog(slot)

    # For every slot we're catching up, we'll propose then send
    # attestations - head should normally be advancing along the same branch
    # in this case
    # TODO what if we receive blocks / attestations while doing this work?
    head = await handleProposal(node, head, curSlot)

    # For each slot we missed, we need to send out attestations - if we were
    # proposing during this time, we'll use the newly proposed head, else just
    # keep reusing the same - the attestation that goes out will actually
    # rewind the state to what it looked like at the time of that slot
    # TODO smells like there's an optimization opportunity here
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

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#attesting
  # A validator should create and broadcast the attestation to the associated
  # attestation subnet when either (a) the validator has received a valid
  # block from the expected block proposer for the assigned slot or
  # (b) one-third of the slot has transpired (`SECONDS_PER_SLOT / 3` seconds
  # after the start of slot) -- whichever comes first.
  template sleepToSlotOffsetWithHeadUpdate(extra: chronos.Duration, msg: static string) =
    if await node.beaconClock.sleepToSlotOffset(extra, slot, msg):
      # Time passed - we might need to select a new head in that case
      head = node.updateHead(slot)

  sleepToSlotOffsetWithHeadUpdate(
    seconds(int64(SECONDS_PER_SLOT)) div 3, "Waiting to send attestations")

  handleAttestations(node, head, slot)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#broadcast-aggregate
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
    # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#configuration
    static:
      doAssert TRAILING_DISTANCE <= ATTESTATION_PROPAGATION_SLOT_RANGE

    let
      aggregationSlot = slot - TRAILING_DISTANCE
      aggregationHead = get_ancestor(head, aggregationSlot)

    broadcastAggregatedAttestations(node, aggregationHead, aggregationSlot)
