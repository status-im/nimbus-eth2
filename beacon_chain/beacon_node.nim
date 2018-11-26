import
  os, net,
  asyncdispatch2, confutils, eth_p2p, eth_keys,
  private/helpers, conf, datatypes, time, fork_choise,
  beacon_chain_db, validator_pool, mainchain_monitor,
  sync_protocol, gossipsub_protocol, trusted_state_snapshots

type
  BeaconNode* = ref object
    beaconState*: BeaconState
    network*: EthereumNode
    db*: BeaconChainDB
    config*: Configuration
    keys*: KeyPair
    attachedValidators: ValidatorPool
    attestations: AttestationPool
    headBlock: BeaconBlock
    mainchainMonitor: MainchainMonitor

const
  version = "v0.1" # read this from the nimble file
  clientId = "nimbus beacon node " & version

  topicBeaconBlocks = "ethereum/2.1/beacon_chain/blocks"
  topicAttestations = "ethereum/2.1/beacon_chain/attestations"

proc ensureNetworkKeys*(dataDir: string): KeyPair =
  # TODO:
  # 1. Check if keys already exist in the data dir
  # 2. Generate new ones and save them in the directory
  # if necessary
  return newKeyPair()

proc init*(T: type BeaconNode, conf: Configuration): T =
  new result
  result.config = conf
  result.db = BeaconChainDB.init(conf.dataDir)
  result.keys = ensureNetworkKeys(conf.dataDir)

  var address: Address
  address.ip = parseIpAddress("0.0.0.0")
  address.tcpPort = Port(conf.tcpPort)
  address.udpPort = Port(conf.udpPort)
  result.network = newEthereumNode(result.keys, address, 0, nil, clientId)

proc sync*(node: BeaconNode): Future[bool] {.async.} =
  let persistedState = node.db.lastFinalizedState()
  if persistedState.isNil or
     persistedState[].slotDistanceFromNow() > WITHDRAWAL_PERIOD:
    node.beaconState = await obtainTrustedStateSnapshot(node.db)
  else:
    node.beaconState = persistedState[]
    var targetSlot = toSlot timeSinceGenesis(node.beaconState)

    while node.beaconState.last_finalized_slot < targetSlot:
      var (peer, changeLog) = node.network.getValidatorChangeLog(
        node.beaconState.validator_set_delta_hash_chain)

      if peer == nil:
        error "Failed to sync with any peer"
        return false

      if applyValidatorChangeLog(changeLog, node.beaconState):
        node.db.persistBlock(changeLog.signedBlock, node.beaconState)
      else:
        warn "Ignoring invalid validator change log", sentFrom = peer

  return true

proc addLocalValidators*(node: BeaconNode) =
  for validator in node.config.validatorKeys:
    # TODO:
    # 1. Parse the validator keys
    #
    # 2. Check whether the validators exist in the beacon state.
    #    (Report a warning otherwise)
    #
    # 3. Add the validators to node.attachedValidators
    discard

proc getAttachedValidator(node: BeaconNode, idx: int): AttachedValidator =
  let validatorKey = node.beaconState.validators[idx].pubkey
  return node.attachedValidators.getValidator(validatorKey)

proc makeAttestationCallback(node: BeaconNode,
                             validator: AttachedValidator): auto =
  proc makeAttestation {.async.} =
    var attestation: Attestation
    attestation.validator = validator.idx

    # TODO: Populate attestation.data

    attestation.signature = await validator.signAttestation(attestation.data)
    await node.network.broadcast(topicAttestations, attestation)

  return proc =
    asyncCheck makeAttestation

proc proposeBlockCallback(node: BeaconNode,
                          validator: AttachedValidator): auto =
  proc proposeBlock {.async.} =
    var proposal: BeaconBlock

    # TODO:
    # 1. Produce a RANDAO reveal from attachedVadalidator.randaoSecret
    # and its matching ValidatorRecord.

    # 2. Get ancestors from the beacon_db

    # 3. Calculate the correct state hash

    proposal.candidate_pow_receipt_root =
      node.mainchainMonitor.getBeaconBlockRef()

    for a in node.attestations.each(firstSlot = node.headBlock.slot + 1,
                                    lastSlot = slot - MIN_ATTESTATION_INCLUSION_DELAY):
      proposal.attestations.add a
      # TODO: this is not quite right,
      # the attestations from individual validators have to be merged.

    for r in node.mainchainMonitor.getValidatorActions():
      proposal.specials.add r

    var signedData: ProposalSignedData
    # TODO: populate the signed data

    proposal.proposer_signature = await validator.signBlockProposal(signedData)
    await node.network.broadcast(topicProposals, proposal)

  return proc =
    asyncCheck proposeBlock

proc scheduleCycleActions(node: BeaconNode)
  ## This schedules the required block proposals and
  ## attestations from our attached validators.
  let cycleStart = node.last_state_recalculation_slot

  for i in 0 ..< CYCLE_LENGTH:
    # Schedule block proposals
    let
      slot = cycleStart + i
      proposerIdx = get_beacon_proposer_idx(node.beaconState, slot)
      attachedValidator = node.getAttachedValidator(proposerIdx)

    if attachedValidator != nil:
      # TODO:
      # Warm-up the proposer earlier to try to obtain previous
      # missing blocks if necessary

      addTimer slotStart(slot),
               proposeBlockCallback(node, attachedValidator)

    # Schedule attestations
    let
      committeesIdx = get_shard_and_committees_idx(node.beaconState, slot)

      for shard in node.beaconState.shard_and_committee_for_slots[committees_idx]:
        for validatorIdx in shard.committee:
          let attachedValidator = node.getAttachedValidator(validatorIdx)
          if attachedValidator != nil:
            addTimer slotMiddle(slot),
                     makeAttestationCallback(node, attachedValidator)

proc processBlocks*(node: BeaconNode) {.async.} =
  node.scheduleCycleActions()

  node.network.subscribe(topicBeaconBlocks) do (b: BeaconBlock):
    # TODO:
    #
    # 1. Check for missing blocks and obtain them
    #
    # 2. Apply fork-choice rule (update node.headBlock)
    #
    # 3. Peform block processing / state recalculation / etc
    #

    if b.slot mod CYCLE_LENGTH == 0:
      node.scheduleCycleActions()
      node.attestations.discardHistoryToSlot(b.slot)

  node.network.subscribe(topicAttestations) do (a: Attestation):
    # TODO
    #
    # 1. Validate the attestation

    node.attestations.add(a, node.beaconState)

when isMainModule:
  let conf = Configuration.load()
  waitFor syncrhronizeClock()
  var node = BeaconNode.init conf

  if not waitFor node.sync():
    quit 1

  node.addLocalValidators()

  waitFor node.processBlocks()

