import
  std_shims/[os_shims, objects], net, sequtils, options,
  asyncdispatch2, chronicles, confutils, eth_p2p, eth_keys,
  spec/[datatypes, digest, crypto, beaconstate, helpers], conf, time,
  state_transition, fork_choice, ssz, beacon_chain_db, validator_pool, extras,
  mainchain_monitor, sync_protocol, gossipsub_protocol, trusted_state_snapshots

type
  BeaconNode* = ref object
    beaconState*: BeaconState
    network*: EthereumNode
    db*: BeaconChainDB
    config*: BeaconNodeConf
    keys*: KeyPair
    attachedValidators: ValidatorPool
    attestationPool: AttestationPool
    mainchainMonitor: MainchainMonitor
    lastScheduledCycle: int
    headBlock: BeaconBlock
    headBlockRoot: Eth2Digest

const
  version = "v0.1" # TODO: read this from the nimble file
  clientId = "nimbus beacon node " & version

  topicBeaconBlocks = "ethereum/2.1/beacon_chain/blocks"
  topicAttestations = "ethereum/2.1/beacon_chain/attestations"

func shortHash(x: auto): string = ($x)[0..7]

proc ensureNetworkKeys*(dataDir: string): KeyPair =
  # TODO:
  # 1. Check if keys already exist in the data dir
  # 2. Generate new ones and save them in the directory
  # if necessary
  return newKeyPair()

proc init*(T: type BeaconNode, conf: BeaconNodeConf): T =
  new result
  result.config = conf

  result.attachedValidators = ValidatorPool.init
  init result.attestationPool, 0
  init result.mainchainMonitor, "", Port(0) # TODO: specify geth address and port

  result.db = BeaconChainDB.init(string conf.dataDir)
  result.keys = ensureNetworkKeys(string conf.dataDir)

  var address: Address
  address.ip = parseIpAddress("127.0.0.1")
  address.tcpPort = Port(conf.tcpPort)
  address.udpPort = Port(conf.udpPort)

  result.network = newEthereumNode(result.keys, address, 0, nil, clientId, minPeers = 1)

  writeFile(string(conf.dataDir) / "beacon_node.address",
            $result.network.listeningAddress)

proc connectToNetwork(node: BeaconNode) {.async.} =
  var bootstrapNodes = newSeq[ENode]()

  for node in node.config.bootstrapNodes:
    bootstrapNodes.add initENode(node)

  let bootstrapFile = string node.config.bootstrapNodesFile
  if bootstrapFile.len > 0:
    for ln in lines(bootstrapFile):
      bootstrapNodes.add initENode(string ln)

  if bootstrapNodes.len > 0:
    info "Connecting to bootstrap nodes", bootstrapNodes
    await node.network.connectToNetwork(bootstrapNodes)
  else:
    info "Waiting for connections"
    node.network.startListening()

proc sync*(node: BeaconNode): Future[bool] {.async.} =
  let persistedState = node.db.lastFinalizedState()
  if persistedState.isNil or
     persistedState[].slotDistanceFromNow() > WEAK_SUBJECTVITY_PERIOD:
    if node.config.stateSnapshot.isSome:
      node.beaconState = node.config.stateSnapshot.get
    else:
      node.beaconState = await obtainTrustedStateSnapshot(node.db)
  else:
    node.beaconState = persistedState[]
    var targetSlot = toSlot timeSinceGenesis(node.beaconState)

    while node.beaconState.finalized_slot.int < targetSlot:
      var (peer, changeLog) = await node.network.getValidatorChangeLog(
        node.beaconState.validator_registry_delta_chain_tip)

      if peer == nil:
        error "Failed to sync with any peer"
        return false

      if applyValidatorChangeLog(changeLog, node.beaconState):
        node.db.persistBlock(node.beaconState, changeLog.signedBlock)
      else:
        warn "Ignoring invalid validator change log", sentFrom = peer

  return true

template findIt(s: openarray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

template isSameKey(lhs, rhs: ValidatorPubKey): bool =
  # TODO: operator `==` for ValidatorPubKey doesn't work properly at the moment
  $lhs == $rhs

proc addLocalValidators*(node: BeaconNode) =
  for validator in node.config.validators:
    let
      privKey = validator.privKey
      pubKey = privKey.pubKey()
      randao = validator.randao

    let idx = node.beaconState.validator_registry.findIt(isSameKey(it.pubKey, pubKey))
    if idx == -1:
      warn "Validator not in registry", pubKey
    else:
      node.attachedValidators.addLocalValidator(idx, pubKey, privKey, randao)

  info "Local validators attached ", count = node.attachedValidators.count

proc getAttachedValidator(node: BeaconNode, idx: int): AttachedValidator =
  let validatorKey = node.beaconState.validator_registry[idx].pubkey
  return node.attachedValidators.getValidator(validatorKey)

proc makeAttestation(node: BeaconNode,
                     validator: AttachedValidator,
                     slot: uint64,
                     shard: uint64,
                     committeeLen: int,
                     indexInCommittee: int) {.async.} =
  doAssert node != nil
  doAssert validator != nil

  let justifiedBlockRoot = get_block_root(node.beaconState, node.beaconState.justified_slot)

  var attestationData = AttestationData(
    slot: slot,
    shard: shard,
    beacon_block_root: node.headBlockRoot,
    epoch_boundary_root: Eth2Digest(), # TODO
    shard_block_root: Eth2Digest(), # TODO
    latest_crosslink_root: Eth2Digest(), # TODO
    justified_slot: node.beaconState.justified_slot,
    justified_block_root: justifiedBlockRoot)

  let validatorSignature = await validator.signAttestation(attestationData)

  var participationBitfield = repeat(0'u8, ceil_div8(committeeLen))
  bitSet(participationBitfield, indexInCommittee)

  var attestation = Attestation(
    data: attestationData,
    aggregate_signature: validatorSignature,
    participation_bitfield: participationBitfield)

  await node.network.broadcast(topicAttestations, attestation)

  info "Attestation sent", slot = slot,
                           shard = shard,
                           validator = validator.idx,
                           signature = shortHash(validatorSignature)

proc proposeBlock(node: BeaconNode,
                  validator: AttachedValidator,
                  slot: uint64) {.async.} =
  doAssert node != nil
  doAssert validator != nil
  doAssert validator.idx < node.beaconState.validator_registry.len

  var state = node.beaconState

  for s in node.beaconState.slot + 1 ..< slot:
    info "Skipping block", slot = s
    let ok = updateState(state, node.headBlockRoot, none[BeaconBlock](), {})
    doAssert ok

  let
    randaoCommitment = node.beaconState.validator_registry[validator.idx].randao_commitment
    randaoReveal =  await validator.randaoReveal(randaoCommitment)

  var blockBody = BeaconBlockBody(
    attestations: node.attestationPool.getAttestationsForBlock(node.beaconState, slot))

  var newBlock = BeaconBlock(
    slot: slot,
    parent_root: node.headBlockRoot,
    randao_reveal: randaoReveal,
    candidate_pow_receipt_root: node.mainchainMonitor.getBeaconBlockRef(),
    signature: ValidatorSig(), # we need the rest of the block first!
    body: blockBody)

  let ok = updateState(state, node.headBlockRoot, some(newBlock), {skipValidation})
  doAssert ok # TODO: err, could this fail somehow?

  newBlock.state_root = Eth2Digest(data: hash_tree_root(state))

  var signedData = ProposalSignedData(
    slot: slot,
    shard: BEACON_CHAIN_SHARD_NUMBER,
    blockRoot: hash_tree_root_final(newBlock))

  newBlock.signature = await validator.signBlockProposal(signedData)

  await node.network.broadcast(topicBeaconBlocks, newBlock)

  info "Block proposed", slot = slot,
                         stateRoot = shortHash(newBlock.state_root),
                         validator = validator.idx

proc scheduleBlockProposal(node: BeaconNode,
                           slot: int,
                           validator: AttachedValidator) =
  # TODO:
  # This function exists only to hide a bug with Nim's closures.
  # If you inline it in `scheduleCycleActions`, you'll see the
  # internal `doAssert` starting to fail.
  doAssert validator != nil

  addTimer(node.beaconState.slotStart(slot)) do (p: pointer):
    doAssert validator != nil
    asyncCheck proposeBlock(node, validator, slot.uint64)

proc scheduleAttestation(node: BeaconNode,
                         validator: AttachedValidator,
                         slot: int,
                         shard: uint64,
                         committeeLen: int,
                         indexInCommittee: int) =
  # TODO:
  # This function exists only to hide a bug with Nim's closures.
  # If you inline it in `scheduleCycleActions`, you'll see the
  # internal `doAssert` starting to fail.
  doAssert validator != nil

  addTimer(node.beaconState.slotMiddle(slot)) do (p: pointer):
    doAssert validator != nil
    asyncCheck makeAttestation(node, validator, slot.uint64,
                               shard, committeeLen, indexInCommittee)

proc scheduleCycleActions(node: BeaconNode, cycleStart: int) =
  ## This schedules the required block proposals and
  ## attestations from our attached validators.
  doAssert node != nil

  # TODO: this copy of the state shouldn't be necessary, but please
  # see the comments in `get_beacon_proposer_index`
  var nextState = node.beaconState

  for i in 1 ..< EPOCH_LENGTH:
    # Schedule block proposals
    nextState.slot = node.beaconState.slot + i.uint64

    let
      slot = cycleStart + i
      proposerIdx = get_beacon_proposer_index(nextState, nextState.slot.uint64)
      validator = node.getAttachedValidator(proposerIdx)

    if validator != nil:
      # TODO:
      # Warm-up the proposer earlier to try to obtain previous
      # missing blocks if necessary
      scheduleBlockProposal(node, slot, validator)

    # Schedule attestations
    let
      committeesIdx = get_shard_committees_index(nextState, nextState.slot.uint64)

    for shard in node.beaconState.shard_committees_at_slots[committees_idx]:
      for i, validatorIdx in shard.committee:
        let validator = node.getAttachedValidator(validatorIdx)
        if validator != nil:
          scheduleAttestation(node, validator, slot, shard.shard, shard.committee.len, i)

  node.lastScheduledCycle = cycleStart
  let nextCycle = cycleStart + EPOCH_LENGTH

  addTimer(node.beaconState.slotMiddle(nextCycle)) do (p: pointer):
    if node.lastScheduledCycle != nextCycle:
      node.scheduleCycleActions(nextCycle)

proc processBlocks*(node: BeaconNode) =
  node.network.subscribe(topicBeaconBlocks) do (newBlock: BeaconBlock):
    info "Block received", slot = newBlock.slot,
                           stateRoot = shortHash(newBlock.state_root)

    let newBlockRoot = hash_tree_root_final(newBlock)

    for slot in node.beaconState.slot + 1 ..< newBlock.slot:
      info "Skipping block", slot
      let ok = updateState(node.beaconState, node.headBlockRoot, none[BeaconBlock](), {})

    let ok = updateState(node.beaconState, node.headBlockRoot, some(newBlock), {})
    doAssert ok

    node.headBlock = newBlock
    node.headBlockRoot = newBlockRoot

    # TODO:
    #
    # 1. Check for missing blocks and obtain them
    #
    # 2. Apply fork-choice rule (update node.headBlock)
    #
    # 3. Peform block processing / state recalculation / etc
    #

    let slot = newBlock.slot.int
    if slot mod EPOCH_LENGTH == 0:
      node.scheduleCycleActions(slot)
      node.attestationPool.discardHistoryToSlot(slot)

  node.network.subscribe(topicAttestations) do (a: Attestation):
    info "Attestation received", slot = a.data.slot,
                                 shard = a.data.shard,
                                 signature = shortHash(a.aggregate_signature)

    node.attestationPool.add(a, node.beaconState)

  dynamicLogScope(node = node.config.tcpPort - 50000):
    let cycleStart = node.beaconState.slot.int
    node.scheduleCycleActions(cycleStart)

    runForever()

var gPidFile: string
proc createPidFile(filename: string) =
  createDir splitFile(filename).dir
  writeFile filename, $getCurrentProcessId()
  gPidFile = filename
  addQuitProc proc {.noconv.} = removeFile gPidFile

when isMainModule:
  let config = load BeaconNodeConf
  case config.cmd
  of createChain:
    createStateSnapshot(config.chainStartupData, config.outputStateFile.string)
    quit 0

  of noCommand:
    waitFor syncrhronizeClock()
    createPidFile(config.dataDir.string / "beacon_node.pid")

    var node = BeaconNode.init config
    waitFor node.connectToNetwork()

    if not waitFor node.sync():
      quit 1

    node.addLocalValidators()
    node.processBlocks()

