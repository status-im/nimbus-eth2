import
  std_shims/[os_shims, objects], net, sequtils, options, tables,
  asyncdispatch2, chronicles, confutils, eth_p2p, eth_keys,
  spec/[datatypes, digest, crypto, beaconstate, helpers, validator], conf, time,
  state_transition, fork_choice, ssz, beacon_chain_db, validator_pool, extras,
  mainchain_monitor, sync_protocol, gossipsub_protocol, trusted_state_snapshots,
  eth_trie/db, eth_trie/backends/rocksdb_backend

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
    lastScheduledEpoch: uint64
    headBlock: BeaconBlock
    headBlockRoot: Eth2Digest
    blocksChildren: Table[Eth2Digest, seq[Eth2Digest]]

const
  version = "v0.1" # TODO: read this from the nimble file
  clientId = "nimbus beacon node " & version

  topicBeaconBlocks = "ethereum/2.1/beacon_chain/blocks"
  topicAttestations = "ethereum/2.1/beacon_chain/attestations"

func shortHash(x: auto): string = ($x)[0..7]
func shortValidatorKey(node: BeaconNode, validatorIdx: int): string =
  ($node.beaconState.validator_registry[validatorIdx].pubkey)[0..7]

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

  let trieDB = trieDB newChainDb(string conf.dataDir)
  result.db = BeaconChainDB.init(trieDB)

  if not result.db.isInitialized:
    # Use stateSnapshot as genesis
    info "Initializing DB"
    result.db.persistState(result.config.stateSnapshot.get)

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
  if persistedState.slotDistanceFromNow() > WEAK_SUBJECTVITY_PERIOD.int64:
    node.beaconState = await obtainTrustedStateSnapshot(node.db)
  else:
    node.beaconState = persistedState
    var targetSlot = toSlot timeSinceGenesis(node.beaconState)

    let t = now()
    if t < node.beaconState.genesisTime * 1000:
      await sleepAsync int(node.beaconState.genesisTime * 1000 - t)

    while node.beaconState.finalized_epoch < targetSlot.slot_to_epoch:
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
      debug "Attaching validator", validator = shortValidatorKey(node, idx),
                                   idx, pubKey
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

  if get_current_epoch(node.beaconState) == node.beaconState.justified_epoch:
    return

  let justifiedBlockRoot = get_block_root(node.beaconState, get_epoch_start_slot(node.beaconState.justified_epoch))

  var attestationData = AttestationData(
    slot: slot,
    shard: shard,
    beacon_block_root: node.headBlockRoot,
    epoch_boundary_root: Eth2Digest(), # TODO
    shard_block_root: Eth2Digest(), # TODO
    latest_crosslink_root: Eth2Digest(), # TODO
    justified_epoch: node.beaconState.justified_epoch,
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
                           validator = shortValidatorKey(node, validator.idx),
                           signature = shortHash(validatorSignature)

proc proposeBlock(node: BeaconNode,
                  validator: AttachedValidator,
                  slot: uint64) {.async.} =
  doAssert node != nil
  doAssert validator != nil
  doAssert validator.idx < node.beaconState.validator_registry.len

  var state = node.beaconState

  if node.beaconState.slot + 1 < slot:
    info "Proposing block after slot gap",
      slot,
      stateSlot = node.beaconState.slot
    for s in node.beaconState.slot + 1 ..< slot:
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
    eth1_data: node.mainchainMonitor.getBeaconBlockRef(),
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
                         validator = shortValidatorKey(node, validator.idx)

proc scheduleBlockProposal(node: BeaconNode,
                           slot: uint64,
                           validator: AttachedValidator) =
  # TODO:
  # This function exists only to hide a bug with Nim's closures.
  # If you inline it in `scheduleEpochActions`, you'll see the
  # internal `doAssert` starting to fail.
  doAssert validator != nil

  let at = node.beaconState.slotStart(slot)

  info "Scheduling block proposal",
    validator = shortValidatorKey(node, validator.idx),
    slot,
    fromNow = (at - fastEpochTime()) div 1000

  addTimer(node.beaconState.slotStart(slot)) do (x: pointer) {.gcsafe.}:
    # TODO timers are generally not accurate / guaranteed to fire at the right
    #      time - need to guard here against early / late firings
    doAssert validator != nil
    asyncCheck proposeBlock(node, validator, slot.uint64)

proc scheduleAttestation(node: BeaconNode,
                         validator: AttachedValidator,
                         slot: uint64,
                         shard: uint64,
                         committeeLen: int,
                         indexInCommittee: int) =
  # TODO:
  # This function exists only to hide a bug with Nim's closures.
  # If you inline it in `scheduleEpochActions`, you'll see the
  # internal `doAssert` starting to fail.
  doAssert validator != nil

  addTimer(node.beaconState.slotMiddle(slot)) do (p: pointer) {.gcsafe.}:
    doAssert validator != nil
    asyncCheck makeAttestation(node, validator, slot.uint64,
                               shard, committeeLen, indexInCommittee)

proc scheduleEpochActions(node: BeaconNode, epoch: uint64) =
  ## This schedules the required block proposals and
  ## attestations from our attached validators.
  doAssert node != nil

  debug "Scheduling epoch actions", epoch

  # TODO: this copy of the state shouldn't be necessary, but please
  # see the comments in `get_beacon_proposer_index`
  var nextState = node.beaconState

  for i in 1.uint64 ..< EPOCH_LENGTH:
    # Schedule block proposals
    let slot = epoch * EPOCH_LENGTH + i
    nextState.slot = slot
    let proposerIdx = get_beacon_proposer_index(nextState, slot)
    let validator = node.getAttachedValidator(proposerIdx)

    if validator != nil:
      # TODO:
      # Warm-up the proposer earlier to try to obtain previous
      # missing blocks if necessary
      scheduleBlockProposal(node, slot, validator)

    # Schedule attestations
    let
      committeesIdx = get_shard_committees_index(nextState, slot)

    #for shard in node.beaconState.shard_committees_at_slots[committees_idx]:
    for crosslink_committee in get_crosslink_committees_at_slot(node.beaconState, committees_idx):
      #for i, validatorIdx in shard.committee:
      for i, validatorIdx in crosslink_committee.a:
        let validator = node.getAttachedValidator(validatorIdx)
        if validator != nil:
          #scheduleAttestation(node, validator, slot, shard.shard, shard.committee.len, i)
          scheduleAttestation(node, validator, slot, crosslink_committee.b, crosslink_committee.a.len, i)

  node.lastScheduledEpoch = epoch
  let
    nextEpoch = epoch + 1
    at = node.beaconState.slotMiddle(nextEpoch * EPOCH_LENGTH)

  info "Scheduling next epoch update",
    fromNow = (at - fastEpochTime()) div 1000,
    nextEpoch

  addTimer(at) do (p: pointer):
    if node.lastScheduledEpoch != nextEpoch:
      node.scheduleEpochActions(nextEpoch)

proc processBlocks*(node: BeaconNode) =
  node.network.subscribe(topicBeaconBlocks) do (newBlock: BeaconBlock):
    let stateSlot = node.beaconState.slot
    info "Block received", slot = newBlock.slot,
                           stateRoot = shortHash(newBlock.state_root),
                           stateSlot

    # TODO: This should be replaced with the real fork-choice rule
    if newBlock.slot <= stateSlot:
      debug "Ignoring block"
      return

    let newBlockRoot = hash_tree_root_final(newBlock)

    var state = node.beaconState
    if stateSlot + 1 < newBlock.slot:
      info "Advancing state past slot gap",
        blockSlot = newBlock.slot,
        stateSlot
      for slot in stateSlot + 1 ..< newBlock.slot:
        let ok = updateState(state, node.headBlockRoot, none[BeaconBlock](), {})
        doAssert ok

    let ok = updateState(state, node.headBlockRoot, some(newBlock), {})
    if not ok:
      debug "Ignoring non-validating block"
      return

    node.headBlock = newBlock
    node.headBlockRoot = newBlockRoot
    node.beaconState = state
    node.db.persistBlock(node.beaconState, newBlock)

    # TODO:
    #
    # 1. Check for missing blocks and obtain them
    #
    # 2. Apply fork-choice rule (update node.headBlock)
    #
    # 3. Peform block processing / state recalculation / etc
    #

    let epoch = newBlock.slot.epoch
    if epoch != node.lastScheduledEpoch:
      node.scheduleEpochActions(epoch)

  node.network.subscribe(topicAttestations) do (a: Attestation):
    let participants = get_attestation_participants(
      node.beaconState, a.data, a.participation_bitfield).
        mapIt(shortValidatorKey(node, it))

    info "Attestation received", slot = a.data.slot,
                                 shard = a.data.shard,
                                 signature = shortHash(a.aggregate_signature),
                                 participants

    node.attestationPool.add(a, node.beaconState)

  let epoch = node.beaconState.timeSinceGenesis().toSlot div EPOCH_LENGTH
  node.scheduleEpochActions(epoch)

  runForever()

var gPidFile: string
proc createPidFile(filename: string) =
  createDir splitFile(filename).dir
  writeFile filename, $getCurrentProcessId()
  gPidFile = filename
  addQuitProc proc {.noconv.} = removeFile gPidFile

when isMainModule:
  let config = load BeaconNodeConf
  if config.logLevel != LogLevel.NONE:
    setLogLevel(config.logLevel)

  case config.cmd
  of createChain:
    createStateSnapshot(config.chainStartupData, config.outputStateFile.string)
    quit 0

  of noCommand:
    waitFor synchronizeClock()
    createPidFile(config.dataDir.string / "beacon_node.pid")

    var node = BeaconNode.init config

    dynamicLogScope(node = node.config.tcpPort - 50000):
      waitFor node.connectToNetwork()

      if not waitFor node.sync():
        quit 1

      info "Starting beacon node",
        slotsSinceFinalization = node.beaconState.slotDistanceFromNow(),
        stateSlot = node.beaconState.slot

      node.addLocalValidators()
      node.processBlocks()
