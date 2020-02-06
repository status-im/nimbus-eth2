import
  # Standard library
  os, net, tables, random, strutils, times, sequtils,

  # Nimble packages
  stew/[objects, bitseqs, byteutils],
  chronos, chronicles, confutils, metrics,
  json_serialization/std/[options, sets], serialization/errors,
  kvstore, kvstore_lmdb, eth/async_utils, eth/p2p/discoveryv5/enr,

  # Local modules
  spec/[datatypes, digest, crypto, beaconstate, helpers, validator, network],
  conf, time, state_transition, beacon_chain_db,
  validator_pool, extras, attestation_pool, block_pool, eth2_network,
  beacon_node_types, mainchain_monitor, version, ssz, ssz/dynamic_navigator,
  sync_protocol, request_manager, validator_keygen, interop, statusbar

const
  genesisFile = "genesis.ssz"
  hasPrompt = not defined(withoutPrompt)
  maxEmptySlotCount = uint64(24*60*60) div SECONDS_PER_SLOT

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#interop-metrics
declareGauge beacon_slot,
  "Latest slot of the beacon chain state"
declareGauge beacon_head_slot,
  "Slot of the head block of the beacon chain"
declareGauge beacon_head_root,
  "Root of the head block of the beacon chain"

# Metrics for tracking attestation and beacon block loss
declareCounter beacon_attestations_sent,
  "Number of beacon chain attestations sent by this peer"
declareCounter beacon_attestations_received,
  "Number of beacon chain attestations received by this peer"
declareCounter beacon_blocks_proposed,
  "Number of beacon chain blocks sent by this peer"
declareCounter beacon_blocks_received,
  "Number of beacon chain blocks received by this peer"

logScope: topics = "beacnde"

type
  BeaconNode = ref object
    nickname: string
    network: Eth2Node
    forkVersion: array[4, byte]
    networkIdentity: Eth2NodeIdentity
    requestManager: RequestManager
    bootstrapNodes: seq[BootstrapAddr]
    bootstrapEnrs: seq[enr.Record]
    db: BeaconChainDB
    config: BeaconNodeConf
    attachedValidators: ValidatorPool
    blockPool: BlockPool
    attestationPool: AttestationPool
    mainchainMonitor: MainchainMonitor
    beaconClock: BeaconClock

proc onBeaconBlock*(node: BeaconNode, blck: SignedBeaconBlock) {.gcsafe.}
proc updateHead(node: BeaconNode): BlockRef

proc saveValidatorKey(keyName, key: string, conf: BeaconNodeConf) =
  let validatorsDir = conf.localValidatorsDir
  let outputFile = validatorsDir / keyName
  createDir validatorsDir
  writeFile(outputFile, key)
  info "Imported validator key", file = outputFile

proc getStateFromSnapshot(conf: BeaconNodeConf, state: var BeaconState): bool =
  var
    genesisPath = conf.dataDir/genesisFile
    snapshotContents: TaintedString
    writeGenesisFile = false

  if conf.stateSnapshot.isSome:
    let
      snapshotPath = conf.stateSnapshot.get.string
      snapshotExt = splitFile(snapshotPath).ext

    if cmpIgnoreCase(snapshotExt, ".ssz") != 0:
      error "The supplied state snapshot must be a SSZ file",
            suppliedPath = snapshotPath
      quit 1

    snapshotContents = readFile(snapshotPath)
    if fileExists(genesisPath):
      let genesisContents = readFile(genesisPath)
      if snapshotContents != genesisContents:
        error "Data directory not empty. Existing genesis state differs from supplied snapshot",
              dataDir = conf.dataDir.string, snapshot = snapshotPath
        quit 1
    else:
      debug "No previous genesis state. Importing snapshot",
            genesisPath, dataDir = conf.dataDir.string
      writeGenesisFile = true
      genesisPath = snapshotPath
  else:
    try:
      snapshotContents = readFile(genesisPath)
    except CatchableError as err:
      error "Failed to read genesis file", err = err.msg
      quit 1

  try:
    state = SSZ.decode(snapshotContents, BeaconState)
  except SerializationError:
    error "Failed to import genesis file", path = genesisPath
    quit 1

  info "Loaded genesis state", path = genesisPath

  if writeGenesisFile:
    try:
      notice "Writing genesis to data directory", path = conf.dataDir/genesisFile
      writeFile(conf.dataDir/genesisFile, snapshotContents.string)
    except CatchableError as err:
      error "Failed to persist genesis file to data dir",
        err = err.msg, genesisFile = conf.dataDir/genesisFile
      quit 1

  result = true

proc addBootstrapAddr(v: var seq[BootstrapAddr], add: TaintedString) =
  try:
    v.add BootstrapAddr.initAddress(string add)
  except CatchableError as e:
    warn "Skipping invalid address", err = e.msg

proc loadBootstrapFile(bootstrapFile: string): seq[BootstrapAddr] =
  if fileExists(bootstrapFile):
    for line in lines(bootstrapFile):
      result.addBootstrapAddr(line)

proc addEnrBootstrapNode(enrBase64: string,
                         bootNodes: var seq[BootstrapAddr],
                         enrs: var seq[enr.Record]) =
  var enrRec: enr.Record
  if enrRec.fromURI(enrBase64):
    try:
      let
        ip = IpAddress(family: IpAddressFamily.IPv4,
                       address_v4: cast[array[4, uint8]](enrRec.get("ip", int)))
        tcpPort = Port enrRec.get("tcp", int)
        # udpPort = Port enrRec.get("udp", int)
      bootNodes.add BootstrapAddr.initAddress(ip, tcpPort)
      enrs.add enrRec
    except CatchableError as err:
      warn "Invalid ENR record", enrRec
  else:
    warn "Failed to parse ENR record", value = enrRec

proc useEnrBootstrapFile(bootstrapFile: string,
                         bootNodes: var seq[BootstrapAddr],
                         enrs: var seq[enr.Record]) =
  let ext = splitFile(bootstrapFile).ext
  if cmpIgnoreCase(ext, ".txt") == 0:
    for ln in lines(bootstrapFile):
      addEnrBootstrapNode(string ln, bootNodes, enrs)
  elif cmpIgnoreCase(ext, ".yaml") == 0:
    # TODO. This is very ugly, but let's try to negotiate the
    # removal of YAML metadata.
    for ln in lines(bootstrapFile):
      addEnrBootstrapNode(string(ln[3..^2]), bootNodes, enrs)
  else:
    error "Unknown bootstrap file format", ext
    quit 1

proc init*(T: type BeaconNode, conf: BeaconNodeConf): Future[BeaconNode] {.async.} =
  let
    networkId = getPersistentNetIdentity(conf)
    nickname = if conf.nodeName == "auto": shortForm(networkId)
               else: conf.nodeName
    db = BeaconChainDB.init(kvStore LmdbStoreRef.init(conf.databaseDir))

  var mainchainMonitor: MainchainMonitor

  if not BlockPool.isInitialized(db):
    # Fresh start - need to load a genesis state from somewhere
    var genesisState = new BeaconState

    # Try file from command line first
    if not conf.getStateFromSnapshot(genesisState[]):
      # Didn't work, try creating a genesis state using main chain monitor
      # TODO Could move this to a separate "GenesisMonitor" process or task
      #      that would do only this - see
      if conf.depositWeb3Url.len != 0:
        mainchainMonitor = MainchainMonitor.init(
          conf.depositWeb3Url, conf.depositContractAddress, Eth2Digest())
        mainchainMonitor.start()
      else:
        error "No initial state, need genesis state or deposit contract address"
        quit 1

      genesisState[] = await mainchainMonitor.getGenesis()

    if genesisState[].slot != GENESIS_SLOT:
      # TODO how to get a block from a non-genesis state?
      error "Starting from non-genesis state not supported",
        stateSlot = genesisState[].slot,
        stateRoot = hash_tree_root(genesisState[])
      quit 1

    let tailBlock = get_initial_beacon_block(genesisState[])

    try:
      BlockPool.preInit(db, genesisState[], tailBlock)
      doAssert BlockPool.isInitialized(db), "preInit should have initialized db"
    except CatchableError as e:
      error "Failed to initialize database", err = e.msg
      quit 1

  # TODO check that genesis given on command line (if any) matches database
  let
    blockPool = BlockPool.init(db)

  if mainchainMonitor.isNil and conf.depositWeb3Url.len != 0:
    mainchainMonitor = MainchainMonitor.init(
      conf.depositWeb3Url, conf.depositContractAddress,
      blockPool.headState.data.data.eth1_data.block_hash)
    # TODO if we don't have any validators attached, we don't need a mainchain
    #      monitor
    mainchainMonitor.start()

  var
    bootNodes: seq[BootstrapAddr]
    enrs: seq[enr.Record]

  for node in conf.bootstrapNodes: bootNodes.addBootstrapAddr(node)
  bootNodes.add(loadBootstrapFile(string conf.bootstrapNodesFile))
  bootNodes.add(loadBootstrapFile(conf.dataDir / "bootstrap_nodes.txt"))

  let enrBootstrapFile = string conf.enrBootstrapNodesFile
  if enrBootstrapFile.len > 0:
    useEnrBootstrapFile(enrBootstrapFile, bootNodes, enrs)

  bootNodes = filterIt(bootNodes, not it.isSameNode(networkId))

  let
    network = await createEth2Node(conf, bootNodes, enrs)

  let addressFile = string(conf.dataDir) / "beacon_node.address"
  network.saveConnectionAddressFile(addressFile)

  var res = BeaconNode(
    nickname: nickname,
    network: network,
    forkVersion: blockPool.headState.data.data.fork.current_version,
    networkIdentity: networkId,
    requestManager: RequestManager.init(network),
    bootstrapNodes: bootNodes,
    bootstrapEnrs: enrs,
    db: db,
    config: conf,
    attachedValidators: ValidatorPool.init(),
    blockPool: blockPool,
    attestationPool: AttestationPool.init(blockPool),
    mainchainMonitor: mainchainMonitor,
    beaconClock: BeaconClock.init(blockPool.headState.data.data),
  )

  # TODO sync is called when a remote peer is connected - is that the right
  #      time to do so?
  let sync = network.protocolState(BeaconSync)
  sync.init(blockPool, res.forkVersion,
    proc(signedBlock: SignedBeaconBlock) =
      if signedBlock.message.slot mod SLOTS_PER_EPOCH == 0:
        # TODO this is a hack to make sure that lmd ghost is run regularly
        #      while syncing blocks - it's poor form to keep it here though -
        #      the logic should be moved elsewhere
        # TODO why only when syncing? well, because the way the code is written
        #      we require a connection to a boot node to start, and that boot
        #      node will start syncing as part of connection setup - it looks
        #      like it needs to finish syncing before the slot timer starts
        #      ticking which is a problem: all the synced blocks will be added
        #      to the block pool without any periodic head updates while this
        #      process is ongoing (during a blank start for example), which
        #      leads to an unhealthy buildup of blocks in the non-finalized part
        #      of the block pool
        # TODO is it a problem that someone sending us a block can force
        #      a potentially expensive head resolution?
        discard res.updateHead()

      onBeaconBlock(res, signedBlock))

  return res

proc connectToNetwork(node: BeaconNode) {.async.} =
  if node.bootstrapNodes.len > 0:
    info "Connecting to bootstrap nodes", bootstrapNodes = node.bootstrapNodes
  else:
    info "Waiting for connections"

  await node.network.connectToNetwork(node.bootstrapNodes)

template findIt(s: openarray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

proc addLocalValidator(
    node: BeaconNode, state: BeaconState, privKey: ValidatorPrivKey) =
  let pubKey = privKey.pubKey()

  let idx = state.validators.findIt(it.pubKey == pubKey)
  if idx == -1:
    # We allow adding a validator even if its key is not in the state registry:
    # it might be that the deposit for this validator has not yet been processed
    warn "Validator not in registry (yet?)", pubKey

  node.attachedValidators.addLocalValidator(pubKey, privKey)

proc addLocalValidators(node: BeaconNode, state: BeaconState) =
  for validatorKey in node.config.validatorKeys:
    node.addLocalValidator state, validatorKey

  info "Local validators attached ", count = node.attachedValidators.count

func getAttachedValidator(node: BeaconNode,
                          state: BeaconState,
                          idx: ValidatorIndex): AttachedValidator =
  let validatorKey = state.validators[idx].pubkey
  node.attachedValidators.getValidator(validatorKey)

proc isSynced(node: BeaconNode, head: BlockRef): bool =
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
  if wallSlot.afterGenesis and (wallSlot.slot > head.slot) and
      (wallSlot.slot - head.slot) > maxEmptySlotCount:
    false
  else:
    true

proc updateHead(node: BeaconNode): BlockRef =
  # Check pending attestations - maybe we found some blocks for them
  node.attestationPool.resolve()

  # Grab the new head according to our latest attestation data
  let newHead = node.attestationPool.selectHead()

  # Store the new head in the block pool - this may cause epochs to be
  # justified and finalized
  node.blockPool.updateHead(newHead)
  beacon_head_root.set newHead.root.toGaugeValue

  newHead

proc sendAttestation(node: BeaconNode,
                     fork: Fork,
                     validator: AttachedValidator,
                     attestationData: AttestationData,
                     committeeLen: int,
                     indexInCommittee: int) {.async.} =
  logScope: pcs = "send_attestation"

  let
    validatorSignature = await validator.signAttestation(attestationData, fork)

  var aggregationBits = CommitteeValidatorsBits.init(committeeLen)
  aggregationBits.setBit indexInCommittee

  var attestation = Attestation(
    data: attestationData,
    signature: validatorSignature,
    aggregation_bits: aggregationBits
  )

  node.network.broadcast(topicAttestations, attestation)

  if node.config.dump:
    SSZ.saveFile(
      node.config.dumpDir / "att-" & $attestationData.slot & "-" &
      $attestationData.index & "-" & validator.pubKey.shortLog &
      ".ssz", attestation)

  info "Attestation sent",
    attestation = shortLog(attestation),
    validator = shortLog(validator),
    indexInCommittee = indexInCommittee,
    cat = "consensus"

  beacon_attestations_sent.inc()

proc proposeBlock(node: BeaconNode,
                  validator: AttachedValidator,
                  head: BlockRef,
                  slot: Slot): Future[BlockRef] {.async.} =
  logScope: pcs = "block_proposal"

  if head.slot >= slot:
    # We should normally not have a head newer than the slot we're proposing for
    # but this can happen if block proposal is delayed
    warn "Skipping proposal, have newer head already",
      headSlot = shortLog(head.slot),
      headBlockRoot = shortLog(head.root),
      slot = shortLog(slot),
      cat = "fastforward"
    return head

  # Advance state to the slot immediately preceding the one we're creating a
  # block for - potentially we will be processing empty slots along the way.
  let (nroot, nblck) = node.blockPool.withState(
      node.blockPool.tmpState, head.atSlot(slot)):
    let (eth1data, deposits) =
      if node.mainchainMonitor.isNil:
        (get_eth1data_stub(
            state.eth1_deposit_index, slot.compute_epoch_at_slot()),
          newSeq[Deposit]())
      else:
        (node.mainchainMonitor.eth1Data,
          node.mainchainMonitor.getPendingDeposits())

    # To create a block, we'll first apply a partial block to the state, skipping
    # some validations.
    let
      fork = state.fork
      blockBody = BeaconBlockBody(
        randao_reveal: validator.genRandaoReveal(fork, slot),
        eth1_data: eth1data,
        attestations:
          node.attestationPool.getAttestationsForBlock(state, slot),
        deposits: deposits)

    var
      newBlock = SignedBeaconBlock(
        message: BeaconBlock(
          slot: slot,
          parent_root: head.root,
          body: blockBody))
      tmpState = hashedState
    discard state_transition(tmpState, newBlock.message, {skipValidation})
    # TODO only enable in fast-fail debugging situations
    # otherwise, bad attestations can bring down network
    # doAssert ok # TODO: err, could this fail somehow?

    newBlock.message.state_root = tmpState.root

    let blockRoot = hash_tree_root(newBlock.message)

    # Careful, state no longer valid after here..
    # We use the fork from the pre-newBlock state which should be fine because
    # fork carries two epochs, so even if it's a fork block, the right thing
    # will happen here
    newBlock.signature =
      await validator.signBlockProposal(fork, slot, blockRoot)

    (blockRoot, newBlock)

  let newBlockRef = node.blockPool.add(nroot, nblck)
  if newBlockRef == nil:
    warn "Unable to add proposed block to block pool",
      newBlock = shortLog(newBlock.message),
      blockRoot = shortLog(blockRoot),
      cat = "bug"
    return head

  info "Block proposed",
    blck = shortLog(newBlock.message),
    blockRoot = shortLog(newBlockRef.root),
    validator = shortLog(validator),
    cat = "consensus"

  if node.config.dump:
    SSZ.saveFile(
      node.config.dumpDir / "block-" & $newBlock.message.slot & "-" &
      shortLog(newBlockRef.root) & ".ssz", newBlock)
    SSZ.saveFile(
      node.config.dumpDir / "state-" & $tmpState.data.slot & "-" &
      shortLog(newBlockRef.root) & "-"  & shortLog(tmpState.root) & ".ssz",
      tmpState.data)

  node.network.broadcast(topicBeaconBlocks, newBlock)

  beacon_blocks_proposed.inc()

  return newBlockRef

proc onAttestation(node: BeaconNode, attestation: Attestation) =
  # We received an attestation from the network but don't know much about it
  # yet - in particular, we haven't verified that it belongs to particular chain
  # we're on, or that it follows the rules of the protocol
  logScope: pcs = "on_attestation"

  let
    wallSlot = node.beaconClock.now().toSlot()
    head = node.blockPool.head

  debug "Attestation received",
    attestation = shortLog(attestation),
    headRoot = shortLog(head.blck.root),
    headSlot = shortLog(head.blck.slot),
    wallSlot = shortLog(wallSlot.slot),
    cat = "consensus" # Tag "consensus|attestation"?

  if not wallSlot.afterGenesis or wallSlot.slot < head.blck.slot:
    warn "Received attestation before genesis or head - clock is wrong?",
      afterGenesis = wallSlot.afterGenesis,
      wallSlot = shortLog(wallSlot.slot),
      headSlot = shortLog(head.blck.slot),
      cat = "clock_drift" # Tag "attestation|clock_drift"?
    return

  if attestation.data.slot > head.blck.slot and
      (attestation.data.slot - head.blck.slot) > maxEmptySlotCount:
    warn "Ignoring attestation, head block too old (out of sync?)",
      attestationSlot = attestation.data.slot, headSlot = head.blck.slot
    return

  node.attestationPool.add(attestation)

proc onBeaconBlock(node: BeaconNode, blck: SignedBeaconBlock) =
  # We received a block but don't know much about it yet - in particular, we
  # don't know if it's part of the chain we're currently building.
  let blockRoot = hash_tree_root(blck.message)
  debug "Block received",
    blck = shortLog(blck.message),
    blockRoot = shortLog(blockRoot),
    cat = "block_listener",
    pcs = "receive_block"

  beacon_blocks_received.inc()

  if node.blockPool.add(blockRoot, blck).isNil:
    return

  # The block we received contains attestations, and we might not yet know about
  # all of them. Let's add them to the attestation pool - in case they block
  # is not yet resolved, neither will the attestations be!
  # But please note that we only care about recent attestations.
  # TODO shouldn't add attestations if the block turns out to be invalid..
  let currentSlot = node.beaconClock.now.toSlot
  if currentSlot.afterGenesis and
     blck.message.slot.epoch + 1 >= currentSlot.slot.epoch:
    for attestation in blck.message.body.attestations:
      node.onAttestation(attestation)

proc handleAttestations(node: BeaconNode, head: BlockRef, slot: Slot) =
  ## Perform all attestations that the validators attached to this node should
  ## perform during the given slot
  logScope: pcs = "on_attestation"

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

  let attestationHead = head.findAncestorBySlot(slot)
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
    attestationSlot = shortLog(slot),
    cat = "attestation"

  # Collect data to send before node.stateCache grows stale
  var attestations: seq[tuple[
    data: AttestationData, committeeLen, indexInCommittee: int,
    validator: AttachedValidator]]

  # We need to run attestations exactly for the slot that we're attesting to.
  # In case blocks went missing, this means advancing past the latest block
  # using empty slots as fillers.
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.4/specs/validator/0_beacon-chain-validator.md#validator-assignments
  # TODO we could cache the validator assignment since it's valid for the entire
  #      epoch since it doesn't change, but that has to be weighed against
  #      the complexity of handling forks correctly - instead, we use an adapted
  #      version here that calculates the committee for a single slot only
  node.blockPool.withState(node.blockPool.tmpState, attestationHead):
    var cache = get_empty_per_epoch_cache()
    let committees_per_slot = get_committee_count_at_slot(state, slot)

    for committee_index in 0'u64..<committees_per_slot:
      let
        committee = get_beacon_committee(state, slot, committee_index, cache)

      for index_in_committee, validatorIdx in committee:
        let validator = node.getAttachedValidator(state, validatorIdx)
        if validator != nil:
          let ad = makeAttestationData(state, slot, committee_index, blck.root)
          attestations.add((ad, committee.len, index_in_committee, validator))

    for a in attestations:
      traceAsyncErrors sendAttestation(
        node, state.fork, a.validator, a.data, a.committeeLen, a.indexInCommittee)

proc handleProposal(node: BeaconNode, head: BlockRef, slot: Slot):
    Future[BlockRef] {.async.} =
  ## Perform the proposal for the given slot, iff we have a validator attached
  ## that is supposed to do so, given the shuffling in head

  # TODO here we advance the state to the new slot, but later we'll be
  #      proposing for it - basically, we're selecting proposer based on an
  #      empty slot

  let proposerKey = node.blockPool.getProposer(head, slot)
  if proposerKey.isNone():
    return head

  let validator = node.attachedValidators.getValidator(proposerKey.get())

  if validator != nil:
    return await proposeBlock(node, validator, head, slot)

  debug "Expecting block proposal",
    headRoot = shortLog(head.root),
    slot = shortLog(slot),
    proposer = shortLog(proposerKey.get()),
    cat = "consensus",
    pcs = "wait_for_proposal"

  return head

proc onSlotStart(node: BeaconNode, lastSlot, scheduledSlot: Slot) {.gcsafe, async.} =
  ## Called at the beginning of a slot - usually every slot, but sometimes might
  ## skip a few in case we're running late.
  ## lastSlot: the last slot that we sucessfully processed, so we know where to
  ##           start work from
  ## scheduledSlot: the slot that we were aiming for, in terms of timing

  logScope: pcs = "slot_start"

  let
    # The slot we should be at, according to the clock
    beaconTime = node.beaconClock.now()
    wallSlot = beaconTime.toSlot()

  info "Slot start",
    lastSlot = shortLog(lastSlot),
    scheduledSlot = shortLog(scheduledSlot),
    beaconTime = shortLog(beaconTime),
    peers = node.network.peersCount,
    headSlot = shortLog(node.blockPool.head.blck.slot),
    headEpoch = shortLog(node.blockPool.head.blck.slot.compute_epoch_at_slot()),
    headRoot = shortLog(node.blockPool.head.blck.root),
    finalizedSlot = shortLog(node.blockPool.finalizedHead.blck.slot),
    finalizedRoot = shortLog(node.blockPool.finalizedHead.blck.root),
    finalizedSlot = shortLog(node.blockPool.finalizedHead.blck.slot.compute_epoch_at_slot()),
    cat = "scheduling"

  if not wallSlot.afterGenesis or (wallSlot.slot < lastSlot):
    let
      slot =
        if wallSlot.afterGenesis: wallSlot.slot
        else: GENESIS_SLOT
      nextSlot = slot + 1 # At least GENESIS_SLOT + 1!

    # This can happen if the system clock changes time for example, and it's
    # pretty bad
    # TODO shut down? time either was or is bad, and PoS relies on accuracy..
    warn "Beacon clock time moved back, rescheduling slot actions",
      beaconTime = shortLog(beaconTime),
      lastSlot = shortLog(lastSlot),
      scheduledSlot = shortLog(scheduledSlot),
      nextSlot = shortLog(nextSlot),
      cat = "clock_drift" # tag "scheduling|clock_drift"?

    addTimer(saturate(node.beaconClock.fromNow(nextSlot))) do (p: pointer):
      asyncCheck node.onSlotStart(slot, nextSlot)

    return

  let
    slot = wallSlot.slot # afterGenesis == true!
    nextSlot = slot + 1

  beacon_slot.set slot.int64

  if slot > lastSlot + SLOTS_PER_EPOCH:
    # We've fallen behind more than an epoch - there's nothing clever we can
    # do here really, except skip all the work and try again later.
    # TODO how long should the period be? Using an epoch because that's roughly
    #      how long attestations remain interesting
    # TODO should we shut down instead? clearly we're unable to keep up
    warn "Unable to keep up, skipping ahead",
      lastSlot = shortLog(lastSlot),
      slot = shortLog(slot),
      nextSlot = shortLog(nextSlot),
      scheduledSlot = shortLog(scheduledSlot),
      cat = "overload"

    addTimer(saturate(node.beaconClock.fromNow(nextSlot))) do (p: pointer):
      # We pass the current slot here to indicate that work should be skipped!
      asyncCheck node.onSlotStart(slot, nextSlot)
    return

  # Whatever we do during the slot, we need to know the head, because this will
  # give us a state to work with and thus a shuffling.
  # TODO typically, what consitutes correct actions stays constant between slot
  #      updates and is stable across some epoch transitions as well - see how
  #      we can avoid recalculating everything here

  var head = node.updateHead()

  # TODO is the slot of the clock or the head block more interestion? provide
  #      rationale in comment
  beacon_head_slot.set slot.int64

  # TODO if the head is very old, that is indicative of something being very
  #      wrong - us being out of sync or disconnected from the network - need
  #      to consider what to do in that case:
  #      * nothing - the other parts of the application will reconnect and
  #                  start listening to broadcasts, learn a new head etc..
  #                  risky, because the network might stall if everyone does
  #                  this, because no blocks will be produced
  #      * shut down - this allows the user to notice and take action, but is
  #                    kind of harsh
  #      * keep going - we create blocks and attestations as usual and send them
  #                     out - if network conditions improve, fork choice should
  #                     eventually select the correct head and the rest will
  #                     disappear naturally - risky because user is not aware,
  #                     and might lose stake on canonical chain but "just works"
  #                     when reconnected..
  if node.attachedValidators.count == 0:
    # There are no validators, thus we don't have any additional work to do
    # beyond keeping track of the head
    discard
  elif not node.isSynced(head):
    warn "Node out of sync, skipping block and attestation production for this slot",
      slot, headSlot = head.slot
  else:
    var curSlot = lastSlot + 1
    while curSlot < slot:
      # Timers may be delayed because we're busy processing, and we might have
      # more work to do. We'll try to do so in an expedited way.
      # TODO maybe even collect all work synchronously to avoid unnecessary
      #      state rewinds while waiting for async operations like validator
      #      signature..
      notice "Catching up",
        curSlot = shortLog(curSlot),
        lastSlot = shortLog(lastSlot),
        slot = shortLog(slot),
        cat = "overload"

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
    # send out attestations at the slot mid-point, so we go back to the clock
    # to see how much time we need to wait.
    # TODO the beacon clock might jump here also. It's probably easier to complete
    #      the work for the whole slot using a monotonic clock instead, then deal
    #      with any clock discrepancies once only, at the start of slot timer
    #      processing..

    # https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/validator/0_beacon-chain-validator.md#attesting
    # A validator should create and broadcast the attestation to the
    # associated attestation subnet one-third of the way through the slot
    # during which the validator is assigned―that is, SECONDS_PER_SLOT / 3
    # seconds after the start of slot.
    let
      attestationStart = node.beaconClock.fromNow(slot)
      thirdSlot = seconds(int64(SECONDS_PER_SLOT)) div 3

    if attestationStart.inFuture or attestationStart.offset <= thirdSlot:
      let fromNow =
        if attestationStart.inFuture: attestationStart.offset + thirdSlot
        else: thirdSlot - attestationStart.offset

      trace "Waiting to send attestations",
        slot = shortLog(slot),
        fromNow = shortLog(fromNow),
        cat = "scheduling"

      await sleepAsync(fromNow)

      # Time passed - we might need to select a new head in that case
      head = node.updateHead()

    handleAttestations(node, head, slot)

  # TODO ... and beacon clock might jump here also. sigh.
  let
    nextSlotStart = saturate(node.beaconClock.fromNow(nextSlot))

  info "Slot end",
    slot = shortLog(slot),
    nextSlot = shortLog(nextSlot),
    headSlot = shortLog(node.blockPool.head.blck.slot),
    headEpoch = shortLog(node.blockPool.head.blck.slot.compute_epoch_at_slot()),
    headRoot = shortLog(node.blockPool.head.blck.root),
    finalizedSlot = shortLog(node.blockPool.finalizedHead.blck.slot),
    finalizedEpoch = shortLog(node.blockPool.finalizedHead.blck.slot.compute_epoch_at_slot()),
    finalizedRoot = shortLog(node.blockPool.finalizedHead.blck.root),
    cat = "scheduling"

  addTimer(nextSlotStart) do (p: pointer):
    asyncCheck node.onSlotStart(slot, nextSlot)

proc handleMissingBlocks(node: BeaconNode) =
  let missingBlocks = node.blockPool.checkMissing()
  if missingBlocks.len > 0:
    var left = missingBlocks.len

    info "Requesting detected missing blocks", missingBlocks
    node.requestManager.fetchAncestorBlocks(missingBlocks) do (b: SignedBeaconBlock):
      onBeaconBlock(node, b)

      # TODO instead of waiting for a full second to try the next missing block
      #      fetching, we'll do it here again in case we get all blocks we asked
      #      for (there might be new parents to fetch). of course, this is not
      #      good because the onSecond fetching also kicks in regardless but
      #      whatever - this is just a quick fix for making the testnet easier
      #      work with while the sync problem is dealt with more systematically
      dec left
      if left == 0:
        addTimer(Moment.now()) do (p: pointer):
          handleMissingBlocks(node)

proc onSecond(node: BeaconNode, moment: Moment) {.async.} =
  node.handleMissingBlocks()

  let nextSecond = max(Moment.now(), moment + chronos.seconds(1))
  addTimer(nextSecond) do (p: pointer):
    asyncCheck node.onSecond(nextSecond)

proc run*(node: BeaconNode) =
  waitFor node.network.subscribe(topicBeaconBlocks) do (signedBlock: SignedBeaconBlock):
    onBeaconBlock(node, signedBlock)

  waitFor node.network.subscribe(topicAttestations) do (attestation: Attestation):
    # Avoid double-counting attestation-topic attestations on shared codepath
    # when they're reflected through beacon blocks
    beacon_attestations_received.inc()

    node.onAttestation(attestation)

  let
    t = node.beaconClock.now().toSlot()
    curSlot = if t.afterGenesis: t.slot
              else: GENESIS_SLOT
    nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
    fromNow = saturate(node.beaconClock.fromNow(nextSlot))

  info "Scheduling first slot action",
    beaconTime = shortLog(node.beaconClock.now()),
    nextSlot = shortLog(nextSlot),
    fromNow = shortLog(fromNow),
    cat = "scheduling"

  addTimer(fromNow) do (p: pointer):
    asyncCheck node.onSlotStart(curSlot, nextSlot)

  let second = Moment.now() + chronos.seconds(1)
  addTimer(second) do (p: pointer):
    asyncCheck node.onSecond(second)

  runForever()

var gPidFile: string
proc createPidFile(filename: string) =
  createDir splitFile(filename).dir
  writeFile filename, $os.getCurrentProcessId()
  gPidFile = filename
  addQuitProc proc {.noconv.} = removeFile gPidFile

proc start(node: BeaconNode) =
  # TODO: while it's nice to cheat by waiting for connections here, we
  #       actually need to make this part of normal application flow -
  #       losing all connections might happen at any time and we should be
  #       prepared to handle it.
  waitFor node.connectToNetwork()

  let
    head = node.blockPool.head
    finalizedHead = node.blockPool.finalizedHead

  info "Starting beacon node",
    version = fullVersionStr,
    timeSinceFinalization =
      int64(finalizedHead.slot.toBeaconTime()) -
      int64(node.beaconClock.now()),
    headSlot = shortLog(head.blck.slot),
    headRoot = shortLog(head.blck.root),
    finalizedSlot = shortLog(finalizedHead.blck.slot),
    finalizedRoot = shortLog(finalizedHead.blck.root),
    SLOTS_PER_EPOCH,
    SECONDS_PER_SLOT,
    SPEC_VERSION,
    dataDir = node.config.dataDir.string,
    cat = "init",
    pcs = "start_beacon_node"

  let
    bs = BlockSlot(blck: head.blck, slot: head.blck.slot)

  node.blockPool.withState(node.blockPool.tmpState, bs):
    node.addLocalValidators(state)

  node.run()

func formatGwei(amount: uint64): string =
  # TODO This is implemented in a quite a silly way.
  # Better routines for formatting decimal numbers
  # should exists somewhere else.
  let
    eth = amount div 1000000000
    remainder = amount mod 1000000000

  result = $eth
  if remainder != 0:
    result.add '.'
    result.add $remainder
    while result[^1] == '0':
      result.setLen(result.len - 1)

when hasPrompt:
  from unicode import Rune
  import terminal, prompt

  proc providePromptCompletions*(line: seq[Rune], cursorPos: int): seq[string] =
    # TODO
    # The completions should be generated with the general-purpose command-line
    # parsing API of Confutils
    result = @[]

  proc processPromptCommands(p: ptr Prompt) {.thread.} =
    while true:
      var cmd = p[].readLine()
      case cmd
      of "quit":
        quit 0
      else:
        p[].writeLine("Unknown command: " & cmd)

  proc slotOrZero(time: BeaconTime): Slot =
    let exSlot = time.toSlot
    if exSlot.afterGenesis: exSlot.slot
    else: Slot(0)

  proc initPrompt(node: BeaconNode) =
    if isatty(stdout) and node.config.statusBarEnabled:
      enableTrueColors()

      # TODO: nim-prompt seems to have threading issues at the moment
      #       which result in sporadic crashes. We should introduce a
      #       lock that guards the access to the internal prompt line
      #       variable.
      #
      # var p = Prompt.init("nimbus > ", providePromptCompletions)
      # p.useHistoryFile()

      proc dataResolver(expr: string): string =
        # TODO:
        # We should introduce a general API for resolving dot expressions
        # such as `db.latest_block.slot` or `metrics.connected_peers`.
        # Such an API can be shared between the RPC back-end, CLI tools
        # such as ncli, a potential GraphQL back-end and so on.
        # The status bar feature would allow the user to specify an
        # arbitrary expression that is resolvable through this API.
        case expr.toLowerAscii
        of "connected_peers":
          $(sync_protocol.libp2p_peers.value.int)

        of "last_finalized_epoch":
          var head = node.blockPool.finalizedHead
          # TODO: Should we display a state root instead?
          $(head.slot.epoch) & " (" & shortLog(head.blck.root) & ")"

        of "epoch":
          $node.beaconClock.now.slotOrZero.epoch

        of "epoch_slot":
          $(node.beaconClock.now.slotOrZero mod SLOTS_PER_EPOCH)

        of "slots_per_epoch":
          $SLOTS_PER_EPOCH

        of "slot":
          $node.beaconClock.now.slotOrZero

        of "slot_trailing_digits":
          var slotStr = $node.beaconClock.now.slotOrZero
          if slotStr.len > 3: slotStr = slotStr[^3..^1]
          slotStr

        of "attached_validators_balance":
          var balance = uint64(0)
          # TODO slow linear scan!
          for idx, b in node.blockPool.headState.data.data.balances:
            if node.getAttachedValidator(
                node.blockPool.headState.data.data, ValidatorIndex(idx)) != nil:
              balance += b
          formatGwei(balance)

        else:
          # We ignore typos for now and just render the expression
          # as it was written. TODO: come up with a good way to show
          # an error message to the user.
          "$" & expr

      var statusBar = StatusBarView.init(
        node.config.statusBarContents,
        dataResolver)

      when compiles(defaultChroniclesStream.output.writer):
        defaultChroniclesStream.output.writer =
          proc (logLevel: LogLevel, msg: LogOutputStr) {.gcsafe.} =
            # p.hidePrompt
            erase statusBar
            # p.writeLine msg
            stdout.write msg
            render statusBar
            # p.showPrompt

      proc statusBarUpdatesPollingLoop() {.async.} =
        while true:
          update statusBar
          await sleepAsync(chronos.seconds(1))

      traceAsyncErrors statusBarUpdatesPollingLoop()

      # var t: Thread[ptr Prompt]
      # createThread(t, processPromptCommands, addr p)

when isMainModule:
  randomize()

  let config = BeaconNodeConf.load(
    version = clientId,
    copyrightBanner = clientId & "\p" & copyrights)

  when compiles(defaultChroniclesStream.output.writer):
    defaultChroniclesStream.output.writer =
      proc (logLevel: LogLevel, msg: LogOutputStr) {.gcsafe.} =
        stdout.write(msg)

  if config.logLevel != LogLevel.NONE:
    setLogLevel(config.logLevel)

  ## Ctrl+C handling
  proc controlCHandler() {.noconv.} =
    when defined(windows):
      # workaround for https://github.com/nim-lang/Nim/issues/4057
      setupForeignThreadGc()
    debug "Shutting down after having received SIGINT"
    quit(QuitFailure)
  setControlCHook(controlCHandler)

  case config.cmd
  of createTestnet:
    var deposits: seq[Deposit]
    for i in config.firstValidator.int ..< config.totalValidators.int:
      let depositFile = config.validatorsDir /
                        validatorFileBaseName(i) & ".deposit.json"
      try:
        deposits.add Json.loadFile(depositFile, Deposit)
      except SerializationError as err:
        stderr.write "Error while loading a deposit file:\n"
        stderr.write err.formatMsg(depositFile), "\n"
        stderr.write "Please regenerate the deposit files by running makeDeposits again\n"
        quit 1

    let
      startTime = uint64(times.toUnix(times.getTime()) + config.genesisOffset)
      outGenesis = config.outputGenesis.string
      eth1Hash = if config.depositWeb3Url.len == 0: eth1BlockHash
                 else: waitFor getLatestEth1BlockHash(config.depositWeb3Url)
    var
      initialState = initialize_beacon_state_from_eth1(
        eth1Hash, startTime, deposits, {skipValidation, skipMerkleValidation})

    # https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#create-genesis-state
    initialState.genesis_time = startTime

    doAssert initialState.validators.len > 0

    let outGenesisExt = splitFile(outGenesis).ext
    if cmpIgnoreCase(outGenesisExt, ".json") == 0:
      Json.saveFile(outGenesis, initialState, pretty = true)
      echo "Wrote ", outGenesis

    let outSszGenesis = outGenesis.changeFileExt "ssz"
    SSZ.saveFile(outSszGenesis, initialState)
    echo "Wrote ", outSszGenesis

    var
      bootstrapAddress = getPersistenBootstrapAddr(
        config, parseIpAddress(config.bootstrapAddress), Port config.bootstrapPort)

    let bootstrapFile = config.outputBootstrapFile.string
    if bootstrapFile.len > 0:
      let bootstrapAddrLine = $bootstrapAddress
      writeFile(bootstrapFile, bootstrapAddrLine)
      echo "Wrote ", bootstrapFile

  of importValidator:
    template reportFailureFor(keyExpr) =
      error "Failed to import validator key", key = keyExpr
      programResult = 1

    if config.keyFiles.len == 0:
      stderr.write "Please specify at least one keyfile to import."
      quit 1

    for keyFile in config.keyFiles:
      try:
        saveValidatorKey(keyFile.string.extractFilename,
                         readFile(keyFile.string), config)
      except:
        reportFailureFor keyFile.string

  of noCommand:
    createPidFile(config.dataDir.string / "beacon_node.pid")

    var node = waitFor BeaconNode.init(config)
    when hasPrompt:
      initPrompt(node)

    when useInsecureFeatures:
      if config.metricsServer:
        let metricsAddress = config.metricsServerAddress
        info "Starting metrics HTTP server",
          address = metricsAddress, port = config.metricsServerPort
        metrics.startHttpServer(metricsAddress, Port(config.metricsServerPort))

    if node.nickname != "":
      dynamicLogScope(node = node.nickname): node.start()
    else:
      node.start()

  of makeDeposits:
    createDir(config.depositsDir)

    let
      quickstartDeposits = generateDeposits(
        config.totalQuickstartDeposits, config.depositsDir, false)

      randomDeposits = generateDeposits(
        config.totalRandomDeposits, config.depositsDir, true,
        firstIdx = config.totalQuickstartDeposits)

    if config.depositWeb3Url.len > 0 and config.depositContractAddress.len > 0:
      info "Sending deposits",
        web3 = config.depositWeb3Url,
        depositContract = config.depositContractAddress

      waitFor sendDeposits(
        quickstartDeposits & randomDeposits,
        config.depositWeb3Url,
        config.depositContractAddress,
        config.depositPrivateKey)

  of query:
    case config.queryCmd
    of QueryCmd.nimQuery:
      # TODO: This will handle a simple subset of Nim using
      #       dot syntax and `[]` indexing.
      echo "nim query: ", config.nimQueryExpression

    of QueryCmd.get:
      let pathFragments = config.getQueryPath.split('/', maxsplit = 1)
      let bytes =
        case pathFragments[0]
        of "genesis_state":
          readFile(config.dataDir/genesisFile).string.toBytes()
        else:
          stderr.write config.getQueryPath & " is not a valid path"
          quit 1

      let navigator = DynamicSszNavigator.init(bytes, BeaconState)

      echo navigator.navigatePath(pathFragments[1 .. ^1]).toJson
