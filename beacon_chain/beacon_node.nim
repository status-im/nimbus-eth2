import
  net, sequtils, tables, osproc, random, strutils, times, strformat,
  stew/shims/os, stew/[objects, bitseqs],
  chronos, chronicles, confutils, metrics,
  json_serialization/std/[options, sets], serialization/errors,
  eth/trie/db, eth/trie/backends/rocksdb_backend, eth/async_utils,
  spec/[datatypes, digest, crypto, beaconstate, helpers, validator,
  state_transition_block, network],
  conf, time, state_transition, fork_choice, ssz, beacon_chain_db,
  validator_pool, extras, attestation_pool, block_pool, eth2_network,
  beacon_node_types, mainchain_monitor, trusted_state_snapshots, version,
  sync_protocol, request_manager, validator_keygen, interop

const
  dataDirValidators = "validators"
  networkMetadataFile = "network.json"
  genesisFile = "genesis.json"
  testnetsBaseUrl = "https://serenity-testnets.status.im"

declareGauge beacon_slot, "Latest slot of the beacon chain state"
declareGauge beacon_head_slot, "Slot of the head block of the beacon chain"
declareGauge beacon_head_root, "Root of the head block of the beacon chain"

declareGauge beacon_current_validators, """Number of status="pending|active|exited|withdrawable" validators in current epoch""" # On epoch transition
declareGauge beacon_previous_validators, """Number of status="pending|active|exited|withdrawable" validators in previous epoch""" # On epoch transition
declareGauge beacon_current_live_validators, "Number of active validators that successfully included attestation on chain for current epoch" # On block
declareGauge beacon_previous_live_validators, "Number of active validators that successfully included attestation on chain for previous epoch" # On block
declareGauge beacon_pending_deposits, "Number of pending deposits (state.eth1_data.deposit_count - state.eth1_deposit_index)" # On block
declareGauge beacon_processed_deposits_total, "Number of total deposits included on chain" # On block
declareGauge beacon_pending_exits, "Number of pending voluntary exits in local operation pool" # On slot
declareGauge beacon_previous_epoch_orphaned_blocks, "Number of blocks orphaned in the previous epoch" # On epoch transition
declareCounter beacon_reorgs_total, "Total occurrences of reorganizations of the chain" # On fork choice

logScope: topics = "beacnde"

proc onBeaconBlock*(node: BeaconNode, blck: BeaconBlock) {.gcsafe.}

func localValidatorsDir(conf: BeaconNodeConf): string =
  conf.dataDir / "validators"

func databaseDir(conf: BeaconNodeConf): string =
  conf.dataDir / "db"

template `//`(url, fragment: string): string =
  url & "/" & fragment

proc downloadFile(url: string): Future[string] {.async.} =
  # TODO We need a proper HTTP client able to perform HTTPS downloads
  let tempFile = getTempDir() / "nimbus.download"
  let cmd = "curl --fail -o " & quoteShell(tempFile) & " " & url
  let (fileContents, errorCode) = execCmdEx(cmd, options = {poUsePath})
  if errorCode != 0:
    raise newException(IOError, "Failed external command: '" & cmd & "', exit code: " & $errorCode & ", output: '" & fileContents & "'")
  return readFile(tempFile)

proc updateTestnetMetadata(conf: BeaconNodeConf): Future[NetworkMetadata] {.async.} =
  let metadataUrl = testnetsBaseUrl // $conf.network // networkMetadataFile
  let latestMetadata = await downloadFile(metadataUrl)

  try:
    result = Json.decode(latestMetadata, NetworkMetadata)
  except SerializationError as err:
    stderr.write "Error while loading the testnet metadata. Your client my be out of date.\n"
    stderr.write err.formatMsg(metadataUrl), "\n"
    stderr.write "Please follow the instructions at https://github.com/status-im/nim-beacon-chain " &
                 "in order to produce an up-to-date build.\n"
    quit 1

  let localMetadataFile = conf.dataDir / networkMetadataFile
  if fileExists(localMetadataFile) and readFile(localMetadataFile).string == latestMetadata:
    return

  info "New testnet genesis data received. Starting with a fresh database."

  createDir conf.dataDir.string
  removeDir conf.databaseDir
  writeFile localMetadataFile, latestMetadata

  let newGenesis = await downloadFile(testnetsBaseUrl // $conf.network // genesisFile)
  writeFile conf.dataDir / genesisFile, newGenesis

proc obtainTestnetKey(conf: BeaconNodeConf): Future[(string, string)] {.async.} =
  let
    metadata = await updateTestnetMetadata(conf)
    privKeyName = validatorFileBaseName(rand(metadata.userValidatorsRange)) & ".privkey"
    privKeyUrl = testnetsBaseUrl // $conf.network // privKeyName
    privKeyContent = strip await downloadFile(privKeyUrl)

  let key = ValidatorPrivKey.init(privKeyContent)
  return (privKeyName, privKeyContent)

proc saveValidatorKey(keyName, key: string, conf: BeaconNodeConf) =
  let validatorsDir = conf.dataDir / dataDirValidators
  let outputFile = validatorsDir / keyName
  createDir validatorsDir
  writeFile(outputFile, key)
  info "Imported validator key", file = outputFile

proc initGenesis(node: BeaconNode) {.async.} =
  template conf: untyped = node.config
  var tailState: BeaconState
  if conf.depositWeb3Url.len != 0:
    info "Waiting for genesis state from eth1"
    tailState = await node.mainchainMonitor.getGenesis()
  else:
    var snapshotFile = conf.dataDir / genesisFile
    try:
      if conf.stateSnapshot.isSome:
        snapshotFile = conf.stateSnapshot.get.string

      if not fileExists(snapshotFile):
        error "Nimbus database not initialized. Please specify the initial state snapshot file."
        quit 1

      template loadSnapshot(Format) =
        info "Importing snapshot file", path = snapshotFile
        tailState = loadFile(Format, snapshotFile, BeaconState)

      let ext = splitFile(snapshotFile).ext
      if cmpIgnoreCase(ext, ".ssz") == 0:
        loadSnapshot SSZ
      elif cmpIgnoreCase(ext, ".json") == 0:
        loadSnapshot Json
      else:
        error "The --stateSnapshot option expects a json or a ssz file."
        quit 1

    except SerializationError as err:
      stderr.write "Failed to import ", snapshotFile, "\n"
      stderr.write err.formatMsg(snapshotFile), "\n"
      quit 1

  info "Got genesis state", hash = hash_tree_root(tailState)
  node.forkVersion = tailState.fork.current_version

  try:
    let tailBlock = get_initial_beacon_block(tailState)
    BlockPool.preInit(node.db, tailState, tailBlock)

  except:
    stderr.write "Failed to initialize database\n"
    stderr.write getCurrentExceptionMsg(), "\n"
    quit 1

proc init*(T: type BeaconNode, conf: BeaconNodeConf): Future[BeaconNode] {.async.} =
  new result
  result.onBeaconBlock = onBeaconBlock
  result.config = conf
  result.networkIdentity = getPersistentNetIdentity(conf)
  result.nickname = if conf.nodename == "auto": shortForm(result.networkIdentity)
                    else: conf.nodename

  template fail(args: varargs[untyped]) =
    stderr.write args, "\n"
    quit 1

  if not conf.quickStart:
    case conf.network
    of "mainnet":
      fail "The Serenity mainnet hasn't been launched yet"
    of "testnet0", "testnet1":
      result.networkMetadata = await updateTestnetMetadata(conf)
    else:
      try:
        result.networkMetadata = Json.loadFile(conf.network, NetworkMetadata)
      except SerializationError as err:
        fail "Failed to load network metadata: \n", err.formatMsg(conf.network)

    var metadataErrorMsg = ""

    template checkCompatibility(metadataField, LOCAL_CONSTANT) =
      let metadataValue = metadataField
      if metadataValue != LOCAL_CONSTANT:
        if metadataErrorMsg.len > 0: metadataErrorMsg.add " and"
        metadataErrorMsg.add " -d:" & astToStr(LOCAL_CONSTANT) & "=" & $metadataValue &
                            " (instead of " & $LOCAL_CONSTANT & ")"

    if result.networkMetadata.networkGeneration != semanticVersion:
      let newerVersionRequired = result.networkMetadata.networkGeneration.int > semanticVersion
      let newerOrOlder = if newerVersionRequired: "a newer" else: "an older"
      stderr.write &"Connecting to '{conf.network}' requires {newerOrOlder} version of Nimbus. "
      if newerVersionRequired:
        stderr.write "Please follow the instructions at https://github.com/status-im/nim-beacon-chain " &
                    "in order to produce an up-to-date build.\n"
      quit 1

    checkCompatibility result.networkMetadata.numShards      , SHARD_COUNT
    checkCompatibility result.networkMetadata.slotDuration   , SECONDS_PER_SLOT
    checkCompatibility result.networkMetadata.slotsPerEpoch  , SLOTS_PER_EPOCH

    if metadataErrorMsg.len > 0:
      fail "To connect to the ", conf.network, " network, please compile with", metadataErrorMsg

    for bootNode in result.networkMetadata.bootstrapNodes:
      if bootNode.isSameNode(result.networkIdentity):
        result.isBootstrapNode = true
      else:
        result.bootstrapNodes.add bootNode

  for bootNode in conf.bootstrapNodes:
    result.bootstrapNodes.add BootstrapAddr.init(bootNode)

  let bootstrapFile = string conf.bootstrapNodesFile
  if bootstrapFile.len > 0:
    for ln in lines(bootstrapFile):
      result.bootstrapNodes.add BootstrapAddr.init(string ln)

  result.attachedValidators = ValidatorPool.init
  if conf.depositWeb3Url.len != 0:
    result.mainchainMonitor = MainchainMonitor.init(conf.depositWeb3Url, conf.depositContractAddress)
    result.mainchainMonitor.start()

  let trieDB = trieDB newChainDb(string conf.databaseDir)
  result.db = BeaconChainDB.init(trieDB)

  # TODO this is problably not the right place to ensure that db is sane..
  # TODO does it really make sense to load from DB if a state snapshot has been
  #      specified on command line? potentially, this should be the other way
  #      around...

  if result.db.getHeadBlock().isNone():
    await result.initGenesis()

  result.blockPool = BlockPool.init(result.db)
  result.attestationPool = AttestationPool.init(result.blockPool)

  result.network = await createEth2Node(conf, result.bootstrapNodes)
  result.requestManager.init result.network

  # TODO sync is called when a remote peer is connected - is that the right
  #      time to do so?
  let sync = result.network.protocolState(BeaconSync)
  sync.node = result
  sync.db = result.db

  result.stateCache = result.blockPool.loadTailState()
  result.justifiedStateCache = result.stateCache

  let addressFile = string(conf.dataDir) / "beacon_node.address"
  result.network.saveConnectionAddressFile(addressFile)
  result.beaconClock = BeaconClock.init(result.stateCache.data.data)

  when useInsecureFeatures:
    if conf.metricsServer:
      let metricsAddress = conf.metricsServerAddress
      info "Starting metrics HTTP server", address = metricsAddress, port = conf.metricsServerPort
      metrics.startHttpServer(metricsAddress, Port(conf.metricsServerPort))

template withState(
    pool: BlockPool, cache: var StateData, blockSlot: BlockSlot, body: untyped): untyped =
  ## Helper template that updates state to a particular BlockSlot - usage of
  ## cache is unsafe outside of block.
  ## TODO async transformations will lead to a race where cache gets updated
  ##      while waiting for future to complete - catch this here somehow?

  updateStateData(pool, cache, blockSlot)

  template hashedState(): HashedBeaconState {.inject.} = cache.data
  template state(): BeaconState {.inject.} = cache.data.data
  template blck(): BlockRef {.inject.} = cache.blck
  template root(): Eth2Digest {.inject.} = cache.data.root

  body

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
    warn "Validator not in registry", pubKey
  else:
    node.attachedValidators.addLocalValidator(pubKey, privKey)

proc addLocalValidators(node: BeaconNode, state: BeaconState) =
  for validatorKeyFile in node.config.validators:
    node.addLocalValidator state, validatorKeyFile.load

  for kind, file in walkDir(node.config.localValidatorsDir):
    if kind in {pcFile, pcLinkToFile}:
      node.addLocalValidator state, ValidatorPrivKey.init(readFile(file).string)

  info "Local validators attached ", count = node.attachedValidators.count

proc getAttachedValidator(
    node: BeaconNode, state: BeaconState, idx: int): AttachedValidator =
  let validatorKey = state.validators[idx].pubkey
  node.attachedValidators.getValidator(validatorKey)

proc updateHead(node: BeaconNode, slot: Slot): BlockRef =
  # Use head state for attestation resolution below

  # Check pending attestations - maybe we found some blocks for them
  node.attestationPool.resolve(node.stateCache)

  # TODO move all of this logic to BlockPool

  let
    justifiedHead = node.blockPool.latestJustifiedBlock()

  let newHead = node.blockPool.withState(
      node.justifiedStateCache, justifiedHead):
    lmdGhost(node.attestationPool, state, justifiedHead.blck)

  node.blockPool.updateHead(node.stateCache, newHead)
  beacon_head_slot.set slot.int64
  beacon_head_root.set newHead.root.toGaugeValue

  newHead

proc sendAttestation(node: BeaconNode,
                     state: BeaconState,
                     validator: AttachedValidator,
                     attestationData: AttestationData,
                     committeeLen: int,
                     indexInCommittee: int) {.async.} =
  logScope: pcs = "send_attestation"

  let
    validatorSignature = await validator.signAttestation(attestationData, state)

  var aggregationBits = CommitteeValidatorsBits.init(committeeLen)
  aggregationBits.raiseBit indexInCommittee

  var attestation = Attestation(
    data: attestationData,
    signature: validatorSignature,
    aggregation_bits: aggregationBits,
    # Stub in phase0
    custody_bits: CommitteeValidatorsBits.init(committeeLen)
  )

  node.network.broadcast(topicAttestations, attestation)

  info "Attestation sent",
    attestationData = shortLog(attestationData),
    validator = shortLog(validator),
    signature = shortLog(validatorSignature),
    indexInCommittee = indexInCommittee,
    cat = "consensus"

proc proposeBlock(node: BeaconNode,
                  validator: AttachedValidator,
                  head: BlockRef,
                  slot: Slot): Future[BlockRef] {.async.} =
  logScope: pcs = "block_proposal"

  if head.slot > slot:
    notice "Skipping proposal, we've already selected a newer head",
      headSlot = shortLog(head.slot),
      headBlockRoot = shortLog(head.root),
      slot = shortLog(slot),
      cat = "fastforward"
    return head

  if head.slot == slot:
    # Weird, we should never see as head the same slot as we're proposing a
    # block for - did someone else steal our slot? why didn't we discard it?
    warn "Found head at same slot as we're supposed to propose for!",
      headSlot = shortLog(head.slot),
      headBlockRoot = shortLog(head.root),
      cat = "consensus_conflict"
    # TODO investigate how and when this happens.. maybe it shouldn't be an
    #      assert?
    doAssert false, "head slot matches proposal slot (!)"
    # return


  var (nroot, nblck) = node.blockPool.withState(
      node.stateCache, BlockSlot(blck: head, slot: slot - 1)):
    # To create a block, we'll first apply a partial block to the state, skipping
    # some validations.
    # TODO monitor main chain here: node.mainchainMonitor.getBeaconBlockRef()
    let (eth1data, deposits) =
      if node.mainchainMonitor.isNil:
        (get_eth1data_stub(
            state.eth1_deposit_index, slot.compute_epoch_of_slot()),
          newSeq[Deposit]()
        )
      else:
        let e1d = await node.mainchainMonitor.getBeaconBlockRef()

        (e1d,
          node.mainchainMonitor.getPendingDeposits()
        )

    let
      blockBody = BeaconBlockBody(
        randao_reveal: validator.genRandaoReveal(state, slot),
        eth1_data: eth1data,
        attestations:
          node.attestationPool.getAttestationsForBlock(state, slot),
        deposits: deposits)

    var
      newBlock = BeaconBlock(
        slot: slot,
        parent_root: head.root,
        body: blockBody,
        signature: ValidatorSig(), # we need the rest of the block first!
      )

    var
      tmpState = hashedState
      cache = get_empty_per_epoch_cache()

    let ok = state_transition(tmpState, newBlock, {skipValidation})
    # TODO only enable in fast-fail debugging situations
    # otherwise, bad attestations can bring down network
    # doAssert ok # TODO: err, could this fail somehow?

    newBlock.state_root = tmpState.root

    let blockRoot = signing_root(newBlock)

    # Careful, state no longer valid after here..
    newBlock.signature =
      await validator.signBlockProposal(state, slot, blockRoot)

    (blockRoot, newBlock)

  let newBlockRef = node.blockPool.add(node.stateCache, nroot, nblck)
  if newBlockRef == nil:
    warn "Unable to add proposed block to block pool",
      newBlock = shortLog(newBlock),
      blockRoot = shortLog(blockRoot),
      cat = "bug"
    return head

  info "Block proposed",
    blck = shortLog(newBlock),
    blockRoot = shortLog(newBlockRef.root),
    validator = shortLog(validator),
    cat = "consensus"

  node.network.broadcast(topicBeaconBlocks, newBlock)

  return newBlockRef

proc onAttestation(node: BeaconNode, attestation: Attestation) =
  # We received an attestation from the network but don't know much about it
  # yet - in particular, we haven't verified that it belongs to particular chain
  # we're on, or that it follows the rules of the protocol
  logScope: pcs = "on_attestation"

  debug "Attestation received",
    attestationData = shortLog(attestation.data),
    signature = shortLog(attestation.signature),
    cat = "consensus" # Tag "consensus|attestation"?

  if (let attestedBlock = node.blockPool.getOrResolve(
        attestation.data.beacon_block_root); attestedBlock != nil):
    let
      wallSlot = node.beaconClock.now().toSlot()
      head = node.blockPool.head

    if not wallSlot.afterGenesis or wallSlot.slot < head.blck.slot:
      warn "Received attestation before genesis or head - clock is wrong?",
        afterGenesis = wallSlot.afterGenesis,
        wallSlot = shortLog(wallSlot.slot),
        headSlot = shortLog(head.blck.slot),
        cat = "clock_drift" # Tag "attestation|clock_drift"?
      return

    # TODO seems reasonable to use the latest head state here.. needs thinking
    #      though - maybe we should use the state from the block pointed to by
    #      the attestation for some of the check? Consider interop with block
    #      production!
    let
      bs = BlockSlot(blck: head.blck, slot: wallSlot.slot)

    node.blockPool.withState(node.stateCache, bs):
      node.attestationPool.add(state, attestedBlock, attestation)
  else:
    node.attestationPool.addUnresolved(attestation)

proc onBeaconBlock(node: BeaconNode, blck: BeaconBlock) =
  # We received a block but don't know much about it yet - in particular, we
  # don't know if it's part of the chain we're currently building.
  let blockRoot = signing_root(blck)
  debug "Block received",
    blck = shortLog(blck),
    blockRoot = shortLog(blockRoot),
    cat = "block_listener",
    pcs = "receive_block"

  if node.blockPool.add(node.stateCache, blockRoot, blck).isNil:
    return

  # The block we received contains attestations, and we might not yet know about
  # all of them. Let's add them to the attestation pool - in case they block
  # is not yet resolved, neither will the attestations be!
  # TODO shouldn't add attestations if the block turns out to be invalid..
  for attestation in blck.body.attestations:
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
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/validator/0_beacon-chain-validator.md#validator-assignments
  # TODO we could cache the validator assignment since it's valid for the entire
  #      epoch since it doesn't change, but that has to be weighed against
  #      the complexity of handling forks correctly - instead, we use an adapted
  #      version here that calculates the committee for a single slot only
  node.blockPool.withState(node.stateCache, attestationHead):
    var cache = get_empty_per_epoch_cache()
    let
      epoch = compute_epoch_of_slot(slot)
      committees_per_slot = get_committee_count(state, epoch) div SLOTS_PER_EPOCH
      start_slot = compute_start_slot_of_epoch(epoch)
      offset = committees_per_slot * (slot mod SLOTS_PER_EPOCH)
      slot_start_shard = (get_start_shard(state, epoch) + offset) mod SHARD_COUNT

    for i in 0'u64..<committees_per_slot:
      let
        shard = Shard((slot_start_shard + i) mod SHARD_COUNT)
        committee = get_crosslink_committee(state, epoch, shard, cache)

      for i, validatorIdx in committee:
        let validator = node.getAttachedValidator(state, validatorIdx)
        if validator != nil:
          let ad = makeAttestationData(state, shard, blck.root)
          attestations.add((ad, committee.len, i, validator))

    for a in attestations:
      traceAsyncErrors sendAttestation(
        node, state, a.validator, a.data, a.committeeLen, a.indexInCommittee)

proc handleProposal(node: BeaconNode, head: BlockRef, slot: Slot):
    Future[BlockRef] {.async.} =
  ## Perform the proposal for the given slot, iff we have a validator attached
  ## that is supposed to do so, given the shuffling in head

  # TODO here we advanced the state to the new slot, but later we'll be
  #      proposing for it - basically, we're selecting proposer based on an
  #      empty slot.. wait for the committee selection to settle, then
  #      revisit this - we should be able to advance behind
  var cache = get_empty_per_epoch_cache()
  node.blockPool.withState(node.stateCache, BlockSlot(blck: head, slot: slot)):
    let
      proposerIdx = get_beacon_proposer_index(state, cache)
      validator = node.getAttachedValidator(state, proposerIdx)

    if validator != nil:
      return await proposeBlock(node, validator, head, slot)

    trace "Expecting block proposal",
      headRoot = shortLog(head.root),
      slot = shortLog(slot),
      proposer = shortLog(state.validators[proposerIdx].pubKey),
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

  debug "Slot start",
    lastSlot = shortLog(lastSlot),
    scheduledSlot = shortLog(scheduledSlot),
    beaconTime = shortLog(beaconTime),
    peers = node.network.peersCount,
    cat = "scheduling"

  if not wallSlot.afterGenesis or (wallSlot.slot < lastSlot):
    # This can happen if the system clock changes time for example, and it's
    # pretty bad
    # TODO shut down? time either was or is bad, and PoS relies on accuracy..
    warn "Beacon clock time moved back, rescheduling slot actions",
      beaconTime = shortLog(beaconTime),
      lastSlot = shortLog(lastSlot),
      scheduledSlot = shortLog(scheduledSlot),
      cat = "clock_drift" # tag "scheduling|clock_drift"?

    let
      slot = Slot(
        if wallSlot.afterGenesis:
          max(1'u64, wallSlot.slot.uint64)
        else: GENESIS_SLOT.uint64 + 1)
      nextSlot = slot + 1

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
    warn "Unable to keep up, skipping ahead without doing work",
      lastSlot = shortLog(lastSlot),
      slot = shortLog(slot),
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

  var head = node.updateHead(slot)

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
  #      Right now, we keep going

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
  let
    attestationStart = node.beaconClock.fromNow(slot)
    halfSlot = seconds(int64(SECONDS_PER_SLOT div 2))

  if attestationStart.inFuture or attestationStart.offset <= halfSlot:
    let fromNow =
      if attestationStart.inFuture: attestationStart.offset + halfSlot
      else: halfSlot - attestationStart.offset

    trace "Waiting to send attestations",
      slot = shortLog(slot),
      fromNow = shortLog(fromNow),
      cat = "scheduling"

    await sleepAsync(fromNow)

    # Time passed - we might need to select a new head in that case
    head = node.updateHead(slot)

  handleAttestations(node, head, slot)

  # TODO ... and beacon clock might jump here also. sigh.
  let
    nextSlotStart = saturate(node.beaconClock.fromNow(nextSlot))

  addTimer(nextSlotStart) do (p: pointer):
    asyncCheck node.onSlotStart(slot, nextSlot)

proc onSecond(node: BeaconNode, moment: Moment) {.async.} =
  let missingBlocks = node.blockPool.checkMissing()
  if missingBlocks.len > 0:
    info "Requesting detected missing blocks", missingBlocks
    node.requestManager.fetchAncestorBlocks(missingBlocks) do (b: BeaconBlock):
      onBeaconBlock(node ,b)

  let nextSecond = max(Moment.now(), moment + chronos.seconds(1))
  addTimer(nextSecond) do (p: pointer):
    asyncCheck node.onSecond(nextSecond)

proc run*(node: BeaconNode) =
  waitFor node.network.subscribe(topicBeaconBlocks) do (blck: BeaconBlock):
    onBeaconBlock(node, blck)

  waitFor node.network.subscribe(topicAttestations) do (attestation: Attestation):
    node.onAttestation(attestation)

  let
    t = node.beaconClock.now()
    startSlot = if t > BeaconTime(0): t.toSlot.slot + 1
                else: GENESIS_SLOT + 1
    fromNow = saturate(node.beaconClock.fromNow(startSlot))

  info "Scheduling first slot action",
    beaconTime = shortLog(node.beaconClock.now()),
    nextSlot = shortLog(startSlot),
    fromNow = shortLog(fromNow),
    cat = "scheduling"

  addTimer(fromNow) do (p: pointer):
    asyncCheck node.onSlotStart(startSlot - 1, startSlot)

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

proc start(node: BeaconNode, headState: BeaconState) =
  # TODO: while it's nice to cheat by waiting for connections here, we
  #       actually need to make this part of normal application flow -
  #       losing all connections might happen at any time and we should be
  #       prepared to handle it.
  waitFor node.connectToNetwork()

  info "Starting beacon node",
    timeSinceFinalization =
      int64(node.blockPool.finalizedHead.slot.toBeaconTime()) -
      int64(node.beaconClock.now()),
    stateSlot = shortLog(headState.slot),
    SHARD_COUNT,
    SLOTS_PER_EPOCH,
    SECONDS_PER_SLOT,
    SPEC_VERSION,
    cat = "init",
    pcs = "start_beacon_node"

  node.addLocalValidators(headState)
  node.run()

when isMainModule:
  randomize()
  let config = BeaconNodeConf.load(version = fullVersionStr())

  if config.logLevel != LogLevel.NONE:
    setLogLevel(config.logLevel)

  ## Ctrl+C handling
  proc controlCHandler() {.noconv.} =
    when defined(windows):
      # workaround for https://github.com/nim-lang/Nim/issues/4057
      setupForeignThreadGc()
    debug "Shutting down after having received SIGINT"
    quit(1)
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


    var
      startTime = uint64(times.toUnix(times.getTime()) + config.genesisOffset)
      initialState = initialize_beacon_state_from_eth1(
        eth1BlockHash, startTime, deposits, {skipValidation})

    # https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#create-genesis-state
    initialState.genesis_time = startTime

    doAssert initialState.validators.len > 0

    Json.saveFile(config.outputGenesis.string, initialState, pretty = true)
    echo "Wrote ", config.outputGenesis.string

    let sszGenesis = config.outputGenesis.string.changeFileExt "ssz"
    SSZ.saveFile(sszGenesis, initialState)
    echo "Wrote ", sszGenesis

    var
      bootstrapAddress = getPersistenBootstrapAddr(
        config, parseIpAddress(config.bootstrapAddress), Port config.bootstrapPort)

      testnetMetadata = NetworkMetadata(
        networkGeneration: semanticVersion,
        genesisRoot:
          if config.withGenesisRoot:
            some(hash_tree_root(initialState))
          else: none(Eth2Digest),
        bootstrapNodes: @[bootstrapAddress],
        numShards: SHARD_COUNT,
        slotDuration: SECONDS_PER_SLOT,
        slotsPerEpoch: SLOTS_PER_EPOCH,
        totalValidators: config.totalValidators,
        lastUserValidator: config.lastUserValidator)

    Json.saveFile(config.outputNetworkMetadata.string, testnetMetadata, pretty = true)
    echo "Wrote ", config.outputNetworkMetadata.string

    let bootstrapFile = config.outputBootstrapNodes.string
    if bootstrapFile.len > 0:
      let bootstrapAddrLine = when networkBackend == libp2pBackend:
        $bootstrapAddress.addresses[0] & "/p2p/" & bootstrapAddress.peer.pretty
      else:
        $bootstrapAddress
      writeFile(bootstrapFile, bootstrapAddrLine)
      echo "Wrote ", bootstrapFile

  of updateTestnet:
    discard waitFor updateTestnetMetadata(config)

  of importValidator:
    template reportFailureFor(keyExpr) =
      error "Failed to import validator key", key = keyExpr
      programResult = 1

    for keyFile in config.keyFiles:
      try:
        saveValidatorKey(keyFile.string.extractFilename,
                         readFile(keyFile.string), config)
      except:
        reportFailureFor keyFile.string

    if config.keyFiles.len == 0:
      if config.network in ["testnet0", "testnet1"]:
        try:
          let (keyName, key) = waitFor obtainTestnetKey(config)
          saveValidatorKey(keyName, key, config)
        except:
          stderr.write "Failed to download key\n", getCurrentExceptionMsg()
          quit 1
      else:
        echo "Validator keys can be downloaded only for testnets"
        quit 1

  of noCommand:
    createPidFile(config.dataDir.string / "beacon_node.pid")

    var node = waitFor BeaconNode.init(config)

    # TODO slightly ugly to rely on node.stateCache state here..
    if node.nickname != "":
      dynamicLogScope(node = node.nickname): node.start(node.stateCache.data.data)
    else:
      node.start(node.stateCache.data.data)

  of makeDeposits:
    let deposits = generateDeposits(
      config.totalDeposits, config.depositsDir, config.randomKeys)

    if config.depositWeb3Url.len() > 0 and config.depositContractAddress.len() > 0:
      waitFor sendDeposits(
        deposits, config.depositWeb3Url, config.depositContractAddress)
