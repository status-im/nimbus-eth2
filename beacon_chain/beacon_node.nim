import
  net, sequtils, options, tables, osproc, random, strutils, times, strformat,
  std_shims/[os_shims, objects],
  chronos, chronicles, confutils, serialization/errors,
  eth/trie/db, eth/trie/backends/rocksdb_backend, eth/async_utils,
  spec/[bitfield, datatypes, digest, crypto, beaconstate, helpers, validator],
  conf, time,
  state_transition, fork_choice, ssz, beacon_chain_db, validator_pool, extras,
  attestation_pool, block_pool, eth2_network, beacon_node_types,
  mainchain_monitor, trusted_state_snapshots, version

const
  topicBeaconBlocks = "ethereum/2.1/beacon_chain/blocks"
  topicAttestations = "ethereum/2.1/beacon_chain/attestations"

  dataDirValidators = "validators"
  networkMetadataFile = "network.json"
  genesisFile = "genesis.json"
  testnetsBaseUrl = "https://serenity-testnets.status.im"

# #################################################
# Careful handling of beacon_node <-> sync_protocol
# to avoid recursive dependencies
proc onBeaconBlock*(node: BeaconNode, blck: BeaconBlock) {.gcsafe.}
  # Forward decl for sync_protocol
import sync_protocol, request_manager
# #################################################

func localValidatorsDir(conf: BeaconNodeConf): string =
  conf.dataDir / "validators"

func databaseDir(conf: BeaconNodeConf): string =
  conf.dataDir / "db"

template `//`(url, fragment: string): string =
  url & "/" & fragment

proc downloadFile(url: string): Future[string] {.async.} =
  let cmd = "curl --fail " & url
  let (fileContents, errorCode) = execCmdEx(cmd, options = {poUsePath})
  if errorCode != 0:
    raise newException(IOError, "Failed external command: '" & cmd & "', exit code: " & $errorCode & ", output: '" & fileContents & "'")
  return fileContents

proc updateTestnetMetadata(conf: BeaconNodeConf): Future[NetworkMetadata] {.async.} =
  let metadataUrl = testnetsBaseUrl // $conf.network //
                    netBackendName & "-" & networkMetadataFile
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

proc persistentNodeId*(conf: BeaconNodeConf): string =
  ($ensureNetworkKeys(conf).pubKey)[0..5]

proc init*(T: type BeaconNode, conf: BeaconNodeConf): Future[BeaconNode] {.async.} =
  new result
  result.config = conf
  result.nickname = if conf.nodename == "auto": persistentNodeId(conf)
                    else: conf.nodename

  template fail(args: varargs[untyped]) =
    stderr.write args, "\n"
    quit 1

  case conf.network
  of "mainnet":
    fail "The Serenity mainnet hasn't been launched yet"
  of "testnet0", "testnet1":
    result.networkMetadata = await updateTestnetMetadata(conf)
  else:
    try:
      result.networkMetadata = Json.loadFile(conf.network, NetworkMetadata)
    except:
      fail "Failed to load network metadata: ", getCurrentExceptionMsg()

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

  result.attachedValidators = ValidatorPool.init
  init result.mainchainMonitor, "", Port(0) # TODO: specify geth address and port

  let trieDB = trieDB newChainDb(string conf.databaseDir)
  result.db = BeaconChainDB.init(trieDB)

  # TODO this is problably not the right place to ensure that db is sane..
  # TODO does it really make sense to load from DB if a state snapshot has been
  #      specified on command line? potentially, this should be the other way
  #      around...

  let headBlock = result.db.getHeadBlock()
  if headBlock.isNone():
    var snapshotFile = conf.dataDir / genesisFile
    if conf.stateSnapshot.isSome:
      snapshotFile = conf.stateSnapshot.get.string
    elif not fileExists(snapshotFile):
      error "Nimbus database not initialized. Please specify the initial state snapshot file."
      quit 1

    try:
      info "Importing snapshot file", path = snapshotFile

      let
        tailState = Json.loadFile(snapshotFile, BeaconState)
        tailBlock = get_initial_beacon_block(tailState)

      BlockPool.preInit(result.db, tailState, tailBlock)

    except SerializationError as err:
      stderr.write "Failed to import ", snapshotFile, "\n"
      stderr.write err.formatMsg(snapshotFile), "\n"
      quit 1
    except:
      stderr.write "Failed to initialize database\n"
      stderr.write getCurrentExceptionMsg(), "\n"
      quit 1

  result.blockPool = BlockPool.init(result.db)
  result.attestationPool = AttestationPool.init(result.blockPool)

  result.network = await createEth2Node(conf)
  result.requestManager.init result.network

  # TODO sync is called when a remote peer is connected - is that the right
  #      time to do so?
  let sync = result.network.protocolState(BeaconSync)
  sync.networkId = result.networkMetadata.networkId
  sync.node = result
  sync.db = result.db

  let head = result.blockPool.get(result.db.getHeadBlock().get())

  result.stateCache = result.blockPool.loadTailState()
  result.justifiedStateCache = result.stateCache

  let addressFile = string(conf.dataDir) / "beacon_node.address"
  result.network.saveConnectionAddressFile(addressFile)
  result.beaconClock = BeaconClock.init(result.stateCache.data)

template withState(
    pool: BlockPool, cache: var StateData, blockSlot: BlockSlot, body: untyped): untyped =
  ## Helper template that updates state to a particular BlockSlot - usage of
  ## cache is unsafe outside of block.
  ## TODO async transformations will lead to a race where cache gets updated
  ##      while waiting for future to complete - catch this here somehow?

  updateStateData(pool, cache, blockSlot)

  template state(): BeaconState {.inject.} = cache.data
  template blck(): BlockRef {.inject.} = cache.blck
  template root(): Eth2Digest {.inject.} = cache.root

  body

proc connectToNetwork(node: BeaconNode) {.async.} =
  let localKeys = ensureNetworkKeys(node.config)
  var bootstrapNodes = newSeq[BootstrapAddr]()

  for bootNode in node.networkMetadata.bootstrapNodes:
    if bootNode.pubkey == localKeys.pubKey:
      node.isBootstrapNode = true
    else:
      bootstrapNodes.add bootNode

  for bootNode in node.config.bootstrapNodes:
    bootstrapNodes.add BootstrapAddr.init(bootNode)

  let bootstrapFile = string node.config.bootstrapNodesFile
  if bootstrapFile.len > 0:
    for ln in lines(bootstrapFile):
      bootstrapNodes.add BootstrapAddr.init(string ln)

  if bootstrapNodes.len > 0:
    info "Connecting to bootstrap nodes", bootstrapNodes
  else:
    info "Waiting for connections"

  await node.network.connectToNetwork(bootstrapNodes)

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

  let idx = state.validator_registry.findIt(it.pubKey == pubKey)
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
  let validatorKey = state.validator_registry[idx].pubkey
  node.attachedValidators.getValidator(validatorKey)

proc updateHead(node: BeaconNode, slot: Slot): BlockRef =
  # Use head state for attestation resolution below
  # TODO do we need to resolve attestations using all available head states?
  node.blockPool.withState(
      node.stateCache, BlockSlot(blck: node.blockPool.head.blck, slot: slot)):
    # Check pending attestations - maybe we found some blocks for them
    node.attestationPool.resolve(state)

    # TODO move all of this logic to BlockPool
    debug "Preparing for fork choice",
      stateRoot = shortLog(root),
      connectedPeers = node.network.connectedPeers,
      stateSlot = humaneSlotNum(state.slot),
      stateEpoch = humaneEpochNum(state.slot.slotToEpoch)

  let
    justifiedHead = node.blockPool.latestJustifiedBlock()

  # TODO slot number is wrong here, it should be the start of the epoch that
  #      got finalized:
  #      https://github.com/ethereum/eth2.0-specs/issues/768
  let newHead = node.blockPool.withState(
      node.justifiedStateCache,
      BlockSlot(blck: justifiedHead, slot: justifiedHead.slot)):

    lmdGhost(node.attestationPool, state, justifiedHead)
  info "Fork chosen",
    newHeadSlot = humaneSlotNum(newHead.slot),
    newHeadEpoch = humaneEpochNum(newHead.slot.slotToEpoch),
    newHeadBlockRoot = shortLog(newHead.root)

  node.blockPool.updateHead(node.stateCache, newHead)
  newHead

proc sendAttestation(node: BeaconNode,
                     validator: AttachedValidator,
                     attestationData: AttestationData,
                     committeeLen: int,
                     indexInCommittee: int) {.async.} =
  let
    validatorSignature = await validator.signAttestation(attestationData)

  var aggregationBitfield = BitField.init(committeeLen)
  set_bitfield_bit(aggregationBitfield, indexInCommittee)

  var attestation = Attestation(
    data: attestationData,
    aggregate_signature: validatorSignature,
    aggregation_bitfield: aggregationBitfield,
    # Stub in phase0
    custody_bitfield: BitField.init(committeeLen)
  )

  node.network.broadcast(topicAttestations, attestation)

  info "Attestation sent",
    attestationData = shortLog(attestationData),
    validator = shortLog(validator),
    signature = shortLog(validatorSignature)

proc proposeBlock(node: BeaconNode,
                  validator: AttachedValidator,
                  head: BlockRef,
                  slot: Slot): Future[BlockRef] {.async.} =
  if head.slot > slot:
    notice "Skipping proposal, we've already selected a newer head",
      headSlot = humaneSlotNum(head.slot),
      headBlockRoot = shortLog(head.root),
      slot = humaneSlotNum(slot)
    return head

  if head.slot == slot:
    # Weird, we should never see as head the same slot as we're proposing a
    # block for - did someone else steal our slot? why didn't we discard it?
    warn "Found head at same slot as we're supposed to propose for!",
      headSlot = humaneSlotNum(head.slot),
      headBlockRoot = shortLog(head.root)
    # TODO investigate how and when this happens.. maybe it shouldn't be an
    #      assert?
    doAssert false, "head slot matches proposal slot (!)"
    # return

  var (nroot, nblck) = node.blockPool.withState(
      node.stateCache, BlockSlot(blck: head, slot: slot - 1)):
    # To create a block, we'll first apply a partial block to the state, skipping
    # some validations.
    let
      blockBody = BeaconBlockBody(
        randao_reveal: validator.genRandaoReveal(state, slot),
        eth1_data: node.mainchainMonitor.getBeaconBlockRef(),
        attestations:
          node.attestationPool.getAttestationsForBlock(state, slot))

    var
      newBlock = BeaconBlock(
        slot: slot,
        previous_block_root: head.root,
        body: blockBody,
        signature: ValidatorSig(), # we need the rest of the block first!
      )

    var tmpState = state

    let ok = updateState(tmpState, newBlock, {skipValidation})
    doAssert ok # TODO: err, could this fail somehow?

    newBlock.state_root = hash_tree_root(tmpState)

    let blockRoot = signed_root(newBlock)

    # Careful, state no longer valid after here..
    newBlock.signature =
      await validator.signBlockProposal(state, slot, blockRoot)

    (blockRoot, newBlock)

  let newBlockRef = node.blockPool.add(node.stateCache, nroot, nblck)
  if newBlockRef == nil:
    warn "Unable to add proposed block to block pool",
      newBlock = shortLog(newBlock),
      blockRoot = shortLog(blockRoot)
    return head

  info "Block proposed",
    blck = shortLog(newBlock),
    blockRoot = shortLog(newBlockRef.root),
    validator = shortLog(validator)

  node.network.broadcast(topicBeaconBlocks, newBlock)

  return newBlockRef

proc onAttestation(node: BeaconNode, attestation: Attestation) =
  # We received an attestation from the network but don't know much about it
  # yet - in particular, we haven't verified that it belongs to particular chain
  # we're on, or that it follows the rules of the protocol
  debug "Attestation received",
    attestationData = shortLog(attestation.data),
    signature = shortLog(attestation.aggregate_signature)

  # TODO seems reasonable to use the latest head state here.. needs thinking
  #      though - maybe we should use the state from the block pointed to by
  #      the attestation for some of the check? Consider interop with block
  #      production!
  node.blockPool.withState(node.stateCache,
      BlockSlot(blck: node.blockPool.head.blck, slot: node.beaconClock.now().toSlot())):
    node.attestationPool.add(state, attestation)

proc onBeaconBlock(node: BeaconNode, blck: BeaconBlock) =
  # We received a block but don't know much about it yet - in particular, we
  # don't know if it's part of the chain we're currently building.
  let blockRoot = signed_root(blck)
  debug "Block received",
    blck = shortLog(blck),
    blockRoot = shortLog(blockRoot)

  if node.blockPool.add(node.stateCache, blockRoot, blck).isNil:
    return

  # The block we received contains attestations, and we might not yet know about
  # all of them. Let's add them to the attestation pool - in case they block
  # is not yet resolved, neither will the attestations be!
  for attestation in blck.body.attestations:
    # TODO attestation pool needs to be taught to deal with overlapping
    #      attestations!
    discard # node.onAttestation(attestation)

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
    notice "Skipping attestation, head is too recent",
      headSlot = humaneSlotNum(head.slot),
      slot = humaneSlotNum(slot)
    return

  let attestationHead = head.findAncestorBySlot(slot)
  if head != attestationHead.blck:
    # In rare cases, such as when we're busy syncing or just slow, we'll be
    # attesting to a past state - we must then recreate the world as it looked
    # like back then
    notice "Attesting to a state in the past, falling behind?",
      headSlot = humaneSlotNum(head.slot),
      attestationHeadSlot = humaneSlotNum(attestationHead.slot),
      attestationSlot = humaneSlotNum(slot)

  debug "Checking attestations",
    attestationHeadRoot = shortLog(attestationHead.blck.root),
    attestationSlot = humaneSlotNum(slot)


  # Collect data to send before node.stateCache grows stale
  var attestations: seq[tuple[
    data: AttestationData, committeeLen, indexInCommittee: int,
    validator: AttachedValidator]]

  # We need to run attestations exactly for the slot that we're attesting to.
  # In case blocks went missing, this means advancing past the latest block
  # using empty slots as fillers.
  node.blockPool.withState(node.stateCache, attestationHead):
    for crosslink_committee in get_crosslink_committees_at_slot(state, slot):
      for i, validatorIdx in crosslink_committee.committee:
        let validator = node.getAttachedValidator(state, validatorIdx)
        if validator != nil:
          attestations.add (
            makeAttestationData(state, crosslink_committee.shard, blck.root),
            crosslink_committee.committee.len, i, validator)

  for a in attestations:
    traceAsyncErrors sendAttestation(
      node, a.validator, a.data, a.committeeLen, a.indexInCommittee)

proc handleProposal(node: BeaconNode, head: BlockRef, slot: Slot):
    Future[BlockRef] {.async.} =
  ## Perform the proposal for the given slot, iff we have a validator attached
  ## that is supposed to do so, given the shuffling in head

  # TODO here we advanced the state to the new slot, but later we'll be
  #      proposing for it - basically, we're selecting proposer based on an
  #      empty slot.. wait for the committee selection to settle, then
  #      revisit this - we should be able to advance behind
  node.blockPool.withState(node.stateCache, BlockSlot(blck: head, slot: slot)):
    let
      proposerIdx = get_beacon_proposer_index(state, slot)
      validator = node.getAttachedValidator(state, proposerIdx)

    if validator != nil:
      return await proposeBlock(node, validator, head, slot)

    debug "Expecting proposal",
      headRoot = shortLog(head.root),
      slot = humaneSlotNum(slot),
      proposer = shortLog(state.validator_registry[proposerIdx].pubKey)

  return head

proc onSlotStart(node: BeaconNode, lastSlot, scheduledSlot: Slot) {.gcsafe, async.} =
  ## Called at the beginning of a slot - usually every slot, but sometimes might
  ## skip a few in case we're running late.
  ## lastSlot: the last slot that we sucessfully processed, so we know where to
  ##           start work from
  ## scheduledSlot: the slot that we were aiming for, in terms of timing

  let
    # The slot we should be at, according to the clock
    slot = node.beaconClock.now().toSlot()
    nextSlot = slot + 1

  debug "Slot start",
    lastSlot = humaneSlotNum(lastSlot),
    scheduledSlot = humaneSlotNum(scheduledSlot),
    slot = humaneSlotNum(slot)

  if slot < lastSlot:
    # This can happen if the system clock changes time for example, and it's
    # pretty bad
    # TODO shut down? time either was or is bad, and PoS relies on accuracy..
    warn "Beacon clock time moved back, rescheduling slot actions",
      slot = humaneSlotNum(slot),
      scheduledSlot = humaneSlotNum(scheduledSlot)

    addTimer(saturate(node.beaconClock.fromNow(nextSlot))) do (p: pointer):
      asyncCheck node.onSlotStart(slot, nextSlot)

    return

  if slot > lastSlot + SLOTS_PER_EPOCH:
    # We've fallen behind more than an epoch - there's nothing clever we can
    # do here really, except skip all the work and try again later.
    # TODO how long should the period be? Using an epoch because that's roughly
    #      how long attestations remain interesting
    # TODO should we shut down instead? clearly we're unable to keep up
    warn "Unable to keep up, skipping ahead without doing work",
      lastSlot = humaneSlotNum(lastSlot),
      slot = humaneSlotNum(slot),
      scheduledSlot = humaneSlotNum(scheduledSlot)

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
      curSlot = humaneSlotNum(curSlot),
      lastSlot = humaneSlotNum(lastSlot),
      slot = humaneSlotNum(slot)

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

    debug "Waiting to send attestations",
      slot = humaneSlotNum(slot),
      fromNow = shortLog(fromNow)

    await sleepAsync(fromNow)

    # Time passed - we might need to select a new head in that case
    head = node.updateHead(slot)

  handleAttestations(node, head, slot)

  # TODO ... and beacon clock might jump here also. sigh.
  let
    nextSlotStart = saturate(node.beaconClock.fromNow(nextSlot))

  info "Scheduling slot actions",
    lastSlot = humaneSlotNum(slot),
    slot = humaneSlotNum(slot),
    nextSlot = humaneSlotNum(nextSlot),
    fromNow = shortLog(nextSlotStart)

  addTimer(nextSlotStart) do (p: pointer):
    asyncCheck node.onSlotStart(slot, nextSlot)

proc onSecond(node: BeaconNode, moment: Moment) {.async.} =
  let missingBlocks = node.blockPool.checkMissing()
  if missingBlocks.len > 0:
    info "Requesting detected missing blocks", missingBlocks
    node.requestManager.fetchAncestorBlocks(missingBlocks) do (b: BeaconBlock):
      node.onBeaconBlock(b)

  let nextSecond = max(Moment.now(), moment + chronos.seconds(1))
  addTimer(nextSecond) do (p: pointer):
    asyncCheck node.onSecond(nextSecond)

proc run*(node: BeaconNode) =
  waitFor node.network.subscribe(topicBeaconBlocks) do (blck: BeaconBlock):
    node.onBeaconBlock(blck)

  waitFor node.network.subscribe(topicAttestations) do (attestation: Attestation):
    node.onAttestation(attestation)

  let
    slot = node.beaconClock.now().toSlot()
    startSlot =
      if slot >= GENESIS_SLOT: slot + 1
      else: GENESIS_SLOT + 1
    fromNow = saturate(node.beaconClock.fromNow(startSlot))

  info "Scheduling first slot action",
    nextSlot = humaneSlotNum(startSlot),
    fromNow = shortLog(fromNow)

  addTimer(fromNow) do (p: pointer):
    asyncCheck node.onSlotStart(startSlot - 1, startSlot)

  let second = Moment.now() + chronos.seconds(1)
  addTimer(second) do (p: pointer):
    asyncCheck node.onSecond(second)

  runForever()

var gPidFile: string
proc createPidFile(filename: string) =
  createDir splitFile(filename).dir
  writeFile filename, $getCurrentProcessId()
  gPidFile = filename
  addQuitProc proc {.noconv.} = removeFile gPidFile

proc start(node: BeaconNode, headState: BeaconState) =
  # TODO: while it's nice to cheat by waiting for connections here, we
  #       actually need to make this part of normal application flow -
  #       losing all connections might happen at any time and we should be
  #       prepared to handle it.
  waitFor node.connectToNetwork()

  info "Starting beacon node",
    slotsSinceFinalization =
      int64(node.blockPool.finalizedHead.slot) -
      int64(node.beaconClock.now()),
    stateSlot = humaneSlotNum(headState.slot),
    SHARD_COUNT,
    SLOTS_PER_EPOCH,
    SECONDS_PER_SLOT,
    SPEC_VERSION

  node.addLocalValidators(headState)
  node.run()

when isMainModule:
  randomize()
  let config = BeaconNodeConf.load(version = fullVersionStr())

  if config.logLevel != LogLevel.NONE:
    setLogLevel(config.logLevel)

  case config.cmd
  of createTestnet:
    var deposits: seq[Deposit]
    for i in config.firstValidator.int ..< config.totalValidators.int:
      let depositFile = config.validatorsDir /
                        validatorFileBaseName(i) & ".deposit.json"
      deposits.add Json.loadFile(depositFile, Deposit)

    let initialState = get_genesis_beacon_state(
      deposits,
      uint64(times.toUnix(times.getTime()) + config.genesisOffset),
      Eth1Data(), {})

    Json.saveFile(config.outputGenesis.string, initialState, pretty = true)
    echo "Wrote ", config.outputGenesis.string

    var
      bootstrapAddress = getPersistenBootstrapAddr(
        config, parseIpAddress(config.bootstrapAddress), Port config.bootstrapPort)

      testnetMetadata = NetworkMetadata(
        networkId: config.networkId,
        networkGeneration: semanticVersion,
        genesisRoot: hash_tree_root(initialState),
        bootstrapNodes: @[bootstrapAddress],
        numShards: SHARD_COUNT,
        slotDuration: SECONDS_PER_SLOT,
        slotsPerEpoch: SLOTS_PER_EPOCH,
        totalValidators: config.totalValidators,
        lastUserValidator: config.lastUserValidator)

    Json.saveFile(config.outputNetwork.string, testnetMetadata, pretty = true)
    echo "Wrote ", config.outputNetwork.string

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
      dynamicLogScope(node = node.nickname): node.start(node.stateCache.data)
    else:
      node.start(node.stateCache.data)
