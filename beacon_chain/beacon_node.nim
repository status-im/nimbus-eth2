import
  std_shims/[os_shims, objects], net, sequtils, options, tables,
  chronos, chronicles, confutils, eth/[p2p, keys],
  spec/[datatypes, digest, crypto, beaconstate, helpers, validator], conf, time,
  state_transition, fork_choice, ssz, beacon_chain_db, validator_pool, extras,
  attestation_pool,
  mainchain_monitor, sync_protocol, gossipsub_protocol, trusted_state_snapshots,
  eth/trie/db, eth/trie/backends/rocksdb_backend

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
    headBlock: BeaconBlock
    headBlockRoot: Eth2Digest
    blocksChildren: Table[Eth2Digest, seq[Eth2Digest]]

const
  version = "v0.1" # TODO: read this from the nimble file
  clientId = "nimbus beacon node " & version

  topicBeaconBlocks = "ethereum/2.1/beacon_chain/blocks"
  topicAttestations = "ethereum/2.1/beacon_chain/attestations"

  stateStoragePeriod = SLOTS_PER_EPOCH.uint64 * 10 # Save states once per this number of slots. TODO: Find a good number.

func shortHash(x: auto): string =
  ($x)[0..7]

func shortValidatorKey(node: BeaconNode, validatorIdx: int): string =
  ($node.beaconState.validator_registry[validatorIdx].pubkey)[0..7]

proc ensureNetworkKeys*(dataDir: string): KeyPair =
  # TODO:
  # 1. Check if keys already exist in the data dir
  # 2. Generate new ones and save them in the directory
  # if necessary
  return newKeyPair()

proc updateHeadBlock(node: BeaconNode, blck: BeaconBlock)

proc init*(T: type BeaconNode, conf: BeaconNodeConf): T =
  new result
  result.config = conf

  result.attachedValidators = ValidatorPool.init
  init result.attestationPool, 42 # TODO compile failure without the dummy int??
  init result.mainchainMonitor, "", Port(0) # TODO: specify geth address and port

  let trieDB = trieDB newChainDb(string conf.dataDir)
  result.db = BeaconChainDB.init(trieDB)

  # TODO does it really make sense to load from DB if a state snapshot has been
  #      specified on command line? potentially, this should be the other way
  #      around...
  if (let head = result.db.getHead(); head.isSome()):
    info "Loading head from database",
      blockSlot = humaneSlotNum(head.get().slot)
    updateHeadBlock(result, head.get())
  else:
    result.beaconState = result.config.stateSnapshot.get()
    result.headBlock = get_initial_beacon_block(result.beaconState)
    result.headBlockRoot = hash_tree_root_final(result.headBlock)

    info "Loaded state from snapshot",
      stateSlot = humaneSlotNum(result.beaconState.slot)
    result.db.putState(result.beaconState)
    # The genesis block is special in that we have to store it at hash 0 - in
    # the genesis state, this block has not been applied..
    result.db.putBlock(result.headBlock)

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
  if node.beaconState.slotDistanceFromNow() > WEAK_SUBJECTVITY_PERIOD.int64:
    node.beaconState = await obtainTrustedStateSnapshot(node.db)
  else:
    var targetSlot = node.beaconState.getSlotFromTime()

    let t = now()
    if t < node.beaconState.genesisTime * 1000:
      await sleepAsync int(node.beaconState.genesisTime * 1000 - t)

    # TODO: change this to a full sync / block download
    info "Syncing state from remote peers",
      finalized_epoch = humaneEpochNum(node.beaconState.finalized_epoch),
      target_slot_epoch = humaneEpochNum(targetSlot.slot_to_epoch)

    # TODO: sync is called at the beginning of the program, but doing this kind
    #       of catching up here is wrong - if we fall behind on processing
    #       for whatever reason, we want to be safe against the damage that
    #       might cause regardless if we just started or have been running for
    #       long. A classic example where this might happen is when the
    #       computer goes to sleep - when waking up, we'll be in the middle of
    #       processing, but behind everyone else.
    # while node.beaconState.finalized_epoch < targetSlot.slot_to_epoch:
    #   var (peer, changeLog) = await node.network.getValidatorChangeLog(
    #     node.beaconState.validator_registry_delta_chain_tip)

    #   if peer == nil:
    #     error "Failed to sync with any peer"
    #     return false

    #   if applyValidatorChangeLog(changeLog, node.beaconState):
    #     node.db.persistState(node.beaconState)
    #     node.db.persistBlock(changeLog.signedBlock)
    #   else:
    #     warn "Ignoring invalid validator change log", sentFrom = peer

  return true

template findIt(s: openarray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

proc addLocalValidators*(node: BeaconNode) =
  for validator in node.config.validators:
    let
      privKey = validator.privKey
      pubKey = privKey.pubKey()

    let idx = node.beaconState.validator_registry.findIt(it.pubKey == pubKey)
    if idx == -1:
      warn "Validator not in registry", pubKey
    else:
      debug "Attaching validator", validator = shortValidatorKey(node, idx),
                                   idx, pubKey
      node.attachedValidators.addLocalValidator(idx, pubKey, privKey)

  info "Local validators attached ", count = node.attachedValidators.count

proc getAttachedValidator(node: BeaconNode, idx: int): AttachedValidator =
  let validatorKey = node.beaconState.validator_registry[idx].pubkey
  return node.attachedValidators.getValidator(validatorKey)

proc makeAttestation(node: BeaconNode,
                     validator: AttachedValidator,
                     slot: Slot,
                     shard: uint64,
                     committeeLen: int,
                     indexInCommittee: int) {.async.} =
  doAssert node != nil
  doAssert validator != nil

  var state = node.beaconState

  if state.slot < slot:
    info "Filling slot gap for attestation",
      slot = humaneSlotNum(slot),
      stateSlot = humaneSlotNum(state.slot)

    for s in state.slot ..< slot:
      let ok = updateState(
        state, node.headBlockRoot, none[BeaconBlock](), {skipValidation})
      doAssert ok

  let
    justifiedBlockRoot =
      get_block_root(state, get_epoch_start_slot(state.justified_epoch))

    attestationData = AttestationData(
      slot: slot,
      shard: shard,
      beacon_block_root: node.headBlockRoot,
      epoch_boundary_root: Eth2Digest(), # TODO
      shard_block_root: Eth2Digest(), # TODO
      latest_crosslink: Crosslink(epoch: state.latest_crosslinks[shard].epoch), # TODO
      justified_epoch: state.justified_epoch,
      justified_block_root: justifiedBlockRoot)

    validatorSignature = await validator.signAttestation(attestationData)

  var participationBitfield = repeat(0'u8, ceil_div8(committeeLen))
  bitSet(participationBitfield, indexInCommittee)

  var attestation = Attestation(
    data: attestationData,
    aggregate_signature: validatorSignature,
    aggregation_bitfield: participationBitfield,
    # Stub in phase0
    custody_bitfield: newSeq[byte](participationBitfield.len)
  )

  await node.network.broadcast(topicAttestations, attestation)

  info "Attestation sent",
    slot = humaneSlotNum(attestationData.slot),
    shard = attestationData.shard,
    validator = shortValidatorKey(node, validator.idx),
    signature = shortHash(validatorSignature),
    beaconBlockRoot = shortHash(attestationData.beacon_block_root)

proc proposeBlock(node: BeaconNode,
                  validator: AttachedValidator,
                  slot: Slot) {.async.} =
  doAssert node != nil
  doAssert validator != nil
  doAssert validator.idx < node.beaconState.validator_registry.len

  var state = node.beaconState

  if state.slot + 1 < slot:
    info "Filling slot gap for block proposal",
      slot = humaneSlotNum(slot),
      stateSlot = humaneSlotNum(state.slot)

    for s in state.slot + 1 ..< slot:
      let ok = updateState(
        state, node.headBlockRoot, none[BeaconBlock](), {skipValidation})
      doAssert ok

  var blockBody = BeaconBlockBody(
    attestations: node.attestationPool.getAttestationsForBlock(state, slot))

  var newBlock = BeaconBlock(
    slot: slot,
    parent_root: node.headBlockRoot,
    randao_reveal: validator.genRandaoReveal(state, state.slot),
    eth1_data: node.mainchainMonitor.getBeaconBlockRef(),
    signature: ValidatorSig(), # we need the rest of the block first!
    body: blockBody)

  let ok =
    updateState(state, node.headBlockRoot, some(newBlock), {skipValidation})
  doAssert ok # TODO: err, could this fail somehow?

  newBlock.state_root = Eth2Digest(data: hash_tree_root(state))

  var signedData = ProposalSignedData(
    slot: slot,
    shard: BEACON_CHAIN_SHARD_NUMBER,
    blockRoot: hash_tree_root_final(newBlock))

  newBlock.signature = await validator.signBlockProposal(state.fork, signedData)

  await node.network.broadcast(topicBeaconBlocks, newBlock)

  info "Block proposed",
    slot = humaneSlotNum(slot),
    stateRoot = shortHash(newBlock.state_root),
    parentRoot = shortHash(newBlock.parent_root),
    validator = shortValidatorKey(node, validator.idx),
    idx = validator.idx

proc scheduleBlockProposal(node: BeaconNode,
                           slot: Slot,
                           validator: AttachedValidator) =
  # TODO:
  # This function exists only to hide a bug with Nim's closures.
  # If you inline it in `scheduleEpochActions`, you'll see the
  # internal `doAssert` starting to fail.
  doAssert validator != nil

  let
    at = node.beaconState.slotStart(slot)
    now = fastEpochTime()

  if now > at:
    warn "Falling behind on block proposals", at, now, slot

  info "Scheduling block proposal",
    validator = shortValidatorKey(node, validator.idx),
    idx = validator.idx,
    slot = humaneSlotNum(slot),
    fromNow = (at - now) div 1000

  addTimer(at) do (x: pointer) {.gcsafe.}:
    # TODO timers are generally not accurate / guaranteed to fire at the right
    #      time - need to guard here against early / late firings
    doAssert validator != nil
    asyncCheck proposeBlock(node, validator, slot)

proc scheduleAttestation(node: BeaconNode,
                         validator: AttachedValidator,
                         slot: Slot,
                         shard: uint64,
                         committeeLen: int,
                         indexInCommittee: int) =
  # TODO:
  # This function exists only to hide a bug with Nim's closures.
  # If you inline it in `scheduleEpochActions`, you'll see the
  # internal `doAssert` starting to fail.
  doAssert validator != nil

  let
    at = node.beaconState.slotStart(slot)
    now = fastEpochTime()

  if now > at:
    warn "Falling behind on attestations", at, now, slot

  debug "Scheduling attestation",
    validator = shortValidatorKey(node, validator.idx),
    fromNow = (at - now) div 1000,
    slot = humaneSlotNum(slot),
    shard

  addTimer(at) do (p: pointer) {.gcsafe.}:
    doAssert validator != nil
    asyncCheck makeAttestation(node, validator, slot,
                               shard, committeeLen, indexInCommittee)

proc scheduleEpochActions(node: BeaconNode, epoch: Epoch) =
  ## This schedules the required block proposals and
  ## attestations from our attached validators.
  doAssert node != nil
  doAssert epoch >= GENESIS_EPOCH,
    "Epoch: " & $epoch & ", humane epoch: " & $humaneSlotNum(epoch)

  debug "Scheduling epoch actions", epoch = humaneEpochNum(epoch)

  # TODO: this copy of the state shouldn't be necessary, but please
  # see the comments in `get_beacon_proposer_index`
  var nextState = node.beaconState

  let start = if epoch == GENESIS_EPOCH: 1.uint64 else: 0.uint64

  for i in start ..< SLOTS_PER_EPOCH:
    let slot = epoch * SLOTS_PER_EPOCH + i
    nextState.slot = slot # ugly trick, see get_beacon_proposer_index

    block: # Schedule block proposals
      let proposerIdx = get_beacon_proposer_index(nextState, slot)
      let validator = node.getAttachedValidator(proposerIdx)

      if validator != nil:
        # TODO:
        # Warm-up the proposer earlier to try to obtain previous
        # missing blocks if necessary
        scheduleBlockProposal(node, slot, validator)

    block: # Schedule attestations
      for crosslink_committee in get_crosslink_committees_at_slot(
          nextState, slot):
        for i, validatorIdx in crosslink_committee.committee:
          let validator = node.getAttachedValidator(validatorIdx)
          if validator != nil:
            scheduleAttestation(
              node, validator, slot, crosslink_committee.shard,
              crosslink_committee.committee.len, i)

  let
    nextEpoch = epoch + 1
    at = node.beaconState.slotStart(nextEpoch.get_epoch_start_slot())

  info "Scheduling next epoch update",
    fromNow = (at - fastEpochTime()) div 1000,
    epoch = humaneEpochNum(nextEpoch)

  addTimer(at) do (p: pointer):
    node.scheduleEpochActions(nextEpoch)

proc stateNeedsSaving(s: BeaconState): bool =
  # TODO: Come up with a better predicate logic
  s.slot mod stateStoragePeriod == 0

proc onAttestation(node: BeaconNode, attestation: Attestation) =
  let participants = get_attestation_participants(
    node.beaconState, attestation.data, attestation.aggregation_bitfield).
      mapIt(shortValidatorKey(node, it))

  info "Attestation received",
    slot = humaneSlotNum(attestation.data.slot),
    shard = attestation.data.shard,
    signature = shortHash(attestation.aggregate_signature),
    participants,
    beaconBlockRoot = shortHash(attestation.data.beacon_block_root)

  node.attestationPool.add(attestation, node.beaconState)

  if not node.db.containsBlock(attestation.data.beacon_block_root):
    notice "Attestation block root missing",
      beaconBlockRoot = shortHash(attestation.data.beacon_block_root)
    # TODO download...

proc skipSlots(state: var BeaconState, parentRoot: Eth2Digest, nextSlot: Slot) =
  if state.slot + 1 < nextSlot:
    info "Advancing state past slot gap",
      targetSlot = humaneSlotNum(nextSlot),
      stateSlot = humaneSlotNum(state.slot)

    for slot in state.slot + 1 ..< nextSlot:
      let ok = updateState(state, parentRoot, none[BeaconBlock](), {})
      doAssert ok, "Empty block state update should never fail!"

proc skipAndUpdateState(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  skipSlots(state, blck.parent_root, blck.slot)
  updateState(state, blck.parent_root, some(blck), flags)

proc updateHeadBlock(node: BeaconNode, blck: BeaconBlock) =
  # To update the head block, we need to apply it to the state. When things
  # progress normally, the block we recieve will be a direct child of the
  # last block we applied to the state:

  if blck.parent_root == node.headBlockRoot:
    let ok = skipAndUpdateState(node.beaconState, blck, {})
    doAssert ok, "Nobody is ever going to send a faulty block!"

    node.headBlock = blck
    node.headBlockRoot = hash_tree_root_final(blck)
    node.db.putHead(node.headBlockRoot)

    info "Updated head",
      stateRoot = shortHash(blck.state_root),
      headBlockRoot = shortHash(node.headBlockRoot),
      stateSlot = humaneSlotNum(node.beaconState.slot)

    return

  # It appears that the parent root of the proposed new block is different from
  # what we expected. We will have to rewind the state to a point along the
  # chain of ancestors of the new block. We will do this by loading each
  # successive parent block and checking if we can find the corresponding state
  # in the database.
  let
    ancestors = node.db.getAncestors(blck) do (bb: BeaconBlock) -> bool:
      node.db.containsState(bb.state_root)
    ancestor = ancestors[^1]

  # Several things can happen, but the most common one should be that we found
  # a beacon state
  if (let state = node.db.getState(ancestor.state_root); state.isSome()):
    # Got it!
    notice "Replaying state transitions",
      stateSlot = humaneSlotNum(node.beaconState.slot),
      prevStateSlot = humaneSlotNum(state.get().slot)
    node.beaconState = state.get()

  elif ancestor.slot == 0:
    # We've arrived at the genesis block and still haven't found what we're
    # looking for. This is very bad - are we receiving blocks from a different
    # chain? What's going on?
    # TODO crashing like this is the wrong thing to do, obviously, but
    #      we'll do it anyway just to see if it ever happens - if it does,
    #      it's likely a bug :)
    error "Couldn't find ancestor state",
      blockSlot = humaneSlotNum(blck.slot),
      blockRoot = shortHash(hash_tree_root_final(blck))
    doAssert false, "Oh noes, we passed big bang!"
  else:
    # We don't have the parent block. This is a bit strange, but may happen
    # if things are happening seriously out of order or if we're back after
    # a net split or restart, for example. Once the missing block arrives,
    # we should retry setting the head block..
    # TODO implement block sync here
    # TODO instead of doing block sync here, make sure we are sync already
    #      elsewhere, so as to simplify the logic of finding the block
    #      here..
    error "Parent missing! Too bad, because sync is also missing :/",
      parentRoot = shortHash(ancestor.parent_root),
      blockSlot = humaneSlotNum(ancestor.slot)
    doAssert false, "So long"

  # If we come this far, we found the state root. The last block on the stack
  # is the one that produced this particular state, so we can pop it
  # TODO it might be possible to use the latest block hashes from the state to
  #      do this more efficiently.. whatever!

  # Time to replay all the blocks between then and now. We skip the one because
  # it's the one that we found the state with, and it has already been
  # applied
  for i in countdown(ancestors.len - 2, 0):
    let last = ancestors[i]

    skipSlots(node.beaconState, last.parent_root, last.slot)

    # TODO technically, we should be storing states here, because we're now
    #      going down a different fork
    let ok = updateState(
      node.beaconState, last.parent_root, some(last),
      if ancestors.len == 0: {} else: {skipValidation})

    doAssert(ok)

  node.headBlock = blck
  node.headBlockRoot = hash_tree_root_final(blck)
  node.db.putHead(node.headBlockRoot)

  info "Updated head",
    stateRoot = shortHash(blck.state_root),
    headBlockRoot = shortHash(node.headBlockRoot),
    stateSlot = humaneSlotNum(node.beaconState.slot)

proc onBeaconBlock(node: BeaconNode, blck: BeaconBlock) =
  let
    blockRoot = hash_tree_root_final(blck)
    stateSlot = node.beaconState.slot

  if node.db.containsBlock(blockRoot):
    debug "Block already seen",
      slot = humaneSlotNum(blck.slot),
      stateRoot = shortHash(blck.state_root),
      blockRoot = shortHash(blockRoot),
      stateSlot = humaneSlotNum(stateSlot)

    return

  info "Block received",
    slot = humaneSlotNum(blck.slot),
    stateRoot = shortHash(blck.state_root),
    parentRoot = shortHash(blck.parent_root),
    blockRoot = shortHash(blockRoot)

  # TODO we should now validate the block to ensure that it's sane - but the
  #      only way to do that is to apply it to the state... for now, we assume
  #      all blocks are good!

  # The block has been validated and it's not in the database yet - first, let's
  # store it there, just to be safe
  node.db.putBlock(blck)

  # Since this is a good block, we should add its attestations in case we missed
  # any. If everything checks out, this should lead to the fork choice selecting
  # this particular block as head, eventually (technically, if we have other
  # attestations, that might not be the case!)
  for attestation in blck.body.attestations:
    # TODO attestation pool needs to be taught to deal with overlapping
    #      attestations!
    discard # node.onAttestation(attestation)

  if blck.slot <= node.beaconState.slot:
    # This is some old block that we received (perhaps as the result of a sync)
    # request. At this point, there's not much we can do, except maybe try to
    # update the state to the head block (this could have failed before due to
    # missing blocks!)..
    # TODO figure out what to do - for example, how to resume setting
    #      the head block...
    return

  # TODO We have a block that is newer than our latest state. What now??
  #      Here, we choose to update our state eagerly, assuming that the block
  #      is the one that the fork choice would have ended up with anyway, but
  #      is this a sane strategy? Technically, we could wait for more
  #      attestations and update the state lazily only when actually needed,
  #      such as when attesting.
  # TODO Also, should we update to the block we just got, or run the fork
  #      choice at this point??

  updateHeadBlock(node, blck)

  if stateNeedsSaving(node.beaconState):
    node.db.putState(node.beaconState)

proc run*(node: BeaconNode) =
  node.network.subscribe(topicBeaconBlocks) do (blck: BeaconBlock):
    node.onBeaconBlock(blck)

  node.network.subscribe(topicAttestations) do (attestation: Attestation):
    node.onAttestation(attestation)

  let epoch = node.beaconState.getSlotFromTime div SLOTS_PER_EPOCH
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
    createStateSnapshot(
      config.chainStartupData, config.genesisOffset,
      config.outputStateFile.string)
    quit 0

  of noCommand:
    waitFor synchronizeClock()
    createPidFile(config.dataDir.string / "beacon_node.pid")

    var node = BeaconNode.init config

    dynamicLogScope(node = node.config.tcpPort - 50000):
      # TODO: while it's nice to cheat by waiting for connections here, we
      #       actually need to make this part of normal application flow -
      #       losing all connections might happen at any time and we should be
      #       prepared to handle it.
      waitFor node.connectToNetwork()

      if not waitFor node.sync():
        quit 1

      info "Starting beacon node",
        slotsSinceFinalization = node.beaconState.slotDistanceFromNow(),
        stateSlot = humaneSlotNum(node.beaconState.slot),
        SHARD_COUNT,
        SLOTS_PER_EPOCH,
        SECONDS_PER_SLOT,
        SPEC_VERSION

      node.addLocalValidators()
      node.run()
