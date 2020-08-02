# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[algorithm, os, tables, strutils, sequtils, times, math, terminal],

  # Nimble packages
  stew/[objects, byteutils, endians2], stew/shims/macros,
  chronos, confutils, metrics, json_rpc/[rpcserver, jsonmarshal],
  chronicles, bearssl,
  json_serialization/std/[options, sets, net], serialization/errors,

  eth/[keys, async_utils],
  eth/common/eth_types_json_serialization,
  eth/db/[kvstore, kvstore_sqlite3],
  eth/p2p/enode, eth/p2p/discoveryv5/[protocol, enr],

  # Local modules
  spec/[datatypes, digest, crypto, beaconstate, helpers, network, presets],
  spec/state_transition,
  conf, time, beacon_chain_db, validator_pool, extras,
  attestation_pool, eth2_network, eth2_discovery,
  beacon_node_common, beacon_node_types,
  block_pools/[spec_cache, chain_dag, quarantine, clearance, block_pools_types],
  nimbus_binary_common, network_metadata,
  mainchain_monitor, version, ssz/[merkleization], sszdump, merkle_minimal,
  sync_protocol, request_manager, keystore_management, interop, statusbar,
  sync_manager, validator_duties, validator_api, attestation_aggregation

const
  genesisFile* = "genesis.ssz"
  hasPrompt = not defined(withoutPrompt)

type
  RpcServer* = RpcHttpServer

  # "state" is already taken by BeaconState
  BeaconNodeStatus* = enum
    Starting, Running, Stopping

# this needs to be global, so it can be set in the Ctrl+C signal handler
var status = BeaconNodeStatus.Starting

template init(T: type RpcHttpServer, ip: ValidIpAddress, port: Port): T =
  newRpcHttpServer([initTAddress(ip, port)])

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#interop-metrics
declareGauge beacon_slot,
  "Latest slot of the beacon chain state"
declareGauge beacon_head_slot,
  "Slot of the head block of the beacon chain"

# Metrics for tracking attestation and beacon block loss
declareCounter beacon_attestations_received,
  "Number of beacon chain attestations received by this peer"
declareCounter beacon_blocks_received,
  "Number of beacon chain blocks received by this peer"

# Finalization tracking
declareGauge finalization_delay,
  "Epoch delay between scheduled epoch and finalized epoch"

const delayBuckets = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, Inf]

declareHistogram beacon_attestation_received_seconds_from_slot_start,
  "Interval between slot start and attestation receival", buckets = delayBuckets

declareHistogram beacon_block_received_seconds_from_slot_start,
  "Interval between slot start and beacon block receival", buckets = delayBuckets

logScope: topics = "beacnde"

proc onBeaconBlock(node: BeaconNode, signedBlock: SignedBeaconBlock) {.gcsafe.}

proc getStateFromSnapshot(conf: BeaconNodeConf, stateSnapshotContents: ref string): NilableBeaconStateRef =
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
  elif fileExists(genesisPath):
    try: snapshotContents = readFile(genesisPath)
    except CatchableError as err:
      error "Failed to read genesis file", err = err.msg
      quit 1
  elif stateSnapshotContents != nil:
    swap(snapshotContents, TaintedString stateSnapshotContents[])
  else:
    # No snapshot was provided. We should wait for genesis.
    return nil

  result = try:
    newClone(SSZ.decode(snapshotContents, BeaconState))
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

func enrForkIdFromState(state: BeaconState): ENRForkID =
  let
    forkVer = state.fork.current_version
    forkDigest = compute_fork_digest(forkVer, state.genesis_validators_root)

  ENRForkID(
    fork_digest: forkDigest,
    next_fork_version: forkVer,
    next_fork_epoch: FAR_FUTURE_EPOCH)

proc init*(T: type BeaconNode,
           rng: ref BrHmacDrbgContext,
           conf: BeaconNodeConf,
           stateSnapshotContents: ref string): Future[BeaconNode] {.async.} =
  let
    netKeys = getPersistentNetKeys(rng[], conf)
    nickname = if conf.nodeName == "auto": shortForm(netKeys)
               else: conf.nodeName
    db = BeaconChainDB.init(kvStore SqStoreRef.init(conf.databaseDir, "nbc").tryGet())

  var mainchainMonitor: MainchainMonitor

  if not ChainDAGRef.isInitialized(db):
    # Fresh start - need to load a genesis state from somewhere
    var genesisState = conf.getStateFromSnapshot(stateSnapshotContents)

    # Try file from command line first
    if genesisState.isNil:
      if conf.web3Url.len == 0:
        fatal "Web3 URL not specified"
        quit 1

      if conf.depositContractAddress.isNone:
        fatal "Deposit contract address not specified"
        quit 1

      if conf.depositContractDeployedAt.isNone:
        # When we don't have a known genesis state, the network metadata
        # must specify the deployment block of the contract.
        fatal "Deposit contract deployment block not specified"
        quit 1

      let web3 = web3Provider(conf.web3Url)
      let deployedAtAsHash =
        if conf.depositContractDeployedAt.get.startsWith "0x":
          try: BlockHash.fromHex conf.depositContractDeployedAt.get
          except ValueError:
            fatal "Invalid hex value specified for deposit-contract-block"
            quit 1
        else:
          let blockNum = try: parseBiggestUInt conf.depositContractDeployedAt.get
                         except ValueError:
                           fatal "Invalid nummeric value for deposit-contract-block"
                           quit 1
          await getEth1BlockHash(conf.web3Url, blockId blockNum)

      # TODO Could move this to a separate "GenesisMonitor" process or task
      #      that would do only this - see Paul's proposal for this.
      mainchainMonitor = MainchainMonitor.init(
        conf.runtimePreset,
        web3,
        conf.depositContractAddress.get,
        Eth1Data(block_hash: deployedAtAsHash.asEth2Digest, deposit_count: 0))

      mainchainMonitor.start()

      genesisState = await mainchainMonitor.waitGenesis()

      info "Eth2 genesis state detected",
        genesisTime = genesisState.genesisTime,
        eth1Block = genesisState.eth1_data.block_hash,
        totalDeposits = genesisState.eth1_data.deposit_count

    # This is needed to prove the not nil property from here on
    if genesisState == nil:
      doAssert false
    else:
      if genesisState.slot != GENESIS_SLOT:
        # TODO how to get a block from a non-genesis state?
        error "Starting from non-genesis state not supported",
          stateSlot = genesisState.slot,
          stateRoot = hash_tree_root(genesisState[])
        quit 1

      let tailBlock = get_initial_beacon_block(genesisState[])

      try:
        ChainDAGRef.preInit(db, genesisState[], tailBlock)
        doAssert ChainDAGRef.isInitialized(db), "preInit should have initialized db"
      except CatchableError as e:
        error "Failed to initialize database", err = e.msg
        quit 1

  if stateSnapshotContents != nil:
    # The memory for the initial snapshot won't be needed anymore
    stateSnapshotContents[] = ""

  # TODO check that genesis given on command line (if any) matches database
  let
    chainDagFlags = if conf.verifyFinalization: {verifyFinalization}
                     else: {}
    chainDag = init(ChainDAGRef, conf.runtimePreset, db, chainDagFlags)
    quarantine = QuarantineRef()

  if mainchainMonitor.isNil and
     conf.web3Url.len > 0 and
     conf.depositContractAddress.isSome:
    mainchainMonitor = MainchainMonitor.init(
      conf.runtimePreset,
      web3Provider(conf.web3Url),
      conf.depositContractAddress.get,
      chainDag.headState.data.data.eth1_data)
    # TODO if we don't have any validators attached, we don't need a mainchain
    #      monitor
    mainchainMonitor.start()

  let rpcServer = if conf.rpcEnabled:
    RpcServer.init(conf.rpcAddress, conf.rpcPort)
  else:
    nil

  let
    enrForkId = enrForkIdFromState(chainDag.headState.data.data)
    topicBeaconBlocks = getBeaconBlocksTopic(enrForkId.forkDigest)
    topicAggregateAndProofs = getAggregateAndProofsTopic(enrForkId.forkDigest)
    network = createEth2Node(rng, conf, enrForkId)

  var res = BeaconNode(
    nickname: nickname,
    graffitiBytes: if conf.graffiti.isSome: conf.graffiti.get.GraffitiBytes
                   else: defaultGraffitiBytes(),
    network: network,
    netKeys: netKeys,
    db: db,
    config: conf,
    attachedValidators: ValidatorPool.init(),
    chainDag: chainDag,
    quarantine: quarantine,
    attestationPool: AttestationPool.init(chainDag, quarantine),
    mainchainMonitor: mainchainMonitor,
    beaconClock: BeaconClock.init(chainDag.headState.data.data),
    rpcServer: rpcServer,
    forkDigest: enrForkId.forkDigest,
    topicBeaconBlocks: topicBeaconBlocks,
    topicAggregateAndProofs: topicAggregateAndProofs,
  )

  res.requestManager = RequestManager.init(network,
    proc(signedBlock: SignedBeaconBlock) =
      onBeaconBlock(res, signedBlock)
  )

  res.addLocalValidators()

  # This merely configures the BeaconSync
  # The traffic will be started when we join the network.
  network.initBeaconSync(chainDag, enrForkId.forkDigest)
  return res

proc onAttestation(node: BeaconNode, attestation: Attestation) =
  # We received an attestation from the network but don't know much about it
  # yet - in particular, we haven't verified that it belongs to particular chain
  # we're on, or that it follows the rules of the protocol
  logScope:
    attestation = shortLog(attestation)
    head = shortLog(node.chainDag.head)
    pcs = "on_attestation"

  let
    wallSlot = node.beaconClock.now().toSlot()
    head = node.chainDag.head

  debug "Attestation received",
    wallSlot = shortLog(wallSlot.slot)

  if not wallSlot.afterGenesis or wallSlot.slot < head.slot:
    warn "Received attestation before genesis or head - clock is wrong?",
      afterGenesis = wallSlot.afterGenesis,
      wallSlot = shortLog(wallSlot.slot)
    return

  if attestation.data.slot > head.slot and
      (attestation.data.slot - head.slot) > MaxEmptySlotCount:
    warn "Ignoring attestation, head block too old (out of sync?)"
    return

  node.attestationPool.addAttestation(attestation, wallSlot.slot)

proc dumpBlock[T](
    node: BeaconNode, signedBlock: SignedBeaconBlock,
    res: Result[T, BlockError]) =
  if node.config.dumpEnabled and res.isErr:
    case res.error
    of Invalid:
      dump(
        node.config.dumpDirInvalid, signedBlock)
    of MissingParent:
      dump(
        node.config.dumpDirIncoming, signedBlock)
    else:
      discard

proc storeBlock(
    node: BeaconNode, signedBlock: SignedBeaconBlock): Result[void, BlockError] =
  debug "Block received",
    signedBlock = shortLog(signedBlock.message),
    blockRoot = shortLog(signedBlock.root),
    pcs = "receive_block"

  beacon_blocks_received.inc()

  {.gcsafe.}: # TODO: fork choice and quarantine should sync via messages instead of callbacks
    let blck = node.chainDag.addRawBlock(node.quarantine, signedBlock) do (
        blckRef: BlockRef, signedBlock: SignedBeaconBlock,
        state: HashedBeaconState):
      # Callback add to fork choice if valid
      let epochRef = getEpochInfo(blckRef, state.data)
      node.attestationPool.addForkChoice(
        epochRef, blckRef, signedBlock.message,
        node.beaconClock.now().slotOrZero())

  node.dumpBlock(signedBlock, blck)

  # There can be a scenario where we receive a block we already received.
  # However this block was before the last finalized epoch and so its parent
  # was pruned from the ForkChoice.
  if blck.isErr:
    return err(blck.error)

  ok()

proc onBeaconBlock(node: BeaconNode, signedBlock: SignedBeaconBlock) =
  # We received a block but don't know much about it yet - in particular, we
  # don't know if it's part of the chain we're currently building.
  discard node.storeBlock(signedBlock)

func verifyFinalization(node: BeaconNode, slot: Slot) =
  # Epoch must be >= 4 to check finalization
  const SETTLING_TIME_OFFSET = 1'u64
  let epoch = slot.compute_epoch_at_slot()

  # Don't static-assert this -- if this isn't called, don't require it
  doAssert SLOTS_PER_EPOCH > SETTLING_TIME_OFFSET

  # Intentionally, loudly assert. Point is to fail visibly and unignorably
  # during testing.
  if epoch >= 4 and slot mod SLOTS_PER_EPOCH > SETTLING_TIME_OFFSET:
    let finalizedEpoch =
      node.chainDag.finalizedHead.slot.compute_epoch_at_slot()
    # Finalization rule 234, that has the most lag slots among the cases, sets
    # state.finalized_checkpoint = old_previous_justified_checkpoint.epoch + 3
    # and then state.slot gets incremented, to increase the maximum offset, if
    # finalization occurs every slot, to 4 slots vs scheduledSlot.
    doAssert finalizedEpoch + 4 >= epoch

proc onSlotStart(node: BeaconNode, lastSlot, scheduledSlot: Slot) {.gcsafe, async.} =
  ## Called at the beginning of a slot - usually every slot, but sometimes might
  ## skip a few in case we're running late.
  ## lastSlot: the last slot that we successfully processed, so we know where to
  ##           start work from
  ## scheduledSlot: the slot that we were aiming for, in terms of timing

  logScope: pcs = "slot_start"

  let
    # The slot we should be at, according to the clock
    beaconTime = node.beaconClock.now()
    wallSlot = beaconTime.toSlot()
    finalizedEpoch =
      node.chainDag.finalizedHead.blck.slot.compute_epoch_at_slot()

  info "Slot start",
    lastSlot = shortLog(lastSlot),
    scheduledSlot = shortLog(scheduledSlot),
    beaconTime = shortLog(beaconTime),
    peers = node.network.peersCount,
    head = shortLog(node.chainDag.head),
    headEpoch = shortLog(node.chainDag.head.slot.compute_epoch_at_slot()),
    finalized = shortLog(node.chainDag.finalizedHead.blck),
    finalizedEpoch = shortLog(finalizedEpoch)

  # Check before any re-scheduling of onSlotStart()
  # Offset backwards slightly to allow this epoch's finalization check to occur
  if scheduledSlot > 3 and node.config.stopAtEpoch > 0'u64 and
      (scheduledSlot - 3).compute_epoch_at_slot() >= node.config.stopAtEpoch:
    info "Stopping at pre-chosen epoch",
      chosenEpoch = node.config.stopAtEpoch,
      epoch = scheduledSlot.compute_epoch_at_slot(),
      slot = scheduledSlot

    # Brute-force, but ensure it's reliable enough to run in CI.
    quit(0)

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
      nextSlot = shortLog(nextSlot)

    addTimer(saturate(node.beaconClock.fromNow(nextSlot))) do (p: pointer):
      asyncCheck node.onSlotStart(slot, nextSlot)

    return

  let
    slot = wallSlot.slot # afterGenesis == true!
    nextSlot = slot + 1

  beacon_slot.set slot.int64
  finalization_delay.set scheduledSlot.epoch.int64 - finalizedEpoch.int64

  if node.config.verifyFinalization:
    verifyFinalization(node, scheduledSlot)

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
      scheduledSlot = shortLog(scheduledSlot)

    addTimer(saturate(node.beaconClock.fromNow(nextSlot))) do (p: pointer):
      # We pass the current slot here to indicate that work should be skipped!
      asyncCheck node.onSlotStart(slot, nextSlot)
    return

  # Whatever we do during the slot, we need to know the head, because this will
  # give us a state to work with and thus a shuffling.
  # TODO typically, what consitutes correct actions stays constant between slot
  #      updates and is stable across some epoch transitions as well - see how
  #      we can avoid recalculating everything here
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
  discard node.updateHead(slot)

  # TODO is the slot of the clock or the head block more interesting? provide
  #      rationale in comment
  beacon_head_slot.set slot.int64

  # Time passes in here..
  asyncCheck node.handleValidatorDuties(lastSlot, slot)

  let
    nextSlotStart = saturate(node.beaconClock.fromNow(nextSlot))

  info "Slot end",
    slot = shortLog(slot),
    nextSlot = shortLog(nextSlot),
    head = shortLog(node.chainDag.head),
    headEpoch = shortLog(node.chainDag.head.slot.compute_epoch_at_slot()),
    finalizedHead = shortLog(node.chainDag.finalizedHead.blck),
    finalizedEpoch = shortLog(node.chainDag.finalizedHead.blck.slot.compute_epoch_at_slot())

  when declared(GC_fullCollect):
    # The slots in the beacon node work as frames in a game: we want to make
    # sure that we're ready for the next one and don't get stuck in lengthy
    # garbage collection tasks when time is of essence in the middle of a slot -
    # while this does not guarantee that we'll never collect during a slot, it
    # makes sure that all the scratch space we used during slot tasks (logging,
    # temporary buffers etc) gets recycled for the next slot that is likely to
    # need similar amounts of memory.
    GC_fullCollect()

  addTimer(nextSlotStart) do (p: pointer):
    asyncCheck node.onSlotStart(slot, nextSlot)

proc handleMissingBlocks(node: BeaconNode) =
  let missingBlocks = node.quarantine.checkMissing()
  if missingBlocks.len > 0:
    info "Requesting detected missing blocks", blocks = shortLog(missingBlocks)
    node.requestManager.fetchAncestorBlocks(missingBlocks)

proc onSecond(node: BeaconNode) {.async.} =
  ## This procedure will be called once per second.
  if not(node.syncManager.inProgress):
    node.handleMissingBlocks()

proc runOnSecondLoop(node: BeaconNode) {.async.} =
  var sleepTime = chronos.seconds(1)
  while true:
    await chronos.sleepAsync(sleepTime)
    let start = chronos.now(chronos.Moment)
    await node.onSecond()
    let finish = chronos.now(chronos.Moment)
    debug "onSecond task completed", elapsed = $(finish - start)
    if finish - start > chronos.seconds(1):
      sleepTime = chronos.seconds(0)
    else:
      sleepTime = chronos.seconds(1) - (finish - start)

proc runForwardSyncLoop(node: BeaconNode) {.async.} =
  func getLocalHeadSlot(): Slot =
    result = node.chainDag.head.slot

  proc getLocalWallSlot(): Slot {.gcsafe.} =
    let epoch = node.beaconClock.now().slotOrZero.compute_epoch_at_slot() +
                1'u64
    result = epoch.compute_start_slot_at_epoch()

  func getFirstSlotAtFinalizedEpoch(): Slot {.gcsafe.} =
    let fepoch = node.chainDag.headState.data.data.finalized_checkpoint.epoch
    compute_start_slot_at_epoch(fepoch)

  proc updateLocalBlocks(list: openArray[SignedBeaconBlock]): Result[void, BlockError] =
    debug "Forward sync imported blocks", count = len(list),
          local_head_slot = getLocalHeadSlot()
    let sm = now(chronos.Moment)
    for blk in list:
      let res = node.storeBlock(blk)
      # We going to ignore `BlockError.Unviable` errors because we have working
      # backward sync and it can happens that we can perform overlapping
      # requests.
      # For the same reason we ignore Duplicate blocks as if they are duplicate
      # from before the current finalized epoch, we can drop them
      # (and they may have no parents anymore in the fork choice if it was pruned)
      if res.isErr and res.error notin {BlockError.Unviable, BlockError.Old, BLockError.Duplicate}:
        return res
    discard node.updateHead(node.beaconClock.now().slotOrZero)

    let dur = now(chronos.Moment) - sm
    let secs = float(chronos.seconds(1).nanoseconds)
    var storeSpeed = 0.0
    if not(dur.isZero()):
      let v = float(len(list)) * (secs / float(dur.nanoseconds))
      # We doing round manually because stdlib.round is deprecated
      storeSpeed = round(v * 10000) / 10000

    info "Forward sync blocks got imported successfully", count = len(list),
         local_head_slot = getLocalHeadSlot(), store_speed = storeSpeed
    ok()

  proc scoreCheck(peer: Peer): bool =
    if peer.score < PeerScoreLowLimit:
      try:
        debug "Peer score is too low, removing it from PeerPool", peer = peer,
              peer_score = peer.score, score_low_limit = PeerScoreLowLimit,
              score_high_limit = PeerScoreHighLimit
      except:
        discard
      result = false
    else:
      result = true

  node.network.peerPool.setScoreCheck(scoreCheck)

  node.syncManager = newSyncManager[Peer, PeerID](
    node.network.peerPool, getLocalHeadSlot, getLocalWallSlot,
    getFirstSlotAtFinalizedEpoch, updateLocalBlocks,
    # 4 blocks per chunk is the optimal value right now, because our current
    # syncing speed is around 4 blocks per second. So there no need to request
    # more then 4 blocks right now. As soon as `store_speed` value become
    # significantly more then 4 blocks per second you can increase this
    # value appropriately.
    chunkSize = 4
  )

  await node.syncManager.sync()

proc currentSlot(node: BeaconNode): Slot =
  node.beaconClock.now.slotOrZero

proc connectedPeersCount(node: BeaconNode): int =
  nbc_peers.value.int

proc installBeaconApiHandlers(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.rpc("getBeaconHead") do () -> Slot:
    return node.chainDag.head.slot

  rpcServer.rpc("getChainHead") do () -> JsonNode:
    let
      head = node.chainDag.head
      finalized = node.chainDag.headState.data.data.finalized_checkpoint
      justified = node.chainDag.headState.data.data.current_justified_checkpoint
    return %* {
      "head_slot": head.slot,
      "head_block_root": head.root.data.toHex(),
      "finalized_slot": finalized.epoch * SLOTS_PER_EPOCH,
      "finalized_block_root": finalized.root.data.toHex(),
      "justified_slot": justified.epoch * SLOTS_PER_EPOCH,
      "justified_block_root": justified.root.data.toHex(),
    }

  rpcServer.rpc("getSyncing") do () -> bool:
    let
      wallSlot = currentSlot(node)
      headSlot = node.chainDag.head.slot
    # FIXME: temporary hack: If more than 1 block away from expected head, then we are "syncing"
    return (headSlot + 1) < wallSlot

  template requireOneOf(x, y: distinct Option) =
    if x.isNone xor y.isNone:
      raise newException(CatchableError,
       "Please specify one of " & astToStr(x) & " or " & astToStr(y))

  template jsonResult(x: auto): auto =
    StringOfJson(Json.encode(x))

  rpcServer.rpc("getBeaconBlock") do (slot: Option[Slot],
                                      root: Option[Eth2Digest]) -> StringOfJson:
    requireOneOf(slot, root)
    var blockHash: Eth2Digest
    if root.isSome:
      blockHash = root.get
    else:
      let foundRef = node.chainDag.getBlockByPreciseSlot(slot.get)
      if foundRef != nil:
        blockHash = foundRef.root
      else:
        return StringOfJson("null")

    let dbBlock = node.db.getBlock(blockHash)
    if dbBlock.isSome:
      return jsonResult(dbBlock.get)
    else:
      return StringOfJson("null")

  rpcServer.rpc("getBeaconState") do (slot: Option[Slot],
                                      root: Option[Eth2Digest]) -> StringOfJson:
    requireOneOf(slot, root)
    if slot.isSome:
      # TODO sanity check slot so that it doesn't cause excessive rewinding
      let blk = node.chainDag.head.atSlot(slot.get)
      node.chainDag.withState(node.chainDag.tmpState, blk):
        return jsonResult(state)
    else:
      let tmp = BeaconStateRef() # TODO use tmpState - but load the entire StateData!
      let state = node.db.getState(root.get, tmp[], noRollback)
      if state:
        return jsonResult(tmp[])
      else:
        return StringOfJson("null")

  rpcServer.rpc("getNetworkPeerId") do () -> string:
    return $publicKey(node.network)

  rpcServer.rpc("getNetworkPeers") do () -> seq[string]:
    for peerId, peer in node.network.peerPool:
      result.add $peerId

  rpcServer.rpc("getNetworkEnr") do () -> string:
    return $node.network.discovery.localNode.record

proc installDebugApiHandlers(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.rpc("getNodeVersion") do () -> string:
    return "Nimbus/" & fullVersionStr

  rpcServer.rpc("getSpecPreset") do () -> JsonNode:
    var res = newJObject()
    genStmtList:
      for presetValue in PresetValue:
        if presetValue notin ignoredValues + runtimeValues:
          let
            settingSym = ident($presetValue)
            settingKey = newLit(toLowerAscii($presetValue))
          let f = quote do:
            res[`settingKey`] = %(presets.`settingSym`)
          yield f

    for field, value in fieldPairs(node.config.runtimePreset):
      res[field] = when value isnot Version: %value
                   else: %value.toUInt64

    return res

  rpcServer.rpc("peers") do () -> JsonNode:
    var res = newJObject()
    var peers = newJArray()
    for id, peer in node.network.peerPool:
      peers.add(
        %(
          info: shortLog(peer.info),
          wasDialed: peer.wasDialed,
          connectionState: $peer.connectionState,
          score: peer.score,
        )
      )
    res.add("peers", peers)

    return res

proc installRpcHandlers(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.installValidatorApiHandlers(node)
  rpcServer.installBeaconApiHandlers(node)
  rpcServer.installDebugApiHandlers(node)

proc installAttestationHandlers(node: BeaconNode) =
  proc attestationHandler(attestation: Attestation) =
    # Avoid double-counting attestation-topic attestations on shared codepath
    # when they're reflected through beacon blocks
    beacon_attestations_received.inc()
    beacon_attestation_received_seconds_from_slot_start.observe(
      node.beaconClock.now.int64 - attestation.data.slot.toBeaconTime.int64)

    node.onAttestation(attestation)

  proc attestationValidator(attestation: Attestation,
                            committeeIndex: uint64): bool =
    let (afterGenesis, slot) = node.beaconClock.now().toSlot()
    if not afterGenesis:
      return false
    node.attestationPool.isValidAttestation(attestation, slot, committeeIndex)

  proc aggregatedAttestationValidator(
      signedAggregateAndProof: SignedAggregateAndProof): bool =
    let (afterGenesis, slot) = node.beaconClock.now().toSlot()
    if not afterGenesis:
      return false
    node.attestationPool.isValidAggregatedAttestation(signedAggregateAndProof, slot)

  var attestationSubscriptions: seq[Future[void]] = @[]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#attestations-and-aggregation
  for it in 0'u64 ..< ATTESTATION_SUBNET_COUNT.uint64:
    closureScope:
      let ci = it
      attestationSubscriptions.add(node.network.subscribe(
        getAttestationTopic(node.forkDigest, ci),
        attestationHandler,
        # This proc needs to be within closureScope; don't lift out of loop.
        proc(attestation: Attestation): bool =
          attestationValidator(attestation, ci)
      ))

  attestationSubscriptions.add(node.network.subscribe(
    getAggregateAndProofsTopic(node.forkDigest),
    proc(signedAggregateAndProof: SignedAggregateAndProof) =
      attestationHandler(signedAggregateAndProof.message.aggregate),
    proc(signedAggregateAndProof: SignedAggregateAndProof): bool =
      aggregatedAttestationValidator(signedAggregateAndProof)
  ))

  waitFor allFutures(attestationSubscriptions)

proc stop*(node: BeaconNode) =
  status = BeaconNodeStatus.Stopping
  info "Graceful shutdown"
  waitFor node.network.stop()

proc run*(node: BeaconNode) =
  if status == BeaconNodeStatus.Starting:
    # it might have been set to "Stopping" with Ctrl+C
    status = BeaconNodeStatus.Running

    if node.rpcServer != nil:
      node.rpcServer.installRpcHandlers(node)
      node.rpcServer.start()

    waitFor node.network.subscribe(node.topicBeaconBlocks) do (signedBlock: SignedBeaconBlock):
      onBeaconBlock(node, signedBlock)
    do (signedBlock: SignedBeaconBlock) -> bool:
      let
        now = node.beaconClock.now
        (afterGenesis, slot) = now.toSlot()

      if not afterGenesis:
        return false

      logScope:
        blk = shortLog(signedBlock.message)
        root = shortLog(signedBlock.root)

      let isKnown = signedBlock.root in node.chainDag.blocks
      if isKnown:
        trace "Received known gossip block"
        # TODO:
        # Potentially use a fast exit here. We only need to check that
        # the contents of the incoming message match our previously seen
        # version of the block. We don't need to use HTR for this - for
        # better efficiency we can use vanilla SHA256 or direct comparison
        # if we still have the previous block in memory.
        # TODO:
        # We are seeing extreme delays sometimes (e.g. 300 seconds).
        # Should we drop such blocks? The spec doesn't set a policy on this.
      else:
        let delay = (now.int64 - signedBlock.message.slot.toBeaconTime.int64)
        debug "Incoming gossip block", delay
        beacon_block_received_seconds_from_slot_start.observe delay

      let blck = node.chainDag.isValidBeaconBlock(node.quarantine,
                                                  signedBlock, slot, {})
      node.dumpBlock(signedBlock, blck)

      blck.isOk

    installAttestationHandlers(node)

    let
      curSlot = node.beaconClock.now().slotOrZero()
      nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
      fromNow = saturate(node.beaconClock.fromNow(nextSlot))

    info "Scheduling first slot action",
      beaconTime = shortLog(node.beaconClock.now()),
      nextSlot = shortLog(nextSlot),
      fromNow = shortLog(fromNow)

    addTimer(fromNow) do (p: pointer):
      asyncCheck node.onSlotStart(curSlot, nextSlot)

    node.onSecondLoop = runOnSecondLoop(node)
    node.forwardSyncLoop = runForwardSyncLoop(node)

    node.requestManager.start()

  # main event loop
  while status == BeaconNodeStatus.Running:
    try:
      poll()
    except CatchableError as e:
      debug "Exception in poll()", exc = e.name, err = e.msg

  # time to say goodbye
  node.stop()

var gPidFile: string
proc createPidFile(filename: string) =
  createDir splitFile(filename).dir
  writeFile filename, $os.getCurrentProcessId()
  gPidFile = filename
  addQuitProc proc {.noconv.} = removeFile gPidFile

proc initializeNetworking(node: BeaconNode) {.async.} =
  await node.network.startListening()

  let addressFile = node.config.dataDir / "beacon_node.enr"
  writeFile(addressFile, node.network.announcedENR.toURI)

  await node.network.startLookingForPeers()

  info "Networking initialized",
    enr = node.network.announcedENR.toURI,
    libp2p = shortLog(node.network.switch.peerInfo)

proc start(node: BeaconNode) =
  let
    head = node.chainDag.head
    finalizedHead = node.chainDag.finalizedHead
    genesisTime = node.beaconClock.fromNow(toBeaconTime(Slot 0))

  info "Starting beacon node",
    version = fullVersionStr,
    nim = shortNimBanner(),
    timeSinceFinalization =
      int64(finalizedHead.slot.toBeaconTime()) -
      int64(node.beaconClock.now()),
    head = shortLog(head),
    finalizedHead = shortLog(finalizedHead),
    SLOTS_PER_EPOCH,
    SECONDS_PER_SLOT,
    SPEC_VERSION,
    dataDir = node.config.dataDir.string,
    pcs = "start_beacon_node"

  if genesisTime.inFuture:
    notice "Waiting for genesis", genesisIn = genesisTime.offset

  waitFor node.initializeNetworking()
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
  import prompt

  func providePromptCompletions*(line: seq[Rune], cursorPos: int): seq[string] =
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
        template justified: untyped = node.chainDag.head.atEpochStart(
          node.chainDag.headState.data.data.current_justified_checkpoint.epoch)
        # TODO:
        # We should introduce a general API for resolving dot expressions
        # such as `db.latest_block.slot` or `metrics.connected_peers`.
        # Such an API can be shared between the RPC back-end, CLI tools
        # such as ncli, a potential GraphQL back-end and so on.
        # The status bar feature would allow the user to specify an
        # arbitrary expression that is resolvable through this API.
        case expr.toLowerAscii
        of "connected_peers":
          $(node.connectedPeersCount)

        of "head_root":
          shortLog(node.chainDag.head.root)
        of "head_epoch":
          $(node.chainDag.head.slot.epoch)
        of "head_epoch_slot":
          $(node.chainDag.head.slot mod SLOTS_PER_EPOCH)
        of "head_slot":
          $(node.chainDag.head.slot)

        of "justifed_root":
          shortLog(justified.blck.root)
        of "justifed_epoch":
          $(justified.slot.epoch)
        of "justifed_epoch_slot":
          $(justified.slot mod SLOTS_PER_EPOCH)
        of "justifed_slot":
          $(justified.slot)

        of "finalized_root":
          shortLog(node.chainDag.finalizedHead.blck.root)
        of "finalized_epoch":
          $(node.chainDag.finalizedHead.slot.epoch)
        of "finalized_epoch_slot":
          $(node.chainDag.finalizedHead.slot mod SLOTS_PER_EPOCH)
        of "finalized_slot":
          $(node.chainDag.finalizedHead.slot)

        of "epoch":
          $node.currentSlot.epoch

        of "epoch_slot":
          $(node.currentSlot mod SLOTS_PER_EPOCH)

        of "slot":
          $node.currentSlot

        of "slots_per_epoch":
          $SLOTS_PER_EPOCH

        of "slot_trailing_digits":
          var slotStr = $node.currentSlot
          if slotStr.len > 3: slotStr = slotStr[^3..^1]
          slotStr

        of "attached_validators_balance":
          var balance = uint64(0)
          # TODO slow linear scan!
          for idx, b in node.chainDag.headState.data.data.balances:
            if node.getAttachedValidator(
                node.chainDag.headState.data.data, ValidatorIndex(idx)) != nil:
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
          proc (logLevel: LogLevel, msg: LogOutputStr) {.gcsafe, raises: [Defect].} =
            try:
              # p.hidePrompt
              erase statusBar
              # p.writeLine msg
              stdout.write msg
              render statusBar
              # p.showPrompt
            except Exception as e: # render raises Exception
              logLoggingFailure(cstring(msg), e)

      proc statusBarUpdatesPollingLoop() {.async.} =
        while true:
          update statusBar
          await sleepAsync(chronos.seconds(1))

      traceAsyncErrors statusBarUpdatesPollingLoop()

      # var t: Thread[ptr Prompt]
      # createThread(t, processPromptCommands, addr p)

programMain:
  var
    config = makeBannerAndConfig(clientId, BeaconNodeConf)
    # This is ref so we can mutate it (to erase it) after the initial loading.
    stateSnapshotContents: ref string

  setupLogging(config.logLevel, config.logFile)

  if config.eth2Network.isSome:
    let
      networkName = config.eth2Network.get
      metadata = case toLowerAscii(networkName)
        of "mainnet":
          mainnetMetadata
        of "altona":
          altonaMetadata
        of "medalla":
          medallaMetadata
        of "testnet0":
          testnet0Metadata
        of "testnet1":
          testnet1Metadata
        else:
          if fileExists(networkName):
            try:
              Json.loadFile(networkName, Eth2NetworkMetadata)
            except SerializationError as err:
              echo err.formatMsg(networkName)
              quit 1
          else:
            fatal "Unrecognized network name", networkName
            quit 1

    if metadata.incompatible:
      fatal "The selected network is not compatible with the current build",
             reason = metadata.incompatibilityDesc
      quit 1

    config.runtimePreset = metadata.runtimePreset

    if config.cmd == noCommand:
      for node in metadata.bootstrapNodes:
        config.bootstrapNodes.add node

      if config.stateSnapshot.isNone and metadata.genesisData.len > 0:
        stateSnapshotContents = newClone metadata.genesisData

    template checkForIncompatibleOption(flagName, fieldName) =
      # TODO: This will have to be reworked slightly when we introduce config files.
      # We'll need to keep track of the "origin" of the config value, so we can
      # discriminate between values from config files that can be overridden and
      # regular command-line options (that may conflict).
      if config.fieldName.isSome:
        fatal "Invalid CLI arguments specified. You must not specify '--network' and '" & flagName & "' at the same time",
            networkParam = networkName, `flagName` = config.fieldName.get
        quit 1

    checkForIncompatibleOption "deposit-contract", depositContractAddress
    checkForIncompatibleOption "deposit-contract-block", depositContractDeployedAt

    config.depositContractAddress = some metadata.depositContractAddress
    config.depositContractDeployedAt = some metadata.depositContractDeployedAt
  else:
    config.runtimePreset = defaultRuntimePreset

  # Single RNG instance for the application - will be seeded on construction
  # and avoid using system resources (such as urandom) after that
  let rng = keys.newRng()

  case config.cmd
  of createTestnet:
    let launchPadDeposits = try:
      Json.loadFile(config.testnetDepositsFile.string, seq[LaunchPadDeposit])
    except SerializationError as err:
      error "Invalid LaunchPad deposits file",
             err = formatMsg(err, config.testnetDepositsFile.string)
      quit 1

    var deposits: seq[Deposit]
    for i in config.firstValidator.int ..< launchPadDeposits.len:
      deposits.add Deposit(data: launchPadDeposits[i] as DepositData)

    attachMerkleProofs(deposits)

    let
      startTime = uint64(times.toUnix(times.getTime()) + config.genesisOffset)
      outGenesis = config.outputGenesis.string
      eth1Hash = if config.web3Url.len == 0: eth1BlockHash
                 else: (waitFor getEth1BlockHash(config.web3Url, blockId("latest"))).asEth2Digest
    var
      initialState = initialize_beacon_state_from_eth1(
        defaultRuntimePreset, eth1Hash, startTime, deposits, {skipBlsValidation})

    # https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#create-genesis-state
    initialState.genesis_time = startTime

    doAssert initialState.validators.len > 0

    let outGenesisExt = splitFile(outGenesis).ext
    if cmpIgnoreCase(outGenesisExt, ".json") == 0:
      Json.saveFile(outGenesis, initialState, pretty = true)
      echo "Wrote ", outGenesis

    let outSszGenesis = outGenesis.changeFileExt "ssz"
    SSZ.saveFile(outSszGenesis, initialState[])
    echo "Wrote ", outSszGenesis

    let bootstrapFile = config.outputBootstrapFile.string
    if bootstrapFile.len > 0:
      let
        networkKeys = getPersistentNetKeys(rng[], config)
        metadata = getPersistentNetMetadata(config)
        bootstrapEnr = enr.Record.init(
          1, # sequence number
          networkKeys.seckey.asEthKey,
          some(config.bootstrapAddress),
          config.bootstrapPort,
          config.bootstrapPort,
          [toFieldPair("eth2", SSZ.encode(enrForkIdFromState initialState[])),
           toFieldPair("attnets", SSZ.encode(metadata.attnets))])

      writeFile(bootstrapFile, bootstrapEnr.tryGet().toURI)
      echo "Wrote ", bootstrapFile

  of noCommand:
    debug "Launching beacon node",
          version = fullVersionStr,
          cmdParams = commandLineParams(),
          config

    createPidFile(config.dataDir.string / "beacon_node.pid")

    config.createDumpDirs()

    var node = waitFor BeaconNode.init(rng, config, stateSnapshotContents)

    ## Ctrl+C handling
    proc controlCHandler() {.noconv.} =
      when defined(windows):
        # workaround for https://github.com/nim-lang/Nim/issues/4057
        setupForeignThreadGc()
      info "Shutting down after having received SIGINT"
      status = BeaconNodeStatus.Stopping
    setControlCHook(controlCHandler)

    when hasPrompt:
      initPrompt(node)

    when useInsecureFeatures:
      if config.metricsEnabled:
        let metricsAddress = config.metricsAddress
        info "Starting metrics HTTP server",
          address = metricsAddress, port = config.metricsPort
        metrics.startHttpServer($metricsAddress, config.metricsPort)

    if node.nickname != "":
      dynamicLogScope(node = node.nickname): node.start()
    else:
      node.start()

  of deposits:
    case config.depositsCmd
    of DepositsCmd.create:
      var walletData = if config.existingWalletId.isSome:
        let id = config.existingWalletId.get
        let found = keystore_management.findWallet(config, id)
        if found.isErr:
          fatal "Unable to find wallet with the specified name/uuid",
                id, err = found.error
          quit 1
        let unlocked = unlockWalletInteractively(found.get)
        if unlocked.isOk:
          unlocked.get
        else:
          quit 1
      else:
        let walletData = createWalletInteractively(rng[], config)
        if walletData.isErr:
          fatal "Unable to create wallet", err = walletData.error
          quit 1
        walletData.get

      defer: burnMem(walletData.mnemonic)

      createDir(config.outValidatorsDir)
      createDir(config.outSecretsDir)

      let deposits = generateDeposits(
        config.runtimePreset,
        rng[],
        walletData,
        config.totalDeposits,
        config.outValidatorsDir,
        config.outSecretsDir)

      if deposits.isErr:
        fatal "Failed to generate deposits", err = deposits.error
        quit 1

      try:
        let depositDataPath = if config.outDepositsFile.isSome:
          config.outDepositsFile.get.string
        else:
          config.outValidatorsDir / "deposit_data-" & $epochTime() & ".json"

        let launchPadDeposits =
          mapIt(deposits.value, LaunchPadDeposit.init(config.runtimePreset, it))

        Json.saveFile(depositDataPath, launchPadDeposits)
        info "Deposit data written", filename = depositDataPath
      except CatchableError as err:
        error "Failed to create launchpad deposit data file", err = err.msg
        quit 1

    of DepositsCmd.`import`:
      importKeystoresFromDir(
        rng[],
        config.importedDepositsDir.string,
        config.validatorsDir, config.secretsDir)

    of DepositsCmd.status:
      echo "The status command is not implemented yet"
      quit 1

  of wallets:
    case config.walletsCmd:
    of WalletsCmd.create:
      let status = createWalletInteractively(rng[], config)
      if status.isErr:
        fatal "Unable to create wallet", err = status.error
        quit 1

    of WalletsCmd.list:
      # TODO
      discard

    of WalletsCmd.restore:
      # TODO
      discard
