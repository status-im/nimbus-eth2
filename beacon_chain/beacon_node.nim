# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, tables, random, strutils, times, math,

  # Nimble packages
  stew/[objects, byteutils], stew/shims/macros,
  chronos, confutils, metrics, json_rpc/[rpcserver, jsonmarshal],
  chronicles,
  json_serialization/std/[options, sets, net], serialization/errors,
  eth/db/kvstore, eth/db/kvstore_sqlite3,
  eth/p2p/enode, eth/[keys, async_utils], eth/p2p/discoveryv5/[protocol, enr],

  # Local modules
  spec/[datatypes, digest, crypto, beaconstate, helpers, network],
  spec/presets/custom,
  conf, time, beacon_chain_db, validator_pool, extras,
  attestation_pool, block_pool, eth2_network, eth2_discovery,
  beacon_node_common, beacon_node_types,
  nimbus_binary_common,
  mainchain_monitor, version, ssz/[merkleization],
  sync_protocol, request_manager, validator_keygen, interop, statusbar,
  sync_manager, state_transition,
  validator_duties, validator_api

const
  genesisFile* = "genesis.ssz"
  hasPrompt = not defined(withoutPrompt)

type
  RpcServer* = RpcHttpServer
  KeyPair = eth2_network.KeyPair

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

declareHistogram beacon_attestation_received_seconds_from_slot_start,
  "Interval between slot start and attestation receival", buckets = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, Inf]

logScope: topics = "beacnde"

proc getStateFromSnapshot(conf: BeaconNodeConf): NilableBeaconStateRef =
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

proc enrForkIdFromState(state: BeaconState): ENRForkID =
  let
    forkVer = state.fork.current_version
    forkDigest = compute_fork_digest(forkVer, state.genesis_validators_root)

  ENRForkID(
    fork_digest: forkDigest,
    next_fork_version: forkVer,
    next_fork_epoch: FAR_FUTURE_EPOCH)

proc init*(T: type BeaconNode, conf: BeaconNodeConf): Future[BeaconNode] {.async.} =
  let
    netKeys = getPersistentNetKeys(conf)
    nickname = if conf.nodeName == "auto": shortForm(netKeys)
               else: conf.nodeName
    db = BeaconChainDB.init(kvStore SqStoreRef.init(conf.databaseDir, "nbc").tryGet())

  var mainchainMonitor: MainchainMonitor

  if not BlockPool.isInitialized(db):
    # Fresh start - need to load a genesis state from somewhere
    var genesisState = conf.getStateFromSnapshot()

    # Try file from command line first
    if genesisState.isNil:
      # Didn't work, try creating a genesis state using main chain monitor
      # TODO Could move this to a separate "GenesisMonitor" process or task
      #      that would do only this - see
      if conf.web3Url.len > 0 and conf.depositContractAddress.len > 0:
        mainchainMonitor = MainchainMonitor.init(
          web3Provider(conf.web3Url),
          conf.depositContractAddress,
          Eth2Digest())
        mainchainMonitor.start()
      else:
        error "No initial state, need genesis state or deposit contract address"
        quit 1

      genesisState = await mainchainMonitor.getGenesis()

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
        BlockPool.preInit(db, genesisState[], tailBlock)
        doAssert BlockPool.isInitialized(db), "preInit should have initialized db"
      except CatchableError as e:
        error "Failed to initialize database", err = e.msg
        quit 1

  # TODO check that genesis given on command line (if any) matches database
  let blockPool = BlockPool.init(
    db,
    if conf.verifyFinalization:
      {verifyFinalization}
    else:
      {})

  if mainchainMonitor.isNil and
     conf.web3Url.len > 0 and
     conf.depositContractAddress.len > 0:
    mainchainMonitor = MainchainMonitor.init(
      web3Provider(conf.web3Url),
      conf.depositContractAddress,
      blockPool.headState.data.data.eth1_data.block_hash)
    # TODO if we don't have any validators attached, we don't need a mainchain
    #      monitor
    mainchainMonitor.start()

  let rpcServer = if conf.rpcEnabled:
    RpcServer.init(conf.rpcAddress, conf.rpcPort)
  else:
    nil

  let
    enrForkId = enrForkIdFromState(blockPool.headState.data.data)
    topicBeaconBlocks = getBeaconBlocksTopic(enrForkId.forkDigest)
    topicAggregateAndProofs = getAggregateAndProofsTopic(enrForkId.forkDigest)
    network = await createEth2Node(conf, enrForkId)

  var res = BeaconNode(
    nickname: nickname,
    network: network,
    netKeys: netKeys,
    requestManager: RequestManager.init(network),
    db: db,
    config: conf,
    attachedValidators: ValidatorPool.init(),
    blockPool: blockPool,
    attestationPool: AttestationPool.init(blockPool),
    mainchainMonitor: mainchainMonitor,
    beaconClock: BeaconClock.init(blockPool.headState.data.data),
    rpcServer: rpcServer,
    forkDigest: enrForkId.forkDigest,
    topicBeaconBlocks: topicBeaconBlocks,
    topicAggregateAndProofs: topicAggregateAndProofs,
  )

  # TODO sync is called when a remote peer is connected - is that the right
  #      time to do so?
  network.initBeaconSync(blockPool, enrForkId.forkDigest,
    proc(signedBlock: SignedBeaconBlock) =
      if signedBlock.message.slot.isEpoch:
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
  await node.network.connectToNetwork()

  let addressFile = node.config.dataDir / "beacon_node.address"
  writeFile(addressFile, node.network.announcedENR.toURI)

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
      node.blockPool.finalizedHead.blck.slot.compute_epoch_at_slot()
    # Finalization rule 234, that has the most lag slots among the cases, sets
    # state.finalized_checkpoint = old_previous_justified_checkpoint.epoch + 3
    # and then state.slot gets incremented, to increase the maximum offset, if
    # finalization occurs every slot, to 4 slots vs scheduledSlot.
    doAssert finalizedEpoch + 4 >= epoch

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
    finalizedEpoch = shortLog(node.blockPool.finalizedHead.blck.slot.compute_epoch_at_slot()),
    cat = "scheduling"

  # Check before any re-scheduling of onSlotStart()
  # Offset backwards slightly to allow this epoch's finalization check to occur
  if scheduledSlot > 3 and node.config.stopAtEpoch > 0'u64 and
      (scheduledSlot - 3).compute_epoch_at_slot() >= node.config.stopAtEpoch:
    info "Stopping at pre-chosen epoch",
      chosenEpoch = node.config.stopAtEpoch,
      epoch = scheduledSlot.compute_epoch_at_slot(),
      slot = scheduledSlot

    # Brute-force, but ensure it's reliably enough to run in CI.
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
      nextSlot = shortLog(nextSlot),
      cat = "clock_drift" # tag "scheduling|clock_drift"?

    addTimer(saturate(node.beaconClock.fromNow(nextSlot))) do (p: pointer):
      asyncCheck node.onSlotStart(slot, nextSlot)

    return

  let
    slot = wallSlot.slot # afterGenesis == true!
    nextSlot = slot + 1

  beacon_slot.set slot.int64

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
  var head = node.updateHead()

  # TODO is the slot of the clock or the head block more interesting? provide
  #      rationale in comment
  beacon_head_slot.set slot.int64

  # Time passes in here..
  head = await node.handleValidatorDuties(head, lastSlot, slot)

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
      # dec left
      # if left == 0:
      #   discard setTimer(Moment.now()) do (p: pointer):
      #     handleMissingBlocks(node)

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
  proc getLocalHeadSlot(): Slot =
    result = node.blockPool.head.blck.slot

  proc getLocalWallSlot(): Slot {.gcsafe.} =
    let epoch = node.beaconClock.now().toSlot().slot.compute_epoch_at_slot() +
                1'u64
    result = epoch.compute_start_slot_at_epoch()

  proc updateLocalBlocks(list: openarray[SignedBeaconBlock]): Result[void, BlockError] =
    debug "Forward sync imported blocks", count = len(list),
          local_head_slot = getLocalHeadSlot()
    let sm = now(chronos.Moment)
    for blk in list:
      let res = node.storeBlock(blk)
      # We going to ignore `BlockError.Old` errors because we have working
      # backward sync and it can happens that we can perform overlapping
      # requests.
      if res.isErr and res.error != BlockError.Old:
        return res
    discard node.updateHead()

    let dur = now(chronos.Moment) - sm
    let secs = float(chronos.seconds(1).nanoseconds)
    var storeSpeed = 0.0
    if not(dur.isZero()):
      let v = float(len(list)) * (secs / float(dur.nanoseconds))
      # We doing round manually because stdlib.round is deprecated
      storeSpeed = round(v * 10000) / 10000

    info "Forward sync blocks got imported sucessfully", count = len(list),
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
    updateLocalBlocks,
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
  libp2p_peers.value.int

proc fromJson(n: JsonNode; argName: string; result: var Slot) =
  var i: int
  fromJson(n, argName, i)
  result = Slot(i)

proc installBeaconApiHandlers(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.rpc("getBeaconHead") do () -> Slot:
    return node.blockPool.head.blck.slot

  rpcServer.rpc("getChainHead") do () -> JsonNode:
    let
      head = node.blockPool.head
      finalized = node.blockPool.headState.data.data.finalized_checkpoint
      justified = node.blockPool.headState.data.data.current_justified_checkpoint
    return %* {
      "head_slot": head.blck.slot,
      "head_block_root": head.blck.root.data.toHex(),
      "finalized_slot": finalized.epoch * SLOTS_PER_EPOCH,
      "finalized_block_root": finalized.root.data.toHex(),
      "justified_slot": justified.epoch * SLOTS_PER_EPOCH,
      "justified_block_root": justified.root.data.toHex(),
    }

  rpcServer.rpc("getSyncing") do () -> bool:
    let
      beaconTime = node.beaconClock.now()
      wallSlot = currentSlot(node)
      headSlot = node.blockPool.head.blck.slot
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
      let foundRef = node.blockPool.getBlockByPreciseSlot(slot.get)
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
      let blk = node.blockPool.head.blck.atSlot(slot.get)
      node.blockPool.withState(node.blockPool.tmpState, blk):
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
    genCode:
      for setting in BeaconChainConstants:
        let
          settingSym = ident($setting)
          settingKey = newLit(toLowerAscii($setting))
        yield quote do:
          res[`settingKey`] = %`settingSym`

    return res

proc installRpcHandlers(rpcServer: RpcServer, node: BeaconNode) =
  # TODO: remove this if statement later - here just to test the config option for now
  if node.config.validatorApi:
    rpcServer.installValidatorApiHandlers(node)
  rpcServer.installBeaconApiHandlers(node)
  rpcServer.installDebugApiHandlers(node)

proc installAttestationHandlers(node: BeaconNode) =
  proc attestationHandler(attestation: Attestation) =
    # Avoid double-counting attestation-topic attestations on shared codepath
    # when they're reflected through beacon blocks
    beacon_attestations_received.inc()
    beacon_attestation_received_seconds_from_slot_start.observe(
      node.beaconClock.now.int64 -
        (attestation.data.slot.int64 * SECONDS_PER_SLOT.int64))

    node.onAttestation(attestation)

  var attestationSubscriptions: seq[Future[void]] = @[]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#mainnet-3
  for it in 0'u64 ..< ATTESTATION_SUBNET_COUNT.uint64:
    closureScope:
      let ci = it
      attestationSubscriptions.add(node.network.subscribe(
        getMainnetAttestationTopic(node.forkDigest, ci), attestationHandler,
        # This proc needs to be within closureScope; don't lift out of loop.
        proc(attestation: Attestation): bool =
          # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#attestation-subnets
          let (afterGenesis, slot) = node.beaconClock.now().toSlot()
          if not afterGenesis:
            return false
          node.attestationPool.isValidAttestation(attestation, slot, ci, {})))

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#interop-3
  attestationSubscriptions.add(node.network.subscribe(
    getInteropAttestationTopic(node.forkDigest), attestationHandler,
    proc(attestation: Attestation): bool =
      # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#attestation-subnets
      let (afterGenesis, slot) = node.beaconClock.now().toSlot()
      if not afterGenesis:
        return false
      # isValidAttestation checks attestation.data.index == topicCommitteeIndex
      # which doesn't make sense here, so rig that check to vacuously pass.
      node.attestationPool.isValidAttestation(
        attestation, slot, attestation.data.index, {})))

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
      let (afterGenesis, slot) = node.beaconClock.now.toSlot()
      if not afterGenesis:
        return false
      node.blockPool.isValidBeaconBlock(signedBlock, slot, {})

    installAttestationHandlers(node)

    let
      curSlot = node.beaconClock.now().slotOrZero()
      nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
      fromNow = saturate(node.beaconClock.fromNow(nextSlot))

    info "Scheduling first slot action",
      beaconTime = shortLog(node.beaconClock.now()),
      nextSlot = shortLog(nextSlot),
      fromNow = shortLog(fromNow),
      cat = "scheduling"

    addTimer(fromNow) do (p: pointer):
      asyncCheck node.onSlotStart(curSlot, nextSlot)

    node.onSecondLoop = runOnSecondLoop(node)
    node.forwardSyncLoop = runForwardSyncLoop(node)

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
          $(node.connectedPeersCount)

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
          $node.currentSlot

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
  let config = makeBannerAndConfig(clientId, BeaconNodeConf)

  setupMainProc(config.logLevel)

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
      eth1Hash = if config.web3Url.len == 0: eth1BlockHash
                 else: waitFor getLatestEth1BlockHash(config.web3Url)
    var
      initialState = initialize_beacon_state_from_eth1(
        eth1Hash, startTime, deposits, {skipBlsValidation, skipMerkleValidation})

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
        networkKeys = getPersistentNetKeys(config)
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
    debug "Launching beacon node",
          version = fullVersionStr,
          cmdParams = commandLineParams(),
          config

    createPidFile(config.dataDir.string / "beacon_node.pid")

    if config.dumpEnabled:
      createDir(config.dumpDir)
      createDir(config.dumpDir / "incoming")

    var node = waitFor BeaconNode.init(config)

    ctrlCHandling: status = BeaconNodeStatus.Stopping

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

  of makeDeposits:
    createDir(config.depositsDir)

    let
      quickstartDeposits = generateDeposits(
        config.totalQuickstartDeposits, config.depositsDir, false)

      randomDeposits = generateDeposits(
        config.totalRandomDeposits, config.depositsDir, true,
        firstIdx = config.totalQuickstartDeposits)

    if config.web3Url.len > 0 and config.depositContractAddress.len > 0:
      if config.minDelay > config.maxDelay:
        echo "The minimum delay should not be larger than the maximum delay"
        quit 1

      var delayGenerator: DelayGenerator
      if config.maxDelay > 0.0:
        delayGenerator = proc (): chronos.Duration {.gcsafe.} =
          chronos.milliseconds (rand(config.minDelay..config.maxDelay)*1000).int

      info "Sending deposits",
        web3 = config.web3Url,
        depositContract = config.depositContractAddress

      waitFor sendDeposits(
        quickstartDeposits & randomDeposits,
        config.web3Url,
        config.depositContractAddress,
        config.depositPrivateKey,
        delayGenerator)
