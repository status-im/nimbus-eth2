# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/os,
  chronicles, chronicles/chronos_tools, chronos,
  eth/keys,
  ./eth1/eth1_monitor,
  ./gossip_processing/optimistic_processor,
  ./networking/topic_params,
  ./spec/beaconstate,
  ./spec/datatypes/[phase0, altair, bellatrix],
  "."/[light_client, nimbus_binary_common, version]

from ./consensus_object_pools/consensus_manager import runForkchoiceUpdated
from ./gossip_processing/block_processor import newExecutionPayload
from ./gossip_processing/eth2_processor import toValidationResult

programMain:
  var config = makeBannerAndConfig(
    "Nimbus light client " & fullVersionStr, LightClientConf)
  setupLogging(config.logLevel, config.logStdout, config.logFile)

  notice "Launching light client",
    version = fullVersionStr, cmdParams = commandLineParams(), config

  let metadata = loadEth2Network(config.eth2Network)
  for node in metadata.bootstrapNodes:
    config.bootstrapNodes.add node
  template cfg(): auto = metadata.cfg

  let
    genesisState =
      try:
        template genesisData(): auto = metadata.genesisData
        newClone(readSszForkedHashedBeaconState(
          cfg, genesisData.toOpenArrayByte(genesisData.low, genesisData.high)))
      except CatchableError as err:
        raiseAssert "Invalid baked-in state: " & err.msg

    beaconClock = BeaconClock.init(
      getStateField(genesisState[], genesis_time))
    getBeaconTime = beaconClock.getBeaconTimeFn()

    genesis_validators_root =
      getStateField(genesisState[], genesis_validators_root)
    forkDigests = newClone ForkDigests.init(cfg, genesis_validators_root)

    genesisBlockRoot = get_initial_beacon_block(genesisState[]).root

    rng = keys.newRng()
    netKeys = getRandomNetKeys(rng[])
    network = createEth2Node(
      rng, config, netKeys, cfg,
      forkDigests, getBeaconTime, genesis_validators_root)

    eth1Monitor =
      if config.web3Urls.len > 0:
        let res = Eth1Monitor.init(
          cfg, db = nil, getBeaconTime, config.web3Urls,
          none(DepositContractSnapshot), metadata.eth1Network,
          forcePolling = false,
          rng[].loadJwtSecret(config, allowCreate = false),
          true)
        waitFor res.ensureDataProvider()
        res
      else:
        nil

    optimisticHandler = proc(signedBlock: ForkedMsgTrustedSignedBeaconBlock):
        Future[void] {.async.} =
      notice "New LC optimistic block",
        opt = signedBlock.toBlockId(),
        wallSlot = getBeaconTime().slotOrZero
      withBlck(signedBlock):
        when stateFork >= BeaconStateFork.Bellatrix:
          if blck.message.is_execution_block:
            template payload(): auto = blck.message.body.execution_payload

            if eth1Monitor != nil and not payload.block_hash.isZero:
              await eth1Monitor.ensureDataProvider()

              # engine_newPayloadV1
              discard await eth1Monitor.newExecutionPayload(payload)

              # engine_forkchoiceUpdatedV1
              discard await eth1Monitor.runForkchoiceUpdated(
                headBlockRoot = payload.block_hash,
                safeBlockRoot = payload.block_hash,  # stub value
                finalizedBlockRoot = ZERO_HASH)
        else: discard
    optimisticProcessor = initOptimisticProcessor(
      getBeaconTime, optimisticHandler)

    lightClient = createLightClient(
      network, rng, config, cfg, forkDigests, getBeaconTime,
      genesis_validators_root, LightClientFinalizationMode.Optimistic)

  info "Listening to incoming network requests"
  network.initBeaconSync(cfg, forkDigests, genesisBlockRoot, getBeaconTime)
  network.addValidator(
    getBeaconBlocksTopic(forkDigests.phase0),
    proc (signedBlock: phase0.SignedBeaconBlock): ValidationResult =
      toValidationResult(
        optimisticProcessor.processSignedBeaconBlock(signedBlock)))
  network.addValidator(
    getBeaconBlocksTopic(forkDigests.altair),
    proc (signedBlock: altair.SignedBeaconBlock): ValidationResult =
      toValidationResult(
        optimisticProcessor.processSignedBeaconBlock(signedBlock)))
  network.addValidator(
    getBeaconBlocksTopic(forkDigests.bellatrix),
    proc (signedBlock: bellatrix.SignedBeaconBlock): ValidationResult =
      toValidationResult(
        optimisticProcessor.processSignedBeaconBlock(signedBlock)))
  lightClient.installMessageValidators()
  waitFor network.startListening()
  waitFor network.start()

  proc onFinalizedHeader(
      lightClient: LightClient, finalizedHeader: BeaconBlockHeader) =
    info "New LC finalized header",
      finalized_header = shortLog(finalizedHeader)
    optimisticProcessor.setFinalizedHeader(finalizedHeader)

  proc onOptimisticHeader(
      lightClient: LightClient, optimisticHeader: BeaconBlockHeader) =
    info "New LC optimistic header",
      optimistic_header = shortLog(optimisticHeader)
    optimisticProcessor.setOptimisticHeader(optimisticHeader)

  lightClient.onFinalizedHeader = onFinalizedHeader
  lightClient.onOptimisticHeader = onOptimisticHeader
  lightClient.trustedBlockRoot = some config.trustedBlockRoot

  # Full blocks gossip is required to portably drive an EL client:
  # - EL clients may not sync when only driven with `forkChoiceUpdated`,
  #   e.g., Geth: "Forkchoice requested unknown head"
  # - `newPayload` requires the full `ExecutionPayload` (most of block content)
  # - `ExecutionPayload` block root is not available in `BeaconBlockHeader`,
  #   so won't be exchanged via light client gossip
  #
  # Future `ethereum/consensus-specs` versions may remove need for full blocks.
  # Therefore, this current mechanism is to be seen as temporary; it is not
  # optimized for reducing code duplication, e.g., with `nimbus_beacon_node`.

  func shouldSyncOptimistically(wallSlot: Slot): bool =
    # Check whether an EL is connected
    if eth1Monitor == nil:
      return false

    # Check whether light client is used
    let optimisticHeader = lightClient.optimisticHeader.valueOr:
      return false

    # Check whether light client has synced sufficiently close to wall slot
    const maxAge = 2 * SLOTS_PER_EPOCH
    if optimisticHeader.slot < max(wallSlot, maxAge.Slot) - maxAge:
      return false

    true

  var blocksGossipState: GossipState = {}
  proc updateBlocksGossipStatus(slot: Slot) =
    let
      isBehind = not shouldSyncOptimistically(slot)

      targetGossipState = getTargetGossipState(
        slot.epoch, cfg.ALTAIR_FORK_EPOCH, cfg.BELLATRIX_FORK_EPOCH, isBehind)

    template currentGossipState(): auto = blocksGossipState
    if currentGossipState == targetGossipState:
      return

    if currentGossipState.card == 0 and targetGossipState.card > 0:
      debug "Enabling blocks topic subscriptions",
        wallSlot = slot, targetGossipState
    elif currentGossipState.card > 0 and targetGossipState.card == 0:
      debug "Disabling blocks topic subscriptions",
        wallSlot = slot
    else:
      # Individual forks added / removed
      discard

    let
      newGossipForks = targetGossipState - currentGossipState
      oldGossipForks = currentGossipState - targetGossipState

    for gossipFork in oldGossipForks:
      let forkDigest = forkDigests[].atStateFork(gossipFork)
      network.unsubscribe(getBeaconBlocksTopic(forkDigest))

    for gossipFork in newGossipForks:
      let forkDigest = forkDigests[].atStateFork(gossipFork)
      network.subscribe(
        getBeaconBlocksTopic(forkDigest), blocksTopicParams,
        enableTopicMetrics = true)

    blocksGossipState = targetGossipState

  var nextExchangeTransitionConfTime = Moment.now + chronos.seconds(60)
  proc onSecond(time: Moment) =
    let wallSlot = getBeaconTime().slotOrZero()

    # engine_exchangeTransitionConfigurationV1
    if time > nextExchangeTransitionConfTime and eth1Monitor != nil:
      nextExchangeTransitionConfTime = time + chronos.seconds(45)
      if wallSlot.epoch >= cfg.BELLATRIX_FORK_EPOCH:
        traceAsyncErrors eth1Monitor.exchangeTransitionConfiguration()

    if checkIfShouldStopAtEpoch(wallSlot, config.stopAtEpoch):
      quit(0)

    updateBlocksGossipStatus(wallSlot + 1)
    lightClient.updateGossipStatus(wallSlot + 1)

  proc runOnSecondLoop() {.async.} =
    let sleepTime = chronos.seconds(1)
    while true:
      let start = chronos.now(chronos.Moment)
      await chronos.sleepAsync(sleepTime)
      let afterSleep = chronos.now(chronos.Moment)
      let sleepTime = afterSleep - start
      onSecond(start)
      let finished = chronos.now(chronos.Moment)
      let processingTime = finished - afterSleep
      trace "onSecond task completed", sleepTime, processingTime

  onSecond(Moment.now())
  lightClient.start()

  asyncSpawn runOnSecondLoop()
  while true:
    poll()
