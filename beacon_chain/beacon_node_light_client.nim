# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  chronos,
  ./consensus_object_pools/block_clearance_light_client,
  ./gossip_processing/[block_processor, light_client_processor],
  ./spec/datatypes/altair,
  ./sync/light_client_manager,
  ./beacon_node

logScope: topics = "beacnde"

proc getLocalWallTime(node: BeaconNode): BeaconTime =
  node.beaconClock.now

proc getLocalWallSlot(node: BeaconNode): Slot =
  node.getLocalWallTime.slotOrZero

proc getLocalWallPeriod(node: BeaconNode): SyncCommitteePeriod =
  node.getLocalWallSlot().sync_committee_period

const maxPeriodsAheadOfDag = 2
  ## Maximum number of periods to sync ahead of DAG's finalized head period.
  ## Bootstrap data from trusted block roots may exceed this limit.

func getTargetPeriod(node: BeaconNode): SyncCommitteePeriod =
  node.dag.finalizedHead.slot.sync_committee_period + maxPeriodsAheadOfDag

func getFinalizedPeriod(node: BeaconNode): SyncCommitteePeriod =
  let store = node.lightClient.store
  if store[].isSome:
    store[].get.finalized_header.slot.sync_committee_period
  else:
    GENESIS_SLOT.sync_committee_period

proc initLightClient*(
    node: BeaconNode,
    cfg: RuntimeConfig,
    rng: ref BrHmacDrbgContext,
    genesisValidatorsRoot: Eth2Digest,
    getBeaconTime: GetBeaconTimeFn) =
  template config(): auto = node.config

  let store = (ref Option[LightClientStore])()

  func getTrustedBlockRoot(): Option[Eth2Digest] =
    node.lightClient.trustedBlockRoot

  proc getLocalWallPeriod(): SyncCommitteePeriod =
    node.getLocalWallPeriod()

  func getTargetPeriod(): SyncCommitteePeriod =
    node.getTargetPeriod()

  func getFinalizedPeriod(): SyncCommitteePeriod =
    node.getFinalizedPeriod()

  func isLightClientStoreInitialized(): bool =
    store[].isSome

  func isNextSyncCommitteeKnown(): bool =
    if store[].isSome:
      not store[].get.next_sync_committee.isZeroMemory
    else:
      false

  let lightClientProcessor = LightClientProcessor.new(
    config.dumpEnabled, config.dumpDirInvalid, config.dumpDirIncoming,
    cfg, genesisValidatorsRoot, LightClientFinalizationMode.Strict,
    store, getBeaconTime, getTrustedBlockRoot)

  proc lightClientVerifier(obj: SomeLightClientObject):
      Future[Result[void, BlockError]] =
    let resfut = newFuture[Result[void, BlockError]]("lightClientVerifier")
    lightClientProcessor[].addObject(MsgSource.gossip, obj, resfut)
    resfut
  let
    bootstrapVerifier = proc(obj: altair.LightClientBootstrap):
        Future[Result[void, BlockError]] =
      lightClientVerifier(obj)
    updateVerifier = proc(obj: altair.LightClientUpdate):
        Future[Result[void, BlockError]] =
      lightClientVerifier(obj)
    optimisticUpdateVerifier = proc(obj: OptimisticLightClientUpdate):
        Future[Result[void, BlockError]] =
      lightClientVerifier(obj)

  node.lightClient.trustedBlockRoot = config.lightClientTrustedBlockRoot
  node.lightClient.store = store
  node.lightClient.processor = lightClientProcessor
  node.lightClient.manager = LightClientManager.init(
    node.network, rng, getTrustedBlockRoot,
    bootstrapVerifier, updateVerifier, optimisticUpdateVerifier,
    getLocalWallPeriod, getTargetPeriod, getFinalizedPeriod,
    isLightClientStoreInitialized, isNextSyncCommitteeKnown)
  node.lightClient.gossipState = {}
  node.lightClient.importTrustedBlocksFut = nil

proc startLightClient*(node: BeaconNode) =
  if node.lightClient.trustedBlockRoot.isNone:
    return

  notice "Starting light client",
    trusted_block_root = node.lightClient.trustedBlockRoot.get
  node.lightClient.manager.start()

proc installLightClientMessageValidators*(node: BeaconNode) =
  let forkDigests = node.dag.forkDigests
  for digest in [forkDigests.altair, forkDigests.bellatrix]:
    node.network.addValidator(
      getOptimisticLightClientUpdateTopic(digest),
      proc(msg: OptimisticLightClientUpdate): ValidationResult =
        template lc(): auto = node.lightClient
        if lc.manager.isGossipSupported(node.getLocalWallPeriod()):
          toValidationResult(
            lc.processor[].optimisticLightClientUpdateValidator(
              MsgSource.gossip, msg))
        else:
          ValidationResult.Ignore)

from
  libp2p/protocols/pubsub/gossipsub
import
  TopicParams, validateParameters, init

const lightClientTopicParams = TopicParams.init()
static: lightClientTopicParams.validateParameters().tryGet()

proc updateLightClientGossipStatus*(node: BeaconNode, slot: Slot) =
  let
    isBehind =
      if node.lightClient.manager.isGossipSupported(slot.sync_committee_period):
        false
      elif node.config.serveLightClientData:
        # While separate message validators can be installed for both
        # full node and light client (both are called unless one rejects msg),
        # only a single subscription can be installed per topic for now.
        # The full node subscription is also handled here, even though it
        # does not directly relate to the client side of the LC sync protocol
        let headDistance =
          if slot > node.dag.head.slot: (slot - node.dag.head.slot).uint64
          else: 0'u64
        headDistance > TOPIC_SUBSCRIBE_THRESHOLD_SLOTS + HYSTERESIS_BUFFER
      else:
        true # Force `targetGossipState` to `{}`
    targetGossipState =
      getTargetGossipState(
        slot.epoch,
        node.dag.cfg.ALTAIR_FORK_EPOCH,
        node.dag.cfg.BELLATRIX_FORK_EPOCH,
        isBehind)
  template currentGossipState(): auto = node.lightClient.gossipState
  if currentGossipState == targetGossipState:
    return

  if currentGossipState.card == 0 and targetGossipState.card > 0:
    debug "Enabling light client topic subscriptions",
      wallSlot = slot, targetGossipState
  elif currentGossipState.card > 0 and targetGossipState.card == 0:
    debug "Disabling light client topic subscriptions",
      wallSlot = slot
  else:
    # Individual forks added / removed
    discard

  let
    newGossipForks = targetGossipState - currentGossipState
    oldGossipForks = currentGossipState - targetGossipState

  for gossipFork in oldGossipForks:
    if gossipFork >= BeaconStateFork.Altair:
      let forkDigest = node.dag.forkDigest(gossipFork)
      node.network.unsubscribe(
        getOptimisticLightClientUpdateTopic(forkDigest))

  for gossipFork in newGossipForks:
    if gossipFork >= BeaconStateFork.Altair:
      let forkDigest = node.dag.forkDigest(gossipFork)
      node.network.subscribe(
        getOptimisticLightClientUpdateTopic(forkDigest),
        lightClientTopicParams)

  node.lightClient.gossipState = targetGossipState

proc importTrustedBlocks*(
    node: BeaconNode, trustedBid: BlockId) {.async.} =
  ## Import trusted blocks up through a given trusted block header.
  template config(): auto = node.config
  let targetBid = node.dag.finalizedHead.blck.bid
  logScope:
    trusted_head = trustedBid
    finalized_head = node.dag.finalizedHead
    target_head = targetBid

  info "Starting trusted light client data import"
  let startTick = Moment.now()
  var backfill = BeaconBlockSummary(
    slot: trustedBid.slot,
    parent_root: trustedBid.root)
  doAssert backfill.slot > targetBid.slot

  # Cache trusted blocks in memory until download is complete
  let numSlots = trustedBid.slot - targetBid.slot + 1
  var trustedBlocks = newSeqOfCap[ForkedSignedBeaconBlock](numSlots)

  # Sync trusted blocks using sync manager
  func getLocalHeadSlot(): Slot =
    trustedBid.slot

  proc getLocalWallSlot(): Slot =
    node.getLocalWallSlot()

  func getFinalizedSlot(): Slot =
    trustedBid.slot

  func getBackfillSlot(): Slot =
    if trustedBlocks.len == 0:
      backfill.slot + 1
    else:
      backfill.slot

  func getFrontfillSlot(): Slot =
    targetBid.slot

  proc trustedBlockVerifier(signedBlock: ForkedSignedBeaconBlock):
      Future[Result[void, BlockError]] =
    let resfut = newFuture[Result[void, BlockError]]("trustedBlockVerifier")
    withBlck(signedBlock):
      resfut.complete(trustedBlocks.cacheTrustedBlock(blck, backfill))
    resfut

  let trustedBlocksSyncManager = newSyncManager[Peer, PeerID](
    node.network.peerPool, SyncQueueKind.Backward, getLocalHeadSlot,
    getLocalWallSlot, getFinalizedSlot, getBackfillSlot, getFrontfillSlot,
    progressPivot = trustedBid.slot, trustedBlockVerifier, maxHeadAge = 0,
    ident = "trustedBlocks")
  trustedBlocksSyncManager.start()
  while trustedBlocksSyncManager.inProgress:
    await chronos.sleepAsync(chronos.seconds(10))
    info "Syncing trusted light client data",
      sync_status = trustedBlocksSyncManager.syncStatus
  if trustedBlocks.len == 0 or trustedBlocks[^1].slot > targetBid.slot:
    error "Trusted light client data incomplete",
      sync_progress =
        if trustedBlocks.len > 0:
          some(trustedBlocks[^1].slot)
        else:
          none(Slot)
    return
  let syncTick = Moment.now()

  # Apply blocks to DAG
  info "Applying trusted light client data"
  const yieldInterval = chronos.milliseconds(300)
  var nextYield = Moment.now() + yieldInterval
  for i in countdown(trustedBlocks.high, trustedBlocks.low):
    defer: trustedBlocks.del(i)

    # Periodically yield to avoid blocking the entire process
    if Moment.now() >= nextYield:
      await chronos.sleepAsync(yieldInterval)
      nextYield = Moment.now() + yieldInterval

    # Attempt to apply the next block
    let newBlockRef =
      withBlck(trustedBlocks[i]):
        node.blockProcessor[].storeBlock(
          MsgSource.gossip, node.getLocalWallTime(), blck,
          verifyMessage = false)
    if newBlockRef.isErr:
      logScope:
        finalized_head = node.dag.finalizedHead.blck.bid
        err = newBlockRef.error
      case newBlockRef.error
      of BlockError.Invalid:
        # Invalid (outer) block signature (not covered by block root validation)
        # The block signatures can only be verified after all blocks are cached.
        info "Trusted light client data import failed"
        await chronos.sleepAsync(chronos.minutes(10))
        return
      of BlockError.MissingParent:
        let slot = trustedBlocks[i].slot
        if slot >= node.dag.finalizedHead.slot:
          # See comments in `UnviableFork` case, this is a similar condition.
          fatal "Fatal error during trusted light client data import",
            weakSubjectivityCheckpoint = config.weakSubjectivityCheckpoint,
            lightClientTrustedBlockRoot = config.lightClientTrustedBlockRoot
          await chronos.sleepAsync(chronos.minutes(60))
          return
        # Otherwise, this can be hit under these conditions:
        # - DAG was pruned while we synced, and sync manager went too far back
        # - The block refers to a finalized slot expected to be empty
        # - Database corruption, has some gaps in finalized data
        # The purpose of this sync is to advance from `dag.finalizedHead`,
        # so, while those conditions are unexpected, this is not fatal.
        error "Error during trusted light client data import",
          finlow =
            node.dag.db.finalizedBlocks.low.expect("at least tailRef written")
        continue
      of BlockError.UnviableFork:
        # This means that the obtained trusted light client data
        # does not match the fork that the DAG is on, which can happen if:
        # - The DAG or LC sync started outside weak subjectivity period,
        #   and multiple conflicting chains were finalized.
        # - The light client sync protocol was attacked, and a supermajority
        #   of the sync committee (> 2/3) is signing malicious data.
        fatal "Fatal error during trusted light client data import",
          weakSubjectivityCheckpoint = config.weakSubjectivityCheckpoint,
          lightClientTrustedBlockRoot = config.lightClientTrustedBlockRoot
        await chronos.sleepAsync(chronos.minutes(60))
        return
      of BlockError.Duplicate:
        # For slots <= the DAG's `finalizedHead`, this is expected and means
        # that the DAG has advanced while we were syncing, or, that the sync
        # manager went too far back.
        # For slots > the DAG's `finalizedHead`, this may happen if a block
        # was supplied through an out-of-band mechanism like REST API or gossip.
        # In both cases, this error is expected and can be ignored.
        continue
  let applyTick = Moment.now()

  info "Trusted light client data imported",
    syncDur = syncTick - startTick,
    applyDur = applyTick - syncTick

proc tryImportLightClientBlocks*(node: BeaconNode) =
  ## Try importing trusted blocks obtained using the light client sync protocol.

  # Only run one import task at a time
  if node.lightClient.importTrustedBlocksFut != nil:
    return

  # If the node is already in sync, no need to import additional blocks
  if not node.syncManager.inProgress:
    return

  # If the `LightClientStore` has not reached its sync target, wait longer
  let store = node.lightClient.store
  if store[].isNone:
    return
  let
    currentPeriod = node.getLocalWallPeriod()
    targetPeriod = min(node.getTargetPeriod(), currentPeriod)
    finalizedPeriod = node.getFinalizedPeriod()
  if finalizedPeriod < targetPeriod:
    return

  # If the `LightClientStore` is behind the DAG, there is nothing to import
  let
    lcSlot = store[].get.finalized_header.slot
    dagSlot = node.dag.finalizedHead.slot
  if lcSlot <= dagSlot:
    return

  # Import trusted blocks from DAG's finalized head through LC's finalized head
  let finalized_bid =
    store[].get.finalized_header.toBlockId()
  node.lightClient.importTrustedBlocksFut =
    node.importTrustedBlocks(finalized_bid)
  node.lightClient.importTrustedBlocksFut.addCallback do (p: pointer):
    node.lightClient.importTrustedBlocksFut = nil

proc lightClientOnSecond*(node: BeaconNode) =
  ## This procedure will be called once per second.
  if node.config.trustLightClientData:
    node.tryImportLightClientBlocks()
