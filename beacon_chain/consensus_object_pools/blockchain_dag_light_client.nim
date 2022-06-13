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
  # Status libraries
  stew/[bitops2, objects],
  chronos,
  # Beacon chain internals
  ../spec/datatypes/[phase0, altair, bellatrix],
  "."/[block_pools_types, blockchain_dag]

logScope: topics = "chaindag"

type
  HashedBeaconStateWithSyncCommittee =
    bellatrix.HashedBeaconState |
    altair.HashedBeaconState

  TrustedSignedBeaconBlockWithSyncAggregate =
    bellatrix.TrustedSignedBeaconBlock |
    altair.TrustedSignedBeaconBlock

template nextEpochBoundarySlot(slot: Slot): Slot =
  ## Compute the first possible epoch boundary state slot of a `Checkpoint`
  ## referring to a block at given slot.
  (slot + (SLOTS_PER_EPOCH - 1)).epoch.start_slot

func computeEarliestLightClientSlot(dag: ChainDAGRef): Slot =
  ## Compute the earliest slot for which light client data is retained.
  let
    minSupportedSlot = max(
      dag.cfg.ALTAIR_FORK_EPOCH.start_slot,
      dag.lightClientCache.importTailSlot)
    currentSlot = getStateField(dag.headState, slot)
  if currentSlot < minSupportedSlot:
    return minSupportedSlot

  let
    MIN_EPOCHS_FOR_BLOCK_REQUESTS =
      dag.cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY +
      dag.cfg.CHURN_LIMIT_QUOTIENT div 2
    MIN_SLOTS_FOR_BLOCK_REQUESTS =
      MIN_EPOCHS_FOR_BLOCK_REQUESTS * SLOTS_PER_EPOCH
  if currentSlot - minSupportedSlot < MIN_SLOTS_FOR_BLOCK_REQUESTS:
    return minSupportedSlot

  let earliestSlot = currentSlot - MIN_SLOTS_FOR_BLOCK_REQUESTS
  max(earliestSlot.sync_committee_period.start_slot, minSupportedSlot)

proc updateExistingState(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bsi: BlockSlotId,
    save: bool, cache: var StateCache): bool =
  ## Wrapper around `updateState` for states expected to exist.
  let ok = dag.updateState(state, bsi, save, cache)
  if not ok:
    error "State failed to load unexpectedly", bsi, tail = dag.tail.slot
    doAssert verifyFinalization notin dag.updateFlags
  ok

template withUpdatedExistingState(
    dag: ChainDAGRef, stateParam: var ForkedHashedBeaconState,
    bsiParam: BlockSlotId, okBody: untyped, failureBody: untyped): untyped =
  ## Wrapper around `withUpdatedState` for states expected to exist.
  block:
    let bsi = bsiParam
    dag.withUpdatedState(stateParam, bsiParam) do:
      okBody
    do:
      error "State failed to load unexpectedly", bsi, tail = dag.tail.slot
      doAssert verifyFinalization notin dag.updateFlags
      failureBody

proc getExistingBlockIdAtSlot(dag: ChainDAGRef, slot: Slot): Opt[BlockSlotId] =
  ## Wrapper around `getBlockIdAtSlot` for blocks expected to exist.
  let bsi = dag.getBlockIdAtSlot(slot)
  if bsi.isErr:
    error "Block failed to load unexpectedly", slot, tail = dag.tail.slot
    doAssert verifyFinalization notin dag.updateFlags
  bsi

proc existingParent(dag: ChainDAGRef, bid: BlockId): Opt[BlockId] =
  ## Wrapper around `parent` for parents known to exist.
  let parent = dag.parent(bid)
  if parent.isErr:
    error "Parent failed to load unexpectedly", bid, tail = dag.tail.slot
    doAssert verifyFinalization notin dag.updateFlags
  parent

proc getExistingForkedBlock(
    dag: ChainDAGRef, bid: BlockId): Opt[ForkedTrustedSignedBeaconBlock] =
  ## Wrapper around `getForkedBlock` for blocks expected to exist.
  let bdata = dag.getForkedBlock(bid)
  if bdata.isErr:
    error "Block failed to load unexpectedly", bid, tail = dag.tail.slot
    doAssert verifyFinalization notin dag.updateFlags
  bdata

proc existingCurrentSyncCommitteeForPeriod(
    dag: ChainDAGRef,
    tmpState: var ForkedHashedBeaconState,
    period: SyncCommitteePeriod): Opt[SyncCommittee] =
  ## Wrapper around `currentSyncCommitteeForPeriod` for states known to exist.
  let syncCommittee = dag.currentSyncCommitteeForPeriod(tmpState, period)
  if syncCommittee.isErr:
    error "Current sync committee failed to load unexpectedly",
      period, tail = dag.tail.slot
    doAssert verifyFinalization notin dag.updateFlags
  syncCommittee

template syncCommitteeRoot(
    state: HashedBeaconStateWithSyncCommittee): Eth2Digest =
  ## Compute a root to uniquely identify `current_sync_committee` and
  ## `next_sync_committee`.
  withEth2Hash:
    h.update state.data.current_sync_committee.hash_tree_root().data
    h.update state.data.next_sync_committee.hash_tree_root().data

proc syncCommitteeRootForPeriod(
    dag: ChainDAGRef,
    tmpState: var ForkedHashedBeaconState,
    period: SyncCommitteePeriod): Opt[Eth2Digest] =
  ## Compute a root to uniquely identify `current_sync_committee` and
  ## `next_sync_committee` for a given sync committee period.
  ## For non-finalized periods, follow the chain as selected by fork choice.
  let lowSlot = max(dag.tail.slot, dag.cfg.ALTAIR_FORK_EPOCH.start_slot)
  if period < lowSlot.sync_committee_period:
    return err()
  let
    periodStartSlot = period.start_slot
    syncCommitteeSlot = max(periodStartSlot, lowSlot)
    bsi = ? dag.getExistingBlockIdAtSlot(syncCommitteeSlot)
  dag.withUpdatedExistingState(tmpState, bsi) do:
    withState(state):
      when stateFork >= BeaconStateFork.Altair:
        ok state.syncCommitteeRoot
      else: raiseAssert "Unreachable"
  do: err()

proc getExistingLightClientData(
    dag: ChainDAGRef,
    bid: BlockId): Opt[CachedLightClientData] =
  ## Fetch cached light client data about a given block.
  ## Data must be cached (`cacheLightClientData`) before calling this function.
  try:
    ok dag.lightClientCache.data[bid]
  except KeyError:
    error "LC data failed to load unexpectedly", bid, tail = dag.tail.slot
    doAssert verifyFinalization notin dag.updateFlags
    err()

proc cacheLightClientData(
    dag: ChainDAGRef, state: HashedBeaconStateWithSyncCommittee, bid: BlockId) =
  ## Cache data for a given block and its post-state to speed up creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances that refer to this
  ## block and state.
  var cachedData {.noinit.}: CachedLightClientData
  state.data.build_proof(
    altair.CURRENT_SYNC_COMMITTEE_INDEX,
    cachedData.current_sync_committee_branch)
  state.data.build_proof(
    altair.NEXT_SYNC_COMMITTEE_INDEX,
    cachedData.next_sync_committee_branch)
  cachedData.finalized_slot =
    state.data.finalized_checkpoint.epoch.start_slot
  state.data.build_proof(
    altair.FINALIZED_ROOT_INDEX,
    cachedData.finality_branch)
  if dag.lightClientCache.data.hasKeyOrPut(bid, cachedData):
    error "Redundant `cacheLightClientData` call", bid
    doAssert verifyFinalization notin dag.updateFlags

proc deleteLightClientData*(dag: ChainDAGRef, bid: BlockId) =
  ## Delete cached light client data for a given block. This needs to be called
  ## when a block becomes unreachable due to finalization of a different fork.
  if dag.importLightClientData == ImportLightClientData.None:
    return

  dag.lightClientCache.data.del bid

func handleUnexpectedLightClientError(dag: ChainDAGRef, buggedSlot: Slot) =
  ## If there is an unexpected error, adjust `importTailSlot` to keep track of
  ## section for which complete light client data is available, and to avoid
  ## failed lookups of cached light client data.
  doAssert verifyFinalization notin dag.updateFlags
  if buggedSlot >= dag.lightClientCache.importTailSlot:
    dag.lightClientCache.importTailSlot = buggedSlot + 1

template lazy_header(name: untyped): untyped {.dirty.} =
  ## `createLightClientUpdates` helper to lazily load a known block header.
  var
    `name _ ptr`: ptr[BeaconBlockHeader]
    `name _ ok` = true
  template `assign _ name`(target: var BeaconBlockHeader, bid: BlockId): bool =
    if `name _ ptr` != nil:
      target = `name _ ptr`[]
    elif `name _ ok`:
      let bdata = dag.getExistingForkedBlock(bid)
      if bdata.isErr:
        dag.handleUnexpectedLightClientError(bid.slot)
        `name _ ok` = false
      else:
        target = bdata.get.toBeaconBlockHeader()
        `name _ ptr` = addr target
    `name _ ok`

template lazy_data(name: untyped): untyped {.dirty.} =
  ## `createLightClientUpdates` helper to lazily load cached light client state.
  var
    `name` {.noinit.}: CachedLightClientData
    `name _ ok` = true
  `name`.finalized_slot = FAR_FUTURE_SLOT
  template `load _ name`(bid: BlockId): bool =
    if `name _ ok` and `name`.finalized_slot == FAR_FUTURE_SLOT:
      `name` = dag.getExistingLightClientData(bid).valueOr:
        dag.handleUnexpectedLightClientError(bid.slot)
        `name _ ok` = false
        default(typeof(`name`))
    `name _ ok`

template lazy_bid(name: untyped): untyped {.dirty.} =
  ## `createLightClientUpdates` helper to lazily load a block id.
  var
    `name` {.noinit.}: BlockId
    `name _ ok` = true
  `name`.slot = FAR_FUTURE_SLOT
  template `load _ name`(slot: Slot): bool =
    if `name _ ok` and `name`.slot == FAR_FUTURE_SLOT:
      let bsi = dag.getBlockIdAtSlot(slot)
      if bsi.isErr:
        # Could happen if latest block through given slot is before DAG tail
        `name _ ok` = false
      else:
        `name` = bsi.get.bid
    `name _ ok`

proc createLightClientUpdates(
    dag: ChainDAGRef,
    state: HashedBeaconStateWithSyncCommittee,
    blck: TrustedSignedBeaconBlockWithSyncAggregate,
    parent_bid: BlockId) =
  ## Create `LightClientUpdate` instances for a given block and its post-state,
  ## and keep track of best / latest ones. Data about the parent block's
  ## post-state must be cached (`cacheLightClientData`) before calling this.

  # Verify sync committee has sufficient participants
  template sync_aggregate(): auto = blck.asSigned().message.body.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64
  if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return

  # Verify attested block (parent) is recent enough and that state is available
  template attested_bid(): auto = parent_bid
  let
    earliest_slot = dag.computeEarliestLightClientSlot
    attested_slot = attested_bid.slot
  if attested_slot < earliest_slot:
    return

  # Lazy variables to hold historic data
  lazy_header(attested_header)
  lazy_data(attested_data)
  lazy_bid(finalized_bid)
  lazy_header(finalized_header)

  # Update latest light client data
  template latest(): auto = dag.lightClientCache.latest
  var
    newFinality = false
    newOptimistic = false
  let
    signature_slot = blck.message.slot
    is_later =
      if attested_slot != latest.attested_header.slot:
        attested_slot > latest.attested_header.slot
      else:
        signature_slot > latest.signature_slot
  if is_later and load_attested_data(attested_bid) and
      latest.attested_header.assign_attested_header(attested_bid):
    let finalized_slot = attested_data.finalized_slot
    if finalized_slot == latest.finalized_header.slot:
      latest.finality_branch = attested_data.finality_branch
    elif finalized_slot == GENESIS_SLOT:
      latest.finalized_header.reset()
      latest.finality_branch = attested_data.finality_branch
    elif load_finalized_bid(finalized_slot) and
        latest.finalized_header.assign_finalized_header(finalized_bid):
      latest.finality_branch = attested_data.finality_branch
      newFinality = true
    else:
      latest.finalized_header.reset()
      latest.finality_branch.reset()
    latest.sync_aggregate = sync_aggregate
    latest.signature_slot = signature_slot
    newOptimistic = true

  # Track best light client data for current period
  let
    attested_period = attested_slot.sync_committee_period
    signature_period = signature_slot.sync_committee_period
  if attested_period == signature_period and load_attested_data(attested_bid):
    template next_sync_committee(): auto = state.data.next_sync_committee

    let isCommitteeFinalized = dag.isNextSyncCommitteeFinalized(attested_period)
    var best =
      if isCommitteeFinalized:
        dag.lightClientCache.best.getOrDefault(attested_period)
      else:
        let key = (attested_period, state.syncCommitteeRoot)
        dag.lightClientCache.pendingBest.getOrDefault(key)

    let
      finalized_slot = attested_data.finalized_slot
      meta = LightClientUpdateMetadata(
        attested_slot: attested_slot,
        finalized_slot: finalized_slot,
        signature_slot: signature_slot,
        has_sync_committee: true,
        has_finality: load_finalized_bid(finalized_slot),
        num_active_participants: num_active_participants)
      is_better = is_better_data(meta, best.toMeta)
    if is_better and best.attested_header.assign_attested_header(attested_bid):
      best.next_sync_committee = next_sync_committee
      best.next_sync_committee_branch = attested_data.next_sync_committee_branch
      if finalized_slot == best.finalized_header.slot:
        best.finality_branch = attested_data.finality_branch
      elif finalized_slot == GENESIS_SLOT:
        best.finalized_header.reset()
        best.finality_branch = attested_data.finality_branch
      elif meta.has_finality and
          best.finalized_header.assign_finalized_header(finalized_bid):
        best.finality_branch = attested_data.finality_branch
      else:
        best.finalized_header.reset()
        best.finality_branch.reset()
      best.sync_aggregate = sync_aggregate
      best.signature_slot = signature_slot

      if isCommitteeFinalized:
        dag.lightClientCache.best[attested_period] = best
        debug "Best LC update for period improved",
          period = attested_period, update = best
      else:
        let key = (attested_period, state.syncCommitteeRoot)
        dag.lightClientCache.pendingBest[key] = best
        debug "Best LC update for period improved",
          period = key, update = best

  if newFinality and dag.onLightClientFinalityUpdate != nil:
    dag.onLightClientFinalityUpdate(latest)
  if newOptimistic and dag.onLightClientOptimisticUpdate != nil:
    dag.onLightClientOptimisticUpdate(latest.toOptimistic)

proc processNewBlockForLightClient*(
    dag: ChainDAGRef,
    state: ForkedHashedBeaconState,
    signedBlock: ForkyTrustedSignedBeaconBlock,
    parentBid: BlockId) =
  ## Update light client data with information from a new block.
  if dag.importLightClientData == ImportLightClientData.None:
    return
  if signedBlock.message.slot < dag.computeEarliestLightClientSlot:
    return

  when signedBlock is bellatrix.TrustedSignedBeaconBlock:
    dag.cacheLightClientData(state.bellatrixData, signedBlock.toBlockId())
    dag.createLightClientUpdates(state.bellatrixData, signedBlock, parentBid)
  elif signedBlock is altair.TrustedSignedBeaconBlock:
    dag.cacheLightClientData(state.altairData, signedBlock.toBlockId())
    dag.createLightClientUpdates(state.altairData, signedBlock, parentBid)
  elif signedBlock is phase0.TrustedSignedBeaconBlock:
    raiseAssert "Unreachable" # `earliestSlot` cannot be before Altair
  else:
    {.error: "Unreachable".}

proc processHeadChangeForLightClient*(dag: ChainDAGRef) =
  ## Update light client data to account for a new head block.
  ## Note that `dag.finalizedHead` is not yet updated when this is called.
  if dag.importLightClientData == ImportLightClientData.None:
    return
  let earliestSlot = dag.computeEarliestLightClientSlot
  if dag.head.slot < earliestSlot:
    return

  # Update `best` from `pendingBest` to ensure light client data
  # only refers to sync committees as selected by fork choice
  let headPeriod = dag.head.slot.sync_committee_period
  if not dag.isNextSyncCommitteeFinalized(headPeriod):
    let lowPeriod =
      max(dag.firstNonFinalizedPeriod, earliestSlot.sync_committee_period)
    if headPeriod > lowPeriod:
      var tmpState = assignClone(dag.headState)
      for period in lowPeriod ..< headPeriod:
        let
          syncCommitteeRoot =
            dag.syncCommitteeRootForPeriod(tmpState[], period).valueOr:
              dag.handleUnexpectedLightClientError(period.start_slot)
              continue
          key = (period, syncCommitteeRoot)
        dag.lightClientCache.best[period] =
          dag.lightClientCache.pendingBest.getOrDefault(key)
    withState(dag.headState): # Common case separate to avoid `tmpState`
      when stateFork >= BeaconStateFork.Altair:
        let key = (headPeriod, state.syncCommitteeRoot)
        dag.lightClientCache.best[headPeriod] =
          dag.lightClientCache.pendingBest.getOrDefault(key)
      else: raiseAssert "Unreachable"

proc processFinalizationForLightClient*(
    dag: ChainDAGRef, oldFinalizedHead: BlockSlot) =
  ## Prune cached data that is no longer useful for creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances.
  ## This needs to be called whenever `finalized_checkpoint` changes.
  if dag.importLightClientData == ImportLightClientData.None:
    return
  let
    earliestSlot = dag.computeEarliestLightClientSlot
    finalizedSlot = dag.finalizedHead.slot
  if finalizedSlot < earliestSlot:
    return

  # Cache `LightClientBootstrap` for newly finalized epoch boundary blocks
  let lowSlot = max(oldFinalizedHead.slot + 1, earliestSlot)
  var boundarySlot = finalizedSlot
  while boundarySlot >= lowSlot:
    let
      bsi = dag.getExistingBlockIdAtSlot(boundarySlot).valueOr:
        dag.handleUnexpectedLightClientError(boundarySlot)
        break
      bid = bsi.bid
    if bid.slot >= lowSlot:
      let cachedData = dag.getExistingLightClientData(bid).valueOr:
        dag.handleUnexpectedLightClientError(bid.slot)
        break
      dag.lightClientCache.bootstrap[bid.slot] =
        CachedLightClientBootstrap(
          current_sync_committee_branch:
            cachedData.current_sync_committee_branch)
    boundarySlot = bid.slot.nextEpochBoundarySlot
    if boundarySlot < SLOTS_PER_EPOCH:
      break
    boundarySlot -= SLOTS_PER_EPOCH

  # Prune light client data that is no longer referrable by future updates
  var bidsToDelete: seq[BlockId]
  for bid, data in dag.lightClientCache.data:
    if bid.slot >= dag.finalizedHead.blck.slot:
      continue
    bidsToDelete.add bid
  for bid in bidsToDelete:
    dag.lightClientCache.data.del bid

  # Prune bootstrap data that is no longer relevant
  var slotsToDelete: seq[Slot]
  for slot in dag.lightClientCache.bootstrap.keys:
    if slot < earliestSlot:
      slotsToDelete.add slot
  for slot in slotsToDelete:
    dag.lightClientCache.bootstrap.del slot

  # Prune best `LightClientUpdate` that are no longer relevant
  let earliestPeriod = earliestSlot.sync_committee_period
  var periodsToDelete: seq[SyncCommitteePeriod]
  for period in dag.lightClientCache.best.keys:
    if period < earliestPeriod:
      periodsToDelete.add period
  for period in periodsToDelete:
    dag.lightClientCache.best.del period

  # Prune best `LightClientUpdate` referring to non-finalized sync committees
  # that are no longer relevant, i.e., orphaned or too old
  let firstNonFinalizedPeriod = dag.firstNonFinalizedPeriod
  var keysToDelete: seq[(SyncCommitteePeriod, Eth2Digest)]
  for (period, committeeRoot) in dag.lightClientCache.pendingBest.keys:
    if period < firstNonFinalizedPeriod:
      keysToDelete.add (period, committeeRoot)
  for key in keysToDelete:
    dag.lightClientCache.pendingBest.del key

proc initLightClientBootstrapForPeriod(
    dag: ChainDAGRef,
    period: SyncCommitteePeriod) =
  ## Compute and cache `LightClientBootstrap` data for all finalized
  ## epoch boundary blocks within a given sync committee period.
  if not dag.isNextSyncCommitteeFinalized(period):
    return
  let
    earliestSlot = dag.computeEarliestLightClientSlot
    periodStartSlot = period.start_slot
    periodEndSlot = periodStartSlot + SLOTS_PER_SYNC_COMMITTEE_PERIOD - 1
  if periodEndSlot < earliestSlot:
    return

  let startTick = Moment.now()
  debug "Caching LC bootstrap data for period", period
  defer:
    let endTick = Moment.now()
    debug "LC bootstrap data for period cached", period,
      cacheDur = endTick - startTick

  let
    lowSlot = max(periodStartSlot, earliestSlot)
    highSlot = min(periodEndSlot, dag.finalizedHead.blck.slot)
    lowBoundarySlot = lowSlot.nextEpochBoundarySlot
    highBoundarySlot = highSlot.nextEpochBoundarySlot
  var
    tmpState = assignClone(dag.headState)
    tmpCache: StateCache
    nextBoundarySlot = lowBoundarySlot
  while nextBoundarySlot <= highBoundarySlot:
    defer: nextBoundarySlot += SLOTS_PER_EPOCH
    let
      bsi = dag.getExistingBlockIdAtSlot(nextBoundarySlot).valueOr:
        dag.handleUnexpectedLightClientError(nextBoundarySlot)
        continue
      bid = bsi.bid
      boundarySlot = bid.slot.nextEpochBoundarySlot
    if boundarySlot == nextBoundarySlot and bid.slot >= lowSlot and
        not dag.lightClientCache.bootstrap.hasKey(bid.slot):
      var cachedBootstrap {.noinit.}: CachedLightClientBootstrap
      if not dag.updateExistingState(
          tmpState[], bid.atSlot, save = false, tmpCache):
        dag.handleUnexpectedLightClientError(bid.slot)
        continue
      withState(tmpState[]):
        when stateFork >= BeaconStateFork.Altair:
          state.data.build_proof(
            altair.CURRENT_SYNC_COMMITTEE_INDEX,
            cachedBootstrap.current_sync_committee_branch)
        else: raiseAssert "Unreachable"
      dag.lightClientCache.bootstrap[bid.slot] = cachedBootstrap

proc initLightClientUpdateForPeriod(
    dag: ChainDAGRef, period: SyncCommitteePeriod) =
  ## Compute and cache the best `LightClientUpdate` within a given
  ## sync committee period up through the finalized head block.
  ## Non-finalized blocks are processed incrementally.
  if not dag.isNextSyncCommitteeFinalized(period):
    return
  let
    earliestSlot = dag.computeEarliestLightClientSlot
    periodStartSlot = period.start_slot
    periodEndSlot = periodStartSlot + SLOTS_PER_SYNC_COMMITTEE_PERIOD - 1
  if periodEndSlot < earliestSlot:
    return
  if dag.lightClientCache.best.hasKey(period):
    return

  let startTick = Moment.now()
  debug "Computing best LC update for period", period
  proc logBest(endTick = Moment.now()) =
    # Using a helper function reduces code size as the `defer` beneath is
    # replicated on every `return`, and the log statement allocates another
    # copy of the arguments on the stack for each instantiation (~1 MB stack!)
    debug "Best LC update for period computed",
      period, update = dag.lightClientCache.best.getOrDefault(period),
      computeDur = endTick - startTick
  defer: logBest()

  proc maxParticipantsBlock(
      dag: ChainDAGRef, highBid: BlockId, lowSlot: Slot): Opt[BlockId] =
    ## Determine the earliest block with most sync committee signatures among
    ## ancestors of `highBid` with at least `lowSlot` as parent block slot.
    ## Return `err` if no block with `MIN_SYNC_COMMITTEE_PARTICIPANTS` exists.
    var
      maxParticipants = MIN_SYNC_COMMITTEE_PARTICIPANTS
      maxBid: Opt[BlockId]
      bid = highBid
    while true:
      let parentBid = dag.parent(bid).valueOr:
        break
      if parentBid.slot < lowSlot:
        break
      let
        bdata = dag.getExistingForkedBlock(bid).valueOr:
          dag.handleUnexpectedLightClientError(bid.slot)
          break
        numParticipants =
          withBlck(bdata):
            when stateFork >= BeaconStateFork.Altair:
              countOnes(blck.message.body.sync_aggregate.sync_committee_bits)
            else: raiseAssert "Unreachable"
      if numParticipants >= maxParticipants:
        maxParticipants = numParticipants
        maxBid = ok bid
      bid = parentBid
    maxBid

  # Determine the block in the period with highest sync committee participation
  let
    lowSlot = max(periodStartSlot, earliestSlot)
    highSlot = min(periodEndSlot, dag.finalizedHead.blck.slot)
    highBsi = dag.getExistingBlockIdAtSlot(highSlot).valueOr:
      dag.handleUnexpectedLightClientError(highSlot)
      return
    highBid = highBsi.bid
    maxParticipantsBid = dag.maxParticipantsBlock(highBid, lowSlot).valueOr:
      dag.lightClientCache.best[period] = default(altair.LightClientUpdate)
      return

  # The block with highest participation may refer to a `finalized_checkpoint`
  # in a different sync committee period. If that is the case, search for a
  # later block with a `finalized_checkpoint` within the given sync committee
  # period, despite it having a lower sync committee participation
  var
    tmpState = assignClone(dag.headState)
    signatureBid {.noinit.}, finalizedBid {.noinit.}: BlockId
  signatureBid.slot = FAR_FUTURE_SLOT
  finalizedBid.slot = FAR_FUTURE_SLOT
  while true:
    if signatureBid.slot == FAR_FUTURE_SLOT:
      signatureBid = maxParticipantsBid
    else:
      let nextLowSlot = signatureBid.slot + 1
      signatureBid = dag.maxParticipantsBlock(highBid, nextLowSlot).valueOr:
        signatureBid = maxParticipantsBid
        break
    let
      attestedBid = dag.existingParent(signatureBid).valueOr:
        dag.handleUnexpectedLightClientError(signatureBid.slot)
        continue
      finalizedEpoch = block:
        dag.withUpdatedExistingState(tmpState[], attestedBid.atSlot) do:
          withState(state):
            when stateFork >= BeaconStateFork.Altair:
              state.data.finalized_checkpoint.epoch
            else: raiseAssert "Unreachable"
        do:
          dag.handleUnexpectedLightClientError(attestedBid.slot)
          continue
      finalizedSlot = finalizedEpoch.start_slot
      finalizedBsi = dag.getBlockIdAtSlot(finalizedSlot).valueOr:
        # Could happen if latest block through finalized slot is before DAG tail
        continue
    if finalizedBid.slot >= lowSlot:
      finalizedBid = finalizedBsi.bid
      break
    if signatureBid == maxParticipantsBid:
      finalizedBid = finalizedBsi.bid # For fallback `break` at start of loop

  # Save best light client data for given period
  var update {.noinit.}: altair.LightClientUpdate
  let attestedBid = dag.existingParent(signatureBid).valueOr:
    dag.handleUnexpectedLightClientError(signatureBid.slot)
    return
  dag.withUpdatedExistingState(tmpState[], attestedBid.atSlot) do:
    let bdata = dag.getExistingForkedBlock(bid).valueOr:
      dag.handleUnexpectedLightClientError(bid.slot)
      return
    withStateAndBlck(state, bdata):
      when stateFork >= BeaconStateFork.Altair:
        update.attested_header = blck.toBeaconBlockHeader()
        update.next_sync_committee = state.data.next_sync_committee
        state.data.build_proof(
          altair.NEXT_SYNC_COMMITTEE_INDEX,
          update.next_sync_committee_branch)
        if finalizedBid.slot == FAR_FUTURE_SLOT:
          update.finality_branch.reset()
        else:
          state.data.build_proof(
            altair.FINALIZED_ROOT_INDEX,
            update.finality_branch)
      else: raiseAssert "Unreachable"
  do:
    dag.handleUnexpectedLightClientError(attestedBid.slot)
    return
  if finalizedBid.slot == FAR_FUTURE_SLOT or finalizedBid.slot == GENESIS_SLOT:
    update.finalized_header.reset()
  else:
    let bdata = dag.getExistingForkedBlock(finalizedBid).valueOr:
      dag.handleUnexpectedLightClientError(finalizedBid.slot)
      return
    withBlck(bdata):
      update.finalized_header = blck.toBeaconBlockHeader()
  let bdata = dag.getExistingForkedBlock(signatureBid).valueOr:
    dag.handleUnexpectedLightClientError(signatureBid.slot)
    return
  withBlck(bdata):
    when stateFork >= BeaconStateFork.Altair:
      update.sync_aggregate = blck.asSigned().message.body.sync_aggregate
    else: raiseAssert "Unreachable"
  update.signature_slot = signatureBid.slot
  dag.lightClientCache.best[period] = update

proc initLightClientCache*(dag: ChainDAGRef) =
  ## Initialize cached light client data
  if dag.importLightClientData == ImportLightClientData.None:
    return
  dag.lightClientCache.importTailSlot = dag.tail.slot
  if dag.importLightClientData == ImportLightClientData.OnlyNew:
    dag.lightClientCache.importTailSlot = dag.head.slot
  var earliestSlot = dag.computeEarliestLightClientSlot
  if dag.head.slot < earliestSlot:
    return

  # Import light client data for finalized period through finalized head
  let
    finalizedSlot = dag.finalizedHead.slot
    finalizedPeriod = finalizedSlot.sync_committee_period
  dag.initLightClientBootstrapForPeriod(finalizedPeriod)
  dag.initLightClientUpdateForPeriod(finalizedPeriod)

  let lightClientStartTick = Moment.now()
  debug "Initializing cached light client data"

  template handleUnexpectedError(buggedBid: BlockId) =
    # Light client data is expected to be available from `earliestSlot` onward.
    # If there is an error, adjust `importTailSlot` to avoid failed lookups of
    # cached light client data. For new blocks / states, the caches can always
    # be updated incrementally, because those blocks / states are passed in
    # directly. It is only historical blocks (or sync committees) that depend
    # on a potentially corrupted database.
    doAssert buggedBid.slot > dag.lightClientCache.importTailSlot
    dag.handleUnexpectedLightClientError(buggedBid.slot)
    earliestSlot = dag.computeEarliestLightClientSlot

  # Build list of block to process.
  # As it is slow to load states in descending order,
  # build a reverse todo list to then process them in ascending order
  let lowSlot = max(finalizedSlot, earliestSlot)
  var
    blocks = newSeqOfCap[BlockId](dag.head.slot - lowSlot + 1)
    bid = dag.head.bid
  while bid.slot > lowSlot:
    blocks.add bid
    bid = dag.existingParent(bid).valueOr:
      handleUnexpectedError(bid)
      break
  if bid.slot == lowSlot:
    blocks.add bid

  # Process blocks (reuses `dag.headState`, but restores it to the current head)
  var
    tmpState = assignClone(dag.headState)
    tmpCache, cache: StateCache
    oldCheckpoint: Checkpoint
    cpIndex = 0
  for i in countdown(blocks.high, blocks.low):
    bid = blocks[i]
    if not dag.updateExistingState(
        dag.headState, bid.atSlot, save = false, cache):
      handleUnexpectedError(bid)
      continue
    let bdata = dag.getExistingForkedBlock(bid).valueOr:
      handleUnexpectedError(bid)
      continue
    withStateAndBlck(dag.headState, bdata):
      when stateFork >= BeaconStateFork.Altair:
        # Cache light client data (non-finalized blocks may refer to this)
        dag.cacheLightClientData(state, blck.toBlockId())

        # Create `LightClientUpdate` instances
        if bid.slot != lowSlot:
          dag.createLightClientUpdates(state, blck, parentBid = blocks[i + 1])
      else: raiseAssert "Unreachable"

  let lightClientEndTick = Moment.now()
  debug "Initialized cached light client data",
    initDur = lightClientEndTick - lightClientStartTick

  # Import historic data
  if dag.importLightClientData == ImportLightClientData.Full:
    let earliestPeriod = earliestSlot.sync_committee_period
    for period in earliestPeriod ..< finalizedPeriod:
      dag.initLightClientBootstrapForPeriod(period)
      dag.initLightClientUpdateForPeriod(period)

proc getLightClientBootstrap*(
    dag: ChainDAGRef,
    blockRoot: Eth2Digest): Opt[altair.LightClientBootstrap] =
  if not dag.serveLightClientData:
    return err()

  let bdata = dag.getForkedBlock(blockRoot).valueOr:
    debug "LC bootstrap unavailable: Block not found", blockRoot
    return err()

  withBlck(bdata):
    let slot = blck.message.slot
    when stateFork >= BeaconStateFork.Altair:
      let earliestSlot = dag.computeEarliestLightClientSlot
      if slot < earliestSlot:
        debug "LC bootstrap unavailable: Block too old", slot
        return err()
      if slot > dag.finalizedHead.blck.slot:
        debug "LC bootstrap unavailable: Not finalized", blockRoot
        return err()
      var cachedBootstrap = dag.lightClientCache.bootstrap.getOrDefault(slot)
      if cachedBootstrap.current_sync_committee_branch.isZeroMemory:
        if dag.importLightClientData == ImportLightClientData.OnDemand:
          let bsi = ? dag.getExistingBlockIdAtSlot(slot)
          var tmpState = assignClone(dag.headState)
          dag.withUpdatedExistingState(tmpState[], bsi) do:
            withState(state):
              when stateFork >= BeaconStateFork.Altair:
                state.data.build_proof(
                  altair.CURRENT_SYNC_COMMITTEE_INDEX,
                  cachedBootstrap.current_sync_committee_branch)
              else: raiseAssert "Unreachable"
          do: return err()
          dag.lightClientCache.bootstrap[slot] = cachedBootstrap
        else:
          debug "LC bootstrap unavailable: Data not cached", slot
          return err()

      let period = slot.sync_committee_period
      var tmpState = assignClone(dag.headState)
      var bootstrap {.noinit.}: altair.LightClientBootstrap
      bootstrap.header =
        blck.toBeaconBlockHeader()
      bootstrap.current_sync_committee =
        ? dag.existingCurrentSyncCommitteeForPeriod(tmpState[], period)
      bootstrap.current_sync_committee_branch =
        cachedBootstrap.current_sync_committee_branch
      return ok bootstrap
    else:
      debug "LC bootstrap unavailable: Block before Altair", slot
      return err()

proc getLightClientUpdateForPeriod*(
    dag: ChainDAGRef,
    period: SyncCommitteePeriod): Option[altair.LightClientUpdate] =
  if not dag.serveLightClientData:
    return

  if not dag.lightClientCache.best.hasKey(period):
    if dag.importLightClientData == ImportLightClientData.OnDemand:
      dag.initLightClientUpdateForPeriod(period)
  result = some(dag.lightClientCache.best.getOrDefault(period))
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result.reset()

proc getLightClientFinalityUpdate*(
    dag: ChainDAGRef): Option[altair.LightClientFinalityUpdate] =
  if not dag.serveLightClientData:
    return

  result = some(dag.lightClientCache.latest)
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result.reset()

proc getLightClientOptimisticUpdate*(
    dag: ChainDAGRef): Option[altair.LightClientOptimisticUpdate] =
  if not dag.serveLightClientData:
    return

  result = some(dag.lightClientCache.latest.toOptimistic)
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result.reset()
