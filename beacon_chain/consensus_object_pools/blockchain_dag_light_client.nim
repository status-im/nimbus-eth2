# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Status libraries
  stew/bitops2,
  # Beacon chain internals
  ../spec/forks,
  ../beacon_chain_db_light_client,
  "."/[block_pools_types, blockchain_dag]

logScope: topics = "chaindag_lc"

template nextEpochBoundarySlot(slot: Slot): Slot =
  ## Compute the first possible epoch boundary state slot of a `Checkpoint`
  ## referring to a block at given slot.
  (slot + (SLOTS_PER_EPOCH - 1)).epoch.start_slot

func hasCurrentSyncCommitteeBranch(dag: ChainDAGRef, slot: Slot): bool =
  let epoch = dag.cfg.consensusForkAtEpoch(slot.epoch)
  withLcDataFork(lcDataForkAtConsensusFork(epoch)):
    when lcDataFork > LightClientDataFork.None:
      hasCurrentSyncCommitteeBranch[lcDataFork.CurrentSyncCommitteeBranch](
        dag.lcDataStore.db, slot)
    else:
      true

proc updateExistingState(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bsi: BlockSlotId,
    save: bool, cache: var StateCache): bool =
  ## Wrapper around `updateState` for states expected to exist.
  let ok = dag.updateState(state, bsi, save, cache)
  if not ok:
    error "State failed to load unexpectedly",
      bsi, tail = dag.tail.slot, backfill = shortLog(dag.backfill)
    doAssert strictVerification notin dag.updateFlags
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
      error "State failed to load unexpectedly",
        bsi, tail = dag.tail.slot, backfill = shortLog(dag.backfill)
      doAssert strictVerification notin dag.updateFlags
      failureBody

proc getExistingBlockIdAtSlot(dag: ChainDAGRef, slot: Slot): Opt[BlockSlotId] =
  ## Wrapper around `getBlockIdAtSlot` for blocks expected to exist.
  let bsi = dag.getBlockIdAtSlot(slot)
  if bsi.isNone:
    error "Block failed to load unexpectedly",
      slot, tail = dag.tail.slot, backfill = shortLog(dag.backfill)
    doAssert strictVerification notin dag.updateFlags
  bsi

proc existingParent(dag: ChainDAGRef, bid: BlockId): Opt[BlockId] =
  ## Wrapper around `parent` for parents known to exist.
  let parent = dag.parent(bid)
  if parent.isNone:
    error "Parent failed to load unexpectedly",
      bid, tail = dag.tail.slot, backfill = shortLog(dag.backfill)
    doAssert strictVerification notin dag.updateFlags
  parent

proc getExistingForkedBlock(
    dag: ChainDAGRef, bid: BlockId): Opt[ForkedTrustedSignedBeaconBlock] =
  ## Wrapper around `getForkedBlock` for blocks expected to exist.
  let bdata = dag.getForkedBlock(bid)
  if bdata.isNone:
    error "Block failed to load unexpectedly",
      bid, tail = dag.tail.slot, backfill = shortLog(dag.backfill)
    doAssert strictVerification notin dag.updateFlags
  bdata

proc existingCurrentSyncCommitteeForPeriod(
    dag: ChainDAGRef,
    tmpState: var ForkedHashedBeaconState,
    period: SyncCommitteePeriod): Opt[SyncCommittee] =
  ## Wrapper around `currentSyncCommitteeForPeriod` for states known to exist.
  let syncCommittee = dag.currentSyncCommitteeForPeriod(tmpState, period)
  if syncCommittee.isNone:
    error "Current sync committee failed to load unexpectedly",
      period, tail = dag.tail.slot, backfill = shortLog(dag.backfill)
    doAssert strictVerification notin dag.updateFlags
  syncCommittee

func pruneToCapacity[A, B](t: var OrderedTable[A, B], capacity: int) =
  while t.len > capacity:
    var key {.noinit.}: A
    for k in t.keys:
      key = k
      break
    t.del(key)

func cacheRecentLightClientHeader(
    dag: ChainDAGRef, bid: BlockId, header: ForkedLightClientHeader) =
  dag.lcDataStore.cache.recentHeaders[bid] = header
  dag.lcDataStore.cache.recentHeaders.pruneToCapacity(10)

func cacheRecentSyncAggregate(
    dag: ChainDAGRef, bid: BlockId, syncAggregate: SyncAggregate) =
  dag.lcDataStore.cache.recentSyncAggregates[bid] = syncAggregate
  dag.lcDataStore.cache.recentSyncAggregates.pruneToCapacity(5)

func lightClientHeader(
    blck: ForkyTrustedSignedBeaconBlock): ForkedLightClientHeader =
  const lcDataFork = max(
    lcDataForkAtConsensusFork(typeof(blck).kind), LightClientDataFork.Altair)
  ForkedLightClientHeader.init(blck.toLightClientHeader(lcDataFork))

func sync_aggregate(
    blck: ForkyTrustedSignedBeaconBlock): SyncAggregate =
  blck.asSigned().message.body.sync_aggregate

proc getExistingLightClientHeader(
    dag: ChainDAGRef, bid: BlockId): ForkedLightClientHeader =
  var res = dag.lcDataStore.cache.recentHeaders.getOrDefault(bid)
  if res.kind > LightClientDataFork.None:
    return res

  let bdata = dag.getExistingForkedBlock(bid)
  if bdata.isNone:
    return res

  res = withBlck(bdata.get): forkyBlck.lightClientHeader()
  dag.cacheRecentLightClientHeader(bid, res)
  res

proc getExistingSyncAggregate(
    dag: ChainDAGRef, bid: BlockId): Opt[SyncAggregate] =
  if bid in dag.lcDataStore.cache.recentSyncAggregates:
    return Opt.some dag.lcDataStore.cache.recentSyncAggregates.getOrDefault(bid)

  let bdata = dag.getExistingForkedBlock(bid)
  if bdata.isNone:
    return Opt.none(SyncAggregate)

  let res = withBlck(bdata.get):
    when consensusFork >= ConsensusFork.Altair:
      Opt.some forkyBlck.sync_aggregate()
    else:
      return Opt.none(SyncAggregate)
  dag.cacheRecentSyncAggregate(bid, res.get)
  res

proc initLightClientDataStore*(
    config: LightClientDataConfig,
    cfg: RuntimeConfig,
    db: LightClientDataDB): LightClientDataStore =
  ## Initialize light client data store.
  let
    defaultMaxPeriods = cfg.defaultLightClientDataMaxPeriods
    maxPeriods = config.maxPeriods.get(distinctBase(SyncCommitteePeriod.high))
  if maxPeriods < defaultMaxPeriods:
    warn "Retaining fewer periods than recommended",
      lightClientDataMaxPeriods = config.maxPeriods,
      specRecommendation = defaultMaxPeriods

  LightClientDataStore(
    db: db,
    serve: config.serve,
    importMode: config.importMode,
    maxPeriods: maxPeriods,
    onLightClientFinalityUpdate: config.onLightClientFinalityUpdate,
    onLightClientOptimisticUpdate: config.onLightClientOptimisticUpdate)

func targetLightClientTailSlot(dag: ChainDAGRef): Slot =
  ## Earliest slot for which light client data is retained.
  let
    maxPeriods = dag.lcDataStore.maxPeriods
    headPeriod = dag.head.slot.sync_committee_period
    lowSlot = dag.cfg.ALTAIR_FORK_EPOCH.start_slot
    tail = max(headPeriod + 1, maxPeriods.SyncCommitteePeriod) - maxPeriods
  max(tail.start_slot, lowSlot)

func handleUnexpectedLightClientError(dag: ChainDAGRef, buggedSlot: Slot) =
  ## If there is an unexpected error, adjust `tailSlot` to keep track of the
  ## section for which complete light client data is available, and to avoid
  ## failed lookups of cached light client data.
  doAssert strictVerification notin dag.updateFlags
  if buggedSlot >= dag.lcDataStore.cache.tailSlot:
    dag.lcDataStore.cache.tailSlot = buggedSlot + 1

proc initLightClientBootstrapForPeriod(
    dag: ChainDAGRef,
    period: SyncCommitteePeriod): Opt[void] =
  ## Compute and cache `LightClientBootstrap` data for all finalized
  ## epoch boundary blocks within a given sync committee period.
  if dag.finalizedHead.slot < period.start_slot:
    return ok()
  if dag.finalizedHead.slot < dag.cfg.ALTAIR_FORK_EPOCH.start_slot:
    return ok()
  if dag.lcDataStore.db.isPeriodSealed(period):
    return ok()

  let startTick = Moment.now()
  debug "Caching historic LC bootstrap data", period
  defer:
    let endTick = Moment.now()
    debug "Historic LC bootstrap data cached", period,
      cacheDur = endTick - startTick

  let
    periodStartSlot = period.start_slot
    periodEndSlot = periodStartSlot + SLOTS_PER_SYNC_COMMITTEE_PERIOD - 1
    tailSlot = max(dag.targetLightClientTailSlot, dag.tail.slot)
    lowSlot = max(periodStartSlot, tailSlot)
    highSlot = min(periodEndSlot, dag.finalizedHead.blck.slot)
    lowBoundarySlot = lowSlot.nextEpochBoundarySlot
    highBoundarySlot = highSlot.nextEpochBoundarySlot
  var
    res = ok()
    tmpState = assignClone(dag.headState)
    tmpCache: StateCache
    nextBoundarySlot = lowBoundarySlot
  while nextBoundarySlot <= highBoundarySlot:
    defer: nextBoundarySlot += SLOTS_PER_EPOCH
    let
      bsi = dag.getExistingBlockIdAtSlot(nextBoundarySlot).valueOr:
        dag.handleUnexpectedLightClientError(nextBoundarySlot)
        res.err()
        continue
      bid = bsi.bid
      boundarySlot = bid.slot.nextEpochBoundarySlot
    if boundarySlot == nextBoundarySlot and bid.slot >= lowSlot and
        not dag.hasCurrentSyncCommitteeBranch(bid.slot):
      let bdata = dag.getExistingForkedBlock(bid).valueOr:
        dag.handleUnexpectedLightClientError(bid.slot)
        res.err()
        continue
      if not dag.updateExistingState(
          tmpState[], bid.atSlot, save = false, tmpCache):
        dag.handleUnexpectedLightClientError(bid.slot)
        res.err()
        continue
      withStateAndBlck(tmpState[], bdata):
        when consensusFork >= ConsensusFork.Altair:
          const lcDataFork = lcDataForkAtConsensusFork(consensusFork)
          if not dag.lcDataStore.db.hasSyncCommittee(period):
            dag.lcDataStore.db.putSyncCommittee(
              period, forkyState.data.current_sync_committee)
          dag.lcDataStore.db.putHeader(
            forkyBlck.toLightClientHeader(lcDataFork))
          dag.lcDataStore.db.putCurrentSyncCommitteeBranch(
            bid.slot, forkyState.data.build_proof(
              lcDataFork.CURRENT_SYNC_COMMITTEE_GINDEX).get)
        else: raiseAssert "Unreachable"
  res

proc initLightClientUpdateForPeriod(
    dag: ChainDAGRef, period: SyncCommitteePeriod): Opt[void] =
  ## Compute and cache the best `LightClientUpdate` within a given
  ## sync committee period up through the finalized head block.
  ## Non-finalized blocks are processed incrementally by other functions.
  ## Should not be called for periods for which incremental computation started.
  if dag.finalizedHead.slot < period.start_slot:
    return ok()
  if dag.finalizedHead.slot < dag.cfg.ALTAIR_FORK_EPOCH.start_slot:
    return ok()
  if dag.lcDataStore.db.isPeriodSealed(period):
    return ok()

  let startTick = Moment.now()
  debug "Computing best historic LC update", period
  proc logBest(endTick = Moment.now()) =
    # Using a helper function reduces code size as the `defer` beneath is
    # replicated on every `return`, and the log statement allocates another
    # copy of the arguments on the stack for each instantiation (~1 MB stack!)
    debug "Best historic LC update computed",
      period, update = dag.lcDataStore.db.getBestUpdate(period),
      computeDur = endTick - startTick
  defer: logBest()

  proc maxParticipantsBlock(
      dag: ChainDAGRef, highBid: BlockId, lowSlot: Slot
  ): tuple[bid: Opt[BlockId], res: Opt[void]] =
    ## Determine the earliest block with most sync committee signatures among
    ## ancestors of `highBid` with at least `lowSlot` as parent block slot.
    ## Return `err` if no block with `MIN_SYNC_COMMITTEE_PARTICIPANTS` exists.
    ## `res` in result indicates whether no unexpected errors occurred.
    var
      maxParticipants = MIN_SYNC_COMMITTEE_PARTICIPANTS
      maxBid: Opt[BlockId]
      res = Opt[void].ok()
      bid = highBid
    while true:
      if bid.slot <= lowSlot:
        break
      let parentBid = dag.existingParent(bid).valueOr:
        dag.handleUnexpectedLightClientError(bid.slot)
        res.err()
        break
      if parentBid.slot < lowSlot:
        break
      let
        bdata = dag.getExistingForkedBlock(bid).valueOr:
          dag.handleUnexpectedLightClientError(bid.slot)
          res.err()
          break
        numParticipants =
          withBlck(bdata):
            when consensusFork >= ConsensusFork.Altair:
              forkyBlck.message.body.sync_aggregate.num_active_participants
            else: raiseAssert "Unreachable"
      if numParticipants >= maxParticipants:
        maxParticipants = numParticipants
        maxBid.ok bid
      bid = parentBid
    (bid: maxBid, res: res)

  # Determine the block in the period with highest sync committee participation
  let
    periodStartSlot = period.start_slot
    periodEndSlot = periodStartSlot + SLOTS_PER_SYNC_COMMITTEE_PERIOD - 1
    tailSlot = max(dag.targetLightClientTailSlot, dag.tail.slot)
    lowSlot = max(periodStartSlot, tailSlot)
    highSlot = min(periodEndSlot, dag.finalizedHead.blck.slot)
    highBsi = dag.getExistingBlockIdAtSlot(highSlot).valueOr:
      dag.handleUnexpectedLightClientError(highSlot)
      return err()
    highBid = highBsi.bid
    maxParticipantsRes = dag.maxParticipantsBlock(highBid, lowSlot)
    maxParticipantsBid = maxParticipantsRes.bid.valueOr:
      const update = default(ForkedLightClientUpdate)
      dag.lcDataStore.db.putBestUpdate(period, update)
      return maxParticipantsRes.res

  # The block with highest participation may refer to a `finalized_checkpoint`
  # in a different sync committee period. If that is the case, search for a
  # later block with a `finalized_checkpoint` within the given sync committee
  # period, despite it having a lower sync committee participation
  var
    res = ok()
    tmpState = assignClone(dag.headState)
    signatureBid {.noinit.}, finalizedBid {.noinit.}: BlockId
  signatureBid.slot = FAR_FUTURE_SLOT
  finalizedBid.slot = FAR_FUTURE_SLOT
  while true:
    if signatureBid.slot == FAR_FUTURE_SLOT:
      signatureBid = maxParticipantsBid
    else:
      let signatureRes = dag.maxParticipantsBlock(highBid, signatureBid.slot)
      if signatureRes.res.isErr:
        res.err()
      signatureBid = signatureRes.bid.valueOr:
        signatureBid = maxParticipantsBid
        break
    let
      attestedBid = dag.existingParent(signatureBid).valueOr:
        dag.handleUnexpectedLightClientError(signatureBid.slot)
        res.err()
        continue
      finalizedEpoch = block:
        dag.withUpdatedExistingState(tmpState[], attestedBid.atSlot) do:
          withState(updatedState):
            when consensusFork >= ConsensusFork.Altair:
              forkyState.data.finalized_checkpoint.epoch
            else: raiseAssert "Unreachable"
        do:
          dag.handleUnexpectedLightClientError(attestedBid.slot)
          res.err()
          continue
      finalizedSlot = finalizedEpoch.start_slot
      finalizedBsi =
        if finalizedSlot >= max(dag.tail.slot, dag.backfill.slot):
          dag.getExistingBlockIdAtSlot(finalizedSlot).valueOr:
            dag.handleUnexpectedLightClientError(finalizedSlot)
            res.err()
            continue
        else:
          continue
    if finalizedBsi.bid.slot >= lowSlot:
      finalizedBid = finalizedBsi.bid
      break
    if signatureBid == maxParticipantsBid:
      finalizedBid = finalizedBsi.bid # For fallback `break` at start of loop

  # Save best light client data for given period
  var update {.noinit.}: ForkedLightClientUpdate
  let attestedBid = dag.existingParent(signatureBid).valueOr:
    dag.handleUnexpectedLightClientError(signatureBid.slot)
    return err()
  dag.withUpdatedExistingState(tmpState[], attestedBid.atSlot) do:
    let bdata = dag.getExistingForkedBlock(bid).valueOr:
      dag.handleUnexpectedLightClientError(bid.slot)
      return err()
    withStateAndBlck(updatedState, bdata):
      when consensusFork >= ConsensusFork.Altair:
        const lcDataFork = lcDataForkAtConsensusFork(consensusFork)
        update = ForkedLightClientUpdate.init(lcDataFork.LightClientUpdate(
          attested_header: forkyBlck.toLightClientHeader(lcDataFork),
          next_sync_committee: forkyState.data.next_sync_committee,
          next_sync_committee_branch: forkyState.data.build_proof(
            lcDataFork.NEXT_SYNC_COMMITTEE_GINDEX).get,
          finality_branch:
            if finalizedBid.slot != FAR_FUTURE_SLOT:
              forkyState.data.build_proof(lcDataFork.FINALIZED_ROOT_GINDEX).get
            else:
              default(lcDataFork.FinalityBranch)))
      else: raiseAssert "Unreachable"
  do:
    dag.handleUnexpectedLightClientError(attestedBid.slot)
    return err()
  if finalizedBid.slot != FAR_FUTURE_SLOT and finalizedBid.slot != GENESIS_SLOT:
    let bdata = dag.getExistingForkedBlock(finalizedBid).valueOr:
      dag.handleUnexpectedLightClientError(finalizedBid.slot)
      return err()
    withBlck(bdata):
      withForkyUpdate(update):
        when lcDataFork > LightClientDataFork.None:
          when lcDataFork >= lcDataForkAtConsensusFork(consensusFork):
            forkyUpdate.finalized_header =
              forkyBlck.toLightClientHeader(lcDataFork)
          else: raiseAssert "Unreachable"
  let bdata = dag.getExistingForkedBlock(signatureBid).valueOr:
    dag.handleUnexpectedLightClientError(signatureBid.slot)
    return err()
  withBlck(bdata):
    when consensusFork >= ConsensusFork.Altair:
      withForkyUpdate(update):
        when lcDataFork > LightClientDataFork.None:
          forkyUpdate.sync_aggregate =
            forkyBlck.asSigned().message.body.sync_aggregate
    else: raiseAssert "Unreachable"
  withForkyUpdate(update):
    when lcDataFork > LightClientDataFork.None:
      forkyUpdate.signature_slot = signatureBid.slot

  dag.lcDataStore.db.putBestUpdate(period, update)
  res

proc initLightClientDataForPeriod(
    dag: ChainDAGRef, period: SyncCommitteePeriod): Opt[void] =
  ## Import light client data for a given sync committee period.
  if dag.lcDataStore.db.isPeriodSealed(period):
    return ok()
  let
    fullPeriodCovered = (dag.finalizedHead.slot >= (period + 1).start_slot)
    res1 = dag.initLightClientBootstrapForPeriod(period)
    res2 = dag.initLightClientUpdateForPeriod(period)
  if res1.isErr or res2.isErr:
    return err()
  if fullPeriodCovered:
    dag.lcDataStore.db.sealPeriod(period)
  ok()

proc getLightClientData(
    dag: ChainDAGRef,
    bid: BlockId): CachedLightClientData =
  ## Fetch cached light client data about a given block.
  ## Data must be cached (`cacheLightClientData`) before calling this function.
  try: dag.lcDataStore.cache.data[bid]
  except KeyError: raiseAssert "Unreachable"

proc cacheLightClientData(
    dag: ChainDAGRef,
    state: ForkyHashedBeaconState,
    blck: ForkyTrustedSignedBeaconBlock,
    current_period_best_update: ref ForkedLightClientUpdate,
    latest_signature_slot: Slot) =
  ## Cache data for a given block and its post-state to speed up creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances that refer to this
  ## block and state.
  const lcDataFork = lcDataForkAtConsensusFork(typeof(state).kind)
  let
    bid = blck.toBlockId()
    cachedData = CachedLightClientData(
      current_sync_committee_branch: normalize_merkle_branch(
        state.data.build_proof(lcDataFork.CURRENT_SYNC_COMMITTEE_GINDEX).get,
        LightClientDataFork.high.CURRENT_SYNC_COMMITTEE_GINDEX),
      next_sync_committee_branch: normalize_merkle_branch(
        state.data.build_proof(lcDataFork.NEXT_SYNC_COMMITTEE_GINDEX).get,
        LightClientDataFork.high.NEXT_SYNC_COMMITTEE_GINDEX),
      finalized_slot:
        state.data.finalized_checkpoint.epoch.start_slot,
      finality_branch: normalize_merkle_branch(
        state.data.build_proof(lcDataFork.FINALIZED_ROOT_GINDEX).get,
        LightClientDataFork.high.FINALIZED_ROOT_GINDEX),
      current_period_best_update:
        current_period_best_update,
      latest_signature_slot:
        latest_signature_slot)
  if dag.lcDataStore.cache.data.hasKeyOrPut(bid, cachedData):
    doAssert false, "Redundant `cacheLightClientData` call"
  dag.cacheRecentLightClientHeader(bid, blck.lightClientHeader())
  dag.cacheRecentSyncAggregate(bid, blck.sync_aggregate())

func shouldImportLcData(dag: ChainDAGRef): bool =
  dag.lcDataStore.importMode != LightClientDataImportMode.None and
  dag.cfg.ALTAIR_FORK_EPOCH != FAR_FUTURE_EPOCH

proc deleteLightClientData*(dag: ChainDAGRef, bid: BlockId) =
  ## Delete cached light client data for a given block. This needs to be called
  ## when a block becomes unreachable due to finalization of a different fork.
  if not dag.shouldImportLcData:
    return

  dag.lcDataStore.cache.data.del bid

proc assignLightClientData(
    obj: var SomeForkedLightClientUpdateWithFinality,
    dag: ChainDAGRef,
    attested_bid: BlockId,
    signature_slot: Slot,
    sync_aggregate: SyncAggregate,
    next_sync_committee = Opt.none(SyncCommittee)): Opt[void] {.discardable.} =
  ## Update `obj` based on `attested_bid` / `signature_slot` / `sync_aggregate`
  ## and `next_sync_committee` (for full `LightClientUpdate`).
  ## Return `ok` if there were changes; `err` otherwise.

  # If `sync_aggregate` is unchanged, the rest is also unchanged
  withForkyObject(obj):
    when lcDataFork > LightClientDataFork.None:
      if forkyObject.signature_slot == signature_slot and
          forkyObject.sync_aggregate == sync_aggregate:
        return err()

  # Bump `attested_header`; if it is unchanged, finality info is also unchanged
  let new_attested_header = withForkyObject(obj):
    when lcDataFork > LightClientDataFork.None:
      template beacon_header: untyped = forkyObject.attested_header.beacon
      beacon_header.slot != attested_bid.slot or
      beacon_header.hash_tree_root() != attested_bid.root
    else:
      true
  if new_attested_header:
    let att_header = dag.getExistingLightClientHeader(attested_bid)
    withForkyHeader(att_header):
      when lcDataFork > LightClientDataFork.None:
        obj.migrateToDataFork(lcDataFork)
        obj.forky(lcDataFork).attested_header = forkyHeader
      else:
        dag.handleUnexpectedLightClientError(attested_bid.slot)
        return err()
    var attested_data = dag.getLightClientData(attested_bid)
    when obj is SomeForkedLightClientUpdateWithSyncCommittee:
      doAssert next_sync_committee.isSome
      withForkyObject(obj):
        when lcDataFork > LightClientDataFork.None:
          forkyObject.next_sync_committee =
            next_sync_committee.get
          forkyObject.next_sync_committee_branch = normalize_merkle_branch(
            attested_data.next_sync_committee_branch,
            lcDataFork.NEXT_SYNC_COMMITTEE_GINDEX)
    else:
      doAssert next_sync_committee.isNone
    var finalized_slot = attested_data.finalized_slot
    withForkyObject(obj):
      when lcDataFork > LightClientDataFork.None:
        if finalized_slot == forkyObject.finalized_header.beacon.slot:
          forkyObject.finality_branch = normalize_merkle_branch(
            attested_data.finality_branch,
            lcDataFork.FINALIZED_ROOT_GINDEX)
        elif finalized_slot < max(dag.tail.slot, dag.backfill.slot):
          forkyObject.finalized_header.reset()
          forkyObject.finality_branch.reset()
        else:
          let finalized_bsi = dag.getExistingBlockIdAtSlot(finalized_slot)
          if finalized_bsi.isNone:
            dag.handleUnexpectedLightClientError(finalized_slot)
            forkyObject.finalized_header.reset()
            forkyObject.finality_branch.reset()
          else:
            let finalized_bid = finalized_bsi.get.bid
            if finalized_bid.slot != finalized_slot:
              # Empty slots at end of epoch, update cache for latest block slot
              finalized_slot = finalized_bid.slot
              attested_data.finalized_slot = finalized_slot
              dag.lcDataStore.cache.data[attested_bid] = attested_data
            if finalized_slot == forkyObject.finalized_header.beacon.slot:
              forkyObject.finality_branch = normalize_merkle_branch(
                attested_data.finality_branch,
                lcDataFork.FINALIZED_ROOT_GINDEX)
            elif finalized_slot == GENESIS_SLOT:
              forkyObject.finalized_header.reset()
              forkyObject.finality_branch = normalize_merkle_branch(
                attested_data.finality_branch,
                lcDataFork.FINALIZED_ROOT_GINDEX)
            else:
              var fin_header = dag.getExistingLightClientHeader(finalized_bid)
              if fin_header.kind == LightClientDataFork.None:
                dag.handleUnexpectedLightClientError(finalized_bid.slot)
                forkyObject.finalized_header.reset()
                forkyObject.finality_branch.reset()
              else:
                fin_header.migrateToDataFork(lcDataFork)
                forkyObject.finalized_header = fin_header.forky(lcDataFork)
                forkyObject.finality_branch = normalize_merkle_branch(
                  attested_data.finality_branch,
                  lcDataFork.FINALIZED_ROOT_GINDEX)
  withForkyObject(obj):
    when lcDataFork > LightClientDataFork.None:
      forkyObject.sync_aggregate = sync_aggregate
      forkyObject.signature_slot = signature_slot
  ok()

proc createLightClientUpdate(
    dag: ChainDAGRef,
    state: ForkyHashedBeaconState,
    blck: ForkyTrustedSignedBeaconBlock,
    parent_bid: BlockId) =
  ## Create `LightClientUpdate` instances for a given block and its post-state,
  ## and keep track of best / latest ones. Data about the parent block's
  ## post-state must be cached (`cacheLightClientData`) before calling this.

  # Verify attested block (parent) is recent enough and that state is available
  template attested_bid(): auto = parent_bid
  let attested_slot = attested_bid.slot
  if attested_slot < dag.lcDataStore.cache.tailSlot:
    dag.cacheLightClientData(state, blck,
      current_period_best_update = (ref ForkedLightClientUpdate)(),
      latest_signature_slot = GENESIS_SLOT)
    return

  # If sync committee period changed, reset `best`
  let
    attested_period = attested_slot.sync_committee_period
    signature_slot = blck.message.slot
    signature_period = signature_slot.sync_committee_period
    attested_data = dag.getLightClientData(attested_bid)
  var best =
    if attested_period != signature_period:
      (ref ForkedLightClientUpdate)()
    else:
      attested_data.current_period_best_update

  # If sync committee does not have sufficient participants, do not bump latest
  template sync_aggregate(): auto = blck.asSigned().message.body.sync_aggregate
  let
    num_active_participants = sync_aggregate.num_active_participants.uint64
    latest_signature_slot =
      if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
        attested_data.latest_signature_slot
      else:
        signature_slot

  # To update `best`, sync committee must have sufficient participants, and
  # `signature_slot` must be in `attested_slot`'s sync committee period
  if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS or
      attested_period != signature_period:
    dag.cacheLightClientData(state, blck,
      current_period_best_update = best,
      latest_signature_slot = latest_signature_slot)
    return

  # Check if light client data improved
  let
    finalized_slot = attested_data.finalized_slot
    finalized_bsi =
      if finalized_slot >= max(dag.tail.slot, dag.backfill.slot):
        dag.getExistingBlockIdAtSlot(finalized_slot)
      else:
        Opt.none(BlockSlotId)
    has_finality =
      finalized_bsi.isSome and
      finalized_bsi.get.bid.slot >= max(dag.tail.slot, dag.backfill.slot)
    meta = LightClientUpdateMetadata(
      attested_slot: attested_slot,
      finalized_slot: finalized_slot,
      signature_slot: signature_slot,
      has_sync_committee: true,
      has_finality: has_finality,
      num_active_participants: num_active_participants)
    is_better = is_better_data(
      meta, attested_data.current_period_best_update[].toMeta())
  if not is_better:
    dag.cacheLightClientData(state, blck,
      current_period_best_update = best,
      latest_signature_slot = latest_signature_slot)
    return

  # Update best light client data for current sync committee period
  best = newClone attested_data.current_period_best_update[]
  let res = best[].assignLightClientData(
    dag, attested_bid, signature_slot, sync_aggregate,
    Opt.some(state.data.next_sync_committee))
  if not res.isOk:
    dag.cacheLightClientData(state, blck,
      current_period_best_update = attested_data.current_period_best_update,
      latest_signature_slot = latest_signature_slot)
    return
  debug "Best LC update improved", period = attested_period, update = best[]
  dag.cacheLightClientData(state, blck,
    current_period_best_update = best,
    latest_signature_slot = latest_signature_slot)

proc createLightClientBootstrap(
    dag: ChainDAGRef, bid: BlockId): Opt[void] =
  let
    bdata = ? dag.getExistingForkedBlock(bid)
    period = bid.slot.sync_committee_period
  if not dag.lcDataStore.db.hasSyncCommittee(period):
    let didPutSyncCommittee = withState(dag.headState):
      when consensusFork >= ConsensusFork.Altair:
        if period == forkyState.data.slot.sync_committee_period:
          dag.lcDataStore.db.putSyncCommittee(
            period, forkyState.data.current_sync_committee)
          true
        else:
          false
      else:
        false
    if not didPutSyncCommittee:
      let
        tmpState = assignClone(dag.headState)
        syncCommittee = ? dag.existingCurrentSyncCommitteeForPeriod(
          tmpState[], period)
      dag.lcDataStore.db.putSyncCommittee(period, syncCommittee)
  withBlck(bdata):
    when consensusFork >= ConsensusFork.Altair:
      const lcDataFork = lcDataForkAtConsensusFork(consensusFork)
      dag.lcDataStore.db.putHeader(
        forkyBlck.toLightClientHeader(lcDataFork))
    else: raiseAssert "Unreachable"
  dag.lcDataStore.db.putCurrentSyncCommitteeBranch(
    bid.slot, dag.getLightClientData(bid).current_sync_committee_branch)
  ok()

proc initLightClientDataCache*(dag: ChainDAGRef) =
  ## Initialize cached light client data
  if not dag.shouldImportLcData:
    return

  # Initialize tail slot.
  # Both state and blocks must be available to construct light client data,
  # see `cacheLightClientData`. If blocks are unavailable, most parts of the
  # `LightClientHeader` could be reconstructed from the corresponding post-state
  # but `execution_branch` (since Capella) requires full block availability.
  # If the assumed-to-be-available range of states / blocks turns out to be
  # actually unavailable (database inconsistencies), the `tailSlot` will adjust
  # using `handleUnexpectedLightClientError`. This is unexpected and is logged,
  # but recoverable by excluding the unavailable range from LC data collection.
  let targetTailSlot = max(
    # User configured horizon
    dag.targetLightClientTailSlot,
    max(
      # State availability, needed for `cacheLightClientData`
      dag.tail.slot,
      # Block availability, needed for `LightClientHeader.execution_branch`
      dag.backfill.slot))

  dag.lcDataStore.cache.tailSlot = max(dag.head.slot, targetTailSlot)
  if dag.head.slot < dag.lcDataStore.cache.tailSlot:
    return

  # Import light client data for finalized period through finalized head
  let
    finalizedSlot = max(dag.finalizedHead.blck.slot, targetTailSlot)
    finalizedPeriod = finalizedSlot.sync_committee_period
  var res =
    if dag.lcDataStore.importMode == LightClientDataImportMode.OnlyNew:
      Opt[void].ok()
    elif finalizedSlot >= dag.lcDataStore.cache.tailSlot:
      Opt[void].ok()
    else:
      dag.lcDataStore.cache.tailSlot = finalizedSlot
      dag.initLightClientDataForPeriod(finalizedPeriod)

  let lightClientStartTick = Moment.now()
  logScope:
    lightClientDataMaxPeriods = dag.lcDataStore.maxPeriods
    importMode = dag.lcDataStore.importMode
  debug "Initializing cached LC data", res, targetTailSlot

  proc isSyncAggregateCanonical(
      dag: ChainDAGRef, state: ForkyHashedBeaconState,
      sync_aggregate: TrustedSyncAggregate, signature_slot: Slot): bool =
    if signature_slot > state.data.slot:
      return false
    let bid = dag.getBlockIdAtSlot(state, signature_slot).valueOr:
      return false
    if bid.slot != signature_slot:
      return false
    let bdata = dag.getForkedBlock(bid).valueOr:
      return false
    withBlck(bdata):
      when consensusFork >= ConsensusFork.Altair:
        forkyBlck.message.body.sync_aggregate == sync_aggregate
      else:
        false

  # Build list of blocks to process.
  # As it is slow to load states in descending order,
  # build a reverse todo list to then process them in ascending order
  let tailSlot = dag.lcDataStore.cache.tailSlot
  var
    blocks = newSeqOfCap[BlockId](dag.head.slot - tailSlot + 1)
    bid = dag.head.bid
  while bid.slot > tailSlot:
    blocks.add bid
    bid = dag.existingParent(bid).valueOr:
      dag.handleUnexpectedLightClientError(bid.slot)
      res.err()
      break
  if bid.slot == tailSlot:
    blocks.add bid

  # Process blocks (reuses `dag.headState`, but restores it to the current head)
  var cache: StateCache
  for i in countdown(blocks.high, blocks.low):
    bid = blocks[i]
    if not dag.updateExistingState(
        dag.headState, bid.atSlot(), save = false, cache):
      dag.handleUnexpectedLightClientError(bid.slot)
      res.err()
      continue
    let bdata = dag.getExistingForkedBlock(bid).valueOr:
      dag.handleUnexpectedLightClientError(bid.slot)
      res.err()
      continue
    withStateAndBlck(dag.headState, bdata):
      when consensusFork >= ConsensusFork.Altair:
        if i == blocks.high:
          let
            period = bid.slot.sync_committee_period
            best = newClone dag.lcDataStore.db.getBestUpdate(period)
          withForkyUpdate(best[]):
            when lcDataFork > LightClientDataFork.None:
              let
                attestedSlot = forkyUpdate.attested_header.beacon.slot
                signatureSlot = forkyUpdate.signature_slot
              if attestedSlot.sync_committee_period != period or
                  signatureSlot.sync_committee_period != period:
                error "Invalid LC data cached", best = best[], period
                best[].reset()
              elif not dag.isSyncAggregateCanonical(
                  forkyState,
                  forkyUpdate.sync_aggregate.asTrusted(),  # From DB, is trusted
                  forkyUpdate.signature_slot):
                best[].reset()  # Cached data is too recent or from other branch
              else:
                discard  # Cached data is ancestor of `bid`
          dag.cacheLightClientData(forkyState, forkyBlck,
            current_period_best_update = best,
            latest_signature_slot = GENESIS_SLOT)
        else:
          dag.createLightClientUpdate(
            forkyState, forkyBlck, parentBid = blocks[i + 1])
      else: raiseAssert "Unreachable"

  # Import initial `LightClientBootstrap`
  if dag.finalizedHead.slot >= dag.lcDataStore.cache.tailSlot:
    if dag.createLightClientBootstrap(dag.finalizedHead.blck.bid).isErr:
      dag.handleUnexpectedLightClientError(dag.finalizedHead.blck.bid.slot)
      res.err()

  let lightClientEndTick = Moment.now()
  debug "Initialized cached LC data",
    initDur = lightClientEndTick - lightClientStartTick, res
  if res.isErr:
    return

  # Import historic data
  if dag.lcDataStore.importMode == LightClientDataImportMode.Full:
    dag.lcDataStore.cache.tailSlot = targetTailSlot
    let targetTailPeriod = targetTailSlot.sync_committee_period
    if targetTailPeriod < finalizedPeriod:
      # `countdown` through 0 fails on distinct `uint64`
      # https://github.com/nim-lang/Nim/pull/19926
      var period = finalizedPeriod - 1
      while period >= targetTailPeriod:
        if dag.initLightClientDataForPeriod(period).isErr:
          res.err()
        if period <= targetTailPeriod:
          break
        dec period
      debug "Historic LC data imported", res

proc processNewBlockForLightClient*(
    dag: ChainDAGRef,
    state: ForkedHashedBeaconState,
    signedBlock: ForkyTrustedSignedBeaconBlock,
    parentBid: BlockId) =
  ## Update light client data with information from a new block.
  if not dag.shouldImportLcData:
    return
  if signedBlock.message.slot < dag.lcDataStore.cache.tailSlot:
    return

  const consensusFork = typeof(signedBlock).kind
  when consensusFork >= ConsensusFork.Altair:
    template forkyState: untyped = state.forky(consensusFork)
    dag.createLightClientUpdate(forkyState, signedBlock, parentBid)
  else:
    raiseAssert "Unreachable"  # `tailSlot` cannot be before Altair

proc processHeadChangeForLightClient*(dag: ChainDAGRef) =
  ## Update light client data to account for a new head block.
  ## Note that `dag.finalizedHead` is not yet updated when this is called.
  if not dag.shouldImportLcData:
    return
  if dag.head.slot < dag.lcDataStore.cache.tailSlot:
    return

  # Commit best light client data for non-finalized periods
  let
    headPeriod = dag.head.slot.sync_committee_period
    lowSlot = max(dag.lcDataStore.cache.tailSlot, dag.finalizedHead.slot)
    lowPeriod = lowSlot.sync_committee_period
  var blck = dag.head
  for period in countdown(headPeriod, lowPeriod):
    blck = blck.get_ancestor((period + 1).start_slot - 1)
    if blck == nil or blck.slot < lowSlot:
      break
    dag.lcDataStore.db.putBestUpdate(
      blck.slot.sync_committee_period,
      dag.getLightClientData(blck.bid).current_period_best_update[])

  # Update latest light client data
  template latest(): untyped = dag.lcDataStore.cache.latest
  let
    head_data = dag.getLightClientData(dag.head.bid)
    signature_slot = head_data.latest_signature_slot
  if signature_slot <= lowSlot:
    latest.reset()
    return
  blck = dag.head.get_ancestor(signature_slot)
  if blck == nil or blck.parent == nil or blck.parent.slot < lowSlot:
    # If `attested_bid` is before `finalizedHead`, we don't have cached data.
    latest.reset()
    return
  let
    signature_bid = blck.bid
    attested_bid = blck.parent.bid
    sync_aggregate = dag.getExistingSyncAggregate(signature_bid).valueOr:
      dag.handleUnexpectedLightClientError(signature_bid.slot)
      return
    old_meta = latest.toMeta()
  latest.assignLightClientData(
    dag, attested_bid, signature_slot, sync_aggregate)
  let
    new_meta = latest.toMeta()
    new_optimistic =
      if new_meta.attested_slot != old_meta.attested_slot:
        new_meta.attested_slot > old_meta.attested_slot
      else:
        new_meta.signature_slot > old_meta.signature_slot
    new_finality =
      if not new_meta.has_finality:
        false
      elif new_meta.finalized_slot != old_meta.finalized_slot:
        new_meta.finalized_slot > old_meta.finalized_slot
      else:
        let
          old_has_supermajority =
            hasSupermajoritySyncParticipation(old_meta.num_active_participants)
          new_has_supermajority =
            hasSupermajoritySyncParticipation(new_meta.num_active_participants)
        new_has_supermajority > old_has_supermajority
  if new_finality and dag.lcDataStore.onLightClientFinalityUpdate != nil:
    dag.lcDataStore.onLightClientFinalityUpdate(latest)
  if new_optimistic and dag.lcDataStore.onLightClientOptimisticUpdate != nil:
    dag.lcDataStore.onLightClientOptimisticUpdate(latest.toOptimistic())

proc processFinalizationForLightClient*(
    dag: ChainDAGRef, oldFinalizedHead: BlockSlot) =
  ## Prune cached data that is no longer useful for creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances.
  ## This needs to be called whenever `finalized_checkpoint` changes.
  if not dag.shouldImportLcData:
    return
  let finalizedSlot = dag.finalizedHead.slot
  if finalizedSlot < dag.lcDataStore.cache.tailSlot:
    return

  # Cache `LightClientBootstrap` for newly finalized epoch boundary blocks
  let
    firstNewSlot = oldFinalizedHead.slot + 1
    lowSlot = max(firstNewSlot, dag.lcDataStore.cache.tailSlot)
  var boundarySlot = finalizedSlot
  while boundarySlot >= lowSlot:
    let
      bsi = dag.getExistingBlockIdAtSlot(boundarySlot).valueOr:
        dag.handleUnexpectedLightClientError(boundarySlot)
        break
      bid = bsi.bid
    if bid.slot >= lowSlot:
      if dag.createLightClientBootstrap(bid).isErr:
        dag.handleUnexpectedLightClientError(bid.slot)
        break
    boundarySlot = bid.slot.nextEpochBoundarySlot
    if boundarySlot < SLOTS_PER_EPOCH:
      break
    boundarySlot -= SLOTS_PER_EPOCH

  # Seal sync committee periods for which data can no longer improve further
  let
    oldFinalizedPeriod = oldFinalizedHead.slot.sync_committee_period
    newFinalizedPeriod = dag.finalizedHead.slot.sync_committee_period
  if newFinalizedPeriod > oldFinalizedPeriod:
    for period in countdown(newFinalizedPeriod - 1, oldFinalizedPeriod):
      if dag.lcDataStore.cache.tailSlot > period.start_slot:
        break
      debug "Best LC update sealed",
        period, update = dag.lcDataStore.db.getBestUpdate(period)
      dag.lcDataStore.db.sealPeriod(period)

  # Prune light client data that is no longer referrable by future updates
  var bidsToDelete: seq[BlockId]
  for bid, data in dag.lcDataStore.cache.data:
    if bid.slot >= dag.finalizedHead.blck.slot:
      continue
    bidsToDelete.add bid
  for bid in bidsToDelete:
    dag.lcDataStore.cache.data.del bid

  # Prune seal tracking data that is no longer relevant
  let targetTailPeriod = dag.targetLightClientTailSlot.sync_committee_period
  dag.lcDataStore.db.keepPeriodsFrom(targetTailPeriod)

proc getLightClientBootstrap(
    dag: ChainDAGRef,
    header: ForkyLightClientHeader): ForkedLightClientBootstrap =
  let
    slot = header.beacon.slot
    period = slot.sync_committee_period
    blockRoot = hash_tree_root(header)
  if slot < dag.targetLightClientTailSlot:
    debug "LC bootstrap unavailable: Block too old", slot
    return default(ForkedLightClientBootstrap)
  if slot > dag.finalizedHead.blck.slot:
    debug "LC bootstrap unavailable: Not finalized", blockRoot
    return default(ForkedLightClientBootstrap)

  # Ensure `current_sync_committee_branch` is known
  if dag.lcDataStore.importMode == LightClientDataImportMode.OnDemand and
      not dag.hasCurrentSyncCommitteeBranch(slot):
    let
      bsi = dag.getExistingBlockIdAtSlot(slot).valueOr:
        return default(ForkedLightClientBootstrap)
      tmpState = assignClone(dag.headState)
    dag.withUpdatedExistingState(tmpState[], bsi) do:
      withState(updatedState):
        when consensusFork >= ConsensusFork.Altair:
          const lcDataFork = lcDataForkAtConsensusFork(consensusFork)
          if not dag.lcDataStore.db.hasSyncCommittee(period):
            dag.lcDataStore.db.putSyncCommittee(
              period, forkyState.data.current_sync_committee)
          dag.lcDataStore.db.putHeader(header)
          dag.lcDataStore.db.putCurrentSyncCommitteeBranch(
            slot, forkyState.data.build_proof(
              lcDataFork.CURRENT_SYNC_COMMITTEE_GINDEX).get)
        else: raiseAssert "Unreachable"
    do: return default(ForkedLightClientBootstrap)

  # Ensure `current_sync_committee` is known
  if not dag.lcDataStore.db.hasSyncCommittee(period):
    let
      tmpState = assignClone(dag.headState)
      syncCommittee = dag.existingCurrentSyncCommitteeForPeriod(
        tmpState[], period).valueOr:
          return default(ForkedLightClientBootstrap)
    dag.lcDataStore.db.putSyncCommittee(period, syncCommittee)

  # Construct `LightClientBootstrap` from cached data
  const lcDataFork = typeof(header).kind
  ForkedLightClientBootstrap.init(lcDataFork.LightClientBootstrap(
    header: header,
    current_sync_committee: (block:
      dag.lcDataStore.db.getSyncCommittee(period).valueOr:
        debug "LC bootstrap unavailable: Sync committee not cached", period
        return default(ForkedLightClientBootstrap)),
    current_sync_committee_branch: (block:
      getCurrentSyncCommitteeBranch[lcDataFork.CurrentSyncCommitteeBranch](
          dag.lcDataStore.db, slot).valueOr:
        debug "LC bootstrap unavailable: Committee branch not cached", slot
        return default(ForkedLightClientBootstrap))))

proc getLightClientBootstrap*(
    dag: ChainDAGRef,
    blockRoot: Eth2Digest): ForkedLightClientBootstrap =
  if not dag.lcDataStore.serve:
    return default(ForkedLightClientBootstrap)

  # Try to load from cache
  withAll(LightClientDataFork):
    when lcDataFork > LightClientDataFork.None:
      let header = getHeader[lcDataFork.LightClientHeader](
        dag.lcDataStore.db, blockRoot)
      if header.isOk:
        return dag.getLightClientBootstrap(header.get)

  # Fallback to DAG
  let bdata = dag.getForkedBlock(blockRoot).valueOr:
    debug "LC bootstrap unavailable: Block not found", blockRoot
    return default(ForkedLightClientBootstrap)
  withBlck(bdata):
    when consensusFork >= ConsensusFork.Altair:
      const lcDataFork = lcDataForkAtConsensusFork(consensusFork)
      let
        header = forkyBlck.toLightClientHeader(lcDataFork)
        bootstrap = dag.getLightClientBootstrap(header)
      if bootstrap.kind > LightClientDataFork.None:
        dag.lcDataStore.db.putHeader(header)
      return bootstrap
    else:
      debug "LC bootstrap unavailable: Block before Altair", blockRoot
      return default(ForkedLightClientBootstrap)

proc getLightClientUpdateForPeriod*(
    dag: ChainDAGRef,
    period: SyncCommitteePeriod): ForkedLightClientUpdate =
  if not dag.lcDataStore.serve:
    return default(ForkedLightClientUpdate)

  if dag.lcDataStore.importMode == LightClientDataImportMode.OnDemand and
      period < dag.finalizedHead.blck.slot.sync_committee_period:
    if dag.initLightClientUpdateForPeriod(period).isErr:
      return default(ForkedLightClientUpdate)
  let
    update = dag.lcDataStore.db.getBestUpdate(period)
    numParticipants = withForkyUpdate(update):
      when lcDataFork > LightClientDataFork.None:
        forkyUpdate.sync_aggregate.num_active_participants
      else:
        0
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return default(ForkedLightClientUpdate)
  update

proc getLightClientFinalityUpdate*(
    dag: ChainDAGRef): ForkedLightClientFinalityUpdate =
  if not dag.lcDataStore.serve:
    return default(ForkedLightClientFinalityUpdate)

  let
    finalityUpdate = dag.lcDataStore.cache.latest
    numParticipants = withForkyFinalityUpdate(finalityUpdate):
      when lcDataFork > LightClientDataFork.None:
        forkyFinalityUpdate.sync_aggregate.num_active_participants
      else:
        0
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return default(ForkedLightClientFinalityUpdate)
  finalityUpdate

proc getLightClientOptimisticUpdate*(
    dag: ChainDAGRef): ForkedLightClientOptimisticUpdate =
  if not dag.lcDataStore.serve:
    return default(ForkedLightClientOptimisticUpdate)

  let
    optimisticUpdate = dag.lcDataStore.cache.latest.toOptimistic
    numParticipants = withForkyOptimisticUpdate(optimisticUpdate):
      when lcDataFork > LightClientDataFork.None:
        forkyOptimisticUpdate.sync_aggregate.num_active_participants
      else:
        0
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return default(ForkedLightClientOptimisticUpdate)
  optimisticUpdate
