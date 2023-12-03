# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
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

proc updateExistingState(
    dag: ChainDAGRef, state: var ForkedHashedBeaconState, bsi: BlockSlotId,
    save: bool, cache: var StateCache): bool =
  ## Wrapper around `updateState` for states expected to exist.
  let ok = dag.updateState(state, bsi, save, cache)
  if not ok:
    error "State failed to load unexpectedly", bsi, tail = dag.tail.slot
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
      error "State failed to load unexpectedly", bsi, tail = dag.tail.slot
      doAssert strictVerification notin dag.updateFlags
      failureBody

proc getExistingBlockIdAtSlot(dag: ChainDAGRef, slot: Slot): Opt[BlockSlotId] =
  ## Wrapper around `getBlockIdAtSlot` for blocks expected to exist.
  let bsi = dag.getBlockIdAtSlot(slot)
  if bsi.isErr:
    error "Block failed to load unexpectedly", slot, tail = dag.tail.slot
    doAssert strictVerification notin dag.updateFlags
  bsi

proc existingParent(dag: ChainDAGRef, bid: BlockId): Opt[BlockId] =
  ## Wrapper around `parent` for parents known to exist.
  let parent = dag.parent(bid)
  if parent.isErr:
    error "Parent failed to load unexpectedly", bid, tail = dag.tail.slot
    doAssert strictVerification notin dag.updateFlags
  parent

proc getExistingForkedBlock(
    dag: ChainDAGRef, bid: BlockId): Opt[ForkedTrustedSignedBeaconBlock] =
  ## Wrapper around `getForkedBlock` for blocks expected to exist.
  let bdata = dag.getForkedBlock(bid)
  if bdata.isErr:
    error "Block failed to load unexpectedly", bid, tail = dag.tail.slot
    doAssert strictVerification notin dag.updateFlags
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
    doAssert strictVerification notin dag.updateFlags
  syncCommittee

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
        not dag.lcDataStore.db.hasCurrentSyncCommitteeBranch(bid.slot):
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
              altair.CURRENT_SYNC_COMMITTEE_GINDEX).get)
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
        if finalizedSlot >= dag.tail.slot:
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
          next_sync_committee_branch:
            forkyState.data.build_proof(altair.NEXT_SYNC_COMMITTEE_GINDEX).get,
          finality_branch:
            if finalizedBid.slot != FAR_FUTURE_SLOT:
              forkyState.data.build_proof(altair.FINALIZED_ROOT_GINDEX).get
            else:
              default(FinalityBranch)))
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
    dag: ChainDAGRef, state: ForkyHashedBeaconState, bid: BlockId,
    current_period_best_update: ref ForkedLightClientUpdate) =
  ## Cache data for a given block and its post-state to speed up creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances that refer to this
  ## block and state.
  let cachedData = CachedLightClientData(
    current_sync_committee_branch:
      state.data.build_proof(altair.CURRENT_SYNC_COMMITTEE_GINDEX).get,
    next_sync_committee_branch:
      state.data.build_proof(altair.NEXT_SYNC_COMMITTEE_GINDEX).get,
    finalized_slot:
      state.data.finalized_checkpoint.epoch.start_slot,
    finality_branch:
      state.data.build_proof(altair.FINALIZED_ROOT_GINDEX).get,
    current_period_best_update:
      current_period_best_update)
  if dag.lcDataStore.cache.data.hasKeyOrPut(bid, cachedData):
    doAssert false, "Redundant `cacheLightClientData` call"

func shouldImportLcData(dag: ChainDAGRef): bool =
  dag.lcDataStore.importMode != LightClientDataImportMode.None and
  dag.cfg.ALTAIR_FORK_EPOCH != FAR_FUTURE_EPOCH

proc deleteLightClientData*(dag: ChainDAGRef, bid: BlockId) =
  ## Delete cached light client data for a given block. This needs to be called
  ## when a block becomes unreachable due to finalization of a different fork.
  if not dag.shouldImportLcData:
    return

  dag.lcDataStore.cache.data.del bid

template lazy_header(name: untyped): untyped {.dirty.} =
  ## `createLightClientUpdates` helper to lazily load a known block header.
  var
    `name _ ptr`: ptr[data_fork.LightClientHeader]
    `name _ ok` = true
  template `assign _ name`(
      obj: var SomeForkyLightClientObject, bid: BlockId): untyped {.used.} =
    if `name _ ptr` != nil:
      obj.name = `name _ ptr`[]
    elif `name _ ok`:
      let bdata = dag.getExistingForkedBlock(bid)
      if bdata.isErr:
        dag.handleUnexpectedLightClientError(bid.slot)
        `name _ ok` = false
      else:
        withBlck(bdata.get):
          when data_fork >= lcDataForkAtConsensusFork(consensusFork):
            obj.name = forkyBlck.toLightClientHeader(data_fork)
          else: raiseAssert "Unreachable"
        `name _ ptr` = addr obj.name
    `name _ ok`
  template `assign _ name _ with_migration`(
      obj: var SomeForkedLightClientObject, bid: BlockId): untyped {.used.} =
    if `name _ ptr` != nil:
      obj.migrateToDataFork(data_fork)
      obj.forky(data_fork).name = `name _ ptr`[]
    elif `name _ ok`:
      let bdata = dag.getExistingForkedBlock(bid)
      if bdata.isErr:
        dag.handleUnexpectedLightClientError(bid.slot)
        `name _ ok` = false
      else:
        obj.migrateToDataFork(data_fork)
        withBlck(bdata.get):
          when data_fork >= lcDataForkAtConsensusFork(consensusFork):
            obj.forky(data_fork).name = forkyBlck.toLightClientHeader(data_fork)
          else: raiseAssert "Unreachable"
        `name _ ptr` = addr obj.forky(data_fork).name
    `name _ ok`

template lazy_bid(name: untyped): untyped {.dirty.} =
  ## `createLightClientUpdates` helper to lazily load a known to exist block id.
  var
    `name` {.noinit.}: BlockId
    `name _ ok` = true
  `name`.slot = FAR_FUTURE_SLOT
  template `load _ name`(slot: Slot): bool =
    if `name _ ok` and `name`.slot == FAR_FUTURE_SLOT:
      let bsi = dag.getExistingBlockIdAtSlot(slot)
      if bsi.isErr:
        dag.handleUnexpectedLightClientError(slot)
        `name _ ok` = false
      else:
        `name` = bsi.get.bid
    `name _ ok`

proc createLightClientUpdates(
    dag: ChainDAGRef,
    state: ForkyHashedBeaconState,
    blck: ForkyTrustedSignedBeaconBlock,
    parent_bid: BlockId,
    data_fork: static LightClientDataFork): ref ForkedLightClientUpdate =
  ## Create `LightClientUpdate` instances for a given block and its post-state,
  ## and keep track of best / latest ones. Data about the parent block's
  ## post-state must be cached (`cacheLightClientData`) before calling this.
  ## Returns the best `LightClientUpdate` for the block's sync committee period.

  # Verify attested block (parent) is recent enough and that state is available
  template attested_bid(): auto = parent_bid
  let attested_slot = attested_bid.slot
  if attested_slot < dag.lcDataStore.cache.tailSlot:
    return (ref ForkedLightClientUpdate)()

  # `blck` and `parent_bid` must be in the same sync committee period
  # to update the best per-period `LightClientUpdate`
  let
    attested_period = attested_slot.sync_committee_period
    signature_slot = blck.message.slot
    signature_period = signature_slot.sync_committee_period
  var
    attested_data = dag.getLightClientData(attested_bid)
    best =
      if attested_period != signature_period:
        (ref ForkedLightClientUpdate)()
      else:
        attested_data.current_period_best_update

  # Verify sync committee has sufficient participants
  template sync_aggregate(): auto = blck.asSigned().message.body.sync_aggregate
  let num_active_participants = sync_aggregate.num_active_participants.uint64
  if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return best

  # Lazy variables to hold historic data
  lazy_header(attested_header)
  lazy_bid(finalized_bid)
  lazy_header(finalized_header)

  # Update latest light client data
  template latest(): untyped = dag.lcDataStore.cache.latest
  var
    newFinality = false
    newOptimistic = false
  let is_later = withForkyFinalityUpdate(latest):
    when lcDataFork > LightClientDataFork.None:
      if attested_slot != forkyFinalityUpdate.attested_header.beacon.slot:
        attested_slot > forkyFinalityUpdate.attested_header.beacon.slot
      else:
        signature_slot > forkyFinalityUpdate.signature_slot
    else:
      true
  if is_later and latest.assign_attested_header_with_migration(attested_bid):
    template forkyLatest: untyped = latest.forky(data_fork)
    var finalized_slot = attested_data.finalized_slot
    if finalized_slot == forkyLatest.finalized_header.beacon.slot:
      forkyLatest.finality_branch = attested_data.finality_branch
      let old_num_active_participants =
        forkyLatest.sync_aggregate.num_active_participants.uint64
      if not hasSupermajoritySyncParticipation(old_num_active_participants) and
          hasSupermajoritySyncParticipation(num_active_participants):
        newFinality = true
    elif finalized_slot < dag.tail.slot or
        not load_finalized_bid(finalized_slot):
      forkyLatest.finalized_header.reset()
      forkyLatest.finality_branch.reset()
    else:
      if finalized_bid.slot != finalized_slot:
        finalized_slot = finalized_bid.slot
        attested_data.finalized_slot = finalized_slot
        dag.lcDataStore.cache.data[attested_bid] = attested_data
      if finalized_slot == forkyLatest.finalized_header.beacon.slot:
        forkyLatest.finality_branch = attested_data.finality_branch
      elif finalized_slot == GENESIS_SLOT:
        forkyLatest.finalized_header.reset()
        forkyLatest.finality_branch = attested_data.finality_branch
      elif forkyLatest.assign_finalized_header(finalized_bid):
        forkyLatest.finality_branch = attested_data.finality_branch
        newFinality = true
      else:
        forkyLatest.finalized_header.reset()
        forkyLatest.finality_branch.reset()
    forkyLatest.sync_aggregate = sync_aggregate
    forkyLatest.signature_slot = signature_slot
    newOptimistic = true

  # Track best light client data for current period
  if attested_period == signature_period:
    let
      finalized_slot = attested_data.finalized_slot
      has_finality =
        finalized_slot >= dag.tail.slot and load_finalized_bid(finalized_slot)
      meta = LightClientUpdateMetadata(
        attested_slot: attested_slot,
        finalized_slot: finalized_slot,
        signature_slot: signature_slot,
        has_sync_committee: true,
        has_finality: has_finality,
        num_active_participants: num_active_participants)
      is_better = is_better_data(
        meta, attested_data.current_period_best_update[].toMeta())
    if is_better:
      best = newClone attested_data.current_period_best_update[]
      if not best[].assign_attested_header_with_migration(attested_bid):
        best = attested_data.current_period_best_update
      else:
        template forkyBest: untyped = best[].forky(data_fork)
        forkyBest.next_sync_committee = state.data.next_sync_committee
        forkyBest.next_sync_committee_branch =
          attested_data.next_sync_committee_branch
        if finalized_slot == forkyBest.finalized_header.beacon.slot:
          forkyBest.finality_branch = attested_data.finality_branch
        elif finalized_slot == GENESIS_SLOT:
          forkyBest.finalized_header.reset()
          forkyBest.finality_branch = attested_data.finality_branch
        elif has_finality and
            forkyBest.assign_finalized_header(finalized_bid):
          forkyBest.finality_branch = attested_data.finality_branch
        else:
          forkyBest.finalized_header.reset()
          forkyBest.finality_branch.reset()
        forkyBest.sync_aggregate = sync_aggregate
        forkyBest.signature_slot = signature_slot
        debug "Best LC update improved",
          period = attested_period, update = forkyBest

  if newFinality and dag.lcDataStore.onLightClientFinalityUpdate != nil:
    dag.lcDataStore.onLightClientFinalityUpdate(latest)
  if newOptimistic and dag.lcDataStore.onLightClientOptimisticUpdate != nil:
    dag.lcDataStore.onLightClientOptimisticUpdate(latest.toOptimistic)
  best

proc createLightClientUpdates(
    dag: ChainDAGRef,
    state: ForkyHashedBeaconState,
    blck: ForkyTrustedSignedBeaconBlock,
    parent_bid: BlockId) =
  # Attested block (parent) determines `LightClientUpdate` fork
  let best = withLcDataFork(dag.cfg.lcDataForkAtEpoch(parent_bid.slot.epoch)):
    when lcDataFork > LightClientDataFork.None:
      dag.createLightClientUpdates(state, blck, parent_bid, lcDataFork)
    else:
      (ref ForkedLightClientUpdate)()
  dag.cacheLightClientData(state, blck.toBlockId(), best)

proc initLightClientDataCache*(dag: ChainDAGRef) =
  ## Initialize cached light client data
  if not dag.shouldImportLcData:
    return

  # Initialize tail slot
  let targetTailSlot = max(dag.targetLightClientTailSlot, dag.tail.slot)
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
  debug "Initializing cached LC data", res

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

  # Build list of block to process.
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
          dag.cacheLightClientData(forkyState, bid, best)
        else:
          dag.createLightClientUpdates(
            forkyState, forkyBlck, parentBid = blocks[i + 1])
      else: raiseAssert "Unreachable"

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
    dag.createLightClientUpdates(forkyState, signedBlock, parentBid)
  else:
    raiseAssert "Unreachable"  # `tailSlot` cannot be before Altair

proc processHeadChangeForLightClient*(dag: ChainDAGRef) =
  ## Update light client data to account for a new head block.
  ## Note that `dag.finalizedHead` is not yet updated when this is called.
  if not dag.shouldImportLcData:
    return
  if dag.head.slot < dag.lcDataStore.cache.tailSlot:
    return
  let
    headPeriod = dag.head.slot.sync_committee_period
    lowSlot = max(dag.lcDataStore.cache.tailSlot, dag.finalizedHead.slot)
    lowPeriod = lowSlot.sync_committee_period

  var blck = dag.head
  for period in countdown(headPeriod, lowPeriod):
    blck = blck.get_ancestor((period + 1).start_slot - 1)
    if blck == nil:
      return
    if blck.slot < lowSlot:
      return
    dag.lcDataStore.db.putBestUpdate(
      blck.slot.sync_committee_period,
      dag.getLightClientData(blck.bid).current_period_best_update[])

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
      let
        bdata = dag.getExistingForkedBlock(bid).valueOr:
          dag.handleUnexpectedLightClientError(bid.slot)
          break
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
            syncCommittee = dag.existingCurrentSyncCommitteeForPeriod(
              tmpState[], period).valueOr:
                dag.handleUnexpectedLightClientError(bid.slot)
                break
          dag.lcDataStore.db.putSyncCommittee(period, syncCommittee)
      withBlck(bdata):
        when consensusFork >= ConsensusFork.Altair:
          const lcDataFork = lcDataForkAtConsensusFork(consensusFork)
          dag.lcDataStore.db.putHeader(
            forkyBlck.toLightClientHeader(lcDataFork))
        else: raiseAssert "Unreachable"
      dag.lcDataStore.db.putCurrentSyncCommitteeBranch(
        bid.slot, dag.getLightClientData(bid).current_sync_committee_branch)
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
      not dag.lcDataStore.db.hasCurrentSyncCommitteeBranch(slot):
    let
      bsi = dag.getExistingBlockIdAtSlot(slot).valueOr:
        return default(ForkedLightClientBootstrap)
      tmpState = assignClone(dag.headState)
    dag.withUpdatedExistingState(tmpState[], bsi) do:
      withState(updatedState):
        when consensusFork >= ConsensusFork.Altair:
          if not dag.lcDataStore.db.hasSyncCommittee(period):
            dag.lcDataStore.db.putSyncCommittee(
              period, forkyState.data.current_sync_committee)
          dag.lcDataStore.db.putHeader(header)
          dag.lcDataStore.db.putCurrentSyncCommitteeBranch(
            slot, forkyState.data.build_proof(
              altair.CURRENT_SYNC_COMMITTEE_GINDEX).get)
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
      dag.lcDataStore.db.getCurrentSyncCommitteeBranch(slot).valueOr:
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
