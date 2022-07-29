# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  # Status libraries
  stew/[bitops2, objects],
  # Beacon chain internals
  ../spec/datatypes/[phase0, altair, bellatrix],
  ../beacon_chain_db_light_client,
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

proc initLightClientDataStore*(
    config: LightClientDataConfig,
    cfg: RuntimeConfig,
    db: LightClientDataDB): LightClientDataStore =
  ## Initialize light client data store.
  LightClientDataStore(
    db: db,
    serve: config.serve,
    importMode: config.importMode,
    maxPeriods: config.maxPeriods.get(cfg.defaultLightClientDataMaxPeriods),
    onLightClientFinalityUpdate: config.onLightClientFinalityUpdate,
    onLightClientOptimisticUpdate: config.onLightClientOptimisticUpdate)

func targetLightClientTailSlot(dag: ChainDAGRef): Slot =
  ## Earliest slot for which light client data is retained.
  let
    maxPeriods = dag.lcDataStore.maxPeriods
    headPeriod = dag.head.slot.sync_committee_period
    lowSlot = max(dag.tail.slot, dag.cfg.ALTAIR_FORK_EPOCH.start_slot)
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
  if not dag.isNextSyncCommitteeFinalized(period):
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
    lowSlot = max(periodStartSlot, dag.targetLightClientTailSlot)
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
      if not dag.updateExistingState(
          tmpState[], bid.atSlot, save = false, tmpCache):
        dag.handleUnexpectedLightClientError(bid.slot)
        res.err()
        continue
      let branch = withState(tmpState[]):
        when stateFork >= BeaconStateFork.Altair:
          state.data.build_proof(altair.CURRENT_SYNC_COMMITTEE_INDEX).get
        else: raiseAssert "Unreachable"
      dag.lcDataStore.db.putCurrentSyncCommitteeBranch(bid.slot, branch)
  res

proc initLightClientUpdateForPeriod(
    dag: ChainDAGRef, period: SyncCommitteePeriod): Opt[void] =
  ## Compute and cache the best `LightClientUpdate` within a given
  ## sync committee period up through the finalized head block.
  ## Non-finalized blocks are processed incrementally by other functions.
  if not dag.isNextSyncCommitteeFinalized(period):
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
            when stateFork >= BeaconStateFork.Altair:
              countOnes(blck.message.body.sync_aggregate.sync_committee_bits)
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
    lowSlot = max(periodStartSlot, dag.targetLightClientTailSlot)
    highSlot = min(periodEndSlot, dag.finalizedHead.blck.slot)
    fullPeriodCovered = (dag.finalizedHead.slot > periodEndSlot)
    highBsi = dag.getExistingBlockIdAtSlot(highSlot).valueOr:
      dag.handleUnexpectedLightClientError(highSlot)
      return err()
    highBid = highBsi.bid
    maxParticipantsRes = dag.maxParticipantsBlock(highBid, lowSlot)
    maxParticipantsBid = maxParticipantsRes.bid.valueOr:
      const update = default(altair.LightClientUpdate)
      if fullPeriodCovered and maxParticipantsRes.res.isOk: # No block in period
        dag.lcDataStore.db.putBestUpdate(period, update)
      else:
        dag.lcDataStore.db.putUpdateIfBetter(period, update)
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
      let
        nextLowSlot = signatureBid.slot + 1
        signatureRes = dag.maxParticipantsBlock(highBid, nextLowSlot)
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
          withState(state):
            when stateFork >= BeaconStateFork.Altair:
              state.data.finalized_checkpoint.epoch
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
    if finalizedBid.slot >= lowSlot:
      finalizedBid = finalizedBsi.bid
      break
    if signatureBid == maxParticipantsBid:
      finalizedBid = finalizedBsi.bid # For fallback `break` at start of loop

  # Save best light client data for given period
  var update {.noinit.}: altair.LightClientUpdate
  let attestedBid = dag.existingParent(signatureBid).valueOr:
    dag.handleUnexpectedLightClientError(signatureBid.slot)
    return err()
  dag.withUpdatedExistingState(tmpState[], attestedBid.atSlot) do:
    let bdata = dag.getExistingForkedBlock(bid).valueOr:
      dag.handleUnexpectedLightClientError(bid.slot)
      return err()
    withStateAndBlck(state, bdata):
      when stateFork >= BeaconStateFork.Altair:
        update.attested_header = blck.toBeaconBlockHeader()
        update.next_sync_committee = state.data.next_sync_committee
        update.next_sync_committee_branch =
           state.data.build_proof(altair.NEXT_SYNC_COMMITTEE_INDEX).get
        if finalizedBid.slot == FAR_FUTURE_SLOT:
          update.finality_branch.reset()
        else:
          update.finality_branch =
             state.data.build_proof(altair.FINALIZED_ROOT_INDEX).get
      else: raiseAssert "Unreachable"
  do:
    dag.handleUnexpectedLightClientError(attestedBid.slot)
    return err()
  if finalizedBid.slot == FAR_FUTURE_SLOT or finalizedBid.slot == GENESIS_SLOT:
    update.finalized_header.reset()
  else:
    let bdata = dag.getExistingForkedBlock(finalizedBid).valueOr:
      dag.handleUnexpectedLightClientError(finalizedBid.slot)
      return err()
    withBlck(bdata):
      update.finalized_header = blck.toBeaconBlockHeader()
  let bdata = dag.getExistingForkedBlock(signatureBid).valueOr:
    dag.handleUnexpectedLightClientError(signatureBid.slot)
    return err()
  withBlck(bdata):
    when stateFork >= BeaconStateFork.Altair:
      update.sync_aggregate = blck.asSigned().message.body.sync_aggregate
    else: raiseAssert "Unreachable"
  update.signature_slot = signatureBid.slot

  if fullPeriodCovered and res.isOk:
    dag.lcDataStore.db.putBestUpdate(period, update)
  else:
    dag.lcDataStore.db.putUpdateIfBetter(period, update)
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
    dag: ChainDAGRef, state: HashedBeaconStateWithSyncCommittee, bid: BlockId) =
  ## Cache data for a given block and its post-state to speed up creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances that refer to this
  ## block and state.
  let cachedData = CachedLightClientData(
    current_sync_committee_branch:
      state.data.build_proof(altair.CURRENT_SYNC_COMMITTEE_INDEX).get,
    next_sync_committee_branch:
      state.data.build_proof(altair.NEXT_SYNC_COMMITTEE_INDEX).get,
    finalized_slot:
      state.data.finalized_checkpoint.epoch.start_slot,
    finality_branch:
      state.data.build_proof(altair.FINALIZED_ROOT_INDEX).get)
  if dag.lcDataStore.cache.data.hasKeyOrPut(bid, cachedData):
    doAssert false, "Redundant `cacheLightClientData` call"

proc deleteLightClientData*(dag: ChainDAGRef, bid: BlockId) =
  ## Delete cached light client data for a given block. This needs to be called
  ## when a block becomes unreachable due to finalization of a different fork.
  if dag.lcDataStore.importMode == LightClientDataImportMode.None:
    return

  dag.lcDataStore.cache.data.del bid

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
  var `name` {.noinit.}: CachedLightClientData
  `name`.finalized_slot = FAR_FUTURE_SLOT
  template `load _ name`(bid: BlockId) =
    if `name`.finalized_slot == FAR_FUTURE_SLOT:
      `name` = dag.getLightClientData(bid)

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
  let attested_slot = attested_bid.slot
  if attested_slot < dag.lcDataStore.cache.tailSlot:
    return

  # Lazy variables to hold historic data
  lazy_header(attested_header)
  lazy_data(attested_data)
  lazy_bid(finalized_bid)
  lazy_header(finalized_header)

  # Update latest light client data
  template latest(): auto = dag.lcDataStore.cache.latest
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
  if is_later and latest.attested_header.assign_attested_header(attested_bid):
    load_attested_data(attested_bid)
    let finalized_slot = attested_data.finalized_slot
    if finalized_slot == latest.finalized_header.slot:
      latest.finality_branch = attested_data.finality_branch
    elif finalized_slot == GENESIS_SLOT:
      latest.finalized_header.reset()
      latest.finality_branch = attested_data.finality_branch
    elif finalized_slot >= dag.tail.slot and
        load_finalized_bid(finalized_slot) and
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
  if attested_period == signature_period:
    template next_sync_committee(): auto = state.data.next_sync_committee

    let isCommitteeFinalized = dag.isNextSyncCommitteeFinalized(attested_period)
    var best =
      if isCommitteeFinalized:
        dag.lcDataStore.db.getBestUpdate(attested_period)
      else:
        let key = (attested_period, state.syncCommitteeRoot)
        dag.lcDataStore.cache.pendingBest.getOrDefault(key)

    load_attested_data(attested_bid)
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
      is_better = is_better_data(meta, best.toMeta)
    if is_better and best.attested_header.assign_attested_header(attested_bid):
      best.next_sync_committee = next_sync_committee
      best.next_sync_committee_branch = attested_data.next_sync_committee_branch
      if finalized_slot == best.finalized_header.slot:
        best.finality_branch = attested_data.finality_branch
      elif finalized_slot == GENESIS_SLOT:
        best.finalized_header.reset()
        best.finality_branch = attested_data.finality_branch
      elif has_finality and
          best.finalized_header.assign_finalized_header(finalized_bid):
        best.finality_branch = attested_data.finality_branch
      else:
        best.finalized_header.reset()
        best.finality_branch.reset()
      best.sync_aggregate = sync_aggregate
      best.signature_slot = signature_slot

      if isCommitteeFinalized:
        dag.lcDataStore.db.putBestUpdate(attested_period, best)
        debug "Best LC update improved", period = attested_period, update = best
      else:
        let key = (attested_period, state.syncCommitteeRoot)
        dag.lcDataStore.cache.pendingBest[key] = best
        debug "Best LC update improved", period = key, update = best

  if newFinality and dag.lcDataStore.onLightClientFinalityUpdate != nil:
    dag.lcDataStore.onLightClientFinalityUpdate(latest)
  if newOptimistic and dag.lcDataStore.onLightClientOptimisticUpdate != nil:
    dag.lcDataStore.onLightClientOptimisticUpdate(latest.toOptimistic)

proc initLightClientDataCache*(dag: ChainDAGRef) =
  ## Initialize cached light client data
  if dag.lcDataStore.importMode == LightClientDataImportMode.None:
    return

  # Prune non-finalized data
  dag.lcDataStore.db.delPeriodsFrom(dag.firstNonFinalizedPeriod)

  # Initialize tail slot
  let targetTailSlot = dag.targetLightClientTailSlot
  dag.lcDataStore.cache.tailSlot = max(dag.head.slot, targetTailSlot)

  # Import head state
  if dag.head.slot < dag.lcDataStore.cache.tailSlot:
    return
  withState(dag.headState):
    when stateFork >= BeaconStateFork.Altair:
      dag.cacheLightClientData(state, dag.head.bid)
    else: raiseAssert "Unreachable" # `tailSlot` cannot be before Altair
  if dag.lcDataStore.importMode == LightClientDataImportMode.OnlyNew:
    return

  # Import light client data for finalized period through finalized head
  let finalizedSlot = max(dag.finalizedHead.blck.slot, targetTailSlot)
  if finalizedSlot >= dag.lcDataStore.cache.tailSlot:
    return
  dag.lcDataStore.cache.tailSlot = finalizedSlot
  let finalizedPeriod = finalizedSlot.sync_committee_period
  var res = dag.initLightClientDataForPeriod(finalizedPeriod)

  let lightClientStartTick = Moment.now()
  logScope: lightClientDataMaxPeriods = dag.lcDataStore.maxPeriods
  debug "Initializing cached LC data", res

  # Build list of block to process.
  # As it is slow to load states in descending order,
  # build a reverse todo list to then process them in ascending order
  var
    blocks = newSeqOfCap[BlockId](dag.head.slot - finalizedSlot + 1)
    bid = dag.head.bid
  while bid.slot > finalizedSlot:
    blocks.add bid
    bid = dag.existingParent(bid).valueOr:
      dag.handleUnexpectedLightClientError(bid.slot)
      res.err()
      break
  if bid.slot == finalizedSlot:
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
      dag.handleUnexpectedLightClientError(bid.slot)
      res.err()
      continue
    let bdata = dag.getExistingForkedBlock(bid).valueOr:
      dag.handleUnexpectedLightClientError(bid.slot)
      res.err()
      continue
    withStateAndBlck(dag.headState, bdata):
      when stateFork >= BeaconStateFork.Altair:
        # Cache light client data (non-finalized blocks may refer to this)
        if i != blocks.low:
          dag.cacheLightClientData(state, bid)  # `dag.head` already cached

        # Create `LightClientUpdate` instances
        if i < blocks.high:
          dag.createLightClientUpdates(state, blck, parentBid = blocks[i + 1])
      else: raiseAssert "Unreachable"

  let lightClientEndTick = Moment.now()
  debug "Initialized cached LC data",
    initDur = lightClientEndTick - lightClientStartTick, res
  if res.isErr:
    return
  if dag.lcDataStore.importMode == LightClientDataImportMode.OnDemand:
    return

  # Import historic data
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
  if dag.lcDataStore.importMode == LightClientDataImportMode.None:
    return
  if signedBlock.message.slot < dag.lcDataStore.cache.tailSlot:
    return

  when signedBlock is bellatrix.TrustedSignedBeaconBlock:
    dag.cacheLightClientData(state.bellatrixData, signedBlock.toBlockId())
    dag.createLightClientUpdates(state.bellatrixData, signedBlock, parentBid)
  elif signedBlock is altair.TrustedSignedBeaconBlock:
    dag.cacheLightClientData(state.altairData, signedBlock.toBlockId())
    dag.createLightClientUpdates(state.altairData, signedBlock, parentBid)
  elif signedBlock is phase0.TrustedSignedBeaconBlock:
    raiseAssert "Unreachable" # `tailSlot` cannot be before Altair
  else:
    {.error: "Unreachable".}

proc processHeadChangeForLightClient*(dag: ChainDAGRef) =
  ## Update light client data to account for a new head block.
  ## Note that `dag.finalizedHead` is not yet updated when this is called.
  if dag.lcDataStore.importMode == LightClientDataImportMode.None:
    return
  if dag.head.slot < dag.lcDataStore.cache.tailSlot:
    return

  # Update `bestUpdates` from `pendingBest` to ensure light client data
  # only refers to sync committees as selected by fork choice
  let headPeriod = dag.head.slot.sync_committee_period
  if not dag.isNextSyncCommitteeFinalized(headPeriod):
    let
      tailPeriod = dag.lcDataStore.cache.tailSlot.sync_committee_period
      lowPeriod = max(dag.firstNonFinalizedPeriod, tailPeriod)
    if headPeriod > lowPeriod:
      var tmpState = assignClone(dag.headState)
      for period in lowPeriod ..< headPeriod:
        let
          syncCommitteeRoot =
            dag.syncCommitteeRootForPeriod(tmpState[], period).valueOr:
              dag.handleUnexpectedLightClientError(period.start_slot)
              continue
          key = (period, syncCommitteeRoot)
        dag.lcDataStore.db.putBestUpdate(
          period, dag.lcDataStore.cache.pendingBest.getOrDefault(key))
    withState(dag.headState): # Common case separate to avoid `tmpState` copy
      when stateFork >= BeaconStateFork.Altair:
        let key = (headPeriod, state.syncCommitteeRoot)
        dag.lcDataStore.db.putBestUpdate(
          headPeriod, dag.lcDataStore.cache.pendingBest.getOrDefault(key))
      else: raiseAssert "Unreachable" # `tailSlot` cannot be before Altair

proc processFinalizationForLightClient*(
    dag: ChainDAGRef, oldFinalizedHead: BlockSlot) =
  ## Prune cached data that is no longer useful for creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances.
  ## This needs to be called whenever `finalized_checkpoint` changes.
  if dag.lcDataStore.importMode == LightClientDataImportMode.None:
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

  # Prune best `LightClientUpdate` referring to non-finalized sync committees
  # that are no longer relevant, i.e., orphaned or too old
  let firstNonFinalizedPeriod = dag.firstNonFinalizedPeriod
  var keysToDelete: seq[(SyncCommitteePeriod, Eth2Digest)]
  for (period, committeeRoot) in dag.lcDataStore.cache.pendingBest.keys:
    if period < firstNonFinalizedPeriod:
      keysToDelete.add (period, committeeRoot)
  for key in keysToDelete:
    dag.lcDataStore.cache.pendingBest.del key

proc getLightClientBootstrap*(
    dag: ChainDAGRef,
    blockRoot: Eth2Digest): Opt[altair.LightClientBootstrap] =
  if not dag.lcDataStore.serve:
    return err()

  let bdata = dag.getForkedBlock(blockRoot).valueOr:
    debug "LC bootstrap unavailable: Block not found", blockRoot
    return err()

  withBlck(bdata):
    let slot = blck.message.slot
    when stateFork >= BeaconStateFork.Altair:
      if slot < dag.targetLightClientTailSlot:
        debug "LC bootstrap unavailable: Block too old", slot
        return err()
      if slot > dag.finalizedHead.blck.slot:
        debug "LC bootstrap unavailable: Not finalized", blockRoot
        return err()
      var branch = dag.lcDataStore.db.getCurrentSyncCommitteeBranch(slot)
      if branch.isZeroMemory:
        if dag.lcDataStore.importMode == LightClientDataImportMode.OnDemand:
          let bsi = ? dag.getExistingBlockIdAtSlot(slot)
          var tmpState = assignClone(dag.headState)
          dag.withUpdatedExistingState(tmpState[], bsi) do:
            branch = withState(state):
              when stateFork >= BeaconStateFork.Altair:
                state.data.build_proof(altair.CURRENT_SYNC_COMMITTEE_INDEX).get
              else: raiseAssert "Unreachable"
          do: return err()
          dag.lcDataStore.db.putCurrentSyncCommitteeBranch(slot, branch)
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
        branch
      return ok bootstrap
    else:
      debug "LC bootstrap unavailable: Block before Altair", slot
      return err()

proc getLightClientUpdateForPeriod*(
    dag: ChainDAGRef,
    period: SyncCommitteePeriod): Option[altair.LightClientUpdate] =
  if not dag.lcDataStore.serve:
    return

  if dag.lcDataStore.importMode == LightClientDataImportMode.OnDemand:
    if dag.initLightClientUpdateForPeriod(period).isErr:
      return
  result = some(dag.lcDataStore.db.getBestUpdate(period))
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result.reset()

proc getLightClientFinalityUpdate*(
    dag: ChainDAGRef): Option[altair.LightClientFinalityUpdate] =
  if not dag.lcDataStore.serve:
    return

  result = some(dag.lcDataStore.cache.latest)
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result.reset()

proc getLightClientOptimisticUpdate*(
    dag: ChainDAGRef): Option[altair.LightClientOptimisticUpdate] =
  if not dag.lcDataStore.serve:
    return

  result = some(dag.lcDataStore.cache.latest.toOptimistic)
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result.reset()
