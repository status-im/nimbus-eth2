# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/[algorithm, sequtils],
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

func fromBlock(
    T: type BeaconBlockHeader,
    blck: ForkyTrustedSignedBeaconBlock): T =
  ## Reduce a given full block to just its `BeaconBlockHeader`.
  BeaconBlockHeader(
    slot: blck.message.slot,
    proposer_index: blck.message.proposer_index,
    parent_root: blck.message.parent_root,
    state_root: blck.message.state_root,
    body_root: blck.message.body.hash_tree_root())

func fromBlock(
    T: type BeaconBlockHeader,
    blck: ForkedTrustedSignedBeaconBlock): T =
  ## Reduce a given full block to just its `BeaconBlockHeader`.
  withBlck(blck):
    BeaconBlockHeader.fromBlock(blck)

template nextEpochBoundarySlot(slot: Slot): Slot =
  ## Compute the first possible epoch boundary state slot of a `Checkpoint`
  ## referring to a block at given slot.
  (slot + (SLOTS_PER_EPOCH - 1)).epoch.start_slot

func computeEarliestLightClientSlot*(dag: ChainDAGRef): Slot =
  ## Compute the earliest slot for which light client data is retained.
  let
    altairStartSlot = dag.cfg.ALTAIR_FORK_EPOCH.start_slot
    currentSlot = getStateField(dag.headState.data, slot)
  if currentSlot < altairStartSlot:
    return altairStartSlot

  let
    MIN_EPOCHS_FOR_BLOCK_REQUESTS =
      dag.cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY +
      dag.cfg.CHURN_LIMIT_QUOTIENT div 2
    MIN_SLOTS_FOR_BLOCK_REQUESTS =
      MIN_EPOCHS_FOR_BLOCK_REQUESTS * SLOTS_PER_EPOCH
    minSlot = max(altairStartSlot, dag.tail.slot)
  if currentSlot - minSlot < MIN_SLOTS_FOR_BLOCK_REQUESTS:
    return minSlot

  let earliestSlot = currentSlot - MIN_SLOTS_FOR_BLOCK_REQUESTS
  max(earliestSlot.sync_committee_period.start_slot, minSlot)

proc currentSyncCommitteeForPeriod(
    dag: ChainDAGRef,
    tmpState: ref StateData,
    period: SyncCommitteePeriod): SyncCommittee =
  ## Fetch a `SyncCommittee` for a given sync committee period.
  ## For non-finalized periods, follow the chain as selected by fork choice.
  let earliestSlot = dag.computeEarliestLightClientSlot
  doAssert period >= earliestSlot.sync_committee_period
  let
    periodStartSlot = period.start_slot
    syncCommitteeSlot = max(periodStartSlot, earliestSlot)
  dag.withUpdatedState(tmpState[], dag.getBlockAtSlot(syncCommitteeSlot)) do:
    withState(stateData.data):
      when stateFork >= BeaconStateFork.Altair:
        state.data.current_sync_committee
      else: raiseAssert "Unreachable"
  do: raiseAssert "Unreachable"

template syncCommitteeRoot(
    state: HashedBeaconStateWithSyncCommittee): Eth2Digest =
  ## Compute a root to uniquely identify `current_sync_committee` and
  ## `next_sync_committee`.
  withEth2Hash:
    h.update state.data.current_sync_committee.hash_tree_root().data
    h.update state.data.next_sync_committee.hash_tree_root().data

proc syncCommitteeRootForPeriod(
    dag: ChainDAGRef,
    tmpState: ref StateData,
    period: SyncCommitteePeriod): Eth2Digest =
  ## Compute a root to uniquely identify `current_sync_committee` and
  ## `next_sync_committee` for a given sync committee period.
  ## For non-finalized periods, follow the chain as selected by fork choice.
  let earliestSlot = dag.computeEarliestLightClientSlot
  doAssert period >= earliestSlot.sync_committee_period
  let
    periodStartSlot = period.start_slot
    syncCommitteeSlot = max(periodStartSlot, earliestSlot)
  dag.withUpdatedState(tmpState[], dag.getBlockAtSlot(syncCommitteeSlot)) do:
    withState(stateData.data):
      when stateFork >= BeaconStateFork.Altair:
        state.syncCommitteeRoot
      else: raiseAssert "Unreachable"
  do: raiseAssert "Unreachable"

proc getLightClientData(
    dag: ChainDAGRef,
    bid: BlockId): CachedLightClientData =
  ## Fetch cached light client data about a given block.
  ## Data must be cached (`cacheLightClientData`) before calling this function.
  try: dag.lightClientDb.cachedData[bid]
  except KeyError: raiseAssert "Unreachable"

template getLightClientData(
    dag: ChainDAGRef,
    blck: BlockRef): CachedLightClientData =
  getLightClientData(dag, blck.bid)

proc cacheLightClientData*(
    dag: ChainDAGRef,
    state: HashedBeaconStateWithSyncCommittee,
    blck: TrustedSignedBeaconBlockWithSyncAggregate,
    isNew = true) =
  ## Cache data for a given block and its post-state to speed up creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances that refer to this
  ## block and state.
  let startTick = Moment.now()

  var current_sync_committee_branch {.noinit.}:
    array[log2trunc(altair.CURRENT_SYNC_COMMITTEE_INDEX), Eth2Digest]
  state.data.build_proof(
    altair.CURRENT_SYNC_COMMITTEE_INDEX, current_sync_committee_branch)

  var next_sync_committee_branch {.noinit.}:
    array[log2trunc(altair.NEXT_SYNC_COMMITTEE_INDEX), Eth2Digest]
  state.data.build_proof(
    altair.NEXT_SYNC_COMMITTEE_INDEX, next_sync_committee_branch)

  var finality_branch {.noinit.}:
    array[log2trunc(altair.FINALIZED_ROOT_INDEX), Eth2Digest]
  state.data.build_proof(
    altair.FINALIZED_ROOT_INDEX, finality_branch)

  template finalized_checkpoint(): auto = state.data.finalized_checkpoint
  let
    bid =
      BlockId(root: blck.root, slot: blck.message.slot)
    finalized_bid =
      dag.getBlockIdAtSlot(finalized_checkpoint.epoch.start_slot).bid
  if dag.lightClientDb.cachedData.hasKeyOrPut(
      bid,
      CachedLightClientData(
        current_sync_committee_branch:
          current_sync_committee_branch,
        next_sync_committee_branch:
          next_sync_committee_branch,
        finalized_bid:
          finalized_bid,
        finality_branch:
          finality_branch)):
    doAssert false, "Redundant `cacheLightClientData` call"

  let endTick = Moment.now()
  if isNew and endTick - startTick > chronos.milliseconds(30):
    debug "Caching light client data took longer than usual",
      root = blck.root, slot = blck.message.slot,
      createDur = endTick - startTick

proc deleteLightClientData*(dag: ChainDAGRef, bid: BlockId) =
  ## Delete cached light client data for a given block. This needs to be called
  ## when a block becomes unreachable due to finalization of a different fork.
  if dag.importLightClientData == ImportLightClientData.None:
    return

  dag.lightClientDb.cachedData.del bid

template lazy_header(name: untyped): untyped {.dirty.} =
  ## `createLightClientUpdates` helper to lazily load a known block header.
  var `name ptr`: ptr[BeaconBlockHeader]
  template `assign name`(target: var BeaconBlockHeader,
                         bid: BlockId | BlockRef): untyped =
    if `name ptr` != nil:
      target = `name ptr`[]
    else:
      target = BeaconBlockHeader.fromBlock(
        when bid is BlockID:
          dag.getForkedBlock(bid).get
        else:
          dag.getForkedBlock(bid))
      `name ptr` = addr target

template lazy_data(name: untyped): untyped {.dirty.} =
  ## `createLightClientUpdates` helper to lazily load cached light client state.
  var `name` {.noinit.}: CachedLightClientData
  `name`.finalized_bid.slot = FAR_FUTURE_SLOT
  template `load name`(bid: BlockId | BlockRef): untyped =
    if `name`.finalized_bid.slot == FAR_FUTURE_SLOT:
      `name` = dag.getLightClientData(bid)

proc createLightClientUpdates(
    dag: ChainDAGRef,
    state: HashedBeaconStateWithSyncCommittee,
    blck: TrustedSignedBeaconBlockWithSyncAggregate,
    parent: BlockRef) =
  ## Create `LightClientUpdate` and `OptimisticLightClientUpdate` instances for
  ## a given block and its post-state, and keep track of best / latest ones.
  ## Data about the parent block's post-state and its `finalized_checkpoint`'s
  ## block's post-state needs to be cached (`cacheLightClientData`) before
  ## calling this function.
  let startTick = Moment.now()

  # Parent needs to be known to continue
  if parent == nil:
    return

  # Verify sync committee has sufficient participants
  template sync_aggregate(): auto = blck.message.body.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64
  if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return

  # Verify attested block (parent) is recent enough and that state is available
  let
    earliest_slot = dag.computeEarliestLightClientSlot
    attested_slot = parent.slot
  if attested_slot < earliest_slot:
    return

  # Verify signature does not skip a sync committee period
  let
    signature_slot = blck.message.slot
    signature_period = signature_slot.sync_committee_period
    attested_period = attested_slot.sync_committee_period
  if signature_period > attested_period + 1:
    return

  # Update to new `OptimisticLightClientUpdate` if it attests to a later slot
  lazy_header(attested_header)
  template optimistic_update(): auto = dag.lightClientDb.optimisticUpdate
  if attested_slot > optimistic_update.attested_header.slot:
    optimistic_update.attested_header
      .assign_attested_header(parent)
    optimistic_update.sync_aggregate =
      isomorphicCast[SyncAggregate](sync_aggregate)
    optimistic_update.fork_version =
      state.data.fork.current_version
    optimistic_update.is_signed_by_next_sync_committee =
      signature_period == attested_period + 1
    if dag.onOptimisticLightClientUpdate != nil:
      dag.onOptimisticLightClientUpdate(optimistic_update)

  # Update to new latest `LightClientUpdate` if it attests to a later slot
  lazy_data(attested_data)
  lazy_data(finalized_data)
  lazy_header(finalized_header)
  template latest_update(): auto = dag.lightClientDb.latestUpdate
  if attested_slot > latest_update.attested_header.slot:
    latest_update.attested_header
      .assign_attested_header(parent)
    latest_update.sync_aggregate =
      isomorphicCast[SyncAggregate](sync_aggregate)
    latest_update.fork_version =
      state.data.fork.current_version

    load_attested_data(parent)
    let finalized_slot = attested_data.finalized_bid.slot
    if finalized_slot + UPDATE_TIMEOUT < attested_slot or
        finalized_slot < earliest_slot:
      latest_update.finalized_header = BeaconBlockHeader()
      latest_update.finality_branch.fill(Eth2Digest())
      if signature_period == attested_period + 1:
        latest_update.next_sync_committee = SyncCommittee()
        latest_update.next_sync_committee_branch.fill(Eth2Digest())
      else:
        latest_update.next_sync_committee =
          state.data.next_sync_committee
        latest_update.next_sync_committee_branch =
          attested_data.next_sync_committee_branch
    else:
      latest_update.finalized_header
        .assign_finalized_header(attested_data.finalized_bid)
      latest_update.finality_branch =
        attested_data.finality_branch
      if signature_period == finalized_slot.sync_committee_period + 1:
        latest_update.next_sync_committee = SyncCommittee()
        latest_update.next_sync_committee_branch.fill(Eth2Digest())
      else:
        load_finalized_data(attested_data.finalized_bid)
        latest_update.next_sync_committee =
          state.data.next_sync_committee
        latest_update.next_sync_committee_branch =
          finalized_data.next_sync_committee_branch

  # Update best `LightClientUpdate` for current period if it improved
  if signature_period == attested_period:
    let isNextSyncCommitteeFinalized =
      signature_period.start_slot <= dag.finalizedHead.slot
    var best_update =
      if isNextSyncCommitteeFinalized:
        dag.lightClientDb.bestUpdates.getOrDefault(signature_period)
      else:
        let key = (signature_period, state.syncCommitteeRoot)
        dag.lightClientDb.pendingBestUpdates.getOrDefault(key)

    type Verdict = enum
      unknown
      new_update_is_worse
      new_update_is_better
    var verdict = unknown

    # If no best update has been recorded, new update is better
    template best_sync_aggregate(): auto = best_update.sync_aggregate
    let best_num_active_participants =
      countOnes(best_sync_aggregate.sync_committee_bits).uint64
    if best_num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
      verdict = new_update_is_better
    else:
      # If finality changes, the finalized update is better
      template finalized_period_at_signature(): auto =
        state.data.finalized_checkpoint.epoch.sync_committee_period
      template best_attested_slot(): auto =
        best_update.attested_header.slot
      if best_update.finality_branch.isZeroMemory:
        if (attested_slot > dag.finalizedHead.slot or
            attested_slot > best_attested_slot) and
            signature_period == finalized_period_at_signature:
          load_attested_data(parent)
          let finalized_slot = attested_data.finalized_bid.slot
          if signature_period == finalized_slot.sync_committee_period and
              finalized_slot >= earliest_slot:
            verdict = new_update_is_better
      elif attested_slot > dag.finalizedHead.slot or
          attested_slot < best_attested_slot:
        if signature_period == finalized_period_at_signature:
          load_attested_data(parent)
          let finalized_slot = attested_data.finalized_bid.slot
          if signature_period != finalized_slot.sync_committee_period or
              finalized_slot < earliest_slot:
            verdict = new_update_is_worse
        else:
          verdict = new_update_is_worse
      if verdict == unknown:
        # If participation changes, higher participation is better
        if num_active_participants < best_num_active_participants:
          verdict = new_update_is_worse
        elif num_active_participants > best_num_active_participants:
          verdict = new_update_is_better
        else:
          # Older updates are better
          if attested_slot >= best_attested_slot:
            verdict = new_update_is_worse
          else:
            verdict = new_update_is_better

    if verdict == new_update_is_better:
      best_update.attested_header
        .assign_attested_header(parent)
      best_update.sync_aggregate =
        isomorphicCast[SyncAggregate](sync_aggregate)
      best_update.fork_version =
        state.data.fork.current_version

      load_attested_data(parent)
      let finalized_slot = attested_data.finalized_bid.slot
      if signature_period != finalized_slot.sync_committee_period or
          finalized_slot < earliest_slot:
        best_update.finalized_header = BeaconBlockHeader()
        best_update.finality_branch.fill(Eth2Digest())
        best_update.next_sync_committee =
          state.data.next_sync_committee
        best_update.next_sync_committee_branch =
          attested_data.next_sync_committee_branch
      else:
        best_update.finalized_header
          .assign_finalized_header(attested_data.finalized_bid)
        best_update.finality_branch =
          attested_data.finality_branch
        load_finalized_data(attested_data.finalized_bid)
        best_update.next_sync_committee =
          state.data.next_sync_committee
        best_update.next_sync_committee_branch =
          finalized_data.next_sync_committee_branch

      if isNextSyncCommitteeFinalized:
        dag.lightClientDb.bestUpdates[signature_period] = best_update
        debug "Best `LightClientUpdate` improved",
          period = signature_period, update = best_update
      else:
        let key = (signature_period, state.syncCommitteeRoot)
        dag.lightClientDb.pendingBestUpdates[key] = best_update
        debug "Best `LightClientUpdate` improved",
          period = key, update = best_update

  let endTick = Moment.now()
  if endTick - startTick > chronos.milliseconds(100):
    debug "`LightClientUpdate` creation took longer than usual",
      root = dag.head.root, slot = dag.head.slot,
      createDur = endTick - startTick

proc processNewBlockForLightClient*(
    dag: ChainDAGRef,
    state: StateData,
    signedBlock: ForkyTrustedSignedBeaconBlock,
    parent: BlockRef) =
  ## Update light client data with information from a new block.
  if dag.importLightClientData == ImportLightClientData.None:
    return
  if signedBlock.message.slot < dag.computeEarliestLightClientSlot:
    return

  when signedBlock is bellatrix.TrustedSignedBeaconBlock:
    dag.cacheLightClientData(state.data.bellatrixData, signedBlock)
    dag.createLightClientUpdates(state.data.bellatrixData, signedBlock, parent)
  elif signedBlock is altair.TrustedSignedBeaconBlock:
    dag.cacheLightClientData(state.data.altairData, signedBlock)
    dag.createLightClientUpdates(state.data.altairData, signedBlock, parent)
  elif signedBlock is phase0.TrustedSignedBeaconBlock:
    discard
  else:
    {.error: "Unreachable".}

proc processHeadChangeForLightClient*(dag: ChainDAGRef) =
  ## Update light client data to account for a new head block.
  ## Note that `dag.finalizedHead` is not yet updated when this is called.
  if dag.importLightClientData == ImportLightClientData.None:
    return
  if dag.head.slot < dag.computeEarliestLightClientSlot:
    return

  let headPeriod = dag.head.slot.sync_committee_period
  if headPeriod.start_slot > dag.finalizedHead.slot:
    let finalizedPeriod = dag.finalizedHead.slot.sync_committee_period
    if headPeriod > finalizedPeriod + 1:
      var tmpState = assignClone(dag.headState)
      for period in finalizedPeriod + 1 ..< headPeriod:
        let key = (period, dag.syncCommitteeRootForPeriod(tmpState, period))
        dag.lightClientDb.bestUpdates[period] =
          dag.lightClientDb.pendingBestUpdates.getOrDefault(key)
    withState(dag.headState.data):
      when stateFork >= BeaconStateFork.Altair:
        let key = (headPeriod, state.syncCommitteeRoot)
        dag.lightClientDb.bestUpdates[headPeriod] =
          dag.lightClientDb.pendingBestUpdates.getOrDefault(key)
      else: raiseAssert "Unreachable"

proc processFinalizationForLightClient*(dag: ChainDAGRef) =
  ## Prune cached data that is no longer useful for creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances.
  ## This needs to be called whenever `finalized_checkpoint` changes.
  if dag.importLightClientData == ImportLightClientData.None:
    return
  let
    altairStartSlot = dag.cfg.ALTAIR_FORK_EPOCH.start_slot
    finalizedSlot = dag.finalizedHead.slot
  if finalizedSlot < altairStartSlot:
    return
  let earliestSlot = dag.computeEarliestLightClientSlot

  # Keep track of latest four finalized checkpoints
  let
    lastIndex = dag.lightClientDb.lastCheckpointIndex
    lastCheckpoint = addr dag.lightClientDb.latestCheckpoints[lastIndex]
  if dag.finalizedHead.slot.epoch != lastCheckpoint.epoch or
      dag.finalizedHead.blck.root != lastCheckpoint.root:
    let
      nextIndex = (lastIndex + 1) mod dag.lightClientDb.latestCheckpoints.len
      nextCheckpoint = addr dag.lightClientDb.latestCheckpoints[nextIndex]
    nextCheckpoint[].epoch = dag.finalizedHead.slot.epoch
    nextCheckpoint[].root = dag.finalizedHead.blck.root
    dag.lightClientDb.lastCheckpointIndex = nextIndex

    # Cache `LightClientBootstrap` for newly finalized epoch boundary blocks.
    # Epoch boundary blocks are the block for the initial slot of an epoch,
    # or the most recent block if no block was proposed at that slot
    let lowSlot = max(lastCheckpoint.epoch.start_slot, earliestSlot)
    var boundarySlot = dag.finalizedHead.slot
    while boundarySlot >= lowSlot:
      let blck = dag.getBlockAtSlot(boundarySlot).blck
      if blck.slot >= lowSlot:
        dag.lightClientDb.cachedBootstrap[blck.slot] =
          CachedLightClientBootstrap(
            current_sync_committee_branch:
              dag.getLightClientData(blck.bid).current_sync_committee_branch)
      boundarySlot = blck.slot.nextEpochBoundarySlot
      if boundarySlot < SLOTS_PER_EPOCH:
        break
      boundarySlot -= SLOTS_PER_EPOCH

  # Prune light client data that is no longer relevant,
  # i.e., can no longer be referred to by future updates, or is too old
  var bidsToDelete: seq[BlockId]
  for bid, data in dag.lightClientDb.cachedData:
    if bid.slot >= earliestSlot:
      if bid.slot >= finalizedSlot:
        continue
      if dag.lightClientDb.latestCheckpoints.anyIt(bid.root == it.root):
        continue
    bidsToDelete.add bid
  for bid in bidsToDelete:
    dag.lightClientDb.cachedData.del bid

  # Prune bootstrap data that is no longer relevant
  var slotsToDelete: seq[Slot]
  for slot in dag.lightClientDb.cachedBootstrap.keys:
    if slot < earliestSlot:
      slotsToDelete.add slot
  for slot in slotsToDelete:
    dag.lightClientDb.cachedBootstrap.del slot

  # Prune best `LightClientUpdate` that are no longer relevant
  let earliestPeriod = earliestSlot.sync_committee_period
  var periodsToDelete: seq[SyncCommitteePeriod]
  for period in dag.lightClientDb.bestUpdates.keys:
    if period < earliestPeriod:
      periodsToDelete.add period
  for period in periodsToDelete:
    dag.lightClientDb.bestUpdates.del period

  # Prune best `LightClientUpdate` referring to non-finalized sync committees
  # that are no longer relevant, i.e., orphaned or too old
  let finalizedPeriod = finalizedSlot.sync_committee_period
  var keysToDelete: seq[(SyncCommitteePeriod, Eth2Digest)]
  for (period, syncCommitteeRoot) in dag.lightClientDb.pendingBestUpdates.keys:
    if period <= finalizedPeriod:
      keysToDelete.add (period, syncCommitteeRoot)
  for key in keysToDelete:
    dag.lightClientDb.pendingBestUpdates.del key

proc initBestLightClientUpdateForPeriod(
    dag: ChainDAGRef, period: SyncCommitteePeriod) =
  ## Compute and cache the `LightClientUpdate` with the most sync committee
  ## signatures (i.e., participation) for a given sync committee period.
  let periodStartSlot = period.start_slot
  if periodStartSlot > dag.finalizedHead.slot:
    return
  let
    earliestSlot = dag.computeEarliestLightClientSlot
    periodEndSlot = periodStartSlot + SLOTS_PER_SYNC_COMMITTEE_PERIOD - 1
  if periodEndSlot < earliestSlot:
    return
  if dag.lightClientDb.bestUpdates.hasKey(period):
    return
  let startTick = Moment.now()
  debug "Computing best `LightClientUpdate`", period
  defer:
    let endTick = Moment.now()
    debug "Best `LightClientUpdate` computed",
      period, update = dag.lightClientDb.bestUpdates.getOrDefault(period),
      computeDur = endTick - startTick

  proc maxParticipantsBlock(highBlck: BlockRef, lowSlot: Slot): BlockRef =
    ## Determine the earliest block with most sync committee signatures among
    ## ancestors of `highBlck` with at least `lowSlot` as parent block slot.
    ## Return `nil` if no block with `MIN_SYNC_COMMITTEE_PARTICIPANTS` is found.
    var
      maxParticipants = 0
      maxBlockRef: BlockRef
      blockRef = highBlck
    while blockRef.parent != nil and blockRef.parent.slot >= lowSlot:
      let numParticipants =
        withBlck(dag.getForkedBlock(blockRef)):
          when stateFork >= BeaconStateFork.Altair:
            countOnes(blck.message.body.sync_aggregate.sync_committee_bits)
          else: raiseAssert "Unreachable"
      if numParticipants >= maxParticipants:
        maxParticipants = numParticipants
        maxBlockRef = blockRef
      blockRef = blockRef.parent
    if maxParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
      maxBlockRef = nil
    maxBlockRef

  # Determine the block in the period with highest sync committee participation
  let
    lowSlot = max(periodStartSlot, earliestSlot)
    highSlot = min(periodEndSlot, dag.finalizedHead.blck.slot)
    highBlck = dag.getBlockAtSlot(highSlot).blck
    bestNonFinalizedRef = maxParticipantsBlock(highBlck, lowSlot)
  if bestNonFinalizedRef == nil:
    dag.lightClientDb.bestUpdates[period] = default(altair.LightClientUpdate)
    return

  # The block with highest participation may refer to a `finalized_checkpoint`
  # in a different sync committee period. If that is the case, search for a
  # later block with a `finalized_checkpoint` within the given sync committee
  # period, despite it having a lower sync committee participation
  var
    tmpState = assignClone(dag.headState)
    bestFinalizedRef = bestNonFinalizedRef
    finalizedBlck {.noinit.}: BlockRef
  while bestFinalizedRef != nil:
    let
      finalizedEpoch = block:
        dag.withUpdatedState(tmpState[], bestFinalizedRef.parent.atSlot) do:
          withState(stateData.data):
            when stateFork >= BeaconStateFork.Altair:
              state.data.finalized_checkpoint.epoch
            else: raiseAssert "Unreachable"
        do: raiseAssert "Unreachable"
      finalizedEpochStartSlot = finalizedEpoch.start_slot
    if finalizedEpochStartSlot >= lowSlot:
      finalizedBlck = dag.getBlockAtSlot(finalizedEpochStartSlot).blck
      if finalizedBlck.slot >= lowSlot:
        break
    bestFinalizedRef = maxParticipantsBlock(highBlck, bestFinalizedRef.slot + 1)

  # If a finalized block has been found within the sync commitee period,
  # create a `LightClientUpdate` for that one. Otherwise, create a non-finalized
  # `LightClientUpdate`
  var update {.noinit.}: LightClientUpdate
  if bestFinalizedRef != nil:
    # Fill data from attested block
    dag.withUpdatedState(tmpState[], bestFinalizedRef.parent.atSlot) do:
      let bdata = dag.getForkedBlock(blck)
      withStateAndBlck(stateData.data, bdata):
        when stateFork >= BeaconStateFork.Altair:
          update.attested_header =
            BeaconBlockHeader.fromBlock(blck)
          state.data.build_proof(
            altair.FINALIZED_ROOT_INDEX, update.finality_branch)
        else: raiseAssert "Unreachable"
    do: raiseAssert "Unreachable"

    # Fill data from signature block
    let bdata = dag.getForkedBlock(bestFinalizedRef)
    withBlck(bdata):
      when stateFork >= BeaconStateFork.Altair:
        update.sync_aggregate =
          isomorphicCast[SyncAggregate](blck.message.body.sync_aggregate)
      else: raiseAssert "Unreachable"
    update.fork_version =
      dag.cfg.forkAtEpoch(bestFinalizedRef.slot.epoch).current_version

    # Fill data from finalized block
    dag.withUpdatedState(tmpState[], finalizedBlck.atSlot) do:
      let bdata = dag.getForkedBlock(blck)
      withStateAndBlck(stateData.data, bdata):
        when stateFork >= BeaconStateFork.Altair:
          update.next_sync_committee =
            state.data.next_sync_committee
          state.data.build_proof(
            altair.NEXT_SYNC_COMMITTEE_INDEX, update.next_sync_committee_branch)
          update.finalized_header =
            BeaconBlockHeader.fromBlock(blck)
        else: raiseAssert "Unreachable"
    do: raiseAssert "Unreachable"
  else:
    # Fill data from attested block
    dag.withUpdatedState(tmpState[], bestNonFinalizedRef.parent.atSlot) do:
      let bdata = dag.getForkedBlock(blck)
      withStateAndBlck(stateData.data, bdata):
        when stateFork >= BeaconStateFork.Altair:
          update.attested_header =
            BeaconBlockHeader.fromBlock(blck)
          update.next_sync_committee =
            state.data.next_sync_committee
          state.data.build_proof(
            altair.NEXT_SYNC_COMMITTEE_INDEX, update.next_sync_committee_branch)
          update.finalized_header = BeaconBlockHeader()
          update.finality_branch.fill(Eth2Digest())
        else: raiseAssert "Unreachable"
    do: raiseAssert "Unreachable"

    # Fill data from signature block
    let bdata = dag.getForkedBlock(bestNonFinalizedRef)
    withBlck(bdata):
      when stateFork >= BeaconStateFork.Altair:
        update.sync_aggregate =
          isomorphicCast[SyncAggregate](blck.message.body.sync_aggregate)
      else: raiseAssert "Unreachable"
    update.fork_version =
      dag.cfg.forkAtEpoch(bestNonFinalizedRef.slot.epoch).current_version
  dag.lightClientDb.bestUpdates[period] = update

proc initLightClientBootstrapForPeriod(
    dag: ChainDAGRef,
    period: SyncCommitteePeriod) =
  ## Compute and cache `LightClientBootstrap` data for all epoch boundary blocks
  ## within a given sync committee period.
  let periodStartSlot = period.start_slot
  if periodStartSlot > dag.finalizedHead.slot:
    return
  let
    earliestSlot = dag.computeEarliestLightClientSlot
    periodEndSlot = periodStartSlot + SLOTS_PER_SYNC_COMMITTEE_PERIOD - 1
  if periodEndSlot < earliestSlot:
    return

  let startTick = Moment.now()
  debug "Caching `LightClientBootstrap` data", period
  defer:
    let endTick = Moment.now()
    debug "`LightClientBootstrap` data cached", period,
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
    let
      blck = dag.getBlockAtSlot(nextBoundarySlot).blck
      boundarySlot = blck.slot.nextEpochBoundarySlot
    if boundarySlot == nextBoundarySlot and
        blck.slot >= lowSlot and blck.slot <= highSlot and
        not dag.lightClientDb.cachedBootstrap.hasKey(blck.slot):
      var cachedBootstrap {.noinit.}: CachedLightClientBootstrap
      doAssert dag.updateStateData(
        tmpState[], blck.atSlot, save = false, tmpCache)
      withStateVars(tmpState[]):
        withState(stateData.data):
          when stateFork >= BeaconStateFork.Altair:
            state.data.build_proof(
              altair.CURRENT_SYNC_COMMITTEE_INDEX,
              cachedBootstrap.current_sync_committee_branch)
          else: raiseAssert "Unreachable"
      dag.lightClientDb.cachedBootstrap[blck.slot] = cachedBootstrap
    nextBoundarySlot += SLOTS_PER_EPOCH

proc initLightClientDb*(dag: ChainDAGRef) =
  ## Initialize cached light client data
  if dag.importLightClientData == ImportLightClientData.None:
    return
  let earliestSlot = dag.computeEarliestLightClientSlot
  if dag.head.slot < earliestSlot:
    return

  let
    finalizedSlot = dag.finalizedHead.slot
    finalizedPeriod = finalizedSlot.sync_committee_period
  dag.initBestLightClientUpdateForPeriod(finalizedPeriod)

  let lightClientStartTick = Moment.now()
  debug "Initializing cached light client data"

  # Build lists of block to process.
  # As it is slow to load states in descending order,
  # first build a todo list, then process them in ascending order
  let lowSlot = max(finalizedSlot, dag.computeEarliestLightClientSlot)
  var
    blocksBetween = newSeqOfCap[BlockRef](dag.head.slot - lowSlot + 1)
    blockRef = dag.head
  while blockRef.slot > lowSlot:
    blocksBetween.add blockRef
    blockRef = blockRef.parent
  blocksBetween.add blockRef

  # Process blocks (reuses `dag.headState`, but restores it to the current head)
  var
    tmpState = assignClone(dag.headState)
    tmpCache, cache: StateCache
    oldCheckpoint: Checkpoint
    checkpointIndex = 0
  for i in countdown(blocksBetween.high, blocksBetween.low):
    blockRef = blocksBetween[i]
    doAssert dag.updateStateData(
      dag.headState, blockRef.atSlot(blockRef.slot), save = false, cache)
    withStateVars(dag.headState):
      let bdata = dag.getForkedBlock(blck)
      withStateAndBlck(stateData.data, bdata):
        when stateFork >= BeaconStateFork.Altair:
          # Cache data for `LightClientUpdate` of descendant blocks
          dag.cacheLightClientData(state, blck, isNew = false)

          # Cache data for the block's `finalized_checkpoint`.
          # The `finalized_checkpoint` may refer to:
          # 1. `finalizedHead.blck -> finalized_checkpoint`
          #    This may happen when there were skipped slots.
          # 2. `finalizedHead -> finalized_checkpoint`
          # 3. One epoch boundary that got justified then finalized
          #    between `finalizedHead -> finalized_checkpoint`
          #    and `finalizedHead`
          # 4. `finalizedHead`
          let checkpoint = state.data.finalized_checkpoint
          if checkpoint != oldCheckpoint:
            oldCheckpoint = checkpoint
            doAssert checkpointIndex < dag.lightClientDb.latestCheckpoints.len
            dag.lightClientDb.latestCheckpoints[checkpointIndex] = checkpoint
            dag.lightClientDb.lastCheckpointIndex = checkpointIndex
            inc checkpointIndex

            # Save new checkpoint block using `tmpState` (avoid replay after it)
            if checkpoint.root != dag.finalizedHead.blck.root:
              let cpRef =
                dag.getBlockAtSlot(checkpoint.epoch.start_slot).blck
              if cpRef != nil and cpRef.slot >= earliestSlot:
                assert cpRef.bid.root == checkpoint.root
                doAssert dag.updateStateData(
                  tmpState[], cpRef.atSlot, save = false, tmpCache)
                withStateVars(tmpState[]):
                  let bdata = dag.getForkedBlock(blck)
                  withStateAndBlck(stateData.data, bdata):
                    when stateFork >= BeaconStateFork.Altair:
                      dag.cacheLightClientData(state, blck, isNew = false)
                    else: raiseAssert "Unreachable"

          # Create `LightClientUpdate` for non-finalized blocks.
          if blockRef.slot > finalizedSlot:
            dag.createLightClientUpdates(state, blck, blockRef.parent)
        else: raiseAssert "Unreachable"

  let lightClientEndTick = Moment.now()
  debug "Initialized cached light client data",
    initDur = lightClientEndTick - lightClientStartTick

  # Import historic data
  if dag.importLightClientData == ImportLightClientData.Full:
    let
      earliestSlot = dag.computeEarliestLightClientSlot
      earliestPeriod = earliestSlot.sync_committee_period
    for period in earliestPeriod ..< finalizedPeriod:
      dag.initBestLightClientUpdateForPeriod(period)
      dag.initLightClientBootstrapForPeriod(period)
    dag.initLightClientBootstrapForPeriod(finalizedPeriod)

proc getBestLightClientUpdateForPeriod*(
    dag: ChainDAGRef,
    period: SyncCommitteePeriod): Option[altair.LightClientUpdate] =
  if not dag.serveLightClientData:
    return none(altair.LightClientUpdate)

  if dag.importLightClientData == ImportLightClientData.OnDemand:
    dag.initBestLightClientUpdateForPeriod(period)
  result = some(dag.lightClientDb.bestUpdates.getOrDefault(period))
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result = none(altair.LightClientUpdate)

proc getLatestLightClientUpdate*(
    dag: ChainDAGRef): Option[altair.LightClientUpdate] =
  if not dag.serveLightClientData:
    return none(altair.LightClientUpdate)

  result = some(dag.lightClientDb.latestUpdate)
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result = none(altair.LightClientUpdate)

proc getOptimisticLightClientUpdate*(
    dag: ChainDAGRef): Option[OptimisticLightClientUpdate] =
  if not dag.serveLightClientData:
    return none(OptimisticLightClientUpdate)

  result = some(dag.lightClientDb.optimisticUpdate)
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result = none(OptimisticLightClientUpdate)

proc getLightClientBootstrap*(
    dag: ChainDAGRef,
    blockRoot: Eth2Digest): Option[altair.LightClientBootstrap] =
  if not dag.serveLightClientData:
    return none(altair.LightClientBootstrap)

  let blck = dag.getForkedBlock(blockRoot)
  if blck.isErr:
    debug "`LightClientBootstrap` unavailable: Block not found", blockRoot
    return none(altair.LightClientBootstrap)

  withBlck(blck.get):
    let slot = blck.message.slot
    when stateFork >= BeaconStateFork.Altair:
      let earliestSlot = dag.computeEarliestLightClientSlot
      if slot < earliestSlot:
        debug "`LightClientBootstrap` unavailable: Block too old", slot
        return none(altair.LightClientBootstrap)
      if slot > dag.finalizedHead.blck.slot:
        debug "`LightClientBootstrap` unavailable: Not finalized", blockRoot
        return none(altair.LightClientBootstrap)
      var cachedBootstrap =
        dag.lightClientDb.cachedBootstrap.getOrDefault(slot)
      if cachedBootstrap.current_sync_committee_branch.isZeroMemory:
        if dag.importLightClientData == ImportLightClientData.OnDemand:
          var tmpState = assignClone(dag.headState)
          dag.withUpdatedState(tmpState[], dag.getBlockAtSlot(slot)) do:
            withState(stateData.data):
              when stateFork >= BeaconStateFork.Altair:
                state.data.build_proof(
                  altair.CURRENT_SYNC_COMMITTEE_INDEX,
                  cachedBootstrap.current_sync_committee_branch)
              else: raiseAssert "Unreachable"
          do: raiseAssert "Unreachable"
          dag.lightClientDb.cachedBootstrap[slot] = cachedBootstrap
        else:
          debug "`LightClientBootstrap` unavailable: Data not cached", slot
          return none(altair.LightClientBootstrap)

      var tmpState = assignClone(dag.headState)
      var bootstrap {.noinit.}: altair.LightClientBootstrap
      bootstrap.header =
        BeaconBlockHeader.fromBlock(blck)
      bootstrap.current_sync_committee =
        dag.currentSyncCommitteeForPeriod(tmpState, slot.sync_committee_period)
      bootstrap.current_sync_committee_branch =
        cachedBootstrap.current_sync_committee_branch
      return some(bootstrap)
    else:
      debug "`LightClientBootstrap` unavailable: Block before Altair", slot
      return none(altair.LightClientBootstrap)
