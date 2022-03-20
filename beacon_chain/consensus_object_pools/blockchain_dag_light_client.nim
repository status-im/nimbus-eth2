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

template nextEpochBoundarySlot(slot: Slot): Slot =
  ## Compute the first possible epoch boundary state slot of a `Checkpoint`
  ## referring to a block at given slot.
  (slot + (SLOTS_PER_EPOCH - 1)).epoch.start_slot

func computeEarliestLightClientSlot*(dag: ChainDAGRef): Slot =
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
    dag: ChainDAGRef, state: var ForkedHashedBeaconState,
    bsiParam: BlockSlotId, okBody: untyped, failureBody: untyped): untyped =
  ## Wrapper around `withUpdatedState` for states expected to exist.
  block:
    let bsi = bsiParam
    dag.withUpdatedState(state, bsiParam) do:
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

proc existingParent*(dag: ChainDAGRef, bid: BlockId): Opt[BlockId] =
  ## Wrapper around `parent` for parents known to exist.
  let parent = dag.parent(bid)
  if parent.isErr:
    error "Parent failed to load unexpectedly", bid, tail = dag.tail.slot
    doAssert verifyFinalization notin dag.updateFlags
  parent

proc getExistingForkedBlock(dag: ChainDAGRef, root: Eth2Digest):
    Opt[ForkedTrustedSignedBeaconBlock] =
  ## Wrapper around `getForkedBlock` for blocks expected to exist.
  let bdata = dag.getForkedBlock(root)
  if bdata.isErr:
    error "Block failed to load unexpectedly", root, tail = dag.tail.slot
    doAssert verifyFinalization notin dag.updateFlags
  bdata

proc getExistingForkedBlock*(
    dag: ChainDAGRef, bid: BlockId): Opt[ForkedTrustedSignedBeaconBlock] =
  ## Wrapper around `getForkedBlock` for blocks expected to exist.
  let bdata = dag.getForkedBlock(bid)
  if bdata.isErr:
    error "Block failed to load unexpectedly", bid, tail = dag.tail.slot
    doAssert verifyFinalization notin dag.updateFlags
  bdata

proc currentSyncCommitteeForPeriod(
    dag: ChainDAGRef,
    tmpState: var ForkedHashedBeaconState,
    period: SyncCommitteePeriod): Opt[SyncCommittee] =
  ## Fetch a `SyncCommittee` for a given sync committee period.
  ## For non-finalized periods, follow the chain as selected by fork choice.
  let earliestSlot = dag.computeEarliestLightClientSlot
  doAssert period >= earliestSlot.sync_committee_period
  let
    periodStartSlot = period.start_slot
    syncCommitteeSlot = max(periodStartSlot, earliestSlot)
    bsi = ? dag.getExistingBlockIdAtSlot(syncCommitteeSlot)
  dag.withUpdatedExistingState(tmpState, bsi) do:
    withState(state):
      when stateFork >= BeaconStateFork.Altair:
        ok state.data.current_sync_committee
      else: raiseAssert "Unreachable"
  do: err()

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
  let earliestSlot = dag.computeEarliestLightClientSlot
  doAssert period >= earliestSlot.sync_committee_period
  let
    periodStartSlot = period.start_slot
    syncCommitteeSlot = max(periodStartSlot, earliestSlot)
    bsi = ? dag.getExistingBlockIdAtSlot(syncCommitteeSlot)
  dag.withUpdatedExistingState(tmpState, bsi) do:
    withState(state):
      when stateFork >= BeaconStateFork.Altair:
        ok state.syncCommitteeRoot
      else: raiseAssert "Unreachable"
  do: err()

proc getLightClientData(
    dag: ChainDAGRef,
    bid: BlockId): CachedLightClientData =
  ## Fetch cached light client data about a given block.
  ## Data must be cached (`cacheLightClientData`) before calling this function.
  try: dag.lightClientCache.data[bid]
  except KeyError: raiseAssert "Unreachable"

proc cacheLightClientData*(
    dag: ChainDAGRef,
    state: HashedBeaconStateWithSyncCommittee,
    blck: TrustedSignedBeaconBlockWithSyncAggregate) =
  ## Cache data for a given block and its post-state to speed up creating future
  ## `LightClientUpdate` and `LightClientBootstrap` instances that refer to this
  ## block and state.
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

  let
    bid =
      BlockId(root: blck.root, slot: blck.message.slot)
    earliest_slot =
      dag.computeEarliestLightClientSlot
    finalized_slot =
      state.data.finalized_checkpoint.epoch.start_slot
    finalized_bsi =
      if finalized_slot >= earliest_slot:
        dag.getExistingBlockIdAtSlot(finalized_slot).valueOr:
          default(BlockSlotId) # Ignored in `createLightClientUpdates`
      else:
        default(BlockSlotId) # Ignored in `createLightClientUpdates`
  if dag.lightClientCache.data.hasKeyOrPut(
      bid,
      CachedLightClientData(
        current_sync_committee_branch:
          current_sync_committee_branch,
        next_sync_committee_branch:
          next_sync_committee_branch,
        finalized_bid:
          finalized_bsi.bid,
        finality_branch:
          finality_branch)):
    doAssert false, "Redundant `cacheLightClientData` call"

proc deleteLightClientData*(dag: ChainDAGRef, bid: BlockId) =
  ## Delete cached light client data for a given block. This needs to be called
  ## when a block becomes unreachable due to finalization of a different fork.
  if dag.importLightClientData == ImportLightClientData.None:
    return

  dag.lightClientCache.data.del bid

template lazy_header(name: untyped): untyped {.dirty.} =
  ## `createLightClientUpdates` helper to lazily load a known block header.
  var `name ptr`: ptr[BeaconBlockHeader]
  template `assign name`(target: var BeaconBlockHeader,
                         bid: BlockId): untyped =
    if `name ptr` != nil:
      target = `name ptr`[]
    else:
      let bdata = dag.getExistingForkedBlock(bid).valueOr:
        return
      target = toBeaconBlockHeader(bdata)
      `name ptr` = addr target

template lazy_data(name: untyped): untyped {.dirty.} =
  ## `createLightClientUpdates` helper to lazily load cached light client state.
  var `name` {.noinit.}: CachedLightClientData
  `name`.finalized_bid.slot = FAR_FUTURE_SLOT
  template `load name`(bid: BlockId): untyped =
    if `name`.finalized_bid.slot == FAR_FUTURE_SLOT:
      `name` = dag.getLightClientData(bid)

proc createLightClientUpdates(
    dag: ChainDAGRef,
    state: HashedBeaconStateWithSyncCommittee,
    blck: TrustedSignedBeaconBlockWithSyncAggregate,
    parent_bid: BlockId) =
  ## Create `LightClientUpdate` and `OptimisticLightClientUpdate` instances for
  ## a given block and its post-state, and keep track of best / latest ones.
  ## Data about the parent block's post-state and its `finalized_checkpoint`'s
  ## block's post-state needs to be cached (`cacheLightClientData`) before
  ## calling this function.

  # Verify sync committee has sufficient participants
  template sync_aggregate(): auto = blck.message.body.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64
  if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return

  # Verify attested block (parent) is recent enough and that state is available
  let
    earliest_slot = dag.computeEarliestLightClientSlot
    attested_slot = parent_bid.slot
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
  template optimistic_update(): auto = dag.lightClientCache.optimisticUpdate
  if attested_slot > optimistic_update.attested_header.slot:
    optimistic_update.attested_header
      .assign_attested_header(parent_bid)
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
  template latest_update(): auto = dag.lightClientCache.latestUpdate
  if attested_slot > latest_update.attested_header.slot:
    latest_update.attested_header
      .assign_attested_header(parent_bid)
    latest_update.sync_aggregate =
      isomorphicCast[SyncAggregate](sync_aggregate)
    latest_update.fork_version =
      state.data.fork.current_version

    load_attested_data(parent_bid)
    let finalized_slot = attested_data.finalized_bid.slot
    if finalized_slot + UPDATE_TIMEOUT < attested_slot or
        finalized_slot < earliest_slot or
        attested_data.finalized_bid.root.isZero:
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
        dag.lightClientCache.bestUpdates.getOrDefault(signature_period)
      else:
        let key = (signature_period, state.syncCommitteeRoot)
        dag.lightClientCache.pendingBestUpdates.getOrDefault(key)

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
          load_attested_data(parent_bid)
          let finalized_slot = attested_data.finalized_bid.slot
          if signature_period == finalized_slot.sync_committee_period and
              finalized_slot >= earliest_slot:
            verdict = new_update_is_better
      elif attested_slot > dag.finalizedHead.slot or
          attested_slot < best_attested_slot:
        if signature_period == finalized_period_at_signature:
          load_attested_data(parent_bid)
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
        .assign_attested_header(parent_bid)
      best_update.sync_aggregate =
        isomorphicCast[SyncAggregate](sync_aggregate)
      best_update.fork_version =
        state.data.fork.current_version

      load_attested_data(parent_bid)
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
        dag.lightClientCache.bestUpdates[signature_period] = best_update
        debug "Best update for period improved",
          period = signature_period, update = best_update
      else:
        let key = (signature_period, state.syncCommitteeRoot)
        dag.lightClientCache.pendingBestUpdates[key] = best_update
        debug "Best update for period improved",
          period = key, update = best_update

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
    dag.cacheLightClientData(state.bellatrixData, signedBlock)
    dag.createLightClientUpdates(state.bellatrixData, signedBlock, parentBid)
  elif signedBlock is altair.TrustedSignedBeaconBlock:
    dag.cacheLightClientData(state.altairData, signedBlock)
    dag.createLightClientUpdates(state.altairData, signedBlock, parentBid)
  elif signedBlock is phase0.TrustedSignedBeaconBlock:
    raiseAssert "Unreachable" # These cannot occur after `earliestSlot`
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
        let
          syncCommitteeRoot =
            dag.syncCommitteeRootForPeriod(tmpState[], period).valueOr:
              continue
          key = (period, syncCommitteeRoot)
        dag.lightClientCache.bestUpdates[period] =
          dag.lightClientCache.pendingBestUpdates.getOrDefault(key)
    withState(dag.headState):
      when stateFork >= BeaconStateFork.Altair:
        let key = (headPeriod, state.syncCommitteeRoot)
        dag.lightClientCache.bestUpdates[headPeriod] =
          dag.lightClientCache.pendingBestUpdates.getOrDefault(key)
      else: raiseAssert "Unreachable"

proc processFinalizationForLightClient*(dag: ChainDAGRef) =
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

  # Keep track of latest four finalized checkpoints
  let
    lastIndex = dag.lightClientCache.lastCheckpointIndex
    lastCheckpoint = addr dag.lightClientCache.latestCheckpoints[lastIndex]
  if dag.finalizedHead.slot.epoch != lastCheckpoint.epoch or
      dag.finalizedHead.blck.root != lastCheckpoint.root:
    let
      nextIndex = (lastIndex + 1) mod dag.lightClientCache.latestCheckpoints.len
      nextCheckpoint = addr dag.lightClientCache.latestCheckpoints[nextIndex]
    nextCheckpoint[].epoch = dag.finalizedHead.slot.epoch
    nextCheckpoint[].root = dag.finalizedHead.blck.root
    dag.lightClientCache.lastCheckpointIndex = nextIndex

    # Cache `LightClientBootstrap` for newly finalized epoch boundary blocks.
    # Epoch boundary blocks are the block for the initial slot of an epoch,
    # or the most recent block if no block was proposed at that slot
    let lowSlot = max(lastCheckpoint[].epoch.start_slot, earliestSlot)
    var boundarySlot = dag.finalizedHead.slot
    while boundarySlot >= lowSlot:
      let
        bsi = dag.getExistingBlockIdAtSlot(boundarySlot).valueOr:
          break
        bid = bsi.bid
      if bid.slot >= lowSlot:
        dag.lightClientCache.bootstrap[bid.slot] =
          CachedLightClientBootstrap(
            current_sync_committee_branch:
              dag.getLightClientData(bid).current_sync_committee_branch)
      boundarySlot = bid.slot.nextEpochBoundarySlot
      if boundarySlot < SLOTS_PER_EPOCH:
        break
      boundarySlot -= SLOTS_PER_EPOCH

  # Prune light client data that is no longer relevant,
  # i.e., can no longer be referred to by future updates, or is too old
  var bidsToDelete: seq[BlockId]
  for bid, data in dag.lightClientCache.data:
    if bid.slot >= earliestSlot:
      if bid.slot >= finalizedSlot:
        continue
      if dag.lightClientCache.latestCheckpoints.anyIt(bid.root == it.root):
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
  for period in dag.lightClientCache.bestUpdates.keys:
    if period < earliestPeriod:
      periodsToDelete.add period
  for period in periodsToDelete:
    dag.lightClientCache.bestUpdates.del period

  # Prune best `LightClientUpdate` referring to non-finalized sync committees
  # that are no longer relevant, i.e., orphaned or too old
  let finalizedPeriod = finalizedSlot.sync_committee_period
  var keysToDelete: seq[(SyncCommitteePeriod, Eth2Digest)]
  for (period, committeeRoot) in dag.lightClientCache.pendingBestUpdates.keys:
    if period <= finalizedPeriod:
      keysToDelete.add (period, committeeRoot)
  for key in keysToDelete:
    dag.lightClientCache.pendingBestUpdates.del key

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
  if dag.lightClientCache.bestUpdates.hasKey(period):
    return
  let startTick = Moment.now()
  debug "Computing best update for period", period
  proc logBestUpdate(endTick = Moment.now()) =
    # Using a helper function reduces code size as the `defer` beneath is
    # replicated on every `return`, and the log statement allocates another
    # copy of the arguments on the stack for each instantiation (~1 MB stack!)
    debug "Best update for period computed",
      period, update = dag.lightClientCache.bestUpdates.getOrDefault(period),
      computeDur = endTick - startTick
  defer: logBestUpdate()

  proc maxParticipantsBlock(
      dag: ChainDAGRef, highBid: BlockId, lowSlot: Slot): Option[BlockId] =
    ## Determine the earliest block with most sync committee signatures among
    ## ancestors of `highBid` with at least `lowSlot` as parent block slot.
    ## Return `none` if no block with `MIN_SYNC_COMMITTEE_PARTICIPANTS` exists.
    var
      maxParticipants = 0
      maxBid: Option[BlockId]
      bid = highBid
    while true:
      let parentBid = dag.parent(bid).valueOr:
        break
      if parentBid.slot < lowSlot:
        break
      let
        bdata = dag.getExistingForkedBlock(bid).valueOr:
          break
        numParticipants =
          withBlck(bdata):
            when stateFork >= BeaconStateFork.Altair:
              countOnes(blck.message.body.sync_aggregate.sync_committee_bits)
            else: raiseAssert "Unreachable"
      if numParticipants >= maxParticipants:
        maxParticipants = numParticipants
        maxBid = some bid
      bid = parentBid
    if maxParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
      maxBid.reset()
    maxBid

  # Determine the block in the period with highest sync committee participation
  let
    lowSlot = max(periodStartSlot, earliestSlot)
    highSlot = min(periodEndSlot, dag.finalizedHead.blck.slot)
    highBsi = dag.getExistingBlockIdAtSlot(highSlot).valueOr:
      return
    highBid = highBsi.bid
    bestNonFinalizedBid = dag.maxParticipantsBlock(highBid, lowSlot)
  if bestNonFinalizedBid.isNone:
    dag.lightClientCache.bestUpdates[period] = default(altair.LightClientUpdate)
    return

  # The block with highest participation may refer to a `finalized_checkpoint`
  # in a different sync committee period. If that is the case, search for a
  # later block with a `finalized_checkpoint` within the given sync committee
  # period, despite it having a lower sync committee participation
  var
    tmpState = assignClone(dag.headState)
    bestFinalizedBid = bestNonFinalizedBid
    finalizedBid {.noinit.}: BlockId
    bestFinalizedHasCheckpointInPeriod = false
  while bestFinalizedBid.isSome:
    defer:
      if not bestFinalizedHasCheckpointInPeriod:
        let newLowSlot = bestFinalizedBid.get.slot + 1
        bestFinalizedBid = dag.maxParticipantsBlock(highBid, newLowSlot)
    let
      attestedBid = dag.existingParent(bestFinalizedBid.get).valueOr:
        continue
      finalizedEpoch = block:
        dag.withUpdatedExistingState(tmpState[], attestedBid.atSlot) do:
          withState(state):
            when stateFork >= BeaconStateFork.Altair:
              state.data.finalized_checkpoint.epoch
            else: raiseAssert "Unreachable"
        do: continue
      finalizedSlot = finalizedEpoch.start_slot
    if finalizedSlot >= lowSlot:
      let finalizedBsi = dag.getExistingBlockIdAtSlot(finalizedSlot).valueOr:
        continue
      finalizedBid = finalizedBsi.bid
      if finalizedBid.slot >= lowSlot:
        bestFinalizedHasCheckpointInPeriod = true
        break

  # If a finalized block has been found within the sync commitee period,
  # create a `LightClientUpdate` for that one. Otherwise, create a non-finalized
  # `LightClientUpdate`
  var update {.noinit.}: LightClientUpdate
  if bestFinalizedBid.isSome:
    # Fill data from attested block
    let attestedBid = dag.existingParent(bestFinalizedBid.get).valueOr:
      return
    dag.withUpdatedExistingState(tmpState[], attestedBid.atSlot) do:
      let bdata = dag.getExistingForkedBlock(bid).valueOr:
        return
      withStateAndBlck(state, bdata):
        when stateFork >= BeaconStateFork.Altair:
          update.attested_header =
            blck.toBeaconBlockHeader
          state.data.build_proof(
            altair.FINALIZED_ROOT_INDEX, update.finality_branch)
        else: raiseAssert "Unreachable"
    do: return

    # Fill data from signature block
    let bdata = dag.getExistingForkedBlock(bestFinalizedBid.get).valueOr:
      return
    withBlck(bdata):
      when stateFork >= BeaconStateFork.Altair:
        update.sync_aggregate =
          isomorphicCast[SyncAggregate](blck.message.body.sync_aggregate)
      else: raiseAssert "Unreachable"
    update.fork_version =
      dag.cfg.forkAtEpoch(bestFinalizedBid.get.slot.epoch).current_version

    # Fill data from finalized block
    dag.withUpdatedExistingState(tmpState[], finalizedBid.atSlot) do:
      let bdata = dag.getExistingForkedBlock(bid).valueOr:
        return
      withStateAndBlck(state, bdata):
        when stateFork >= BeaconStateFork.Altair:
          update.next_sync_committee =
            state.data.next_sync_committee
          state.data.build_proof(
            altair.NEXT_SYNC_COMMITTEE_INDEX, update.next_sync_committee_branch)
          update.finalized_header =
            blck.toBeaconBlockHeader
        else: raiseAssert "Unreachable"
    do: return
  else:
    # Fill data from attested block
    let attestedBid = dag.existingParent(bestNonFinalizedBid.get).valueOr:
      return
    dag.withUpdatedExistingState(tmpState[], attestedBid.atSlot) do:
      let bdata = dag.getExistingForkedBlock(bid).valueOr:
        return
      withStateAndBlck(state, bdata):
        when stateFork >= BeaconStateFork.Altair:
          update.attested_header =
            blck.toBeaconBlockHeader
          update.next_sync_committee =
            state.data.next_sync_committee
          state.data.build_proof(
            altair.NEXT_SYNC_COMMITTEE_INDEX, update.next_sync_committee_branch)
          update.finalized_header = BeaconBlockHeader()
          update.finality_branch.fill(Eth2Digest())
        else: raiseAssert "Unreachable"
    do: raiseAssert "Unreachable"

    # Fill data from signature block
    let bdata = dag.getExistingForkedBlock(bestNonFinalizedBid.get).valueOr:
      return
    withBlck(bdata):
      when stateFork >= BeaconStateFork.Altair:
        update.sync_aggregate =
          isomorphicCast[SyncAggregate](blck.message.body.sync_aggregate)
      else: raiseAssert "Unreachable"
    update.fork_version =
      dag.cfg.forkAtEpoch(bestNonFinalizedBid.get.slot.epoch).current_version
  dag.lightClientCache.bestUpdates[period] = update

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
  debug "Caching bootstrap data for period", period
  defer:
    let endTick = Moment.now()
    debug "Bootstrap data for period cached", period,
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
        continue
      bid = bsi.bid
      boundarySlot = bid.slot.nextEpochBoundarySlot
    if boundarySlot == nextBoundarySlot and
        bid.slot >= lowSlot and bid.slot <= highSlot and
        not dag.lightClientCache.bootstrap.hasKey(bid.slot):
      var cachedBootstrap {.noinit.}: CachedLightClientBootstrap
      if not dag.updateExistingState(
          tmpState[], bid.atSlot, save = false, tmpCache):
        continue
      withStateVars(tmpState[]):
        withState(state):
          when stateFork >= BeaconStateFork.Altair:
            state.data.build_proof(
              altair.CURRENT_SYNC_COMMITTEE_INDEX,
              cachedBootstrap.current_sync_committee_branch)
          else: raiseAssert "Unreachable"
      dag.lightClientCache.bootstrap[bid.slot] = cachedBootstrap

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

  let
    finalizedSlot = dag.finalizedHead.slot
    finalizedPeriod = finalizedSlot.sync_committee_period
  dag.initBestLightClientUpdateForPeriod(finalizedPeriod)

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
    dag.lightClientCache.importTailSlot = buggedBid.slot + 1
    earliestSlot = dag.computeEarliestLightClientSlot

  # Build lists of block to process.
  # As it is slow to load states in descending order,
  # first build a todo list, then process them in ascending order
  let lowSlot = max(finalizedSlot, earliestSlot)
  var
    blocksBetween = newSeqOfCap[BlockId](dag.head.slot - lowSlot + 1)
    bid = dag.head.bid
  while bid.slot > lowSlot:
    blocksBetween.add bid
    bid = dag.existingParent(bid).valueOr:
      handleUnexpectedError(bid)
      break
  if bid.slot >= earliestSlot:
    # Add the finalized head itself (`== lowSlot`, or the last block before it)
    blocksBetween.add bid

  # Process blocks (reuses `dag.headState`, but restores it to the current head)
  var
    tmpState = assignClone(dag.headState)
    tmpCache, cache: StateCache
    oldCheckpoint: Checkpoint
    cpIndex = 0
  for i in countdown(blocksBetween.high, blocksBetween.low):
    bid = blocksBetween[i]
    if not dag.updateExistingState(
        dag.headState, bid.atSlot, save = false, cache):
      handleUnexpectedError(bid)
      continue
    withStateVars(dag.headState):
      let bdata = dag.getExistingForkedBlock(bid).valueOr:
        handleUnexpectedError(bid)
        continue
      withStateAndBlck(state, bdata):
        when stateFork >= BeaconStateFork.Altair:
          # Cache data for `LightClientUpdate` of descendant blocks
          dag.cacheLightClientData(state, blck)

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
            doAssert cpIndex < dag.lightClientCache.latestCheckpoints.len
            dag.lightClientCache.latestCheckpoints[cpIndex] = checkpoint
            dag.lightClientCache.lastCheckpointIndex = cpIndex
            inc cpIndex

            # Save new checkpoint block using `tmpState` (avoid replay after it)
            # Note that light client finality proofs refer to checkpoint blocks
            # at their original slot, without advancing to an epoch boundary.
            # This is because light clients are unable to advance slots.
            if checkpoint.root != dag.finalizedHead.blck.root:
              let cpSlot = checkpoint.epoch.start_slot
              if cpSlot >= earliestSlot:
                let
                  cpBsi = dag.getExistingBlockIdAtSlot(cpSlot).valueOr:
                    handleUnexpectedError(bid)
                    continue
                  cpBid = cpBsi.bid
                if cpBid.slot >= earliestSlot:
                  assert cpBid.root == checkpoint.root
                  if not dag.updateExistingState(
                      tmpState[], cpBid.atSlot, save = false, tmpCache):
                    handleUnexpectedError(bid)
                    continue
                  withStateVars(tmpState[]):
                    let bdata = dag.getExistingForkedBlock(cpBid).valueOr:
                      handleUnexpectedError(bid)
                      continue
                    withStateAndBlck(state, bdata):
                      when stateFork >= BeaconStateFork.Altair:
                        dag.cacheLightClientData(state, blck)
                      else: raiseAssert "Unreachable"

          # Create `LightClientUpdate` for non-finalized blocks.
          if bid.slot > finalizedSlot:
            let parentBid = dag.existingParent(bid).valueOr:
              handleUnexpectedError(bid)
              continue
            dag.createLightClientUpdates(state, blck, parentBid)
        else: raiseAssert "Unreachable"

  let lightClientEndTick = Moment.now()
  debug "Initialized cached light client data",
    initDur = lightClientEndTick - lightClientStartTick

  # Import historic data
  if dag.importLightClientData == ImportLightClientData.Full:
    let
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
  result = some(dag.lightClientCache.bestUpdates.getOrDefault(period))
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result = none(altair.LightClientUpdate)

proc getLatestLightClientUpdate*(
    dag: ChainDAGRef): Option[altair.LightClientUpdate] =
  if not dag.serveLightClientData:
    return none(altair.LightClientUpdate)

  result = some(dag.lightClientCache.latestUpdate)
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result = none(altair.LightClientUpdate)

proc getOptimisticLightClientUpdate*(
    dag: ChainDAGRef): Option[OptimisticLightClientUpdate] =
  if not dag.serveLightClientData:
    return none(OptimisticLightClientUpdate)

  result = some(dag.lightClientCache.optimisticUpdate)
  let numParticipants = countOnes(result.get.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    result = none(OptimisticLightClientUpdate)

proc getLightClientBootstrap*(
    dag: ChainDAGRef,
    blockRoot: Eth2Digest): Opt[altair.LightClientBootstrap] =
  if not dag.serveLightClientData:
    return err()

  let bdata = dag.getForkedBlock(blockRoot).valueOr:
    debug "Bootstrap unavailable: Block not found", blockRoot
    return err()

  withBlck(bdata):
    let slot = blck.message.slot
    when stateFork >= BeaconStateFork.Altair:
      let earliestSlot = dag.computeEarliestLightClientSlot
      if slot < earliestSlot:
        debug "Bootstrap unavailable: Block too old", slot
        return err()
      if slot > dag.finalizedHead.blck.slot:
        debug "Bootstrap unavailable: Not finalized", blockRoot
        return err()
      var cachedBootstrap =
        dag.lightClientCache.bootstrap.getOrDefault(slot)
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
          debug "Bootstrap unavailable: Data not cached", slot
          return err()

      let period = slot.sync_committee_period
      var tmpState = assignClone(dag.headState)
      var bootstrap {.noinit.}: altair.LightClientBootstrap
      bootstrap.header =
        blck.toBeaconBlockHeader
      bootstrap.current_sync_committee =
        ? dag.currentSyncCommitteeForPeriod(tmpState[], period)
      bootstrap.current_sync_committee_branch =
        cachedBootstrap.current_sync_committee_branch
      return ok bootstrap
    else:
      debug "Bootstrap unavailable: Block before Altair", slot
      return err()
