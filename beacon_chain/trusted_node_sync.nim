import
  std/[os],

  stew/[assign2, base10],
  chronicles, chronos,
  ./sync/sync_manager,
  ./consensus_object_pools/blockchain_dag,
  ./spec/eth2_apis/rest_beacon_client,
  ./spec/[beaconstate, eth2_merkleization, forks, presets, state_transition],
  "."/[beacon_clock, beacon_chain_db]

{.push raises: [Defect].}

type
  DbCache = object
    summaries: Table[Eth2Digest, BeaconBlockSummary]
    slots: seq[Option[Eth2Digest]]

const
  emptyHash = Eth2Digest()

proc updateSlots(cache: var DbCache, root: Eth2Digest, slot: Slot) =
  # The slots mapping stores one linear block history - we construct it by
  # starting from a given root/slot and walking the known parents as far back
  # as possible - this ensures that
  if cache.slots.len() < slot.int + 1:
    cache.slots.setLen(slot.int + 1)

  var
    root = root
    lastSlot = slot

  while true:
    cache.summaries.withValue(root, v) do:
      let slot = v[].slot

      for i in slot.int + 1..<lastSlot.int: # Avoid re-querying known gaps
        cache.slots[i] = some(emptyHash)

      cache.slots[slot.int] = some(root)

      if slot == 0:
        return

      root = v[].parent_root
      lastSlot = slot
    do:
      return

proc update(cache: var DbCache, blck: ForkySignedBeaconBlock) =
  let
    slot = blck.message.slot

  if blck.root notin cache.summaries:
    cache.summaries[blck.root] = blck.message.toBeaconBlockSummary()

  cache.updateSlots(blck.root, blck.message.slot)

proc isKnown(cache: DbCache, slot: Slot): bool =
  slot.int < cache.slots.len and cache.slots[slot.int].isSome()

proc doTrustedNodeSync*(
    cfg: RuntimeConfig, databaseDir: string, restUrl: string,
    blockId: string, backfill: bool,
    genesisState: ref ForkedHashedBeaconState = nil) {.async.} =
  notice "Starting trusted node sync",
    databaseDir, restUrl, blockId

  let
    db = BeaconChainDB.new(databaseDir, inMemory = false)

  var
    dbCache = DbCache(summaries: db.loadSummaries())

  let
    dbHead = db.getHeadBlock()
    headSlot = if dbHead.isSome():
      if dbHead.get() notin dbCache.summaries:
        # This can happen with pre-blocksummary database - it's better to start
        # over in this case
        error "Database missing head block summary - database too old or corrupt"
        quit 1
      let slot =  dbCache.summaries[dbHead.get()].slot
      dbCache.updateSlots(dbHead.get(), slot)
      slot
    else:
      # When we don't have a head, we'll use the given checkpoint as head
      FAR_FUTURE_SLOT

  var client = RestClientRef.new(restUrl).get()

  proc downloadBlock(slot: Slot):
      Future[Option[ForkedSignedBeaconBlock]] {.async.} =
    # Download block at given slot, retrying a few times,
    var lastError: ref CatchableError
    for i in 0..<3:
      try:
        return await client.getBlockV2(BlockIdent.init(slot), cfg)
      except CatchableError as exc:
        lastError = exc
        warn "Retrying download of block", slot, err = exc.msg
        client = RestClientRef.new(restUrl).get()

    error "Unable to download block",
      slot, error = lastError.msg, url = client.address

    quit 1

  let
    dbGenesis = db.getGenesisBlock()
    genesisRoot = if dbGenesis.isSome():
      dbGenesis.get()
    else:
      let genesisState = if genesisState != nil:
        genesisState
      else:
        notice "Downloading genesis state", restUrl
        let state = try:
          await client.getStateV2(
            StateIdent.init(StateIdentType.Genesis), cfg)
        except CatchableError as exc:
          error "Unable to download genesis state",
            error = exc.msg, restUrl
          quit 1

        if isNil(state):
          error "Server is missing genesis state",
            restUrl
          quit 1
        state

      withState(genesisState[]):
        info "Writing genesis state",
          stateRoot = shortLog(state.root)

        db.putStateRoot(state.latest_block_root(), state.data.slot, state.root)
        db.putState(state.root, state.data)

        let blck = get_initial_beacon_block(state)

        info "Writing genesis block",
          blockRoot = shortLog(blck.root),
          blck = shortLog(blck.message)
        db.putBlock(blck)
        db.putGenesisBlock(blck.root)

        dbCache.update(blck.asSigned())
        blck.root

  let genesisHeader =
    try:
      (await client.getBlockHeader(BlockIdent.init(BlockIdentType.Genesis))).data.data
    except CatchableError as exc:
      error "Unable to download genesis header",
        error = exc.msg, restUrl
      quit 1
  if genesisHeader.root != genesisRoot:
    error "Server genesis block root does not match local genesis",
      localGenesis = shortLog(genesisRoot),
      remoteGenesis = shortLog(genesisHeader.root)
    quit 1

  notice "Downloading checkpoint block", restUrl, blockId
  let
    checkpointBlock = block:
      let blck =
        try:
          await client.getBlockV2(BlockIdent.decodeString(blockId).tryGet(), cfg)
        except CatchableError as exc:
          error "Unable to download checkpoint block",
            error = exc.msg, restUrl
          quit 1

      if blck.isNone():
        # TODO we could walk backwards in time here and get an earlier block
        error "No block found at the given slot, try a different slot",
          blockId
        quit 1

      blck.get()

    checkpointSlot = getForkedBlockField(checkpointBlock, slot)

  if checkpointSlot > headSlot:
    # When the checkpoint is newer than the head, we run into trouble: the
    # current backfill in ChainDAG does not support filling in arbitrary gaps.
    # If we were to update the backfill pointer in this case, the ChainDAG
    # backfiller would re-download the entire backfill history.
    # For now, we'll abort and let the user choose what to do.
    error "Checkpoint block is newer than head slot - start with a new database or use a checkpoint no more recent than the head",
      checkpointSlot, checkpointRoot = shortLog(checkpointBlock.root), headSlot
    quit 1

  if checkpointSlot.uint64 mod SLOTS_PER_EPOCH != 0:
    # Else the ChainDAG logic might get messed up - this constraint could
    # potentially be avoided with appropriate refactoring
    error "Checkpoint block must fall on an epoch boundary",
      checkpointSlot, checkpointRoot = shortLog(checkpointBlock.root), headSlot
    quit 1

  if checkpointBlock.root in dbCache.summaries:
    notice "Checkpoint block is already known, skipping checkpoint state download"

    withBlck(checkpointBlock):
      dbCache.updateSlots(blck.root, blck.message.slot)

  else:
    notice "Downloading checkpoint state", restUrl, blockId, checkpointSlot

    let
      state = try:
        await client.getStateV2(StateIdent.init(checkpointSlot), cfg)
      except CatchableError as exc:
        error "Unable to download checkpoint state",
          error = exc.msg, restUrl, checkpointSlot
        quit 1

    if isNil(state):
      notice "No state found at given checkpoint", checkpointSlot
      quit 1

    withState(state[]):
      info "Writing checkpoint state",
        stateRoot = shortLog(state.root)
      db.putStateRoot(state.latest_block_root(), state.data.slot, state.root)
      db.putState(state.root, state.data)

    withBlck(checkpointBlock):
      info "Writing checkpoint block",
        blockRoot = shortLog(blck.root),
        blck = shortLog(blck.message)

      db.putBlock(blck.asTrusted())
      db.putHeadBlock(blck.root)
      db.putTailBlock(blck.root)

      dbCache.update(blck)

  # Coming this far, we've done what ChainDAGRef.preInit would normally do -
  # Let's do a sanity check and start backfilling blocks from the trusted node
  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    error "Database not initialized after checkpoint sync, report bug",
      err = v.error()
    quit 1

  let missingSlots = block:
    var total = 0
    for i in 0..<checkpointSlot.int:
      if dbCache.slots[i].isNone():
        total += 1
    total

  if missingSlots == 0:
    info "Database fully backfilled"
  elif backfill:
    notice "Backfilling historical blocks",
      checkpointSlot, missingSlots

    var # Same averaging as SyncManager
      syncCount = 0
      processed = 0'u64
      avgSyncSpeed = 0.0
      stamp = SyncMoment.now(0)

    var gets: array[8, Future[Option[ForkedSignedBeaconBlock]]]
    proc processBlock(fut: Future[Option[ForkedSignedBeaconBlock]], slot: Slot) {.async.} =
      processed += 1
      var blck = await fut
      if blck.isNone():
        dbCache.slots[slot.int] = some emptyHash
        return

      let data = blck.get()
      withBlck(data):
        debug "Processing",
          blck = shortLog(blck.message),
          blockRoot = shortLog(blck.root)

        var childSlot = blck.message.slot + 1
        while true:
          if childSlot.int >= dbCache.slots.len():
            error "Downloaded block does not match checkpoint history"
            quit 1

          if not dbCache.slots[childSlot.int].isSome():
            # Should never happen - we download slots backwards
            error "Downloaded block does not match checkpoint history"
            quit 1

          let knownRoot = dbCache.slots[childSlot.int].get()
          if knownRoot == emptyHash:
            childSlot += 1
            continue

          dbCache.summaries.withValue(knownRoot, summary):
            if summary[].parent_root != blck.root:
              error "Downloaded block does not match checkpoint history",
                blockRoot = shortLog(blck.root),
                expectedRoot = shortLog(summary[].parent_root)
              quit 1

            break

          # This shouldn't happen - we should have downloaded the child and
          # updated knownBlocks before here
          error "Expected child block not found in checkpoint history"
          quit 1

        if blck.root notin dbCache.summaries:
          db.putBlock(blck.asTrusted())

        dbCache.update(blck)

        let newStamp = SyncMoment.now(processed)
        if newStamp.stamp - stamp.stamp > 12.seconds:
          syncCount += 1

          let
            remaining = blck.message.slot.int.float
            slotsPerSec = speed(stamp, newStamp)
          avgSyncSpeed = avgSyncSpeed + (slotsPerSec - avgSyncSpeed) / float(syncCount)

          info "Backfilling",
            timeleft = toTimeLeftString(
              if avgSyncSpeed >= 0.001:
                Duration.fromFloatSeconds(remaining / avgSyncSpeed)
              else: InfiniteDuration),
            avgSyncSpeed,
            remaining
          stamp = newStamp

    # Download blocks backwards from the checkpoint slot, skipping the ones we
    # already have in the database. We'll do a few downloads in parallel which
    # risks having some redundant downloads going on, but speeds things up
    for i in 0..checkpointSlot.int64 + gets.len():
      if not isNil(gets[i mod gets.len]):
        await processBlock(gets[i mod gets.len], Slot(
          gets.len().int64 + checkpointSlot.int64 - i))
        gets[i mod gets.len] = nil

      if i < checkpointSlot.int64:
        let slot = Slot(checkpointSlot.int64 - i)
        if dbCache.isKnown(slot):
          continue

        gets[i mod gets.len] = downloadBlock(slot)
  else:
    notice "Database initialized, historical blocks will be backfilled when starting the node",
      missingSlots

  notice "Done, your beacon node is ready to serve you! Don't forget to check that you're on the canoncial chain by comparing the checkpoint root with other online sources. See https://nimbus.guide/trusted-node-sync.html for more infromation.",
    checkpointRoot = checkpointBlock.root

when isMainModule:
  let backfill = os.paramCount() > 3 and os.paramStr(4) == "true"

  waitFor doTrustedNodeSync(
    defaultRuntimeConfig, os.paramStr(1), os.paramStr(2), os.paramStr(3),
    backfill)
