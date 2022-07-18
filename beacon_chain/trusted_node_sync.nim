# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  stew/base10,
  chronicles, chronos,
  ./sync/sync_manager,
  ./consensus_object_pools/blockchain_dag,
  ./spec/eth2_apis/rest_beacon_client,
  ./spec/[beaconstate, eth2_merkleization, forks, presets, state_transition],
  "."/[beacon_clock, beacon_chain_db]

type
  DbCache = object
    summaries: Table[Eth2Digest, BeaconBlockSummary]
    slots: seq[Option[Eth2Digest]]

proc updateSlots(cache: var DbCache, root: Eth2Digest, slot: Slot) =
  # The slots mapping stores one linear block history - we construct it by
  # starting from a given root/slot and walking the known parents as far back
  # as possible which ensures that all blocks belong to the same history

  if cache.slots.len() < slot.int + 1:
    cache.slots.setLen(slot.int + 1)

  var
    root = root
    lastSlot = slot

  while true:
    cache.summaries.withValue(root, v) do:
      let slot = v[].slot

      for i in slot.int + 1..<lastSlot.int: # Avoid re-querying known gaps
        cache.slots[i] = some(ZERO_HASH)

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
  slot < cache.slots.lenu64 and cache.slots[slot.int].isSome()

proc doTrustedNodeSync*(
    cfg: RuntimeConfig, databaseDir: string, restUrl: string,
    blockId: string, backfill: bool, reindex: bool,
    genesisState: ref ForkedHashedBeaconState = nil) {.async.} =
  notice "Starting trusted node sync",
    databaseDir, restUrl, blockId, backfill, reindex

  let
    db = BeaconChainDB.new(databaseDir, inMemory = false)
  defer:
    db.close()

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

      let slot = dbCache.summaries[dbHead.get()].slot
      dbCache.updateSlots(dbHead.get(), slot)
      slot
    else:
      # When we don't have a head, we'll use the given checkpoint as head
      FAR_FUTURE_SLOT

  var client = RestClientRef.new(restUrl).get()

  proc downloadBlock(slot: Slot):
      Future[Option[ref ForkedSignedBeaconBlock]] {.async.} =
    # Download block at given slot, retrying a few times,
    var lastError: ref CatchableError
    for i in 0..<3:
      try:
        return await client.getBlockV2(BlockIdent.init(slot), cfg)
      except CatchableError as exc:
        lastError = exc
        warn "Retrying download of block", slot, err = exc.msg
        client = RestClientRef.new(restUrl).get()

    error "Unable to download block - backfill incomplete, but will resume when you start the beacon node",
      slot, error = lastError.msg, url = client.address

    quit 1

  let
    dbGenesis = db.getGenesisBlock()
    localGenesisRoot = if dbGenesis.isSome():
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
          stateRoot = shortLog(state.root),
          genesis_validators_root = shortLog(state.data.genesis_validators_root)

        db.putState(state)

        let blck = get_initial_beacon_block(state)

        info "Writing genesis block",
          blockRoot = shortLog(blck.root),
          blck = shortLog(blck.message)
        db.putBlock(blck)
        db.putGenesisBlock(blck.root)

        dbCache.update(blck.asSigned())
        blck.root

    remoteGenesisRoot = try:
      (await client.getBlockRoot(
        BlockIdent.init(BlockIdentType.Genesis))).data.data.root
    except CatchableError as exc:
      error "Unable to download genesis block root",
        error = exc.msg, restUrl
      quit 1

  if remoteGenesisRoot != localGenesisRoot:
    error "Server genesis block root does not match local genesis, is the server serving the same chain?",
      localGenesisRoot = shortLog(localGenesisRoot),
      remoteGenesisRoot = shortLog(remoteGenesisRoot)
    quit 1

  let (checkpointSlot, checkpointRoot) = if dbHead.isNone:
    notice "Downloading checkpoint block", restUrl, blockId

    let checkpointBlock = block:
      # Finding a checkpoint block is tricky: we need the block to fall on an
      # epoch boundary and when making the first request, we don't know exactly
      # what slot we'll get - to find it, we'll keep walking backwards for a
      # reasonable number of tries
      var
        checkpointBlock: ref ForkedSignedBeaconBlock
        id = BlockIdent.decodeString(blockId).valueOr:
          error "Cannot decode checkpoint block id, must be a slot, hash, 'finalized' or 'head'",
            blockId
          quit 1
        found = false

      for i in 0..<10:
        let blck = try:
          await client.getBlockV2(id, cfg)
        except CatchableError as exc:
          error "Unable to download checkpoint block",
            error = exc.msg, restUrl
          quit 1

        if blck.isNone():
          # Server returned 404 - no block was found at the given id, so we need
          # to try an earlier slot - assuming we know of one!
          if id.kind == BlockQueryKind.Slot:
            let slot = id.slot
            id = BlockIdent.init((id.slot.epoch() - 1).start_slot)

            info "No block found at given slot, trying an earlier epoch",
              slot, id
            continue
          else:
            error "Cannot find a block at given block id, and cannot compute an earlier slot",
              id, blockId
            quit 1

        checkpointBlock = blck.get()

        let checkpointSlot = getForkedBlockField(checkpointBlock[], slot)
        if checkpointSlot.is_epoch():
          found = true
          break

        id = BlockIdent.init((checkpointSlot.epoch() - 1).start_slot)

        info "Downloaded checkpoint block does not fall on epoch boundary, trying an earlier epoch",
          checkpointSlot, id

      if not found:
        # The ChainDAG requires that the tail falls on an epoch boundary, or it
        # will be unable to load the corresponding state - this could be fixed, but
        # for now, we ask the user to fix it instead
        error "A checkpoint block from the first slot of an epoch could not be found with the given block id - pass an epoch slot with a block using the --block-id parameter",
          blockId
        quit 1
      checkpointBlock

    let checkpointSlot = getForkedBlockField(checkpointBlock[], slot)
    if checkpointBlock[].root in dbCache.summaries:
      notice "Checkpoint block is already known, skipping checkpoint state download"

      withBlck(checkpointBlock[]):
        dbCache.updateSlots(blck.root, blck.message.slot)

    else:
      notice "Downloading checkpoint state", restUrl, checkpointSlot

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
        let latest_block_root = state.latest_block_root

        if latest_block_root != checkpointBlock[].root:
          error "Checkpoint state does not match checkpoint block, server error?",
            blockRoot = shortLog(checkpointBlock[].root),
            blck = shortLog(checkpointBlock[]),
            stateBlockRoot = shortLog(latest_block_root)
          quit 1

        info "Writing checkpoint state",
          stateRoot = shortLog(state.root)
        db.putState(state)

      withBlck(checkpointBlock[]):
        info "Writing checkpoint block",
          blockRoot = shortLog(blck.root),
          blck = shortLog(blck.message)

        db.putBlock(blck.asTrusted())
        db.putHeadBlock(blck.root)
        db.putTailBlock(blck.root)

        dbCache.update(blck)
    (checkpointSlot, checkpointBlock[].root)
  else:
    notice "Skipping checkpoint download, database already exists",
      head = shortLog(dbHead.get())
    (headSlot, dbHead.get())

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

  let canReindex = if missingSlots == 0:
    info "Database fully backfilled"
    true
  elif backfill:
    notice "Downloading historical blocks - you can interrupt this process at any time and it automatically be completed when you start the beacon node",
      checkpointSlot, missingSlots

    var # Same averaging as SyncManager
      syncCount = 0
      processed = 0'u64
      avgSyncSpeed = 0.0
      stamp = SyncMoment.now(0)

    # Download several blocks in parallel but process them serially
    var gets: array[16, Future[Option[ref ForkedSignedBeaconBlock]]]
    proc processBlock(
        fut: Future[Option[ref ForkedSignedBeaconBlock]], slot: Slot) {.async.} =
      processed += 1
      var blck = await fut
      if blck.isNone():
        dbCache.slots[slot.int] = some ZERO_HASH
        return

      let data = blck.get()
      withBlck(data[]):
        debug "Processing",
          blck = shortLog(blck.message),
          blockRoot = shortLog(blck.root)

        var childSlot = blck.message.slot + 1
        while true:
          if childSlot >= dbCache.slots.lenu64():
            error "Downloaded block does not match checkpoint history"
            quit 1

          if not dbCache.slots[childSlot.int].isSome():
            # Should never happen - we download slots backwards
            error "Downloaded block does not match checkpoint history"
            quit 1

          let knownRoot = dbCache.slots[childSlot.int].get()
          if knownRoot == ZERO_HASH:
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
            remaining = blck.message.slot.int
            slotsPerSec = speed(stamp, newStamp)
          avgSyncSpeed = avgSyncSpeed + (slotsPerSec - avgSyncSpeed) / float(syncCount)

          info "Backfilling",
            timeleft = toTimeLeftString(
              if avgSyncSpeed >= 0.001:
                Duration.fromFloatSeconds(remaining.float / avgSyncSpeed)
              else: InfiniteDuration),
            slotsPerSecond = avgSyncSpeed,
            remainingSlots = remaining
          stamp = newStamp

    # Download blocks backwards from the checkpoint slot, skipping the ones we
    # already have in the database. We'll do a few downloads in parallel which
    # risks having some redundant downloads going on, but speeds things up
    for i in 0'u64..<(checkpointSlot.uint64 + gets.lenu64()):
      if not isNil(gets[int(i mod gets.lenu64)]):
        await processBlock(
          gets[int(i mod gets.lenu64)],
          checkpointSlot + gets.lenu64() - uint64(i))
        gets[int(i mod gets.lenu64)] = nil

      if i < checkpointSlot:
        let slot = checkpointSlot - i
        if dbCache.isKnown(slot):
          continue

        gets[int(i mod gets.lenu64)] = downloadBlock(slot)

      if i mod 1024 == 0:
        db.checkpoint() # Transfer stuff from wal periodically
    true
  else:
    notice "Database initialized, historical blocks will be backfilled when starting the node",
      missingSlots

    false

  if reindex and canReindex:
    notice "Reindexing historical state lookup tables (you can interrupt this process at any time)"

    # Build a DAG
    let
      validatorMonitor = newClone(ValidatorMonitor.init(false, false))
      dag = ChainDAGRef.init(cfg, db, validatorMonitor, {})

    dag.rebuildIndex()

  notice "Done, your beacon node is ready to serve you! Don't forget to check that you're on the canoncial chain by comparing the checkpoint root with other online sources. See https://nimbus.guide/trusted-node-sync.html for more information.",
    checkpointRoot

when isMainModule:
  import std/[os]

  let backfill = os.paramCount() > 3 and os.paramStr(4) == "true"

  waitFor doTrustedNodeSync(
    defaultRuntimeConfig, os.paramStr(1), os.paramStr(2), os.paramStr(3),
    backfill)
