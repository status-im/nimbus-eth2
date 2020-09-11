  import
  confutils, stats, chronicles, strformat, tables,
  stew/byteutils,
  ../beacon_chain/network_metadata,
  ../beacon_chain/[beacon_chain_db, extras],
  ../beacon_chain/block_pools/[chain_dag],
  ../beacon_chain/spec/[crypto, datatypes, digest, helpers,
                        state_transition, presets],
  ../beacon_chain/sszdump, ../research/simutils,
  eth/db/[kvstore, kvstore_sqlite3]

type Timers = enum
  tInit = "Initialize DB"
  tLoadBlock = "Load block from database"
  tLoadState = "Load state from database"
  tApplyBlock = "Apply block"
  tApplyEpochBlock = "Apply epoch block"
  tDbStore = "Database block store"

type
  DbCmd* = enum
    bench
    dumpState
    dumpBlock
    pruneDatabase
    rewindState

  # TODO:
  # This should probably allow specifying a run-time preset
  DbConf = object
    databaseDir* {.
        defaultValue: ""
        desc: "Directory where `nbc.sqlite` is stored"
        name: "db" }: InputDir

    eth2Network* {.
      desc: "The Eth2 network preset to use"
      name: "network" }: Option[string]

    case cmd* {.
      command
      desc: ""
      .}: DbCmd

    of bench:
      slots* {.
        defaultValue: 50000
        desc: "Number of slots to run benchmark for".}: uint64
      storeBlocks* {.
        defaultValue: false
        desc: "Store each read block back into a separate database".}: bool

    of dumpState:
      stateRoot* {.
        argument
        desc: "State roots to save".}: seq[string]

    of dumpBlock:
      blockRootx* {.
        argument
        desc: "Block roots to save".}: seq[string]

    of pruneDatabase:
      dryRun* {.
        defaultValue: false
        desc: "Don't write to the database copy; only simulate actions; default false".}: bool
      keepOldStates* {.
        defaultValue: true
        desc: "Keep pre-finalization states; default true".}: bool
      verbose* {.
        defaultValue: false
        desc: "Enables verbose output; default false".}: bool

    of rewindState:
      blockRoot* {.
        argument
        desc: "Block root".}: string

      slot* {.
        argument
        desc: "Slot".}: uint64

proc cmdBench(conf: DbConf, runtimePreset: RuntimePreset) =
  var timers: array[Timers, RunningStat]

  echo "Opening database..."
  let
    db = BeaconChainDB.init(
      kvStore SqStoreRef.init(conf.databaseDir.string, "nbc").tryGet())
    dbBenchmark = BeaconChainDB.init(
      kvStore SqStoreRef.init(".", "benchmark").tryGet())

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let pool = withTimerRet(timers[tInit]):
    ChainDAGRef.init(runtimePreset, db, {})

  echo &"Loaded {pool.blocks.len} blocks, head slot {pool.head.slot}"

  var
    blockRefs: seq[BlockRef]
    blocks: seq[TrustedSignedBeaconBlock]
    cur = pool.head

  while cur != nil:
    blockRefs.add cur
    cur = cur.parent

  for b in 1..<blockRefs.len: # Skip genesis block
    if blockRefs[blockRefs.len - b - 1].slot > conf.slots:
      break

    withTimer(timers[tLoadBlock]):
      blocks.add db.getBlock(blockRefs[blockRefs.len - b - 1].root).get()

  let state = (ref HashedBeaconState)(
    root: db.getBlock(blockRefs[^1].root).get().message.state_root
  )

  withTimer(timers[tLoadState]):
    discard db.getState(state[].root, state[].data, noRollback)

  for b in blocks:
    let
      isEpoch = state[].data.get_current_epoch() !=
        b.message.slot.compute_epoch_at_slot
    withTimer(timers[if isEpoch: tApplyEpochBlock else: tApplyBlock]):
      if not state_transition(runtimePreset, state[], b, {}, noRollback):
        dump("./", b)
        echo "State transition failed (!)"
        quit 1
    if conf.storeBlocks:
      withTimer(timers[tDbStore]):
        dbBenchmark.putBlock(b)

  printTimers(false, timers)

proc cmdDumpState(conf: DbConf) =
  let
    db = BeaconChainDB.init(
      kvStore SqStoreRef.init(conf.databaseDir.string, "nbc").tryGet())

  for stateRoot in conf.stateRoot:
    try:
      let root = Eth2Digest(data: hexToByteArray[32](stateRoot))
      var state = (ref HashedBeaconState)(root: root)
      if not db.getState(root, state.data, noRollback):
        echo "Couldn't load ", root
      else:
        dump("./", state[])
    except CatchableError as e:
      echo "Couldn't load ", stateRoot, ": ", e.msg

proc cmdDumpBlock(conf: DbConf) =
  let
    db = BeaconChainDB.init(
      kvStore SqStoreRef.init(conf.databaseDir.string, "nbc").tryGet())

  for blockRoot in conf.blockRootx:
    try:
      let root = Eth2Digest(data: hexToByteArray[32](blockRoot))
      if (let blck = db.getBlock(root); blck.isSome):
        dump("./", blck.get())
      else:
        echo "Couldn't load ", root
    except CatchableError as e:
      echo "Couldn't load ", blockRoot, ": ", e.msg

proc copyPrunedDatabase(
    db: BeaconChainDB, copyDb: BeaconChainDB,
    dryRun, verbose, keepOldStates: bool) =
  ## Create a pruned copy of the beacon chain database

  let
    headBlock = db.getHeadBlock()
    tailBlock = db.getTailBlock()

  doAssert headBlock.isOk and tailBlock.isOk
  doAssert db.getBlock(headBlock.get).isOk
  doAssert db.getBlock(tailBlock.get).isOk

  var
    beaconState: ref BeaconState
    finalizedEpoch: Epoch  # default value of 0 is conservative/safe
    prevBlockSlot = db.getBlock(db.getHeadBlock().get).get.message.slot

  beaconState = new BeaconState
  let headEpoch = db.getBlock(headBlock.get).get.message.slot.epoch

  # Tail states are specially addressed; no stateroot intermediary
  if not db.getState(
      db.getBlock(tailBlock.get).get.message.state_root, beaconState[],
      noRollback):
    doAssert false, "could not load tail state"
  if not dry_run:
    copyDb.putState(beaconState[])

  for signedBlock in getAncestors(db, headBlock.get):
    if not dry_run:
      copyDb.putBlock(signedBlock)
    if verbose:
      echo "copied block at slot ", signedBlock.message.slot

    for slot in countdown(prevBlockSlot, signedBlock.message.slot + 1):
      if slot mod SLOTS_PER_EPOCH != 0 or
          ((not keepOldStates) and slot.epoch < finalizedEpoch):
        continue

      # Could also only copy these states, head and finalized, plus tail state
      let stateRequired = slot.epoch in [finalizedEpoch, headEpoch]

      let sr = db.getStateRoot(signedBlock.root, slot)
      if sr.isErr:
        if stateRequired:
          doAssert false, "state root and state required"
        continue

      if not db.getState(sr.get, beaconState[], noRollback):
        # Don't copy dangling stateroot pointers
        if stateRequired:
          doAssert false, "state root and state required"
        continue

      finalizedEpoch = max(
        finalizedEpoch, beaconState.finalized_checkpoint.epoch)

      if not dry_run:
        copyDb.putStateRoot(signedBlock.root, slot, sr.get)
        copyDb.putState(beaconState[])
      if verbose:
        echo "copied state at slot ", slot, " from block at ", shortLog(signedBlock.message.slot)

    prevBlockSlot = signedBlock.message.slot

  if not dry_run:
    copyDb.putHeadBlock(headBlock.get)
    copyDb.putTailBlock(tailBlock.get)

  copyDb.close()

proc cmdPrune(conf: DbConf) =
  let
    db = BeaconChainDB.init(
      kvStore SqStoreRef.init(conf.databaseDir.string, "nbc").tryGet())
    copyDb = BeaconChainDB.init(
      kvStore SqStoreRef.init(conf.databaseDir.string, "nbc_pruned").tryGet())

  db.copyPrunedDatabase(copyDb, conf.dryRun, conf.verbose, conf.keepOldStates)

proc cmdRewindState(conf: DbConf, runtimePreset: RuntimePreset) =
  echo "Opening database..."
  let
    db = BeaconChainDB.init(
      kvStore SqStoreRef.init(conf.databaseDir.string, "nbc").tryGet())

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let dag = init(ChainDAGRef, runtimePreset, db)

  let blckRef = dag.getRef(fromHex(Eth2Digest, conf.blockRoot))
  if blckRef == nil:
    echo "Block not found in database"
    return

  dag.withState(dag.tmpState, blckRef.atSlot(Slot(conf.slot))):
    echo "Writing state..."
    dump("./", hashedState, blck)

when isMainModule:
  var
    conf = DbConf.load()
    runtimePreset = getRuntimePresetForNetwork(conf.eth2Network)

  case conf.cmd
  of bench:
    cmdBench(conf, runtimePreset)
  of dumpState:
    cmdDumpState(conf)
  of dumpBlock:
    cmdDumpBlock(conf)
  of pruneDatabase:
    cmdPrune(conf)
  of rewindState:
    cmdRewindState(conf, runtimePreset)
