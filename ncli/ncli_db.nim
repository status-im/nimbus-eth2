  import
  confutils, stats, chronicles, strformat, tables,
  stew/byteutils,
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
    rewindState

  # TODO:
  # This should probably allow specifying a run-time preset
  DbConf = object
    databaseDir* {.
        defaultValue: ""
        desc: "Directory where `nbc.sqlite` is stored"
        name: "db" }: InputDir

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

    of rewindState:
      blockRoot* {.
        argument
        desc: "Block root".}: string

      slot* {.
        argument
        desc: "Slot".}: uint64

proc cmdBench(conf: DbConf) =
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
    ChainDAGRef.init(defaultRuntimePreset, db, {})

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
      if not state_transition(defaultRuntimePreset, state[], b, {}, noRollback):
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

proc cmdRewindState(conf: DbConf) =
  echo "Opening database..."
  let
    db = BeaconChainDB.init(
      kvStore SqStoreRef.init(conf.databaseDir.string, "nbc").tryGet())

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let dag = init(ChainDAGRef, defaultRuntimePreset, db)

  let blckRef = dag.getRef(fromHex(Eth2Digest, conf.blockRoot))
  if blckRef == nil:
    echo "Block not found in database"
    return

  dag.withState(dag.tmpState, blckRef.atSlot(Slot(conf.slot))):
    echo "Writing state..."
    dump("./", hashedState, blck)

when isMainModule:
  let
    conf = DbConf.load()

  case conf.cmd
  of bench:
    cmdBench(conf)
  of dumpState:
    cmdDumpState(conf)
  of dumpBlock:
    cmdDumpBlock(conf)
  of rewindState:
    cmdRewindState(conf)
