  import
  confutils, stats, chronicles, strformat, tables,
  stew/byteutils,
  ../beacon_chain/[beacon_chain_db, block_pool, extras, state_transition],
  ../beacon_chain/spec/[crypto, datatypes, digest, helpers],
  ../beacon_chain/sszdump,
  ../research/simutils,
  eth/db/[kvstore, kvstore_sqlite3]

type Timers = enum
  tInit = "Initialize DB"
  tLoadBlock = "Load block from database"
  tLoadState = "Load state from database"
  tApplyBlock = "Apply block"
  tApplyEpochBlock = "Apply epoch block"

type
  DbCmd* = enum
    bench
    dumpState

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
      validate* {.
        defaultValue: true
        desc: "Enable BLS validation" }: bool

    of dumpState:
      stateRoot* {.
        argument
        desc: "State roots to save".}: seq[string]

proc cmdBench(conf: DbConf) =
  var timers: array[Timers, RunningStat]

  echo "Opening database..."
  let
    db = BeaconChainDB.init(
      kvStore SqStoreRef.init(conf.databaseDir.string, "nbc").tryGet())

  if not BlockPool.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let pool = withTimerRet(timers[tInit]):
    CandidateChains.init(db, {})

  echo &"Loaded {pool.blocks.len} blocks, head slot {pool.head.blck.slot}"

  var
    blockRefs: seq[BlockRef]
    blocks: seq[SignedBeaconBlock]
    cur = pool.head.blck

  while cur != nil:
    blockRefs.add cur
    cur = cur.parent

  for b in 1..<blockRefs.len: # Skip genesis block
    withTimer(timers[tLoadBlock]):
      blocks.add db.getBlock(blockRefs[blockRefs.len - b - 1].root).get()

  let state = (ref HashedBeaconState)(
    root: db.getBlock(blockRefs[^1].root).get().message.state_root
  )

  withTimer(timers[tLoadState]):
    discard db.getState(state[].root, state[].data, noRollback)

  let flags = if conf.validate: {} else: {skipBlsValidation}
  for b in blocks:
    let
      isEpoch = state[].data.slot.compute_epoch_at_slot !=
        b.message.slot.compute_epoch_at_slot
    withTimer(timers[if isEpoch: tApplyEpochBlock else: tApplyBlock]):
      discard state_transition(state[], b, flags, noRollback)

  printTimers(conf.validate, timers)

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

when isMainModule:
  let
    conf = DbConf.load()

  case conf.cmd
  of bench:
    cmdBench(conf)
  of dumpState:
    cmdDumpState(conf)
