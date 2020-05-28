import
  confutils, stats, chronicles, strformat, tables,
  ../beacon_chain/block_pool,
  ../beacon_chain/spec/[crypto, datatypes],
  ../beacon_chain/[beacon_chain_db, extras, state_transition, ssz],
  ../research/simutils,
  eth/db/[kvstore, kvstore_sqlite3]

type Timers = enum
  tInit = "Initialize DB"
  tLoadBlock = "Load block from database"
  tLoadState = "Load state from database"
  tApplyBlock = "Apply block"

cli do(databaseDir: string, cmd: string):
  var timers: array[Timers, RunningStat]

  echo "Opening database..."
  let
    db = BeaconChainDB.init(kvStore SqStoreRef.init(databaseDir, "nbc").tryGet())

  if not BlockPool.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let pool = withTimerRet(timers[tInit]):
    CandidateChains.init(db, {})

  echo &"Loaded {pool.blocks.len} blocks, head slot {pool.head.blck.slot}"

  case cmd
  of "bench":
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

    for b in blocks:
      withTimer(timers[tApplyBlock]):
        discard state_transition(state[], b, {}, noRollback)

  printTimers(true, timers)
