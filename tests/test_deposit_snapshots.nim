{.used.}

import
  std/[os, random, strutils, times],
  chronos, stew/results, unittest2, chronicles,
  ../../beacon_chain/beacon_chain_db,
  ../../beacon_chain/spec/deposit_snapshots

from eth/db/kvstore import kvStore
from nimcrypto import toDigest
from snappy import encode
from stew/byteutils import hexToSeqByte

const ROOT = "342cecb5a18945fbbda7c62ede3016f3"

template databaseRoot: string = getTempDir().joinPath(ROOT)
template key1: array[1, byte] = [byte(kOldDepositContractSnapshot)]
template key2: array[1, byte] = [byte(kDepositTreeSnapshot)]

type
  DepositSnapshotUpgradeProc = proc(old: OldDepositContractSnapshot): DepositTreeSnapshot
                                   {.gcsafe, raises: [Defect].}

proc ifNecessaryMigrateDCS(db: BeaconChainDB,
                           upgradeProc: DepositSnapshotUpgradeProc) =
  if not db.hasDepositTreeSnapshot():
    let oldSnapshot = db.getUpgradableDepositSnapshot()
    if oldSnapshot.isSome:
      db.putDepositTreeSnapshot upgradeProc(oldSnapshot.get)

# Hexlified copy of
# eth2-networks/shared/mainnet/genesis_deposit_contract_snapshot.ssz
let ds1: seq[byte] = hexToSeqByte(
  """
  eeea1373d4aa9e099d7c9deddb694db9aeb4577755ef83f9b6345ce4357d9abfca3bfce2c
  304c4f52e0c83f96daf8c98a05f80281b62cf08f6be9c1bc10c0adbabcf2f74605a9eb36c
  f243bb5009259a3717d44df3caf02acc53ab49cfd2eeb6d4079d31e57638b3a6928ff3940
  d0d06545ae164278597bb8d46053084c335eaf9585ef52fc5eaf1f11718df7988d3f414d8
  b0be2e56e15d7ade9f5ee4cc7ee4a4c96f16c3a300034788ba8bf79c3125a697488006a4a
  4288c38fdc4e9891891cae036d14b83ff1523749d4fabf5c91e8d455dce2f14eae3408dce
  22f901efc7858ccad1a32af9e9796d3026ba18925103cad44cba4bdc1f3d3c23be125bba1
  811f1e08405d5d180444147397ea0d4aebf12edff5cebc52cb05983c8d4bd2d4a93d66676
  459ab2c5ca9d553a5c5599cc6992ed90edc939c51cc99d1820b5691914bfcab6eb8016c51
  77e9e8f006e7893ea46b232b91b1f923b05273a927cd6d0aa14720bc149ce68f20809d6fe
  55816acf09e72c14b54637dea24eb961558a7ac726d03ced287a817fa8fea71c90bd89955
  b093d7c5908305177efa8289457190435298b2d5b2b67543e4dceaf2c8b7fdbdac12836a7
  0ed910c34abcd10b3ddf53f640c85e35fef7e7ba4ab8c561fe9f1d763a32c65a1fbad5756
  6bda135236257aa502116cb72c9347d10dca1b64a342b41a829cc7ba95e71499f57be2be3
  cd00000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000000000005251
  """.replace(" ", "").replace("\n", "")
)

const
  ds1Root = toDigest("1a4c3cce02935defd159e4e207890ae26a325bf03e205c9ee94ca040ecce008a")

proc fixture1() =
  ## Inserts a OldDepositContractSnapshot fixture.
  let
    compressed = snappy.encode(ds1)
    db = SqStoreRef.init(databaseRoot, "nbc").expect("")
    kv = kvStore(db.openKvStore("key_values", true).expect(""))
  kv.put(key1, compressed).expect("")
  db.close()

proc inspectDCS(snapshot: OldDepositContractSnapshot | DepositTreeSnapshot) =
  ## Inspects a DCS and checks if all of its data corresponds to
  ## what's encoded in ds1.
  const zero = toDigest("0000000000000000000000000000000000000000000000000000000000000000")
  const root = toDigest("1a4c3cce02935defd159e4e207890ae26a325bf03e205c9ee94ca040ecce008a")
  const want = [
    "ca3bfce2c304c4f52e0c83f96daf8c98a05f80281b62cf08f6be9c1bc10c0adb",
    "abcf2f74605a9eb36cf243bb5009259a3717d44df3caf02acc53ab49cfd2eeb6",
    "d4079d31e57638b3a6928ff3940d0d06545ae164278597bb8d46053084c335ea",
    "f9585ef52fc5eaf1f11718df7988d3f414d8b0be2e56e15d7ade9f5ee4cc7ee4",
    "a4c96f16c3a300034788ba8bf79c3125a697488006a4a4288c38fdc4e9891891",
    "cae036d14b83ff1523749d4fabf5c91e8d455dce2f14eae3408dce22f901efc7",
    "858ccad1a32af9e9796d3026ba18925103cad44cba4bdc1f3d3c23be125bba18",
    "11f1e08405d5d180444147397ea0d4aebf12edff5cebc52cb05983c8d4bd2d4a",
    "93d66676459ab2c5ca9d553a5c5599cc6992ed90edc939c51cc99d1820b56919",
    "14bfcab6eb8016c5177e9e8f006e7893ea46b232b91b1f923b05273a927cd6d0",
    "aa14720bc149ce68f20809d6fe55816acf09e72c14b54637dea24eb961558a7a",
    "c726d03ced287a817fa8fea71c90bd89955b093d7c5908305177efa828945719",
    "0435298b2d5b2b67543e4dceaf2c8b7fdbdac12836a70ed910c34abcd10b3ddf",
    "53f640c85e35fef7e7ba4ab8c561fe9f1d763a32c65a1fbad57566bda1352362",
    "57aa502116cb72c9347d10dca1b64a342b41a829cc7ba95e71499f57be2be3cd",
  ]
  # Check eth1Block.
  check($snapshot.eth1Block == "eeea1373d4aa9e099d7c9deddb694db9aeb4577755ef83f9b6345ce4357d9abf")
  # Check branch.
  for i in 0..want.high():
    check($snapshot.depositContractState.branch[i] == want[i])
  for i in (want.high() + 1)..31:
    check(snapshot.depositContractState.branch[i] == zero)
  # Check deposit_count.
  check(snapshot.getDepositCountU64() == 21073)
  # Check deposit root.
  check(snapshot.getDepositRoot == root)

proc inspectDCS(snapshot: DepositTreeSnapshot, wantedBlockHeight: uint64) =
  inspectDCS(snapshot)
  check(snapshot.blockHeight == wantedBlockHeight)

suite "DepositTreeSnapshot":
  setup:
    randomize()

  teardown:
    # removeDir(databaseRoot)
    discard

  test "SSZ":
    var snapshot = OldDepositContractSnapshot()
    check(decodeSSZ(ds1, snapshot))
    inspectDCS(snapshot)

  test "Migration":
    # Start with a fresh database.
    removeDir(databaseRoot)
    createDir(databaseRoot)
    # Make sure there's no DepositTreeSnapshot yet.
    let db = BeaconChainDB.new(databaseRoot, inMemory=false)
    check(db.getDepositTreeSnapshot().isErr())
    # Setup fixture.
    fixture1()
    # Make sure there's still no DepositTreeSnapshot as
    # BeaconChainDB::getDepositTreeSnapshot() checks only for DCSv2.
    check(db.getDepositTreeSnapshot().isErr())
    # Migrate DB.
    db.ifNecessaryMigrateDCS do (d: OldDepositContractSnapshot) -> DepositTreeSnapshot:
      d.toDepositTreeSnapshot(11052984)
    # Make sure now there actually is a snapshot.
    check(db.getDepositTreeSnapshot().isOk())
    # Inspect content.
    let snapshot = db.getDepositTreeSnapshot().expect("")
    inspectDCS(snapshot, 11052984)

  test "depositCount":
    let now = getTime()
    var rand = initRand(12345678)
    for i in 1..1000:
      let n = rand.next()
      let m = n mod 4294967296'u64
      check(depositCountU64(depositCountBytes(m)) == m)

  test "isValid":
    const ZERO = toDigest("0000000000000000000000000000000000000000000000000000000000000000")
    # Use our hard-coded ds1 as a model.
    var model: OldDepositContractSnapshot
    check(decodeSSZ(ds1, model))
    # Check blockHeight.
    var dcs = model.toDepositTreeSnapshot(0)
    check(not dcs.isValid(ds1Root))
    dcs.blockHeight = 11052984
    check(dcs.isValid(ds1Root))
    # Check eth1Block.
    dcs.eth1Block = ZERO
    check(not dcs.isValid(ds1Root))
    dcs.eth1Block = model.eth1Block
    check(dcs.isValid(ds1Root))
    # Check branch.
    for i in 0..len(dcs.depositContractState.branch)-1:
      dcs.depositContractState.branch[i] = ZERO
    check(not dcs.isValid(ds1Root))
    dcs.depositContractState.branch = model.depositContractState.branch
    check(dcs.isValid(ds1Root))
    # Check deposit count.
    for i in 0..len(dcs.depositContractState.deposit_count)-1:
      dcs.depositContractState.deposit_count[i] = 0
    check(not dcs.isValid(ds1Root))
    dcs.depositContractState.deposit_count = model.depositContractState.deposit_count
    check(dcs.isValid(ds1Root))
