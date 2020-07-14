{.used.}

import
  unittest,
  chronos, web3/ethtypes,
  ../beacon_chain/mainchain_monitor

type
  MockDataProvider = ref object of DataProvider


method getBlockByHash*(p: MockDataProvider, hash: BlockHash): Future[BlockObject] {.
  async
  gcsafe
  # raises: [Defect]
.} =
  return BlockObject()

method onDisconnect*(p: MockDataProvider, handler: DisconnectHandler) {.
  async
  gcsafe
  # raises: []
.} =
  discard

method onDepositEvent*(p: MockDataProvider,
                       startBlock: Eth1BlockNumber,
                       handler: DepositEventHandler): Future[void] {.
  async
  gcsafe
  # raises: []
.} =
  discard

method close*(p: MockDataProvider): Future[void] {.
  async
  gcsafe
  # raises: [Defect]
.} =
  discard

method fetchDepositData*(p: MockDataProvider,
                         web3Block: BlockObject): Future[Eth1Block] {.
  async
  gcsafe
  # raises: [Defect, CatchableError]
.} =
  return Eth1Block()

suite "Eth1 Chain":
  discard

suite "Mainchain monitor":
  discard
