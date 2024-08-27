# beacon_chain
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/el/[el_conf, el_manager],
  ./testutil

suite "Eth1 monitor":
  test "Rewrite URLs":
    var
      gethHttpUrl = "http://localhost:8545"
      gethHttpsUrl = "https://localhost:8545"
      gethWsUrl = "ws://localhost:8545"
      unspecifiedProtocolUrl = "localhost:8545"

    fixupWeb3Urls gethHttpUrl
    fixupWeb3Urls gethHttpsUrl
    fixupWeb3Urls gethWsUrl
    fixupWeb3Urls unspecifiedProtocolUrl

    check:
      gethHttpUrl == "http://localhost:8545"
      gethHttpsUrl == "https://localhost:8545"
      unspecifiedProtocolUrl == "ws://localhost:8545"

      gethWsUrl == "ws://localhost:8545"

  test "Deposits chain":
    var
      chain = Eth1Chain()
      depositIndex = 0.uint64
    for i in 0 ..< (MAX_DEPOSITS + 1) * 3:
      var deposits = newSeqOfCap[DepositData](i)
      for _ in 0 ..< i mod (MAX_DEPOSITS + 1):
        deposits.add DepositData(amount: depositIndex.Gwei)
        inc depositIndex

      const interval = defaultRuntimeConfig.SECONDS_PER_ETH1_BLOCK
      chain.blocks.addLast Eth1Block(
        number: i.Eth1BlockNumber,
        timestamp: i.Eth1BlockTimestamp * interval,
        deposits: deposits,
        depositCount: depositIndex)

    proc doTest(first, last: uint64) =
      var idx = first
      for data in chain.getDepositsRange(first, last):
        check data.amount == idx.Gwei
        inc idx
      check idx == last

    for i in 0 .. depositIndex:
      for j in i .. depositIndex:
        doTest(i, j)