# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ./testutil,
  ../beacon_chain/spec/[forks, network]

template getTargetGossipState(a, b, c, d: int, e: Epoch, isBehind: bool): auto =
  getTargetGossipState(a.Epoch, b.Epoch, c.Epoch, d.Epoch, e, isBehind)

suite "Gossip fork transition":
  test "Gossip fork transition":
    check:
      getTargetGossipState(0, 1, 6, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipState(7, 2, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(5, 0, 2, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(4, 2, 4, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix, BeaconStateFork.Capella}
      getTargetGossipState(1, 2, 3, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipState(9, 2, 4, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(5, 2, 3, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 0, 1, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(7, 2, 6, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(5, 0, 5, 7, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(8, 1, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(8, 3, 4, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(4, 1, 2, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(0, 1, 4, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipState(9, 1, 4, 7, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(9, 2, 4, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(4, 0, 1, 5, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(1, 1, 5, 6, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(2, 0, 0, 7, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(7, 1, 5, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(5, 1, 3, 6, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(8, 4, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(3, 0, 4, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(1, 2, 6, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipState(1, 0, 1, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(6, 0, 3, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(0, 4, 5, 6, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(3, 0, 3, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 1, 3, 5, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(4, 3, 4, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix, BeaconStateFork.Capella}
      getTargetGossipState(6, 1, 2, 5, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(8, 3, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(1, 4, 6, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(2, 5, 6, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(5, 3, 4, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(5, 1, 4, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(6, 2, 4, 7, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(7, 3, 5, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(6, 0, 1, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix, BeaconStateFork.Capella}
      getTargetGossipState(0, 1, 4, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipState(7, 0, 1, 4, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(6, 0, 4, 5, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(3, 0, 0, 1, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(2, 1, 3, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(8, 0, 2, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(7, 0, 1, 4, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(8, 1, 2, 7, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(3, 0, 2, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(9, 1, 2, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(6, 1, 4, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(0, 3, 4, 5, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(9, 1, 3, 4, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(1, 1, 4, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair}
      getTargetGossipState(5, 1, 4, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix, BeaconStateFork.Capella}
      getTargetGossipState(7, 0, 5, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(9, 0, 0, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(5, 0, 0, 0, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(9, 2, 3, 4, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(3, 0, 0, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(0, 0, 1, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 1, 4, 6, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(4, 1, 2, 3, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(6, 1, 3, 4, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(4, 0, 0, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix, BeaconStateFork.Capella}
      getTargetGossipState(8, 0, 3, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(2, 2, 3, 4, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(6, 2, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(3, 0, 6, 7, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(1, 1, 2, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(2, 2, 4, 5, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(9, 0, 3, 7, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(4, 1, 3, 7, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(7, 0, 0, 3, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(0, 2, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(2, 0, 1, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(9, 1, 6, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(6, 3, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(2, 0, 0, 3, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix, BeaconStateFork.Capella}
      getTargetGossipState(3, 1, 3, 4, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(7, 0, 1, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(2, 0, 3, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(2, 0, 2, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(1, 2, 4, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipState(8, 0, 2, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(6, 1, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(6, 4, 5, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix, BeaconStateFork.Capella}
      getTargetGossipState(3, 0, 5, 6, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(4, 0, 2, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 4, 5, 6, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(3, 0, 4, 5, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(6, 0, 2, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(2, 1, 2, 3, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix, BeaconStateFork.Capella}
      getTargetGossipState(1, 0, 5, 6, FAR_FUTURE_EPOCH,  true) == {}
      getTargetGossipState(5, 2, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix, BeaconStateFork.Capella}
      getTargetGossipState(8, 0, 1, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(4, 2, 5, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(1, 1, 2, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(9, 1, 4, 6, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Capella}
      getTargetGossipState(1, 0, 0, 5, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(0, 0, 5, 7, FAR_FUTURE_EPOCH, false) == {BeaconStateFork.Altair}
