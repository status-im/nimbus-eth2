{.used.}

import
  unittest2,
  ./testutil,
  ../beacon_chain/spec/[forks, network]

template getTargetGossipState(a, b, c: int, isBehind: bool): auto =
  getTargetGossipState(a.Epoch, b.Epoch, c.Epoch, isBehind)

suite "Gossip fork transition":
  test "Gossip fork transition":
    check:
      getTargetGossipState(0, 0, 0, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(0, 0, 2, false) == {BeaconStateFork.Altair}
      getTargetGossipState(0, 1, 2, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipState(0, 2, 3, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(0, 2, 5, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(0, 3, 4, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(0, 3, 5, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(0, 4, 4, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(0, 4, 5, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(1, 0, 1, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(1, 0, 5, false) == {BeaconStateFork.Altair}
      getTargetGossipState(1, 1, 4, false) == {BeaconStateFork.Altair}
      getTargetGossipState(2, 0, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(2, 2, 3, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(2, 2, 4, false) == {BeaconStateFork.Altair}
      getTargetGossipState(2, 3, 4, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipState(2, 3, 5,  true) == {}
      getTargetGossipState(2, 5, 5, false) == {BeaconStateFork.Phase0}
      getTargetGossipState(3, 0, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(3, 0, 3, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(3, 0, 5, false) == {BeaconStateFork.Altair}
      getTargetGossipState(3, 1, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(3, 1, 1, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(3, 1, 3, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(3, 1, 5,  true) == {}
      getTargetGossipState(3, 1, 4, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(3, 2, 3, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(3, 3, 4, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(3, 3, 4,  true) == {}
      getTargetGossipState(3, 4, 4, false) == {BeaconStateFork.Phase0, BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 0, 0, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 0, 1, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 1, 1, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 1, 3, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 2, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 3, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 4, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 5, 5, false) == {BeaconStateFork.Phase0, BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 0, 0, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 0, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 0, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 0, 5, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 0, 5,  true) == {}
      getTargetGossipState(5, 1, 5, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 2, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 2, 4,  true) == {}
      getTargetGossipState(5, 3, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 3, 5, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(5, 5, 5, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipState(2, 0, 3, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipState(4, 1, 2, false) == {BeaconStateFork.Bellatrix}
