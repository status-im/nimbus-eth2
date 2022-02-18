{.used.}

import
  unittest2,
  ./testutil,
  ../beacon_chain/spec/[forks, network]

template getTargetGossipForks(a, b, c: int, isBehind: bool): auto =
  getTargetGossipForks(a.Epoch, b.Epoch, c.Epoch, isBehind)

suite "Gossip fork transition":
  test "Gossip fork transition":
    check:
      getTargetGossipForks(0, 0, 0, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(0, 0, 2, false) == {BeaconStateFork.Altair}
      getTargetGossipForks(0, 1, 2, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipForks(0, 2, 3, false) == {BeaconStateFork.Phase0}
      getTargetGossipForks(0, 2, 5, false) == {BeaconStateFork.Phase0}
      getTargetGossipForks(0, 3, 4, false) == {BeaconStateFork.Phase0}
      getTargetGossipForks(0, 3, 5, false) == {BeaconStateFork.Phase0}
      getTargetGossipForks(0, 4, 4, false) == {BeaconStateFork.Phase0}
      getTargetGossipForks(0, 4, 5, false) == {BeaconStateFork.Phase0}
      getTargetGossipForks(1, 0, 1, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(1, 0, 5, false) == {BeaconStateFork.Altair}
      getTargetGossipForks(1, 1, 4, false) == {BeaconStateFork.Altair}
      getTargetGossipForks(2, 0, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(2, 2, 3, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipForks(2, 2, 4, false) == {BeaconStateFork.Altair}
      getTargetGossipForks(2, 3, 4, false) == {BeaconStateFork.Phase0, BeaconStateFork.Altair}
      getTargetGossipForks(2, 3, 5,  true) == {}
      getTargetGossipForks(2, 5, 5, false) == {BeaconStateFork.Phase0}
      getTargetGossipForks(3, 0, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(3, 0, 3, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(3, 0, 5, false) == {BeaconStateFork.Altair}
      getTargetGossipForks(3, 1, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(3, 1, 1, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(3, 1, 3, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(3, 1, 5,  true) == {}
      getTargetGossipForks(3, 1, 4, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipForks(3, 2, 3, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(3, 3, 4, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipForks(3, 3, 4,  true) == {}
      getTargetGossipForks(3, 4, 4, false) == {BeaconStateFork.Phase0, BeaconStateFork.Bellatrix}
      getTargetGossipForks(4, 0, 0, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(4, 0, 1, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(4, 1, 1, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(4, 1, 3, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(4, 2, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(4, 3, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(4, 4, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(4, 5, 5, false) == {BeaconStateFork.Phase0, BeaconStateFork.Bellatrix}
      getTargetGossipForks(5, 0, 0, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(5, 0, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(5, 0, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(5, 0, 5, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(5, 0, 5,  true) == {}
      getTargetGossipForks(5, 1, 5, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(5, 2, 2, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(5, 2, 4,  true) == {}
      getTargetGossipForks(5, 3, 4, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(5, 3, 5, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(5, 5, 5, false) == {BeaconStateFork.Bellatrix}
      getTargetGossipForks(2, 0, 3, false) == {BeaconStateFork.Altair, BeaconStateFork.Bellatrix}
      getTargetGossipForks(4, 1, 2, false) == {BeaconStateFork.Bellatrix}
