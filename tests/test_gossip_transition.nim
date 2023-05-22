# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ./testutil,
  ../beacon_chain/spec/[forks, network]

template getTargetGossipState(a, b, c, d, e: int, isBehind: bool): auto =
  getTargetGossipState(a.Epoch, b.Epoch, c.Epoch, d.Epoch, e.Epoch, isBehind)

suite "Gossip fork transition":
  test "Gossip fork transition":
    check:
      getTargetGossipState( 5,  0,  1,  8, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  4,  7,  9, 11,  true) == {}
      getTargetGossipState( 3,  0,  5,  6, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState(11,  2,  6, 10, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 8,  4,  6, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 9,  2,  4,  9, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 7,  2,  3,  5, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 9,  0,  4,  8,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 7,  1,  2,  3, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState(11,  3,  4,  5, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  0,  1,  2,  3,  true) == {}
      getTargetGossipState(10,  0,  6,  7,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 5,  1,  3,  4,  7, false) == {ConsensusFork.Capella}
      getTargetGossipState( 0,  3,  7, 10, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState(10,  0,  5,  8, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 8,  1,  3,  6, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState( 6,  1,  4, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 3,  0,  5,  7,  8, false) == {ConsensusFork.Altair}
      getTargetGossipState( 3,  2,  3,  4,  7, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 4,  3,  6,  7,  8, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  2,  6,  7,  9, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState(11,  1,  5,  7,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  1,  2,  7, 10,  true) == {}
      getTargetGossipState( 2,  1,  2,  3,  9, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 4,  0,  4,  8, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 4,  4,  5,  7,  9, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 8,  0,  0,  4,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 6,  5,  7,  8, 10, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 6,  0,  2, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  1,  2, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 5,  0,  2,  3,  6, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 2,  2,  6,  8, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState(10,  0,  6,  8, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 8,  0,  0,  2,  3,  true) == {}
      getTargetGossipState( 4,  3,  7,  8,  9,  true) == {}
      getTargetGossipState( 0,  0,  2,  5, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 1,  3,  4,  5,  9, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 5,  2,  6,  8, 10, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 7,  0,  1,  4, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 3,  2,  3,  9, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 8,  3,  5,  9, 11,  true) == {}
      getTargetGossipState( 9,  3,  6,  7,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  1,  2,  8,  9, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 6,  2,  7,  8, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  3,  4,  6,  7, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 1,  3,  5,  8, 10, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 1,  2,  5,  8, 10,  true) == {}
      getTargetGossipState( 9,  4,  5,  7,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState(11,  0,  5,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  1,  5,  7,  9, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 0,  2,  6,  8, 10,  true) == {}
      getTargetGossipState( 8,  0,  5,  8, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 7,  4,  7, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 6,  2,  3,  5,  7, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState(11,  0,  1,  3,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 6,  5,  6,  8,  9, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  2,  5,  8, 11, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState(11,  1,  5,  9, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  3,  6,  7,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 3,  0,  1,  6,  8, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 5,  1,  6,  8, 10, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 5,  2,  3,  8, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 4,  2,  8,  9, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 3,  1,  3,  4,  5, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState(11,  2,  7, 10, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState(10,  3,  5, 10, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 5,  2,  6,  8, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 4,  2,  6,  8, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 2,  0,  1,  4, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  1,  4,  6, 10,  true) == {}
      getTargetGossipState( 4,  0,  6,  7, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 7,  3,  4,  7,  8,  true) == {}
      getTargetGossipState( 1,  0,  0,  6,  8, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  1,  3,  6, 10,  true) == {}
      getTargetGossipState( 7,  2,  3,  7,  8, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 3,  2,  4,  5, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  4,  5,  7,  8, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 1,  3,  7,  8, 10, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 8,  0,  1,  6, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState( 7,  1,  5,  7, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 1,  6,  8, 10, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 0,  1,  2,  3,  7, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState(11,  2,  4,  5,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 6,  1,  5,  7,  9, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 7,  0,  3,  5, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 6,  0,  3,  9, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 8,  2,  7,  8, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState( 7,  3,  5,  6,  9, false) == {ConsensusFork.Capella}
      getTargetGossipState( 8,  0,  4,  7, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 8,  0,  3,  8, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 4,  1,  2,  4,  6, false) == {ConsensusFork.Capella}
      getTargetGossipState(10,  0,  2,  4, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 1,  0,  2,  7, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 6,  1,  2,  5,  7, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState(10,  0,  1,  8,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  1,  3,  4,  5,  true) == {}
      getTargetGossipState(11,  0,  2,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 7,  2,  7,  8,  9, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 0,  0,  5,  6,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState( 4,  2,  6,  8,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState( 2,  2,  6,  7,  8, false) == {ConsensusFork.Altair}
      getTargetGossipState(11,  2,  8,  9, 10,  true) == {}
      getTargetGossipState( 8,  1,  2,  8, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 7,  0,  1,  2,  8, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 7,  0,  1,  8,  9, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 3,  1,  7,  9, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 6,  2,  6,  7, 11, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 2,  3,  5,  7, 10, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState(10,  4,  5,  7,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 8,  1,  4,  5,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  0,  2,  7, 10, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 8,  1,  5,  7,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 8,  1,  3,  7,  9, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 4,  0,  3,  4, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 0,  1,  5,  9, 10, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 3,  4,  6,  7,  8, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState(11,  4,  5,  6, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 4,  2,  4,  9, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState(11,  0,  3,  5,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  0,  3,  7, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState(11,  1,  7,  8, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  0,  1,  3,  4, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 3,  4,  5,  7,  9, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState(10,  3,  6,  8,  9,  true) == {}
      getTargetGossipState( 6,  7,  9, 10, 11, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 7,  2,  4,  5,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  0,  0,  6, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 4,  2,  3,  7, 10,  true) == {}
      getTargetGossipState( 3,  0,  2,  3,  5, false) == {ConsensusFork.Capella}
      getTargetGossipState(10,  4,  6,  7,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  2,  6,  9, 11,  true) == {}
      getTargetGossipState( 7,  0,  1,  3,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  0,  6,  8, 11,  true) == {}
      getTargetGossipState( 6,  2,  4, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 8,  1,  3,  7, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState(10,  0,  5,  7, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 4,  0,  0,  4,  7,  true) == {}
      getTargetGossipState( 0,  1,  2,  5,  9,  true) == {}
      getTargetGossipState( 6,  2,  3, 10, 11,  true) == {}
      getTargetGossipState( 5,  1,  5,  9, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState(10,  3,  5,  7, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 3,  0,  1,  2,  5, false) == {ConsensusFork.Capella}
      getTargetGossipState( 8,  0,  1,  7, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState( 2,  0,  5,  7, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState(11,  0,  1,  3, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 8,  5,  7,  8,  9, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 0,  0,  0,  1, 11,  true) == {}
      getTargetGossipState( 6,  1,  4,  5,  9, false) == {ConsensusFork.Capella}
      getTargetGossipState( 8,  2,  4,  5,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  5,  8,  9, 10, false) == {ConsensusFork.Phase0}
      getTargetGossipState(10,  2,  5,  6,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 5,  1,  2,  5,  9, false) == {ConsensusFork.Capella}
      getTargetGossipState(10,  1,  5,  6, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 5,  0,  0,  1,  4, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 8,  0,  2,  5,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 7,  3,  4,  8, 10, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 9,  1,  6,  9, 10, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 5,  4,  5,  7, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 5,  2,  8,  9, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 0,  2,  4,  7, 10, false) == {ConsensusFork.Phase0}
      getTargetGossipState(11,  1,  4,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 4,  0,  6,  8, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState(10,  0,  1,  6, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  0,  1,  3, 11, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 2,  2,  5,  6, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 1,  0,  4,  5,  8, false) == {ConsensusFork.Altair}
      getTargetGossipState( 5,  0,  2,  3,  8, false) == {ConsensusFork.Capella}
      getTargetGossipState( 2,  6,  7,  8,  9, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 2,  2,  4,  6,  7, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  2,  5,  6,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 4,  5,  8,  9, 10,  true) == {}
      getTargetGossipState( 0,  0,  3,  5, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  0,  1,  2,  4, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  5,  7,  9, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 8,  1,  3,  6,  9, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 1,  5,  6,  7,  8, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 5,  0,  5,  8, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 0,  0,  2,  9, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState(10,  4,  6,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  5,  9, 10, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState(10,  3,  5,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 6,  0,  1,  2, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState( 2,  0,  5,  8,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState( 1,  1,  2,  8,  9, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 6,  4,  7,  9, 10, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState(10,  0,  1,  6,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 3,  5,  6,  9, 10, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 4,  0,  1,  6,  7, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 4,  1,  2,  5,  6, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 9,  0,  6,  9, 10, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState(11,  0,  2,  5, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  0,  2,  6,  9,  true) == {}
      getTargetGossipState( 5,  1,  5, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 0,  0,  1,  5,  7, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 9,  4,  5,  6,  7,  true) == {}
      getTargetGossipState( 6,  1,  2,  9, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 6,  0,  3,  4,  8, false) == {ConsensusFork.Capella}
      getTargetGossipState( 3,  1,  3, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 8,  0,  3,  5, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 2,  1,  2,  5,  9, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  1,  3,  8, 10, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  0,  3,  4,  7, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState(11,  4,  7,  8,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 4,  0,  2,  3,  9, false) == {ConsensusFork.Capella}
      getTargetGossipState( 4,  1,  2,  8, 10,  true) == {}
      getTargetGossipState( 6,  3,  5,  6, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 1,  3,  4,  9, 10,  true) == {}
      getTargetGossipState( 7,  0,  4,  7, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 1,  0,  5,  7, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 7,  3,  4,  7,  8, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState(10,  5,  7,  8,  9,  true) == {}
      getTargetGossipState( 9,  1,  3,  4,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  0,  1,  8, 10, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 4,  0,  4,  7, 11,  true) == {}
      getTargetGossipState( 3,  0,  2,  5, 11,  true) == {}
      getTargetGossipState( 5,  1,  3,  7,  9, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  2,  3,  8, 10, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 6,  0,  4,  5, 10,  true) == {}
      getTargetGossipState( 9,  0,  0,  4,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 7,  2,  3,  9, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  2,  4,  7,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState( 4,  1,  6,  9, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  1,  2,  9, 11,  true) == {}
      getTargetGossipState( 6,  1,  6,  7,  9, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 2,  2,  6,  9, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 6,  0,  1,  6, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState( 9,  1,  2,  5, 10, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 6,  1,  2,  5, 11,  true) == {}
      getTargetGossipState( 5,  3,  4,  8,  9, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  0,  2,  5,  9, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 7,  1,  4,  9, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 5,  0,  4,  7, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  4,  6,  8, 10, false) == {ConsensusFork.Phase0}
      getTargetGossipState(11,  1,  2,  4,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  6,  8,  9, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 1,  0,  9, 10, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 9,  1,  2,  6,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  1,  6,  8, 11,  true) == {}
      getTargetGossipState( 6,  1,  4,  8, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 5,  2,  3,  5,  8, false) == {ConsensusFork.Capella}
      getTargetGossipState( 0,  1,  2,  3, 11, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 4,  3,  6,  8,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  0,  2,  4,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState(10,  0,  1,  6, 10,  true) == {}
      getTargetGossipState( 3,  1,  9, 10, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 7,  2,  6,  8, 10, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 7,  2,  3,  7, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState(10,  5,  8,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState(11,  3,  6,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 8,  0,  0,  5, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState(10,  2,  6,  7, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 2,  2,  3,  5,  7, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState(10,  2,  7,  8, 10,  true) == {}
      getTargetGossipState( 5,  0,  4,  5,  9,  true) == {}
      getTargetGossipState( 5,  0,  1,  2,  3, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  1,  2,  3,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  1,  3,  4, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 5,  0,  1,  3,  9, false) == {ConsensusFork.Capella}
      getTargetGossipState( 9,  0,  4, 10, 11, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 4,  1,  5,  7, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 4,  0,  1,  4,  7, false) == {ConsensusFork.Capella}
      getTargetGossipState( 8,  5,  8, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState(11,  2,  3,  5,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  6,  7,  9, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 8,  3,  4,  7, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 0,  1,  2,  3,  6, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 0,  3,  4,  5,  9, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 5,  3,  6,  7,  9, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 5,  5,  7,  8, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState(10,  1,  3,  7,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState(11,  0,  3,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  0,  2,  3,  4,  true) == {}
      getTargetGossipState( 1,  0,  1,  8,  9, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 6,  0,  6,  7,  8,  true) == {}
      getTargetGossipState( 4,  0,  1,  4, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState(11,  4,  5,  7,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  1,  4,  5,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState( 6,  0,  2,  4,  7,  true) == {}
      getTargetGossipState( 6,  3,  8, 10, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 3,  0,  1,  7, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  0,  6,  9, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 7,  2,  4,  6, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState(10,  0,  3,  5,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState(10,  0,  5,  7,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  2,  8,  9, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 3,  0,  1,  5,  8, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  0,  0,  3,  4, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  2,  4,  5,  8, false) == {ConsensusFork.Altair}
      getTargetGossipState( 6,  0,  0,  3,  8, false) == {ConsensusFork.Capella}
      getTargetGossipState( 4,  0,  2,  5,  6,  true) == {}
      getTargetGossipState( 2,  0,  2,  3,  5, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 8,  0,  5,  6, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 7,  0,  2,  5,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState(11,  1,  2,  5,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState(10,  0,  3,  6, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  0,  0,  2,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  1,  2,  7,  8, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 5,  0,  1,  2,  8, false) == {ConsensusFork.Capella}
      getTargetGossipState( 5,  3,  6,  9, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 4,  4,  5,  9, 10, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  1,  5,  6,  7, false) == {ConsensusFork.Altair}
      getTargetGossipState( 3,  0,  0,  4,  8, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 3,  0,  0,  1,  4, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 2,  0,  2,  5,  8, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  4,  7,  8, 10, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 6,  0,  3,  8,  9, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 9,  2,  3,  5,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState(11,  1,  6, 10, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  1,  4,  7, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  4,  5,  7,  9, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 9,  1,  8, 10, 11, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 5,  0,  1,  4,  5, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  2,  7,  8, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 7,  3,  6,  7,  8, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState(10,  3,  4,  7, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 4,  2,  3,  5,  8, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState(11,  1,  2,  3,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  2,  8,  9, 11, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 1,  1,  5, 10, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 2,  2,  9, 10, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState(11,  0,  0,  1, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 8,  2,  4,  6, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 1,  0,  3,  5, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 2,  3,  4,  9, 11, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 8,  1,  2,  4,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  4,  5,  6,  7, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 5,  3,  7,  9, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 3,  0,  5,  6,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState(11,  4,  6,  9, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 6,  5,  8, 10, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState(11,  2,  3,  4,  5, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  3,  5,  6, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState(11,  5,  6,  7, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 5,  2,  6,  8,  9, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  1,  3,  6, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 6,  0,  0,  1,  3, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 6,  2,  6,  8,  9, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 1,  3,  5,  6,  7, false) == {ConsensusFork.Phase0}
      getTargetGossipState(10,  3,  4,  5,  8,  true) == {}
      getTargetGossipState( 8,  3,  7,  8, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState( 5,  1,  3,  6, 10, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 1,  0,  1,  2,  7, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 0,  0,  5,  6,  8, false) == {ConsensusFork.Altair}
      getTargetGossipState( 9,  2,  4,  5,  8,  true) == {}
      getTargetGossipState( 1,  0,  0,  2, 10, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 3,  0,  3,  7,  8, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState(10,  2,  3,  5,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 5,  3,  6,  9, 10,  true) == {}
      getTargetGossipState( 4,  2,  3,  8, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  1,  3, 10, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 4,  0,  5,  7, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 8,  2,  3,  7,  8,  true) == {}
      getTargetGossipState( 8,  2,  4,  7,  9,  true) == {}
      getTargetGossipState(10,  4,  5,  6,  8,  true) == {}
      getTargetGossipState( 1,  1,  2,  8, 10, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 3,  5,  6,  8,  9,  true) == {}
      getTargetGossipState( 7,  0,  0,  1,  6,  true) == {}
      getTargetGossipState( 8,  0,  4,  5, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 2,  0,  6,  8,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState( 0,  1,  4,  8, 10, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState(10,  0,  0,  0,  4, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  1,  3,  5,  9, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  1,  4, 10, 11,  true) == {}
      getTargetGossipState(11,  1,  8,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  0,  1,  4,  5, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 3,  4,  8, 10, 11, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 5,  7,  8,  9, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 6,  0,  1,  3,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState(10,  0,  2,  6,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 3,  0,  5,  9, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 5,  0,  6,  7,  9, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 8,  6,  7,  8, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 2,  3,  4,  8, 11, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState(10,  6,  7,  9, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 5,  1,  2,  8, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState(10,  4,  7,  9, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  0,  0,  2,  3, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 6,  0,  5,  7,  8,  true) == {}
      getTargetGossipState(10,  1,  2,  3,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 3,  3,  5,  7,  8,  true) == {}
      getTargetGossipState( 7,  1,  2,  3,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 6,  3,  4,  7,  9, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 4,  0,  3, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 9,  0,  0,  0,  2, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 5,  3,  6,  7, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 9,  0,  2,  4,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  1,  4,  9, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 6,  3,  5,  6, 10, false) == {ConsensusFork.Capella}
      getTargetGossipState( 0,  4,  7,  9, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 9,  0,  5,  8, 10, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 5,  4,  5,  7,  9,  true) == {}
      getTargetGossipState( 4,  0,  1,  2,  3, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 4,  0,  2,  8, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState(10,  0,  1,  4,  5, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  4,  5,  8,  9, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 7,  1,  3,  7, 11,  true) == {}
      getTargetGossipState(11,  0,  1,  2, 10,  true) == {}
      getTargetGossipState( 8,  1,  4,  8, 10,  true) == {}
      getTargetGossipState( 2,  2,  3,  9, 11, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 3,  2,  6,  8,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState( 7,  0,  7,  8,  9, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 7,  0,  5,  6,  8, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 9,  1,  9, 10, 11, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 9,  4,  5,  6, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 9,  1,  4,  6,  8,  true) == {}
      getTargetGossipState( 4,  0,  3,  8,  9, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 0,  2,  3,  6, 10, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 9,  2,  4,  7, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 3,  0,  3,  7,  9, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 9,  1,  2,  3,  8,  true) == {}
      getTargetGossipState( 0,  2,  3,  6,  8, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 7,  6,  9, 10, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 5,  1,  5,  8, 11,  true) == {}
      getTargetGossipState( 4,  1,  2,  5, 11,  true) == {}
      getTargetGossipState( 0,  4,  6, 10, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 7,  3,  6,  9, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  0,  4,  6,  7, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  2,  4, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 4,  6,  7,  8, 10,  true) == {}
      getTargetGossipState(11,  0,  1,  7,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 0,  1,  2,  3,  4, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 3,  5,  6,  7,  9, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 8,  0,  2,  3,  5, false) == {ConsensusFork.Deneb}
      getTargetGossipState(11,  0,  6,  7,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState(10,  1,  2,  3, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 9,  1,  3,  6, 10,  true) == {}
      getTargetGossipState( 0,  2,  7,  8,  9, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 2,  1,  2,  4, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 6,  0,  2,  7,  8, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 0,  1,  6,  7,  9, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 1,  5,  7,  9, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 1,  1,  8,  9, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 9,  2,  6,  8, 11,  true) == {}
      getTargetGossipState( 3,  0,  4,  8, 10, false) == {ConsensusFork.Altair,    ConsensusFork.Bellatrix}
      getTargetGossipState( 9,  2,  3,  9, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 6,  0,  1,  2,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState(11,  0,  3,  8, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  2,  4,  5,  6, false) == {ConsensusFork.Altair}
      getTargetGossipState( 1,  1,  3,  6,  8, false) == {ConsensusFork.Altair}
      getTargetGossipState( 5,  1,  3,  6,  9, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 5,  1,  3,  6, 10,  true) == {}
      getTargetGossipState( 3,  2,  3,  8, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 2,  1,  2,  3, 10, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 3,  0,  1,  9, 10, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 0,  1,  3,  7,  9, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 2,  3,  6, 10, 11, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 2,  0,  4,  6,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  0,  8,  9, 11, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 0,  0,  4,  6,  9, false) == {ConsensusFork.Altair}
      getTargetGossipState(10,  1,  2,  3,  4, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 4,  0,  3,  4,  7, false) == {ConsensusFork.Capella}
      getTargetGossipState( 0,  2,  3,  8, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 0,  3,  5,  7, 10,  true) == {}
      getTargetGossipState( 9,  0,  0,  3,  7, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 2,  1,  5,  6, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState(10,  2,  3,  6, 10, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 5,  0,  4,  6, 11,  true) == {}
      getTargetGossipState( 1,  1,  3,  4,  5, false) == {ConsensusFork.Altair}
      getTargetGossipState(11,  1,  7,  8, 11,  true) == {}
      getTargetGossipState( 3,  1,  5,  7,  9,  true) == {}
      getTargetGossipState( 6,  0,  2,  5,  9, false) == {ConsensusFork.Capella}
      getTargetGossipState( 4,  0,  1,  4,  9, false) == {ConsensusFork.Capella}
      getTargetGossipState( 6,  4,  8,  9, 11,  true) == {}
      getTargetGossipState(10,  0,  1,  2,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState(10,  1,  3,  7, 11, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 3,  2,  5,  6,  7, false) == {ConsensusFork.Altair}
      getTargetGossipState( 9,  4,  9, 10, 11, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 2,  2,  4,  9, 10, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  2,  4, 10, 11,  true) == {}
      getTargetGossipState(11,  0,  8, 10, 11, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 7,  0,  1,  7,  8, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 4,  2,  8, 10, 11, false) == {ConsensusFork.Altair}
      getTargetGossipState( 8,  5,  6,  8, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 8,  1,  5,  8, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 6,  1,  6,  7, 11, false) == {ConsensusFork.Bellatrix, ConsensusFork.Capella}
      getTargetGossipState( 9,  3,  4,  5,  6, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 1,  0,  3,  4,  7, false) == {ConsensusFork.Altair}
      getTargetGossipState( 6,  1,  2,  3, 11, false) == {ConsensusFork.Capella}
      getTargetGossipState( 1,  2,  5,  9, 10, false) == {ConsensusFork.Phase0,    ConsensusFork.Altair}
      getTargetGossipState( 5,  0,  5,  7,  8, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 8,  0,  3, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState(11,  3,  6,  7,  8, false) == {ConsensusFork.Deneb}
      getTargetGossipState( 3,  6,  7,  9, 10,  true) == {}
      getTargetGossipState( 7,  1,  6, 10, 11, false) == {ConsensusFork.Bellatrix}
      getTargetGossipState( 0,  6,  9, 10, 11, false) == {ConsensusFork.Phase0}
      getTargetGossipState( 4,  1,  2,  3,  5, false) == {ConsensusFork.Capella,   ConsensusFork.Deneb}
      getTargetGossipState( 9,  1,  2,  7,  8, false) == {ConsensusFork.Deneb}
