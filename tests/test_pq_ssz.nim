# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/os, ssz_serialization,
  unittest2,
  ../beacon_chain/spec/[eth2_ssz_serialization, eth2_merkleization],
  ../beacon_chain/spec/datatypes/pq

suite "PQ SSZ":
  test "Genesis state from ethpandaops/eth-beacon-genesis":
    let path = getEnv("PQ_GENESIS_SSZ")
    if path.len == 0:
      skip()
    else:
      let
        data = readFile(path)
        state = newClone(SSZ.decode(data, pq.BeaconState))
      echo "validators: ", state[].validators.len
      echo "state root: ", hash_tree_root(state[])
      echo "validators root: ", hash_tree_root(state[].validators)
      echo "v0 pubkey: ", state[].validators.item(0).pubkey
      echo "fork: ", state[].fork
      check SSZ.encode(state[]).len == data.len
      if getEnv("PQ_GENESIS_ROOT").len > 0:
        check $hash_tree_root(state[]) == getEnv("PQ_GENESIS_ROOT")
