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

import ../beacon_chain/spec/[beaconstate, forks, state_transition]

suite "PQ state transition":
  test "Genesis aggregation window and slot processing":
    let path = getEnv("PQ_GENESIS_SSZ")
    if path.len == 0:
      skip()
    else:
      let state = newClone(SSZ.decode(readFile(path), pq.BeaconState))
      var
        cache: StateCache
        recomputed = newClone(state[])
      initialize_aggregation_committee_window(recomputed[], cache)
      check hash_tree_root(recomputed[].aggregation_committee_window) ==
        hash_tree_root(state[].aggregation_committee_window)

      let forked = ForkedHashedBeaconState.new(state[])
      var
        cfg = defaultRuntimeConfig
        info: ForkedEpochInfo
      cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
      cfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
      cfg.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
      cfg.DENEB_FORK_EPOCH = GENESIS_EPOCH
      cfg.ELECTRA_FORK_EPOCH = GENESIS_EPOCH
      cfg.FULU_FORK_EPOCH = GENESIS_EPOCH
      cfg.GLOAS_FORK_EPOCH = GENESIS_EPOCH
      cfg.PQ_FORK_EPOCH = GENESIS_EPOCH
      check:
        forked[].kind == ConsensusFork.Pq
        process_slots(
          cfg, forked[], Slot(3 * SLOTS_PER_EPOCH + 1), cache, info,
          {}).isOk()
      withState(forked[]):
        when consensusFork == ConsensusFork.Pq:
          for i in 0'u64 ..< 3 * SLOTS_PER_EPOCH:
            check forkyState.data.aggregation_committee_window.item(i.int).len > 0
