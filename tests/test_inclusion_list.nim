# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/[beaconstate, forks],
  ./consensus_spec/fixtures_utils,
  ./teststateutil,
  ./testutil

suite "Inclusion list" & preset():
  test "get_inclusion_list_committee":
    let
      cfg = genesisTestRuntimeConfig(ConsensusFork.Heze)
      forkedState = initGenesisState(cfg)
    var cache = StateCache()

    check forkedState[].kind == ConsensusFork.Heze
    let state = addr forkedState[].hezeData.data

    let
      slot = state[].slot
      committee = get_inclusion_list_committee(state[], slot, cache)

    # The committee always has exactly INCLUSION_LIST_COMMITTEE_SIZE members ...
    check committee.len == int INCLUSION_LIST_COMMITTEE_SIZE

    # ... and equals the slot's beacon committees concatenated and cycled, with
    # every member a valid validator index.
    var indices: seq[ValidatorIndex]
    let committees_per_slot =
      get_committee_count_per_slot(state[], slot.epoch, cache)
    for i in 0'u64 ..< committees_per_slot:
      indices.add get_beacon_committee(state[], slot, CommitteeIndex(i), cache)

    check indices.len > 0
    for i in 0 ..< int INCLUSION_LIST_COMMITTEE_SIZE:
      check:
        committee[i] == indices[i mod indices.len]
        committee[i].uint64 < state[].validators.lenu64
