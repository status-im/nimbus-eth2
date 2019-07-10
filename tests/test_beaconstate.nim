# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  sequtils, unittest,
  ./testutil,
  ../beacon_chain/extras,
  ../beacon_chain/spec/[beaconstate, datatypes, digest]

suite "Beacon state" & preset():
  test "Smoke test initialize_beacon_state_from_eth1" & preset():
    let state = initialize_beacon_state_from_eth1(
      makeInitialDeposits(SLOTS_PER_EPOCH, {}), 0, Eth1Data(), {})
    check: state.validators.len == SLOTS_PER_EPOCH
