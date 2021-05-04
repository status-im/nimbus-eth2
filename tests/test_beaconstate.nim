# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ../beacon_chain/spec/[beaconstate, datatypes, digest, presets],
  ./testutil, ./testblockutil

suite "Beacon state" & preset():
  test "Smoke test initialize_beacon_state_from_eth1" & preset():
    let state = initialize_beacon_state_from_eth1(
      defaultRuntimePreset, Eth2Digest(), 0, makeInitialDeposits(SLOTS_PER_EPOCH, {}), {})
    check: state.validators.lenu64 == SLOTS_PER_EPOCH
