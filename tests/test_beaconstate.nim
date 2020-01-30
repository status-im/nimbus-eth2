# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  times, unittest,
  ./testutil, ./testblockutil,
  ../beacon_chain/spec/[beaconstate, datatypes, digest],
  ../beacon_chain/extras

suite "Beacon state" & preset():
  timedTest "Smoke test initialize_beacon_state_from_eth1" & preset():
    let state = initialize_beacon_state_from_eth1(
      Eth2Digest(), 0,
      makeInitialDeposits(SLOTS_PER_EPOCH, {}), {skipMerkleValidation})
    check: state.validators.len == SLOTS_PER_EPOCH
