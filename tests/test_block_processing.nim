# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, unittest,
  ../beacon_chain/spec/[datatypes, digest],
  ../beacon_chain/state_transition

suite "Block processing":
  ## For now just test that we can compile and execute block processing with mock data.

  test "Mock process_block":
    let
      state = BeaconState()
      blck = BeaconBlock(
        ancestor_hashes: @[Eth2Digest()]
      )
      newState = process_block(state, blck).get()
    check:
      newState.genesis_time == state.genesis_time