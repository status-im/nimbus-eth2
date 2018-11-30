# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, sequtils, unittest,
  ./testhelpers,
  ../beacon_chain/spec/[beaconstate, datatypes, digest],
  ../beacon_chain/[extras, state_transition]

suite "Block processing":
  ## For now just test that we can compile and execute block processing with mock data.

  test "Mock process_block":
    let
      state = on_startup(makeInitialValidators(), 0, Eth2Digest())
      blck = BeaconBlock(
        slot: 1,
        ancestor_hashes: @[Eth2Digest()]
      )
      newState = process_block(state, blck)
    check:
      newState.isNone() # Broken block, should fail processing
