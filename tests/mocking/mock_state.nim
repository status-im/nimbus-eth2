# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking helpers for BeaconState
# ---------------------------------------------------------------

import
  # Specs
  ../../beacon_chain/spec/[datatypes, state_transition]

proc nextEpoch*(state: var HashedBeaconState) =
  ## Transition to the start of the next epoch
  var cache = StateCache()
  let slot =
    state.data.slot + SLOTS_PER_EPOCH - (state.data.slot mod SLOTS_PER_EPOCH)
  doAssert process_slots(state, slot, cache)

proc nextSlot*(state: var HashedBeaconState) =
  ## Transition to the next slot
  var cache = StateCache()
  doAssert process_slots(state, state.data.slot + 1, cache)
