# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking helpers for BeaconState
# ---------------------------------------------------------------

import
  # Specs
  ../../beacon_chain/spec/[forks, presets, state_transition],
  ../../beacon_chain/spec/datatypes/base

proc nextEpoch*(state: var ForkedHashedBeaconState) =
  ## Transition to the start of the next epoch
  var
    cache = StateCache()
    rewards = RewardInfo()
  let slot =
    getStateField(state, slot) + SLOTS_PER_EPOCH -
      (getStateField(state, slot) mod SLOTS_PER_EPOCH)
  doAssert process_slots(defaultRuntimeConfig, state, slot, cache, rewards, {})

proc nextSlot*(state: var ForkedHashedBeaconState) =
  ## Transition to the next slot
  var
    cache = StateCache()
    rewards = RewardInfo()

  doAssert process_slots(
    defaultRuntimeConfig, state, getStateField(state, slot) + 1, cache, rewards, {})
