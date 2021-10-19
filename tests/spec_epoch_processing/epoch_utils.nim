# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Specs
  ../../beacon_chain/spec/[
    forks, presets, state_transition, state_transition_epoch],
  ../../beacon_chain/spec/datatypes/phase0

proc processSlotsUntilEndCurrentEpoch(state: var ForkedHashedBeaconState) =
  # Process all slots until the end of the last slot of the current epoch
  var
    cache = StateCache()
    info = ForkedEpochInfo()
  let slot =
    getStateField(state, slot) + SLOTS_PER_EPOCH -
      (getStateField(state, slot) mod SLOTS_PER_EPOCH)

  # Transition to slot before the epoch state transition
  discard process_slots(defaultRuntimeConfig, state, slot - 1, cache, info, {})

  # For the last slot of the epoch,
  # only process_slot without process_epoch
  # (see process_slots()) - state.root is invalid after here!
  process_slot(state.phase0Data.data, getStateRoot(state))

proc transitionEpochUntilJustificationFinalization*(state: var ForkedHashedBeaconState) =
  # Process slots and do the epoch transition until crosslinks
  processSlotsUntilEndCurrentEpoch(state)

  var
    cache = StateCache()
    info: phase0.EpochInfo

  info.init(state.phase0Data.data)
  info.process_attestations(state.phase0Data.data, cache)
  process_justification_and_finalization(
    state.phase0Data.data, info.total_balances)
