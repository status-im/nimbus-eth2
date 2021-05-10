# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Specs
  ../../beacon_chain/spec/[
    datatypes, state_transition_epoch, state_transition]

proc processSlotsUntilEndCurrentEpoch(state: var HashedBeaconState) =
  # Process all slots until the end of the last slot of the current epoch
  var
    cache = StateCache()
    rewards = RewardInfo()
  let slot =
    state.data.slot + SLOTS_PER_EPOCH - (state.data.slot mod SLOTS_PER_EPOCH)

  # Transition to slot before the epoch state transition
  discard process_slots(state, slot - 1, cache, rewards)

  # For the last slot of the epoch,
  # only process_slot without process_epoch
  # (see process_slots()) - state.root is invalid after here!
  process_slot(state.data, state.root)

proc transitionEpochUntilJustificationFinalization*(state: var HashedBeaconState) =
  # Process slots and do the epoch transition until crosslinks
  processSlotsUntilEndCurrentEpoch(state)

  var
    cache = StateCache()
    rewards = RewardInfo()

  rewards.init(state.data)
  rewards.process_attestations(state.data, cache)
  process_justification_and_finalization(
    state.data, rewards.total_balances)
