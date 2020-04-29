# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Specs
  ../../beacon_chain/spec/[datatypes, state_transition_epoch, validator],
  # Internals
  ../../beacon_chain/[state_transition]

proc processSlotsUntilEndCurrentEpoch(state: var HashedBeaconState) =
  # Process all slots until the end of the last slot of the current epoch
  let slot =
    state.data.slot + SLOTS_PER_EPOCH - (state.data.slot mod SLOTS_PER_EPOCH)

  # Transition to slot before the epoch state transition
  process_slots(state, slot - 1)

  # For the last slot of the epoch,
  # only process_slot without process_epoch
  # (see process_slots())
  process_slot(state)

proc transitionEpochUntilJustificationFinalization*(state: var HashedBeaconState) =
  # Process slots and do the epoch transition until crosslinks
  processSlotsUntilEndCurrentEpoch(state)

  # From process_epoch()
  var per_epoch_cache = get_empty_per_epoch_cache()

  process_justification_and_finalization(state.data, per_epoch_cache)
