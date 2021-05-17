# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  ./datatypes, ./digest, ./helpers

const
  SAFETY_DECAY* = 10'u64

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/weak-subjectivity.md#calculating-the-weak-subjectivity-period
func compute_weak_subjectivity_period(state: StateData): uint64 =
  var weak_subjectivity_period = MIN_VALIDATOR_WITHDRAWABILITY_DELAY
  let validator_count =
    get_active_validator_indices_len(
      state.data.data, get_current_epoch(state.data.data))
  if validator_count >= MIN_PER_EPOCH_CHURN_LIMIT * CHURN_LIMIT_QUOTIENT:
    weak_subjectivity_period += SAFETY_DECAY * CHURN_LIMIT_QUOTIENT div (2 * 100)
  else:
    weak_subjectivity_period += SAFETY_DECAY * validator_count div (2 * 100 * MIN_PER_EPOCH_CHURN_LIMIT)
  return weak_subjectivity_period

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/weak-subjectivity.md#checking-for-stale-weak-subjectivity-checkpoint
func is_within_weak_subjectivity_period*(current_slot: Slot,
                                         ws_state: StateData,
                                         ws_checkpoint: Checkpoint): bool =
  # Clients may choose to validate the input state against the input Weak Subjectivity Checkpoint
  doAssert getStateField(ws_state, latest_block_header).state_root ==
    ws_checkpoint.root
  doAssert compute_epoch_at_slot(getStateField(ws_state, slot)) ==
    ws_checkpoint.epoch

  let
    ws_period = compute_weak_subjectivity_period(ws_state)
    ws_state_epoch = compute_epoch_at_slot(getStateField(ws_state, slot))
    current_epoch = compute_epoch_at_slot(current_slot)

  current_epoch <= ws_state_epoch + ws_period

