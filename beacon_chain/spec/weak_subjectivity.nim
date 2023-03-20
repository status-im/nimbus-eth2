# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  ./datatypes/base, ./forks, ./helpers

const
  SAFETY_DECAY* = 10'u64

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/weak-subjectivity.md#calculating-the-weak-subjectivity-period
func compute_weak_subjectivity_period(
    cfg: RuntimeConfig, state: ForkedHashedBeaconState): uint64 =
  var weak_subjectivity_period = cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY
  let validator_count =
    get_active_validator_indices_len(state, get_current_epoch(state))
  if validator_count >= cfg.MIN_PER_EPOCH_CHURN_LIMIT * cfg.CHURN_LIMIT_QUOTIENT:
    weak_subjectivity_period += SAFETY_DECAY * cfg.CHURN_LIMIT_QUOTIENT div (2 * 100)
  else:
    weak_subjectivity_period +=
      SAFETY_DECAY * validator_count div (2 * 100 * cfg.MIN_PER_EPOCH_CHURN_LIMIT)
  return weak_subjectivity_period

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/specs/phase0/weak-subjectivity.md#checking-for-stale-weak-subjectivity-checkpoint
func is_within_weak_subjectivity_period*(cfg: RuntimeConfig, current_slot: Slot,
                                         ws_state: ForkedHashedBeaconState,
                                         ws_checkpoint: Checkpoint): bool =
  # Clients may choose to validate the input state against the input Weak Subjectivity Checkpoint
  doAssert getStateField(ws_state, latest_block_header).state_root ==
    ws_checkpoint.root
  doAssert epoch(getStateField(ws_state, slot)) == ws_checkpoint.epoch

  let
    ws_period = compute_weak_subjectivity_period(cfg, ws_state)
    ws_state_epoch = epoch(getStateField(ws_state, slot))
    current_epoch = epoch(current_slot)

  current_epoch <= ws_state_epoch + ws_period
