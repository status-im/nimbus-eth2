# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  ./datatypes/base, ./beaconstate, ./forks, ./helpers

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/weak-subjectivity.md#configuration
const SAFETY_DECAY* = 10'u64

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/weak-subjectivity.md#compute_weak_subjectivity_period
func compute_weak_subjectivity_period(
    cfg: RuntimeConfig, state: ForkyBeaconState): uint64 =
  ## Returns the weak subjectivity period for the current ``state``.
  ## This computation takes into account the effect of:
  ##     - validator set churn
  ##       (bounded by ``get_validator_churn_limit()`` per epoch), and
  ##     - validator balance top-ups
  ##       (bounded by ``MAX_DEPOSITS * SLOTS_PER_EPOCH`` per epoch).
  ## A detailed calculation can be found at:
  ## https://github.com/runtimeverification/beacon-chain-verification/blob/master/weak-subjectivity/weak-subjectivity-analysis.pdf
  var
    cache: StateCache
    ws_period = cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY
  let
    N = get_active_validator_indices_len(state, get_current_epoch(state))
    t = (get_total_active_balance(state, cache) div N).toEther
  const T = MAX_EFFECTIVE_BALANCE.toEther
  let delta = cfg.get_validator_churn_limit(state, cache)
  const
    Delta = MAX_DEPOSITS * SLOTS_PER_EPOCH
    D = SAFETY_DECAY

  if T * (200 + 3 * D) < t * (200 + 12 * D):
    let
      epochs_for_validator_set_churn =
        N * (t * (200 + 12 * D) - T * (200 + 3 * D)) div
          (600 * delta * (2 * t + T))
      epochs_for_balance_top_ups =
        N * (200 + 3 * D) div (600 * Delta)
    ws_period += max(epochs_for_validator_set_churn, epochs_for_balance_top_ups)
  else:
    ws_period += 3 * N * D * t div (200 * Delta * (T - t))

  ws_period

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/weak-subjectivity.md#is_within_weak_subjectivity_period
func is_within_weak_subjectivity_period*(cfg: RuntimeConfig, current_slot: Slot,
                                         ws_state: ForkedHashedBeaconState,
                                         ws_checkpoint: Checkpoint): bool =
  ## Clients may choose to validate the input state against the input Weak Subjectivity Checkpoint
  doAssert getStateField(ws_state, latest_block_header).state_root ==
    ws_checkpoint.root
  doAssert epoch(getStateField(ws_state, slot)) == ws_checkpoint.epoch

  let
    ws_period = withState(ws_state):
      cfg.compute_weak_subjectivity_period(forkyState.data)
    ws_state_epoch = epoch(getStateField(ws_state, slot))
    current_epoch = epoch(current_slot)

  current_epoch <= ws_state_epoch + ws_period
