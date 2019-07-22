# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.


# processDeposits (state_transition_block.nim)
# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#deposits
# ---------------------------------------------------------------

import
  # Standard library
  unittest, math,
  # Specs
  ../../beacon_chain/spec/[beaconstate, datatypes, crypto, helpers, validator],
  # Internals
  ../../beacon_chain/[ssz, extras, state_transition],
  # Mock helpers
  ../mocking/[mock_deposits, mock_genesis],
  ../testutil, ../helpers/math_helpers

suite "[Unit - Spec - Block processing] Deposits " & preset():

  const NumValidators = uint64 5 * SLOTS_PER_EPOCH
  let genesisState = createGenesisState(NumValidators)
  doAssert genesisState.validators.len == int NumValidators

  template valid_deposit(deposit_amount: uint64, name: string): untyped =
    # TODO: BLS signature
    test "Deposit " & name & " MAX_EFFECTIVE_BALANCE balance (" &
          $(MAX_EFFECTIVE_BALANCE div 10'u64^9) & " ETH)":
      var state: BeaconState
      deepCopy(state, genesisState)

      # Test configuration
      # ----------------------------------------
      let validator_index = state.validators.len
      let deposit = mockUpdateStateForNewDeposit(
                      state,
                      uint64 validator_index,
                      deposit_amount,
                      flags = {skipValidation}
                    )

      # Params for sanity checks
      # ----------------------------------------
      let pre_val_count = state.validators.len
      let pre_balance = if validator_index < pre_val_count:
                          state.balances[validator_index]
                        else:
                          0

      # State transition
      # ----------------------------------------
      check: state.process_deposit(deposit, {skipValidation})

      # Check invariants
      # ----------------------------------------
      check:
        state.validators.len == pre_val_count + 1
        state.balances.len == pre_val_count + 1
        state.balances[validator_index] == pre_balance + deposit.data.amount
        state.validators[validator_index].effective_balance ==
          round_multiple_down(
            min(MAX_EFFECTIVE_BALANCE, state.balances[validator_index]),
            EFFECTIVE_BALANCE_INCREMENT
          )

  valid_deposit(MAX_EFFECTIVE_BALANCE - 1, "under")
  valid_deposit(MAX_EFFECTIVE_BALANCE, "at")
  valid_deposit(MAX_EFFECTIVE_BALANCE + 1, "over")

  test "Validator top-up":

    var state: BeaconState
    deepCopy(state, genesisState)

    # Test configuration
    # ----------------------------------------
    let validator_index = 0
    let deposit_amount = MAX_EFFECTIVE_BALANCE div 4
    let deposit = mockUpdateStateForNewDeposit(
                    state,
                    uint64 validator_index,
                    deposit_amount,
                    flags = {skipValidation}
                  )

    # Params for sanity checks
    # ----------------------------------------
    let pre_val_count = state.validators.len
    let pre_balance = if validator_index < pre_val_count:
                        state.balances[validator_index]
                      else:
                        0

    # State transition
    # ----------------------------------------
    check: state.process_deposit(deposit, {skipValidation})

    # Check invariants
    # ----------------------------------------
    check:
      state.validators.len == pre_val_count
      state.balances.len == pre_val_count
      state.balances[validator_index] == pre_balance + deposit.data.amount
      state.validators[validator_index].effective_balance ==
        round_multiple_down(
          min(MAX_EFFECTIVE_BALANCE, state.balances[validator_index]),
          EFFECTIVE_BALANCE_INCREMENT
        )
