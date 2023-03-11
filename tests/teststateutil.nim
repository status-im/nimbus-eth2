# Nimbus
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles,
  std/options,
  ./mocking/mock_deposits,
  ./helpers/math_helpers,
  ../beacon_chain/spec/[
    forks, helpers, state_transition, state_transition_block]

proc valid_deposit(state: var ForkyHashedBeaconState) =
  const deposit_amount = MAX_EFFECTIVE_BALANCE
  let validator_index = state.data.validators.len
  let deposit = mockUpdateStateForNewDeposit(
                  state.data,
                  uint64 validator_index,
                  deposit_amount,
                  flags = {}
                )

  let pre_val_count = state.data.validators.len
  let pre_balance = if validator_index < pre_val_count:
                      state.data.balances.item(validator_index)
                    else:
                      0
  doAssert process_deposit(defaultRuntimeConfig, state.data, deposit, {}).isOk
  doAssert state.data.validators.len == pre_val_count + 1
  doAssert state.data.balances.len == pre_val_count + 1
  doAssert state.data.balances.item(validator_index) == pre_balance + deposit.data.amount
  doAssert state.data.validators.item(validator_index).effective_balance ==
    round_multiple_down(
      min(MAX_EFFECTIVE_BALANCE, state.data.balances.item(validator_index)),
      EFFECTIVE_BALANCE_INCREMENT
    )
  state.root = hash_tree_root(state.data)

proc getTestStates*(
    initialState: ForkedHashedBeaconState, consensusFork: ConsensusFork):
    seq[ref ForkedHashedBeaconState] =
  # Randomly generated slot numbers, with a jump to around
  # SLOTS_PER_HISTORICAL_ROOT to force wraparound of those
  # slot-based mod/increment fields.
  const stateEpochs = [
    0, 1,

    # Around minimal wraparound SLOTS_PER_HISTORICAL_ROOT wraparound
    7, 8, 9,

    # Unexceptional cases, with 2 and 3-long runs
    39, 40, 114, 115, 116, 130, 131,

    # Approaching and passing mainnet SLOTS_PER_HISTORICAL_ROOT wraparound
    255, 256, 257]

  var
    tmpState = assignClone(initialState)
    cache = StateCache()
    info = ForkedEpochInfo()
    cfg = defaultRuntimeConfig

  static: doAssert high(ConsensusFork) == ConsensusFork.Deneb
  if consensusFork >= ConsensusFork.Altair:
    cfg.ALTAIR_FORK_EPOCH = 1.Epoch
  if consensusFork >= ConsensusFork.Bellatrix:
    cfg.BELLATRIX_FORK_EPOCH = 2.Epoch
  if consensusFork >= ConsensusFork.Capella:
    cfg.CAPELLA_FORK_EPOCH = 3.Epoch
  if consensusFork >= ConsensusFork.Deneb:
    cfg.DENEB_FORK_EPOCH = 4.Epoch

  for i, epoch in stateEpochs:
    let slot = epoch.Epoch.start_slot
    if getStateField(tmpState[], slot) < slot:
      process_slots(
        cfg, tmpState[], slot, cache, info, {}).expect("no failure")

    if i mod 3 == 0:
      withState(tmpState[]):
        valid_deposit(forkyState)
    doAssert getStateField(tmpState[], slot) == slot

    if tmpState[].kind == consensusFork:
      result.add assignClone(tmpState[])
