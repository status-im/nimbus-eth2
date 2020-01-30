# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking a genesis state
# ---------------------------------------------------------------

import
  # Specs
  ../../beacon_chain/spec/[datatypes, beaconstate],
  # Internals
  ../../beacon_chain/[extras, interop],
  # Mocking procs
  ./mock_deposits


proc initGenesisState*(num_validators: uint64, genesis_time: uint64 = 0): BeaconState =
  let deposits = mockGenesisBalancedDeposits(
      validatorCount = num_validators,
      amountInEth = 32, # We create canonical validators with 32 Eth
      flags = {skipValidation}
    )

  initialize_beacon_state_from_eth1(
    eth1BlockHash, 0, deposits, {skipValidation, skipMerkleValidation})

when isMainModule:
  # Smoke test
  let state = initGenesisState(num_validators = SLOTS_PER_EPOCH)
  doAssert state.validators.len == SLOTS_PER_EPOCH
