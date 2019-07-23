# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.


# initialize_beacon_state_from_eth1 (beaconstate.nim)
# https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/core/0_beacon-chain.md#genesis
# ---------------------------------------------------------------

import
  # Standard library
  unittest,
  # Specs
  ../../beacon_chain/spec/[beaconstate, datatypes, helpers, validator, digest],
  # Internals
  ../../beacon_chain/[ssz, extras, state_transition],
  # Mock helpers
  ../mocking/[mock_deposits, mock_genesis],
  ../testutils


# TODO:
#   - MIN_GENESIS_ACTIVE_VALIDATOR_COUNT is not implemented
#   - MIN_GENESIS_TIME is not implemented
#   - is_valid_genesis_state is not implemented

suite "[Unit - Spec - Genesis] Genesis block checks " & preset():
  test "is_valid_genesis_state for a valid state":
    let state = initGenesisState(
      num_validators = MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
      genesis_time = MIN_GENESIS_TIME
    )
    discard "TODO"

  test "Invalid genesis time":
    let state = initGenesisState(
      num_validators = MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
      genesis_time = MIN_GENESIS_TIME - 1
    )
    discard "TODO"

  test "Not enough validators":
    let state = initGenesisState(
      num_validators = MIN_GENESIS_ACTIVE_VALIDATOR_COUNT - 1,
      genesis_time = MIN_GENESIS_TIME - 1
    )
    discard "TODO"

  test "Validators with more than 32 ETH":
    discard "TODO"

  test "More validators than minimum":
    discard "TODO"
