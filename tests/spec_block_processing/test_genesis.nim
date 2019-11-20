# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.


# initialize_beacon_state_from_eth1 (beaconstate.nim)
# https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/core/0_beacon-chain.md#genesis
# ---------------------------------------------------------------

{.used.}

import
  # Standard library
  unittest,
  # Specs
  ../../beacon_chain/spec/datatypes,
  # Internals
  ../../beacon_chain/ssz,
  # Mock helpers
  ../mocking/mock_genesis,
  ../testutil


# TODO:
#   - MIN_GENESIS_ACTIVE_VALIDATOR_COUNT is not implemented
#   - MIN_GENESIS_TIME is not implemented
#   - is_valid_genesis_state is not implemented

suite "[Unit - Spec - Genesis] Genesis block checks " & preset():
  test "is_valid_genesis_state for a valid state":
    discard initGenesisState(
      num_validators = MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
      genesis_time = MIN_GENESIS_TIME
    )
    discard "TODO"

  test "Invalid genesis time":
    discard initGenesisState(
      num_validators = MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
      genesis_time = MIN_GENESIS_TIME.uint64 - 1
    )
    discard "TODO"

  test "Not enough validators":
    discard initGenesisState(
      num_validators = MIN_GENESIS_ACTIVE_VALIDATOR_COUNT.uint64 - 1,
      genesis_time = MIN_GENESIS_TIME.uint64 - 1
    )
    discard "TODO"

  test "Validators with more than 32 ETH":
    discard "TODO"

  test "More validators than minimum":
    discard "TODO"
