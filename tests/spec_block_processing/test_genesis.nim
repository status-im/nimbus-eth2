# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.


# initialize_beacon_state_from_eth1 (beaconstate.nim)
# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/core/0_beacon-chain.md#genesis
# ---------------------------------------------------------------

{.used.}

import
  # Standard library
  unittest,
  # Specs
  ../../beacon_chain/spec/datatypes,
  # Mock helpers
  ../mocking/mock_genesis,
  ../testutil


# TODO:
#   - MIN_GENESIS_ACTIVE_VALIDATOR_COUNT is not implemented
#   - MIN_GENESIS_TIME is not implemented
#   - is_valid_genesis_state is not implemented

suite "[Unit - Spec - Genesis] Genesis block checks " & preset():
  timedTest "is_valid_genesis_state for a valid state":
    discard initGenesisState(
      num_validators = MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
      genesis_time = MIN_GENESIS_TIME
    )
    discard "TODO"

  timedTest "Invalid genesis time":
    discard initGenesisState(
      num_validators = MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
      genesis_time = MIN_GENESIS_TIME.uint64 - 1
    )
    discard "TODO"

  timedTest "Validators with more than 32 ETH":
    discard "TODO"

  timedTest "More validators than minimum":
    discard "TODO"

when false:
  # TODO causes possible stack overflow in mainnet
  timedTest "Not enough validators":
    discard initGenesisState(
      num_validators = MIN_GENESIS_ACTIVE_VALIDATOR_COUNT.uint64 - 1,
      genesis_time = MIN_GENESIS_TIME.uint64 - 1
    )
    discard "TODO"
