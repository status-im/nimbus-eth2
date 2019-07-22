# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking a genesis state
# ---------------------------------------------------------------

import
  # Specs
  ../../beacon_chain/spec/[datatypes, beaconstate, digest],
  # Internals
  ../../beacon_chain/extras,
  # Mocking procs
  ./mock_deposits


proc createGenesisState*(num_validators: uint64): BeaconState =

  # EF magic number (similar to https://en.wikipedia.org/wiki/Magic_number_(programming))
  const deposit_root = Eth2Digest(
    data: [byte 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42]
  )

  let eth1_data = Eth1Data(
    deposit_root: deposit_root,
    deposit_count: num_validators,
    block_hash: ZERO_HASH
  )

  result = initialize_beacon_state_from_eth1(
    genesis_validator_deposits = mockGenesisBalancedDeposits(
      validatorCount = num_validators,
      amountInEth = 32, # We create canonical validators with 32 Eth
      flags = {skipValidation}
    ),
    genesis_time = 0,
    genesis_eth1_data = eth1_data,
  )

when isMainModule:
  # Smoke test
  discard createGenesisState(SLOTS_PER_EPOCH)
