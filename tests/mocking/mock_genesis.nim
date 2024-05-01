# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Mocking a genesis state
# ---------------------------------------------------------------

import
  # Specs
  ../../beacon_chain/spec/[beaconstate, forks, state_transition],
  # Mocking procs
  ./mock_deposits

const mockEth1BlockHash* =
  Eth2Digest.fromHex("0x4242424242424242424242424242424242424242")

proc initGenesisState*(
    num_validators = 8'u64 * SLOTS_PER_EPOCH,
    cfg = defaultRuntimeConfig): ref ForkedHashedBeaconState =
  let deposits = mockGenesisBalancedDeposits(
      validatorCount = num_validators,
      amountInEth = 32.Ether, # We create canonical validators with 32 Eth
      flags = {}
    )

  result = (ref ForkedHashedBeaconState)(
    kind: ConsensusFork.Phase0,
    phase0Data: initialize_hashed_beacon_state_from_eth1(
      cfg, mockEth1BlockHash, 0, deposits, {}))

  var cache: StateCache
  maybeUpgradeState(cfg, result[], cache)

when isMainModule:
  # Smoke test
  let state = initGenesisState(num_validators = SLOTS_PER_EPOCH)
  doAssert state.validators.len == SLOTS_PER_EPOCH