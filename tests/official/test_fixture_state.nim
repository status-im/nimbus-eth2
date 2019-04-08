# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard lib
  ospaths, strutils, json, unittest, strformat,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, crypto, digest, beaconstate],
  ../../beacon_chain/ssz,
  # Test utilities
  ./state_test_utils

const TestFolder = currentSourcePath.rsplit(DirSep, 1)[0]
const TestsPath = "fixtures" / "json_tests" / "state" / "sanity-check_default-config_100-vals.json"

suite "Official - State tests": # Initializing a beacon state from the deposits
  var stateTests: StateTest
  test "Parsing the official state tests into Nimbus beacon types":
    stateTests = parseStateTests(TestFolder / TestsPath)
    doAssert $stateTests.test_cases[0].name == "test_empty_block_transition"
  var initialState: BeaconState
  test "Initializing from scratch a new beacon chain with the same constants and deposit configuration as official state test 0":
    var deposits: seq[Deposit]
    var index = 0'u64
    for v in stateTests.test_cases[0].initial_state.validator_registry:
      deposits.add Deposit(
        proof: default(array[DEPOSIT_CONTRACT_TREE_DEPTH, Eth2Digest]),
        index: index,
        deposit_data: DepositData(
          amount: 32000000000'u64, # TODO: read that from validator_balances
          timestamp: 0'u64,        # TODO: not initialized in test
          deposit_input: DepositInput(
            pubkey: v.pubkey,
            withdrawal_credentials: v.withdrawal_credentials,
            proof_of_possession: default(ValidatorSig) # TODO: not initialized in test
          )
        )
      )

    initialState = get_genesis_beacon_state(
      genesis_validator_deposits = deposits,
      genesis_time = 0,
      genesis_eth1_data = Eth1Data()
    )
  test "[For information] Comparing state hashes":
    # TODO - Add official hashes when available
    # TODO - Make that a blocking test requirement
    echo "Deserialized state hash: 0x" & $stateTests.test_cases[0].initial_state.hash_tree_root()
    echo "From-scratch state hash: 0x" & $initialState.hash_tree_root()
  test "[For information]  Print list of official tests to implement":
    for i, test in stateTests.test_cases:
      echo &"Test #{i:03}: {test.name}"