# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard lib
  ospaths, strutils, json,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, crypto, digest, beaconstate],
  ../../beacon_chain/ssz,
  # Test utilities
  ./fixtures_utils

const TestFolder = currentSourcePath.rsplit(DirSep, 1)[0]
const TestsPath = "/sanity-check_default-config_100-vals-first_test.json"

block: # Initializing a beacon state from the deposits
  echo "Initializing a beacon state with the same deposit config as official test vectors"
  let stateTests = parseStateTests(TestFolder & TestsPath)
  doAssert $stateTests.test_cases[0].name == "test_empty_block_transition"

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

  let initialState = get_genesis_beacon_state(
    genesis_validator_deposits = deposits,
    genesis_time = 0,
    genesis_eth1_data = Eth1Data()
  )

  echo "From-scratch state hash: 0x" & $initialState.hash_tree_root()

  echo "Comparing with the official beacon state hash"
  echo "Deserialized state hash: 0x" & $stateTests.test_cases[0].initial_state.hash_tree_root()