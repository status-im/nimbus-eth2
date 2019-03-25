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

# const TestFolder = currentSourcePath.rsplit(DirSep, 1)[0] &
#   "/eth2.0-tests/state/"
# const StateTest = "sanity-check_default-config_100-vals.yaml"

const TestFolder = currentSourcePath.rsplit(DirSep, 1)[0]
const StateTest = "/sanity-check_default-config_100-vals-first_test.yaml"


let tests = yamlToJson(TestFolder & StateTest)

let test_empty_block_transition = tests[0]["test_cases"][0]
doAssert $test_empty_block_transition["name"].getStr() == "test_empty_block_transition", test_empty_block_transition["name"].getStr()

let validatorsJSON = test_empty_block_transition["initial_state"]["validator_registry"]

# var validators: seq[Validator]
# for v in validatorsJSON:
#   validators.add Validator(
#     pubkey: v["pubkey"].toPubkey,
#     withdrawal_credentials: v["withdrawal_credentials"].toDigest,
#     activation_epoch: v["activation_epoch"].toUint64.Epoch,
#     exit_epoch: v["exit_epoch"].toUint64.Epoch,
#     withdrawable_epoch: v["withdrawable_epoch"].toUint64.Epoch,
#     initiated_exit: v["initiated_exit"].getBool,
#     slashed: v["slashed"].getBool
#   )
# echo validators

var deposits: seq[Deposit]
var index = 0'u64
for v in validatorsJSON:
  deposits.add Deposit(
    proof: default(array[DEPOSIT_CONTRACT_TREE_DEPTH, Eth2Digest]),
    index: index,
    deposit_data: DepositData(
      amount: 32000000000'u64, # TODO: read that from validator_balances
      timestamp: 0'u64,        # TODO: not initialized in test
      deposit_input: DepositInput(
        pubkey: v["pubkey"].toPubkey,
        withdrawal_credentials: v["withdrawal_credentials"].toDigest,
        proof_of_possession: default(ValidatorSig) # TODO: not initialized in test
      )
    )
  )

let initialState = get_genesis_beacon_state(
  genesis_validator_deposits = deposits,
  genesis_time = 0,
  genesis_eth1_data = Eth1Data()
)

echo "State hash: 0x" & initialState.hash_tree_root().toHex()