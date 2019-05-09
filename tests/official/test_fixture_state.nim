# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard libs
  ospaths, strutils, json, unittest, strformat,
  # Third parties
  byteutils,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, crypto, digest, beaconstate],
  ../../beacon_chain/[ssz, state_transition],
  # Test utilities
  ./fixtures_utils

const TestFolder = currentSourcePath.rsplit(DirSep, 1)[0]
const TestsPath = "fixtures" / "json_tests" / "state" / "sanity-check_default-config_100-vals.json"


var stateTests: StateTests
suite "Official - State tests": # Initializing a beacon state from the deposits
  # Source: https://github.com/ethereum/eth2.0-specs/blob/2baa242ac004b0475604c4c4ef4315e14f56c5c7/tests/phase0/test_sanity.py#L55-L460
  test "Parsing the official state tests into Nimbus beacon types":
    stateTests = parseTests(TestFolder / TestsPath, StateTests) # TODO pending typedesc fix in fixture_utils.nim
    doAssert $stateTests.test_cases[0].name == "test_empty_block_transition"
  
  test "[For information - Non-blocking] Block root signing":
    # TODO: Currently we are unable to use the official EF tests:
    #   - The provided zero signature "0x0000..." is an invalid compressed BLS signature
    #   - Block headers are using that signature
    #   - Block processing checks that block.previous_block_root == signing_root(state.latest_block_header)
    #     -> Changing EF provided previous_block_root would render the block transition tests meaningless
    #     -> Changing the signature to a valid "0xc000..." makes all hashes/signing_root wrong ...
    #
    # So we only test that block header signing in Nimbus matches block header signing from the EF
    # And we can't deserialize from the raw YAML/JSON to avoid sanity checks on the signature
    
    # TODO: Move that in an actual SSZ test suite

    block: # sanity-check_default-config_100-vals.yaml - test "test_empty_block_transition"
      let header = BeaconBlockHeader(
        slot: Slot(4294967296),
        previous_block_root: ZERO_HASH,
        state_root: ZERO_HASH,
        block_body_root: Eth2Digest(data:
          hexToByteArray[32]("0x13f2001ff0ee4a528b3c43f63d70a997aefca990ed8eada2223ee6ec3807f7cc")
        ),
        signature: ValidatorSig()
      )
      let previous_block_root = Eth2Digest(data:
          hexToByteArray[32]("0x1179346f489d8be1731377cb199af5cc61faa38353e2d67e096bed182677062a")
        )
      echo "         Expected previous block root: 0x", previous_block_root
      echo "         Computed header signed root: 0x", signing_root(header)

  test "[For information] Print list of official tests to implement":
    for i, test in stateTests.test_cases:
      echo &"         Test #{i:03}: {test.name}"

  # test "Empty block transition":
  #   # TODO - assert that the constants match
  #   var state: BeaconState
  #   doAssert stateTests.test_cases[0].name == "test_empty_block_transition"
    
  #   template tcase(): untyped {.dirty.} =
  #     # Alias
  #     stateTests.test_cases[0]

  #   deepCopy(state, tcase.initial_state)

  #   # Use the provided empty block
  #   # Alternatively, generate one with `build_empty_block_for_next_slot`
  #   let blck = tcase.blocks[0]
  #   debugEcho blck.previous_block_root
    
  #   let ok = updateState(state, blck, flags = {})
  #   check:
  #     ok
  #     tcase.expected_state.eth1_data_votes.len == state.eth1_data_votes.len + 1
  #     get_block_root(tcase.expected_state, state.slot) == blck.previous_block_root
  
suite "[For information - non-blocking] Extra state tests":
  var initialState: BeaconState
  test "Initializing from scratch a new beacon chain with the same constants and deposit configuration as official state test 0":
    var deposits: seq[Deposit]
    var index = 0'u64
    for v in stateTests.test_cases[0].initial_state.validator_registry:
      deposits.add Deposit(
        proof: default(array[DEPOSIT_CONTRACT_TREE_DEPTH, Eth2Digest]),
        index: index,
        data: DepositData(
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
  test "Comparing state hashes":
    # TODO - Add official hashes when available
    # TODO - Make that a blocking test requirement
    echo "         Deserialized state hash: 0x" & $stateTests.test_cases[0].initial_state.hash_tree_root()
    echo "         From-scratch state hash: 0x" & $initialState.hash_tree_root()