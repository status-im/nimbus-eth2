# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, sequtils, unittest,
  ./testutil,
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers],
  ../beacon_chain/[extras, state_transition]

suite "Block processing":
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  let
    # Genesis state with minimal number of deposits
    # TODO bls verification is a bit of a bottleneck here
    genesisState = get_initial_beacon_state(
      makeInitialDeposits(), 0, Eth2Digest())
    genesisBlock = makeGenesisBlock(genesisState)

  test "Passes from genesis state, no block":
    let
      state = genesisState
      latest_block = genesisBlock
      new_state = updateState(state, latest_block, none(BeaconBlock), false)
    check:
      new_state.state.slot == latest_block.slot + 1
      new_state.block_ok

  test "Passes from genesis state, empty block":
    let
      state = genesisState
      latest_block = genesisBlock
      new_block = makeBlock(state, latest_block)
      new_state = updateState(state, latest_block, some(new_block), false)

    check:
      new_state.state.slot == latest_block.slot + 1
      new_state.block_ok

  test "Passes through epoch update, no block":
    var
      state = genesisState
      latest_block = genesisBlock

    for i in 1..EPOCH_LENGTH.int:
      let new_state = updateState(state, latest_block, none(BeaconBlock), false)
      check:
        new_state.block_ok
      state = new_state.state

    check:
      state.slot == latest_block.slot + EPOCH_LENGTH

  test "Passes through epoch update, empty block":
    var
      state = genesisState
      latest_block = genesisBlock

    for i in 1..EPOCH_LENGTH.int:
      var new_block = makeBlock(state, latest_block)

      let new_state = updateState(state, latest_block, some(new_block), false)

      check:
        new_state.block_ok
      state = new_state.state
      latest_block = new_block

    check:
      state.slot == latest_block.slot

  test "Increments proposer randao_layers, no block":
    let
      state = genesisState
      latest_block = genesisBlock
      proposer_index = getNextBeaconProposerIndex(state)
      previous_randao_layers =
        state.validator_registry[proposer_index].randao_layers
      new_state = updateState(state, latest_block, none(BeaconBlock), false)
      updated_proposer = new_state.state.validator_registry[proposer_index]

    check:
      updated_proposer.randao_layers == previous_randao_layers + 1

  test "Proposer randao layers unchanged, empty block":
    let
      state = genesisState
      latest_block = genesisBlock
      proposer_index = getNextBeaconProposerIndex(state)
      previous_randao_layers =
        state.validator_registry[proposer_index].randao_layers
      new_block = makeBlock(state, latest_block)
      new_state = updateState(state, latest_block, some(new_block), false)
      updated_proposer = new_state.state.validator_registry[proposer_index]

    check:
      updated_proposer.randao_layers == previous_randao_layers
