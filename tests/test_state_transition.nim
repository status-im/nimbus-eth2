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

  test "Passes from genesis state, no block":
    let
      state = on_startup(makeInitialValidators(), 0, Eth2Digest())
      latest_block = makeGenesisBlock(state)
      new_state = updateState(state, latest_block, none(BeaconBlock))
    check:
      new_state.state.slot == latest_block.slot + 1
      new_state.block_ok

  test "Passes from genesis state, empty block":
    let
      state = on_startup(makeInitialValidators(), 0, Eth2Digest())
      latest_block = makeGenesisBlock(state)
      new_block = makeBlock(state, latest_block)
      new_state = updateState(state, latest_block, some(new_block))

    check:
      new_state.state.slot == latest_block.slot + 1
      new_state.block_ok

  test "Passes through epoch update, no block":
    var
      state = on_startup(makeInitialValidators(), 0, Eth2Digest())
      latest_block = makeGenesisBlock(state)

    for i in 1..EPOCH_LENGTH.int:
      let new_state = updateState(state, latest_block, none(BeaconBlock))
      check:
        new_state.block_ok
      state = new_state.state

    check:
      state.slot == latest_block.slot + EPOCH_LENGTH

  test "Passes through epoch update, empty block":
    var
      state = on_startup(makeInitialValidators(), 0, Eth2Digest())
      latest_block = makeGenesisBlock(state)

    for i in 1..EPOCH_LENGTH.int:
      var new_block = makeBlock(state, latest_block)

      let new_state = updateState(state, latest_block, some(new_block))

      check:
        new_state.block_ok
      state = new_state.state
      latest_block = new_block

    check:
      state.slot == latest_block.slot
