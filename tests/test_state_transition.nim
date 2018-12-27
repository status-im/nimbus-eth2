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
  ../beacon_chain/[extras, state_transition, ssz]

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
    var
      state = genesisState
      proposer_index = getNextBeaconProposerIndex(state)
      previous_block_root = hash_tree_root_final(genesisBlock)
    let block_ok =
      updateState(state, previous_block_root, none(BeaconBlock), {})
    check:
      block_ok

      state.slot == genesisState.slot + 1

      # When proposer skips their proposal, randao layer is still peeled!
      state.validator_registry[proposer_index].randao_layers ==
        genesisState.validator_registry[proposer_index].randao_layers + 1

  test "Passes from genesis state, empty block":
    var
      state = genesisState
      proposer_index = getNextBeaconProposerIndex(state)
      previous_block_root = hash_tree_root_final(genesisBlock)
      new_block = makeBlock(state, previous_block_root, BeaconBlockBody())

    let block_ok = updateState(
      state, previous_block_root, some(new_block), {})

    check:
      block_ok

      state.slot == genesisState.slot + 1

      # Proposer proposed, no need for additional peeling
      state.validator_registry[proposer_index].randao_layers ==
        genesisState.validator_registry[proposer_index].randao_layers

  test "Passes through epoch update, no block":
    var
      state = genesisState
      previous_block_root = hash_tree_root_final(genesisBlock)

    for i in 1..EPOCH_LENGTH.int:
      let block_ok = updateState(
        state, previous_block_root, none(BeaconBlock), {})
      check:
        block_ok

    check:
      state.slot == genesisState.slot + EPOCH_LENGTH

  test "Passes through epoch update, empty block":
    var
      state = genesisState
      previous_block_root = hash_tree_root_final(genesisBlock)

    for i in 1..EPOCH_LENGTH.int:
      var new_block = makeBlock(state, previous_block_root, BeaconBlockBody())

      let block_ok = updateState(
        state, previous_block_root, some(new_block), {})

      check:
        block_ok

      previous_block_root = hash_tree_root_final(new_block)

    check:
      state.slot == genesisState.slot + EPOCH_LENGTH

  test "Attestation gets processed at epoch":
    var
      state = genesisState
      previous_block_root = hash_tree_root_final(genesisBlock)

    # Slot 0 is a finalized slot - won't be making attestations for it..
    discard updateState(
        state, previous_block_root, none(BeaconBlock), {})

    let
      # Create an attestation for slot 1 signed by the only attester we have!
      attestation = makeAttestation(
        state, previous_block_root,
        state.shard_committees_at_slots[state.slot][0].committee[0])

    # Some time needs to pass before attestations are included - this is
    # to let the attestation propagate properly to interested participants
    while state.slot < MIN_ATTESTATION_INCLUSION_DELAY + 1:
      discard updateState(
        state, previous_block_root, none(BeaconBlock), {})

    let
      new_block = makeBlock(state, previous_block_root, BeaconBlockBody(
        attestations: @[attestation]
      ))
    discard updateState(state, previous_block_root, some(new_block), {})

    check:
      state.latest_attestations.len == 1

    # TODO Can't run more than 127 for now:
    # https://github.com/ethereum/eth2.0-specs/issues/352
    while state.slot < 127:
      discard updateState(
        state, previous_block_root, none(BeaconBlock), {})

    # Would need to process more epochs for the attestation to be removed from
    # the state! (per above bug)
    #
    # check:
    #  state.latest_attestations.len == 0
