# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest,
  ./testutil, ./testblockutil,
  ../beacon_chain/spec/[beaconstate, datatypes, digest, validator],
  ../beacon_chain/[extras, state_transition, ssz]

suite "Block processing" & preset():
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  let
    # Genesis state with minimal number of deposits
    # TODO bls verification is a bit of a bottleneck here
    genesisState = initialize_beacon_state_from_eth1(
      Eth2Digest(), 0,
      makeInitialDeposits(), {skipMerkleValidation})
    genesisBlock = get_initial_beacon_block(genesisState)
    genesisRoot = hash_tree_root(genesisBlock.message)

  timedTest "Passes from genesis state, no block" & preset():
    var
      state = genesisState

    process_slots(state, state.slot + 1)
    check:
      state.slot == genesisState.slot + 1

  timedTest "Passes from genesis state, empty block" & preset():
    var
      state = genesisState
      previous_block_root = hash_tree_root(genesisBlock.message)
      new_block = makeBlock(state, previous_block_root, BeaconBlockBody())

    let block_ok = state_transition(state, new_block.message, {})

    check:
      block_ok

      state.slot == genesisState.slot + 1

  timedTest "Passes through epoch update, no block" & preset():
    var
      state = genesisState

    process_slots(state, Slot(SLOTS_PER_EPOCH))

    check:
      state.slot == genesisState.slot + SLOTS_PER_EPOCH

  timedTest "Passes through epoch update, empty block" & preset():
    var
      state = genesisState
      previous_block_root = genesisRoot

    for i in 1..SLOTS_PER_EPOCH.int:
      var new_block = makeBlock(state, previous_block_root, BeaconBlockBody())

      let block_ok = state_transition(state, new_block.message, {})

      check:
        block_ok

      previous_block_root = hash_tree_root(new_block.message)

    check:
      state.slot == genesisState.slot + SLOTS_PER_EPOCH

  timedTest "Attestation gets processed at epoch" & preset():
    var
      state = genesisState
      previous_block_root = genesisRoot
      cache = get_empty_per_epoch_cache()

    # Slot 0 is a finalized slot - won't be making attestations for it..
    process_slots(state, state.slot + 1)

    let
      # Create an attestation for slot 1 signed by the only attester we have!
      beacon_committee =
        get_beacon_committee(state, state.slot, 0, cache)
      attestation = makeAttestation(
        state, previous_block_root, beacon_committee[0], cache)

    # Some time needs to pass before attestations are included - this is
    # to let the attestation propagate properly to interested participants
    process_slots(state, GENESIS_SLOT + MIN_ATTESTATION_INCLUSION_DELAY + 1)

    let
      new_block = makeBlock(state, previous_block_root, BeaconBlockBody(
        attestations: @[attestation]
      ))
    discard state_transition(state, new_block.message, {})

    check:
      # TODO epoch attestations can get multiplied now; clean up paths to
      # enable exact 1-check again and keep finalization.
      state.current_epoch_attestations.len >= 1

    when const_preset=="minimal":
      # Can take several minutes with mainnet settings
      process_slots(state, Slot(191))

    # Would need to process more epochs for the attestation to be removed from
    # the state! (per above bug)
    #
    # check:
    #  state.latest_attestations.len == 0
