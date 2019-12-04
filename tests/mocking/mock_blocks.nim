# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options,
  # Specs
  ../../beacon_chain/spec/[datatypes, crypto, helpers, validator],
  # Internals
  ../../beacon_chain/[ssz, extras, state_transition],
  # Mock helpers
  ./mock_validator_keys

# Routines for mocking blocks
# ---------------------------------------------------------------

proc signMockBlockImpl(
      state: BeaconState,
      blck: var BeaconBlock,
      proposer_index: ValidatorIndex
    ) =
  doAssert state.slot <= blck.slot

  let privkey = MockPrivKeys[proposer_index]

  blck.body.randao_reveal = bls_sign(
    key = privkey,
    msg = blck.slot
              .compute_epoch_at_slot()
              .hash_tree_root()
              .data,
    domain = get_domain(
      state,
      DOMAIN_RANDAO,
      message_epoch = blck.slot.compute_epoch_at_slot(),
    )
  )

  blck.signature = bls_sign(
    key = privkey,
    msg = blck.signing_root().data,
    domain = get_domain(
      state,
      DOMAIN_BEACON_PROPOSER,
      message_epoch = blck.slot.compute_epoch_at_slot(),
    )
  )

proc signMockBlock*(
  state: BeaconState,
  blck: var BeaconBlock,
  proposer_index: ValidatorIndex
  ) =
  signMockBlockImpl(state, blck, proposer_index)

proc signMockBlock*(
  state: BeaconState,
  blck: var BeaconBlock
  ) =

  var emptyCache = get_empty_per_epoch_cache()
  let proposer_index =
    if blck.slot == state.slot:
      get_beacon_proposer_index(state, emptyCache)
    else:
      # Stub to get proposer index of future slot
      # Note: this relies on ``let`` deep-copying the state
      #       i.e. BeaconState should have value semantics
      #            and not contain ref objects or pointers
      var stubState = state
      process_slots(stub_state, blck.slot)
      get_beacon_proposer_index(stub_state, emptyCache)

  # In tests, just let this throw if appropriate
  signMockBlockImpl(state, blck, proposer_index.get)

proc mockBlock*(
    state: BeaconState,
    slot: Slot,
    flags: UpdateFlags = {}): BeaconBlock =
  ## Mock a BeaconBlock for the specific slot
  ## Add skipValidation if block should not be signed

  result.slot = slot
  result.body.eth1_data.deposit_count = state.eth1_deposit_index

  var previous_block_header = state.latest_block_header
  if previous_block_header.state_root == ZERO_HASH:
    previous_block_header.state_root = state.hash_tree_root()
  result.parent_root = previous_block_header.signing_root()

  if skipValidation notin flags:
    signMockBlock(state, result)

proc mockBlockForNextSlot*(state: BeaconState, flags: UpdateFlags = {}): BeaconBlock =
  mockBlock(state, state.slot + 1, flags)

proc applyEmptyBlock*(state: var BeaconState) =
  ## Do a state transition with an empty signed block
  ## on the current slot
  let blck = mockBlock(state, state.slot, flags = {})
  # TODO: we only need to skip verifyStateRoot validation
  #       processBlock validation should work
  doAssert state_transition(state, blck, {skipValidation})
