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
      signedBlock: var SignedBeaconBlock,
      proposer_index: ValidatorIndex
    ) =
  let block_slot = signedBlock.message.slot
  doAssert state.slot <= block_slot

  let privkey = MockPrivKeys[proposer_index]

  signedBlock.message.body.randao_reveal = bls_sign(
    key = privkey,
    msg = block_slot
              .compute_epoch_at_slot()
              .hash_tree_root()
              .data,
    domain = get_domain(
      state,
      DOMAIN_RANDAO,
      message_epoch = block_slot.compute_epoch_at_slot(),
    )
  )

  signedBlock.signature = bls_sign(
    key = privkey,
    msg = signedBlock.message.hash_tree_root().data,
    domain = get_domain(
      state,
      DOMAIN_BEACON_PROPOSER,
      message_epoch = block_slot.compute_epoch_at_slot(),
    )
  )

proc signMockBlock*(
  state: BeaconState,
  signedBlock: var SignedBeaconBlock
  ) =

  var emptyCache = get_empty_per_epoch_cache()
  let proposer_index =
    if signedBlock.message.slot == state.slot:
      get_beacon_proposer_index(state, emptyCache)
    else:
      # Stub to get proposer index of future slot
      # Note: this relies on ``let`` deep-copying the state
      #       i.e. BeaconState should have value semantics
      #            and not contain ref objects or pointers
      var stubState = state
      process_slots(stub_state, signedBlock.message.slot)
      get_beacon_proposer_index(stub_state, emptyCache)

  # In tests, just let this throw if appropriate
  signMockBlockImpl(state, signedBlock, proposer_index.get)

proc mockBlock(
    state: BeaconState,
    slot: Slot,
    flags: UpdateFlags = {}): SignedBeaconBlock =
  ## Mock a BeaconBlock for the specific slot
  ## Add skipValidation if block should not be signed

  result.message.slot = slot
  result.message.body.eth1_data.deposit_count = state.eth1_deposit_index

  var previous_block_header = state.latest_block_header
  if previous_block_header.state_root == ZERO_HASH:
    previous_block_header.state_root = state.hash_tree_root()
  result.message.parent_root = previous_block_header.hash_tree_root()

  if skipValidation notin flags:
    signMockBlock(state, result)

proc mockBlockForNextSlot*(state: BeaconState, flags: UpdateFlags = {}):
    SignedBeaconBlock =
  mockBlock(state, state.slot + 1, flags)

proc applyEmptyBlock*(state: var BeaconState) =
  ## Do a state transition with an empty signed block
  ## on the current slot
  let signedBlock = mockBlock(state, state.slot, flags = {})
  # TODO: we only need to skip verifyStateRoot validation
  #       processBlock validation should work
  doAssert state_transition(state, signedBlock.message, {skipValidation})
