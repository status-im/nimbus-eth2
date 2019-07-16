# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Specs
  ../../beacon_chain/spec/[datatypes, crypto, helpers, validator],
  # Internals
  ../../beacon_chain/[ssz, extras, state_transition],
  # Mock helpers
  ./mock_validator_keys

# Routines for mocking block
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
              .slot_to_epoch()
              .hash_tree_root()
              .data,
    domain = get_domain(
      state,
      DOMAIN_RANDAO,
      message_epoch = blck.slot.slot_to_epoch(),
    )
  )

  blck.signature = bls_sign(
    key = privkey,
    msg = blck.signing_root().data,
    domain = get_domain(
      state,
      DOMAIN_BEACON_PROPOSER,
      message_epoch = blck.slot.slot_to_epoch(),
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

  var proposer_index: ValidatorIndex
  var emptyCache = get_empty_per_epoch_cache()
  if blck.slot == state.slot:
    proposer_index = get_beacon_proposer_index(state, emptyCache)
  else:
    # Stub to get proposer index of future slot
    # Note: this relies on ``let`` deep-copying the state
    #       i.e. BeaconState should have value semantics
    #            and not contain ref objects or pointers
    var stubState = state
    process_slots(stub_state, blck.slot)
    proposer_index = get_beacon_proposer_index(stub_state, emptyCache)

  signMockBlockImpl(state, blck, proposer_index)

proc mockBlock*(
    state: BeaconState,
    slot: Slot,
    flags: UpdateFlags = {}): BeaconBlock =
  ## Mock a BeaconBlock for the specific slot
  ## Add skipValidation if block should not be signed

  result.slot = slot
  result.body.eth1_data.deposit_count = state.eth1_deposit_index

  if state.latest_block_header.state_root == ZERO_HASH:
    result.parent_root = signing_root(state.latest_block_header)
  else:
    result.parent_root = state.hash_tree_root().signing_root()

  if skipValidation notin flags:
    signMockBlock(state, result)

proc mockBlockForNextSlot*(state: BeaconState, flags: UpdateFlags = {}): BeaconBlock =
  mockBlock(state, state.slot + 1, flags)
