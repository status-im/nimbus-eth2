# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options,
  # Specs
  ../../beacon_chain/spec/datatypes/phase0,
  ../../beacon_chain/spec/[helpers, signatures, validator],
  # Mock helpers
  ./mock_validator_keys

# Routines for mocking blocks
# ---------------------------------------------------------------

proc signMockBlockImpl(
      state: phase0.BeaconState,
      signedBlock: var phase0.SignedBeaconBlock
    ) =
  let block_slot = signedBlock.message.slot
  doAssert state.slot <= block_slot

  let privkey = MockPrivKeys[signedBlock.message.proposer_index]

  signedBlock.message.body.randao_reveal = get_epoch_signature(
    state.fork, state.genesis_validators_root, block_slot.compute_epoch_at_slot,
    privkey).toValidatorSig()
  signedBlock.root = hash_tree_root(signedBlock.message)
  signedBlock.signature = get_block_signature(
    state.fork, state.genesis_validators_root, block_slot,
    signedBlock.root, privkey).toValidatorSig()

proc signMockBlock*(state: phase0.BeaconState, signedBlock: var phase0.SignedBeaconBlock) =
  signMockBlockImpl(state, signedBlock)

proc mockBlock(
    state: phase0.BeaconState,
    slot: Slot): phase0.SignedBeaconBlock =
  ## TODO don't do this gradual construction, for exception safety
  ## Mock a BeaconBlock for the specific slot

  var emptyCache = StateCache()
  let proposer_index = get_beacon_proposer_index(state, emptyCache, slot)
  result.message.slot = slot
  result.message.proposer_index = proposer_index.get.uint64
  result.message.body.eth1_data.deposit_count = state.eth1_deposit_index

  var previous_block_header = state.latest_block_header
  if previous_block_header.state_root == ZERO_HASH:
    previous_block_header.state_root = state.hash_tree_root()
  result.message.parent_root = previous_block_header.hash_tree_root()

  signMockBlock(state, result)

proc mockBlockForNextSlot*(state: phase0.BeaconState): phase0.SignedBeaconBlock =
  mockBlock(state, state.slot + 1)
