# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Beacon chain internals
  ../../beacon_chain/spec/
    [forks, helpers, signatures, state_transition, validator],
  ../../beacon_chain/spec/datatypes/[phase0, altair, bellatrix],
  # Test utilities
  ../testblockutil

# Routines for mocking blocks
# ---------------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/tests/core/pyspec/eth2spec/test/helpers/block.py#L26-L35
func apply_randao_reveal(state: ForkyBeaconState, blck: var ForkySignedBeaconBlock) =
  doAssert state.slot <= blck.message.slot
  let
    proposer_index = blck.message.proposer_index.ValidatorIndex
    privkey = MockPrivKeys[proposer_index]

  blck.message.body.randao_reveal = get_epoch_signature(
    state.fork,
    state.genesis_validators_root,
    blck.message.slot.epoch,
    privkey).toValidatorSig()

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/tests/core/pyspec/eth2spec/test/helpers/block.py#L38-L54
func sign_block(state: ForkyBeaconState, blck: var ForkySignedBeaconBlock) =
  let
    proposer_index = blck.message.proposer_index.ValidatorIndex
    privkey = MockPrivKeys[proposer_index]

  blck.root = blck.message.hash_tree_root()
  blck.signature = get_block_signature(
    state.fork,
    state.genesis_validators_root,
    blck.message.slot,
    blck.root,
    privkey).toValidatorSig()

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/tests/core/pyspec/eth2spec/test/helpers/block.py#L75-L104
proc mockBlock*(
    state: ForkedHashedBeaconState,
    slot: Slot,
    cfg = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  ## TODO don't do this gradual construction, for exception safety
  ## Mock a BeaconBlock for the specific slot
  var
    cache = StateCache()
    tmpState = assignClone(state)
  if getStateField(state, slot) != slot:
    var info = ForkedEpochInfo()
    process_slots(cfg, tmpState[], slot, cache, info, flags = {}).expect("no failure")

  result.kind = case tmpState[].kind
                of BeaconStateFork.Phase0:    BeaconBlockFork.Phase0
                of BeaconStateFork.Altair:    BeaconBlockFork.Altair
                of BeaconStateFork.Bellatrix: BeaconBlockFork.Bellatrix
  withStateAndBlck(tmpState[], result):
    blck.message.slot = slot
    blck.message.proposer_index =
      get_beacon_proposer_index(state.data, cache, slot).get.uint64
    blck.message.body.eth1_data.deposit_count = state.data.eth1_deposit_index
    blck.message.parent_root = block:
      var previous_block_header = state.data.latest_block_header
      if previous_block_header.state_root == ZERO_HASH:
        previous_block_header.state_root = state.data.hash_tree_root()
      previous_block_header.hash_tree_root()

    apply_randao_reveal(state.data, blck)

    when stateFork >= BeaconStateFork.Altair:
      blck.message.body.sync_aggregate = SyncAggregate.init()

    when stateFork >= BeaconStateFork.Bellatrix:
      blck.message.body.execution_payload =
        build_empty_execution_payload(state.data)

    sign_block(state.data, blck)

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/tests/core/pyspec/eth2spec/test/helpers/block.py#L107-L108
proc mockBlockForNextSlot*(
    state: ForkedHashedBeaconState): ForkedSignedBeaconBlock =
  ## Mock a BeaconBlock for the next slot
  mockBlock(state, getStateField(state, slot) + 1)
