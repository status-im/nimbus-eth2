# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Beacon chain internals
  ../../beacon_chain/spec/
    [forks, helpers, signatures, state_transition, validator],
  ../../beacon_chain/spec/datatypes/[phase0, altair, merge],
  # Test utilities
  ../testblockutil

# Routines for mocking blocks
# ---------------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/tests/core/pyspec/eth2spec/test/helpers/block.py#L26-L35
func apply_randao_reveal(
    state: SomeBeaconState,
    blck: var (phase0.SignedBeaconBlock | altair.SignedBeaconBlock |
               merge.SignedBeaconBlock)) =
  doAssert state.slot <= blck.message.slot
  let
    proposer_index = blck.message.proposer_index.ValidatorIndex
    privkey = MockPrivKeys[proposer_index]

  blck.message.body.randao_reveal = get_epoch_signature(
    state.fork,
    state.genesis_validators_root,
    blck.message.slot.compute_epoch_at_slot,
    privkey).toValidatorSig()

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/tests/core/pyspec/eth2spec/test/helpers/block.py#L38-L54
func sign_block(
    state: SomeBeaconState,
    blck: var (phase0.SignedBeaconBlock | altair.SignedBeaconBlock |
               merge.SignedBeaconBlock)) =
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

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/tests/core/pyspec/eth2spec/test/helpers/execution_payload.py#L1-L31
func build_empty_execution_payload(
    state: merge.BeaconState): ExecutionPayload =
  ## Assuming a pre-state of the same slot, build a valid ExecutionPayload
  ## without any transactions.
  let
    latest = state.latest_execution_payload_header
    timestamp = compute_timestamp_at_slot(state, state.slot)
    randao_mix = get_randao_mix(state, get_current_epoch(state))

  var payload = ExecutionPayload(
    parent_hash: latest.block_hash,
    state_root: latest.state_root, # no changes to the state
    receipt_root: Eth2Digest(data: cast[array[32, uint8]](
      "no receipts here\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")),
    block_number: latest.block_number + 1,
    random: randao_mix,
    gas_limit: latest.gas_limit, # retain same limit
    gas_used: 0, # empty block, 0 gas
    timestamp: timestamp,
    base_fee_per_gas: latest.base_fee_per_gas) # retain same base_fee

  payload.block_hash = withEth2Hash:
    h.update payload.hash_tree_root().data
    h.update cast[array[13, uint8]]("FAKE RLP HASH")

  payload

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/tests/core/pyspec/eth2spec/test/helpers/block.py#L75-L104
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
    doAssert process_slots(cfg, tmpState[], slot, cache, info, flags = {})

  result.kind = case tmpState[].kind
                of BeaconStateFork.Phase0: BeaconBlockFork.Phase0
                of BeaconStateFork.Altair: BeaconBlockFork.Altair
                of BeaconStateFork.Merge:  BeaconBlockFork.Merge
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

    when stateFork >= BeaconStateFork.Merge:
      blck.message.body.execution_payload =
        build_empty_execution_payload(state.data)

    sign_block(state.data, blck)

# https://github.com/ethereum/consensus-specs/blob/v1.1.1/tests/core/pyspec/eth2spec/test/helpers/block.py#L107-L108
proc mockBlockForNextSlot*(
    state: ForkedHashedBeaconState): ForkedSignedBeaconBlock =
  ## Mock a BeaconBlock for the next slot
  mockBlock(state, getStateField(state, slot) + 1)
