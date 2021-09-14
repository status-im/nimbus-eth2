# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Beacon chain internals
  ../../beacon_chain/spec/[forks, helpers, signatures, state_transition],
  # Mock helpers
  ./mock_validator_keys

# Routines for mocking blocks
# ---------------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/tests/core/pyspec/eth2spec/test/helpers/block.py#L26-L35
proc applyRandaoReveal(state: ForkedHashedBeaconState, b: var ForkedSignedBeaconBlock) =
  withBlck(b):
    doAssert getStateField(state, slot) <= blck.message.slot

    let proposer_index = blck.message.proposer_index
    let privkey = MockPrivKeys[proposer_index]

    blck.message.body.randao_reveal = 
      get_epoch_signature(
        getStateField(state, fork), 
        getStateField(state, genesis_validators_root),
        blck.message.slot.compute_epoch_at_slot,
        privkey).toValidatorSig()

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/tests/core/pyspec/eth2spec/test/helpers/block.py#L38-L54
proc signMockBlock*(state: ForkedHashedBeaconState, b: var ForkedSignedBeaconBlock) =
  withBlck(b):
    let proposer_index = blck.message.proposer_index
    let privkey = MockPrivKeys[proposer_index]

    blck.root = blck.message.hash_tree_root()
    blck.signature = 
      get_block_signature(
        getStateField(state, fork), 
        getStateField(state, genesis_validators_root),
        blck.message.slot,
        blck.root,
        privkey).toValidatorSig()

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/tests/core/pyspec/eth2spec/test/helpers/block.py#L75-L105
proc mockBlock*(
    state: ForkedHashedBeaconState, 
    slot: Slot, 
    cfg = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  ## TODO don't do this gradual construction, for exception safety
  ## Mock a BeaconBlock for the specific slot

  var cache = StateCache()
  var rewards = RewardInfo()
  var tmpState = assignClone(state)
  doAssert process_slots(cfg, tmpState[], slot, cache, rewards, flags = {})
  
  var previous_block_header = getStateField(tmpState[], latest_block_header)
  if previous_block_header.state_root == ZERO_HASH:
    previous_block_header.state_root = tmpState[].hash_tree_root()

  result.kind = case tmpState[].beaconStateFork
                of forkPhase0: BeaconBlockFork.Phase0
                of forkAltair: BeaconBlockFork.Altair
  withBlck(result):
    blck.message.slot = slot
    blck.message.proposer_index = get_beacon_proposer_index(tmpState[], cache, slot).get.uint64
    blck.message.body.eth1_data.deposit_count = getStateField(tmpState[], eth1_deposit_index)
    blck.message.parent_root = previous_block_header.hash_tree_root()
    
  applyRandaoReveal(tmpState[], result)

  if result.kind >= BeaconBlockFork.Altair:
    result.altairBlock.message.body.sync_aggregate.sync_committee_signature = ValidatorSig.infinity

  signMockBlock(tmpState[], result)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/tests/core/pyspec/eth2spec/test/helpers/block.py#L108-L109
proc mockBlockForNextSlot*(state: ForkedHashedBeaconState): ForkedSignedBeaconBlock =
  mockBlock(state, getStateField(state, slot) + 1)
