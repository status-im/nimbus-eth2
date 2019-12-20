# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  unittest,
  # Vendored packages
  stew/bitops2,
  # Specs
  ../../beacon_chain/spec/datatypes,
  # Test helpers
  ../mocking/[mock_genesis],
  ./epoch_utils,
  ./justification_finalization_helpers,
  ../testutil

# See diagram: eth2-finalization.png
# (source) https://github.com/protolambda/eth2-docs#justification-and-finalization
# for a visualization of finalization rules

proc finalizeOn234(state: var BeaconState, epoch: Epoch, sufficient_support: bool) =
  ## Check finalization on rule 1 "234"
  doAssert epoch > 4
  state.slot = Slot((epoch * SLOTS_PER_EPOCH) - 1) # Skip ahead to just before epoch

  # 43210 -- epochs ago
  # 3210x -- justification bitfields indices
  # 11*0. -- justification bitfield contents. . = this epoch, * is being justified now

  # checkpoints for epochs ago
  let (c1, c2, c3, c4, _) = getCheckpoints(epoch)
  putCheckpointsInBlockRoots(state, [c1, c2, c3, c4])

  # Save for final checks
  let old_finalized = state.finalized_checkpoint

  # Mock the state
  state.previous_justified_checkpoint = c4
  state.current_justified_checkpoint = c3
  state.justification_bits = 0'u8 # Bitvector of length 4
  # mock 3rd and 4th latest epochs as justified
  # indices are pre-shift
  state.justification_bits.setBit 1
  state.justification_bits.setBit 2
  # mock the 2nd latest epoch as justifiable, with 4th as the source
  addMockAttestations(
    state,
    epoch = epoch - 2,
    source = c4,
    target = c2,
    sufficient_support = sufficient_support
  )

  # State transition
  transitionEpochUntilJustificationFinalization(state)

  # Checks
  doAssert state.previous_justified_checkpoint == c3     # changed to old current
  if sufficient_support:
    doAssert state.current_justified_checkpoint == c2    # changed to second latest
    doAssert state.finalized_checkpoint == c4            # finalized old previous justified epoch
  else:
    doAssert state.current_justified_checkpoint == c3    # still old current
    doAssert state.finalized_checkpoint == old_finalized # no new finalized checkpoint

proc finalizeOn23(state: var BeaconState, epoch: Epoch, sufficient_support: bool) =
  ## Check finalization on rule 2 "23"
  doAssert epoch > 3
  state.slot = Slot((epoch * SLOTS_PER_EPOCH) - 1) # Skip ahead to just before epoch

  # 43210 -- epochs ago
  # 210xx -- justification bitfields indices preshift
  # 3210x -- justification bitfield indices postshift
  # 01*0. -- justification bitfield contents. . = this epoch, * is being justified now

  # checkpoints for epochs ago
  let (c1, c2, c3, _, _) = getCheckpoints(epoch)
  putCheckpointsInBlockRoots(state, [c1, c2, c3])

  # Save for final checks
  let old_finalized = state.finalized_checkpoint

  # Mock the state
  state.previous_justified_checkpoint = c3
  state.current_justified_checkpoint = c3
  state.justification_bits = 0'u8 # Bitvector of length 4
  # mock 3rd as justified
  # indices are pre-shift
  state.justification_bits.setBit 1
  # mock the 2nd latest epoch as justifiable, with 3rd as the source
  addMockAttestations(
    state,
    epoch = epoch - 2,
    source = c3,
    target = c2,
    sufficient_support = sufficient_support
  )

  # State transition
  transitionEpochUntilJustificationFinalization(state)

  # Checks
  doAssert state.previous_justified_checkpoint == c3     # changed to old current
  if sufficient_support:
    doAssert state.current_justified_checkpoint == c2    # changed to second latest
    doAssert state.finalized_checkpoint == c3            # finalized old previous justified epoch
  else:
    doAssert state.current_justified_checkpoint == c3    # still old current
    doAssert state.finalized_checkpoint == old_finalized # no new finalized checkpoint

proc finalizeOn123(state: var BeaconState, epoch: Epoch, sufficient_support: bool) =
  ## Check finalization on rule 3 "123"
  doAssert epoch > 5
  state.slot = Slot((epoch * SLOTS_PER_EPOCH) - 1) # Skip ahead to just before epoch

  # 43210 -- epochs ago
  # 210xx -- justification bitfields indices preshift
  # 3210x -- justification bitfield indices postshift
  # 0110*. -- justification bitfield contents. . = this epoch, * is being justified now

  # checkpoints for epochs ago
  let (c1, c2, c3, c4, c5) = getCheckpoints(epoch)
  putCheckpointsInBlockRoots(state, [c1, c2, c3, c4, c5])

  # Save for final checks
  let old_finalized = state.finalized_checkpoint

  # Mock the state
  state.previous_justified_checkpoint = c5
  state.current_justified_checkpoint = c3
  state.justification_bits = 0'u8 # Bitvector of length 4
  # mock 3rd as justified
  # indices are pre-shift
  state.justification_bits.setBit 1
  # mock the 2nd latest epoch as justifiable, with 5th as the source
  addMockAttestations(
    state,
    epoch = epoch - 2,
    source = c5,
    target = c2,
    sufficient_support = sufficient_support
  )
  # mock the 1st latest epoch as justifiable with 3rd as source
  addMockAttestations(
    state,
    epoch = epoch - 1,
    source = c3,
    target = c1,
    sufficient_support = sufficient_support
  )

  # State transition
  transitionEpochUntilJustificationFinalization(state)

  # Checks
  doAssert state.previous_justified_checkpoint == c3     # changed to old current
  if sufficient_support:
    doAssert state.current_justified_checkpoint == c1    # changed to second latest
    doAssert state.finalized_checkpoint == c3            # finalized old previous justified epoch
  else:
    doAssert state.current_justified_checkpoint == c3    # still old current
    doAssert state.finalized_checkpoint == old_finalized # no new finalized checkpoint

proc finalizeOn12(state: var BeaconState, epoch: Epoch, sufficient_support: bool) =
  ## Check finalization on rule 4 "12"
  doAssert epoch > 2
  state.slot = Slot((epoch * SLOTS_PER_EPOCH) - 1) # Skip ahead to just before epoch

  # 43210 -- epochs ago
  # 210xx -- justification bitfields indices preshift
  # 3210x -- justification bitfield indices postshift
  # 01*0. -- justification bitfield contents. . = this epoch, * is being justified now

  # checkpoints for epochs ago
  let (c1, c2, _, _, _) = getCheckpoints(epoch)
  putCheckpointsInBlockRoots(state, [c1, c2])

  # Save for final checks
  let old_finalized = state.finalized_checkpoint

  # Mock the state
  state.previous_justified_checkpoint = c2
  state.current_justified_checkpoint = c2
  state.justification_bits = 0'u8 # Bitvector of length 4
  # mock 3rd as justified
  # indices are pre-shift
  state.justification_bits.setBit 0
  # mock the 2nd latest epoch as justifiable, with 3rd as the source
  addMockAttestations(
    state,
    epoch = epoch - 1,
    source = c2,
    target = c1,
    sufficient_support = sufficient_support
  )

  # State transition
  transitionEpochUntilJustificationFinalization(state)

  # Checks
  doAssert state.previous_justified_checkpoint == c2     # changed to old current
  if sufficient_support:
    doAssert state.current_justified_checkpoint == c1    # changed to second latest
    doAssert state.finalized_checkpoint == c2            # finalized old previous justified epoch
  else:
    doAssert state.current_justified_checkpoint == c2    # still old current
    doAssert state.finalized_checkpoint == old_finalized # no new finalized checkpoint

suite "[Unit - Spec - Epoch processing] Justification and Finalization " & preset():
  echo "   Finalization rules are detailed at https://github.com/protolambda/eth2-docs#justification-and-finalization"

  const NumValidators = uint64(8) * SLOTS_PER_EPOCH
  let genesisState = initGenesisState(NumValidators)
  doAssert genesisState.validators.len == int NumValidators

  var state: BeaconState
  template resetState: untyped =
    deepCopy(state, genesisState)

  timedTest " Rule I - 234 finalization with enough support":
    resetState()
    finalizeOn234(state, Epoch 5, sufficient_support = true)

  timedTest " Rule I - 234 finalization without support":
    resetState()
    finalizeOn234(state, Epoch 5, sufficient_support = false)

  timedTest " Rule II - 23 finalization with enough support":
    resetState()
    finalizeOn23(state, Epoch 4, sufficient_support = true)

  timedTest " Rule II - 23 finalization without support":
    resetState()
    finalizeOn23(state, Epoch 4, sufficient_support = false)


  timedTest " Rule III - 123 finalization with enough support":
    resetState()
    finalizeOn123(state, Epoch 6, sufficient_support = true)

  timedTest " Rule III - 123 finalization without support":
    resetState()
    finalizeOn123(state, Epoch 6, sufficient_support = false)

  timedTest " Rule IV - 12 finalization with enough support":
    resetState()
    finalizeOn12(state, Epoch 3, sufficient_support = true)

  timedTest " Rule IV - 12 finalization without support":
    resetState()
    finalizeOn12(state, Epoch 3, sufficient_support = false)
