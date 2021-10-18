# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  # Vendored packages
  stew/bitops2,
  # Specs
  ../../beacon_chain/spec/datatypes/base,
  ../../beacon_chain/spec/forks,
  # Test helpers
  ../mocking/mock_genesis,
  ./epoch_utils,
  ./justification_finalization_helpers,
  ../testutil

# See diagram: eth2-finalization.png
# (source) https://github.com/protolambda/eth2-docs#justification-and-finalization
# for a visualization of finalization rules

proc finalizeOn234(
    state: var ForkedHashedBeaconState, epoch: Epoch, sufficient_support: bool) =
  ## Check finalization on rule 1 "234"
  doAssert epoch > 4
  getStateField(state, slot) = Slot((epoch * SLOTS_PER_EPOCH) - 1) # Skip ahead to just before epoch

  # 43210 -- epochs ago
  # 3210x -- justification bitfields indices
  # 11*0. -- justification bitfield contents. . = this epoch, * is being justified now

  # checkpoints for epochs ago
  let (c1, c2, c3, c4, _) = getCheckpoints(epoch)
  putCheckpointsInBlockRoots(state.phase0Data.data, [c1, c2, c3, c4])

  # Save for final checks
  let old_finalized = getStateField(state, finalized_checkpoint)

  # Mock the state
  getStateField(state, previous_justified_checkpoint) = c4
  getStateField(state, current_justified_checkpoint) = c3
  getStateField(state, justification_bits) = 0'u8 # Bitvector of length 4
  # mock 3rd and 4th latest epochs as justified
  # indices are pre-shift
  getStateField(state, justification_bits).setBit 1
  getStateField(state, justification_bits).setBit 2
  # mock the 2nd latest epoch as justifiable, with 4th as the source
  addMockAttestations(
    state.phase0Data.data,
    epoch = epoch - 2,
    source = c4,
    target = c2,
    sufficient_support = sufficient_support
  )

  # State transition
  transitionEpochUntilJustificationFinalization(state)

  # Checks
  doAssert getStateField(state, previous_justified_checkpoint) == c3     # changed to old current
  if sufficient_support:
    doAssert getStateField(state, current_justified_checkpoint) == c2    # changed to second latest
    doAssert getStateField(state, finalized_checkpoint) == c4            # finalized old previous justified epoch
  else:
    doAssert getStateField(state, current_justified_checkpoint) == c3    # still old current
    doAssert getStateField(state, finalized_checkpoint) == old_finalized # no new finalized checkpoint

proc finalizeOn23(state: var ForkedHashedBeaconState, epoch: Epoch, sufficient_support: bool) =
  ## Check finalization on rule 2 "23"
  doAssert epoch > 3
  getStateField(state, slot) = Slot((epoch * SLOTS_PER_EPOCH) - 1) # Skip ahead to just before epoch

  # 43210 -- epochs ago
  # 210xx -- justification bitfields indices preshift
  # 3210x -- justification bitfield indices postshift
  # 01*0. -- justification bitfield contents. . = this epoch, * is being justified now

  # checkpoints for epochs ago
  let (c1, c2, c3, _, _) = getCheckpoints(epoch)
  putCheckpointsInBlockRoots(state.phase0Data.data, [c1, c2, c3])

  # Save for final checks
  let old_finalized = getStateField(state, finalized_checkpoint)

  # Mock the state
  getStateField(state, previous_justified_checkpoint) = c3
  getStateField(state, current_justified_checkpoint) = c3
  getStateField(state, justification_bits) = 0'u8 # Bitvector of length 4
  # mock 3rd as justified
  # indices are pre-shift
  getStateField(state, justification_bits).setBit 1
  # mock the 2nd latest epoch as justifiable, with 3rd as the source
  addMockAttestations(
    state.phase0Data.data,
    epoch = epoch - 2,
    source = c3,
    target = c2,
    sufficient_support = sufficient_support
  )

  # State transition
  transitionEpochUntilJustificationFinalization(state)

  # Checks
  doAssert getStateField(state, previous_justified_checkpoint) == c3     # changed to old current
  if sufficient_support:
    doAssert getStateField(state, current_justified_checkpoint) == c2    # changed to second latest
    doAssert getStateField(state, finalized_checkpoint) == c3            # finalized old previous justified epoch
  else:
    doAssert getStateField(state, current_justified_checkpoint) == c3    # still old current
    doAssert getStateField(state, finalized_checkpoint) == old_finalized # no new finalized checkpoint

proc finalizeOn123(state: var ForkedHashedBeaconState, epoch: Epoch, sufficient_support: bool) =
  ## Check finalization on rule 3 "123"
  doAssert epoch > 5
  getStateField(state, slot) = Slot((epoch * SLOTS_PER_EPOCH) - 1) # Skip ahead to just before epoch

  # 43210 -- epochs ago
  # 210xx -- justification bitfields indices preshift
  # 3210x -- justification bitfield indices postshift
  # 0110*. -- justification bitfield contents. . = this epoch, * is being justified now

  # checkpoints for epochs ago
  let (c1, c2, c3, c4, c5) = getCheckpoints(epoch)
  putCheckpointsInBlockRoots(state.phase0Data.data, [c1, c2, c3, c4, c5])

  # Save for final checks
  let old_finalized = getStateField(state, finalized_checkpoint)

  # Mock the state
  getStateField(state, previous_justified_checkpoint) = c5
  getStateField(state, current_justified_checkpoint) = c3
  getStateField(state, justification_bits) = 0'u8 # Bitvector of length 4
  # mock 3rd as justified
  # indices are pre-shift
  getStateField(state, justification_bits).setBit 1
  # mock the 2nd latest epoch as justifiable, with 5th as the source
  addMockAttestations(
    state.phase0Data.data,
    epoch = epoch - 2,
    source = c5,
    target = c2,
    sufficient_support = sufficient_support
  )
  # mock the 1st latest epoch as justifiable with 3rd as source
  addMockAttestations(
    state.phase0Data.data,
    epoch = epoch - 1,
    source = c3,
    target = c1,
    sufficient_support = sufficient_support
  )

  # State transition
  transitionEpochUntilJustificationFinalization(state)

  # Checks
  doAssert getStateField(state, previous_justified_checkpoint) == c3     # changed to old current
  if sufficient_support:
    doAssert getStateField(state, current_justified_checkpoint) == c1    # changed to second latest
    doAssert getStateField(state, finalized_checkpoint) == c3            # finalized old previous justified epoch
  else:
    doAssert getStateField(state, current_justified_checkpoint) == c3    # still old current
    doAssert getStateField(state, finalized_checkpoint) == old_finalized # no new finalized checkpoint

proc finalizeOn12(state: var ForkedHashedBeaconState, epoch: Epoch, sufficient_support: bool) =
  ## Check finalization on rule 4 "12"
  doAssert epoch > 2
  getStateField(state, slot) = Slot((epoch * SLOTS_PER_EPOCH) - 1) # Skip ahead to just before epoch

  # 43210 -- epochs ago
  # 210xx -- justification bitfields indices preshift
  # 3210x -- justification bitfield indices postshift
  # 01*0. -- justification bitfield contents. . = this epoch, * is being justified now

  # checkpoints for epochs ago
  let (c1, c2, _, _, _) = getCheckpoints(epoch)
  putCheckpointsInBlockRoots(state.phase0Data.data, [c1, c2])

  # Save for final checks
  let old_finalized = getStateField(state, finalized_checkpoint)

  # Mock the state
  getStateField(state, previous_justified_checkpoint) = c2
  getStateField(state, current_justified_checkpoint) = c2
  getStateField(state, justification_bits) = 0'u8 # Bitvector of length 4
  # mock 3rd as justified
  # indices are pre-shift
  getStateField(state, justification_bits).setBit 0
  # mock the 2nd latest epoch as justifiable, with 3rd as the source
  addMockAttestations(
    state.phase0Data.data,
    epoch = epoch - 1,
    source = c2,
    target = c1,
    sufficient_support = sufficient_support
  )

  # State transition
  transitionEpochUntilJustificationFinalization(state)

  # Checks
  doAssert getStateField(state, previous_justified_checkpoint) == c2     # changed to old current
  if sufficient_support:
    doAssert getStateField(state, current_justified_checkpoint) == c1    # changed to second latest
    doAssert getStateField(state, finalized_checkpoint) == c2            # finalized old previous justified epoch
  else:
    doAssert getStateField(state, current_justified_checkpoint) == c2    # still old current
    doAssert getStateField(state, finalized_checkpoint) == old_finalized # no new finalized checkpoint

proc payload =
  suite "[Unit - Spec - Epoch processing] Justification and Finalization " & preset():
    echo "   Finalization rules are detailed at https://github.com/protolambda/eth2-docs#justification-and-finalization"

    const NumValidators = uint64(8) * SLOTS_PER_EPOCH
    let genesisState = initGenesisState(NumValidators)
    doAssert getStateField(genesisState[], validators).lenu64 == NumValidators

    setup:
      var state = assignClone(genesisState[])

    test " Rule I - 234 finalization with enough support":
      finalizeOn234(state[], Epoch 5, sufficient_support = true)

    test " Rule I - 234 finalization without support":
      finalizeOn234(state[], Epoch 5, sufficient_support = false)

    test " Rule II - 23 finalization with enough support":
      finalizeOn23(state[], Epoch 4, sufficient_support = true)

    test " Rule II - 23 finalization without support":
      finalizeOn23(state[], Epoch 4, sufficient_support = false)

    test " Rule III - 123 finalization with enough support":
      finalizeOn123(state[], Epoch 6, sufficient_support = true)

    test " Rule III - 123 finalization without support":
      finalizeOn123(state[], Epoch 6, sufficient_support = false)

    test " Rule IV - 12 finalization with enough support":
      finalizeOn12(state[], Epoch 3, sufficient_support = true)

    test " Rule IV - 12 finalization without support":
      finalizeOn12(state[], Epoch 3, sufficient_support = false)

payload()
