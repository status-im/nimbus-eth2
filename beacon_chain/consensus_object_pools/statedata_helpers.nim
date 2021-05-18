# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  ../spec/[beaconstate, datatypes, digest, helpers, presets, validator],
  ./block_pools_types

# State-related functionality based on StateData instead of BeaconState

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(stateData: StateData): Epoch =
  ## Return the current epoch.
  getStateField(stateData, slot).epoch

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(stateData: StateData): Epoch =
  ## Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  let current_epoch = get_current_epoch(stateData)
  if current_epoch == GENESIS_EPOCH:
    GENESIS_EPOCH
  else:
    current_epoch - 1

# Dispatch functions
func get_beacon_committee*(
    state: StateData, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): seq[ValidatorIndex] =
  # This one is used by tests/, ncli/, and a couple of places in RPC
  # TODO use the iterator version alone, to remove the risk of using
  # diverging get_beacon_committee() in tests and beacon_chain/ by a
  # wrapper approach (e.g., toSeq). This is a perf tradeoff for test
  # correctness/consistency.
  get_beacon_committee(state.data.data, slot, index, cache)

func get_committee_count_per_slot*(state: StateData,
                                   epoch: Epoch,
                                   cache: var StateCache): uint64 =
  # Return the number of committees at ``epoch``.
  get_committee_count_per_slot(state.data.data, epoch, cache)

template hash_tree_root*(stateData: StateData): Eth2Digest =
  # Dispatch here based on type/fork of state. Since StateData is a ref object
  # type, if Nim chooses the wrong overload, it will simply fail to compile.
  stateData.data.root

func get_shuffled_active_validator_indices*(
    cache: var StateCache, state: StateData, epoch: Epoch):
    var seq[ValidatorIndex] =
  cache.get_shuffled_active_validator_indices(state.data.data, epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_block_root_at_slot
func get_block_root_at_slot*(state: StateData,
                             slot: Slot): Eth2Digest =
  ## Return the block root at a recent ``slot``.

  get_block_root_at_slot(state.data.data, slot)
