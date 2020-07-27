# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/sets,
  # Internals
  ./datatypes, ./beaconstate

# Helpers used in epoch transition and trace-level block transition
# --------------------------------------------------------

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#helper-functions-1
func get_attesting_indices*(
    state: BeaconState, attestations: openArray[PendingAttestation],
    cache: var StateCache): HashSet[ValidatorIndex] =
  # This is part of get_unslashed_attesting_indices(...) in spec.
  # Exported bceause of external trace-level chronicles logging.
  result = initHashSet[ValidatorIndex]()
  for a in attestations:
    result.incl get_attesting_indices(
      state, a.data, a.aggregation_bits, cache)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#helper-functions-1
func get_unslashed_attesting_indices*(
    state: BeaconState, attestations: openArray[PendingAttestation],
    cache: var StateCache): HashSet[ValidatorIndex] =
  result = get_attesting_indices(state, attestations, cache)
  for index in result:
    if state.validators[index].slashed:
      result.excl index
