# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  sets,
  stew/[bitseqs],
  # Internals
  ./datatypes, ./digest, ./beaconstate
import
  deques, sequtils, tables, options,
  chronicles, stew/[bitseqs, byteutils],
  beaconstate, datatypes, crypto, digest, helpers, validator

# Logging utilities
# --------------------------------------------------------

# TODO: gather all logging utilities
#       from crypto, digest, etc in a single file
func shortLog*(x: Checkpoint): string =
  "(epoch: " & $x.epoch & ", root: \"" & shortLog(x.root) & "\")"

# Helpers used in epoch transition and trace-level block transition
# --------------------------------------------------------

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#helper-functions-1
proc get_attesting_indices*(
    state: BeaconState, attestations: openarray[PendingAttestation],
    stateCache: var StateCache): HashSet[ValidatorIndex] =
  # This is part of get_unslashed_attesting_indices(...) in spec.
  result = initHashSet[ValidatorIndex]()
  for a in attestations:
    debug "FOOBAR: get_attesting_indices()",
      attestation_data = shortLog(a.data),
      aggregation_bits = a.aggregation_bits
    result = result.union(get_attesting_indices(
      state, a.data, a.aggregation_bits, stateCache))

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#helper-functions-1
proc get_unslashed_attesting_indices*(
    state: BeaconState, attestations: openarray[PendingAttestation],
    stateCache: var StateCache): HashSet[ValidatorIndex] =
  result = get_attesting_indices(state, attestations, stateCache)
  for index in result:
    if state.validators[index].slashed:
      result.excl index
