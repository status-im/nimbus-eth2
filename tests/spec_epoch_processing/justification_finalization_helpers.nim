# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  strformat, tables,
  # Specs
  ../../beacon_chain/spec/datatypes/phase0,
  ../../beacon_chain/spec/[beaconstate, validator, helpers],
  # Test helpers
  ../helpers/digest_helpers

# Justification and finalization utils
# ---------------------------------------------------------------

func addMockAttestations*(
       state: var phase0.BeaconState, epoch: Epoch,
       source, target: Checkpoint,
       sufficient_support = false
  ) =
  # We must be at the end of the epoch
  doAssert (state.slot + 1).is_epoch

  # Alias the attestations container
  var attestations: ptr seq[PendingAttestation]
  if state.get_current_epoch() == epoch:
    attestations = state.current_epoch_attestations.asSeq.addr
  elif state.get_previous_epoch() == epoch:
    attestations = state.previous_epoch_attestations.asSeq.addr
  else:
    raise newException(ValueError, &"Cannot include attestations from epoch {state.get_current_epoch()} in epoch {epoch}")

  # TODO: Working with an unsigned Gwei balance is a recipe for underflows to happen
  var cache = StateCache()
  var remaining_balance = state.get_total_active_balance(cache).int64 * 2 div 3

  let
    committees_per_slot = get_committee_count_per_slot(state, epoch, cache)

  for slot in epoch.slots():
    for committee_index in get_committee_indices(committees_per_slot):
      let committee = get_beacon_committee(state, slot, committee_index, cache)

      # Create a bitfield filled with the given count per attestation,
      # exactly on the right-most part of the committee field.
      var aggregation_bits = init(CommitteeValidatorsBits, committee.len)
      for v in 0 ..< committee.len * 2 div 3 + 1:
        if remaining_balance > 0:
          # Beware of the underflows, use int
          remaining_balance -= state.validators[v].effective_balance.int64
          aggregation_bits[v] = true
        else:
          break

      # Remove just one attester to make the marginal support insufficient
      if not sufficient_support:
        # Find the first attester if any
        let idx = aggregation_bits.find(true)
        if idx != -1:
          aggregation_bits[idx] = false

      attestations[].add PendingAttestation(
        aggregation_bits: aggregation_bits,
        data: AttestationData(
          slot: slot.Slot,
          index: committee_index.uint64,
          beacon_block_root: [byte 0xFF] * 32, # Irrelevant for testing
          source: source,
          target: target,
        ),
        inclusion_delay: 1
      )

func getCheckpoints*(epoch: Epoch): tuple[c1, c2, c3, c4, c5: Checkpoint] =
  if epoch >= 1: result.c1 = Checkpoint(epoch: epoch - 1, root: [byte 0xAA] * 32)
  if epoch >= 2: result.c2 = Checkpoint(epoch: epoch - 2, root: [byte 0xBB] * 32)
  if epoch >= 3: result.c3 = Checkpoint(epoch: epoch - 3, root: [byte 0xCC] * 32)
  if epoch >= 4: result.c4 = Checkpoint(epoch: epoch - 4, root: [byte 0xDD] * 32)
  if epoch >= 5: result.c5 = Checkpoint(epoch: epoch - 5, root: [byte 0xEE] * 32)

func putCheckpointsInBlockRoots*(
       state: var phase0.BeaconState,
       checkpoints: openArray[Checkpoint]) =
  for c in checkpoints:
    let idx = c.epoch.start_slot() mod SLOTS_PER_HISTORICAL_ROOT
    state.block_roots[idx] = c.root
