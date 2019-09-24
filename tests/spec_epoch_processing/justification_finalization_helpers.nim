# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  strformat,
  # Specs
  ../../beacon_chain/spec/[datatypes, state_transition_epoch, validator, helpers],
  # Internals
  ../../beacon_chain/[state_transition],
  # Test helpers
  ../helpers/digest_helpers

# Justification and finalization utils
# ---------------------------------------------------------------

iterator getShardsForSlot(state: BeaconState, slot: Slot): Shard =
  let
    epoch = compute_epoch_of_slot(slot)
    epoch_start_shard = get_start_shard(state, epoch)
    committees_per_slot = get_committee_count(state, epoch) div SLOTS_PER_EPOCH
    shard = epoch_start_shard + committees_per_slot * (slot mod SLOTS_PER_EPOCH)

  for i in 0 ..< committees_per_slot.int:
    yield shard + Shard(i)

proc addMockAttestations*(
       state: var BeaconState, epoch: Epoch,
       source, target: Checkpoint,
       sufficient_support = false
  ) =
  # We must be at the end of the epoch
  doAssert (state.slot + 1) mod SLOTS_PER_EPOCH == 0

  # Alias the attestations container
  var attestations: ptr seq[PendingAttestation]
  if state.get_current_epoch() == epoch:
    attestations = state.current_epoch_attestations.addr
  elif state.get_previous_epoch() == epoch:
    attestations = state.previous_epoch_attestations.addr
  else:
    raise newException(ValueError, &"Cannot include attestations from epoch {state.get_current_epoch()} in epoch {epoch}")

  # TODO: Working with an unsigned Gwei balance is a recipe for underflows to happen
  var remaining_balance = state.get_total_active_balance().int64 * 2 div 3

  let start_slot = compute_start_slot_of_epoch(epoch)

  # for-loop of distinct type is broken: https://github.com/nim-lang/Nim/issues/12074
  for slot in start_slot.uint64 ..< start_slot.uint64 + SLOTS_PER_EPOCH:
    for shard in getShardsForSlot(state, slot.Slot):

      # TODO: can we move cache out of the loops
      var cache = get_empty_per_epoch_cache()

      let committee = get_crosslink_committee(
                        state, slot.Slot.compute_epoch_of_slot(),
                        shard, cache
                      )

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
          beacon_block_root: [byte 0xFF] * 32, # Irrelevant for testing
          source: source,
          target: target,
          crosslink: Crosslink(shard: shard)
        ),
        inclusion_delay: 1
      )

proc getCheckpoints*(epoch: Epoch): tuple[c1, c2, c3, c4, c5: Checkpoint] =
  if epoch >= 1: result.c1 = Checkpoint(epoch: epoch - 1, root: [byte 0xAA] * 32)
  if epoch >= 2: result.c2 = Checkpoint(epoch: epoch - 2, root: [byte 0xBB] * 32)
  if epoch >= 3: result.c3 = Checkpoint(epoch: epoch - 3, root: [byte 0xCC] * 32)
  if epoch >= 4: result.c4 = Checkpoint(epoch: epoch - 4, root: [byte 0xDD] * 32)
  if epoch >= 5: result.c5 = Checkpoint(epoch: epoch - 5, root: [byte 0xEE] * 32)

proc putCheckpointsInBlockRoots*(
       state: var BeaconState,
       checkpoints: openarray[Checkpoint]) =
  for c in checkpoints:
    let idx = c.epoch.compute_start_slot_of_epoch() mod SLOTS_PER_HISTORICAL_ROOT
    state.block_roots[idx] = c.root
