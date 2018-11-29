# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# A imcomplete implementation of the state transition function, as described
# under "Per-block processing" in https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md
#
# The code is here mainly to verify the data types and get an idea about
# missing pieces - needs testing throughout

import
  options,
  ./spec/[beaconstate, crypto, datatypes, digest, helpers],
  ./ssz,
  milagro_crypto # nimble install https://github.com/status-im/nim-milagro-crypto@#master

func checkAttestations(state: BeaconState, blck: BeaconBlock):
    seq[ProcessedAttestation] =
  discard

func process_block*(state: BeaconState, blck: BeaconBlock): Option[BeaconState] =
  ## When a new block is received, all participants must verify that the block
  ## makes sense and update their state accordingly. This function will return
  ## the new state, unless something breaks along the way

  # XXX: simplistic way to be able to rollback state
  var state = state

  let
    parent_hash = blck.ancestor_hashes[0]
    slot = blck.slot
    parent_slot = slot - 1 # XXX Not!! can skip slots...
  # TODO actually get parent block, which means fixing up BeaconState refs above;
  # there's no distinction between active/crystallized state anymore, etc.

  state.recent_block_hashes =
    append_to_recent_block_hashes(state.recent_block_hashes, parent_slot, slot,
      parent_hash)

  state.pending_attestations.add checkAttestations(state, blck)

  doAssert blck.attestations.len <= MAX_ATTESTATION_COUNT

  for attestation in blck.attestations:
    if attestation.data.slot <= blck.slot - MIN_ATTESTATION_INCLUSION_DELAY:
      return
    if attestation.data.slot >= max(parent_slot - CYCLE_LENGTH + 1, 0):
      return
    #doAssert attestation.data.justified_slot == justification_source if attestation.data.slot >= state.last_state_recalculation_slot else prev_cycle_justification_source
    # doAssert attestation.data.justified_block_hash == get_block_hash(state, block, attestation.data.justified_slot).
    # doAssert either attestation.data.last_crosslink_hash or attestation.data.shard_block_hash equals state.crosslinks[shard].shard_block_hash.

    let attestation_participants = get_attestation_participants(
      state, attestation.data, attestation.attester_bitfield)

    var
      agg_pubkey: ValidatorPubKey
      empty = true

    for attester_idx in attestation_participants:
      let validator = state.validators[attester_idx]
      if empty:
        agg_pubkey = validator.pubkey
        empty = false
      else:
        agg_pubkey.combine(validator.pubkey)

    # Verify that aggregate_sig verifies using the group pubkey.
    let msg = hashSSZ(attestation.data)

    # For now only check compilation
    # doAssert attestation.aggregate_sig.verifyMessage(msg, agg_pubkey)
    debugEcho "Aggregate sig verify message: ", attestation.aggregate_sig.verifyMessage(msg, agg_pubkey)

  return some(state)
  # Extend the list of AttestationRecord objects in the active_state, ordering the new additions in the same order as they came in the block.
  # TODO

  # Verify that the slot % len(get_indices_for_slot(state, slot-1)[0])'th attester in get_indices_for_slot(state, slot-1)[0]is part of at least one of the AttestationRecord objects; this attester can be considered to be the proposer of the block.
  # TODO
