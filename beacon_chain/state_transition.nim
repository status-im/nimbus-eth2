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
  ./extras,
  ./spec/[beaconstate, crypto, datatypes, digest, helpers],
  ./ssz,
  milagro_crypto # nimble install https://github.com/status-im/nim-milagro-crypto@#master

# TODO there's an ugly mix of functional and procedural styles here that
#      is due to how the spec is mixed as well - once we're past the prototype
#      stage, this will need clearing up and unification.

func checkAttestations(state: BeaconState,
                       blck: BeaconBlock,
                       parent_slot: uint64): Option[seq[ProcessedAttestation]] =
  # TODO perf improvement potential..
  if blck.attestations.len > MAX_ATTESTATION_COUNT:
    return

  var res: seq[ProcessedAttestation]
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
    debugEcho "Aggregate sig verify message: ",
      attestation.aggregate_sig.verifyMessage(msg, agg_pubkey)

    res.add ProcessedAttestation(
      data: attestation.data,
      attester_bitfield: attestation.attester_bitfield,
      poc_bitfield: attestation.poc_bitfield,
      slot_included: blck.slot
    )

  some(res)

func verifyProposerSignature(state: BeaconState, blck: BeaconBlock): bool =
  var blck_without_sig = blck
  blck_without_sig.proposer_signature = ValidatorSig()

  let
    proposal_hash = hashSSZ(ProposalSignedData(
      slot: blck.slot,
      shard: BEACON_CHAIN_SHARD,
      block_hash: Eth2Digest(data: hashSSZ(blck_without_sig))
    ))

  verifyMessage(
    blck.proposer_signature, proposal_hash,
    state.validators[get_beacon_proposer_index(state, blck.slot).int].pubkey)

func processRandaoReveal(state: var BeaconState,
                         blck: BeaconBlock,
                         parent_slot: uint64): bool =
  # Update randao skips
  for slot in parentslot + 1 ..< blck.slot:
    let proposer_index = get_beacon_proposer_index(state, slot)
    state.validators[proposer_index.int].randao_skips.inc()

  var
    proposer_index = get_beacon_proposer_index(state, blck.slot)
    proposer = state.validators[proposer_index.int]

  # Check that proposer commit and reveal match
  if repeat_hash(blck.randao_reveal, proposer.randao_skips + 1) !=
      proposer.randao_commitment:
    return

  # Update state and proposer now that we're alright
  for i, b in state.randao_mix.data:
    state.randao_mix.data[i] = b xor blck.randao_reveal.data[i]

  proposer.randao_commitment = blck.randao_reveal
  proposer.randao_skips = 0

  true

func process_block*(state: BeaconState, blck: BeaconBlock): Option[BeaconState] =
  ## When a new block is received, all participants must verify that the block
  ## makes sense and update their state accordingly. This function will return
  ## the new state, unless something breaks along the way

  # TODO: simplistic way to be able to rollback state
  var state = state

  let
    parent_hash = blck.ancestor_hashes[0]
    slot = blck.slot
    parent_slot = slot - 1 # TODO Not!! can skip slots...
  # TODO actually get parent block, which means fixing up BeaconState refs above;
  # there's no distinction between active/crystallized state anymore, etc.

  state.recent_block_hashes =
    append_to_recent_block_hashes(state.recent_block_hashes, parent_slot, slot,
      parent_hash)

  let processed_attestations = checkAttestations(state, blck, parent_slot)
  if processed_attestations.isNone:
    return

  state.pending_attestations.add processed_attestations.get()

  if not verifyProposerSignature(state, blck):
    return

  if not processRandaoReveal(state, blck, parent_slot):
    return

  some(state) # Looks ok - move on with the updated state
