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
  math, options, sequtils,
  ./extras,
  ./spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  ./ssz,
  milagro_crypto # nimble install https://github.com/status-im/nim-milagro-crypto@#master

# TODO there's an ugly mix of functional and procedural styles here that
#      is due to how the spec is mixed as well - once we're past the prototype
#      stage, this will need clearing up and unification.

func checkAttestations(state: BeaconState,
                       blck: BeaconBlock,
                       parent_slot: uint64): Option[seq[PendingAttestationRecord]] =
  # TODO perf improvement potential..
  if blck.attestations.len > MAX_ATTESTATIONS_PER_BLOCK:
    return

  var res: seq[PendingAttestationRecord]
  for attestation in blck.attestations:
    if attestation.data.slot <= blck.slot - MIN_ATTESTATION_INCLUSION_DELAY:
      return
    # TODO unsigned undeflow in spec
    if attestation.data.slot >= max(parent_slot.int - EPOCH_LENGTH + 1, 0).uint64:
      return

    let expected_justified_slot =
      if attestation.data.slot >= state.latest_state_recalculation_slot:
        state.justified_slot
      else:
        state.previous_justified_slot
    if attestation.data.justified_slot != expected_justified_slot:
      return

    let expected_justified_block_hash =
      get_block_hash(state, blck, attestation.data.justified_slot)
    if attestation.data.justified_block_hash != expected_justified_block_hash:
      return

    if state.latest_crosslinks[attestation.data.shard].shard_block_hash notin [
        attestation.data.latest_crosslink_hash, attestation.data.shard_block_hash]:
      return

    let attestation_participants = get_attestation_participants(
      state, attestation.data, attestation.participation_bitfield)

    var
      agg_pubkey: ValidatorPubKey
      empty = true

    for attester_idx in attestation_participants:
      let validator = state.validator_registry[attester_idx]
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

    res.add PendingAttestationRecord(
      data: attestation.data,
      participation_bitfield: attestation.participation_bitfield,
      custody_bitfield: attestation.custody_bitfield,
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
    state.validator_registry[get_beacon_proposer_index(state, blck.slot).int].pubkey)

func processRandaoReveal(state: var BeaconState,
                         blck: BeaconBlock,
                         parent_slot: uint64): bool =
  # Update randao skips
  for slot in parentslot + 1 ..< blck.slot:
    let proposer_index = get_beacon_proposer_index(state, slot)
    state.validator_registry[proposer_index.int].randao_skips.inc()

  var
    proposer_index = get_beacon_proposer_index(state, blck.slot)
    proposer = state.validator_registry[proposer_index.int]

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

func processPoWReceiptRoot(state: var BeaconState, blck: BeaconBlock): bool =
  for x in state.candidate_pow_receipt_roots.mitems():
    if blck.candidate_pow_receipt_root == x.candidate_pow_receipt_root:
      x.votes.inc
      return true

  state.candidate_pow_receipt_roots.add CandidatePoWReceiptRootRecord(
    candidate_pow_receipt_root: blck.candidate_pow_receipt_root,
    votes: 1
  )
  return true

func processSpecials(state: var BeaconState, blck: BeaconBlock): bool =
  # TODO incoming spec changes here..
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

  state.latest_block_hashes =
    append_to_recent_block_hashes(state.latest_block_hashes, parent_slot, slot,
      parent_hash)

  let processed_attestations = checkAttestations(state, blck, parent_slot)
  if processed_attestations.isNone:
    return

  state.latest_attestations.add processed_attestations.get()

  if not verifyProposerSignature(state, blck):
    return

  if not processRandaoReveal(state, blck, parent_slot):
    return

  if not processPoWReceiptRoot(state, blck):
    return

  if not processSpecials(state, blck):
    return

  some(state) # Looks ok - move on with the updated state

func flatten[T](v: openArray[seq[T]]): seq[T] =
  for x in v: result.add x

func get_epoch_boundary_attesters(
    state: BeaconState,
    attestations: openArray[PendingAttestationRecord]): seq[int] =
  deduplicate(flatten(mapIt(attestations,
    get_attestation_participants(state, it.data, it.participation_bitfield))))

func adjust_for_inclusion_distance[T](magnitude: T, dist: T): T =
  magnitude div 2 + (magnitude div 2) * MIN_ATTESTATION_INCLUSION_DELAY div dist

func processEpoch*(state: BeaconState, blck: BeaconBlock): Option[BeaconState] =
  ## Epoch processing happens every time we've passed EPOCH_LENGTH blocks.
  ## Because some slots may be skipped, it may happen that we go through the
  ## loop more than once - each time the latest_state_recalculation_slot will be
  ## increased by EPOCH_LENGTH.

  # TODO: simplistic way to be able to rollback state
  var state = state

  # Precomputation

  while blck.slot >= EPOCH_LENGTH.uint64 + state.latest_state_recalculation_slot:
    let s = state.latest_state_recalculation_slot

    let
      active_validators =
        mapIt(get_active_validator_indices(state.validator_registry),
          state.validator_registry[it])

      total_balance = sum(mapIt(active_validators, get_effective_balance(it)))

      total_balance_in_eth = total_balance.int div GWEI_PER_ETH

      # The per-slot maximum interest rate is `2/reward_quotient`.)
      reward_quotient = BASE_REWARD_QUOTIENT * int_sqrt(total_balance_in_eth)

    proc base_reward(v: ValidatorRecord): uint64 =
      get_effective_balance(v) div reward_quotient.uint64

    # TODO doing this with iterators failed:
    #      https://github.com/nim-lang/Nim/issues/9827
    let
      this_epoch_attestations = filterIt(state.latest_attestations,
        s <= it.data.slot and it.data.slot < s + EPOCH_LENGTH)

      this_epoch_boundary_attestations = filterIt(this_epoch_attestations,
        it.data.epoch_boundary_hash == get_block_hash(state, blck, s) and
          it.data.justified_slot == state.justified_slot)

      this_epoch_boundary_attesters =
        get_epoch_boundary_attesters(state, this_epoch_attestations)

      this_epoch_boundary_attesting_balance = sum(
        mapIt(this_epoch_boundary_attesters,
          get_effective_balance(state.validator_registry[it]))
      )

    let
      previous_epoch_attestations = filterIt(state.latest_attestations,
        s <= it.data.slot + EPOCH_LENGTH and it.data.slot < s)
      previous_epoch_boundary_attestations = filterIt(previous_epoch_attestations,
        it.data.epoch_boundary_hash == get_block_hash(state, blck, s) and
          it.data.justified_slot == state.justified_slot)
      previous_epoch_boundary_attesters =
        get_epoch_boundary_attesters(state, previous_epoch_boundary_attestations)
      previous_epoch_boundary_attesting_balance = sum(
        mapIt(previous_epoch_boundary_attesters,
          get_effective_balance(state.validator_registry[it]))
      )

    # TODO gets pretty hairy here
    func attesting_validators(
        obj: ShardAndCommittee, shard_block_hash: Eth2Digest): seq[int] =
      flatten(
        mapIt(
          filterIt(concat(this_epoch_attestations, previous_epoch_attestations),
            it.data.shard == obj.shard and
              it.data.shard_block_hash == shard_block_hash),
          get_attestation_participants(state, it.data, it.participation_bitfield)))

    # TODO which shard_block_hash:es?
    # * Let `attesting_validators(obj)` be equal to `attesting_validators(obj, shard_block_hash)` for the value of `shard_block_hash` such that `sum([get_effective_balance(v) for v in attesting_validators(obj, shard_block_hash)])` is maximized (ties broken by favoring lower `shard_block_hash` values).
    # * Let `total_attesting_balance(obj)` be the sum of the balances-at-stake of `attesting_validators(obj)`.
    # * Let `winning_hash(obj)` be the winning `shard_block_hash` value.
    # * Let `total_balance(obj) = sum([get_effective_balance(v) for v in obj.committee])`.

    # Let `inclusion_slot(v)` equal `a.slot_included` for the attestation `a` where `v` is in `get_attestation_participants(state, a.data, a.participation_bitfield)`, and `inclusion_distance(v) = a.slot_included - a.data.slot` for the same attestation. We define a function `adjust_for_inclusion_distance(magnitude, distance)` which adjusts the reward of an attestation based on how long it took to get included (the longer, the lower the reward). Returns a value between 0 and `magnitude`.

    # Adjust justified slots and crosslink status

    var new_justified_slot: Option[uint64]
    # overflow intentional!
    state.justified_slot_bitfield = state.justified_slot_bitfield * 2

    if 3'u64 * previous_epoch_boundary_attesting_balance >= 2'u64 * total_balance:
      # TODO spec says "flip the second lowest bit to 1" and does "AND", wrong?
      state.justified_slot_bitfield = state.justified_slot_bitfield or 2
      new_justified_slot = some(s - EPOCH_LENGTH)

    if 3'u64 * this_epoch_boundary_attesting_balance >= 2'u64 * total_balance:
      # TODO spec says "flip the second lowest bit to 1" and does "AND", wrong?
      state.justified_slot_bitfield = state.justified_slot_bitfield or 1
      new_justified_slot = some(s)

    if state.justified_slot == s - EPOCH_LENGTH and
        state.justified_slot_bitfield mod 4 == 3:
      state.finalized_slot = state.justified_slot
    if state.justified_slot == s - EPOCH_LENGTH - EPOCH_LENGTH and
        state.justified_slot_bitfield mod 8 == 7:
      state.finalized_slot = state.justified_slot

    if state.justified_slot == s - EPOCH_LENGTH - 2 * EPOCH_LENGTH and
        state.justified_slot_bitfield mod 16 in [15'u64, 14]:
      state.finalized_slot = state.justified_slot

    state.previous_justified_slot = state.justified_slot

    if new_justified_slot.isSome():
      state.justified_slot = new_justified_slot.get()

    # for obj in state.shard_and_committee_for_slots:
    #   3 * total_attesting_balance(obj) >= 2 * total_balance(obj):
    #     state.crosslinks[shard] = CrosslinkRecord(
    #       slot: latest_state_recalculation_slot + EPOCH_LENGTH,
    #       hash: winning_hash(obj))

    # Balance recalculations related to FFG rewards
    let
      # The portion lost by offline [validators](#dfn-validator) after `D`
      # epochs is about `D*D/2/inactivity_penalty_quotient`.
      inactivity_penalty_quotient = SQRT_E_DROP_TIME^2
      time_since_finality = blck.slot - state.finalized_slot

    if time_since_finality <= 4'u64 * EPOCH_LENGTH:
      # for v in previous_epoch_boundary_attesters:
      #   state.validators[v].balance.inc(adjust_for_inclusion_distance(
      #     base_reward(state.validators[v]) *
      #       prev_cycle_boundary_attesting_balance div total_balance,
      #     inclusion_distance(v)))

      for v in get_active_validator_indices(state.validator_registry):
        if v notin previous_epoch_boundary_attesters:
          state.validator_registry[v].balance.dec(
            base_reward(state.validator_registry[v]).int)
    else:
      # Any validator in `prev_cycle_boundary_attesters` sees their balance
      # unchanged.
      # Others might get penalized:
      for vindex, v in state.validator_registry.mpairs():
        if (v.status == ACTIVE and vindex notin previous_epoch_boundary_attesters) or
            v.status == EXITED_WITH_PENALTY:
          v.balance.dec(
            (base_reward(v) + get_effective_balance(v) * time_since_finality div
              inactivity_penalty_quotient.uint64).int)

      # For each `v` in `prev_cycle_boundary_attesters`, we determine the proposer `proposer_index = get_beacon_proposer_index(state, inclusion_slot(v))` and set `state.validators[proposer_index].balance += base_reward(v) // INCLUDER_REWARD_SHARE_QUOTIENT`.

    # Balance recalculations related to crosslink rewards

    # Ethereum 1.0 chain related rules

    # Validator registry change

    # If a validator registry change does NOT happen

    # Proposer reshuffling

    # Finally...

  some(state)
