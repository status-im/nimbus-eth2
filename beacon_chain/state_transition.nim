# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition, as described in
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
#
# The purpose of this code right is primarily educational, to help piece
# together the mechanics of the beacon state and to discover potential problem
# areas.
#
# General notes about the code (TODO):
# * It's inefficient - we quadratically copy, allocate and iterate when there
#   are faster options
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * We mix procedural and functional styles for no good reason, except that the
#   spec does so also.
# * There are no tests, and likely lots of bugs.
# * For validators, sometimes indices are used and sometimes instances - this
#   causes unnecessary friction in some sections
# * For indices, we get a mix of uint64, Uint24 and int - this is currently
#   swept under the rug with casts
# * The spec uses uint64 for data types, but functions in the spec often assume
#   signed bigint semantics - under- and overflows ensue
# * Sane error handling is missing in most cases (yay, we'll get the chance to
#   debate exceptions again!)
#
# When updating the code, add TODO sections to mark where there are clear
# improvements to be made - other than that, keep things similar to spec for
# now.

import
  math, options, sequtils,
  ./extras, ./ssz,
  ./spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  milagro_crypto

func processAttestations(state: var BeaconState,
                         blck: BeaconBlock,
                         parent_slot: uint64): bool =
  # Each block includes a number of attestations that the proposer chose. Each
  # attestation represents an update to a specific shard and is signed by a
  # committee of validators.
  # Here we make sanity checks for each attestation and it to the state - most
  # updates will happen at the epoch boundary where state updates happen in
  # bulk.
  if blck.attestations.len > MAX_ATTESTATIONS_PER_BLOCK:
    return

  var res: seq[PendingAttestationRecord]
  for attestation in blck.attestations:
    if attestation.data.slot <= blck.slot - MIN_ATTESTATION_INCLUSION_DELAY:
      return

    # TODO spec - unsigned underflow
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

    # All checks passed - update state
    # TODO no rollback in case of errors
    state.latest_attestations.add PendingAttestationRecord(
      data: attestation.data,
      participation_bitfield: attestation.participation_bitfield,
      custody_bitfield: attestation.custody_bitfield,
      slot_included: blck.slot
    )

  true

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

  let
    proposer_index = get_beacon_proposer_index(state, blck.slot)
    proposer = state.validator_registry[proposer_index.int].addr

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

func processBlock(state: var BeaconState, blck: BeaconBlock): bool =
  ## When a new block is received, all participants must verify that the block
  ## makes sense and update their state accordingly. This function will return
  ## the new state, unless something breaks along the way
  # TODO state not rolled back in case of failure

  let
    parent_hash = blck.ancestor_hashes[0]
    slot = blck.slot
    parent_slot = slot - 1 # TODO Not!! can skip slots...
  # TODO actually get parent block, which means fixing up BeaconState refs above;

  state.latest_block_hashes =
    append_to_recent_block_hashes(state.latest_block_hashes, parent_slot, slot,
      parent_hash)

  if not processAttestations(state, blck, parent_slot):
    return

  if not verifyProposerSignature(state, blck):
    return

  if not processRandaoReveal(state, blck, parent_slot):
    return

  if not processPoWReceiptRoot(state, blck):
    return

  if not processSpecials(state, blck):
    return

  true

func flatten[T](v: openArray[seq[T]]): seq[T] =
  # TODO not in nim - doh.
  for x in v: result.add x

func get_epoch_boundary_attesters(
    state: BeaconState,
    attestations: openArray[PendingAttestationRecord]): seq[Uint24] =
  # TODO spec - add as helper?
  deduplicate(flatten(mapIt(attestations,
    get_attestation_participants(state, it.data, it.participation_bitfield))))

func adjust_for_inclusion_distance[T](magnitude: T, dist: T): T =
  magnitude div 2 + (magnitude div 2) * MIN_ATTESTATION_INCLUSION_DELAY div dist

func boundary_attestations(
    state: BeaconState, boundary_hash: Eth2Digest,
    attestations: openArray[PendingAttestationRecord]
    ): seq[PendingAttestationRecord] =
  # TODO spec - add as helper?
  filterIt(attestations,
    it.data.epoch_boundary_hash == boundary_hash and
    it.data.justified_slot == state.justified_slot)

func sum_effective_balances(
    state: BeaconState, validator_indices: openArray[Uint24]): uint64 =
    # TODO spec - add as helper?
  sum(mapIt(
    validator_indices, get_effective_balance(state.validator_registry[it]))
  )

func lowerThan(candidate, current: Eth2Digest): bool =
  # return true iff candidate is "lower" than current, per spec rule:
  # "ties broken by favoring lower `shard_block_hash` values"
  # TODO spec - clarify hash ordering..
  for i, v in current.data:
    if v > candidate.data[i]: return true
  return false

func processEpoch(state: var BeaconState, blck: BeaconBlock): bool =
  ## Epoch processing happens every time we've passed EPOCH_LENGTH blocks.
  ## Because some slots may be skipped, it may happen that we go through the
  ## loop more than once - each time the latest_state_recalculation_slot will be
  ## increased by EPOCH_LENGTH.

  while blck.slot >= EPOCH_LENGTH.uint64 + state.latest_state_recalculation_slot:
    # Convenience shortcut, from spec
    let s = state.latest_state_recalculation_slot

    # Precomputation
    let
      active_validator_indices =
        get_active_validator_indices(state.validator_registry)
      total_balance = sum_effective_balances(state, active_validator_indices)
      total_balance_in_eth = total_balance.int div GWEI_PER_ETH

      # The per-slot maximum interest rate is `2/reward_quotient`.)
      reward_quotient = BASE_REWARD_QUOTIENT * int_sqrt(total_balance_in_eth)

      # TODO not in spec, convenient
      epoch_boundary_hash = get_block_hash(state, blck, s)

    proc base_reward(v: ValidatorRecord): uint64 =
      get_effective_balance(v) div reward_quotient.uint64

    # TODO doing this with iterators failed:
    #      https://github.com/nim-lang/Nim/issues/9827
    let
      this_epoch_attestations = filterIt(state.latest_attestations,
        s <= it.data.slot and it.data.slot < s + EPOCH_LENGTH)

      this_epoch_boundary_attestations =
        boundary_attestations(state, epoch_boundary_hash,
          this_epoch_attestations)

      this_epoch_boundary_attesters =
        get_epoch_boundary_attesters(state, this_epoch_attestations)

      this_epoch_boundary_attesting_balance =
        sum_effective_balances(state, this_epoch_boundary_attesters)

    let
      previous_epoch_attestations = filterIt(state.latest_attestations,
        s <= it.data.slot + EPOCH_LENGTH and it.data.slot < s)

      previous_epoch_boundary_attestations =
        boundary_attestations(state, epoch_boundary_hash,
          previous_epoch_attestations)

      previous_epoch_boundary_attesters =
        get_epoch_boundary_attesters(state, previous_epoch_boundary_attestations)

      previous_epoch_boundary_attesting_balance =
        sum_effective_balances(state, this_epoch_boundary_attesters)

    # TODO this is really hairy - we cannot capture `state` directly, but we
    #      can capture a pointer to it - this is safe because we don't leak
    #      these closures outside this scope, but still..
    let statePtr = state.addr
    func attesting_validators(
        obj: ShardAndCommittee, shard_block_hash: Eth2Digest): seq[Uint24] =
      flatten(
        mapIt(
          filterIt(concat(this_epoch_attestations, previous_epoch_attestations),
            it.data.shard == obj.shard and
              it.data.shard_block_hash == shard_block_hash),
          get_attestation_participants(statePtr[], it.data, it.participation_bitfield)))

    func winning_hash(obj: ShardAndCommittee): Eth2Digest =
      # * Let `winning_hash(obj)` be the winning `shard_block_hash` value.
      # ... such that `sum([get_effective_balance(v) for v in attesting_validators(obj, shard_block_hash)])`
      # is maximized (ties broken by favoring lower `shard_block_hash` values).
      let candidates =
        mapIt(
          filterIt(concat(this_epoch_attestations, previous_epoch_attestations),
            it.data.shard == obj.shard),
          it.data.shard_block_hash)

      var max_hash = candidates[0]
      var max_val =
        sum_effective_balances(statePtr[], attesting_validators(obj, max_hash))
      for candidate in candidates[1..^1]:
        let val = sum_effective_balances(statePtr[], attesting_validators(obj, candidate))
        if val > max_val or (val == max_val and candidate.lowerThan(max_hash)):
          max_hash = candidate
          max_val = val
      max_hash

    func attesting_validators(obj: ShardAndCommittee): seq[Uint24] =
      attesting_validators(obj, winning_hash(obj))

    func total_attesting_balance(obj: ShardAndCommittee): uint64 =
      sum_effective_balances(statePtr[], attesting_validators(obj))

    func total_balance_sac(obj: ShardAndCommittee): uint64 =
      sum_effective_balances(statePtr[], obj.committee)

    func inclusion_slot(v: Uint24): uint64 =
      for a in statePtr[].latest_attestations:
        if v in get_attestation_participants(statePtr[], a.data, a.participation_bitfield):
          return a.slot_included
      assert false # shouldn't happen..

    func inclusion_distance(v: Uint24): uint64 =
      for a in statePtr[].latest_attestations:
        if v in get_attestation_participants(statePtr[], a.data, a.participation_bitfield):
          return a.slot_included - a.data.slot
      assert false # shouldn't happen..

    block: # Adjust justified slots and crosslink status
      var new_justified_slot: Option[uint64]
      # TODO where's that bitfield type when you need it?
      # TODO what happens with the bits that drop off..?
      state.justified_slot_bitfield = state.justified_slot_bitfield shl 1

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

      for sac in state.shard_and_committee_for_slots:
        # TODO or just state.shard_and_committee_for_slots[s]?
        for obj in sac:
          if 3'u64 * total_attesting_balance(obj) >= 2'u64 * total_balance_sac(obj):
            state.latest_crosslinks[obj.shard] = CrosslinkRecord(
              slot: state.latest_state_recalculation_slot + EPOCH_LENGTH,
              shard_block_hash: winning_hash(obj))

    block: # Balance recalculations related to FFG rewards
      let
        # The portion lost by offline [validators](#dfn-validator) after `D`
        # epochs is about `D*D/2/inactivity_penalty_quotient`.
        inactivity_penalty_quotient = SQRT_E_DROP_TIME^2
        time_since_finality = blck.slot - state.finalized_slot

      if time_since_finality <= 4'u64 * EPOCH_LENGTH:
        for v in previous_epoch_boundary_attesters:
          state.validator_registry[v].balance.inc(adjust_for_inclusion_distance(
            base_reward(state.validator_registry[v]) *
            previous_epoch_boundary_attesting_balance div total_balance,
            inclusion_distance(v)).int)

        for v in active_validator_indices:
          if v notin previous_epoch_boundary_attesters:
            state.validator_registry[v].balance.dec(
              base_reward(state.validator_registry[v]).int)
      else:
        # Any validator in `prev_cycle_boundary_attesters` sees their balance
        # unchanged.
        # Others might get penalized:
        for vindex, v in state.validator_registry.mpairs():
          if (v.status == ACTIVE and
                vindex.Uint24 notin previous_epoch_boundary_attesters) or
              v.status == EXITED_WITH_PENALTY:
            v.balance.dec(
              (base_reward(v) + get_effective_balance(v) * time_since_finality div
                inactivity_penalty_quotient.uint64).int)

        for v in previous_epoch_boundary_attesters:
          let proposer_index = get_beacon_proposer_index(state, inclusion_slot(v))
          state.validator_registry[proposer_index].balance.inc(
            (base_reward(state.validator_registry[v]) div INCLUDER_REWARD_QUOTIENT.uint64).int)

    block: # Balance recalculations related to crosslink rewards
      for sac in state.shard_and_committee_for_slots[0 ..< EPOCH_LENGTH]:
        for obj in sac:
          for vindex in obj.committee:
            let v = state.validator_registry[vindex].addr

            if vindex in attesting_validators(obj):
              v.balance.inc(adjust_for_inclusion_distance(
                base_reward(v[]) * total_attesting_balance(obj) div total_balance_sac(obj),
                inclusion_distance(vindex)).int)
            else:
              v.balance.dec(base_reward(v[]).int)

    block: # Ethereum 1.0 chain related rules
      if state.latest_state_recalculation_slot mod
          POW_RECEIPT_ROOT_VOTING_PERIOD.uint64 == 0:
        for x in state.candidate_pow_receipt_roots:
          if x.votes * 2 >= POW_RECEIPT_ROOT_VOTING_PERIOD.uint64:
            state.processed_pow_receipt_root = x.candidate_pow_receipt_root
            break
        state.candidate_pow_receipt_roots = @[]

    block: # Validator registry change
      if state.finalized_slot > state.validator_registry_latest_change_slot and
          allIt(state.shard_and_committee_for_slots,
            allIt(it,
              state.latest_crosslinks[it.shard].slot >
                state.validator_registry_latest_change_slot)):
        state.change_validators(s)
        state.validator_registry_latest_change_slot = s + EPOCH_LENGTH
        for i in 0..<EPOCH_LENGTH:
          state.shard_and_committee_for_slots[i] =
            state.shard_and_committee_for_slots[EPOCH_LENGTH + i]
        # https://github.com/ethereum/eth2.0-specs/issues/223
        let next_start_shard = (state.shard_and_committee_for_slots[^1][^1].shard + 1) mod SHARD_COUNT
        for i, v in get_new_shuffling(
            state.next_seed, state.validator_registry, next_start_shard):
          state.shard_and_committee_for_slots[i + EPOCH_LENGTH] = v
        state.next_seed = state.randao_mix
      else:
        # If a validator registry change does NOT happen
        for i in 0..<EPOCH_LENGTH:
          state.shard_and_committee_for_slots[i] =
            state.shard_and_committee_for_slots[EPOCH_LENGTH + i]
        let time_since_finality = blck.slot - state.validator_registry_latest_change_slot
        let start_shard = state.shard_and_committee_for_slots[0][0].shard
        if time_since_finality * EPOCH_LENGTH <= MIN_VALIDATOR_REGISTRY_CHANGE_INTERVAL.uint64 or
            is_power_of_2(time_since_finality):
          for i, v in get_new_shuffling(
              state.next_seed, state.validator_registry, start_shard):
            state.shard_and_committee_for_slots[i + EPOCH_LENGTH] = v
          state.next_seed = state.randao_mix
          # Note that `start_shard` is not changed from the last epoch.

    block: # Proposer reshuffling
      let active_validator_indices = get_active_validator_indices(state.validator_registry)
      let num_validators_to_reshuffle = len(active_validator_indices) div SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD
      for i in 0..<num_validators_to_reshuffle:
        # Multiplying i to 2 to ensure we have different input to all the required hashes in the shuffling
        # and none of the hashes used for entropy in this loop will be the same
        let validator_index = 0.Uint24 # active_validator_indices[hash(state.randao_mix + bytes8(i * 2)) mod len(active_validator_indices)]
        let new_shard = 0'u64 # hash(state.randao_mix + bytes8(i * 2 + 1)) mod SHARD_COUNT
        let shard_reassignment_record = ShardReassignmentRecord(
            validator_index: validator_index,
            shard: new_shard,
            slot: s + SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD.uint64
        )
        state.persistent_committee_reassignments.add(shard_reassignment_record)

      while len(state.persistent_committee_reassignments) > 0 and
          state.persistent_committee_reassignments[0].slot <= s:
        let reassignment = state.persistent_committee_reassignments[0]
        state.persistent_committee_reassignments.delete(0)
        for committee in state.persistent_committees.mitems():
          if reassignment.validator_index in committee:
            committee.delete(committee.find(reassignment.validator_index))
        state.persistent_committees[reassignment.shard.int].add(
          reassignment.validator_index)

    block: # Finally...
      # Remove all attestation records older than slot `s`.
      for i, v in state.validator_registry:
        if v.balance < MIN_BALANCE.uint64 and v.status == ACTIVE:
          exit_validator(i.Uint24, state, penalize=false, current_slot=blck.slot)
      state.latest_block_hashes = state.latest_block_hashes[EPOCH_LENGTH..^1]
      state.latest_state_recalculation_slot.inc(EPOCH_LENGTH)

  true

func updateState*(state: BeaconState, blck: BeaconBlock): Option[BeaconState] =
  ## Adjust `state` according to the information in `blck`.
  ## Returns the new state, or `none` if the block is invalid.

  # TODO check to which extent this copy can be avoided (considering forks etc),
  #      for now, it serves as a reminder that we need to handle invalid blocks
  #      somewhere..
  # TODO many functions will mutate `state` partially without rolling back
  #      the changes in case of failure (look out for `var BeaconState` and
  #      bool return values...)
  var state = state

  # Block processing is split up into two phases - lightweight updates done
  # for each block, and bigger updates done for each epoch.

  # Lightweight updates that happen for every block
  if not processBlock(state, blck): return

  # Heavy updates that happen for every epoch
  if not processEpoch(state, blck): return

  # All good, we can return the new state
  some(state)
