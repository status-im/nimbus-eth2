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
                         blck: BeaconBlock): bool =
  # Each block includes a number of attestations that the proposer chose. Each
  # attestation represents an update to a specific shard and is signed by a
  # committee of validators.
  # Here we make sanity checks for each attestation and it to the state - most
  # updates will happen at the epoch boundary where state updates happen in
  # bulk.
  if blck.body.attestations.len > MAX_ATTESTATIONS_PER_BLOCK:
    return

  if not allIt(blck.body.attestations, checkAttestation(state, it)):
    return

  # All checks passed - update state
  state.latest_attestations.add mapIt(blck.body.attestations,
    PendingAttestationRecord(
      data: it.data,
      participation_bitfield: it.participation_bitfield,
      custody_bitfield: it.custody_bitfield,
      slot_included: state.slot
    )
  )

  true

func verifyProposerSignature(state: BeaconState, blck: BeaconBlock): bool =
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#proposer-signature

  var blck_without_sig = blck
  blck_without_sig.signature = ValidatorSig()

  let
    proposal_hash = hash_tree_root(ProposalSignedData(
      slot: state.slot,
      shard: BEACON_CHAIN_SHARD,
      block_root: Eth2Digest(data: hash_tree_root(blck_without_sig))
    ))

  let validator_idx = get_beacon_proposer_index(state, state.slot)
  BLSVerify(
    state.validator_registry[validator_idx].pubkey,
    proposal_hash, blck.signature,
    get_domain(state.fork_data, state.slot, DOMAIN_PROPOSAL))

func processRandaoReveal(state: var BeaconState,
                         blck: BeaconBlock): bool =
  let
    proposer_index = get_beacon_proposer_index(state, state.slot)
    proposer = addr state.validator_registry[proposer_index]

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
      x.votes += 1
      return true

  state.candidate_pow_receipt_roots.add CandidatePoWReceiptRootRecord(
    candidate_pow_receipt_root: blck.candidate_pow_receipt_root,
    votes: 1
  )
  return true


func processBlock(state: var BeaconState, blck: BeaconBlock): bool =
  if not processAttestations(state, blck):
    false
  elif not verifyProposerSignature(state, blck):
    false
  elif not processRandaoReveal(state, blck):
    false
  elif not processPoWReceiptRoot(state, blck):
    false
  else:
    true

func processSlot(state: var BeaconState, latest_block: BeaconBlock): bool =
  ## Time on the beacon chain moves in slots. Every time we make it to a new
  ## slot, a proposer cleates a block to represent the state of the beacon
  ## chain at that time. In case the proposer is missing, it may happen that
  ## the no block is produced during the slot.
  ##
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#per-slot-processing
  # TODO state not rolled back in case of failure

  let
    latest_hash = Eth2Digest(data: hash_tree_root(latest_block))

  state.slot += 1
  state.latest_block_roots.add latest_hash

  if state.latest_block_roots.len < 2 or
      state.latest_block_roots[^2] != state.latest_block_roots[^1]:
    # TODO a bit late for the following checks?
    # https://github.com/ethereum/eth2.0-specs/issues/284
    if latest_block.slot != state.slot:
      false
    elif latest_block.ancestor_hashes !=
        get_updated_ancestor_hashes(latest_block, latest_hash):
      false
    else:
      processBlock(state, latest_block)
  else:
    state.validator_registry[get_beacon_proposer_index(state, state.slot)].randao_skips += 1
    # Skip all other per-slot processing. Move directly to epoch processing
    # prison. Do not do any slot updates when passing go.
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
    it.data.epoch_boundary_root == boundary_hash and
    it.data.justified_slot == state.justified_slot)

func sum_effective_balances(
    state: BeaconState, validator_indices: openArray[Uint24]): uint64 =
    # TODO spec - add as helper?
  sum(mapIt(
    validator_indices, get_effective_balance(state.validator_registry[it]))
  )

func lowerThan(candidate, current: Eth2Digest): bool =
  # return true iff candidate is "lower" than current, per spec rule:
  # "ties broken by favoring lower `shard_block_root` values"
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
      total_balance_in_eth = total_balance div GWEI_PER_ETH

      # The per-slot maximum interest rate is `2/reward_quotient`.)
      reward_quotient = BASE_REWARD_QUOTIENT * int_sqrt(total_balance_in_eth)

      # TODO not in spec, convenient
      epoch_boundary_root = get_block_root(state, s)

    proc base_reward(v: ValidatorRecord): uint64 =
      get_effective_balance(v) div reward_quotient.uint64

    # TODO doing this with iterators failed:
    #      https://github.com/nim-lang/Nim/issues/9827
    let
      this_epoch_attestations = filterIt(state.latest_attestations,
        s <= it.data.slot and it.data.slot < s + EPOCH_LENGTH)

      this_epoch_boundary_attestations =
        boundary_attestations(state, epoch_boundary_root,
          this_epoch_attestations)

      this_epoch_boundary_attesters =
        get_epoch_boundary_attesters(state, this_epoch_attestations)

      this_epoch_boundary_attesting_balance =
        sum_effective_balances(state, this_epoch_boundary_attesters)

    let
      previous_epoch_attestations = filterIt(state.latest_attestations,
        s <= it.data.slot + EPOCH_LENGTH and it.data.slot < s)

      previous_epoch_boundary_attestations =
        boundary_attestations(state, epoch_boundary_root,
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
        obj: ShardCommittee, shard_block_root: Eth2Digest): seq[Uint24] =
      flatten(
        mapIt(
          filterIt(concat(this_epoch_attestations, previous_epoch_attestations),
            it.data.shard == obj.shard and
              it.data.shard_block_root == shard_block_root),
          get_attestation_participants(statePtr[], it.data, it.participation_bitfield)))

    func winning_hash(obj: ShardCommittee): Eth2Digest =
      # * Let `winning_hash(obj)` be the winning `shard_block_root` value.
      # ... such that `sum([get_effective_balance(v) for v in attesting_validators(obj, shard_block_root)])`
      # is maximized (ties broken by favoring lower `shard_block_root` values).
      let candidates =
        mapIt(
          filterIt(concat(this_epoch_attestations, previous_epoch_attestations),
            it.data.shard == obj.shard),
          it.data.shard_block_root)

      var max_hash = candidates[0]
      var max_val =
        sum_effective_balances(statePtr[], attesting_validators(obj, max_hash))
      for candidate in candidates[1..^1]:
        let val = sum_effective_balances(statePtr[], attesting_validators(obj, candidate))
        if val > max_val or (val == max_val and candidate.lowerThan(max_hash)):
          max_hash = candidate
          max_val = val
      max_hash

    func attesting_validators(obj: ShardCommittee): seq[Uint24] =
      attesting_validators(obj, winning_hash(obj))

    func total_attesting_balance(obj: ShardCommittee): uint64 =
      sum_effective_balances(statePtr[], attesting_validators(obj))

    func total_balance_sac(obj: ShardCommittee): uint64 =
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

    block: # Receipt roots
      if state.slot mod POW_RECEIPT_ROOT_VOTING_PERIOD == 0:
        for x in state.candidate_pow_receipt_roots:
          if x.votes * 2 >= POW_RECEIPT_ROOT_VOTING_PERIOD:
            state.processed_pow_receipt_root = x.candidate_pow_receipt_root
            break
        state.candidate_pow_receipt_roots = @[]

    block: # Justification
      state.previous_justified_slot = state.justified_slot

      # TODO where's that bitfield type when you need it?
      # TODO why are all bits kept?
      state.justification_bitfield = state.justification_bitfield shl 1

      if 3'u64 * previous_epoch_boundary_attesting_balance >=
          2'u64 * total_balance:
        state.justification_bitfield = state.justification_bitfield or 2
        state.justified_slot = state.slot - 2 * EPOCH_LENGTH

      if 3'u64 * this_epoch_boundary_attesting_balance >=
          2'u64 * total_balance:
        state.justification_bitfield = state.justification_bitfield or 1
        state.justified_slot = state.slot - 1 * EPOCH_LENGTH

    block: # Finalization
      if
        (state.previous_justified_slot == state.slot - 2 * EPOCH_LENGTH and
          state.justification_bitfield mod 4 == 3) or
        (state.previous_justified_slot == state.slot - 3 * EPOCH_LENGTH and
          state.justification_bitfield mod 8 == 7) or
        (state.previous_justified_slot == state.slot - 4 * EPOCH_LENGTH and
          state.justification_bitfield mod 16 in [15'u64, 14]):
        state.finalized_slot = state.justified_slot

    block: # Crosslinks
      for sac in state.shard_committees_at_slots:
        for obj in sac:
          if 3'u64 * total_attesting_balance(obj) >=
              2'u64 * total_balance_sac(obj):
            state.latest_crosslinks[obj.shard] = CrosslinkRecord(
              slot: state.latest_state_recalculation_slot + EPOCH_LENGTH,
              shard_block_root: winning_hash(obj))

    block: # Justification and finalization rewards and penalties
      let
        slots_since_finality = blck.slot - state.finalized_slot

      if slots_since_finality <= 4'u64 * EPOCH_LENGTH:
        for v in previous_epoch_boundary_attesters:
          state.validator_registry[v].balance += adjust_for_inclusion_distance(
            base_reward(state.validator_registry[v]) *
            previous_epoch_boundary_attesting_balance div total_balance,
            inclusion_distance(v))

        for v in active_validator_indices:
          if v notin previous_epoch_boundary_attesters:
            state.validator_registry[v].balance -=
              base_reward(state.validator_registry[v])
      else:
        # Any validator in `prev_cycle_boundary_attesters` sees their balance
        # unchanged.
        # Others might get penalized:
        for vindex, v in state.validator_registry.mpairs():
          if (v.status == ACTIVE and
                vindex.Uint24 notin previous_epoch_boundary_attesters) or
              v.status == EXITED_WITH_PENALTY:
            v.balance -= base_reward(v) +
              get_effective_balance(v) * slots_since_finality div
                INACTIVITY_PENALTY_QUOTIENT

        for v in previous_epoch_boundary_attesters:
          let proposer_index =
            get_beacon_proposer_index(state, inclusion_slot(v))
          state.validator_registry[proposer_index].balance +=
            base_reward(state.validator_registry[v]) div
              INCLUDER_REWARD_QUOTIENT

    block: # Crosslink rewards and penalties
      for sac in state.shard_committees_at_slots[0 ..< EPOCH_LENGTH]:
        for obj in sac:
          for vindex in obj.committee:
            let v = state.validator_registry[vindex].addr

            if vindex in attesting_validators(obj):
              v.balance += adjust_for_inclusion_distance(
                base_reward(v[]) * total_attesting_balance(obj) div total_balance_sac(obj),
                inclusion_distance(vindex))
            else:
              v.balance -= base_reward(v[])

    block: # Validator registry

      if state.finalized_slot > state.validator_registry_latest_change_slot and
          allIt(state.shard_committees_at_slots,
            allIt(it,
              state.latest_crosslinks[it.shard].slot >
                state.validator_registry_latest_change_slot)):
        update_validator_registry(state)
        state.validator_registry_latest_change_slot = state.slot
        for i in 0..<EPOCH_LENGTH:
          state.shard_committees_at_slots[i] =
            state.shard_committees_at_slots[EPOCH_LENGTH + i]

        let next_start_shard =
          (state.shard_committees_at_slots[^1][^1].shard + 1) mod SHARD_COUNT
        for i, v in get_new_shuffling(
            state.next_seed, state.validator_registry, next_start_shard):
          state.shard_committees_at_slots[i + EPOCH_LENGTH] = v

        state.next_seed = state.randao_mix

      else:
        # If a validator registry change does NOT happen
        for i in 0..<EPOCH_LENGTH:
          state.shard_committees_at_slots[i] =
            state.shard_committees_at_slots[EPOCH_LENGTH + i]

        let slots_since_finality =
          state.slot - state.validator_registry_latest_change_slot
        let start_shard = state.shard_committees_at_slots[0][0].shard
        if slots_since_finality * EPOCH_LENGTH <=
            MIN_VALIDATOR_REGISTRY_CHANGE_INTERVAL or
            is_power_of_2(slots_since_finality):
          for i, v in get_new_shuffling(
              state.next_seed, state.validator_registry, start_shard):
            state.shard_committees_at_slots[i + EPOCH_LENGTH] = v
          state.next_seed = state.randao_mix
          # Note that `start_shard` is not changed from the last epoch.

    block: # Proposer reshuffling
      let active_validator_indices = get_active_validator_indices(state.validator_registry)
      let num_validators_to_reshuffle =
        len(active_validator_indices) div
          SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD.int
      for i in 0..<num_validators_to_reshuffle:
        # Multiplying i to 2 to ensure we have different input to all the required hashes in the shuffling
        # and none of the hashes used for entropy in this loop will be the same
        let validator_index = 0.Uint24 # active_validator_indices[hash(state.randao_mix + bytes8(i * 2)) mod len(active_validator_indices)]
        let new_shard = 0'u64 # hash(state.randao_mix + bytes8(i * 2 + 1)) mod SHARD_COUNT
        let shard_reassignment_record = ShardReassignmentRecord(
            validator_index: validator_index,
            shard: new_shard,
            slot: s + SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD
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

    block: # Final updates
      # TODO Remove all attestation records older than slot `s`.
      state.latest_block_roots = state.latest_block_roots[EPOCH_LENGTH..^1]

  true

func updateState*(state: BeaconState, latest_block: BeaconBlock): Option[BeaconState] =
  ## Adjust `state` according to the information in `blck`.
  ## Returns the new state, or `none` if the block is invalid.

  # TODO check to which extent this copy can be avoided (considering forks etc),
  #      for now, it serves as a reminder that we need to handle invalid blocks
  #      somewhere..
  # TODO many functions will mutate `state` partially without rolling back
  #      the changes in case of failure (look out for `var BeaconState` and
  #      bool return values...)
  var state = state

  # Slot processing is split up into two phases - lightweight updates done
  # for each slot, and bigger updates done for each epoch.

  # Lightweight updates that happen for every slot
  if not processSlot(state, latest_block): return

  # Heavy updates that happen for every epoch
  if not processEpoch(state, latest_block): return

  # All good, we can return the new state
  some(state)
