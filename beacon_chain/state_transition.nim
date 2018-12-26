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
# areas. The entry point is `updateState` which is at the bottom of the file!
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
# When updating the code, add TODO sections to mark where there are clear
# improvements to be made - other than that, keep things similar to spec for
# now.

import
  chronicles, math, options, sequtils,
  ./extras, ./ssz, ./work_pool,
  ./spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  milagro_crypto

type
  UpdateFlag* = enum
    skipValidation

  UpdateFlags* = set[UpdateFlag]

func flatten[T](v: openArray[seq[T]]): seq[T] =
  # TODO not in nim - doh.
  for x in v: result.add x

func verifyProposerSignature(state: BeaconState, blck: BeaconBlock): bool =
  ## When creating the block, the proposer will sign a version of the block that
  ## doesn't contain the data (chicken and egg), then add the signature to that
  ## block.

  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#proposer-signature

  var blck_without_sig = blck
  blck_without_sig.signature = ValidatorSig()

  let
    signed_data = ProposalSignedData(
      slot: state.slot,
      shard: BEACON_CHAIN_SHARD_NUMBER,
      block_root: hash_tree_root_final(blck_without_sig)
    )
    proposal_hash = hash_tree_root_final(signed_data)
    proposer_index = get_beacon_proposer_index(state, state.slot)

  bls_verify(
    state.validator_registry[proposer_index].pubkey,
    proposal_hash.data, blck.signature,
    get_domain(state.fork_data, state.slot, DOMAIN_PROPOSAL))

func processRandao(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  ## When a validator signs up, they will commit an hash to the block,
  ## the randao_commitment - this hash is the result of a secret value
  ## hashed n times.
  ## The first time the proposer proposes a block, they will hash their secret
  ## value n-1 times, and provide that as "reveal" - now everyone else can
  ## verify the reveal by hashing once.
  ## The next time the proposer proposes, they will reveal the secret value
  ## hashed n-2 times and so on, and everyone will verify that it matches n-1.
  ##
  ## Effectively, the block proposer can only reveal n - 1 times, so better pick
  ## a large N!
  ##
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#randao
  let
    proposer_index = get_beacon_proposer_index(state, state.slot)
    proposer = addr state.validator_registry[proposer_index]

  if skipValidation notin flags:
    # Check that proposer commit and reveal match
    if repeat_hash(blck.randao_reveal, proposer.randao_layers) !=
        proposer.randao_commitment:
      return false

  # Update state and proposer now that we're alright
  let mix = state.slot mod LATEST_RANDAO_MIXES_LENGTH
  for i, b in state.latest_randao_mixes[mix].data:
    state.latest_randao_mixes[mix].data[i] = b xor blck.randao_reveal.data[i]

  proposer.randao_commitment = blck.randao_reveal
  proposer.randao_layers = 0

  return true

func processPoWReceiptRoot(state: var BeaconState, blck: BeaconBlock) =
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#pow-receipt-root

  for x in state.candidate_pow_receipt_roots.mitems():
    if blck.candidate_pow_receipt_root == x.candidate_pow_receipt_root:
      x.votes += 1
      return

  state.candidate_pow_receipt_roots.add CandidatePoWReceiptRootRecord(
    candidate_pow_receipt_root: blck.candidate_pow_receipt_root,
    votes: 1
  )

proc processProposerSlashings(state: var BeaconState, blck: BeaconBlock): bool =
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#proposer-slashings-1

  if len(blck.body.proposer_slashings) > MAX_PROPOSER_SLASHINGS:
    warn("PropSlash: too many!",
      proposer_slashings = len(blck.body.proposer_slashings))
    return false

  for proposer_slashing in blck.body.proposer_slashings:
    let proposer = addr state.validator_registry[proposer_slashing.proposer_index]
    if not bls_verify(
        proposer.pubkey,
        hash_tree_root_final(proposer_slashing.proposal_data_1).data,
        proposer_slashing.proposal_signature_1,
        get_domain(
          state.fork_data, proposer_slashing.proposal_data_1.slot,
          DOMAIN_PROPOSAL)):
      warn("PropSlash: invalid signature 1")
      return false
    if not bls_verify(
        proposer.pubkey,
        hash_tree_root_final(proposer_slashing.proposal_data_2).data,
        proposer_slashing.proposal_signature_2,
        get_domain(
          state.fork_data, proposer_slashing.proposal_data_2.slot,
          DOMAIN_PROPOSAL)):
      warn("PropSlash: invalid signature 2")
      return false

    if not (proposer_slashing.proposal_data_1.slot ==
        proposer_slashing.proposal_data_2.slot):
      warn("PropSlash: slot mismatch")
      return false

    if not (proposer_slashing.proposal_data_1.shard ==
        proposer_slashing.proposal_data_2.shard):
      warn("PropSlash: shard mismatch")
      return false

    if not (proposer_slashing.proposal_data_1.block_root ==
        proposer_slashing.proposal_data_2.block_root):
      warn("PropSlash: block root mismatch")
      return false

    if not (proposer.status != EXITED_WITH_PENALTY):
      warn("PropSlash: wrong status")
      return false

    update_validator_status(
      state, proposer_slashing.proposer_index, EXITED_WITH_PENALTY)

  return true

func verify_slashable_vote_data(state: BeaconState, vote_data: SlashableVoteData): bool =
  if len(vote_data.aggregate_signature_poc_0_indices) +
      len(vote_data.aggregate_signature_poc_1_indices) > MAX_CASPER_VOTES:
    return false

  let pubs = [
    bls_aggregate_pubkeys(mapIt(vote_data.aggregate_signature_poc_0_indices,
      state.validator_registry[it].pubkey)),
    bls_aggregate_pubkeys(mapIt(vote_data.aggregate_signature_poc_1_indices,
      state.validator_registry[it].pubkey))]

  # TODO
  # return bls_verify_multiple(pubs, [hash_tree_root(votes)+bytes1(0), hash_tree_root(votes)+bytes1(1), signature=aggregate_signature)

  return true

proc indices(vote: SlashableVoteData): seq[Uint24] =
  vote.aggregate_signature_poc_0_indices &
    vote.aggregate_signature_poc_1_indices

proc processCasperSlashings(state: var BeaconState, blck: BeaconBlock): bool =
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#casper-slashings-1
  if len(blck.body.casper_slashings) > MAX_CASPER_SLASHINGS:
    warn("CaspSlash: too many!")
    return false

  for casper_slashing in blck.body.casper_slashings:
    let
      slashable_vote_data_1 = casper_slashing.slashable_vote_data_1
      slashable_vote_data_2 = casper_slashing.slashable_vote_data_2
      intersection = filterIt(
        indices(slashable_vote_data_1), it in indices(slashable_vote_data_2))

    if not (slashable_vote_data_1.data != slashable_vote_data_2.data):
      warn("CaspSlash: invalid data")
      return false

    if not (len(intersection) >= 1):
      warn("CaspSlash: no intersection")
      return false

    if not (
      is_double_vote(slashable_vote_data_1.data, slashable_vote_data_2.data) or
      is_surround_vote(slashable_vote_data_1.data, slashable_vote_data_2.data)):
      warn("CaspSlash: surround or double vote check failed")
      return false

    if not verify_slashable_vote_data(state, slashable_vote_data_1):
      warn("CaspSlash: invalid votes 1")
      return false

    if not verify_slashable_vote_data(state, slashable_vote_data_2):
      warn("CaspSlash: invalid votes 2")
      return false

    for i in intersection:
      if state.validator_registry[i].status != EXITED_WITH_PENALTY:
        update_validator_status(state, i, EXITED_WITH_PENALTY)

  return true

proc processAttestations(state: var BeaconState, blck: BeaconBlock): bool =
  ## Each block includes a number of attestations that the proposer chose. Each
  ## attestation represents an update to a specific shard and is signed by a
  ## committee of validators.
  ## Here we make sanity checks for each attestation and it to the state - most
  ## updates will happen at the epoch boundary where state updates happen in
  ## bulk.
  ##
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#attestations-1
  if blck.body.attestations.len > MAX_ATTESTATIONS:
    warn("Attestation: too many!", attestations = blck.body.attestations.len)
    return false

  if not allIt(blck.body.attestations, checkAttestation(state, it)):
    return false

  # All checks passed - update state
  state.latest_attestations.add mapIt(blck.body.attestations,
    PendingAttestationRecord(
      data: it.data,
      participation_bitfield: it.participation_bitfield,
      custody_bitfield: it.custody_bitfield,
      slot_included: state.slot,
    )
  )

  return true

proc processDeposits(state: var BeaconState, blck: BeaconBlock): bool =
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#deposits-1
  # TODO! Spec writing in progress
  true

proc processExits(state: var BeaconState, blck: BeaconBlock): bool =
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#exits-1
  if len(blck.body.exits) > MAX_EXITS:
    warn("Exit: too many!")
    return false

  for exit in blck.body.exits:
    let validator = state.validator_registry[exit.validator_index]

    if not bls_verify(
        validator.pubkey, ZERO_HASH.data, exit.signature,
        get_domain(state.fork_data, exit.slot, DOMAIN_EXIT)):
      warn("Exit: invalid signature")
      return false

    if not (validator.status == ACTIVE):
      warn("Exit: validator not active")
      return false

    if not (state.slot >= exit.slot):
      warn("Exit: bad slot")
      return false

    if not (state.slot >=
        validator.latest_status_change_slot +
          SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD):
      warn("Exit: not within committee change period")

    update_validator_status(state, exit.validator_index, ACTIVE_PENDING_EXIT)

  return true

proc process_ejections(state: var BeaconState) =
  ## Iterate through the validator registry and eject active validators with
  ## balance below ``EJECTION_BALANCE``
  ##
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#ejections

  for index, validator in state.validator_registry:
    if is_active_validator(validator) and validator.balance < EJECTION_BALANCE:
        update_validator_status(state, index.Uint24, EXITED_WITHOUT_PENALTY)

func processSlot(state: var BeaconState, previous_block_root: Eth2Digest) =
  ## Time on the beacon chain moves in slots. Every time we make it to a new
  ## slot, a proposer cleates a block to represent the state of the beacon
  ## chain at that time. In case the proposer is missing, it may happen that
  ## the no block is produced during the slot.
  ##
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#per-slot-processing

  state.slot += 1
  state.validator_registry[
    get_beacon_proposer_index(state, state.slot)].randao_layers += 1
  state.latest_randao_mixes[state.slot mod LATEST_RANDAO_MIXES_LENGTH] =
    state.latest_randao_mixes[(state.slot - 1) mod LATEST_RANDAO_MIXES_LENGTH]
  state.latest_block_roots[(state.slot - 1) mod LATEST_BLOCK_ROOTS_LENGTH] =
    previous_block_root

  if state.slot mod LATEST_BLOCK_ROOTS_LENGTH == 0:
    state.batched_block_roots.add(merkle_root(state.latest_block_roots))

proc processBlock(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly

  # TODO when there's a failure, we should reset the state!
  # TODO probably better to do all verification first, then apply state changes

  if not (blck.slot == state.slot):
    warn("Unexpected block slot number")
    return false

  # Spec does not have this check explicitly, but requires that this condition
  # holds - so we give verify it as well - this would happen naturally if
  # `blck.parent_root` was used in `processSlot` - but that doesn't cut it for
  # blockless slot processing.
  if not (blck.parent_root ==
      state.latest_block_roots[(state.slot - 1) mod LATEST_BLOCK_ROOTS_LENGTH]):
    warn("Unexpected parent root")
    return false

  if skipValidation notin flags:
    # TODO Technically, we could make processBlock take a generic type instead
    #      of BeaconBlock - we would then have an intermediate `ProposedBlock`
    #      type that omits some fields - this way, the compiler would guarantee
    #      that we don't try to access fields that don't have a value yet
    if not verifyProposerSignature(state, blck):
      warn("Proposer signature not valid")
      return false

  if not processRandao(state, blck, flags):
    warn("Randao reveal failed")
    return false

  processPoWReceiptRoot(state, blck)

  if not processProposerSlashings(state, blck):
    return false

  if not processCasperSlashings(state, blck):
    return false

  if not processAttestations(state, blck):
    return false

  if not processDeposits(state, blck):
    return false

  if not processExits(state, blck):
    return false

  process_ejections(state)

  return true

func get_attesters(
    state: BeaconState,
    attestations: openArray[PendingAttestationRecord]): seq[Uint24] =
  # Union of attesters that participated in some attestations
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

func processEpoch(state: var BeaconState) =
  ## https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#per-epoch-processing

  if state.slot mod EPOCH_LENGTH != 0:
    return

  # Precomputation
  let
    active_validator_indices =
      get_active_validator_indices(state.validator_registry)
    total_balance = sum_effective_balances(state, active_validator_indices)
    total_balance_in_eth = total_balance div GWEI_PER_ETH

    # The per-slot maximum interest rate is `2/reward_quotient`.)
    base_reward_quotient =
      BASE_REWARD_QUOTIENT * integer_squareroot(total_balance_in_eth)

  func base_reward(v: ValidatorRecord): uint64 =
    get_effective_balance(v) div base_reward_quotient.uint64 div 4

  func inactivity_penalty(
      v: ValidatorRecord, slots_since_finality: uint64): uint64 =
    base_reward(v) +
      get_effective_balance(v) *
        slots_since_finality div INACTIVITY_PENALTY_QUOTIENT

  # TODO doing this with iterators failed:
  #      https://github.com/nim-lang/Nim/issues/9827
  let
    this_epoch_attestations =
      filterIt(state.latest_attestations,
        state.slot <= it.data.slot + EPOCH_LENGTH and
        it.data.slot < state.slot)

    this_epoch_boundary_attestations =
      boundary_attestations(
        state, get_block_root(state, state.slot-EPOCH_LENGTH),
        this_epoch_attestations)

    this_epoch_boundary_attesters =
      get_attesters(state, this_epoch_attestations)

    this_epoch_boundary_attesting_balance =
      sum_effective_balances(state, this_epoch_boundary_attesters)

  let
    previous_epoch_attestations = filterIt(
      state.latest_attestations,
      state.slot <= it.data.slot + 2 * EPOCH_LENGTH and
      it.data.slot + EPOCH_LENGTH < state.slot)

  let
    previous_epoch_attesters =
      get_attesters(state, previous_epoch_attestations)

  let # Previous epoch justified
    previous_epoch_justified_attestations = filterIt(
      concat(this_epoch_attestations, previous_epoch_attestations),
        it.data.justified_slot == state.previous_justified_slot
      )

    previous_epoch_justified_attesters =
      get_attesters(state, previous_epoch_justified_attestations)

    previous_epoch_justified_attesting_balance =
      sum_effective_balances(state, previous_epoch_justified_attesters)

  let # Previous epoch boundary
    # TODO check this with spec...
    negative_uint_hack =
      if state.slot < 2 * EPOCH_LENGTH: 0'u64 else: state.slot - 2 * EPOCH_LENGTH
    previous_epoch_boundary_attestations =
      boundary_attestations(
        state, get_block_root(state, negative_uint_hack),
        previous_epoch_attestations)

    previous_epoch_boundary_attesters =
      get_attesters(state, previous_epoch_boundary_attestations)

    previous_epoch_boundary_attesting_balance =
      sum_effective_balances(state, previous_epoch_boundary_attesters)

  let # Previous epoch head
    previous_epoch_head_attestations =
      filterIt(
        previous_epoch_attestations,
        it.data.beacon_block_root == get_block_root(state, it.data.slot))

    previous_epoch_head_attesters =
      get_attesters(state, previous_epoch_head_attestations)

    previous_epoch_head_attesting_balance =
      sum_effective_balances(state, previous_epoch_head_attesters)

  # TODO this is really hairy - we cannot capture `state` directly, but we
  #      can capture a pointer to it - this is safe because we don't leak
  #      these closures outside this scope, but still..
  let statePtr = state.addr
  func attesting_validators(
      shard_committee: ShardCommittee, shard_block_root: Eth2Digest): seq[Uint24] =
    let shard_block_attestations =
      filterIt(concat(this_epoch_attestations, previous_epoch_attestations),
        it.data.shard == shard_committee.shard and
          it.data.shard_block_root == shard_block_root)
    get_attesters(statePtr[], shard_block_attestations)

  func winning_hash(obj: ShardCommittee): Eth2Digest =
    # * Let `winning_hash(obj)` be the winning `shard_block_root` value.
    # ... such that `sum([get_effective_balance(v) for v in attesting_validators(obj, shard_block_root)])`
    # is maximized (ties broken by favoring lower `shard_block_root` values).
    let candidates =
      mapIt(
        filterIt(concat(this_epoch_attestations, previous_epoch_attestations),
          it.data.shard == obj.shard),
        it.data.shard_block_root)

    # TODO not covered by spec!
    if candidates.len == 0:
      return

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
    doAssert false # shouldn't happen..

  func inclusion_distance(v: Uint24): uint64 =
    for a in statePtr[].latest_attestations:
      if v in get_attestation_participants(statePtr[], a.data, a.participation_bitfield):
        return a.slot_included - a.data.slot
    doAssert false # shouldn't happen..

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

    # TODO Spec - underflow
    if state.slot >= 2'u64 * EPOCH_LENGTH:
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
      (state.previous_justified_slot + 2 * EPOCH_LENGTH == state.slot and
        state.justification_bitfield mod 4 == 3) or
      (state.previous_justified_slot + 3 * EPOCH_LENGTH == state.slot and
        state.justification_bitfield mod 8 == 7) or
      (state.previous_justified_slot + 4 * EPOCH_LENGTH == state.slot and
        state.justification_bitfield mod 16 in [15'u64, 14]):
      state.finalized_slot = state.justified_slot

  block: # Crosslinks
    for sac in state.shard_committees_at_slots:
      for shard_committee in sac:
        if 3'u64 * total_attesting_balance(shard_committee) >=
            2'u64 * total_balance_sac(shard_committee):
          state.latest_crosslinks[shard_committee.shard] = CrosslinkRecord(
            slot: state.latest_state_recalculation_slot + EPOCH_LENGTH,
            shard_block_root: winning_hash(shard_committee))

  block: # Justification and finalization
    let
      slots_since_finality = state.slot - state.finalized_slot

    proc update_balance(attesters: openArray[Uint24], attesting_balance: uint64) =
      # TODO Spec - add helper?
      for v in attesters:
        statePtr.validator_registry[v].balance += adjust_for_inclusion_distance(
          base_reward(statePtr.validator_registry[v]) *
          attesting_balance div total_balance, inclusion_distance(v))

      for v in active_validator_indices:
        if v notin attesters:
          statePtr.validator_registry[v].balance -=
            base_reward(statePtr.validator_registry[v])

    if slots_since_finality <= 4'u64 * EPOCH_LENGTH:
      # Expected FFG source
      update_balance(
        previous_epoch_justified_attesters,
        previous_epoch_justified_attesting_balance)

      # Expected FFG target:
      update_balance(
        previous_epoch_boundary_attesters,
        previous_epoch_boundary_attesting_balance)

      # Expected beacon chain head:
      update_balance(
        previous_epoch_head_attesters,
        previous_epoch_head_attesting_balance)

    else:
      for v in active_validator_indices:
        let validator = addr state.validator_registry[v]
        if v notin previous_epoch_justified_attesters:
          validator[].balance -=
            inactivity_penalty(validator[], slots_since_finality)
        if v notin previous_epoch_boundary_attesters:
          validator[].balance -=
            inactivity_penalty(validator[], slots_since_finality)
        if v notin previous_epoch_head_attesters:
          validator[].balance -=
            inactivity_penalty(validator[], slots_since_finality)
        if validator[].status == EXITED_WITH_PENALTY:
          validator[].balance -=
            3'u64 * inactivity_penalty(validator[], slots_since_finality)

  block: # Attestation inclusion
    for v in previous_epoch_attesters:
      let proposer_index = get_beacon_proposer_index(state, inclusion_slot(v))
      state.validator_registry[proposer_index].balance +=
        base_reward(state.validator_registry[v]) div INCLUDER_REWARD_QUOTIENT

  block: # Crosslinks
    for sac in state.shard_committees_at_slots[0 ..< EPOCH_LENGTH]:
      for obj in sac:
        for vindex in obj.committee:
          let v = state.validator_registry[vindex].addr

          if vindex in attesting_validators(obj):
            v.balance += adjust_for_inclusion_distance(
              base_reward(v[]) * total_attesting_balance(obj) div
                total_balance_sac(obj),
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
          state.latest_randao_mixes[
            (state.slot - EPOCH_LENGTH) mod LATEST_RANDAO_MIXES_LENGTH],
          state.validator_registry, next_start_shard):
        state.shard_committees_at_slots[i + EPOCH_LENGTH] = v

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
            state.latest_randao_mixes[
              (state.slot - EPOCH_LENGTH) mod LATEST_RANDAO_MIXES_LENGTH],
            state.validator_registry, start_shard):
          state.shard_committees_at_slots[i + EPOCH_LENGTH] = v
        # Note that `start_shard` is not changed from the last epoch.

  block: # Proposer reshuffling
    let num_validators_to_reshuffle =
      len(active_validator_indices) div
        SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD.int
    for i in 0..<num_validators_to_reshuffle:
      # Multiplying i to 2 to ensure we have different input to all the required hashes in the shuffling
      # and none of the hashes used for entropy in this loop will be the same
      # TODO Modulo of hash value.. hm...
      let
        validator_index = 0.Uint24 # TODO active_validator_indices[hash(state.latest_randao_mixes[state.slot % LATEST_RANDAO_MIXES_LENGTH] + bytes8(i * 2)) % len(active_validator_indices)]
        new_shard = 0'u64 # TODO hash(state.randao_mix + bytes8(i * 2 + 1)) mod SHARD_COUNT
        shard_reassignment_record = ShardReassignmentRecord(
          validator_index: validator_index,
          shard: new_shard,
          slot: state.slot + SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD
        )
      state.persistent_committee_reassignments.add(shard_reassignment_record)

    while len(state.persistent_committee_reassignments) > 0 and
        state.persistent_committee_reassignments[0].slot <= state.slot:
      let reassignment = state.persistent_committee_reassignments[0]
      state.persistent_committee_reassignments.delete(0)
      for committee in state.persistent_committees.mitems():
        if reassignment.validator_index in committee:
          committee.delete(committee.find(reassignment.validator_index))
      state.persistent_committees[reassignment.shard.int].add(
        reassignment.validator_index)

  block: # Final updates
    state.latest_attestations.keepItIf(
      not (it.data.slot + EPOCH_LENGTH < state.slot)
    )

proc verifyStateRoot(state: BeaconState, blck: BeaconBlock): bool =
  let state_root = hash_tree_root_final(state)
  if state_root != blck.state_root:
    warn("Block: root verification failed",
      block_state_root = blck.state_root, state_root)
    false
  else:
    true

proc updateState*(state: BeaconState, previous_block_root: Eth2Digest,
    new_block: Option[BeaconBlock], flags: UpdateFlags):
      tuple[state: BeaconState, block_ok: bool] =
  ## Time in the beacon chain moves by slots. Every time (haha.) that happens,
  ## we will update the beacon state. Normally, the state updates will be driven
  ## by the contents of a new block, but it may happen that the block goes
  ## missing - the state updates happen regardless.
  ## Each call to this function will advance the state by one slot - new_block,
  ## if present, must match that slot.
  ##
  ## The flags are used to specify that certain validations should be skipped
  ## for the new block. This is done during block proposal, to create a state
  ## whose hash can be included in the new block.
  #
  # TODO this function can be written with a loop inside to handle all empty
  #      slots up to the slot of the new_block - but then again, why not eagerly
  #      update the state as time passes? Something to ponder...
  #      One reason to keep it this way is that you need to look ahead if you're
  #      the block proposer, though in reality we only need a partial update for
  #      that
  # TODO check to which extent this copy can be avoided (considering forks etc),
  #      for now, it serves as a reminder that we need to handle invalid blocks
  #      somewhere..
  # TODO many functions will mutate `state` partially without rolling back
  #      the changes in case of failure (look out for `var BeaconState` and
  #      bool return values...)
  # TODO There's a discussion about what this function should do, and when:
  #      https://github.com/ethereum/eth2.0-specs/issues/284
  var new_state = state

  # Per-slot updates - these happen regardless if there is a block or not
  processSlot(new_state, previous_block_root)

  if new_block.isSome():
    # Block updates - these happen when there's a new block being suggested
    # by the block proposer. Every actor in the network will update its state
    # according to the contents of this block - but first they will validate
    # that the block is sane.
    # TODO what should happen if block processing fails?
    #      https://github.com/ethereum/eth2.0-specs/issues/293
    if processBlock(new_state, new_block.get(), flags):
      # Block ok so far, proceed with state update
      processEpoch(new_state)

      # This is a bit awkward - at the end of processing we verify that the
      # state we arrive at is what the block producer thought it would be -
      # meaning that potentially, it could fail verification
      if skipValidation in flags or verifyStateRoot(new_state, new_block.get()):
        # State root is what it should be - we're done!
        return (new_state, true)

    # Block processing failed, have to start over
    new_state = state
    processSlot(new_state, previous_block_root)
    processEpoch(new_state)
    (new_state, false)
  else:
    # Skip all per-block processing. Move directly to epoch processing
    # prison. Do not do any block updates when passing go.

    # Heavy updates that happen for every epoch - these never fail (or so we hope)
    processEpoch(new_state)
    (new_state, true)
