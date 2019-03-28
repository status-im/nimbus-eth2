# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
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
# * For indices, we get a mix of uint64, ValidatorIndex and int - this is currently
#   swept under the rug with casts
# * The spec uses uint64 for data types, but functions in the spec often assume
#   signed bigint semantics - under- and overflows ensue
# * Sane error handling is missing in most cases (yay, we'll get the chance to
#   debate exceptions again!)
# When updating the code, add TODO sections to mark where there are clear
# improvements to be made - other than that, keep things similar to spec for
# now.

import
  algorithm, collections/sets, chronicles, math, options, sequtils, tables,
  ./extras, ./ssz,
  ./spec/[beaconstate, bitfield, crypto, datatypes, digest, helpers, validator]

func flatten[T](v: openArray[seq[T]]): seq[T] =
  # TODO not in nim - doh.
  for x in v: result.add x

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#block-header
proc processBlockHeader(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  # Verify that the slots match
  if not (blck.slot == state.slot):
    notice "Block header: slot mismatch",
      block_slot = humaneSlotNum(blck.slot),
      state_slot = humaneSlotNum(state.slot)
    return false

  # state_root not set yet, when skipping validation
  if skipValidation notin flags and not (blck.previous_block_root ==
      signed_root(state.latest_block_header)):
    notice "Block header: previous block root mismatch",
      latest_block_header = state.latest_block_header,
      blck = shortLog(blck),
      latest_block_header_root = shortLog(signed_root(state.latest_block_header))
    return false

  state.latest_block_header = get_temporary_block_header(blck)

  let proposer =
    state.validator_registry[get_beacon_proposer_index(state, state.slot)]
  if skipValidation notin flags and not bls_verify(
      proposer.pubkey,
      signed_root(blck).data,
      blck.signature,
      get_domain(state.fork, get_current_epoch(state), DOMAIN_BEACON_BLOCK)):
    notice "Block header: invalid block header",
      proposer_pubkey = proposer.pubkey,
      block_root = shortLog(signed_root(blck)),
      block_signature = blck.signature
    return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#randao
proc processRandao(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  let
    proposer_index = get_beacon_proposer_index(state, state.slot)
    proposer = addr state.validator_registry[proposer_index]

  if skipValidation notin flags:
    if not bls_verify(
      proposer.pubkey,
      hash_tree_root(get_current_epoch(state).uint64).data,
      blck.body.randao_reveal,
      get_domain(state.fork, get_current_epoch(state), DOMAIN_RANDAO)):

      notice "Randao mismatch", proposer_pubkey = proposer.pubkey,
                                message = get_current_epoch(state),
                                signature = blck.body.randao_reveal,
                                slot = state.slot,
                                blck_slot = blck.slot
      return false

  # Mix it in
  let
    mix = get_current_epoch(state) mod LATEST_RANDAO_MIXES_LENGTH
    # TODO hash_tree_root has some overloading for this
    rr = eth2hash(blck.body.randao_reveal.getBytes()).data

  for i, b in state.latest_randao_mixes[mix].data:
    state.latest_randao_mixes[mix].data[i] = b xor rr[i]

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#eth1-data-1
func processEth1Data(state: var BeaconState, blck: BeaconBlock) =
  # TODO verify that there's at most one match
  for x in state.eth1_data_votes.mitems():
    if blck.body.eth1_data == x.eth1_data:
      x.vote_count += 1
      return

  state.eth1_data_votes.add Eth1DataVote(
    eth1_data: blck.body.eth1_data,
    vote_count: 1
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#proposer-slashings
proc processProposerSlashings(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  if len(blck.body.proposer_slashings) > MAX_PROPOSER_SLASHINGS:
    notice "PropSlash: too many!",
      proposer_slashings = len(blck.body.proposer_slashings)
    return false

  for proposer_slashing in blck.body.proposer_slashings:
    let proposer = state.validator_registry[proposer_slashing.proposer_index.int]

    if not (slot_to_epoch(proposer_slashing.header_1.slot) ==
        slot_to_epoch(proposer_slashing.header_2.slot)):
      notice "PropSlash: epoch mismatch"
      return false

    if not (proposer_slashing.header_1 != proposer_slashing.header_2):
      notice "PropSlash: headers not different"
      return false

    if not (proposer.slashed == false):
      notice "PropSlash: slashed proposer"
      return false

    if skipValidation notin flags:
      for i, header in @[proposer_slashing.header_1, proposer_slashing.header_2]:
        if not bls_verify(
            proposer.pubkey,
            signed_root(header).data,
            header.signature,
            get_domain(
              state.fork, slot_to_epoch(header.slot), DOMAIN_BEACON_BLOCK)):
          notice "PropSlash: invalid signature",
            signature_index = i
          return false

    slashValidator(state, proposer_slashing.proposer_index.ValidatorIndex)

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#verify_slashable_attestation
func verify_slashable_attestation(state: BeaconState, slashable_attestation: SlashableAttestation): bool =
  # Verify validity of ``slashable_attestation`` fields.

  if anyIt(slashable_attestation.custody_bitfield.bits, it != 0):   # [TO BE REMOVED IN PHASE 1]
    return false

  if len(slashable_attestation.validator_indices) == 0:
     return false

  for i in 0 ..< (len(slashable_attestation.validator_indices) - 1):
    if slashable_attestation.validator_indices[i] >= slashable_attestation.validator_indices[i + 1]:
      return false

  if not verify_bitfield(slashable_attestation.custody_bitfield,
      len(slashable_attestation.validator_indices)):
    return false

  if len(slashable_attestation.validator_indices) > MAX_INDICES_PER_SLASHABLE_VOTE:
    return false

  var
    custody_bit_0_indices: seq[uint64] = @[]
    custody_bit_1_indices: seq[uint64] = @[]

  for i, validator_index in slashable_attestation.validator_indices:
    if not get_bitfield_bit(slashable_attestation.custody_bitfield, i):
      custody_bit_0_indices.add(validator_index)
    else:
      custody_bit_1_indices.add(validator_index)

  bls_verify_multiple(
    @[
      bls_aggregate_pubkeys(mapIt(custody_bit_0_indices, state.validator_registry[it.int].pubkey)),
      bls_aggregate_pubkeys(mapIt(custody_bit_1_indices, state.validator_registry[it.int].pubkey)),
    ],
    @[
      hash_tree_root(AttestationDataAndCustodyBit(
        data: slashable_attestation.data, custody_bit: false)),
      hash_tree_root(AttestationDataAndCustodyBit(
        data: slashable_attestation.data, custody_bit: true)),
    ],
    slashable_attestation.aggregate_signature,
    get_domain(
      state.fork,
      slot_to_epoch(slashable_attestation.data.slot),
      DOMAIN_ATTESTATION,
    ),
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#attester-slashings
proc processAttesterSlashings(state: var BeaconState, blck: BeaconBlock): bool =
  ## Process ``AttesterSlashing`` transaction.
  ## Note that this function mutates ``state``.
  if len(blck.body.attester_slashings) > MAX_ATTESTER_SLASHINGS:
    notice "CaspSlash: too many!"
    return false

  for attester_slashing in blck.body.attester_slashings:
    let
      slashable_attestation_1 = attester_slashing.slashable_attestation_1
      slashable_attestation_2 = attester_slashing.slashable_attestation_2

    # Check that the attestations are conflicting
    if not (slashable_attestation_1.data != slashable_attestation_2.data):
      notice "CaspSlash: invalid data"
      return false

    if not (
      is_double_vote(slashable_attestation_1.data, slashable_attestation_2.data) or
      is_surround_vote(slashable_attestation_1.data, slashable_attestation_2.data)):
      notice "CaspSlash: surround or double vote check failed"
      return false

    if not verify_slashable_attestation(state, slashable_attestation_1):
      notice "CaspSlash: invalid votes 1"
      return false

    if not verify_slashable_attestation(state, slashable_attestation_2):
      notice "CaspSlash: invalid votes 2"
      return false

    let
      indices2 = toSet(slashable_attestation_2.validator_indices)
      slashable_indices =
        slashable_attestation_1.validator_indices.filterIt(
          it in indices2 and not state.validator_registry[it.int].slashed)

    if not (len(slashable_indices) >= 1):
      notice "CaspSlash: no intersection"
      return false

    for index in slashable_indices:
      slash_validator(state, index.ValidatorIndex)

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#attestations
proc processAttestations(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  ## Each block includes a number of attestations that the proposer chose. Each
  ## attestation represents an update to a specific shard and is signed by a
  ## committee of validators.
  ## Here we make sanity checks for each attestation and it to the state - most
  ## updates will happen at the epoch boundary where state updates happen in
  ## bulk.
  if blck.body.attestations.len > MAX_ATTESTATIONS:
    notice "Attestation: too many!", attestations = blck.body.attestations.len
    return false

  if not blck.body.attestations.allIt(checkAttestation(state, it, flags)):
    return false

  # All checks passed - update state
  # Apply the attestations
  for attestation in blck.body.attestations:
    let pending_attestation = PendingAttestation(
      data: attestation.data,
      aggregation_bitfield: attestation.aggregation_bitfield,
      custody_bitfield: attestation.custody_bitfield,
      inclusion_slot: state.slot
    )

    if slot_to_epoch(attestation.data.slot) == get_current_epoch(state):
      state.current_epoch_attestations.add(pending_attestation)
    else:
      state.previous_epoch_attestations.add(pending_attestation)

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#deposits
proc processDeposits(state: var BeaconState, blck: BeaconBlock): bool =
  if not (len(blck.body.deposits) <= MAX_DEPOSITS):
    notice "processDeposits: too many deposits"
    return false

  for deposit in blck.body.deposits:
    if not process_deposit(state, deposit):
      notice "processDeposits: deposit invalid"
      return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#voluntary-exits
proc processExits(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  ## Process ``VoluntaryExit`` transaction.
  ## Note that this function mutates ``state``.
  if len(blck.body.voluntary_exits) > MAX_VOLUNTARY_EXITS:
    notice "Exit: too many!"
    return false

  for exit in blck.body.voluntary_exits:
    let validator = state.validator_registry[exit.validator_index.int]

    # Verify the validator has not yet exited
    if not (validator.exit_epoch == FAR_FUTURE_EPOCH):
      notice "Exit: validator has exited"
      return false

    # Verify the validator has not initiated an exit
    if not (not validator.initiated_exit):
      notice "Exit: validator has initiated an exit"
      return false

    ## Exits must specify an epoch when they become valid; they are not valid
    ## before then
    if not (get_current_epoch(state) >= exit.epoch):
      notice "Exit: exit epoch not passed"
      return false

    # Must have been in the validator set long enough
    if not (get_current_epoch(state) - validator.activation_epoch >=
        PERSISTENT_COMMITTEE_PERIOD):
      notice "Exit: not in validator set long enough"
      return false

    # Verify signature
    if skipValidation notin flags:
      if not bls_verify(
          validator.pubkey, signed_root(exit).data, exit.signature,
          get_domain(state.fork, exit.epoch, DOMAIN_VOLUNTARY_EXIT)):
        notice "Exit: invalid signature"
        return false

    # Run the exit
    initiate_validator_exit(state, exit.validator_index.ValidatorIndex)

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#validator-registry-and-shuffling-seed-data
func update_registry_and_shuffling_data(state: var BeaconState) =
  # First set previous shuffling data to current shuffling data
  state.previous_shuffling_epoch = state.current_shuffling_epoch
  state.previous_shuffling_start_shard = state.current_shuffling_start_shard
  state.previous_shuffling_seed = state.current_shuffling_seed

  let
    current_epoch = get_current_epoch(state)
    next_epoch = current_epoch + 1

  # Check if we should update, and if so, update
  if should_update_validator_registry(state):
    update_validator_registry(state)
    # If we update the registry, update the shuffling data and shards as well
    state.current_shuffling_epoch = next_epoch
    state.current_shuffling_start_shard = (
      state.current_shuffling_start_shard +
      get_current_epoch_committee_count(state) mod SHARD_COUNT
    ) mod SHARD_COUNT
    state.current_shuffling_seed =
      generate_seed(state, state.current_shuffling_epoch)
  else:
    ## If processing at least one crosslink keeps failing, then reshuffle every
    ## power of two, but don't update the current_shuffling_start_shard
    let epochs_since_last_registry_update =
      current_epoch - state.validator_registry_update_epoch
    if epochs_since_last_registry_update > 1'u64 and
        is_power_of_2(epochs_since_last_registry_update):
      state.current_shuffling_epoch = next_epoch
      state.current_shuffling_seed =
        generate_seed(state, state.current_shuffling_epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#transfers
proc processTransfers(state: var BeaconState, blck: BeaconBlock,
                      flags: UpdateFlags): bool =
  ## Note: Transfers are a temporary functionality for phases 0 and 1, to be
  ## removed in phase 2.
  if not (len(blck.body.transfers) <= MAX_TRANSFERS):
    notice "Transfer: too many transfers"
    return false

  for transfer in blck.body.transfers:
    let sender_balance = state.validator_balances[transfer.sender.int]

    ## Verify the amount and fee aren't individually too big (for anti-overflow
    ## purposes)
    if not (sender_balance >= max(transfer.amount, transfer.fee)):
      notice "Transfer: sender balance too low for transfer amount or fee"
      return false

    ## Verify that we have enough ETH to send, and that after the transfer the
    ## balance will be either exactly zero or at least MIN_DEPOSIT_AMOUNT
    if not (
        sender_balance == transfer.amount + transfer.fee or
        sender_balance >= transfer.amount + transfer.fee + MIN_DEPOSIT_AMOUNT):
      notice "Transfer: sender balance too low for amount + fee"
      return false

    # A transfer is valid in only one slot
    if not (state.slot == transfer.slot):
      notice "Transfer: slot mismatch"
      return false

    # Only withdrawn or not-yet-deposited accounts can transfer
    if not (get_current_epoch(state) >=
        state.validator_registry[
          transfer.sender.int].withdrawable_epoch or
        state.validator_registry[transfer.sender.int].activation_epoch ==
          FAR_FUTURE_EPOCH):
      notice "Transfer: only withdrawn or not-deposited accounts can transfer"
      return false

    # Verify that the pubkey is valid
    let wc = state.validator_registry[transfer.sender.int].
      withdrawal_credentials
    if not (wc.data[0] == BLS_WITHDRAWAL_PREFIX_BYTE and
            wc.data[1..^1] == eth2hash(transfer.pubkey.getBytes).data[1..^1]):
      notice "Transfer: incorrect withdrawal credentials"
      return false

    # Verify that the signature is valid
    if skipValidation notin flags:
      if not bls_verify(
          transfer.pubkey, signed_root(transfer).data, transfer.signature,
          get_domain(
            state.fork, slot_to_epoch(transfer.slot), DOMAIN_TRANSFER)):
        notice "Transfer: incorrect signature"
        return false

    # TODO https://github.com/ethereum/eth2.0-specs/issues/727
    reduce_balance(
      state.validator_balances[transfer.sender.int],
      transfer.amount + transfer.fee)
    state.validator_balances[transfer.recipient.int] += transfer.amount
    state.validator_balances[
      get_beacon_proposer_index(state, state.slot)] += transfer.fee

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#per-slot-processing
func advance_slot(state: var BeaconState) =
  ## Time on the beacon chain moves in slots. Every time we make it to a new
  ## slot, a proposer creates a block to represent the state of the beacon
  ## chain at that time. In case the proposer is missing, it may happen that
  ## the no block is produced during the slot.

  state.slot += 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#state-caching
func cacheState(state: var BeaconState) =
  let previous_slot_state_root = hash_tree_root(state)

  # store the previous slot's post state transition root
  state.latest_state_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    previous_slot_state_root

  # cache state root in stored latest_block_header if empty
  if state.latest_block_header.state_root == ZERO_HASH:
    state.latest_block_header.state_root = previous_slot_state_root

  # store latest known block for previous slot
  state.latest_block_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    signed_root(state.latest_block_header)

proc processBlock(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly

  # TODO when there's a failure, we should reset the state!
  # TODO probably better to do all verification first, then apply state changes

  if not processBlockHeader(state, blck, flags):
    notice "Block header not valid", slot = humaneSlotNum(state.slot)
    return false

  if not processRandao(state, blck, flags):
    return false

  processEth1Data(state, blck)

  if not processProposerSlashings(state, blck, flags):
    return false

  if not processAttesterSlashings(state, blck):
    return false

  if not processAttestations(state, blck, flags):
    return false

  if not processDeposits(state, blck):
    return false

  if not processExits(state, blck, flags):
    return false

  if not processTransfers(state, blck, flags):
    return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#helper-functions-1
func get_current_total_balance(state: BeaconState): Gwei =
  return get_total_balance(
    state,
    get_active_validator_indices(state.validator_registry,
    get_current_epoch(state)))

func get_previous_total_balance(state: BeaconState): Gwei =
  get_total_balance(
    state,
    get_active_validator_indices(state.validator_registry,
    get_previous_epoch(state)))

func get_attesting_indices(
    state: BeaconState,
    attestations: openArray[PendingAttestation]): seq[ValidatorIndex] =
  # Union of attesters that participated in some attestations
  attestations.
    mapIt(
      get_attestation_participants(state, it.data, it.aggregation_bitfield)).
    flatten().
    deduplicate().
    sorted(system.cmp)

func get_attesting_indices_cached(
    state: BeaconState,
    attestations: openArray[PendingAttestation],
    crosslink_committee_cache: var auto): seq[ValidatorIndex] =
  # Union of attesters that participated in some attestations
  attestations.
    mapIt(
      get_attestation_participants_cached(state, it.data, it.aggregation_bitfield, crosslink_committee_cache)).
    flatten().
    deduplicate().
    sorted(system.cmp)

func get_attesting_balance(state: BeaconState,
                           attestations: seq[PendingAttestation]): Gwei =
  get_total_balance(state, get_attesting_indices(state, attestations))

func get_attesting_balance_cached(
    state: BeaconState,
    attestations: seq[PendingAttestation],
    crosslink_committees_cache: var auto): Gwei =
  get_total_balance(state, get_attesting_indices_cached(
    state, attestations, crosslink_committees_cache))

func get_current_epoch_boundary_attestations(state: BeaconState):
    seq[PendingAttestation] =
  filterIt(
    state.current_epoch_attestations,
    it.data.target_root == get_block_root(
      state, get_epoch_start_slot(get_current_epoch(state))))

func get_previous_epoch_boundary_attestations(state: BeaconState):
    seq[PendingAttestation] =
  filterIt(
    state.previous_epoch_attestations,
    it.data.target_root ==
      get_block_root(state, get_epoch_start_slot(get_previous_epoch(state))))

func get_previous_epoch_matching_head_attestations(state: BeaconState):
    seq[PendingAttestation] =
  filterIt(
    state.previous_epoch_attestations,
    it.data.beacon_block_root == get_block_root(state, it.data.slot))

# Not exactly in spec, but for get_winning_root_and_participants
func lowerThan(candidate, current: Eth2Digest): bool =
  # return true iff candidate is "lower" than current, per spec rule:
  # "ties broken in favor of lexicographically higher hash
  for i, v in current.data:
    if v > candidate.data[i]: return true
  false

func get_winning_root_and_participants(
    state: BeaconState, shard: Shard, crosslink_committees_cache: var auto):
    tuple[a: Eth2Digest, b: seq[ValidatorIndex]] =
  let
    all_attestations =
      concat(state.current_epoch_attestations,
             state.previous_epoch_attestations)
    valid_attestations =
      filterIt(
        all_attestations,
        it.data.previous_crosslink == state.latest_crosslinks[shard])
    all_roots = mapIt(valid_attestations, it.data.crosslink_data_root)

  # handle when no attestations for shard available
  if len(all_roots) == 0:
    return (ZERO_HASH, @[])

  # 0.5.1 spec has less-than-ideal get_attestations_for nested function.
  var attestations_for = initTable[Eth2Digest, seq[PendingAttestation]]()
  for valid_attestation in valid_attestations:
    if valid_attestation.data.crosslink_data_root in attestations_for:
      attestations_for[valid_attestation.data.crosslink_data_root].add(
        valid_attestation)
    else:
      attestations_for[valid_attestation.data.crosslink_data_root] =
        @[valid_attestation]

  ## Winning crosslink root is the root with the most votes for it, ties broken
  ## in favor of lexicographically higher hash
  var
    winning_root: Eth2Digest
    winning_root_balance = 0'u64

  for r in all_roots:
    let root_balance = get_attesting_balance_cached(
      state, attestations_for.getOrDefault(r), crosslink_committees_cache)
    if (root_balance > winning_root_balance or
        (root_balance == winning_root_balance and
         lowerThan(winning_root, r))):
      winning_root = r
      winning_root_balance = root_balance

  (winning_root,
   get_attesting_indices_cached(
     state,
     attestations_for.getOrDefault(winning_root), crosslink_committees_cache))

# Combination of earliest_attestation and inclusion_slot avoiding O(n^2)
# TODO merge/refactor these two functions, which differ only very slightly.
func inclusion_slots(state: BeaconState): auto =
  result = initTable[ValidatorIndex, Slot]()

  for a in sorted(state.previous_epoch_attestations,
      func (x, y: PendingAttestation): auto =
        system.cmp(x.inclusion_slot, y.inclusion_slot)):
    for v in get_attestation_participants(
        state, a.data, a.aggregation_bitfield):
      if v notin result:
        result[v] = a.inclusion_slot

# Combination of earliest_attestation and inclusion_distance avoiding O(n^2)
func inclusion_distances(state: BeaconState): auto =
  result = initTable[ValidatorIndex, Slot]()

  for a in sorted(state.previous_epoch_attestations,
      func (x, y: PendingAttestation): auto =
        system.cmp(x.inclusion_slot, y.inclusion_slot)):
    for v in get_attestation_participants(
        state, a.data, a.aggregation_bitfield):
      if v notin result:
        result[v] = Slot(a.inclusion_slot - a.data.slot)

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#justification
func update_justification_and_finalization(state: var BeaconState) =
  var
    new_justified_epoch = state.current_justified_epoch
    new_finalized_epoch = state.finalized_epoch

  ## Rotate the justification bitfield up one epoch to make room for the
  ## current epoch
  state.justification_bitfield = state.justification_bitfield shl 1

  # If the previous epoch gets justified, fill the second last bit
  let previous_boundary_attesting_balance =
   get_attesting_balance(
     state, get_previous_epoch_boundary_attestations(state))
  if previous_boundary_attesting_balance * 3'u64 >=
      get_previous_total_balance(state) * 2'u64:
    new_justified_epoch = get_current_epoch(state) - 1
    state.justification_bitfield = state.justification_bitfield or 2

  # If the current epoch gets justified, fill the last bit
  let current_boundary_attesting_balance =
    get_attesting_balance(
      state, get_current_epoch_boundary_attestations(state))
  if current_boundary_attesting_balance * 3'u64 >=
      get_current_total_balance(state) * 2'u64:
    new_justified_epoch = get_current_epoch(state)
    state.justification_bitfield = state.justification_bitfield or 1

  # Process finalizations
  let
    bitfield = state.justification_bitfield
    current_epoch = get_current_epoch(state)

  ## The 2nd/3rd/4th most recent epochs are all justified, the 2nd using the
  ## 4th as source
  if (bitfield shr 1) mod 8 == 0b111 and
      state.previous_justified_epoch == current_epoch - 3:
    new_finalized_epoch = state.previous_justified_epoch

  ## The 2nd/3rd most recent epochs are both justified, the 2nd using the 3rd
  ## as source
  if (bitfield shr 1) mod 4 == 0b11 and
     state.previous_justified_epoch == current_epoch - 2:
   new_finalized_epoch = state.previous_justified_epoch

  ## The 1st/2nd/3rd most recent epochs are all justified, the 1st using the
  ## 3rd as source
  if (bitfield shr 0) mod 8 == 0b111 and
      state.current_justified_epoch == current_epoch - 2:
    new_finalized_epoch = state.current_justified_epoch

  ## The 1st/2nd most recent epochs are both justified, the 1st using the 2nd
  ## as source
  if (bitfield shr 0) mod 4 == 0b11 and
      state.current_justified_epoch == current_epoch - 1:
    new_finalized_epoch = state.current_justified_epoch

  # Update state jusification/finality fields
  state.previous_justified_epoch = state.current_justified_epoch
  state.previous_justified_root = state.current_justified_root
  if new_justified_epoch != state.current_justified_epoch:
    state.current_justified_epoch = new_justified_epoch
    state.current_justified_root =
      get_block_root(state, get_epoch_start_slot(new_justified_epoch))
  if new_finalized_epoch != state.finalized_epoch:
    state.finalized_epoch = new_finalized_epoch
    state.finalized_root =
      get_block_root(state, get_epoch_start_slot(new_finalized_epoch))

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#crosslinks
func process_crosslinks(
    state: var BeaconState, crosslink_committee_cache: var auto,
    winning_root_participants_cache: var auto) =
  let
    current_epoch = get_current_epoch(state)
    previous_epoch = current_epoch - 1
    next_epoch = current_epoch + 1

  ## TODO is it actually correct to be setting state.latest_crosslinks[shard]
  ## to something pre-GENESIS_EPOCH, ever? I guess the intent is if there are
  ## a quorum of participants for  get_epoch_start_slot(previous_epoch), when
  ## state.slot == GENESIS_SLOT, then there will be participants for a quorum
  ## in the current-epoch (i.e. genesis epoch) version of that shard?
  #for slot in get_epoch_start_slot(previous_epoch).uint64 ..<
  for slot in max(
      GENESIS_SLOT.uint64, get_epoch_start_slot(previous_epoch).uint64) ..<
      get_epoch_start_slot(next_epoch).uint64:
    for cas in get_crosslink_committees_at_slot_cached(
        state, slot, false, crosslink_committee_cache):
      let
        (crosslink_committee, shard) = cas
        # In general, it'll loop over the same shards twice, and
        # get_winning_root_and_participants is defined to return
        # the same results from the previous epoch as current.
        (winning_root, participants) =
          if shard notin winning_root_participants_cache:
            get_winning_root_and_participants(
              state, shard, crosslink_committee_cache)
          else:
            (ZERO_HASH, winning_root_participants_cache[shard])
        participating_balance = get_total_balance(state, participants)
        total_balance = get_total_balance(state, crosslink_committee)

      winning_root_participants_cache[shard] = participants

      if 3'u64 * participating_balance >= 2'u64 * total_balance:
        # Check not from spec; seems kludgy
        doAssert slot >= GENESIS_SLOT

        state.latest_crosslinks[shard] = Crosslink(
          epoch: slot_to_epoch(slot),
          crosslink_data_root: winning_root
        )

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#eth1-data
func maybe_reset_eth1_period(state: var BeaconState) =
  if (get_current_epoch(state) + 1) mod EPOCHS_PER_ETH1_VOTING_PERIOD == 0:
    for eth1_data_vote in state.eth1_data_votes:
      ## If a majority of all votes were for a particular eth1_data value,
      ## then set that as the new canonical value
      if eth1_data_vote.vote_count * 2 >
          EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH:
        state.latest_eth1_data = eth1_data_vote.eth1_data
    state.eth1_data_votes = @[]

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#rewards-and-penalties
func get_base_reward(state: BeaconState, index: ValidatorIndex): uint64 =
  if get_previous_total_balance(state) == 0:
    return 0

  let adjusted_quotient =
    integer_squareroot(get_previous_total_balance(state)) div
      BASE_REWARD_QUOTIENT
  get_effective_balance(state, index) div adjusted_quotient.uint64 div 5

func get_inactivity_penalty(
    state: BeaconState, index: ValidatorIndex,
    epochs_since_finality: uint64): uint64 =
  # TODO Left/right associativity sensitivity on * and div?
  get_base_reward(state, index) +
    get_effective_balance(state, index) * epochs_since_finality div
    INACTIVITY_PENALTY_QUOTIENT div 2

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#justification-and-finalization
func compute_normal_justification_and_finalization_deltas(state: BeaconState):
    tuple[a: seq[Gwei], b: seq[Gwei]] =
  # deltas[0] for rewards
  # deltas[1] for penalties
  var deltas = (
    repeat(0'u64, len(state.validator_registry)),
    repeat(0'u64, len(state.validator_registry))
  )
  # Some helper variables
  let
    boundary_attestations = get_previous_epoch_boundary_attestations(state)
    boundary_attesting_balance =
      get_attesting_balance(state, boundary_attestations)
    total_balance = get_previous_total_balance(state)
    total_attesting_balance =
      get_attesting_balance(state, state.previous_epoch_attestations)
    matching_head_attestations =
      get_previous_epoch_matching_head_attestations(state)
    matching_head_balance =
      get_attesting_balance(state, matching_head_attestations)

  let
    inclusion_distance = inclusion_distances(state)
    inclusion_slot = inclusion_slots(state)
    previous_epoch_attestation_indices =
      toSet(get_attesting_indices(state, state.previous_epoch_attestations))
    boundary_attestation_indices =
      toSet(get_attesting_indices(state, boundary_attestations))
    matching_head_attestation_indices =
      toSet(get_attesting_indices(state, matching_head_attestations))
  # Process rewards or penalties for all validators
  for index in get_active_validator_indices(
      state.validator_registry, get_previous_epoch(state)):
    # Expected FFG source
    if index in previous_epoch_attestation_indices:
      deltas[0][index] +=
        get_base_reward(state, index) * total_attesting_balance div
        total_balance
      # Inclusion speed bonus
      deltas[0][index] += (
        get_base_reward(state, index) * MIN_ATTESTATION_INCLUSION_DELAY div
        inclusion_distance[index]
      )
    else:
      deltas[1][index] += get_base_reward(state, index)
    # Expected FFG target
    if index in boundary_attestation_indices:
      deltas[0][index] +=
        get_base_reward(state, index) * boundary_attesting_balance div
        total_balance
    else:
      deltas[1][index] += get_base_reward(state, index)
    # Expected head
    if index in matching_head_attestation_indices:
      deltas[0][index] +=
        get_base_reward(state, index) *
          matching_head_balance div total_balance
    else:
      deltas[1][index] += get_base_reward(state, index)
    # Proposer bonus
    if index in previous_epoch_attestation_indices:
      let proposer_index =
        get_beacon_proposer_index(state, inclusion_slot[index])
      deltas[0][proposer_index] +=
        get_base_reward(state, index) div ATTESTATION_INCLUSION_REWARD_QUOTIENT
  deltas

func compute_inactivity_leak_deltas(state: BeaconState):
    tuple[a: seq[Gwei], b: seq[Gwei]] =
  # When blocks are not finalizing normally
  # deltas[0] for rewards
  # deltas[1] for penalties
  var deltas = (
    repeat(0'u64, len(state.validator_registry)),
    repeat(0'u64, len(state.validator_registry))
  )

  let
    boundary_attestations = get_previous_epoch_boundary_attestations(state)
    matching_head_attestations =
      get_previous_epoch_matching_head_attestations(state)
    active_validator_indices = toSet(get_active_validator_indices(
      state.validator_registry, get_previous_epoch(state)))
    epochs_since_finality =
      get_current_epoch(state) + 1 - state.finalized_epoch
  let
    inclusion_distance = inclusion_distances(state)
    previous_epoch_attestation_indices =
      toSet(get_attesting_indices(state, state.previous_epoch_attestations))
    boundary_attestation_indices =
      toSet(get_attesting_indices(state, boundary_attestations))
    matching_head_attestation_indices =
      toSet(get_attesting_indices(state, matching_head_attestations))
  for index in active_validator_indices:
    if index notin previous_epoch_attestation_indices:
      deltas[1][index] +=
        get_inactivity_penalty(state, index, epochs_since_finality)
    else:
      ## If a validator did attest, apply a small penalty for getting
      ## attestations included late
      deltas[0][index] += (
        get_base_reward(state, index) * MIN_ATTESTATION_INCLUSION_DELAY div
          inclusion_distance[index]
      )
      deltas[1][index] += get_base_reward(state, index)
    if index notin boundary_attestation_indices:
      deltas[1][index] +=
        get_inactivity_penalty(state, index, epochs_since_finality)
    if index notin matching_head_attestation_indices:
      deltas[1][index] += get_base_reward(state, index)

  ## Penalize slashed-but-inactive validators as though they were active but
  ## offline
  for index in 0 ..< len(state.validator_registry):
    let eligible = (
      index.ValidatorIndex notin active_validator_indices and
      state.validator_registry[index].slashed and
      get_current_epoch(state) <
        state.validator_registry[index].withdrawable_epoch
    )
    if eligible:
      deltas[1][index] += (
        2'u64 * get_inactivity_penalty(
          state, index.ValidatorIndex, epochs_since_finality) +
        get_base_reward(state, index.ValidatorIndex)
      )
  deltas

func get_justification_and_finalization_deltas(state: BeaconState):
    tuple[a: seq[Gwei], b: seq[Gwei]] =
  let epochs_since_finality =
    get_current_epoch(state) + 1 - state.finalized_epoch
  if epochs_since_finality <= 4:
    compute_normal_justification_and_finalization_deltas(state)
  else:
    compute_inactivity_leak_deltas(state)

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#crosslinks-1
func get_crosslink_deltas(
    state: BeaconState, crosslink_committees_cache: var auto,
    winning_root_participants_cache: var auto):
    tuple[a: seq[Gwei], b: seq[Gwei]] =
  # deltas[0] for rewards
  # deltas[1] for penalties
  var deltas = (
    repeat(0'u64, len(state.validator_registry)),
    repeat(0'u64, len(state.validator_registry))
  )
  let
    previous_epoch_start_slot =
      get_epoch_start_slot(get_previous_epoch(state))
    current_epoch_start_slot =
      get_epoch_start_slot(get_current_epoch(state))
  for slot in previous_epoch_start_slot.uint64 ..<
      current_epoch_start_slot.uint64:
    for cas in get_crosslink_committees_at_slot_cached(state, slot, false, crosslink_committees_cache):
      let
        (crosslink_committee, shard) = cas
        (winning_root, participants) = get_winning_root_and_participants(
          state, shard, crosslink_committees_cache)
        nonquadraticParticipants = toSet(participants)
        participating_balance = get_total_balance(state, participants)
        total_balance = get_total_balance(state, crosslink_committee)
      for index in crosslink_committee:
        if index in nonquadraticParticipants:
          deltas[0][index] +=
            get_base_reward(state, index) * participating_balance div
              total_balance
        else:
          deltas[1][index] += get_base_reward(state, index)

  deltas

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#apply-rewards
func apply_rewards(
    state: var BeaconState, crosslink_committees_cache: var auto,
    winning_root_participants_cache: var auto) =
  let
    deltas1 = get_justification_and_finalization_deltas(state)
    deltas2 = get_crosslink_deltas(
      state, crosslink_committees_cache, winning_root_participants_cache)
  for i in 0 ..< len(state.validator_registry):
    state.validator_balances[i] =
      max(
        0'u64,
        state.validator_balances[i] + deltas1[0][i] + deltas2[0][i] -
                                      deltas1[1][i] - deltas2[1][i])

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#slashings-and-exit-queue
func process_slashings(state: var BeaconState) =
  ## Process the slashings.
  ## Note that this function mutates ``state``.
  let
    current_epoch = get_current_epoch(state)
    active_validator_indices = get_active_validator_indices(
      state.validator_registry, current_epoch)
    total_balance = get_total_balance(state, active_validator_indices)

    # Compute `total_penalties`
    total_at_start = state.latest_slashed_balances[
      (current_epoch + 1) mod LATEST_SLASHED_EXIT_LENGTH]
    total_at_end =
      state.latest_slashed_balances[current_epoch mod
        LATEST_SLASHED_EXIT_LENGTH]
    total_penalties = total_at_end - total_at_start

  for index, validator in state.validator_registry:
    if validator.slashed and current_epoch == validator.withdrawable_epoch -
        LATEST_SLASHED_EXIT_LENGTH div 2:
      let
        penalty = max(
          get_effective_balance(state, index.ValidatorIndex) *
            min(total_penalties * 3, total_balance) div total_balance,
          get_effective_balance(state, index.ValidatorIndex) div
            MIN_PENALTY_QUOTIENT)
      reduce_balance(state.validator_balances[index], penalty)

func process_exit_queue(state: var BeaconState) =
  ## Process the exit queue.
  ## Note that this function mutates ``state``.

  func eligible(index: ValidatorIndex): bool =
    let validator = state.validator_registry[index]
    # Filter out dequeued validators
    if validator.withdrawable_epoch != FAR_FUTURE_EPOCH:
      return false
    # Dequeue if the minimum amount of time has passed
    else:
      return get_current_epoch(state) >= validator.exit_epoch +
        MIN_VALIDATOR_WITHDRAWABILITY_DELAY

    var eligible_indices: seq[ValidatorIndex]
    for vi in 0 ..< len(state.validator_registry):
      if eligible(vi.ValidatorIndex):
        eligible_indices.add vi.ValidatorIndex
    let
      ## Sort in order of exit epoch, and validators that exit within the same
      ## epoch exit in order of validator index
      sorted_indices = sorted(
        eligible_indices,
        func(x, y: ValidatorIndex): int =
          system.cmp(
            state.validator_registry[x].exit_epoch,
            state.validator_registry[y].exit_epoch))

    for dequeues, index in sorted_indices:
      if dequeues >= MAX_EXIT_DEQUEUES_PER_EPOCH:
        break
      prepare_validator_for_withdrawal(state, index)

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#final-updates
func finish_epoch_update(state: var BeaconState) =
  let
    current_epoch = get_current_epoch(state)
    next_epoch = current_epoch + 1

  # Set active index root
  let index_root_position =
    (next_epoch + ACTIVATION_EXIT_DELAY) mod LATEST_ACTIVE_INDEX_ROOTS_LENGTH
  state.latest_active_index_roots[index_root_position] =
    hash_tree_root(get_active_validator_indices(
      state.validator_registry, next_epoch + ACTIVATION_EXIT_DELAY)
  )

  # Set total slashed balances
  state.latest_slashed_balances[next_epoch mod LATEST_SLASHED_EXIT_LENGTH] = (
    state.latest_slashed_balances[current_epoch mod LATEST_SLASHED_EXIT_LENGTH]
  )

  # Set randao mix
  state.latest_randao_mixes[next_epoch mod LATEST_RANDAO_MIXES_LENGTH] =
    get_randao_mix(state, current_epoch)

  # Set historical root accumulator
  if next_epoch mod (SLOTS_PER_HISTORICAL_ROOT div SLOTS_PER_EPOCH).uint64 == 0:
    let historical_batch = HistoricalBatch(
      block_roots: state.latest_block_roots,
      state_roots: state.latest_state_roots,
    )
    state.historical_roots.add (hash_tree_root(historical_batch))

  # Rotate current/previous epoch attestations
  state.previous_epoch_attestations = state.current_epoch_attestations
  state.current_epoch_attestations = @[]

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#per-epoch-processing
func processEpoch(state: var BeaconState) =
  if not (state.slot > GENESIS_SLOT and
         (state.slot + 1) mod SLOTS_PER_EPOCH == 0):
    return

  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#justification
  update_justification_and_finalization(state)

  var
    crosslink_committee_cache =
      initTable[tuple[a: uint64, b: bool], seq[CrosslinkCommittee]]()
    winning_root_participants_cache =
      initTable[Shard, seq[ValidatorIndex]]()
  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#crosslinks
  process_crosslinks(
    state, crosslink_committee_cache, winning_root_participants_cache)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#eth1-data
  maybe_reset_eth1_period(state)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#apply-rewards
  apply_rewards(
    state, crosslink_committee_cache, winning_root_participants_cache)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#ejections
  process_ejections(state)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#validator-registry-and-shuffling-seed-data
  update_registry_and_shuffling_data(state)

  # Not from spec.
  updateShufflingCache(state)

  ## Regardless of whether or not a validator set change happens run
  ## process_slashings(state) and process_exit_queue(state)
  process_slashings(state)
  process_exit_queue(state)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#final-updates
  finish_epoch_update(state)

# https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#state-root-verification
proc verifyStateRoot(state: BeaconState, blck: BeaconBlock): bool =
  let state_root = hash_tree_root(state)
  if state_root != blck.state_root:
    notice "Block: root verification failed",
      block_state_root = blck.state_root, state_root
    false
  else:
    true

proc advanceState*(state: var BeaconState) =
  ## Sometimes we need to update the state even though we don't have a block at
  ## hand - this happens for example when a block proposer fails to produce a
  ## a block.

  ## https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
  ## We now define the state transition function. At a high level the state
  ## transition is made up of four parts:

  ## 1. State caching, which happens at the start of every slot.
  ## The state caching, caches the state root of the previous slot
  cacheState(state)

  ## 2. The per-epoch transitions, which happens at the start of the first
  ## slot of every epoch.
  ## The per-epoch transitions focus on the validator registry, including
  ## adjusting balances and activating and exiting validators, as well as
  ## processing crosslinks and managing block justification/finalization.
  processEpoch(state)

  ## 3. The per-slot transitions, which happens at every slot.
  ## The per-slot transitions focus on the slot counter and block roots
  ## records updates.
  advance_slot(state)

proc updateState*(
    state: var BeaconState, new_block: BeaconBlock, flags: UpdateFlags): bool =
  ## Time in the beacon chain moves by slots. Every time (haha.) that happens,
  ## we will update the beacon state. Normally, the state updates will be driven
  ## by the contents of a new block, but it may happen that the block goes
  ## missing - the state updates happen regardless.
  ##
  ## Each call to this function will advance the state by one slot - new_block,
  ## must match that slot. If the update fails, the state will remain unchanged.
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
  # TODO There's a discussion about what this function should do, and when:
  #      https://github.com/ethereum/eth2.0-specs/issues/284

  # TODO check to which extent this copy can be avoided (considering forks etc),
  #      for now, it serves as a reminder that we need to handle invalid blocks
  #      somewhere..
  #      many functions will mutate `state` partially without rolling back
  #      the changes in case of failure (look out for `var BeaconState` and
  #      bool return values...)

  ## TODO, of cacheState/processEpoch/processSlot/processBloc, only the last
  ## might fail, so should this bother capturing here, or?
  var old_state = state

  # These should never fail.
  advanceState(state)

  # Block updates - these happen when there's a new block being suggested
  # by the block proposer. Every actor in the network will update its state
  # according to the contents of this block - but first they will validate
  # that the block is sane.
  # TODO what should happen if block processing fails?
  #      https://github.com/ethereum/eth2.0-specs/issues/293
  if processBlock(state, new_block, flags):
    # This is a bit awkward - at the end of processing we verify that the
    # state we arrive at is what the block producer thought it would be -
    # meaning that potentially, it could fail verification
    if skipValidation in flags or verifyStateRoot(state, new_block):
      # State root is what it should be - we're done!
      return true

  # Block processing failed, roll back changes
  state = old_state
  false

proc skipSlots*(state: var BeaconState, slot: Slot,
    afterSlot: proc (state: BeaconState) = nil) =
  if state.slot < slot:
    debug "Advancing state with empty slots",
      targetSlot = humaneSlotNum(slot),
      stateSlot = humaneSlotNum(state.slot)

    while state.slot < slot:
      advanceState(state)

      if not afterSlot.isNil:
        afterSlot(state)

# TODO document this:

# Jacek Sieka
# @arnetheduck
# Dec 21 11:32
# question about making attestations: in the attestation we carry slot and a justified_slot - just to make sure, this justified_slot is the slot that was justified when the state was at slot, not whatever the client may be seeing now? effectively, because we're attesting to MIN_ATTESTATION_INCLUSION_DELAYold states, it might be that we know about a newer justified slot, but don't include it - correct?
# Danny Ryan
# @djrtwo
# Dec 21 11:34
# You are attesting to what you see as the head of the chain at that slot
# The MIN_ATTESTATION_INCLUSION_DELAY is just how many slots must past before this message can be included on chain
# so whatever the justified_slot was inside the state that was associate with the head you are attesting to
# Jacek Sieka
# @arnetheduck
# Dec 21 11:37
# can I revise an attestation, once I get new information (about the shard or state)?
# Danny Ryan
# @djrtwo
# Dec 21 11:37
# We are attesting to the exact current state at that slot. The MIN_ATTESTATION_INCLUSION_DELAY is to attempt to reduce centralization risk in light of fast block times (ensure attestations have time to fully propagate so fair playing field on including them on chain)
# No, if you create two attestations for the same slot, you can be slashed
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#is_double_vote
# Jacek Sieka
# @arnetheduck
# Dec 21 11:39
# is there any interest for me to publish my attestation before MIN_ATTESTATION_INCLUSION_DELAY-1 time has passed?
# (apart from the risk of it not being picked up on time)
# Danny Ryan
# @djrtwo
# Dec 21 11:40

# that’s the main risk.

# Note, we’re a bit unsure about MIN_ATTESTATION_INCLUSION_DELAY because it might open up an attestors timing strategy too much. In the case where MIN_ATTESTATION_INCLUSION_DELAY is removed, we just set it to 1
# part of validator honesty assumption is to attest during your slot. That said, a rational actor might act in any number of interesting ways..
# Jacek Sieka
# @arnetheduck
# Dec 21 11:59
# I can probably google this somehow, but bls signatures, anyone knows off the top of their head if they have to be combined one by one, or can two group signatures be combined? what happens to overlap then?
# Danny Ryan
# @djrtwo
# Dec 21 12:00
# Yeah, you can do any linear combination of signatures. but you have to remember the linear combination of pubkeys that constructed
# if you have two instances of a signature from pubkey p, then you need 2*p in the group pubkey
# because the attestation bitfield is only 1 bit per pubkey right now, attestations do not support this
# it could be extended to support N overlaps up to N times per pubkey if we had N bits per validator instead of 1
# We are shying away from this for the time being. If there end up being substantial difficulties in network layer aggregation, then adding bits to aid in supporting overlaps is one potential solution
# Jacek Sieka
# @arnetheduck
# Dec 21 12:02
# ah nice, you anticipated my followup question there :) so it's not a straight-off set union operation
# Danny Ryan
# @djrtwo
# Dec 21 12:02
# depending on the particular network level troubles we run into
# right
# aggregatng sigs and pubkeys are both just ec adds https://github.com/ethereum/py-evm/blob/d82b10ae361cde6abbac62f171fcea7809c4e3cf/eth/_utils/bls.py#L191-L202
# subtractions work too (i suppose this is obvious). You can linearly combine sigs or pubs in any way
# Jacek Sieka
# @arnetheduck
# Dec 21 12:05
# hm.. well, because one thing I'm thinking of is the scenario where someone attests to some shard head and I receive that attestation.. now, let's say that's an honest attestation, but within that same slot, I have more fresh information about a shard for example.. now, I can either sign the data in the old attestation or churn out a new one, risking that neither of these get enough votes to be useful - does that sound.. accurate?
# Danny Ryan
# @djrtwo
# Dec 21 12:08

# So you won’t just be signing the head of the shard. This isn’t specified yet, but it would be targeting some recent epoch boundary to ensure higher chance of consensus.

# If your recent info is about a better fork in the shard than the one you see the other attester signed, then you are better off signing that fork because if it is winning in your few of the shard chain fork choice, then you would assume it is winning in the view of most attesters shard fork choice
# If some strange circumstance arose in which you saw a majority of attestations that signed something you think is unexpected before you signed, a rational actor might defect to this majority. An honest actor would sign what they believe to be true
# in practice, the actor would have to wait some amount of time past when they should have attested to gather this info.
# also, at the end of the day the validator has to compute the non-outsourcable proof of custody bit, so if the other validators are signing off on some shard chain fork they don’t know about, then they can’t attest to that data anyway
# (for fear of signing a bad custody bit)
# so their rational move is to just attest to the data they acutally know about and can accurately compute their proof of custody bit on
# Jacek Sieka
# @arnetheduck
# Dec 21 12:58
# what's justified_block_root doing in attestation_data? isn't that available already as get_block_root(state, attestation.data.justified_slot)?
# also, when we sign hash_tree_root(attestation.data) + bytes1(0) - what's the purpose of the 0 byte, given we have domain already?
# Danny Ryan
# @djrtwo
# Dec 21 13:03
# 0 byte is a stub for the proof of custody bit in phase 0
# If the attestation is included in a short range fork but still votes for the chain it is added to’s justified_block_root/slot, then we want to count the casper vote
# likely if I see the head of the chain as different from what ends up being the canonical chain, my view of the latest justified block might still be in accordance with the canonical chain
# if my attesation is included in a fork, the head i voted on doesn’t necessarily lead back to the justified block in the fork. Without including justified_block_root, my vote could be used in any fork for the same epoch even if the block at that justified_slot height was different
# Danny Ryan
# @djrtwo
# Dec 21 13:14
# Long story short, because attestations can be included in forks of the head they are actually attesting to, we can’t be sure of the justified_block that was being voted on by just usng the justified_slot. The security of properties of Casper FFG require that the voter makes a firm commitment to the actual source block, not just the height of the source block
# Jacek Sieka
# @arnetheduck
# Dec 21 13:23
# ok. that's quite a piece. I'm gonna have to draw some diagrams I think :)
# ah. ok. actually makes sense.. I think :)
# Jacek Sieka
# @arnetheduck
# Dec 21 13:31
# how does that interact then with the following check:

#     Verify that attestation.data.justified_block_root is equal to get_block_root(state, attestation.data.justified_slot).

# Danny Ryan
# @djrtwo
# Dec 21 13:32
# ah, my bad above. We only include an attestation on chain if it is for the correct source
# That’s one of the bare minimum requirements to get it included on chain. Without the justified_block_root, we can’t do that check
# essentially that checks if this attestation is relevant at all to the current fork’s consensus.
# if the justified_block is wrong, then we know the target of the vote and the head of the attestation are wrong too
# sorry for the slight mix up there
# logic still holds — the justified_slot alone is not actually a firm commitment to a particular chain history. You need the associated hash
# Jacek Sieka
# @arnetheduck
# Dec 21 13:35
# can't you just follow Block.parent_root?
# well, that, and ultimately.. Block.state_root
# Danny Ryan
# @djrtwo
# Dec 21 13:37
# The block the attestation is included in might not be for the same fork the attestation was made
# we first make sure that the attestation and the block that it’s included in match at the justified_slot. if not, throw it out
# then in the incentives, we give some extra reward if the epoch_boundary_root and the chain match
# and some extra reward if the beacon_block_root match
# if all three match, then the attestation is fully agreeing with the canonical chain. +1 casper vote and strengthening the head of the fork choice
# if just justified_block_root and epoch_boundary_root match then the attestation agrees enough to successfully cast an ffg vote
# if just justified_block_root match, then at least the attestation agrees on the base of the fork choice, but this isn’t enough to cast an FFG vote
# Jacek Sieka
# @arnetheduck
# Dec 21 13:41

#     if not, throw it out

# it = block or attestation?
# Danny Ryan
# @djrtwo
# Dec 21 13:42
# well, if you are buildling the block ,you shouldn’t include it (thus throw it out of current consideration). If you are validating a block you just received and that conditon fails for an attestation, throw the block out because it included a bad attestation and is thus invalid
# The block producer knows when producing the block if they are including bad attestations or other data that will fail state transition
# and should not do that
# Jacek Sieka
# @arnetheduck
# Dec 21 13:43
# yeah, that makes sense, just checking
# ok, I think I'm gonna let that sink in a bit before asking more questions.. thanks :)
