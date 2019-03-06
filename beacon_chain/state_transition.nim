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
  ./spec/[beaconstate, crypto, datatypes, digest, helpers, validator]

func flatten[T](v: openArray[seq[T]]): seq[T] =
  # TODO not in nim - doh.
  for x in v: result.add x

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#proposer-signature
func verifyProposerSignature(state: BeaconState, blck: BeaconBlock): bool =
  ## When creating a block, the proposer will sign a version of the block that
  ## doesn't contain the data (chicken and egg), then add the signature to that
  ## block. Here, we check that the signature is correct by repeating the same
  ## process.
  var blck_without_signature = blck
  blck_without_signature.signature = ValidatorSig()

  let
    signed_data = ProposalSignedData(
      slot: state.slot,
      shard: BEACON_CHAIN_SHARD_NUMBER,
      block_root: hash_tree_root_final(blck_without_signature)
    )
    proposal_root = hash_tree_root_final(signed_data)
    proposer_index = get_beacon_proposer_index(state, state.slot)

  bls_verify(
    state.validator_registry[proposer_index].pubkey,
    proposal_root.data, blck.signature,
    get_domain(state.fork, get_current_epoch(state), DOMAIN_PROPOSAL))

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#randao
proc processRandao(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  let
    proposer_index = get_beacon_proposer_index(state, state.slot)
    proposer = addr state.validator_registry[proposer_index]

  if skipValidation notin flags:
    if not bls_verify(
      proposer.pubkey,
      int_to_bytes32(get_current_epoch(state)),
      blck.randao_reveal,
      get_domain(state.fork, get_current_epoch(state), DOMAIN_RANDAO)):

      notice "Randao mismatch", proposer_pubkey = proposer.pubkey,
                                message = get_current_epoch(state),
                                signature = blck.randao_reveal,
                                slot = state.slot,
                                blck_slot = blck.slot
      return false

  # Update state and proposer now that we're alright
  let
    mix = get_current_epoch(state) mod LATEST_RANDAO_MIXES_LENGTH
    rr = hash_tree_root_final(blck.randao_reveal).data

  for i, b in state.latest_randao_mixes[mix].data:
    state.latest_randao_mixes[mix].data[i] = b xor rr[i]

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#eth1-data
func processDepositRoot(state: var BeaconState, blck: BeaconBlock) =
  # TODO verify that there's at most one match
  for x in state.eth1_data_votes.mitems():
    if blck.eth1_data == x.eth1_data:
      x.vote_count += 1
      return

  state.eth1_data_votes.add Eth1DataVote(
    eth1_data: blck.eth1_data,
    vote_count: 1
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#slashValidator
func slashValidator(state: var BeaconState, index: ValidatorIndex) =
  ## Slash the validator of the given ``index``.
  ## Note that this function mutates ``state``.
  var validator = addr state.validator_registry[index]

  doAssert state.slot < get_epoch_start_slot(validator.withdrawable_epoch) ##\
  ## [TO BE REMOVED IN PHASE 2]

  exit_validator(state, index)
  state.latest_slashed_balances[(get_current_epoch(state) mod
    LATEST_SLASHED_EXIT_LENGTH).int] += get_effective_balance(state,
      index.ValidatorIndex)

  let
    whistleblower_index = get_beacon_proposer_index(state, state.slot)
    whistleblower_reward = get_effective_balance(state, index) div
      WHISTLEBLOWER_REWARD_QUOTIENT
  state.validator_balances[whistleblower_index] += whistleblower_reward
  reduce_balance(state.validator_balances[index], whistleblower_reward)
  validator.slashed_epoch = get_current_epoch(state)

  # v0.3.0 spec bug, fixed later, involving renamed constants. Use v0.3.0 name.
  validator.withdrawable_epoch = get_current_epoch(state) + LATEST_SLASHED_EXIT_LENGTH

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#proposer-slashings-1
proc processProposerSlashings(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  if len(blck.body.proposer_slashings) > MAX_PROPOSER_SLASHINGS:
    notice "PropSlash: too many!",
      proposer_slashings = len(blck.body.proposer_slashings)
    return false

  for proposer_slashing in blck.body.proposer_slashings:
    let proposer = state.validator_registry[proposer_slashing.proposer_index.int]
    if skipValidation notin flags:
      if not bls_verify(
          proposer.pubkey,
          hash_tree_root_final(proposer_slashing.proposal_data_1).data,
          proposer_slashing.proposal_signature_1,
          get_domain(
            state.fork, slot_to_epoch(proposer_slashing.proposal_data_1.slot),
            DOMAIN_PROPOSAL)):
        notice "PropSlash: invalid signature 1"
        return false
      if not bls_verify(
          proposer.pubkey,
          hash_tree_root_final(proposer_slashing.proposal_data_2).data,
          proposer_slashing.proposal_signature_2,
          get_domain(
            state.fork, slot_to_epoch(proposer_slashing.proposal_data_2.slot),
            DOMAIN_PROPOSAL)):
        notice "PropSlash: invalid signature 2"
        return false

    if not (proposer_slashing.proposal_data_1.slot ==
        proposer_slashing.proposal_data_2.slot):
      notice "PropSlash: slot mismatch"
      return false

    if not (proposer_slashing.proposal_data_1.shard ==
        proposer_slashing.proposal_data_2.shard):
      notice "PropSlash: shard mismatch"
      return false

    if not (proposer_slashing.proposal_data_1.block_root ==
        proposer_slashing.proposal_data_2.block_root):
      notice "PropSlash: block root mismatch"
      return false

    if not (proposer.slashed_epoch > get_current_epoch(state)):
      notice "PropSlash: penalized slot"
      return false

    slashValidator(state, proposer_slashing.proposer_index.ValidatorIndex)

  return true

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#verify_slashable_attestation
func verify_slashable_attestation(state: BeaconState, slashable_attestation: SlashableAttestation): bool =
  # Verify validity of ``slashable_attestation`` fields.

  if anyIt(slashable_attestation.custody_bitfield, it != 0):   # [TO BE REMOVED IN PHASE 1]
    return false

  if len(slashable_attestation.validator_indices) == 0:
     return false

  for i in 0 ..< (len(slashable_attestation.validator_indices) - 1):
    if slashable_attestation.validator_indices[i] >= slashable_attestation.validator_indices[i + 1]:
      return false

  if not verify_bitfield(slashable_attestation.custody_bitfield, len(slashable_attestation.validator_indices)):
    return false

  if len(slashable_attestation.validator_indices) > MAX_INDICES_PER_SLASHABLE_VOTE:
    return false

  var
    custody_bit_0_indices: seq[uint64] = @[]
    custody_bit_1_indices: seq[uint64] = @[]

  for i, validator_index in slashable_attestation.validator_indices:
    if get_bitfield_bit(slashable_attestation.custody_bitfield, i) == 0b0:
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#attester-slashings-1
proc processAttesterSlashings(state: var BeaconState, blck: BeaconBlock): bool =
  if len(blck.body.attester_slashings) > MAX_ATTESTER_SLASHINGS:
    notice "CaspSlash: too many!"
    return false

  for attester_slashing in blck.body.attester_slashings:
    let
      slashable_attestation_1 = attester_slashing.slashable_attestation_1
      slashable_attestation_2 = attester_slashing.slashable_attestation_2

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
      indices2 = slashable_attestation_2.validator_indices
      slashable_indices =
        slashable_attestation_1.validator_indices.filterIt(it in indices2)

    if not (len(slashable_indices) >= 1):
      notice "CaspSlash: no intersection"
      return false

    for index in slashable_indices:
      if state.validator_registry[index.int].slashed_epoch > get_current_epoch(state):
        slash_validator(state, index.ValidatorIndex)

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#attestations-1
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
  state.latest_attestations.add blck.body.attestations.mapIt(
    PendingAttestation(
      data: it.data,
      aggregation_bitfield: it.aggregation_bitfield,
      custody_bitfield: it.custody_bitfield,
      inclusion_slot: state.slot,
    )
  )

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#deposits-1
func processDeposits(state: var BeaconState, blck: BeaconBlock): bool =
  # TODO! Spec writing in progress as of v0.3.0
  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#voluntary-exits-1
proc processExits(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  if len(blck.body.voluntary_exits) > MAX_VOLUNTARY_EXITS:
    notice "Exit: too many!"
    return false

  for exit in blck.body.voluntary_exits:
    let validator = state.validator_registry[exit.validator_index.int]

    if not (validator.exit_epoch > get_entry_exit_effect_epoch(get_current_epoch(state))):
      notice "Exit: exit/entry too close"
      return false

    if not (get_current_epoch(state) >= exit.epoch):
      notice "Exit: bad epoch"
      return false

    if skipValidation notin flags:
      let exit_message = hash_tree_root(
        # In 0.3.0 spec, this is "Exit", but that's a renaming mismatch
        VoluntaryExit(
          epoch: exit.epoch, validator_index: exit.validator_index,
          signature: EMPTY_SIGNATURE))
      if not bls_verify(
          validator.pubkey, exit_message, exit.signature,
          get_domain(state.fork, exit.epoch, DOMAIN_EXIT)):
        notice "Exit: invalid signature"
        return false

    initiate_validator_exit(state, exit.validator_index.ValidatorIndex)

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#transfers-1
proc processTransfers(state: var BeaconState, blck: BeaconBlock,
                      flags: UpdateFlags): bool =
  ## Note: Transfers are a temporary functionality for phases 0 and 1, to be
  ## removed in phase 2.
  if not (len(blck.body.transfers) <= MAX_TRANSFERS):
    notice "Transfer: too many transfers"
    return false

  for transfer in blck.body.transfers:
    let from_balance = state.validator_balances[transfer.from_field.int]

    if not (from_balance >= transfer.amount):
      notice "Transfer: source balance too low for amount"
      return false

    if not (from_balance >= transfer.fee):
      notice "Transfer: source balance too low for fee"
      return false

    if not (from_balance == transfer.amount + transfer.fee or from_balance >=
            transfer.amount + transfer.fee + MIN_DEPOSIT_AMOUNT):
      notice "Transfer: source balance too low for amount + fee"
      return false

    if not (state.slot == transfer.slot):
      notice "Transfer: slot mismatch"
      return false

    if not (get_current_epoch(state) >=
        state.validator_registry[transfer.from_field.int].withdrawable_epoch):
      notice "Transfer: epoch mismatch"
      return false

    let wc = state.validator_registry[transfer.from_field.int].
      withdrawal_credentials
    if not (wc.data[0] == BLS_WITHDRAWAL_PREFIX_BYTE and
            wc.data[1..^1] == eth2hash(transfer.pubkey.getBytes).data[1..^1]):
      notice "Transfer: incorrect withdrawal credentials"
      return false

    if skipValidation notin flags:
      let transfer_message = hash_tree_root(
        Transfer(
          from_field: transfer.from_field, to: transfer.to,
          amount: transfer.amount, fee: transfer.fee, slot: transfer.slot,
          signature: EMPTY_SIGNATURE))
      if not bls_verify(
          pubkey=transfer.pubkey, transfer_message, transfer.signature,
          get_domain(state.fork, slot_to_epoch(transfer.slot), DOMAIN_TRANSFER)):
        notice "Transfer: incorrect signature"
        return false

    reduce_balance(
      state.validator_balances[transfer.from_field.int],
      transfer.amount + transfer.fee)
    state.validator_balances[transfer.to.int] += transfer.amount
    state.validator_balances[
      get_beacon_proposer_index(state, state.slot)] += transfer.fee

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.2.0/specs/core/0_beacon-chain.md#per-slot-processing
func processSlot(state: var BeaconState, previous_block_root: Eth2Digest) =
  ## Time on the beacon chain moves in slots. Every time we make it to a new
  ## slot, a proposer creates a block to represent the state of the beacon
  ## chain at that time. In case the proposer is missing, it may happen that
  ## the no block is produced during the slot.

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#slot
  state.slot += 1

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#block-roots
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

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#slot-1
  if not (blck.slot == state.slot):
    notice "Unexpected block slot number",
      blockSlot = humaneSlotNum(blck.slot),
      stateSlot = humaneSlotNum(state.slot)
    return false

  # Spec does not have this check explicitly, but requires that this condition
  # holds - so we give verify it as well - this would happen naturally if
  # `blck.parent_root` was used in `processSlot` - but that doesn't cut it for
  # blockless slot processing.
  let stateParentRoot =
    state.latest_block_roots[(state.slot - 1) mod LATEST_BLOCK_ROOTS_LENGTH]
  if not (blck.parent_root == stateParentRoot):
    notice "Unexpected parent root",
      blockParentRoot = blck.parent_root,
      stateParentRoot
    return false

  if skipValidation notin flags:
    # TODO Technically, we could make processBlock take a generic type instead
    #      of BeaconBlock - we would then have an intermediate `ProposedBlock`
    #      type that omits some fields - this way, the compiler would guarantee
    #      that we don't try to access fields that don't have a value yet
    if not verifyProposerSignature(state, blck):
      notice "Proposer signature not valid", slot = humaneSlotNum(state.slot)
      return false

  if not processRandao(state, blck, flags):
    return false

  processDepositRoot(state, blck)

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

func get_attester_indices(
    state: BeaconState,
    attestations: openArray[PendingAttestation]): seq[ValidatorIndex] =
  # Union of attesters that participated in some attestations
  # TODO spec - add as helper?
  attestations.
    mapIt(
      get_attestation_participants(state, it.data, it.aggregation_bitfield)).
    flatten().
    deduplicate()

func boundary_attestations(
    state: BeaconState, boundary_hash: Eth2Digest,
    attestations: openArray[PendingAttestation]
    ): seq[PendingAttestation] =
  # TODO spec - add as helper?
  attestations.filterIt(it.data.epoch_boundary_root == boundary_hash)

func lowerThan(candidate, current: Eth2Digest): bool =
  # return true iff candidate is "lower" than current, per spec rule:
  # "ties broken by favoring lower `shard_block_root` values"
  # TODO spec - clarify hash ordering..
  for i, v in current.data:
    if v > candidate.data[i]: return true
  false

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#validator-registry-and-shuffling-seed-data
func process_slashings(state: var BeaconState) =
  ## Process the slashings.
  ## Note that this function mutates ``state``.
  let
    current_epoch = get_current_epoch(state)
    active_validator_indices = get_active_validator_indices(
      state.validator_registry, current_epoch)
    # TODO 0.3.0 spec doesn't use this helper function?
    total_balance = get_total_balance(state, active_validator_indices)

  for index, validator in state.validator_registry:
    if current_epoch ==
        validator.slashed_epoch + LATEST_SLASHED_EXIT_LENGTH div 2:
      let
        epoch_index = current_epoch mod LATEST_SLASHED_EXIT_LENGTH
        total_at_start = state.latest_slashed_balances[
          (epoch_index + 1) mod LATEST_SLASHED_EXIT_LENGTH]
        total_at_end = state.latest_slashed_balances[epoch_index]
        total_penalties = total_at_end - total_at_start
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
    if validator.withdrawable_epoch < FAR_FUTURE_EPOCH:
      return false
    # Dequeue if the minimum amount of time has passed
    else:
      return get_current_epoch(state) >= validator.exit_epoch +
        # TODO in future versions, remove workaround for 0.3.0 spec bug
        # but for 0.3.0 use MIN_VALIDATOR_WITHDRAWAL_DELAY constant
        MIN_VALIDATOR_WITHDRAWAL_DELAY

    # TODO try again with filterIt
    var eligible_indices: seq[ValidatorIndex]
    for vi in 0 ..< len(state.validator_registry):
      if eligible(vi.ValidatorIndex):
        eligible_indices.add vi.ValidatorIndex
    let
      # Sort in order of exit epoch, and validators that exit within the same
      # epoch exit in order of validator index
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#per-epoch-processing
func processEpoch(state: var BeaconState) =
  if (state.slot + 1) mod SLOTS_PER_EPOCH != 0:
    return

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#helper-variables
  let
    current_epoch = get_current_epoch(state)
    previous_epoch =
      if current_epoch > GENESIS_EPOCH:
        current_epoch - 1
      else:
        current_epoch
    next_epoch = (current_epoch + 1).Epoch

    active_validator_indices =
      get_active_validator_indices(state.validator_registry, current_epoch)

    current_total_balance =
      get_total_balance(state, active_validator_indices)

    # TODO doing this with iterators failed:
    #      https://github.com/nim-lang/Nim/issues/9827
    current_epoch_attestations =
      state.latest_attestations.filterIt(
        current_epoch == slot_to_epoch(it.data.slot))

    current_epoch_boundary_attestations =
      boundary_attestations(
        state, get_block_root(state, get_epoch_start_slot(current_epoch)),
        current_epoch_attestations)

    current_epoch_boundary_attester_indices =
      get_attester_indices(state, current_epoch_boundary_attestations)

    current_epoch_boundary_attesting_balance =
      get_total_balance(state, current_epoch_boundary_attester_indices)

  # Validators attesting during the previous epoch

  ## Validators that made an attestation during the previous epoch, targeting
  ## the previous justified slot
  let
    previous_total_balance = get_total_balance(
      state, get_active_validator_indices(
        state.validator_registry, previous_epoch))

    previous_epoch_attestations =
      state.latest_attestations.filterIt(
        previous_epoch == slot_to_epoch(it.data.slot))

    previous_epoch_attester_indices =
      toSet(get_attester_indices(state, previous_epoch_attestations))

    previous_epoch_attesting_balance =
      get_total_balance(state, previous_epoch_attester_indices)

  ## Validators justifying the epoch boundary block at the start of the
  ## previous epoch
  let
    previous_epoch_boundary_attestations =
      boundary_attestations(
        state, get_block_root(state, get_epoch_start_slot(previous_epoch)),
        previous_epoch_attestations)

    previous_epoch_boundary_attester_indices =
      toSet(get_attester_indices(state, previous_epoch_boundary_attestations))

    previous_epoch_boundary_attesting_balance =
      get_total_balance(state, previous_epoch_boundary_attester_indices)

  ## Validators attesting to the expected beacon chain head during the
  ## previous epoch
  let
    previous_epoch_head_attestations =
      previous_epoch_attestations.filterIt(
        it.data.beacon_block_root == get_block_root(state, it.data.slot))

    previous_epoch_head_attester_indices =
      toSet(get_attester_indices(state, previous_epoch_head_attestations))

    previous_epoch_head_attesting_balance =
      get_total_balance(state, previous_epoch_head_attester_indices)

  # TODO this is really hairy - we cannot capture `state` directly, but we
  #      can capture a pointer to it - this is safe because we don't leak
  #      these closures outside this scope, but still..
  let statePtr = state.addr
  func attesting_validator_indices(
      crosslink_committee: CrosslinkCommittee, shard_block_root: Eth2Digest): seq[ValidatorIndex] =
    let shard_block_attestations =
      concat(current_epoch_attestations, previous_epoch_attestations).
      filterIt(it.data.shard == crosslink_committee.shard and
        it.data.shard_block_root == shard_block_root)
    get_attester_indices(statePtr[], shard_block_attestations)

  func winning_root(crosslink_committee: CrosslinkCommittee): Eth2Digest =
    # * Let `winning_root(crosslink_committee)` be equal to the value of
    #   `shard_block_root` such that
    #   `sum([get_effective_balance(state, i) for i in attesting_validator_indices(crosslink_committee, shard_block_root)])`
    #   is maximized (ties broken by favoring lower `shard_block_root` values).
    let candidates =
      concat(current_epoch_attestations, previous_epoch_attestations).
        filterIt(it.data.shard == crosslink_committee.shard).
        mapIt(it.data.shard_block_root)

    # TODO not covered by spec!
    if candidates.len == 0:
      return

    var max_hash = candidates[0]
    var max_val =
      get_total_balance(
        statePtr[], attesting_validator_indices(crosslink_committee, max_hash))
    for candidate in candidates[1..^1]:
      let val = get_total_balance(
        statePtr[], attesting_validator_indices(crosslink_committee, candidate))
      if val > max_val or (val == max_val and candidate.lowerThan(max_hash)):
        max_hash = candidate
        max_val = val
    max_hash

  func attesting_validators(crosslink_committee: CrosslinkCommittee): seq[ValidatorIndex] =
    attesting_validator_indices(crosslink_committee, winning_root(crosslink_committee))

  func attesting_validator_indices(crosslink_committee: CrosslinkCommittee): seq[ValidatorIndex] =
    attesting_validator_indices(crosslink_committee, winning_root(crosslink_committee))

  func total_attesting_balance(crosslink_committee: CrosslinkCommittee): uint64 =
    get_total_balance(
      statePtr[], attesting_validator_indices(crosslink_committee))

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#eth1-data-1
  block:
    if next_epoch mod EPOCHS_PER_ETH1_VOTING_PERIOD == 0:
      for x in state.eth1_data_votes:
        if x.vote_count * 2 >= EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH:
          # more than half the votes in this voting period were for that value
          state.latest_eth1_data = x.eth1_data
          break
      state.eth1_data_votes = @[]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#justification
  block:
    # First, update the justification bitfield
    var new_justified_epoch = state.justified_epoch
    state.justification_bitfield = state.justification_bitfield shl 1
    if 3'u64 * previous_epoch_boundary_attesting_balance >= 2'u64 * previous_total_balance:
      state.justification_bitfield = state.justification_bitfield or 2
      new_justified_epoch = previous_epoch
    if 3'u64 * current_epoch_boundary_attesting_balance >= 2'u64 * current_total_balance:
      state.justification_bitfield = state.justification_bitfield or 1
      new_justified_epoch = current_epoch

    # Next, update last finalized epoch if possible
    if (state.justification_bitfield shr 1) mod 8 == 0b111 and state.previous_justified_epoch == previous_epoch - 2:
      state.finalized_epoch = state.previous_justified_epoch
    if (state.justification_bitfield shr 1) mod 4 == 0b11 and state.previous_justified_epoch == previous_epoch - 1:
      state.finalized_epoch = state.previous_justified_epoch
    if (state.justification_bitfield shr 0) mod 8 == 0b111 and state.justified_epoch == previous_epoch - 1:
      state.finalized_epoch = state.justified_epoch
    if (state.justification_bitfield shr 0) mod 4 == 0b11 and state.justified_epoch == previous_epoch:
      state.finalized_epoch = state.justified_epoch

    # Finally, update the following
    state.previous_justified_epoch = state.justified_epoch
    state.justified_epoch = new_justified_epoch

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#crosslinks
  block:
    for slot in get_epoch_start_slot(previous_epoch) ..< get_epoch_start_slot(next_epoch):
      let crosslink_committees_at_slot = get_crosslink_committees_at_slot(state, slot)

      for crosslink_committee in crosslink_committees_at_slot:
        if 3'u64 * total_attesting_balance(crosslink_committee) >=
            2'u64 * get_total_balance(state, crosslink_committee.committee):
          state.latest_crosslinks[crosslink_committee.shard] = Crosslink(
            epoch: slot_to_epoch(slot),
            shard_block_root: winning_root(crosslink_committee))

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#rewards-and-penalties
  ## First, we define some additional helpers
  ## Note: When applying penalties in the following balance recalculations
  ## implementers should make sure the uint64 does not underflow
  let base_reward_quotient =
    integer_squareroot(previous_total_balance) div BASE_REWARD_QUOTIENT

  func base_reward(state: BeaconState, index: ValidatorIndex): uint64 =
    get_effective_balance(state, index) div base_reward_quotient.uint64 div 5

  func inactivity_penalty(
      state: BeaconState, index: ValidatorIndex, epochs_since_finality: uint64): uint64 =
    base_reward(state, index) +
      get_effective_balance(state, index) * epochs_since_finality div
      INACTIVITY_PENALTY_QUOTIENT div 2

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#justification-and-finalization
  ## TODO remove inclusion_{slot,distance} when fully replaced, but note
  ## intentional absence, for spec sync purposes. Both positively invite
  ## quadratic behavior.
  func inclusion_slot(state: BeaconState, v: ValidatorIndex): uint64 =
    for a in previous_epoch_attestations:
      if v in get_attestation_participants(state, a.data, a.aggregation_bitfield):
        return a.inclusion_slot
    doAssert false

  func inclusion_distance(state: BeaconState, v: ValidatorIndex): uint64 =
    for a in previous_epoch_attestations:
      if v in get_attestation_participants(state, a.data, a.aggregation_bitfield):
        return a.inclusion_slot - a.data.slot
    doAssert false

  func inclusion_distances(state: BeaconState): auto =
    result = initTable[ValidatorIndex, uint64]()

    for a in previous_epoch_attestations:
      for v in get_attestation_participants(
          state, a.data, a.aggregation_bitfield):
        if v notin result:
          result[v] = a.inclusion_slot - a.data.slot

  block: # Justification and finalization
    let
      epochs_since_finality = next_epoch - state.finalized_epoch

    proc update_balance(attesters: HashSet[ValidatorIndex], attesting_balance: uint64) =
      # TODO Spec - add helper?
      for v in attesters:
        statePtr.validator_balances[v] +=
          base_reward(statePtr[], v) *
          attesting_balance div previous_total_balance

      for v in active_validator_indices:
        if v notin attesters:
          reduce_balance(
            statePtr.validator_balances[v], base_reward(statePtr[], v))

    if epochs_since_finality <= 4'u64:
      # Case 1: epochs_since_finality <= 4
      # Expected FFG source
      update_balance(
        previous_epoch_attester_indices,
        previous_epoch_attesting_balance)

      # Expected FFG target:
      update_balance(
        previous_epoch_boundary_attester_indices,
        previous_epoch_boundary_attesting_balance)

      # Expected beacon chain head:
      update_balance(
        previous_epoch_head_attester_indices,
        previous_epoch_head_attesting_balance)

      # Inclusion distance
      let distances = inclusion_distances(state)

      for v in previous_epoch_attester_indices:
        statePtr.validator_balances[v] +=
          base_reward(state, v) *
          MIN_ATTESTATION_INCLUSION_DELAY div distances[v]
        when false:
          doAssert inclusion_distance(state, v) == distances[v]

    else:
      # Case 2: epochs_since_finality > 4
      let distances =
        if previous_epoch_attester_indices.len > 0:
          inclusion_distances(state)
        else:
          ## Last case will not occur. If this assumption becomes false,
          ## indexing into distances will fail.
          initTable[ValidatorIndex, uint64]()

      for index in active_validator_indices:
        if index notin previous_epoch_attester_indices:
          reduce_balance(
            state.validator_balances[index],
            inactivity_penalty(state, index, epochs_since_finality))
        if index notin previous_epoch_boundary_attester_indices:
          reduce_balance(
            state.validator_balances[index],
            inactivity_penalty(state, index, epochs_since_finality))
        if index notin previous_epoch_head_attester_indices:
          reduce_balance(
            state.validator_balances[index], base_reward(state, index))
        if state.validator_registry[index].slashed_epoch <= current_epoch:
          reduce_balance(
            state.validator_balances[index],
            2'u64 * inactivity_penalty(
              state, index, epochs_since_finality) + base_reward(state, index))
        if index in previous_epoch_attester_indices:
          reduce_balance(
            state.validator_balances[index],
            base_reward(state, index) -
            base_reward(state, index) * MIN_ATTESTATION_INCLUSION_DELAY div
            distances[index])
          when false:
            doAssert inclusion_distance(state, index) == distances[index]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#attestation-inclusion
  block:
    ## Minimally transform spec algorithm into something non-quadratic, while
    ## retaining enough resemblance to both verify equivalence and update, if
    ## it changes. inclusion_slot iterates across previous_epoch_attestations
    ## until it finds the attester index `v` represented. Instead construct a
    ## (reverse) index based on one O(n) scan of previous_epoch_attestations,
    ## then perform O(n) O(1) lookups. Keep same iteration order and rules in
    ## which first match wins and terminates for each ValidatorIndex.
    var proposer_indexes = initTable[ValidatorIndex, uint64]()

    # This is the loop from inclusion_slot(...)
    for a in previous_epoch_attestations:
      for v in get_attestation_participants(
          state, a.data, a.aggregation_bitfield):
        ## Here, though, collect all results (but only, though it shouldn't
        ## happen regardless, the first proposer index per ValidatorIndex),
        ## which avoids the quadratic behavior.
        if v notin proposer_indexes:
          proposer_indexes[v] = a.inclusion_slot

    for v in previous_epoch_attester_indices:
      ## inclusion_slot(...) doAsserts false if it doesn't find anything, so
      ## equivalently, simply look up table element, intentionally fragilely
      ## such that a useful stack trace is produced.
      let proposer_index =
        get_beacon_proposer_index(state, proposer_indexes[v])

      # Ensure this keeps getting compiled to some extent to help compare.
      when false:
        let proposer_index_slow =
          get_beacon_proposer_index(state, inclusion_slot(state, v))
        doAssert proposer_index == proposer_index_slow

      state.validator_balances[proposer_index] +=
        base_reward(state, v) div ATTESTATION_INCLUSION_REWARD_QUOTIENT

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#crosslinks-1
  block:
    for slot in get_epoch_start_slot(previous_epoch) ..< get_epoch_start_slot(current_epoch):
      let crosslink_committees_at_slot = get_crosslink_committees_at_slot(state, slot)
      for crosslink_committee in crosslink_committees_at_slot:
        let
          committee_attesting_validators =
            toSet(attesting_validators(crosslink_committee))
          ## Keep numerator and denominator separate to allow different
          ## orders of operation to keep exact equivalence. TODO, check
          ## spec to see if this kind of fragility is in spec. Wouldn't
          ## be great to depend on whether integer (a*b)/c or a*(b/c)'s
          ## being performed.
          committee_attesting_balance =
            total_attesting_balance(crosslink_committee)
          committee_total_balance =
            get_total_balance(state, crosslink_committee.committee)
        for index in crosslink_committee.committee:
          if index in committee_attesting_validators:
            state.validator_balances[index.int] +=
              base_reward(state, index) * committee_attesting_balance div
                committee_total_balance
          else:
            reduce_balance(
              state.validator_balances[index], base_reward(state, index))

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#ejections
  process_ejections(state, active_validator_indices)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#validator-registry-and-shuffling-seed-data
  block:
    state.previous_shuffling_epoch = state.current_shuffling_epoch
    state.previous_shuffling_start_shard = state.current_shuffling_start_shard
    state.previous_shuffling_seed = state.current_shuffling_seed

    if state.finalized_epoch > state.validator_registry_update_epoch and
       allIt(
         0 ..< get_current_epoch_committee_count(state).int,
         state.latest_crosslinks[
           (state.current_shuffling_start_shard + it.uint64) mod
             SHARD_COUNT].epoch > state.validator_registry_update_epoch):

      # update the validator registry and associated fields by running
      update_validator_registry(state)

      # and perform the following updates
      state.current_shuffling_epoch = next_epoch
      state.current_shuffling_start_shard =
        (state.current_shuffling_start_shard +
          get_current_epoch_committee_count(state)) mod SHARD_COUNT
      state.current_shuffling_seed = generate_seed(
        state, state.current_shuffling_epoch)
    else:
      # If a validator registry change does NOT happen
      let epochs_since_last_registry_update =
        current_epoch - state.validator_registry_update_epoch
      if epochs_since_last_registry_update > 1'u64 and
          is_power_of_2(epochs_since_last_registry_update):
        state.current_shuffling_epoch = next_epoch
        state.current_shuffling_seed = generate_seed(state, state.current_shuffling_epoch)
        # /Note/ that state.current_shuffling_start_shard is left unchanged

  updateShufflingCache(state)

  ## Regardless of whether or not a validator set change happens run
  ## process_slashings(state) and process_exit_queue(state)
  process_slashings(state)
  process_exit_queue(state)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#final-updates
  block:
    state.latest_active_index_roots[
      (next_epoch + ACTIVATION_EXIT_DELAY) mod
      LATEST_ACTIVE_INDEX_ROOTS_LENGTH] =
      Eth2Digest(data: hash_tree_root(get_active_validator_indices(
        # TODO 0.3.0 spec here has bug: get_active_validator_indices(state, ...)
        state.validator_registry, next_epoch + ACTIVATION_EXIT_DELAY)))
    state.latest_slashed_balances[(next_epoch mod
      LATEST_SLASHED_EXIT_LENGTH).int] =
      state.latest_slashed_balances[
        (current_epoch mod LATEST_SLASHED_EXIT_LENGTH).int]
    state.latest_randao_mixes[next_epoch mod LATEST_RANDAO_MIXES_LENGTH] =
      get_randao_mix(state, current_epoch)
    state.latest_attestations.keepItIf(
      not (slot_to_epoch(it.data.slot) < current_epoch)
    )

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/core/0_beacon-chain.md#state-root-verification
proc verifyStateRoot(state: BeaconState, blck: BeaconBlock): bool =
  let state_root = hash_tree_root_final(state)
  if state_root != blck.state_root:
    notice "Block: root verification failed",
      block_state_root = blck.state_root, state_root
    false
  else:
    true

proc updateState*(state: var BeaconState, previous_block_root: Eth2Digest,
    new_block: Option[BeaconBlock], flags: UpdateFlags): bool =
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
  var old_state = state

  # Per-slot updates - these happen regardless if there is a block or not
  processSlot(state, previous_block_root)

  if new_block.isSome():
    # Block updates - these happen when there's a new block being suggested
    # by the block proposer. Every actor in the network will update its state
    # according to the contents of this block - but first they will validate
    # that the block is sane.
    # TODO what should happen if block processing fails?
    #      https://github.com/ethereum/eth2.0-specs/issues/293
    if processBlock(state, new_block.get(), flags):
      # Block ok so far, proceed with state update
      processEpoch(state)

      # This is a bit awkward - at the end of processing we verify that the
      # state we arrive at is what the block producer thought it would be -
      # meaning that potentially, it could fail verification
      if skipValidation in flags or verifyStateRoot(state, new_block.get()):
        # State root is what it should be - we're done!
        return true

    # Block processing failed, have to start over
    state = old_state
    processSlot(state, previous_block_root)
    processEpoch(state)
    false
  else:
    # Skip all per-block processing. Move directly to epoch processing
    # prison. Do not do any block updates when passing go.

    # Heavy updates that happen for every epoch - these never fail (or so we hope)
    processEpoch(state)
    true

proc skipSlots*(state: var BeaconState, parentRoot: Eth2Digest, slot: Slot) =
  if state.slot < slot:
    info "Advancing state past slot gap",
      targetSlot = humaneSlotNum(slot),
      stateSlot = humaneSlotNum(state.slot)

    while state.slot < slot:
      let ok = updateState(state, parentRoot, none[BeaconBlock](), {})
      doAssert ok, "Empty block state update should never fail!"

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
