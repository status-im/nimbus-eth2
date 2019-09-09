# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition - block processing, as described in
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
#
# The purpose of this code right is primarily educational, to help piece
# together the mechanics of the beacon state and to discover potential problem
# areas.
#
# The entry point is `process_block` which is at the bottom of this file.
#
# General notes about the code (TODO):
# * It's inefficient - we quadratically copy, allocate and iterate when there
#   are faster options
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * We mix procedural and functional styles for no good reason, except that the
#   spec does so also.
# * There are likely lots of bugs.
# * For indices, we get a mix of uint64, ValidatorIndex and int - this is currently
#   swept under the rug with casts
# * The spec uses uint64 for data types, but functions in the spec often assume
#   signed bigint semantics - under- and overflows ensue
# * Sane error handling is missing in most cases (yay, we'll get the chance to
#   debate exceptions again!)
# When updating the code, add TODO sections to mark where there are clear
# improvements to be made - other than that, keep things similar to spec for
# now.

import # TODO - cleanup imports
  algorithm, collections/sets, chronicles, math, options, sequtils, sets, tables,
  ../extras, ../ssz, ../beacon_node_types,
  beaconstate, crypto, datatypes, digest, helpers, validator

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#block-header
proc process_block_header*(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags,
    stateCache: var StateCache): bool =
  # Verify that the slots match
  if not (blck.slot == state.slot):
    notice "Block header: slot mismatch",
      block_slot = shortLog(blck.slot),
      state_slot = shortLog(state.slot)
    return false

  # Verify that the parent matches
  if skipValidation notin flags and not (blck.parent_root ==
      signing_root(state.latest_block_header)):
    notice "Block header: previous block root mismatch",
      latest_block_header = state.latest_block_header,
      blck = shortLog(blck),
      latest_block_header_root = shortLog(signing_root(state.latest_block_header))
    return false

  # Save current block as the new latest block
  state.latest_block_header = BeaconBlockHeader(
    slot: blck.slot,
    parent_root: blck.parent_root,
    # state_root: zeroed, overwritten in the next `process_slot` call
    body_root: hash_tree_root(blck.body),
    # signature is always zeroed
    # TODO - Pure BLSSig cannot be zero: https://github.com/status-im/nim-beacon-chain/issues/374
    signature: BlsValue[Signature](kind: OpaqueBlob)
  )


  # Verify proposer is not slashed
  let proposer =
    state.validators[get_beacon_proposer_index(state, stateCache)]
  if proposer.slashed:
    notice "Block header: proposer slashed"
    return false

  # Verify proposer signature
  if skipValidation notin flags and not bls_verify(
      proposer.pubkey,
      signing_root(blck).data,
      blck.signature,
      get_domain(state, DOMAIN_BEACON_PROPOSER)):
    notice "Block header: invalid block header",
      proposer_pubkey = proposer.pubkey,
      block_root = shortLog(signing_root(blck)),
      block_signature = blck.signature
    return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#randao
proc process_randao(
    state: var BeaconState, body: BeaconBlockBody, flags: UpdateFlags,
    stateCache: var StateCache): bool =
  let
    epoch = state.get_current_epoch()
    proposer_index = get_beacon_proposer_index(state, stateCache)
    proposer = addr state.validators[proposer_index]

  # Verify that the provided randao value is valid
  if skipValidation notin flags:
    if not bls_verify(
      proposer.pubkey,
      hash_tree_root(epoch.uint64).data,
      body.randao_reveal,
      get_domain(state, DOMAIN_RANDAO)):

      notice "Randao mismatch", proposer_pubkey = proposer.pubkey,
                                message = epoch,
                                signature = body.randao_reveal,
                                slot = state.slot
      return false

  # Mix it in
  let
    mix = get_randao_mix(state, epoch)
    rr = eth2hash(body.randao_reveal.getBytes()).data

  for i in 0 ..< mix.data.len:
    state.randao_mixes[epoch mod EPOCHS_PER_HISTORICAL_VECTOR].data[i] = mix.data[i] xor rr[i]

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#eth1-data
func processEth1Data(state: var BeaconState, body: BeaconBlockBody) =
  state.eth1_data_votes.add body.eth1_data
  if state.eth1_data_votes.count(body.eth1_data) * 2 >
      SLOTS_PER_ETH1_VOTING_PERIOD:
    state.eth1_data = body.eth1_data

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#is_slashable_validator
func is_slashable_validator(validator: Validator, epoch: Epoch): bool =
  # Check if ``validator`` is slashable.
  (not validator.slashed) and
    (validator.activation_epoch <= epoch) and
    (epoch < validator.withdrawable_epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#proposer-slashings
proc processProposerSlashings(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags,
    stateCache: var StateCache): bool =
  if len(blck.body.proposer_slashings) > MAX_PROPOSER_SLASHINGS:
    notice "PropSlash: too many!",
      proposer_slashings = len(blck.body.proposer_slashings)
    return false

  for proposer_slashing in blck.body.proposer_slashings:
    let proposer = state.validators[proposer_slashing.proposer_index.int]

    # Verify that the epoch is the same
    if not (compute_epoch_of_slot(proposer_slashing.header_1.slot) ==
        compute_epoch_of_slot(proposer_slashing.header_2.slot)):
      notice "PropSlash: epoch mismatch"
      return false

    # But the headers are different
    if not (proposer_slashing.header_1 != proposer_slashing.header_2):
      notice "PropSlash: headers not different"
      return false

    # Check proposer is slashable
    if not is_slashable_validator(proposer, get_current_epoch(state)):
      notice "PropSlash: slashed proposer"
      return false

    # Signatures are valid
    if skipValidation notin flags:
      for i, header in @[proposer_slashing.header_1, proposer_slashing.header_2]:
        if not bls_verify(
            proposer.pubkey,
            signing_root(header).data,
            header.signature,
            get_domain(
              state, DOMAIN_BEACON_PROPOSER, compute_epoch_of_slot(header.slot))):
          notice "PropSlash: invalid signature",
            signature_index = i
          return false

    slashValidator(
      state, proposer_slashing.proposer_index.ValidatorIndex, stateCache)

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#is_slashable_attestation_data
func is_slashable_attestation_data(
    data_1: AttestationData, data_2: AttestationData): bool =
  ## Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG
  ## rules.

  # Double vote
  (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
  # Surround vote
    (data_1.source.epoch < data_2.source.epoch and
     data_2.target.epoch < data_1.target.epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#attester-slashings
proc processAttesterSlashings(state: var BeaconState, blck: BeaconBlock,
    stateCache: var StateCache): bool =
  # Process ``AttesterSlashing`` operation.
  if len(blck.body.attester_slashings) > MAX_ATTESTER_SLASHINGS:
    notice "CaspSlash: too many!"
    return false

  result = true
  for attester_slashing in blck.body.attester_slashings:
    let
      attestation_1 = attester_slashing.attestation_1
      attestation_2 = attester_slashing.attestation_2

    if not is_slashable_attestation_data(
        attestation_1.data, attestation_2.data):
      notice "CaspSlash: surround or double vote check failed"
      return false

    if not is_valid_indexed_attestation(state, attestation_1):
      notice "CaspSlash: invalid votes 1"
      return false

    if not is_valid_indexed_attestation(state, attestation_2):
      notice "CaspSlash: invalid votes 2"
      return false

    var slashed_any = false

    ## TODO there's a lot of sorting/set construction here and
    ## verify_indexed_attestation, but go by spec unless there
    ## is compelling perf evidence otherwise.
    let attesting_indices_1 =
      attestation_1.custody_bit_0_indices & attestation_1.custody_bit_1_indices
    let attesting_indices_2 =
      attestation_2.custody_bit_0_indices & attestation_2.custody_bit_1_indices
    for index in sorted(toSeq(intersection(toSet(attesting_indices_1),
        toSet(attesting_indices_2)).items), system.cmp):
      if is_slashable_validator(state.validators[index.int],
          get_current_epoch(state)):
        slash_validator(state, index.ValidatorIndex, stateCache)
        slashed_any = true
    result = result and slashed_any

func get_attesting_indices(
    state: BeaconState, attestations: openarray[PendingAttestation],
    stateCache: var StateCache): HashSet[ValidatorIndex] =
  result = initSet[ValidatorIndex]()
  for a in attestations:
    result = result.union(get_attesting_indices(
      state, a.data, a.aggregation_bits, stateCache))

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#attestations
proc processAttestations*(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags,
    stateCache: var StateCache): bool =
  ## Each block includes a number of attestations that the proposer chose. Each
  ## attestation represents an update to a specific shard and is signed by a
  ## committee of validators.
  ## Here we make sanity checks for each attestation and it to the state - most
  ## updates will happen at the epoch boundary where state updates happen in
  ## bulk.
  if blck.body.attestations.len > MAX_ATTESTATIONS:
    notice "Attestation: too many!", attestations = blck.body.attestations.len
    return false

  trace "in processAttestations, not processed attestations",
    attestations_len = blck.body.attestations.len()

  if not blck.body.attestations.allIt(process_attestation(state, it, flags, stateCache)):
    return false

  # All checks passed - update state
  # Apply the attestations
  var committee_count_cache = initTable[Epoch, uint64]()

  trace "in processAttestations, has processed attestations",
    attestations_len = blck.body.attestations.len()

  var cache = get_empty_per_epoch_cache()

  for attestation in blck.body.attestations:
    # Caching
    let
      epoch = attestation.data.target.epoch
      committee_count = if epoch in committee_count_cache:
          committee_count_cache[epoch]
        else:
          get_committee_count(state, epoch)
    committee_count_cache[epoch] = committee_count

    # Spec content
    let attestation_slot =
      get_attestation_data_slot(state, attestation.data, committee_count)
    let pending_attestation = PendingAttestation(
      data: attestation.data,
      aggregation_bits: attestation.aggregation_bits,
      inclusion_delay: state.slot - attestation_slot,
      proposer_index: get_beacon_proposer_index(state, stateCache),
    )

    if attestation.data.target.epoch == get_current_epoch(state):
      state.current_epoch_attestations.add(pending_attestation)
    else:
      state.previous_epoch_attestations.add(pending_attestation)

    trace "processAttestations",
      target_epoch=attestation.data.target.epoch,
      current_epoch= get_current_epoch(state),
      current_epoch_attestations_len=len(get_attesting_indices(state, state.current_epoch_attestations, cache)),
      previous_epoch_attestations_len=len(get_attesting_indices(state, state.previous_epoch_attestations, cache)),
      prev_unslashed_attesting_indices=get_unslashed_attesting_indices(state, state.previous_epoch_attestations, cache),
      cur_unslashed_attesting_indices=get_unslashed_attesting_indices(state, state.current_epoch_attestations, cache),
      prev_attesting_indices=get_attesting_indices(state, state.previous_epoch_attestations, cache),
      cur_attesting_indices=get_attesting_indices(state, state.current_epoch_attestations, cache),
      new_attestation_indices=get_attesting_indices(state, attestation.data, attestation.aggregation_bits, cache)

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

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#voluntary-exits
proc processVoluntaryExits(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  # Process ``VoluntaryExit`` transaction.
  if len(blck.body.voluntary_exits) > MAX_VOLUNTARY_EXITS:
    notice "Exit: too many!"
    return false

  for exit in blck.body.voluntary_exits:
    let validator = state.validators[exit.validator_index.int]

    # Verify the validator is active
    if not is_active_validator(validator, get_current_epoch(state)):
      notice "Exit: validator not active"
      return false

    # Verify the validator has not yet exited
    if not (validator.exit_epoch == FAR_FUTURE_EPOCH):
      notice "Exit: validator has exited"
      return false

    ## Exits must specify an epoch when they become valid; they are not valid
    ## before then
    if not (get_current_epoch(state) >= exit.epoch):
      notice "Exit: exit epoch not passed"
      return false

    # Verify the validator has been active long enough
    # TODO detect underflow
    if not (get_current_epoch(state) - validator.activation_epoch >=
        PERSISTENT_COMMITTEE_PERIOD):
      notice "Exit: not in validator set long enough"
      return false

    # Verify signature
    if skipValidation notin flags:
      if not bls_verify(
          validator.pubkey, signing_root(exit).data, exit.signature,
          get_domain(state, DOMAIN_VOLUNTARY_EXIT, exit.epoch)):
        notice "Exit: invalid signature"
        return false

    # Initiate exit
    initiate_validator_exit(state, exit.validator_index.ValidatorIndex)

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#transfers
proc processTransfers(state: var BeaconState, blck: BeaconBlock,
                      flags: UpdateFlags, stateCache: var StateCache): bool =
  if not (len(blck.body.transfers) <= MAX_TRANSFERS):
    notice "Transfer: too many transfers"
    return false

  for transfer in blck.body.transfers:
    let sender_balance = state.balances[transfer.sender.int]

    ## Verify the amount and fee are not individually too big (for anti-overflow
    ## purposes)
    if not (sender_balance >= max(transfer.amount, transfer.fee)):
      notice "Transfer: sender balance too low for transfer amount or fee"
      return false

    # A transfer is valid in only one slot
    if not (state.slot == transfer.slot):
      notice "Transfer: slot mismatch"
      return false

    ## Sender must be not yet eligible for activation, withdrawn, or transfer
    ## balance over MAX_EFFECTIVE_BALANCE
    if not (
      state.validators[transfer.sender.int].activation_epoch ==
        FAR_FUTURE_EPOCH or
      get_current_epoch(state) >=
        state.validators[
          transfer.sender.int].withdrawable_epoch or
      transfer.amount + transfer.fee + MAX_EFFECTIVE_BALANCE <=
        state.balances[transfer.sender.int]):
      notice "Transfer: only withdrawn or not-activated accounts with sufficient balance can transfer"
      return false

    # Verify that the pubkey is valid
    let wc = state.validators[transfer.sender.int].
      withdrawal_credentials
    if not (wc.data[0] == BLS_WITHDRAWAL_PREFIX and
            wc.data[1..^1] == eth2hash(transfer.pubkey.getBytes).data[1..^1]):
      notice "Transfer: incorrect withdrawal credentials"
      return false

    # Verify that the signature is valid
    if skipValidation notin flags:
      if not bls_verify(
          transfer.pubkey, signing_root(transfer).data, transfer.signature,
          get_domain(state, DOMAIN_TRANSFER)):
        notice "Transfer: incorrect signature"
        return false

    # Process the transfer
    decrease_balance(
      state, transfer.sender.ValidatorIndex, transfer.amount + transfer.fee)
    increase_balance(
      state, transfer.recipient.ValidatorIndex, transfer.amount)
    increase_balance(
      state, get_beacon_proposer_index(state, stateCache), transfer.fee)

    # Verify balances are not dust
    if not (
        0'u64 < state.balances[transfer.sender.int] and
        state.balances[transfer.sender.int] < MIN_DEPOSIT_AMOUNT):
      notice "Transfer: sender balance too low for transfer amount or fee"
      return false

    if not (
        0'u64 < state.balances[transfer.recipient.int] and
        state.balances[transfer.recipient.int] < MIN_DEPOSIT_AMOUNT):
      notice "Transfer: sender balance too low for transfer amount or fee"
      return false

  true


proc processBlock*(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags,
    stateCache: var StateCache): bool =
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly

  # TODO when there's a failure, we should reset the state!
  # TODO probably better to do all verification first, then apply state changes

  if not process_block_header(state, blck, flags, stateCache):
    notice "Block header not valid", slot = shortLog(state.slot)
    return false

  if not processRandao(state, blck.body, flags, stateCache):
    debug "[Block processing] Randao failure", slot = shortLog(state.slot)
    return false

  processEth1Data(state, blck.body)

  if not processProposerSlashings(state, blck, flags, stateCache):
    debug "[Block processing] Proposer slashing failure", slot = shortLog(state.slot)
    return false

  if not processAttesterSlashings(state, blck, stateCache):
    debug "[Block processing] Attester slashing failure", slot = shortLog(state.slot)
    return false

  if not processAttestations(state, blck, flags, stateCache):
    debug "[Block processing] Attestation processing failure", slot = shortLog(state.slot)
    return false

  if not processDeposits(state, blck):
    debug "[Block processing] Deposit processing failure", slot = shortLog(state.slot)
    return false

  if not processVoluntaryExits(state, blck, flags):
    debug "[Block processing] Exit processing failure", slot = shortLog(state.slot)
    return false

  if not processTransfers(state, blck, flags, stateCache):
    debug "[Block processing] Transfer processing failure", slot = shortLog(state.slot)
    return false

  true
