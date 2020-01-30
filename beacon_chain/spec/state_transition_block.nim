# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
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

import
  algorithm, collections/sets, chronicles, options, sequtils, sets, tables,
  ../extras, ../ssz, metrics,
  beaconstate, crypto, datatypes, digest, helpers, validator,
  ../../nbench/bench_lab

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#additional-metrics
declareGauge beacon_current_live_validators, "Number of active validators that successfully included attestation on chain for current epoch" # On block
declareGauge beacon_previous_live_validators, "Number of active validators that successfully included attestation on chain for previous epoch" # On block
declareGauge beacon_pending_deposits, "Number of pending deposits (state.eth1_data.deposit_count - state.eth1_deposit_index)" # On block
declareGauge beacon_processed_deposits_total, "Number of total deposits included on chain" # On block

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#block-header
proc process_block_header*(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags,
    stateCache: var StateCache): bool {.nbench.}=
  # Verify that the slots match
  if not (blck.slot == state.slot):
    notice "Block header: slot mismatch",
      block_slot = shortLog(blck.slot),
      state_slot = shortLog(state.slot)
    return false

  # Verify that the parent matches
  if skipValidation notin flags and not (blck.parent_root ==
      hash_tree_root(state.latest_block_header)):
    # TODO: skip validation is too strong
    #       can't do "invalid_parent_root" test
    notice "Block header: previous block root mismatch",
      latest_block_header = state.latest_block_header,
      blck = shortLog(blck),
      latest_block_header_root = shortLog(hash_tree_root(state.latest_block_header))
    return false

  # Save current block as the new latest block
  state.latest_block_header = BeaconBlockHeader(
    slot: blck.slot,
    parent_root: blck.parent_root,
    # state_root: zeroed, overwritten in the next `process_slot` call
    body_root: hash_tree_root(blck.body),
  )

  # Verify proposer is not slashed
  let proposer_index = get_beacon_proposer_index(state, stateCache)
  if proposer_index.isNone:
    debug "Block header: proposer missing"
    return false

  let proposer = state.validators[proposer_index.get]
  if proposer.slashed:
    notice "Block header: proposer slashed"
    return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/core/0_beacon-chain.md#randao
proc process_randao(
    state: var BeaconState, body: BeaconBlockBody, flags: UpdateFlags,
    stateCache: var StateCache): bool {.nbench.}=
  let
    epoch = state.get_current_epoch()
    proposer_index = get_beacon_proposer_index(state, stateCache)

  if proposer_index.isNone:
    debug "Proposer index missing, probably along with any active validators"
    return false

  let proposer = addr state.validators[proposer_index.get]

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

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#eth1-data
func process_eth1_data(state: var BeaconState, body: BeaconBlockBody) {.nbench.}=
  state.eth1_data_votes.add body.eth1_data
  if state.eth1_data_votes.count(body.eth1_data) * 2 >
      SLOTS_PER_ETH1_VOTING_PERIOD:
    state.eth1_data = body.eth1_data

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#is_slashable_validator
func is_slashable_validator(validator: Validator, epoch: Epoch): bool =
  # Check if ``validator`` is slashable.
  (not validator.slashed) and
    (validator.activation_epoch <= epoch) and
    (epoch < validator.withdrawable_epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/core/0_beacon-chain.md#proposer-slashings
proc process_proposer_slashing*(
    state: var BeaconState, proposer_slashing: ProposerSlashing,
    flags: UpdateFlags, stateCache: var StateCache): bool {.nbench.}=
  if proposer_slashing.proposer_index.int >= state.validators.len:
    notice "Proposer slashing: invalid proposer index"
    return false

  let proposer = state.validators[proposer_slashing.proposer_index.int]

  # Verify slots match
  if not (proposer_slashing.signed_header_1.message.slot ==
      proposer_slashing.signed_header_2.message.slot):
    notice "Proposer slashing: slot mismatch"
    return false

  # But the headers are different
  if not (proposer_slashing.signed_header_1.message !=
      proposer_slashing.signed_header_2.message):
    notice "Proposer slashing: headers not different"
    return false

  # Check proposer is slashable
  if not is_slashable_validator(proposer, get_current_epoch(state)):
    notice "Proposer slashing: slashed proposer"
    return false

  # Signatures are valid
  if skipValidation notin flags:
    for i, signed_header in [proposer_slashing.signed_header_1,
        proposer_slashing.signed_header_2]:
      if not bls_verify(
          proposer.pubkey,
          hash_tree_root(signed_header.message).data,
          signed_header.signature,
          get_domain(
            state, DOMAIN_BEACON_PROPOSER,
            compute_epoch_at_slot(signed_header.message.slot))):
        notice "Proposer slashing: invalid signature",
          signature_index = i
        return false

  slashValidator(
    state, proposer_slashing.proposer_index.ValidatorIndex, stateCache)

  true

proc processProposerSlashings(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags,
    stateCache: var StateCache): bool {.nbench.}=
  if len(blck.body.proposer_slashings) > MAX_PROPOSER_SLASHINGS:
    notice "PropSlash: too many!",
      proposer_slashings = len(blck.body.proposer_slashings)
    return false

  for proposer_slashing in blck.body.proposer_slashings:
    if not process_proposer_slashing(
        state, proposer_slashing, flags, stateCache):
      return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#is_slashable_attestation_data
func is_slashable_attestation_data(
    data_1: AttestationData, data_2: AttestationData): bool =
  ## Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG
  ## rules.

  # Double vote
  (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
  # Surround vote
    (data_1.source.epoch < data_2.source.epoch and
     data_2.target.epoch < data_1.target.epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#attester-slashings
proc process_attester_slashing*(
       state: var BeaconState,
       attester_slashing: AttesterSlashing,
       flags: UpdateFlags,
       stateCache: var StateCache
     ): bool {.nbench.}=
    let
      attestation_1 = attester_slashing.attestation_1
      attestation_2 = attester_slashing.attestation_2

    if not is_slashable_attestation_data(
        attestation_1.data, attestation_2.data):
      notice "Attester slashing: surround or double vote check failed"
      return false

    if not is_valid_indexed_attestation(state, attestation_1, flags):
      notice "Attester slashing: invalid attestation 1"
      return false

    if not is_valid_indexed_attestation(state, attestation_2, flags):
      notice "Attester slashing: invalid attestation 2"
      return false

    var slashed_any = false

    for index in sorted(toSeq(intersection(
        toHashSet(attestation_1.attesting_indices),
        toHashSet(attestation_2.attesting_indices)).items), system.cmp):
      if is_slashable_validator(
          state.validators[index.int], get_current_epoch(state)):
        slash_validator(state, index.ValidatorIndex, stateCache)
        slashed_any = true
    if not slashed_any:
      notice "Attester slashing: Trying to slash participant(s) twice"
      return false
    return true

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#attester-slashings
proc processAttesterSlashings(state: var BeaconState, blck: BeaconBlock,
    stateCache: var StateCache): bool {.nbench.}=
  # Process ``AttesterSlashing`` operation.
  if len(blck.body.attester_slashings) > MAX_ATTESTER_SLASHINGS:
    notice "Attester slashing: too many!"
    return false

  for attester_slashing in blck.body.attester_slashings:
    if not process_attester_slashing(state, attester_slashing, {}, stateCache):
      return false
  return true

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.4/specs/core/0_beacon-chain.md#attestations
proc processAttestations(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags,
    stateCache: var StateCache): bool {.nbench.}=
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

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.4/specs/core/0_beacon-chain.md#deposits
proc processDeposits(state: var BeaconState, blck: BeaconBlock,
    flags: UpdateFlags): bool {.nbench.}=
  if not (len(blck.body.deposits) <= MAX_DEPOSITS):
    notice "processDeposits: too many deposits"
    return false

  for deposit in blck.body.deposits:
    if not process_deposit(state, deposit, flags):
      notice "processDeposits: deposit invalid"
      return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/core/0_beacon-chain.md#voluntary-exits
proc process_voluntary_exit*(
    state: var BeaconState,
    signed_voluntary_exit: SignedVoluntaryExit,
    flags: UpdateFlags): bool {.nbench.}=

  let voluntary_exit = signed_voluntary_exit.message

  # Not in spec. Check that validator_index is in range
  if voluntary_exit.validator_index.int >= state.validators.len:
    notice "Exit: invalid validator index",
      index = voluntary_exit.validator_index,
      num_validators = state.validators.len
    return false

  let validator = state.validators[voluntary_exit.validator_index.int]

  # Verify the validator is active
  if not is_active_validator(validator, get_current_epoch(state)):
    notice "Exit: validator not active"
    return false

  # Verify the validator has not yet exited
  if validator.exit_epoch != FAR_FUTURE_EPOCH:
    notice "Exit: validator has exited"
    return false

  ## Exits must specify an epoch when they become valid; they are not valid
  ## before then
  if not (get_current_epoch(state) >= voluntary_exit.epoch):
    notice "Exit: exit epoch not passed"
    return false

  # Verify the validator has been active long enough
  if not (get_current_epoch(state) >= validator.activation_epoch +
      PERSISTENT_COMMITTEE_PERIOD):
    notice "Exit: not in validator set long enough"
    return false

  # Verify signature
  if skipValidation notin flags:
    let domain = get_domain(state, DOMAIN_VOLUNTARY_EXIT, voluntary_exit.epoch)
    if not bls_verify(
        validator.pubkey,
        hash_tree_root(voluntary_exit).data,
        signed_voluntary_exit.signature,
        domain):
      notice "Exit: invalid signature"
      return false

  # Initiate exit
  debug "Exit: processing voluntary exit (validator_leaving)",
    index = voluntary_exit.validator_index,
    num_validators = state.validators.len,
    epoch = voluntary_exit.epoch,
    current_epoch = get_current_epoch(state),
    validator_slashed = validator.slashed,
    validator_withdrawable_epoch = validator.withdrawable_epoch,
    validator_exit_epoch = validator.exit_epoch,
    validator_effective_balance = validator.effective_balance
  initiate_validator_exit(state, voluntary_exit.validator_index.ValidatorIndex)

  true

proc processVoluntaryExits(state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool {.nbench.}=
  if len(blck.body.voluntary_exits) > MAX_VOLUNTARY_EXITS:
    notice "[Block processing - Voluntary Exit]: too many exits!"
    return false
  for exit in blck.body.voluntary_exits:
    if not process_voluntary_exit(state, exit, flags):
      return false
  return true

proc processBlock*(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags,
    stateCache: var StateCache): bool {.nbench.}=
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly

  # TODO when there's a failure, we should reset the state!
  # TODO probably better to do all verification first, then apply state changes

  # https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#additional-metrics
  # doesn't seem to specify at what point in block processing this metric is to be read,
  # and this avoids the early-return issue (could also use defer, etc).
  beacon_pending_deposits.set(
    state.eth1_data.deposit_count.int64 - state.eth1_deposit_index.int64)
  beacon_processed_deposits_total.set(state.eth1_deposit_index.int64)

  # Adds nontrivial additional computation, but only does so when metrics
  # enabled.
  beacon_current_live_validators.set(toHashSet(
    mapIt(state.current_epoch_attestations, it.proposerIndex)).len.int64)
  beacon_previous_live_validators.set(toHashSet(
    mapIt(state.previous_epoch_attestations, it.proposerIndex)).len.int64)

  if not process_block_header(state, blck, flags, stateCache):
    notice "Block header not valid", slot = shortLog(state.slot)
    return false

  if not processRandao(state, blck.body, flags, stateCache):
    debug "[Block processing] Randao failure", slot = shortLog(state.slot)
    return false

  process_eth1_data(state, blck.body)

  # TODO, everything below is now in process_operations
  # and implementation is per element instead of the whole seq

  if not processProposerSlashings(state, blck, flags, stateCache):
    debug "[Block processing] Proposer slashing failure", slot = shortLog(state.slot)
    return false

  if not processAttesterSlashings(state, blck, stateCache):
    debug "[Block processing] Attester slashing failure", slot = shortLog(state.slot)
    return false

  if not processAttestations(state, blck, flags, stateCache):
    debug "[Block processing] Attestation processing failure", slot = shortLog(state.slot)
    return false

  if not processDeposits(state, blck, flags):
    debug "[Block processing] Deposit processing failure", slot = shortLog(state.slot)
    return false

  if not processVoluntaryExits(state, blck, flags):
    debug "[Block processing - Voluntary Exit] Exit processing failure", slot = shortLog(state.slot)
    return false

  true
