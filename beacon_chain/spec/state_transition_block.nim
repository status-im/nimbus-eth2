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
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * We mix procedural and functional styles for no good reason, except that the
#   spec does so also.
# * For indices, we get a mix of uint64, ValidatorIndex and int - this is currently
#   swept under the rug with casts
# When updating the code, add TODO sections to mark where there are clear
# improvements to be made - other than that, keep things similar to spec for
# now.

{.push raises: [Defect].}

import
  algorithm, collections/sets, chronicles, options, sequtils, sets,
  ../extras, ../ssz/merkleization, metrics,
  ./beaconstate, ./crypto, ./datatypes, ./digest, ./helpers, ./validator,
  ./signatures, ./presets,
  ../../nbench/bench_lab

# https://github.com/ethereum/eth2.0-metrics/blob/master/metrics.md#additional-metrics
declareGauge beacon_current_live_validators, "Number of active validators that successfully included attestation on chain for current epoch" # On block
declareGauge beacon_previous_live_validators, "Number of active validators that successfully included attestation on chain for previous epoch" # On block
declareGauge beacon_pending_deposits, "Number of pending deposits (state.eth1_data.deposit_count - state.eth1_deposit_index)" # On block
declareGauge beacon_processed_deposits_total, "Number of total deposits included on chain" # On block

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#block-header
func process_block_header*(
    state: var BeaconState, blck: SomeBeaconBlock, flags: UpdateFlags,
    stateCache: var StateCache): Result[void, cstring] {.nbench.} =
  # Verify that the slots match
  if not (blck.slot == state.slot):
    return err("process_block_header: slot mismatch")

  # Verify that the block is newer than latest block header
  if not (blck.slot > state.latest_block_header.slot):
    return err("process_block_header: block not newer than latest block header")

  # Verify that proposer index is the correct index
  let proposer_index = get_beacon_proposer_index(state, stateCache)
  if proposer_index.isNone:
    return err("process_block_header: proposer missing")

  if not (blck.proposer_index.ValidatorIndex == proposer_index.get):
    return err("process_block_header: proposer index incorrect")

  # Verify that the parent matches
  if not (blck.parent_root == hash_tree_root(state.latest_block_header)):
    return err("process_block_header: previous block root mismatch")

  # Cache current block as the new latest block
  state.latest_block_header = BeaconBlockHeader(
    slot: blck.slot,
    proposer_index: blck.proposer_index,
    parent_root: blck.parent_root,
    # state_root: zeroed, overwritten in the next `process_slot` call
    body_root: hash_tree_root(blck.body),
  )

  # Verify proposer is not slashed
  let proposer = state.validators[proposer_index.get]
  if proposer.slashed:
    return err("process_block_header: proposer slashed")

  ok()

func `xor`[T: array](a, b: T): T =
  for i in 0..<result.len:
    result[i] = a[i] xor b[i]

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#randao
proc process_randao(
    state: var BeaconState, body: SomeBeaconBlockBody, flags: UpdateFlags,
    stateCache: var StateCache): bool {.nbench.} =
  let
    proposer_index = get_beacon_proposer_index(state, stateCache)

  if proposer_index.isNone:
    debug "Proposer index missing, probably along with any active validators"
    return false

  # Verify RANDAO reveal
  let
    epoch = state.get_current_epoch()

  if skipBLSValidation notin flags:
    let proposer_pubkey = state.validators[proposer_index.get].pubkey

    if not verify_epoch_signature(
        state.fork, state.genesis_validators_root, epoch, proposer_pubkey,
        body.randao_reveal):
      notice "Randao mismatch", proposer_pubkey = shortLog(proposer_pubkey),
                                epoch,
                                signature = shortLog(body.randao_reveal),
                                slot = state.slot
      return false

  # Mix it in
  let
    mix = get_randao_mix(state, epoch)
    rr = eth2digest(body.randao_reveal.toRaw()).data

  state.randao_mixes[epoch mod EPOCHS_PER_HISTORICAL_VECTOR].data =
    mix.data xor rr

  true

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#eth1-data
func process_eth1_data(state: var BeaconState, body: SomeBeaconBlockBody) {.nbench.}=
  state.eth1_data_votes.add body.eth1_data

  if state.eth1_data_votes.asSeq.count(body.eth1_data).uint64 * 2 >
      SLOTS_PER_ETH1_VOTING_PERIOD:
    state.eth1_data = body.eth1_data

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#is_slashable_validator
func is_slashable_validator(validator: Validator, epoch: Epoch): bool =
  # Check if ``validator`` is slashable.
  (not validator.slashed) and
    (validator.activation_epoch <= epoch) and
    (epoch < validator.withdrawable_epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#proposer-slashings
proc process_proposer_slashing*(
    state: var BeaconState, proposer_slashing: ProposerSlashing,
    flags: UpdateFlags, stateCache: var StateCache):
    Result[void, cstring] {.nbench.} =

  let
    header_1 = proposer_slashing.signed_header_1.message
    header_2 = proposer_slashing.signed_header_2.message

  # Not from spec
  if header_1.proposer_index >= state.validators.lenu64:
    return err("process_proposer_slashing: invalid proposer index")

  # Verify header slots match
  if not (header_1.slot == header_2.slot):
    return err("process_proposer_slashing: slot mismatch")

  # Verify header proposer indices match
  if not (header_1.proposer_index == header_2.proposer_index):
    return err("process_proposer_slashing: proposer indices mismatch")

  # Verify the headers are different
  if not (header_1 != header_2):
    return err("process_proposer_slashing: headers not different")

  # Verify the proposer is slashable
  let proposer = state.validators[header_1.proposer_index]
  if not is_slashable_validator(proposer, get_current_epoch(state)):
    return err("process_proposer_slashing: slashed proposer")

  # Verify signatures
  if skipBlsValidation notin flags:
    for i, signed_header in [proposer_slashing.signed_header_1,
        proposer_slashing.signed_header_2]:
      if not verify_block_signature(
          state.fork, state.genesis_validators_root, signed_header.message.slot,
          signed_header.message, proposer.pubkey, signed_header.signature):
        return err("process_proposer_slashing: invalid signature")

  slashValidator(state, header_1.proposer_index.ValidatorIndex, stateCache)

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#is_slashable_attestation_data
func is_slashable_attestation_data(
    data_1: AttestationData, data_2: AttestationData): bool =
  ## Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG
  ## rules.

  # Double vote
  (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
  # Surround vote
    (data_1.source.epoch < data_2.source.epoch and
     data_2.target.epoch < data_1.target.epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#attester-slashings
proc process_attester_slashing*(
       state: var BeaconState,
       attester_slashing: AttesterSlashing,
       flags: UpdateFlags,
       stateCache: var StateCache
     ): Result[void, cstring] {.nbench.}=
  let
    attestation_1 = attester_slashing.attestation_1
    attestation_2 = attester_slashing.attestation_2

  if not is_slashable_attestation_data(
      attestation_1.data, attestation_2.data):
    return err("Attester slashing: surround or double vote check failed")

  if not is_valid_indexed_attestation(state, attestation_1, flags).isOk():
    return err("Attester slashing: invalid attestation 1")

  if not is_valid_indexed_attestation(state, attestation_2, flags).isOk():
    return err("Attester slashing: invalid attestation 2")

  var slashed_any = false

  for index in sorted(toSeq(intersection(
      toHashSet(attestation_1.attesting_indices.asSeq),
      toHashSet(attestation_2.attesting_indices.asSeq)).items), system.cmp):
    if is_slashable_validator(
        state.validators[index], get_current_epoch(state)):
      slash_validator(state, index.ValidatorIndex, stateCache)
      slashed_any = true
  if not slashed_any:
    return err("Attester slashing: Trying to slash participant(s) twice")
  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#voluntary-exits
proc process_voluntary_exit*(
    state: var BeaconState,
    signed_voluntary_exit: SignedVoluntaryExit,
    flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] {.nbench.} =

  let voluntary_exit = signed_voluntary_exit.message

  # Not in spec. Check that validator_index is in range
  if voluntary_exit.validator_index >= state.validators.lenu64:
    return err("Exit: invalid validator index")

  let validator = state.validators[voluntary_exit.validator_index]

  # Verify the validator is active
  if not is_active_validator(validator, get_current_epoch(state)):
    return err("Exit: validator not active")

  # Verify exit has not been initiated
  if validator.exit_epoch != FAR_FUTURE_EPOCH:
    return err("Exit: validator has exited")

  # Exits must specify an epoch when they become valid; they are not valid
  # before then
  if not (get_current_epoch(state) >= voluntary_exit.epoch):
    return err("Exit: exit epoch not passed")

  # Verify the validator has been active long enough
  if not (get_current_epoch(state) >= validator.activation_epoch +
      SHARD_COMMITTEE_PERIOD):
    return err("Exit: not in validator set long enough")

  # Verify signature
  if skipBlsValidation notin flags:
    if not verify_voluntary_exit_signature(
        state.fork, state.genesis_validators_root, voluntary_exit,
        validator.pubkey, signed_voluntary_exit.signature):
      return err("Exit: invalid signature")

  # Initiate exit
  initiate_validator_exit(
    state, voluntary_exit.validator_index.ValidatorIndex, cache)

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#operations
proc process_operations(preset: RuntimePreset,
                        state: var BeaconState,
                        blck: SomeBeaconBlock,
                        flags: UpdateFlags,
                        cache: var StateCache): Result[void, cstring] {.nbench.} =
  # Verify that outstanding deposits are processed up to the maximum number of
  # deposits
  let
    body = blck.body   # so processing validator exit can record blck information
    num_deposits = uint64 len(body.deposits)
    req_deposits = min(MAX_DEPOSITS,
                       state.eth1_data.deposit_count - state.eth1_deposit_index)
  if not (num_deposits == req_deposits):
    return err("incorrect number of deposits")

  template for_ops(operations: auto, fn: auto) =
    for operation in operations:
      let res = fn(state, operation, flags, cache)
      if res.isErr:
        return res

  for_ops(body.proposer_slashings, process_proposer_slashing)
  for_ops(body.attester_slashings, process_attester_slashing)
  for_ops(body.attestations, process_attestation)

  for deposit in body.deposits:
    let res = process_deposit(preset, state, deposit, flags)
    if res.isErr:
      return res

  for signed_voluntary_exit in body.voluntary_exits:
    let
      res = process_voluntary_exit(state, signed_voluntary_exit, flags, cache)
      voluntary_exit = signed_voluntary_exit.message
    if res.isOk:
      let validator = state.validators[voluntary_exit.validator_index]
      debug "Exit: processed valid voluntary exit (validator_leaving)",
        index = voluntary_exit.validator_index,
        num_validators = state.validators.len,
        epoch = voluntary_exit.epoch,
        current_epoch = get_current_epoch(state),
        validator_slashed = validator.slashed,
        validator_withdrawable_epoch = validator.withdrawable_epoch,
        validator_exit_epoch = validator.exit_epoch,
        validator_effective_balance = validator.effective_balance,
        blck = shortLog(blck),
        block_root = hash_tree_root(blck)
    else:
      debug "Exit: processed invalid voluntary exit (validator_leaving)",
        index = voluntary_exit.validator_index,
        num_validators = state.validators.len,
        epoch = voluntary_exit.epoch,
        current_epoch = get_current_epoch(state),
        blck = shortLog(blck),
        block_root = hash_tree_root(blck)
      return res

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#block-processing
proc process_block*(
    preset: RuntimePreset,
    state: var BeaconState, blck: SomeBeaconBlock, flags: UpdateFlags,
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

  logScope:
    blck = shortLog(blck)
  let res_block = process_block_header(state, blck, flags, stateCache)
  if res_block.isErr:
    debug "Block header not valid",
      block_header_error = $(res_block.error),
      slot = state.slot
    return false

  if not process_randao(state, blck.body, flags, stateCache):
    debug "Randao failure", slot = shortLog(state.slot)
    return false

  process_eth1_data(state, blck.body)

  # process_operations only uses the full `blck` for process_voluntary_exit()
  # logging
  let res_ops = process_operations(preset, state, blck, flags, stateCache)
  if res_ops.isErr:
    debug "process_operations encountered error",
      operation_error = $(res_ops.error),
      slot = state.slot,
      eth1_deposit_index = state.eth1_deposit_index,
      deposit_root = shortLog(state.eth1_data.deposit_root)
    return false

  true
