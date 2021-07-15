# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition - block processing, as described in
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
#
# The entry point is `process_block` which is at the bottom of this file.
#
# General notes about the code:
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * When updating the code, add TODO sections to mark where there are clear
#   improvements to be made - other than that, keep things similar to spec unless
#   motivated by security or performance considerations

{.push raises: [Defect].}

import
  std/[algorithm, intsets, options, sequtils, sets, tables],
  chronicles,
  ../extras, ../ssz/merkleization, metrics,
  ./beaconstate, ./crypto, ./datatypes/[phase0, altair], ./digest, ./helpers,
  ./validator, ./signatures, ./presets,
  ../../nbench/bench_lab

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#block-header
func process_block_header*(
    state: var SomeBeaconState, blck: SomeSomeBeaconBlock, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] {.nbench.} =
  # Verify that the slots match
  if not (blck.slot == state.slot):
    return err("process_block_header: slot mismatch")

  # Verify that the block is newer than latest block header
  if not (blck.slot > state.latest_block_header.slot):
    return err("process_block_header: block not newer than latest block header")

  # Verify that proposer index is the correct index
  let proposer_index = get_beacon_proposer_index(state, cache)
  if proposer_index.isNone:
    return err("process_block_header: proposer missing")

  if not (blck.proposer_index.ValidatorIndex == proposer_index.get):
    return err("process_block_header: proposer index incorrect")

  # Verify that the parent matches
  if not (blck.parent_root == hash_tree_root(state.latest_block_header)):
    return err("process_block_header: previous block root mismatch")

  # Verify proposer is not slashed
  if state.validators.asSeq()[blck.proposer_index].slashed:
    return err("process_block_header: proposer slashed")

  # Cache current block as the new latest block
  state.latest_block_header = BeaconBlockHeader(
    slot: blck.slot,
    proposer_index: blck.proposer_index,
    parent_root: blck.parent_root,
    # state_root: zeroed, overwritten in the next `process_slot` call
    body_root: hash_tree_root(blck.body),
  )

  ok()

func `xor`[T: array](a, b: T): T =
  for i in 0..<result.len:
    result[i] = a[i] xor b[i]

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#randao
proc process_randao(
    state: var SomeBeaconState, body: SomeSomeBeaconBlockBody, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] {.nbench.} =
  let
    proposer_index = get_beacon_proposer_index(state, cache)

  if proposer_index.isNone:
    return err("process_randao: proposer index missing, probably along with any active validators")

  # Verify RANDAO reveal
  let
    epoch = state.get_current_epoch()

  if skipBLSValidation notin flags:
    let proposer_pubkey = state.validators.asSeq()[proposer_index.get].pubkey

    if not verify_epoch_signature(
        state.fork, state.genesis_validators_root, epoch, proposer_pubkey,
        body.randao_reveal):

      return err("process_randao: invalid epoch signature")

  # Mix it in
  let
    mix = get_randao_mix(state, epoch)
    rr = eth2digest(body.randao_reveal.toRaw()).data

  state.randao_mixes[epoch mod EPOCHS_PER_HISTORICAL_VECTOR].data =
    mix.data xor rr

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#eth1-data
func process_eth1_data(state: var SomeBeaconState, body: SomeSomeBeaconBlockBody): Result[void, cstring] {.nbench.}=
  if not state.eth1_data_votes.add body.eth1_data:
    # Count is reset  in process_final_updates, so this should never happen
    return err("process_eth1_data: no more room for eth1 data")

  if state.eth1_data_votes.asSeq.count(body.eth1_data).uint64 * 2 >
      SLOTS_PER_ETH1_VOTING_PERIOD:
    state.eth1_data = body.eth1_data
  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#is_slashable_validator
func is_slashable_validator(validator: Validator, epoch: Epoch): bool =
  # Check if ``validator`` is slashable.
  (not validator.slashed) and
    (validator.activation_epoch <= epoch) and
    (epoch < validator.withdrawable_epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#proposer-slashings
proc check_proposer_slashing*(
    state: var SomeBeaconState, proposer_slashing: SomeProposerSlashing,
    flags: UpdateFlags):
    Result[void, cstring] {.nbench.} =

  let
    header_1 = proposer_slashing.signed_header_1.message
    header_2 = proposer_slashing.signed_header_2.message

  # Not from spec
  if header_1.proposer_index >= state.validators.lenu64:
    return err("check_proposer_slashing: invalid proposer index")

  # Verify header slots match
  if not (header_1.slot == header_2.slot):
    return err("check_proposer_slashing: slot mismatch")

  # Verify header proposer indices match
  if not (header_1.proposer_index == header_2.proposer_index):
    return err("check_proposer_slashing: proposer indices mismatch")

  # Verify the headers are different
  if not (header_1 != header_2):
    return err("check_proposer_slashing: headers not different")

  # Verify the proposer is slashable
  let proposer = unsafeAddr state.validators.asSeq()[header_1.proposer_index]
  if not is_slashable_validator(proposer[], get_current_epoch(state)):
    return err("check_proposer_slashing: slashed proposer")

  # Verify signatures
  if skipBlsValidation notin flags:
    for signed_header in [proposer_slashing.signed_header_1,
        proposer_slashing.signed_header_2]:
      if not verify_block_signature(
          state.fork, state.genesis_validators_root, signed_header.message.slot,
          signed_header.message, proposer[].pubkey,
          signed_header.signature):
        return err("check_proposer_slashing: invalid signature")

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#proposer-slashings
proc process_proposer_slashing*(
    cfg: RuntimeConfig, state: var SomeBeaconState,
    proposer_slashing: SomeProposerSlashing, flags: UpdateFlags,
    cache: var StateCache):
    Result[void, cstring] {.nbench.} =
  ? check_proposer_slashing(state, proposer_slashing, flags)
  slash_validator(
    cfg, state,
    proposer_slashing.signed_header_1.message.proposer_index.ValidatorIndex,
    cache)
  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#is_slashable_attestation_data
func is_slashable_attestation_data(
    data_1: AttestationData, data_2: AttestationData): bool =
  ## Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG
  ## rules.

  # Double vote
  (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
  # Surround vote
    (data_1.source.epoch < data_2.source.epoch and
     data_2.target.epoch < data_1.target.epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#attester-slashings
proc check_attester_slashing*(
       state: var SomeBeaconState,
       attester_slashing: SomeAttesterSlashing,
       flags: UpdateFlags
     ): Result[seq[ValidatorIndex], cstring] {.nbench.} =
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

  var slashed_indices: seq[ValidatorIndex]

  for index in sorted(toSeq(intersection(
      toIntSet(attestation_1.attesting_indices.asSeq),
      toIntSet(attestation_2.attesting_indices.asSeq)).items), system.cmp):
    if is_slashable_validator(
        state.validators.asSeq()[index], get_current_epoch(state)):
      slashed_indices.add index.ValidatorIndex
  if slashed_indices.len == 0:
    return err("Attester slashing: Trying to slash participant(s) twice")

  ok slashed_indices

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#attester-slashings
proc process_attester_slashing*(
    cfg: RuntimeConfig,
    state: var SomeBeaconState,
    attester_slashing: SomeAttesterSlashing,
    flags: UpdateFlags,
    cache: var StateCache
    ): Result[void, cstring] {.nbench.} =
  let attester_slashing_validity =
    check_attester_slashing(state, attester_slashing, flags)

  if attester_slashing_validity.isErr:
    return err(attester_slashing_validity.error)

  for index in attester_slashing_validity.value:
    slash_validator(cfg, state, index, cache)

  ok()

proc process_deposit*(cfg: RuntimeConfig,
                      state: var SomeBeaconState,
                      deposit: Deposit,
                      flags: UpdateFlags): Result[void, cstring] {.nbench.} =
  ## Process an Eth1 deposit, registering a validator or increasing its balance.

  # Verify the Merkle branch
  if not is_valid_merkle_branch(
    hash_tree_root(deposit.data),
    deposit.proof,
    DEPOSIT_CONTRACT_TREE_DEPTH + 1,  # Add 1 for the `List` length mix-in
    state.eth1_deposit_index,
    state.eth1_data.deposit_root,
  ):
    return err("process_deposit: deposit Merkle validation failed")

  # Deposits must be processed in order
  state.eth1_deposit_index += 1

  let
    pubkey = deposit.data.pubkey
    amount = deposit.data.amount

  var index = -1

  # This linear scan is unfortunate, but should be fairly fast as we do a simple
  # byte comparison of the key. The alternative would be to build a Table, but
  # given that each block can hold no more than 16 deposits, it's slower to
  # build the table and use it for lookups than to scan it like this.
  # Once we have a reusable, long-lived cache, this should be revisited
  for i in 0..<state.validators.len():
    if state.validators.asSeq()[i].pubkey == pubkey:
      index = i
      break

  if index != -1:
    # Increase balance by deposit amount
    increase_balance(state, index.ValidatorIndex, amount)
  else:
    # Verify the deposit signature (proof of possession) which is not checked
    # by the deposit contract
    if skipBLSValidation in flags or verify_deposit_signature(cfg, deposit.data):
      # New validator! Add validator and balance entries
      if not state.validators.add(get_validator_from_deposit(deposit.data)):
        return err("process_deposit: too many validators")
      if not state.balances.add(amount):
        static: doAssert state.balances.maxLen == state.validators.maxLen
        raiseAssert "adding validator succeeded, so should balances"

      when state is altair.BeaconState:
        if not state.previous_epoch_participation.add(ParticipationFlags(0)):
          return err("process_deposit: too many validators (previous_epoch_participation)")
        if not state.current_epoch_participation.add(ParticipationFlags(0)):
          return err("process_deposit: too many validators (current_epoch_participation)")
        if not state.inactivity_scores.add(0'u64):
          return err("process_deposit: too many validators (inactivity_scores)")

      doAssert state.validators.len == state.balances.len
    else:
      # Deposits may come with invalid signatures - in that case, they are not
      # turned into a validator but still get processed to keep the deposit
      # index correct
      trace "Skipping deposit with invalid signature",
        deposit = shortLog(deposit.data)

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#voluntary-exits
proc check_voluntary_exit*(
    cfg: RuntimeConfig,
    state: SomeBeaconState,
    signed_voluntary_exit: SomeSignedVoluntaryExit,
    flags: UpdateFlags): Result[void, cstring] {.nbench.} =

  let voluntary_exit = signed_voluntary_exit.message

  # Not in spec. Check that validator_index is in range
  if voluntary_exit.validator_index >= state.validators.lenu64:
    return err("Exit: invalid validator index")

  let validator = unsafeAddr state.validators.asSeq()[voluntary_exit.validator_index]

  # Verify the validator is active
  if not is_active_validator(validator[], get_current_epoch(state)):
    return err("Exit: validator not active")

  # Verify exit has not been initiated
  if validator[].exit_epoch != FAR_FUTURE_EPOCH:
    return err("Exit: validator has exited")

  # Exits must specify an epoch when they become valid; they are not valid
  # before then
  if not (get_current_epoch(state) >= voluntary_exit.epoch):
    return err("Exit: exit epoch not passed")

  # Verify the validator has been active long enough
  if not (get_current_epoch(state) >= validator[].activation_epoch +
      cfg.SHARD_COMMITTEE_PERIOD):
    return err("Exit: not in validator set long enough")

  # Verify signature
  if skipBlsValidation notin flags:
    if not verify_voluntary_exit_signature(
        state.fork, state.genesis_validators_root, voluntary_exit,
        validator[].pubkey, signed_voluntary_exit.signature):
      return err("Exit: invalid signature")

  # Initiate exit
  debug "Exit: checking voluntary exit (validator_leaving)",
    index = voluntary_exit.validator_index,
    num_validators = state.validators.len,
    epoch = voluntary_exit.epoch,
    current_epoch = get_current_epoch(state),
    validator_slashed = validator[].slashed,
    validator_withdrawable_epoch = validator[].withdrawable_epoch,
    validator_exit_epoch = validator[].exit_epoch,
    validator_effective_balance = validator[].effective_balance

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#voluntary-exits
proc process_voluntary_exit*(
    cfg: RuntimeConfig,
    state: var SomeBeaconState,
    signed_voluntary_exit: SomeSignedVoluntaryExit,
    flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] {.nbench.} =
  ? check_voluntary_exit(cfg, state, signed_voluntary_exit, flags)
  initiate_validator_exit(
    cfg, state, signed_voluntary_exit.message.validator_index.ValidatorIndex,
    cache)
  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#operations
proc process_operations(cfg: RuntimeConfig,
                        state: var SomeBeaconState,
                        body: SomeSomeBeaconBlockBody,
                        flags: UpdateFlags,
                        cache: var StateCache): Result[void, cstring] {.nbench.} =
  # Verify that outstanding deposits are processed up to the maximum number of
  # deposits
  template base_reward_per_increment(state: phase0.BeaconState): Gwei = 0.Gwei
  template base_reward_per_increment(state: altair.BeaconState): Gwei =
    get_base_reward_per_increment(state, cache)

  let
    req_deposits = min(MAX_DEPOSITS,
                       state.eth1_data.deposit_count - state.eth1_deposit_index)
    generalized_base_reward_per_increment = base_reward_per_increment(state)

  if state.eth1_data.deposit_count < state.eth1_deposit_index or
      body.deposits.lenu64 != req_deposits:
    return err("incorrect number of deposits")

  for op in body.proposer_slashings:
    ? process_proposer_slashing(cfg, state, op, flags, cache)
  for op in body.attester_slashings:
    ? process_attester_slashing(cfg, state, op, flags, cache)
  for op in body.attestations:
    ? process_attestation(state, op, flags, generalized_base_reward_per_increment, cache)
  for op in body.deposits:
    ? process_deposit(cfg, state, op, flags)
  for op in body.voluntary_exits:
    ? process_voluntary_exit(cfg, state, op, flags, cache)

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.6/specs/altair/beacon-chain.md#sync-committee-processing
proc process_sync_aggregate*(
    state: var altair.BeaconState, aggregate: SyncAggregate, cache: var StateCache):
    Result[void, cstring] {.nbench.} =
  # Verify sync committee aggregate signature signing over the previous slot
  # block root
  let
    committee_pubkeys = state.current_sync_committee.pubkeys
    previous_slot = max(state.slot, Slot(1)) - 1
    domain = get_domain(state, DOMAIN_SYNC_COMMITTEE, compute_epoch_at_slot(previous_slot))
    signing_root = compute_signing_root(get_block_root_at_slot(state, previous_slot), domain)

  var participant_pubkeys: seq[ValidatorPubKey]
  for i in 0 ..< committee_pubkeys.len:
    if aggregate.sync_committee_bits[i]:
      participant_pubkeys.add committee_pubkeys[i]

  # Empty participants allowed
  if participant_pubkeys.len > 0 and not blsFastAggregateVerify(
      participant_pubkeys, signing_root.data, aggregate.sync_committee_signature):
    return err("process_sync_aggregate: invalid signature")

  # Compute participant and proposer rewards
  let
    total_active_increments = get_total_active_balance(state, cache) div EFFECTIVE_BALANCE_INCREMENT
    total_base_rewards = get_base_reward_per_increment(state, cache) * total_active_increments
    max_participant_rewards = total_base_rewards * SYNC_REWARD_WEIGHT div WEIGHT_DENOMINATOR div SLOTS_PER_EPOCH
    participant_reward = max_participant_rewards div SYNC_COMMITTEE_SIZE
    proposer_reward = participant_reward * PROPOSER_WEIGHT div (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT)

  # Apply participant and proposer rewards

  # stand-in to be replaced
  # TODO obviously not viable as written
  # TODO also, this could use the pubkey -> index map that's been approached a couple places
  let s = toHashSet(state.current_sync_committee.pubkeys.data)  # TODO leaking abstraction
  var pubkeyIndices: Table[ValidatorPubKey, ValidatorIndex]
  for i, v in state.validators:
    if v.pubkey in s:
      pubkeyIndices[v.pubkey] = i.ValidatorIndex

  # TODO could use a sequtils2 zipIt
  for i in 0 ..< min(
      state.current_sync_committee.pubkeys.len,
      aggregate.sync_committee_bits.len):
    let proposer_index = get_beacon_proposer_index(state, cache)
    if proposer_index.isSome:
      let participant_index =
        pubkeyIndices.getOrDefault(state.current_sync_committee.pubkeys[i])
      if aggregate.sync_committee_bits[i]:
        increase_balance(state, participant_index, participant_reward)
        increase_balance(state, proposer_index.get, proposer_reward)
      else:
        decrease_balance(state, participant_index, participant_reward)
    else:
      warn "process_sync_aggregate: get_beacon_proposer_index failed"

  ok()

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/phase0.nim
type SomePhase0Block =
  phase0.BeaconBlock | phase0.SigVerifiedBeaconBlock | phase0.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var phase0.BeaconState, blck: SomePhase0Block, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] {.nbench.}=
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)
  ? process_operations(cfg, state, blck.body, flags, cache)

  ok()

proc process_block*(
    cfg: RuntimeConfig,
    state: var altair.BeaconState, blck: SomePhase0Block, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] {.nbench.} =
  # The transition-triggering block creates, not acts on, an Altair state
  err("process_block: Altair state with Phase 0 block")

# https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.8/specs/altair/beacon-chain.md#block-processing
# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of datatypes/altair.nim
type SomeAltairBlock =
  altair.BeaconBlock | altair.SigVerifiedBeaconBlock | altair.TrustedBeaconBlock
proc process_block*(
    cfg: RuntimeConfig,
    state: var altair.BeaconState, blck: SomeAltairBlock, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] {.nbench.}=
  ## When there's a new block, we need to verify that the block is sane and
  ## update the state accordingly - the state is left in an unknown state when
  ## block application fails (!)

  ? process_block_header(state, blck, flags, cache)
  ? process_randao(state, blck.body, flags, cache)
  ? process_eth1_data(state, blck.body)
  ? process_operations(cfg, state, blck.body, flags, cache)
  ? process_sync_aggregate(state, blck.body.sync_aggregate, cache)  # [New in Altair]

  ok()

proc process_block*(
    cfg: RuntimeConfig,
    state: var phase0.BeaconState, blck: SomeAltairBlock, flags: UpdateFlags,
    cache: var StateCache): Result[void, cstring] {.nbench.}=
  err("process_block: Phase 0 state with Altair block")
