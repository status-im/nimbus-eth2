# beacon_chain
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/assign2,
  ./spec/forks

func diffModIncEpoch[maxLen, T](hl: HashArray[maxLen, T], startSlot: uint64):
    array[SLOTS_PER_EPOCH, T] =
  static: doAssert maxLen.uint64 mod SLOTS_PER_EPOCH == 0
  doAssert startSlot mod SLOTS_PER_EPOCH == 0
  for i in startSlot ..< startSlot + SLOTS_PER_EPOCH:
    result[i mod SLOTS_PER_EPOCH] = hl[i mod maxLen.uint64]

func applyModIncrement[maxLen, T](
    ha: var HashArray[maxLen, T], hl: array[SLOTS_PER_EPOCH, T], slot: uint64) =
  var indexSlot = slot

  for item in hl:
    ha[indexSlot mod maxLen.uint64] = item
    indexSlot += 1

func applyValidatorIdentities(
    validators: var HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT],
    hl: auto) =
  for item in hl:
    if not validators.add Validator(
        pubkey: item.pubkey.toPubKey(),
        withdrawal_credentials: item.withdrawal_credentials):
      raiseAssert "cannot readd"

func setValidatorStatusesNoWithdrawals(
    validators: var HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT],
    hl: List[ValidatorStatus, Limit VALIDATOR_REGISTRY_LIMIT]) =
  doAssert validators.len == hl.len

  for i in 0 ..< hl.len:
    let validator = addr validators.mitem(i)
    validator[].effective_balance = hl[i].effective_balance
    validator[].slashed = hl[i].slashed

    validator[].activation_eligibility_epoch =
      hl[i].activation_eligibility_epoch
    validator[].activation_epoch = hl[i].activation_epoch
    validator[].exit_epoch = hl[i].exit_epoch
    validator[].withdrawable_epoch = hl[i].withdrawable_epoch

func replaceOrAddEncodeEth1Votes[T, maxLen](
    votes0: openArray[T], votes0_len: int, votes1: HashList[T, maxLen]):
    (bool, List[T, maxLen]) =
  let
    num_votes0 = votes0.len
    lower_bound =
      if  votes1.len < num_votes0 or
          (num_votes0 > 0 and votes0[num_votes0 - 1] != votes1[num_votes0 - 1]):
        # EPOCHS_PER_ETH1_VOTING_PERIOD epochs have passed, and
        # eth1_data_votes has been reset/cleared. Because their
        # deposit_index counts increase monotonically, it works
        # to use only the last element for comparison.
        0
      else:
        num_votes0

  var res = (lower_bound == 0, default(List[T, maxLen]))
  for i in lower_bound ..< votes1.len:
    if not result[1].add votes1[i]:
      raiseAssert "same limit"
  res

func replaceOrAddDecodeEth1Votes[T, maxLen](
    votes0: var HashList[T, maxLen], eth1_data_votes_replaced: bool,
    votes1: List[T, maxLen]) =
  if eth1_data_votes_replaced:
    votes0 = HashList[T, maxLen]()

  for item in votes1:
    if not votes0.add item:
      raiseAssert "same limit"

func getMutableValidatorStatuses(state: capella.BeaconState):
    List[ValidatorStatus, Limit VALIDATOR_REGISTRY_LIMIT] =
  if not result.setLen(state.validators.len):
    raiseAssert "same limit as validators"
  for i in 0 ..< state.validators.len:
    let validator = unsafeAddr state.validators.data[i]
    assign(result[i].effective_balance, validator.effective_balance)
    assign(result[i].slashed, validator.slashed)
    assign(
      result[i].activation_eligibility_epoch,
      validator.activation_eligibility_epoch)
    assign(result[i].activation_epoch, validator.activation_epoch)
    assign(result[i].exit_epoch, validator.exit_epoch)
    assign(result[i].withdrawable_epoch, validator.withdrawable_epoch)

from "."/spec/beaconstate import has_eth1_withdrawal_credential

func getValidatorWithdrawalChanges(
    presummary: BeaconStateDiffPreSnapshot, state: capella.BeaconState):
    List[IndexedWithdrawalCredentials, Limit VALIDATOR_REGISTRY_LIMIT] =
  # The only possible change is a one-time-per-validator change from BLS to
  # execution withdrawal credentials, within the scope of Capella.

  var res: List[IndexedWithdrawalCredentials, Limit VALIDATOR_REGISTRY_LIMIT]

  for i in 0 ..< state.validators.lenu64:
    if  state.validators.item(i).has_eth1_withdrawal_credential and
        not presummary.eth1_withdrawal_credential[i]:
      if not res.add IndexedWithdrawalCredentials(
          validator_index: i,
          withdrawal_credentials:
            state.validators.item(i).withdrawal_credentials):
        raiseAssert "same limit as validators"

  res

func diffStates*(
    state0: BeaconStateDiffPreSnapshot, state1: capella.BeaconState):
    BeaconStateDiff =
  let
    historical_summary_added =
      state0.historical_summaries_len != state1.historical_summaries.len
    (eth1_data_votes_replaced, eth1_data_votes) =
      replaceOrAddEncodeEth1Votes(
        state0.eth1_data_votes_recent, state0.eth1_data_votes_len,
        state1.eth1_data_votes)

  BeaconStateDiff(
    slot: state1.slot,
    latest_block_header: state1.latest_block_header,

    block_roots: diffModIncEpoch(state1.block_roots, state0.slot.uint64),
    state_roots: diffModIncEpoch(state1.state_roots, state0.slot.uint64),
    eth1_data: state1.eth1_data,
    eth1_data_votes_replaced: eth1_data_votes_replaced,
    eth1_data_votes: eth1_data_votes,
    eth1_deposit_index: state1.eth1_deposit_index,

    validator_statuses: getMutableValidatorStatuses(state1),
    withdrawal_credential_changes:
      getValidatorWithdrawalChanges(state0, state1),
    balances: state1.balances.data,

    # RANDAO mixes gets updated every block, in place
    randao_mix: state1.randao_mixes[state0.slot.epoch.uint64 mod
      EPOCHS_PER_HISTORICAL_VECTOR.uint64],
    slashing: state1.slashings[state0.slot.epoch.uint64 mod
      EPOCHS_PER_HISTORICAL_VECTOR.uint64],

    previous_epoch_participation: state1.previous_epoch_participation,
    current_epoch_participation: state1.current_epoch_participation,

    justification_bits: state1.justification_bits,
    previous_justified_checkpoint: state1.previous_justified_checkpoint,
    current_justified_checkpoint: state1.current_justified_checkpoint,
    finalized_checkpoint: state1.finalized_checkpoint,

    inactivity_scores: state1.inactivity_scores.data,

    current_sync_committee: state1.current_sync_committee,
    next_sync_committee: state1.next_sync_committee,

    latest_execution_payload_header: state1.latest_execution_payload_header,

    next_withdrawal_index: state1.next_withdrawal_index,
    next_withdrawal_validator_index: state1.next_withdrawal_validator_index,

    historical_summary_added: historical_summary_added,
    historical_summary:
      if historical_summary_added:
        state1.historical_summaries[state0.historical_summaries_len]
      else:
        (static(default(HistoricalSummary)))
  )

from std/sequtils import mapIt

func getBeaconStateDiffSummary*(state0: capella.BeaconState):
    BeaconStateDiffPreSnapshot =
  BeaconStateDiffPreSnapshot(
    eth1_data_votes_recent:
      if state0.eth1_data_votes.len > 0:
        # replaceOrAddEncodeEth1Votes will check whether it needs to replace or add
        # the votes. Which happens is a function of effectively external data, i.e.
        # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#eth1-data
        # notes it depends on things not deterministic, from a pure consensus-layer
        # perspective. It thus must distinguish between adding and replacing votes,
        # which it accomplishes by checking lengths and the most recent votes. This
        # enables it to disambiguate when, for example, the number of Eth1 votes in
        # both states is identical, but they're distinct because they were replaced
        # between said states. This should not be feasible for the usual, intended,
        # use case of exactly one epoch strides, but avoids a design coupling while
        # not adding much runtime or storage cost.
        state0.eth1_data_votes[^1 .. ^1]
      else:
        @[],
    eth1_data_votes_len: state0.eth1_data_votes.len,
    slot: state0.slot,
    historical_summaries_len: state0.historical_summaries.len,
    eth1_withdrawal_credential:
      mapIt(state0.validators, it.has_eth1_withdrawal_credential))

func applyDiff*(
    state: var capella.BeaconState,
    immutableValidators: openArray[ImmutableValidatorData2],
    stateDiff: BeaconStateDiff) =
  template assign[T, maxLen](
      tgt: var HashList[T, maxLen], src: List[T, maxLen]) =
    assign(tgt.data, src)
    tgt.resetCache()

  # Carry over unchanged genesis_time, genesis_validators_root, and fork.
  assign(state.latest_block_header, stateDiff.latest_block_header)

  applyModIncrement(state.block_roots, stateDiff.block_roots, state.slot.uint64)
  applyModIncrement(state.state_roots, stateDiff.state_roots, state.slot.uint64)

  # Capella freezes historical_roots

  assign(state.eth1_data, stateDiff.eth1_data)
  replaceOrAddDecodeEth1Votes(
    state.eth1_data_votes, stateDiff.eth1_data_votes_replaced,
    stateDiff.eth1_data_votes)
  assign(state.eth1_deposit_index, stateDiff.eth1_deposit_index)

  applyValidatorIdentities(state.validators, immutableValidators)
  setValidatorStatusesNoWithdrawals(
    state.validators, stateDiff.validator_statuses)
  for withdrawalUpdate in stateDiff.withdrawal_credential_changes:
    assign(
      state.validators.mitem(
        withdrawalUpdate.validator_index).withdrawal_credentials,
      withdrawalUpdate.withdrawal_credentials)
  assign(state.balances, stateDiff.balances)

  # RANDAO mixes gets updated every block, in place, so ensure there's always
  # >=1 value from it
  let epochIndex =
    state.slot.epoch.uint64 mod EPOCHS_PER_HISTORICAL_VECTOR.uint64
  assign(state.randao_mixes.mitem(epochIndex), stateDiff.randao_mix)
  assign(state.slashings.mitem(epochIndex), stateDiff.slashing)

  assign(
    state.previous_epoch_participation, stateDiff.previous_epoch_participation)
  assign(
    state.current_epoch_participation, stateDiff.current_epoch_participation)

  state.justification_bits = stateDiff.justification_bits
  assign(
    state.previous_justified_checkpoint,
    stateDiff.previous_justified_checkpoint)
  assign(
    state.current_justified_checkpoint, stateDiff.current_justified_checkpoint)
  assign(state.finalized_checkpoint, stateDiff.finalized_checkpoint)

  assign(state.inactivity_scores, stateDiff.inactivity_scores)

  assign(state.current_sync_committee, stateDiff.current_sync_committee)
  assign(state.next_sync_committee, stateDiff.next_sync_committee)

  assign(
    state.latest_execution_payload_header,
    stateDiff.latest_execution_payload_header)

  assign(state.next_withdrawal_index, stateDiff.next_withdrawal_index)
  assign(
    state.next_withdrawal_validator_index,
    stateDiff.next_withdrawal_validator_index)

  if stateDiff.historical_summary_added:
    if not state.historical_summaries.add stateDiff.historical_summary:
      raiseAssert "cannot readd historical summary"

  # Don't update slot until the end, because various other updates depend on it
  state.slot = stateDiff.slot
