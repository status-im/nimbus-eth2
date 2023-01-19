# beacon_chain
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/assign2,
  ./spec/datatypes/bellatrix,
  ./spec/helpers

func diffModIncEpoch[T, U](hl: HashArray[U, T], startSlot: uint64):
    array[SLOTS_PER_EPOCH, T] =
  static: doAssert U.uint64 mod SLOTS_PER_EPOCH == 0
  doAssert startSlot mod SLOTS_PER_EPOCH == 0
  for i in startSlot ..< startSlot + SLOTS_PER_EPOCH:
    result[i mod SLOTS_PER_EPOCH] = hl[i mod U.uint64]

func applyModIncrement[T, U](
    ha: var HashArray[U, T], hl: array[SLOTS_PER_EPOCH, T], slot: uint64) =
  var indexSlot = slot

  for item in hl:
    ha[indexSlot mod U.uint64] = item
    indexSlot += 1

func applyValidatorIdentities(
    validators: var HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT],
    hl: auto) =
  for item in hl:
    if not validators.add Validator(
        pubkey: item.pubkey.toPubKey(),
        withdrawal_credentials: item.withdrawal_credentials):
      raiseAssert "cannot readd"

func setValidatorStatuses(
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

func replaceOrAddEncodeEth1Votes[T, U](votes0, votes1: HashList[T, U]):
    (bool, List[T, U]) =
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

  result[0] = lower_bound == 0
  for i in lower_bound ..< votes1.len:
    if not result[1].add votes1[i]:
      raiseAssert "same limit"

func replaceOrAddDecodeEth1Votes[T, U](
    votes0: var HashList[T, U], eth1_data_votes_replaced: bool,
    votes1: List[T, U]) =
  if eth1_data_votes_replaced:
    votes0 = HashList[T, U]()

  for item in votes1:
    if not votes0.add item:
      raiseAssert "same limit"

func getMutableValidatorStatuses(state: bellatrix.BeaconState):
    List[ValidatorStatus, Limit VALIDATOR_REGISTRY_LIMIT] =
  if not result.setLen(state.validators.len):
    raiseAssert "same limt as validators"
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

func diffStates*(state0, state1: bellatrix.BeaconState): BeaconStateDiff =
  doAssert state1.slot > state0.slot
  doAssert state0.slot.is_epoch
  doAssert state1.slot == state0.slot + SLOTS_PER_EPOCH
  # TODO not here, but in dag, an isancestorof check

  doAssert state0.genesis_time == state1.genesis_time
  doAssert state0.genesis_validators_root == state1.genesis_validators_root
  doAssert state0.fork == state1.fork
  doAssert state1.historical_roots.len - state0.historical_roots.len in [0, 1]

  let
    historical_root_added =
      state0.historical_roots.len != state1.historical_roots.len
    (eth1_data_votes_replaced, eth1_data_votes) =
      replaceOrAddEncodeEth1Votes(state0.eth1_data_votes, state1.eth1_data_votes)

  BeaconStateDiff(
    slot: state1.slot,
    latest_block_header: state1.latest_block_header,

    block_roots: diffModIncEpoch(state1.block_roots, state0.slot.uint64),
    state_roots: diffModIncEpoch(state1.state_roots, state0.slot.uint64),
    historical_root_added: historical_root_added,
    historical_root:
      if historical_root_added:
        state1.historical_roots[state0.historical_roots.len]
      else:
        default(Eth2Digest),
    eth1_data: state1.eth1_data,
    eth1_data_votes_replaced: eth1_data_votes_replaced,
    eth1_data_votes: eth1_data_votes,
    eth1_deposit_index: state1.eth1_deposit_index,

    validatorStatuses: getMutableValidatorStatuses(state1),
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
    next_sync_committee: state1.next_sync_committee
  )

func applyDiff*(
    state: var bellatrix.BeaconState,
    immutableValidators: openArray[ImmutableValidatorData2],
    stateDiff: BeaconStateDiff) =
  template assign[T, U](tgt: var HashList[T, U], src: List[T, U]) =
    assign(tgt.data, src)
    tgt.resetCache()

  # Carry over unchanged genesis_time, genesis_validators_root, and fork.
  assign(state.latest_block_header, stateDiff.latest_block_header)

  applyModIncrement(state.block_roots, stateDiff.block_roots, state.slot.uint64)
  applyModIncrement(state.state_roots, stateDiff.state_roots, state.slot.uint64)
  if stateDiff.historical_root_added:
    if not state.historical_roots.add stateDiff.historical_root:
      raiseAssert "cannot readd historical state root"

  assign(state.eth1_data, stateDiff.eth1_data)
  replaceOrAddDecodeEth1Votes(
    state.eth1_data_votes, stateDiff.eth1_data_votes_replaced,
    stateDiff.eth1_data_votes)
  assign(state.eth1_deposit_index, stateDiff.eth1_deposit_index)

  applyValidatorIdentities(state.validators, immutableValidators)
  setValidatorStatuses(state.validators, stateDiff.validator_statuses)
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
    state.previous_justified_checkpoint, stateDiff.previous_justified_checkpoint)
  assign(
    state.current_justified_checkpoint, stateDiff.current_justified_checkpoint)
  assign(state.finalized_checkpoint, stateDiff.finalized_checkpoint)

  assign(state.inactivity_scores, stateDiff.inactivity_scores)

  assign(state.current_sync_committee, stateDiff.current_sync_committee)
  assign(state.next_sync_committee, stateDiff.next_sync_committee)

  # Don't update slot until the end, because various other updates depend on it
  state.slot = stateDiff.slot
