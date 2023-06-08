# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[os, strutils],
  stew/bitops2,
  ../beacon_chain/spec/[
    datatypes/base,
    datatypes/phase0,
    datatypes/altair,
    datatypes/bellatrix,
    beaconstate,
    state_transition_epoch,
    state_transition_block,
    signatures],
  ../beacon_chain/consensus_object_pools/blockchain_dag

from ../beacon_chain/spec/datatypes/capella import BeaconState

type
  RewardsAndPenalties* = object
    source_outcome*: int64
    max_source_reward*: Gwei
    target_outcome*: int64
    max_target_reward*: Gwei
    head_outcome*: int64
    max_head_reward*: Gwei
    inclusion_delay_outcome*: int64
    max_inclusion_delay_reward*: Gwei
    sync_committee_outcome*: int64
    max_sync_committee_reward*: Gwei
    proposer_outcome*: int64
    inactivity_penalty*: Gwei
    slashing_outcome*: int64
    deposits*: Gwei
    inclusion_delay*: Option[uint64]

  ParticipationFlags* = object
    currentEpochParticipation: EpochParticipationFlags
    previousEpochParticipation: EpochParticipationFlags

  PubkeyToIndexTable = Table[ValidatorPubKey, ValidatorIndex]

  AuxiliaryState* = object
    epochParticipationFlags: ParticipationFlags
    pubkeyToIndex: PubkeyToIndexTable

const
  epochInfoFileNameDigitsCount = 8
  epochFileNameExtension = ".epoch"

func copyParticipationFlags*(auxiliaryState: var AuxiliaryState,
                             forkedState: ForkedHashedBeaconState) =
  withState(forkedState):
    when consensusFork > ConsensusFork.Phase0:
      template flags: untyped = auxiliaryState.epochParticipationFlags
      flags.currentEpochParticipation =
        forkyState.data.current_epoch_participation
      flags.previousEpochParticipation =
        forkyState.data.previous_epoch_participation

from std/sequtils import allIt

func matchFilenameUnaggregatedFiles(filename: string): bool =
  # epochNumberRegexStr & epochFileNameExtension
  filename.len == epochInfoFileNameDigitsCount + epochFileNameExtension.len and
    filename.endsWith(epochFileNameExtension) and
    # TODO should use toOpenArray, but
    # https://github.com/nim-lang/Nim/issues/15952
    # https://github.com/nim-lang/Nim/issues/19969
    allIt(filename[0 ..< epochInfoFileNameDigitsCount], it.isDigit)

static:
  for filename in [
      "00000000.epoch", "00243929.epoch", "04957024.epoch", "39820353.epoch",
      "82829191.epoch", "85740966.epoch", "93321944.epoch", "98928899.epoch"]:
    doAssert filename.matchFilenameUnaggregatedFiles

  for filename in [
      # Valid aggregated, not unaggregated
      "03820350_13372742.epoch", "04117778_69588614.epoch",
      "25249017_64218993.epoch", "34265267_41589365.epoch",
      "57926659_59282297.epoch", "67699314_92835461.epoch",

      "0000000.epoch",     # Too short
      "000000000.epoch",   # Too long
      "75787x73.epoch",    # Incorrect number format
      "00000000.ecpoh"]:   # Wrong extension
    doAssert not filename.matchFilenameUnaggregatedFiles

func matchFilenameAggregatedFiles(filename: string): bool =
  # epochNumberRegexStr & "_" & epochNumberRegexStr & epochFileNameExtension
  filename.len == epochInfoFileNameDigitsCount * 2 + "_".len + epochFileNameExtension.len and
    filename.endsWith(epochFileNameExtension) and
    # TODO should use toOpenArray, but
    # https://github.com/nim-lang/Nim/issues/15952
    # https://github.com/nim-lang/Nim/issues/19969
    allIt(filename[0 ..< epochInfoFileNameDigitsCount], it.isDigit) and
    filename[epochInfoFileNameDigitsCount] == '_' and
    allIt(
      filename[epochInfoFileNameDigitsCount + 1 ..< 2 * epochInfoFileNameDigitsCount + 1],
      it.isDigit)

static:
  for filename in [
      "03820350_13372742.epoch", "04117778_69588614.epoch",
      "25249017_64218993.epoch", "34265267_41589365.epoch",
      "57926659_59282297.epoch", "67699314_92835461.epoch"]:
    doAssert filename.matchFilenameAggregatedFiles

  for filename in [
      # Valid unaggregated, not aggregated
      "00000000.epoch", "00243929.epoch", "04957024.epoch", "39820353.epoch",
      "82829191.epoch", "85740966.epoch", "93321944.epoch", "98928899.epoch",

      "00000000_0000000.epoch",   # Too short
      "31x85971_93149672.epoch",  # Incorrect number format, first field
      "18049105&72034596.epoch",  # No underscore separator
      "31485971_931496x2.epoch",  # Incorrect number format, second field
      "15227487_86601706.echop"]: # Wrong extension
    doAssert not filename.matchFilenameAggregatedFiles

proc getUnaggregatedFilesEpochRange*(dir: string):
    tuple[firstEpoch, lastEpoch: Epoch] =
  var smallestEpochFileName =
    '9'.repeat(epochInfoFileNameDigitsCount) & epochFileNameExtension
  var largestEpochFileName =
    '0'.repeat(epochInfoFileNameDigitsCount) & epochFileNameExtension
  for (_, fn) in walkDir(dir.string, relative = true):
    if fn.matchFilenameUnaggregatedFiles:
      if fn < smallestEpochFileName:
        smallestEpochFileName = fn
      if fn > largestEpochFileName:
        largestEpochFileName = fn
  result.firstEpoch = parseUInt(
    smallestEpochFileName[0 ..< epochInfoFileNameDigitsCount]).Epoch
  result.lastEpoch = parseUInt(
    largestEpochFileName[0 ..< epochInfoFileNameDigitsCount]).Epoch

proc getUnaggregatedFilesLastEpoch*(dir: string): Epoch =
  dir.getUnaggregatedFilesEpochRange.lastEpoch

proc getAggregatedFilesLastEpoch*(dir: string): Epoch =
  var largestEpochInFileName = 0'u
  for (_, fn) in walkDir(dir.string, relative = true):
    if fn.matchFilenameAggregatedFiles:
      let fileLastEpoch = parseUInt(
        fn[epochInfoFileNameDigitsCount + 1 .. 2 * epochInfoFileNameDigitsCount])
      if fileLastEpoch > largestEpochInFileName:
        largestEpochInFileName = fileLastEpoch
  largestEpochInFileName.Epoch

func epochAsString*(epoch: Epoch): string =
  let strEpoch = $epoch
  '0'.repeat(epochInfoFileNameDigitsCount - strEpoch.len) & strEpoch

func getFilePathForEpoch*(epoch: Epoch, dir: string): string =
  dir / epochAsString(epoch) & epochFileNameExtension

func getFilePathForEpochs*(startEpoch, endEpoch: Epoch, dir: string): string =
  let fileName = epochAsString(startEpoch) & "_"  &
                 epochAsString(endEpoch) & epochFileNameExtension
  dir / fileName

func getBlockRange*(dag: ChainDAGRef, start, ends: Slot): seq[BlockId] =
  # Range of block in reverse order
  doAssert start < ends
  result = newSeqOfCap[BlockId](ends - start)
  var current = ends
  while current > start:
    current -= 1
    let bsid = dag.getBlockIdAtSlot(current).valueOr:
      continue

    if bsid.bid.slot < start: # current might be empty
      break

    result.add(bsid.bid)
    current = bsid.bid.slot # skip empty slots

func getOutcome(delta: RewardDelta): int64 =
  delta.rewards.int64 - delta.penalties.int64

func collectSlashings(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    state: ForkyBeaconState, total_balance: Gwei) =
  let
    epoch = get_current_epoch(state)
    adjusted_total_slashing_balance = get_adjusted_total_slashing_balance(
      state, total_balance)

  for index in 0 ..< state.validators.len:
    let validator = unsafeAddr state.validators[index]
    if slashing_penalty_applies(validator[], epoch):
      rewardsAndPenalties[index].slashing_outcome +=
        validator[].get_slashing_penalty(
          adjusted_total_slashing_balance, total_balance).int64

proc collectEpochRewardsAndPenalties*(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    state: var phase0.BeaconState, cache: var StateCache, cfg: RuntimeConfig,
    flags: UpdateFlags) =
  if get_current_epoch(state) == GENESIS_EPOCH:
    return

  var info: phase0.EpochInfo

  info.init(state)
  info.process_attestations(state, cache)
  doAssert info.validators.len == state.validators.len
  rewardsAndPenalties.setLen(state.validators.len)

  process_justification_and_finalization(state, info.balances, flags)

  let
    finality_delay = get_finality_delay(state)
    total_balance = info.balances.current_epoch
    total_balance_sqrt = integer_squareroot(total_balance)

  for index, validator in info.validators:
    if not is_eligible_validator(validator):
      continue

    let base_reward  = get_base_reward_sqrt(
      state, index.ValidatorIndex, total_balance_sqrt)

    template get_attestation_component_reward_helper(attesting_balance: Gwei): Gwei =
      get_attestation_component_reward(attesting_balance,
        info.balances.current_epoch, base_reward.uint64, finality_delay)

    template rp: untyped = rewardsAndPenalties[index]

    rp.source_outcome = get_source_delta(
      validator, base_reward, info.balances, finality_delay).getOutcome
    rp.max_source_reward = get_attestation_component_reward_helper(
      info.balances.previous_epoch_attesters)

    rp.target_outcome = get_target_delta(
      validator, base_reward, info.balances, finality_delay).getOutcome
    rp.max_target_reward = get_attestation_component_reward_helper(
      info.balances.previous_epoch_target_attesters)

    rp.head_outcome = get_head_delta(
       validator, base_reward, info.balances, finality_delay).getOutcome
    rp.max_head_reward = get_attestation_component_reward_helper(
      info.balances.previous_epoch_head_attesters)

    let (inclusion_delay_delta, proposer_delta) = get_inclusion_delay_delta(
      validator, base_reward)
    rp.inclusion_delay_outcome = inclusion_delay_delta.getOutcome
    rp.max_inclusion_delay_reward =
      base_reward - state_transition_epoch.get_proposer_reward(base_reward)

    rp.inactivity_penalty = get_inactivity_penalty_delta(
      validator, base_reward, finality_delay).penalties

    if proposer_delta.isSome:
      let proposer_index = proposer_delta.get[0]
      if proposer_index < info.validators.lenu64:
        rewardsAndPenalties[proposer_index].proposer_outcome +=
          proposer_delta.get[1].getOutcome

  rewardsAndPenalties.collectSlashings(state, info.balances.current_epoch)

proc collectEpochRewardsAndPenalties*(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    state: var (altair.BeaconState | bellatrix.BeaconState |
                capella.BeaconState | deneb.BeaconState),
    cache: var StateCache, cfg: RuntimeConfig, flags: UpdateFlags) =
  if get_current_epoch(state) == GENESIS_EPOCH:
    return

  var info: altair.EpochInfo
  info.init(state)
  doAssert info.validators.len == state.validators.len
  rewardsAndPenalties.setLen(state.validators.len)

  process_justification_and_finalization(state, info.balances, flags)
  process_inactivity_updates(cfg, state, info)

  let
    total_active_balance = info.balances.current_epoch
    base_reward_per_increment = get_base_reward_per_increment(
      total_active_balance)
    finality_delay = get_finality_delay(state)

  for flag_index in 0 ..< PARTICIPATION_FLAG_WEIGHTS.len:
    for validator_index, delta in get_flag_index_deltas(
        state, flag_index, base_reward_per_increment, info, finality_delay):
      template rp: untyped = rewardsAndPenalties[validator_index]

      let
        base_reward = get_base_reward_increment(
          state, validator_index, base_reward_per_increment)
        active_increments = get_active_increments(info)
        unslashed_participating_increment =
          get_unslashed_participating_increment(info, flag_index)
        max_flag_index_reward = get_flag_index_reward(
          state, base_reward, active_increments,
          unslashed_participating_increment,
          PARTICIPATION_FLAG_WEIGHTS[flag_index].uint64,
          finality_delay)

      case flag_index
      of TIMELY_SOURCE_FLAG_INDEX:
        rp.source_outcome = delta.getOutcome
        rp.max_source_reward = max_flag_index_reward
      of TIMELY_TARGET_FLAG_INDEX:
        rp.target_outcome = delta.getOutcome
        rp.max_target_reward = max_flag_index_reward
      of TIMELY_HEAD_FLAG_INDEX:
        rp.head_outcome = delta.getOutcome
        rp.max_head_reward = max_flag_index_reward
      else:
        raiseAssert(&"Unknown flag index {flag_index}.")

  for validator_index, penalty in get_inactivity_penalty_deltas(
      cfg, state, info):
    rewardsAndPenalties[validator_index].inactivity_penalty += penalty

  rewardsAndPenalties.collectSlashings(state, info.balances.current_epoch)

func collectFromSlashedValidator(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    state: ForkyBeaconState, slashedIndex, proposerIndex: ValidatorIndex) =
  template slashed_validator: untyped = state.validators[slashedIndex]
  let slashingPenalty = get_slashing_penalty(state, slashed_validator.effective_balance)
  let whistleblowerReward = get_whistleblower_reward(slashed_validator.effective_balance)
  rewardsAndPenalties[slashedIndex].slashing_outcome -= slashingPenalty.int64
  rewardsAndPenalties[proposerIndex].slashing_outcome += whistleblowerReward.int64

func collectFromProposerSlashings(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    forkedState: ForkedHashedBeaconState,
    forkedBlock: ForkedTrustedSignedBeaconBlock) =
  withStateAndBlck(forkedState, forkedBlock):
    for proposer_slashing in blck.message.body.proposer_slashings:
      doAssert check_proposer_slashing(
        forkyState.data, proposer_slashing, {}).isOk
      let slashedIndex =
        proposer_slashing.signed_header_1.message.proposer_index
      rewardsAndPenalties.collectFromSlashedValidator(
        forkyState.data, slashedIndex.ValidatorIndex,
        blck.message.proposer_index.ValidatorIndex)

func collectFromAttesterSlashings(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    forkedState: ForkedHashedBeaconState,
    forkedBlock: ForkedTrustedSignedBeaconBlock) =
  withStateAndBlck(forkedState, forkedBlock):
    for attester_slashing in blck.message.body.attester_slashings:
      let attester_slashing_validity = check_attester_slashing(
        forkyState.data, attester_slashing, {})
      doAssert attester_slashing_validity.isOk
      for slashedIndex in attester_slashing_validity.value:
        rewardsAndPenalties.collectFromSlashedValidator(
          forkyState.data, slashedIndex,
          blck.message.proposer_index.ValidatorIndex)

func collectFromAttestations(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    forkedState: ForkedHashedBeaconState,
    forkedBlock: ForkedTrustedSignedBeaconBlock,
    epochParticipationFlags: var ParticipationFlags,
    cache: var StateCache) =
  withStateAndBlck(forkedState, forkedBlock):
    when consensusFork > ConsensusFork.Phase0:
      let base_reward_per_increment = get_base_reward_per_increment(
        get_total_active_balance(forkyState.data, cache))
      doAssert base_reward_per_increment > 0
      for attestation in blck.message.body.attestations:
        doAssert check_attestation(
          forkyState.data, attestation, {}, cache).isOk
        let proposerReward =
          if attestation.data.target.epoch == get_current_epoch(forkyState.data):
            get_proposer_reward(
              forkyState.data, attestation, base_reward_per_increment, cache,
              epochParticipationFlags.currentEpochParticipation)
          else:
            get_proposer_reward(
              forkyState.data, attestation, base_reward_per_increment, cache,
              epochParticipationFlags.previousEpochParticipation)
        rewardsAndPenalties[blck.message.proposer_index].proposer_outcome +=
          proposerReward.int64
        let inclusionDelay = forkyState.data.slot - attestation.data.slot
        for index in get_attesting_indices(
            forkyState.data, attestation.data, attestation.aggregation_bits,
            cache):
          rewardsAndPenalties[index].inclusion_delay = some(inclusionDelay.uint64)

proc collectFromDeposits(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    forkedState: ForkedHashedBeaconState,
    forkedBlock: ForkedTrustedSignedBeaconBlock,
    pubkeyToIndex: var PubkeyToIndexTable,
    cfg: RuntimeConfig) =
  withStateAndBlck(forkedState, forkedBlock):
    for deposit in blck.message.body.deposits:
      let pubkey = deposit.data.pubkey
      let amount = deposit.data.amount
      var index = findValidatorIndex(forkyState.data, pubkey)
      if index.isNone:
        if pubkey in pubkeyToIndex:
          index = Opt[ValidatorIndex].ok(pubkeyToIndex[pubkey])
      if index.isSome:
        rewardsAndPenalties[index.get()].deposits += amount
      elif verify_deposit_signature(cfg, deposit.data):
        pubkeyToIndex[pubkey] = ValidatorIndex(rewardsAndPenalties.len)
        rewardsAndPenalties.add(
          RewardsAndPenalties(deposits: amount))

func collectFromSyncAggregate(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    forkedState: ForkedHashedBeaconState,
    forkedBlock: ForkedTrustedSignedBeaconBlock,
    cache: var StateCache) =
  withStateAndBlck(forkedState, forkedBlock):
    when consensusFork > ConsensusFork.Phase0:
      let
        total_active_balance = get_total_active_balance(forkyState.data, cache)
        participant_reward = get_participant_reward(total_active_balance)
        proposer_reward =
          state_transition_block.get_proposer_reward(participant_reward)
        indices = get_sync_committee_cache(
          forkyState.data, cache).current_sync_committee

      template aggregate: untyped = blck.message.body.sync_aggregate

      doAssert indices.len == SYNC_COMMITTEE_SIZE
      doAssert aggregate.sync_committee_bits.len == SYNC_COMMITTEE_SIZE
      doAssert forkyState.data.current_sync_committee.pubkeys.len ==
        SYNC_COMMITTEE_SIZE

      for i in 0 ..< SYNC_COMMITTEE_SIZE:
        rewardsAndPenalties[indices[i]].max_sync_committee_reward +=
          participant_reward
        if aggregate.sync_committee_bits[i]:
          rewardsAndPenalties[indices[i]].sync_committee_outcome +=
            participant_reward.int64
          rewardsAndPenalties[blck.message.proposer_index].proposer_outcome +=
            proposer_reward.int64
        else:
          rewardsAndPenalties[indices[i]].sync_committee_outcome -=
            participant_reward.int64

proc collectBlockRewardsAndPenalties*(
    rewardsAndPenalties: var seq[RewardsAndPenalties],
    forkedState: ForkedHashedBeaconState,
    forkedBlock: ForkedTrustedSignedBeaconBlock,
    auxiliaryState: var AuxiliaryState,
    cache: var StateCache, cfg: RuntimeConfig) =
  rewardsAndPenalties.collectFromProposerSlashings(forkedState, forkedBlock)
  rewardsAndPenalties.collectFromAttesterSlashings(forkedState, forkedBlock)
  rewardsAndPenalties.collectFromAttestations(
    forkedState, forkedBlock, auxiliaryState.epochParticipationFlags, cache)
  rewardsAndPenalties.collectFromDeposits(
    forkedState, forkedBlock, auxiliaryState.pubkeyToIndex, cfg)
  # This table is needed only to resolve double deposits in the same block, so
  # it can be cleared after processing all deposits for the current block.
  auxiliaryState.pubkeyToIndex.clear
  rewardsAndPenalties.collectFromSyncAggregate(forkedState, forkedBlock, cache)

func serializeToCsv*(rp: RewardsAndPenalties,
                     avgInclusionDelay = none(float)): string =
  for name, value in fieldPairs(rp):
    if value isnot Option:
      result &= $value & ","
  if avgInclusionDelay.isSome:
    result.addFloat(avgInclusionDelay.get)
  elif rp.inclusion_delay.isSome:
    result &= $rp.inclusion_delay.get
  result &= "\n"
