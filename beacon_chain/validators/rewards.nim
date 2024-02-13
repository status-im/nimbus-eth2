# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ".."/spec/[forks, beaconstate, state_transition_block, helpers]

type
  AuxiliaryState = object
    currentEpochParticipation: EpochParticipationFlags
    previousEpochParticipation: EpochParticipationFlags

  RewardingBlock* = ForkedBeaconBlock | capella_mev.BlindedBeaconBlock |
                    deneb_mev.BlindedBeaconBlock

template withStateAndMaybeBlindedBlck(
    s: ForkedHashedBeaconState,
    b: RewardingBlock,
    body: untyped): untyped =
  when b is ForkedBeaconBlock:
    case s.kind
    of ConsensusFork.Deneb:
      const consensusFork {.inject, used.} = ConsensusFork.Deneb
      template forkyState: untyped {.inject.} = s.denebData
      template forkyBlck: untyped {.inject.} = b.denebData
      body
    of ConsensusFork.Capella:
      const consensusFork {.inject, used.} = ConsensusFork.Capella
      template forkyState: untyped {.inject.} = s.capellaData
      template forkyBlck: untyped {.inject.} = b.capellaData
      body
    of ConsensusFork.Bellatrix:
      const consensusFork {.inject, used.} = ConsensusFork.Bellatrix
      template forkyState: untyped {.inject.} = s.bellatrixData
      template forkyBlck: untyped {.inject.} = b.bellatrixData
      body
    of ConsensusFork.Altair:
      const consensusFork {.inject, used.} = ConsensusFork.Altair
      template forkyState: untyped {.inject.} = s.altairData
      template forkyBlck: untyped {.inject.} = b.altairData
      body
    of ConsensusFork.Phase0:
      const consensusFork {.inject, used.} = ConsensusFork.Phase0
      template forkyState: untyped {.inject, used.} = s.phase0Data
      template forkyBlck: untyped {.inject, used.} = b.phase0Data
      body
  elif b is capella_mev.BlindedBeaconBlock:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    template forkyState: untyped {.inject.} = s.capellaData
    template forkyBlck: untyped {.inject.} = b
  elif b is deneb_mev.BlindedBeaconBlock:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    template forkyState: untyped {.inject.} = s.denebData
    template forkyBlck: untyped {.inject.} = b
  else:
    {.error: "withStateAndMaybeBlindedBlock does not support " & $typeof(b).}

func init(t: typedesc[AuxiliaryState],
          forkedState: ForkedHashedBeaconState): Opt[AuxiliaryState] =
  withState(forkedState):
    when consensusFork > ConsensusFork.Phase0:
      Opt.some(
        AuxiliaryState(
          currentEpochParticipation:
            forkyState.data.current_epoch_participation,
          previousEpochParticipation:
            forkyState.data.previous_epoch_participation
        )
      )
    else:
      Opt.none(AuxiliaryState)

func collectFromSlashedValidator(
    proposerOutcome: var Gwei,
    state: ForkyBeaconState,
    slashedIndex, proposerIndex: ValidatorIndex
) =
  template slashed_validator: untyped =
    state.validators[slashedIndex]
  let whistleblowerReward =
    get_whistleblower_reward(slashed_validator.effective_balance)
  proposerOutcome += whistleblowerReward

proc collectFromProposerSlashings(
    proposerOutcome: var Gwei,
    forkedState: ForkedHashedBeaconState,
    forkedBlock: RewardingBlock
) =
  withStateAndMaybeBlindedBlck(forkedState, forkedBlock):
    for proposer_slashing in forkyBlck.body.proposer_slashings:
      doAssert check_proposer_slashing(
        forkyState.data, proposer_slashing, {}).isOk
      let slashedIndex =
        proposer_slashing.signed_header_1.message.proposer_index
      proposerOutcome.collectFromSlashedValidator(
        forkyState.data, slashedIndex.ValidatorIndex,
        forkyBlck.proposer_index.ValidatorIndex)

proc collectFromAttesterSlashings(
    proposerOutcome: var Gwei,
    forkedState: ForkedHashedBeaconState,
    forkedBlock: RewardingBlock
) =
  withStateAndMaybeBlindedBlck(forkedState, forkedBlock):
    for attester_slashing in forkyBlck.body.attester_slashings:
      let attester_slashing_validity =
        check_attester_slashing(forkyState.data, attester_slashing, {})
      doAssert attester_slashing_validity.isOk
      for slashedIndex in attester_slashing_validity.value:
        proposerOutcome.collectFromSlashedValidator(
          forkyState.data, slashedIndex,
          forkyBlck.proposer_index.ValidatorIndex)

proc collectFromAttestations(
    proposerOutcome: var Gwei,
    forkedState: ForkedHashedBeaconState,
    forkedBlock: RewardingBlock,
    auxiliaryState: var AuxiliaryState,
    cache: var StateCache
) =
  withStateAndMaybeBlindedBlck(forkedState, forkedBlock):
    when consensusFork > ConsensusFork.Phase0:
      let base_reward_per_increment = get_base_reward_per_increment(
        get_total_active_balance(forkyState.data, cache))
      doAssert base_reward_per_increment > 0
      for attestation in forkyBlck.body.attestations:
        doAssert check_attestation(
          forkyState.data, attestation, {}, cache).isOk
        let proposerReward =
          if attestation.data.target.epoch == get_current_epoch(forkyState.data):
            get_proposer_reward(forkyState.data, attestation,
              base_reward_per_increment, cache,
              auxiliaryState.currentEpochParticipation)
          else:
            get_proposer_reward(
              forkyState.data, attestation, base_reward_per_increment, cache,
              auxiliaryState.previousEpochParticipation)
        proposerOutcome += proposerReward

proc collectFromSyncAggregate(
    proposerOutcome: var Gwei,
    forkedState: ForkedHashedBeaconState,
    forkedBlock: RewardingBlock,
    cache: var StateCache
) =
  withStateAndMaybeBlindedBlck(forkedState, forkedBlock):
    when consensusFork > ConsensusFork.Phase0:
      let
        total_active_balance = get_total_active_balance(forkyState.data, cache)
        participant_reward = get_participant_reward(total_active_balance)
        proposer_reward =
          state_transition_block.get_proposer_reward(participant_reward)
        indices = get_sync_committee_cache(
          forkyState.data, cache).current_sync_committee

      template aggregate: untyped = forkyBlck.body.sync_aggregate

      doAssert indices.len == SYNC_COMMITTEE_SIZE
      doAssert aggregate.sync_committee_bits.len == SYNC_COMMITTEE_SIZE
      doAssert forkyState.data.current_sync_committee.pubkeys.len ==
        SYNC_COMMITTEE_SIZE

      for i in 0 ..< SYNC_COMMITTEE_SIZE:
        if aggregate.sync_committee_bits[i]:
          proposerOutcome += proposer_reward

proc collectBlockRewards*(
    forkedState: ForkedHashedBeaconState,
    forkedBlock: RewardingBlock
): Opt[UInt256] =
  var
    auxiliaryState = AuxiliaryState.init(forkedState).valueOr:
      return Opt.none(UInt256)
    cache: StateCache
    reward = Gwei(0'u64)

  reward.collectFromProposerSlashings(forkedState, forkedBlock)
  reward.collectFromAttesterSlashings(forkedState, forkedBlock)
  reward.collectFromAttestations(
    forkedState, forkedBlock, auxiliaryState, cache)
  reward.collectFromSyncAggregate(forkedState, forkedBlock, cache)
  ok(reward.toWei)
