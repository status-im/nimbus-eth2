# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Inspired by Lighthouse research here:
# https://gist.github.com/blacktemplar/5c1862cb3f0e32a1a7fb0b25e79e6e2c#file-generate-scoring-params-py
# by Lighthouse actual implementation here:
# https://github.com/sigp/lighthouse/blob/stable/beacon_node/lighthouse_network/src/service/gossipsub_scoring_parameters.rs
# by Prysm actual implementation here:
# https://github.com/prysmaticlabs/prysm/blob/develop/beacon-chain/p2p/gossip_scoring_params.go

import std/[math, strutils]
import results, chronos
import ".."/spec/[presets, network, validator]

from libp2p/protocols/pubsub/gossipsub import
  TopicParams, validateParameters, init

type
  MeshMessageInfo = object
    meshMessageDecayTime: chronos.Duration
    meshMessageCapFactor: float64
    meshMessageActivation: chronos.Duration
    dampeningFactor: float64

func slotsDuration(number: int): chronos.Duration =
  chronos.seconds(int64(SECONDS_PER_SLOT) * number)

func epochsDuration(number: int): chronos.Duration =
  chronos.seconds(int64(SECONDS_PER_SLOT * SLOTS_PER_EPOCH) * number)

const
  GossipD = 8
  ## `BeaconBlockWeight` specifies the scoring weight that we apply to
  ## our beacon block topic.
  ## blacktemplar's code uses 0.5
  BeaconBlockWeight = 0.5'f64
  ## `AggregateWeight` specifies the scoring weight that we apply to
  ## our aggregate topic.
  AggregateWeight = 0.5'f64
  ## `SyncContributionWeight` specifies the scoring weight that we apply to
  ## our sync contribution topic.
  SyncContributionWeight = 0.2'f64
  ## `AttestationTotalWeight` specifies the scoring weight that we apply to
  ## our attestation subnet topic.
  AttestationTotalWeight = 1'f64
  ## `SyncCommitteesTotalWeight` specifies the scoring weight that we apply to
  ## our sync subnet topic.
  SyncCommitteesTotalWeight = 0.4'f64
  ## `AttesterSlashingWeight` specifies the scoring weight that we apply to
  ## our attester slashing topic.
  AttesterSlashingWeight = 0.05'f64
  ## `ProposerSlashingWeight` specifies the scoring weight that we apply to
  ## our proposer slashing topic.
  ProposerSlashingWeight = 0.05'f64
  ## `VoluntaryExitWeight` specifies the scoring weight that we apply to
  ## our voluntary exit topic.
  VoluntaryExitWeight = 0.05'f64
  ## `BlsToExecutionChangeWeight` specifies the scoring weight that we apply to
  ## our bls to execution topic.
  BlsToExecutionChangeWeight = 0.05'f64
  ## `MaxInMeshScore` describes the max score a peer can attain from being in
  ## the mesh.
  MaxInMeshScore = 10'f64
  ## `MaxFirstDeliveryScore` describes the max score a peer can obtain from
  ## first deliveries.
  MaxFirstDeliveryScore = 40'f64
  ## `DecayToZero` specifies the terminal value that we will use when decaying
  ## a value.
  DecayToZero = 0.01'f64
  DecayInterval = chronos.seconds(int64(SECONDS_PER_SLOT))
  ## `DampeningFactor` reduces the amount by which the various thresholds and
  ## caps are created. Python code and Lighthouse using 50.0, while Prysm
  ## using 90.0.
  DampeningFactor = 50'f64
  ## The time window (seconds) that we expect messages to be forwarded to us
  ## in the mesh.
  MeshMessageDeliveriesWindow = chronos.seconds(2)
  ## `MaxScore` maximum score a peer can get.
  MaxScore =
    (MaxInMeshScore + MaxFirstDeliveryScore) *
    (BeaconBlockWeight + AggregateWeight +
     AttestationTotalWeight +
     AttesterSlashingWeight + ProposerSlashingWeight + VoluntaryExitWeight +
     SyncCommitteesTotalWeight + SyncContributionWeight +
     BlsToExecutionChangeWeight)
  InvalidMessageDecayPeriod = epochsDuration(50)

func init(
    t: typedesc[MeshMessageInfo],
    meshMessageDecayTime: chronos.Duration,
    meshMessageCapFactor: float64,
    meshMessageActivation: chronos.Duration,
    dampeningFactor = DampeningFactor
): MeshMessageInfo =
  MeshMessageInfo(
    meshMessageDecayTime: meshMessageDecayTime,
    meshMessageCapFactor: meshMessageCapFactor,
    meshMessageActivation: meshMessageActivation,
    dampeningFactor: dampeningFactor
  )

func scoreParameterDecay(decayDuration: chronos.Duration): float64 =
  ## Computes the decay to use such that a value of 1 decays to 0 (using the
  ## DecayToZero parameter) within the specified `decayDuration`.
  let ticks = decayDuration.seconds div DecayInterval.seconds
  math.pow(DecayToZero, 1'f64 / float64(ticks))

func decayConvergence(decay, rate: float64): float64 =
  ## Computes the limit to which a decay process will convert if it has the
  ## given issuaence rate per decay interval and the given decay factor.
  rate / (1 - decay)

func threshold(decay, requiredRate: float64): float64 =
  ## Computes a threshold value if we require at least the given rate with the
  ## given decay (In fact we require strictly more than the given rate, since
  ## the rate will reach the threshold only at infinity).
  decayConvergence(decay, requiredRate) * decay

func expectedAggregatorCountPerSloot(validators: uint64): float64 =
  let
    committees =
      get_committee_count_per_slot(validators) * SLOTS_PER_EPOCH
    (smallerCommitteeSize, numLargerCommittees) = divmod(validators, committees)
    moduloSmaller =
      max(1'u64,
          smallerCommitteeSize div TARGET_AGGREGATORS_PER_COMMITTEE)
    moduleLarger =
      max(1'u64,
          (smallerCommitteeSize + 1) div TARGET_AGGREGATORS_PER_COMMITTEE)

  (float64((committees - numLargerCommittees) * smallerCommitteeSize) /
     float64(moduloSmaller) +
     float64(numLargerCommittees * (smallerCommitteeSize + 1)) /
     float64(moduleLarger)) / float64(SLOTS_PER_EPOCH)

func topicParams(
    topicWeight: float64,
    expectedMessageRate: float64,
    firstMessageDecayTime: chronos.Duration,
    meshMessageInfo: Opt[MeshMessageInfo] = Opt.none(MeshMessageInfo)
): TopicParams =
  let
    timeInMeshCap = float64(3600) / float64(SECONDS_PER_SLOT)
    firstMessageDeliveriesDecay =
      scoreParameterDecay(firstMessageDecayTime)
    firstMessageDeliveriesCap =
      decayConvergence(firstMessageDeliveriesDecay,
                       2'f64 * expectedMessageRate / float64(GossipD))
  if meshMessageInfo.isNone():
    TopicParams(
      topicWeight:
        topicWeight,
      timeInMeshWeight:
        MaxInMeshScore / timeInMeshCap,
      timeInMeshQuantum:
        chronos.seconds(int64(SECONDS_PER_SLOT)),
      timeInMeshCap:
        timeInMeshCap,
      firstMessageDeliveriesDecay:
        firstMessageDeliveriesDecay,
      firstMessageDeliveriesCap:
        firstMessageDeliveriesCap,
      firstMessageDeliveriesWeight:
        MaxFirstDeliveryScore / firstMessageDeliveriesCap,
      meshMessageDeliveriesWeight: 0.0'f64,
      meshMessageDeliveriesThreshold: 0.0'f64,
      meshMessageDeliveriesDecay: 0.0'f64,
      meshMessageDeliveriesCap: 0.0'f64,
      meshMessageDeliveriesActivation: ZeroDuration,
      meshMessageDeliveriesWindow: ZeroDuration,
      meshFailurePenaltyDecay: 0.0'f64,
      meshFailurePenaltyWeight: 0.0'f64,
      invalidMessageDeliveriesWeight:
        -MaxScore / topicWeight,
      invalidMessageDeliveriesDecay:
        scoreParameterDecay(InvalidMessageDecayPeriod)
    )
  else:
    let
      info = meshMessageInfo.get()
      meshMessageDeliveriesDecay =
        if info.meshMessageDecayTime.isZero():
          0.0'f64
        else:
          scoreParameterDecay(info.meshMessageDecayTime)
      meshMessageDeliveriesThreshold =
        if info.meshMessageDecayTime.isZero():
          0.0'f64
        else:
          threshold(meshMessageDeliveriesDecay,
                    expectedMessageRate / info.dampeningFactor)
      meshMessageDeliveriesWeight =
        if info.meshMessageDecayTime.isZero():
          0.0'f64
        else:
          -MaxScore / (topicWeight * meshMessageDeliveriesThreshold *
                       meshMessageDeliveriesThreshold)
      meshMessageDeliveriesCap =
        info.meshMessageCapFactor * meshMessageDeliveriesThreshold
      meshMessageDeliveriesActivation =
        if info.meshMessageDecayTime.isZero():
          ZeroDuration
        else:
          info.meshMessageActivation
      meshMessageDeliveriesWindow =
        if info.meshMessageDecayTime.isZero():
          ZeroDuration
        else:
          MeshMessageDeliveriesWindow
      meshFailurePenaltyWeight = meshMessageDeliveriesWeight
      meshFailurePenaltyDecay = meshMessageDeliveriesDecay

    TopicParams(
      topicWeight:
        topicWeight,
      timeInMeshWeight:
        MaxInMeshScore / timeInMeshCap,
      timeInMeshQuantum:
        chronos.seconds(int64(SECONDS_PER_SLOT)),
      timeInMeshCap:
        timeInMeshCap,
      firstMessageDeliveriesDecay:
        firstMessageDeliveriesDecay,
      firstMessageDeliveriesCap:
        firstMessageDeliveriesCap,
      firstMessageDeliveriesWeight:
        MaxFirstDeliveryScore / firstMessageDeliveriesCap,
      meshMessageDeliveriesDecay:
        meshMessageDeliveriesDecay,
      meshMessageDeliveriesThreshold:
        meshMessageDeliveriesThreshold,
      meshMessageDeliveriesWeight:
        meshMessageDeliveriesWeight,
      meshMessageDeliveriesCap:
        meshMessageDeliveriesCap,
      meshMessageDeliveriesActivation:
        meshMessageDeliveriesActivation,
      meshMessageDeliveriesWindow:
        meshMessageDeliveriesWindow,
      meshFailurePenaltyWeight:
        meshFailurePenaltyWeight,
      meshFailurePenaltyDecay:
        meshFailurePenaltyDecay,
      invalidMessageDeliveriesWeight:
        -MaxScore / topicWeight,
      invalidMessageDeliveriesDecay:
        scoreParameterDecay(InvalidMessageDecayPeriod),
    )

func getBlockTopicParams*(): TopicParams =
  let meshInfo =
    MeshMessageInfo.init(epochsDuration(5), 3.0'f64,
                         epochsDuration(1))
  topicParams(BeaconBlockWeight, 1.0'f64, epochsDuration(20),
              Opt.some(meshInfo))

func getAttestationSubnetTopicParams*(validatorsCount: uint64): TopicParams =
  let
    committeesPerSlot = get_committee_count_per_slot(validatorsCount)
    multipleBurstsPerSubnetPerEpoch =
      committeesPerSlot >= 2 * ATTESTATION_SUBNET_COUNT div SLOTS_PER_EPOCH
    topicWeight = 1.0'f64 / float64(ATTESTATION_SUBNET_COUNT)
    messageRate =
      float64(validatorsCount) / float64(ATTESTATION_SUBNET_COUNT) /
      float64(SLOTS_PER_EPOCH)
    firstMessageDecayTime =
      if multipleBurstsPerSubnetPerEpoch:
        epochsDuration(1)
      else:
        epochsDuration(4)
    meshMessageDecayTime =
      if multipleBurstsPerSubnetPerEpoch:
        epochsDuration(4)
      else:
        epochsDuration(16)
    meshMessageCapFactor = 16.0'f64
    meshMessageActivation =
      if multipleBurstsPerSubnetPerEpoch:
        slotsDuration(int(SLOTS_PER_EPOCH) div 2 + 1)
      else:
        epochsDuration(3)
    meshInfo = MeshMessageInfo.init(meshMessageDecayTime, meshMessageCapFactor,
                                    meshMessageActivation)
  topicParams(topicWeight, messageRate, firstMessageDecayTime,
              Opt.some(meshInfo))

func getSyncCommitteeSubnetTopicParams*(validatorsCount: uint64): TopicParams =
  let
    topicWeight =
      SyncCommitteesTotalWeight / float64(SYNC_COMMITTEE_SUBNET_COUNT)
    activeValidators =
      if validatorsCount > SYNC_COMMITTEE_SIZE:
        uint64(SYNC_COMMITTEE_SIZE)
      else:
        validatorsCount
    messageRate =
      float64(activeValidators) / float64(SYNC_COMMITTEE_SUBNET_COUNT)
    firstMessageDecayTime = epochsDuration(1)
    meshMessageDecayTime = epochsDuration(4)
    meshMessageCapFactor = 4.0'f64
    meshMessageActivation = epochsDuration(1)
    meshInfo = MeshMessageInfo.init(meshMessageDecayTime, meshMessageCapFactor,
                                    meshMessageActivation)
  topicParams(topicWeight, messageRate, firstMessageDecayTime,
              Opt.some(meshInfo))

func getAggregateProofTopicParams*(validatorsCount: uint64): TopicParams =
  let
    messageRate = expectedAggregatorCountPerSloot(validatorsCount)
    meshInfo = MeshMessageInfo.init(epochsDuration(2), 4.0'f64,
                                    epochsDuration(1))
  topicParams(AggregateWeight, messageRate, epochsDuration(1),
              Opt.some(meshInfo))

func getSyncContributionTopicParams*(): TopicParams =
  let
    messageRate = float64(
      SYNC_COMMITTEE_SUBNET_COUNT * TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
    meshInfo = MeshMessageInfo.init(epochsDuration(1), 4.0'f64,
                                    epochsDuration(1))
  topicParams(SyncContributionWeight, messageRate, epochsDuration(1),
              Opt.some(meshInfo))

func getVoluntaryExitTopicParams*(): TopicParams =
  let messageRate = 4.0'f64 / float(SLOTS_PER_EPOCH)
  topicParams(VoluntaryExitWeight, messageRate, epochsDuration(100),
              Opt.none(MeshMessageInfo))

func getProposerSlashingTopicParams*(): TopicParams =
  let messageRate = 1.0'f64 / 5.0'f64 / float64(SLOTS_PER_EPOCH)
  topicParams(ProposerSlashingWeight, messageRate, epochsDuration(100),
              Opt.none(MeshMessageInfo))

func getAttesterSlashingTopicParams*(): TopicParams =
  let messageRate = 1.0'f64 / 5.0'f64 / float64(SLOTS_PER_EPOCH)
  topicParams(AttesterSlashingWeight, messageRate, epochsDuration(100),
              Opt.none(MeshMessageInfo))

func getBlsToExecutionChangeTopicParams*(): TopicParams =
  let messageRate = 1.0'f64 / 5.0'f64 / float64(SLOTS_PER_EPOCH)
  topicParams(BlsToExecutionChangeWeight, messageRate, epochsDuration(100),
              Opt.none(MeshMessageInfo))

func basicParams*(): TopicParams = TopicParams.init()

proc `$`*(params: TopicParams): string =
  const FormatString =
    "TopicWeight: $1\p" &
    "TimeInMeshWeight: $2\p" &
    "TimeInMeshQuantum: $3\p" &
    "TimeInMeshCap: $4\p" &
    "FirstMessageDeliveriesWeight: $5\p" &
    "FirstMessageDeliveriesDecay: $6\p" &
    "FirstMessageDeliveriesCap:: $7\p" &
    "MeshMessageDeliveriesWeight: $8\p" &
    "MeshMessageDeliveriesDecay: $9\p" &
    "MeshMessageDeliveriesCap: $10\p" &
    "MeshMessageDeliveriesThreshold: $11\p" &
    "MeshMessageDeliveriesWindow: $12\p" &
    "MeshMessageDeliveriesActivation: $13\p" &
    "MeshFailurePenaltyWeight: $14\p" &
    "MeshFailurePenaltyDecay: $15\p" &
    "InvalidMessageDeliveriesWeight: $16\p" &
    "InvalidMessageDeliveriesDecay: $17\p"
  try:
    FormatString % [
      $params.topicWeight,
      $params.timeInMeshWeight,
      $params.timeInMeshQuantum,
      $params.timeInMeshCap,
      $params.firstMessageDeliveriesWeight,
      $params.firstMessageDeliveriesDecay,
      $params.firstMessageDeliveriesCap,
      $params.meshMessageDeliveriesWeight,
      $params.meshMessageDeliveriesDecay,
      $params.meshMessageDeliveriesCap,
      $params.meshMessageDeliveriesThreshold,
      $params.meshMessageDeliveriesWindow,
      $params.meshMessageDeliveriesActivation,
      $params.meshFailurePenaltyWeight,
      $params.meshFailurePenaltyDecay,
      $params.invalidMessageDeliveriesWeight,
      $params.invalidMessageDeliveriesDecay
    ]
  except ValueError:
    raiseAssert "Should not happen"
