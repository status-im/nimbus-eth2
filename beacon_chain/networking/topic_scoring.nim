# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import std/math
import pkg/chronos

from
  libp2p/protocols/pubsub/gossipsub
import
  TopicParams, validateParameters, init


# Gossipsub scoring explained:
# A score of a peer in a topic is the sum of 5 different scores:
#
# `timeInMesh`: for each `Quantum` spent in a mesh,
# the peer will win `Weight` points, up to `(Cap * Weight)`
#
# Every following score decays: score is multiplied by `Decay` in every heartbeat
# until they reach `decayToZero` (0.1 by default)
#
# `firstMessageDelivery`: for each message delivered first,
# the peer will win `Weight` points, up to `(Cap * Weight)`
#
# `meshMessageDeliveries`: The most convoluted way possible to punish
# peers not sending enough traffic in a topic.
#
# For each message (duplicate or first) received in a topic, the score is incremented, up to `Cap`.
# If the score of the topic gets below `Threshold`, the peer
# since at least `Activation` time will have: `score += (Threshold - Score)² * Weight`
# (`Weight` should be negative to punish them)
#
# `meshFailurePenalty`: same as meshMessageDeliveries, but only happens on prune
# to avoid peers constantly unsubbing-resubbing
#
# `invalidMessageDeliveries`: for each message not passing validation received, a peer
# score is incremented. Final score = `Score * Score * Weight`
#
#
# Once we have the 5 scores for each peer/topic, we sum them up per peer
# using the topicWeight of each topic.
#
# Nimbus strategy:
# Trying to get a 100 possible points in each topic before weighting
# And then, weight each topic to have 100 points max total
#
# In order of priority:
# - A badly behaving peer (eg, sending bad messages) will be heavily sanctionned
# - A good peer will gain good scores
# - Inactive/slow peers will be mildly sanctionned.
#
# Since a "slow" topic will punish everyone in it, we don't want to punish
# good peers which are unlucky and part of a slow topic. So, we give more points to
# good peers than we remove to slow peers
#
# Global topics are good to check stability of peers, but since we can only
# have ~20 peers in global topics, we need to score on subnets to have data
# about as much peers as possible, even the subnets are less stable
func computeDecay(
  startValue: float,
  endValue: float,
  timeToEndValue: Duration,
  heartbeatTime: Duration
  ): float =
  # startValue will to to endValue in timeToEndValue
  # given the returned decay

  let heartbeatsToZero = timeToEndValue.milliseconds.float / heartbeatTime.milliseconds.float
  pow(endValue / startValue, 1 / heartbeatsToZero)

func computeMessageDeliveriesWeight(
  messagesThreshold: float,
  maxLostPoints: float): float =

  let maxDeficit = messagesThreshold
  -maxLostPoints / (maxDeficit * maxDeficit)

type TopicScoringType* = enum
  BlockTopic,
  AggregateTopic,
  SubnetTopic,
  OtherTopic

proc getTopicParams*(
  topicWeight: float,
  heartbeatPeriod: Duration,
  period: Duration,
  averageOverNPeriods: float,
  peersPerTopic: int,
  expectedMessagesPerPeriod: int,
  timeInMeshQuantum: Duration
  ): TopicParams =

  let
    # Statistically, a peer will be first for every `receivedMessage / d`
    shouldBeFirstPerPeriod = expectedMessagesPerPeriod / peersPerTopic
    shouldBeFirstOverNPeriod = shouldBeFirstPerPeriod * averageOverNPeriods
    shouldBeFirstEvery = nanoseconds(period.nanoseconds div expectedMessagesPerPeriod) * peersPerTopic
    firstMessageCap = shouldBeFirstOverNPeriod

    # If peer is first every `shouldBeFirstEvery`
    # he will be able to stay at cap
    firstMessageDecay =
      computeDecay(
        startValue = firstMessageCap,
        endValue = firstMessageCap - 1,
        timeToEndValue = shouldBeFirstEvery,
        heartbeatPeriod)

    # Start to remove up to 30 points when peer send less
    # than half message than expected
    shouldSendAtLeastPerPeriod = expectedMessagesPerPeriod / 2
    shouldSendAtLeastOverNPeriod = shouldSendAtLeastPerPeriod * averageOverNPeriods

    messageDeliveryThreshold = shouldSendAtLeastOverNPeriod
    messageDeliveryWeight = computeMessageDeliveriesWeight(messageDeliveryThreshold, 30.0)
    messageDeliveryDecay =
      computeDecay(
        startValue = expectedMessagesPerPeriod.float * averageOverNPeriods,
        endValue = 0,
        timeToEndValue = period * averageOverNPeriods.int,
        heartbeatPeriod)

    # Invalid message should be remembered a long time
    invalidMessageDecay = computeDecay(
                            startValue = 1,
                            endValue = 0.1,
                            timeToEndValue = chronos.minutes(1),
                            heartbeatPeriod)

  let topicParams = TopicParams(
    topicWeight: topicWeight,
    timeInMeshQuantum: timeInMeshQuantum,
    timeInMeshCap: 200, # 20 points after timeInMeshQuantum * 200
    timeInMeshWeight: 0.1, # timeInMesh should be less powerful than inactive penalties
    firstMessageDeliveriesCap: firstMessageCap,
    firstMessageDeliveriesDecay: firstMessageDecay,
    firstMessageDeliveriesWeight: 80.0 / firstMessageCap, # Max points: 80
    meshMessageDeliveriesWeight: messageDeliveryWeight,
    meshMessageDeliveriesDecay: messageDeliveryDecay,
    meshMessageDeliveriesThreshold: messageDeliveryThreshold,
    meshMessageDeliveriesCap: expectedMessagesPerPeriod.float * averageOverNPeriods,
    meshMessageDeliveriesActivation: period * averageOverNPeriods.int,
    meshMessageDeliveriesWindow: chronos.milliseconds(10),
    meshFailurePenaltyWeight: messageDeliveryWeight,
    meshFailurePenaltyDecay: messageDeliveryDecay,
    invalidMessageDeliveriesWeight: -1, # 10 invalid messages = -100 points
    invalidMessageDeliveriesDecay: invalidMessageDecay
  )
  topicParams
