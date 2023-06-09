# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronos

from
  libp2p/protocols/pubsub/gossipsub
import
  TopicParams, validateParameters, init

# inspired by lighthouse research here
# https://gist.github.com/blacktemplar/5c1862cb3f0e32a1a7fb0b25e79e6e2c#file-generate-scoring-params-py
const
  blocksTopicParams* = TopicParams(
    topicWeight: 0.5,
    timeInMeshWeight: 0.03333333333333333,
    timeInMeshQuantum: chronos.seconds(12),
    timeInMeshCap: 300,
    firstMessageDeliveriesWeight: 1.1471603557060206,
    firstMessageDeliveriesDecay: 0.9928302477768374,
    firstMessageDeliveriesCap: 34.86870846001471,
    meshMessageDeliveriesWeight: -458.31054878249114,
    meshMessageDeliveriesDecay: 0.9716279515771061,
    meshMessageDeliveriesThreshold: 0.6849191409056553,
    meshMessageDeliveriesCap: 2.054757422716966,
    meshMessageDeliveriesActivation: chronos.seconds(384),
    meshMessageDeliveriesWindow: chronos.seconds(2),
    meshFailurePenaltyWeight: -458.31054878249114 ,
    meshFailurePenaltyDecay: 0.9716279515771061,
    invalidMessageDeliveriesWeight: -214.99999999999994,
    invalidMessageDeliveriesDecay: 0.9971259067705325
  )
  aggregateTopicParams* = TopicParams(
    topicWeight: 0.5,
    timeInMeshWeight: 0.03333333333333333,
    timeInMeshQuantum: chronos.seconds(12),
    timeInMeshCap: 300,
    firstMessageDeliveriesWeight: 0.10764904539552399,
    firstMessageDeliveriesDecay: 0.8659643233600653,
    firstMessageDeliveriesCap: 371.5778421725158,
    meshMessageDeliveriesWeight: -0.07538533073670682,
    meshMessageDeliveriesDecay: 0.930572040929699,
    meshMessageDeliveriesThreshold: 53.404248450179836,
    meshMessageDeliveriesCap: 213.61699380071934,
    meshMessageDeliveriesActivation: chronos.seconds(384),
    meshMessageDeliveriesWindow: chronos.seconds(2),
    meshFailurePenaltyWeight: -0.07538533073670682 ,
    meshFailurePenaltyDecay: 0.930572040929699,
    invalidMessageDeliveriesWeight: -214.99999999999994,
    invalidMessageDeliveriesDecay: 0.9971259067705325
  )
  basicParams* = TopicParams.init()

static:
  # compile time validation
  blocksTopicParams.validateParameters().tryGet()
  aggregateTopicParams.validateParameters().tryGet()
  basicParams.validateParameters.tryGet()
