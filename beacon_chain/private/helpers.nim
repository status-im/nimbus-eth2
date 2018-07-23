# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Helper functions
import ../datatypes, sequtils, nimcrypto

func getShuffling*(seed: Blake2_256_Digest, validatorCount: int): seq[int] {.noInit.}=
  ## Pseudorandomly shuffles the validator set based on some seed

  assert validatorCount <= MaxValidatorCount

  let randMax = MaxValidatorCount - MaxValidatorCount mod validatorCount
  result = toSeq(0 ..< validatorCount)
  var source = seed

  var i = 0
  while i < validatorCount:
    source = blake2_256.digest source.data
    for pos in countup(0, 29, 3):
      let remaining = validatorCount - i
      if remaining == 0:
        break

      let m = source.data[pos].int shl 16 or source.data[pos+1].int shl 8 or source.data[pos+2].int

      if validatorCount < randMax:
        let replacementPos = m mod remaining + i
        swap result[i], result[replacementPos]
        inc i

func getCutoffs*(validatorCount: int): tuple[height, shard: seq[int]] {.noInit.} =
  ## Split up validators into groups at the start of every epoch,
  ## determining at what height they can make attestations and what shard they are making crosslinks for
  ## Implementation should do the following: http://vitalik.ca/files/ShuffleAndAssign.png
  ## TODO: It doens't work.

  result.height = @[0]
  let cofactor = 39 # EpochLength / phi
  const StandardCommitteeSize = MaxValidatorCount div ShardCount

  var heightCount: int
  var heights: seq[int]

  if validatorCount < EpochLength * MinCommitteeSize:
    # If there are not enough validators to fill a minimally
    # sized committee at every height, skip some heights
    heightCount = validatorCount div MinCommitteeSize or 1 # TODO div/or precedence ?
    for i in 0 ..< heightCount:
      heights.add (i * cofactor) mod EpochLength
  else:
    # If there are enough validators, fill all the heights
    heightCount = EpochLength
    heights = toSeq(0 ..< EpochLength)

  var filled = 0
  for i in 0 ..< EpochLength - 1:
    if i notin heights: # TODO, this will be slow for seq, use intsets instead?
      result.height.add result.height[^1]
    else:
      inc filled
      result.height.add filled * validatorCount div heightCount
  result.height.add validatorCount

  # For the validators assigned to each height, split them up
  # into committees for different shards. Do not assign the
  # last END_EPOCH_GRACE_PERIOD heights in an epoch to any shards.

  result.shard = @[0]
  for i in 0 ..< EpochLength - EndEpochGracePeriod:
    let
      size = result.height[i+1] - result.height[i]
      shards = (size + StandardCommitteeSize - 1) div StandardCommitteeSize
      pre = result.shard[^1]
    for j in 1 .. shards:
      result.shard.add pre + size * j div shards
